// crates/node/src/gossip.rs
// Peer-to-peer gossip layer.
//
// Responsibilities:
//   1. When this node produces or receives a PBFT vote, forward it to all peers.
//   2. When this node writes a new block, announce it to peers so they can sync.
//   3. When a peer announces a block we don't have, fetch and apply it.
//
// The gossip model is simple: every node fans out to every known peer.
// In a larger network this would be replaced with a structured gossip
// (epidemic broadcast), but for a registry with tens of nodes, full fan-out is fine.

// anyhow::Result is unused in this module
use common::Block;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Mutex;
use std::time::Duration;

/// Configurable gossip parameters for larger validator sets.
#[derive(Debug, Clone)]
pub struct GossipConfig {
    /// HTTP request timeout for peer calls (default: 3 s).
    pub request_timeout: Duration,
    /// Maximum concurrent outbound requests per broadcast (default: 20).
    /// Prevents overwhelming the local network stack at 50+ validators.
    pub max_concurrent_fanout: usize,
    /// How long (in seconds) to remember a message hash for dedup (default: 60 s).
    pub message_ttl_secs: u64,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(3),
            max_concurrent_fanout: 20,
            message_ttl_secs: 60,
        }
    }
}

/// Domain-separation tag for the canonical consensus vote message format.
/// Bumping the version invalidates any cached signatures from older validators.
pub const VOTE_MESSAGE_DOMAIN: &str = "creg-vote-v2";

/// Canonical message that a validator signs when casting a PBFT vote.
///
/// Binds the package canonical, the exact tarball content hash, the verdict,
/// the validator's Ed25519 public key, the scanner profile digest, and the
/// deterministic evidence digest so that:
///   (a) signatures cannot be replayed across package versions,
///   (b) signatures cannot be replayed across approve/reject flips,
///   (c) a signature cannot be relabelled to come from a different validator,
///   (d) a vote cannot be stripped of the scanner/evidence profile it used.
pub fn canonical_vote_message(
    canonical: &str,
    content_hash: &str,
    approved: bool,
    validator_pubkey: &str,
    scanner_profile_digest: &str,
    evidence_digest: &str,
) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}|{}",
        VOTE_MESSAGE_DOMAIN,
        canonical,
        content_hash,
        approved,
        validator_pubkey,
        scanner_profile_digest,
        evidence_digest
    )
}

/// Message sent to peers when we produce a PBFT vote.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteGossip {
    /// Package-consensus subject identifier.
    ///
    /// Deserializes legacy `block_hash` payloads during the field rename.
    #[serde(alias = "block_hash")]
    pub consensus_subject: String,
    /// SHA-256 of the tarball bytes — bound into the signature to prevent
    /// cross-version replay. Serde default keeps wire-format backward compat.
    #[serde(default)]
    pub content_hash: String,
    pub validator_id: String,
    /// Hex-encoded Ed25519 public key of the voting validator.
    pub validator_pubkey: String,
    /// ML model version used by the validator during deep scan.
    #[serde(default)]
    pub ml_model_version: String,
    /// Versioned analysis bundles active for this vote.
    #[serde(default)]
    pub analysis_bundles: common::AnalysisBundleRefs,
    /// Digest over deterministic evidence considered by the sender.
    #[serde(default)]
    pub evidence_digest: String,
    /// Compact deterministic risk summary captured when the vote was formed.
    #[serde(default)]
    pub deterministic_risk: common::DeterministicRiskSummary,
    pub phase: String, // "prepare" | "commit"
    pub approved: bool,
    pub reject_reason: Option<String>,
    /// Hex-encoded Ed25519 signature of `canonical_vote_message(...)`.
    /// The signed payload includes the scanner profile and evidence digest.
    pub signature: String,
}

/// Message sent to peers when we write a new block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockAnnouncement {
    pub height: u64,
    pub block_hash: String,
    pub proposer: String,
}

/// Message sent to peers to share a decryption share for a shielded package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptionShareGossip {
    /// The canonical package identifier being decrypted.
    pub canonical: String,
    /// The validator broadcasting this share.
    pub validator_id: String,
    /// Share index (1-based; corresponds to the validator's position).
    pub share_index: u8,
    /// The decrypted share value (hex-encoded).
    pub share_value: String,
    /// Ed25519 signature over "decrypt:<canonical>:<share_index>:<share_value>".
    pub signature: String,
}

pub struct Gossip {
    client: Client,
    peer_urls: Vec<String>,
    config: GossipConfig,
    /// Recently-seen message hashes to avoid re-processing duplicates.
    seen: Mutex<HashSet<String>>,
}

impl Gossip {
    pub fn new(peer_urls: Vec<String>) -> Self {
        Self::with_config(peer_urls, GossipConfig::default())
    }

    pub fn with_config(peer_urls: Vec<String>, config: GossipConfig) -> Self {
        let client = Client::builder()
            .timeout(config.request_timeout)
            .build()
            .expect("Failed to build HTTP client");
        Self {
            client,
            peer_urls,
            config,
            seen: Mutex::new(HashSet::new()),
        }
    }

    /// Returns `true` if this message hash has already been processed within the
    /// configured TTL window.  Inserts the hash if it is new.
    pub fn is_duplicate(&self, msg_hash: &str) -> bool {
        let mut seen = self.seen.lock().expect("gossip seen-set mutex poisoned");
        !seen.insert(msg_hash.to_owned())
    }

    /// Evict entries older than `message_ttl_secs`.
    /// Call periodically (e.g. from a background timer) to bound memory.
    pub fn evict_stale(&self) {
        let mut seen = self.seen.lock().expect("gossip seen-set mutex poisoned");
        // Simple strategy: just clear when the set grows large.
        // A production implementation would pair each entry with an Instant.
        if seen.len() > 10_000 {
            seen.clear();
            tracing::debug!(
                "Evicted gossip dedup cache ({} TTL)",
                self.config.message_ttl_secs
            );
        }
    }

    // ── Vote fan-out ──────────────────────────────────────────────────────────

    /// Broadcast a PBFT vote to all known peers concurrently.
    /// Failures are logged but do not propagate — a peer being down is expected.
    /// Fan-out is bounded by `config.max_concurrent_fanout` to avoid overwhelming
    /// the local network stack in large validator sets.
    pub async fn broadcast_vote(&self, vote: &VoteGossip) {
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(
            self.config.max_concurrent_fanout,
        ));

        let tasks: Vec<_> = self
            .peer_urls
            .iter()
            .map(|url| {
                let client = self.client.clone();
                let url = format!("{}/v1/consensus/vote", url.trim_end_matches('/'));
                let body = vote.clone();
                let sem = sem.clone();
                tokio::spawn(async move {
                    let _permit = sem.acquire().await;
                    if let Err(e) = client.post(&url).json(&body).send().await {
                        tracing::debug!("Vote gossip to {} failed: {}", url, e);
                    }
                })
            })
            .collect();

        futures::future::join_all(tasks).await;
    }

    // ── Block announcement ────────────────────────────────────────────────────

    /// Announce a new block height to all peers.
    /// Peers will fetch the full block via GET /v1/blocks/:height if they need it.
    pub async fn announce_block(&self, block: &Block) {
        let ann = BlockAnnouncement {
            height: block.header.height,
            block_hash: block.hash(),
            proposer: block.header.proposer_id.clone(),
        };

        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(
            self.config.max_concurrent_fanout,
        ));

        let tasks: Vec<_> = self
            .peer_urls
            .iter()
            .map(|url| {
                let client = self.client.clone();
                let url = format!("{}/v1/blocks/announce", url.trim_end_matches('/'));
                let body = ann.clone();
                let sem = sem.clone();
                tokio::spawn(async move {
                    let _permit = sem.acquire().await;
                    if let Err(e) = client.post(&url).json(&body).send().await {
                        tracing::debug!("Block announce to {} failed: {}", url, e);
                    }
                })
            })
            .collect();

        futures::future::join_all(tasks).await;
    }

    // ── Block fetching ────────────────────────────────────────────────────────

    /// Fetch a specific block from the first peer that has it.
    pub async fn fetch_block(&self, height: u64) -> Option<Block> {
        for url in &self.peer_urls {
            let full_url = format!("{}/v1/blocks/{}", url.trim_end_matches('/'), height);
            match self.client.get(&full_url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    if let Ok(block) = resp.json::<Block>().await {
                        tracing::debug!("Fetched block {} from {}", height, url);
                        return Some(block);
                    }
                }
                _ => continue,
            }
        }
        None
    }

    /// Fetch the chain tip height from the first reachable peer.
    pub async fn peer_tip_height(&self) -> Option<u64> {
        #[derive(Deserialize)]
        struct Stats {
            tip_height: u64,
        }

        for url in &self.peer_urls {
            let full_url = format!("{}/v1/chain/stats", url.trim_end_matches('/'));
            if let Ok(resp) = self.client.get(&full_url).send().await {
                if let Ok(stats) = resp.json::<Stats>().await {
                    return Some(stats.tip_height);
                }
            }
        }
        None
    }

    pub fn peer_count(&self) -> usize {
        self.peer_urls.len()
    }
}
