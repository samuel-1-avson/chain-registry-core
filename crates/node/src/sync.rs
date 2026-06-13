// crates/node/src/sync.rs
// Chain synchronisation — brings a lagging node up to the network tip.
//
// On startup, and periodically during operation, this module:
//   1. Asks peers for their chain tip height.
//   2. If we are behind, fetches each missing block in order.
//   3. Validates each block's prev_hash linkage before inserting.
//   4. Applies each block to the publisher index.
//
// This is a simple linear sync. In a production network with thousands of
// blocks, a state-snapshot sync (download a snapshot + apply delta) would
// be more efficient, but for a registry where each block contains a handful
// of package verification transactions, linear sync is perfectly adequate.

use crate::NodeState;
use common::{Transaction, ValidatorSet, ValidatorVote};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};

/// Sync interval — check for new blocks from peers every 10 seconds.
const SYNC_INTERVAL_SECS: u64 = 10;

/// Maximum reorg depth this node will automatically recover from. Forks
/// deeper than this require operator intervention (they indicate either a
/// long partition or an attack and should not be auto-adopted).
const MAX_REORG_DEPTH: u64 = 64;

pub async fn run(state: Arc<RwLock<NodeState>>) {
    // Initial sync at startup.
    if let Err(e) = sync_once(Arc::clone(&state)).await {
        tracing::warn!("Initial chain sync failed: {}", e);
    }

    let mut ticker = interval(Duration::from_secs(SYNC_INTERVAL_SECS));
    tracing::info!("Chain sync running (interval: {}s)", SYNC_INTERVAL_SECS);

    loop {
        ticker.tick().await;
        if let Err(e) = sync_once(Arc::clone(&state)).await {
            tracing::debug!("Chain sync tick failed: {}", e);
        }
    }
}

async fn sync_once(state: Arc<RwLock<NodeState>>) -> anyhow::Result<()> {
    let (our_height, peer_urls) = {
        let s = state.read().await;
        (s.chain.tip_height()?, s.config.peers.clone())
    };

    // Ask peers for their tip.
    let mut peer_height = 0;
    let client = reqwest::Client::new();

    for url in &peer_urls {
        let full_url = format!("{}/v1/chain/stats", url.trim_end_matches('/'));
        if let Ok(resp) = client.get(&full_url).send().await {
            #[derive(serde::Deserialize)]
            struct Stats {
                tip_height: u64,
            }
            if let Ok(stats) = resp.json::<Stats>().await {
                peer_height = peer_height.max(stats.tip_height);
            }
        }
    }

    if peer_height <= our_height {
        tracing::debug!("Chain is up to date (height {})", our_height);
        return Ok(());
    }

    tracing::info!(
        "Chain sync: our height={} peer height={} — fetching {} blocks",
        our_height,
        peer_height,
        peer_height - our_height
    );

    // Fetch each missing block in order and validate the chain linkage.
    let mut prev_hash = {
        let s = state.read().await;
        s.chain.tip_hash()?
    };

    for height in (our_height + 1)..=peer_height {
        let block = match fetch_block(&client, &peer_urls, height).await {
            Some(b) => b,
            None => {
                tracing::warn!("Could not fetch block {} from any peer", height);
                break;
            }
        };

        // Validate chain linkage. A mismatch means our local chain forked
        // from the network's canonical chain — attempt reorg recovery
        // instead of halting sync forever.
        if block.header.prev_hash != prev_hash {
            tracing::warn!(
                "Block {} has wrong prev_hash (expected {}, got {}) — \
                 local chain has diverged from peers, attempting reorg recovery",
                height,
                &prev_hash[..12],
                &block.header.prev_hash[..12]
            );
            match attempt_reorg_recovery(&state, &client, &peer_urls, height - 1, peer_height).await
            {
                Ok(true) => {
                    tracing::info!("Reorg recovery succeeded — chain re-aligned with peers");
                }
                Ok(false) => {
                    tracing::warn!("Reorg recovery not applied — will retry on next sync tick");
                }
                Err(e) => {
                    tracing::error!("Reorg recovery failed: {}", e);
                }
            }
            break;
        }

        if block.header.height != height {
            tracing::error!(
                "Block claims height {} but we requested {}",
                block.header.height,
                height
            );
            break;
        }

        // Verify that every Publish transaction carries a PBFT quorum of valid
        // signatures against the current validator set. Without this check a
        // malicious peer could serve a syntactically-valid block whose payload
        // never reached consensus. (ISSUE-018)
        let (validator_set, data_dir) = {
            let s = state.read().await;
            (s.validator_set.clone(), s.config.data_dir.clone())
        };
        // Verify against the validator set that was active at THIS block's
        // height (ISSUE-050), falling back to the current set when no
        // historical snapshot covers it (no regression).
        let effective_set = crate::validator_set_history::set_at(&data_dir, block.header.height)
            .unwrap_or(validator_set);
        if let Err(e) = verify_block_signatures(&block, &effective_set) {
            tracing::error!(
                "Block {} failed signature verification: {} — halting sync",
                height,
                e
            );
            break;
        }

        prev_hash = block.hash();

        // Insert and index the block.
        {
            let mut s = state.write().await;
            s.chain.insert_block(&block)?;
            s.publisher_index.apply_block(&block);
        }

        tracing::info!("Synced block {} ({})", height, &prev_hash[..12]);
    }

    Ok(())
}

/// Fetch a block at `height` from the first peer that serves it.
async fn fetch_block(
    client: &reqwest::Client,
    peer_urls: &[String],
    height: u64,
) -> Option<common::Block> {
    for url in peer_urls {
        let full_url = format!("{}/v1/blocks/{}", url.trim_end_matches('/'), height);
        if let Ok(resp) = client.get(&full_url).send().await {
            if let Ok(b) = resp.json::<common::Block>().await {
                return Some(b);
            }
        }
    }
    None
}

/// Attempt to recover from a fork between the local chain and the network.
///
/// `local_tip` is the highest local height that conflicts with the peers'
/// branch (the block whose hash the peers' next block does not link to).
///
/// Strategy (longest-valid-chain):
///   1. Walk back from `local_tip` (bounded by `MAX_REORG_DEPTH`) comparing
///      local block hashes with peer block hashes to find the common ancestor.
///   2. Fetch the peers' branch from `ancestor+1..=peer_height`, verifying
///      linkage and the PBFT signature quorum on every block *before*
///      mutating any local state.
///   3. Only adopt the new branch if it is strictly longer than ours.
///   4. Roll back to the ancestor, insert the new branch, rebuild the package
///      and publisher indexes, and record a `ReorgEvent` for /v1/reorgs.
///
/// Returns Ok(true) if the reorg was applied, Ok(false) if it was declined
/// (no ancestor found within depth limit, branch invalid, or not longer).
async fn attempt_reorg_recovery(
    state: &Arc<RwLock<NodeState>>,
    client: &reqwest::Client,
    peer_urls: &[String],
    local_tip: u64,
    peer_height: u64,
) -> anyhow::Result<bool> {
    // ── 1. Find the common ancestor ───────────────────────────────────────
    let floor = local_tip.saturating_sub(MAX_REORG_DEPTH);
    let mut ancestor: Option<(u64, String)> = None;

    for k in (floor..=local_tip).rev() {
        let ours = {
            let s = state.read().await;
            s.chain.get_block_by_height(k)?
        };
        let Some(ours) = ours else { continue };
        let Some(theirs) = fetch_block(client, peer_urls, k).await else {
            tracing::warn!(
                "Reorg recovery: could not fetch peer block {} — aborting",
                k
            );
            return Ok(false);
        };
        if ours.hash() == theirs.hash() {
            ancestor = Some((k, ours.hash()));
            break;
        }
    }

    let Some((fork_height, ancestor_hash)) = ancestor else {
        tracing::error!(
            "Reorg recovery: no common ancestor within {} blocks of height {} — \
             this fork is too deep to auto-recover; operator intervention required",
            MAX_REORG_DEPTH,
            local_tip
        );
        return Ok(false);
    };

    // ── 2. Fetch and fully validate the peers' branch before adopting ────
    let (validator_set, data_dir) = {
        let s = state.read().await;
        (s.validator_set.clone(), s.config.data_dir.clone())
    };

    let mut new_branch: Vec<common::Block> = Vec::new();
    let mut link_hash = ancestor_hash;
    for h in (fork_height + 1)..=peer_height {
        let Some(b) = fetch_block(client, peer_urls, h).await else {
            tracing::warn!(
                "Reorg recovery: peer branch incomplete at height {} — aborting",
                h
            );
            return Ok(false);
        };
        if b.header.height != h {
            tracing::warn!(
                "Reorg recovery: block claims height {} at {} — aborting",
                b.header.height,
                h
            );
            return Ok(false);
        }
        if b.header.prev_hash != link_hash {
            tracing::warn!(
                "Reorg recovery: peer branch broke linkage at height {} — aborting",
                h
            );
            return Ok(false);
        }
        let effective_set = crate::validator_set_history::set_at(&data_dir, b.header.height)
            .unwrap_or_else(|| validator_set.clone());
        if let Err(e) = verify_block_signatures(&b, &effective_set) {
            tracing::error!(
                "Reorg recovery: peer branch block {} failed signature verification: {} — \
                 refusing to adopt fork",
                h,
                e
            );
            return Ok(false);
        }
        link_hash = b.hash();
        new_branch.push(b);
    }

    // ── 3. Longest-chain rule: only adopt a strictly longer branch ───────
    let new_tip_height = fork_height + new_branch.len() as u64;
    if new_tip_height <= local_tip {
        tracing::warn!(
            "Reorg recovery: peer branch tip {} is not longer than local tip {} — keeping ours",
            new_tip_height,
            local_tip
        );
        return Ok(false);
    }

    // ── 4. Apply: rewind, adopt, rebuild derived state, record the event ─
    {
        let mut s = state.write().await;
        let abandoned = s.chain.rollback_to_height(fork_height)?;
        for b in &new_branch {
            s.chain.insert_block(b)?;
        }
        s.chain.rebuild_package_index()?;

        let tip = s.chain.tip_height()?;
        let mut canonical_blocks = Vec::with_capacity((tip + 1) as usize);
        for h in 0..=tip {
            if let Some(b) = s.chain.get_block_by_height(h)? {
                canonical_blocks.push(b);
            }
        }
        s.publisher_index
            .rebuild_from_chain(canonical_blocks.iter());

        let depth = local_tip - fork_height;
        s.record_reorg(depth, abandoned, link_hash.clone());
    }

    tracing::info!(
        "Reorg applied: fork at height {}, new tip {} ({})",
        fork_height,
        new_tip_height,
        &link_hash[..link_hash.len().min(12)]
    );
    Ok(true)
}

/// Verify PBFT consensus signatures on every Publish transaction in a block.
///
/// Each `ChainRecord` in the block must carry at least `⌊2n/3⌋ + 1` valid
/// Ed25519 signatures from validators currently in the active set, where each
/// signature is over the domain-separated payload produced by
/// `crate::gossip::canonical_vote_message(...)`.
///
/// Notes and limitations:
///   * Uses the *current* validator set. Historical validator-set tracking is
///     a follow-up enhancement (ISSUE-050 in the roadmap). A node syncing
///     across a validator-set transition may legitimately see signatures from
///     validators not in the current set — those are simply ignored.
///   * Non-Publish transactions (Revoke, Slash, ValidatorJoin/Leave,
///     RotatePublisherKey) are intentionally not verified here; they are
///     governance-originated and validated at the state-transition layer.
///   * Single-validator deployments still require the one validator's signature.
fn verify_block_signatures(
    block: &common::Block,
    validator_set: &ValidatorSet,
) -> anyhow::Result<()> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    // Genesis has no signatures by design.
    if block.header.height == 0 {
        return Ok(());
    }

    let n = validator_set.validators.len();
    if n == 0 {
        anyhow::bail!("cannot verify block: local validator set is empty");
    }
    let quorum = (2 * n / 3) + 1;

    // Build a pubkey → validator_id lookup once so per-signature verification
    // is O(1) instead of O(n).
    let known: std::collections::HashMap<String, &common::Validator> = validator_set
        .validators
        .iter()
        .map(|v| (v.pubkey.to_ascii_lowercase(), v))
        .collect();

    for (tx_idx, tx) in block.transactions.iter().enumerate() {
        let record = match tx {
            Transaction::Publish(r) => r,
            _ => continue,
        };
        let canonical = record.id.canonical();

        let mut approval_groups: HashMap<String, usize> = HashMap::new();
        let mut seen = HashSet::new();

        for sig in &record.validator_signatures {
            if !matches!(sig.vote, ValidatorVote::Approve) {
                continue;
            }
            if !common::is_consensus_grade_vote(
                &sig.ml_model_version,
                &sig.analysis_bundles,
                &sig.evidence_digest,
            ) {
                tracing::debug!(
                    "sync: tx {} carries consensus-ineligible signature from {} — ignored",
                    tx_idx,
                    sig.validator_id
                );
                continue;
            }

            let pubkey_key = sig.validator_pubkey.to_ascii_lowercase();
            if !known.contains_key(&pubkey_key) {
                tracing::debug!(
                    "sync: tx {} carries signature from unknown validator pubkey {} — ignored",
                    tx_idx,
                    pubkey_key
                );
                continue;
            }
            if !seen.insert(pubkey_key.clone()) {
                // Duplicate signature from the same validator — count only once.
                continue;
            }

            let pubkey_bytes = match hex::decode(&sig.validator_pubkey) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let vk = match VerifyingKey::try_from(pubkey_bytes.as_slice()) {
                Ok(k) => k,
                Err(_) => continue,
            };
            let sig_bytes = match hex::decode(&sig.signature) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let ed_sig = match Signature::try_from(sig_bytes.as_slice()) {
                Ok(s) => s,
                Err(_) => continue,
            };

            let message = crate::gossip::canonical_vote_message(
                &canonical,
                &record.content_hash,
                matches!(sig.vote, ValidatorVote::Approve),
                &sig.validator_pubkey,
                &common::scanner_profile_digest(&sig.ml_model_version, &sig.analysis_bundles),
                &sig.evidence_digest,
            );

            if vk.verify(message.as_bytes(), &ed_sig).is_ok() {
                let profile_key = format!(
                    "{}:{}",
                    common::scanner_profile_digest(&sig.ml_model_version, &sig.analysis_bundles),
                    sig.evidence_digest
                );
                *approval_groups.entry(profile_key).or_default() += 1;
            }
        }

        let approvals = approval_groups.values().copied().max().unwrap_or(0);
        if approvals < quorum {
            anyhow::bail!(
                "tx {} ({}): only {} valid signatures, need {} ({}/{} validators)",
                tx_idx,
                canonical,
                approvals,
                quorum,
                approvals,
                n
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::verify_block_signatures;
    use chrono::Utc;
    use common::{
        merkle_root, AnalysisBundleRefs, Block, BlockHeader, ChainRecord, DeterministicRiskSummary,
        PackageId, PackageStatus, Transaction, Validator, ValidatorSet, ValidatorSignature,
        ValidatorVote,
    };
    use consensus::{aggregate_evidence_votes, EvidenceVoteOutcome};
    use ed25519_dalek::{Signer, SigningKey};

    #[derive(Clone, Copy)]
    enum VotePayloadFormat {
        Canonical,
        Legacy,
    }

    fn validator(id: &str, signing_key: &SigningKey) -> Validator {
        Validator {
            id: id.into(),
            alias: id.into(),
            pubkey: hex::encode(signing_key.verifying_key().as_bytes()),
            eth_address: String::new(),
            stake: 100,
            reputation: 100,
            status: "online".into(),
        }
    }

    fn signed_approval(
        validator_id: &str,
        signing_key: &SigningKey,
        canonical: &str,
        content_hash: &str,
        format: VotePayloadFormat,
    ) -> ValidatorSignature {
        let validator_pubkey = hex::encode(signing_key.verifying_key().as_bytes());
        let analysis_bundles = AnalysisBundleRefs {
            policy_bundle_id: "policy-v1".into(),
            feature_schema_id: "features-v1".into(),
            expert_bundle_id: "experts-v1".into(),
            embedding_model_id: "embeddings-v1".into(),
            index_epoch: "index-epoch-1".into(),
            threshold_profile_id: "thresholds-v1".into(),
            llm_prompt_profile_id: "llm-prompt-v1".into(),
            osv_snapshot_epoch: "osv-off".into(),
        };
        let evidence_digest =
            common::sha256_hex(format!("{canonical}:{content_hash}:sync-test-evidence").as_bytes());
        let ml_model_version = "creg-detect-v1.0.0".to_string();
        let message = match format {
            VotePayloadFormat::Canonical => crate::gossip::canonical_vote_message(
                canonical,
                content_hash,
                true,
                &validator_pubkey,
                &common::scanner_profile_digest(&ml_model_version, &analysis_bundles),
                &evidence_digest,
            ),
            VotePayloadFormat::Legacy => format!("{}-{}", canonical, content_hash),
        };

        ValidatorSignature {
            validator_id: validator_id.into(),
            validator_pubkey,
            signature: hex::encode(signing_key.sign(message.as_bytes()).to_bytes()),
            vote: ValidatorVote::Approve,
            signed_at: Utc::now(),
            ml_model_version,
            analysis_bundles,
            evidence_digest,
            deterministic_risk: DeterministicRiskSummary::default(),
        }
    }

    fn publish_block(record: ChainRecord) -> Block {
        let tx = Transaction::Publish(record);

        Block {
            header: BlockHeader {
                height: 1,
                prev_hash: Block::genesis().hash(),
                merkle_root: merkle_root(std::slice::from_ref(&tx)),
                proposer_id: "node-1".into(),
                timestamp: Utc::now(),
                validator_set_hash: "dev".into(),
                vrf_output: None,
                vrf_proof: None,
            },
            transactions: vec![tx],
            pbft_signatures: vec![],
        }
    }

    fn publish_record(
        package_id: &PackageId,
        content_hash: &str,
        validator_signatures: Vec<ValidatorSignature>,
    ) -> ChainRecord {
        ChainRecord {
            id: package_id.clone(),
            content_hash: content_hash.into(),
            ipfs_cid: "bafytestcid".into(),
            publisher_pubkey: "publisher-pubkey".into(),
            block_hash: String::new(),
            published_at: Utc::now(),
            validator_signatures,
            status: PackageStatus::Verified,
            shielded: false,
            key_bundle: None,
            pgp_fingerprint: None,
            findings: vec![],
            analysis_bundles: AnalysisBundleRefs::default(),
            evidence_digest: String::new(),
            deterministic_risk: DeterministicRiskSummary::default(),
            access_count: 0,
            last_accessed: None,
            threshold: 0,
            publisher_pubkeys: vec![],
            manifest: None,
        }
    }

    #[test]
    fn aggregated_votes_pass_sync_only_with_canonical_payload() {
        let package_id = PackageId::new("npm", "pkg", "1.0.0");
        let canonical = package_id.canonical();
        let content_hash = common::sha256_hex(b"vote-sync-regression");

        let signing_keys = [
            ("node-1", SigningKey::from_bytes(&[7u8; 32])),
            ("node-2", SigningKey::from_bytes(&[8u8; 32])),
            ("node-3", SigningKey::from_bytes(&[9u8; 32])),
        ];
        let validator_set = ValidatorSet::new(
            signing_keys
                .iter()
                .map(|(id, key)| validator(id, key))
                .collect(),
        );

        let canonical_votes: Vec<_> = signing_keys
            .iter()
            .map(|(id, key)| {
                signed_approval(
                    id,
                    key,
                    &canonical,
                    &content_hash,
                    VotePayloadFormat::Canonical,
                )
            })
            .collect();
        let canonical_outcome =
            aggregate_evidence_votes(&canonical_votes, validator_set.validators.len())
                .expect("three canonical approvals should satisfy aggregation quorum");
        let EvidenceVoteOutcome::Verified(canonical_signatures) = canonical_outcome else {
            panic!("expected verified aggregation outcome for canonical votes");
        };

        let canonical_block = publish_block(publish_record(
            &package_id,
            &content_hash,
            canonical_signatures,
        ));
        verify_block_signatures(&canonical_block, &validator_set)
            .expect("follower sync should accept canonical aggregated votes");

        let legacy_votes: Vec<_> = signing_keys
            .iter()
            .map(|(id, key)| {
                signed_approval(
                    id,
                    key,
                    &canonical,
                    &content_hash,
                    VotePayloadFormat::Legacy,
                )
            })
            .collect();
        let legacy_outcome =
            aggregate_evidence_votes(&legacy_votes, validator_set.validators.len())
                .expect("three legacy approvals still satisfy vote aggregation quorum");
        let EvidenceVoteOutcome::Verified(legacy_signatures) = legacy_outcome else {
            panic!("expected verified aggregation outcome for legacy votes");
        };

        let legacy_block = publish_block(publish_record(
            &package_id,
            &content_hash,
            legacy_signatures,
        ));
        let error = verify_block_signatures(&legacy_block, &validator_set)
            .expect_err("follower sync must reject the legacy vote payload format");

        assert!(
            error
                .to_string()
                .contains("only 0 valid signatures, need 3"),
            "unexpected sync failure: {error}"
        );
    }
}
