// crates/common/src/package.rs

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum FindingSeverity {
    /// Package must be rejected — direct evidence of malice.
    Critical,
    /// Strongly suspicious — requires human appeal to override.
    High,
    /// Notable but possibly legitimate — shown as warning.
    Medium,
    /// Informational only.
    #[default]
    Low,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: FindingSeverity,
    pub description: String,
    pub file: String,
    pub line: Option<usize>,
}

/// Uniquely identifies a package across all ecosystems.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct PackageId {
    /// Ecosystem: "npm" | "pypi" | "cargo" | "rubygems" | "maven"
    pub ecosystem: String,
    pub name: String,
    pub version: String,
}

impl PackageId {
    pub fn new(
        ecosystem: impl Into<String>,
        name: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        Self {
            ecosystem: ecosystem.into(),
            name: name.into(),
            version: version.into(),
        }
    }

    /// Canonical string used as a cache key and chain identifier.
    pub fn canonical(&self) -> String {
        format!("{}:{}@{}", self.ecosystem, self.name, self.version)
    }
}

pub fn canonical_publisher_address(publisher_address: &str) -> String {
    let trimmed = publisher_address.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let stripped = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    format!("0x{}", stripped.to_ascii_lowercase())
}

pub fn publish_signature_message(
    id: &PackageId,
    content_hash: &str,
    publisher_address: &str,
) -> String {
    format!(
        "{}{}{}",
        id.canonical(),
        content_hash,
        canonical_publisher_address(publisher_address)
    )
}

impl std::fmt::Display for PackageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.canonical())
    }
}

/// Declared package behaviors submitted alongside the tarball.
/// Validators check *against* this manifest rather than blanket policy —
/// an HTTP client that declares outbound HTTPS calls is legitimate.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PackageManifest {
    /// Allowed outbound hosts, e.g. ["api.example.com"]
    pub allowed_network_hosts: Vec<String>,
    /// Allowed filesystem paths the package may write to.
    pub allowed_fs_writes: Vec<String>,
    /// Whether the package spawns child processes.
    pub spawns_processes: bool,
    /// Fine-grained process spawn allowlist — binary names or full paths.
    /// Only checked when `spawns_processes` is true.  If empty and
    /// `spawns_processes` is true, all spawns are permitted (backwards compat).
    #[serde(default)]
    pub allowed_process_spawns: Vec<String>,
    /// Free-text description for human reviewers.
    pub description: Option<String>,
}

/// Submitted by a publisher to place a package in the pending pool.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PublishRequest {
    pub id: PackageId,
    /// SHA-256 of the tarball bytes.
    pub content_hash: String,
    /// IPFS CID where the tarball is already pinned.
    pub ipfs_cid: String,
    /// Publisher's staked EVM address (0x-prefixed). Bound into the Ed25519
    /// publish signature so runtime admission can enforce on-chain stake.
    #[serde(default)]
    pub publisher_address: String,
    /// Publisher's Ed25519 public key (hex-encoded).
    pub publisher_pubkey: String,
    /// Ed25519 signature over canonical(id) + content_hash + publisher_address.
    pub signature: String,
    pub manifest: PackageManifest,
    pub submitted_at: DateTime<Utc>,
    /// Whether the tarball is encrypted (AES-256-GCM).
    pub shielded: bool,
    /// Ephemeral symmetric key encrypted for the validator set (ECIES bundle).
    pub key_bundle: Option<String>,
    /// Optional detached PGP signature for the tarball.
    pub pgp_signature: Option<String>,
    /// Optional PGP public key for verification.
    pub pgp_public_key: Option<String>,
    /// Multi-sig: minimum signatures required (default 2).
    #[serde(default)]
    pub threshold: usize,
    /// Multi-sig: list of publisher pubkeys (2-of-3 support).
    #[serde(default)]
    pub publisher_pubkeys: Vec<String>,
    /// Multi-sig: signatures corresponding to `publisher_pubkeys`.
    #[serde(default)]
    pub signatures: Vec<String>,
}

/// Shared references to the analysis bundles active when a validator formed a verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnalysisBundleRefs {
    #[serde(default)]
    pub policy_bundle_id: String,
    #[serde(default)]
    pub feature_schema_id: String,
    #[serde(default)]
    pub expert_bundle_id: String,
    #[serde(default)]
    pub embedding_model_id: String,
    #[serde(default)]
    pub index_epoch: String,
    #[serde(default)]
    pub threshold_profile_id: String,
    #[serde(default)]
    pub llm_prompt_profile_id: String,
    /// Pinned OSV snapshot epoch (`osv-off` when consensus OSV is disabled).
    #[serde(default)]
    pub osv_snapshot_epoch: String,
}

fn default_osv_snapshot_epoch() -> String {
    "osv-off".to_string()
}

impl Default for AnalysisBundleRefs {
    fn default() -> Self {
        Self {
            policy_bundle_id: String::new(),
            feature_schema_id: String::new(),
            expert_bundle_id: String::new(),
            embedding_model_id: String::new(),
            index_epoch: String::new(),
            threshold_profile_id: String::new(),
            llm_prompt_profile_id: String::new(),
            osv_snapshot_epoch: default_osv_snapshot_epoch(),
        }
    }
}

impl AnalysisBundleRefs {
    /// Effective OSV epoch for digests and completeness checks.
    pub fn effective_osv_snapshot_epoch(&self) -> String {
        let trimmed = self.osv_snapshot_epoch.trim();
        if trimmed.is_empty() {
            default_osv_snapshot_epoch()
        } else {
            trimmed.to_string()
        }
    }

    /// True when the vote names every deterministic scanner artifact needed
    /// to reproduce its consensus decision.
    pub fn is_consensus_complete(&self) -> bool {
        [
            self.policy_bundle_id.as_str(),
            self.feature_schema_id.as_str(),
            self.expert_bundle_id.as_str(),
            self.embedding_model_id.as_str(),
            self.index_epoch.as_str(),
            self.threshold_profile_id.as_str(),
            self.llm_prompt_profile_id.as_str(),
        ]
        .iter()
        .all(|value| !value.trim().is_empty())
            && !self.effective_osv_snapshot_epoch().trim().is_empty()
    }

    /// Stable, domain-separated digest of the scanner/profile references.
    pub fn scanner_profile_digest(&self, scanner_version: &str) -> String {
        let input = format!(
            "creg-scanner-profile-v1|scanner={}|policy={}|features={}|experts={}|embedding={}|index={}|thresholds={}|llm_prompt={}|osv={}",
            scanner_version.trim(),
            self.policy_bundle_id.trim(),
            self.feature_schema_id.trim(),
            self.expert_bundle_id.trim(),
            self.embedding_model_id.trim(),
            self.index_epoch.trim(),
            self.threshold_profile_id.trim(),
            self.llm_prompt_profile_id.trim(),
            self.effective_osv_snapshot_epoch().trim(),
        );
        crate::sha256_hex(input.as_bytes())
    }
}

pub fn scanner_profile_digest(
    scanner_version: &str,
    analysis_bundles: &AnalysisBundleRefs,
) -> String {
    analysis_bundles.scanner_profile_digest(scanner_version)
}

pub fn is_consensus_grade_vote(
    scanner_version: &str,
    analysis_bundles: &AnalysisBundleRefs,
    evidence_digest: &str,
) -> bool {
    !scanner_version.trim().starts_with("degraded")
        && analysis_bundles.is_consensus_complete()
        && !evidence_digest.trim().is_empty()
}

/// Compact deterministic risk data exposed on finalized records and validator votes.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct DeterministicRiskSummary {
    #[serde(default)]
    pub score: u8,
    #[serde(default)]
    pub deterministic_score: u8,
    #[serde(default)]
    pub advisory_score: u8,
    #[serde(default)]
    pub band: String,
    #[serde(default)]
    pub disposition: String,
    #[serde(default)]
    pub deterministic_findings: usize,
    #[serde(default)]
    pub advisory_findings: usize,
    #[serde(default)]
    pub critical_findings: usize,
    #[serde(default)]
    pub high_findings: usize,
    #[serde(default)]
    pub medium_findings: usize,
    #[serde(default)]
    pub low_findings: usize,
    #[serde(default)]
    pub reasons: Vec<String>,
}

/// A single entry in the on-chain package index.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChainRecord {
    pub id: PackageId,
    pub content_hash: String,
    pub ipfs_cid: String,
    pub publisher_pubkey: String,
    /// Hex block hash of the block that included this record.
    pub block_hash: String,
    pub published_at: DateTime<Utc>,
    /// Signatures from the N-of-M validators that approved this package.
    pub validator_signatures: Vec<ValidatorSignature>,
    pub status: PackageStatus,
    /// Whether this record represents a private (encrypted) package.
    pub shielded: bool,
    /// Encrypted key bundle required for decryption (available to authorized nodes).
    pub key_bundle: Option<String>,
    /// Verified PGP fingerprint (if any).
    pub pgp_fingerprint: Option<String>,
    /// Security validation findings (Sandbox, Static, Diff).
    pub findings: Vec<Finding>,
    /// Versioned policy and feature bundles used while producing this record.
    #[serde(default)]
    pub analysis_bundles: AnalysisBundleRefs,
    /// Digest over deterministic evidence that shaped the final decision.
    #[serde(default)]
    pub evidence_digest: String,
    /// Compact deterministic risk summary captured when the record was finalized.
    #[serde(default)]
    pub deterministic_risk: DeterministicRiskSummary,
    /// Real-time access metrics (Kind Enhancement)
    pub access_count: u32,
    pub last_accessed: Option<DateTime<Utc>>,
    /// Multi-sig: minimum signatures required.
    #[serde(default)]
    pub threshold: usize,
    /// Multi-sig: list of publisher pubkeys.
    #[serde(default)]
    pub publisher_pubkeys: Vec<String>,
    /// Package manifest from the publisher (declared behaviors).
    /// Stored at finalization so that future versions can diff against it.
    #[serde(default)]
    pub manifest: Option<PackageManifest>,
}

/// Current lifecycle state of a package on the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PackageStatus {
    /// Accepted by consensus — safe to install.
    Verified,
    /// Submitted but not yet through consensus — pending pool only.
    #[default]
    Pending,
    /// Rejected by consensus or later found malicious.
    Revoked { reason: String },
}

/// A validator's signature over a package hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSignature {
    pub validator_id: String,
    pub validator_pubkey: String,
    pub signature: String,
    pub vote: ValidatorVote,
    pub signed_at: DateTime<Utc>,
    /// ML model version used for deep scan (e.g., "codebert-v0.1.0" or "degraded-no-model").
    /// Allows consensus to verify validators used compatible model versions.
    #[serde(default)]
    pub ml_model_version: String,
    /// Versioned analysis bundles active when this vote was produced.
    #[serde(default)]
    pub analysis_bundles: AnalysisBundleRefs,
    /// Digest over deterministic evidence considered by the voting validator.
    #[serde(default)]
    pub evidence_digest: String,
    /// Compact deterministic risk summary captured when this vote was formed.
    #[serde(default)]
    pub deterministic_risk: DeterministicRiskSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ValidatorVote {
    #[default]
    Approve,
    Reject {
        reason: String,
    },
}
