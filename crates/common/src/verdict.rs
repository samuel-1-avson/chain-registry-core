// crates/common/src/verdict.rs

use crate::PackageId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The trust decision the CLI uses to allow, warn, or block an install.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustVerdict {
    pub package: PackageId,
    pub status: VerdictStatus,
    /// ISO-8601 timestamp when the verdict was determined.
    pub resolved_at: DateTime<Utc>,
    /// Whether this verdict came from the local cache or a live chain query.
    pub source: VerdictSource,
    /// MAL-004/LLM-002: risk band, deterministic vs advisory (LLM) finding
    /// split from the finalized record. None for gRPC fast path, legacy
    /// cache entries, and nodes that predate the field.
    #[serde(default)]
    pub deterministic_risk: Option<crate::DeterministicRiskSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerdictStatus {
    /// Chain has a valid consensus record — install proceeds silently.
    Verified {
        block_hash: String,
        content_hash: String,
        /// IPFS CID of the verified tarball — used for P2P download.
        ipfs_cid: String,
        findings: Vec<crate::Finding>,
    },
    /// Package exists but is not yet through consensus — warn the user.
    Unverified,
    /// Package was explicitly revoked — hard block.
    Revoked {
        reason: String,
        findings: Vec<crate::Finding>,
    },
    /// Package is entirely unknown to the chain.
    Unknown,
}

impl VerdictStatus {
    pub fn is_safe(&self) -> bool {
        matches!(self, VerdictStatus::Verified { .. })
    }

    pub fn is_blocked(&self) -> bool {
        matches!(self, VerdictStatus::Revoked { .. })
    }

    /// Human-readable label for terminal output.
    pub fn label(&self) -> &'static str {
        match self {
            VerdictStatus::Verified { .. } => "VERIFIED",
            VerdictStatus::Unverified => "UNVERIFIED",
            VerdictStatus::Revoked { .. } => "REVOKED",
            VerdictStatus::Unknown => "UNKNOWN",
        }
    }

    /// ANSI colour code for the label (used in the CLI terminal output).
    pub fn ansi_color(&self) -> &'static str {
        match self {
            VerdictStatus::Verified { .. } => "\x1b[32m", // green
            VerdictStatus::Unverified => "\x1b[33m",      // yellow
            VerdictStatus::Revoked { .. } => "\x1b[31m",  // red
            VerdictStatus::Unknown => "\x1b[33m",         // yellow
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerdictSource {
    /// Read from the local TTL cache — fast path.
    Cache { expires_at: DateTime<Utc> },
    /// Fetched live from a chain node.
    Chain { node_url: String },
}
