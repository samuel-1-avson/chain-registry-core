// crates/node/src/state.rs
// Shared NodeState and associated types.  Factored into its own module so
// that the library target (lib.rs) and binary target (main.rs) can both
// include it, enabling integration tests to construct and inspect the state.

use std::{
    collections::{hash_map::Entry, HashMap},
    sync::Arc,
};

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::RwLock;

use common::ValidatorIdentity;

use crate::{
    chain_store::ChainStore, config::NodeConfig, pending_pool::PendingPool,
    publisher_index::PublisherIndex,
};

pub use consensus::pbft::PbftEngine;

// ─── Validator registration ───────────────────────────────────────────────────

#[derive(Serialize, Clone, Debug, Default)]
pub struct ValidatorRegistrationStatus {
    pub alias: String,
    pub identity: ValidatorIdentity,
    pub registered_with_node: bool,
    pub applied_on_chain: bool,
    pub governance_approved: bool,
    pub admitted_to_consensus: bool,
    pub active: bool,
    pub staking_state: String,
    pub status: String,
    pub stake: u64,
    pub reputation: u32,
    pub last_error: Option<String>,
    pub last_synced_at: Option<String>,
}

pub fn normalized_validator_key(evm_address: &str) -> String {
    evm_address.trim().to_ascii_lowercase()
}

pub fn validator_registration_status_text(registration: &ValidatorRegistrationStatus) -> String {
    if registration.active {
        "active".to_string()
    } else if registration.admitted_to_consensus {
        "admitted-to-consensus".to_string()
    } else if registration.governance_approved {
        "governance-approved".to_string()
    } else if registration.applied_on_chain {
        "applied-on-chain".to_string()
    } else if registration.registered_with_node {
        "identity-registered".to_string()
    } else {
        "unregistered".to_string()
    }
}

// ─── Live status snapshots ─────────────────────────────────────────────────────

#[derive(Serialize, Clone, Default)]
pub struct P2PStatus {
    pub peers: Vec<String>,
    pub protocols: Vec<String>,
}

#[derive(Serialize, Clone, Default)]
pub struct BridgeStatus {
    pub last_finalized_eth_block: u64,
    pub registry_address: String,
    pub bridge_sync_status: String,
    pub current_state_root: String,
    /// L1 transaction hash of the most recent anchor commit (the governance
    /// vote/execute transaction that landed `submitRollupBatch`).
    pub last_anchor_tx_hash: Option<String>,
    /// RFC 3339 timestamp of the most recent anchor commit.
    pub last_anchor_at: Option<String>,
    /// The most recent L1 block reported as *finalized* by the RPC
    /// (`eth_getBlockByNumber("finalized")`), as opposed to
    /// `last_finalized_eth_block` which historically recorded the head.
    pub finalized_l1_block: Option<u64>,
    /// Honesty label for the anchoring trust model. The current Groth16
    /// batch circuit only proves the batch is non-empty — state roots are
    /// computed off-chain and trusted from the bridge operator — so this is
    /// a checkpoint attestation, not a validity proof.
    pub proof_mode: String,
    /// Number of anchor commits persisted in the local anchor journal.
    pub anchor_count: usize,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct ValidatorSetSyncStatus {
    pub enabled: bool,
    pub mode: String,
    pub state: String,
    pub last_finalized_source_block: Option<u64>,
    pub cursor_block: Option<u64>,
    pub cursor_log_index: Option<u32>,
    pub cursor_block_hash: Option<String>,
    pub last_poll_at: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct ReorgEvent {
    pub id: String,
    pub timestamp: String,
    pub depth: u64,
    pub abandoned_blocks: Vec<String>,
    pub new_tip: String,
}

/// Maximum number of reorg events retained in memory (and served by
/// `/v1/reorgs`). Oldest entries are dropped first.
pub const MAX_REORG_EVENTS: usize = 100;

#[derive(Clone, Debug)]
pub struct PackageRound {
    pub subject: String,
    pub first_vote_at: DateTime<Utc>,
    pub last_vote_at: DateTime<Utc>,
    signatures: Vec<common::ValidatorSignature>,
}

impl PackageRound {
    pub fn from_vote(subject: impl Into<String>, vote: common::ValidatorSignature) -> Self {
        let mut round = Self {
            subject: subject.into(),
            first_vote_at: Utc::now(),
            last_vote_at: Utc::now(),
            signatures: vec![vote],
        };
        round.refresh_timestamps();
        round
    }

    pub fn record_vote(&mut self, vote: common::ValidatorSignature) {
        let unique_key = package_round_vote_key(&vote);
        if let Some(existing) = self
            .signatures
            .iter_mut()
            .find(|existing| package_round_vote_key(existing) == unique_key)
        {
            *existing = vote;
        } else {
            self.signatures.push(vote);
        }
        self.refresh_timestamps();
    }

    pub fn signatures(&self) -> &[common::ValidatorSignature] {
        &self.signatures
    }

    pub fn vote_count(&self) -> usize {
        self.signatures.len()
    }

    fn refresh_timestamps(&mut self) {
        let Some(first_vote_at) = self
            .signatures
            .iter()
            .map(|signature| signature.signed_at.clone())
            .min()
        else {
            let now = Utc::now();
            self.first_vote_at = now;
            self.last_vote_at = now;
            return;
        };

        self.first_vote_at = first_vote_at;
        self.last_vote_at = self
            .signatures
            .iter()
            .map(|signature| signature.signed_at.clone())
            .max()
            .unwrap_or_else(Utc::now);
    }
}

fn package_round_vote_key(signature: &common::ValidatorSignature) -> String {
    if signature.validator_pubkey.is_empty() {
        format!("id:{}", signature.validator_id.to_ascii_lowercase())
    } else {
        format!("pubkey:{}", signature.validator_pubkey.to_ascii_lowercase())
    }
}

// ─── NodeState ─────────────────────────────────────────────────────────────────

/// Shared mutable state passed to every subsystem via `Arc<RwLock<_>>`.
pub struct NodeState {
    pub chain: ChainStore,
    pub pending_pool: PendingPool,
    pub publisher_index: PublisherIndex,
    pub validator_set_bootstrap: common::ValidatorSet,
    pub validator_set: common::ValidatorSet,
    /// Live package-consensus rounds keyed by the current consensus subject.
    pub package_rounds: HashMap<String, PackageRound>,
    pub config: NodeConfig,
    // Live metrics for the Explorer UI
    pub p2p_status: P2PStatus,
    pub bridge_status: BridgeStatus,
    /// Cached VRF proofs from other validators: validator_id → (output, proof).
    pub vrf_proofs: HashMap<String, (String, String)>,
    /// Decryption shares received from peers: canonical → Vec<KeyShare>.
    pub decryption_shares: HashMap<String, Vec<threshold_encryption::KeyShare>>,
    /// Validator registrations keyed by canonical EVM address.
    pub validator_registrations: HashMap<String, ValidatorRegistrationStatus>,
    pub validator_set_sync: ValidatorSetSyncStatus,
    /// View-change certificates accumulated from peers.
    /// Outer key: block_hash. Middle key: proposed new_view number.
    /// Inner set: validator IDs that have sent a certificate for this (block, view).
    ///
    /// A view-change is applied once ⌊n/3⌋+1 certificates are received,
    /// preventing a single Byzantine node from forcing a view-change.
    pub view_change_certs: HashMap<String, HashMap<u32, std::collections::HashSet<String>>>,
    pub reorgs: Vec<ReorgEvent>,
    /// The PBFT consensus engine managing block finalization.
    pub pbft_engine: PbftEngine,
}

impl NodeState {
    /// Record a chain reorganization event so it is visible via `/v1/reorgs`
    /// and the explorer Reorgs tab. Newest events are kept at the front.
    pub fn record_reorg(
        &mut self,
        depth: u64,
        abandoned_blocks: Vec<String>,
        new_tip: impl Into<String>,
    ) {
        let new_tip = new_tip.into();
        let event = ReorgEvent {
            id: format!("reorg-{}", uuid::Uuid::new_v4()),
            timestamp: Utc::now().to_rfc3339(),
            depth,
            abandoned_blocks,
            new_tip: new_tip.clone(),
        };
        tracing::warn!(
            depth = depth,
            new_tip = %new_tip,
            "Chain reorganization recorded ({} abandoned blocks)",
            event.abandoned_blocks.len()
        );
        self.reorgs.insert(0, event);
        self.reorgs.truncate(MAX_REORG_EVENTS);
    }

    pub fn record_package_vote(
        &mut self,
        subject: impl Into<String>,
        vote: common::ValidatorSignature,
    ) {
        let subject = subject.into();
        match self.package_rounds.entry(subject.clone()) {
            Entry::Occupied(mut entry) => entry.get_mut().record_vote(vote),
            Entry::Vacant(entry) => {
                entry.insert(PackageRound::from_vote(subject, vote));
            }
        }
    }

    pub fn package_round(&self, subject: &str) -> Option<&PackageRound> {
        self.package_rounds.get(subject)
    }

    pub fn clear_package_round(&mut self, subject: &str) {
        self.package_rounds.remove(subject);
    }
}

pub type SharedState = Arc<RwLock<NodeState>>;

#[cfg(test)]
mod tests {
    use super::PackageRound;
    use chrono::Utc;
    use common::{AnalysisBundleRefs, ValidatorSignature, ValidatorVote};

    fn sig(id: &str, vote: ValidatorVote, model_version: &str) -> ValidatorSignature {
        ValidatorSignature {
            validator_id: id.to_string(),
            validator_pubkey: format!("{}-pubkey", id),
            signature: format!("{}-sig", id),
            vote,
            signed_at: Utc::now(),
            ml_model_version: model_version.to_string(),
            analysis_bundles: AnalysisBundleRefs::default(),
            evidence_digest: String::new(),
            deterministic_risk: common::DeterministicRiskSummary::default(),
        }
    }

    #[test]
    fn package_round_replaces_duplicate_validator_votes() {
        let mut round = PackageRound::from_vote(
            "npm:test@1.0.0",
            sig("validator-1", ValidatorVote::Approve, "creg-detect-v1.0.0"),
        );

        round.record_vote(sig(
            "validator-1",
            ValidatorVote::Reject {
                reason: "malicious".to_string(),
            },
            "creg-detect-v2.0.0",
        ));

        assert_eq!(round.subject, "npm:test@1.0.0");
        assert_eq!(round.vote_count(), 1);
        assert_eq!(round.signatures()[0].ml_model_version, "creg-detect-v2.0.0");
        assert!(matches!(
            round.signatures()[0].vote,
            ValidatorVote::Reject { .. }
        ));
    }
}
