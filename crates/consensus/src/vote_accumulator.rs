// crates/consensus/src/vote_accumulator.rs
// Cross-node PBFT vote accumulator with Ed25519 signature verification.
//
// In the single-node dev path the pipeline validates and immediately writes
// a block. In a real multi-validator network each validator node:
//   1. Runs its own 3-stage validation.
//   2. Broadcasts its PREPARE vote to all peers via gossip.
//   3. Collects incoming votes (including its own).
//   4. Once quorum PREPARE votes are in, broadcasts COMMIT.
//   5. Once quorum COMMIT approvals are in, the round is finalised.
//
// This module manages the per-package vote state that accumulates
// incoming votes from peers. It is owned by the validator pipeline.
//
// **Signature scheme**: Ed25519 over the canonical PBFT vote message
// `"creg-vote-v2|<canonical>|<content_hash>|<approved>|<validator_pubkey>|<scanner_profile_digest>|<evidence_digest>"`.
// This matches the format used by the REST `/v1/consensus/vote` endpoint and
// the libp2p gossip vote broadcaster (see `gossip::canonical_vote_message`
// in the node crate). Prior to ISSUE-009 this module used ECDSA/secp256k1
// over 20-byte Ethereum addresses, which was inconsistent with the rest of
// the codebase — validators' Ed25519 keys are what is actually registered
// with the validator set.

use chrono::{DateTime, Utc};
use common::{ValidatorSignature, ValidatorVote};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Domain-separation tag for the canonical consensus vote message. Must be
/// kept in sync with `node/src/gossip.rs::VOTE_MESSAGE_DOMAIN`.
pub const VOTE_MESSAGE_DOMAIN: &str = "creg-vote-v2";

/// Returns true when a vote carries enough deterministic scanner/evidence
/// metadata to count toward quorum.
fn is_consensus_grade(vote: &IncomingVote) -> bool {
    common::is_consensus_grade_vote(
        vote.ml_model_version.as_deref().unwrap_or_default(),
        &vote.analysis_bundles,
        &vote.evidence_digest,
    )
}

/// Build the canonical message that a validator must sign when casting a PBFT
/// vote. Binds the package canonical, tarball content hash, verdict, and the
/// validator's Ed25519 public key so that:
///   (a) signatures cannot be replayed across package versions,
///   (b) signatures cannot be replayed across approve/reject flips,
///   (c) a signature cannot be relabelled to come from a different validator.
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

/// All votes received for a single package's PBFT round.
#[derive(Debug, Clone)]
pub struct PackageVoteState {
    pub canonical: String,
    pub started_at: DateTime<Utc>,
    pub phase: VotePhase,

    /// validator_id → PREPARE vote
    pub prepare_votes: HashMap<String, IncomingVote>,
    /// validator_id → COMMIT vote
    pub commit_votes: HashMap<String, IncomingVote>,

    /// How many validators were assigned to this package by VRF.
    pub assigned_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VotePhase {
    Collecting,
    PrepareQuorumReached,
    CommitQuorumReached,
    Finalised,
    Failed { reason: String },
    TimedOut,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncomingVote {
    pub validator_id: String,
    /// Hex-encoded 32-byte Ed25519 public key of the voting validator.
    pub validator_pubkey: String,
    /// SHA-256 of the tarball bytes — bound into the signed message to
    /// prevent cross-version / cross-package replay.
    #[serde(default)]
    pub content_hash: String,
    pub approved: bool,
    pub reject_reason: Option<String>,
    /// Hex-encoded 64-byte Ed25519 signature of `canonical_vote_message(...)`.
    pub signature: String,
    pub received_at: DateTime<Utc>,
    /// ML model version used by this validator for deep scan.
    #[serde(default)]
    pub ml_model_version: Option<String>,
    /// Versioned scanner/profile artifacts used by this validator.
    #[serde(default)]
    pub analysis_bundles: common::AnalysisBundleRefs,
    /// Digest over deterministic evidence considered by this validator.
    #[serde(default)]
    pub evidence_digest: String,
}

/// Result of signature verification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureVerification {
    Valid,
    Invalid(String),
    Malformed(String),
}

impl PackageVoteState {
    pub fn new(canonical: &str, assigned_count: usize) -> Self {
        Self {
            canonical: canonical.to_string(),
            started_at: Utc::now(),
            phase: VotePhase::Collecting,
            prepare_votes: HashMap::new(),
            commit_votes: HashMap::new(),
            assigned_count,
        }
    }

    /// Quorum threshold: ⌊2n/3⌋ + 1
    pub fn quorum(&self) -> usize {
        (2 * self.assigned_count / 3) + 1
    }

    /// Verify the Ed25519 signature of a vote against the canonical PBFT
    /// vote message `canonical_vote_message(canonical, content_hash,
    /// approved, validator_pubkey)`.
    ///
    /// The `_block_hash` argument is currently unused — the canonical
    /// consensus subject is the package canonical + content hash, not the
    /// block hash, so signatures can be verified before the finalised block
    /// is even built. Kept in the signature for backward compatibility with
    /// call sites that still pass it through.
    pub fn verify_signature(
        &self,
        vote: &IncomingVote,
        _block_hash: &str,
    ) -> SignatureVerification {
        let sig_bytes = match hex::decode(&vote.signature) {
            Ok(bytes) => bytes,
            Err(e) => {
                return SignatureVerification::Malformed(format!(
                    "Failed to decode signature hex: {}",
                    e
                ));
            }
        };
        let signature = match Signature::try_from(sig_bytes.as_slice()) {
            Ok(sig) => sig,
            Err(e) => {
                return SignatureVerification::Malformed(format!(
                    "Invalid Ed25519 signature format: {}",
                    e
                ));
            }
        };

        let pubkey_hex = vote.validator_pubkey.trim_start_matches("0x");
        let pubkey_bytes = match hex::decode(pubkey_hex) {
            Ok(bytes) => bytes,
            Err(e) => {
                return SignatureVerification::Malformed(format!(
                    "Failed to decode validator pubkey: {}",
                    e
                ));
            }
        };
        if pubkey_bytes.len() != 32 {
            return SignatureVerification::Malformed(format!(
                "Invalid Ed25519 pubkey length: expected 32 bytes, got {}",
                pubkey_bytes.len()
            ));
        }
        let verifying_key = match VerifyingKey::try_from(pubkey_bytes.as_slice()) {
            Ok(k) => k,
            Err(e) => {
                return SignatureVerification::Malformed(format!(
                    "Invalid Ed25519 public key: {}",
                    e
                ));
            }
        };

        let message = canonical_vote_message(
            &self.canonical,
            &vote.content_hash,
            vote.approved,
            &vote.validator_pubkey,
            &common::scanner_profile_digest(
                vote.ml_model_version.as_deref().unwrap_or_default(),
                &vote.analysis_bundles,
            ),
            &vote.evidence_digest,
        );

        if let Err(e) = verifying_key.verify(message.as_bytes(), &signature) {
            return SignatureVerification::Invalid(format!("Ed25519 verification failed: {}", e));
        }

        SignatureVerification::Valid
    }

    /// Record a PREPARE vote from a peer.
    /// Returns true if prepare quorum is now reached.
    ///
    /// # Arguments
    /// * `vote` - The incoming PREPARE vote
    /// * `block_hash` - The hash of the block being voted on (for signature verification)
    /// * `skip_verification` - If true, skips signature verification (for testing only)
    pub fn record_prepare(
        &mut self,
        vote: IncomingVote,
        block_hash: &str,
        skip_verification: bool,
    ) -> Result<bool, String> {
        // Verify signature unless skipping (for testing)
        if !skip_verification {
            match self.verify_signature(&vote, block_hash) {
                SignatureVerification::Valid => {}
                SignatureVerification::Invalid(reason) => {
                    tracing::warn!(
                        "[VoteAccum] Invalid PREPARE signature from {}: {}",
                        vote.validator_id,
                        reason
                    );
                    return Err(format!("Invalid signature: {}", reason));
                }
                SignatureVerification::Malformed(reason) => {
                    tracing::warn!(
                        "[VoteAccum] Malformed PREPARE signature from {}: {}",
                        vote.validator_id,
                        reason
                    );
                    return Err(format!("Malformed signature: {}", reason));
                }
            }
        }

        self.prepare_votes
            .insert(vote.validator_id.clone(), vote.clone());

        // Votes without consensus-grade scanner/evidence metadata are stored
        // for transparency but excluded from quorum calculation.
        let total_votes = self.prepare_votes.len();
        let effective_count = self
            .prepare_votes
            .values()
            .filter(|v| is_consensus_grade(v))
            .count();
        let excluded_count = total_votes - effective_count;

        // Warn when the degraded-validator ratio exceeds the configured threshold.
        // If too many validators lack a trained model, quorum may become unreachable.
        let warn_ratio: f64 = std::env::var("CREG_DEGRADED_VALIDATOR_WARN_RATIO")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0.5);
        if self.assigned_count > 0
            && (excluded_count as f64 / self.assigned_count as f64) > warn_ratio
        {
            tracing::warn!(
                "[VoteAccum] {} CONSENSUS METADATA QUORUM RISK: {}/{} assigned validators sent \
                 votes without consensus-grade scanner/evidence metadata ({:.0}% > {:.0}% warn threshold). Effective quorum requires \
                 {} non-degraded votes but only {} available so far. \
                 Deploy a pinned scanner profile/evidence bundle or lower CREG_DEGRADED_VALIDATOR_WARN_RATIO to suppress.",
                self.canonical,
                excluded_count,
                self.assigned_count,
                100.0 * excluded_count as f64 / self.assigned_count as f64,
                100.0 * warn_ratio,
                self.quorum(),
                effective_count,
            );
        }

        if effective_count >= self.quorum() && self.phase == VotePhase::Collecting {
            self.phase = VotePhase::PrepareQuorumReached;
            tracing::info!(
                "[VoteAccum] {} PREPARE quorum reached ({}/{})",
                self.canonical,
                self.prepare_votes.len(),
                self.assigned_count
            );
            return Ok(true);
        }
        Ok(false)
    }

    /// Record a COMMIT vote from a peer.
    /// Returns the outcome if commit quorum is reached.
    ///
    /// # Arguments
    /// * `vote` - The incoming COMMIT vote
    /// * `block_hash` - The hash of the block being voted on (for signature verification)
    /// * `skip_verification` - If true, skips signature verification (for testing only)
    pub fn record_commit(
        &mut self,
        vote: IncomingVote,
        block_hash: &str,
        skip_verification: bool,
    ) -> Result<Option<CommitOutcome>, String> {
        // Verify signature unless skipping (for testing)
        if !skip_verification {
            match self.verify_signature(&vote, block_hash) {
                SignatureVerification::Valid => {}
                SignatureVerification::Invalid(reason) => {
                    tracing::warn!(
                        "[VoteAccum] Invalid COMMIT signature from {}: {}",
                        vote.validator_id,
                        reason
                    );
                    return Err(format!("Invalid signature: {}", reason));
                }
                SignatureVerification::Malformed(reason) => {
                    tracing::warn!(
                        "[VoteAccum] Malformed COMMIT signature from {}: {}",
                        vote.validator_id,
                        reason
                    );
                    return Err(format!("Malformed signature: {}", reason));
                }
            }
        }

        self.commit_votes
            .insert(vote.validator_id.clone(), vote.clone());

        // Exclude votes without consensus-grade scanner/evidence metadata.
        let non_degraded: Vec<&IncomingVote> = self
            .commit_votes
            .values()
            .filter(|v| is_consensus_grade(v))
            .collect();
        let degraded_commit_count = self.commit_votes.len() - non_degraded.len();
        let warn_ratio: f64 = std::env::var("CREG_DEGRADED_VALIDATOR_WARN_RATIO")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0.5);
        if self.assigned_count > 0
            && (degraded_commit_count as f64 / self.assigned_count as f64) > warn_ratio
        {
            tracing::warn!(
                "[VoteAccum] {} COMMIT DEGRADED QUORUM RISK: {}/{} commit votes from \
                 degraded-model validators. Non-degraded commit votes: {}.",
                self.canonical,
                degraded_commit_count,
                self.assigned_count,
                non_degraded.len(),
            );
        }
        let total_commits = non_degraded.len();
        let approvals = non_degraded.iter().filter(|v| v.approved).count();
        let rejections = non_degraded.iter().filter(|v| !v.approved).count();
        let quorum = self.quorum();

        // Enough approvals → finalise.
        if approvals >= quorum {
            self.phase = VotePhase::Finalised;
            tracing::info!(
                "[VoteAccum] {} FINALISED ({} approvals / {} commits)",
                self.canonical,
                approvals,
                total_commits
            );
            let sigs = self.build_validator_sigs(true);
            return Ok(Some(CommitOutcome::Verified(sigs)));
        }

        // Enough rejections that quorum can never be reached → fail.
        let max_possible_approvals = self.assigned_count - rejections;
        if max_possible_approvals < quorum {
            let primary_reason = self
                .commit_votes
                .values()
                .filter(|v| !v.approved)
                .filter_map(|v| v.reject_reason.as_deref())
                .next()
                .unwrap_or("Consensus rejected")
                .to_string();

            self.phase = VotePhase::Failed {
                reason: primary_reason.clone(),
            };
            tracing::warn!(
                "[VoteAccum] {} FAILED (cannot reach quorum: {} approvals, {} rejections)",
                self.canonical,
                approvals,
                rejections
            );
            return Ok(Some(CommitOutcome::Rejected(primary_reason)));
        }

        // Not decided yet.
        Ok(None)
    }

    fn build_validator_sigs(&self, approvers_only: bool) -> Vec<ValidatorSignature> {
        self.commit_votes
            .values()
            .filter(|v| !approvers_only || v.approved)
            .map(|v| ValidatorSignature {
                validator_id: v.validator_id.clone(),
                validator_pubkey: v.validator_pubkey.clone(),
                signature: v.signature.clone(),
                vote: if v.approved {
                    ValidatorVote::Approve
                } else {
                    ValidatorVote::Reject {
                        reason: v.reject_reason.clone().unwrap_or_default(),
                    }
                },
                signed_at: v.received_at,
                ml_model_version: v.ml_model_version.clone().unwrap_or_default(),
                analysis_bundles: v.analysis_bundles.clone(),
                evidence_digest: v.evidence_digest.clone(),
                deterministic_risk: common::DeterministicRiskSummary::default(),
            })
            .collect()
    }

    /// True if this round has been waiting too long and should be abandoned.
    pub fn is_timed_out(&self) -> bool {
        let elapsed = Utc::now() - self.started_at;
        elapsed.num_seconds() > 120 // 2-minute timeout per round
    }
}

#[derive(Debug, Clone)]
pub enum CommitOutcome {
    Verified(Vec<ValidatorSignature>),
    Rejected(String),
}

/// Manages vote state for all currently active PBFT rounds.
pub struct VoteAccumulator {
    /// canonical → vote state
    rounds: HashMap<String, PackageVoteState>,
}

impl VoteAccumulator {
    pub fn new() -> Self {
        Self {
            rounds: HashMap::new(),
        }
    }

    /// Open a new PBFT round for a package.
    pub fn open_round(&mut self, canonical: &str, assigned_count: usize) {
        tracing::info!(
            "[VoteAccum] Opening round for {} ({} validators assigned)",
            canonical,
            assigned_count
        );
        self.rounds.insert(
            canonical.to_string(),
            PackageVoteState::new(canonical, assigned_count),
        );
    }

    /// Record an incoming vote (from a peer or from this node itself).
    /// Returns Some(outcome) if the round is decided.
    ///
    /// # Arguments
    /// * `canonical` - Package canonical ID
    /// * `phase` - "prepare" or "commit"
    /// * `validator_id` - Validator node ID
    /// * `validator_pubkey` - Validator's hex-encoded Ed25519 public key (32 bytes)
    /// * `content_hash` - SHA-256 of the tarball bytes (bound into the signature)
    /// * `approved` - Whether validator approves the package
    /// * `reject_reason` - Reason for rejection (if rejected)
    /// * `signature` - Hex-encoded Ed25519 signature over `canonical_vote_message(...)`
    /// * `block_hash` - Hash of block being voted on (plumbed through for auditing)
    /// * `skip_verification` - Skip signature verification (testing only)
    #[allow(clippy::too_many_arguments)]
    pub fn record_vote(
        &mut self,
        canonical: &str,
        phase: &str,
        validator_id: &str,
        validator_pubkey: &str,
        content_hash: &str,
        approved: bool,
        reject_reason: Option<String>,
        signature: String,
        ml_model_version: Option<String>,
        analysis_bundles: common::AnalysisBundleRefs,
        evidence_digest: String,
        block_hash: &str,
        skip_verification: bool,
    ) -> Result<Option<CommitOutcome>, String> {
        let vote = IncomingVote {
            validator_id: validator_id.to_string(),
            validator_pubkey: validator_pubkey.to_string(),
            content_hash: content_hash.to_string(),
            approved,
            reject_reason,
            signature,
            received_at: Utc::now(),
            ml_model_version,
            analysis_bundles,
            evidence_digest,
        };

        let state = self
            .rounds
            .get_mut(canonical)
            .ok_or_else(|| format!("No active round for {}", canonical))?;

        match phase {
            "prepare" => state
                .record_prepare(vote, block_hash, skip_verification)
                .map(|quorum| if quorum { None } else { None }),
            "commit" => state.record_commit(vote, block_hash, skip_verification),
            _ => {
                tracing::warn!("Unknown vote phase: {}", phase);
                Err(format!("Unknown vote phase: {}", phase))
            }
        }
    }

    /// Expire rounds that have been open too long.
    /// Returns a list of timed-out canonicals so the pipeline can fail them.
    pub fn expire_timed_out(&mut self) -> Vec<String> {
        let timed_out: Vec<_> = self
            .rounds
            .iter()
            .filter(|(_, s)| {
                s.is_timed_out()
                    && matches!(
                        s.phase,
                        VotePhase::Collecting | VotePhase::PrepareQuorumReached
                    )
            })
            .map(|(k, _)| k.clone())
            .collect();

        for canonical in &timed_out {
            if let Some(s) = self.rounds.get_mut(canonical.as_str()) {
                s.phase = VotePhase::TimedOut;
                tracing::warn!("[VoteAccum] {} timed out after 2 minutes", canonical);
            }
        }

        timed_out
    }

    pub fn remove(&mut self, canonical: &str) {
        self.rounds.remove(canonical);
    }

    pub fn active_count(&self) -> usize {
        self.rounds.len()
    }

    /// Get the vote state for a specific package (for testing/inspection).
    pub fn get_state(&self, canonical: &str) -> Option<&PackageVoteState> {
        self.rounds.get(canonical)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::RngCore;

    fn fresh_keypair() -> (SigningKey, String) {
        let mut rng = rand::rngs::OsRng;
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let sk = SigningKey::from_bytes(&seed);
        let pub_hex = hex::encode(sk.verifying_key().as_bytes());
        (sk, pub_hex)
    }

    fn test_analysis_bundles() -> common::AnalysisBundleRefs {
        common::AnalysisBundleRefs {
            policy_bundle_id: "policy-v1".into(),
            feature_schema_id: "features-v1".into(),
            expert_bundle_id: "experts-v1".into(),
            embedding_model_id: "embeddings-v1".into(),
            index_epoch: "index-epoch-1".into(),
            threshold_profile_id: "thresholds-v1".into(),
            llm_prompt_profile_id: "llm-prompt-v1".into(),
            osv_snapshot_epoch: "osv-off".into(),
        }
    }

    fn test_evidence_digest(canonical: &str, content_hash: &str) -> String {
        common::sha256_hex(format!("{canonical}:{content_hash}:consensus-test").as_bytes())
    }

    fn sign_vote(
        sk: &SigningKey,
        pub_hex: &str,
        canonical: &str,
        content_hash: &str,
        approved: bool,
    ) -> String {
        let analysis_bundles = test_analysis_bundles();
        let model_version = "creg-detect-v1.0.0";
        let evidence_digest = test_evidence_digest(canonical, content_hash);
        let msg = canonical_vote_message(
            canonical,
            content_hash,
            approved,
            pub_hex,
            &common::scanner_profile_digest(model_version, &analysis_bundles),
            &evidence_digest,
        );
        hex::encode(sk.sign(msg.as_bytes()).to_bytes())
    }

    /// Build a plaintext (unsigned) vote with a fake signature — useful when
    /// the test calls `record_prepare/record_commit` with `skip_verification = true`.
    fn unsigned_vote(validator_id: &str, validator_pubkey: &str, approved: bool) -> IncomingVote {
        let content_hash = "00".repeat(32);
        IncomingVote {
            validator_id: validator_id.to_string(),
            validator_pubkey: validator_pubkey.to_string(),
            content_hash: content_hash.clone(),
            approved,
            reject_reason: if approved {
                None
            } else {
                Some("bad code".into())
            },
            signature: "00".repeat(64),
            received_at: Utc::now(),
            ml_model_version: Some("creg-detect-v1.0.0".into()),
            analysis_bundles: test_analysis_bundles(),
            evidence_digest: test_evidence_digest("npm:test@1.0.0", &content_hash),
        }
    }

    #[test]
    fn quorum_calculation() {
        // n=7 → quorum = ⌊14/3⌋+1 = 5
        let state = PackageVoteState::new("npm:test@1.0.0", 7);
        assert_eq!(state.quorum(), 5);
    }

    #[test]
    fn finalises_with_quorum_approvals() {
        let mut state = PackageVoteState::new("npm:test@1.0.0", 4);
        // quorum = 3
        let block_hash = "0x1234abcd";

        for id in &["v1", "v2", "v3"] {
            let pub_hex = format!("{:0>64}", id);
            state
                .record_prepare(unsigned_vote(id, &pub_hex, true), block_hash, true)
                .unwrap();
        }
        assert!(matches!(state.phase, VotePhase::PrepareQuorumReached));

        for id in &["v1", "v2"] {
            let pub_hex = format!("{:0>64}", id);
            state
                .record_commit(unsigned_vote(id, &pub_hex, true), block_hash, true)
                .unwrap();
        }
        let outcome = state
            .record_commit(
                unsigned_vote("v3", &format!("{:0>64}", "v3"), true),
                block_hash,
                true,
            )
            .unwrap();

        assert!(matches!(outcome, Some(CommitOutcome::Verified(_))));
        assert!(matches!(state.phase, VotePhase::Finalised));
    }

    #[test]
    fn fails_when_rejections_make_quorum_impossible() {
        let mut state = PackageVoteState::new("npm:bad@1.0.0", 4);
        let block_hash = "0x1234abcd";

        for id in &["v1", "v2", "v3"] {
            let pub_hex = format!("{:0>64}", id);
            state
                .record_prepare(unsigned_vote(id, &pub_hex, false), block_hash, true)
                .unwrap();
        }

        for id in &["v1", "v2"] {
            let pub_hex = format!("{:0>64}", id);
            state
                .record_commit(unsigned_vote(id, &pub_hex, false), block_hash, true)
                .unwrap();
        }
        let outcome = state
            .record_commit(
                unsigned_vote("v3", &format!("{:0>64}", "v3"), false),
                block_hash,
                true,
            )
            .unwrap();

        assert!(matches!(outcome, Some(CommitOutcome::Rejected(_))));
    }

    #[test]
    fn accumulator_tracks_multiple_rounds() {
        let mut acc = VoteAccumulator::new();
        acc.open_round("npm:a@1.0.0", 3);
        acc.open_round("npm:b@1.0.0", 3);
        assert_eq!(acc.active_count(), 2);
        acc.remove("npm:a@1.0.0");
        assert_eq!(acc.active_count(), 1);
    }

    #[test]
    fn rejects_invalid_signature_format() {
        let state = PackageVoteState::new("npm:test@1.0.0", 4);
        let (_, pub_hex) = fresh_keypair();

        let bad_vote = IncomingVote {
            validator_id: "v1".to_string(),
            validator_pubkey: pub_hex,
            content_hash: "abcd".into(),
            approved: true,
            reject_reason: None,
            signature: "not_valid_hex!!!".into(),
            received_at: Utc::now(),
            ml_model_version: None,
            analysis_bundles: test_analysis_bundles(),
            evidence_digest: test_evidence_digest("npm:test@1.0.0", "abcd"),
        };

        let result = state.verify_signature(&bad_vote, "0x1234");
        assert!(matches!(result, SignatureVerification::Malformed(_)));
    }

    #[test]
    fn ed25519_signature_roundtrip() {
        // A valid Ed25519 signature over the canonical vote message must pass.
        let canonical = "npm:widget@1.2.3";
        let content_hash = "deadbeef".repeat(8);
        let state = PackageVoteState::new(canonical, 4);
        let (sk, pub_hex) = fresh_keypair();

        let vote = IncomingVote {
            validator_id: "v1".into(),
            validator_pubkey: pub_hex.clone(),
            content_hash: content_hash.clone(),
            approved: true,
            reject_reason: None,
            signature: sign_vote(&sk, &pub_hex, canonical, &content_hash, true),
            received_at: Utc::now(),
            ml_model_version: Some("creg-detect-v1.0.0".into()),
            analysis_bundles: test_analysis_bundles(),
            evidence_digest: test_evidence_digest(canonical, &content_hash),
        };

        assert_eq!(
            state.verify_signature(&vote, "unused"),
            SignatureVerification::Valid
        );
    }

    #[test]
    fn ed25519_wrong_content_hash_fails() {
        // Flipping the content hash after signing must invalidate the signature.
        let canonical = "npm:widget@1.2.3";
        let signed_hash = "aa".repeat(32);
        let actual_hash = "bb".repeat(32);
        let state = PackageVoteState::new(canonical, 4);
        let (sk, pub_hex) = fresh_keypair();

        let mut vote = IncomingVote {
            validator_id: "v1".into(),
            validator_pubkey: pub_hex.clone(),
            content_hash: signed_hash.clone(),
            approved: true,
            reject_reason: None,
            signature: sign_vote(&sk, &pub_hex, canonical, &signed_hash, true),
            received_at: Utc::now(),
            ml_model_version: Some("creg-detect-v1.0.0".into()),
            analysis_bundles: test_analysis_bundles(),
            evidence_digest: test_evidence_digest(canonical, &signed_hash),
        };
        vote.content_hash = actual_hash;

        assert!(matches!(
            state.verify_signature(&vote, "unused"),
            SignatureVerification::Invalid(_)
        ));
    }

    #[test]
    fn ed25519_pubkey_substitution_fails() {
        // A signature signed by validator A cannot be relabelled to come from
        // validator B. The pubkey is bound into the signed message.
        let canonical = "npm:widget@1.2.3";
        let content_hash = "cd".repeat(32);
        let state = PackageVoteState::new(canonical, 4);
        let (sk_a, pub_a) = fresh_keypair();
        let (_, pub_b) = fresh_keypair();

        let mut vote = IncomingVote {
            validator_id: "v1".into(),
            validator_pubkey: pub_a.clone(),
            content_hash: content_hash.clone(),
            approved: true,
            reject_reason: None,
            signature: sign_vote(&sk_a, &pub_a, canonical, &content_hash, true),
            received_at: Utc::now(),
            ml_model_version: Some("creg-detect-v1.0.0".into()),
            analysis_bundles: test_analysis_bundles(),
            evidence_digest: test_evidence_digest(canonical, &content_hash),
        };
        // Attacker swaps the pubkey to B while keeping A's signature.
        vote.validator_pubkey = pub_b;

        assert!(matches!(
            state.verify_signature(&vote, "unused"),
            SignatureVerification::Invalid(_)
        ));
    }

    #[test]
    fn ed25519_wrong_length_pubkey_malformed() {
        let state = PackageVoteState::new("npm:test@1.0.0", 4);
        let bad_vote = IncomingVote {
            validator_id: "v1".into(),
            validator_pubkey: "abcd".into(), // 2 bytes, not 32
            content_hash: "00".repeat(32),
            approved: true,
            reject_reason: None,
            signature: "00".repeat(64),
            received_at: Utc::now(),
            ml_model_version: None,
            analysis_bundles: test_analysis_bundles(),
            evidence_digest: test_evidence_digest("npm:test@1.0.0", &"00".repeat(32)),
        };

        let result = state.verify_signature(&bad_vote, "unused");
        assert!(matches!(result, SignatureVerification::Malformed(_)));
    }

    #[test]
    fn degraded_votes_are_excluded_from_prepare_and_commit_quorum() {
        let mut state = PackageVoteState::new("npm:test@1.0.0", 4);
        let block_hash = "0x1234abcd";

        let mut vote = unsigned_vote("v1", &format!("{:0>64}", "v1"), true);
        vote.ml_model_version = Some("creg-detect-v1.0.0".into());
        assert!(!state.record_prepare(vote, block_hash, true).unwrap());

        let mut vote = unsigned_vote("v2", &format!("{:0>64}", "v2"), true);
        vote.ml_model_version = Some("creg-detect-v1.0.0".into());
        assert!(!state.record_prepare(vote, block_hash, true).unwrap());

        let mut vote = unsigned_vote("v3", &format!("{:0>64}", "v3"), true);
        vote.ml_model_version = Some("degraded-no-model".into());
        assert!(
            !state.record_prepare(vote, block_hash, true).unwrap(),
            "degraded prepare votes must not satisfy quorum"
        );
        assert!(matches!(state.phase, VotePhase::Collecting));

        let mut vote = unsigned_vote("v4", &format!("{:0>64}", "v4"), true);
        vote.ml_model_version = Some("creg-detect-v1.0.0".into());
        assert!(state.record_prepare(vote, block_hash, true).unwrap());
        assert!(matches!(state.phase, VotePhase::PrepareQuorumReached));

        let mut vote = unsigned_vote("v1", &format!("{:0>64}", "v1"), true);
        vote.ml_model_version = Some("creg-detect-v1.0.0".into());
        assert!(state
            .record_commit(vote, block_hash, true)
            .unwrap()
            .is_none());

        let mut vote = unsigned_vote("v2", &format!("{:0>64}", "v2"), true);
        vote.ml_model_version = Some("creg-detect-v1.0.0".into());
        assert!(state
            .record_commit(vote, block_hash, true)
            .unwrap()
            .is_none());

        let mut vote = unsigned_vote("v3", &format!("{:0>64}", "v3"), true);
        vote.ml_model_version = Some("degraded-no-model".into());
        assert!(
            state
                .record_commit(vote, block_hash, true)
                .unwrap()
                .is_none(),
            "degraded commit votes must not satisfy quorum"
        );

        let mut vote = unsigned_vote("v4", &format!("{:0>64}", "v4"), true);
        vote.ml_model_version = Some("creg-detect-v1.0.0".into());
        let outcome = state.record_commit(vote, block_hash, true).unwrap();

        assert!(matches!(outcome, Some(CommitOutcome::Verified(_))));
        assert!(matches!(state.phase, VotePhase::Finalised));
    }
}
