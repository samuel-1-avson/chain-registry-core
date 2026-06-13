use common::{ValidatorSignature, ValidatorVote};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub enum EvidenceVoteOutcome {
    Verified(Vec<ValidatorSignature>),
    Rejected { reason: String },
}

fn consensus_profile_key(sig: &ValidatorSignature) -> Option<String> {
    if !common::is_consensus_grade_vote(
        &sig.ml_model_version,
        &sig.analysis_bundles,
        &sig.evidence_digest,
    ) {
        return None;
    }
    Some(format!(
        "{}:{}",
        common::scanner_profile_digest(&sig.ml_model_version, &sig.analysis_bundles),
        sig.evidence_digest
    ))
}

pub fn aggregate_evidence_votes(
    signatures: &[ValidatorSignature],
    assigned_count: usize,
) -> Option<EvidenceVoteOutcome> {
    let quorum_size = (assigned_count * 2 / 3) + 1;
    let mut seen_indices = HashMap::new();
    let mut unique_votes = Vec::new();

    for sig in signatures {
        let unique_key = if sig.validator_pubkey.is_empty() {
            format!("id:{}", sig.validator_id.to_ascii_lowercase())
        } else {
            format!("pubkey:{}", sig.validator_pubkey.to_ascii_lowercase())
        };
        if let Some(index) = seen_indices.get(&unique_key).copied() {
            unique_votes[index] = sig.clone();
        } else {
            seen_indices.insert(unique_key, unique_votes.len());
            unique_votes.push(sig.clone());
        }
    }

    let mut approvals_by_profile: HashMap<String, Vec<ValidatorSignature>> = HashMap::new();
    let mut rejections = Vec::new();

    for sig in unique_votes {
        let Some(profile_key) = consensus_profile_key(&sig) else {
            continue;
        };

        match &sig.vote {
            ValidatorVote::Approve => {
                let approvals = approvals_by_profile.entry(profile_key).or_default();
                approvals.push(sig.clone());
                if approvals.len() >= quorum_size {
                    return Some(EvidenceVoteOutcome::Verified(approvals.clone()));
                }
            }
            ValidatorVote::Reject { reason } => rejections.push(reason.clone()),
        }
    }

    let max_possible_approvals = assigned_count.saturating_sub(rejections.len());
    if max_possible_approvals < quorum_size {
        return Some(EvidenceVoteOutcome::Rejected {
            reason: rejections
                .into_iter()
                .next()
                .unwrap_or_else(|| "Consensus rejected".to_string()),
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::{aggregate_evidence_votes, EvidenceVoteOutcome};
    use chrono::Utc;
    use common::{ValidatorSignature, ValidatorVote};

    fn sig(id: &str, vote: ValidatorVote, model_version: &str) -> ValidatorSignature {
        let analysis_bundles = common::AnalysisBundleRefs {
            policy_bundle_id: "policy-v1".into(),
            feature_schema_id: "features-v1".into(),
            expert_bundle_id: "experts-v1".into(),
            embedding_model_id: "embeddings-v1".into(),
            index_epoch: "index-epoch-1".into(),
            threshold_profile_id: "thresholds-v1".into(),
            llm_prompt_profile_id: "llm-prompt-v1".into(),
            osv_snapshot_epoch: "osv-off".into(),
        };
        ValidatorSignature {
            validator_id: id.to_string(),
            validator_pubkey: format!("{}-pubkey", id),
            signature: format!("{}-sig", id),
            vote,
            signed_at: Utc::now(),
            ml_model_version: model_version.to_string(),
            analysis_bundles,
            evidence_digest: common::sha256_hex(b"pipeline-test-evidence"),
            deterministic_risk: common::DeterministicRiskSummary::default(),
        }
    }

    #[test]
    fn aggregates_to_verified_from_approval_quorum() {
        let outcome = aggregate_evidence_votes(
            &[
                sig("v1", ValidatorVote::Approve, "creg-detect-v1.0.0"),
                sig("v2", ValidatorVote::Approve, "creg-detect-v1.0.0"),
                sig("v3", ValidatorVote::Approve, "creg-detect-v1.0.0"),
                sig(
                    "v4",
                    ValidatorVote::Reject {
                        reason: "malicious".to_string(),
                    },
                    "creg-detect-v1.0.0",
                ),
            ],
            4,
        );

        match outcome {
            Some(EvidenceVoteOutcome::Verified(sigs)) => assert_eq!(sigs.len(), 3),
            other => panic!("expected verified quorum, got {:?}", other),
        }
    }

    #[test]
    fn aggregates_to_rejected_when_quorum_is_impossible() {
        let outcome = aggregate_evidence_votes(
            &[
                sig(
                    "v1",
                    ValidatorVote::Reject {
                        reason: "malicious".to_string(),
                    },
                    "creg-detect-v1.0.0",
                ),
                sig(
                    "v2",
                    ValidatorVote::Reject {
                        reason: "backdoor".to_string(),
                    },
                    "creg-detect-v1.0.0",
                ),
            ],
            3,
        );

        match outcome {
            Some(EvidenceVoteOutcome::Rejected { reason }) => assert_eq!(reason, "malicious"),
            other => panic!("expected rejection quorum failure, got {:?}", other),
        }
    }

    #[test]
    fn duplicate_votes_do_not_count_twice() {
        let outcome = aggregate_evidence_votes(
            &[
                sig("v1", ValidatorVote::Approve, "creg-detect-v1.0.0"),
                sig("v1", ValidatorVote::Approve, "creg-detect-v1.0.0"),
                sig("v2", ValidatorVote::Approve, "creg-detect-v1.0.0"),
            ],
            3,
        );

        assert!(
            outcome.is_none(),
            "duplicate validator votes must not satisfy quorum"
        );
    }

    #[test]
    fn degraded_votes_are_excluded_from_quorum() {
        let outcome = aggregate_evidence_votes(
            &[
                sig("v1", ValidatorVote::Approve, "degraded-no-model"),
                sig("v2", ValidatorVote::Approve, "creg-detect-v1.0.0"),
                sig("v3", ValidatorVote::Approve, "creg-detect-v1.0.0"),
            ],
            4,
        );

        assert!(
            outcome.is_none(),
            "degraded validator votes must not satisfy quorum"
        );
    }

    #[test]
    fn approvals_must_share_the_same_profile_and_evidence_digest() {
        let mut v1 = sig("v1", ValidatorVote::Approve, "creg-detect-v1.0.0");
        let mut v2 = sig("v2", ValidatorVote::Approve, "creg-detect-v1.0.0");
        let mut v3 = sig("v3", ValidatorVote::Approve, "creg-detect-v1.0.0");
        v1.evidence_digest = common::sha256_hex(b"evidence-a");
        v2.evidence_digest = common::sha256_hex(b"evidence-a");
        v3.evidence_digest = common::sha256_hex(b"evidence-b");

        let outcome = aggregate_evidence_votes(&[v1, v2, v3], 3);

        assert!(
            outcome.is_none(),
            "mixed evidence bundles must not satisfy a single quorum"
        );
    }
}
