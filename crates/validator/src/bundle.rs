use serde::{Deserialize, Serialize};

/// Versioned analysis artifacts that shaped a validator's local decision.
///
/// These IDs are intentionally lightweight for the first implementation pass:
/// they let the validator record which policy, feature, model, index, and
/// prompt profiles were active without yet introducing a full signed-bundle
/// distribution protocol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnalysisBundleSet {
    pub policy_bundle_id: String,
    pub feature_schema_id: String,
    pub expert_bundle_id: String,
    pub embedding_model_id: String,
    pub index_epoch: String,
    pub threshold_profile_id: String,
    pub llm_prompt_profile_id: String,
    pub osv_snapshot_epoch: String,
}

impl AnalysisBundleSet {
    pub fn current() -> Self {
        Self {
            policy_bundle_id: env_or("CREG_POLICY_BUNDLE_ID", "policy-v1"),
            feature_schema_id: env_or("CREG_FEATURE_SCHEMA_ID", "features-v1"),
            expert_bundle_id: env_or("CREG_EXPERT_BUNDLE_ID", "experts-v1"),
            embedding_model_id: env_or("CREG_EMBEDDING_MODEL_ID", "embeddings-v1"),
            index_epoch: env_or("CREG_INDEX_EPOCH", "index-epoch-0"),
            threshold_profile_id: env_or("CREG_THRESHOLD_PROFILE_ID", "thresholds-v1"),
            llm_prompt_profile_id: env_or("CREG_LLM_PROMPT_PROFILE_ID", "llm-prompt-v1"),
            osv_snapshot_epoch: ml_validator::osv_bundle_epoch(),
        }
    }

    pub fn to_refs(&self) -> common::AnalysisBundleRefs {
        common::AnalysisBundleRefs {
            policy_bundle_id: self.policy_bundle_id.clone(),
            feature_schema_id: self.feature_schema_id.clone(),
            expert_bundle_id: self.expert_bundle_id.clone(),
            embedding_model_id: self.embedding_model_id.clone(),
            index_epoch: self.index_epoch.clone(),
            threshold_profile_id: self.threshold_profile_id.clone(),
            llm_prompt_profile_id: self.llm_prompt_profile_id.clone(),
            osv_snapshot_epoch: self.osv_snapshot_epoch.clone(),
        }
    }
}

impl Default for AnalysisBundleSet {
    fn default() -> Self {
        Self::current()
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_stable_and_non_empty() {
        let bundles = AnalysisBundleSet::default();

        assert!(!bundles.policy_bundle_id.is_empty());
        assert!(!bundles.feature_schema_id.is_empty());
        assert!(!bundles.expert_bundle_id.is_empty());
        assert!(!bundles.embedding_model_id.is_empty());
        assert!(!bundles.index_epoch.is_empty());
        assert!(!bundles.threshold_profile_id.is_empty());
        assert!(!bundles.llm_prompt_profile_id.is_empty());
        assert!(!bundles.osv_snapshot_epoch.is_empty());
    }
}
