// crates/common/src/intelligence.rs
// Lane C — post-consensus package intelligence report (non-binding).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const INTELLIGENCE_SCHEMA_V1: &str = "creg.intelligence.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntelligenceStatus {
    Pending,
    Ready,
    Degraded,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConsensusAdvisorySnapshot {
    pub maliciousness_score: u8,
    pub risk_tier: String,
    pub package_summary: String,
    pub model_used: String,
    pub degraded: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IntelligenceSections {
    pub executive_summary: String,
    pub what_it_does: String,
    pub architecture: String,
    pub supply_chain: String,
    pub security_assessment: String,
    #[serde(default)]
    pub residual_risks: Vec<String>,
    #[serde(default)]
    pub recommended_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStep {
    pub step: u32,
    pub tool: String,
    pub summary: String,
    pub duration_ms: u64,
}

/// Full Lane C report persisted by the node intelligence worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageIntelligenceReport {
    pub schema_version: String,
    pub canonical: String,
    pub content_hash: String,
    pub generated_at: DateTime<Utc>,
    pub status: IntelligenceStatus,
    pub lane: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consensus_advisory: Option<ConsensusAdvisorySnapshot>,
    pub sections: IntelligenceSections,
    pub agent_trace: Vec<AgentStep>,
    pub report_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl PackageIntelligenceReport {
    pub fn pending(canonical: impl Into<String>, content_hash: impl Into<String>) -> Self {
        Self {
            schema_version: INTELLIGENCE_SCHEMA_V1.to_string(),
            canonical: canonical.into(),
            content_hash: content_hash.into(),
            generated_at: Utc::now(),
            status: IntelligenceStatus::Pending,
            lane: "C".into(),
            consensus_advisory: None,
            sections: IntelligenceSections::default(),
            agent_trace: Vec::new(),
            report_digest: String::new(),
            error: None,
        }
    }

    pub fn compute_digest(&self) -> String {
        let mut clone = self.clone();
        clone.report_digest = String::new();
        let bytes = serde_json::to_vec(&clone).unwrap_or_default();
        crate::sha256_hex(&bytes)
    }

    pub fn finalize_digest(&mut self) {
        self.report_digest = self.compute_digest();
    }
}

/// API wrapper when no report exists yet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageIntelligenceResponse {
    pub canonical: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    pub status: IntelligenceStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<PackageIntelligenceReport>,
}
