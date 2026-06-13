use crate::bundle::AnalysisBundleSet;
use crate::llm::LlmReview;
use crate::reputation::{FinalDecision, ReputationAssessment};
use common::{sha256_hex, DeterministicRiskSummary, Finding, FindingSeverity, PackageId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskBand {
    Low,
    Guarded,
    Elevated,
    High,
    Critical,
}

impl std::fmt::Display for RiskBand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            RiskBand::Low => "low",
            RiskBand::Guarded => "guarded",
            RiskBand::Elevated => "elevated",
            RiskBand::High => "high",
            RiskBand::Critical => "critical",
        };
        f.write_str(label)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskDisposition {
    Accept,
    Review,
    Block,
}

impl std::fmt::Display for RiskDisposition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            RiskDisposition::Accept => "accept",
            RiskDisposition::Review => "review",
            RiskDisposition::Block => "block",
        };
        f.write_str(label)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskSummary {
    pub bundle_set: AnalysisBundleSet,
    pub score: u8,
    pub deterministic_score: u8,
    pub advisory_score: u8,
    pub ensemble_score: u8,
    pub band: RiskBand,
    pub disposition: RiskDisposition,
    pub deterministic_block: bool,
    pub llm_review_recommended: bool,
    pub llm_review_used: bool,
    pub deterministic_findings: usize,
    pub advisory_findings: usize,
    pub critical_findings: usize,
    pub high_findings: usize,
    pub medium_findings: usize,
    pub low_findings: usize,
    pub reputation_delta: i32,
    pub evidence_digest: String,
    pub reasons: Vec<String>,
}

impl RiskSummary {
    pub fn primary_reason(&self) -> String {
        self.reasons.first().cloned().unwrap_or_else(|| {
            format!(
                "Deterministic risk band '{}' (score {})",
                self.band, self.score
            )
        })
    }

    pub fn to_common_summary(&self) -> DeterministicRiskSummary {
        DeterministicRiskSummary {
            score: self.score,
            deterministic_score: self.deterministic_score,
            advisory_score: self.advisory_score,
            band: self.band.to_string(),
            disposition: self.disposition.to_string(),
            deterministic_findings: self.deterministic_findings,
            advisory_findings: self.advisory_findings,
            critical_findings: self.critical_findings,
            high_findings: self.high_findings,
            medium_findings: self.medium_findings,
            low_findings: self.low_findings,
            reasons: self.reasons.clone(),
        }
    }
}

pub struct RiskAggregator {
    block_threshold: u8,
    review_threshold: u8,
    llm_review_threshold: u8,
}

impl Default for RiskAggregator {
    fn default() -> Self {
        Self {
            block_threshold: env_u8("CREG_RISK_BLOCK_THRESHOLD", 85),
            review_threshold: env_u8("CREG_RISK_REVIEW_THRESHOLD", 55),
            llm_review_threshold: env_u8("CREG_RISK_LLM_THRESHOLD", 40),
        }
    }
}

impl RiskAggregator {
    pub fn summarize(
        &self,
        package: &PackageId,
        findings: &[Finding],
        deterministic_score: f64,
        advisory_score: f64,
        ensemble_score: f64,
        llm_review: Option<&LlmReview>,
        bundle_set: &AnalysisBundleSet,
        reputation: &ReputationAssessment,
    ) -> RiskSummary {
        let deterministic: Vec<&Finding> = findings
            .iter()
            .filter(|finding| is_deterministic_finding(finding.id.as_str()))
            .collect();
        let advisory_findings = findings.len().saturating_sub(deterministic.len());
        let allow_testnet_dev_sandbox_bypass = allow_testnet_dev_sandbox_bypass();

        let critical_findings = deterministic
            .iter()
            .filter(|finding| finding.severity == FindingSeverity::Critical)
            .count();
        let high_findings = deterministic
            .iter()
            .filter(|finding| finding.severity == FindingSeverity::High)
            .count();
        let medium_findings = deterministic
            .iter()
            .filter(|finding| finding.severity == FindingSeverity::Medium)
            .count();
        let low_findings = deterministic
            .iter()
            .filter(|finding| finding.severity == FindingSeverity::Low)
            .count();

        let deterministic_score = deterministic_score.round().clamp(0.0, 100.0) as u8;
        let advisory_score = advisory_score.round().clamp(0.0, 100.0) as u8;
        let ensemble_score = ensemble_score.round().clamp(0.0, 100.0) as u8;

        let mut score = i32::from(deterministic_score);
        score += (critical_findings as i32) * 25;
        score += deterministic
            .iter()
            .filter(|finding| {
                finding.severity == FindingSeverity::High
                    && !is_non_blocking_testnet_dev_bypass(
                        finding,
                        allow_testnet_dev_sandbox_bypass,
                    )
            })
            .count() as i32
            * 15;
        score += (medium_findings as i32) * 5;
        score += low_findings as i32;

        if reputation.confidence_delta < 0 {
            score += (-reputation.confidence_delta + 4) / 5;
        } else {
            score -= reputation.confidence_delta / 20;
        }

        let score = score.clamp(0, 100) as u8;
        let deterministic_block = critical_findings > 0 || score >= self.block_threshold;
        let llm_review_used = llm_review.is_some_and(|review| !review.degraded);
        let llm_review_recommended = !llm_review_used
            && deterministic_score.max(advisory_score) >= self.llm_review_threshold;

        let advisory_review = advisory_score >= self.review_threshold;

        let disposition = if deterministic_block {
            RiskDisposition::Block
        } else if score >= self.review_threshold || high_findings > 0 || advisory_review {
            RiskDisposition::Review
        } else {
            RiskDisposition::Accept
        };

        let band = match score {
            0..=19 => RiskBand::Low,
            20..=44 => RiskBand::Guarded,
            45..=69 => RiskBand::Elevated,
            70..=89 => RiskBand::High,
            _ => RiskBand::Critical,
        };

        let reasons = build_reasons(&deterministic, reputation.confidence_delta);

        RiskSummary {
            bundle_set: bundle_set.clone(),
            score,
            deterministic_score,
            advisory_score,
            ensemble_score,
            band,
            disposition,
            deterministic_block,
            llm_review_recommended,
            llm_review_used,
            deterministic_findings: deterministic.len(),
            advisory_findings,
            critical_findings,
            high_findings,
            medium_findings,
            low_findings,
            reputation_delta: reputation.confidence_delta,
            evidence_digest: build_evidence_digest(
                package,
                &deterministic,
                bundle_set,
                reputation.confidence_delta,
                deterministic_score,
            ),
            reasons,
        }
    }

    pub fn decide(&self, summary: &RiskSummary) -> FinalDecision {
        match summary.disposition {
            RiskDisposition::Block => FinalDecision::Reject {
                reason: summary.primary_reason(),
                confidence: summary.score.max(70),
            },
            RiskDisposition::Review => FinalDecision::ApproveWithWarning {
                warning: format!(
                    "Deterministic risk band '{}' (score {}) requires review: {}",
                    summary.band,
                    summary.score,
                    summary.primary_reason()
                ),
                confidence: (90u8).saturating_sub(summary.score / 2).max(20),
            },
            RiskDisposition::Accept => FinalDecision::Approve {
                confidence: (95u8).saturating_sub(summary.score / 2).max(35),
            },
        }
    }
}

fn env_u8(key: &str, default: u8) -> u8 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse::<u8>().ok())
        .unwrap_or(default)
}

fn env_truthy(key: &str) -> bool {
    std::env::var(key)
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn allow_testnet_dev_sandbox_bypass() -> bool {
    env_truthy("CREG_TESTNET") && !env_truthy("CREG_PRODUCTION")
}

fn is_non_blocking_testnet_dev_bypass(
    finding: &Finding,
    allow_testnet_dev_sandbox_bypass: bool,
) -> bool {
    allow_testnet_dev_sandbox_bypass && finding.id == "SB012"
}

fn is_deterministic_finding(id: &str) -> bool {
    if id.starts_with("OSV") {
        return id == "OSV002" && ml_validator::osv_block_critical_enabled();
    }
    !matches!(id, "SA011" | "SA012") && !id.starts_with("LLM")
}

fn build_reasons(findings: &[&Finding], reputation_delta: i32) -> Vec<String> {
    let mut ordered: Vec<&Finding> = findings.to_vec();
    ordered.sort_by_key(|finding| {
        (
            std::cmp::Reverse(severity_rank(finding.severity)),
            finding.id.as_str(),
            finding.file.as_str(),
            finding.line.unwrap_or(0),
        )
    });

    let mut reasons: Vec<String> = ordered
        .into_iter()
        .take(5)
        .map(|finding| format!("[{}] {}", finding.id, finding.title))
        .collect();

    if reputation_delta < 0 {
        reasons.push(format!(
            "Publisher reputation delta {} increases deterministic risk",
            reputation_delta
        ));
    }

    if reasons.is_empty() {
        reasons.push("No deterministic blockers detected".to_string());
    }

    reasons
}

fn severity_rank(severity: FindingSeverity) -> u8 {
    match severity {
        FindingSeverity::Critical => 4,
        FindingSeverity::High => 3,
        FindingSeverity::Medium => 2,
        FindingSeverity::Low => 1,
    }
}

fn build_evidence_digest(
    package: &PackageId,
    findings: &[&Finding],
    bundle_set: &AnalysisBundleSet,
    reputation_delta: i32,
    deterministic_score: u8,
) -> String {
    let mut evidence_items: Vec<String> = findings
        .iter()
        .map(|finding| {
            format!(
                "{}|{:?}|{}|{}|{}",
                finding.id,
                finding.severity,
                finding.file,
                finding.line.unwrap_or(0),
                finding.title
            )
        })
        .collect();
    evidence_items.sort_unstable();

    let digest_input = [
        package.canonical(),
        bundle_set.policy_bundle_id.clone(),
        bundle_set.feature_schema_id.clone(),
        bundle_set.expert_bundle_id.clone(),
        bundle_set.embedding_model_id.clone(),
        bundle_set.index_epoch.clone(),
        bundle_set.threshold_profile_id.clone(),
        bundle_set.osv_snapshot_epoch.clone(),
        reputation_delta.to_string(),
        deterministic_score.to_string(),
        evidence_items.join("||"),
    ]
    .join("::");

    sha256_hex(digest_input.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    static ENV_LOCK: std::sync::LazyLock<std::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(()));

    fn finding(id: &str, severity: FindingSeverity) -> Finding {
        Finding {
            id: id.to_string(),
            title: format!("{} title", id),
            severity,
            description: String::new(),
            file: "file.rs".into(),
            line: None,
        }
    }

    fn reputation(delta: i32) -> ReputationAssessment {
        ReputationAssessment {
            confidence_delta: delta,
            publisher_pubkey: "pubkey".into(),
            notes: Vec::new(),
            revoked_pgp_fps: Vec::new(),
        }
    }

    #[test]
    fn critical_static_finding_blocks() {
        let aggregator = RiskAggregator::default();
        let summary = aggregator.summarize(
            &PackageId::new("npm", "pkg", "1.0.0"),
            &[finding("SA001", FindingSeverity::Critical)],
            75.0,
            0.0,
            25.0,
            None,
            &AnalysisBundleSet::default(),
            &reputation(0),
        );

        assert!(summary.deterministic_block);
        assert_eq!(summary.disposition, RiskDisposition::Block);
    }

    #[test]
    fn llm_only_findings_do_not_create_deterministic_block() {
        let aggregator = RiskAggregator::default();
        let summary = aggregator.summarize(
            &PackageId::new("npm", "pkg", "1.0.0"),
            &[finding("LLM000", FindingSeverity::Critical)],
            0.0,
            90.0,
            10.0,
            None,
            &AnalysisBundleSet::default(),
            &reputation(0),
        );

        assert!(!summary.deterministic_block);
        assert_eq!(summary.deterministic_findings, 0);
        assert_eq!(summary.advisory_findings, 1);
        assert_eq!(summary.disposition, RiskDisposition::Review);
    }

    #[test]
    fn snippet_llm_static_finding_is_treated_as_advisory() {
        let aggregator = RiskAggregator::default();
        let summary = aggregator.summarize(
            &PackageId::new("npm", "pkg", "1.0.0"),
            &[finding("SA011", FindingSeverity::Critical)],
            0.0,
            90.0,
            15.0,
            None,
            &AnalysisBundleSet::default(),
            &reputation(0),
        );

        assert_eq!(summary.deterministic_findings, 0);
        assert_eq!(summary.advisory_findings, 1);
    }

    #[test]
    fn osv_findings_are_advisory_not_deterministic() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("CREG_OSV_BLOCK_CRITICAL");
        std::env::remove_var("CREG_OSV_CONSENSUS");

        let aggregator = RiskAggregator::default();
        let summary = aggregator.summarize(
            &PackageId::new("npm", "pkg", "1.0.0"),
            &[finding("OSV003", FindingSeverity::High)],
            0.0,
            0.0,
            65.0,
            None,
            &AnalysisBundleSet::default(),
            &reputation(0),
        );

        assert!(!summary.deterministic_block);
        assert_eq!(summary.deterministic_findings, 0);
        assert_eq!(summary.advisory_findings, 1);
    }

    #[test]
    fn osv002_blocks_when_block_critical_enabled() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("CREG_OSV_CONSENSUS", "true");
        std::env::set_var("CREG_OSV_BLOCK_CRITICAL", "true");

        let aggregator = RiskAggregator::default();
        let summary = aggregator.summarize(
            &PackageId::new("npm", "pkg", "1.0.0"),
            &[finding("OSV002", FindingSeverity::Critical)],
            0.0,
            90.0,
            15.0,
            None,
            &AnalysisBundleSet::default(),
            &reputation(0),
        );

        assert!(summary.deterministic_block);
        assert_eq!(summary.deterministic_findings, 1);
        assert_eq!(summary.disposition, RiskDisposition::Block);

        std::env::remove_var("CREG_OSV_BLOCK_CRITICAL");
        std::env::remove_var("CREG_OSV_CONSENSUS");
    }

    #[test]
    fn negative_reputation_can_force_review() {
        let aggregator = RiskAggregator::default();
        let summary = aggregator.summarize(
            &PackageId::new("npm", "pkg", "1.0.0"),
            &[finding("SA005", FindingSeverity::Low)],
            54.0,
            0.0,
            54.0,
            None,
            &AnalysisBundleSet::default(),
            &reputation(-40),
        );

        assert_eq!(summary.disposition, RiskDisposition::Review);
    }

    #[test]
    fn testnet_dev_sandbox_bypass_requires_review_not_block() {
        let _env_lock = ENV_LOCK.lock().unwrap();
        let old_testnet = std::env::var("CREG_TESTNET").ok();
        let old_production = std::env::var("CREG_PRODUCTION").ok();

        std::env::set_var("CREG_TESTNET", "true");
        std::env::remove_var("CREG_PRODUCTION");

        let aggregator = RiskAggregator::default();
        let summary = aggregator.summarize(
            &PackageId::new("npm", "pkg", "1.0.0"),
            &[finding("SB012", FindingSeverity::High)],
            75.0,
            0.0,
            75.0,
            None,
            &AnalysisBundleSet::default(),
            &reputation(0),
        );

        match old_testnet {
            Some(value) => std::env::set_var("CREG_TESTNET", value),
            None => std::env::remove_var("CREG_TESTNET"),
        }
        match old_production {
            Some(value) => std::env::set_var("CREG_PRODUCTION", value),
            None => std::env::remove_var("CREG_PRODUCTION"),
        }

        assert!(!summary.deterministic_block);
        assert_eq!(summary.disposition, RiskDisposition::Review);
    }
}
