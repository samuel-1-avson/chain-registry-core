// crates/validator/src/report.rs

use crate::bundle::AnalysisBundleSet;
use crate::llm::{LlmReview, RiskTier};
use crate::risk::RiskSummary;
use crate::sandbox::SandboxResult;
use crate::static_analysis::{EvidenceGroup, StaticAnalysisResult};
pub use common::{Finding, FindingSeverity, PackageId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditProof {
    /// Cryptographic signature from the authorized AI model (hex).
    pub signature: String,
    /// The public key of the AI auditor that produced this verdict.
    pub auditor_pubkey: String,
    /// The verdict: "cleared" or "confirmed_malicious".
    #[serde(default)]
    pub verdict: String,
    /// Detailed rationales for the verdict.
    pub rationales: Vec<Rationale>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rationale {
    pub finding_id: String,
    pub logic: String,
    pub confidence: u8,
}

pub struct ValidationReport {
    pub package: PackageId,
    pub findings: Vec<Finding>,
    pub aaa_verdict: Option<AuditProof>,
    pub analysis_bundles: AnalysisBundleSet,
    pub static_evidence_groups: Vec<EvidenceGroup>,
    /// Deterministic score (0-100) from non-advisory stages.
    pub deterministic_score: f64,
    /// Advisory score (0-100) from semantic review stages.
    pub advisory_score: f64,
    /// Weighted ensemble score (0–100) from static analysis, ML, deep scan, and LLM.
    pub ensemble_score: f64,
    /// Full output from the LLM-assisted review stage (Stage 4).
    /// `None` when the LLM stage has not yet run.
    pub llm_review: Option<LlmReview>,
    pub deterministic_risk: Option<RiskSummary>,
}

impl ValidationReport {
    pub fn new(package: PackageId) -> Self {
        Self {
            package,
            findings: Vec::new(),
            aaa_verdict: None,
            analysis_bundles: AnalysisBundleSet::current(),
            static_evidence_groups: Vec::new(),
            deterministic_score: 0.0,
            advisory_score: 0.0,
            ensemble_score: 0.0,
            llm_review: None,
            deterministic_risk: None,
        }
    }

    pub fn apply_static(&mut self, result: StaticAnalysisResult) {
        self.static_evidence_groups = result.evidence_groups;
        self.deterministic_score = result.deterministic_score;
        self.advisory_score = result.advisory_score;
        self.ensemble_score = result.ensemble_score;
        self.findings.extend(result.findings);
    }

    pub fn apply_sandbox(&mut self, result: SandboxResult) {
        self.deterministic_score = self
            .deterministic_score
            .max(max_deterministic_finding_score(&result.findings));
        self.ensemble_score = self.ensemble_score.max(self.deterministic_score);
        self.findings.extend(result.findings);
    }

    pub fn apply_diff(&mut self, result: crate::diff::DiffResult) {
        self.deterministic_score = self
            .deterministic_score
            .max(max_deterministic_finding_score(&result.findings));
        self.ensemble_score = self.ensemble_score.max(self.deterministic_score);
        self.findings.extend(result.findings);
    }

    pub fn apply_pgp(&mut self, result: crate::pgp::PgpResult) {
        self.deterministic_score = self
            .deterministic_score
            .max(max_deterministic_finding_score(&result.findings));
        self.ensemble_score = self.ensemble_score.max(self.deterministic_score);
        self.findings.extend(result.findings);
    }

    /// Integrate the LLM review into the report.
    ///
    /// - All LLM-generated findings are added to the main findings list.
    /// - The `ensemble_score` is updated using a weighted blend: existing score
    ///   (60 %) + LLM maliciousness score (40 %). This prevents a single noisy
    ///   LLM call from dominating while still allowing it to tip borderline cases.
    /// - When the LLM review is degraded (not run), no findings are added and
    ///   the ensemble score is unchanged.
    pub fn apply_llm(&mut self, review: LlmReview) {
        if !review.degraded {
            self.advisory_score = self.advisory_score.max(review.maliciousness_score as f64);
            self.ensemble_score = self.deterministic_score * 0.6 + self.advisory_score * 0.4;

            // Emit a summary finding when the LLM flagged the package
            if review.maliciousness_score >= 60
                || review.risk_tier == RiskTier::LikelyMalicious
                || review.risk_tier == RiskTier::ConfirmedMalicious
            {
                let severity = if review.maliciousness_score >= 80 {
                    FindingSeverity::Critical
                } else {
                    FindingSeverity::High
                };
                self.findings.push(Finding {
                    id: "LLM000".into(),
                    title: format!(
                        "LLM Assessment: {} (score {})",
                        review.risk_tier, review.maliciousness_score
                    ),
                    severity,
                    description: format!(
                        "Model '{}' assessed this package as '{}' with a maliciousness score of {}.\n\n\
                         Summary: {}\n\n\
                         Injection patterns detected: {}",
                        review.model_used,
                        review.risk_tier,
                        review.maliciousness_score,
                        review.package_summary,
                        if review.injection_patterns.is_empty() {
                            "none".into()
                        } else {
                            review.injection_patterns.join(", ")
                        }
                    ),
                    file: "llm-review".into(),
                    line: None,
                });
            }

            // Add all per-file findings
            self.findings.extend(review.findings.clone());

            // High-entropy files that were not LLM-analysed get a degraded finding
            for alert in &review.high_entropy_files {
                if !alert.llm_analysed {
                    self.findings.push(Finding {
                        id: "LLM-ENT".into(),
                        title: "High-entropy file not LLM-verified".into(),
                        severity: FindingSeverity::Medium,
                        description: format!(
                            "File '{}' has Shannon entropy {:.2} bits/byte (threshold: 7.0) \
                             and was not submitted for LLM analysis (file limit reached or binary). \
                             Manual inspection recommended.",
                            alert.path,
                            alert.entropy,
                        ),
                        file: alert.path.clone(),
                        line: None,
                    });
                }
            }
        } else {
            // LLM was skipped — emit a single Low finding so consensus can see
            // that Stage 4 did not run. This is informational: other stages may
            // still provide sufficient signal.
            let reason = review.degraded_reason.as_deref().unwrap_or("unknown");
            self.findings.push(Finding {
                id: "LLM-SKIP".into(),
                title: "LLM Stage 4 skipped".into(),
                severity: FindingSeverity::Low,
                description: format!(
                    "The LLM-assisted review stage (Stage 4) was not executed: {}. \
                     Static analysis, sandbox, and ML stages still ran. \
                     Enable CREG_LLM_ENABLED=true and configure a provider key \
                     to activate deep semantic analysis.",
                    reason
                ),
                file: "llm-review".into(),
                line: None,
            });

            // Even in degraded mode, surface entropy alerts as Medium findings
            // so operators know there are suspicious files even without LLM analysis.
            for alert in &review.high_entropy_files {
                self.findings.push(Finding {
                    id: "LLM-ENT".into(),
                    title: "High-entropy file (LLM stage skipped)".into(),
                    severity: FindingSeverity::Medium,
                    description: format!(
                        "File '{}' has Shannon entropy {:.2} bits/byte — possible obfuscated \
                         or encrypted payload. LLM stage was not available to verify intent.",
                        alert.path, alert.entropy,
                    ),
                    file: alert.path.clone(),
                    line: None,
                });
            }
        }

        self.llm_review = Some(review);
    }

    pub fn record_deterministic_risk(&mut self, summary: RiskSummary) {
        self.deterministic_risk = Some(summary);
    }

    /// True if any Critical or High findings were recorded.
    pub fn has_critical_findings(&self) -> bool {
        self.findings.iter().any(|f| {
            matches!(
                f.severity,
                FindingSeverity::Critical | FindingSeverity::High
            )
        })
    }

    /// Concise summary of all critical/high findings for the rejection reason.
    pub fn critical_finding_summary(&self) -> String {
        self.findings
            .iter()
            .filter(|f| {
                matches!(
                    f.severity,
                    FindingSeverity::Critical | FindingSeverity::High
                )
            })
            .map(|f| format!("[{}] {}", f.id, f.description))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

fn max_deterministic_finding_score(findings: &[Finding]) -> f64 {
    findings
        .iter()
        .filter(|finding| {
            !finding.id.starts_with("LLM") && !matches!(finding.id.as_str(), "SA011" | "SA012")
        })
        .map(|finding| match finding.severity {
            FindingSeverity::Critical => 100.0,
            FindingSeverity::High => 75.0,
            FindingSeverity::Medium => 50.0,
            FindingSeverity::Low => 25.0,
        })
        .fold(0.0, f64::max)
}
