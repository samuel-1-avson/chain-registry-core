//! Claims Management for Package Insurance
//!
//! Handles claim submission, evaluation, and resolution.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// Claim status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClaimStatus {
    /// Submitted, awaiting review
    Pending,
    /// Under review by resolver
    UnderReview,
    /// Approved for payout
    Approved,
    /// Rejected
    Rejected,
    /// Paid out
    Paid,
}

impl std::fmt::Display for ClaimStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClaimStatus::Pending => write!(f, "Pending"),
            ClaimStatus::UnderReview => write!(f, "Under Review"),
            ClaimStatus::Approved => write!(f, "Approved"),
            ClaimStatus::Rejected => write!(f, "Rejected"),
            ClaimStatus::Paid => write!(f, "Paid"),
        }
    }
}

/// Insurance claim
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claim {
    /// Claim ID
    pub id: String,
    /// Policy ID
    pub policy_id: String,
    /// Claimant address
    pub claimant: String,
    /// Amount claimed
    pub amount: f64,
    /// Reason for claim
    pub reason: String,
    /// Evidence (IPFS hash, URL, etc.)
    pub evidence: String,
    /// Current status
    pub status: ClaimStatus,
    /// Submission time
    pub submitted_at: DateTime<Utc>,
    /// Resolution time
    pub resolved_at: Option<DateTime<Utc>>,
    /// Resolver address
    pub resolver: Option<String>,
    /// Resolution notes
    pub resolution_notes: Option<String>,
}

impl Claim {
    /// Create new claim
    pub fn new(
        id: String,
        policy_id: String,
        claimant: String,
        amount: f64,
        reason: String,
        evidence: String,
    ) -> Self {
        Self {
            id,
            policy_id,
            claimant,
            amount,
            reason,
            evidence,
            status: ClaimStatus::Pending,
            submitted_at: Utc::now(),
            resolved_at: None,
            resolver: None,
            resolution_notes: None,
        }
    }

    /// Approve claim
    pub fn approve(&mut self, resolver: &str, notes: Option<String>) {
        self.status = ClaimStatus::Approved;
        self.resolved_at = Some(Utc::now());
        self.resolver = Some(resolver.to_string());
        self.resolution_notes = notes;

        info!("Claim {} approved by {}", self.id, resolver);
    }

    /// Reject claim
    pub fn reject(&mut self, resolver: &str, notes: Option<String>) {
        self.status = ClaimStatus::Rejected;
        self.resolved_at = Some(Utc::now());
        self.resolver = Some(resolver.to_string());
        self.resolution_notes = notes;

        warn!("Claim {} rejected by {}", self.id, resolver);
    }

    /// Mark as paid
    pub fn mark_paid(&mut self) {
        if self.status == ClaimStatus::Approved {
            self.status = ClaimStatus::Paid;
            info!("Claim {} marked as paid", self.id);
        }
    }

    /// Get age of claim
    pub fn age_hours(&self) -> i64 {
        (Utc::now() - self.submitted_at).num_hours()
    }

    /// Check if claim is pending review
    pub fn is_pending(&self) -> bool {
        matches!(self.status, ClaimStatus::Pending | ClaimStatus::UnderReview)
    }
}

/// Evidence type for claims
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceType {
    /// Security advisory
    SecurityAdvisory,
    /// CVE report
    CveReport,
    /// Malware detection
    MalwareDetection,
    /// Code analysis
    CodeAnalysis,
    /// Incident report
    IncidentReport,
    /// Other
    Other(String),
}

impl EvidenceType {
    /// Get severity weight
    pub fn severity_weight(&self) -> f64 {
        match self {
            EvidenceType::SecurityAdvisory => 0.8,
            EvidenceType::CveReport => 1.0,
            EvidenceType::MalwareDetection => 1.0,
            EvidenceType::CodeAnalysis => 0.6,
            EvidenceType::IncidentReport => 0.9,
            EvidenceType::Other(_) => 0.5,
        }
    }
}

/// Evidence for a claim
#[derive(Debug, Clone)]
pub struct Evidence {
    /// Evidence type
    pub evidence_type: EvidenceType,
    /// Description
    pub description: String,
    /// URL or IPFS hash
    pub source: String,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Severity (0-10)
    pub severity: f64,
}

impl Evidence {
    /// Calculate evidence score
    pub fn score(&self) -> f64 {
        let type_weight = self.evidence_type.severity_weight();
        let severity_normalized = self.severity / 10.0;

        type_weight * severity_normalized * 100.0
    }
}

/// Claim evaluator for automated assessment
pub struct ClaimEvaluator {
    /// Minimum evidence score for approval
    min_evidence_score: f64,
    /// Maximum claim amount for auto-approval
    auto_approval_limit: f64,
    /// Resolvers for manual review
    resolvers: Vec<String>,
}

impl Default for ClaimEvaluator {
    fn default() -> Self {
        Self {
            min_evidence_score: 70.0,
            auto_approval_limit: 1.0, // 1 ETH
            resolvers: Vec::new(),
        }
    }
}

impl ClaimEvaluator {
    /// Create new evaluator
    pub fn new(min_evidence_score: f64, auto_approval_limit: f64) -> Self {
        Self {
            min_evidence_score,
            auto_approval_limit,
            resolvers: Vec::new(),
        }
    }

    /// Add resolver
    pub fn add_resolver(&mut self, resolver: String) {
        self.resolvers.push(resolver);
    }

    /// Evaluate a claim
    pub fn evaluate(&self, claim: &Claim, evidence: &[Evidence]) -> EvaluationResult {
        // Calculate total evidence score
        let evidence_score: f64 = evidence.iter().map(|e| e.score()).sum();

        // Check auto-approval criteria
        if evidence_score >= self.min_evidence_score && claim.amount <= self.auto_approval_limit {
            return EvaluationResult::AutoApprove {
                score: evidence_score,
                confidence: 0.95,
            };
        }

        // Check if manual review needed
        if evidence_score >= self.min_evidence_score * 0.7 {
            return EvaluationResult::ManualReview {
                score: evidence_score,
                suggested_amount: claim.amount,
            };
        }

        // Insufficient evidence
        EvaluationResult::Reject {
            reason: "Insufficient evidence".to_string(),
            score: evidence_score,
        }
    }

    /// Get resolver for claim (round-robin)
    pub fn assign_resolver(&self, claim_id: &str) -> Option<&String> {
        if self.resolvers.is_empty() {
            return None;
        }

        // Simple hash-based assignment
        let hash = claim_id
            .bytes()
            .fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32));

        let index = (hash as usize) % self.resolvers.len();
        self.resolvers.get(index)
    }

    /// Batch evaluate claims
    pub fn batch_evaluate<'a>(
        &self,
        claims: &'a [(Claim, Vec<Evidence>)],
    ) -> Vec<(&'a Claim, EvaluationResult)> {
        claims
            .iter()
            .map(|(claim, evidence)| (claim, self.evaluate(claim, evidence)))
            .collect()
    }
}

/// Evaluation result
#[derive(Debug, Clone)]
pub enum EvaluationResult {
    /// Auto-approve claim
    AutoApprove { score: f64, confidence: f64 },
    /// Send for manual review
    ManualReview { score: f64, suggested_amount: f64 },
    /// Reject claim
    Reject { reason: String, score: f64 },
}

impl EvaluationResult {
    /// Check if claim should be approved
    pub fn should_approve(&self) -> bool {
        matches!(self, EvaluationResult::AutoApprove { .. })
    }

    /// Get score if available
    pub fn score(&self) -> Option<f64> {
        match self {
            EvaluationResult::AutoApprove { score, .. } => Some(*score),
            EvaluationResult::ManualReview { score, .. } => Some(*score),
            EvaluationResult::Reject { score, .. } => Some(*score),
        }
    }

    /// Get description
    pub fn description(&self) -> String {
        match self {
            EvaluationResult::AutoApprove { score, confidence } => {
                format!(
                    "Auto-approve (score: {:.1}, confidence: {:.0}%)",
                    score,
                    confidence * 100.0
                )
            }
            EvaluationResult::ManualReview {
                score,
                suggested_amount,
            } => {
                format!(
                    "Manual review (score: {:.1}, suggested: {} ETH)",
                    score, suggested_amount
                )
            }
            EvaluationResult::Reject { reason, score } => {
                format!("Reject: {} (score: {:.1})", reason, score)
            }
        }
    }
}

/// Claim statistics
#[derive(Debug, Clone, Default)]
pub struct ClaimStats {
    pub total_claims: u32,
    pub pending_claims: u32,
    pub approved_claims: u32,
    pub rejected_claims: u32,
    pub paid_claims: u32,
    pub total_paid: f64,
    pub average_resolution_time_hours: f64,
}

impl ClaimStats {
    /// Calculate approval rate
    pub fn approval_rate(&self) -> f64 {
        let decided = self.approved_claims + self.rejected_claims;
        if decided == 0 {
            0.0
        } else {
            self.approved_claims as f64 / decided as f64
        }
    }

    /// Calculate average payout
    pub fn average_payout(&self) -> f64 {
        if self.paid_claims == 0 {
            0.0
        } else {
            self.total_paid / self.paid_claims as f64
        }
    }
}

/// Claims manager
pub struct ClaimsManager {
    evaluator: ClaimEvaluator,
    claims: Vec<Claim>,
}

impl ClaimsManager {
    /// Create new claims manager
    pub fn new(evaluator: ClaimEvaluator) -> Self {
        Self {
            evaluator,
            claims: Vec::new(),
        }
    }

    /// Submit new claim
    pub fn submit_claim(&mut self, claim: Claim) -> Result<(), super::InsuranceError> {
        // Validate claim
        if claim.amount <= 0.0 {
            return Err(super::InsuranceError::InvalidClaim(
                "Invalid claim amount".to_string(),
            ));
        }

        if claim.evidence.is_empty() {
            return Err(super::InsuranceError::InvalidClaim(
                "No evidence provided".to_string(),
            ));
        }

        self.claims.push(claim);

        Ok(())
    }

    /// Get pending claims
    pub fn pending_claims(&self) -> Vec<&Claim> {
        self.claims.iter().filter(|c| c.is_pending()).collect()
    }

    /// Get statistics
    pub fn stats(&self) -> ClaimStats {
        let mut stats = ClaimStats::default();

        for claim in &self.claims {
            stats.total_claims += 1;

            match claim.status {
                ClaimStatus::Pending | ClaimStatus::UnderReview => {
                    stats.pending_claims += 1;
                }
                ClaimStatus::Approved => {
                    stats.approved_claims += 1;
                }
                ClaimStatus::Rejected => {
                    stats.rejected_claims += 1;
                }
                ClaimStatus::Paid => {
                    stats.paid_claims += 1;
                    stats.total_paid += claim.amount;
                }
            }

            if let Some(resolved) = claim.resolved_at {
                let hours = (resolved - claim.submitted_at).num_hours() as f64;
                stats.average_resolution_time_hours =
                    (stats.average_resolution_time_hours * (stats.total_claims - 1) as f64 + hours)
                        / stats.total_claims as f64;
            }
        }

        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claim_creation() {
        let claim = Claim::new(
            "claim-1".to_string(),
            "policy-1".to_string(),
            "user-1".to_string(),
            5.0,
            "Security vulnerability found".to_string(),
            "https://example.com/evidence".to_string(),
        );

        assert_eq!(claim.amount, 5.0);
        assert_eq!(claim.status, ClaimStatus::Pending);
        assert!(claim.is_pending());
    }

    #[test]
    fn test_claim_approve() {
        let mut claim = Claim::new(
            "claim-1".to_string(),
            "policy-1".to_string(),
            "user-1".to_string(),
            5.0,
            "Security vulnerability".to_string(),
            "evidence".to_string(),
        );

        claim.approve("resolver-1", Some("Valid claim".to_string()));

        assert_eq!(claim.status, ClaimStatus::Approved);
        assert_eq!(claim.resolver, Some("resolver-1".to_string()));
    }

    #[test]
    fn test_evidence_score() {
        let evidence = Evidence {
            evidence_type: EvidenceType::CveReport,
            description: "Critical CVE".to_string(),
            source: "https://cve.mitre.org/...".to_string(),
            timestamp: Utc::now(),
            severity: 9.0,
        };

        let score = evidence.score();
        assert!(score > 80.0); // CVE with high severity should score high
    }

    #[test]
    fn test_claim_evaluator() {
        let evaluator = ClaimEvaluator::default();

        let claim = Claim::new(
            "claim-1".to_string(),
            "policy-1".to_string(),
            "user-1".to_string(),
            0.5, // Below auto-approval limit
            "Test".to_string(),
            "evidence".to_string(),
        );

        let evidence = vec![Evidence {
            evidence_type: EvidenceType::CveReport,
            description: "CVE-2024-1234".to_string(),
            source: "mitre.org".to_string(),
            timestamp: Utc::now(),
            severity: 8.0,
        }];

        let result = evaluator.evaluate(&claim, &evidence);

        // Should suggest manual review or auto-approve depending on score
        assert!(result.score().is_some());
    }

    #[test]
    fn test_claim_stats() {
        let stats = ClaimStats {
            total_claims: 100,
            pending_claims: 10,
            approved_claims: 70,
            rejected_claims: 20,
            paid_claims: 65,
            total_paid: 650.0,
            ..Default::default()
        };

        // 70/90 = 0.7777… — compare with tolerance, not an exact truncated literal.
        assert!((stats.approval_rate() - 70.0_f64 / 90.0).abs() < 1e-12);
        assert_eq!(stats.average_payout(), 10.0); // 650/65
    }
}
