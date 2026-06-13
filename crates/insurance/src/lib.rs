//! Package Insurance Management
//!
//! This crate provides risk modeling, premium calculation, and claims
//! management for the Chain Registry insurance system.
//!
//! # Example
//!
//! ```rust
//! use insurance::{RiskModel, PremiumCalculator, Policy};
//!
//! let risk_model = RiskModel::default();
//! let calculator = PremiumCalculator::new(risk_model);
//!
//! let premium = calculator.calculate(
//!     "npm:express@4.18.2",
//!     10.0, // 10 ETH coverage
//! );
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use tracing::{debug, info, warn};

pub mod claims;
pub mod risk_model;

pub use claims::{Claim, ClaimEvaluator, ClaimStatus};
pub use risk_model::{PackageMetrics, RiskFactor, RiskModel};

/// Errors that can occur in insurance operations
#[derive(Error, Debug)]
pub enum InsuranceError {
    #[error("Invalid coverage amount: {0}")]
    InvalidCoverage(f64),

    #[error("Invalid premium: {0}")]
    InvalidPremium(f64),

    #[error("Policy not found: {0}")]
    PolicyNotFound(String),

    #[error("Claim not valid: {0}")]
    InvalidClaim(String),

    #[error("Risk calculation error: {0}")]
    RiskCalculationError(String),

    #[error("Pool insolvent: {0}")]
    PoolInsolvent(String),
}

/// Insurance policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Policy ID
    pub id: String,
    /// Insured party address
    pub insured: String,
    /// Package canonical name
    pub package: String,
    /// Coverage amount (in ETH)
    pub coverage_amount: f64,
    /// Premium paid (in ETH)
    pub premium: f64,
    /// Policy creation time
    pub created_at: DateTime<Utc>,
    /// Policy expiration time
    pub expires_at: DateTime<Utc>,
    /// Whether policy is active
    pub active: bool,
    /// Risk score at time of purchase
    pub risk_score: f64,
}

impl Policy {
    /// Create a new policy
    pub fn new(
        id: String,
        insured: String,
        package: String,
        coverage_amount: f64,
        premium: f64,
        duration_days: i64,
        risk_score: f64,
    ) -> Self {
        let now = Utc::now();
        Self {
            id,
            insured,
            package,
            coverage_amount,
            premium,
            created_at: now,
            expires_at: now + chrono::Duration::days(duration_days),
            active: true,
            risk_score,
        }
    }

    /// Check if policy is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Get remaining coverage period in days
    pub fn remaining_days(&self) -> i64 {
        let now = Utc::now();
        if now > self.expires_at {
            0
        } else {
            (self.expires_at - now).num_days()
        }
    }

    /// Calculate refund amount if canceled
    pub fn refund_amount(&self) -> f64 {
        if !self.active || self.is_expired() {
            return 0.0;
        }

        let remaining = self.remaining_days();
        let total = (self.expires_at - self.created_at).num_days();

        // Pro-rata refund minus 10% fee
        let refund = (self.premium * remaining as f64 / total as f64) * 0.9;
        refund
    }
}

/// Premium calculator for insurance policies
pub struct PremiumCalculator {
    risk_model: RiskModel,
    base_rate: f64,
    min_premium: f64,
    max_premium: f64,
}

impl PremiumCalculator {
    /// Create new premium calculator
    pub fn new(risk_model: RiskModel) -> Self {
        Self {
            risk_model,
            base_rate: 0.01,    // 1% base rate
            min_premium: 0.001, // 0.001 ETH min
            max_premium: 10.0,  // 10 ETH max
        }
    }

    /// Set base rate
    pub fn with_base_rate(mut self, rate: f64) -> Self {
        self.base_rate = rate;
        self
    }

    /// Calculate premium for a package
    pub fn calculate(&self, package: &str, coverage: f64) -> Result<f64, InsuranceError> {
        if coverage <= 0.0 {
            return Err(InsuranceError::InvalidCoverage(coverage));
        }

        // Get risk score
        let risk_score = self.risk_model.calculate_score(package)?;

        // Calculate base premium
        let base_premium = coverage * self.base_rate;

        // Apply risk multiplier
        let risk_multiplier = 1.0 + (risk_score / 100.0);
        let premium = base_premium * risk_multiplier;

        // Apply bounds
        let premium = premium.max(self.min_premium).min(self.max_premium);

        debug!(
            "Premium calculated for {}: {} ETH (risk: {}, coverage: {})",
            package, premium, risk_score, coverage
        );

        Ok(premium)
    }

    /// Calculate premium with custom risk factors
    pub fn calculate_with_factors(
        &self,
        package: &str,
        coverage: f64,
        factors: &HashMap<String, f64>,
    ) -> Result<f64, InsuranceError> {
        let base = self.calculate(package, coverage)?;

        // Apply custom factors
        let multiplier: f64 = factors.values().product();
        let adjusted = base * multiplier;

        Ok(adjusted.min(self.max_premium))
    }

    /// Batch calculate premiums
    pub fn batch_calculate(
        &self,
        packages: &[(String, f64)], // (package, coverage)
    ) -> Vec<(String, Result<f64, InsuranceError>)> {
        packages
            .iter()
            .map(|(pkg, cov)| (pkg.clone(), self.calculate(pkg, *cov)))
            .collect()
    }
}

/// Insurance pool manager
pub struct InsurancePool {
    /// Current pool balance
    pub balance: f64,
    /// Total coverage issued
    pub total_coverage: f64,
    /// Active policies
    pub policies: HashMap<String, Policy>,
    /// Claims history
    pub claims: Vec<claims::Claim>,
    /// Minimum solvency ratio
    min_solvency_ratio: f64,
}

impl InsurancePool {
    /// Create new insurance pool
    pub fn new(initial_balance: f64) -> Self {
        Self {
            balance: initial_balance,
            total_coverage: 0.0,
            policies: HashMap::new(),
            claims: Vec::new(),
            min_solvency_ratio: 1.0, // 100%
        }
    }

    /// Add policy to pool
    pub fn add_policy(&mut self, policy: Policy) -> Result<(), InsuranceError> {
        // Check solvency
        let new_coverage = self.total_coverage + policy.coverage_amount;
        let solvency = self.balance / new_coverage;

        if solvency < self.min_solvency_ratio {
            return Err(InsuranceError::PoolInsolvent(format!(
                "Solvency would be {:.2}%",
                solvency * 100.0
            )));
        }

        self.balance += policy.premium;
        self.total_coverage = new_coverage;
        let policy_id = policy.id.clone();
        self.policies.insert(policy_id.clone(), policy);

        info!("Policy {} added to pool", policy_id);

        Ok(())
    }

    /// Process a claim
    pub fn process_claim(
        &mut self,
        claim: claims::Claim,
        approved: bool,
    ) -> Result<f64, InsuranceError> {
        let payout = if approved {
            let amount = claim.amount;

            if amount > self.balance {
                return Err(InsuranceError::PoolInsolvent(
                    "Insufficient funds for payout".to_string(),
                ));
            }

            self.balance -= amount;
            self.total_coverage -= amount;

            info!("Claim {} approved: {} ETH payout", claim.id, amount);
            amount
        } else {
            0.0
        };

        let mut claim = claim;
        claim.status = if approved {
            ClaimStatus::Approved
        } else {
            ClaimStatus::Rejected
        };
        claim.resolved_at = Some(Utc::now());

        self.claims.push(claim);

        Ok(payout)
    }

    /// Get pool health metrics
    pub fn health(&self) -> PoolHealth {
        let solvency = if self.total_coverage > 0.0 {
            self.balance / self.total_coverage
        } else {
            1.0
        };

        let utilization = if self.balance > 0.0 {
            self.total_coverage / (self.balance * 3.0) // Assume 3x leverage max
        } else {
            0.0
        };

        PoolHealth {
            balance: self.balance,
            total_coverage: self.total_coverage,
            solvency_ratio: solvency,
            utilization_rate: utilization,
            active_policies: self.policies.len(),
            total_claims: self.claims.len(),
        }
    }

    /// Replenish pool
    pub fn replenish(&mut self, amount: f64) {
        self.balance += amount;
        info!(
            "Pool replenished: +{} ETH, new balance: {} ETH",
            amount, self.balance
        );
    }

    /// Clean up expired policies
    pub fn cleanup_expired(&mut self) -> usize {
        let before = self.policies.len();

        self.policies.retain(|_, policy| {
            if policy.is_expired() {
                self.total_coverage -= policy.coverage_amount;
                false
            } else {
                true
            }
        });

        let removed = before - self.policies.len();
        if removed > 0 {
            info!("Cleaned up {} expired policies", removed);
        }

        removed
    }
}

/// Pool health metrics
#[derive(Debug, Clone)]
pub struct PoolHealth {
    pub balance: f64,
    pub total_coverage: f64,
    pub solvency_ratio: f64,
    pub utilization_rate: f64,
    pub active_policies: usize,
    pub total_claims: usize,
}

impl PoolHealth {
    /// Check if pool is healthy
    pub fn is_healthy(&self) -> bool {
        self.solvency_ratio >= 1.0 && self.utilization_rate <= 0.8
    }

    /// Get risk level
    pub fn risk_level(&self) -> RiskLevel {
        if self.solvency_ratio < 0.8 || self.utilization_rate > 0.9 {
            RiskLevel::Critical
        } else if self.solvency_ratio < 1.0 || self.utilization_rate > 0.8 {
            RiskLevel::High
        } else if self.solvency_ratio < 1.2 {
            RiskLevel::Medium
        } else {
            RiskLevel::Low
        }
    }
}

/// Risk level for pool
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "LOW"),
            RiskLevel::Medium => write!(f, "MEDIUM"),
            RiskLevel::High => write!(f, "HIGH"),
            RiskLevel::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_creation() {
        let policy = Policy::new(
            "policy-1".to_string(),
            "user-1".to_string(),
            "npm:test@1.0.0".to_string(),
            10.0,
            0.1,
            365,
            50.0,
        );

        assert_eq!(policy.coverage_amount, 10.0);
        assert_eq!(policy.premium, 0.1);
        assert!(policy.active);
        assert!(!policy.is_expired());
    }

    #[test]
    fn test_premium_calculation() {
        let risk_model = RiskModel::default();
        let calculator = PremiumCalculator::new(risk_model);

        let premium = calculator.calculate("npm:express@4.18.2", 10.0).unwrap();

        // Should be at least base rate
        assert!(premium >= 0.1); // 1% of 10 ETH
    }

    #[test]
    fn test_insurance_pool() {
        let mut pool = InsurancePool::new(1000.0);

        let policy = Policy::new(
            "policy-1".to_string(),
            "user-1".to_string(),
            "npm:test@1.0.0".to_string(),
            100.0,
            1.0,
            365,
            50.0,
        );

        pool.add_policy(policy).unwrap();

        let health = pool.health();
        assert_eq!(health.balance, 1001.0);
        assert_eq!(health.total_coverage, 100.0);
        assert!(health.is_healthy());
    }

    #[test]
    fn test_pool_health_risk_levels() {
        let health = PoolHealth {
            balance: 100.0,
            total_coverage: 150.0, // 66% solvency
            solvency_ratio: 0.66,
            utilization_rate: 0.5,
            active_policies: 10,
            total_claims: 2,
        };

        assert_eq!(health.risk_level(), RiskLevel::Critical);
        assert!(!health.is_healthy());
    }
}
