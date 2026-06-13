//! Machine Learning Pipeline for Package Threat Detection
//!
//! This crate provides ML-based threat detection for packages, identifying
//! sophisticated attacks that may evade traditional static analysis.
//!
//! # Features
//!
//! - **Feature Extraction**: AST-based feature extraction for multiple languages
//! - **Rule-based Detection**: Fast rule-based threat scoring
//! - **Batch Processing**: Parallel processing of multiple packages
//! - **Deep Scanning**: Transformer-based semantic malware detection via ONNX
//!
//! # Example
//!
//! ```rust
//! use ml_validator::{MlValidator, FeatureExtractor};
//!
//! let package_code = "console.log('hello world')";
//! let validator = MlValidator::new();
//! let features = FeatureExtractor::extract("npm", package_code).unwrap();
//! let _score = validator.predict(&features);
//! ```

use std::collections::HashMap;
use tracing::{debug, instrument};

pub mod features;
pub use features::{FeatureExtractor, PackageFeatures};

pub mod deep_scan;
pub use deep_scan::{
    deep_scan, DeepScanResult, DeepScanner, MlError, SuspiciousFile, ThreatClassification,
};
pub use osv_snapshot::{
    bundle_epoch as osv_bundle_epoch, lookup_advisory as osv_lookup_advisory,
    lookup_pinned as osv_lookup_pinned, osv_block_critical_enabled, osv_consensus_enabled,
    osv_live_fallback_enabled, snapshot_available as osv_snapshot_available, OsvSnapshot,
    SCHEMA_V1,
};

pub mod osv_client;
pub mod osv_snapshot;
pub mod threat_intel;
pub mod yara_scanner;

/// Threat level classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ThreatLevel {
    /// Safe package (score 0-25)
    Safe = 0,
    /// Low risk (score 26-50)
    Low = 1,
    /// Suspicious (score 51-75)
    Suspicious = 2,
    /// High risk/malicious (score 76-100)
    Malicious = 3,
}

impl ThreatLevel {
    /// Create from threat score
    pub fn from_score(score: u8) -> Self {
        match score {
            0..=25 => ThreatLevel::Safe,
            26..=50 => ThreatLevel::Low,
            51..=75 => ThreatLevel::Suspicious,
            _ => ThreatLevel::Malicious,
        }
    }

    /// Human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            ThreatLevel::Safe => "Safe - No threats detected",
            ThreatLevel::Low => "Low Risk - Minor concerns",
            ThreatLevel::Suspicious => "Suspicious - Requires review",
            ThreatLevel::Malicious => "Malicious - Likely harmful",
        }
    }

    /// Whether this level should block installation
    pub fn should_block(&self) -> bool {
        matches!(self, ThreatLevel::Malicious)
    }
}

/// Prediction result from the ML model
#[derive(Debug, Clone)]
pub struct PredictionResult {
    /// Overall threat score (0-100)
    pub threat_score: u8,
    /// Threat level classification
    pub threat_level: ThreatLevel,
    /// Confidence in prediction (0.0-1.0)
    pub confidence: f32,
    /// Per-class probabilities
    pub class_probabilities: HashMap<ThreatLevel, f32>,
    /// Feature importance scores
    pub feature_importance: Option<HashMap<String, f32>>,
}

impl PredictionResult {
    /// Create a new prediction result
    pub fn new(
        threat_score: u8,
        confidence: f32,
        class_probabilities: HashMap<ThreatLevel, f32>,
    ) -> Self {
        Self {
            threat_level: ThreatLevel::from_score(threat_score),
            threat_score,
            confidence,
            class_probabilities,
            feature_importance: None,
        }
    }

    /// Whether this package should be rejected
    pub fn should_reject(&self) -> bool {
        self.threat_level.should_block()
    }
}

/// ML Validator for package threat detection
pub struct MlValidator;

impl MlValidator {
    /// Create a new ML validator
    pub fn new() -> Self {
        Self
    }

    /// Predict threat score for a package
    #[instrument(skip(self, features), level = "debug")]
    pub fn predict(&self, features: &PackageFeatures) -> PredictionResult {
        debug!("Running ML prediction (rule-based)");

        // Use rule-based scoring (to be replaced with ONNX model in future)
        RuleBasedValidator::assess(features)
    }

    /// Batch predict multiple packages
    #[instrument(skip(self, features_list), level = "debug")]
    pub fn batch_predict(&self, features_list: &[PackageFeatures]) -> Vec<PredictionResult> {
        debug!(
            "Running batch prediction for {} packages",
            features_list.len()
        );

        features_list
            .iter()
            .map(|features| self.predict(features))
            .collect()
    }

    /// Get model metadata
    pub fn model_info(&self) -> HashMap<String, String> {
        let mut info = HashMap::new();
        info.insert("type".to_string(), "rule-based".to_string());
        info.insert("version".to_string(), "0.1.0".to_string());
        info
    }
}

impl Default for MlValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Rule-based threat assessment
///
/// Used as primary detection and fallback when ONNX model is not available
pub struct RuleBasedValidator;

impl RuleBasedValidator {
    /// Quick rule-based threat assessment
    pub fn assess(features: &PackageFeatures) -> PredictionResult {
        let mut score = 0u8;
        let mut reasons = vec![];

        // Check for suspicious patterns
        if features.entropy > 7.5 {
            score += 20;
            reasons.push("High entropy (possible obfuscation)");
        }

        if features.eval_count > 0 {
            score += 25;
            reasons.push("Uses eval()");
        }

        if features.network_calls > 5 {
            score += 15;
            reasons.push("Many network calls");
        }

        if features.file_system_ops > 10 {
            score += 10;
            reasons.push("Many filesystem operations");
        }

        if features.dynamic_imports > 3 {
            score += 10;
            reasons.push("Many dynamic imports");
        }

        if features.obfuscation_indicators > 5 {
            score += 20;
            reasons.push("Obfuscation detected");
        }

        // AST depth factor (higher depth = more complex = more risk)
        if features.ast_depth > 10 {
            score += 5;
            reasons.push("Deep AST nesting");
        }

        // Cap at 100
        score = score.min(100);

        let mut class_probs = HashMap::new();
        let threat_level = ThreatLevel::from_score(score);
        class_probs.insert(threat_level, 0.7);
        class_probs.insert(ThreatLevel::Safe, if score < 25 { 0.7 } else { 0.1 });

        PredictionResult::new(score, 0.7, class_probs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_level_from_score() {
        assert_eq!(ThreatLevel::from_score(10), ThreatLevel::Safe);
        assert_eq!(ThreatLevel::from_score(30), ThreatLevel::Low);
        assert_eq!(ThreatLevel::from_score(60), ThreatLevel::Suspicious);
        assert_eq!(ThreatLevel::from_score(90), ThreatLevel::Malicious);
    }

    #[test]
    fn test_threat_level_should_block() {
        assert!(!ThreatLevel::Safe.should_block());
        assert!(!ThreatLevel::Low.should_block());
        assert!(!ThreatLevel::Suspicious.should_block());
        assert!(ThreatLevel::Malicious.should_block());
    }

    #[test]
    fn test_rule_based_assessment() {
        let features = PackageFeatures {
            eval_count: 1,
            entropy: 8.0,
            network_calls: 10,
            ..Default::default()
        };

        let result = RuleBasedValidator::assess(&features);

        assert!(result.threat_score > 50);
        assert!(result.confidence > 0.0);
    }
}
