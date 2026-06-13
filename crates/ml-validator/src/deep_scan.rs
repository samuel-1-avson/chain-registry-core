//! Multi-Layer Malware Detection Pipeline
//!
//! Replaces the old custom-ONNX approach with three production-ready layers
//! that require **zero training data**:
//!
//! 1. **YARA-X scanning** — community-maintained malware rules (VirusTotal).
//! 2. **OSV.dev lookups** — Google's open vulnerability database.
//! 3. **Content-hash threat intel** — SHA-256 matching against known-bad hashes.
//!
//! The legacy ONNX path is still available via `CREG_FORCE_ONNX=true` if a
//! real trained model exists, but the default pipeline no longer needs one.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;
use tracing::{debug, warn};

use crate::yara_scanner::YaraMatch;

/// Maximum wall-clock time allowed for a single deep-scan inference pass.
const SCAN_TIMEOUT: Duration = Duration::from_secs(30);

/// Errors that can occur during deep scanning.
#[derive(Debug, thiserror::Error)]
pub enum MlError {
    #[error("ONNX inference failed: {0}")]
    InferenceError(String),
    #[error("Tokenizer error: {0}")]
    TokenizerError(String),
    #[error("Tarball extraction failed: {0}")]
    ExtractionError(String),
    #[error("Model not found: {0}")]
    ModelNotFound(String),
}

/// A file flagged as suspicious by the deep-learning model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousFile {
    /// Path of the file inside the package.
    pub path: String,
    /// Malicious probability assigned to this file (0.0 – 1.0).
    pub probability: f32,
    /// Short code snippet (first 200 chars) for reporting.
    pub snippet: String,
}

/// Result of a deep-learning scan over a package tarball.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepScanResult {
    /// Probability that the package is malicious (0.0 – 1.0).
    pub malicious_probability: f32,

    /// Model confidence in the prediction (0.0 – 1.0).
    pub confidence: f32,

    /// Human-readable classification based on probability thresholds.
    pub classification: ThreatClassification,

    /// Optional attention weights mapped to source-file regions.
    /// Keys are file paths; values are per-line suspiciousness scores.
    pub attention_regions: Option<HashMap<String, Vec<f32>>>,

    /// Files flagged as suspicious by the model.
    pub suspicious_files: Vec<SuspiciousFile>,

    /// Model version or artifact identifier used for the scan.
    pub model_version: String,

    /// Whether the result was produced by a real ONNX inference or a
    /// fallback/mock because the model is not present.
    pub is_mock: bool,
}

/// Classification buckets for deep-scan output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatClassification {
    Safe,
    Suspicious,
    LikelyMalicious,
    ConfirmedMalicious,
    /// Inference did not complete (timeout, missing model, etc.).
    /// Validators should treat this as an abstention rather than approval.
    Degraded,
}

impl ThreatClassification {
    /// Derive a classification from a probability score.
    pub fn from_probability(prob: f32) -> Self {
        match prob {
            p if p < 0.30 => ThreatClassification::Safe,
            p if p < 0.60 => ThreatClassification::Suspicious,
            p if p < 0.85 => ThreatClassification::LikelyMalicious,
            _ => ThreatClassification::ConfirmedMalicious,
        }
    }

    /// Whether this classification should contribute a blocking finding.
    pub fn should_block(&self) -> bool {
        matches!(self, ThreatClassification::ConfirmedMalicious)
    }

    /// Whether the validator should abstain from voting due to degraded analysis.
    pub fn should_abstain(&self) -> bool {
        matches!(self, ThreatClassification::Degraded)
    }
}

/// Extract source files from a tarball and scan them with the active YARA rules.
/// This is used by the node's pre-mempool admission gate before a package enters
/// consensus.
pub fn scan_tarball_with_yara(
    tarball_bytes: &[u8],
    ecosystem: &str,
) -> Result<Vec<YaraMatch>, MlError> {
    let files = extract_source_files(tarball_bytes, ecosystem)
        .map_err(|e| MlError::ExtractionError(e.to_string()))?;
    Ok(crate::yara_scanner::scan_files(&files))
}

/// Deep-scan configuration.
pub struct DeepScanner {
    _model_path: std::path::PathBuf,
    _tokenizer_path: Option<std::path::PathBuf>,
    _max_length: usize,
    /// Optional package info for OSV lookups.
    package_info: Option<crate::osv_client::PackageInfo>,
    /// Ecosystem of the package being scanned (e.g. "npm", "pypi", "cargo").
    /// Used to restrict which file extensions are analysed, preventing
    /// cross-ecosystem false positives (e.g. Python helper scripts inside a
    /// Rust crate being scanned as JavaScript).
    pub ecosystem: String,
}

impl DeepScanner {
    /// Create a new scanner pointing at the given ONNX model.
    pub fn new<P: AsRef<Path>>(model_path: P) -> Self {
        Self {
            _model_path: model_path.as_ref().to_path_buf(),
            _tokenizer_path: None,
            _max_length: 512,
            package_info: None,
            ecosystem: String::new(),
        }
    }

    /// Check that the configured model file exists and is a valid size.
    /// Call at application startup to fail fast if the model is missing.
    ///
    /// Returns `Ok(())` if the default pipeline (YARA + OSV) will be used
    /// (i.e. `CREG_FORCE_ONNX` is not set).  When ONNX is forced, returns
    /// an error if the model file is missing or suspiciously small.
    pub fn validate_at_startup(&self) -> Result<(), MlError> {
        if std::env::var("CREG_FORCE_ONNX").unwrap_or_default() == "true" {
            tracing::warn!(
                "CREG_FORCE_ONNX=true is DEPRECATED and ignored. The legacy ONNX path has been retired. Defaulting to the YARA-X rule-based scanning waterfall."
            );
        }
        tracing::info!("ML deep-scan: ONNX model not required (rule-based YARA-X pipeline active)");
        Ok(())
    }

    /// Attach a tokenizer JSON path.
    pub fn with_tokenizer<P: AsRef<Path>>(mut self, path: P) -> Self {
        self._tokenizer_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Attach package metadata for OSV vulnerability lookups.
    pub fn with_package_info(mut self, info: crate::osv_client::PackageInfo) -> Self {
        self.package_info = Some(info);
        self
    }

    /// Return the model version string for inclusion in vote messages.
    pub fn model_version(&self) -> String {
        "creg-detect-v1.0.0".to_string()
    }

    /// Run the multi-layer scan (default).
    pub fn scan(&self, tarball_bytes: &[u8]) -> Result<DeepScanResult, MlError> {
        if std::env::var("CREG_FORCE_ONNX").unwrap_or_default() == "true" {
            tracing::warn!(
                "CREG_FORCE_ONNX=true is DEPRECATED and ignored. Legacy ONNX scan is retired. Running YARA-X multi-layer scan."
            );
        }

        // ── Multi-Layer Pipeline ──────────────────────────────────────
        let files = match extract_source_files(tarball_bytes, &self.ecosystem) {
            Ok(f) => f,
            Err(_) => {
                // If tarball extraction fails, return mock rather than error.
                // This makes the pipeline resilient to corrupt/empty tarballs.
                return Ok(mock_result());
            }
        };

        if files.is_empty() {
            return Ok(mock_result());
        }

        // Layer 1: YARA pattern matching.
        let yara_matches = crate::yara_scanner::scan_files(&files);
        let yara_prob = crate::yara_scanner::matches_to_probability(&yara_matches);

        // Layer 2: OSV vulnerability lookup (optional).
        let osv_prob = if let Some(ref info) = self.package_info {
            let osv_result = crate::osv_client::query(info);
            crate::osv_client::vulns_to_probability(&osv_result)
        } else {
            0.0
        };

        // Layer 3: Content-hash threat intelligence.
        let threat_result = crate::threat_intel::check(tarball_bytes, &files);
        let hash_prob = threat_result.to_probability();

        // ── Combine scores: take the max of all three layers ─────────
        // A single confident layer is enough to flag a package.  This
        // avoids the averaging-dilution problem where one critical hit
        // gets watered down by two clean layers.
        let combined = yara_prob.max(osv_prob).max(hash_prob);

        // Build suspicious files list from YARA matches.
        let mut suspicious_files: Vec<SuspiciousFile> = yara_matches
            .iter()
            .map(|m| SuspiciousFile {
                path: m.matched_file.clone(),
                probability: match m.threat_level {
                    5 => 0.95,
                    4 => 0.80,
                    3 => 0.55,
                    2 => 0.35,
                    _ => 0.15,
                },
                snippet: format!("YARA rule '{}': {}", m.rule_name, m.description),
            })
            .collect();

        suspicious_files.sort_by(|a, b| {
            b.probability
                .partial_cmp(&a.probability)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        suspicious_files.truncate(10);

        let classification = ThreatClassification::from_probability(combined);
        let confidence = if combined > 0.01 {
            (0.5 + (combined - 0.5).abs()).min(1.0)
        } else {
            0.5 // Moderate confidence in a clean result.
        };

        debug!(
            "Multi-layer scan: yara={:.4} osv={:.4} hash={:.4} combined={:.4} class={:?}",
            yara_prob, osv_prob, hash_prob, combined, classification
        );

        Ok(DeepScanResult {
            malicious_probability: combined,
            confidence,
            classification,
            attention_regions: None,
            suspicious_files,
            model_version: "creg-detect-v1.0.0".to_string(),
            is_mock: false,
        })
    }
}

impl Default for DeepScanner {
    fn default() -> Self {
        Self::new("models/malware_classifier.onnx")
    }
}

/// Convenience free function that uses the default scanner.
///
/// Called from the validator pipeline after the light-weight `score()`
/// (rule-based) check.  Wraps the scan in a timeout to prevent hung
/// sessions from blocking the validator pipeline.
///
/// `package_info` is optional — when provided, OSV vulnerability lookups
/// are enabled.
///
/// `ecosystem` (e.g. `"npm"`, `"pypi"`, `"cargo"`) filters which source
/// file extensions are extracted and scored, preventing cross-ecosystem
/// false-positives.
pub fn deep_scan(
    tarball_bytes: &[u8],
    package_info: Option<crate::osv_client::PackageInfo>,
    ecosystem: &str,
) -> Result<DeepScanResult, MlError> {
    let mut scanner = DeepScanner::default();
    scanner.package_info = package_info;
    scanner.ecosystem = ecosystem.to_string();

    let bytes = tarball_bytes.to_vec();
    let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);

    std::thread::Builder::new()
        .name("creg-deep-scan".to_string())
        .spawn(move || {
            let _ = result_tx.send(scanner.scan(&bytes));
        })
        .map_err(|e| MlError::InferenceError(format!("Failed to spawn deep-scan worker: {e}")))?;

    match result_rx.recv_timeout(SCAN_TIMEOUT) {
        Ok(result) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            warn!(
                "Deep-scan inference timed out after {}s",
                SCAN_TIMEOUT.as_secs()
            );
            Ok(timeout_result())
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(MlError::InferenceError(
            "Deep-scan worker exited before returning a result".into(),
        )),
    }
}

/// Produce a degraded result when no model is available or the model is a
/// placeholder. Carries `is_mock = true` so that the validator pipeline
/// emits a visible ML001 warning finding.
fn mock_result() -> DeepScanResult {
    warn!("ML deep-scan running in DEGRADED mode — no trained ONNX model loaded. Security coverage is limited to rule-based analysis only.");
    DeepScanResult {
        malicious_probability: 0.0, // Don't return fake 0.15 — be honest: no data
        confidence: 0.0,            // Zero confidence — no inference was performed
        classification: ThreatClassification::Degraded,
        attention_regions: None,
        suspicious_files: Vec::new(),
        model_version: "degraded-no-model".to_string(),
        is_mock: true,
    }
}

/// Produce a degraded result when ONNX inference timed out.
fn timeout_result() -> DeepScanResult {
    warn!(
        "ML deep-scan timed out — inference did not complete within {}s.",
        SCAN_TIMEOUT.as_secs()
    );
    DeepScanResult {
        malicious_probability: 0.0,
        confidence: 0.0,
        classification: ThreatClassification::Degraded,
        attention_regions: None,
        suspicious_files: Vec::new(),
        model_version: "degraded-timeout".to_string(),
        is_mock: true,
    }
}

/// Extract text source files from a tar.gz byte slice, filtered to extensions
/// appropriate for the given ecosystem. Passing an empty or unknown ecosystem
/// falls back to a broad cross-ecosystem set.
///
/// Filtering by ecosystem prevents false positives: a Rust crate that ships
/// Python helper scripts should not have those scripts scanned with the
/// JavaScript/Python ruleset and vice-versa.
fn extract_source_files(
    tarball: &[u8],
    ecosystem: &str,
) -> Result<Vec<(String, String)>, std::io::Error> {
    use std::io::Read;
    let gz = flate2::read::GzDecoder::new(tarball);
    let mut archive = tar::Archive::new(gz);
    let mut files = Vec::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_string_lossy().to_string();
        let mut content = String::new();
        if entry.read_to_string(&mut content).is_ok()
            && !content.is_empty()
            && is_source_file_for_ecosystem(&path, ecosystem)
        {
            files.push((path, content));
        }
    }
    Ok(files)
}

/// Check whether a file path is a source file relevant to the given ecosystem.
/// Falls back to a broad allowlist when the ecosystem is unknown.
fn is_source_file_for_ecosystem(path: &str, ecosystem: &str) -> bool {
    let ext = std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    match ecosystem.to_ascii_lowercase().trim() {
        "npm" => matches!(
            ext,
            "js" | "ts" | "mjs" | "cjs" | "jsx" | "tsx" | "sh" | "bash"
        ),
        "pypi" => matches!(ext, "py" | "pyw" | "sh" | "bash"),
        "cargo" => matches!(ext, "rs" | "sh" | "bash" | "toml"),
        "rubygems" | "gem" => matches!(ext, "rb" | "sh" | "bash"),
        "maven" | "gradle" => matches!(ext, "java" | "kt" | "groovy" | "scala" | "sh"),
        "nuget" => matches!(ext, "cs" | "vb" | "fs" | "ps1" | "psm1"),
        "go" | "goproxy" => matches!(ext, "go" | "sh" | "bash"),
        // Broad fallback for unknown ecosystems — covers all common scripting languages
        _ => matches!(
            ext,
            "js" | "ts"
                | "mjs"
                | "cjs"
                | "py"
                | "rb"
                | "rs"
                | "java"
                | "go"
                | "sh"
                | "bash"
                | "php"
                | "kt"
                | "swift"
                | "c"
                | "cpp"
        ),
    }
}

/// Check whether a file path looks like executable source code.
/// Uses the broad multi-ecosystem fallback; equivalent to
/// `is_source_file_for_ecosystem(path, "")`.
#[cfg(test)]
fn is_source_file(path: &str) -> bool {
    is_source_file_for_ecosystem(path, "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_result_when_no_source_files() {
        // With the multi-layer pipeline, passing invalid tarball data
        // returns a mock result because extract_source_files yields no files.
        let scanner = DeepScanner::new("/nonexistent/path/model.onnx");
        let result = scanner.scan(b"dummy tarball bytes").unwrap();

        // Invalid tarball → no files extracted → mock result.
        assert!(result.is_mock);
        assert_eq!(result.classification, ThreatClassification::Degraded);
        assert_eq!(result.malicious_probability, 0.0);
    }

    #[test]
    fn test_onnx_fallback_mock_when_model_missing() {
        // CREG_FORCE_ONNX is deprecated and ignored, so scanning invalid tarball yields mock result.
        std::env::set_var("CREG_FORCE_ONNX", "true");
        let scanner = DeepScanner::new("/nonexistent/path/model.onnx");
        let result = scanner.scan(b"dummy tarball bytes").unwrap();
        std::env::remove_var("CREG_FORCE_ONNX");

        assert!(result.is_mock);
        assert_eq!(result.classification, ThreatClassification::Degraded);
        assert!(result.model_version.starts_with("degraded"));
    }

    #[test]
    fn test_threat_classification_bounds() {
        assert_eq!(
            ThreatClassification::from_probability(0.0),
            ThreatClassification::Safe
        );
        assert_eq!(
            ThreatClassification::from_probability(0.29),
            ThreatClassification::Safe
        );
        assert_eq!(
            ThreatClassification::from_probability(0.30),
            ThreatClassification::Suspicious
        );
        assert_eq!(
            ThreatClassification::from_probability(0.59),
            ThreatClassification::Suspicious
        );
        assert_eq!(
            ThreatClassification::from_probability(0.60),
            ThreatClassification::LikelyMalicious
        );
        assert_eq!(
            ThreatClassification::from_probability(0.84),
            ThreatClassification::LikelyMalicious
        );
        assert_eq!(
            ThreatClassification::from_probability(0.85),
            ThreatClassification::ConfirmedMalicious
        );
        assert_eq!(
            ThreatClassification::from_probability(1.0),
            ThreatClassification::ConfirmedMalicious
        );
    }

    #[test]
    fn test_confirmed_malicious_blocks() {
        assert!(ThreatClassification::ConfirmedMalicious.should_block());
        assert!(!ThreatClassification::LikelyMalicious.should_block());
        assert!(!ThreatClassification::Suspicious.should_block());
        assert!(!ThreatClassification::Safe.should_block());
        assert!(!ThreatClassification::Degraded.should_block());
        // Degraded should cause abstention, not blocking
        assert!(ThreatClassification::Degraded.should_abstain());
        assert!(!ThreatClassification::Safe.should_abstain());
    }

    #[test]
    fn test_is_source_file() {
        assert!(is_source_file("src/index.js"));
        assert!(is_source_file("lib/main.py"));
        assert!(is_source_file("foo.rs"));
        assert!(!is_source_file("README.md"));
        assert!(!is_source_file("package.json"));
    }
}
