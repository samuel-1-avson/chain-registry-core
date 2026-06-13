//! Integration tests for WASM sandbox

use wasm_sandbox::{SandboxConfig, SandboxInput, WasmSandbox};

#[tokio::test]
async fn test_sandbox_creation() {
    let config = SandboxConfig::default();
    let sandbox = WasmSandbox::new(config);
    
    assert!(sandbox.is_ok(), "Should be able to create WASM sandbox");
}

#[test]
fn test_sandbox_config() {
    let config = SandboxConfig::default()
        .with_memory_limit(1024 * 1024)
        .with_timeout_secs(60);
    
    assert_eq!(config.memory_limit, 1024 * 1024);
    assert_eq!(config.timeout_secs, 60);
}

#[test]
fn test_sandbox_input() {
    let input = SandboxInput::new("test-pkg", "1.0.0", "npm")
        .with_tarball(vec![1, 2, 3, 4, 5]);
    
    assert_eq!(input.package_name, "test-pkg");
    assert_eq!(input.package_version, "1.0.0");
    assert_eq!(input.tarball_bytes, vec![1, 2, 3, 4, 5]);
}

#[tokio::test]
async fn test_sandbox_resource_limits() {
    let config = SandboxConfig::default()
        .with_memory_limit(256 * 1024 * 1024)
        .with_timeout_secs(30);
    
    let sandbox = WasmSandbox::new(config).expect("Failed to create sandbox");
    let stats = sandbox.stats();
    
    assert_eq!(stats.get("memory_limit"), Some(&(256 * 1024 * 1024 as u64)));
    assert_eq!(stats.get("timeout_secs"), Some(&30u64));
}

#[test]
fn test_sandbox_capability_set() {
    use wasm_sandbox::CapabilitySet;
    
    let mut caps = CapabilitySet::empty();
    assert!(!caps.has("stdio"));
    
    caps.add("stdio");
    assert!(caps.has("stdio"));
    
    caps.remove("stdio");
    assert!(!caps.has("stdio"));
}

#[test]
fn test_resource_limits() {
    use wasm_sandbox::ResourceLimits;
    
    let strict = ResourceLimits::strict();
    assert_eq!(strict.max_memory, 64 * 1024 * 1024);
    assert_eq!(strict.max_time_ms, 10000);
    
    let relaxed = ResourceLimits::relaxed();
    assert_eq!(relaxed.max_memory, 512 * 1024 * 1024);
    assert_eq!(relaxed.max_time_ms, 60000);
}
