use crate::sandbox::{NetworkMode, SandboxConfig, SandboxMetrics, SandboxResult};
use anyhow::{Context, Result};
use common::{Finding, FindingSeverity, PackageManifest};
use std::time::Instant;

fn extract_wasm_files(tarball_path: &std::path::Path) -> Result<Vec<(String, Vec<u8>)>> {
    use flate2::read::GzDecoder;
    use std::io::Read;

    let tarball_bytes = std::fs::read(tarball_path)
        .with_context(|| format!("Failed to read tarball at {:?}", tarball_path))?;

    let gz = GzDecoder::new(&tarball_bytes[..]);
    let mut archive = tar::Archive::new(gz);
    let mut wasm_files = Vec::new();

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_string_lossy().to_string();
        if path.ends_with(".wasm") {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            wasm_files.push((path, buf));
        }
    }
    Ok(wasm_files)
}

/// Cross-platform fallback sandbox using wasmtime.
/// Executes package payload within a WebAssembly sandbox.
pub async fn run_in_wasm(
    pkg_id: &common::PackageId,
    tarball_path: &std::path::Path,
    config: &SandboxConfig,
    _manifest: &PackageManifest,
) -> Result<SandboxResult> {
    tracing::info!(
        "[WASM] Initializing WASM sandbox execution for {}...",
        pkg_id
    );
    let start_time = Instant::now();

    let mut findings = Vec::new();

    // ── Extract WASM payloads from tarball ──
    let wasm_files = match extract_wasm_files(tarball_path) {
        Ok(files) => files,
        Err(e) => {
            tracing::error!("[WASM] Tarball extraction failed: {}", e);
            findings.push(Finding {
                id: "SB006".into(),
                title: "WASM Extraction Failure".into(),
                severity: FindingSeverity::Critical,
                description: format!("Failed to extract WASM payload from tarball: {}", e),
                file: "wasm_sandbox".into(),
                line: None,
            });
            return Ok(SandboxResult {
                findings,
                observed_network_hosts: vec![],
                observed_fs_writes: vec![],
                observed_process_spawns: vec![],
                metrics: SandboxMetrics {
                    engine_used: "wasm".into(),
                    wall_time_ms: start_time.elapsed().as_millis() as u64,
                    exit_code: 1,
                    observations_count: 0,
                    findings_count: 1,
                },
            });
        }
    };

    if wasm_files.is_empty() {
        tracing::warn!("[WASM] Package does not contain any .wasm files.");
        findings.push(Finding {
            id: "SB006".into(),
            title: "Missing WASM Content".into(),
            severity: FindingSeverity::Critical,
            description:
                "Package was flagged as a WASM candidate but contains no valid .wasm modules."
                    .into(),
            file: "wasm_sandbox".into(),
            line: None,
        });
        return Ok(SandboxResult {
            findings,
            observed_network_hosts: vec![],
            observed_fs_writes: vec![],
            observed_process_spawns: vec![],
            metrics: SandboxMetrics {
                engine_used: "wasm".into(),
                wall_time_ms: start_time.elapsed().as_millis() as u64,
                exit_code: 1,
                observations_count: 0,
                findings_count: 1,
            },
        });
    }

    // ── Configure and Instantiate WasmSandbox ──
    let memory_limit = (config.memory_mb as usize) * 1024 * 1024;
    let wasm_config = wasm_sandbox_crate::SandboxConfig::default()
        .with_memory_limit(memory_limit)
        .with_timeout_secs(config.timeout_secs);

    let sandbox = match wasm_sandbox_crate::WasmSandbox::new(wasm_config) {
        Ok(sb) => sb,
        Err(e) => {
            tracing::error!("[WASM] Failed to create WASM sandbox: {}", e);
            findings.push(Finding {
                id: "SB006".into(),
                title: "WASM Sandbox Initialization Error".into(),
                severity: FindingSeverity::Critical,
                description: format!("Failed to create WASM sandbox: {}", e),
                file: "wasm_sandbox".into(),
                line: None,
            });
            return Ok(SandboxResult {
                findings,
                observed_network_hosts: vec![],
                observed_fs_writes: vec![],
                observed_process_spawns: vec![],
                metrics: SandboxMetrics {
                    engine_used: "wasm".into(),
                    wall_time_ms: start_time.elapsed().as_millis() as u64,
                    exit_code: 1,
                    observations_count: 0,
                    findings_count: 1,
                },
            });
        }
    };

    let sandbox_input =
        wasm_sandbox_crate::SandboxInput::new(&pkg_id.name, &pkg_id.version, &pkg_id.ecosystem);

    let mut execution_failed = false;

    for (path, wasm_bytes) in wasm_files {
        tracing::info!("[WASM] Executing WASM module: {} ...", path);
        match sandbox.run(&wasm_bytes, &sandbox_input).await {
            Ok(res) => {
                for f in res.findings {
                    findings.push(Finding {
                        id: f.category.clone(),
                        title: f.description.clone(),
                        severity: match f.severity {
                            wasm_sandbox_crate::Severity::Info => FindingSeverity::Low,
                            wasm_sandbox_crate::Severity::Low => FindingSeverity::Low,
                            wasm_sandbox_crate::Severity::Medium => FindingSeverity::Medium,
                            wasm_sandbox_crate::Severity::High => FindingSeverity::High,
                            wasm_sandbox_crate::Severity::Critical => FindingSeverity::Critical,
                        },
                        description: f.description,
                        file: path.clone(),
                        line: None,
                    });
                }
                if res.exit_code != 0 {
                    findings.push(Finding {
                        id: "SB006".into(),
                        title: "WASM execution failed".into(),
                        severity: FindingSeverity::Critical,
                        description: format!(
                            "WASM module {} exited with non-zero code {}.",
                            path, res.exit_code
                        ),
                        file: path,
                        line: None,
                    });
                    execution_failed = true;
                    break;
                }
            }
            Err(e) => {
                tracing::warn!("[WASM] Sandbox execution error for {}: {}", path, e);
                let description = match e {
                    wasm_sandbox_crate::SandboxError::Timeout(d) => {
                        format!("WASM module {} execution timed out after {:?}", path, d)
                    }
                    wasm_sandbox_crate::SandboxError::ResourceLimitExceeded(msg) => {
                        format!("WASM module {} exceeded resource limit: {}", path, msg)
                    }
                    wasm_sandbox_crate::SandboxError::CompilationError(msg) => {
                        format!("WASM module {} failed to compile: {}", path, msg)
                    }
                    other => {
                        format!("WASM module {} execution failed: {}", path, other)
                    }
                };
                findings.push(Finding {
                    id: "SB006".into(),
                    title: "WASM sandbox execution failed".into(),
                    severity: FindingSeverity::Critical,
                    description,
                    file: path,
                    line: None,
                });
                execution_failed = true;
                break;
            }
        }
    }

    if !execution_failed {
        findings.push(Finding {
            id: "SB005".into(),
            title: "WASM Execution Succeeded".into(),
            severity: FindingSeverity::Low,
            description:
                "Package was securely executed within WebAssembly strict architecture boundaries."
                    .into(),
            file: "wasm_sandbox".into(),
            line: None,
        });
    }

    let findings_count = findings.len();

    Ok(SandboxResult {
        findings,
        observed_network_hosts: vec![],
        observed_fs_writes: vec![],
        observed_process_spawns: vec![],
        metrics: SandboxMetrics {
            engine_used: "wasm".into(),
            wall_time_ms: start_time.elapsed().as_millis() as u64,
            exit_code: if execution_failed { 1 } else { 0 },
            observations_count: 0,
            findings_count,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{PackageId, PackageManifest};
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    use tar::Builder;
    use tempfile::NamedTempFile;

    fn create_test_tarball(wasm_filename: &str, wasm_bytes: &[u8]) -> NamedTempFile {
        let temp_file = NamedTempFile::new().unwrap();
        {
            let gz = GzEncoder::new(temp_file.as_file(), Compression::default());
            let mut tar = Builder::new(gz);

            let mut header = tar::Header::new_gnu();
            header.set_size(wasm_bytes.len() as u64);
            header.set_mode(0o755);
            tar.append_data(&mut header, wasm_filename, wasm_bytes)
                .unwrap();
            tar.finish().unwrap();
        }
        temp_file
    }

    #[tokio::test]
    async fn test_wasm_sandbox_success() {
        // Hand-crafted bytecode omitted memory/import sections and traps on wasmtime 17+.
        let wasm_bytes = wat::parse_str(
            r#"(module
                (func (export "main") (result i32)
                  i32.const 0)
            )"#,
        )
        .expect("valid WAT");

        let temp_tarball = create_test_tarball("payload.wasm", &wasm_bytes);
        let pkg_id = PackageId {
            name: "test-package-wasm".into(),
            version: "1.0.0".into(),
            ecosystem: "npm".into(),
        };

        let config = SandboxConfig {
            timeout_secs: 2,
            memory_mb: 64,
            network_mode: NetworkMode::Isolated,
            nsjail_config_path: None,
            docker_seccomp_path: None,
            rootfs_base_dir: None,
            tarball_hash: None,
        };
        let manifest = PackageManifest::default();

        let result = run_in_wasm(&pkg_id, temp_tarball.path(), &config, &manifest)
            .await
            .unwrap();

        assert_eq!(result.metrics.engine_used, "wasm");
        assert_eq!(result.metrics.exit_code, 0);

        // Should contain SB005 indicating success
        let has_success = result.findings.iter().any(|f| f.id == "SB005");
        assert!(
            has_success,
            "Expected SB005 success finding, got {:?}",
            result.findings
        );
    }

    #[tokio::test]
    #[ignore = "wasmtime infinite-loop modules can exhaust the blocking pool on Windows; run with --ignored"]
    async fn test_wasm_sandbox_timeout_disruption() {
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(8),
            test_wasm_sandbox_timeout_disruption_inner(),
        )
        .await;
        match result {
            Ok(inner) => inner,
            Err(_) => panic!("WASM timeout test exceeded 8s — sandbox may be hung"),
        }
    }

    async fn test_wasm_sandbox_timeout_disruption_inner() {
        // WASM bytecode that executes an infinite loop: loop { br 0 }
        // Signature must be () -> i32 to match WasmSandbox::run()'s get_typed_func call.
        // The i32.const 0 after the loop is unreachable but satisfies the type checker.
        let loop_wasm_bytes = &[
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // Magic & Version
            0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f, // Type: () -> i32
            0x03, 0x02, 0x01, 0x00, // Function index 0 uses type index 0
            0x07, 0x08, 0x01, 0x04, 0x6d, 0x61, 0x69, 0x6e, 0x00,
            0x00, // Export "main" as function index 0
            0x0a, 0x0b, 0x01, 0x09, 0x00, 0x03, 0x40, 0x0c, 0x00, 0x0b, 0x41, 0x00,
            0x0b, // Code: loop { br 0 }; i32.const 0; end
        ];

        let temp_tarball = create_test_tarball("payload.wasm", loop_wasm_bytes);
        let pkg_id = PackageId {
            name: "test-loop-wasm".into(),
            version: "1.0.0".into(),
            ecosystem: "npm".into(),
        };

        // Use a very short 1 second timeout to ensure it triggers quickly
        let config = SandboxConfig {
            timeout_secs: 1,
            memory_mb: 64,
            network_mode: NetworkMode::Isolated,
            nsjail_config_path: None,
            docker_seccomp_path: None,
            rootfs_base_dir: None,
            tarball_hash: None,
        };
        let manifest = PackageManifest::default();

        let result = run_in_wasm(&pkg_id, temp_tarball.path(), &config, &manifest)
            .await
            .unwrap();

        assert_eq!(result.metrics.exit_code, 1);

        // Should contain SB006 indicating execution failure/timeout
        let failure_finding = result.findings.iter().find(|f| f.id == "SB006");
        assert!(failure_finding.is_some(), "Expected SB006 failure finding");
        let desc = &failure_finding.unwrap().description;
        assert!(
            desc.contains("timed out"),
            "Expected description to mention timeout, got: {}",
            desc
        );
    }

    #[tokio::test]
    async fn test_wasm_sandbox_no_wasm_files() {
        let temp_tarball = create_test_tarball("not_wasm.txt", b"some text content");
        let pkg_id = PackageId {
            name: "test-package-wasm".into(),
            version: "1.0.0".into(),
            ecosystem: "npm".into(),
        };

        let config = SandboxConfig {
            timeout_secs: 5,
            memory_mb: 64,
            network_mode: NetworkMode::Isolated,
            nsjail_config_path: None,
            docker_seccomp_path: None,
            rootfs_base_dir: None,
            tarball_hash: None,
        };
        let manifest = PackageManifest::default();

        let result = run_in_wasm(&pkg_id, temp_tarball.path(), &config, &manifest)
            .await
            .unwrap();

        assert_eq!(result.metrics.exit_code, 1);
        let failure_finding = result.findings.iter().find(|f| f.id == "SB006");
        assert!(failure_finding.is_some());
        assert!(failure_finding
            .unwrap()
            .description
            .contains("no valid .wasm modules"));
    }
}
