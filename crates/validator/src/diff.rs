// crates/validator/src/diff.rs
// Security-focused version diffing.
// detects "delta inflation" of permissions (e.g., version 1.0.1 adds network access).

use crate::sandbox::SandboxResult;
use common::PackageManifest;
use common::{Finding, FindingSeverity};

pub struct DiffResult {
    pub findings: Vec<Finding>,
    pub new_hosts: Vec<String>,
    pub new_paths: Vec<String>,
}

/// Compare current findings and sandbox observations against the previous verified version.
pub fn analyze(
    current_manifest: &PackageManifest,
    current_sandbox: &SandboxResult,
    prev_manifest: Option<&PackageManifest>,
    prev_sandbox: Option<&SandboxResult>,
) -> DiffResult {
    let mut findings = Vec::new();
    let mut new_hosts = Vec::new();
    let mut new_paths = Vec::new();

    if let Some(prev) = prev_manifest {
        // Detect new network hosts declared in manifest.
        for host in &current_manifest.allowed_network_hosts {
            if !prev.allowed_network_hosts.contains(host) {
                new_hosts.push(host.clone());
                findings.push(Finding {
                    id: "DF001".into(),
                    title: "New network host".into(),
                    severity: FindingSeverity::Medium,
                    description: format!("New undeclared network host access: {}", host),
                    file: "manifest".into(),
                    line: None,
                });
            }
        }

        // Detect new filesystem write paths declared in manifest.
        for path in &current_manifest.allowed_fs_writes {
            if !prev.allowed_fs_writes.contains(path) {
                new_paths.push(path.clone());
                findings.push(Finding {
                    id: "DF002".into(),
                    title: "New fs write path".into(),
                    severity: FindingSeverity::Medium,
                    description: format!("New undeclared filesystem write path: {}", path),
                    file: "manifest".into(),
                    line: None,
                });
            }
        }

        // Detect change in child process spawning.
        if current_manifest.spawns_processes && !prev.spawns_processes {
            findings.push(Finding {
                id: "DF003".into(),
                title: "Permission escalation: process-spawn".into(),
                severity: FindingSeverity::High,
                description: "Package now requests child process execution (previously disabled)"
                    .into(),
                file: "manifest".into(),
                line: None,
            });
        }
    }

    // Compare actual runtime observations from the sandbox (not just declared manifest).
    // This catches supply-chain attacks that escalate actual behavior without updating
    // the manifest (e.g., a new version contacts an exfiltration host not listed anywhere).
    if let Some(prev_sb) = prev_sandbox {
        // New network hosts accessed at runtime (not seen in previous version).
        for host in &current_sandbox.observed_network_hosts {
            if !prev_sb.observed_network_hosts.contains(host) {
                new_hosts.push(host.clone());
                findings.push(Finding {
                    id: "DF005".into(),
                    title: "Runtime behavior change: new network host".into(),
                    severity: FindingSeverity::High,
                    description: format!(
                        "Sandbox observed contact with '{}' — not seen in previous version's sandbox run",
                        host
                    ),
                    file: "sandbox".into(),
                    line: None,
                });
            }
        }

        // New filesystem write paths accessed at runtime.
        for path in &current_sandbox.observed_fs_writes {
            if !prev_sb.observed_fs_writes.contains(path) {
                new_paths.push(path.clone());
                findings.push(Finding {
                    id: "DF006".into(),
                    title: "Runtime behavior change: new fs write path".into(),
                    severity: FindingSeverity::Medium,
                    description: format!(
                        "Sandbox observed write to '{}' — not seen in previous version's sandbox run",
                        path
                    ),
                    file: "sandbox".into(),
                    line: None,
                });
            }
        }

        // New process spawns at runtime.
        for proc in &current_sandbox.observed_process_spawns {
            if !prev_sb.observed_process_spawns.contains(proc) {
                findings.push(Finding {
                    id: "DF007".into(),
                    title: "Runtime behavior change: new process spawn".into(),
                    severity: FindingSeverity::High,
                    description: format!(
                        "Sandbox observed spawn of '{}' — not seen in previous version's sandbox run",
                        proc
                    ),
                    file: "sandbox".into(),
                    line: None,
                });
            }
        }
    }

    // Manifest violation: sandbox accessed a host not declared in the current manifest.
    for host in &current_sandbox.observed_network_hosts {
        if !current_manifest.allowed_network_hosts.contains(host) {
            findings.push(Finding {
                id:          "DF004".into(),
                title:       "Sandbox violation: Undeclared host egress".into(),
                severity:    FindingSeverity::High,
                description: format!(
                    "Suspicious behavior: Real-world access to '{}' detected in sandbox but not in manifest",
                    host
                ),
                file:        "sandbox".into(),
                line:        None,
            });
        }
    }

    DiffResult {
        findings,
        new_hosts,
        new_paths,
    }
}
