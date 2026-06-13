// crates/cli/src/batch.rs
// Batch operations for verifying and installing multiple packages at once.

use anyhow::Result;
use colored::Colorize;
use common::VerdictStatus;
use futures::future::join_all;
use std::path::Path;

/// Batch verification result for a single package
#[derive(Debug)]
pub struct BatchResult {
    pub package: String,
    pub status: VerdictStatus,
    pub success: bool,
    pub error: Option<String>,
}

/// Verify multiple packages in parallel
pub async fn verify_packages(
    packages: Vec<String>,
    ecosystem: Option<&str>,
    node_url: Option<&str>,
) -> Vec<BatchResult> {
    let mut results = Vec::new();

    println!(
        "{} Verifying {} packages in parallel...",
        "→".cyan(),
        packages.len()
    );

    // Create futures for all package verifications
    let futures: Vec<_> = packages
        .into_iter()
        .map(|pkg| {
            let eco = ecosystem.map(String::from);
            let url = node_url.map(String::from);
            tokio::spawn(async move {
                let eco_ref = eco.as_deref();
                match resolver::resolve(&pkg, eco_ref, url.as_deref()).await {
                    Ok(verdict) => BatchResult {
                        package: pkg.clone(),
                        status: verdict.status.clone(),
                        success: verdict.status.is_safe(),
                        error: None,
                    },
                    Err(e) => BatchResult {
                        package: pkg.clone(),
                        status: VerdictStatus::Unknown,
                        success: false,
                        error: Some(e.to_string()),
                    },
                }
            })
        })
        .collect();

    // Wait for all verifications to complete
    let completed = join_all(futures).await;

    for result in completed {
        match result {
            Ok(batch_result) => {
                print_result(&batch_result);
                results.push(batch_result);
            }
            Err(e) => {
                eprintln!("{} Task failed: {}", "✗".red(), e);
            }
        }
    }

    results
}

/// Install multiple packages with batch verification
pub async fn install_batch(
    packages: Vec<String>,
    ecosystem: Option<&str>,
    allow_unverified: bool,
    node_url: Option<&str>,
) -> Result<()> {
    // First verify all packages
    let results = verify_packages(packages.clone(), ecosystem, node_url).await;

    // Count statistics
    let verified = results.iter().filter(|r| r.success).count();
    let revoked = results
        .iter()
        .filter(|r| matches!(r.status, VerdictStatus::Revoked { .. }))
        .count();
    let unknown = results
        .iter()
        .filter(|r| matches!(r.status, VerdictStatus::Unknown))
        .count();
    let errors = results.iter().filter(|r| r.error.is_some()).count();

    println!("\n{} Batch verification complete:", "▶".cyan());
    println!("  {} Verified: {}", "✓".green(), verified);
    println!("  {} Revoked: {}", "✗".red(), revoked);
    println!("  {} Unknown: {}", "?".yellow(), unknown);
    println!("  {} Errors: {}", "!".red(), errors);

    // Check if we should proceed
    if revoked > 0 {
        eprintln!(
            "\n{} {} package(s) are REVOKED. Installation aborted.",
            "✗".red().bold(),
            revoked
        );
        return Err(anyhow::anyhow!("Revoked packages detected"));
    }

    if unknown > 0 && !allow_unverified {
        use dialoguer::Confirm;
        let proceed = Confirm::new()
            .with_prompt(format!(
                "{} unknown/unverified package(s). Proceed with installation?",
                unknown
            ))
            .default(false)
            .interact()?;

        if !proceed {
            return Err(anyhow::anyhow!("Installation cancelled by user"));
        }
    }

    // Install verified packages
    let _ecosystem_str = ecosystem.unwrap_or("npm");
    for pkg in &packages {
        println!("\n{} Installing {}...", "→".cyan(), pkg.bold());
        crate::install::run(pkg, ecosystem, allow_unverified, node_url).await?;
    }

    println!("\n{} Batch installation complete!", "✓".green().bold());
    Ok(())
}

/// Verify all dependencies from a lockfile or manifest
pub async fn verify_dependencies(
    manifest_path: Option<&Path>,
    node_url: Option<&str>,
) -> Result<Vec<BatchResult>> {
    let deps = detect_dependencies(manifest_path).await?;

    if deps.is_empty() {
        println!("{} No dependencies found to verify.", "ℹ".blue());
        return Ok(Vec::new());
    }

    println!("{} Found {} dependencies", "→".cyan(), deps.len());

    let results = verify_packages(deps, None, node_url).await;

    // Print summary
    let verified = results.iter().filter(|r| r.success).count();
    let total = results.len();

    println!(
        "\n{} Verification summary: {}/{} packages verified",
        if verified == total {
            "✓".green()
        } else {
            "⚠".yellow()
        },
        verified,
        total
    );

    Ok(results)
}

/// Detect dependencies from various manifest files
async fn detect_dependencies(manifest_path: Option<&Path>) -> Result<Vec<String>> {
    let cwd = std::env::current_dir()?;

    // Check for package.json
    let package_json = manifest_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| cwd.join("package.json"));
    if package_json.exists() {
        return extract_npm_deps(&package_json).await;
    }

    // Check for Cargo.toml
    let cargo_toml = cwd.join("Cargo.toml");
    if cargo_toml.exists() {
        return extract_cargo_deps(&cargo_toml).await;
    }

    // Check for requirements.txt
    let requirements = cwd.join("requirements.txt");
    if requirements.exists() {
        return extract_pip_deps(&requirements).await;
    }

    Err(anyhow::anyhow!(
        "No supported manifest file found. Looked for: package.json, Cargo.toml, requirements.txt"
    ))
}

async fn extract_npm_deps(path: &Path) -> Result<Vec<String>> {
    let content = tokio::fs::read_to_string(path).await?;
    let package: serde_json::Value = serde_json::from_str(&content)?;

    let mut deps = Vec::new();

    // Extract from dependencies
    if let Some(dependencies) = package.get("dependencies") {
        if let Some(obj) = dependencies.as_object() {
            for (name, version) in obj {
                let version_str = version.as_str().unwrap_or("latest");
                deps.push(format!(
                    "{}@{}",
                    name,
                    version_str.trim_start_matches('^').trim_start_matches('~')
                ));
            }
        }
    }

    // Extract from devDependencies
    if let Some(dev_deps) = package.get("devDependencies") {
        if let Some(obj) = dev_deps.as_object() {
            for (name, version) in obj {
                let version_str = version.as_str().unwrap_or("latest");
                deps.push(format!(
                    "{}@{}",
                    name,
                    version_str.trim_start_matches('^').trim_start_matches('~')
                ));
            }
        }
    }

    Ok(deps)
}

async fn extract_cargo_deps(path: &Path) -> Result<Vec<String>> {
    let content = tokio::fs::read_to_string(path).await?;
    let cargo: toml::Value = toml::from_str(&content)?;

    let mut deps = Vec::new();

    if let Some(dependencies) = cargo.get("dependencies") {
        if let Some(table) = dependencies.as_table() {
            for (name, version_val) in table {
                let version = match version_val {
                    toml::Value::String(v) => v.clone(),
                    toml::Value::Table(t) => t
                        .get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("latest")
                        .to_string(),
                    _ => "latest".to_string(),
                };
                deps.push(format!("{}@{}", name, version));
            }
        }
    }

    Ok(deps)
}

async fn extract_pip_deps(path: &Path) -> Result<Vec<String>> {
    let content = tokio::fs::read_to_string(path).await?;
    let mut deps = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        // Skip comments and empty lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Handle package==version, package>=version, etc.
        if let Some(idx) = line.find(|c: char| c == '=' || c == '<' || c == '>') {
            let name = &line[..idx];
            let version = &line[idx..];
            deps.push(format!("{}{}", name, version));
        } else {
            // Just package name, use latest
            deps.push(format!("{}@latest", line));
        }
    }

    Ok(deps)
}

fn print_result(result: &BatchResult) {
    let icon = if result.success {
        "✓".green()
    } else if result.error.is_some() {
        "!".red()
    } else {
        "✗".red()
    };

    let status_str = match &result.status {
        VerdictStatus::Verified { .. } => "VERIFIED".green(),
        VerdictStatus::Revoked { .. } => "REVOKED".red(),
        VerdictStatus::Unverified => "UNVERIFIED".yellow(),
        VerdictStatus::Unknown => "UNKNOWN".dimmed(),
    };

    if let Some(ref error) = result.error {
        println!(
            "  {} {} {} (Error: {})",
            icon,
            result.package,
            status_str,
            error.dimmed()
        );
    } else {
        println!("  {} {} {}", icon, result.package, status_str);
    }
}
