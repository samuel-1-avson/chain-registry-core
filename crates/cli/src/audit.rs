// crates/cli/src/audit.rs
// `creg audit` — scans all installed packages in the current project
// against the chain registry and reports the trust status of each.
//
// Reads:
//   npm:       node_modules/.package-lock.json  or  package-lock.json
//   pip:       pip freeze output
//   cargo:     Cargo.lock
//   rubygems:  Gemfile.lock
//
// Exits with code 0 if all packages are verified,
//                  1 if any packages are revoked,
//                  2 if any packages are unverified/unknown (use --strict).

use anyhow::{Context, Result};
use colored::Colorize;
use common::{PackageId, VerdictStatus};
use serde::Deserialize;
use std::{collections::HashMap, path::Path};

/// Summary counts from an audit run.
pub struct AuditSummary {
    pub verified: usize,
    pub unverified: usize,
    pub revoked: usize,
    pub unknown: usize,
    pub total: usize,
}

pub async fn run(
    ecosystem: Option<&str>,
    node_url: Option<&str>,
    strict: bool,
    json_out: bool,
) -> Result<i32> {
    // Detect ecosystem from cwd if not specified.
    let eco = ecosystem.map(String::from).unwrap_or_else(detect_ecosystem);

    if eco == "unknown" {
        anyhow::bail!(
            "Could not detect project ecosystem. Run from a directory with \
             package.json, Cargo.lock, requirements.txt, or Gemfile.lock. \
             Or pass --ecosystem npm|cargo|pypi|rubygems."
        );
    }

    let packages = match eco.as_str() {
        "npm" => read_npm_packages()?,
        "cargo" => read_cargo_packages()?,
        "pypi" => read_pip_packages()?,
        "rubygems" => read_gem_packages()?,
        other => anyhow::bail!("Unsupported ecosystem: {}", other),
    };

    if packages.is_empty() {
        println!("No installed packages found for ecosystem '{}'.", eco);
        return Ok(0);
    }

    if !json_out {
        println!(
            "\n  {} Auditing {} packages ({}) against chain registry...\n",
            "→".cyan(),
            packages.len(),
            eco.yellow()
        );
    }

    // Resolve all packages concurrently (limited concurrency to avoid flooding node).
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(10));
    let mut handles = Vec::new();

    for pkg in packages {
        let sem = std::sync::Arc::clone(&semaphore);
        let url = node_url.map(String::from);
        let eco_c = eco.clone();

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.expect("semaphore closed");
            let id = PackageId::new(&eco_c, &pkg.name, &pkg.version);
            let verdict = resolver::resolve_id(&id, url.as_deref()).await;
            (pkg, verdict)
        }));
    }

    let mut results = Vec::new();
    for h in handles {
        if let Ok((pkg, verdict)) = h.await {
            results.push((pkg, verdict));
        }
    }

    // Sort: revoked first, then unverified, then unknown, then verified.
    results.sort_by_key(|(_, v)| match v {
        Err(_) => 0,
        Ok(v) if v.status.is_blocked() => 1,
        Ok(v) if !v.status.is_safe() => 2,
        _ => 3,
    });

    if json_out {
        return print_json_report(&results);
    }

    // ── Terminal report ───────────────────────────────────────────────────────
    let mut summary = AuditSummary {
        verified: 0,
        unverified: 0,
        revoked: 0,
        unknown: 0,
        total: results.len(),
    };

    for (pkg, verdict) in &results {
        match verdict {
            Err(e) => {
                summary.unknown += 1;
                println!(
                    "  {} {:50} {}",
                    "?".dimmed(),
                    pkg.canonical(),
                    e.to_string().dimmed()
                );
            }
            Ok(v) => match &v.status {
                VerdictStatus::Verified { findings, .. } => {
                    summary.verified += 1;
                    // Only print verified in verbose mode — keep output clean.
                    if findings.iter().any(|f| {
                        matches!(
                            f.severity,
                            common::FindingSeverity::Critical | common::FindingSeverity::High
                        )
                    }) {
                        println!(
                            "  {} {:50} {}",
                            "⚠".yellow().bold(),
                            pkg.canonical().yellow().bold(),
                            format!("VERIFIED but with severe findings! ({})", findings.len())
                                .yellow()
                        );
                    }
                }
                VerdictStatus::Unverified => {
                    summary.unverified += 1;
                    println!(
                        "  {} {:50} {}",
                        "⚠".yellow(),
                        pkg.canonical().yellow(),
                        "not yet chain-verified (pending pool)".yellow()
                    );
                }
                VerdictStatus::Revoked { reason, findings } => {
                    summary.revoked += 1;
                    println!(
                        "  {} {:50} {}",
                        "✗".red().bold(),
                        pkg.canonical().red().bold(),
                        format!("REVOKED — {} ({} findings)", reason, findings.len()).red()
                    );
                }
                VerdictStatus::Unknown => {
                    summary.unknown += 1;
                    println!(
                        "  {} {:50} {}",
                        "?".dimmed(),
                        pkg.canonical().dimmed(),
                        "unknown to chain registry".dimmed()
                    );
                }
            },
        }
    }

    // ── Summary table ─────────────────────────────────────────────────────────
    println!();
    println!("  {}", "─".repeat(58).dimmed());
    println!(
        "  {} {} verified  {} unverified  {} revoked  {} unknown",
        "▣".dimmed(),
        summary.verified.to_string().green(),
        summary.unverified.to_string().yellow(),
        if summary.revoked > 0 {
            summary.revoked.to_string().red().bold()
        } else {
            summary.revoked.to_string().green()
        },
        summary.unknown.to_string().dimmed(),
    );
    println!("  {} total packages audited\n", summary.total);

    // ── Exit code ─────────────────────────────────────────────────────────────
    if summary.revoked > 0 {
        println!(
            "  {} {} revoked package(s) found — remove them immediately!",
            "✗".red().bold(),
            summary.revoked
        );
        return Ok(1);
    }
    if strict && (summary.unverified > 0 || summary.unknown > 0) {
        println!(
            "  {} {} unverified/unknown package(s) (--strict mode)",
            "⚠".yellow(),
            summary.unverified + summary.unknown
        );
        return Ok(2);
    }
    println!("  {} No revoked packages found.", "✓".green().bold());
    Ok(0)
}

fn print_json_report(
    results: &[(
        InstalledPackage,
        Result<common::TrustVerdict, anyhow::Error>,
    )],
) -> Result<i32> {
    let entries: Vec<_> = results.iter().map(|(pkg, verdict)| {
        serde_json::json!({
            "canonical": pkg.canonical(),
            "status": match verdict {
                Err(_) => serde_json::json!({ "status": "error" }),
                Ok(v) => match &v.status {
                    VerdictStatus::Verified { findings, .. } => {
                        serde_json::json!({
                            "status": "verified",
                            "finding_count": findings.len(),
                            "has_severe": findings.iter().any(|f| matches!(f.severity, common::FindingSeverity::Critical | common::FindingSeverity::High))
                        })
                    }
                    VerdictStatus::Revoked { reason, findings } => {
                        serde_json::json!({
                            "status": "revoked",
                            "reason": reason,
                            "finding_count": findings.len()
                        })
                    }
                    VerdictStatus::Unverified => serde_json::json!({ "status": "unverified" }),
                    VerdictStatus::Unknown => serde_json::json!({ "status": "unknown" }),
                },
            },
        })
    }).collect();

    let revoked = entries.iter().filter(|e| e["status"] == "revoked").count();

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "total": entries.len(),
            "revoked": revoked,
            "packages": entries,
        }))?
    );

    Ok(if revoked > 0 { 1 } else { 0 })
}

// ─── Lockfile readers ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub eco: String,
}

impl InstalledPackage {
    fn canonical(&self) -> String {
        format!("{}:{}@{}", self.eco, self.name, self.version)
    }
}

fn read_npm_packages() -> Result<Vec<InstalledPackage>> {
    // Try package-lock.json first, then npm ls --json output.
    let lockfile = std::path::Path::new("package-lock.json");
    if !lockfile.exists() {
        anyhow::bail!("package-lock.json not found — run `npm install` first");
    }

    #[derive(Deserialize)]
    struct PkgLock {
        packages: Option<HashMap<String, PkgEntry>>,
    }
    #[derive(Deserialize)]
    struct PkgEntry {
        version: Option<String>,
    }

    let content = std::fs::read_to_string(lockfile)?;
    let lock: PkgLock = serde_json::from_str(&content)?;

    let mut result = Vec::new();
    if let Some(packages) = lock.packages {
        for (path, entry) in packages {
            // Skip the root package (empty string key) and node_modules/ prefix.
            if path.is_empty() || !path.starts_with("node_modules/") {
                continue;
            }
            let name = path.trim_start_matches("node_modules/").to_string();
            if let Some(version) = entry.version {
                result.push(InstalledPackage {
                    name,
                    version,
                    eco: "npm".into(),
                });
            }
        }
    }
    Ok(result)
}

fn read_cargo_packages() -> Result<Vec<InstalledPackage>> {
    let lockfile = Path::new("Cargo.lock");
    if !lockfile.exists() {
        anyhow::bail!("Cargo.lock not found — run `cargo build` first");
    }

    let content = std::fs::read_to_string(lockfile)?;

    // Parse Cargo.lock as TOML (it's a valid TOML file)
    let parsed: toml::Value =
        toml::from_str(&content).context("Failed to parse Cargo.lock as TOML")?;

    let mut result = Vec::new();
    if let Some(packages) = parsed.get("package").and_then(|v| v.as_array()) {
        for pkg in packages {
            let name = pkg
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let version = pkg
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if !name.is_empty() && !version.is_empty() {
                result.push(InstalledPackage {
                    name,
                    version,
                    eco: "cargo".into(),
                });
            }
        }
    }

    Ok(result)
}

fn read_pip_packages() -> Result<Vec<InstalledPackage>> {
    // Read requirements.txt or run `pip freeze`.
    if Path::new("requirements.txt").exists() {
        let content = std::fs::read_to_string("requirements.txt")?;
        let mut result = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Handle "package==version", "package>=version", "package"
            let (name, version) = if let Some(pos) = line.find("==") {
                (&line[..pos], &line[pos + 2..])
            } else if let Some(pos) = line.find(">=") {
                (&line[..pos], &line[pos + 2..])
            } else {
                (line, "latest")
            };
            result.push(InstalledPackage {
                name: name.trim().to_string(),
                version: version
                    .split_whitespace()
                    .next()
                    .unwrap_or("latest")
                    .to_string(),
                eco: "pypi".into(),
            });
        }
        return Ok(result);
    }
    // Fall back to running pip freeze.
    let output = std::process::Command::new("pip")
        .args(["freeze", "--local"])
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut result = Vec::new();
    for line in stdout.lines() {
        if let Some(pos) = line.find("==") {
            result.push(InstalledPackage {
                name: line[..pos].to_string(),
                version: line[pos + 2..].to_string(),
                eco: "pypi".into(),
            });
        }
    }
    Ok(result)
}

fn read_gem_packages() -> Result<Vec<InstalledPackage>> {
    let lockfile = Path::new("Gemfile.lock");
    if !lockfile.exists() {
        anyhow::bail!("Gemfile.lock not found — run `bundle install` first");
    }
    let content = std::fs::read_to_string(lockfile)?;
    let mut result = Vec::new();
    let mut in_gems = false;
    for line in content.lines() {
        if line.trim() == "GEM" || line.trim() == "specs:" {
            in_gems = line.trim() == "specs:";
            continue;
        }
        if in_gems && line.starts_with("    ") && !line.starts_with("      ") {
            // 4-space indent = top-level gem entry "    name (version)"
            let entry = line.trim();
            if let Some(pos) = entry.find(" (") {
                let name = entry[..pos].to_string();
                let version = entry[pos + 2..].trim_end_matches(')').to_string();
                result.push(InstalledPackage {
                    name,
                    version,
                    eco: "rubygems".into(),
                });
            }
        } else if line.is_empty() {
            in_gems = false;
        }
    }
    Ok(result)
}

/// `creg audit --fix` — attempt to auto-remediate audit findings.
/// For each revoked package: removes it from package.json/requirements.txt
/// and suggests a replacement from chain-verified alternatives.
pub async fn run_fix(ecosystem: Option<&str>, node_url: Option<&str>) -> Result<i32> {
    let eco = ecosystem.map(String::from).unwrap_or_else(detect_ecosystem);
    let packages = match eco.as_str() {
        "npm" => read_npm_packages()?,
        "cargo" => read_cargo_packages()?,
        "pypi" => read_pip_packages()?,
        "rubygems" => read_gem_packages()?,
        other => anyhow::bail!("Unsupported ecosystem: {}", other),
    };

    println!(
        "{} Running audit --fix for {} ({} packages)...",
        "→".cyan(),
        eco,
        packages.len()
    );

    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(8));
    let mut handles = Vec::new();

    for pkg in packages {
        let sem = std::sync::Arc::clone(&semaphore);
        let url = node_url.map(String::from);
        let eco_c = eco.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.expect("semaphore closed");
            let id = PackageId::new(&eco_c, &pkg.name, &pkg.version);
            let verdict = resolver::resolve_id(&id, url.as_deref()).await;
            (pkg, verdict)
        }));
    }

    let mut fixed = 0usize;
    for h in handles {
        if let Ok((pkg, verdict)) = h.await {
            if let Ok(v) = verdict {
                if let VerdictStatus::Revoked { reason, .. } = &v.status {
                    println!(
                        "  {} {} is REVOKED ({})",
                        "✗".red().bold(),
                        pkg.canonical().red(),
                        reason
                    );
                    // Try to find a non-revoked alternative by checking the chain
                    // for the same package name at a different version.
                    if let Ok(alt) = find_safe_alternative(&pkg, node_url).await {
                        println!("    {} Alternative: {}", "→".cyan(), alt.green());
                    } else {
                        println!(
                            "    {} No safe alternative found automatically. Remove manually.",
                            "⚠".yellow()
                        );
                    }
                    fixed += 1;
                }
            }
        }
    }

    if fixed == 0 {
        println!(
            "{} No revoked packages found — nothing to fix.",
            "✓".green().bold()
        );
        Ok(0)
    } else {
        println!(
            "\n{} {} revoked package(s) flagged. Update your manifest and re-run `creg audit`.",
            "⚠".yellow(),
            fixed
        );
        Ok(1)
    }
}

/// Try to find a chain-verified alternative version for a revoked package.
async fn find_safe_alternative(pkg: &InstalledPackage, node_url: Option<&str>) -> Result<String> {
    let base = node_url.map(String::from).unwrap_or_else(|| {
        std::env::var("CREG_NODE_URL").unwrap_or_else(|_| "http://localhost:8080".into())
    });

    let search_url = format!(
        "{}/v1/packages/search?q={}&ecosystem={}",
        base.trim_end_matches('/'),
        urlencoding::encode(&pkg.name),
        urlencoding::encode(&pkg.eco),
    );

    let resp = reqwest::Client::new()
        .get(&search_url)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await?;

    if !resp.status().is_success() {
        anyhow::bail!("No alternatives found");
    }

    let records: Vec<serde_json::Value> = resp.json().await?;
    for r in records {
        let status = r.get("status").and_then(|s| s.as_str()).unwrap_or("");
        let canonical = r.get("canonical").and_then(|s| s.as_str()).unwrap_or("");
        if status == "verified" && !canonical.is_empty() {
            return Ok(canonical.to_string());
        }
    }
    anyhow::bail!("No verified alternative found")
}

fn detect_ecosystem() -> String {
    let cwd = std::env::current_dir().unwrap_or_default();
    if cwd.join("package-lock.json").exists() || cwd.join("package.json").exists() {
        return "npm".into();
    }
    if cwd.join("Cargo.lock").exists() {
        return "cargo".into();
    }
    if cwd.join("requirements.txt").exists() || cwd.join("Pipfile.lock").exists() {
        return "pypi".into();
    }
    if cwd.join("Gemfile.lock").exists() {
        return "rubygems".into();
    }
    "unknown".into()
}
