// crates/cli/src/lockfile.rs
// pkg-lock.chain — an append-only audit receipt file written alongside
// package.json / Cargo.toml / requirements.txt after every verified install.
//
// Format: newline-delimited JSON, one receipt per line (NDJSON).
// Each receipt records the package, its trust verdict, the chain block hash,
// and a local timestamp. This gives teams a cryptographic audit trail of
// every dependency that entered a project.
//
// Example entry:
//   {"canonical":"npm:express@4.18.2","status":"verified","block_hash":"4a3f1b2c...","content_hash":"sha256:abc123","ts":"2025-01-15T14:02:31Z","source":"chain"}

use anyhow::{Context, Result};
use chrono::Utc;
use common::{TrustVerdict, VerdictSource, VerdictStatus};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const LOCKFILE_NAME: &str = "pkg-lock.chain";

/// A single audit receipt entry in the lockfile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReceipt {
    pub canonical: String,
    pub status: String,
    pub block_hash: Option<String>,
    pub content_hash: Option<String>,
    pub ts: String,
    /// "chain" | "cache" | "unverified" | "revoked"
    pub source: String,
}

impl AuditReceipt {
    #[allow(dead_code)]
    pub fn from_verdict(verdict: &TrustVerdict) -> Self {
        let (status, block_hash, content_hash) = match &verdict.status {
            VerdictStatus::Verified {
                block_hash,
                content_hash,
                ..
            } => (
                "verified",
                Some(block_hash.clone()),
                Some(content_hash.clone()),
            ),
            VerdictStatus::Unverified => ("unverified", None, None),
            VerdictStatus::Revoked { .. } => ("revoked", None, None),
            VerdictStatus::Unknown => ("unknown", None, None),
        };

        let source = match &verdict.source {
            VerdictSource::Cache { .. } => "cache",
            VerdictSource::Chain { .. } => "chain",
        };

        Self {
            canonical: verdict.package.canonical(),
            status: status.to_string(),
            block_hash,
            content_hash,
            ts: Utc::now().to_rfc3339(),
            source: source.to_string(),
        }
    }
}

/// Append an audit receipt for `verdict` to the lockfile in `project_dir`.
/// Creates the file if it doesn't exist.
#[allow(dead_code)]
pub fn write_receipt(project_dir: &Path, verdict: &TrustVerdict) -> Result<()> {
    let path = find_lockfile_path(project_dir);
    let receipt = AuditReceipt::from_verdict(verdict);
    let line = serde_json::to_string(&receipt).context("Failed to serialise audit receipt")?;

    let mut content = if path.exists() {
        std::fs::read_to_string(&path).context("Failed to read existing lockfile")?
    } else {
        format!("# pkg-lock.chain — chain registry audit receipts\n# Do not edit manually. Commit this file alongside your lockfile.\n")
    };

    // Avoid duplicate entries for the same canonical + block_hash.
    if !content.contains(&format!("\"canonical\":\"{}\"", receipt.canonical)) {
        content.push_str(&line);
        content.push('\n');
        std::fs::write(&path, &content).context("Failed to write lockfile")?;
    }

    Ok(())
}

/// Read all receipts from the lockfile in `project_dir`.
pub fn read_receipts(project_dir: &Path) -> Result<Vec<AuditReceipt>> {
    let path = find_lockfile_path(project_dir);
    if !path.exists() {
        return Ok(vec![]);
    }

    let content = std::fs::read_to_string(&path)?;
    let mut receipts = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Ok(receipt) = serde_json::from_str::<AuditReceipt>(line) {
            receipts.push(receipt);
        }
    }

    Ok(receipts)
}

/// Find the project root's lockfile path.
/// Walks up from `project_dir` until it finds a package manifest.
fn find_lockfile_path(start: &Path) -> PathBuf {
    let mut dir = start.to_path_buf();
    loop {
        let markers = [
            "package.json",
            "Cargo.toml",
            "requirements.txt",
            "Gemfile",
            "pom.xml",
        ];
        if markers.iter().any(|m| dir.join(m).exists()) {
            return dir.join(LOCKFILE_NAME);
        }
        if !dir.pop() {
            break;
        }
    }
    // Fallback: write in the starting directory.
    start.join(LOCKFILE_NAME)
}

/// Print a formatted summary of the lockfile contents.
pub fn print_lockfile(project_dir: &Path) -> Result<()> {
    let receipts = read_receipts(project_dir)?;
    if receipts.is_empty() {
        println!("No audit receipts found. Install packages with `creg install` to populate.");
        return Ok(());
    }

    let path = find_lockfile_path(project_dir);
    println!("\n  {} ({})\n", LOCKFILE_NAME, path.display());
    println!("  {:<55} {:<12} {}", "Package", "Status", "Block hash");
    println!("  {}", "─".repeat(85));

    for r in &receipts {
        let block = r
            .block_hash
            .as_deref()
            .map(|h| &h[..std::cmp::min(12, h.len())])
            .unwrap_or("—");
        let status_colored = match r.status.as_str() {
            "verified" => format!("\x1b[32m{:<12}\x1b[0m", r.status),
            "revoked" => format!("\x1b[31m{:<12}\x1b[0m", r.status),
            "unverified" => format!("\x1b[33m{:<12}\x1b[0m", r.status),
            _ => format!("{:<12}", r.status),
        };
        println!("  {:<55} {} {}", r.canonical, status_colored, block);
    }

    println!("\n  {} total receipts\n", receipts.len());
    Ok(())
}

/// Diff the local lockfile against current chain state.
/// Reports packages that have been revoked or changed since the lockfile was written.
pub async fn diff(project_dir: &Path, node_url: Option<&str>) -> Result<()> {
    use colored::Colorize;

    let receipts = read_receipts(project_dir)?;
    if receipts.is_empty() {
        println!("{} No receipts in lockfile to diff.", "ℹ".blue());
        return Ok(());
    }

    let base = node_url.map(String::from).unwrap_or_else(|| {
        std::env::var("CREG_NODE_URL").unwrap_or_else(|_| "http://localhost:8080".into())
    });

    println!(
        "{} Diffing {} lockfile entries against chain...",
        "→".cyan(),
        receipts.len()
    );

    let client = reqwest::Client::new();
    let mut drifted = 0usize;

    for receipt in &receipts {
        let url = format!(
            "{}/v1/packages/{}",
            base.trim_end_matches('/'),
            urlencoding::encode(&receipt.canonical)
        );

        let chain_status = match client
            .get(&url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => r
                .json::<serde_json::Value>()
                .await
                .ok()
                .and_then(|v| v.get("status").and_then(|s| s.as_str()).map(String::from))
                .unwrap_or_else(|| "unknown".into()),
            _ => "unreachable".into(),
        };

        let local_status = receipt.status.as_str();
        let chain_changed = chain_status != local_status && chain_status != "unreachable";
        let now_revoked = chain_status == "revoked" && local_status != "revoked";

        if now_revoked {
            println!(
                "  {} {} — {} locally, {} on chain",
                "⚠".red().bold(),
                receipt.canonical.white().bold(),
                local_status.green(),
                "REVOKED".red().bold()
            );
            drifted += 1;
        } else if chain_changed {
            println!(
                "  {} {} — {} → {}",
                "~".yellow(),
                receipt.canonical,
                local_status.dimmed(),
                chain_status.yellow()
            );
            drifted += 1;
        } else {
            println!("  {} {}", "✓".green(), receipt.canonical.dimmed());
        }
    }

    println!();
    if drifted == 0 {
        println!("{} Lockfile is in sync with chain.", "✓".green().bold());
    } else {
        println!(
            "{} {} package(s) have drifted from the lockfile.",
            "⚠".yellow().bold(),
            drifted
        );
        println!("  Run: creg audit --fix  to remediate automatically.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use common::{PackageId, TrustVerdict, VerdictSource, VerdictStatus};
    use tempfile::TempDir;

    fn make_verdict(name: &str, verified: bool) -> TrustVerdict {
        let id = PackageId::new("npm", name, "1.0.0");
        let status = if verified {
            VerdictStatus::Verified {
                block_hash: "a".repeat(64),
                content_hash: "b".repeat(64),
                ipfs_cid: String::new(),
                findings: vec![],
            }
        } else {
            VerdictStatus::Unverified
        };
        TrustVerdict {
            package: id,
            status,
            resolved_at: Utc::now(),
            source: VerdictSource::Chain {
                node_url: "http://localhost".into(),
            },
            deterministic_risk: None,
        }
    }

    #[test]
    fn write_and_read_receipt() {
        let dir = TempDir::new().unwrap();
        // Create a package.json so find_lockfile_path resolves here.
        std::fs::write(dir.path().join("package.json"), "{}").unwrap();

        let verdict = make_verdict("express", true);
        write_receipt(dir.path(), &verdict).unwrap();

        let receipts = read_receipts(dir.path()).unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].canonical, "npm:express@1.0.0");
        assert_eq!(receipts[0].status, "verified");
    }

    #[test]
    fn no_duplicate_entries() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("package.json"), "{}").unwrap();

        let verdict = make_verdict("lodash", true);
        write_receipt(dir.path(), &verdict).unwrap();
        write_receipt(dir.path(), &verdict).unwrap(); // write again

        let receipts = read_receipts(dir.path()).unwrap();
        assert_eq!(receipts.len(), 1, "Should not write duplicate receipts");
    }

    #[test]
    fn multiple_packages() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "[package]").unwrap();

        for name in &["serde", "tokio", "anyhow"] {
            let verdict = make_verdict(name, true);
            write_receipt(dir.path(), &verdict).unwrap();
        }

        let receipts = read_receipts(dir.path()).unwrap();
        assert_eq!(receipts.len(), 3);
    }
}
