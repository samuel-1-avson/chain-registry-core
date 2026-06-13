// crates/cli/src/diff.rs
// `creg diff <pkg>@v1 <pkg>@v2` — file-level diff between two published versions.
// Fetches both tarballs from IPFS, unpacks them, and reports:
//   - Files added / removed / changed
//   - New executables, new network calls, new eval() patterns

use anyhow::{Context, Result};
use colored::Colorize;
use std::collections::{BTreeMap, HashSet};
use std::io::Read;

pub async fn run(pkg_a: &str, pkg_b: &str, node_url: Option<&str>, json: bool) -> Result<()> {
    let base = node_url.map(String::from).unwrap_or_else(|| {
        std::env::var("CREG_NODE_URL").unwrap_or_else(|_| "http://localhost:8080".into())
    });

    let ipfs_url =
        std::env::var("CREG_IPFS_URL").unwrap_or_else(|_| "http://127.0.0.1:5001".into());

    println!(
        "{} Fetching records for {} and {}",
        "→".cyan(),
        pkg_a.bold(),
        pkg_b.bold()
    );

    let (rec_a, rec_b) = tokio::try_join!(fetch_record(pkg_a, &base), fetch_record(pkg_b, &base),)?;

    let cid_a = rec_a
        .get("ipfs_cid")
        .and_then(|v| v.as_str())
        .context("Package A has no IPFS CID")?;
    let cid_b = rec_b
        .get("ipfs_cid")
        .and_then(|v| v.as_str())
        .context("Package B has no IPFS CID")?;

    println!("{} Downloading tarballs from IPFS...", "→".cyan());
    let (tarball_a, tarball_b) = tokio::try_join!(
        fetch_from_ipfs(cid_a, &ipfs_url),
        fetch_from_ipfs(cid_b, &ipfs_url),
    )?;

    println!("{} Comparing contents...", "→".cyan());
    let files_a = extract_files(&tarball_a).context("Failed to extract package A")?;
    let files_b = extract_files(&tarball_b).context("Failed to extract package B")?;

    let diff = compute_diff(&files_a, &files_b);

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "a": pkg_a,
                "b": pkg_b,
                "added":   diff.added,
                "removed": diff.removed,
                "changed": diff.changed,
                "security_concerns": diff.security_concerns,
            }))?
        );
        return Ok(());
    }

    print_diff(&diff, pkg_a, pkg_b);
    Ok(())
}

async fn fetch_record(canonical: &str, base: &str) -> Result<serde_json::Value> {
    let url = format!(
        "{}/v1/packages/{}",
        base.trim_end_matches('/'),
        urlencoding::encode(canonical)
    );
    let resp = reqwest::Client::new()
        .get(&url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .context("Failed to reach registry node")?;

    if !resp.status().is_success() {
        anyhow::bail!("Package '{}' not found (HTTP {})", canonical, resp.status());
    }
    resp.json().await.context("Failed to parse package record")
}

async fn fetch_from_ipfs(cid: &str, ipfs_url: &str) -> Result<Vec<u8>> {
    let url = format!("{}/api/v0/cat?arg={}", ipfs_url.trim_end_matches('/'), cid);
    let bytes = reqwest::Client::new()
        .post(&url)
        .timeout(std::time::Duration::from_secs(60))
        .send()
        .await
        .context("IPFS fetch failed")?
        .bytes()
        .await
        .context("Failed to read IPFS response body")?;
    Ok(bytes.to_vec())
}

fn extract_files(tarball: &[u8]) -> Result<BTreeMap<String, Vec<u8>>> {
    let gz = flate2::read::GzDecoder::new(tarball);
    let mut archive = tar::Archive::new(gz);
    let mut files = BTreeMap::new();

    for entry in archive.entries()? {
        let mut entry = entry?;
        if entry.header().entry_type().is_file() {
            let path = entry.path()?.to_string_lossy().to_string();
            let mut content = Vec::new();
            entry.read_to_end(&mut content)?;
            files.insert(path, content);
        }
    }

    Ok(files)
}

#[derive(Debug)]
struct DiffResult {
    added: Vec<String>,
    removed: Vec<String>,
    changed: Vec<String>,
    security_concerns: Vec<String>,
}

fn compute_diff(
    files_a: &BTreeMap<String, Vec<u8>>,
    files_b: &BTreeMap<String, Vec<u8>>,
) -> DiffResult {
    let keys_a: HashSet<_> = files_a.keys().collect();
    let keys_b: HashSet<_> = files_b.keys().collect();

    let added: Vec<String> = keys_b.difference(&keys_a).map(|s| (*s).clone()).collect();
    let removed: Vec<String> = keys_a.difference(&keys_b).map(|s| (*s).clone()).collect();
    // intersection yields &&String; collect into owned Strings first, then filter
    let both: Vec<String> = keys_a.intersection(&keys_b).map(|s| (*s).clone()).collect();
    let changed: Vec<String> = both
        .iter()
        .filter(|k| files_a.get(k.as_str()) != files_b.get(k.as_str()))
        .cloned()
        .collect();

    // Security analysis: check added/changed files for suspicious patterns
    let mut concerns = Vec::new();
    let suspicious_patterns = [
        ("eval(", "eval() call"),
        ("exec(", "exec() call"),
        ("require('child_process')", "child_process usage"),
        ("require(\"child_process\")", "child_process usage"),
        ("fetch(", "network fetch call"),
        ("axios.", "axios HTTP call"),
        ("http.request", "http.request call"),
        ("fs.writeFile", "filesystem write"),
        ("Buffer.from(", "Buffer.from() (potential base64 decode)"),
        ("process.env", "environment variable access"),
        ("__dirname", "__dirname reference"),
        ("os.exec", "os.exec call"),
    ];

    for path in added.iter().chain(changed.iter()) {
        if let Some(content) = files_b.get(path) {
            if let Ok(text) = std::str::from_utf8(content) {
                for (pattern, label) in &suspicious_patterns {
                    if text.contains(pattern) {
                        concerns.push(format!("{}: {}", path, label));
                    }
                }
                // Check for newly added executable bits (heuristic: .sh, no extension + shebang)
                if path.ends_with(".sh") || (!path.contains('.') && text.starts_with("#!/")) {
                    concerns.push(format!("{}: executable script (new/changed)", path));
                }
            }
        }
    }
    concerns.sort();
    concerns.dedup();

    DiffResult {
        added,
        removed,
        changed,
        security_concerns: concerns,
    }
}

fn print_diff(diff: &DiffResult, pkg_a: &str, pkg_b: &str) {
    println!();
    println!("{} {} → {}", "diff".bold(), pkg_a.cyan(), pkg_b.cyan());
    println!("{}", "─".repeat(60).dimmed());

    if diff.added.is_empty() && diff.removed.is_empty() && diff.changed.is_empty() {
        println!("  {} Packages are identical", "✓".green());
        return;
    }

    if !diff.added.is_empty() {
        println!("\n  {} Added ({}):", "+".green().bold(), diff.added.len());
        for f in &diff.added {
            println!("    {} {}", "+".green(), f);
        }
    }

    if !diff.removed.is_empty() {
        println!("\n  {} Removed ({}):", "-".red().bold(), diff.removed.len());
        for f in &diff.removed {
            println!("    {} {}", "-".red(), f);
        }
    }

    if !diff.changed.is_empty() {
        println!(
            "\n  {} Changed ({}):",
            "~".yellow().bold(),
            diff.changed.len()
        );
        for f in &diff.changed {
            println!("    {} {}", "~".yellow(), f);
        }
    }

    if !diff.security_concerns.is_empty() {
        println!("\n  {} Security concerns:", "⚠".yellow().bold());
        for c in &diff.security_concerns {
            println!("    {} {}", "⚠".yellow(), c.yellow());
        }
    }

    println!();
}
