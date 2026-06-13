// crates/cli/src/update.rs
// `creg update` — self-update the CLI binary from the chain registry release artifact.

use anyhow::{Context, Result};
use colored::Colorize;
use sha2::{Digest, Sha256};

pub async fn run(node_url: Option<&str>, check_only: bool) -> Result<()> {
    let base = node_url.map(String::from).unwrap_or_else(|| {
        std::env::var("CREG_NODE_URL").unwrap_or_else(|_| "http://localhost:8080".into())
    });

    let current_version = env!("CARGO_PKG_VERSION");
    println!(
        "{} Checking for creg updates (current: v{})...",
        "→".cyan(),
        current_version
    );

    let releases_url = format!("{}/v1/releases/cli/latest", base.trim_end_matches('/'));
    let client = reqwest::Client::new();

    let resp = client
        .get(&releases_url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => match r.json::<serde_json::Value>().await {
            Ok(release) => {
                let latest = release
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let download_url = release
                    .get("download_url")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if latest == current_version {
                    println!("{} Already up to date (v{})", "✓".green(), current_version);
                    return Ok(());
                }

                println!("{} New version available: v{}", "⬆".yellow().bold(), latest);
                println!("  Current: v{}", current_version);
                println!("  Latest:  v{}", latest);

                if check_only {
                    println!("\n  Run: creg update  (without --check) to install");
                    return Ok(());
                }

                if download_url.is_empty() {
                    anyhow::bail!("No download URL in release record");
                }

                let expected_checksum = release
                    .get("sha256")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                install_update(download_url, latest, expected_checksum.as_deref()).await?;
            }
            Err(_) => {
                println!("{} Could not parse release response", "⚠".yellow());
            }
        },
        Ok(r) if r.status() == 404 => {
            // Node does not host releases — fall back to GitHub releases API
            println!(
                "{} Node does not host releases. Checking GitHub...",
                "ℹ".blue()
            );
            check_github_releases(current_version, check_only).await?;
        }
        Ok(r) => {
            println!(
                "{} Could not check for updates: HTTP {}",
                "⚠".yellow(),
                r.status()
            );
        }
        Err(e) => {
            println!("{} Could not reach update server: {}", "⚠".yellow(), e);
            println!("  You can manually download releases from the registry node.");
        }
    }

    Ok(())
}

async fn check_github_releases(current_version: &str, check_only: bool) -> Result<()> {
    // Placeholder — in a real deployment this would hit the project's GitHub API
    println!("{} No automatic update path configured.", "ℹ".blue());
    println!("  Current version: v{}", current_version);
    println!("  Set CREG_NODE_URL to a node that hosts CLI releases, or update manually.");
    if !check_only {
        println!("  Build from source: cargo install --git <repo-url> chain-registry-cli");
    }
    Ok(())
}

async fn install_update(
    download_url: &str,
    version: &str,
    expected_sha256: Option<&str>,
) -> Result<()> {
    use indicatif::{ProgressBar, ProgressStyle};

    println!("{} Downloading creg v{}...", "→".cyan(), version);

    let client = reqwest::Client::new();
    let resp = client
        .get(download_url)
        .timeout(std::time::Duration::from_secs(120))
        .send()
        .await
        .context("Failed to download update")?;

    let total = resp.content_length().unwrap_or(0);
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .context("Invalid progress bar template")?
            .progress_chars("#>-"),
    );

    let mut bytes = Vec::new();
    use futures::StreamExt;
    let mut byte_stream = resp.bytes_stream();
    while let Some(chunk) = byte_stream.next().await {
        let chunk = chunk.context("Error reading update stream")?;
        pb.inc(chunk.len() as u64);
        bytes.extend_from_slice(&chunk);
    }
    pb.finish_with_message("Download complete");

    // Verify SHA-256 checksum if the release provided one
    let actual_hash = hex::encode(Sha256::digest(&bytes));
    match expected_sha256 {
        Some(expected) => {
            if actual_hash != expected.to_lowercase() {
                anyhow::bail!(
                    "Checksum mismatch!\n  Expected: {}\n  Actual:   {}\nDownload may be corrupted or tampered with. Aborting.",
                    expected, actual_hash
                );
            }
            println!(
                "  {} SHA-256 checksum verified: {}",
                "✓".green(),
                &actual_hash[..16]
            );
        }
        None => {
            println!(
                "  {} No checksum in release metadata — skipping verification",
                "⚠".yellow()
            );
            println!("    SHA-256: {}", actual_hash);
        }
    }

    // Write to a temp path then replace the current executable
    let current_exe =
        std::env::current_exe().context("Cannot determine current executable path")?;
    let tmp_path = current_exe.with_extension("update.tmp");

    std::fs::write(&tmp_path, &bytes).context("Failed to write update binary")?;

    // Make executable on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o755))?;
    }

    // Atomic replace
    std::fs::rename(&tmp_path, &current_exe)
        .context("Failed to replace binary — try running with elevated permissions")?;

    println!("{} creg updated to v{}!", "✓".green().bold(), version);
    println!("  Restart your shell or run `creg --version` to confirm.");

    Ok(())
}
