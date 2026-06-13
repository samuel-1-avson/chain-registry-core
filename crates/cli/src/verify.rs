// crates/cli/src/verify.rs
// `creg verify` — cryptographically verify a package using SPV-style
// Merkle inclusion proofs without trusting the node's response blindly.

use anyhow::Result;
use colored::Colorize;
use common::{PackageId, VerdictStatus};
use resolver::light_client::{verify_package, Checkpoint};

pub async fn run(
    package: &str,
    ecosystem: Option<&str>,
    node_url: Option<&str>,
    checkpoint: Option<&str>,
    json_out: bool,
) -> Result<()> {
    let (name, version) = parse_pkg(package);
    let eco = ecosystem.unwrap_or_else(|| detect_eco());
    let id = PackageId::new(eco, &name, version.as_deref().unwrap_or("latest"));

    let url = node_url.map(String::from).unwrap_or_else(|| {
        std::env::var("CREG_NODE_URL").unwrap_or_else(|_| "http://localhost:8080".into())
    });

    // Load checkpoint from file or use genesis.
    let cp = match checkpoint {
        Some(path) => {
            let raw = std::fs::read_to_string(path)?;
            serde_json::from_str::<Checkpoint>(&raw)?
        }
        None => Checkpoint::genesis(),
    };

    println!(
        "\n  {} Light-client verification for {}",
        "→".cyan(),
        id.canonical().white().bold()
    );
    println!("  {} Node:       {}", "·".dimmed(), url.dimmed());
    println!("  {} Checkpoint: height={}", "·".dimmed(), cp.height);

    // First get standard verdict (for the status field).
    let verdict = resolver::resolve_id(&id, Some(&url)).await?;

    if !verdict.status.is_safe() {
        if json_out {
            println!(
                "{}",
                serde_json::json!({
                    "canonical": id.canonical(),
                    "verified":  false,
                    "status":    format!("{:?}", verdict.status),
                })
            );
        } else {
            println!(
                "\n  {} {} — status: {}",
                "✗".red().bold(),
                id.canonical().red(),
                verdict.status.label().red()
            );
            if let VerdictStatus::Revoked { reason, .. } = &verdict.status {
                println!("  {} Reason: {}", "·".dimmed(), reason.red());
            }
        }
        return Ok(());
    }

    // Fetch and verify the Merkle inclusion proof.
    print!("  {} Fetching Merkle proof...", "·".dimmed());
    match verify_package(&id.canonical(), &url, &cp).await {
        Ok(true) => {
            if json_out {
                println!(
                    "{}",
                    serde_json::json!({
                        "canonical": id.canonical(),
                        "verified":  true,
                        "proof":     "merkle-inclusion-verified",
                    })
                );
            } else {
                println!(
                    "\r  {} {} — Merkle proof verified ✓     ",
                    "✓".green().bold(),
                    id.canonical().green().bold()
                );
                println!(
                    "  {}",
                    "Package is cryptographically confirmed on chain.".dimmed()
                );
            }
        }
        Ok(false) => {
            println!(
                "\r  {} {} — Merkle proof FAILED ✗     ",
                "✗".red().bold(),
                id.canonical().red()
            );
            println!(
                "  {}",
                "The node's verdict could not be proven via Merkle inclusion.".red()
            );
            println!(
                "  {}",
                "The node may be dishonest or serving stale data.".red()
            );
            anyhow::bail!("Light-client verification failed");
        }
        Err(e) => {
            println!(
                "\r  {} Proof unavailable — {}     ",
                "✗".red(),
                e.to_string().dimmed()
            );
            println!(
                "  {}",
                "Cannot verify package without Merkle proof. Failing closed.".red()
            );
            println!(
                "  {}",
                "Use --allow-unverified to accept unproven verdicts.".dimmed()
            );
            anyhow::bail!("Merkle proof unavailable — cannot verify package integrity");
        }
    }

    println!();
    Ok(())
}

fn parse_pkg(raw: &str) -> (String, Option<String>) {
    if raw.starts_with('@') {
        let rest = &raw[1..];
        if let Some(idx) = rest.rfind('@') {
            return (
                format!("@{}", &rest[..idx]),
                Some(rest[idx + 1..].to_string()),
            );
        }
        return (raw.to_string(), None);
    }
    match raw.rfind('@') {
        Some(idx) => (raw[..idx].to_string(), Some(raw[idx + 1..].to_string())),
        None => (raw.to_string(), None),
    }
}

fn detect_eco() -> &'static str {
    let cwd = std::env::current_dir().unwrap_or_default();
    if cwd.join("package.json").exists() {
        return "npm";
    }
    if cwd.join("Cargo.toml").exists() {
        return "cargo";
    }
    if cwd.join("requirements.txt").exists() {
        return "pypi";
    }
    if cwd.join("Gemfile").exists() {
        return "rubygems";
    }
    "npm"
}
