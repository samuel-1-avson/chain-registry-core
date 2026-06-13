// crates/cli/src/policy.rs
// `creg policy show` — display active insurance policies for the current key.
// `creg policy apply <file>` — enforce org-wide rules (policy-as-code).

use anyhow::{Context, Result};
use colored::Colorize;
use serde::{Deserialize, Serialize};

// ─── Policy-as-code TOML schema ───────────────────────────────────────────────

/// An org-wide installation policy loaded from a TOML file.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct PolicyFile {
    /// Human-readable description of this policy.
    #[serde(default)]
    pub description: String,

    /// Block installation of packages with these security findings.
    #[serde(default)]
    pub block_on_findings: Vec<String>,

    /// Ecosystems to enforce (empty = all).
    #[serde(default)]
    pub enforce_ecosystems: Vec<String>,

    /// Require packages to be chain-verified (not just pending).
    #[serde(default = "default_true")]
    pub require_verified: bool,

    /// Block packages published less than N days ago (0 = disabled).
    #[serde(default)]
    pub min_age_days: u32,

    /// Only allow packages by these publisher pubkey prefixes (empty = allow all).
    #[serde(default)]
    pub allowed_publishers: Vec<String>,

    /// Block packages that are not in this allowlist (empty = disable allowlist).
    #[serde(default)]
    pub allowlist: Vec<String>,

    /// Block specific packages regardless of status.
    #[serde(default)]
    pub blocklist: Vec<String>,
}

fn default_true() -> bool {
    true
}

impl PolicyFile {
    /// Load from a TOML file path.
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read policy file: {}", path.display()))?;
        toml::from_str(&raw).with_context(|| format!("Invalid policy TOML: {}", path.display()))
    }

    /// Save to the default location: ~/.creg/policy.toml
    pub fn save_default(&self) -> Result<std::path::PathBuf> {
        let path = default_policy_path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = toml::to_string_pretty(self).context("Failed to serialize policy")?;
        std::fs::write(&path, content)?;
        Ok(path)
    }

    /// Evaluate a package against this policy. Returns list of violations.
    pub fn evaluate(&self, canonical: &str, status: &str, publisher: &str) -> Vec<String> {
        let mut violations = Vec::new();

        // Blocklist
        for blocked in &self.blocklist {
            if canonical.contains(blocked.as_str()) {
                violations.push(format!("Package '{}' is in the blocklist", canonical));
            }
        }

        // Allowlist
        if !self.allowlist.is_empty() {
            let allowed = self
                .allowlist
                .iter()
                .any(|a| canonical.contains(a.as_str()));
            if !allowed {
                violations.push(format!("Package '{}' is not in the allowlist", canonical));
            }
        }

        // Verification requirement
        if self.require_verified && status != "verified" {
            violations.push(format!(
                "Package '{}' is not chain-verified (status: {})",
                canonical, status
            ));
        }

        // Publisher whitelist
        if !self.allowed_publishers.is_empty() {
            let ok = self
                .allowed_publishers
                .iter()
                .any(|p| publisher.starts_with(p.as_str()));
            if !ok {
                violations.push(format!(
                    "Publisher '{}...' is not in the allowed publishers list",
                    &publisher[..publisher.len().min(12)]
                ));
            }
        }

        violations
    }
}

fn default_policy_path() -> Result<std::path::PathBuf> {
    Ok(dirs::home_dir()
        .context("Could not determine home directory")?
        .join(".creg")
        .join("policy.toml"))
}

// ─── Commands ────────────────────────────────────────────────────────────────

pub async fn show(pubkey: Option<&str>, node_url: Option<&str>, json: bool) -> Result<()> {
    let base = node_url.map(String::from).unwrap_or_else(|| {
        std::env::var("CREG_NODE_URL").unwrap_or_else(|_| "http://localhost:8080".into())
    });

    // Show active local policy if it exists
    let policy_path = default_policy_path()?;
    if policy_path.exists() {
        let policy = PolicyFile::load(&policy_path)?;
        println!("{}", "Active policy:".bold());
        println!("  File: {}", policy_path.display().to_string().dimmed());
        println!(
            "  Desc: {}",
            if policy.description.is_empty() {
                "(none)"
            } else {
                &policy.description
            }
        );
        println!(
            "  Require verified: {}",
            if policy.require_verified {
                "yes".green()
            } else {
                "no".red()
            }
        );
        println!("  Blocklist:  {} entries", policy.blocklist.len());
        println!("  Allowlist:  {} entries", policy.allowlist.len());
        println!("  Publishers: {} entries", policy.allowed_publishers.len());
        println!("  Min age:    {} days", policy.min_age_days);
        println!();
    } else {
        println!(
            "{} No local policy file found ({})",
            "ℹ".blue(),
            policy_path.display()
        );
        println!("  Run: creg policy apply <policy.toml> — to activate a policy");
        println!();
    }

    // Optionally fetch publisher's insurance policies from node
    let key = pubkey
        .map(String::from)
        .or_else(|| std::env::var("CREG_PUBLISHER_PUBKEY").ok());

    if let Some(k) = key {
        let url = format!("{}/v1/publishers/{}", base.trim_end_matches('/'), k);
        match reqwest::Client::new()
            .get(&url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                if let Ok(data) = r.json::<serde_json::Value>().await {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&data)?);
                    } else {
                        print_publisher_info(&data);
                    }
                }
            }
            _ => {
                println!(
                    "{} Could not fetch publisher info for key {}...",
                    "ℹ".blue(),
                    &k[..k.len().min(12)]
                );
            }
        }
    }

    Ok(())
}

fn print_publisher_info(data: &serde_json::Value) {
    println!("{}", "Publisher record:".bold());
    let pkgs = data
        .get("packages_submitted")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let stake = data
        .get("stake_amount")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    println!("  Packages submitted: {}", pkgs);
    println!("  Stake:              {} ETH", stake);
}

pub async fn apply(policy_path: &std::path::Path, dry_run: bool) -> Result<()> {
    let policy = PolicyFile::load(policy_path)?;

    if dry_run {
        println!("{} Dry run — validating policy file only", "ℹ".blue());
        println!(
            "  Description:    {}",
            if policy.description.is_empty() {
                "(none)"
            } else {
                &policy.description
            }
        );
        println!("  Require verified: {}", policy.require_verified);
        println!(
            "  Blocklist ({} entries): {:?}",
            policy.blocklist.len(),
            &policy.blocklist[..policy.blocklist.len().min(3)]
        );
        println!("  {} Policy is valid.", "✓".green());
        return Ok(());
    }

    let dest = policy.save_default()?;
    println!("{} Policy applied: {}", "✓".green(), dest.display());
    println!(
        "  All future `creg install` and `creg batch install` commands will enforce this policy."
    );

    Ok(())
}

pub fn show_policy_init() -> Result<()> {
    let example = PolicyFile {
        description: "Example org policy".into(),
        require_verified: true,
        block_on_findings: vec!["Critical".into(), "High".into()],
        enforce_ecosystems: vec!["npm".into(), "pypi".into()],
        min_age_days: 7,
        allowed_publishers: vec![],
        allowlist: vec![],
        blocklist: vec![],
    };
    let content = toml::to_string_pretty(&example)?;
    println!(
        "# creg policy template — save to policy.toml and run: creg policy apply policy.toml\n"
    );
    println!("{}", content);
    Ok(())
}
