// crates/resolver/src/lib.rs
// Resolves a package name/ID to a TrustVerdict.
// Cache-first: checks the local sled DB, then hits the chain node.

pub mod cache;
mod chain_client;
pub mod downloader;

use anyhow::Result;
use chrono::Utc;
use common::{PackageId, TrustVerdict, VerdictSource, VerdictStatus};

/// Resolve "name@version" or "name" in the given ecosystem.
pub async fn resolve(
    raw: &str,
    ecosystem: Option<&str>,
    node_url: Option<&str>,
) -> Result<TrustVerdict> {
    let (name, version) = parse_pkg(raw);
    let eco = ecosystem.unwrap_or("npm");
    let id = PackageId::new(eco, name, version.as_deref().unwrap_or("latest"));
    resolve_id(&id, node_url).await
}

/// Resolve a fully-formed PackageId.
pub async fn resolve_id(id: &PackageId, node_url: Option<&str>) -> Result<TrustVerdict> {
    // ── 1. Check local TTL cache ──────────────────────────────────────────────
    if let Some(cached) = cache::get(id)? {
        tracing::debug!("cache hit for {}", id.canonical());
        return Ok(cached);
    }

    // ── 2. Query live chain node ──────────────────────────────────────────────
    let url = node_url
        .map(String::from)
        .unwrap_or_else(|| default_node_url());

    let verdict = match chain_client::fetch_verdict(id, &url).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("chain node unreachable ({}): returning Unknown", e);
            TrustVerdict {
                package: id.clone(),
                status: VerdictStatus::Unknown,
                resolved_at: Utc::now(),
                source: VerdictSource::Chain { node_url: url },
                deterministic_risk: None,
            }
        }
    };

    // ── 3. Write to cache ─────────────────────────────────────────────────────
    cache::set(id, &verdict)?;

    Ok(verdict)
}

fn parse_pkg(raw: &str) -> (String, Option<String>) {
    // Strip ecosystem prefix if present (e.g. "npm:express" -> "express")
    let mut clean = raw;
    for eco in &["npm:", "pypi:", "cargo:", "rubygems:", "maven:"] {
        if raw.starts_with(eco) {
            clean = &raw[eco.len()..];
            break;
        }
    }

    if clean.starts_with('@') {
        let rest = &clean[1..];
        if let Some(idx) = rest.rfind('@') {
            return (
                format!("@{}", &rest[..idx]),
                Some(rest[idx + 1..].to_string()),
            );
        }
        return (clean.to_string(), None);
    }
    match clean.rfind('@') {
        Some(idx) => (clean[..idx].to_string(), Some(clean[idx + 1..].to_string())),
        None => (clean.to_string(), None),
    }
}

fn default_node_url() -> String {
    std::env::var("CREG_NODE_URL").unwrap_or_else(|_| "http://localhost:8080".into())
}

pub mod light_client;

use light_client::{verify_package, Checkpoint};

/// Resolve a package using light-client SPV verification.
/// Provides stronger guarantees than trusting the node's verdict directly,
/// at the cost of one extra round-trip for the Merkle proof.
pub async fn resolve_verified(
    id: &common::PackageId,
    node_url: Option<&str>,
    checkpoint: Option<&Checkpoint>,
) -> anyhow::Result<common::TrustVerdict> {
    let url = node_url.map(String::from).unwrap_or_else(|| {
        std::env::var("CREG_NODE_URL").unwrap_or_else(|_| "http://localhost:8080".into())
    });
    let cp = checkpoint.cloned().unwrap_or_else(Checkpoint::genesis);

    // First get the standard verdict (fast path via cache).
    let verdict = resolve_id(id, Some(&url)).await?;

    // If verified, additionally validate via Merkle proof.
    if verdict.status.is_safe() {
        match verify_package(&id.canonical(), &url, &cp).await {
            Ok(true) => Ok(verdict),
            Ok(false) => {
                tracing::warn!(
                    "Light-client proof failed for {} — downgrading to Unknown",
                    id.canonical()
                );
                Ok(common::TrustVerdict {
                    status: common::VerdictStatus::Unknown,
                    ..verdict
                })
            }
            Err(e) => {
                tracing::warn!(
                    "Light-client proof error for {}: {} — using standard verdict",
                    id.canonical(),
                    e
                );
                Ok(verdict) // Fall back to standard verdict on proof error.
            }
        }
    } else {
        Ok(verdict)
    }
}
