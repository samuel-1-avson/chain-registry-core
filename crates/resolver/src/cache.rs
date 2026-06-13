// crates/resolver/src/cache.rs
// Local sled-backed KV store for TrustVerdicts.
// Verified packages cache for 24h; Unverified/Unknown cache for 5 minutes.

use anyhow::Result;
use chrono::{Duration, Utc};
use common::{PackageId, TrustVerdict, VerdictSource, VerdictStatus};
use sled::Db;
use std::sync::OnceLock;

static DB: OnceLock<Db> = OnceLock::new();

fn db() -> Result<&'static Db> {
    DB.get_or_init(|| {
        let path = dirs::cache_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
            .join("chain-registry")
            .join("verdict-cache");
        sled::open(path).expect("Failed to open verdict cache")
    });
    Ok(DB
        .get()
        .ok_or_else(|| anyhow::anyhow!("Verdict cache not initialized"))?)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct CacheEntry {
    verdict: TrustVerdict,
    expires_at: chrono::DateTime<Utc>,
}

/// Retrieve a cached verdict. Returns None if missing or expired.
pub fn get(id: &PackageId) -> Result<Option<TrustVerdict>> {
    let db = db()?;
    let key = id.canonical();
    match db.get(key.as_bytes())? {
        None => Ok(None),
        Some(bytes) => {
            let entry: CacheEntry = serde_json::from_slice(&bytes)?;
            if Utc::now() > entry.expires_at {
                // Stale — evict and signal a miss.
                db.remove(key.as_bytes())?;
                return Ok(None);
            }
            // Patch source to indicate this is a cache hit.
            let mut v = entry.verdict;
            v.source = VerdictSource::Cache {
                expires_at: entry.expires_at,
            };
            Ok(Some(v))
        }
    }
}

/// Store a verdict with an appropriate TTL.
pub fn set(id: &PackageId, verdict: &TrustVerdict) -> Result<()> {
    let ttl = match &verdict.status {
        VerdictStatus::Verified { .. } => Duration::hours(24),
        VerdictStatus::Revoked { .. } => Duration::hours(48), // cache revocations longer
        VerdictStatus::Unverified => Duration::minutes(5),
        VerdictStatus::Unknown => Duration::minutes(5),
    };
    let expires_at = Utc::now() + ttl;
    let entry = CacheEntry {
        verdict: verdict.clone(),
        expires_at,
    };
    let bytes = serde_json::to_vec(&entry)?;
    db()?.insert(id.canonical().as_bytes(), bytes)?;
    Ok(())
}

/// Clear all entries from the local cache.
pub fn clear() -> Result<()> {
    db()?.clear()?;
    Ok(())
}

/// Print a summary of all cached entries.
pub fn print_entries() -> Result<()> {
    let db = db()?;
    println!("{:<50} {:<12} {}", "Package", "Status", "Expires");
    println!("{}", "-".repeat(90));
    for item in db.iter() {
        let (_, v) = item?;
        if let Ok(entry) = serde_json::from_slice::<CacheEntry>(&v) {
            println!(
                "{:<50} {:<12} {}",
                entry.verdict.package.canonical(),
                entry.verdict.status.label(),
                entry.expires_at.format("%Y-%m-%d %H:%M UTC")
            );
        }
    }
    Ok(())
}
