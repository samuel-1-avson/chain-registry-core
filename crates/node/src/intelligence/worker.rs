use std::path::PathBuf;
use std::time::Duration;

use common::{ChainRecord, IntelligenceStatus, PackageIntelligenceReport, Transaction};
use tracing::{info, warn};

use super::IntelligenceStore;

const MAX_IPFS_BYTES: u64 = 512 * 1024 * 1024;

pub fn intelligence_enabled() -> bool {
    std::env::var("CREG_INTELLIGENCE_ENABLED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

pub fn intelligence_auto_enabled() -> bool {
    std::env::var("CREG_INTELLIGENCE_AUTO")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true)
}

pub fn schedule_for_block(block: &common::Block, data_dir: PathBuf, ipfs_url: Option<String>) {
    if !intelligence_enabled() || !intelligence_auto_enabled() {
        return;
    }

    for tx in &block.transactions {
        let Transaction::Publish(record) = tx else {
            continue;
        };
        if !matches!(record.status, common::PackageStatus::Verified) {
            continue;
        }
        let record = record.clone();
        let data_dir = data_dir.clone();
        let ipfs_url = ipfs_url.clone();
        tokio::spawn(async move {
            if let Err(error) = generate_and_store(&record, &data_dir, ipfs_url.as_deref()).await {
                warn!(
                    "{} intelligence generation failed: {}",
                    record.id.canonical(),
                    error
                );
            }
        });
    }
}

pub async fn generate_and_store(
    record: &ChainRecord,
    data_dir: &std::path::Path,
    ipfs_url: Option<&str>,
) -> anyhow::Result<PackageIntelligenceReport> {
    let store = IntelligenceStore::new(data_dir);
    let canonical = record.id.canonical();

    if let Some(existing) = store.get_by_content_hash(&record.content_hash) {
        if matches!(
            existing.status,
            IntelligenceStatus::Ready | IntelligenceStatus::Degraded
        ) {
            info!("{} intelligence cache hit", canonical);
            return Ok(existing);
        }
    }

    let pending = PackageIntelligenceReport::pending(&canonical, &record.content_hash);
    let _ = store.put(&pending);

    let ipfs_url = ipfs_url
        .filter(|u| !u.is_empty())
        .ok_or_else(|| anyhow::anyhow!("CREG_IPFS_URL not configured"))?;

    let tarball = fetch_ipfs(&record.ipfs_cid, ipfs_url).await?;
    let mut report = validator::intelligence::generate_report(record, &tarball).await;
    store.put(&report)?;
    info!(
        "{} intelligence report stored (status={:?})",
        canonical, report.status
    );
    Ok(report)
}

async fn fetch_ipfs(cid: &str, ipfs_url: &str) -> anyhow::Result<Vec<u8>> {
    let url = format!("{}/api/v0/cat?arg={}", ipfs_url.trim_end_matches('/'), cid);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(300))
        .build()?;
    let response = client.post(&url).send().await?;
    if !response.status().is_success() {
        anyhow::bail!("IPFS HTTP {} for CID {}", response.status(), cid);
    }
    if let Some(len) = response.content_length() {
        if len > MAX_IPFS_BYTES {
            anyhow::bail!("IPFS object too large for intelligence worker");
        }
    }
    let bytes = response.bytes().await?.to_vec();
    if bytes.len() as u64 > MAX_IPFS_BYTES {
        anyhow::bail!("IPFS object exceeded max size after download");
    }
    Ok(bytes)
}
