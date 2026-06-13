// crates/node/src/chain_spec_boot.rs
// Chain spec resolution: fetch → cache → validate → apply.

/// Resolve a chain spec from network or cache.
///
/// 1. If `url` is provided and `offline` is false, fetch from network with retry.
/// 2. On fetch success, validate JSON parse and cache to disk.
/// 3. On fetch failure (or offline), fall back to cached copy.
/// 4. If no cache exists, return an error.
pub async fn resolve_chain_spec(
    url: Option<&str>,
    data_dir: &std::path::PathBuf,
    offline: bool,
) -> anyhow::Result<common::ChainSpec> {
    let cache_path = data_dir.join("chain-spec.cached.json");

    // Try network fetch first (unless offline)
    if !offline {
        if let Some(url) = url {
            match fetch_with_retry(url, 3).await {
                Ok(json) => {
                    let spec: common::ChainSpec = serde_json::from_str(&json)
                        .map_err(|e| anyhow::anyhow!("Failed to parse fetched spec: {}", e))?;
                    // Cache for next boot
                    if let Err(e) = tokio::fs::write(&cache_path, &json).await {
                        tracing::warn!(
                            "Failed to cache chain spec to {}: {}",
                            cache_path.display(),
                            e
                        );
                    }
                    return Ok(spec);
                }
                Err(e) => {
                    tracing::warn!("Failed to fetch chain spec from {}: {}", url, e);
                }
            }
        }
    }

    // Fallback to cache
    if cache_path.exists() {
        let json = tokio::fs::read_to_string(&cache_path)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read cached spec: {}", e))?;
        let spec: common::ChainSpec = serde_json::from_str(&json)
            .map_err(|e| anyhow::anyhow!("Failed to parse cached spec: {}", e))?;
        tracing::warn!(
            "Using cached chain spec from {} (network fetch failed or offline)",
            cache_path.display()
        );
        return Ok(spec);
    }

    anyhow::bail!(
        "No chain spec available. Set CREG_CHAIN_SPEC_URL or CREG_CHAIN_SPEC_OFFLINE=true with a cached spec."
    )
}

/// Fetch a URL with exponential backoff retry.
async fn fetch_with_retry(url: &str, max_retries: u32) -> anyhow::Result<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    for attempt in 1..=max_retries {
        match client.get(url).send().await {
            Ok(resp) if resp.status().is_success() => {
                return Ok(resp.text().await?);
            }
            Ok(resp) => {
                tracing::warn!(
                    "Chain spec fetch attempt {}/{}: HTTP {}",
                    attempt,
                    max_retries,
                    resp.status()
                );
            }
            Err(e) => {
                tracing::warn!(
                    "Chain spec fetch attempt {}/{}: {}",
                    attempt,
                    max_retries,
                    e
                );
            }
        }
        let delay = std::time::Duration::from_secs(2u64.pow((attempt - 1).min(4)));
        tokio::time::sleep(delay).await;
    }

    anyhow::bail!("Failed to fetch chain spec after {} retries", max_retries)
}

/// Fetch the detached signature for a chain spec.
pub async fn fetch_spec_signature(url: &str) -> anyhow::Result<String> {
    let client = reqwest::Client::new();
    let resp = client.get(url).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("HTTP {} fetching signature", resp.status());
    }
    Ok(resp.text().await?.trim().to_string())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fetch_with_retry_hits_mock_server() {
        // This test requires a mock HTTP server; placeholder for now.
        // In practice, use wiremock or a local tokio::net::TcpListener.
    }

    #[test]
    fn test_cache_path_construction() {
        let dir = std::path::PathBuf::from("/tmp/creg");
        let path = dir.join("chain-spec.cached.json");
        assert_eq!(
            path,
            std::path::PathBuf::from("/tmp/creg/chain-spec.cached.json")
        );
    }
}
