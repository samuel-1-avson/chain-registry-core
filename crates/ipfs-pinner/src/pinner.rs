//! IPFS pinning implementation

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Configuration for the IPFS pinner
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PinnerConfig {
    /// IPFS API endpoint
    pub ipfs_api_url: String,
    /// Local cache directory
    pub cache_dir: PathBuf,
    /// Maximum cache size (bytes)
    pub max_cache_size: u64,
    /// Whether to pin recursively
    pub recursive: bool,
    /// IPFS timeout (seconds)
    pub timeout: u64,
}

impl Default for PinnerConfig {
    fn default() -> Self {
        Self {
            ipfs_api_url: "http://localhost:5001".to_string(),
            cache_dir: PathBuf::from("./ipfs_cache"),
            max_cache_size: 10 * 1024 * 1024 * 1024, // 10GB
            recursive: true,
            timeout: 300,
        }
    }
}

/// Interface for IPFS pinning operations
#[async_trait]
pub trait IpfsPinner: Send + Sync {
    /// Pin a CID to the local IPFS node
    async fn pin(&self, cid: &str) -> Result<()>;

    /// Unpin a CID
    async fn unpin(&self, cid: &str) -> Result<()>;

    /// Check if a CID is pinned locally
    async fn is_pinned(&self, cid: &str) -> Result<bool>;

    /// Get the size of a CID
    async fn get_size(&self, cid: &str) -> Result<u64>;

    /// Fetch content from IPFS
    async fn fetch(&self, cid: &str) -> Result<Vec<u8>>;

    /// Get local pinning statistics
    async fn get_stats(&self) -> Result<PinnerStats>;
}

/// Statistics about the local IPFS node
#[derive(Debug, Clone, Default)]
pub struct PinnerStats {
    pub total_pins: usize,
    pub total_size: u64,
    pub repo_size: u64,
    pub repo_path: String,
    pub version: String,
}

/// IPFS API client implementation
pub struct IpfsApiPinner {
    config: PinnerConfig,
    client: reqwest::Client,
}

impl IpfsApiPinner {
    pub fn new(config: PinnerConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout))
            .build()
            .expect("Failed to build HTTP client");

        Self { config, client }
    }

    fn api_url(&self, endpoint: &str) -> String {
        format!("{}{}", self.config.ipfs_api_url, endpoint)
    }
}

#[async_trait]
impl IpfsPinner for IpfsApiPinner {
    async fn pin(&self, cid: &str) -> Result<()> {
        tracing::info!("Pinning CID: {}", cid);
        let recursive = self.config.recursive.to_string();

        let url = self.api_url("/api/v0/pin/add");
        let response = self
            .client
            .post(&url)
            .query(&[("arg", cid), ("recursive", recursive.as_str())])
            .send()
            .await
            .context("Failed to send pin request")?;

        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            anyhow::bail!("IPFS pin failed: {}", error);
        }

        tracing::info!("Successfully pinned CID: {}", cid);
        Ok(())
    }

    async fn unpin(&self, cid: &str) -> Result<()> {
        tracing::info!("Unpinning CID: {}", cid);
        let recursive = self.config.recursive.to_string();

        let url = self.api_url("/api/v0/pin/rm");
        let response = self
            .client
            .post(&url)
            .query(&[("arg", cid), ("recursive", recursive.as_str())])
            .send()
            .await
            .context("Failed to send unpin request")?;

        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            anyhow::bail!("IPFS unpin failed: {}", error);
        }

        tracing::info!("Successfully unpinned CID: {}", cid);
        Ok(())
    }

    async fn is_pinned(&self, cid: &str) -> Result<bool> {
        let url = self.api_url("/api/v0/pin/ls");
        let response = self
            .client
            .post(&url)
            .query(&[("arg", cid), ("type", "all")])
            .send()
            .await
            .context("Failed to list pins")?;

        if !response.status().is_success() {
            return Ok(false);
        }

        // Parse JSON response and check for exact CID match in the Keys map.
        // The /pin/ls response is: {"Keys": {"<cid>": {"Type": "..."}}}
        let data: serde_json::Value = response.json().await.unwrap_or(serde_json::Value::Null);
        Ok(data
            .get("Keys")
            .and_then(|k| k.as_object())
            .map(|keys| keys.contains_key(cid))
            .unwrap_or(false))
    }

    async fn get_size(&self, cid: &str) -> Result<u64> {
        let url = self.api_url("/api/v0/object/stat");
        let response = self
            .client
            .post(&url)
            .query(&[("arg", cid)])
            .send()
            .await
            .context("Failed to stat CID")?;

        if !response.status().is_success() {
            anyhow::bail!("Failed to get size for CID: {}", cid);
        }

        let data: serde_json::Value = response.json().await?;
        let size = data["Size"]
            .as_u64()
            .or_else(|| data["CumulativeSize"].as_u64())
            .unwrap_or(0);

        Ok(size)
    }

    async fn fetch(&self, cid: &str) -> Result<Vec<u8>> {
        let url = self.api_url("/api/v0/cat");
        let response = self
            .client
            .post(&url)
            .query(&[("arg", cid)])
            .send()
            .await
            .context("Failed to fetch CID")?;

        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            anyhow::bail!("IPFS cat failed: {}", error);
        }

        let bytes = response.bytes().await?;
        Ok(bytes.to_vec())
    }

    async fn get_stats(&self) -> Result<PinnerStats> {
        let url = self.api_url("/api/v0/repo/stat");
        let response = self
            .client
            .post(&url)
            .send()
            .await
            .context("Failed to get repo stats")?;

        let data: serde_json::Value = response.json().await?;

        let stats = PinnerStats {
            total_pins: 0, // Would need separate pin/ls call
            total_size: data["Size"].as_u64().unwrap_or(0),
            repo_size: data["RepoSize"].as_u64().unwrap_or(0),
            repo_path: data["Path"].as_str().unwrap_or("").to_string(),
            version: String::new(),
        };

        Ok(stats)
    }
}

/// Mock implementation for testing
pub struct MockPinner {
    pins: std::sync::Arc<tokio::sync::RwLock<std::collections::HashMap<String, Vec<u8>>>>,
}

impl MockPinner {
    pub fn new() -> Self {
        Self {
            pins: std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        }
    }
}

#[async_trait]
impl IpfsPinner for MockPinner {
    async fn pin(&self, cid: &str) -> Result<()> {
        tracing::debug!("Mock pin: {}", cid);
        let mut pins = self.pins.write().await;
        pins.entry(cid.to_string()).or_insert_with(Vec::new);
        Ok(())
    }

    async fn unpin(&self, cid: &str) -> Result<()> {
        tracing::debug!("Mock unpin: {}", cid);
        let mut pins = self.pins.write().await;
        pins.remove(cid);
        Ok(())
    }

    async fn is_pinned(&self, cid: &str) -> Result<bool> {
        let pins = self.pins.read().await;
        Ok(pins.contains_key(cid))
    }

    async fn get_size(&self, cid: &str) -> Result<u64> {
        let pins = self.pins.read().await;
        Ok(pins.get(cid).map(|v| v.len() as u64).unwrap_or(0))
    }

    async fn fetch(&self, cid: &str) -> Result<Vec<u8>> {
        let pins = self.pins.read().await;
        pins.get(cid)
            .cloned()
            .context("CID not found in mock storage")
    }

    async fn get_stats(&self) -> Result<PinnerStats> {
        let pins = self.pins.read().await;
        let total_size: u64 = pins.values().map(|v| v.len() as u64).sum();

        Ok(PinnerStats {
            total_pins: pins.len(),
            total_size,
            repo_size: total_size,
            repo_path: "/mock".to_string(),
            version: "mock-0.1.0".to_string(),
        })
    }
}
