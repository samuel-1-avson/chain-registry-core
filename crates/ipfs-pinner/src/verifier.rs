//! IPFS content verification system

use anyhow::{Context, Result};
use async_trait::async_trait;
use sha2::{Digest, Sha256};

/// Result of a verification check
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Whether the content is available
    pub is_available: bool,
    /// Response time in milliseconds
    pub response_time_ms: u64,
    /// Content size in bytes (if available)
    pub content_size: Option<u64>,
    /// Hash of verification proof data
    pub proof_hash: [u8; 32],
    /// Number of peers providing the content
    pub provider_count: u32,
    /// Error message if verification failed
    pub error: Option<String>,
}

/// Interface for content verification
#[async_trait]
pub trait Verifier: Send + Sync {
    /// Verify that a CID is available on the network
    async fn verify(&self, cid: &str) -> Result<VerificationResult>;

    /// Verify with a specific timeout
    async fn verify_with_timeout(&self, cid: &str, timeout_secs: u64)
        -> Result<VerificationResult>;

    /// Batch verify multiple CIDs
    async fn verify_batch(&self, cids: &[String]) -> Vec<Result<VerificationResult>>;
}

/// IPFS DHT-based verifier
pub struct IpfsVerifier {
    ipfs_api_url: String,
    client: reqwest::Client,
}

impl IpfsVerifier {
    pub fn new(ipfs_api_url: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .expect("Failed to build HTTP client");

        Self {
            ipfs_api_url,
            client,
        }
    }

    fn api_url(&self, endpoint: &str) -> String {
        format!("{}{}", self.ipfs_api_url, endpoint)
    }

    /// Generate proof hash from verification data
    fn generate_proof_hash(
        cid: &str,
        is_available: bool,
        timestamp: u64,
        provider_count: u32,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(cid.as_bytes());
        hasher.update(&[if is_available { 1 } else { 0 }]);
        hasher.update(&timestamp.to_le_bytes());
        hasher.update(&provider_count.to_le_bytes());
        hasher.finalize().into()
    }
}

#[async_trait]
impl Verifier for IpfsVerifier {
    async fn verify(&self, cid: &str) -> Result<VerificationResult> {
        self.verify_with_timeout(cid, 30).await
    }

    async fn verify_with_timeout(
        &self,
        cid: &str,
        timeout_secs: u64,
    ) -> Result<VerificationResult> {
        let start = std::time::Instant::now();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Method 1: Check if we can find providers via DHT
        let providers_result = self.find_providers(cid).await;

        // Method 2: Try to fetch the content (lightweight - just headers)
        let fetch_result = self.check_content_available(cid, timeout_secs).await;

        let response_time_ms = start.elapsed().as_millis() as u64;

        // Determine availability based on results
        let (is_available, provider_count, error, content_size) =
            match (providers_result, fetch_result) {
                (Ok(providers), Ok(size)) => {
                    tracing::debug!(
                        "CID {} verified: {} providers, size: {} bytes",
                        cid,
                        providers.len(),
                        size.unwrap_or(0)
                    );
                    (true, providers.len() as u32, None, size)
                }
                (Ok(providers), Err(e)) if !providers.is_empty() => {
                    // Providers exist but fetch failed - might be network issues
                    tracing::warn!(
                        "CID {} has {} providers but fetch failed: {}",
                        cid,
                        providers.len(),
                        e
                    );
                    (true, providers.len() as u32, None, None)
                }
                (Err(e1), Err(e2)) => {
                    let error_msg = format!("DHT: {}, Fetch: {}", e1, e2);
                    tracing::warn!("CID {} unavailable: {}", cid, error_msg);
                    (false, 0, Some(error_msg), None)
                }
                _ => {
                    tracing::warn!("CID {} verification inconclusive", cid);
                    (
                        false,
                        0,
                        Some("Verification inconclusive".to_string()),
                        None,
                    )
                }
            };

        let proof_hash = Self::generate_proof_hash(cid, is_available, timestamp, provider_count);

        Ok(VerificationResult {
            is_available,
            response_time_ms,
            content_size,
            proof_hash,
            provider_count,
            error,
        })
    }

    async fn verify_batch(&self, cids: &[String]) -> Vec<Result<VerificationResult>> {
        // Run verifications concurrently with bounded parallelism.
        const MAX_CONCURRENT: usize = 32;

        let mut results = Vec::with_capacity(cids.len());
        for chunk in cids.chunks(MAX_CONCURRENT) {
            let mut set = tokio::task::JoinSet::new();

            for cid in chunk {
                let cid = cid.clone();
                let client = self.client.clone();
                let api_url = self.ipfs_api_url.clone();
                set.spawn(async move {
                    let verifier = IpfsVerifier {
                        ipfs_api_url: api_url,
                        client,
                    };
                    verifier.verify(&cid).await
                });
            }

            while let Some(join_result) = set.join_next().await {
                match join_result {
                    Ok(result) => results.push(result),
                    Err(e) => {
                        results.push(Err(anyhow::anyhow!("Verification task panicked: {}", e)))
                    }
                }
            }
        }

        results
    }
}

impl IpfsVerifier {
    /// Find providers for a CID via DHT
    async fn find_providers(&self, cid: &str) -> Result<Vec<String>> {
        let url = self.api_url("/api/v0/dht/findprovs");

        let response = self
            .client
            .post(&url)
            .query(&[("arg", cid), ("num-providers", "20")])
            .send()
            .await
            .context("Failed to query DHT for providers")?;

        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            anyhow::bail!("DHT query failed: {}", error);
        }

        // Parse the streaming JSON response
        let text = response.text().await?;
        let mut providers = Vec::new();

        for line in text.lines() {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
                if let Some(responses) = json.get("Responses").and_then(|r| r.as_array()) {
                    for resp in responses {
                        if let Some(id) = resp.get("ID").and_then(|i| i.as_str()) {
                            providers.push(id.to_string());
                        }
                    }
                }
            }
        }

        Ok(providers)
    }

    /// Check if content is available by attempting a lightweight fetch
    async fn check_content_available(&self, cid: &str, timeout_secs: u64) -> Result<Option<u64>> {
        let url = self.api_url("/api/v0/files/stat");

        let response = self
            .client
            .post(&url)
            .query(&[("arg", format!("/ipfs/{}", cid))])
            .timeout(std::time::Duration::from_secs(timeout_secs))
            .send()
            .await
            .context("Failed to stat content")?;

        if !response.status().is_success() {
            anyhow::bail!("Content stat failed");
        }

        let data: serde_json::Value = response.json().await?;
        let size = data["Size"]
            .as_u64()
            .or_else(|| data["CumulativeSize"].as_u64());

        Ok(size)
    }
}

/// Mock verifier for testing
pub struct MockVerifier {
    should_succeed: bool,
    latency_ms: u64,
}

impl MockVerifier {
    pub fn new(should_succeed: bool, latency_ms: u64) -> Self {
        Self {
            should_succeed,
            latency_ms,
        }
    }

    pub fn always_succeeds() -> Self {
        Self::new(true, 10)
    }

    pub fn always_fails() -> Self {
        Self::new(false, 10)
    }
}

#[async_trait]
impl Verifier for MockVerifier {
    async fn verify(&self, cid: &str) -> Result<VerificationResult> {
        tokio::time::sleep(tokio::time::Duration::from_millis(self.latency_ms)).await;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let proof_hash = IpfsVerifier::generate_proof_hash(cid, self.should_succeed, timestamp, 5);

        Ok(VerificationResult {
            is_available: self.should_succeed,
            response_time_ms: self.latency_ms,
            content_size: Some(1024 * 1024), // 1MB mock
            proof_hash,
            provider_count: 5,
            error: if self.should_succeed {
                None
            } else {
                Some("Mock verification failure".to_string())
            },
        })
    }

    async fn verify_with_timeout(
        &self,
        cid: &str,
        _timeout_secs: u64,
    ) -> Result<VerificationResult> {
        self.verify(cid).await
    }

    async fn verify_batch(&self, cids: &[String]) -> Vec<Result<VerificationResult>> {
        let mut results = Vec::with_capacity(cids.len());
        for cid in cids {
            results.push(self.verify(cid).await);
        }
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_verifier_succeeds() {
        let verifier = MockVerifier::always_succeeds();
        let result = verifier.verify("QmTest").await.unwrap();

        assert!(result.is_available);
        assert_eq!(result.provider_count, 5);
        assert!(result.error.is_none());
    }

    #[tokio::test]
    async fn test_mock_verifier_fails() {
        let verifier = MockVerifier::always_fails();
        let result = verifier.verify("QmTest").await.unwrap();

        assert!(!result.is_available);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_proof_hash_generation() {
        let hash1 = IpfsVerifier::generate_proof_hash("cid1", true, 1000, 5);
        let hash2 = IpfsVerifier::generate_proof_hash("cid1", true, 1000, 5);
        let hash3 = IpfsVerifier::generate_proof_hash("cid2", true, 1000, 5);

        // Same inputs should produce same hash
        assert_eq!(hash1, hash2);
        // Different CID should produce different hash
        assert_ne!(hash1, hash3);
    }
}
