//! IPFS Pinning Rewards System
//!
//! This crate provides:
//! - Automatic pinning of verified packages
//! - Verification of content availability
//! - Rewards tracking and claiming
//! - Integration with the PinningRewards.sol contract

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

pub mod contract;
pub mod pinner;
pub mod verifier;

pub use contract::{PinningContract, PinningRewardsClient};
pub use pinner::{IpfsPinner, PinnerConfig};
pub use verifier::{VerificationResult, Verifier};

/// Configuration for the pinning rewards system
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PinningConfig {
    /// IPFS node RPC endpoint
    pub ipfs_url: String,
    /// Ethereum RPC endpoint
    pub eth_rpc: String,
    /// PinningRewards contract address
    pub contract_address: String,
    /// Node operator's Ethereum private key
    pub operator_key: String,
    /// Minimum stake required (in CREG wei)
    pub min_stake: u128,
    /// Auto-register as pinner on startup
    pub auto_register: bool,
    /// Verification interval (seconds)
    pub verification_interval: u64,
    /// Max pins to track per node
    pub max_pins: usize,
    /// Path to persist CID map state (e.g., /data/pinner_state.json)
    pub db_path: Option<String>,
}

impl Default for PinningConfig {
    fn default() -> Self {
        Self {
            ipfs_url: "http://localhost:5001".to_string(),
            eth_rpc: "http://localhost:8545".to_string(),
            contract_address: "0x0000000000000000000000000000000000000000".to_string(),
            operator_key: String::new(),
            min_stake: 1_000_000_000_000_000_000_000, // 1000 CREG
            auto_register: false,
            verification_interval: 3600, // 1 hour
            max_pins: 10000,
            db_path: None,
        }
    }
}

/// Information about a pinned CID
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinInfo {
    /// The content identifier
    pub cid: String,
    /// Content size in bytes
    pub size: u64,
    /// When first pinned
    pub pinned_at: DateTime<Utc>,
    /// Last successful verification
    pub last_verified: Option<DateTime<Utc>>,
    /// Number of times content was served
    pub access_count: u64,
    /// Whether currently active
    pub is_active: bool,
    /// Local file path (if cached)
    pub local_path: Option<PathBuf>,
}

/// Pinner statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PinnerStats {
    /// Total CIDs pinned
    pub total_pins: usize,
    /// Total size pinned (bytes)
    pub total_size: u64,
    /// Successful verifications
    pub successful_verifications: u64,
    /// Failed verifications
    pub failed_verifications: u64,
    /// Cumulative rewards earned (CREG wei)
    pub cumulative_rewards: u128,
    /// Pending rewards (CREG wei)
    pub pending_rewards: u128,
    /// Current stake (CREG wei)
    pub current_stake: u128,
}

/// The main pinning rewards manager
pub struct PinningManager {
    config: PinningConfig,
    pinner: Arc<dyn IpfsPinner>,
    contract: Arc<dyn PinningContract>,
    verifier: Arc<dyn Verifier>,
    /// Tracked pins
    pins: Arc<RwLock<HashMap<String, PinInfo>>>,
    /// Runtime statistics
    stats: Arc<RwLock<PinnerStats>>,
}

impl PinningManager {
    /// Create a new pinning manager
    pub async fn new(
        config: PinningConfig,
        pinner: Arc<dyn IpfsPinner>,
        contract: Arc<dyn PinningContract>,
        verifier: Arc<dyn Verifier>,
    ) -> Result<Self> {
        let manager = Self {
            config,
            pinner,
            contract,
            verifier,
            pins: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(PinnerStats::default())),
        };

        // Auto-register if configured
        if manager.config.auto_register {
            manager.ensure_registered().await?;
        }

        // Load existing pins
        manager.load_existing_pins().await?;

        Ok(manager)
    }

    /// Start the background tasks
    pub async fn start(&self) -> Result<()> {
        info!("Starting IPFS pinning manager");

        // Spawn verification loop
        let pins = Arc::clone(&self.pins);
        let verifier = Arc::clone(&self.verifier);
        let contract = Arc::clone(&self.contract);
        let stats = Arc::clone(&self.stats);
        let interval = self.config.verification_interval;

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(interval));
            loop {
                ticker.tick().await;
                if let Err(e) = Self::run_verification(&pins, &verifier, &contract, &stats).await {
                    warn!("Verification error: {}", e);
                }
            }
        });

        // Spawn rewards claiming loop
        let contract_claim = Arc::clone(&self.contract);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(86400)); // Daily
            loop {
                ticker.tick().await;
                if let Err(e) = contract_claim.claim_rewards().await {
                    warn!("Rewards claim error: {}", e);
                }
            }
        });

        info!("Pinning manager started successfully");
        Ok(())
    }

    /// Pin a new package CID
    pub async fn pin_package(&self, cid: &str, size: u64) -> Result<()> {
        debug!("Pinning package: {} ({} bytes)", cid, size);

        // Check if already pinned
        {
            let pins = self.pins.read().await;
            if pins.contains_key(cid) {
                debug!("CID {} already pinned", cid);
                return Ok(());
            }
        }

        // Pin to IPFS
        self.pinner.pin(cid).await.context("IPFS pin failed")?;

        // Register on-chain
        let cid_hash = cid_to_bytes32(cid)?;
        self.contract
            .register_pin(cid_hash, size)
            .await
            .context("Contract registration failed")?;

        // Track locally
        let pin_info = PinInfo {
            cid: cid.to_string(),
            size,
            pinned_at: Utc::now(),
            last_verified: None,
            access_count: 0,
            is_active: true,
            local_path: None,
        };

        {
            let mut pins = self.pins.write().await;
            pins.insert(cid.to_string(), pin_info);
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_pins += 1;
            stats.total_size += size;
        }
        self.save_state(&None).await;

        info!("Successfully pinned {} ({} bytes)", cid, size);
        Ok(())
    }

    /// Unpin a package
    pub async fn unpin_package(&self, cid: &str) -> Result<()> {
        debug!("Unpinning package: {}", cid);

        // Unpin from IPFS
        self.pinner.unpin(cid).await?;

        // Unregister on-chain
        let cid_hash = cid_to_bytes32(cid)?;
        self.contract.unregister_pin(cid_hash).await?;

        // Update local tracking
        {
            let mut pins = self.pins.write().await;
            if let Some(pin) = pins.get_mut(cid) {
                pin.is_active = false;
            }
        }
        self.save_state(&None).await;

        info!("Successfully unpinned {}", cid);
        Ok(())
    }

    /// Get current statistics
    pub async fn get_stats(&self) -> PinnerStats {
        self.stats.read().await.clone()
    }

    /// Get list of pinned CIDs
    pub async fn get_pins(&self) -> Vec<PinInfo> {
        let pins = self.pins.read().await;
        pins.values().cloned().collect()
    }

    /// Calculate pending rewards
    pub async fn calculate_pending_rewards(&self) -> Result<u128> {
        self.contract.calculate_rewards().await
    }

    /// Manually claim rewards
    pub async fn claim_rewards(&self) -> Result<u128> {
        self.contract.claim_rewards().await
    }

    // ============ Private Methods ============

    async fn ensure_registered(&self) -> Result<()> {
        let is_registered = self.contract.is_registered().await?;

        if !is_registered {
            info!(
                "Registering as pinner with stake: {}",
                self.config.min_stake
            );
            self.contract
                .register_pinner(self.config.min_stake)
                .await
                .context("Pinner registration failed")?;
            info!("Successfully registered as pinner");
        }

        Ok(())
    }

    async fn load_existing_pins(&self) -> Result<()> {
        let cid_hashes = self.contract.get_pinner_cids().await.unwrap_or_default();

        if !cid_hashes.is_empty() {
            warn!(
                "PinningRewards stores {} CID hashes. Reconstruction requires local state.",
                cid_hashes.len()
            );
        }

        if let Some(path) = &self.config.db_path {
            if let Ok(data) = tokio::fs::read(path).await {
                if let Ok(saved_pins) = serde_json::from_slice::<HashMap<String, PinInfo>>(&data) {
                    let mut pins = self.pins.write().await;
                    let mut stats = self.stats.write().await;

                    for (cid, info) in saved_pins {
                        pins.insert(cid.clone(), info.clone());
                        stats.total_pins += 1;
                        stats.total_size += info.size;
                    }
                    info!("Loaded {} existing pins from state file", pins.len());
                    return Ok(());
                }
            }
        }

        info!("Loaded 0 existing pins (no state file found)");
        Ok(())
    }

    /// Flush in-memory pins to disk
    async fn save_state(&self, current_pins: &Option<HashMap<String, PinInfo>>) {
        if let Some(path) = &self.config.db_path {
            let data = match current_pins {
                Some(p) => serde_json::to_vec_pretty(p),
                None => {
                    let pins = self.pins.read().await;
                    serde_json::to_vec_pretty(&*pins)
                }
            };

            if let Ok(json) = data {
                if let Err(e) = tokio::fs::write(path, json).await {
                    warn!("Failed to persist pinner state to {}: {}", path, e);
                }
            }
        }
    }

    async fn run_verification(
        pins: &Arc<RwLock<HashMap<String, PinInfo>>>,
        verifier: &Arc<dyn Verifier>,
        contract: &Arc<dyn PinningContract>,
        stats: &Arc<RwLock<PinnerStats>>,
    ) -> Result<()> {
        let pins_to_verify: Vec<String> = {
            let pins = pins.read().await;
            pins.values()
                .filter(|p| p.is_active)
                .map(|p| p.cid.clone())
                .collect()
        };

        if pins_to_verify.is_empty() {
            return Ok(());
        }

        info!(
            "Running verification for {} pinned CIDs",
            pins_to_verify.len()
        );

        for cid in pins_to_verify {
            match verifier.verify(&cid).await {
                Ok(result) => {
                    let cid_hash = cid_to_bytes32(&cid)?;
                    let success = result.is_available;
                    let proof_hash = result.proof_hash;

                    // Submit to contract
                    if let Err(e) = contract
                        .submit_verification(cid_hash, success, proof_hash)
                        .await
                    {
                        warn!("Failed to submit verification for {}: {}", cid, e);
                    }

                    // Update local pin state and stats
                    {
                        let mut stats = stats.write().await;
                        if success {
                            stats.successful_verifications += 1;
                            let mut pins = pins.write().await;
                            if let Some(pin) = pins.get_mut(&cid) {
                                pin.last_verified = Some(Utc::now());
                            }
                        } else {
                            stats.failed_verifications += 1;
                        }
                    }
                }
                Err(e) => {
                    warn!("Verification failed for {}: {}", cid, e);
                    let mut stats = stats.write().await;
                    stats.failed_verifications += 1;
                }
            }
        }

        Ok(())
    }
}

/// Convert CID string to bytes32
fn cid_to_bytes32(cid: &str) -> Result<[u8; 32]> {
    let digest = Sha256::digest(cid.as_bytes());
    Ok(digest.into())
}

#[cfg(test)]
mod tests {
    use super::cid_to_bytes32;

    #[test]
    fn cid_hashing_is_stable_and_uses_all_32_bytes() {
        let hash1 = cid_to_bytes32("QmTestCid").expect("hash should succeed");
        let hash2 = cid_to_bytes32("QmTestCid").expect("hash should succeed");
        let hash3 = cid_to_bytes32("QmDifferentCid").expect("hash should succeed");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
        assert_ne!(hash1, [0u8; 32]);
        assert_ne!(&hash1[8..], &[0u8; 24]);
    }
}
