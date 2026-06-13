//! Threshold Decryption Service
//!
//! Runs in validator nodes to handle decryption requests for shielded packages.
//! Coordinates M-of-N consensus for package decryption.

use crate::{
    distribution::{DecryptionRequest, DecryptionResponse, ShieldedPackageMetadata},
    KeyShare, ThresholdEncryption, ThresholdError,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

// hex encoding used when deriving the requestor identity from a public key
use hex;

/// Service configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    /// Validator ID
    pub validator_id: String,
    /// Validator's private key (for decrypting shares)
    pub validator_key: Vec<u8>,
    /// Validator's public key
    pub validator_pubkey: Vec<u8>,
    /// Threshold (M)
    pub threshold: u8,
    /// Total shares (N)
    pub total_shares: u8,
    /// Request timeout (seconds)
    pub request_timeout: u64,
    /// Maximum concurrent decryptions
    pub max_concurrent: usize,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            validator_id: String::new(),
            validator_key: vec![],
            validator_pubkey: vec![],
            threshold: 3,
            total_shares: 5,
            request_timeout: 300, // 5 minutes
            max_concurrent: 10,
        }
    }
}

/// Decryption service running in each validator
pub struct DecryptionService {
    config: ServiceConfig,
    /// Threshold encryption instance
    te: ThresholdEncryption,
    /// Stored key shares (package_canonical -> decrypted_share)
    shares: Arc<RwLock<HashMap<String, KeyShare>>>,
    /// Request queue
    request_rx: mpsc::Receiver<DecryptionCommand>,
    /// Response sender
    response_tx: mpsc::Sender<DecryptionResponse>,
    /// Active decryptions
    active_count: Arc<RwLock<usize>>,
}

/// Commands for the decryption service
#[derive(Debug, Clone)]
pub enum DecryptionCommand {
    /// Store a key share for a package
    StoreShare {
        canonical: String,
        encrypted_share: Vec<u8>,
    },
    /// Process a decryption request
    ProcessRequest(DecryptionRequest),
    /// Get service status
    GetStatus,
}

/// Service status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub validator_id: String,
    pub stored_shares: usize,
    pub active_decryptions: usize,
    pub total_decryptions: u64,
    pub is_ready: bool,
}

impl DecryptionService {
    /// Create a new decryption service
    pub fn new(
        config: ServiceConfig,
        request_rx: mpsc::Receiver<DecryptionCommand>,
        response_tx: mpsc::Sender<DecryptionResponse>,
    ) -> Result<Self, ThresholdError> {
        let te = ThresholdEncryption::new(config.threshold, config.total_shares)?;

        Ok(Self {
            config,
            te,
            shares: Arc::new(RwLock::new(HashMap::new())),
            request_rx,
            response_tx,
            active_count: Arc::new(RwLock::new(0)),
        })
    }

    /// Start the service loop
    pub async fn run(mut self) {
        info!(
            "Decryption service started for validator {}",
            self.config.validator_id
        );

        while let Some(cmd) = self.request_rx.recv().await {
            match cmd {
                DecryptionCommand::StoreShare {
                    canonical,
                    encrypted_share,
                } => {
                    if let Err(e) = self.store_share(&canonical, &encrypted_share).await {
                        error!("Failed to store share for {}: {}", canonical, e);
                    }
                }
                DecryptionCommand::ProcessRequest(request) => {
                    if let Err(e) = self.process_request(request).await {
                        error!("Failed to process decryption request: {}", e);
                    }
                }
                DecryptionCommand::GetStatus => {
                    let status = self.get_status().await;
                    debug!("Service status: {:?}", status);
                }
            }
        }

        info!("Decryption service stopped");
    }

    /// Store a decrypted key share
    async fn store_share(
        &self,
        canonical: &str,
        encrypted_share: &[u8],
    ) -> Result<(), ThresholdError> {
        debug!("Storing share for package: {}", canonical);

        // Decrypt the share using validator's key
        let share_bytes = self.decrypt_share(encrypted_share)?;
        let share = self.bytes_to_share(&share_bytes)?;

        let mut shares = self.shares.write().await;
        shares.insert(canonical.to_string(), share);

        info!("Stored share for package: {}", canonical);
        Ok(())
    }

    /// Process a decryption request
    async fn process_request(&self, request: DecryptionRequest) -> Result<(), ThresholdError> {
        let canonical = request.canonical.clone();

        info!(
            "Processing decryption request for {} from {}",
            canonical, request.requestor
        );

        // Check if we have a share for this package
        let share = {
            let shares = self.shares.read().await;
            shares.get(&canonical).cloned()
        };

        if let Some(share) = share {
            // Check concurrent limit
            {
                let active = self.active_count.read().await;
                if *active >= self.config.max_concurrent {
                    warn!("Max concurrent decryptions reached, dropping request");
                    return Ok(());
                }
            }

            // Increment active count
            {
                let mut active = self.active_count.write().await;
                *active += 1;
            }

            // Create response
            let response = self.create_response(&request, &share).await;

            // Send response
            if let Err(e) = self.response_tx.send(response).await {
                error!("Failed to send decryption response: {}", e);
            }

            // Decrement active count
            {
                let mut active = self.active_count.write().await;
                *active -= 1;
            }

            info!("Sent decryption share for {}", canonical);
        } else {
            warn!("No share available for package: {}", canonical);
        }

        Ok(())
    }

    /// Create a decryption response
    async fn create_response(
        &self,
        request: &DecryptionRequest,
        share: &KeyShare,
    ) -> DecryptionResponse {
        let timestamp = current_timestamp();

        // Encrypt share to requestor's public key
        let encrypted_share = self.encrypt_to_requestor(share, &request.requestor_pubkey);

        // Create signature
        let signature = self.sign_response(&request.canonical, &encrypted_share, timestamp);

        DecryptionResponse {
            validator_id: self.config.validator_id.clone(),
            canonical: request.canonical.clone(),
            encrypted_share,
            share_index: share.index,
            timestamp,
            signature,
        }
    }

    /// Get service status
    async fn get_status(&self) -> ServiceStatus {
        let stored_shares = self.shares.read().await.len();
        let active_decryptions = *self.active_count.read().await;

        ServiceStatus {
            validator_id: self.config.validator_id.clone(),
            stored_shares,
            active_decryptions,
            total_decryptions: 0, // TODO: Track this
            is_ready: stored_shares > 0,
        }
    }

    /// Decrypt an encrypted share using validator's private key
    fn decrypt_share(&self, encrypted: &[u8]) -> Result<Vec<u8>, ThresholdError> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };

        if encrypted.len() < 12 {
            return Err(ThresholdError::DecryptionError(
                "Encrypted data too short".to_string(),
            ));
        }

        // Derive decryption key from validator's key
        let mut key = [0u8; 32];
        let mut hasher = sha2::Sha256::new();
        hasher.update(&self.config.validator_key);
        hasher.update(b"share-encryption-salt");
        let hash = hasher.finalize();
        key.copy_from_slice(&hash[..32]);

        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| ThresholdError::DecryptionError(e.to_string()))?;

        let nonce = Nonce::from_slice(&encrypted[..12]);
        let ciphertext = &encrypted[12..];

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| ThresholdError::DecryptionError(e.to_string()))?;

        Ok(plaintext)
    }

    /// Convert bytes to KeyShare
    fn bytes_to_share(&self, bytes: &[u8]) -> Result<KeyShare, ThresholdError> {
        if bytes.len() < 6 {
            return Err(ThresholdError::InvalidShare(
                "Share bytes too short".to_string(),
            ));
        }

        let index = bytes[0];
        let value_len = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;

        if bytes.len() < 5 + value_len + 32 {
            return Err(ThresholdError::InvalidShare(
                "Invalid share format".to_string(),
            ));
        }

        let value = bytes[5..5 + value_len].to_vec();
        let public_key = bytes[5 + value_len..5 + value_len + 32].to_vec();

        Ok(KeyShare::new(index, value, public_key))
    }

    /// Encrypt share to requestor's public key
    fn encrypt_to_requestor(&self, share: &KeyShare, requestor_pubkey: &[u8]) -> Vec<u8> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };
        use rand::RngCore;

        // Derive encryption key
        let mut key = [0u8; 32];
        let mut hasher = sha2::Sha256::new();
        hasher.update(requestor_pubkey);
        hasher.update(&self.config.validator_pubkey);
        let hash = hasher.finalize();
        key.copy_from_slice(&hash[..32]);

        let cipher = Aes256Gcm::new_from_slice(&key).expect("Valid key size");

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = share.to_bytes();
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .expect("Encryption success");

        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);
        result
    }

    /// Sign a decryption share response with the validator's Ed25519 key.
    ///
    /// Message layout: `canonical_bytes || encrypted_share || timestamp_be_8bytes`
    /// Recipients can verify using the validator's registered `validator_pubkey`.
    fn sign_response(&self, canonical: &str, encrypted_share: &[u8], timestamp: u64) -> Vec<u8> {
        use ed25519_dalek::{Signer, SigningKey};

        // Build signing key from the 32-byte validator private key.
        if self.config.validator_key.len() != 32 {
            warn!(
                "Validator key is {} bytes (expected 32); response will carry an empty signature",
                self.config.validator_key.len()
            );
            return vec![];
        }

        let key_bytes: [u8; 32] = self.config.validator_key[..32]
            .try_into()
            .expect("length checked above");
        let signing_key = SigningKey::from_bytes(&key_bytes);

        // Construct the message to sign.
        let mut msg = canonical.as_bytes().to_vec();
        msg.extend_from_slice(encrypted_share);
        msg.extend_from_slice(&timestamp.to_be_bytes());

        let signature = signing_key.sign(&msg);
        signature.to_bytes().to_vec()
    }
}

/// Client for requesting decryptions
pub struct DecryptionClient {
    /// Request sender
    request_tx: mpsc::Sender<DecryptionCommand>,
    /// Response receiver
    response_rx: mpsc::Receiver<DecryptionResponse>,
    /// Requestor's private key
    requestor_key: Vec<u8>,
    /// Requestor's public key
    requestor_pubkey: Vec<u8>,
    /// Threshold M — minimum shares needed for reconstruction
    threshold: u8,
    /// Total shares N
    total_shares: u8,
}

impl DecryptionClient {
    /// Create a new client
    pub fn new(
        request_tx: mpsc::Sender<DecryptionCommand>,
        response_rx: mpsc::Receiver<DecryptionResponse>,
        requestor_key: Vec<u8>,
        requestor_pubkey: Vec<u8>,
    ) -> Self {
        Self {
            request_tx,
            response_rx,
            requestor_key,
            requestor_pubkey,
            threshold: 3,
            total_shares: 5,
        }
    }

    /// Override the default threshold parameters (must match the service's config).
    pub fn with_params(mut self, threshold: u8, total_shares: u8) -> Self {
        self.threshold = threshold;
        self.total_shares = total_shares;
        self
    }

    /// Request decryption of a package.
    ///
    /// The request is signed with the requestor's Ed25519 key so validators can
    /// authenticate the requestor before releasing a decryption share.
    /// Message layout: `canonical_bytes || purpose_bytes || timestamp_be_8bytes`
    pub async fn request_decryption(
        &mut self,
        canonical: &str,
        purpose: &str,
    ) -> Result<Vec<DecryptionResponse>, ThresholdError> {
        use ed25519_dalek::{Signer, SigningKey};

        let timestamp = current_timestamp();

        // Derive requestor identity (hex-encoded public key) and sign the request.
        let (requestor_id, signature) = if self.requestor_key.len() == 32 {
            let key_bytes: [u8; 32] = self.requestor_key[..32]
                .try_into()
                .expect("length checked above");
            let signing_key = SigningKey::from_bytes(&key_bytes);
            let pubkey_hex = hex::encode(signing_key.verifying_key().as_bytes());

            let mut msg = canonical.as_bytes().to_vec();
            msg.extend_from_slice(purpose.as_bytes());
            msg.extend_from_slice(&timestamp.to_be_bytes());
            let sig = signing_key.sign(&msg);

            (pubkey_hex, sig.to_bytes().to_vec())
        } else {
            warn!("Requestor key is not 32 bytes — sending unsigned decryption request");
            (hex::encode(&self.requestor_pubkey), vec![])
        };

        let request = DecryptionRequest {
            canonical: canonical.to_string(),
            requestor: requestor_id,
            requestor_pubkey: self.requestor_pubkey.clone(),
            timestamp,
            signature,
            purpose: purpose.to_string(),
        };

        // Send request
        self.request_tx
            .send(DecryptionCommand::ProcessRequest(request))
            .await
            .map_err(|e| {
                ThresholdError::IoError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                ))
            })?;

        // Collect responses (timeout after 60 seconds)
        let mut responses = Vec::new();
        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(60);

        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(
                tokio::time::Duration::from_millis(100),
                self.response_rx.recv(),
            )
            .await
            {
                Ok(Some(response)) if response.canonical == canonical => {
                    responses.push(response);
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }

        Ok(responses)
    }

    /// Decrypt collected shares to get package content
    pub fn reconstruct_package(
        &self,
        encrypted_package: &[u8],
        responses: &[DecryptionResponse],
    ) -> Result<Vec<u8>, ThresholdError> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };

        // Decrypt each share
        let mut shares = Vec::new();
        for response in responses {
            let share = self.decrypt_response_share(response)?;
            shares.push(KeyShare::new(share.index, share.value, vec![]));
        }

        // Reconstruct encryption key using Shamir with the configured threshold params.
        let te = ThresholdEncryption::new(self.threshold, self.total_shares)?;
        let key = te.reconstruct_key(&shares)?;

        // Decrypt package
        if encrypted_package.len() < 12 {
            return Err(ThresholdError::DecryptionError(
                "Invalid package".to_string(),
            ));
        }

        let nonce = Nonce::from_slice(&encrypted_package[..12]);
        let ciphertext = &encrypted_package[12..];

        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| ThresholdError::DecryptionError(e.to_string()))?;

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| ThresholdError::DecryptionError(e.to_string()))?;

        Ok(plaintext)
    }

    /// Decrypt a response share
    fn decrypt_response_share(
        &self,
        response: &DecryptionResponse,
    ) -> Result<crate::shamir::Share, ThresholdError> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };

        // Derive decryption key
        let mut key = [0u8; 32];
        let mut hasher = sha2::Sha256::new();
        hasher.update(&self.requestor_pubkey);
        hasher.update(&self.requestor_key);
        let hash = hasher.finalize();
        key.copy_from_slice(&hash[..32]);

        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| ThresholdError::DecryptionError(e.to_string()))?;

        let encrypted = &response.encrypted_share;
        if encrypted.len() < 12 {
            return Err(ThresholdError::DecryptionError("Invalid share".to_string()));
        }

        let nonce = Nonce::from_slice(&encrypted[..12]);
        let ciphertext = &encrypted[12..];

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| ThresholdError::DecryptionError(e.to_string()))?;

        // Parse share
        let index = plaintext[0];
        let value = plaintext[1..].to_vec();

        Ok(crate::shamir::Share::new(index, value))
    }
}

/// Create channels for service and client
pub fn create_channels() -> (
    (
        mpsc::Sender<DecryptionCommand>,
        mpsc::Receiver<DecryptionResponse>,
    ),
    (
        mpsc::Sender<DecryptionResponse>,
        mpsc::Receiver<DecryptionCommand>,
    ),
) {
    let (cmd_tx, cmd_rx) = mpsc::channel(100);
    let (resp_tx, resp_rx) = mpsc::channel(100);

    ((cmd_tx, resp_rx), (resp_tx, cmd_rx))
}

/// Get current Unix timestamp
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_service_status() {
        let config = ServiceConfig::default();
        let ((cmd_tx, _resp_rx), (resp_tx, cmd_rx)) = create_channels();

        let service = DecryptionService::new(config, cmd_rx, resp_tx).unwrap();
        let status = service.get_status().await;

        assert_eq!(status.stored_shares, 0);
        assert!(!status.is_ready);
    }

    #[test]
    fn test_service_config_default() {
        let config = ServiceConfig::default();
        assert_eq!(config.threshold, 3);
        assert_eq!(config.total_shares, 5);
        assert_eq!(config.request_timeout, 300);
    }
}
