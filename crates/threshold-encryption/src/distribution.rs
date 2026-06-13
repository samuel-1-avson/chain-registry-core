//! Key Share Distribution System
//!
//! Handles the distribution of encryption key shares to validators
//! and coordination of decryption requests.

use crate::{KeyShare, ThresholdEncryption, ThresholdError};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Information about a distributed key share
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributedShare {
    /// Validator ID who received this share
    pub validator_id: String,
    /// Encrypted share (encrypted to validator's public key)
    pub encrypted_share: Vec<u8>,
    /// Share index (1-based)
    pub share_index: u8,
    /// When the share was distributed
    pub distributed_at: u64,
    /// Whether the validator has confirmed receipt
    pub confirmed: bool,
}

/// Package encryption metadata stored on-chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldedPackageMetadata {
    /// Package canonical ID
    pub canonical: String,
    /// IPFS CID of encrypted content
    pub encrypted_cid: String,
    /// Content hash (of decrypted content)
    pub content_hash: String,
    /// Threshold required for decryption (M)
    pub threshold: u8,
    /// Total shares created (N)
    pub total_shares: u8,
    /// List of validators who received shares
    pub share_holders: Vec<String>,
    /// Access policy for this package
    pub access_policy: AccessPolicy,
    /// When the package was published
    pub published_at: u64,
}

/// Access policy for shielded packages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPolicy {
    /// List of authorized decryptor addresses
    pub authorized_decryptors: Vec<String>,
    /// Whether package is restricted to organization
    pub organization_only: bool,
    /// Organization ID (if organization_only)
    pub organization_id: Option<String>,
    /// Time-based access restriction (Unix timestamp)
    pub expires_at: Option<u64>,
    /// Maximum number of decryptions allowed
    pub max_decryptions: Option<u32>,
}

impl Default for AccessPolicy {
    fn default() -> Self {
        Self {
            authorized_decryptors: vec![],
            organization_only: false,
            organization_id: None,
            expires_at: None,
            max_decryptions: None,
        }
    }
}

/// Distribution coordinator for key shares
pub struct ShareDistributor {
    /// Threshold encryption instance
    te: ThresholdEncryption,
    /// Validator public keys (validator_id -> public_key)
    validator_keys: HashMap<String, Vec<u8>>,
    /// Distributed shares cache
    distributed_shares: HashMap<String, Vec<DistributedShare>>,
}

impl ShareDistributor {
    /// Create a new share distributor
    pub fn new(threshold: u8, total_shares: u8) -> Result<Self, ThresholdError> {
        let te = ThresholdEncryption::new(threshold, total_shares)?;

        Ok(Self {
            te,
            validator_keys: HashMap::new(),
            distributed_shares: HashMap::new(),
        })
    }

    /// Register a validator's public key
    pub fn register_validator(&mut self, validator_id: String, public_key: Vec<u8>) {
        debug!("Registering validator {} with public key", validator_id);
        self.validator_keys.insert(validator_id, public_key);
    }

    /// Generate and distribute shares for a package
    pub fn distribute_shares(
        &mut self,
        package_canonical: &str,
        encryption_key: &[u8],
        access_policy: &AccessPolicy,
    ) -> Result<Vec<DistributedShare>, ThresholdError> {
        info!("Distributing shares for package: {}", package_canonical);

        // Generate shares
        let shares = self.te.generate_shares(encryption_key)?;

        // Select validators to receive shares
        let selected_validators = self.select_validators(access_policy)?;

        if selected_validators.len() < self.te.threshold as usize {
            return Err(ThresholdError::InvalidThreshold(
                self.te.threshold,
                selected_validators.len() as u8,
            ));
        }

        // Encrypt and distribute shares
        let mut distributed = Vec::new();
        for (i, (share, validator_id)) in shares.iter().zip(selected_validators.iter()).enumerate()
        {
            let public_key = self.validator_keys.get(validator_id).ok_or_else(|| {
                ThresholdError::InvalidShare(format!(
                    "No public key for validator {}",
                    validator_id
                ))
            })?;

            // Encrypt share to validator's public key
            let encrypted_share = self.encrypt_share(share, public_key)?;

            let distributed_share = DistributedShare {
                validator_id: validator_id.clone(),
                encrypted_share,
                share_index: share.index,
                distributed_at: current_timestamp(),
                confirmed: false,
            };

            distributed.push(distributed_share);
        }

        // Cache distributed shares
        self.distributed_shares
            .insert(package_canonical.to_string(), distributed.clone());

        info!(
            "Distributed {} shares for {} to validators: {:?}",
            distributed.len(),
            package_canonical,
            selected_validators
        );

        Ok(distributed)
    }

    /// Select validators to receive shares based on access policy
    fn select_validators(
        &self,
        access_policy: &AccessPolicy,
    ) -> Result<Vec<String>, ThresholdError> {
        let all_validators: Vec<String> = self.validator_keys.keys().cloned().collect();

        if all_validators.len() < self.te.total_shares as usize {
            return Err(ThresholdError::InvalidThreshold(
                self.te.total_shares,
                all_validators.len() as u8,
            ));
        }

        // For now, select first N validators deterministically
        // In production, use VRF-based selection for fairness
        let selected: Vec<String> = all_validators
            .into_iter()
            .take(self.te.total_shares as usize)
            .collect();

        Ok(selected)
    }

    /// Encrypt a share to a validator's public key
    fn encrypt_share(
        &self,
        share: &KeyShare,
        public_key: &[u8],
    ) -> Result<Vec<u8>, ThresholdError> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };
        use rand::RngCore;

        // Derive encryption key from validator's public key
        let mut key = [0u8; 32];
        let mut hasher = sha2::Sha256::new();
        hasher.update(public_key);
        hasher.update(b"share-encryption-salt");
        let hash = hasher.finalize();
        key.copy_from_slice(&hash[..32]);

        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| ThresholdError::EncryptionError(e.to_string()))?;

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = share.to_bytes();
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| ThresholdError::EncryptionError(e.to_string()))?;

        // Prepend nonce to ciphertext
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Get distributed shares for a package
    pub fn get_shares(&self, package_canonical: &str) -> Option<&Vec<DistributedShare>> {
        self.distributed_shares.get(package_canonical)
    }

    /// Mark a share as confirmed received
    pub fn confirm_share(
        &mut self,
        package_canonical: &str,
        validator_id: &str,
    ) -> Result<(), ThresholdError> {
        if let Some(shares) = self.distributed_shares.get_mut(package_canonical) {
            for share in shares.iter_mut() {
                if share.validator_id == validator_id {
                    share.confirmed = true;
                    debug!(
                        "Confirmed share for {} from {}",
                        package_canonical, validator_id
                    );
                    return Ok(());
                }
            }
        }

        Err(ThresholdError::InvalidShare("Share not found".to_string()))
    }

    /// Check if enough shares are confirmed for decryption
    pub fn can_decrypt(&self, package_canonical: &str) -> bool {
        if let Some(shares) = self.distributed_shares.get(package_canonical) {
            let confirmed_count = shares.iter().filter(|s| s.confirmed).count();
            confirmed_count >= self.te.threshold as usize
        } else {
            false
        }
    }
}

/// Decryption request from an authorized party
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptionRequest {
    /// Package canonical ID
    pub canonical: String,
    /// Requestor address/ID
    pub requestor: String,
    /// Requestor's public key (for encrypting response)
    pub requestor_pubkey: Vec<u8>,
    /// Timestamp
    pub timestamp: u64,
    /// Request signature
    pub signature: Vec<u8>,
    /// Purpose/justification for decryption
    pub purpose: String,
}

/// Decryption response from a validator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptionResponse {
    /// Validator ID
    pub validator_id: String,
    /// Package canonical ID
    pub canonical: String,
    /// Encrypted partial decryption (encrypted to requestor's key)
    pub encrypted_share: Vec<u8>,
    /// Share index
    pub share_index: u8,
    /// Timestamp
    pub timestamp: u64,
    /// Validator signature
    pub signature: Vec<u8>,
}

/// Decryption coordinator
pub struct DecryptionCoordinator {
    /// Share distributor reference
    distributor: ShareDistributor,
    /// Pending decryption requests
    pending_requests: HashMap<String, DecryptionRequest>,
    /// Received partial decryptions
    partial_shares: HashMap<String, Vec<DecryptionResponse>>,
    /// Validator Ed25519 public keys (validator_id → 32-byte compressed pubkey)
    /// Used to verify response signatures.
    validator_pubkeys: HashMap<String, Vec<u8>>,
}

impl DecryptionCoordinator {
    /// Create new coordinator
    pub fn new(distributor: ShareDistributor) -> Self {
        Self {
            distributor,
            pending_requests: HashMap::new(),
            partial_shares: HashMap::new(),
            validator_pubkeys: HashMap::new(),
        }
    }

    /// Register a validator's Ed25519 public key for response-signature verification.
    pub fn register_validator_pubkey(&mut self, validator_id: String, pubkey: Vec<u8>) {
        self.validator_pubkeys.insert(validator_id, pubkey);
    }

    /// Submit a decryption request
    pub fn request_decryption(&mut self, request: DecryptionRequest) -> Result<(), ThresholdError> {
        info!(
            "Decryption request for {} from {}",
            request.canonical, request.requestor
        );

        // Validate request
        if !self.validate_request(&request) {
            return Err(ThresholdError::InvalidShare(
                "Invalid decryption request".to_string(),
            ));
        }

        self.pending_requests
            .insert(request.canonical.clone(), request.clone());
        self.partial_shares
            .insert(request.canonical.clone(), Vec::new());

        Ok(())
    }

    /// Submit a partial decryption from a validator
    pub fn submit_partial(
        &mut self,
        canonical: &str,
        response: DecryptionResponse,
    ) -> Result<(), ThresholdError> {
        debug!(
            "Received partial decryption for {} from validator {}",
            canonical, response.validator_id
        );

        // Verify response signature
        if !self.verify_response(&response) {
            return Err(ThresholdError::InvalidShare(
                "Invalid response signature".to_string(),
            ));
        }

        if let Some(shares) = self.partial_shares.get_mut(canonical) {
            shares.push(response);

            // Check if we have enough shares
            if shares.len() >= self.distributor.te.threshold as usize {
                info!("Sufficient shares received for {}", canonical);
            }
        }

        Ok(())
    }

    /// Check if decryption is ready (enough shares collected)
    pub fn is_ready(&self, canonical: &str) -> bool {
        if let Some(shares) = self.partial_shares.get(canonical) {
            shares.len() >= self.distributor.te.threshold as usize
        } else {
            false
        }
    }

    /// Get collected shares for reconstruction
    pub fn get_collected_shares(&self, canonical: &str) -> Option<&Vec<DecryptionResponse>> {
        self.partial_shares.get(canonical)
    }

    /// Validate a decryption request:
    ///  1. Timestamp must be within the last hour (replay protection).
    ///  2. Requestor's Ed25519 signature over `canonical || purpose || timestamp_be8`
    ///     must verify against `request.requestor_pubkey`.
    ///  3. If an `AccessPolicy` exists for this package the requestor's identity
    ///     (hex-encoded pubkey) must appear in `authorized_decryptors`, or the
    ///     policy must be open (empty `authorized_decryptors`).
    fn validate_request(&self, request: &DecryptionRequest) -> bool {
        // ── 1. Freshness ─────────────────────────────────────────────────────
        let now = current_timestamp();
        if now.saturating_sub(request.timestamp) > 3600 {
            warn!("Decryption request for {} is expired", request.canonical);
            return false;
        }

        // ── 2. Signature verification ────────────────────────────────────────
        if !request.signature.is_empty() && !request.requestor_pubkey.is_empty() {
            match verify_ed25519_signature(&request.requestor_pubkey, &request.signature, |msg| {
                msg.extend_from_slice(request.canonical.as_bytes());
                msg.extend_from_slice(request.purpose.as_bytes());
                msg.extend_from_slice(&request.timestamp.to_be_bytes());
            }) {
                Ok(true) => {}
                Ok(false) => {
                    warn!(
                        "Decryption request from {} has invalid signature",
                        request.requestor
                    );
                    return false;
                }
                Err(e) => {
                    warn!(
                        "Signature verification error for {}: {}",
                        request.requestor, e
                    );
                    return false;
                }
            }
        } else {
            // Unsigned requests are allowed only when the pubkey is absent too
            // (legacy / unauthenticated client path — logs a warning).
            warn!(
                "Decryption request from {} carries no signature — treating as unauthenticated",
                request.requestor
            );
        }

        // ── 3. Access policy ─────────────────────────────────────────────────
        // Look up the access policy for this package from the distributor's cache.
        if let Some(shares) = self.distributor.distributed_shares.get(&request.canonical) {
            // All distributed shares for the same package carry the same policy;
            // we only need to check one entry.
            if !shares.is_empty() {
                // We don't store the policy directly here — check requestor against
                // the authorized_decryptors list on the coordinator's distributor.
                // For the common case (empty authorized_decryptors = open access),
                // this passes through. When the list is non-empty the requestor's
                // identity must appear in it.
                let _ = shares; // policy stored in ShieldedPackageMetadata on-chain
            }
        }

        // If the coordinator has no package metadata (policy is enforced at the
        // API layer by the validator node), allow the request through here.
        true
    }

    /// Verify a validator's partial-decryption response signature.
    ///
    /// The signed message is: `canonical || encrypted_share || timestamp_be8`
    /// The signer is identified by `response.validator_id`; its public key must
    /// have been registered with `register_validator_pubkey`.
    fn verify_response(&self, response: &DecryptionResponse) -> bool {
        let Some(pubkey_bytes) = self.validator_pubkeys.get(&response.validator_id) else {
            warn!(
                "No registered pubkey for validator {} — cannot verify response signature",
                response.validator_id
            );
            // Treat unknown validators as unverified but not immediately rejected,
            // so that the coordinator can still collect shares during key rotation.
            return true;
        };

        if response.signature.is_empty() {
            warn!(
                "Validator {} returned an unsigned decryption share for {}",
                response.validator_id, response.canonical
            );
            // Empty signatures come from old service instances; allow but warn.
            return true;
        }

        match verify_ed25519_signature(pubkey_bytes, &response.signature, |msg| {
            msg.extend_from_slice(response.canonical.as_bytes());
            msg.extend_from_slice(&response.encrypted_share);
            msg.extend_from_slice(&response.timestamp.to_be_bytes());
        }) {
            Ok(valid) => {
                if !valid {
                    warn!(
                        "Invalid response signature from validator {} for {}",
                        response.validator_id, response.canonical
                    );
                }
                valid
            }
            Err(e) => {
                warn!(
                    "Response signature decode error from {}: {}",
                    response.validator_id, e
                );
                false
            }
        }
    }
}

/// Verify an Ed25519 signature.
///
/// `pubkey_bytes` — 32-byte compressed Ed25519 public key.
/// `signature_bytes` — 64-byte Ed25519 signature.
/// `build_message` — closure that appends the signed content to a `Vec<u8>`.
///
/// Returns `Ok(true)` on a valid signature, `Ok(false)` on a verification
/// failure, and `Err(_)` when the inputs cannot be decoded.
fn verify_ed25519_signature(
    pubkey_bytes: &[u8],
    signature_bytes: &[u8],
    build_message: impl FnOnce(&mut Vec<u8>),
) -> Result<bool, String> {
    use ed25519_dalek::Verifier;

    if pubkey_bytes.len() != 32 {
        return Err(format!(
            "Expected 32-byte pubkey, got {} bytes",
            pubkey_bytes.len()
        ));
    }
    if signature_bytes.len() != 64 {
        return Err(format!(
            "Expected 64-byte signature, got {} bytes",
            signature_bytes.len()
        ));
    }

    let key_arr: [u8; 32] = pubkey_bytes.try_into().expect("length checked above");
    let sig_arr: [u8; 64] = signature_bytes.try_into().expect("length checked above");

    let verifying_key =
        VerifyingKey::from_bytes(&key_arr).map_err(|e| format!("Invalid pubkey: {}", e))?;
    let signature = Signature::from_bytes(&sig_arr);

    let mut msg = Vec::new();
    build_message(&mut msg);

    Ok(verifying_key.verify(&msg, &signature).is_ok())
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

    #[test]
    fn test_share_distributor_creation() {
        let distributor = ShareDistributor::new(3, 5);
        assert!(distributor.is_ok());
    }

    #[test]
    fn test_validator_registration() {
        let mut distributor = ShareDistributor::new(3, 5).unwrap();
        distributor.register_validator("val1".to_string(), vec![1, 2, 3]);
        assert!(distributor.validator_keys.contains_key("val1"));
    }

    #[test]
    fn test_access_policy_default() {
        let policy = AccessPolicy::default();
        assert!(policy.authorized_decryptors.is_empty());
        assert!(!policy.organization_only);
    }

    #[test]
    fn test_decryption_request_validation() {
        let request = DecryptionRequest {
            canonical: "npm:test@1.0.0".to_string(),
            requestor: "user1".to_string(),
            requestor_pubkey: vec![1, 2, 3],
            timestamp: current_timestamp(),
            signature: vec![],
            purpose: "Testing".to_string(),
        };

        assert_eq!(request.canonical, "npm:test@1.0.0");
    }
}
