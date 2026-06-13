//! End-to-end tests for the threshold-encryption crate (FIX-19).
//!
//! Exercises the full public API across five scenarios:
//!   1. Full 3-of-5 encrypt/decrypt round-trip via secp256k1 ECIES share encryption
//!   2. Threshold property — exactly M shares work; M-1 are rejected
//!   3. DecryptionService channel flow with Ed25519-signed responses
//!   4. DecryptionCoordinator request validation (valid / expired / tampered)
//!   5. AccessPolicy + ShareDistributor integration
//!
//! Run with: `cargo test -p threshold-encryption`

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use sha2::{Digest, Sha256};
use threshold_encryption::{
    access_control::{AccessPolicy, Permission, Role},
    distribution::{
        AccessPolicy as ShieldedAccessPolicy, DecryptionCoordinator, DecryptionRequest,
        DecryptionResponse, ShareDistributor,
    },
    service::{DecryptionCommand, DecryptionService, ServiceConfig},
    KeyShare, ThresholdEncryption, ThresholdError,
};

// ── Test helpers ──────────────────────────────────────────────────────────────

/// Generate a secp256k1 keypair: (compressed-SEC1 public key, raw 32-byte private key).
fn gen_secp256k1() -> (Vec<u8>, Vec<u8>) {
    use k256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};
    let sk = SecretKey::random(&mut rand::thread_rng());
    let pk = sk.public_key().to_encoded_point(true).as_bytes().to_vec();
    (pk, sk.to_bytes().to_vec())
}

/// Generate an Ed25519 keypair: (signing key bytes 32, verifying key bytes 32).
fn gen_ed25519() -> ([u8; 32], [u8; 32]) {
    let sk = SigningKey::generate(&mut rand::thread_rng());
    (sk.to_bytes(), sk.verifying_key().to_bytes())
}

/// Encrypt `share` in the format `DecryptionService::decrypt_share` expects:
///   `nonce(12B) || AES-GCM(key=SHA256(validator_key || "share-encryption-salt"), share.to_bytes())`
///
/// Mirrors the AES-GCM KDF in `service.rs::decrypt_share` so the service can
/// successfully call `bytes_to_share` on the result.
fn service_encrypt_share(validator_key: &[u8], share: &KeyShare) -> Vec<u8> {
    let aes_key = {
        let mut h = Sha256::new();
        h.update(validator_key);
        h.update(b"share-encryption-salt");
        h.finalize()
    };
    let cipher = Aes256Gcm::new(&aes_key);
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, share.to_bytes().as_ref())
        .expect("service_encrypt_share: AES-GCM encrypt must succeed");
    let mut out = nonce_bytes.to_vec();
    out.extend_from_slice(&ciphertext);
    out
}

/// Build a `DecryptionRequest` signed with the given Ed25519 signing key.
///
/// Message: `canonical || purpose || timestamp_be8`
/// This matches `DecryptionClient::request_decryption` and `validate_request`.
fn signed_request(
    canonical: &str,
    purpose: &str,
    signing_key_bytes: &[u8; 32],
    requestor_pubkey: Vec<u8>,
    timestamp: u64,
) -> DecryptionRequest {
    let sk = SigningKey::from_bytes(signing_key_bytes);
    let mut msg = canonical.as_bytes().to_vec();
    msg.extend_from_slice(purpose.as_bytes());
    msg.extend_from_slice(&timestamp.to_be_bytes());
    let sig = sk.sign(&msg);
    DecryptionRequest {
        canonical: canonical.to_string(),
        requestor: format!("requestor-{}", &canonical[..4]),
        requestor_pubkey,
        timestamp,
        signature: sig.to_bytes().to_vec(),
        purpose: purpose.to_string(),
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// --------------------------------------------------------------------------
// 1. Full lifecycle
// --------------------------------------------------------------------------

/// 3-of-5 encrypt → per-validator ECIES decrypt → reconstruct plaintext.
/// Verifies that any contiguous window of 3 decrypted shares recovers content.
#[test]
fn test_e2e_full_lifecycle_3_of_5() {
    let te = ThresholdEncryption::new(3, 5).expect("valid threshold");

    let pairs: Vec<(Vec<u8>, Vec<u8>)> = (0..5).map(|_| gen_secp256k1()).collect();
    let validator_pubs: Vec<Vec<u8>> = pairs.iter().map(|(pk, _)| pk.clone()).collect();
    let validator_secs: Vec<Vec<u8>> = pairs.iter().map(|(_, sk)| sk.clone()).collect();

    let content = b"hello threshold world -- this is the secret package payload";
    let encrypted = te
        .encrypt_package(content, &validator_pubs)
        .expect("encrypt_package must succeed");

    assert_eq!(encrypted.threshold, 3);
    assert_eq!(encrypted.total_shares, 5);
    assert_eq!(encrypted.encrypted_shares.len(), 5);
    assert!(!encrypted.ciphertext.is_empty());

    // Each validator independently decrypts their ECIES-wrapped share.
    let shares: Vec<KeyShare> = (1u8..=5)
        .map(|idx| {
            let enc = encrypted.encrypted_shares.get(&idx).expect("share present");
            te.decrypt_share(enc, &validator_secs[(idx - 1) as usize])
                .unwrap_or_else(|e| panic!("decrypt_share for validator {idx} failed: {e}"))
        })
        .collect();

    // Any 3-share window must recover the original content.
    for start in 0..=2usize {
        let subset = &shares[start..start + 3];
        let plaintext = te
            .decrypt_with_shares(&encrypted, subset)
            .unwrap_or_else(|e| {
                panic!(
                    "decrypt_with_shares (shares {start}..{}) failed: {e}",
                    start + 3
                )
            });
        assert_eq!(
            plaintext, content,
            "window starting at share {start} produced wrong plaintext"
        );
    }
}

/// Content hash mismatch: tampered ciphertext is detected and rejected.
#[test]
fn test_e2e_tampered_ciphertext_rejected() {
    let te = ThresholdEncryption::new(2, 3).expect("valid threshold");
    let pairs: Vec<(Vec<u8>, Vec<u8>)> = (0..3).map(|_| gen_secp256k1()).collect();
    let pubs: Vec<Vec<u8>> = pairs.iter().map(|(pk, _)| pk.clone()).collect();
    let secs: Vec<Vec<u8>> = pairs.iter().map(|(_, sk)| sk.clone()).collect();

    let mut encrypted = te.encrypt_package(b"canary", &pubs).expect("encrypt ok");

    // Flip a byte deep in the ciphertext to corrupt plaintext without breaking AES-GCM
    // directly — instead this exercises the SHA-256 content-hash check.
    // Because AES-GCM is authenticated, any single-byte flip fails AEAD before the
    // content-hash check, so the error is a DecryptionError regardless.
    let last = encrypted.ciphertext.len() - 1;
    encrypted.ciphertext[last] ^= 0x01;

    let shares: Vec<KeyShare> = (1u8..=2)
        .map(|idx| {
            let enc = encrypted.encrypted_shares.get(&idx).unwrap();
            te.decrypt_share(enc, &secs[(idx - 1) as usize]).unwrap()
        })
        .collect();

    let result = te.decrypt_with_shares(&encrypted, &shares);
    assert!(result.is_err(), "tampered ciphertext must be rejected");
}

/// Tampered encrypted share (ECIES ciphertext byte flipped) must fail AEAD auth.
#[test]
fn test_e2e_tampered_encrypted_share_rejected() {
    let te = ThresholdEncryption::new(2, 3).expect("valid threshold");
    let pairs: Vec<(Vec<u8>, Vec<u8>)> = (0..3).map(|_| gen_secp256k1()).collect();
    let pubs: Vec<Vec<u8>> = pairs.iter().map(|(pk, _)| pk.clone()).collect();
    let secs: Vec<Vec<u8>> = pairs.iter().map(|(_, sk)| sk.clone()).collect();

    let encrypted = te.encrypt_package(b"sensitive", &pubs).expect("encrypt ok");

    let (&idx, raw_share) = encrypted.encrypted_shares.iter().next().unwrap();
    let mut tampered = raw_share.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xff;

    let result = te.decrypt_share(&tampered, &secs[(idx as usize) - 1]);
    assert!(
        result.is_err(),
        "tampered share must fail AEAD authentication"
    );
}

/// Mismatched validator key count is caught before any encryption starts.
#[test]
fn test_e2e_wrong_validator_key_count_rejected() {
    let te = ThresholdEncryption::new(2, 3).expect("valid threshold");
    // Only 2 keys for a 3-share system.
    let pubs: Vec<Vec<u8>> = (0..2).map(|_| gen_secp256k1().0).collect();
    let result = te.encrypt_package(b"content", &pubs);
    assert!(
        result.is_err(),
        "mismatched key count must be caught before encryption"
    );
}

// --------------------------------------------------------------------------
// 2. Threshold property
// --------------------------------------------------------------------------

/// Exactly M-1 (= 2) shares out of 5 must fail with InsufficientShares(2, 3).
#[test]
fn test_e2e_threshold_m_minus_1_insufficient() {
    let te = ThresholdEncryption::new(3, 5).expect("valid threshold");
    let pairs: Vec<(Vec<u8>, Vec<u8>)> = (0..5).map(|_| gen_secp256k1()).collect();
    let pubs: Vec<Vec<u8>> = pairs.iter().map(|(pk, _)| pk.clone()).collect();
    let secs: Vec<Vec<u8>> = pairs.iter().map(|(_, sk)| sk.clone()).collect();

    let encrypted = te.encrypt_package(b"secret", &pubs).expect("encrypt ok");

    let shares: Vec<KeyShare> = (1u8..=2)
        .map(|idx| {
            let enc = encrypted.encrypted_shares.get(&idx).unwrap();
            te.decrypt_share(enc, &secs[(idx - 1) as usize])
                .expect("decrypt ok")
        })
        .collect();

    let result = te.decrypt_with_shares(&encrypted, &shares);
    assert!(
        matches!(result, Err(ThresholdError::InsufficientShares(2, 3))),
        "expected InsufficientShares(2, 3), got: {result:?}"
    );
}

/// 2-of-3: 1 share insufficient; 2 shares sufficient.
#[test]
fn test_e2e_threshold_2_of_3() {
    let te = ThresholdEncryption::new(2, 3).expect("valid threshold");
    let pairs: Vec<(Vec<u8>, Vec<u8>)> = (0..3).map(|_| gen_secp256k1()).collect();
    let pubs: Vec<Vec<u8>> = pairs.iter().map(|(pk, _)| pk.clone()).collect();
    let secs: Vec<Vec<u8>> = pairs.iter().map(|(_, sk)| sk.clone()).collect();

    let content = b"two of three";
    let encrypted = te.encrypt_package(content, &pubs).expect("encrypt ok");

    let share1 = te
        .decrypt_share(encrypted.encrypted_shares.get(&1).unwrap(), &secs[0])
        .expect("decrypt share 1");

    // One share is insufficient.
    assert!(
        matches!(
            te.decrypt_with_shares(&encrypted, &[share1.clone()]),
            Err(ThresholdError::InsufficientShares(1, 2))
        ),
        "1 share must be insufficient for 2-of-3"
    );

    let share2 = te
        .decrypt_share(encrypted.encrypted_shares.get(&2).unwrap(), &secs[1])
        .expect("decrypt share 2");

    // Two shares are sufficient.
    let plaintext = te
        .decrypt_with_shares(&encrypted, &[share1, share2])
        .expect("2-of-3 decrypt must succeed");
    assert_eq!(plaintext, content);
}

/// Invalid threshold parameters are rejected at construction time.
#[test]
fn test_e2e_invalid_threshold_params() {
    assert!(
        ThresholdEncryption::new(0, 5).is_err(),
        "threshold 0 must be invalid"
    );
    assert!(
        ThresholdEncryption::new(6, 5).is_err(),
        "threshold > total must be invalid"
    );
    assert!(
        ThresholdEncryption::new(5, 5).is_ok(),
        "threshold == total (5-of-5) is valid"
    );
    assert!(
        ThresholdEncryption::new(1, 1).is_ok(),
        "1-of-1 is the degenerate valid case"
    );
}

// --------------------------------------------------------------------------
// 3. DecryptionService channel flow
// --------------------------------------------------------------------------

/// The service stores a share, processes a decryption request, and emits a
/// response with a valid Ed25519 signature over (canonical || encrypted_share || timestamp).
#[tokio::test]
async fn test_e2e_service_channel_store_and_signed_response() {
    // Validator identity: Ed25519 key used for signing responses.
    let (val_sk_bytes, val_vk_bytes) = gen_ed25519();

    let config = ServiceConfig {
        validator_id: "validator-e2e".to_string(),
        validator_key: val_sk_bytes.to_vec(),
        validator_pubkey: val_vk_bytes.to_vec(),
        threshold: 2,
        total_shares: 3,
        request_timeout: 60,
        max_concurrent: 10,
    };

    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel::<DecryptionCommand>(16);
    let (resp_tx, mut resp_rx) =
        tokio::sync::mpsc::channel::<threshold_encryption::distribution::DecryptionResponse>(16);

    let service = DecryptionService::new(config, cmd_rx, resp_tx).expect("service init ok");
    tokio::spawn(service.run());

    // Build a KeyShare with a 32-byte value and 32-byte public_key so that
    // `DecryptionService::bytes_to_share` can parse it (requires >= 5+value_len+32 bytes).
    let share_value: Vec<u8> = (0u8..32).collect();
    let share_pubkey: Vec<u8> = Sha256::digest(&share_value).to_vec();
    let share = KeyShare::new(1, share_value, share_pubkey);

    // Encrypt the share in the format the service's decrypt_share expects.
    let enc_share = service_encrypt_share(&val_sk_bytes, &share);

    let canonical = "npm:example-pkg@1.0.0";

    // ── Step A: store the share ───────────────────────────────────────────────
    cmd_tx
        .send(DecryptionCommand::StoreShare {
            canonical: canonical.to_string(),
            encrypted_share: enc_share,
        })
        .await
        .expect("StoreShare send ok");

    // Give the service a moment to process the store command.
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // ── Step B: request decryption ────────────────────────────────────────────
    let requestor_pubkey = vec![0xde; 32];
    let request = DecryptionRequest {
        canonical: canonical.to_string(),
        requestor: "test-requestor".to_string(),
        requestor_pubkey,
        timestamp: unix_now(),
        signature: vec![],
        purpose: "e2e-test".to_string(),
    };

    cmd_tx
        .send(DecryptionCommand::ProcessRequest(request))
        .await
        .expect("ProcessRequest send ok");

    // ── Step C: collect response (up to 500 ms) ───────────────────────────────
    let response = tokio::time::timeout(tokio::time::Duration::from_millis(500), resp_rx.recv())
        .await
        .expect("timed out waiting for service response")
        .expect("response channel closed unexpectedly");

    assert_eq!(response.canonical, canonical, "canonical mismatch");
    assert_eq!(
        response.validator_id, "validator-e2e",
        "validator_id mismatch"
    );
    assert_eq!(response.share_index, 1, "share_index mismatch");
    assert!(
        !response.encrypted_share.is_empty(),
        "encrypted_share must not be empty"
    );
    assert_eq!(
        response.signature.len(),
        64,
        "Ed25519 signature must be 64 bytes"
    );

    // ── Step D: verify Ed25519 response signature ─────────────────────────────
    // Message layout from service.rs::sign_response:
    //   canonical_bytes || encrypted_share_bytes || timestamp_be8
    let vk = VerifyingKey::from_bytes(&val_vk_bytes).expect("valid verifying key");
    let mut msg = response.canonical.as_bytes().to_vec();
    msg.extend_from_slice(&response.encrypted_share);
    msg.extend_from_slice(&response.timestamp.to_be_bytes());

    let sig_bytes: [u8; 64] = response
        .signature
        .try_into()
        .expect("signature must be exactly 64 bytes");
    let sig = Signature::from_bytes(&sig_bytes);

    vk.verify(&msg, &sig)
        .expect("response signature must verify against validator's public key");
}

/// Requesting decryption for a package with no stored share produces no response.
#[tokio::test]
async fn test_e2e_service_no_share_no_response() {
    let (val_sk_bytes, val_vk_bytes) = gen_ed25519();
    let config = ServiceConfig {
        validator_id: "validator-empty".to_string(),
        validator_key: val_sk_bytes.to_vec(),
        validator_pubkey: val_vk_bytes.to_vec(),
        threshold: 2,
        total_shares: 3,
        request_timeout: 60,
        max_concurrent: 10,
    };

    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel::<DecryptionCommand>(16);
    let (resp_tx, mut resp_rx) =
        tokio::sync::mpsc::channel::<threshold_encryption::distribution::DecryptionResponse>(16);

    let service = DecryptionService::new(config, cmd_rx, resp_tx).expect("service init ok");
    tokio::spawn(service.run());

    // Send a request for a package we never stored a share for.
    let request = DecryptionRequest {
        canonical: "cargo:unknown@0.0.1".to_string(),
        requestor: "nobody".to_string(),
        requestor_pubkey: vec![0u8; 32],
        timestamp: unix_now(),
        signature: vec![],
        purpose: "test".to_string(),
    };
    cmd_tx
        .send(DecryptionCommand::ProcessRequest(request))
        .await
        .expect("send ok");

    // Expect no response within 100 ms.
    let result =
        tokio::time::timeout(tokio::time::Duration::from_millis(100), resp_rx.recv()).await;

    assert!(
        result.is_err(),
        "service must not emit a response when no share is stored"
    );
}

// --------------------------------------------------------------------------
// 4. DecryptionCoordinator request validation
// --------------------------------------------------------------------------

/// Valid signed request is accepted; expired and tampered requests are rejected.
#[test]
fn test_e2e_coordinator_request_validation() {
    let (req_sk, req_vk) = gen_ed25519();
    let requestor_pubkey = req_vk.to_vec();

    // Need 3 validators registered (total_shares = 3).
    let mut distributor = ShareDistributor::new(2, 3).expect("valid threshold");
    for i in 1..=3u8 {
        distributor.register_validator(format!("val-{i}"), gen_secp256k1().0);
    }
    let mut coordinator = DecryptionCoordinator::new(distributor);

    let canonical = "pypi:requests@2.28.0";
    let now = unix_now();

    // ── Valid signed request ──────────────────────────────────────────────────
    let valid_req = signed_request(canonical, "audit", &req_sk, requestor_pubkey.clone(), now);
    assert!(
        coordinator.request_decryption(valid_req).is_ok(),
        "valid signed request must be accepted"
    );

    // ── No partial shares yet → not ready ────────────────────────────────────
    assert!(
        !coordinator.is_ready(canonical),
        "coordinator must not be ready before any partial shares arrive"
    );

    // ── Expired request (timestamp > 3600s old) ───────────────────────────────
    let stale_ts = now.saturating_sub(3601);
    let stale_req = signed_request(
        canonical,
        "audit",
        &req_sk,
        requestor_pubkey.clone(),
        stale_ts,
    );
    assert!(
        coordinator.request_decryption(stale_req).is_err(),
        "expired request must be rejected"
    );

    // ── Tampered signature (last byte flipped) ────────────────────────────────
    let mut tampered_req = signed_request(
        canonical,
        "audit",
        &req_sk,
        requestor_pubkey.clone(),
        unix_now(),
    );
    let sig_len = tampered_req.signature.len();
    tampered_req.signature[sig_len - 1] ^= 0x01;
    assert!(
        coordinator.request_decryption(tampered_req).is_err(),
        "tampered signature must be rejected"
    );
}

/// Coordinator collects partial shares and reports ready once M are received.
#[test]
fn test_e2e_coordinator_collects_partial_shares_and_becomes_ready() {
    let (req_sk, req_vk) = gen_ed25519();
    let (v1_sk, v1_vk) = gen_ed25519();

    let mut distributor = ShareDistributor::new(2, 3).expect("valid threshold");
    for i in 1..=3u8 {
        distributor.register_validator(format!("val-{i}"), gen_secp256k1().0);
    }
    let mut coordinator = DecryptionCoordinator::new(distributor);

    // Register val-1's Ed25519 key so its signature can be verified.
    coordinator.register_validator_pubkey("val-1".to_string(), v1_vk.to_vec());
    // val-2 is not registered → unknown validator → allowed through with a warning.

    let canonical = "cargo:serde@1.0.190";
    let req = signed_request(canonical, "test", &req_sk, req_vk.to_vec(), unix_now());
    coordinator
        .request_decryption(req)
        .expect("request accepted");

    // Build a signed partial response from val-1.
    let enc_share_bytes = vec![0xaa; 48]; // arbitrary blob
    let ts = unix_now();
    let val1_signature = {
        let sk = SigningKey::from_bytes(&v1_sk);
        let mut msg = canonical.as_bytes().to_vec();
        msg.extend_from_slice(&enc_share_bytes);
        msg.extend_from_slice(&ts.to_be_bytes());
        sk.sign(&msg).to_bytes().to_vec()
    };

    let partial1 = DecryptionResponse {
        validator_id: "val-1".to_string(),
        canonical: canonical.to_string(),
        encrypted_share: enc_share_bytes.clone(),
        share_index: 1,
        timestamp: ts,
        signature: val1_signature,
    };
    coordinator
        .submit_partial(canonical, partial1)
        .expect("partial 1 accepted");
    assert!(
        !coordinator.is_ready(canonical),
        "need 2 shares for 2-of-3, have 1"
    );

    // Second partial from unregistered val-2 (empty sig → allowed, logged as warning).
    let partial2 = DecryptionResponse {
        validator_id: "val-2".to_string(),
        canonical: canonical.to_string(),
        encrypted_share: enc_share_bytes,
        share_index: 2,
        timestamp: ts,
        signature: vec![],
    };
    coordinator
        .submit_partial(canonical, partial2)
        .expect("partial 2 accepted");
    assert!(
        coordinator.is_ready(canonical),
        "2 shares collected — coordinator must report ready"
    );

    let collected = coordinator
        .get_collected_shares(canonical)
        .expect("collected shares must be present");
    assert_eq!(collected.len(), 2, "exactly 2 partial shares");
}

// --------------------------------------------------------------------------
// 5. AccessPolicy + ShareDistributor integration
// --------------------------------------------------------------------------

/// access_control::AccessPolicy enforces size, ecosystem, and stake rules.
#[test]
fn test_e2e_access_policy_strict_rules() {
    let strict = AccessPolicy::strict();

    // All valid.
    assert!(strict.validate_package(1_000, "npm", 200_000).is_ok());
    assert!(strict.validate_package(5_000_000, "pypi", 100_001).is_ok());

    // Over the 10 MB size limit.
    assert!(
        strict
            .validate_package(10 * 1024 * 1024 + 1, "npm", 200_000)
            .is_err(),
        "over-size must fail"
    );

    // Disallowed ecosystem.
    assert!(
        strict.validate_package(1_000, "cargo", 200_000).is_err(),
        "cargo must be disallowed by strict policy"
    );

    // Insufficient stake.
    assert!(
        strict.validate_package(1_000, "npm", 99_999).is_err(),
        "stake below 100k must fail"
    );
}

/// Relaxed policy accepts everything that strict rejects.
#[test]
fn test_e2e_access_policy_relaxed_allows_all() {
    let relaxed = AccessPolicy::relaxed();
    assert!(relaxed.validate_package(400_000_000, "cargo", 0).is_ok());
    assert!(relaxed.validate_package(1, "maven", 1).is_ok());
}

/// Role-based permission checks.
#[test]
fn test_e2e_role_permissions() {
    assert!(Role::Admin.has_permission(Permission::Manage));
    assert!(Role::Admin.has_permission(Permission::Publish));
    assert!(Role::Admin.has_permission(Permission::Decrypt));

    assert!(Role::Publisher.has_permission(Permission::Publish));
    assert!(!Role::Publisher.has_permission(Permission::Manage));
    assert!(!Role::Publisher.has_permission(Permission::Decrypt));

    assert!(Role::Reader.has_permission(Permission::Read));
    assert!(Role::Reader.has_permission(Permission::Decrypt));
    assert!(!Role::Reader.has_permission(Permission::Publish));

    assert!(Role::Observer.has_permission(Permission::Read));
    assert!(!Role::Observer.has_permission(Permission::Decrypt));
}

/// ShareDistributor: register validators → distribute shares → confirm → can_decrypt.
#[test]
fn test_e2e_share_distributor_full_flow() {
    let mut distributor = ShareDistributor::new(2, 3).expect("valid threshold");

    // Register 3 secp256k1 public keys (one per validator).
    for i in 1..=3u8 {
        distributor.register_validator(format!("val-{i}"), gen_secp256k1().0);
    }

    let canonical = "npm:lodash@4.17.21";
    let mut encryption_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut encryption_key);
    let policy = ShieldedAccessPolicy::default();

    let distributed = distributor
        .distribute_shares(canonical, &encryption_key, &policy)
        .expect("distribute_shares must succeed");

    assert_eq!(distributed.len(), 3, "one share per validator");

    // No confirmations yet.
    assert!(
        !distributor.can_decrypt(canonical),
        "no confirmations → can_decrypt must be false"
    );

    // Confirm val-1 (1 of 2 needed).
    distributor
        .confirm_share(canonical, "val-1")
        .expect("confirm val-1");
    assert!(
        !distributor.can_decrypt(canonical),
        "only 1 confirmation — still below threshold"
    );

    // Confirm val-2 (2 of 2 needed).
    distributor
        .confirm_share(canonical, "val-2")
        .expect("confirm val-2");
    assert!(
        distributor.can_decrypt(canonical),
        "2 confirmations — can_decrypt must be true"
    );

    // Confirm non-existent share.
    let err = distributor.confirm_share(canonical, "val-99");
    assert!(
        err.is_err(),
        "confirming a non-existent share must return an error"
    );
}

/// ShareDistributor with fewer registered validators than total_shares must fail.
#[test]
fn test_e2e_share_distributor_insufficient_validators() {
    let mut distributor = ShareDistributor::new(2, 3).expect("valid threshold");
    // Register only 2 validators, but total_shares = 3.
    distributor.register_validator("val-1".to_string(), gen_secp256k1().0);
    distributor.register_validator("val-2".to_string(), gen_secp256k1().0);

    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    let result =
        distributor.distribute_shares("npm:pkg@1.0.0", &key, &ShieldedAccessPolicy::default());
    assert!(
        result.is_err(),
        "distribute_shares must fail when fewer validators than total_shares"
    );
}
