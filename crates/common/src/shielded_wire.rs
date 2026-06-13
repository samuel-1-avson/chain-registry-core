//! On-wire format for `creg publish --shield` (SEC-304/305).
//!
//! Tarball bytes on IPFS: `nonce (12) || aes256_gcm_ciphertext`.
//! Key bundle on the publish request: `plain:<key_hex>:<nonce_hex>` or `ecies:...`.

use anyhow::{bail, Context, Result};
use rand::RngCore;

/// Encrypt a plaintext tarball for validator decryption.
///
/// When `validator_pubkey_x25519` is `None`, emits a `plain:` bundle (dev only).
pub fn encrypt_shielded_package(
    plaintext: &[u8],
    validator_pubkey_x25519: Option<&[u8; 32]>,
) -> Result<(Vec<u8>, String)> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Key, Nonce,
    };

    let mut aes_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut aes_key);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("shielded encrypt failed: {}", e))?;

    let raw_bundle = format!("{}:{}", hex::encode(aes_key), hex::encode(nonce_bytes));

    let bundle = match validator_pubkey_x25519 {
        Some(pubkey) => ecies_wrap_bundle(pubkey, &raw_bundle)?,
        None => format!("plain:{}", raw_bundle),
    };

    let mut wire = nonce_bytes.to_vec();
    wire.extend(ciphertext);
    Ok((wire, bundle))
}

/// Decrypt shielded IPFS bytes using the publish request key bundle.
pub fn decrypt_shielded_package(wire: &[u8], bundle: &str) -> Result<Vec<u8>> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

    let (aes_key, aes_nonce) = parse_key_bundle(bundle)?;

    if wire.len() < 12 + 16 {
        bail!(
            "shielded tarball too short ({} bytes) — expected nonce(12) + ciphertext(≥16)",
            wire.len()
        );
    }

    if &wire[..12] != aes_nonce.as_slice() {
        bail!("shielded tarball nonce prefix does not match authenticated bundle nonce");
    }

    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|e| anyhow::anyhow!("invalid AES key from bundle: {}", e))?;
    cipher
        .decrypt(Nonce::from_slice(&aes_nonce), &wire[12..])
        .map_err(|e| anyhow::anyhow!("shielded AES-GCM decrypt failed: {}", e))
}

fn ecies_wrap_bundle(validator_pubkey: &[u8; 32], raw_bundle: &str) -> Result<String> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Key, Nonce,
    };
    use sha2::{Digest, Sha256};
    use x25519_dalek::{EphemeralSecret, PublicKey};

    let their_public = PublicKey::from(*validator_pubkey);
    let ephemeral_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let shared = ephemeral_secret.diffie_hellman(&their_public);
    let wrap_key_bytes: [u8; 32] = Sha256::digest(shared.as_bytes()).into();
    let wrap_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&wrap_key_bytes));

    let mut wrap_nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut wrap_nonce_bytes);
    let wrap_nonce = Nonce::from_slice(&wrap_nonce_bytes);
    let wrapped = wrap_cipher
        .encrypt(wrap_nonce, raw_bundle.as_bytes())
        .map_err(|e| anyhow::anyhow!("ecies bundle wrap failed: {}", e))?;

    Ok(format!(
        "ecies:{}:{}:{}",
        hex::encode(ephemeral_public.as_bytes()),
        hex::encode(wrap_nonce_bytes),
        hex::encode(wrapped)
    ))
}

/// Parse `plain:` or `ecies:` key bundles from `PublishRequest.key_bundle`.
pub fn parse_key_bundle(bundle: &str) -> Result<([u8; 32], [u8; 12])> {
    if let Some(rest) = bundle.strip_prefix("plain:") {
        let (k_hex, n_hex) = rest
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("malformed plain bundle"))?;
        let key: [u8; 32] = hex::decode(k_hex)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("plain bundle: AES key must be 32 bytes"))?;
        let nonce: [u8; 12] = hex::decode(n_hex)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("plain bundle: nonce must be 12 bytes"))?;
        return Ok((key, nonce));
    }

    if let Some(rest) = bundle.strip_prefix("ecies:") {
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
        use sha2::{Digest, Sha256};
        use x25519_dalek::{PublicKey, StaticSecret};

        let parts: Vec<&str> = rest.split(':').collect();
        if parts.len() != 3 {
            bail!(
                "malformed ecies bundle: expected 3 fields, got {}",
                parts.len()
            );
        }
        let eph_pub: [u8; 32] = hex::decode(parts[0])?
            .try_into()
            .map_err(|_| anyhow::anyhow!("ecies: ephemeral pubkey must be 32 bytes"))?;
        let wrap_nonce_bytes: [u8; 12] = hex::decode(parts[1])?
            .try_into()
            .map_err(|_| anyhow::anyhow!("ecies: wrap nonce must be 12 bytes"))?;
        let wrapped = hex::decode(parts[2])?;

        let secret_hex = std::env::var("CREG_VALIDATOR_PRIVKEY_X25519").map_err(|_| {
            anyhow::anyhow!(
                "CREG_VALIDATOR_PRIVKEY_X25519 is not set — cannot decrypt ecies key bundle"
            )
        })?;
        let secret_bytes: [u8; 32] = hex::decode(secret_hex.trim())?
            .try_into()
            .map_err(|_| anyhow::anyhow!("CREG_VALIDATOR_PRIVKEY_X25519 must be 32 bytes"))?;

        let shared = StaticSecret::from(secret_bytes).diffie_hellman(&PublicKey::from(eph_pub));
        let wrap_key_bytes: [u8; 32] = Sha256::digest(shared.as_bytes()).into();
        let wrap_cipher = Aes256Gcm::new_from_slice(&wrap_key_bytes)
            .map_err(|e| anyhow::anyhow!("ecies wrap key init: {}", e))?;
        let raw = wrap_cipher
            .decrypt(Nonce::from_slice(&wrap_nonce_bytes), wrapped.as_slice())
            .map_err(|e| anyhow::anyhow!("ecies bundle unwrap failed: {}", e))?;
        let raw_bundle = std::str::from_utf8(&raw).context("ecies raw payload not UTF-8")?;
        let (k_hex, n_hex) = raw_bundle
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("ecies: malformed raw payload"))?;
        let key: [u8; 32] = hex::decode(k_hex)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("ecies: AES key must be 32 bytes"))?;
        let nonce: [u8; 12] = hex::decode(n_hex)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("ecies: AES nonce must be 12 bytes"))?;
        return Ok((key, nonce));
    }

    let preview: String = bundle.chars().take(16).collect();
    bail!(
        "unsupported key bundle format (expected 'plain:' or 'ecies:', got {:?}…)",
        preview
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());
        MUTEX.lock().unwrap()
    }

    #[test]
    fn plain_round_trip() {
        let plaintext = b"npm package payload for shielded e2e";
        let (wire, bundle) = encrypt_shielded_package(plaintext, None).unwrap();
        assert!(bundle.starts_with("plain:"));
        let got = decrypt_shielded_package(&wire, &bundle).unwrap();
        assert_eq!(got, plaintext);
    }

    #[test]
    fn ecies_round_trip() {
        let _lock = env_lock();
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let public = PublicKey::from(&secret);
        std::env::set_var(
            "CREG_VALIDATOR_PRIVKEY_X25519",
            hex::encode(secret.to_bytes()),
        );

        let plaintext = b"ecies shielded round trip";
        let (wire, bundle) = encrypt_shielded_package(plaintext, Some(public.as_bytes())).unwrap();
        assert!(bundle.starts_with("ecies:"));
        let got = decrypt_shielded_package(&wire, &bundle).unwrap();
        assert_eq!(got, plaintext);

        std::env::remove_var("CREG_VALIDATOR_PRIVKEY_X25519");
    }

    #[test]
    fn nonce_prefix_mismatch_fails() {
        let plaintext = b"data";
        let (mut wire, bundle) = encrypt_shielded_package(plaintext, None).unwrap();
        wire[0] ^= 0xff;
        assert!(decrypt_shielded_package(&wire, &bundle).is_err());
    }
}
