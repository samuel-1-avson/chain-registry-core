//! Warnings for secp256k1 keys loaded from environment (SEC-101b).

use sha2::{Digest, Sha256};

/// Short fingerprint for logs (first 8 bytes of SHA-256 of raw key bytes). Never logs the key itself.
pub fn secp256k1_key_fingerprint(key_hex: &str) -> String {
    let cleaned = key_hex.trim().trim_start_matches("0x");
    let bytes = hex::decode(cleaned).unwrap_or_default();
    let hash = Sha256::digest(&bytes);
    format!("0x{}", hex::encode(&hash[..8]))
}

/// Emit a startup warning when a hot key is loaded outside testnet mode.
pub fn warn_hot_key_from_env(service: &str, env_var: &str, key_hex: &str, testnet_mode: bool) {
    if testnet_mode || key_hex.trim().is_empty() {
        return;
    }
    let fingerprint = secp256k1_key_fingerprint(key_hex);
    tracing::warn!(
        service = service,
        env_var = env_var,
        fingerprint = %fingerprint,
        "Hot secp256k1 key loaded from environment; use KMS/Vault in production and rotate if exposed"
    );
}

pub fn is_testnet_env() -> bool {
    std::env::var("CREG_TESTNET")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable_and_short() {
        let fp = secp256k1_key_fingerprint(
            "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
        );
        assert!(fp.starts_with("0x"));
        assert_eq!(fp.len(), 2 + 16);
    }
}
