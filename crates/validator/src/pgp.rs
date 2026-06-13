// crates/validator/src/pgp.rs
// Web-of-Trust (WoT) PGP signature verification using the `pgp` crate.
// Verifies a detached armored or binary PGP signature over the tarball bytes.

use common::{Finding, FindingSeverity};
use pgp::types::KeyTrait;
use pgp::{Deserializable, SignedPublicKey, StandaloneSignature};

pub struct PgpResult {
    pub findings: Vec<Finding>,
    pub fingerprint: Option<String>,
}

/// Verify a detached PGP signature for the tarball.
/// `signature_bytes`  — raw bytes of the detached sig (armored or binary)
/// `public_key_bytes` — raw bytes of the signer's public key (armored or binary)
pub fn verify_signature(
    tarball: &[u8],
    signature_bytes: &[u8],
    public_key_bytes: &[u8],
) -> PgpResult {
    // Parse public key — try ASCII-armor first, fall back to binary DER.
    let pubkey_result = SignedPublicKey::from_armor_single(std::io::Cursor::new(public_key_bytes))
        .map(|(k, _)| k)
        .or_else(|_| SignedPublicKey::from_bytes(std::io::Cursor::new(public_key_bytes)));

    let pubkey = match pubkey_result {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!("PGP: failed to parse public key: {}", e);
            return PgpResult {
                findings: vec![Finding {
                    id: "PGP001".into(),
                    title: "Invalid PGP public key".into(),
                    severity: FindingSeverity::High,
                    description: format!("Could not parse publisher PGP public key: {}", e),
                    file: "pgp".into(),
                    line: None,
                }],
                fingerprint: None,
            };
        }
    };

    // Parse detached signature — try ASCII-armor first, fall back to binary.
    let sig_result = StandaloneSignature::from_armor_single(std::io::Cursor::new(signature_bytes))
        .map(|(s, _)| s)
        .or_else(|_| StandaloneSignature::from_bytes(std::io::Cursor::new(signature_bytes)));

    let sig = match sig_result {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("PGP: failed to parse detached signature: {}", e);
            return PgpResult {
                findings: vec![Finding {
                    id: "PGP002".into(),
                    title: "Invalid PGP signature format".into(),
                    severity: FindingSeverity::High,
                    description: format!("Could not parse PGP detached signature: {}", e),
                    file: "pgp".into(),
                    line: None,
                }],
                fingerprint: None,
            };
        }
    };

    // Verify signature over the raw tarball bytes.
    let fingerprint = hex::encode(pubkey.fingerprint());
    match sig.verify(&pubkey, tarball) {
        Ok(()) => {
            tracing::info!("PGP: signature verified — fp {}", &fingerprint[..16]);
            PgpResult {
                findings: vec![],
                fingerprint: Some(fingerprint),
            }
        }
        Err(e) => {
            tracing::warn!("PGP: invalid signature — fp {}: {}", &fingerprint[..16], e);
            PgpResult {
                findings: vec![Finding {
                    id: "PGP003".into(),
                    title: "PGP signature verification failed".into(),
                    severity: FindingSeverity::Critical,
                    description: format!(
                        "Tarball signature does not match public key (fp {}): {}",
                        fingerprint, e
                    ),
                    file: "pgp".into(),
                    line: None,
                }],
                fingerprint: Some(fingerprint),
            }
        }
    }
}
