//! Batch state-transition ZK proving for the L2 rollup bridge.
//!
//! This module provides the `BatchStateTransitionValidator` which generates
//! and verifies Groth16 proofs for the [`BatchStateTransitionCircuit`].
//!
//! The validator is designed to be held as a long-lived shared object
//! (`Arc<BatchStateTransitionValidator>`). Keys are loaded lazily on first
//! proof generation via `OnceLock` and reused across the node's lifetime.
//!
//! # Key storage
//!
//! Keys are stored under `$CREG_ZK_KEYS_DIR` (default `./circuits`):
//! - `batch_pk.bin` — Groth16 proving key (uncompressed arkworks format)
//! - `batch_vk.bin` — Groth16 verifying key
//!
//! On first use without existing key files, ephemeral keys are generated and
//! persisted with a warning. A trusted-ceremony setup should replace them.

use std::{
    path::PathBuf,
    sync::{Arc, OnceLock},
};

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use tracing::{info, warn};

use crate::{circuits::BatchStateTransitionCircuit, ZkError, ZkProof};

// ── Lazy global key store ─────────────────────────────────────────────────────

static BATCH_KEYS: OnceLock<Arc<(ProvingKey<Bn254>, VerifyingKey<Bn254>)>> = OnceLock::new();

// ── Public types ──────────────────────────────────────────────────────────────

/// Inputs required to prove a batch state transition.
#[derive(Clone, Debug)]
pub struct BatchInputs {
    /// SHA-256 of the previous batch (on-chain `latestStateRoot()`).
    pub prev_root: [u8; 32],
    /// Merkle root of the batch transactions.
    pub data_root: [u8; 32],
    /// SHA-256(prev_root || data_root) — the new state root.
    pub next_root: [u8; 32],
    /// Number of transactions in this batch (must be ≥ 1).
    pub tx_count: u64,
}

impl BatchInputs {
    pub fn new(
        prev_root: [u8; 32],
        data_root: [u8; 32],
        next_root: [u8; 32],
        tx_count: u64,
    ) -> Self {
        Self {
            prev_root,
            data_root,
            next_root,
            tx_count,
        }
    }

    /// Produce the 6-element public input vector for the on-chain verifier.
    pub fn public_inputs(&self) -> Vec<Fr> {
        BatchStateTransitionCircuit::from_roots(
            &self.prev_root,
            &self.data_root,
            &self.next_root,
            self.tx_count,
        )
        .public_inputs()
    }

    /// Serialize the public inputs to big-endian 32-byte arrays.
    ///
    /// Returns one `[u8; 32]` per Fr element, suitable for on-chain ABI encoding.
    /// The bridge crate is responsible for converting these to its own U256 type.
    pub fn public_inputs_bytes(&self) -> Vec<[u8; 32]> {
        use ark_serialize::CanonicalSerialize;
        self.public_inputs()
            .iter()
            .map(|fr| {
                let mut le_bytes = Vec::new();
                fr.serialize_uncompressed(&mut le_bytes).unwrap_or_default();
                // ark-ff serializes in little-endian; reverse to big-endian.
                le_bytes.reverse();
                let mut out = [0u8; 32];
                let len = le_bytes.len().min(32);
                out[32 - len..].copy_from_slice(&le_bytes[..len]);
                out
            })
            .collect()
    }
}

/// Validator for batch state-transition proofs.
///
/// Holds a reference to the loaded Groth16 keys. Construct via
/// [`BatchStateTransitionValidator::new`] and share as `Arc<Self>`.
pub struct BatchStateTransitionValidator;

impl BatchStateTransitionValidator {
    /// Load (or generate) the batch ZK keys and return a validator handle.
    pub fn new() -> Result<Self, ZkError> {
        load_or_generate_keys()?;
        Ok(Self)
    }

    /// Generate a Groth16 proof for the given batch inputs.
    ///
    /// Runs synchronously (call inside `tokio::task::spawn_blocking` from
    /// async contexts — proof generation is CPU-bound and may take seconds).
    pub fn generate_proof(&self, inputs: &BatchInputs) -> Result<ZkProof, ZkError> {
        if inputs.tx_count == 0 {
            return Err(ZkError::InvalidInput(
                "tx_count must be ≥ 1 for a batch proof".into(),
            ));
        }

        let keys = load_or_generate_keys()?;
        let circuit = BatchStateTransitionCircuit::from_roots(
            &inputs.prev_root,
            &inputs.data_root,
            &inputs.next_root,
            inputs.tx_count,
        );

        let mut rng = rand::thread_rng();
        let proof = Groth16::<Bn254>::prove(&keys.0, circuit, &mut rng)
            .map_err(|e| ZkError::ProofGenerationError(e.to_string()))?;

        // Self-verify before returning — catches key mismatches immediately.
        let public_inputs = inputs.public_inputs();
        let ok = Groth16::<Bn254>::verify(&keys.1, &public_inputs, &proof)
            .map_err(|e| ZkError::VerificationError(e.to_string()))?;
        if !ok {
            return Err(ZkError::VerificationError(
                "generated batch proof failed self-verification; \
                 keys may be stale — delete batch_pk.bin and batch_vk.bin to regenerate"
                    .into(),
            ));
        }

        info!(
            tx_count = inputs.tx_count,
            "Batch state-transition ZK proof generated and self-verified"
        );
        Ok(proof)
    }

    /// Verify a batch state-transition proof.
    pub fn verify_proof(&self, proof: &ZkProof, inputs: &BatchInputs) -> Result<bool, ZkError> {
        let keys = load_or_generate_keys()?;
        let public_inputs = inputs.public_inputs();
        Groth16::<Bn254>::verify(&keys.1, &public_inputs, proof)
            .map_err(|e| ZkError::VerificationError(e.to_string()))
    }

    /// Serialize a proof to bytes (uncompressed arkworks format).
    pub fn serialize_proof(proof: &ZkProof) -> Result<Vec<u8>, ZkError> {
        let mut bytes = Vec::new();
        proof
            .serialize_uncompressed(&mut bytes)
            .map_err(|e| ZkError::SerializationError(e.to_string()))?;
        Ok(bytes)
    }

    /// Serialize a proof to eight 32-byte big-endian chunks.
    ///
    /// Layout: [Ax, Ay, Bx0, Bx1, By0, By1, Cx, Cy], matching the
    /// `uint256[8] proof` parameter expected by `submitRollupBatch`.
    /// The bridge crate converts these to its own U256 type.
    pub fn proof_to_chunks(proof: &ZkProof) -> Result<Vec<[u8; 32]>, ZkError> {
        let bytes = Self::serialize_proof(proof)?;
        let chunks: Vec<[u8; 32]> = bytes
            .chunks(32)
            .take(8)
            .map(|chunk| {
                let mut out = [0u8; 32];
                out[32 - chunk.len()..].copy_from_slice(chunk);
                out
            })
            .collect();
        Ok(chunks)
    }
}

// ── Key management ────────────────────────────────────────────────────────────

const PK_FILE: &str = "batch_pk.bin";
const VK_FILE: &str = "batch_vk.bin";

fn keys_dir() -> PathBuf {
    std::env::var("CREG_ZK_KEYS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("circuits"))
}

fn load_or_generate_keys() -> Result<Arc<(ProvingKey<Bn254>, VerifyingKey<Bn254>)>, ZkError> {
    if let Some(arc) = BATCH_KEYS.get() {
        return Ok(Arc::clone(arc));
    }

    let dir = keys_dir();
    let pk_path = dir.join(PK_FILE);
    let vk_path = dir.join(VK_FILE);

    let pair = if pk_path.exists() && vk_path.exists() {
        info!("Loading batch ZK keys from {}", dir.display());
        let pk_bytes = std::fs::read(&pk_path)
            .map_err(|e| ZkError::SerializationError(format!("Read batch_pk.bin: {}", e)))?;
        let vk_bytes = std::fs::read(&vk_path)
            .map_err(|e| ZkError::SerializationError(format!("Read batch_vk.bin: {}", e)))?;

        let pk = ProvingKey::<Bn254>::deserialize_uncompressed(pk_bytes.as_slice())
            .map_err(|e| ZkError::SerializationError(e.to_string()))?;
        let vk = VerifyingKey::<Bn254>::deserialize_uncompressed(vk_bytes.as_slice())
            .map_err(|e| ZkError::SerializationError(e.to_string()))?;
        (pk, vk)
    } else {
        if std::env::var("CREG_PRODUCTION")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
        {
            return Err(ZkError::InvalidInput(format!(
                "PRODUCTION GUARD: Batch ZK key files not found in '{}'. \
                 Refusing to generate ephemeral keys on a production node. \
                 Run `creg advanced zk-setup`, or set CREG_ZK_KEYS_DIR correctly.",
                dir.display()
            )));
        }

        warn!(
            "Batch ZK key files not found in {} — generating ephemeral keys. \
             These keys are NOT from a trusted ceremony and must not be used in \
             production. Set CREG_PRODUCTION=true to make this a hard error. \
             Run `creg advanced zk-setup` to generate proper keys.",
            dir.display()
        );

        let circuit = BatchStateTransitionCircuit::default();
        let mut rng = rand::thread_rng();
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng)
            .map_err(|e| ZkError::ProofGenerationError(e.to_string()))?;

        // Best-effort persist.
        if let Err(e) = save_keys(&dir, &pk, &vk) {
            warn!("Could not persist generated batch ZK keys: {}", e);
        }

        (pk, vk)
    };

    let arc = Arc::new(pair);
    // OnceLock::set may fail if another thread raced us; in that case use
    // whatever was stored by the winner.
    let _ = BATCH_KEYS.set(Arc::clone(&arc));
    Ok(BATCH_KEYS.get().cloned().unwrap_or(arc))
}

fn save_keys(
    dir: &std::path::Path,
    pk: &ProvingKey<Bn254>,
    vk: &VerifyingKey<Bn254>,
) -> Result<(), ZkError> {
    std::fs::create_dir_all(dir)
        .map_err(|e| ZkError::SerializationError(format!("Create key dir: {}", e)))?;

    let mut pk_bytes = Vec::new();
    pk.serialize_uncompressed(&mut pk_bytes)
        .map_err(|e| ZkError::SerializationError(e.to_string()))?;
    std::fs::write(dir.join(PK_FILE), &pk_bytes)
        .map_err(|e| ZkError::SerializationError(format!("Write {}: {}", PK_FILE, e)))?;

    let mut vk_bytes = Vec::new();
    vk.serialize_uncompressed(&mut vk_bytes)
        .map_err(|e| ZkError::SerializationError(e.to_string()))?;
    std::fs::write(dir.join(VK_FILE), &vk_bytes)
        .map_err(|e| ZkError::SerializationError(format!("Write {}: {}", VK_FILE, e)))?;

    info!("Batch ZK keys saved to {}", dir.display());
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_inputs(tx_count: u64) -> BatchInputs {
        BatchInputs::new([0x01u8; 32], [0x02u8; 32], [0x03u8; 32], tx_count)
    }

    #[test]
    fn test_batch_prove_and_verify() {
        let validator = BatchStateTransitionValidator::new().unwrap();
        let inputs = make_inputs(5);
        let proof = validator
            .generate_proof(&inputs)
            .expect("proof generation must succeed");
        let ok = validator
            .verify_proof(&proof, &inputs)
            .expect("verification must not error");
        assert!(ok, "self-generated proof must verify");
    }

    #[test]
    fn test_batch_empty_batch_rejected() {
        let validator = BatchStateTransitionValidator::new().unwrap();
        let inputs = make_inputs(0);
        let result = validator.generate_proof(&inputs);
        assert!(
            result.is_err(),
            "tx_count=0 must be rejected before proving"
        );
    }

    #[test]
    fn test_batch_wrong_inputs_fails_verify() {
        let validator = BatchStateTransitionValidator::new().unwrap();
        let inputs = make_inputs(3);
        let proof = validator.generate_proof(&inputs).unwrap();

        // Verify against different inputs — must fail.
        let wrong = BatchInputs::new([0xFF; 32], [0xFF; 32], [0xFF; 32], 3);
        let ok = validator.verify_proof(&proof, &wrong).unwrap_or(false);
        assert!(!ok, "proof must not verify against wrong public inputs");
    }

    #[test]
    fn test_batch_public_inputs_bytes_count() {
        let inputs = make_inputs(1);
        assert_eq!(
            inputs.public_inputs_bytes().len(),
            6,
            "must produce 6 big-endian byte arrays"
        );
        for chunk in inputs.public_inputs_bytes() {
            assert_eq!(chunk.len(), 32, "each public input must be 32 bytes");
        }
    }

    #[test]
    fn test_batch_proof_to_chunks() {
        let validator = BatchStateTransitionValidator::new().unwrap();
        let inputs = make_inputs(2);
        let proof = validator.generate_proof(&inputs).unwrap();
        let chunks = BatchStateTransitionValidator::proof_to_chunks(&proof)
            .expect("serialization must succeed");
        assert_eq!(chunks.len(), 8, "proof must serialize to 8 chunks");
    }
}
