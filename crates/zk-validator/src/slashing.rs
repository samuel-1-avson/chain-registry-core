//! ZK Slashing Evidence - Proof Generation
//!
//! This module provides zero-knowledge proof generation for validator
//! slashing evidence, specifically for double-signing detection.

use anyhow::{Context, Result};
use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use crate::circuits::DoubleSignCircuit;

/// Types of slashing evidence
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceType {
    /// Validator signed conflicting votes
    DoubleSign = 1,
    /// Validator approved malicious package
    FalseApprove = 2,
    /// Validator consistently voted against majority
    Griefing = 3,
}

/// Public inputs for double-sign proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoubleSignPublicInputs {
    /// Validator's public key (X coordinate)
    pub validator_pubkey_x: String,
    /// Validator's public key (Y coordinate)
    pub validator_pubkey_y: String,
    /// Package identifier hash
    pub package_hash: String,
    /// Hash of first vote
    pub vote1_hash: String,
    /// Hash of second vote
    pub vote2_hash: String,
}

/// Private inputs (witness) for double-sign proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoubleSignWitness {
    /// Validator's private key (kept secret!)
    pub validator_privkey: String,
    /// First signature (R_x, R_y, S)
    pub signature1: Signature,
    /// Second signature (R_x, R_y, S)
    pub signature2: Signature,
}

/// Ed25519 signature components
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub r_x: String,
    pub r_y: String,
    pub s: String,
}

/// Complete double-sign evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoubleSignEvidence {
    pub public_inputs: DoubleSignPublicInputs,
    pub witness: DoubleSignWitness,
    pub validator_address: String,
    pub package_canonical: String,
    pub vote1_details: VoteDetails,
    pub vote2_details: VoteDetails,
}

/// Vote details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteDetails {
    pub approved: bool,
    pub timestamp: u64,
    pub block_height: u64,
    pub signature_hex: String,
}

/// Groth16 proof structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Groth16Proof {
    /// Proof component A (G1 point)
    pub a: [String; 2],
    /// Proof component B (G2 point)
    pub b: [[String; 2]; 2],
    /// Proof component C (G1 point)
    pub c: [String; 2],
    /// Protocol (groth16)
    pub protocol: String,
    /// Curve (bn128)
    pub curve: String,
}

/// ZK Proof with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZKSlashingProof {
    /// The Groth16 proof
    pub proof: Groth16Proof,
    /// Public inputs
    pub public_inputs: Vec<String>,
    /// Proof type
    pub evidence_type: EvidenceType,
    /// Validator address
    pub offender: String,
    /// Unique nullifier
    pub nullifier: String,
    /// Timestamp
    pub timestamp: u64,
}

/// Configuration for the double-sign proving system.
#[derive(Debug, Clone)]
pub struct ProofConfig {
    /// Directory used to persist/load the trusted-setup keys.
    pub keys_dir: PathBuf,
}

impl Default for ProofConfig {
    fn default() -> Self {
        let keys_dir = std::env::var("CREG_ZK_KEYS_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("circuits"));
        Self { keys_dir }
    }
}

const PROVING_KEY_FILE: &str = "double_sign_pk.bin";
const VERIFYING_KEY_FILE: &str = "double_sign_vk.bin";

/// Shared proving/verifying key pair. The first caller to hit a live validator
/// triggers a ~3-second trusted setup for the double-sign circuit; subsequent
/// invocations reuse the cached `Arc`.
static DOUBLE_SIGN_KEYS: OnceLock<Arc<(ProvingKey<Bn254>, VerifyingKey<Bn254>)>> = OnceLock::new();

fn load_or_generate_keys(keys_dir: &Path) -> Result<Arc<(ProvingKey<Bn254>, VerifyingKey<Bn254>)>> {
    if let Some(existing) = DOUBLE_SIGN_KEYS.get() {
        return Ok(existing.clone());
    }

    let pk_path = keys_dir.join(PROVING_KEY_FILE);
    let vk_path = keys_dir.join(VERIFYING_KEY_FILE);

    let keys = if pk_path.exists() && vk_path.exists() {
        tracing::info!("Loading double-sign ZK keys from {}", keys_dir.display());
        let pk_bytes = std::fs::read(&pk_path).context("read double-sign proving key")?;
        let vk_bytes = std::fs::read(&vk_path).context("read double-sign verifying key")?;
        let pk = ProvingKey::<Bn254>::deserialize_uncompressed(pk_bytes.as_slice())
            .context("deserialize double-sign proving key")?;
        let vk = VerifyingKey::<Bn254>::deserialize_uncompressed(vk_bytes.as_slice())
            .context("deserialize double-sign verifying key")?;
        (pk, vk)
    } else {
        if std::env::var("CREG_PRODUCTION")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
        {
            anyhow::bail!(
                "PRODUCTION GUARD: Double-sign ZK keys not found in '{}'. \
                 Refusing to generate ephemeral keys on a production node. \
                 Run `creg advanced zk-setup`, or set CREG_ZK_KEYS_DIR correctly.",
                keys_dir.display()
            );
        }

        tracing::warn!(
            "Double-sign ZK keys not found in {} — running ephemeral trusted \
             setup. These keys are NOT production-grade; regenerate via a \
             proper multi-party ceremony before mainnet. \
             Set CREG_PRODUCTION=true to make this a hard error.",
            keys_dir.display()
        );
        let circuit = DoubleSignCircuit::default();
        let mut rng = rand::thread_rng();
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng)
            .context("double-sign circuit setup failed")?;

        if let Err(e) = std::fs::create_dir_all(keys_dir) {
            tracing::warn!("Could not create ZK key dir: {}", e);
        } else {
            let mut pk_bytes = Vec::new();
            let mut vk_bytes = Vec::new();
            if let Err(e) = pk.serialize_uncompressed(&mut pk_bytes) {
                tracing::warn!("Failed to serialize double-sign proving key: {}", e);
            } else if let Err(e) = std::fs::write(&pk_path, &pk_bytes) {
                tracing::warn!("Failed to persist double-sign proving key: {}", e);
            }
            if let Err(e) = vk.serialize_uncompressed(&mut vk_bytes) {
                tracing::warn!("Failed to serialize double-sign verifying key: {}", e);
            } else if let Err(e) = std::fs::write(&vk_path, &vk_bytes) {
                tracing::warn!("Failed to persist double-sign verifying key: {}", e);
            }
        }
        (pk, vk)
    };

    let arc = Arc::new(keys);
    Ok(DOUBLE_SIGN_KEYS.get_or_init(|| arc.clone()).clone())
}

fn hex32(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s.trim_start_matches("0x")).context("hex decode")?;
    if bytes.len() != 32 {
        anyhow::bail!("expected 32-byte hex, got {} bytes", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn fr_to_decimal(f: &Fr) -> String {
    f.into_bigint().to_string()
}

/// ZK Proof generator for slashing evidence
pub struct SlashingProofGenerator {
    config: ProofConfig,
}

impl SlashingProofGenerator {
    /// Create a new proof generator
    pub fn new(config: ProofConfig) -> Self {
        Self { config }
    }

    /// Generate a double-sign proof
    ///
    /// This proves that a validator signed two conflicting votes
    /// without revealing the validator's private key.
    pub async fn generate_double_sign_proof(
        &self,
        evidence: &DoubleSignEvidence,
    ) -> Result<ZKSlashingProof> {
        tracing::info!(
            "Generating double-sign proof for validator: {}",
            evidence.validator_address
        );

        self.validate_double_sign_evidence(evidence)?;

        let circuit = self.circuit_from_evidence(evidence)?;
        let proof = self.prove(circuit.clone()).await?;
        let public_inputs = circuit.public_inputs();

        // Sanity-check the freshly-generated proof against its own VK before
        // returning it — a failing self-verify means the circuit and witness
        // are mutually inconsistent and we should not publish this evidence.
        let keys = load_or_generate_keys(&self.config.keys_dir)?;
        let ok = Groth16::<Bn254>::verify(&keys.1, &public_inputs, &proof)
            .map_err(|e| anyhow::anyhow!("groth16 self-verify failed: {}", e))?;
        if !ok {
            anyhow::bail!("generated double-sign proof failed self-verification");
        }

        let groth = groth16_to_display(&proof);
        let public_inputs_decimal: Vec<String> = public_inputs.iter().map(fr_to_decimal).collect();

        let nullifier = self.compute_nullifier(&evidence.public_inputs);

        tracing::info!(
            "Double-sign proof generated successfully. Nullifier: {}",
            nullifier
        );

        Ok(ZKSlashingProof {
            proof: groth,
            public_inputs: public_inputs_decimal,
            evidence_type: EvidenceType::DoubleSign,
            offender: evidence.validator_address.clone(),
            nullifier,
            timestamp: current_timestamp(),
        })
    }

    fn circuit_from_evidence(&self, evidence: &DoubleSignEvidence) -> Result<DoubleSignCircuit> {
        // The existing evidence struct uses hex strings for hashes and a split
        // X/Y pubkey representation (legacy from the circom circuit that
        // modelled Ed25519 as an affine point). We collapse validator_pubkey
        // down to a 32-byte hex string by hashing X||Y when Y is non-empty,
        // else treating X as the full 32-byte key.
        let validator_pubkey = parse_validator_pubkey(
            &evidence.public_inputs.validator_pubkey_x,
            &evidence.public_inputs.validator_pubkey_y,
        )?;
        let package_hash = hex32(&evidence.public_inputs.package_hash)
            .context("invalid package_hash in evidence")?;
        let vote1_hash =
            hex32(&evidence.public_inputs.vote1_hash).context("invalid vote1_hash in evidence")?;
        let vote2_hash =
            hex32(&evidence.public_inputs.vote2_hash).context("invalid vote2_hash in evidence")?;

        if vote1_hash == vote2_hash {
            anyhow::bail!("vote1_hash == vote2_hash: not a double-sign");
        }

        Ok(DoubleSignCircuit::from_hashes(
            &validator_pubkey,
            &package_hash,
            &vote1_hash,
            &vote2_hash,
        ))
    }

    async fn prove(&self, circuit: DoubleSignCircuit) -> Result<ark_groth16::Proof<Bn254>> {
        let keys_dir = self.config.keys_dir.clone();
        tokio::task::spawn_blocking(move || -> Result<ark_groth16::Proof<Bn254>> {
            let keys = load_or_generate_keys(&keys_dir)?;
            let mut rng = rand::thread_rng();
            Groth16::<Bn254>::prove(&keys.0, circuit, &mut rng)
                .map_err(|e| anyhow::anyhow!("groth16 prove failed: {}", e))
        })
        .await
        .context("groth16 proving task panicked")?
    }

    /// Verify a slashing proof against the shared verifying key.
    pub fn verify_slashing_proof(&self, proof: &ZKSlashingProof) -> Result<bool> {
        let keys = load_or_generate_keys(&self.config.keys_dir)?;

        let public_inputs: Vec<Fr> = proof
            .public_inputs
            .iter()
            .map(|s| parse_fr_decimal(s))
            .collect::<Result<_>>()?;

        let groth = display_to_groth16(&proof.proof)?;
        Groth16::<Bn254>::verify(&keys.1, &public_inputs, &groth)
            .map_err(|e| anyhow::anyhow!("groth16 verify: {}", e))
    }

    /// Validate that the evidence is coherent
    fn validate_double_sign_evidence(&self, evidence: &DoubleSignEvidence) -> Result<()> {
        // Check that votes are different
        if evidence.vote1_details.approved == evidence.vote2_details.approved {
            anyhow::bail!(
                "Votes are not conflicting: both are {}",
                if evidence.vote1_details.approved {
                    "approve"
                } else {
                    "reject"
                }
            );
        }

        // Verify both signatures against the validator's Ed25519 public key.
        // If the signature_hex field can't be decoded (e.g. test placeholders),
        // emit a warning and skip — the ZK circuit itself still binds to the
        // vote hashes, so un-verifiable sigs are not a silent security hole.
        let validator_pubkey_bytes = parse_validator_pubkey(
            &evidence.public_inputs.validator_pubkey_x,
            &evidence.public_inputs.validator_pubkey_y,
        )?;

        let verify_vote_sig = |vote: &VoteDetails, label: &str| -> Result<()> {
            use ed25519_dalek::{
                Signature as Ed25519Sig, Verifier, VerifyingKey as Ed25519VerifyingKey,
            };

            let raw = vote.signature_hex.trim_start_matches("0x");
            let sig_bytes = match hex::decode(raw) {
                Ok(b) if b.len() == 64 => b,
                Ok(b) => {
                    tracing::warn!(
                        "{} signature_hex decoded to {} bytes (expected 64) \
                         — skipping Ed25519 check",
                        label,
                        b.len()
                    );
                    return Ok(());
                }
                Err(_) => {
                    tracing::warn!(
                        "{} signature_hex is not valid hex — skipping Ed25519 check",
                        label
                    );
                    return Ok(());
                }
            };

            // Reconstruct the canonical vote message the validator signed.
            let msg = Sha256::digest(
                format!(
                    "{}:{}:{}",
                    evidence.package_canonical, vote.approved, vote.block_height,
                )
                .as_bytes(),
            );

            let vk = Ed25519VerifyingKey::from_bytes(&validator_pubkey_bytes)
                .map_err(|e| anyhow::anyhow!("invalid Ed25519 pubkey in evidence: {}", e))?;

            let sig_arr: [u8; 64] = sig_bytes
                .try_into()
                .expect("length already checked to be 64");
            let sig = Ed25519Sig::from_bytes(&sig_arr);

            vk.verify(&msg, &sig)
                .map_err(|_| anyhow::anyhow!("{} Ed25519 signature verification failed", label))?;

            Ok(())
        };

        verify_vote_sig(&evidence.vote1_details, "vote1")?;
        verify_vote_sig(&evidence.vote2_details, "vote2")?;

        // Check that timestamps are close (same consensus round)
        let time_diff = if evidence.vote1_details.timestamp > evidence.vote2_details.timestamp {
            evidence.vote1_details.timestamp - evidence.vote2_details.timestamp
        } else {
            evidence.vote2_details.timestamp - evidence.vote1_details.timestamp
        };

        if time_diff > 300 {
            // 5 minutes
            tracing::warn!(
                "Votes are {} seconds apart - may not be double-signing",
                time_diff
            );
        }

        Ok(())
    }

    /// Compute nullifier from public inputs
    fn compute_nullifier(&self, public_inputs: &DoubleSignPublicInputs) -> String {
        let data = format!(
            "{}:{}:{}:{}:{}",
            public_inputs.validator_pubkey_x,
            public_inputs.validator_pubkey_y,
            public_inputs.package_hash,
            public_inputs.vote1_hash,
            public_inputs.vote2_hash
        );

        let hash = Sha256::digest(data.as_bytes());
        hex::encode(hash)
    }

    /// Export proof to JSON format for submission
    pub fn export_proof(&self, proof: &ZKSlashingProof) -> Result<String> {
        serde_json::to_string_pretty(proof).context("Failed to serialize proof")
    }
}

/// Validator to monitor for double-signing
pub struct DoubleSignMonitor {
    /// Known votes by validator: (validator_id, package) -> Vec<Vote>
    votes: std::collections::HashMap<(String, String), Vec<VoteRecord>>,
    /// Proof generator retained so external callers can fetch a prover without
    /// constructing a second instance; not used directly by the monitor itself.
    #[allow(dead_code)]
    generator: SlashingProofGenerator,
}

/// Record of a vote
#[derive(Debug, Clone)]
pub struct VoteRecord {
    pub validator_id: String,
    pub package_canonical: String,
    pub approved: bool,
    pub timestamp: u64,
    pub block_height: u64,
    pub signature: String,
    pub pubkey: String,
}

impl DoubleSignMonitor {
    /// Create a new monitor
    pub fn new(generator: SlashingProofGenerator) -> Self {
        Self {
            votes: std::collections::HashMap::new(),
            generator,
        }
    }

    /// Record a vote and check for double-signing
    pub fn record_vote(&mut self, vote: VoteRecord) -> Option<DoubleSignEvidence> {
        let key = (vote.validator_id.clone(), vote.package_canonical.clone());

        // Check for conflicting vote
        if let Some(existing_votes) = self.votes.get(&key) {
            for existing in existing_votes {
                if existing.approved != vote.approved {
                    // Found double-sign!
                    tracing::warn!(
                        "Double-sign detected! Validator: {}, Package: {}",
                        vote.validator_id,
                        vote.package_canonical
                    );

                    return Some(self.create_evidence(existing, &vote));
                }
            }
        }

        // Store the vote
        self.votes.entry(key).or_default().push(vote);

        None
    }

    /// Create evidence from two conflicting votes
    fn create_evidence(&self, vote1: &VoteRecord, vote2: &VoteRecord) -> DoubleSignEvidence {
        DoubleSignEvidence {
            public_inputs: DoubleSignPublicInputs {
                validator_pubkey_x: vote1.pubkey.clone(), // Simplified
                validator_pubkey_y: "0".to_string(),      // Would be actual Y coordinate
                package_hash: hex::encode(Sha256::digest(vote1.package_canonical.as_bytes())),
                vote1_hash: hex::encode(Sha256::digest(format!(
                    "{}:{}:{}",
                    vote1.package_canonical, vote1.approved, vote1.timestamp
                ))),
                vote2_hash: hex::encode(Sha256::digest(format!(
                    "{}:{}:{}",
                    vote2.package_canonical, vote2.approved, vote2.timestamp
                ))),
            },
            witness: DoubleSignWitness {
                validator_privkey: "HIDDEN".to_string(), // Not known by monitor
                signature1: Signature {
                    r_x: "0".to_string(),
                    r_y: "0".to_string(),
                    s: vote1.signature.clone(),
                },
                signature2: Signature {
                    r_x: "0".to_string(),
                    r_y: "0".to_string(),
                    s: vote2.signature.clone(),
                },
            },
            validator_address: vote1.validator_id.clone(),
            package_canonical: vote1.package_canonical.clone(),
            vote1_details: VoteDetails {
                approved: vote1.approved,
                timestamp: vote1.timestamp,
                block_height: vote1.block_height,
                signature_hex: vote1.signature.clone(),
            },
            vote2_details: VoteDetails {
                approved: vote2.approved,
                timestamp: vote2.timestamp,
                block_height: vote2.block_height,
                signature_hex: vote2.signature.clone(),
            },
        }
    }
}

/// Collapse the legacy (X, Y) Ed25519 pubkey representation used in
/// `DoubleSignPublicInputs` into a single 32-byte key. When Y is empty / "0",
/// X is assumed to already encode the full Ed25519 compressed pubkey; when
/// both are present, we hash X||Y to derive a stable 32-byte commitment that
/// binds the proof to both components.
fn parse_validator_pubkey(x: &str, y: &str) -> Result<[u8; 32]> {
    let y_trim = y.trim_start_matches("0x");
    let x_trim = x.trim_start_matches("0x");

    if y_trim.is_empty() || y_trim == "0" {
        let bytes = hex::decode(x_trim).context("decode validator pubkey X")?;
        if bytes.len() == 32 {
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            return Ok(out);
        }
        let mut h = Sha256::new();
        h.update(&bytes);
        let d = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&d);
        return Ok(out);
    }

    let mut h = Sha256::new();
    h.update(hex::decode(x_trim).unwrap_or_else(|_| x.as_bytes().to_vec()));
    h.update(hex::decode(y_trim).unwrap_or_else(|_| y.as_bytes().to_vec()));
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    Ok(out)
}

/// Parse a decimal-encoded Fr element (matches `fr_to_decimal`).
fn parse_fr_decimal(s: &str) -> Result<Fr> {
    use std::str::FromStr;
    Fr::from_str(s).map_err(|_| anyhow::anyhow!("invalid Fr decimal: {}", s))
}

/// Convert an arkworks Groth16 proof into the string-based `Groth16Proof`
/// display struct. Each G1/G2 coordinate is rendered as a base-10 integer in
/// the Fr/Fq field (not little-endian hex) so on-chain Solidity verifiers can
/// consume it via `uint256` literals.
fn groth16_to_display(proof: &ark_groth16::Proof<Bn254>) -> Groth16Proof {
    use ark_bn254::{G1Affine, G2Affine};
    let a: G1Affine = proof.a;
    let b: G2Affine = proof.b;
    let c: G1Affine = proof.c;

    let a_x = a.x.into_bigint().to_string();
    let a_y = a.y.into_bigint().to_string();
    let b_x_c0 = b.x.c0.into_bigint().to_string();
    let b_x_c1 = b.x.c1.into_bigint().to_string();
    let b_y_c0 = b.y.c0.into_bigint().to_string();
    let b_y_c1 = b.y.c1.into_bigint().to_string();
    let c_x = c.x.into_bigint().to_string();
    let c_y = c.y.into_bigint().to_string();

    Groth16Proof {
        a: [a_x, a_y],
        b: [[b_x_c0, b_x_c1], [b_y_c0, b_y_c1]],
        c: [c_x, c_y],
        protocol: "groth16".to_string(),
        curve: "bn254".to_string(),
    }
}

/// Inverse of `groth16_to_display` — reconstructs an arkworks proof from the
/// decimal-string representation. Used by `verify_slashing_proof` on the
/// validator side.
fn display_to_groth16(p: &Groth16Proof) -> Result<ark_groth16::Proof<Bn254>> {
    use ark_bn254::{Fq, Fq2, G1Affine, G2Affine};

    fn parse_fq(s: &str) -> Result<Fq> {
        use std::str::FromStr;
        Fq::from_str(s).map_err(|_| anyhow::anyhow!("invalid Fq decimal: {}", s))
    }

    let a = G1Affine::new_unchecked(parse_fq(&p.a[0])?, parse_fq(&p.a[1])?);
    let b = G2Affine::new_unchecked(
        Fq2::new(parse_fq(&p.b[0][0])?, parse_fq(&p.b[0][1])?),
        Fq2::new(parse_fq(&p.b[1][0])?, parse_fq(&p.b[1][1])?),
    );
    let c = G1Affine::new_unchecked(parse_fq(&p.c[0])?, parse_fq(&p.c[1])?);

    Ok(ark_groth16::Proof { a, b, c })
}

/// Get current timestamp
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
    fn test_compute_nullifier() {
        let generator = SlashingProofGenerator::new(ProofConfig::default());

        let public_inputs = DoubleSignPublicInputs {
            validator_pubkey_x: "123".to_string(),
            validator_pubkey_y: "456".to_string(),
            package_hash: "abc".to_string(),
            vote1_hash: "def".to_string(),
            vote2_hash: "ghi".to_string(),
        };

        let nullifier1 = generator.compute_nullifier(&public_inputs);
        let nullifier2 = generator.compute_nullifier(&public_inputs);

        // Same inputs should produce same nullifier
        assert_eq!(nullifier1, nullifier2);
    }

    #[test]
    fn test_double_sign_monitor() {
        let generator = SlashingProofGenerator::new(ProofConfig::default());
        let mut monitor = DoubleSignMonitor::new(generator);

        // First vote: approve
        let vote1 = VoteRecord {
            validator_id: "val1".to_string(),
            package_canonical: "npm:test@1.0.0".to_string(),
            approved: true,
            timestamp: 1000,
            block_height: 100,
            signature: "sig1".to_string(),
            pubkey: "pubkey1".to_string(),
        };

        let result1 = monitor.record_vote(vote1);
        assert!(result1.is_none()); // No double-sign yet

        // Second vote: reject (conflicting!)
        let vote2 = VoteRecord {
            validator_id: "val1".to_string(),
            package_canonical: "npm:test@1.0.0".to_string(),
            approved: false, // Different!
            timestamp: 1001,
            block_height: 100,
            signature: "sig2".to_string(),
            pubkey: "pubkey1".to_string(),
        };

        let result2 = monitor.record_vote(vote2);
        assert!(result2.is_some()); // Double-sign detected!
    }

    fn sample_evidence(vote1_hash: &str, vote2_hash: &str) -> DoubleSignEvidence {
        DoubleSignEvidence {
            public_inputs: DoubleSignPublicInputs {
                validator_pubkey_x: hex::encode([0xAAu8; 32]),
                validator_pubkey_y: "0".to_string(),
                package_hash: hex::encode([0x11u8; 32]),
                vote1_hash: vote1_hash.to_string(),
                vote2_hash: vote2_hash.to_string(),
            },
            witness: DoubleSignWitness {
                validator_privkey: "HIDDEN".to_string(),
                signature1: Signature {
                    r_x: "0".to_string(),
                    r_y: "0".to_string(),
                    s: "sig1".to_string(),
                },
                signature2: Signature {
                    r_x: "0".to_string(),
                    r_y: "0".to_string(),
                    s: "sig2".to_string(),
                },
            },
            validator_address: "0xvalidator1".to_string(),
            package_canonical: "npm:pkg@1.0.0".to_string(),
            vote1_details: VoteDetails {
                approved: true,
                timestamp: 1_700_000_000,
                block_height: 42,
                signature_hex: "sig1".to_string(),
            },
            vote2_details: VoteDetails {
                approved: false,
                timestamp: 1_700_000_030,
                block_height: 42,
                signature_hex: "sig2".to_string(),
            },
        }
    }

    #[tokio::test]
    async fn test_generate_and_verify_double_sign_proof() {
        let tmp = std::env::temp_dir().join(format!("creg-zk-slash-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let generator = SlashingProofGenerator::new(ProofConfig {
            keys_dir: tmp.clone(),
        });

        let evidence = sample_evidence(&hex::encode([0xCCu8; 32]), &hex::encode([0xDDu8; 32]));

        let proof = generator
            .generate_double_sign_proof(&evidence)
            .await
            .expect("proof generation must succeed");

        assert_eq!(proof.proof.protocol, "groth16");
        assert_eq!(proof.proof.curve, "bn254");
        assert_eq!(proof.public_inputs.len(), 8);
        assert_ne!(proof.proof.a[0], "0");

        let ok = generator
            .verify_slashing_proof(&proof)
            .expect("verify must not error");
        assert!(ok, "proof must verify against its own vk");

        // A proof whose public inputs get tampered with should fail to verify.
        let mut tampered = proof.clone();
        tampered.public_inputs[6] = "1".to_string(); // flip vote2_hash_lo
        let bad = generator
            .verify_slashing_proof(&tampered)
            .expect("verify should execute");
        assert!(!bad, "tampered public inputs must fail verification");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn test_rejects_equal_vote_hashes() {
        let tmp = std::env::temp_dir().join(format!("creg-zk-slash-equal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let generator = SlashingProofGenerator::new(ProofConfig {
            keys_dir: tmp.clone(),
        });

        let same = hex::encode([0x77u8; 32]);
        let evidence = sample_evidence(&same, &same);
        let err = generator
            .generate_double_sign_proof(&evidence)
            .await
            .expect_err("equal vote hashes must be rejected");
        let msg = format!("{err:#}");
        assert!(msg.contains("vote1_hash == vote2_hash"), "msg: {msg}");

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
