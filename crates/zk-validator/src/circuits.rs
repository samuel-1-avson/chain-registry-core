//! Zero-Knowledge Circuits for Package Validation
//!
//! This module defines the R1CS (Rank-1 Constraint System) circuits
//! used for proving package safety without revealing the package contents.

use ark_bn254::Fr;
use ark_ff::{One, PrimeField};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::{PackageInputs, ZkError};

/// Split a 32-byte hash into low/high 128-bit field limbs (BN254-safe).
fn split_hash32(hash: &[u8]) -> ([u8; 16], [u8; 16]) {
    let mut lo = [0u8; 16];
    let mut hi = [0u8; 16];
    lo.copy_from_slice(&hash[..16]);
    hi.copy_from_slice(&hash[16..32]);
    (lo, hi)
}

fn bind_hash32_limbs(cs: ConstraintSystemRef<Fr>, hash: &[u8]) -> Result<(), SynthesisError> {
    let (lo_bytes, hi_bytes) = split_hash32(hash);
    let lo_input = FpVar::new_input(cs.clone(), || Ok(Fr::from_le_bytes_mod_order(&lo_bytes)))?;
    let hi_input = FpVar::new_input(cs.clone(), || Ok(Fr::from_le_bytes_mod_order(&hi_bytes)))?;
    let lo_witness = FpVar::new_witness(cs.clone(), || Ok(Fr::from_le_bytes_mod_order(&lo_bytes)))?;
    let hi_witness = FpVar::new_witness(cs.clone(), || Ok(Fr::from_le_bytes_mod_order(&hi_bytes)))?;
    lo_input.enforce_equal(&lo_witness)?;
    hi_input.enforce_equal(&hi_witness)?;
    Ok(())
}

/// Circuit for validating a package's safety
///
/// This circuit proves that:
/// 1. The content hash and manifest hash are bound as public inputs
/// 2. Static analysis score is above threshold (≥80)
/// 3. Sandbox execution passed
/// 4. No vulnerable dependencies
/// 5. Code complexity is within acceptable limits
///
/// # Public inputs (7 Fr elements, order fixed for verifier compatibility)
/// ```text
///   0. content_hash_lo
///   1. content_hash_hi
///   2. manifest_hash_lo
///   3. manifest_hash_hi
///   4. static_analysis_score
///   5. sandbox_safe
///   6. no_vulnerable_deps
/// ```
#[derive(Clone)]
pub struct PackageValidationCircuit {
    /// Private witness: The actual package content (hashed)
    pub content_hash: Vec<u8>,
    /// Private witness: Manifest content
    pub manifest_hash: Vec<u8>,
    /// Public input: Static analysis score
    pub static_analysis_score: u8,
    /// Public input: Sandbox passed
    pub sandbox_safe: bool,
    /// Public input: No vulnerable deps
    pub no_vulnerable_deps: bool,
    /// Private witness: Complexity score
    pub complexity_score: u8,
}

impl Default for PackageValidationCircuit {
    fn default() -> Self {
        Self {
            content_hash: vec![0u8; 32],
            manifest_hash: vec![0u8; 32],
            static_analysis_score: 0,
            sandbox_safe: false,
            no_vulnerable_deps: false,
            complexity_score: 0,
        }
    }
}

impl PackageValidationCircuit {
    /// Create circuit from package inputs
    pub fn from_inputs(inputs: &PackageInputs) -> Result<Self, ZkError> {
        Ok(Self {
            content_hash: inputs.content_hash.to_vec(),
            manifest_hash: inputs.manifest_hash.to_vec(),
            static_analysis_score: inputs.static_analysis_score,
            sandbox_safe: inputs.sandbox_safe,
            no_vulnerable_deps: inputs.no_vulnerable_deps,
            complexity_score: inputs.complexity_score,
        })
    }
}

impl ConstraintSynthesizer<Fr> for PackageValidationCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        if self.content_hash.len() != 32 || self.manifest_hash.len() != 32 {
            return Err(SynthesisError::Unsatisfiable);
        }

        // Bind content/manifest hashes as public inputs (witness equality).
        bind_hash32_limbs(cs.clone(), &self.content_hash)?;
        bind_hash32_limbs(cs.clone(), &self.manifest_hash)?;

        // One field element per public policy flag (matches PackageInputs::public_inputs).
        let static_score_input = FpVar::new_input(cs.clone(), || {
            Ok(Fr::from(self.static_analysis_score as u64))
        })?;
        let sandbox_safe_input = FpVar::new_input(cs.clone(), || {
            Ok(Fr::from(if self.sandbox_safe { 1u64 } else { 0 }))
        })?;
        let no_vuln_deps_input = FpVar::new_input(cs.clone(), || {
            Ok(Fr::from(if self.no_vulnerable_deps { 1u64 } else { 0 }))
        })?;

        // Private witnesses mirror the public inputs for range/flag constraints.
        let static_score_var = UInt8::new_witness(cs.clone(), || Ok(self.static_analysis_score))?;
        let sandbox_safe_var = Boolean::new_witness(cs.clone(), || Ok(self.sandbox_safe))?;
        let no_vuln_deps_var = Boolean::new_witness(cs.clone(), || Ok(self.no_vulnerable_deps))?;
        let complexity_var = UInt8::new_witness(cs.clone(), || Ok(self.complexity_score))?;

        let static_score_witness_fp = static_score_var
            .to_bits_le()?
            .iter()
            .enumerate()
            .fold(FpVar::zero(), |acc, (i, b)| {
                acc + FpVar::from(b.to_owned()) * FpVar::constant(Fr::from(1u64 << i))
            });
        static_score_input.enforce_equal(&static_score_witness_fp)?;

        let sandbox_witness_fp = FpVar::from(sandbox_safe_var.to_bits_le()?[0].clone());
        sandbox_safe_input.enforce_equal(&sandbox_witness_fp)?;

        let no_vuln_witness_fp = FpVar::from(no_vuln_deps_var.to_bits_le()?[0].clone());
        no_vuln_deps_input.enforce_equal(&no_vuln_witness_fp)?;

        // Constraint 1: Static analysis score >= 80
        // Strategy: compute `diff = score - 80` in the field and constrain `diff` to
        // fit in a UInt8 (8-bit value in [0, 255]). If score < 80, the field
        // subtraction wraps modulo p (producing a huge number) which cannot be
        // represented as an 8-bit value, making the circuit unsatisfiable.
        // Max valid diff = 255 - 80 = 175, which fits comfortably in 8 bits.
        let score_le = static_score_var.to_bits_le()?.iter().enumerate().fold(
            ark_r1cs_std::fields::fp::FpVar::zero(),
            |acc, (i, b)| {
                let coeff = Fr::from(1u64 << i);
                acc + FpVar::from(b.to_owned()) * FpVar::constant(coeff)
            },
        );
        let threshold_le = ark_r1cs_std::fields::fp::FpVar::constant(Fr::from(80u64));
        // Enforce score_field - threshold_field >= 0 by constraining the difference
        // to fit in [0, 175] (max score 255 - min threshold 80 = 175).
        let diff_le = score_le - threshold_le;
        // Allocate the difference as a public scalar and range-check it is non-negative.
        // A negative difference would wrap modulo the field prime — too large to fit in 8 bits.
        let diff_bits = UInt8::new_witness(cs.clone(), || {
            let v = self.static_analysis_score.saturating_sub(80);
            Ok(v)
        })?
        .to_bits_le()?;
        let diff_recomputed = diff_bits.iter().enumerate().fold(
            ark_r1cs_std::fields::fp::FpVar::zero(),
            |acc, (i, b)| {
                let coeff = Fr::from(1u64 << i);
                acc + FpVar::from(b.to_owned()) * FpVar::constant(coeff)
            },
        );
        diff_le.enforce_equal(&diff_recomputed)?;

        // Constraint 2: Sandbox must have passed
        sandbox_safe_var.enforce_equal(&Boolean::constant(true))?;

        // Constraint 3: No vulnerable dependencies
        no_vuln_deps_var.enforce_equal(&Boolean::constant(true))?;

        // Constraint 4: Complexity score <= 90
        // Encode as: 90 - complexity_score must be representable as a 7-bit non-negative value.
        let max_complexity = UInt8::<Fr>::constant(90u8);
        let max_complexity_le = max_complexity.to_bits_le()?.iter().enumerate().fold(
            ark_r1cs_std::fields::fp::FpVar::zero(),
            |acc, (i, b)| {
                let coeff = Fr::from(1u64 << i);
                acc + FpVar::from(b.to_owned()) * FpVar::constant(coeff)
            },
        );
        let complexity_le = complexity_var.to_bits_le()?.iter().enumerate().fold(
            ark_r1cs_std::fields::fp::FpVar::zero(),
            |acc, (i, b)| {
                let coeff = Fr::from(1u64 << i);
                acc + FpVar::from(b.to_owned()) * FpVar::constant(coeff)
            },
        );
        let complexity_diff = max_complexity_le - complexity_le;
        let complexity_diff_witness =
            UInt8::new_witness(
                cs.clone(),
                || Ok(90u8.saturating_sub(self.complexity_score)),
            )?
            .to_bits_le()?;
        let complexity_diff_recomputed = complexity_diff_witness.iter().enumerate().fold(
            ark_r1cs_std::fields::fp::FpVar::zero(),
            |acc, (i, b)| {
                let coeff = Fr::from(1u64 << i);
                acc + FpVar::from(b.to_owned()) * FpVar::constant(coeff)
            },
        );
        complexity_diff.enforce_equal(&complexity_diff_recomputed)?;

        Ok(())
    }
}

/// Circuit for proving knowledge of package content without revealing it
///
/// Used for private registries where the content should remain confidential
#[derive(Clone)]
pub struct PrivatePackageCircuit {
    /// Private: Content hash preimage
    pub content: Vec<u8>,
    /// Public: Expected hash
    pub expected_hash: [u8; 32],
}

impl ConstraintSynthesizer<Fr> for PrivatePackageCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocate private witness: content
        let _content_vars: Vec<UInt8<Fr>> = self
            .content
            .iter()
            .map(|b| UInt8::new_witness(cs.clone(), || Ok(*b)))
            .collect::<Result<Vec<_>, _>>()?;

        // Allocate public input: expected hash
        let _expected_hash_vars: Vec<UInt8<Fr>> = self
            .expected_hash
            .iter()
            .map(|b| UInt8::new_input(cs.clone(), || Ok(*b)))
            .collect::<Result<Vec<_>, _>>()?;

        // Hash verification would go here using ark-crypto-primitives
        // For now, simplified constraint

        Ok(())
    }
}

/// Circuit for proving validator double-signing evidence.
///
/// Public inputs (8 Fr elements, order matters for verifier compatibility):
///   0. validator_pubkey_lo  — low 16 bytes of the Ed25519 pubkey
///   1. validator_pubkey_hi  — high 16 bytes
///   2. package_hash_lo      — low 16 bytes of SHA-256(package_canonical)
///   3. package_hash_hi      — high 16 bytes
///   4. vote1_hash_lo        — low 16 bytes of SHA-256(vote1_canonical)
///   5. vote1_hash_hi        — high 16 bytes
///   6. vote2_hash_lo        — low 16 bytes of SHA-256(vote2_canonical)
///   7. vote2_hash_hi        — high 16 bytes
///
/// The circuit constrains that `(vote1_hash_lo, vote1_hash_hi) != (vote2_hash_lo,
/// vote2_hash_hi)` — i.e. the two signed messages must genuinely differ. The
/// validator_pubkey and package_hash values are committed via public-input
/// binding so the downstream verifier (on-chain slashing contract) can match
/// them against the stored evidence record without trusting the prover.
///
/// Ed25519 signature validity itself is NOT verified inside R1CS (that would
/// blow up the constraint count by ~200k); the off-chain evidence collector
/// performs native Ed25519 verification before invoking the prover, and the
/// on-chain contract re-checks the signatures against the stored pubkey.
/// The ZK proof's job here is to commit to the conflicting-vote structure in
/// a way that's succinctly verifiable on L1.
#[derive(Clone, Default)]
pub struct DoubleSignCircuit {
    pub validator_pubkey_lo: [u8; 16],
    pub validator_pubkey_hi: [u8; 16],
    pub package_hash_lo: [u8; 16],
    pub package_hash_hi: [u8; 16],
    pub vote1_hash_lo: [u8; 16],
    pub vote1_hash_hi: [u8; 16],
    pub vote2_hash_lo: [u8; 16],
    pub vote2_hash_hi: [u8; 16],
}

impl DoubleSignCircuit {
    /// Build a circuit from raw 32-byte hashes.
    pub fn from_hashes(
        validator_pubkey: &[u8; 32],
        package_hash: &[u8; 32],
        vote1_hash: &[u8; 32],
        vote2_hash: &[u8; 32],
    ) -> Self {
        fn split(h: &[u8; 32]) -> ([u8; 16], [u8; 16]) {
            let mut lo = [0u8; 16];
            let mut hi = [0u8; 16];
            lo.copy_from_slice(&h[..16]);
            hi.copy_from_slice(&h[16..]);
            (lo, hi)
        }
        let (vpk_lo, vpk_hi) = split(validator_pubkey);
        let (pkg_lo, pkg_hi) = split(package_hash);
        let (v1_lo, v1_hi) = split(vote1_hash);
        let (v2_lo, v2_hi) = split(vote2_hash);
        Self {
            validator_pubkey_lo: vpk_lo,
            validator_pubkey_hi: vpk_hi,
            package_hash_lo: pkg_lo,
            package_hash_hi: pkg_hi,
            vote1_hash_lo: v1_lo,
            vote1_hash_hi: v1_hi,
            vote2_hash_lo: v2_lo,
            vote2_hash_hi: v2_hi,
        }
    }

    /// Return the public-input vector in the canonical verifier order.
    pub fn public_inputs(&self) -> Vec<Fr> {
        vec![
            Fr::from_le_bytes_mod_order(&self.validator_pubkey_lo),
            Fr::from_le_bytes_mod_order(&self.validator_pubkey_hi),
            Fr::from_le_bytes_mod_order(&self.package_hash_lo),
            Fr::from_le_bytes_mod_order(&self.package_hash_hi),
            Fr::from_le_bytes_mod_order(&self.vote1_hash_lo),
            Fr::from_le_bytes_mod_order(&self.vote1_hash_hi),
            Fr::from_le_bytes_mod_order(&self.vote2_hash_lo),
            Fr::from_le_bytes_mod_order(&self.vote2_hash_hi),
        ]
    }
}

impl ConstraintSynthesizer<Fr> for DoubleSignCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let validator_pubkey_lo = FpVar::new_input(cs.clone(), || {
            Ok(Fr::from_le_bytes_mod_order(&self.validator_pubkey_lo))
        })?;
        let validator_pubkey_hi = FpVar::new_input(cs.clone(), || {
            Ok(Fr::from_le_bytes_mod_order(&self.validator_pubkey_hi))
        })?;
        let package_hash_lo = FpVar::new_input(cs.clone(), || {
            Ok(Fr::from_le_bytes_mod_order(&self.package_hash_lo))
        })?;
        let package_hash_hi = FpVar::new_input(cs.clone(), || {
            Ok(Fr::from_le_bytes_mod_order(&self.package_hash_hi))
        })?;
        let vote1_lo = FpVar::new_input(cs.clone(), || {
            Ok(Fr::from_le_bytes_mod_order(&self.vote1_hash_lo))
        })?;
        let vote1_hi = FpVar::new_input(cs.clone(), || {
            Ok(Fr::from_le_bytes_mod_order(&self.vote1_hash_hi))
        })?;
        let vote2_lo = FpVar::new_input(cs.clone(), || {
            Ok(Fr::from_le_bytes_mod_order(&self.vote2_hash_lo))
        })?;
        let vote2_hi = FpVar::new_input(cs.clone(), || {
            Ok(Fr::from_le_bytes_mod_order(&self.vote2_hash_hi))
        })?;

        // Binding constraints: ensure allocated variables are actually used in
        // the constraint system so the Groth16 verifier binds the public
        // inputs. Enforcing equality with themselves is cheap and compiles
        // down to trivial gates.
        validator_pubkey_lo.enforce_equal(&validator_pubkey_lo)?;
        validator_pubkey_hi.enforce_equal(&validator_pubkey_hi)?;
        package_hash_lo.enforce_equal(&package_hash_lo)?;
        package_hash_hi.enforce_equal(&package_hash_hi)?;

        // Core constraint: vote1_hash != vote2_hash (at least one half differs).
        // Compute the differences and witness their non-zero status via
        // `is_zero().not()`, then OR them together.
        let diff_lo = &vote1_lo - &vote2_lo;
        let diff_hi = &vote1_hi - &vote2_hi;

        let lo_is_zero = diff_lo.is_zero()?;
        let hi_is_zero = diff_hi.is_zero()?;
        let lo_nonzero = lo_is_zero.not();
        let hi_nonzero = hi_is_zero.not();

        let at_least_one_nonzero = lo_nonzero.or(&hi_nonzero)?;
        at_least_one_nonzero.enforce_equal(&Boolean::constant(true))?;

        Ok(())
    }
}

/// Circuit for batch validation of multiple packages
///
/// Proves that all packages in a batch meet safety criteria
#[derive(Clone)]
pub struct BatchValidationCircuit {
    pub packages: Vec<PackageValidationCircuit>,
}

impl ConstraintSynthesizer<Fr> for BatchValidationCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        for (_i, package) in self.packages.iter().enumerate() {
            // In arkworks 0.4, we create a namespace differently
            package.clone().generate_constraints(cs.clone())?;
        }
        Ok(())
    }
}

/// Circuit for proving a valid L2 rollup batch state transition.
///
/// This circuit binds the L2 node to a specific `(prev_root, data_root,
/// next_root)` triple and proves that the batch is non-empty, without
/// revealing the individual transactions. The on-chain `ZKVerifier` checks
/// the proof against these public inputs, and `Registry.submitRollupBatch`
/// checks that `prev_root == latestStateRoot()`.
///
/// # Public inputs (6 Fr elements, order fixed for on-chain verifier)
/// ```text
///   0. prev_root_lo  — low  16 bytes of prev_root (SHA-256 of prior batch)
///   1. prev_root_hi  — high 16 bytes of prev_root
///   2. data_root_lo  — low  16 bytes of data_root (Merkle root of batch txns)
///   3. data_root_hi  — high 16 bytes of data_root
///   4. next_root_lo  — low  16 bytes of next_root (SHA-256(prev_root||data_root))
///   5. next_root_hi  — high 16 bytes of next_root
/// ```
///
/// # Private witnesses
/// ```text
///   tx_count      — number of transactions in the batch (must be > 0)
///   tx_count_inv  — multiplicative inverse of tx_count in Fr
/// ```
///
/// # Core constraint
/// `tx_count * tx_count_inv == 1`
///
/// This proves `tx_count ≠ 0` (a non-zero field element always has an inverse)
/// which prevents an empty-batch proof. The six public inputs form the
/// cryptographic commitment verified on-chain.
///
/// Note: SHA-256 is NOT verified inside R1CS here (that requires ~22 000+
/// constraints per call via `ark-crypto-primitives`). The hash relationship
/// `next_root = SHA-256(prev_root || data_root)` is computed off-chain by
/// the node and enforced on-chain by `submitRollupBatch` comparing `prevRoot`
/// against `latestStateRoot()`. The ZK proof's role is to commit to the
/// batch roots in a way succinctly verifiable on L1.
#[derive(Clone)]
pub struct BatchStateTransitionCircuit {
    // ── Public inputs ────────────────────────────────────────────────────────
    pub prev_root_lo: [u8; 16],
    pub prev_root_hi: [u8; 16],
    pub data_root_lo: [u8; 16],
    pub data_root_hi: [u8; 16],
    pub next_root_lo: [u8; 16],
    pub next_root_hi: [u8; 16],
    // ── Private witnesses ────────────────────────────────────────────────────
    /// Number of transactions in this batch (proven > 0).
    pub tx_count: u64,
}

impl Default for BatchStateTransitionCircuit {
    fn default() -> Self {
        Self {
            prev_root_lo: [0u8; 16],
            prev_root_hi: [0u8; 16],
            data_root_lo: [0u8; 16],
            data_root_hi: [0u8; 16],
            next_root_lo: [0u8; 16],
            next_root_hi: [0u8; 16],
            // Default tx_count must be > 0 for the circuit to be satisfiable.
            // Use 1 as the safe default for key generation.
            tx_count: 1,
        }
    }
}

impl BatchStateTransitionCircuit {
    /// Construct from raw 32-byte root hashes and a transaction count.
    pub fn from_roots(
        prev_root: &[u8; 32],
        data_root: &[u8; 32],
        next_root: &[u8; 32],
        tx_count: u64,
    ) -> Self {
        fn split(h: &[u8; 32]) -> ([u8; 16], [u8; 16]) {
            let mut lo = [0u8; 16];
            let mut hi = [0u8; 16];
            lo.copy_from_slice(&h[..16]);
            hi.copy_from_slice(&h[16..]);
            (lo, hi)
        }
        let (pr_lo, pr_hi) = split(prev_root);
        let (dr_lo, dr_hi) = split(data_root);
        let (nr_lo, nr_hi) = split(next_root);
        Self {
            prev_root_lo: pr_lo,
            prev_root_hi: pr_hi,
            data_root_lo: dr_lo,
            data_root_hi: dr_hi,
            next_root_lo: nr_lo,
            next_root_hi: nr_hi,
            tx_count,
        }
    }

    /// Return the 6 public inputs in the canonical on-chain verifier order.
    pub fn public_inputs(&self) -> Vec<Fr> {
        vec![
            Fr::from_le_bytes_mod_order(&self.prev_root_lo),
            Fr::from_le_bytes_mod_order(&self.prev_root_hi),
            Fr::from_le_bytes_mod_order(&self.data_root_lo),
            Fr::from_le_bytes_mod_order(&self.data_root_hi),
            Fr::from_le_bytes_mod_order(&self.next_root_lo),
            Fr::from_le_bytes_mod_order(&self.next_root_hi),
        ]
    }
}

impl ConstraintSynthesizer<Fr> for BatchStateTransitionCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // ── Public inputs ────────────────────────────────────────────────────
        // These six allocations bind the proof to a specific (prev, data, next)
        // root triple. The Groth16 verifier checks them against the caller's
        // claimed public inputs, so no explicit equality constraint is needed.
        let _prev_lo = FpVar::new_input(cs.clone(), || {
            Ok(Fr::from_le_bytes_mod_order(&self.prev_root_lo))
        })?;
        let _prev_hi = FpVar::new_input(cs.clone(), || {
            Ok(Fr::from_le_bytes_mod_order(&self.prev_root_hi))
        })?;
        let _data_lo = FpVar::new_input(cs.clone(), || {
            Ok(Fr::from_le_bytes_mod_order(&self.data_root_lo))
        })?;
        let _data_hi = FpVar::new_input(cs.clone(), || {
            Ok(Fr::from_le_bytes_mod_order(&self.data_root_hi))
        })?;
        let _next_lo = FpVar::new_input(cs.clone(), || {
            Ok(Fr::from_le_bytes_mod_order(&self.next_root_lo))
        })?;
        let _next_hi = FpVar::new_input(cs.clone(), || {
            Ok(Fr::from_le_bytes_mod_order(&self.next_root_hi))
        })?;

        // ── Non-empty batch constraint ───────────────────────────────────────
        //
        // Prove tx_count ≠ 0 using the standard non-zero witness trick:
        //   allocate tx_count_inv as a private witness, then enforce
        //   tx_count * tx_count_inv == 1.
        //
        // A zero tx_count has no multiplicative inverse in Fr, so no valid
        // assignment for tx_count_inv exists → the circuit is unsatisfiable
        // for empty batches.
        use ark_ff::Field;
        let tx_count_fr = Fr::from(self.tx_count);
        let tx_count_inv_fr = tx_count_fr
            .inverse()
            .ok_or(SynthesisError::AssignmentMissing)?; // fails for tx_count == 0

        let tc = FpVar::new_witness(cs.clone(), || Ok(tx_count_fr))?;
        let tc_inv = FpVar::new_witness(cs.clone(), || Ok(tx_count_inv_fr))?;

        // tc * tc_inv == 1
        let one = FpVar::constant(Fr::one());
        let product = tc.clone() * tc_inv;
        product.enforce_equal(&one)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_package_validation_public_input_count() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let circuit = PackageValidationCircuit {
            content_hash: vec![1u8; 32],
            manifest_hash: vec![2u8; 32],
            static_analysis_score: 95,
            sandbox_safe: true,
            no_vulnerable_deps: true,
            complexity_score: 70,
        };
        circuit.generate_constraints(cs.clone()).unwrap();
        assert_eq!(cs.num_instance_variables(), 8, "constant + 7 public inputs");
    }

    #[test]
    fn test_package_validation_circuit() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let circuit = PackageValidationCircuit {
            content_hash: vec![1u8; 32],
            manifest_hash: vec![2u8; 32],
            static_analysis_score: 95,
            sandbox_safe: true,
            no_vulnerable_deps: true,
            complexity_score: 70,
        };

        circuit.generate_constraints(cs.clone()).unwrap();

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_package_validation_low_score_rejected() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let circuit = PackageValidationCircuit {
            content_hash: vec![1u8; 32],
            manifest_hash: vec![2u8; 32],
            static_analysis_score: 50, // Below threshold of 80
            sandbox_safe: true,
            no_vulnerable_deps: true,
            complexity_score: 70,
        };

        // Constraint generation succeeds (it just adds constraints)
        circuit.generate_constraints(cs.clone()).unwrap();
        // But the constraint system must NOT be satisfied: score 50 < threshold 80
        assert!(
            !cs.is_satisfied().unwrap(),
            "Circuit must reject static_analysis_score below threshold (50 < 80)"
        );
    }

    #[test]
    fn test_package_validation_boundary_score_80() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let circuit = PackageValidationCircuit {
            content_hash: vec![1u8; 32],
            manifest_hash: vec![2u8; 32],
            static_analysis_score: 80, // Exactly at threshold
            sandbox_safe: true,
            no_vulnerable_deps: true,
            complexity_score: 70,
        };

        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(
            cs.is_satisfied().unwrap(),
            "Circuit must accept static_analysis_score exactly at threshold (80)"
        );
    }

    #[test]
    fn test_package_validation_high_complexity_rejected() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let circuit = PackageValidationCircuit {
            content_hash: vec![1u8; 32],
            manifest_hash: vec![2u8; 32],
            static_analysis_score: 95,
            sandbox_safe: true,
            no_vulnerable_deps: true,
            complexity_score: 95, // Above max complexity of 90
        };

        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(
            !cs.is_satisfied().unwrap(),
            "Circuit must reject complexity_score above maximum (95 > 90)"
        );
    }

    #[test]
    fn test_double_sign_circuit_accepts_different_hashes() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let circuit =
            DoubleSignCircuit::from_hashes(&[7u8; 32], &[9u8; 32], &[0x11; 32], &[0x22; 32]);
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_double_sign_circuit_rejects_equal_hashes() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let circuit = DoubleSignCircuit::from_hashes(
            &[7u8; 32],
            &[9u8; 32],
            &[0x33; 32],
            &[0x33; 32], // identical vote hash — not a double sign
        );
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(
            !cs.is_satisfied().unwrap(),
            "Circuit must reject when vote1_hash == vote2_hash"
        );
    }

    #[test]
    fn test_double_sign_circuit_accepts_single_half_diff() {
        // Only the high half differs — must still satisfy.
        let mut v1 = [0u8; 32];
        let mut v2 = [0u8; 32];
        v1[..16].copy_from_slice(&[0xAA; 16]);
        v2[..16].copy_from_slice(&[0xAA; 16]);
        v1[16..].copy_from_slice(&[0xBB; 16]);
        v2[16..].copy_from_slice(&[0xCC; 16]);
        let cs = ConstraintSystem::<Fr>::new_ref();
        DoubleSignCircuit::from_hashes(&[1u8; 32], &[2u8; 32], &v1, &v2)
            .generate_constraints(cs.clone())
            .unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_package_validation_sandbox_failed_rejected() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let circuit = PackageValidationCircuit {
            content_hash: vec![1u8; 32],
            manifest_hash: vec![2u8; 32],
            static_analysis_score: 95,
            sandbox_safe: false, // Sandbox failed
            no_vulnerable_deps: true,
            complexity_score: 70,
        };

        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(
            !cs.is_satisfied().unwrap(),
            "Circuit must reject when sandbox_safe is false"
        );
    }

    // ── BatchStateTransitionCircuit tests ─────────────────────────────────────

    #[test]
    fn test_batch_circuit_non_empty_batch_satisfied() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let circuit = BatchStateTransitionCircuit::from_roots(
            &[0xAAu8; 32],
            &[0xBBu8; 32],
            &[0xCCu8; 32],
            42, // non-empty batch
        );
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(
            cs.is_satisfied().unwrap(),
            "Circuit must accept a non-empty batch"
        );
    }

    #[test]
    fn test_batch_circuit_single_tx_satisfied() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let circuit = BatchStateTransitionCircuit::from_roots(
            &[0x01u8; 32],
            &[0x02u8; 32],
            &[0x03u8; 32],
            1, // minimum non-empty batch
        );
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(
            cs.is_satisfied().unwrap(),
            "tx_count=1 must satisfy circuit"
        );
    }

    #[test]
    fn test_batch_circuit_zero_tx_unsatisfied() {
        // tx_count == 0 → no inverse exists → circuit fails at synthesis
        let circuit = BatchStateTransitionCircuit {
            tx_count: 0,
            ..Default::default()
        };
        let cs = ConstraintSystem::<Fr>::new_ref();
        // generate_constraints returns Err(AssignmentMissing) for tx_count=0
        let result = circuit.generate_constraints(cs.clone());
        assert!(
            result.is_err() || !cs.is_satisfied().unwrap_or(true),
            "Empty batch (tx_count=0) must not satisfy the circuit"
        );
    }

    #[test]
    fn test_batch_circuit_different_roots_distinguished() {
        // Two circuits with different roots must produce different public inputs.
        let c1 = BatchStateTransitionCircuit::from_roots(
            &[0x01u8; 32],
            &[0x02u8; 32],
            &[0x03u8; 32],
            10,
        );
        let c2 = BatchStateTransitionCircuit::from_roots(
            &[0x11u8; 32],
            &[0x22u8; 32],
            &[0x33u8; 32],
            10,
        );
        assert_ne!(
            c1.public_inputs(),
            c2.public_inputs(),
            "Different roots must produce different public input vectors"
        );
    }

    #[test]
    fn test_batch_circuit_public_inputs_count() {
        let circuit = BatchStateTransitionCircuit::default();
        assert_eq!(
            circuit.public_inputs().len(),
            6,
            "BatchStateTransitionCircuit must expose exactly 6 public inputs"
        );
    }
}
