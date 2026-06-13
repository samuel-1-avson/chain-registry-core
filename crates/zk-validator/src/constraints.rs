//! Constraint Gadgets for Package Validation
//!
//! This module provides reusable constraint gadgets for common operations
//! in the ZK circuits.

use ark_ff::PrimeField;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::SynthesisError;

/// Gadget for boolean combinations
pub struct BooleanLogicGadget;

impl BooleanLogicGadget {
    /// All conditions must be true (AND of all)
    pub fn all<F: PrimeField>(conditions: &[Boolean<F>]) -> Result<Boolean<F>, SynthesisError> {
        if conditions.is_empty() {
            return Ok(Boolean::constant(true));
        }

        let mut result = conditions[0].clone();
        for cond in &conditions[1..] {
            result = result.and(cond)?;
        }
        Ok(result)
    }

    /// At least one condition must be true (OR of all)
    pub fn any<F: PrimeField>(conditions: &[Boolean<F>]) -> Result<Boolean<F>, SynthesisError> {
        if conditions.is_empty() {
            return Ok(Boolean::constant(false));
        }

        let mut result = conditions[0].clone();
        for cond in &conditions[1..] {
            result = result.or(cond)?;
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_all_conditions() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let cond1 = Boolean::new_witness(cs.clone(), || Ok(true)).unwrap();
        let cond2 = Boolean::new_witness(cs.clone(), || Ok(true)).unwrap();
        let cond3 = Boolean::new_witness(cs.clone(), || Ok(true)).unwrap();

        let all_true = BooleanLogicGadget::all(&[cond1, cond2, cond3]).unwrap();
        all_true.enforce_equal(&Boolean::constant(true)).unwrap();

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_any_condition() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let cond1 = Boolean::new_witness(cs.clone(), || Ok(false)).unwrap();
        let cond2 = Boolean::new_witness(cs.clone(), || Ok(true)).unwrap();
        let cond3 = Boolean::new_witness(cs.clone(), || Ok(false)).unwrap();

        let any_true = BooleanLogicGadget::any(&[cond1, cond2, cond3]).unwrap();
        any_true.enforce_equal(&Boolean::constant(true)).unwrap();

        assert!(cs.is_satisfied().unwrap());
    }
}
