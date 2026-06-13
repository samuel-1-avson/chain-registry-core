//! Integration tests for ZK validation

use zk_validator::{PackageInputs, ZkValidator};

#[test]
fn test_zk_proof_generation_and_verification() {
    // Initialize validator
    let validator = ZkValidator::new().expect("Failed to create ZK validator");
    
    // Create test inputs
    let inputs = PackageInputs::new(
        [1u8; 32],  // content hash
        [2u8; 32],  // manifest hash
        95,          // high safety score
        true,        // sandbox passed
    );
    
    // Generate proof
    let proof = validator.generate_proof(&inputs)
        .expect("Failed to generate proof");
    
    // Verify proof
    let public_inputs = inputs.public_inputs();
    let is_valid = validator.verify_proof(&proof, &public_inputs)
        .expect("Failed to verify proof");
    
    assert!(is_valid, "Proof should be valid");
}

#[test]
fn test_zk_proof_serialization() {
    let validator = ZkValidator::new().expect("Failed to create ZK validator");
    let inputs = PackageInputs::new([1u8; 32], [2u8; 32], 95, true);
    
    // Generate and serialize
    let proof = validator.generate_proof(&inputs).expect("Failed to generate proof");
    let serialized = ZkValidator::serialize_proof(&proof).expect("Failed to serialize");
    
    // Deserialize and verify
    let deserialized = ZkValidator::deserialize_proof(&serialized).expect("Failed to deserialize");
    let is_valid = validator.verify_proof(&deserialized, &inputs.public_inputs()).expect("Failed to verify");
    
    assert!(is_valid);
}

#[test]
fn test_zk_batch_verification() {
    let validator = ZkValidator::new().expect("Failed to create ZK validator");
    
    // Create multiple proofs
    let mut proofs = Vec::new();
    let mut public_inputs = Vec::new();
    
    for i in 0..5 {
        let inputs = PackageInputs::new(
            [i as u8; 32],
            [i as u8; 32],
            90 + i as u8,
            true,
        );
        let proof = validator.generate_proof(&inputs).expect("Failed to generate proof");
        proofs.push(proof);
        public_inputs.push(inputs.public_inputs());
    }
    
    // Batch verify
    let results = validator.batch_verify(&proofs, &public_inputs)
        .expect("Failed to batch verify");
    
    assert_eq!(results.len(), 5);
    assert!(results.iter().all(|&r| r), "All proofs should be valid");
}
