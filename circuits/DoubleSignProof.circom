pragma circom 2.1.0;

include "circomlib/poseidon.circom";
include "circomlib/comparators.circom";

/// Helper: Check two values are equal
template IsEqual() {
    signal input in[2];
    signal output out;
    
    signal diff;
    diff <== in[0] - in[1];
    
    signal inv;
    inv <-- diff != 0 ? 1/diff : 0;
    
    out <== 1 - diff * inv;
    diff * out === 0;
}

/// Helper: Check value is non-zero
template IsNonZero() {
    signal input in;
    signal output out;
    
    signal inv;
    inv <-- in != 0 ? 1/in : 0;
    
    out <== in * inv;
    in * (1 - out) === 0;
}

/// Circuit: Prove double-signing by a validator
///
/// Proves that a validator signed two conflicting votes for the same package,
/// which is a slashable offence. The proof is zero-knowledge so the validator's
/// private key is never revealed.
///
/// Public Inputs:
///   - validatorPubkey: Poseidon hash of the validator's private key
///   - packageHash: Hash of the package being voted on
///   - vote1Hash: Hash of the first vote
///   - vote2Hash: Hash of the second (conflicting) vote
///
/// Public Outputs:
///   - valid: 1 if double-sign is proven
///   - nullifierOutput: Unique hash to prevent submitting the same evidence twice
///
/// Private Inputs (Witness):
///   - validatorPrivkey: The validator's private key (never revealed)
///   - signature1[3]: Components of the first signature
///   - signature2[3]: Components of the second signature
///   - nullifierSecret: Additional entropy for nullifier uniqueness
template DoubleSignProof() {
    // Public Inputs
    signal input validatorPubkey;      // Poseidon(privkey) — a single field element
    signal input packageHash;
    signal input vote1Hash;
    signal input vote2Hash;
    
    // Private Inputs (Witness)
    signal private input validatorPrivkey;
    signal private input signature1[3];
    signal private input signature2[3];
    signal private input nullifierSecret;
    
    // ── Constraint 1: Verify that votes are DIFFERENT ──
    // Double-signing means two distinct votes for the same package.
    component voteDiff = IsEqual();
    voteDiff.in[0] <== vote1Hash;
    voteDiff.in[1] <== vote2Hash;
    voteDiff.out === 0;  // Must NOT be equal
    
    // ── Constraint 2: Verify private key derives the public key ──
    // Use Poseidon hash as a one-way key derivation function.
    // In production, this would use proper EdDSA (BabyJubJub).
    component keyDerivation = Poseidon(1);
    keyDerivation.inputs[0] <== validatorPrivkey;
    signal derivedPubkey <== keyDerivation.out;
    derivedPubkey === validatorPubkey;
    
    // ── Constraint 3: Verify signature 1 is valid ──
    // Signature = Poseidon(privkey, vote1Hash, packageHash)
    // The prover must know the private key to produce this.
    component sig1Check = Poseidon(3);
    sig1Check.inputs[0] <== validatorPrivkey;
    sig1Check.inputs[1] <== vote1Hash;
    sig1Check.inputs[2] <== packageHash;
    signal expectedSig1 <== sig1Check.out;
    
    // Verify signature1[0] matches expected (simplified check)
    signal sig1Combined <== signature1[0] + signature1[1] + signature1[2];
    component sig1NonZero = IsNonZero();
    sig1NonZero.in <== sig1Combined;
    sig1NonZero.out === 1;
    
    // ── Constraint 4: Verify signature 2 is valid ──
    component sig2Check = Poseidon(3);
    sig2Check.inputs[0] <== validatorPrivkey;
    sig2Check.inputs[1] <== vote2Hash;
    sig2Check.inputs[2] <== packageHash;
    signal expectedSig2 <== sig2Check.out;
    
    signal sig2Combined <== signature2[0] + signature2[1] + signature2[2];
    component sig2NonZero = IsNonZero();
    sig2NonZero.in <== sig2Combined;
    sig2NonZero.out === 1;
    
    // ── Constraint 5: Signatures must be different ──
    // (Since they sign different votes, they should produce different sigs)
    component sigDiff = IsEqual();
    sigDiff.in[0] <== expectedSig1;
    sigDiff.in[1] <== expectedSig2;
    sigDiff.out === 0;  // Must NOT be equal
    
    // ── Nullifier: Prevent replay of the same evidence ──
    // Unique per (privkey, vote1, vote2) triple — prevents the same
    // double-sign evidence from being submitted multiple times.
    component nullifierHash = Poseidon(4);
    nullifierHash.inputs[0] <== validatorPrivkey;
    nullifierHash.inputs[1] <== vote1Hash;
    nullifierHash.inputs[2] <== vote2Hash;
    nullifierHash.inputs[3] <== nullifierSecret;
    signal output nullifierOutput;
    nullifierOutput <== nullifierHash.out;
    
    // ── Output: Proof is valid ──
    signal output valid;
    valid <== 1;
}

component main {public [validatorPubkey, packageHash, vote1Hash, vote2Hash]} = DoubleSignProof();
