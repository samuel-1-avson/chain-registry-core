#!/bin/bash
# Build ZK Circuit for Double-Sign Slashing Evidence
# 
# This script compiles the Circom circuit and generates the proving/verifying keys

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "🔨 Building ZK Slashing Circuit"
echo "================================"

# Check dependencies
check_dependency() {
    if ! command -v "$1" &> /dev/null; then
        echo "❌ $1 not found. Please install it."
        exit 1
    fi
    echo "✅ $1 found"
}

echo ""
echo "Checking dependencies..."
check_dependency circom
check_dependency snarkjs
check_dependency node

# Install circomlib if not present
if [ ! -d "node_modules/circomlib" ]; then
    echo ""
    echo "📦 Installing circomlib..."
    npm install circomlib
fi

# Create output directories
mkdir -p build
mkdir -p keys

echo ""
echo "📝 Compiling circuit..."
circom DoubleSignProof.circom --r1cs --wasm --sym -o build/

echo ""
echo "📊 Circuit info:"
snarkjs r1cs info build/DoubleSignProof.r1cs

echo ""
echo "🔑 Setting up trusted setup (powers of tau)..."

# Download powers of tau file if not exists
if [ ! -f "keys/pot12_final.ptau" ]; then
    echo "Downloading powers of tau..."
    # In production, generate or download from trusted source
    # This is a placeholder for development
    snarkjs powersoftau new bn128 12 keys/pot12_0000.ptau -v
    snarkjs powersoftau contribute keys/pot12_0000.ptau keys/pot12_0001.ptau --name="First Contributor" -v -e="random text"
    snarkjs powersoftau prepare phase2 keys/pot12_0001.ptau keys/pot12_final.ptau -v
fi

echo ""
echo "🔐 Generating proving key..."
snarkjs groth16 setup build/DoubleSignProof.r1cs keys/pot12_final.ptau keys/DoubleSignProof_0000.zkey

echo ""
echo "📝 Contributing to phase 2..."
snarkjs zkey contribute keys/DoubleSignProof_0000.zkey keys/DoubleSignProof_0001.zkey --name="1st Contributor" -v -e="another random text"

echo ""
echo "📤 Exporting final key..."
snarkjs zkey beacon keys/DoubleSignProof_0001.zkey keys/DoubleSignProof_final.zkey 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 10 -n="Final Beacon"

echo ""
echo "🔍 Verifying proving key..."
snarkjs zkey verify build/DoubleSignProof.r1cs keys/pot12_final.ptau keys/DoubleSignProof_final.zkey

echo ""
echo "📄 Exporting verification key..."
snarkjs zkey export verificationkey keys/DoubleSignProof_final.zkey keys/verification_key.json

echo ""
echo "📝 Exporting Solidity verifier..."
snarkjs zkey export solidityverifier keys/DoubleSignProof_final.zkey ../chain-registry/contracts/Groth16Verifier.sol

echo ""
echo "✅ Circuit build complete!"
echo ""
echo "Files generated:"
echo "  - build/DoubleSignProof.r1cs (constraint system)"
echo "  - build/DoubleSignProof.wasm (witness generator)"
echo "  - keys/DoubleSignProof_final.zkey (proving key)"
echo "  - keys/verification_key.json (verification key)"
echo "  - ../chain-registry/contracts/Groth16Verifier.sol (Solidity verifier)"
echo ""
echo "Next steps:"
echo "  1. Deploy the Groth16Verifier.sol contract"
echo "  2. Update ZKSlashingVerifier with the new verifying key"
echo "  3. Test proof generation and verification"
