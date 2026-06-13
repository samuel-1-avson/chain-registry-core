#!/usr/bin/env bash
# Generate a persistent libp2p identity key for a bootstrap node.
# The key is written to ./p2p-key/identity.pb (protobuf format, libp2p compatible).
# The Peer ID is printed to stdout.
#
# Usage:
#   ./generate-peer-key.sh
#   # Copy p2p-key/ into your bootstrap node volume

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEY_DIR="${SCRIPT_DIR}/p2p-key"
mkdir -p "$KEY_DIR"

# Use the chain-registry-node binary to generate a key
# If not available, use openssl + a small Rust helper

if command -v creg-node >/dev/null 2>&1; then
    echo "Using creg-node to generate key..."
    creg-node --generate-p2p-key "$KEY_DIR/identity.pb"
else
    echo "creg-node not found in PATH. Using temporary Rust binary..."
    # Fallback: compile a tiny keygen tool
    cat > /tmp/creg-keygen.rs <<'RUST'
use libp2p::identity::Keypair;
use std::{env, fs};

fn main() {
    let path = env::args().nth(1).expect("Usage: creg-keygen <output.pb>");
    let keypair = Keypair::generate_ed25519();
    let proto = keypair.to_protobuf_encoding().expect("encode");
    fs::write(&path, proto).expect("write");
    println!("Peer ID: {}", keypair.public().to_peer_id());
}
RUST
    rustc --edition 2021 -L target/release/deps /tmp/creg-keygen.rs -o /tmp/creg-keygen 2>/dev/null || {
        echo "ERROR: Cannot compile keygen. Install creg-node or Rust toolchain."
        exit 1
    }
    /tmp/creg-keygen "$KEY_DIR/identity.pb"
fi

echo ""
echo "Key saved to: $KEY_DIR/identity.pb"
echo "Mount this directory into your bootstrap node container:"
echo "  volumes:"
echo "    - ./p2p-key:/app/p2p-key:ro"
