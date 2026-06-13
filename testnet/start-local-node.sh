#!/usr/bin/env bash
# Chain Registry — Start Single Local Node (Linux/macOS/WSL)
# Usage: ./start-local-node.sh [-k VALIDATOR_KEY] [-n NODE_ID]
#
# This starts a single chain-registry node against Sepolia using the signed chain spec.
# No Docker required. Uses cargo run (debug build).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

VALIDATOR_KEY=""
NODE_ID="local-test"
DATA_DIR="$SCRIPT_DIR/node-data"
RPC_URL="https://ethereum-sepolia-rpc.publicnode.com"
VALIDATOR=false

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -k, --key KEY       Validator private key (hex, 64 chars)"
    echo "  -n, --node-id ID    Node identifier (default: local-test)"
    echo "  -d, --data-dir DIR  Data directory (default: ./node-data)"
    echo "  -r, --rpc URL       Sepolia RPC URL (default: publicnode)"
    echo "  -v, --validator     Enable validator mode"
    echo "  -h, --help          Show this help"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -k|--key) VALIDATOR_KEY="$2"; shift 2 ;;
        -n|--node-id) NODE_ID="$2"; shift 2 ;;
        -d|--data-dir) DATA_DIR="$2"; shift 2 ;;
        -r|--rpc) RPC_URL="$2"; shift 2 ;;
        -v|--validator) VALIDATOR=true; shift ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

echo "═══════════════════════════════════════════════════════"
echo "  Chain Registry — Local Node Starter"
echo "═══════════════════════════════════════════════════════"

# [1/5] Check prerequisites
echo ""
echo "[1/5] Checking prerequisites..."

if ! command -v cargo &> /dev/null; then
    echo "ERROR: Rust/Cargo not found. Install from https://rustup.rs/"
    exit 1
fi
echo "  ✓ Cargo found: $(cargo --version)"

SPEC_PATH="$REPO_ROOT/testnet/chain-spec.sepolia.json"
SIG_PATH="$REPO_ROOT/testnet/chain-spec.sepolia.json.sig"

if [[ ! -f "$SPEC_PATH" ]]; then
    echo "ERROR: Chain spec not found: $SPEC_PATH"
    exit 1
fi
echo "  ✓ Chain spec found"

if [[ ! -f "$SIG_PATH" ]]; then
    echo "  ⚠ Signature file not found: $SIG_PATH"
    echo "    Node will skip signature verification"
fi

mkdir -p "$DATA_DIR"
echo "  ✓ Data directory: $(cd "$DATA_DIR" && pwd)"

# [2/5] Configure environment
echo ""
echo "[2/5] Configuring environment..."

export CREG_CHAIN_SPEC_URL="file://$SPEC_PATH"
export CREG_SPEC_SIGNING_PUBKEY="0437e4adac481519cd6ae66907294c40cfcbf0bdeadd47806f6233be4bd5f82d"
export CREG_ETH_RPC_URL="$RPC_URL"
export CREG_NODE_ID="$NODE_ID"
export CREG_DATA_DIR="$(cd "$DATA_DIR" && pwd)"
export CREG_LISTEN="0.0.0.0:8080"
export CREG_P2P_LISTEN="/ip4/0.0.0.0/tcp/9000"
export CREG_P2P_SEEDS=""   # Empty = you are the bootstrap
export RUST_LOG="info,chain_registry_node=debug"

if [[ "$VALIDATOR" == true ]]; then
    export CREG_IS_VALIDATOR="true"
    if [[ -n "$VALIDATOR_KEY" ]]; then
        export CREG_VALIDATOR_KEY="$VALIDATOR_KEY"
        echo "  ✓ Validator mode ENABLED (key provided)"
    else
        # Generate random key
        KEY=$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | xxd -p)
        export CREG_VALIDATOR_KEY="$KEY"
        echo "  ✓ Validator mode ENABLED (random key: $KEY)"
    fi
else
    export CREG_IS_VALIDATOR="false"
    echo "  ✓ Full node mode (non-validator)"
fi

echo "  ✓ Chain spec: $CREG_CHAIN_SPEC_URL"
echo "  ✓ L1 RPC: $RPC_URL"
echo "  ✓ Node ID: $NODE_ID"

# [3/5] Verify chain spec
echo ""
echo "[3/5] Verifying chain spec..."
if [[ -f "$SIG_PATH" ]]; then
    SIG=$(cat "$SIG_PATH" | tr -d ' \n')
    if cargo run --example verify_chain_spec --package common --quiet -- "$SPEC_PATH" "$SIG" 2>/dev/null; then
        echo "  ✓ Chain spec signature VALID"
    else
        echo "  ⚠ Signature verification had issues (non-fatal for local testing)"
    fi
else
    echo "  ⚠ No signature to verify"
fi

# [4/5] Compute genesis hash
echo ""
echo "[4/5] Computing genesis hash..."
GENESIS_HASH=$(cargo run --example compute_genesis_hash --package common --quiet -- "$SPEC_PATH" 2>/dev/null || echo "unknown")
echo "  ✓ Genesis hash: $GENESIS_HASH"

# [5/5] Start node
echo ""
echo "[5/5] Starting node..."
echo "  Press Ctrl+C to stop"
echo ""
echo "  API:     http://localhost:8080/v1/health"
echo "  Metrics: http://localhost:8080/metrics"
echo "  gRPC:    localhost:50051"
echo "  P2P:     localhost:9000"
echo ""

cd "$REPO_ROOT"
exec cargo run --bin creg-node --package chain-registry-node
