#!/usr/bin/env bash
# Install creg + creg-node from GitHub Releases or build from source.
#
# Usage:
#   ./scripts/install-creg.sh
#   ./scripts/install-creg.sh --version v0.1.0-testnet
#   ./scripts/install-creg.sh --build

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.creg/bin}"
VERSION=""
BUILD=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --build) BUILD=1; shift ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

mkdir -p "$INSTALL_DIR"

if [[ "$BUILD" -eq 1 ]]; then
  cd "$ROOT"
  cargo build --release --package chain-registry-cli --package chain-registry-node
  install -m 755 target/release/creg target/release/creg-node "$INSTALL_DIR/"
  echo "Installed to $INSTALL_DIR"
  exit 0
fi

if [[ -z "$VERSION" ]]; then
  echo "No --version; building from source (publish a GitHub release to download binaries)."
  exec "$0" --build
fi

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) TARBALL="chain-registry-${VERSION}-linux-amd64.tar.gz" ;;
  *) echo "Unsupported arch: $ARCH"; exit 1 ;;
esac

# Override when releases live on a fork: export CREG_GITHUB_REPO=owner/repo
GITHUB_REPO="${CREG_GITHUB_REPO:-samuel-1-avson/chain-registry-core}"
URL="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/${TARBALL}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

curl -fsSL "$URL" -o "$TMP/$TARBALL"
tar -xzf "$TMP/$TARBALL" -C "$INSTALL_DIR"
echo "Installed creg + creg-node to $INSTALL_DIR"
echo "export PATH=\"$INSTALL_DIR:\$PATH\""
