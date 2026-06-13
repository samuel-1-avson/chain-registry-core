#!/usr/bin/env bash
# Rebuild release binaries twice and verify byte-identical outputs.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ART="${ROOT}/artifacts/release-assurance"

usage() {
  cat <<'EOF'
Usage: release-assurance.sh [--help]

Build chain-registry-cli (creg) and chain-registry-node (creg-node) twice
with deterministic release flags. Outputs must be byte-identical.

Evidence is written to artifacts/release-assurance/.
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

cd "$ROOT"
mkdir -p "$ART"

export CARGO_INCREMENTAL=0
if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
  export SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct)"
fi
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=${ROOT}=/creg"

build_into() {
  local label="$1"
  local target_dir="$2"
  CARGO_TARGET_DIR="$target_dir" cargo build --locked --release \
    --package chain-registry-cli \
    --package chain-registry-node
  install -m 0755 "$target_dir/release/creg" "$ART/creg-${label}"
  install -m 0755 "$target_dir/release/creg-node" "$ART/creg-node-${label}"
}

echo "release-assurance: build A (SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH})"
build_into a "${ROOT}/target-release-assurance-a"
echo "release-assurance: build B"
build_into b "${ROOT}/target-release-assurance-b"

if ! cmp -s "$ART/creg-a" "$ART/creg-b"; then
  echo "release-assurance: creg binaries differ between builds" >&2
  exit 1
fi
if ! cmp -s "$ART/creg-node-a" "$ART/creg-node-b"; then
  echo "release-assurance: creg-node binaries differ between builds" >&2
  exit 1
fi

{
  echo "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}"
  sha256sum "$ART/creg-a" "$ART/creg-node-a"
} > "$ART/sha256sum.txt"

echo "release-assurance: OK — reproducible release binaries verified"
cat "$ART/sha256sum.txt"
