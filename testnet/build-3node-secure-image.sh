#!/usr/bin/env bash
# Build chain-registry-app + nsjail secure node image for SANDBOX-301.
# Requires Linux Docker (Docker Desktop WSL2 on Windows is OK).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DOCKERFILE="${1:-Dockerfile}"
SKIP_APP="${SKIP_APP_BUILD:-0}"
if [[ "$(docker info --format '{{.OSType}}' 2>/dev/null || echo unknown)" != "linux" ]]; then
  echo "SANDBOX-301 requires Docker Linux containers" >&2
  exit 1
fi
if [[ "$SKIP_APP" != "1" ]] && ! docker image inspect chain-registry-app:latest >/dev/null 2>&1; then
  echo "[build-secure] Building chain-registry-app:latest from ${DOCKERFILE} ..."
  docker build -t chain-registry-app:latest -f "$DOCKERFILE" .
elif docker image inspect chain-registry-app:latest >/dev/null 2>&1; then
  echo "[build-secure] Using existing chain-registry-app:latest (set SKIP_APP_BUILD=1 or rebuild manually)"
fi
echo "[build-secure] Building chain-registry-node-secure:latest ..."
docker build -t chain-registry-node-secure:latest -f Dockerfile.secure .
docker run --rm --entrypoint nsjail chain-registry-node-secure:latest --help >/dev/null
echo "OK chain-registry-node-secure:latest ready"
