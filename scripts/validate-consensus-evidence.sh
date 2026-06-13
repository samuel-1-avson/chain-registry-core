#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/validate-consensus-evidence.sh [--fixtures-dir DIR]

Validates the scanner-profile and evidence-bundle fixtures used by the
evidence-bound validator vote path.
USAGE
}

fixtures_dir="config/consensus-evidence/fixtures"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --fixtures-dir)
      fixtures_dir="${2:?--fixtures-dir requires a value}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

command -v node >/dev/null 2>&1 || {
  echo "node is required" >&2
  exit 127
}

node scripts/validate-consensus-evidence.mjs --fixtures-dir "$fixtures_dir"
