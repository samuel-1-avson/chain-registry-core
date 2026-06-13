#!/usr/bin/env bash
# Diverse double-compiling verification for declared toolchain inventory targets.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INVENTORY="${ROOT}/config/release-assurance/toolchain-inventory.json"

usage() {
  cat <<'EOF'
Usage: ddc-verify.sh [--help]

Verify direct DDC (diverse double-compiling) targets listed in
config/release-assurance/toolchain-inventory.json.

When no component has direct_ddc_target=true with non-empty artifacts,
this script validates the inventory and exits successfully.
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

if [[ ! -f "$INVENTORY" ]]; then
  echo "ddc-verify: missing $INVENTORY" >&2
  exit 1
fi

python3 - "$INVENTORY" <<'PY'
import json
import sys
from pathlib import Path

inventory = Path(sys.argv[1])
data = json.loads(inventory.read_text(encoding="utf-8"))
targets = [
    c
    for c in data.get("components", [])
    if c.get("direct_ddc_target") and c.get("artifacts")
]
if not targets:
    print("ddc-verify: no direct DDC targets with artifacts configured; inventory OK")
    sys.exit(0)

print("ddc-verify: the following targets require explicit DDC verification:")
for t in targets:
    print(f"  - {t.get('id')}: {', '.join(t.get('artifacts', []))}")
print("ddc-verify: add verification steps for these targets before release")
sys.exit(1)
PY
