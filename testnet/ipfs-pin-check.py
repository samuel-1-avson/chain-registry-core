#!/usr/bin/env python3
"""IPFS-001 / IPFS-002 — operator pinning + CID availability checker.

Enumerates every non-revoked package in the registry, pins each CID on the
operator IPFS node, then verifies the block is actually retrievable. Writes a
JSON report and exits non-zero when any package content is unavailable, so it
can run under cron and feed alerting.

Stdlib only (no pip deps) — runs on the edge VM's system python3.

Environment:
  CREG_API_URL         Registry node API (default http://localhost:8080)
  CREG_IPFS_API        Kubo RPC API (default http://localhost:5001)
  CREG_PIN_TIMEOUT     Per-request timeout seconds (default 30)
  CREG_PIN_REPORT_DIR  Where to write report JSON (default ./ipfs-pin-logs)
  CREG_PIN_SKIP_PIN    Set to 1 to only check availability (no pin add)

Cron example (edge VM, hourly):
  0 * * * * CREG_API_URL=https://api.testnet.cregnet.dev \
            CREG_IPFS_API=http://localhost:15001 \
            python3 /opt/creg/ipfs-pin-check.py >> /var/log/creg-pin-check.log 2>&1
"""

import json
import os
import sys
import time
import urllib.parse
import urllib.request

API = os.environ.get("CREG_API_URL", "http://localhost:8080").rstrip("/")
IPFS = os.environ.get("CREG_IPFS_API", "http://localhost:5001").rstrip("/")
TIMEOUT = int(os.environ.get("CREG_PIN_TIMEOUT", "30"))
REPORT_DIR = os.environ.get("CREG_PIN_REPORT_DIR", "./ipfs-pin-logs")
SKIP_PIN = os.environ.get("CREG_PIN_SKIP_PIN", "0") == "1"


def get_json(url, timeout=TIMEOUT):
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.load(resp)


def ipfs_post(path, arg, timeout=TIMEOUT):
    url = f"{IPFS}{path}?arg={urllib.parse.quote(arg)}"
    req = urllib.request.Request(url, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def list_all_packages():
    packages, offset = [], 0
    while True:
        page = get_json(f"{API}/v1/packages?offset={offset}&limit=200")
        batch = page.get("packages", [])
        packages.extend(batch)
        offset += len(batch)
        if not batch or offset >= page.get("total", 0):
            return packages


def main():
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    try:
        packages = list_all_packages()
    except Exception as exc:  # API down is itself an availability incident
        print(f"FATAL: cannot list packages from {API}: {exc}", file=sys.stderr)
        return 2

    results = []
    pinned = available = unavailable = skipped = 0

    for pkg in packages:
        canonical = pkg.get("canonical", "")
        status = pkg.get("status", "")
        if status == "revoked":
            skipped += 1
            continue

        entry = {
            "canonical": canonical,
            "status": status,
            "cid": None,
            "pinned": False,
            "available": False,
            "error": None,
        }
        try:
            detail = get_json(f"{API}/v1/packages/{urllib.parse.quote(canonical)}")
            cid = detail.get("ipfs_cid") or (detail.get("package") or {}).get("ipfs_cid")
            entry["cid"] = cid
            if not cid:
                raise RuntimeError("package record has no ipfs_cid")

            if not SKIP_PIN:
                ipfs_post("/api/v0/pin/add", cid, timeout=max(TIMEOUT, 60))
                entry["pinned"] = True
                pinned += 1

            # Availability: block must be fetchable from this node within timeout.
            ipfs_post("/api/v0/block/stat", cid)
            entry["available"] = True
            available += 1
        except Exception as exc:
            entry["error"] = str(exc)
            unavailable += 1
            print(f"UNAVAILABLE {canonical} cid={entry['cid']}: {exc}", file=sys.stderr)

        results.append(entry)

    report = {
        "started": started,
        "finished": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "api": API,
        "ipfs": IPFS,
        "total_packages": len(packages),
        "checked": len(results),
        "skipped_revoked": skipped,
        "pinned": pinned,
        "available": available,
        "unavailable": unavailable,
        "ok": unavailable == 0,
        "results": results,
    }

    os.makedirs(REPORT_DIR, exist_ok=True)
    out_path = os.path.join(
        REPORT_DIR, f"ipfs-pin-check-{time.strftime('%Y%m%d-%H%M%S')}.json"
    )
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    print(
        f"[ipfs-pin-check] checked={report['checked']} pinned={pinned} "
        f"available={available} unavailable={unavailable} report={out_path}"
    )
    return 0 if unavailable == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
