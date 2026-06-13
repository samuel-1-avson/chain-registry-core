# CREG testnet — external phase scope

**Status:** Phase open (limited) — coordinated 3-node lab  
**Network:** Sepolia L1 + `creg-testnet-1` (signed chain spec)  
**Effective:** 2026-05-30  
**Review:** 2026-07-30 or when [SEC-401](./SEC-401-AUDIT-SCOPE.md) audit completes

This page defines what external participants can expect from the **current** testnet. It is not a mainnet commitment.

---

## What this testnet is

A **coordinated Sepolia deployment** of Chain Registry: publishers submit signed packages; validators (when deployed) analyze and finalize; observers sync L1 validator-set state and expose APIs.

**Canonical operator docs:** [TESTNET_SEPOLIA_RUNBOOK.md](./TESTNET_SEPOLIA_RUNBOOK.md) · [../chain-registry/testnet/OPERATOR.md](../chain-registry/testnet/OPERATOR.md)

---

## Node roles

| Mode | `CREG_IS_VALIDATOR` | What it does |
|------|---------------------|--------------|
| **Observer** (default in reuse scripts) | `false` | Syncs Sepolia staking/registry; serves API; admits publishes into **pending**; does **not** run local PBFT finalization |
| **Validator** | `true` + `CREG_VALIDATOR_KEY` + stake | Runs analysis, votes, and can drive packages to **verified** on the local chain |

**NET-301 (2026-06-09):** Maintainer lab runs **2 validators + 1 observer** with PBFT quorum; publish reaches **`verified`** with `validator_count=2`. **HOSTING-301 (2026-06-10):** Public HTTPS at `https://api.testnet.cregnet.dev` and sibling vhosts (see [README](../README.md)). **SANDBOX-301 (2026-06-10):** Production compose uses real nsjail sandbox (`sandbox-301-verify.ps1`). Windows dev soak may still use `CREG_DEV_SANDBOX=true` locally only.

---

## Package statuses (what “verified” means)

| Status | Meaning on API / `creg status` |
|--------|--------------------------------|
| **pending** | Admitted to the node’s in-memory pending pool; consensus not complete on this node |
| **UNVERIFIED** | CLI label for pending (install allowed with warnings per product policy) |
| **verified** | Record on the node’s RocksDB chain after validator pipeline + finalization |
| **revoked** | Rejected or revoked on chain |
| **UNKNOWN** | Not on chain and not in pending (wrong node, restart, wrong URL, or cache) |

**Verified** means this **node’s** chain store has accepted the package after validator workflow. On the public fleet, use `CREG_NODE_URL=https://api.testnet.cregnet.dev` (or the operator URL you trust).

---

## Known limits (read before integrating)

1. **Pending pool persistence** — 3-node fleet persists to `pending_pool.json` under `CREG_DATA_DIR`; single-node dev stacks may still lose pending state on restart unless configured.
2. **Observer nodes keep pending visible** — As of `validator_pipeline` observer fix, observers no longer delete pending entries after ~1s (rebuild required).
3. **No cross-chain** — `feature_flags.cross_chain: false` in spec (SEC-303c in [REMEDIATION_BACKLOG.md](./REMEDIATION_BACKLOG.md)); bridge UI/receipts deferred.
4. **Governance API disabled** — HTTP 501 by design (REM-201); explorer governance gated.
5. **Shielded publish** — Off unless `CREG_SHIELDED_PUBLISH_ENABLED=true` on client and node (experimental, SEC-304/305).
6. **CLI / REST footguns** — Always pass `--node-url` (or `CREG_NODE_URL`) for local testnet; URL-encode canonicals in REST paths (`@` and `/` break unencoded routes).
7. **Bootnodes / public IPFS in spec** — Example hostnames; production testnet fleet not operated by this repo alone.
8. **Dev sandbox profile** — `CREG_DEV_SANDBOX=true` in `sepolia-3node.env` skips real behavioural sandboxing (SB012 approve-with-warning). Do not treat that profile as production security validation; use `start-3node-sandbox.ps1` + `sandbox-301-verify.ps1` for SANDBOX-301 (Linux container backend; Docker Desktop WSL2 on Windows qualifies).
9. **Public URLs** — Live at `*.testnet.cregnet.dev` after HOSTING-301. Re-patch spec with [prepare-public-hosting.ps1](../chain-registry/testnet/prepare-public-hosting.ps1) when URLs change; verify with [hosting-301-verify.ps1](../chain-registry/testnet/hosting-301-verify.ps1).

---

## What is in scope for external participants

- Run an **observer** against published `chain-spec.sepolia.json` + signature
- **Publish** (staked publisher, IPFS, Ed25519 key) and read **pending** status
- Integrate **public REST** (`/v1/public/*`) and health/metrics
- Report issues against pinned commit on `main`

## Out of scope (this phase)

- Mainnet or economic guarantees
- Cross-chain verification
- On-chain private registries (Planned / D5)
- Production KMS for all hot keys (in progress; see [ADR-KMS-HOT-KEYS.md](./adr/ADR-KMS-HOT-KEYS.md))
- Formal security audit completion (scheduled; [SEC-401-AUDIT-SCOPE.md](./SEC-401-AUDIT-SCOPE.md))

---

## Phase-open checklist (maintainers)

| Step | Done |
|------|------|
| Observer pending-pool fix on `main` | Yes |
| E2E-301 publish smoke documented and verified | Yes |
| OPS-201 sign-off | Done 2026-05-30 (see [TESTNET_SEPOLIA_RUNBOOK.md](./TESTNET_SEPOLIA_RUNBOOK.md)) |
| This scope page published | Yes |
| NET-301 multi-validator quorum (maintainer lab) | **Done** 2026-06-09 (`net-301-quorum-verify.ps1`; dev sandbox on Windows) |
| SANDBOX-301 real nsjail engine | **Done** 2026-06-10 (`sandbox-301-verify.ps1`; `Dockerfile.windows` app rebuild + secure image overlay) |
| Public chain-spec URLs + hosting (HOSTING-301) | **Done** 2026-06-10 — [gcp-public-hosting.md](../chain-registry/testnet/gcp-public-hosting.md) |
| Waitlist (static + Firebase) | **Done** — [WAITLIST_FIREBASE_DEPLOY.md](./WAITLIST_FIREBASE_DEPLOY.md) |

---

## Contact / issues

Use the repository issue tracker listed in the chain spec `support.issues` field. Security: `support.security` in spec.
