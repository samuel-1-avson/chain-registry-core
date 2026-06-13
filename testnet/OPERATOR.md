# Chain Registry testnet — operator runbook

**Network:** Sepolia (`creg-testnet-1`, L1 chain id `11155111`)  
**Fleet:** 2 validators + 1 observer via `docker-compose.3node.yml`

---

## Topology (NET-301)

| Node | Container | Role | `CREG_NODE_ID` | API (default host port) |
|------|-----------|------|----------------|-------------------------|
| 1 | `creg-3node-node1` | Validator (bootstrap) | `core-1` | `28180` |
| 2 | `creg-3node-node2` | Validator | `validator-2` | `28181` |
| 3 | `creg-3node-node3` | Observer | `observer-1` | `28182` |

Shared: IPFS (`15001`), chain-spec nginx (`18888`), P2P `29100–29102`.

**Multi-host deployment:** Run one validator per machine using `docker-compose.validator.yml` with the same `chain-spec.sepolia.json`, distinct `CREG_VALIDATOR_KEY`, and P2P bootnodes pointing at peers. Each host needs Sepolia RPC, IPFS (shared or per-node with pin sync), and on-chain stake for its validator EOA.

**NET-301 acceptance:** ≥2 validators active on L1, `CREG_PBFT_ALLOW_SMALL_CLUSTER_QUORUM` unset, publish reaches `verified` with PBFT quorum — not single-validator override.

```powershell
# Same-machine lab (compose)
.\testnet\init-sepolia-3node-env.ps1
.\testnet\start-3node-test.ps1
$env:VALIDATOR_2_ETH_PRIVATE_KEY = "0x..."   # never commit
.\testnet\register-validator-2-sepolia.ps1
.\testnet\net-301-quorum-verify.ps1
```

### GCP fleet (`creg-validator-vm`): validator-2 identity

L1 can show **Active** while runtime still reports `active_validators: 1` if `/v1/validators/registrations` is empty on the fleet APIs.

1. `.\testnet\register-validator-2-sepolia.ps1 -CheckOnly` (L1 Active + Ed25519 pubkey).
2. Do not rely on `-RegisterIdentity` alone on Windows — `node-api.ps1` targets local `creg-3node-*` Docker, not GCP `creg-fleet-node*`. Sign locally (same logic as the script), `gcloud compute scp` the JSON body to the VM, then POST `/v1/validators/register` on ports **28180** and **28181** via `.\testnet\gcp\ssh-validator-vm.ps1`.
3. Repeat the same POST on the **observer pool** (`creg-observer-pool-*`, port **28182**) so `api.testnet.cregnet.dev` chain stats match the validators.
4. Poll until `active_validators` is **2** on validator VM and public API.
5. `.\testnet\approve-validator-governance-sepolia.ps1 -Applicant <EVM>` only if `governance_approved` stays false (2026-06-12: not needed; L1 already Active).

---

## Sandbox (SANDBOX-301)

| Profile | Image | `CREG_DEV_SANDBOX` | Host |
|---------|-------|-------------------|------|
| Windows dev soak | `Dockerfile.windows` | `true` optional | Windows |
| Credible testnet | `Dockerfile.secure` (nsjail) | `false` | Linux container backend (Docker Desktop WSL2 on Windows qualifies) |
| GCP public fleet (MAL-001) | `Dockerfile.secure` on fleet image (`chain-registry-node-secure:fleet`) | `false` (forced by `docker-compose.fleet-sandbox.yml`) | creg-validator-vm (Linux) |

Linux secure fleet:

```powershell
.\testnet\build-3node-secure-image.ps1          # or -SkipAppBuild if app image is current
.\testnet\start-3node-sandbox.ps1
.\testnet\sandbox-301-verify.ps1                # or soak-3node-sandbox.ps1
```

GCP public fleet (MAL-001 — secure sandbox is the default):

```powershell
.\testnet\gcp\deploy-validator-fleet.ps1        # builds nsjail image on VM, applies fleet-sandbox overlay
.\testnet\gcp\verify-fleet-sandbox.ps1          # evidence JSON in testnet/sandbox-301-logs/
```

Public validator profiles must never run `CREG_DEV_SANDBOX=true`. The fleet start script only skips the secure overlay when `CREG_FLEET_DEV_SANDBOX=1` is set explicitly (dev fleets only).

Build images manually: `.\testnet\build-3node-secure-image.ps1` (or `build-3node-secure-image.sh` on Linux). After validator code changes, rebuild with `-RebuildApp`.

Reference privileged profile: `docker-compose.testnet.yml` (`node-1` uses `chain-registry-node-secure:latest`).

---

## IPFS Pinning & Availability (IPFS-001 / IPFS-002)

Every accepted (non-revoked) package CID must be pinned by operator infrastructure, and availability must be checked on a schedule.

```powershell
.\testnet\gcp\run-ipfs-pin-check.ps1                 # pin all CIDs on edge Kubo + verify availability
.\testnet\gcp\run-ipfs-pin-check.ps1 -CheckOnly      # availability check only
```

Reports land in `testnet/ipfs-pin-logs/` (launch-gate evidence). On the edge VM, schedule hourly via cron — see the header of `testnet/ipfs-pin-check.py`. Non-zero exit = unavailable content → treat as Scenario 4 in `docs/INCIDENT_RESPONSE_RUNBOOK.md`.

---

## Distribution (DIST-301)

Maintainers tag and push; CI publishes binaries:

```bash
git tag v0.1.0-testnet
git push origin v0.1.0-testnet
```

Verify release + install URL:

```powershell
.\testnet\verify-dist-301.ps1 -Version v0.1.0-testnet
.\testnet\verify-dist-301.ps1 -Version v0.1.0-testnet -RunInstallSh   # Linux/Git Bash
```

Install (uses `CREG_GITHUB_REPO` or git `origin`):

```bash
export CREG_GITHUB_REPO=samuel-1-avson/chain-registry-blockchain-CREG-
./scripts/install-creg.sh --version v0.1.0-testnet
```

---

## Sepolia L1 JSON-RPC (public)

| URL | Purpose |
|-----|---------|
| `https://explorer.<base>/rpc` | Sepolia `eth_*` for wallets, `cast`, staking txs |
| `https://faucet.<base>/rpc` | Same proxy on faucet host (after edge Caddy `sepolia-public-rpc.caddy`) |
| `https://api.<base>/rpc` | **CREG only** (`creg_chainId`, `creg_blockNumber`, …) — not Sepolia |

Verify: `.\testnet\verify-sepolia-rpc-endpoints.ps1`

`FAUCET_PUBLIC_RPC_URL` in the faucet container must point at **explorer** `/rpc`, never `api.* /rpc`.

---

## L1 anchoring & reorg safety (P0 hardening)

**Trust model (honesty label):** L1 anchors are **checkpoint attestations** (`proof_mode: checkpoint-attestation`), not validity proofs — the Groth16 batch circuit only proves the batch is non-empty; state roots are computed off-chain by the bridge. Do not market them as ZK-proven rollup batches until the circuit constrains the real state transition.

| Knob | Default | Meaning |
|------|---------|---------|
| `CREG_VALIDATOR_SET_FINALITY_LAG` | `2` (testnet) / `6` | L1 blocks to wait before applying staking events to the validator set. `0` logs a warning — shallow Sepolia reorgs can flap membership. |
| `CREG_BRIDGE_SELF_APPROVE` | `true` | When `false`, the bridge only **submits** batch proposals; an independent governance signer must vote to execute. Required for a meaningful `GOVERNANCE_THRESHOLD>=2` setup. |

**Anchor journal:** every settled batch is persisted to `$CREG_DATA_DIR/bridge_anchors.json` (capped at 500, newest first) with L1 tx hash, L1 block, roots, and tx count. Served by `GET /v1/bridge/anchors`; the explorer Bridge tab now shows real history.

**Reorg journal:** L2 fork events are recorded automatically (PBFT same-height replacement, and peer-sync divergence recovery up to depth 64 with signature re-verification + longest-chain rule) and served by `GET /v1/reorgs`. A reorg deeper than 64 blocks halts auto-recovery and requires operator investigation — treat as an incident.

**Governance threshold:** `deploy-sepolia.ps1` warns when `GOVERNANCE_THRESHOLD<=1` (single key can propose **and** execute anchoring/minting/slashing). Redeploy with `GOVERNANCE_THRESHOLD>=2` and independent `GENESIS_SIGNERS` before public exposure; the node also logs this warning at each batch submit.

---

## Routine operations

| Task | Command |
|------|---------|
| Start fleet | `.\testnet\start-3node-test.ps1` |
| Soak (parity + publish) | `.\testnet\soak-3node-consensus.ps1` |
| Stop | `docker compose -f testnet/docker-compose.3node.yml --env-file testnet/sepolia-3node.env down` |
| Health | `Invoke-RestMethod http://localhost:28180/v1/health` |
| Logs | `docker compose -f testnet/docker-compose.3node.yml logs -f creg-node-1` |

---

## Security audit (SEC-401)

Scope: [docs/SEC-401-AUDIT-SCOPE.md](../../docs/SEC-401-AUDIT-SCOPE.md)  
Outreach template: [docs/SEC-401-VENDOR-OUTREACH.md](../../docs/SEC-401-VENDOR-OUTREACH.md)

Generate send-ready email: `.\testnet\prepare-sec-401-outreach.ps1` → `docs/SEC-401-outreach-ready.md` (pins `v0.1.0-testnet` SHA).

Record vendor and **start date** in [docs/NEXT_WORK.md](../../docs/NEXT_WORK.md) when booked.

## Public hosting (HOSTING-301)

Runbook: [gcp-public-hosting.md](./gcp-public-hosting.md)

```powershell
.\testnet\prepare-public-hosting.ps1 -BaseDomain testnet.YOUR_DOMAIN -AcmeEmail you@example.com
# On GCP VM: ./testnet/start-3node-gcp.sh
.\testnet\hosting-301-verify.ps1 -BaseDomain testnet.YOUR_DOMAIN
```

---

## References

- [TESTNET_SEPOLIA_RUNBOOK.md](../../docs/TESTNET_SEPOLIA_RUNBOOK.md)
- [TESTNET_READINESS_REPORT.md](../TESTNET_READINESS_REPORT.md)
- [NEXT_WORK.md](../../docs/NEXT_WORK.md)
