# Chain Registry — Testnet Readiness Report

> **Report date:** 2026-06-08 (progress addendum **2026-06-09**)  
> **Network:** `creg-testnet-1` on Ethereum **Sepolia** (L1 chain id `11155111`)  
> **Scope:** Readiness assessment for public testnet launch.  
> **Status:** Historical snapshot below; **current status** is in [README.md](../README.md) and [NEXT_WORK.md](../docs/NEXT_WORK.md).

### Progress since this report (2026-06-09)

| Item | Status |
|------|--------|
| NET-301 — 2-validator PBFT quorum | **Done** 2026-06-09 |
| SANDBOX-301 — real nsjail sandbox | **Done** 2026-06-10 |
| DIST-301 — `v0.1.0-testnet` binaries | **Done** 2026-06-10 |
| HOSTING-301 — `testnet.cregnet.dev` public HTTPS | **Done** 2026-06-10 |
| Waitlist — `waitlist.cregnet.dev` + Firebase `registerWaitlist` | **Done** 2026-06-09 |
| SEC-401 — external audit | **Open** — scope ready, vendor TBD |

**Revised lens (June 2026):** Coordinated public alpha is **live**. Remaining P0 before broad external stake: **SEC-401 audit**. See [TESTNET_PHASE_SCOPE.md](../docs/TESTNET_PHASE_SCOPE.md) for participant expectations.

---

## 1. Executive Summary

Chain Registry is a **decentralized software supply-chain registry**: publishers submit content-addressed packages, a fleet of economically-staked validators runs a multi-stage security pipeline, packages are finalized through **PBFT consensus** into a RocksDB chain, gossiped over **libp2p**, and anchored to **Sepolia L1** via a Groth16 rollup bridge. The architecture is ambitious and **substantially built** — 17 Rust crates, 17+ Solidity contracts deployed on Sepolia, an explorer, CLI, faucet, relayer, indexer, and Docker/Kubernetes deployment assets.

**The single most important finding:** there are **two very different readiness bars**, and the system sits on opposite sides of them.

| Lens | Verdict | Score |
|------|---------|-------|
| **Coordinated Sepolia testnet** (maintainers run the fleet, run controlled smoke/soak) | **Ready (conditional go)** | **78 / 100 — B+** |
| **Public self-service testnet** (strangers publish, validate, install, and browse unaided) | **Not ready (Alpha)** | **55 / 100 — C** |
| **Overall engineering build maturity** (how much is actually implemented & tested) | **Solid** | **~72 / 100 — B-** |

**Headline rate for "are we ready for a *public* testnet": ~62/100 — Alpha / Conditional-Go.**
The consensus core, contracts, and validation pipeline are real and were just proven end-to-end (a 3-node soak committed blocks to `tip_height=2` with cross-node parity). What blocks a *public* launch is **not** the core protocol — it is **operational packaging**: placeholder infrastructure URLs in the signed chain spec, a single-validator finalization reality, CLI footguns (default node URL + a broken `creg stake` path for Sepolia tCREG), in-memory pending state, missing/again-broken onboarding docs, and no consumer-facing `creg` distribution.

**Bottom line:** This is a credible **alpha** that maintainers can operate today. To open it to the public, the work is mostly **hardening and finishing the "last mile"**, not rebuilding the engine.

---

## 1.1 Progress Since Report (2026-06-08)

P0 documentation and small CLI fixes applied after the initial report:

| Item | Status |
|------|--------|
| **Publisher/Developer/Validator quickstart** | **Done** — [`docs/PUBLIC_TESTNET_QUICKSTART.md`](../docs/PUBLIC_TESTNET_QUICKSTART.md) |
| **`creg stake` for Sepolia tCREG** | **Already fixed** in `crates/cli/src/stake.rs` (ERC-20 `approve` + `stakeAsPublisher` / `applyToBeValidator` via `cast`) |
| **README stake amount** | **Fixed** — documents 1 tCREG publisher minimum with Sepolia contract env |
| **Broken doc index links** | **Fixed** — `testnet/README.md`, `testnet/QUICKSTART.md`, root `README.md` now point at existing docs |
| **`YOUR_ORG` placeholder** | **Fixed** in `testnet/.env.example` and `testnet/QUICKSTART.md` → `chain-registry/chain-registry` |
| **Multisig submit endpoint** | **Fixed** — `multisig.rs` now posts to `/v1/publisher/packages` |

**Corrections to this report:**

- CLI default node URL is **`http://localhost:8080`**, not `https://registry.chain-pkg.io` (verified in `resolver`, `config.rs`, `config_file.rs`). The real footgun is **no public hosted endpoint** — users must set `CREG_NODE_URL` explicitly for remote fleets.

**Infra P0 progress (2026-06-08, second pass):**

| Item | Status |
|------|--------|
| Chain-spec service URLs (local lab) | **Done** — `chain-spec.sepolia.json` bootnodes cleared, services → localhost ports; re-signed |
| Public lab compose (explorer + faucet overlay) | **Done** — `docker-compose.3node-services.yml`, `start-3node-public.ps1` |
| Pending pool persistence | **Done** — `pending_pool.json` under `CREG_DATA_DIR` |
| `CREG_DEV_SANDBOX` default | **Done** — 3-node compose defaults `false` (override in env for Windows soak) |
| Bridge key wiring | **Done** — optional `CREG_BRIDGE_KEY` on validator-1 via services overlay |
| NET-301 single-validator UX | **Done** — explorer `TestnetPhaseBanner` + `VITE_SINGLE_VALIDATOR` |
| `creg` install path | **Done** — `scripts/install-creg.sh` / `install-creg.ps1` (+ existing `release-binaries.yml`) |

**Still open for true *public* internet hosting:** DNS/TLS bootnodes, hosted node API reachable without localhost, publishing a GitHub release tag, NET-301 multi-validator quorum, real sandbox engine validation with `CREG_DEV_SANDBOX=false`.

**Revised public-readiness estimate:** ~**68/100** (local public lab operable; internet-facing hosting still required).

---

## 2. How I Know — Methodology

This rating is **not** a vibe check. It is derived from:

1. **Live operational evidence** — a 3-node Sepolia fleet (2 validators + 1 observer) was brought to health and a consensus **soak test passed end-to-end**: package published, blocks committed, `tip_height=2` with parity across all three API ports (`28180/28181/28182`), `validator_set_sync=synced`, `peer_count=2`.
2. **Re-verification of the prior security audit** — all 14 issues from `DEEP_DIVE_ANALYSIS.md` (2026-06-06) were re-checked against the *current* tree, file-by-file, with line-level quotes. Result: **9 FIXED, 2 PARTIAL, 3 OPEN**.
3. **Test & CI inventory** — ripgrep counts of every `#[test]`/`#[tokio::test]` (~397 Rust), Forge `function test*` (~99 Solidity), Playwright specs (~32), and a read of `.github/workflows/`.
4. **User-journey walkthroughs** — tracing the actual code paths for publish, install, stake, validator registration, and explorer wiring to find where a real external user would get stuck.
5. **Existing technical deep-dive** — `DEEP_DIVE_ANALYSIS.md` (architecture, subsystem behavior, issue registry) and `testnet/OPERATOR.md` (current operator runbook).

**Confidence:** High for code/test/issue status (directly verified). Medium for performance/scale (only a single-machine 3-node soak observed; no multi-host, multi-operator, or sustained-load data yet).

---

## 3. Readiness Scorecard

Per-dimension scores (0–100). The **weight** reflects how much each dimension matters for a *public testnet*. The weighted composite is the headline "rate."

| # | Dimension | Score | Grade | Weight | Basis |
|---|-----------|:-----:|:-----:|:------:|-------|
| 1 | Consensus & block production (PBFT, VRF, block producer) | 80 | B+ | 12% | Soak committed blocks w/ parity; PBFT sig verify fixed; 36 consensus + 116 node tests |
| 2 | Smart contracts (Registry/Staking/Governance/ZKVerifier) | 70 | B- | 12% | Deployed on Sepolia; ~99 Forge tests; critical contract bugs fixed; **no external audit**; aux contracts weak |
| 3 | Validator pipeline & scanning (static/sandbox/ML/LLM) | 68 | C+ | 10% | Strong design + 38+42 tests; **`CREG_DEV_SANDBOX=true` active** on fleet; ML degraded/mock mode |
| 4 | CLI / publisher & developer UX | 58 | C | 12% | Flows exist; `creg stake` fixed for tCREG; default is localhost (no public endpoint); IPFS hard-dep + shim/install mismatch remain |
| 5 | ZK validation (Groth16 circuits, trusted setup) | 65 | C+ | 6% | Hash-binding (ISSUE-001) **fixed**; prod key guard fixed; no external ZK audit |
| 6 | P2P networking (libp2p, gossipsub, mesh) | 70 | B- | 6% | Full mesh achieved (peer_count=2); needed manual seed fixes; redial fix not yet in image |
| 7 | Validator-set sync (chain-authoritative) | 70 | B- | 6% | Now `synced` after epoch-block fix; disabled on bad staking addr (ISSUE-024 partial) |
| 8 | Explorer / frontend | 65 | C+ | 7% | Capable, well-wired in main compose; **not wired to 3-node fleet**; placeholder public URLs; gov page 501 |
| 9 | L1 bridge / rollup anchoring | 55 | C- | 5% | Implemented (Groth16 + Governance); **disabled without bridge key**; not exercised in soak |
| 10 | Testing & CI | 70 | B- | 8% | ~397 Rust + ~99 Forge tests, CI gates fmt/clippy/build/test/forge; frontend & soak not gated; some crates untested |
| 11 | Documentation & onboarding | 62 | C+ | 8% | Operator runbook + **PUBLIC_TESTNET_QUICKSTART** added; index links fixed; chain-spec placeholder URLs remain |
| 12 | Deployment infra (Docker/K8s/observability) | 80 | B+ | 4% | Compose, k8s manifests, Prometheus, signed spec server — mature |
| 13 | Distribution / release (`creg` binary) | 40 | D | 4% | Release workflow exists; **no consumer install path**; build-from-source + Foundry + IPFS is a high bar |

**Weighted composite ≈ 65/100** for raw technical maturity → adjusted to **~62/100 for *public* testnet readiness** once the self-service launch blockers (§7) are weighted in.

---

## 4. What Is Proven to Work Today

These are not aspirational — they were observed or directly verified:

- **Consensus produces blocks.** The 3-node fleet published a package and committed blocks to `tip_height=2`, identical across all three nodes. PBFT prepare/commit with Ed25519 domain-separated signatures is wired and verified on the gossip path.
- **Validator-set sync works in chain-authoritative mode.** After setting `epoch_block_height` to the staking-contract deploy block (`10952156`), nodes reach `validator_set_sync=synced` reading the Sepolia staking contract.
- **P2P mesh forms.** Nodes discover each other and report `peer_count=2` (full mesh for the 3-node topology).
- **Publish admission enforces real gates.** Submission verifies Ed25519 signature, **on-chain publisher stake** (`stakedBalance > 0`), and a YARA/policy gate before entering the pending pool.
- **Contracts are live on Sepolia.** Registry, Staking, Governance, ZKVerifier, Token are deployed, addressed in the signed chain spec, and covered by ~99 Forge tests.
- **Signed chain spec boot.** Nodes fetch `chain-spec.sepolia.json` + detached Ed25519 signature from the spec server — tamper-evident network config.
- **The build is green.** `cargo check -p chain-registry-node` compiles; CI gates `fmt + clippy -D warnings + build + cargo test --workspace + forge test` on every PR to `main`.

---

## 5. Subsystem Readiness Detail

### 5.1 Consensus & Node Core — **B+ (80)**
PBFT three-phase commit, VRF/deterministic proposer selection, block producer, RocksDB chain store. Heaviest test coverage in the repo (`node` 116, `consensus` 36). PBFT gossip now does **full** signature verification (ISSUE-007 fixed). **Caveat:** the live fleet effectively runs with one on-chain validator (`core-1`) and relies on `CREG_PBFT_ALLOW_SMALL_CLUSTER_QUORUM=true`; true multi-operator Byzantine fault tolerance is unproven.

### 5.2 Smart Contracts — **B- (70)**
Core contracts (Registry, Staking, Governance, ZKVerifier) are active, deployed, and well-tested. Critical contract defects from the prior audit are fixed: `submitPackageFor(publisher, …)` restores batch publisher identity (ISSUE-003), and CrossChain `setChainName` is now governance-gated (ISSUE-010). **Open:** `finalizePackage` is **permissionless by default** (ISSUE-008 partial) — the Sepolia deploy script enables relay enforcement, but a fresh deploy does not. Many satellite contracts (`GovernanceV2`, `ValidatorRewards`, `PackageInsurance`, `SlashingEvidence`) are untested. **No external security audit exists** — mandatory before mainnet, strongly advised before a *public* testnet that holds real stake.

### 5.3 Validator Pipeline & Scanning — **C+ (68)**
Defense-in-depth design (static analysis → sandbox → diff → LLM → PGP → reputation) with explicit consensus-grade vs degraded vote separation. **Two real caveats:** (a) `CREG_DEV_SANDBOX=true` is currently set on the 3-node fleet — it **skips real behavioral sandboxing** and emits a High finding instead of fail-closing (ISSUE-013 open); this must be `false` with a real sandbox engine (nsjail/gVisor/Docker) for any meaningful security claim. (b) ML deep scan runs in degraded/mock mode when models are absent.

### 5.4 ZK Validation — **C+ (65)**
The critical soundness gap (ISSUE-001 — circuit not binding content/manifest hashes) is **fixed**: `bind_hash32_limbs` now constrains content & manifest hashes as public inputs, and the production key guard returns an error instead of panicking (ISSUE-005 fixed). Trusted setup management and the absence of an external ZK audit keep this from scoring higher.

### 5.5 L1 Bridge / Rollup — **C- (55)**
Batches verified blocks, computes Merkle roots, generates Groth16 proofs, submits via Governance. **Disabled unless `CREG_BRIDGE_KEY` is set** — and it is **not** set on the 3-node fleet, so L1 anchoring was **not exercised** in the soak. The RPC-parse panic (ISSUE-004) is fixed (now logs and retries). Needs a dedicated bridge-key + a funded hot wallet and an explicit end-to-end anchoring test.

### 5.6 P2P, Sync & Networking — **B- (70)**
libp2p Gossipsub mesh works; sync reaches tip. **Caveats:** the mesh required manual seed corrections (`/dns4/...` not `/ip4/hostname`), the `main.rs` seed-redial robustness fix is in the working tree but **not yet baked into the running image**, and historical validator-set verification during long-range sync is not implemented (ISSUE-016 open).

### 5.7 Explorer / Frontend — **C+ (65)**
Full-featured React explorer, cleanly reverse-proxied to the node API in the **main** `docker-compose.yml` (port 3007, operator key injected). **It is not part of the 3-node Sepolia fleet** — you must point it at a node port manually or use the node's embedded `/ui`. Public deployment URLs in the chain spec are placeholders, the governance page is backed by a `501` API (ISSUE-017 open), and the 32 Playwright tests are **not run in CI**.

### 5.8 Deployment Infra — **B+ (80)**
Docker Compose (Sepolia + local), Kubernetes manifests (validators 1–10, ingress, backup), Prometheus scraping, and the signed spec server are all present and coherent — genuinely operations-grade scaffolding.

---

## 6. Security Posture — Prior Audit Re-Verified

All 14 issues from the 2026-06-06 deep dive were re-checked against the current code:

| Status | Count | Issues |
|--------|:-----:|--------|
| **FIXED** | 9 | ISSUE-001 (ZK hash binding), 002 (gossip sig fallback), 003 (BatchOperations identity), 004 (bridge RPC panic), 005 (ZK prod guard), 006 (gossip serialize), 007 (PBFT verify), 010 (CrossChain ACL) |
| **PARTIAL** | 2 | ISSUE-008 (permissionless `finalizePackage` — enforcement exists but **default off**), ISSUE-024 (validator-set sync still disabled on bad staking addr, but now surfaces explicit status/warnings) |
| **OPEN** | 3 | ISSUE-013 (`CREG_DEV_SANDBOX` bypass), ISSUE-016 (no historical validator-set verification on sync), ISSUE-017 (governance API returns 501) |

**Interpretation:** the **critical** items that would undermine trust (ZK soundness, gossip signature integrity, contract publisher identity, bridge crash) are resolved. The residual items are **medium**-severity and mostly about *defaults and completeness*, not exploitable holes — provided operators run with `CREG_DEV_SANDBOX=false`, a real sandbox engine, and relay enforcement enabled.

---

## 7. Public-Testnet Launch Blockers (P0)

These are the things that will make a *stranger's* first experience fail. Each must be closed (or loudly documented) before opening the doors.

1. **Placeholder infrastructure in the signed chain spec.** `chain-spec.sepolia.json` ships bootnodes `*.creg-testnet.example`, faucet `localhost:8082`, and explorer/Discord placeholders. Public users have nothing real to connect to.
2. **No public hosted node endpoint.** CLI defaults to `http://localhost:8080` — correct for local dev, but there is no maintained public API for strangers to use without operator coordination (`CREG_NODE_URL` required).
3. **Single-validator finalization reality.** Today packages reach **pending** but fleet-wide **verified** depends on a real validator quorum (the public multi-validator milestone, NET-301, is not shipped). Either ship it or display the single-observer limitation prominently.
4. ~~**`creg stake` broken for Sepolia tCREG**~~ **Resolved** — `crates/cli/src/stake.rs` uses ERC-20 approve + `stakeAsPublisher`/`applyToBeValidator`; README documents 1 tCREG publisher minimum. Helpers `creg testnet stake-publisher` remain valid alternatives.
5. **In-memory pending pool.** A node restart drops pending submissions — surprising and lossy for public users.
6. **No consumer distribution.** No published `creg` binary / installer; build-from-source + Foundry + a local IPFS daemon is too high a bar for casual publishers/developers.
7. ~~**Documentation debt (index + quickstart)**~~ **Partially resolved** — [`docs/PUBLIC_TESTNET_QUICKSTART.md`](../docs/PUBLIC_TESTNET_QUICKSTART.md) added; `testnet/README.md` / `QUICKSTART.md` / `.env.example` links and `YOUR_ORG` fixed. Chain-spec placeholder URLs still need real endpoints + re-sign.
8. **Bridge not exercised.** L1 anchoring has not been demonstrated on the fleet (no bridge key configured).
9. **`CREG_DEV_SANDBOX=true` on the fleet.** Must be flipped to a real sandbox engine before any security claim is credible publicly.

---

## 8. Roadmap to Public Testnet

Prioritized, with rough effort. **P0 = launch-blocking.**

### P0 — Must fix before public launch
- [ ] Replace all placeholder URLs (bootnodes, faucet, explorer, RPC, Discord) in `chain-spec.sepolia.json` with **real public endpoints**; re-sign the spec. *(S)*
- [ ] Stand up and host: a **public node** endpoint, a **public faucet**, and a **public explorer**; bake those into CLI defaults or make the CLI fail-fast with a clear "set `CREG_NODE_URL`" message. *(M)*
- [x] Fix or deprecate `creg stake` so the documented publisher/validator staking path actually works against Sepolia tCREG. *(S–M)* — done in `stake.rs`; README updated
- [ ] Flip `CREG_DEV_SANDBOX=false` and validate a real sandbox engine (nsjail/gVisor/Docker) in the fleet. *(M)*
- [ ] Publish `creg` release artifacts (the `release-binaries.yml` workflow exists). *(S–M)*
- [x] One-page **Publisher / Developer / Validator quickstart** — [`docs/PUBLIC_TESTNET_QUICKSTART.md`](../docs/PUBLIC_TESTNET_QUICKSTART.md)
- [ ] Decide the validator story: ship multi-operator quorum (NET-301) **or** prominently document the single-observer limitation on the explorer landing page. *(L if shipping)*
- [x] Restore or remove the missing canonical docs and fix `YOUR_ORG` placeholders. *(S)* — index links + quickstart; chain-spec URLs still placeholder

### P1 — Strongly recommended before scale
- [ ] Persist the pending pool (survive restarts). *(M)*
- [ ] Enable + demonstrate the L1 bridge end-to-end (dedicated bridge key + funded hot wallet + anchoring test). *(M)*
- [ ] Commission an **external security audit** of the core contracts and ZK circuits. *(L, external)*
- [ ] Enable `enforceFinalizeRelays` by default for the public deployment (ISSUE-008). *(S)*
- [ ] Wire the explorer Playwright suite into CI; add tests for `db-sync`, `faucet`, and the new intelligence modules. *(M)*
- [ ] Implement governance proposals API (replace the 501) so the explorer governance page works (ISSUE-017). *(M)*

### P2 — Hardening & polish
- [ ] Historical validator-set verification on long-range sync (ISSUE-016). *(M)*
- [ ] Make `forge snapshot --check` blocking; add `forge fmt --check` / solhint and pre-commit hooks. *(S)*
- [ ] Rebuild & ship `creg-node:local-3node` with the `main.rs` P2P redial fix for durable mesh after restarts. *(S)*
- [x] Reconcile multisig submit endpoint (`/v1/packages` vs `/v1/publisher/packages`). *(S)* — multisig uses `/v1/publisher/packages`
- [ ] Align shim security model with `creg install`. *(S)*
- [ ] Add tests for satellite contracts (`GovernanceV2`, `ValidatorRewards`, `PackageInsurance`). *(M)*

*Effort key: S = ≤1 day, M = a few days, L = 1–3+ weeks.*

---

## 9. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|:----------:|:------:|------------|
| Public users hit placeholder/wrong endpoints and bounce | High | High | P0: real URLs + CLI defaults/fail-fast |
| "Verified" expectation unmet on single-validator net | High | High | Ship NET-301 or document the limit loudly |
| Sandbox bypass leaks unanalyzed packages | Medium | High | `CREG_DEV_SANDBOX=false` + real engine before launch |
| Contract bug with no external audit | Medium | High | Commission audit; enable finalize-relay allowlist |
| Pending pool loss on restart | Medium | Medium | Persist pending pool (P1) |
| Infura/RPC rate-limit → `validator_set_sync` degraded | Medium | Medium | Dedicated/archive RPC; documented in OPERATOR.md |
| Bridge misconfig halts L1 anchoring silently | Low–Med | Medium | Bridge logs+retries (fixed); add health check + alert |
| Doc rot blocks onboarding | High | Medium | P0 doc cleanup + single quickstart |

---

## 10. Final Verdict

- **For a coordinated, maintainer-run Sepolia testnet (smoke/soak among known operators): GO (conditional).** The protocol works end-to-end; run with `CREG_DEV_SANDBOX=false` + real sandbox, a dedicated RPC, and the documented quorum flags.
- **For a public, self-service testnet: NOT YET — Alpha.** Close the §7 P0 blockers first. The gap is **operational last-mile**, not core engineering.

**Overall public-testnet readiness: ~62/100 (Alpha / Conditional-Go).** With focused effort on the P0 list (mostly Small/Medium tasks plus the public-infra hosting and the validator-quorum decision), a credible public testnet is **weeks, not months** away.

---

## Appendix A — Evidence Sources

- `DEEP_DIVE_ANALYSIS.md` — architecture, subsystem behavior, original 25-issue registry.
- `testnet/OPERATOR.md` — current 3-node Sepolia operator runbook.
- `docs/TESTNET_PHASE_SCOPE.md` — declared single-observer phase + NET-301 milestone.
- `docs/PUBLIC_TESTNET_QUICKSTART.md` — publisher / developer / validator quickstart (added 2026-06-08).
- Live soak: `testnet/soak-3node-consensus.ps1` (published package, `tip_height=2` parity, `validator_set_sync=synced`, `peer_count=2`).
- Security re-verification: 9 FIXED / 2 PARTIAL / 3 OPEN against current tree (file:line confirmed).
- Test inventory: ~397 Rust tests, ~99 Forge tests, ~32 Playwright specs; CI `.github/workflows/ci.yml` gates fmt/clippy/build/test/forge.
- Recent commits: `3b00bac` (Sepolia ops + `submitPackageFor` + `bind_hash32_limbs`), `f4b7a97` (PBFT signature verification), `3fd5942` (`CREG_PRODUCTION` ZK key guard).

## Appendix B — Scoring Notes

Scores are evidence-weighted, not aspirational. A dimension scores high only when it is **both implemented and verified** (tests, soak, or contract deployment). Dimensions with working code but missing public-facing packaging (CLI UX, docs, distribution) are deliberately scored lower because they are exactly what a *public* user hits first. The composite intentionally distinguishes "engineering build maturity" (~72) from "public-testnet operational readiness" (~62) so the two should not be conflated when planning the launch.
