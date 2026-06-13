# SEC-401 — External security audit scope

**Status:** Draft for vendor RFP / internal red-team scheduling  
**Parent:** [SECURITY_AND_REMEDIATION_IMPLEMENTATION_PLAN.md](./SECURITY_AND_REMEDIATION_IMPLEMENTATION_PLAN.md) Epic 3.5  
**Target network:** Sepolia testnet (`creg-testnet-1`) — not mainnet

---

## 1. Objectives

1. Validate that **package admission** and **validator pipeline** cannot be bypassed to land malicious or unstaked packages on the verified set.
2. Review **L1 staking and registry** contracts for fund safety, role abuse, and event/log assumptions used by off-chain sync.
3. Confirm **operational controls** (spec signing, hot keys, rate limits, operator API) match documented threat model.
4. Produce a **prioritized finding list** (P0–P3) with reproduction steps suitable for [REMEDIATION_BACKLOG.md](./REMEDIATION_BACKLOG.md).

**Out of scope (this engagement):** Mainnet deployment, `PrivateRegistry` (Planned), cross-chain (`cross_chain: false`), governance UI (disabled), full ZK circuit soundness proof (spot-check only), frontend wallet UX beyond relayer/sponsor paths.

---

## 2. In-scope components

### 2.1 Off-chain — admission and validation

| Component | Path | Focus |
|-----------|------|--------|
| Package admission | `chain-registry/crates/node/src/package_admission.rs` | Stake checks, YARA gate, shielded path (`CREG_SHIELDED_PUBLISH_ENABLED`), rate limits |
| Pre-mempool scan | `chain-registry/crates/node/src/admission_scan.rs` | IPFS fetch, malware rules, shielded skip semantics |
| Validator pipeline | `chain-registry/crates/node/src/validator_pipeline.rs` | ML/ZK stages, vote aggregation, evidence digests |
| Publish / submit API | `chain-registry/crates/node/src/api.rs` (publisher routes) | AuthN on publish, signature message, gRPC + REST parity |
| Validator set sync | `chain-registry/crates/node/src/validator_set_sync.rs` | `eth_getLogs` chunking, cursor, reorg handling |
| Chain spec boot | `chain-registry/crates/node/src/chain_spec_boot.rs`, `main.rs` | Signature verify, pinning, cache fallback |
| CLI publish | `chain-registry/crates/cli/src/publish.rs` | Signing, IPFS pin, shielded wire format |
| Shared wire | `chain-registry/crates/common/src/shielded_wire.rs` | Encrypt/decrypt round-trip, canonical hashes |

### 2.2 Smart contracts (Sepolia deployment)

| Contract | Path | Focus |
|----------|------|--------|
| **Staking.sol** | `chain-registry/contracts/Staking.sol` | `stakeAsPublisher`, `joinAsValidator`, slash/withdraw, permit path |
| **Registry.sol** | `chain-registry/contracts/Registry.sol` | Package lifecycle, appeals linkage |
| **ZKVerifier.sol** | `chain-registry/contracts/ZKVerifier.sol` | Pairing check (ISSUE-002 remediated — verify) |
| **CregToken.sol** | `chain-registry/contracts/CregToken.sol` | Mint/transfer assumptions for stake |
| **Governance.sol** | `chain-registry/contracts/Governance.sol` | Low priority (UI disabled); admin paths |
| **Reputation.sol**, **Appeal.sol** | respective files | Secondary; time-boxed |

**Addresses:** From `chain-registry/testnet/chain-spec.sepolia.json` (`contracts.*`).

### 2.3 Supporting services

| Service | Path | Focus |
|---------|------|--------|
| Secrets loader | `chain-registry/crates/secrets/` | Env vs Vault, prod gate |
| Faucet / relayer | `chain-registry/crates/faucet/`, `relayer/` | Hot-key warnings, sponsorship abuse |
| Bridge worker | `chain-registry/crates/node/src/bridge.rs` | `CREG_BRIDGE_KEY` usage |
| Rate limiting | `chain-registry/crates/node/src/rate_limit.rs` | `/v1/publisher/*`, `/v1/validator/*` buckets |

### 2.4 Infrastructure (light touch)

| Artifact | Path | Focus |
|----------|------|--------|
| Network partition test | `chain-registry/k8s/55-network-partition-test.yaml` | Complement to SEC-402; auditors may review manifest |
| Prod compose / K8s | `docker-compose.prod.yml`, `k8s/` | Unsafe env flags, TLS, operator API key |

---

## 3. Threat model (summary)

| Threat | Mitigation under review |
|--------|-------------------------|
| Unstaked publisher submits package | On-chain stake read in admission |
| Malware in tarball | YARA pre-mempool + pipeline ML/hash stages |
| Shielded publish bypass (wrong hash) | SEC-305 wire format + admission skip rules |
| Fake validator votes | Ed25519 + validator set from L1 logs |
| Spec substitution attack | Ed25519 spec signature + pinned pubkey |
| Hot key exfiltration | Runbook + fingerprints; Vault ADR |
| DoS on public API | Rate limits; cluster limit ADR deferred (SEC-307) |
| PBFT partition | SEC-402 chaos test (separate deliverable) |

---

## 4. Test environment

Auditors receive:

1. This repo at commit: _______________
2. [TESTNET_SEPOLIA_RUNBOOK.md](./TESTNET_SEPOLIA_RUNBOOK.md) and [../chain-registry/testnet/OPERATOR.md](../chain-registry/testnet/OPERATOR.md)
3. Sepolia RPC (operator-provided key or shared read-only endpoint)
4. Optional: running node on `:8090` with synced `validator_set_sync`

**Deliverable environment:** Sepolia only. No mainnet keys.

---

## 5. Deliverables

| # | Deliverable | Due |
|---|-------------|-----|
| 1 | Kickoff + architecture walkthrough (2h) | Week 1 |
| 2 | Threat model alignment memo | Week 1 |
| 3 | Draft findings (rolling) | Weeks 2–3 |
| 4 | Final report (PDF/Markdown) with severity, PoC, recommendation | Week 4 |
| 5 | Retest window for P0/P1 fixes (optional) | Week 5–6 |

---

## 6. Acceptance criteria (SEC-401 done)

- [ ] Scope document approved by engineering lead
- [ ] Vendor or internal red-team **scheduled** with start date
- [ ] In-scope file list matches Section 2 (or written delta)
- [ ] Findings tracked in backlog with IDs

---

## 7. Suggested audit phases

```mermaid
flowchart LR
    A[Architecture review] --> B[Admission + pipeline]
    B --> C[Contracts Staking Registry]
    C --> D[Integration Sepolia]
    D --> E[Report + retest]
```

---

## 8. References

- [SECURITY_OPS_RUNBOOK.md](./SECURITY_OPS_RUNBOOK.md)
- [REMEDIATION_BACKLOG.md](./REMEDIATION_BACKLOG.md) (SEC-303c cross-chain deferral)
- [WALLET_KEY_DERIVATION.md](./WALLET_KEY_DERIVATION.md)
- [adr/ADR-KMS-HOT-KEYS.md](./adr/ADR-KMS-HOT-KEYS.md)

---

## 9. Vendor outreach

Email template and checklist: [SEC-401-VENDOR-OUTREACH.md](./SEC-401-VENDOR-OUTREACH.md)

Generate send-ready copy (pinned tag + SHA): from `chain-registry/`, run `.\testnet\prepare-sec-401-outreach.ps1` → [SEC-401-outreach-ready.md](./SEC-401-outreach-ready.md).

When a vendor confirms, update [NEXT_WORK.md](./NEXT_WORK.md) SEC-401 booking table with vendor name and start date.

---

_Update status in [REMEDIATION_BACKLOG.md](./REMEDIATION_BACKLOG.md) when vendor is selected._
