# Public Testnet Quickstart

One-page guide for **publishers**, **developers**, and **validators** joining the Chain Registry Sepolia testnet (`creg-testnet-1`).

**Read first:** [TESTNET_PHASE_SCOPE.md](./TESTNET_PHASE_SCOPE.md) — defines what “verified” means today and known limits.

**Public API:** `https://api.testnet.cregnet.dev` — set `CREG_NODE_URL` to this (or pass `--node-url`).

**Readiness snapshot:** [TESTNET_READINESS_REPORT.md](../chain-registry/TESTNET_READINESS_REPORT.md)

---

## Before you start

| Requirement | Notes |
|-------------|--------|
| **Node URL** | Set `CREG_NODE_URL=https://api.testnet.cregnet.dev` for the public fleet. Default `http://localhost:8080` is for local dev only. |
| **Sepolia RPC** | For staking: `SEPOLIA_RPC_URL` or `CREG_ETH_RPC` |
| **Foundry `cast`** | Required for `creg stake` and `creg testnet stake-*` |
| **IPFS** | Local Kubo (`ipfs daemon`) or operator-provided gateway for `creg publish` |
| **Two key types** | **Ed25519** (`creg keygen`) signs packages; **secp256k1 EOA** stakes tCREG on L1. See [WALLET_KEY_DERIVATION.md](./WALLET_KEY_DERIVATION.md). |

**Contract addresses (Sepolia defaults):**

| Contract | Address |
|----------|---------|
| Staking | `0xf28C63C4Aafd27025E535Ab9ab7B4daC18C96Bc2` |
| CREG Token | `0x97c21d46B3eac604e92E907D54aA92eEc0Af550b` |
| Registry | `0x3aCfF05d00AC199412a94326eD8aA874aaA3596c` |

Minimum stakes (from chain spec): **1 tCREG** publisher, **100 tCREG** validator.

---

## Publisher — publish a package

### 1. Build the CLI

```bash
cd chain-registry
cargo build --release -p cli
export PATH="$PWD/target/release:$PATH"
```

### 2. Generate an Ed25519 publish key

```bash
creg keygen publisher --out ~/.creg/publisher.key
```

### 3. Fund and stake (Sepolia tCREG)

Use a **separate Ethereum wallet** (not the Ed25519 key file):

```bash
export SEPOLIA_RPC_URL=https://sepolia.infura.io/v3/YOUR_KEY
export CREG_STAKING_ADDR=0xf28C63C4Aafd27025E535Ab9ab7B4daC18C96Bc2
export CREG_TOKEN_ADDR=0x97c21d46B3eac604e92E907D54aA92eEc0Af550b

# Option A — unified stake command (approve + stakeAsPublisher)
creg stake --amount 1 --role publisher \
  --key ~/.creg/publisher-eoa.key \
  --rpc-url "$SEPOLIA_RPC_URL"

# Option B — testnet helper
creg testnet stake-publisher 1 --key 0xYourEoaPrivateKey --rpc-url "$SEPOLIA_RPC_URL"

# Option C — faucet first (if operator runs faucet on :8082)
creg testnet drip --address 0xYourPublisherAddress
```

Acquire tCREG via the operator faucet or `testnet/stake-publisher-sepolia.ps1`.

### 4. Start IPFS and publish

```bash
ipfs daemon   # or use operator IPFS API via CREG_IPFS_URL

export CREG_NODE_URL=https://api.testnet.cregnet.dev   # public fleet (local: http://localhost:28182)

creg publish ./my-package-1.0.0.tgz \
  --key-file ~/.creg/publisher.key \
  --publisher-address 0xYourPublisherAddress \
  --ecosystem npm
```

### 5. Track status

```bash
creg status npm:my-package@1.0.0 --node-url "$CREG_NODE_URL"
```

**Expected today:** `pending` on observer nodes; `verified` only after a validator fleet finalizes (see NET-301 in [NEXT_WORK.md](./NEXT_WORK.md)).

---

## Developer — install and verify

### Install a verified package

```bash
export CREG_NODE_URL=https://api.testnet.cregnet.dev

creg install npm:lodash@4.17.21
# Add --unverified to allow pending/unknown (not recommended for production)
```

### Verify with light-client proof

```bash
creg verify npm:lodash@4.17.21 --node-url "$CREG_NODE_URL"
```

### Optional: package-manager shims

```bash
creg setup-shims
# Shims warn on unverified installs but may fall through to npm/pip on chain errors.
# Prefer `creg install` for verified IPFS-backed installs.
```

### Browse the registry (explorer)

| Stack | URL | Notes |
|-------|-----|-------|
| Main Docker compose | http://localhost:3007 | Proxied to node :8090 |
| 3-node Sepolia lab | http://localhost:28180/ui | Embedded node UI if image includes explorer dist |
| Standalone dev | `cd explorer && VITE_API_BASE=http://localhost:28180 npm run dev` | Point at any node API port |

---

## Validator — join the network

**Internal operators:** [chain-registry/testnet/OPERATOR.md](../chain-registry/testnet/OPERATOR.md) (3-node Sepolia fleet).

**External validators (high level):**

1. Stake **≥ 100 tCREG** and apply on L1:

```bash
creg stake --amount 100 --role validator \
  --key ~/.creg/validator-eoa.key \
  --rpc-url "$SEPOLIA_RPC_URL"
```

2. Generate Ed25519 validator key; register identity on the node API (`POST /v1/validators/register`).
3. Wait for consensus admission (`approveByConsensus` from an active validator).
4. Run `creg-node` with `CREG_IS_VALIDATOR=true`, `CREG_VALIDATOR_KEY`, signed chain spec URL.

For validator-2 on the internal 3-node fleet:

```powershell
$env:VALIDATOR_2_ETH_PRIVATE_KEY = "0x..."
.\chain-registry\testnet\register-validator-2-sepolia.ps1
```

See [TESTNET_SEPOLIA_RUNBOOK.md](./TESTNET_SEPOLIA_RUNBOOK.md) and [OPERATOR.md](../chain-registry/testnet/OPERATOR.md) for validator fleet operations.

---

## Operator stacks (reference)

| Goal | Command / doc |
|------|----------------|
| Full Sepolia stack (node + explorer + faucet) | `cd chain-registry && docker compose up -d` |
| 3-node consensus lab | `.\chain-registry\testnet\start-3node-test.ps1` |
| 3-node + explorer (+ optional faucet) | `.\chain-registry\testnet\start-3node-public.ps1` |
| Patch chain-spec service URLs (local lab) | `.\chain-registry\testnet\patch-sepolia-chain-spec-services.ps1` |
| Soak test (maintainers) | `.\chain-registry\testnet\soak-3node-consensus.ps1` |
| Preflight | `creg doctor` (load `testnet/scanner-fleet.env` first) |
| Sepolia deploy | [TESTNET_SEPOLIA_RUNBOOK.md](./TESTNET_SEPOLIA_RUNBOOK.md) |

**3-node API ports (defaults):** 28180 (validator-1), 28181 (validator-2), 28182 (observer).  
**Public lab UI:** explorer `http://localhost:3007`, faucet `http://localhost:8082` (when started with `-WithFaucet`).

### Install `creg` without building manually

```bash
# Linux — from source until a release tag exists
./chain-registry/scripts/install-creg.sh --build

# Windows
.\chain-registry\scripts\install-creg.ps1 -BuildFromSource
```

When maintainers publish a tag (`v*`), GitHub Actions workflow `release-binaries.yml` attaches `creg` and `creg-node` to the release. Then:

```bash
./scripts/install-creg.sh --version v0.1.1-testnet
```

---

## Common failures

| Symptom | Fix |
|---------|-----|
| `Publisher has no on-chain stake` | Run `creg stake --amount 1 --role publisher` with tCREG + EOA key |
| `Insufficient stake` / 403 on publish | Same; confirm `stakedBalance > 0` on Staking contract |
| `expected value at line 1 column 1` on publish | UTF-8 BOM in `package.json` inside tarball |
| `validator_set_sync=degraded` | Use archive-capable Sepolia RPC; set `epoch_block_height` in chain spec |
| `UnknownValidator` on node 2 | Complete L1 registration per OPERATOR.md |
| `Consensus timeout` | Align scanner env across validators (`scanner-fleet.env`); check `creg doctor` profile digest |
| Wrong node / UNKNOWN status | Set `CREG_NODE_URL`; pending is lost on node restart |

---

## Alpha limitations

- **SEC-401** external security audit not yet complete — treat as public alpha, not production.
- **L1 bridge anchoring** requires operator `CREG_BRIDGE_KEY` configuration.
- **Cross-chain** and **shielded publish** remain disabled in chain spec.
- **Governance HTTP API** returns 501 by design.

**Support:** GitHub Issues URL in `chain-spec.sepolia.json` → `support.issues`
