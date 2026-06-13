# Chain Registry — public documentation

Curated entry point for **protocol, validators, publishers, and auditors**.  
Hosting runbooks, Firebase deploy guides, budget models, and internal maintainer docs are kept in-repo for the core team but are **not** linked from the public README or waitlist.

**GitHub:** [chain-registry-core](https://github.com/samuel-1-avson/chain-registry-core) — protocol source at repository root.

---

## Start here

| Document | Audience |
|----------|----------|
| [PUBLIC_TESTNET_QUICKSTART.md](./PUBLIC_TESTNET_QUICKSTART.md) | Publishers, developers, validators |
| [TESTNET_PHASE_SCOPE.md](./TESTNET_PHASE_SCOPE.md) | Testnet limits, verified semantics, alpha scope |
| [WALLET_KEY_DERIVATION.md](./WALLET_KEY_DERIVATION.md) | Ed25519 (packages) vs Ethereum EOA (staking) |

---

## Protocol & architecture

| Document | Description |
|----------|-------------|
| [DEEP_DIVE_ANALYSIS.md](../chain-registry/DEEP_DIVE_ANALYSIS.md) | Architecture, data flows, issue registry |
| [TESTNET_READINESS_REPORT.md](../chain-registry/TESTNET_READINESS_REPORT.md) | Evidence-based readiness snapshot |
| [chain-spec.sepolia.json](../chain-registry/testnet/chain-spec.sepolia.json) | Live testnet chain parameters |
| [contracts/README.md](../chain-registry/contracts/README.md) | Solidity contracts on Sepolia |
| [circuits/README.md](../circuits/README.md) | ZK Groth16 circuits (Circom) |
| [migrations/README.md](../chain-registry/migrations/README.md) | Database migration order (`db-sync`) |
| [DATABASE_SCHEMA.md](./DATABASE_SCHEMA.md) | PostgreSQL schema reference |

---

## Run a node (operators)

| Document | Description |
|----------|-------------|
| [testnet/QUICKSTART.md](../chain-registry/testnet/QUICKSTART.md) | Fastest path to a local node |
| [testnet/OPERATOR.md](../chain-registry/testnet/OPERATOR.md) | Sepolia validator fleet overview |
| [testnet/README.md](../chain-registry/testnet/README.md) | Testnet directory index |
| [DOCKER.md](../chain-registry/DOCKER.md) | Docker Compose profiles |

---

## Build from source

```bash
cd chain-registry
cargo build --release -p cli
cargo test --workspace
cd contracts && forge test
```

Release binaries: [v0.1.0-testnet](https://github.com/samuel-1-avson/chain-registry-core/releases/tag/v0.1.0-testnet).

---

## Repository map (blockchain core)

| Path | Contents |
|------|----------|
| [`chain-registry/crates/`](../chain-registry/crates/) | Rust workspace — node, consensus, CLI, validators |
| [`chain-registry/contracts/`](../chain-registry/contracts/) | Staking, registry, governance, ZK verifier |
| [`circuits/`](../circuits/) | Circom sources and build scripts |
| [`chain-registry/schemas/`](../chain-registry/schemas/) | JSON schemas for packages and verdicts |
| [`chain-registry/rules/`](../chain-registry/rules/) | Supply-chain YARA rules |
| [`chain-registry/tests/`](../chain-registry/tests/) | Integration tests |

Web frontends (explorer, hub) and cloud deploy scripts live in the private chain-registry-ops repository and are **not** part of this public documentation set. The waitlist SPA is maintained in the separate [Creg-waitlist](https://github.com/samuel-1-avson/Creg-waitlist) repository.
