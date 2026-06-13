# Chain Registry Testnet

This directory contains the chain spec, bootstrap-node material, local
multi-node lab assets, and operator guides for the Chain Registry testnet.

The live operational source of truth is [`../TESTNET_READINESS_REPORT.md`](../TESTNET_READINESS_REPORT.md) plus [`../docs/PUBLIC_TESTNET_QUICKSTART.md`](../docs/PUBLIC_TESTNET_QUICKSTART.md).
Use those pages for the current topology, verified workflows, and known limits.

## Current Operating Model

- `../local-testnet.ps1` and `../docker-compose.local-testnet.yml` are the canonical local distributed bootstrap path.
- `../docker-compose.testnet.yml` and `../testnet.ps1` are the bootstrap-host path.
- `../docker-compose.validator.yml` is the one-validator-per-host expansion path.
- `docker-compose.3node.yml` in this folder is a local lab harness for consensus testing, not the canonical operator topology.

## Quick Links

- [`QUICKSTART.md`](./QUICKSTART.md) — fastest path to a running node
- [`FRIEND_ONBOARDING.md`](./FRIEND_ONBOARDING.md) — join an existing private alpha
- [`TAILSCALE_SETUP.md`](./TAILSCALE_SETUP.md) — private multi-host networking
- [`SOAK_TEST.md`](./SOAK_TEST.md) — longer-form resilience test plan
- [`../docs/PUBLIC_TESTNET_QUICKSTART.md`](../docs/PUBLIC_TESTNET_QUICKSTART.md) — publisher / developer / validator quickstart
- [`OPERATOR.md`](./OPERATOR.md) — 3-node Sepolia operator runbook
- [`soak-3node-consensus.ps1`](./soak-3node-consensus.ps1) — maintainer consensus soak script
- [`../docs/TESTNET_SEPOLIA_RUNBOOK.md`](../docs/TESTNET_SEPOLIA_RUNBOOK.md) — Sepolia deploy, chain-spec sign/publish, node env
- [`bootstrap/README.md`](./bootstrap/README.md) — bootstrap node deployment
- [`spec-server/README.md`](./spec-server/README.md) — signed chain-spec hosting
- [`../TESTNET_READINESS_REPORT.md`](../TESTNET_READINESS_REPORT.md) — evidence-based public testnet readiness (2026-06-08)

## Verification Commands

Use these against any running node:

```bash
curl http://localhost:8080/v1/health
curl http://localhost:8080/v1/chain/stats | jq
curl http://localhost:8080/v1/nodes | jq
creg testnet status --node-url http://localhost:8080
```

`/v1/chain/stats` is the current quick view for block height, peer count, and
validator count. `/v1/nodes` is the supported REST surface for enumerating the
known node set.

## Publishing On Testnet

Use the CLI rather than posting raw multipart payloads to `/v1/packages`.
Publishing now requires a canonical `publisher_address` with active on-chain
stake.

```bash
creg --node-url http://localhost:8080 publish ./my-pkg-1.0.0.tgz \
  --key-file ~/.creg/publisher.key \
  --publisher-address 0xYourPublisherAddress
```

The node verifies the signature against the package id, content hash, and
publisher address, then rejects unstaked publishers before pending-pool
admission.

## Chain Spec Verification

Any operator can verify the signed chain spec independently:

```bash
cargo run --example verify_chain_spec --package common -- \
  testnet/chain-spec.sepolia.json \
  $(cat testnet/chain-spec.sepolia.json.sig)
```

## Directory Highlights

| File or Directory | Purpose |
| --- | --- |
| `chain-spec.sepolia.json` | Signed canonical chain spec for the Sepolia-backed testnet |
| `chain-spec.sepolia.json.sig` | Detached Ed25519 signature for the chain spec |
| `.env.sepolia.example` | Example Sepolia/testnet environment template |
| `docker-compose.3node.yml` | Local three-node lab harness |
| `run-3node-host.ps1` | PowerShell helper for the local three-node lab |
| `finalize-sepolia-spec.ps1` | Sign and publish the chain spec |
| `deploy-sepolia.ps1` / `deploy-sepolia.sh` | Deploy contracts to Sepolia |
| `bootstrap/` | Bootstrap-node deployment assets |
| `spec-server/` | Static hosting for the signed chain spec |
| `soak-test/` | Automation and scenario files for longer soak runs |

## Recommended Flow

1. Start with [`QUICKSTART.md`](./QUICKSTART.md) if you need a fast local bootstrap.
2. Use [`bootstrap/README.md`](./bootstrap/README.md) when you are exposing a dedicated bootstrap node.
3. Use [`FRIEND_ONBOARDING.md`](./FRIEND_ONBOARDING.md) and [`TAILSCALE_SETUP.md`](./TAILSCALE_SETUP.md) for multi-host private-alpha runs.
4. Use [`SOAK_TEST.md`](./SOAK_TEST.md) only after the bootstrap-host flow is stable.
