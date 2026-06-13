# Chain Registry — Quick Start Guide

> Goal: get a node running quickly and verify the supported health/status surfaces.

For publisher/developer/validator flows, see [`../../docs/PUBLIC_TESTNET_QUICKSTART.md`](../../docs/PUBLIC_TESTNET_QUICKSTART.md). For readiness limits, see [`../TESTNET_READINESS_REPORT.md`](../TESTNET_READINESS_REPORT.md).

## Choose Your Path

| Path | Time | What You Get | Best For |
|---|---|---|---|
| A. Single node (native) | 15 min | One node on your machine | Local development |
| B. Bootstrap host (Docker) | 15-20 min | Shared services plus `node-1` | Local bootstrap/testnet bring-up |
| C. 3-node local lab | 30 min | Local consensus simulation | PBFT and sync testing |
| D. Friends alpha | 1-2 hours | Multi-host private alpha | Distributed networking checks |

## Path A: Single Node — Native

```bash
git clone https://github.com/chain-registry/chain-registry.git
cd chain-registry/testnet
cp .env.example .env
# Edit .env and set a unique CREG_NODE_ID
```

Linux/macOS:

```bash
./start-local-node.sh -n my-node
```

Windows PowerShell:

```powershell
.\start-local-node.ps1 -NodeId my-node
```

Verify:

```bash
curl http://localhost:8080/v1/health
curl http://localhost:8080/v1/chain/stats | jq
curl http://localhost:8080/v1/nodes | jq
```

## Path B: Bootstrap Host — Docker

From the repo root:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File testnet.ps1
```

Equivalent Docker Compose flow:

```bash
docker compose --env-file .env.testnet -f docker-compose.testnet.yml up -d --build
```

Verify the bootstrap host:

```bash
creg doctor --testnet --skip-drip
curl http://localhost:8080/v1/health
curl http://localhost:8080/v1/chain/stats | jq
curl http://localhost:8080/v1/nodes | jq
```

## Path C: 3-Node Local Lab

Use this only for local consensus experiments.

```bash
cd testnet
docker compose -f docker-compose.3node.yml up -d --build
```

Verify all three nodes:

```bash
curl http://localhost:8080/v1/chain/stats | jq '.block_height'
curl http://localhost:8081/v1/chain/stats | jq '.block_height'
curl http://localhost:8082/v1/chain/stats | jq '.block_height'
```

## Path D: Friends Alpha

Use [`TAILSCALE_SETUP.md`](TAILSCALE_SETUP.md) for the bootstrap-side setup and
[`FRIEND_ONBOARDING.md`](FRIEND_ONBOARDING.md) for the joiner checklist.

## Supported Smoke Checks

Once a node is running, use these checks first:

```bash
curl http://localhost:8080/v1/health
curl http://localhost:8080/v1/chain/stats | jq '{height: .block_height, peers: .peer_count, validators: .validator_count}'
curl http://localhost:8080/v1/nodes | jq
curl http://localhost:8080/metrics
creg testnet status --node-url http://localhost:8080
```

## Publishing A Package

Use the CLI rather than posting raw multipart data directly to `/v1/packages`.
Publishing now requires a staked publisher address.

```bash
creg --node-url http://localhost:8080 publish ./my-package.tgz \
  --key-file ~/.creg/publisher.key \
  --publisher-address 0xYourPublisherAddress
```

If `0xYourPublisherAddress` is not staked on-chain, the node rejects the
request before it enters the pending pool.

## Common Issues

### Port already in use

Change `CREG_LISTEN` or free the port.

### Chain spec signature invalid

Re-verify the spec and detached signature before restarting the node.

### Peer count stays at 0

- Check `CREG_P2P_SEEDS` against the bootstrap multiaddr.
- Confirm the bootstrap host is reachable.
- On Tailscale setups, confirm `tailscale status` is healthy.

## Next Steps

1. Start with Path A or B.
2. Run Path C once you want local consensus coverage.
3. Move to Path D only after the bootstrap-host flow is stable.
