# Chain Registry Bootstrap Nodes

Bootstrap nodes are the entry points for the P2P network. They run a minimal chain-registry node (no validation, no block production) and provide peer discovery via libp2p Kademlia DHT and Gossipsub.

## Requirements

- **Static IP or DNS name** — validators must be able to dial you reliably
- **Port 9000/tcp open** — P2P libp2p traffic
- **Port 8080/tcp open** — REST API (health checks, metrics)
- **~2 vCPU, 4 GB RAM, 20 GB SSD** — minimal; mostly network I/O
- **Docker + Docker Compose** — or systemd for bare-metal

## Quick Start

```bash
cd testnet/bootstrap

# 1. Copy env template
cp bootstrap.env.example bootstrap.env
# Edit bootstrap.env — set CREG_P2P_ANNOUNCE, CREG_ETH_RPC_URL, etc.

# 2. Generate persistent P2P key
mkdir -p data p2p-key
# The node will generate a key on first boot; check logs for Peer ID:
docker compose up bootstrap
# Look for: "local_peer_id=12D3KooW..."

# 3. Note the Peer ID and add it to the chain spec
# Then restart:
docker compose up -d
```

## Deployment Options

### Option A: VPS with Static IP (Recommended)

Providers: Hetzner, OVH, DigitalOcean, AWS EC2

1. Provision VM with Ubuntu 24.04
2. Open firewall: `ufw allow 9000/tcp && ufw allow 8080/tcp`
3. Install Docker: `curl -fsSL https://get.docker.com | sh`
4. Clone repo, configure `bootstrap.env`
5. `docker compose up -d`

### Option B: Behind NAT with Cloudflare Tunnel

If you cannot get a static IP or open ports:

```bash
# In bootstrap.env, set:
# TUNNEL_TOKEN=your-token-from-cloudflare-zero-trust

# Deploy with tunnel profile
docker compose --profile tunnel up -d
```

**Caveat:** Cloudflare Tunnel adds latency. Use direct IP when possible.

### Option C: Kubernetes

See `k8s/bootstrap-node.yaml` (TODO: create Helm chart).

## Chain Spec Updates

When a new bootstrap node joins, update the chain spec:

```json
{
  "bootnodes": [
    {
      "id": "bootstrap-1",
      "operator": "core-team",
      "region": "eu-central",
      "multiaddr": "/dns4/bootnode-1.creg-testnet.example/tcp/9000/p2p/12D3KooW..."
    },
    {
      "id": "bootstrap-2",
      "operator": "community",
      "region": "us-east",
      "multiaddr": "/dns4/bootnode-2.creg-testnet.example/tcp/9000/p2p/12D3KooW..."
    }
  ]
}
```

Then re-sign and publish:

```bash
cd testnet
./finalize-sepolia-spec.ps1
```

## Monitoring

Each bootstrap node exposes:

| Endpoint | Purpose |
|----------|---------|
| `GET /v1/health` | Health check (200 = OK) |
| `GET /metrics` | Prometheus metrics |
| `GET /v1/chain/stats` | Quick view of height, peer count, and validator count |
| `GET /v1/nodes` | Known node inventory |
| `GET /v1/p2p/status` | P2P transport and swarm status |

Recommended alerts:
- `peer_count < 3` from `/v1/chain/stats` for >5 min → node may be isolated
- `up == 0` for >1 min → node is down

## Security

- Bootstrap nodes do **not** hold validator keys
- Do not run `--validator=true` on a bootstrap node
- Keep `bootstrap.env` private (contains RPC URLs)
- Use a read-only L1 RPC if possible (no signing needed)

## Geographic Distribution

For resilience, deploy at least 2 bootstrap nodes in different regions:

| Region | Provider | Cost (mo) |
|--------|----------|-----------|
| EU Central | Hetzner CX21 | ~€6 |
| US East | DigitalOcean Droplet | ~$6 |
| APAC | AWS Lightsail | ~$5 |

Total: ~$15–20/month for 3 bootstrap nodes.
