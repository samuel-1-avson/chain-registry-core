# Chain Registry Docker Guide

Complete Docker setup for running the Chain Registry blockchain with all new features including the enhanced Web Explorer and TUI Explorer.

## 🆕 What's New in v0.3.0

- **Enhanced Web Explorer**: Search, copy-to-clipboard, animations, reputation bars
- **TUI Explorer**: Terminal-based blockchain explorer with real-time updates
- **Improved CLI**: Dashboard, wizard, and explorer commands
- **Better Docker Integration**: New services for TUI and standalone web explorer

## 📁 Docker Compose Files

| File | Purpose | Use Case |
|------|---------|----------|
| `docker-compose.local-testnet.yml` | Canonical local distributed stack | Three-validator local bootstrap and smoke validation |
| `docker-compose.yml` | Single-validator dev setup | Local development |
| `docker-compose.testnet.yml` | Shared testnet services + bootstrap validator | Bootstrap host for testnet |
| `docker-compose.validator.yml` | One validator on one machine | Additional validator hosts |
| `docker-compose.light.yml` | Resource-constrained setup | Consumer hardware |
| `docker-compose.prebuilt.yml` | Prebuilt images | Fast smoke testing |

## 📌 Current Status

The repo's live operational status is tracked in [TESTNET_READINESS_REPORT.md](TESTNET_READINESS_REPORT.md) and [../docs/NEXT_WORK.md](../docs/NEXT_WORK.md).

Current Docker model:

- `local-testnet.ps1` + `docker-compose.local-testnet.yml` is the canonical local distributed bootstrap path
- `docker-compose.yml` runs one local validator node
- `docker-compose.testnet.yml` runs the bootstrap host with `node-1`
- `docker-compose.validator.yml` runs exactly one validator on each additional computer

Migration note: if you previously ran the older multi-node testnet compose locally,
start the updated testnet with `--remove-orphans` once so Docker removes the retired
`node-2` through `node-10` containers.

Known operational note: `deploy-contracts` can still exit non-zero after writing a
fresh deployment manifest because of Foundry import/remapping issues. If
`contracts/deployments/latest.json` exists, start `node-1`, `faucet`, and
`web-explorer` with `--no-deps` while the remapping issue is being fixed.

## 🚀 Quick Start

### 1. Canonical Local Distributed Stack

```powershell
./local-testnet.ps1 -RunSmokeTests
```

After changing explorer code, add `-RebuildImages` so Docker rebuilds the local
explorer image before running checks:

```powershell
./local-testnet.ps1 -SkipCleanup -RebuildImages -RunSmokeTests
```

After changing Rust code that must be tested inside Docker, also pass
`-RebuildAppImage`. This path compiles native RocksDB bindings and can fail if
the Docker builder's libclang toolchain is not healthy:

```powershell
./local-testnet.ps1 -SkipCleanup -RebuildImages -RebuildAppImage -RunSmokeTests
```

This is the repo-validated path for proving distributed local behavior. It normalizes `.env.local-testnet`, deploys contracts, starts the three-validator stack from `docker-compose.local-testnet.yml`, and can run the smoke flow after startup.

Use `-SkipExplorer` when you only want the core free local rehearsal path
(Anvil, IPFS, Postgres, three validators, observer, indexer, faucet, and
relayer). The smoke flow runs `creg doctor`, probes faucet drip, stakes a local
publisher, publishes a generated smoke package, waits for inclusion, and prints
final chain stats.

For full local readiness, omit `-SkipExplorer` so the standalone web explorer is
started and checked as part of doctor:

```powershell
./local-testnet.ps1 -RunSmokeTests
```

For a local mini-soak after the stack is running:

```powershell
./local-soak.ps1 -SkipExplorer -DurationMinutes 60 -IntervalSeconds 60
```

The soak runner repeats the smoke flow on a cadence, saves chain stats snapshots,
waits for published packages to move out of the pending pool, and writes the
final compose log tail under `tmp/local-soak/<run-id>/`. Use `-SkipPublish`
when you only want repeated health and doctor checks, `-SkipDrip` when you are
debugging without exercising faucet token transfer, or `-SkipInclusionWait`
when you are debugging publish admission separately from consensus progress.

### 2. Single Validator (Development)

```bash
# Start all services
docker compose up -d --build

# View logs
docker compose logs -f node

# Access the Enhanced Web Explorer
open http://localhost:8080/ui/

# Check health
curl http://localhost:8080/v1/health
```

### 3. Launch TUI Explorer (Terminal UI)

```bash
# NEW: Interactive terminal blockchain explorer
docker compose run --rm tui-explorer

# Or for testnet
docker compose -f docker-compose.testnet.yml run --rm tui-explorer
```

The TUI Explorer features:
- Real-time block monitoring
- Validator status with reputation bars
- Network peer visualization
- Live event stream
- Keyboard navigation (vim-style)

### 4. Run CLI Commands

```bash
# Check node status
docker compose run --rm cli status

# View dashboard
docker compose run --rm cli dashboard

# Use the interactive wizard
docker compose run --rm cli init

# Check system health
docker compose run --rm cli doctor

# Check the local bootstrap testnet end to end
docker compose run --rm cli doctor --testnet --skip-drip

# Request testnet tokens from the faucet (CLI handles the PoW challenge automatically)
docker compose run --rm cli testnet drip 0xYourAddress

# Publish a package (publisher address must already have on-chain stake)
docker compose run --rm cli publish ./package.tgz --key-file /keys/publisher.key --publisher-address 0xYourPublisherAddress
```

The publish request is signed over the package id, content hash, and canonical
`publisher_address`, and the node rejects unstaked publishers before pending-pool
admission.

### 4. Start Distributed Testnet

```bash
# Bootstrap host: one command for env generation, deployment, artifact sync, faucet funding, and runtime startup
pwsh -NoProfile -ExecutionPolicy Bypass -File testnet.ps1

# Optional GNU make wrapper if make is installed
make testnet

# Additional validator hosts: point at shared Anvil/IPFS/Postgres
docker compose --env-file validator.env -f docker-compose.validator.yml up -d --build

# View bootstrap logs
docker compose --env-file .env.testnet -f docker-compose.testnet.yml logs -f

# View validator-host logs
docker compose -f docker-compose.validator.yml logs -f validator
```

Bootstrap host helpers:

- `pwsh -NoProfile -ExecutionPolicy Bypass -File testnet.ps1 -RunSmokeTests` — start and run the smoke tests automatically
- `pwsh -NoProfile -ExecutionPolicy Bypass -File testnet.ps1 -SkipExplorer` — skip the standalone explorer container
- `creg doctor --testnet --skip-drip` — verify the bootstrap testnet endpoints, contract wiring, faucet config, explorer, and Anvil RPC without mutating balances
- `creg doctor --testnet` — same as above, but also execute a live faucet drip probe against a throwaway address
- `make testnet-*` aliases are also available if GNU make is installed

Set these env vars on every validator host:
- `CREG_VALIDATOR_KEY`
- `CREG_ETH_RPC`
- `CREG_IPFS_URL`
- `CREG_PG_URL` if Postgres mirroring is enabled
- `CREG_P2P_SEEDS` to join the existing validator mesh

## 🎯 Available Services

### Core Services

| Service | Description | Port | Access |
|---------|-------------|------|--------|
| `node` | Validator node + API | 8080 | http://localhost:8080 |
| `ipfs` | IPFS daemon | 5001 | http://localhost:5001 |
| `anvil` | Local Ethereum | 8545 | http://localhost:8545 |

### Explorer Services (NEW)

| Service | Description | Command |
|---------|-------------|---------|
| `tui-explorer` | Terminal blockchain explorer | `docker compose run --rm --no-deps tui-explorer` |
| `web-explorer` | Standalone nginx explorer | `docker compose up -d web-explorer` |
| `cli` | Management CLI | `docker compose run --rm cli <command>` |

## 🌐 Accessing the Explorers

### Web Explorer (Enhanced)

The node automatically serves the enhanced web explorer:

```
http://localhost:8080/ui/
```

Features:
- 🔍 **Search**: Filter blocks by height, hash, or proposer (press `/`)
- 📋 **Copy**: Click any hash to copy to clipboard
- 📊 **Stats**: Real-time network statistics
- ⚡ **Validators**: Stake and reputation visualization
- 📡 **Events**: Live event stream

### TUI Explorer (Terminal)

Launch the terminal-based explorer:

```bash
docker compose run --rm --no-deps tui-explorer
```

Keyboard shortcuts:
- `1-7` - Switch views (Overview, Blocks, Validators, etc.)
- `j/k` or `↑/↓` - Navigate
- `Enter` or `d` - View details
- `q` - Quit
- `/` - Search
- `?` - Help

### Standalone Web Explorer (Optional)

For better performance, run the explorer via nginx:

```bash
# Start standalone explorer on port 3007
docker compose up -d web-explorer

# Access it
open http://localhost:3007
```

> **Note:** The current production stack defaults to port **3007** for the standalone explorer to avoid collisions with other local services.

## 🔧 Environment Variables

### Node Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `CREG_NODE_ID` | Node identifier | `node-1` |
| `CREG_IS_VALIDATOR` | Enable validator mode | `true` |
| `CREG_VALIDATOR_KEY` | Validator private key | - |
| `CREG_BLOCK_INTERVAL` | Block time in seconds | `2` |
| `CREG_ETH_RPC` | Ethereum RPC URL | `http://anvil:8545` |
| `CREG_DOCKER_ETH_RPC` | Docker-internal Ethereum RPC URL for the testnet compose | `http://anvil:8545` |
| `CREG_DOCKER_IPFS_URL` | Docker-internal IPFS API URL for the testnet compose | `http://ipfs:5001` |
| `CREG_CORS_ALLOWED_ORIGINS` | Comma-separated browser origins allowed to call the REST API | empty (deny cross-origin) |
| `CREG_CORS_ALLOWED_METHODS` | Comma-separated methods returned in CORS preflight responses | `GET,POST,DELETE,OPTIONS` |
| `CREG_CORS_ALLOW_CREDENTIALS` | Emit `Access-Control-Allow-Credentials` for explicit origins | `false` |

For `.env.testnet`, keep `CREG_ETH_RPC` and `CREG_IPFS_URL` as host-facing
`localhost` values for commands you run on Windows. Use `CREG_DOCKER_ETH_RPC`
and `CREG_DOCKER_IPFS_URL` for containers inside
`docker-compose.testnet.yml`.

### Feature Flags

| Variable | Description | Default |
|----------|-------------|---------|
| `CREG_ZK_ENABLED` | Enable ZK validation | `true` |
| `CREG_ML_ENABLED` | Enable ML threat detection | `true` |
| `CREG_WASM_ENABLED` | Enable WASM sandbox | `true` |
| `CREG_DEV_SANDBOX` | Dev sandbox mode (no nsjail) | `true` |

### Explorer Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `CREG_NODE_URL` | Node API endpoint | `http://node:8080` |

If you use the embedded explorer at `http://localhost:8080/ui/`, no CORS configuration is needed because the browser stays on the node origin. If you use the standalone explorer on `http://localhost:3000` or a Vite dev server such as `http://localhost:5173`, set `CREG_CORS_ALLOWED_ORIGINS` on the node to an explicit comma-separated allowlist such as `http://localhost:3000,http://localhost:5173`. Keep `CREG_CORS_ALLOW_CREDENTIALS=false` unless the browser flow actually needs credentials; wildcard `*` origins are rejected when credentials are enabled.

## 📊 Monitoring

### Health Checks

```bash
# Node health
curl http://localhost:8080/v1/health

# Full stats
curl http://localhost:8080/v1/chain/stats

# Validator set
curl http://localhost:8080/v1/nodes

# P2P status
curl http://localhost:8080/v1/p2p/status
```

### Logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f node

# Last 100 lines
docker compose logs --tail=100 node
```

## 💾 Data Volumes

| Volume | Purpose | Location |
|--------|---------|----------|
| `node-data` | Blockchain data | `/data` |
| `ipfs-data` | IPFS storage | `/data/ipfs` |
| `anvil-data` | Ethereum state | `/data` |

To reset data:

```bash
docker compose down -v
```

## 🔒 Security

The Docker setup includes:

- **Non-root user**: Node runs as `creg` user
- **Read-only mounts**: Circuits and validators are read-only
- **Health checks**: Automatic restart on failure
- **Resource limits**: Memory and CPU constraints

## 🐛 Troubleshooting

### Node won't start

```bash
# Check logs
docker compose logs node

# Verify contracts deployed
docker compose logs deploy-contracts

# Reset and retry
docker compose down -v
docker compose up -d --build
```

### Explorer not loading

```bash
# Verify node is healthy
curl http://localhost:8080/v1/health

# Check node logs
docker compose logs node | grep -i "explorer\|embed"

# Rebuild with fresh explorer
docker compose down
docker compose up -d --build
```

### TUI display issues

```bash
# Ensure TTY is allocated
docker compose run --rm -it tui-explorer

# Check terminal size (minimum 80x24)
stty size
```

## 📚 Examples

### Publish a Package

```bash
# Create test package
tar czf test-package.tgz -C ./my-package .

# Publish via CLI
docker compose run --rm cli publish ./test-package.tgz \
  --key-file /keys/publisher.key \
  --publisher-address 0xYourPublisherAddress \
  --manifest ./my-package/manifest.toml
```

### Stake as Validator

```bash
# Check current stake
docker compose run --rm cli stake 100 --role validator
```

### Run Stress Test

```bash
# First build caches aiohttp/PyNaCl in the stress-test image
docker compose --env-file .env.testnet -f docker-compose.testnet.yml \
  --profile stress-test build stress-test

# Testnet only
docker compose --env-file .env.testnet -f docker-compose.testnet.yml \
  --profile stress-test run --rm --no-deps stress-test --packages 1000
```

## 📝 Build Arguments

To customize the build:

```bash
# Build with specific Rust version
docker compose build --build-arg RUST_VERSION=1.90.0

# No-cache build
docker compose build --no-cache
```

## 🔄 Updates

To update to the latest version:

```bash
# Pull latest code
git pull origin main

# Rebuild runtime images
docker compose --env-file .env.testnet -f docker-compose.testnet.yml --profile build build app-image web-explorer-image

# Restart bootstrap services
docker compose --env-file .env.testnet -f docker-compose.testnet.yml up -d

# Restart a validator host
docker compose --env-file validator.env -f docker-compose.validator.yml up -d --build

# Rebuild and restart
docker compose down
docker compose up -d --build

# Verify new features
docker compose run --rm cli --version
docker compose run --rm tui-explorer
```
