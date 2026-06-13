# Chain Registry Soak Test Procedure

> **Target:** 72-hour multi-validator soak test  
> **Minimum validators:** 5 (3 core team + 2 community)  
> **Regions:** EU Central, US East, US West (minimum 2 regions)  
> **L1:** Sepolia testnet  

For the current P0 launch execution path, use
[`../docs/PUBLIC_TESTNET_DEPLOYMENT_AND_SOAK_RUNBOOK.md`](../docs/PUBLIC_TESTNET_DEPLOYMENT_AND_SOAK_RUNBOOK.md)
with the live tracker in
[`../docs/PUBLIC_TESTNET_INFRASTRUCTURE_CHECKLIST.md`](../docs/PUBLIC_TESTNET_INFRASTRUCTURE_CHECKLIST.md).
This file remains the detailed scenario catalog and failure-response reference.

---

## Prerequisites

Before starting the soak test, ensure:

- [ ] All 10 contracts deployed to Sepolia ✅
- [ ] Chain spec published to HTTPS URL with valid signature ✅
- [ ] At least 2 bootstrap nodes running ✅
- [ ] All validator operators have:
  - [ ] Generated Ed25519 validator key
  - [ ] Obtained tCREG from faucet (100+ tCREG)
  - [ ] Applied as validator on Staking contract
  - [ ] Been approved by consensus or governance
- [ ] Each validator node has:
  - [ ] Static IP or DNS name
  - [ ] Port 9000/tcp open (P2P)
  - [ ] Port 8080/tcp open (REST API)
  - [ ] Port 50051/tcp open (gRPC)
  - [ ] 4 vCPU, 8 GB RAM, 50 GB SSD
  - [ ] Docker + Docker Compose installed

---

## Test Topology

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Sepolia L1                                      │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐              │
│  │Staking  │ │Registry │ │Governance│ │VRF      │ │ZKVerifier│              │
│  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘              │
│       └─────────────┴─────────────┴─────────────┴───────────────────────────┘
│                                      │                                      │
│                            L1 Bridge RPC                                     │
└──────────────────────────────────────┼──────────────────────────────────────┘
                                       │
    ┌──────────────────────────────────┼──────────────────────────────────┐
    │                                  │                                  │
    ▼                                  ▼                                  ▼
┌──────────┐                    ┌──────────┐                    ┌──────────┐
│Validator 1│◄──────P2P────────►│Validator 2│◄──────P2P────────►│Validator 3│
│ EU-Central│                    │ US-East  │                    │ US-West  │
│ Core Team │                    │ Community│                    │ Core Team│
└─────┬─────┘                    └─────┬─────┘                    └─────┬─────┘
      │                                │                                │
      ▼                                ▼                                ▼
┌──────────┐                    ┌──────────┐                    ┌──────────┐
│Bootstrap 1│                   │Bootstrap 2│                   │Bootstrap 3│
│ EU-Central│                   │ US-East  │                   │ (backup) │
└──────────┘                    └──────────┘                    └──────────┘
```

---

## Phase 1: Pre-Soak (Day 0, ~2 hours)

### Step 1: Deploy Bootstrap Nodes

On each bootstrap host:

```bash
git clone https://github.com/your-org/chain-registry.git
cd chain-registry/testnet/bootstrap
cp bootstrap.env.example bootstrap.env
# Edit bootstrap.env
vim bootstrap.env
docker compose up -d
```

Verify each bootstrap:

```bash
curl -s http://bootnode-1.creg-testnet.example:8080/v1/health | jq .
curl -s http://bootnode-1.creg-testnet.example:8080/metrics | grep "peer_count"
```

### Step 2: Distribute tCREG to Validators

From the deployer wallet:

```bash
# Transfer 500 tCREG to each validator
cast send 0xEf657D9Af6779CCb5A8Cfad8D98b97bbB52AD3a1 \
  "transfer(address,uint256)" 0x<VALIDATOR1_ADDRESS> 500000000000000000000 \
  --rpc-url $SEPOLIA_RPC_URL \
  --private-key $DEPLOYER_KEY
```

### Step 3: Validator Onboarding

Each operator runs:

```bash
# 1. Generate keys
./scripts/generate-validator-keys.sh --out ./validator.env --node-id <handle>

# 2. Stake on Sepolia
cast send 0xe58324Ce72718F802f3d6182e8eA06Cf91cc5d22 \
  "applyAsValidator(uint256)" 100000000000000000000 \
  --rpc-url $SEPOLIA_RPC_URL \
  --private-key $VALIDATOR_KEY

# 3. Start node
docker compose --env-file validator.env -f docker-compose.validator.yml up -d
```

Wait for all validators to show `active` status:

```bash
curl -s http://<any-validator>:8080/v1/chain/stats | jq '.validator_count'
# Should return 5
```

### Step 4: Baseline Metrics

Record starting values:

```bash
for host in validator-{1..5}; do
  echo "=== $host ==="
  curl -s "http://$host:8080/v1/chain/stats" | jq '{height: .block_height, peers: .peer_count, validators: .validator_count}'
done
```

Save to `soak-test/baseline.json`.

---

## Phase 2: Steady-State Soak (Days 1–3)

### Continuous Load: Package Publishing

Run a background publisher on one validator using a staked publisher address.
The harness must generate unique package artifacts or manifests over time so it
does not repeatedly submit the same package id.

```bash
# Publish 1 package every 30 seconds = 2,880 packages/day
while true; do
  creg --node-url http://validator-1:8080 publish ./test-package.tar.gz \
    --key-file ./publisher.key \
    --publisher-address 0xYourPublisherAddress
  sleep 30
done
```

Target: **≥2,000 packages/day** across all validators.

### Scheduled Scenarios

| Time | Scenario | Expected Behavior |
|------|----------|-------------------|
| Hour 4 | Kill 1 validator (30 min) | Chain continues, 4 validators maintain quorum |
| Hour 8 | Restart all validators | All sync to tip within 5 min |
| Hour 12 | Publish burst (100 packages in 60s) | ≥95% verified within 30s |
| Hour 16 | Network partition (2 validators isolated) | Minor fork, rejoin and resolve |
| Hour 20 | L1 RPC outage (15 min) | Bridge retries, no panic, resumes when RPC returns |
| Hour 24 | Validator set sync test | New validator applies + gets approved by consensus |
| Hour 36 | Double the block time | Config change, observe consensus adapts |
| Hour 48 | Memory pressure test | Run for 2h with 50% RAM reduction, no OOM |
| Hour 60 | Disk fill test | 80% disk, observe graceful degradation |
| Hour 72 | Final burst + shutdown | Graceful shutdown of all nodes |

---

## Phase 3: Validation (Day 3, ~2 hours)

### Metrics to Collect

```bash
# Run on each validator
for host in validator-{1..5}; do
  curl -s "http://$host:8080/v1/chain/stats" > "soak-test/final-$host.json"
  curl -s "http://$host:8080/metrics" > "soak-test/metrics-$host.prom"
done
```

### Success Criteria

| Metric | Target | Measurement |
|--------|--------|-------------|
| Chain height | ≥17,280 blocks (72h × 5s block time) | `block_height` |
| Block time P50 | ≤6s | Prometheus `block_time_seconds_bucket` |
| Block time P99 | ≤15s | Prometheus |
| Peer count (min) | ≥4 per validator | `peer_count` |
| Package verification rate | ≥98% | `verified_count / published_count` |
| Validator uptime | ≥99% | `up` metric |
| Bridge settlement success | ≥95% | L1 receipt success rate |
| Memory growth | ≤2× baseline | `process_resident_memory_bytes` |
| Disk growth | ≤10 GB | Chain DB size |
| No restarts due to panic | 0 | `process_start_time_seconds` stable |

### Failure Criteria (Any = Soak Test Failed)

- Chain stall >10 minutes
- Fork that does not resolve within 30 minutes
- Validator crash (panic, OOM)
- Data loss (block missing from DB)
- Bridge settlement failure rate >10%

---

## Phase 4: Report

Generate `SOAK_TEST_REPORT.md` with:

1. **Environment:** Hardware, OS, network topology
2. **Timeline:** What happened when
3. **Metrics:** Grafana screenshots, Prometheus data
4. **Anomalies:** Any deviations from expected behavior
5. **Recommendations:** Changes needed before public beta

---

## Automation

A Python script automates the soak test:

```bash
pip install -r soak-test/requirements.txt
python soak-test/runner.py \
  --validators validator-1,validator-2,validator-3,validator-4,validator-5 \
  --duration 72h \
  --publish-rate 30s \
  --scenarios soak-test/scenarios.json \
  --output soak-test/results/
```

See `soak-test/` directory for implementation.

---

## Emergency Procedures

### Chain Stall

1. Check validator health: `curl /v1/health`
2. Check peer connectivity: `curl /v1/chain/stats` and inspect `peer_count`
3. Check L1 RPC: `cast block-number --rpc-url $RPC`
4. Restart minority validators one at a time
5. If still stalled, restart majority with `--resync-from=0`

### Validator Crash

1. Collect logs: `docker logs creg-node > crash.log`
2. Check for panic: `grep -i panic crash.log`
3. Check memory: `dmesg | grep -i oom`
4. Restart with `--debug`
5. Open GitHub issue with crash.log attached

### Fork

1. Identify canonical chain by validator weight
2. Ask minority validators to stop
3. Wipe their data dirs
4. Restart with `--resync`
5. Investigate root cause in consensus logs
