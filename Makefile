# Makefile — chain-registry dev commands

.PHONY: build test lint clean node cluster contracts deploy-local fmt check \
        testnet testnet-smoke testnet-no-explorer testnet-stop testnet-reset testnet-logs \
        up up-dev up-testnet down down-testnet logs-testnet release-assurance ddc-verify

POWERSHELL ?= pwsh
# Run testnet compose in a clean env so shell-level overrides don't win over .env.testnet.
# docker-compose (standalone) is used instead of "docker compose" (plugin) because the
# plugin requires additional Windows-specific env vars that env -i would strip.
DOCKER_COMPOSE_CMD := $(shell command -v docker-compose 2>/dev/null || echo docker-compose)
TESTNET_COMPOSE = env -i PATH="$(PATH)" HOME="$(HOME)" USERPROFILE="$(USERPROFILE)" APPDATA="$(APPDATA)" LOCALAPPDATA="$(LOCALAPPDATA)" PROGRAMFILES="$(PROGRAMFILES)" $(DOCKER_COMPOSE_CMD) --project-directory . --env-file .env.testnet -f docker-compose.testnet.yml

# ── Rust ──────────────────────────────────────────────────────────────────────

build:
	cargo build --release

test:
	cargo test --workspace -- --nocapture

lint:
	cargo clippy --workspace --all-targets -- -D warnings

fmt:
	cargo fmt --all

check:
	cargo check --workspace

## Rebuild release binaries twice and emit release-assurance evidence.
release-assurance:
	bash ./scripts/release-assurance.sh

## Run DDC for an explicitly configured compiler/codegen target.
ddc-verify:
	bash ./scripts/ddc-verify.sh

clean:
	cargo clean

# ── Node ──────────────────────────────────────────────────────────────────────

## Run a single dev node (no validators, data in ./dev-data)
node:
	CREG_LISTEN=0.0.0.0:8080 \
	CREG_DATA_DIR=./dev-data \
	CREG_NODE_ID=dev-node \
	CREG_IS_VALIDATOR=true \
	CREG_BLOCK_INTERVAL=3 \
	RUST_LOG=info,chain_registry_node=debug \
	cargo run --release --bin creg-node

## Spin up the full 3-node + IPFS + Anvil cluster
cluster:
	docker compose up --build

cluster-down:
	docker compose down -v

# ── Docker testnet (single command) ───────────────────────────────────────────

## Build + start the full testnet (blockchain + faucet + web explorer)
## Usage: make up
up: up-testnet

## Start dev cluster (main docker-compose.yml, no env-file needed)
up-dev:
	docker compose up -d --build

## Start full testnet with blockchain, faucet, relayer, web explorer
## Equivalent to the manual: docker compose --env-file .env.testnet -f docker-compose.testnet.yml up -d --build
up-testnet:
	$(TESTNET_COMPOSE) up -d --build
	@echo ""
	@echo "Testnet is starting. Services will be ready in ~60s."
	@echo "  Node API:     http://localhost:8080/v1/health"
	@echo "  Faucet:       http://localhost:8082/health"
	@echo "  Relayer:      http://localhost:8083/health"
	@echo "  Web Explorer: http://localhost:3007"
	@echo "  Anvil RPC:    http://localhost:8545"
	@echo "  PostgreSQL:   localhost:5437"
	@echo ""
	@echo "Tail logs with: make logs-testnet"

## Stop testnet without removing volumes (data preserved)
down-testnet:
	$(TESTNET_COMPOSE) down --remove-orphans

## Stop testnet AND delete all volumes (clean reset)
reset-testnet:
	$(TESTNET_COMPOSE) down -v --remove-orphans

## Tail all testnet service logs
logs-testnet:
	$(TESTNET_COMPOSE) logs -f

## Stop dev cluster
down:
	docker compose down -v

## Start the bootstrap testnet (GNU make convenience wrapper around ./testnet.ps1)
testnet:
	$(POWERSHELL) -NoProfile -ExecutionPolicy Bypass -File testnet.ps1

## Start the bootstrap testnet and run the smoke checks at the end
testnet-smoke:
	$(POWERSHELL) -NoProfile -ExecutionPolicy Bypass -File testnet.ps1 -RunSmokeTests

## Start the bootstrap testnet without the standalone web explorer
testnet-no-explorer:
	$(POWERSHELL) -NoProfile -ExecutionPolicy Bypass -File testnet.ps1 -SkipExplorer

## Stop the bootstrap testnet services without deleting volumes
testnet-stop:
	$(TESTNET_COMPOSE) down --remove-orphans

## Stop the bootstrap testnet and delete volumes for a clean reset
testnet-reset:
	$(TESTNET_COMPOSE) down -v --remove-orphans

## Tail bootstrap testnet logs
testnet-logs:
	$(TESTNET_COMPOSE) logs -f

# ── CLI shims ─────────────────────────────────────────────────────────────────

## Install PATH shims so npm/pip/cargo are intercepted
install-shims: build
	./target/release/creg setup-shims
	@echo ""
	@echo "Add this to your shell profile:"
	@echo '  export PATH="$$HOME/.local/bin:$$PATH"'

remove-shims:
	./target/release/creg remove-shims

# ── Smart contracts ───────────────────────────────────────────────────────────

## Install Foundry (one-time)
install-foundry:
	curl -L https://foundry.paradigm.xyz | bash
	foundryup

## Compile contracts
contracts:
	forge build

## Run Solidity tests
test-contracts:
	forge test -vvv

## Run tests with gas report
gas:
	forge test --gas-report

## Deploy to local Anvil
deploy-local:
	@echo "Starting Anvil..."
	anvil &
	sleep 2
	DEPLOYER_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
	GENESIS_SIGNERS="" \
	GOVERNANCE_THRESHOLD=1 \
	forge script contracts/script/Deploy.s.sol \
		--rpc-url http://127.0.0.1:8545 \
		--broadcast \
		-vvvv

## Deploy to Sepolia testnet
deploy-sepolia:
	forge script contracts/script/Deploy.s.sol \
		--rpc-url $$SEPOLIA_RPC_URL \
		--broadcast \
		--verify \
		-vvvv

# ── Utilities ─────────────────────────────────────────────────────────────────

## Generate a new Ed25519 publisher keypair
keygen:
	cargo run --bin creg -- keygen

## Check the trust status of a package
status:
	cargo run --bin creg -- status $(PKG) --ecosystem $(ECO)

## Watch logs from all docker compose services
logs:
	docker compose logs -f

## Print chain stats from the local dev node
stats:
	curl -s http://localhost:8080/v1/chain/stats | jq .

## List pending pool
pending:
	curl -s http://localhost:8080/v1/pending | jq .
