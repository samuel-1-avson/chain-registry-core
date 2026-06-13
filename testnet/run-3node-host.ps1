# Chain Registry 3-Node Local Test (Host-based fallback)
# Runs 3 nodes directly on the host for rapid iteration.
# Use this if Docker build is too slow or unavailable.
#
# Prerequisites:
#   - cargo installed
#   - Anvil running on localhost:8545 (or start it below)
#
# Usage:
#   .\testnet\run-3node-host.ps1

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
Set-Location $repoRoot

function Write-Step($msg) {
    Write-Host ""
    Write-Host "=== $msg ===" -ForegroundColor Cyan
}

function Write-Success($msg) {
    Write-Host "✓ $msg" -ForegroundColor Green
}

# Step 1: Build node binary if needed
$nodeBinary = Join-Path $repoRoot "target" "release" "creg-node.exe"
if (-not (Test-Path $nodeBinary)) {
    Write-Step "Building node binary"
    cargo build --release --package chain-registry-node
    if ($LASTEXITCODE -ne 0) { throw "Build failed" }
    Write-Success "Build complete"
}

# Step 2: Start Anvil if not running
try {
    $bn = cast block-number --rpc-url http://localhost:8545 2>$null
    Write-Success "Anvil already running at block $bn"
} catch {
    Write-Step "Starting Anvil"
    Start-Process -FilePath "anvil" -ArgumentList @("--block-time", "2", "--accounts", "20", "--balance", "10000", "--chain-id", "31337", "--host", "0.0.0.0") -WindowStyle Hidden
    Start-Sleep -Seconds 5
    $bn = cast block-number --rpc-url http://localhost:8545 2>$null
    Write-Success "Anvil started at block $bn"
}

# Step 3: Deploy contracts
Write-Step "Deploying contracts to Anvil"
$env:DEPLOYER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
$env:CREG_BRIDGE_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"

Set-Location $repoRoot
forge script contracts/script/DeploySepolia.s.sol:DeploySepolia `
    --rpc-url http://localhost:8545 `
    --private-key $env:DEPLOYER_KEY `
    --broadcast `
    --chain-id 31337 `
    -vvv

if ($LASTEXITCODE -ne 0) {
    Write-Warn "Deployment script failed, using existing latest.json"
}

# Step 4: Patch chain-spec
Write-Step "Patching chain-spec"
$specPath = Join-Path $scriptDir "chain-spec.local.json"
$spec = Get-Content $specPath | ConvertFrom-Json

$manifestPath = Join-Path $repoRoot "contracts" "deployments" "sepolia-latest.json"
if (Test-Path $manifestPath) {
    $m = Get-Content $manifestPath | ConvertFrom-Json
    $spec.contracts.governance    = $m.governance
    $spec.contracts.registry      = $m.registry
    $spec.contracts.staking       = $m.staking
    $spec.contracts.reputation    = $m.reputation
    $spec.contracts.creg_token    = $m.cregToken
    $spec.contracts.zk_verifier   = $m.zkVerifier
    $spec.contracts.appeal        = $m.appeal
    $spec.contracts.validator_rewards = $m.validatorRewards
    $spec.contracts.vrf           = $m.vrf
}

$specJson = $spec | ConvertTo-Json -Depth 20 -Compress
Set-Content -Path $specPath -Value $specJson
Write-Success "chain-spec.local.json updated"

# Step 5: Sign chain spec
Write-Step "Signing chain spec"
$sig = cargo run --example sign_chain_spec --package common -- $specPath 9d91e9e0d82a02b7be8c40a522d899eea9eeffad244323be3e568973211f3a6d 2>$null | Select-Object -Last 1
$sigPath = Join-Path $scriptDir "chain-spec.local.json.sig"
Set-Content -Path $sigPath -Value $sig
Write-Success "Signature generated"

# Step 6: Start 3 nodes
Write-Step "Starting 3 nodes"

$dataDir = Join-Path $repoRoot "data"
New-Item -ItemType Directory -Path "$dataDir\node1", "$dataDir\node2", "$dataDir\node3" -Force | Out-Null

$specUrl = "file:///$($specPath -replace '\\', '/')")

# Node 1
$env1 = @{
    CREG_CHAIN_ID = "creg-testnet-1"
    CREG_EXPECTED_L1_CHAIN_ID = "31337"
    CREG_ETH_RPC = "http://localhost:8545"
    CREG_IS_VALIDATOR = "true"
    CREG_VALIDATOR_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    CREG_NODE_ID = "validator-1"
    CREG_LISTEN = "127.0.0.1:8080"
    CREG_DATA_DIR = "$dataDir\node1"
    CREG_BLOCK_INTERVAL = "5"
    CREG_CHAIN_SPEC_URL = $specUrl
    CREG_CHAIN_SPEC_OFFLINE = "false"
    CREG_SPEC_SIGNING_PUBKEY = "0437e4adac481519cd6ae66907294c40cfcbf0bdeadd47806f6233be4bd5f82d"
    CREG_P2P_LISTEN = "/ip4/127.0.0.1/tcp/9000"
    RUST_LOG = "info,chain_registry_node=debug"
}

# Node 2
$env2 = @{
    CREG_CHAIN_ID = "creg-testnet-1"
    CREG_EXPECTED_L1_CHAIN_ID = "31337"
    CREG_ETH_RPC = "http://localhost:8545"
    CREG_IS_VALIDATOR = "true"
    CREG_VALIDATOR_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
    CREG_NODE_ID = "validator-2"
    CREG_LISTEN = "127.0.0.1:8081"
    CREG_DATA_DIR = "$dataDir\node2"
    CREG_BLOCK_INTERVAL = "5"
    CREG_CHAIN_SPEC_URL = $specUrl
    CREG_CHAIN_SPEC_OFFLINE = "false"
    CREG_SPEC_SIGNING_PUBKEY = "0437e4adac481519cd6ae66907294c40cfcbf0bdeadd47806f6233be4bd5f82d"
    CREG_P2P_LISTEN = "/ip4/127.0.0.1/tcp/9001"
    CREG_P2P_SEEDS = "/ip4/127.0.0.1/tcp/9000/p2p/12D3KooWGenesis"
    RUST_LOG = "info,chain_registry_node=debug"
}

# Node 3
$env3 = @{
    CREG_CHAIN_ID = "creg-testnet-1"
    CREG_EXPECTED_L1_CHAIN_ID = "31337"
    CREG_ETH_RPC = "http://localhost:8545"
    CREG_IS_VALIDATOR = "false"
    CREG_NODE_ID = "observer-1"
    CREG_LISTEN = "127.0.0.1:8082"
    CREG_DATA_DIR = "$dataDir\node3"
    CREG_BLOCK_INTERVAL = "5"
    CREG_CHAIN_SPEC_URL = $specUrl
    CREG_CHAIN_SPEC_OFFLINE = "false"
    CREG_SPEC_SIGNING_PUBKEY = "0437e4adac481519cd6ae66907294c40cfcbf0bdeadd47806f6233be4bd5f82d"
    CREG_P2P_LISTEN = "/ip4/127.0.0.1/tcp/9002"
    CREG_P2P_SEEDS = "/ip4/127.0.0.1/tcp/9000/p2p/12D3KooWGenesis,/ip4/127.0.0.1/tcp/9001/p2p/12D3KooWGenesis"
    RUST_LOG = "info,chain_registry_node=debug"
}

function Start-Node($name, $binary, $envVars) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $binary
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $envVars.GetEnumerator() | ForEach-Object {
        $psi.EnvironmentVariables[$_.Key] = $_.Value
    }
    $proc = [System.Diagnostics.Process]::Start($psi)
    return $proc
}

$proc1 = Start-Node "Node1" $nodeBinary $env1
$proc2 = Start-Node "Node2" $nodeBinary $env2
$proc3 = Start-Node "Node3" $nodeBinary $env3

Write-Success "All 3 nodes started"
Write-Host ""
Write-Host "Node 1 PID: $($proc1.Id)  API: http://localhost:8080"
Write-Host "Node 2 PID: $($proc2.Id)  API: http://localhost:8081"
Write-Host "Node 3 PID: $($proc3.Id)  API: http://localhost:8082"
Write-Host ""
Write-Host "Press Ctrl+C to stop all nodes..." -ForegroundColor Yellow

# Wait for Ctrl+C
try {
    while ($true) {
        Start-Sleep -Seconds 1
        if ($proc1.HasExited) { Write-Warn "Node 1 exited with code $($proc1.ExitCode)"; break }
        if ($proc2.HasExited) { Write-Warn "Node 2 exited with code $($proc2.ExitCode)"; break }
        if ($proc3.HasExited) { Write-Warn "Node 3 exited with code $($proc3.ExitCode)"; break }
    }
} finally {
    Write-Step "Stopping nodes"
    if (-not $proc1.HasExited) { $proc1.Kill() }
    if (-not $proc2.HasExited) { $proc2.Kill() }
    if (-not $proc3.HasExited) { $proc3.Kill() }
    Write-Success "All nodes stopped"
}
