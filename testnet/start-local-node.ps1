# Chain Registry — Start Single Local Node (Windows PowerShell)
# Usage: ./start-local-node.ps1 [-ValidatorKey <hex>]
#
# This starts a single chain-registry node against Sepolia using the signed chain spec.
# No Docker required. Uses cargo run (debug build).

param(
    [string]$ValidatorKey = "",
    [string]$NodeId = "local-test",
    [string]$DataDir = "./node-data",
    [string]$RpcUrl = "https://ethereum-sepolia-rpc.publicnode.com",
    [switch]$Validator
)

$ErrorActionPreference = "Stop"
$repoRoot = Resolve-Path "$PSScriptRoot/.."

Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Chain Registry — Local Node Starter" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan

# Check prerequisites
Write-Host "`n[1/5] Checking prerequisites..." -ForegroundColor Yellow

$hasCargo = Get-Command cargo -ErrorAction SilentlyContinue
if (-not $hasCargo) {
    Write-Error "Rust/Cargo not found. Install from https://rustup.rs/"
    exit 1
}
Write-Host "  ✓ Cargo found: $(cargo --version)"

# Check chain spec exists
$specPath = "$repoRoot/testnet/chain-spec.sepolia.json"
if (-not (Test-Path $specPath)) {
    Write-Error "Chain spec not found: $specPath"
    exit 1
}
Write-Host "  ✓ Chain spec found"

# Check signature exists
$sigPath = "$repoRoot/testnet/chain-spec.sepolia.json.sig"
if (-not (Test-Path $sigPath)) {
    Write-Warning "Signature file not found: $sigPath"
    Write-Warning "Node will skip signature verification"
}

# Create data directory
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
Write-Host "  ✓ Data directory: $(Resolve-Path $DataDir)"

# Set environment variables
Write-Host "`n[2/5] Configuring environment..." -ForegroundColor Yellow

$env:CARGO_MANIFEST_DIR = "$repoRoot"
$env:CREG_CHAIN_SPEC_URL = "file:///$($specPath -replace '\\','/')"
$env:CREG_SPEC_SIGNING_PUBKEY = "0437e4adac481519cd6ae66907294c40cfcbf0bdeadd47806f6233be4bd5f82d"
$env:CREG_ETH_RPC_URL = $RpcUrl
$env:CREG_NODE_ID = $NodeId
$env:CREG_DATA_DIR = (Resolve-Path $DataDir).Path
$env:CREG_LISTEN = "0.0.0.0:8080"
$env:CREG_P2P_LISTEN = "/ip4/0.0.0.0/tcp/9000"
$env:CREG_P2P_SEEDS = ""   # Empty = you are the bootstrap
$env:CREG_IS_VALIDATOR = if ($Validator) { "true" } else { "false" }
$env:RUST_LOG = "info,chain_registry_node=debug"

if ($Validator -and $ValidatorKey) {
    $env:CREG_VALIDATOR_KEY = $ValidatorKey
    Write-Host "  ✓ Validator mode ENABLED"
} elseif ($Validator) {
    Write-Warning "Validator mode requested but no key provided. Generating random key..."
    # Generate a random key using .NET
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[] 32
    $rng.GetBytes($bytes)
    $hex = [BitConverter]::ToString($bytes) -replace '-',''
    $env:CREG_VALIDATOR_KEY = $hex.ToLower()
    Write-Host "  ✓ Generated random validator key: $hex"
} else {
    Write-Host "  ✓ Full node mode (non-validator)"
}

Write-Host "  ✓ Chain spec: $($env:CREG_CHAIN_SPEC_URL)"
Write-Host "  ✓ L1 RPC: $RpcUrl"
Write-Host "  ✓ Node ID: $NodeId"

# Verify chain spec signature
Write-Host "`n[3/5] Verifying chain spec..." -ForegroundColor Yellow
try {
    $verifyOutput = & cargo run --example verify_chain_spec --package common --quiet -- "$specPath" (Get-Content $sigPath) 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  ✓ Chain spec signature VALID" -ForegroundColor Green
    } else {
        Write-Warning "Chain spec signature verification had issues (non-fatal for local testing)"
    }
} catch {
    Write-Warning "Could not verify signature: $_"
}

# Compute genesis hash
Write-Host "`n[4/5] Computing genesis hash..." -ForegroundColor Yellow
try {
    $genesisHash = & cargo run --example compute_genesis_hash --package common --quiet -- "$specPath" 2>$null
    Write-Host "  ✓ Genesis hash: $genesisHash"
} catch {
    Write-Warning "Could not compute genesis hash: $_"
}

# Start node
Write-Host "`n[5/5] Starting node..." -ForegroundColor Yellow
Write-Host "  Press Ctrl+C to stop`n" -ForegroundColor Gray
Write-Host "  API:     http://localhost:8080/v1/health" -ForegroundColor Cyan
Write-Host "  Metrics: http://localhost:8080/metrics" -ForegroundColor Cyan
Write-Host "  gRPC:    localhost:50051" -ForegroundColor Cyan
Write-Host "  P2P:     localhost:9000`n" -ForegroundColor Cyan

Set-Location $repoRoot
cargo run --bin creg-node --package chain-registry-node
