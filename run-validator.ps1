# Run Validator Node Script for Windows
# This script properly sets up the environment and runs the single validator

param(
    [switch]$Help
)

if ($Help) {
    Write-Host @"
Run Validator Node Script

Usage:
    .\run-validator.ps1 [OPTIONS]

Options:
    -Help                 Show this help

Examples:
    .\run-validator.ps1              # Run the validator
"@
    exit 0
}

$ValidatorNumber = 1

Write-Host "========================================"
Write-Host "Chain Registry - Validator Starter"
Write-Host "========================================"
Write-Host ""

# Get the project root
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

# Check if binary exists
$BinaryPath = Join-Path $ProjectRoot "target\release\creg-node.exe"
if (-not (Test-Path $BinaryPath)) {
    Write-Error "Binary not found at $BinaryPath"
    Write-Host "Please build first: cargo build --release --package chain-registry-node"
    exit 1
}

# Read .env file
$EnvFile = Join-Path $ProjectRoot ".env"
if (-not (Test-Path $EnvFile)) {
    Write-Error ".env file not found!"
    Write-Host "Please run: .\scripts\generate-validator-keys.ps1 3"
    exit 1
}

# Parse .env file properly
$EnvContent = Get-Content $EnvFile
$ValidatorKey = $null

foreach ($line in $EnvContent) {
    if ($line -match "^NODE${ValidatorNumber}_VALIDATOR_KEY=(.+)$") {
        $ValidatorKey = $matches[1].Trim()
        # Remove quotes if present
        $ValidatorKey = $ValidatorKey -replace '^"', '' -replace '"$', ''
        break
    }
}

if (-not $ValidatorKey) {
    Write-Error "NODE${ValidatorNumber}_VALIDATOR_KEY not found in .env file"
    exit 1
}

Write-Host "Configuration:"
Write-Host "  Validator Number: $ValidatorNumber"
Write-Host "  Validator Key: $($ValidatorKey.Substring(0,20))..."
Write-Host "  Data Directory: ./data/node-$ValidatorNumber"
Write-Host ""

# Set environment variables
$env:CREG_NODE_ID = "node-$ValidatorNumber"
$env:CREG_IS_VALIDATOR = "true"
$env:CREG_VALIDATOR_KEY = $ValidatorKey
$env:CREG_DATA_DIR = "./data/node-$ValidatorNumber"
$env:CREG_ETH_RPC = "http://localhost:8545"
$env:CREG_LISTEN = "0.0.0.0:$((8080 + $ValidatorNumber - 1))"
$env:CREG_P2P_LISTEN = "/ip4/0.0.0.0/tcp/$((9000 + $ValidatorNumber - 1))"
$env:CREG_SINGLE_VALIDATOR_MODE = "true"
$env:CREG_DEV_SANDBOX = "true"
$env:RUST_LOG = "info,chain_registry_node=debug"

# Create data directory
$DataDir = Join-Path $ProjectRoot "data\node-$ValidatorNumber"
if (-not (Test-Path $DataDir)) {
    New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
}

Write-Host "Starting validator $ValidatorNumber..."
Write-Host "Press Ctrl+C to stop"
Write-Host ""

# Run the node
& $BinaryPath
