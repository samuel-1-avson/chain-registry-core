# Start 3-node CREG fleet locally (hybrid mode). Edge services run on GCP.
#
# Prerequisites:
#   1. WireGuard client connected (see testnet/gcp/wireguard/README.md)
#   2. testnet/sepolia-3node.env with validator keys + CREG_ETH_RPC=http://10.128.0.3:8545
#   3. Docker Desktop running
#
# Usage:
#   .\testnet\start-local-validators.ps1
#   .\testnet\start-local-validators.ps1 -FreshVolumes

param(
    [switch]$FreshVolumes
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$envFile = Join-Path $scriptDir "sepolia-3node.env"

if (-not (Test-Path $envFile)) {
    throw "Missing $envFile - copy from sepolia-3node.env.example"
}

# Quick Sepolia RPC reachability (via WireGuard route to internal Geth).
$rpcTest = $null
Get-Content $envFile | ForEach-Object {
    if ($_ -match '^\s*CREG_ETH_RPC\s*=\s*(.+)$') { $rpcTest = $Matches[1].Trim() }
}
if ($rpcTest) {
    Write-Host "[local-validators] Checking Sepolia RPC at $rpcTest ..."
    try {
        $body = '{"jsonrpc":"2.0","method":"eth_chainId","id":1}'
        $r = Invoke-RestMethod -Uri $rpcTest -Method Post -ContentType "application/json" -Body $body -TimeoutSec 8
        if ($r.result -ne "0xaa36a7") {
            Write-Warning "Unexpected chainId $($r.result) - is WireGuard up and Geth synced?"
        }
    } catch {
        Write-Warning "Cannot reach CREG_ETH_RPC ($rpcTest). Connect WireGuard first: see testnet/gcp/wireguard/README.md"
    }
}

Set-Location $repoRoot

$compose = @(
    "compose",
    "-f", (Join-Path $scriptDir "docker-compose.3node.yml"),
    "-f", (Join-Path $scriptDir "docker-compose.local-hybrid.yml"),
    "--env-file", $envFile
)

if ($FreshVolumes) {
    Write-Host "[local-validators] Removing node volumes..."
    docker @compose down -v 2>$null
}

Write-Host "[local-validators] Building creg-node image..."
docker @compose build creg-node-1

Write-Host "[local-validators] Starting nodes (no IPFS/spec on host)..."
docker @compose up -d --build creg-node-1 creg-node-2 creg-node-3

Write-Host ""
Write-Host "Local APIs (WireGuard peer must match CREG_WG_LOCAL_PEER on cloud):" -ForegroundColor Cyan
Write-Host "  node-1: http://127.0.0.1:28180"
Write-Host "  node-2: http://127.0.0.1:28181  (operator / explorer backend)"
Write-Host "  node-3: http://127.0.0.1:28182  (public API via Caddy)"
Write-Host ""
Write-Host "Public URLs (after cloud edge + Caddy are up):" -ForegroundColor Cyan
Write-Host "  https://api.testnet.cregnet.dev/v1/health"
