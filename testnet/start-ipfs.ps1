# Start local IPFS (Kubo) for E2E-301 publish smoke — no native ipfs CLI required.
#
# Usage:
#   .\testnet\start-ipfs.ps1
#   .\testnet\start-ipfs.ps1 -Stop
#
# API: http://127.0.0.1:5001  (set CREG_IPFS_URL to match)

param(
    [switch]$Stop
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $scriptDir "ipfs-api.ps1")
$composeFile = Join-Path $scriptDir "docker-compose.ipfs.yml"
$apiUrl = "http://127.0.0.1:5001"

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    if (Test-CregIpfsApi -BaseUrl $apiUrl) {
        Write-Host "OK IPFS API already reachable at $apiUrl" -ForegroundColor Green
        exit 0
    }
    Write-Host "Docker is not on PATH." -ForegroundColor Red
    Write-Host ""
    Write-Host "Option A — install Kubo CLI:" -ForegroundColor Yellow
    Write-Host "  winget install IPFS.Kubo"
    Write-Host "  # restart PowerShell, then: ipfs daemon"
    Write-Host ""
    Write-Host "Option B — install Docker Desktop, then re-run this script."
    exit 1
}

if ($Stop) {
    docker compose -f $composeFile down 2>$null
    Write-Host "Stopped creg-ipfs-local (if it was running)." -ForegroundColor Green
    Write-Host "To stop local-testnet IPFS: docker stop creg-local-ipfs"
    exit 0
}

if (Test-CregIpfsApi -BaseUrl $apiUrl) {
    $name = (docker ps --filter "publish=5001" --format "{{.Names}}" 2>$null | Select-Object -First 1)
    if ($name) {
        Write-Host "OK IPFS API ready at $apiUrl (container: $name)" -ForegroundColor Green
    } else {
        Write-Host "OK IPFS API ready at $apiUrl" -ForegroundColor Green
    }
    Write-Host ""
    Write-Host "No need to start creg-ipfs-local. Run:"
    Write-Host "  .\testnet\run-ops-201-verify.ps1 -Force"
    exit 0
}

$on5001 = Get-NetTCPConnection -LocalPort 5001 -State Listen -ErrorAction SilentlyContinue
if ($on5001) {
    Write-Host "Port 5001 is in use but Kubo API did not respond." -ForegroundColor Yellow
    Write-Host "Check: docker ps --filter publish=5001"
    Write-Host "Or free the port, then re-run this script."
    exit 1
}

Write-Host "Starting Kubo via Docker (creg-ipfs-local)..." -ForegroundColor Cyan
docker compose -f $composeFile up -d 2>&1 | Write-Host
if ($LASTEXITCODE -ne 0) {
    if (Test-CregIpfsApi -BaseUrl $apiUrl) {
        Write-Host "OK IPFS API ready at $apiUrl (existing listener)" -ForegroundColor Green
        exit 0
    }
    exit $LASTEXITCODE
}

$deadline = (Get-Date).AddSeconds(90)
while ((Get-Date) -lt $deadline) {
    if (Test-CregIpfsApi -BaseUrl $apiUrl) {
        Write-Host "OK IPFS API ready at $apiUrl" -ForegroundColor Green
        Write-Host ""
        Write-Host "  .\testnet\run-ops-201-verify.ps1 -Force"
        exit 0
    }
    Start-Sleep -Seconds 3
}

Write-Host "IPFS container started but API not ready yet. Check: docker logs creg-ipfs-local" -ForegroundColor Yellow
exit 1
