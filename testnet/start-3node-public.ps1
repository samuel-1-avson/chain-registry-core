# Start 3-node Sepolia fleet + public lab services (faucet + explorer + optional TLS ingress).
#
# Local lab:
#   .\testnet\start-3node-public.ps1 -PatchChainSpec
#   .\testnet\start-3node-public.ps1 -WithFaucet
#
# Internet-hosted (after DNS points at the VM):
#   .\testnet\start-3node-public.ps1 -PatchChainSpec -BaseDomain testnet.example.com `
#     -WithFaucet -WithIngress

param(
    [switch]$PatchChainSpec,
    [switch]$WithFaucet,
    [switch]$WithIngress,
    [switch]$FreshVolumes,
    [string]$BaseDomain = "",
    [string]$PublicHost = ""
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir

if ($PatchChainSpec) {
    $patchArgs = @()
    if ($BaseDomain) {
        $patchArgs += "-BaseDomain"
        $patchArgs += $BaseDomain
    } elseif ($PublicHost) {
        $patchArgs += "-PublicHost"
        $patchArgs += $PublicHost
    }
    & (Join-Path $scriptDir "patch-sepolia-chain-spec-services.ps1") @patchArgs
}

$startArgs = @()
if ($FreshVolumes) { $startArgs += "-FreshVolumes" }
& (Join-Path $scriptDir "start-3node-test.ps1") @startArgs

Set-Location $repoRoot

$composeBase = Join-Path $scriptDir "docker-compose.3node.yml"
$composeServices = Join-Path $scriptDir "docker-compose.3node-services.yml"
$composeIngress = Join-Path $scriptDir "docker-compose.3node-ingress.yml"
$envFile = Join-Path $scriptDir "sepolia-3node.env"

$composeFiles = @("-f", $composeBase, "-f", $composeServices)
if ($WithIngress) {
    $composeFiles += @("-f", $composeIngress)
}

$services = @("web-explorer")
if ($WithFaucet) {
    $services = @("faucet") + $services
}
if ($WithIngress) {
    $services += "caddy"
}

$explorerPort = 3017
if (Test-Path $envFile) {
    foreach ($line in Get-Content $envFile) {
        if ($line -match '^\s*CREG_3NODE_EXPLORER_PORT\s*=\s*(\d+)\s*$') {
            $explorerPort = [int]$matches[1]
            break
        }
    }
}
if ($env:CREG_3NODE_EXPLORER_PORT) {
    $explorerPort = [int]$env:CREG_3NODE_EXPLORER_PORT
}

$legacyExplorer = docker ps --format "{{.Names}}" 2>$null | Select-String -SimpleMatch "creg-web-explorer"
if ($legacyExplorer -and $explorerPort -eq 3007) {
    Write-Host ""
    Write-Host "WARNING: creg-web-explorer already uses port 3007 (main docker-compose stack)." -ForegroundColor Yellow
    Write-Host "         Set CREG_3NODE_EXPLORER_PORT=3017 in testnet/sepolia-3node.env (recommended on Windows)." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Starting public lab services: $($services -join ', ') ===" -ForegroundColor Cyan
docker compose @composeFiles --env-file $envFile up -d --build --no-deps @services

function Test-ExplorerApi {
    param([int]$Port)
    try {
        $r = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/v1/public/health" -TimeoutSec 5 -UseBasicParsing
        return $r.StatusCode -eq 200 -and $r.Headers["X-Frame-Options"] -eq "SAMEORIGIN"
    } catch {
        return $false
    }
}

Write-Host ""
Write-Host "=== Verifying explorer (port $explorerPort) ===" -ForegroundColor Cyan
Start-Sleep -Seconds 3
if (Test-ExplorerApi -Port $explorerPort) {
    Write-Host "Explorer API reachable at http://127.0.0.1:$explorerPort" -ForegroundColor Green
} else {
    $container = "creg-3node-explorer"
    $running = docker ps --format "{{.Names}}" 2>$null | Select-String -SimpleMatch $container
    if ($running) {
        $inner = docker exec $container wget -qO- http://127.0.0.1/v1/public/health 2>&1
        if ($LASTEXITCODE -eq 0 -and $inner -match '"status"\s*:\s*"ok"') {
            Write-Host "Explorer container is healthy; host port $explorerPort may be blocked (Windows Docker port relay)." -ForegroundColor Yellow
            Write-Host "Use http://127.0.0.1:$explorerPort in the browser, or: docker exec $container wget -qO- http://127.0.0.1/v1/public/health" -ForegroundColor Yellow
        } else {
            Write-Host "Explorer failed health check. Logs: docker logs $container" -ForegroundColor Red
        }
    } else {
        Write-Host "Explorer container not running. Check: docker compose -f testnet/docker-compose.3node.yml -f testnet/docker-compose.3node-services.yml ps" -ForegroundColor Red
    }
}

Write-Host ""
if ($WithIngress -and $BaseDomain) {
    Write-Host "Public HTTPS endpoints (after DNS + cert issuance):" -ForegroundColor Green
    Write-Host "  Node API (CLI):  https://api.$BaseDomain"
    Write-Host "  Explorer:        https://explorer.$BaseDomain"
    Write-Host "  Faucet:          https://faucet.$BaseDomain"
    Write-Host "  Chain spec:      https://spec.$BaseDomain/chain-spec.json"
    Write-Host ""
    Write-Host "  export CREG_NODE_URL=https://api.$BaseDomain"
} else {
    Write-Host "Public lab endpoints:" -ForegroundColor Green
    Write-Host "  Node API (validator-2): http://localhost:28181"
    Write-Host "  Node API (observer):    http://localhost:28182"
    Write-Host "  Explorer:               http://127.0.0.1:$explorerPort"
    Write-Host "  Faucet:                 http://localhost:8082  (if -WithFaucet and keys configured)"
    Write-Host "  Chain spec:          http://localhost:18888/chain-spec.json"
    Write-Host ""
    Write-Host "Set before publishing:" -ForegroundColor Yellow
    Write-Host "  `$env:CREG_NODE_URL = 'http://localhost:28182'"
}

if ($WithIngress) {
    Write-Host ""
    Write-Host "Caddy: allow 2-5 minutes for Let's Encrypt on first boot. Check: docker logs creg-3node-caddy" -ForegroundColor Yellow
}
