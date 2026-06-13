# Start the testnet Join Hub locally (hub-web :8094, hub-api :8095).
#
# Usage:
#   .\testnet\start-hub-local.ps1
#   .\testnet\start-hub-local.ps1 -Down
#
# Dev without Docker (two terminals):
#   cd hub-api && npm install && npm run dev
#   cd hub-web && npm install --legacy-peer-deps --install-strategy=nested --omit=optional && npm run dev
#   (Optional WC: npm install @walletconnect/ethereum-provider)

param(
    [switch]$Down,
    [switch]$Build
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$composeFile = Join-Path $scriptDir "docker-compose.hub.yml"
$envFile = Join-Path $scriptDir "sepolia-3node.env"
$envExample = Join-Path $scriptDir "sepolia-3node.env.example"

Push-Location $repoRoot
try {
    $composeArgs = @("-f", $composeFile)
    if (Test-Path $envFile) {
        $composeArgs += @("--env-file", $envFile)
    } elseif (Test-Path $envExample) {
        $composeArgs += @("--env-file", $envExample)
    }

    if ($Down) {
        docker compose @composeArgs down
        Write-Host "Hub stack stopped." -ForegroundColor Green
        return
    }

    $upArgs = @("up", "-d")
    if ($Build) { $upArgs += "--build" }

    docker compose @composeArgs @upArgs

    $webPort = if ($env:CREG_HUB_WEB_PORT) { $env:CREG_HUB_WEB_PORT } else { "8094" }
    $apiPort = if ($env:CREG_HUB_API_PORT) { $env:CREG_HUB_API_PORT } else { "8095" }

    Write-Host ""
    Write-Host "Join Hub (Phase 1)" -ForegroundColor Cyan
    Write-Host "  Web:  http://localhost:$webPort"
    Write-Host "  API:  http://localhost:$apiPort/api/health"
    Write-Host ""
    Write-Host "Stop: .\testnet\start-hub-local.ps1 -Down" -ForegroundColor DarkGray
} finally {
    Pop-Location
}
