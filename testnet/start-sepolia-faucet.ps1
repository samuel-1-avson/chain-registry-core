# Run the CREG faucet against Sepolia (reads testnet/.env.sepolia.faucet).
#
# Usage:
#   .\testnet\start-sepolia-faucet.ps1
#   # UI: http://localhost:8082

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$envFile = Join-Path $scriptDir ".env.sepolia.faucet"

if (-not (Test-Path $envFile)) {
    throw "Missing $envFile - run .\testnet\setup-sepolia-faucet.ps1"
}

& (Join-Path $scriptDir "sync-sepolia-faucet-env.ps1")

Get-Content $envFile | ForEach-Object {
    if ($_ -match '^\s*([^#\s][^=]*)\s*=\s*(.*)\s*$') {
        [Environment]::SetEnvironmentVariable($matches[1].Trim(), $matches[2].Trim().Trim('"'), "Process")
    }
}

$cast = Join-Path $scriptDir ".tools\foundry\cast.exe"
if (-not (Test-Path $cast)) {
    $cc = Get-Command cast -ErrorAction SilentlyContinue
    if ($cc) { $cast = $cc.Source }
}
if ($cast -and $env:FAUCET_ADDRESS) {
    $env:FOUNDRY_DISABLE_NIGHTLY_WARNING = "1"
    $eth = & $cast balance $env:FAUCET_ADDRESS --rpc-url $env:FAUCET_RPC_URL 2>&1 | Out-String
    $creg = & $cast call $env:FAUCET_TOKEN_CONTRACT "balanceOf(address)(uint256)" $env:FAUCET_ADDRESS --rpc-url $env:FAUCET_RPC_URL 2>&1 | Out-String
    Write-Host "Faucet $($env:FAUCET_ADDRESS)" -ForegroundColor Cyan
    Write-Host "  ETH:  $($eth.Trim())"
    Write-Host "  CREG: $($creg.Trim())"
    if ($creg -match '^\s*0\s*$' -or ($creg.Trim() -eq '0')) {
        Write-Host "  WARNING: zero CREG on token $($env:FAUCET_TOKEN_CONTRACT) - run fund-sepolia-faucet-governance.ps1" -ForegroundColor Yellow
    }
    if ($eth -match '^\s*0\s*$' -or ($eth.Trim() -eq '0')) {
        Write-Host "  WARNING: zero ETH - drips will fail; run fund-sepolia-faucet-eth.ps1" -ForegroundColor Yellow
    }
    Write-Host ""
}

$port = if ($env:FAUCET_PORT) { $env:FAUCET_PORT } else { "8082" }
$baseUrl = "http://127.0.0.1:$port"

function Get-ListenerPid([string]$TcpPort) {
    $conn = Get-NetTCPConnection -LocalPort $TcpPort -State Listen -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($conn) { return $conn.OwningProcess }
    $line = netstat -ano | Select-String ":\s*$TcpPort\s+.*LISTENING" | Select-Object -First 1
    if ($line -match '\s+(\d+)\s*$') { return [int]$matches[1] }
    return $null
}

$existingPid = Get-ListenerPid $port
if ($existingPid) {
    $procName = (Get-Process -Id $existingPid -ErrorAction SilentlyContinue).ProcessName
    $health = curl.exe -s -m 5 "$baseUrl/health" 2>&1 | Out-String
    if ($health -match 'healthy') {
        Write-Host "Faucet already running at $baseUrl (PID $existingPid, $procName)." -ForegroundColor Green
        Write-Host "Use drip-sepolia-faucet.ps1 or the UI; no second instance needed." -ForegroundColor DarkGray
        Write-Host "To restart: Stop-Process -Id $existingPid -Force; then run this script again." -ForegroundColor DarkGray
        exit 0
    }
    Write-Host "Port $port is in use by PID $existingPid ($procName) but /health did not respond." -ForegroundColor Yellow
    Write-Host "Free the port: Stop-Process -Id $existingPid -Force" -ForegroundColor Yellow
    exit 1
}

Write-Host "Starting faucet on http://localhost:$port (Ctrl+C to stop)" -ForegroundColor Green
Write-Host ""

Set-Location $repoRoot
cargo run --release -p faucet
