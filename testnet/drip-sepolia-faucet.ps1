# Request CREG from the local Sepolia faucet HTTP API (PoW disabled when FAUCET_POW_DISABLED=true).
#
# Usage:
#   .\testnet\start-sepolia-faucet.ps1   # other window
#   .\testnet\drip-sepolia-faucet.ps1 -Address 0x8E468575568756E210caA39D04A24a8bF2266B84

param(
    [Parameter(Mandatory = $true)]
    [string]$Address,
    [string]$FaucetUrl = "http://127.0.0.1:8082"
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if ($Address -notmatch '^0x[a-fA-F0-9]{40}$') { throw "Invalid address" }

$base = $FaucetUrl.TrimEnd('/')
$bodyJson = (@{ address = $Address } | ConvertTo-Json -Compress)

function Invoke-FaucetDripViaDocker {
    param([string]$JsonBody)
    $container = "creg-faucet"
    $running = docker ps --format "{{.Names}}" 2>$null | Select-String -SimpleMatch $container
    if (-not $running) { return $null }
    $tmpHost = Join-Path $scriptDir ".drip-body.json"
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($tmpHost, $JsonBody, $utf8NoBom)
    try {
        docker cp $tmpHost "${container}:/tmp/drip.json" | Out-Null
        if ($LASTEXITCODE -ne 0) { return $null }
        $raw = docker exec $container curl -s -X POST http://localhost:8082/api/drip `
            -H "Content-Type: application/json" "-d@/tmp/drip.json" 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0 -or -not $raw.Trim()) { return $null }
        return $raw.Trim() | ConvertFrom-Json
    } finally {
        Remove-Item $tmpHost -Force -ErrorAction SilentlyContinue
    }
}

$health = curl.exe -s -m 5 "$base/health"
$useDocker = ($LASTEXITCODE -ne 0 -or $health -notmatch 'healthy')

if ($useDocker) {
    Write-Host "Host faucet unreachable at $base; using docker exec via creg-faucet ..." -ForegroundColor Yellow
    $result = Invoke-FaucetDripViaDocker -JsonBody $bodyJson
    if (-not $result) {
        throw "Faucet not reachable at $base and docker fallback failed. Run .\testnet\start-sepolia-faucet.ps1 or docker compose up faucet."
    }
} else {
    Write-Host "Dripping CREG to $Address via $base/api/drip ..." -ForegroundColor Cyan
    try {
        $result = Invoke-RestMethod -Uri "$base/api/drip" -Method Post -ContentType "application/json; charset=utf-8" `
            -Body $bodyJson -TimeoutSec 120
    } catch {
        if ($_.ErrorDetails.Message) { Write-Host $_.ErrorDetails.Message }
        Write-Host "HTTP drip failed; trying docker exec fallback ..." -ForegroundColor Yellow
        $result = Invoke-FaucetDripViaDocker -JsonBody $bodyJson
        if (-not $result) {
            throw "Drip HTTP failed: $($_.Exception.Message). Is .\testnet\start-sepolia-faucet.ps1 running?"
        }
    }
}

$result | ConvertTo-Json -Compress | Write-Host
if (-not $result.success) {
    if ($result.message -match 'out of testnet ETH') {
        throw @"
Drip failed: $($result.message)

Refill the docker faucet wallet, then retry:
  .\testnet\fund-sepolia-faucet-eth.ps1 -AmountEth 0.05
  .\testnet\drip-sepolia-faucet.ps1 -Address $Address
"@
    }
    throw "Drip failed: $($result.message). Check faucet CREG/ETH balance and cooldown."
}
Write-Host "OK" -ForegroundColor Green
if ($result.tx_hash) { Write-Host "  tx: $($result.tx_hash)" -ForegroundColor DarkGray }
if ($result.token_tx_hash) { Write-Host "  token tx: $($result.token_tx_hash)" -ForegroundColor DarkGray }
