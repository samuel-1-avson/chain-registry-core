# Verify CREG public API and JSON-RPC endpoints (HOSTING-301 / RPC smoke test).
#
# Usage:
#   .\testnet\verify-rpc-endpoints.ps1
#   .\testnet\verify-rpc-endpoints.ps1 -BaseUrl https://api.testnet.cregnet.dev

param(
    [string]$BaseUrl = "https://api.testnet.cregnet.dev"
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Log($msg) { Write-Host "[verify-rpc] $msg" }
function Pass($msg) { Write-Host "[verify-rpc] OK   $msg" -ForegroundColor Green }
function Fail($msg) { Write-Host "[verify-rpc] FAIL $msg" -ForegroundColor Red; exit 1 }

$base = $BaseUrl.TrimEnd("/")
Log "Base URL: $base"

# 1. REST health
try {
    $health = Invoke-RestMethod -Uri "$base/v1/health" -Method GET -TimeoutSec 15
    if ($health.status -ne "ok") { Fail "health status != ok: $($health | ConvertTo-Json -Compress)" }
    Pass "GET /v1/health -> status=ok (version=$($health.version))"
} catch {
    Fail "GET /v1/health: $_"
}

# 2. JSON-RPC creg_chainId
$body = '{"jsonrpc":"2.0","method":"creg_chainId","id":1}'
try {
    $rpc = Invoke-RestMethod -Uri "$base/rpc" -Method POST -ContentType "application/json" -Body $body -TimeoutSec 15
    if (-not $rpc.result) { Fail "rpc creg_chainId missing result: $($rpc | ConvertTo-Json -Compress)" }
    Pass "POST /rpc creg_chainId -> $($rpc.result)"
} catch {
    Fail "POST /rpc: $_"
}

# 3. JSON-RPC creg_blockNumber
$body2 = '{"jsonrpc":"2.0","method":"creg_blockNumber","id":2}'
try {
    $rpc2 = Invoke-RestMethod -Uri "$base/jsonrpc" -Method POST -ContentType "application/json" -Body $body2 -TimeoutSec 15
    if (-not $rpc2.result) { Fail "jsonrpc creg_blockNumber missing result" }
    Pass "POST /jsonrpc creg_blockNumber -> $($rpc2.result)"
} catch {
    Fail "POST /jsonrpc: $_"
}

# 4. Chain stats (public REST)
try {
    $stats = Invoke-RestMethod -Uri "$base/v1/public/chain/stats" -Method GET -TimeoutSec 15
    Pass "GET /v1/public/chain/stats -> tip_height=$($stats.tip_height)"
} catch {
    Log "WARN /v1/public/chain/stats: $_ (non-fatal)"
}

# 5. Metrics reachable (Prometheus scrape path)
try {
    $metrics = Invoke-WebRequest -Uri "$base/metrics" -Method GET -TimeoutSec 15 -UseBasicParsing
    if ($metrics.StatusCode -ge 200 -and $metrics.StatusCode -lt 300) {
        Pass "GET /metrics -> HTTP $($metrics.StatusCode)"
    } else {
        Log "WARN /metrics HTTP $($metrics.StatusCode)"
    }
} catch {
    Log "WARN /metrics: $_"
}

Log "All required RPC checks passed."
Log "Sepolia L1 RPC is separate - set SEPOLIA_RPC_URL in sepolia-3node.env (see docs/GCP-RPC-ARCHITECTURE.md)."
