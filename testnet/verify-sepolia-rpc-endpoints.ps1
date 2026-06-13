# Verify public Sepolia L1 JSON-RPC proxies (eth_*), separate from CREG node /rpc (creg_*).
#
# Usage:
#   .\testnet\verify-sepolia-rpc-endpoints.ps1
#   .\testnet\verify-sepolia-rpc-endpoints.ps1 -ExplorerHost explorer.testnet.cregnet.dev -FaucetHost faucet.testnet.cregnet.dev

param(
    [string]$ExplorerHost = "",
    [string]$FaucetHost = "",
    [string]$EnvFile = ""
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Log($msg) { Write-Host "[verify-sepolia-rpc] $msg" }
function Pass($msg) { Write-Host "[verify-sepolia-rpc] OK   $msg" -ForegroundColor Green }
function Fail($msg) { Write-Host "[verify-sepolia-rpc] FAIL $msg" -ForegroundColor Red; exit 1 }

if (-not $EnvFile) { $EnvFile = Join-Path $scriptDir "sepolia-3node.env" }
if ((-not $ExplorerHost -or -not $FaucetHost) -and (Test-Path $EnvFile)) {
    $envVars = @{}
    foreach ($line in Get-Content $EnvFile) {
        if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$') {
            $envVars[$matches[1]] = $matches[2].Trim().Trim('"')
        }
    }
    if (-not $ExplorerHost) { $ExplorerHost = $envVars["CREG_PUBLIC_EXPLORER_HOST"] }
    if (-not $FaucetHost) { $FaucetHost = $envVars["CREG_PUBLIC_FAUCET_HOST"] }
}
if (-not $ExplorerHost) { Fail "Set -ExplorerHost or CREG_PUBLIC_EXPLORER_HOST in $EnvFile" }

$body = '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'

function Test-SepoliaRpc([string]$Label, [string]$Url) {
    try {
        $rpc = Invoke-RestMethod -Uri $Url -Method POST -ContentType "application/json" -Body $body -TimeoutSec 20
        if ($rpc.result -ne "0xaa36a7") {
            Fail "$Label $Url eth_chainId expected 0xaa36a7 got $($rpc | ConvertTo-Json -Compress)"
        }
        Pass "$Label POST $Url eth_chainId -> Sepolia (0xaa36a7)"
    } catch {
        Fail "$Label POST $Url : $_"
    }
}

Test-SepoliaRpc "explorer" "https://$ExplorerHost/rpc"
if ($FaucetHost) {
    Test-SepoliaRpc "faucet" "https://$FaucetHost/rpc"
} else {
    Log "WARN skipping faucet /rpc (CREG_PUBLIC_FAUCET_HOST unset)"
}

# api.* /rpc must remain CREG-only (eth_* should not work there).
$apiHost = $null
if (Test-Path $EnvFile) {
    foreach ($line in Get-Content $EnvFile) {
        if ($line -match '^\s*CREG_PUBLIC_API_HOST\s*=\s*(.*)\s*$') {
            $apiHost = $matches[1].Trim().Trim('"')
            break
        }
    }
}
if ($apiHost) {
    try {
        $bad = Invoke-RestMethod -Uri "https://$apiHost/rpc" -Method POST -ContentType "application/json" -Body $body -TimeoutSec 20
        if ($bad.result -eq "0xaa36a7") {
            Fail "api host $apiHost/rpc unexpectedly serves Sepolia eth_chainId (should be CREG creg_* only)"
        }
        Pass "api host $apiHost/rpc correctly rejects eth_chainId (CREG JSON-RPC only)"
    } catch {
        Pass "api host $apiHost/rpc eth_chainId unreachable or rejected (expected)"
    }
}

Log "Sepolia L1 RPC checks passed."
