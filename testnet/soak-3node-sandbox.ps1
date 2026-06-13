# SANDBOX-301 soak: CREG_DEV_SANDBOX=false + nsjail secure image.
#
# Prerequisites:
#   .\testnet\start-3node-sandbox.ps1
#
# Usage:
#   .\testnet\soak-3node-sandbox.ps1

param(
    [switch]$SkipPublish
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Log($msg) { Write-Host "[sandbox-301] $msg" }

foreach ($ctr in @("creg-3node-node1", "creg-3node-node2")) {
    $inspect = docker inspect --format '{{.Config.Image}}' $ctr 2>$null
    if ($LASTEXITCODE -ne 0) { throw "Container $ctr not running - start with .\testnet\start-3node-sandbox.ps1" }
    if ($inspect -notmatch "secure") {
        throw "Container $ctr image=$inspect - expected chain-registry-node-secure (run start-3node-sandbox.ps1)"
    }
    $sandboxEnv = docker exec $ctr printenv CREG_DEV_SANDBOX 2>$null
    if ($sandboxEnv -eq "true") {
        throw "$ctr has CREG_DEV_SANDBOX=true - SANDBOX-301 requires false"
    }
    Log "$ctr image=$inspect CREG_DEV_SANDBOX=$sandboxEnv"
}

$nsjailOk = docker exec creg-3node-node1 nsjail --help 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "nsjail not available inside creg-3node-node1"
}
Log "nsjail present in validator container"

& (Join-Path $scriptDir "soak-3node-consensus.ps1") -SkipPublish:$SkipPublish
if ($LASTEXITCODE -ne 0) { throw "soak-3node-consensus failed" }

$logTail = docker logs creg-3node-node1 --tail 500 2>&1 | Out-String
if ($logTail -match "dev-bypass") {
    throw "Found dev-bypass in node1 logs - sandbox engine must not use dev bypass"
}
if ($logTail -notmatch "nsjail|engine_used.*wasm") {
    Log "WARN: no explicit nsjail/wasm engine in recent logs - confirm pipeline ran a behavioural stage"
} else {
    Log "OK sandbox engine evidence in node logs"
}

Log "SANDBOX-301 soak PASSED"
