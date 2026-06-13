# SANDBOX-301 — Real behavioural sandbox verification (nsjail, CREG_DEV_SANDBOX=false).
#
# Proves:
#   - Validator containers use chain-registry-node-secure image
#   - CREG_DEV_SANDBOX is not true on validators
#   - nsjail binary is present inside validator containers
#   - Optional: consensus soak without dev-bypass in logs
#
# Prerequisites:
#   - Fleet running: .\testnet\start-3node-sandbox.ps1
#   - NET-301 L1 quorum (validator-2 Active) for full publish soak
#
# Usage:
#   .\testnet\sandbox-301-verify.ps1
#   .\testnet\sandbox-301-verify.ps1 -SkipPublish

param(
    [switch]$SkipPublish
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
Set-Location $repoRoot

function Log($msg) { Write-Host "[sandbox-301] $msg" }

$dockerOs = docker info --format "{{.OSType}}" 2>$null
if ($dockerOs -and $dockerOs -ne "linux") {
    throw "SANDBOX-301 requires Docker Linux containers (OSType=$dockerOs)"
}

$checks = @{
    timestamp      = (Get-Date).ToUniversalTime().ToString("o")
    sandbox301     = $false
    docker_ostype  = $dockerOs
    validators     = @()
    nsjail_present = $false
    dev_bypass     = $false
    soak_passed    = $false
}

foreach ($ctr in @("creg-3node-node1", "creg-3node-node2")) {
    $inspect = docker inspect --format '{{.Config.Image}}' $ctr 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "Container $ctr not running - start with .\testnet\start-3node-sandbox.ps1"
    }
    if ($inspect -notmatch "secure") {
        throw "Container $ctr image=$inspect - expected chain-registry-node-secure (dev fleet uses creg-node:local-3node)"
    }
    $sandboxEnv = docker exec $ctr printenv CREG_DEV_SANDBOX 2>$null
    if ($sandboxEnv -eq "true") {
        throw "$ctr has CREG_DEV_SANDBOX=true - SANDBOX-301 requires false"
    }
    Log "$ctr image=$inspect CREG_DEV_SANDBOX=$sandboxEnv"
    $checks.validators += @{
        container = $ctr
        image     = $inspect
        dev_sandbox = $sandboxEnv
    }
}

docker exec creg-3node-node1 nsjail --help 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "nsjail not available inside creg-3node-node1"
}
$checks.nsjail_present = $true
Log "nsjail present in validator container"

& (Join-Path $scriptDir "soak-3node-sandbox.ps1") -SkipPublish:$SkipPublish
if ($LASTEXITCODE -ne 0) { throw "soak-3node-sandbox failed" }
$checks.soak_passed = $true

$logTail = docker logs creg-3node-node1 --tail 500 2>&1 | Out-String
$checks.dev_bypass = ($logTail -match "dev-bypass")
if ($checks.dev_bypass) {
    throw "Found dev-bypass in node1 logs - sandbox engine must not use dev bypass"
}

$checks.sandbox301 = $true
$outDir = Join-Path $repoRoot "testnet\sandbox-301-logs"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$outPath = Join-Path $outDir ("sandbox-301-{0}.json" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
$checks | ConvertTo-Json -Depth 5 | Set-Content -Path $outPath -Encoding utf8
Log "SANDBOX-301 verify PASSED (see $outPath)"
