# Build chain-registry-app + nsjail secure node image for SANDBOX-301.
# Requires Linux container backend (Docker Desktop WSL2 on Windows is OK; Windows containers are not).
#
# Usage:
#   .\testnet\build-3node-secure-image.ps1
#   .\testnet\build-3node-secure-image.ps1 -RebuildApp
#   .\testnet\build-3node-secure-image.ps1 -SkipAppBuild

param(
    [string]$Dockerfile = "Dockerfile",
    [switch]$RebuildApp,
    [switch]$SkipAppBuild
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
Set-Location $repoRoot

function Log($msg) { Write-Host "[build-secure] $msg" -ForegroundColor Cyan }

$dockerInfo = docker info --format "{{.OSType}}" 2>$null
if ($dockerInfo -and $dockerInfo -ne "linux") {
    throw "SANDBOX-301 requires Docker Linux containers (got OSType=$dockerInfo). Switch Docker Desktop to Linux mode or use a Linux VM/GCP host."
}

$appExists = $false
docker image inspect chain-registry-app:latest 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) { $appExists = $true }

if ($SkipAppBuild -and -not $appExists) {
    throw "chain-registry-app:latest missing - omit -SkipAppBuild or run with -RebuildApp"
}
if ($RebuildApp -or (-not $SkipAppBuild -and -not $appExists)) {
    Log "Building chain-registry-app:latest from $Dockerfile ..."
    docker build -t chain-registry-app:latest -f $Dockerfile .
    if ($LASTEXITCODE -ne 0) { throw "docker build app failed" }
} elseif ($appExists) {
    Log "Using existing chain-registry-app:latest (pass -RebuildApp to rebuild base image)"
}

Log "Building chain-registry-node-secure:latest from Dockerfile.secure ..."
docker build -t chain-registry-node-secure:latest -f Dockerfile.secure .
if ($LASTEXITCODE -ne 0) { throw "docker build secure failed" }

Log "Verifying nsjail in secure image (nsjail has no --version; use --help) ..."
$nsjailTest = docker run --rm --entrypoint nsjail chain-registry-node-secure:latest --help 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) {
    if ($nsjailTest -match "GLIBC") {
        throw "nsjail glibc mismatch - rebuild base with -RebuildApp (chain-registry-app must match Dockerfile Ubuntu 24.04 runtime)"
    }
    throw "nsjail not runnable in chain-registry-node-secure:latest: $nsjailTest"
}

Write-Host "OK chain-registry-node-secure:latest ready" -ForegroundColor Green
