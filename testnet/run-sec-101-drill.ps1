# SEC-101-ops - hot-key rotation drill helper (testnet).
# Documents fingerprints before/after; does NOT generate or store new secrets.
#
# Usage:
#   .\testnet\run-sec-101-drill.ps1 -EnvFile .\.env.sepolia
#   .\testnet\run-sec-101-drill.ps1 -EnvFile .\.env.sepolia -Label before
#   # rotate key in .env.sepolia, then:
#   .\testnet\run-sec-101-drill.ps1 -EnvFile .\.env.sepolia -Label after

param(
    [switch]$WhatIf,
    [string]$EnvFile = "",
    [string]$Label = ""
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$logDir = Join-Path $scriptDir "ops-201-logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$ts = Get-Date -Format "yyyyMMdd-HHmmss"
$logFile = Join-Path $logDir "sec-101-drill-$ts.log"

function Log($msg) {
    $line = "[$(Get-Date -Format 'HH:mm:ss')] $msg"
    Add-Content -Path $logFile -Value $line
    Write-Host $line
}

function Import-EnvFile {
    param([string]$Path)
    $resolved = if ([System.IO.Path]::IsPathRooted($Path)) { $Path } else { Join-Path $scriptDir $Path }
    if (-not (Test-Path $resolved)) {
        throw "Env file not found: $resolved"
    }
    Log "Loading env file (values not logged): $resolved"
    Get-Content $resolved | ForEach-Object {
        $line = $_.Trim()
        if (-not $line -or $line.StartsWith("#")) { return }
        if ($line -match '^\s*([^#=]+)=(.*)$') {
            $name = $matches[1].Trim()
            $val = $matches[2].Trim().Trim('"').Trim("'")
            Set-Item -Path "Env:$name" -Value $val
        }
    }
}

$defaultEnv = Join-Path $scriptDir ".env.sepolia"
if (-not $EnvFile -and (Test-Path $defaultEnv)) {
    $EnvFile = $defaultEnv
}
if ($EnvFile) {
    Import-EnvFile -Path $EnvFile
}

if ($Label) {
    $logFile = Join-Path $logDir "sec-101-drill-$Label-$ts.log"
}

$vars = @(
    @{ Name = "CREG_BRIDGE_KEY"; Service = "node bridge" },
    @{ Name = "FAUCET_PRIVATE_KEY"; Service = "faucet" },
    @{ Name = "RELAYER_PRIVATE_KEY"; Service = "relayer" }
)

function Get-Fingerprint([string]$hexKey) {
    if ([string]::IsNullOrWhiteSpace($hexKey)) { return "(unset)" }
    $trim = $hexKey.Trim()
    if ($trim -match '(?i)\.\.\.|YOUR|CHANGEME|REPLACE|xxx') { return "(placeholder)" }
    $clean = $trim.TrimStart("0x")
    if ($clean.Length -ne 64 -or $clean -match '[^0-9a-fA-F]') { return "(invalid)" }
    try {
        $bytes = [byte[]]::new($clean.Length / 2)
        for ($i = 0; $i -lt $bytes.Length; $i++) {
            $bytes[$i] = [Convert]::ToByte($clean.Substring($i * 2, 2), 16)
        }
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $hash = $sha.ComputeHash($bytes)
        $sha.Dispose()
        $hex = ([BitConverter]::ToString($hash)).Replace("-", "").ToLower()
        return "0x" + $hex.Substring(0, 8) + "..." + $hex.Substring($hex.Length - 8)
    } catch {
        return "(parse error)"
    }
}

Log "=== SEC-101-ops drill: hot-key fingerprint snapshot ==="
Log "See docs/SECURITY_OPS_RUNBOOK.md for full procedure"
Log ""

$testnet = $env:CREG_TESTNET
if ($testnet -ne "true") {
    Log "WARN: CREG_TESTNET is not true - production builds should show hot-key WARN on boot"
}

$setKeys = @()
foreach ($v in $vars) {
    $val = [Environment]::GetEnvironmentVariable($v.Name)
    $fp = Get-Fingerprint $val
    $set = if ($val) { "set" } else { "unset" }
    if ($val) { $setKeys += $v.Name }
    Log "$($v.Name) [$($v.Service)]: $set fingerprint=$fp"
}

if ($setKeys.Count -eq 0) {
    Log "WARN: No hot keys set. Add CREG_BRIDGE_KEY to .env.sepolia (recommended for Sepolia node drill)."
} elseif ($setKeys.Count -eq 1) {
    Log "Rotate this key for the drill: $($setKeys[0])"
} else {
    Log "Pick ONE key to rotate (drill scope): $($setKeys -join ', ')"
}

Log ""
Log "Drill steps (manual):"
Log "  1. Stop affected service"
Log "  2. Rotate key in vault / .env (never commit)"
Log "  3. Restart with CREG_TESTNET=true"
Log "  4. Re-run this script and confirm fingerprint changed"
Log "  5. Record sign-off in docs/NEXT_WORK.md (SEC-101-ops)"
Log ""

if ($WhatIf) {
    Log "WhatIf: no rotation performed"
} else {
    Log ('Snapshot complete. Log: ' + $logFile)
}
