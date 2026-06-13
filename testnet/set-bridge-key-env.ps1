# Write CREG_BRIDGE_KEY + CREG_TESTNET=true into testnet/.env.sepolia (SEC-101 drill).
# Does not print the key after writing.
#
# Usage:
#   $k = (.\testnet\generate-hot-key.ps1 | Out-String)  # copy key from output instead
#   .\testnet\set-bridge-key-env.ps1 -PrivateKey 0x<64 hex chars>

param(
    [Parameter(Mandatory = $true)]
    [string]$PrivateKey
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$envPath = Join-Path $scriptDir ".env.sepolia"

$trim = $PrivateKey.Trim()
if ($trim -notmatch '^0x[0-9a-fA-F]{64}$') {
    throw "PrivateKey must be 0x + 64 hex characters (32 bytes)"
}

if (-not (Test-Path $envPath)) {
    throw "Missing $envPath — copy from .env.sepolia.example first"
}

$lines = Get-Content $envPath
$out = New-Object System.Collections.Generic.List[string]
$seenBridge = $false
$seenTestnet = $false

foreach ($line in $lines) {
    if ($line -match '^\s*CREG_BRIDGE_KEY\s*=') {
        $out.Add("CREG_BRIDGE_KEY=$trim")
        $seenBridge = $true
        continue
    }
    if ($line -match '^\s*CREG_TESTNET\s*=') {
        $out.Add("CREG_TESTNET=true")
        $seenTestnet = $true
        continue
    }
    $out.Add($line)
}

if (-not $seenBridge) { $out.Add("CREG_BRIDGE_KEY=$trim") }
if (-not $seenTestnet) { $out.Add("CREG_TESTNET=true") }

$out | Set-Content -Path $envPath -Encoding utf8
Write-Host "Updated $envPath (CREG_BRIDGE_KEY + CREG_TESTNET=true). Key not echoed."
Write-Host "Run: .\testnet\run-sec-101-drill.ps1 -Label after"
