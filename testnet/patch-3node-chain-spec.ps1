# Anvil/local only: patch validator Ed25519 pubkeys in chain-spec.local.json.
# Sepolia 3-node fleet uses signed chain-spec.sepolia.json — do not run this for Sepolia.
# Run from repo root after changing validator secrets in local Anvil compose / run-3node-host.ps1.
#
# Usage:
#   .\testnet\patch-3node-chain-spec.ps1

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
Set-Location $repoRoot

$specPath = Join-Path $scriptDir "chain-spec.local.json"
if (-not (Test-Path $specPath)) {
    throw "Missing $specPath"
}

$secrets = @(
    @{ id = "validator-1"; secret = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" },
    @{ id = "validator-2"; secret = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" }
)

$pubkeys = @()
foreach ($entry in $secrets) {
    $out = cargo run -q --example ed25519_pubkey_from_secret -p common -- $entry.secret 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to derive pubkey for $($entry.id): $out"
    }
    $pubkeys += @{ id = $entry.id; pubkey = ($out | Select-Object -Last 1).Trim() }
}

$spec = Get-Content $specPath -Raw | ConvertFrom-Json
foreach ($validator in $spec.validator_set.validators) {
    $match = $pubkeys | Where-Object { $_.id -eq $validator.id }
    if ($match) {
        $validator.pubkey = $match.pubkey
        Write-Host "Patched $($validator.id) pubkey -> $($match.pubkey)"
    }
}

$spec | ConvertTo-Json -Depth 20 | Set-Content -Path $specPath -Encoding utf8
Write-Host "Updated $specPath"
