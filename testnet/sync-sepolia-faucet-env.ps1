# Point .env.sepolia.faucet at the current Sepolia CREG token (after redeploy).
#
# Usage:
#   .\testnet\sync-sepolia-faucet-env.ps1

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$envFile = Join-Path $scriptDir ".env.sepolia.faucet"
$manifestPath = Join-Path $repoRoot "contracts\deployments\sepolia-latest.json"
$specPath = Join-Path $scriptDir "chain-spec.sepolia.json"

if (-not (Test-Path $envFile)) {
    throw "Missing $envFile. Run .\testnet\setup-sepolia-faucet.ps1"
}

$token = $null
if (Test-Path $manifestPath) {
    $token = (Get-Content $manifestPath -Raw | ConvertFrom-Json).cregToken
} elseif (Test-Path $specPath) {
    $token = (Get-Content $specPath -Raw | ConvertFrom-Json).contracts.creg_token
} else {
    throw "No sepolia-latest.json or chain-spec.sepolia.json"
}

$lines = Get-Content $envFile
$out = New-Object System.Collections.Generic.List[string]
$replaced = $false
$oldToken = $null
foreach ($line in $lines) {
    if ($line -match '^\s*FAUCET_TOKEN_CONTRACT\s*=\s*(.+)\s*$') {
        $oldToken = $matches[1].Trim()
        if (-not $replaced) {
            $out.Add("FAUCET_TOKEN_CONTRACT=$token")
            $replaced = $true
        }
        continue
    }
    $out.Add($line)
}
if (-not $replaced) { $out.Add("FAUCET_TOKEN_CONTRACT=$token") }
$out | Set-Content -Path $envFile -Encoding utf8

if ($oldToken -and ($oldToken.ToLower() -ne $token.ToLower())) {
    Write-Host "Updated FAUCET_TOKEN_CONTRACT" -ForegroundColor Green
    Write-Host "  was: $oldToken"
    Write-Host "  now: $token"
} else {
    Write-Host "FAUCET_TOKEN_CONTRACT already current: $token" -ForegroundColor Green
}
