# One Sepolia authority wallet: same key for deploy + governance (threshold 1).
# Use this instead of the lost 0xf4c0... deployer. Does NOT touch old contracts.
#
# Usage:
#   .\testnet\setup-sepolia-authority.ps1              # reuse governance-signer-sepolia-latest.key
#   .\testnet\setup-sepolia-authority.ps1 -Force       # generate a brand-new authority key
#
# Then redeploy (new contract addresses):
#   .\testnet\deploy-sepolia-new-authority.ps1

param([switch]$Force)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$secretsDir = Join-Path $scriptDir "secrets"
$envFile = Join-Path $scriptDir ".env.sepolia"
New-Item -ItemType Directory -Force -Path $secretsDir | Out-Null

$govLatest = Join-Path $secretsDir "governance-signer-sepolia-latest.key"
$authLatest = Join-Path $secretsDir "sepolia-authority-latest.key"
$addrLatest = Join-Path $secretsDir "sepolia-authority-latest.address.txt"

$cast = Join-Path $scriptDir ".tools\foundry\cast.exe"
if (-not (Test-Path $cast)) { $cast = (Get-Command cast -ErrorAction Stop).Source }
$env:FOUNDRY_DISABLE_NIGHTLY_WARNING = "1"

function Set-EnvLine {
    param([string[]]$Lines, [string]$Name, [string]$Value)
    $out = New-Object System.Collections.Generic.List[string]
    $replaced = $false
    foreach ($line in $Lines) {
        if ($line -match "^\s*#?\s*$([regex]::Escape($Name))\s*=") {
            if (-not $replaced) {
                $out.Add("$Name=$Value")
                $replaced = $true
            }
            continue
        }
        $out.Add($line)
    }
    if (-not $replaced) {
        $out.Add("")
        $out.Add("# Sepolia authority (setup-sepolia-authority.ps1) - deploy + governance")
        $out.Add("$Name=$Value")
    }
    return $out
}

$hex = $null
if (-not $Force -and (Test-Path $authLatest)) {
    $hex = (Get-Content $authLatest -Raw).Trim()
} elseif (-not $Force -and (Test-Path $govLatest)) {
    $hex = (Get-Content $govLatest -Raw).Trim()
    Write-Host "Reusing governance-signer-sepolia-latest.key as Sepolia authority." -ForegroundColor DarkGray
} else {
    $bytes = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $hex = "0x" + ([BitConverter]::ToString($bytes) -replace "-", "").ToLower()
    Write-Host "Generated new Sepolia authority key." -ForegroundColor Cyan
}

$raw = (& $cast wallet address --private-key $hex 2>&1 | Out-String)
if ($raw -notmatch '(0x[a-fA-F0-9]{40})') { throw "Could not derive address from authority key" }
$address = $matches[1]

$ts = Get-Date -Format "yyyyMMdd-HHmmss"
Set-Content -Path $authLatest -Value $hex -Encoding utf8 -NoNewline
Set-Content -Path $addrLatest -Value $address -Encoding utf8
Set-Content -Path (Join-Path $secretsDir "sepolia-authority-$ts.key") -Value $hex -Encoding utf8 -NoNewline
Set-Content -Path (Join-Path $secretsDir "governance-signer-sepolia-latest.key") -Value $hex -Encoding utf8 -NoNewline
Set-Content -Path (Join-Path $secretsDir "governance-signer-sepolia-latest.address.txt") -Value $address -Encoding utf8
try { icacls $authLatest /inheritance:r /grant:r "${env:USERNAME}:(R,W)" | Out-Null } catch { }

$lines = if (Test-Path $envFile) { Get-Content $envFile } else { Get-Content (Join-Path $scriptDir ".env.sepolia.example") }
$lines = Set-EnvLine -Lines $lines -Name "DEPLOYER_KEY" -Value $hex
$lines = Set-EnvLine -Lines $lines -Name "GOVERNANCE_SIGNER_KEY" -Value $hex
$lines = Set-EnvLine -Lines $lines -Name "GOVERNANCE_SIGNER_ADDRESS" -Value $address
$lines = Set-EnvLine -Lines $lines -Name "GOVERNANCE_THRESHOLD" -Value "1"
if (-not ($lines -join "`n" -match '^\s*SEPOLIA_RPC_URL\s*=')) {
    $lines = Set-EnvLine -Lines $lines -Name "SEPOLIA_RPC_URL" -Value "https://ethereum-sepolia-rpc.publicnode.com"
}
$lines | Set-Content -Path $envFile -Encoding utf8

Write-Host ""
Write-Host "=== Sepolia authority (single wallet) ===" -ForegroundColor Cyan
Write-Host "Address:     $address" -ForegroundColor Green
Write-Host "Key file:    $authLatest"
Write-Host "Env:         $envFile"
Write-Host "  DEPLOYER_KEY = GOVERNANCE_SIGNER_KEY (same wallet)"
Write-Host "  GOVERNANCE_THRESHOLD = 1"
Write-Host ""
Write-Host "Fund this address with Sepolia ETH, then:" -ForegroundColor Yellow
Write-Host "  .\testnet\deploy-sepolia-new-authority.ps1"
Write-Host ""
Write-Host "Old deployment 0xf4c0 is NOT used. Redeploy creates new contracts." -ForegroundColor DarkGray
Write-Host "Private key is NOT printed. Back up $authLatest securely." -ForegroundColor DarkGray
