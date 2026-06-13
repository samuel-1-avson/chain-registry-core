# Generate a NEW Sepolia governance signer key and save to secrets + testnet/.env.sepolia.
#
# Preferred path (no lost deployer): unify deploy + governance and redeploy:
#   .\testnet\setup-sepolia-authority.ps1
#   .\testnet\deploy-sepolia-new-authority.ps1
#
# Only if you still control the OLD 0xf4c0... deployer key on the existing deployment:
#   .\testnet\register-governance-signer-sepolia.ps1 -LegacyDeployerKey 0x...
#
# Usage:
#   .\testnet\setup-governance-signer-sepolia.ps1
#   .\testnet\setup-governance-signer-sepolia.ps1 -Force

param(
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$secretsDir = Join-Path $scriptDir "secrets"
$envFile = Join-Path $scriptDir ".env.sepolia"
New-Item -ItemType Directory -Force -Path $secretsDir | Out-Null

$keyLatest = Join-Path $secretsDir "governance-signer-sepolia-latest.key"
$addrLatest = Join-Path $secretsDir "governance-signer-sepolia-latest.address.txt"

if ((Test-Path $keyLatest) -and (Test-Path $envFile) -and -not $Force) {
    $existing = (Get-Content $addrLatest -Raw).Trim()
    Write-Host "Governance signer already set up ($existing). Use -Force to rotate." -ForegroundColor Yellow
    exit 0
}

$bytes = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$hex = "0x" + ([BitConverter]::ToString($bytes) -replace "-", "").ToLower()

$cast = Join-Path $scriptDir ".tools\foundry\cast.exe"
if (-not (Test-Path $cast)) { $cast = (Get-Command cast -ErrorAction Stop).Source }
$env:FOUNDRY_DISABLE_NIGHTLY_WARNING = "1"
$raw = (& $cast wallet address --private-key $hex 2>&1 | Out-String)
if ($raw -notmatch '(0x[a-fA-F0-9]{40})') { throw "Could not derive address" }
$address = $matches[1]

$ts = Get-Date -Format "yyyyMMdd-HHmmss"
$keyFile = Join-Path $secretsDir "governance-signer-sepolia-$ts.key"
Set-Content -Path $keyFile -Value $hex -Encoding utf8 -NoNewline
Set-Content -Path $keyLatest -Value $hex -Encoding utf8 -NoNewline
Set-Content -Path $addrLatest -Value $address -Encoding utf8
Set-Content -Path (Join-Path $secretsDir "governance-signer-sepolia-$ts.address.txt") -Value $address -Encoding utf8
try { icacls $keyLatest /inheritance:r /grant:r "${env:USERNAME}:(R,W)" | Out-Null } catch { }

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
        $out.Add("# Governance signer (setup-governance-signer-sepolia.ps1)")
        $out.Add("$Name=$Value")
    }
    return $out
}

$lines = if (Test-Path $envFile) { Get-Content $envFile } else { Get-Content (Join-Path $scriptDir ".env.sepolia.example") }
$lines = Set-EnvLine -Lines $lines -Name "GOVERNANCE_SIGNER_KEY" -Value $hex
$lines = Set-EnvLine -Lines $lines -Name "GOVERNANCE_SIGNER_ADDRESS" -Value $address
if (-not ($lines -join "`n" -match '^\s*SEPOLIA_RPC_URL\s*=')) {
    $lines = Set-EnvLine -Lines $lines -Name "SEPOLIA_RPC_URL" -Value "https://ethereum-sepolia-rpc.publicnode.com"
}
$lines | Set-Content -Path $envFile -Encoding utf8

Write-Host ""
Write-Host "=== New governance signer (Sepolia) ===" -ForegroundColor Cyan
Write-Host "Address:  $address" -ForegroundColor Green
Write-Host "Key file: $keyLatest"
Write-Host "Env:      $envFile (GOVERNANCE_SIGNER_KEY set)"
Write-Host ""
Write-Host "Private key is NOT printed. Back up the key file to a password manager." -ForegroundColor DarkGray
Write-Host ""
Write-Host "On-chain status:" -ForegroundColor Yellow
Write-Host "  Not a signer on the OLD deployment until you register or redeploy."
Write-Host ""
Write-Host "Next (recommended — new authority, safe key you hold):" -ForegroundColor Cyan
Write-Host "  .\testnet\setup-sepolia-authority.ps1"
Write-Host "  .\testnet\deploy-sepolia-new-authority.ps1"
Write-Host ""
