# Check whether a private key is a governance signer on Sepolia.
#
# Usage:
#   .\testnet\check-governance-signer.ps1 -PrivateKey 0xYOUR_KEY
#   .\testnet\check-governance-signer.ps1   # reads GOVERNANCE_SIGNER_KEY from .env.sepolia

param(
    [string]$PrivateKey = "",
    [string]$RpcUrl = "https://ethereum-sepolia-rpc.publicnode.com"
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$sepoliaEnv = Join-Path $scriptDir ".env.sepolia"

if (-not $PrivateKey -and (Test-Path $sepoliaEnv)) {
    Get-Content $sepoliaEnv | ForEach-Object {
        if ($_ -match '^\s*GOVERNANCE_SIGNER_KEY\s*=\s*(.+)\s*$') {
            $PrivateKey = $matches[1].Trim().Trim('"')
        }
    }
}
if (-not $PrivateKey) {
    throw "Pass -PrivateKey or set GOVERNANCE_SIGNER_KEY in testnet\.env.sepolia"
}

$manifest = Get-Content (Join-Path (Split-Path -Parent $scriptDir) "contracts\deployments\sepolia-latest.json") -Raw | ConvertFrom-Json
$gov = $manifest.governance

$cast = Join-Path $scriptDir ".tools\foundry\cast.exe"
if (-not (Test-Path $cast)) { $cast = (Get-Command cast -ErrorAction Stop).Source }
$env:FOUNDRY_DISABLE_NIGHTLY_WARNING = "1"

$addrRaw = & $cast wallet address --private-key $PrivateKey 2>&1 | Out-String
if ($addrRaw -notmatch '(0x[a-fA-F0-9]{40})') { throw "Invalid key" }
$addr = $matches[1]

$isRaw = & $cast call $gov "isSigner(address)(bool)" $addr --rpc-url $RpcUrl 2>&1 | Out-String
$threshRaw = & $cast call $gov "threshold()(uint256)" --rpc-url $RpcUrl 2>&1 | Out-String
$signer0 = & $cast call $gov "signers(uint256)(address)" 0 --rpc-url $RpcUrl 2>&1 | Out-String

Write-Host ""
Write-Host "Governance: $gov"
Write-Host "Your address: $addr"
Write-Host "isSigner:     $($isRaw.Trim())"
Write-Host "threshold:    $($threshRaw.Trim())"
Write-Host "signers[0]:   $(if ($signer0 -match '(0x[a-fA-F0-9]{40})') { $matches[1] } else { '?' })"
Write-Host ""
if ($isRaw -match 'true') {
    Write-Host "OK - you can run .\testnet\fund-sepolia-faucet-governance.ps1" -ForegroundColor Green
} else {
    Write-Host "This key is NOT a governance signer. Mint via governance will fail." -ForegroundColor Yellow
    Write-Host "Ask whoever controls the deployer/signer wallet, or get CREG sent directly to your publisher/faucet address."
}
Write-Host ""
