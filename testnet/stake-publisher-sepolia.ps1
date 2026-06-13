# Approve + stakeAsPublisher on Sepolia without printing the private key.
#
# Usage:
#   .\testnet\stake-publisher-sepolia.ps1 -PublisherKeyFile .\testnet\secrets\publisher-stake-latest.key
#   .\testnet\stake-publisher-sepolia.ps1 -PublisherKeyFile .\testnet\secrets\publisher-stake-20260530-040213.key

param(
    [Parameter(Mandatory = $true)]
    [string]$PublisherKeyFile,
    [string]$RpcUrl = "https://ethereum-sepolia-rpc.publicnode.com",
    [double]$StakeAmountEth = 1.0,
    [switch]$ApproveOnly,
    [switch]$StakeOnly
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not (Test-Path $PublisherKeyFile)) { throw "Key file not found: $PublisherKeyFile" }

$PublisherKey = (Get-Content $PublisherKeyFile -Raw).Trim()
if ($PublisherKey -notmatch '^0x[a-fA-F0-9]{64}$') { throw "Key file must contain 0x + 64 hex chars" }

$spec = Get-Content (Join-Path $scriptDir "chain-spec.sepolia.json") -Raw | ConvertFrom-Json
$token = $spec.contracts.creg_token
$staking = $spec.contracts.staking
$wei = [bigint]([math]::Floor($StakeAmountEth * 1e18))

$toolsCast = Join-Path $scriptDir ".tools\foundry\cast.exe"
$cast = if (Test-Path $toolsCast) { $toolsCast } else { (Get-Command cast -ErrorAction Stop).Source }
$env:FOUNDRY_DISABLE_NIGHTLY_WARNING = "1"

$raw = (& $cast wallet address --private-key $PublisherKey 2>&1 | Out-String)
if ($raw -notmatch '(0x[a-fA-F0-9]{40})') { throw "Could not derive publisher address" }
$pubAddr = $matches[1]

Write-Host ""
Write-Host "Publisher: $pubAddr" -ForegroundColor Cyan
Write-Host "Stake:     $StakeAmountEth CREG ($wei wei)"
Write-Host ""

$balRaw = & $cast call $token "balanceOf(address)(uint256)" $pubAddr --rpc-url $RpcUrl 2>&1 | Out-String
$balWei = if ($balRaw -match '\b(\d+)\b') { [bigint]$matches[1] } else { [bigint]0 }
Write-Host "CREG balance: $balWei wei"
if ($balWei -lt $wei -and -not $ApproveOnly) {
    throw @"
CREG balance ($balWei wei) is below stake amount ($wei wei).
Send at least $StakeAmountEth CREG to $pubAddr on Sepolia, then re-run.
Note: approve() can succeed even with zero balance; only stake transfers tokens.
"@
}

if (-not $StakeOnly) {
    Write-Host "Sending approve..." -ForegroundColor Yellow
    & $cast send $token "approve(address,uint256)" $staking $wei --private-key $PublisherKey --rpc-url $RpcUrl
    if ($LASTEXITCODE -ne 0) { throw "approve failed (exit $LASTEXITCODE). Need CREG balance >= stake amount." }
}

if (-not $ApproveOnly) {
    Write-Host "Sending stakeAsPublisher..." -ForegroundColor Yellow
    & $cast send $staking "stakeAsPublisher(uint256)" $wei --private-key $PublisherKey --rpc-url $RpcUrl
    if ($LASTEXITCODE -ne 0) { throw "stakeAsPublisher failed (exit $LASTEXITCODE)" }
}

Write-Host ""
Write-Host "Done. Verify:" -ForegroundColor Green
Write-Host "  .\testnet\check-publisher-stake.ps1 -PublisherAddress $pubAddr"
Write-Host ""
