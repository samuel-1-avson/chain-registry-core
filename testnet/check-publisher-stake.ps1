# Check on-chain publisher stake for E2E-301 (Sepolia).
#
# Usage:
#   .\testnet\check-publisher-stake.ps1
#   .\testnet\check-publisher-stake.ps1 -PublisherAddress 0x...

param(
    [string]$RpcUrl = "https://ethereum-sepolia-rpc.publicnode.com",
    [string]$PublisherAddress = ""
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

$specPath = Join-Path $scriptDir "chain-spec.sepolia.json"
$spec = Get-Content $specPath -Raw | ConvertFrom-Json
$staking = $spec.contracts.staking
$token = $spec.contracts.creg_token

$publishEnv = Join-Path $scriptDir ".env.publish.local"
if (-not $PublisherAddress -and (Test-Path $publishEnv)) {
    Get-Content $publishEnv | ForEach-Object {
        if ($_ -match '^\s*CREG_PUBLISHER_ADDRESS\s*=\s*(.+)$') {
            $PublisherAddress = $matches[1].Trim().Trim('"')
        }
    }
}
if (-not $PublisherAddress) {
    throw "Set -PublisherAddress or run prepare-sepolia-publish.ps1 first (writes .env.publish.local)"
}

$toolsCast = Join-Path $scriptDir ".tools\foundry\cast.exe"
$castCmd = Get-Command cast -ErrorAction SilentlyContinue
$cast = if (Test-Path $toolsCast) { $toolsCast } elseif ($castCmd) { $castCmd.Source } else { $null }
if (-not $cast) { throw "cast not found. Run .\testnet\install-foundry.ps1" }

$env:FOUNDRY_DISABLE_NIGHTLY_WARNING = "1"
function Invoke-CastCall {
    param([string[]]$CastArgs)
    $raw = & $cast @CastArgs 2>&1 | Out-String
    if ($raw -match '\b(\d+)\b') { return $matches[1] }
    return $raw.Trim()
}

$staked = Invoke-CastCall -CastArgs @(
    "call", $staking, "stakedBalance(address)(uint256)", $PublisherAddress, "--rpc-url", $RpcUrl
)
$bal = Invoke-CastCall -CastArgs @(
    "call", $token, "balanceOf(address)(uint256)", $PublisherAddress, "--rpc-url", $RpcUrl
)
$ethRaw = & $cast balance $PublisherAddress --rpc-url $RpcUrl 2>&1 | Out-String
$ethWei = if ($ethRaw -match '\b(\d+)\b') { $matches[1] } else { "?" }

Write-Host ""
Write-Host "Publisher: $PublisherAddress" -ForegroundColor Cyan
Write-Host "ETH bal:   $ethWei wei (need > 0 for approve/stake gas)"
Write-Host "CREG bal:  $bal wei (need >= 1000000000000000000 for approve + 1 CREG stake)"
Write-Host "Staked:    $staked wei (need >= 1000000000000000000 after stake)"
Write-Host ""
$ethNum = [bigint]0
if ($ethWei -ne "?") { [void][bigint]::TryParse($ethWei, [ref]$ethNum) }
if ($ethNum -eq 0) {
    Write-Host "Get Sepolia ETH: https://www.alchemy.com/faucets/ethereum-sepolia" -ForegroundColor Yellow
}
$balNum = [bigint]0
[void][bigint]::TryParse($bal, [ref]$balNum)
if ($balNum -lt 1000000000000000000) {
    Write-Host "Get CREG: .\testnet\fund-publisher-sepolia.ps1 (needs DEPLOYER_KEY in .env.sepolia)" -ForegroundColor Yellow
    Write-Host "  Or ask deployer 0xf4c0bdBB681A61Aa0B123E82C04b0d692F53D58e to transfer CREG."
}
Write-Host ""

$stakedNum = [bigint]0
[void][bigint]::TryParse($staked, [ref]$stakedNum)
if ($stakedNum -ge 1000000000000000000) {
    Write-Host "OK - publisher has minimum stake. Re-run .\testnet\run-ops-201-verify.ps1 -Force" -ForegroundColor Green
    exit 0
}

Write-Host "Not staked yet. Run approve + stakeAsPublisher from prepare-sepolia-publish.ps1 output." -ForegroundColor Yellow
Write-Host "You need Sepolia ETH (gas) and >= 1 CREG token on this address."
exit 1
