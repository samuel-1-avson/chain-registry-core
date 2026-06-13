# Emergency governance path: approve a Pending staking applicant on Sepolia.
# Use when activeValidatorCount is 0 and approveByConsensus cannot run yet.
#
# Requires a governance signer key in testnet/.env.sepolia (GOVERNANCE_SIGNER_KEY or DEPLOYER_KEY).
#
# Usage:
#   .\testnet\approve-validator-governance-sepolia.ps1 -Applicant 0x5A336471567fA312d81CA6Fe30DC9851C47D3394
#   .\testnet\approve-validator-governance-sepolia.ps1 -Applicant 0x... -CheckOnly

param(
    [Parameter(Mandatory = $true)]
    [string]$Applicant,
    [string]$RpcUrl = "",
    [string]$GovernanceSignerKey = "",
    [switch]$CheckOnly
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
Set-Location $repoRoot

function Import-DotEnv {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return }
    Get-Content $Path | ForEach-Object {
        if ($_ -match '^\s*([^#\s][^=]*)\s*=\s*(.*)\s*$') {
            $k = $matches[1].Trim()
            $v = $matches[2].Trim().Trim('"')
            if ($v -and $v -notmatch 'YOUR_') {
                Set-Item -Path "Env:$k" -Value $v
            }
        }
    }
}

Import-DotEnv (Join-Path $scriptDir "sepolia-3node.env")
Import-DotEnv (Join-Path $scriptDir ".env.sepolia")

if (-not $RpcUrl) {
    $RpcUrl = $env:CREG_ETH_RPC
    if (-not $RpcUrl) { $RpcUrl = $env:SEPOLIA_RPC_URL }
}
if (-not $RpcUrl) { throw "Set CREG_ETH_RPC in testnet/sepolia-3node.env" }

if (-not $GovernanceSignerKey) {
    $GovernanceSignerKey = $env:GOVERNANCE_SIGNER_KEY
    if (-not $GovernanceSignerKey) { $GovernanceSignerKey = $env:DEPLOYER_KEY }
}
if (-not $GovernanceSignerKey) {
    throw "Set GOVERNANCE_SIGNER_KEY or DEPLOYER_KEY in testnet/.env.sepolia"
}
$GovernanceSignerKey = $GovernanceSignerKey.Trim()

$manifestPath = Join-Path $repoRoot "contracts\deployments\sepolia-latest.json"
if (-not (Test-Path $manifestPath)) { throw "Missing $manifestPath" }
$manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
$gov = $manifest.governance
$staking = $manifest.staking

$toolsCast = Join-Path $scriptDir ".tools\foundry\cast.exe"
$castCmd = Get-Command cast -ErrorAction SilentlyContinue
$cast = if (Test-Path $toolsCast) { $toolsCast } elseif ($castCmd) { $castCmd.Source } else { $null }
if (-not $cast) { throw "cast not found" }
$env:FOUNDRY_DISABLE_NIGHTLY_WARNING = "1"

$Applicant = $Applicant.Trim()
if ($Applicant -notmatch '^0x[a-fA-F0-9]{40}$') { throw "Invalid -Applicant address" }

function Get-ValidatorState {
    param([string]$Addr)
    $jsonRaw = & $cast call $staking "validators(address)(uint256,uint8,uint256,uint256,uint256,uint256)" $Addr `
        --rpc-url $RpcUrl --json 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0 -and $jsonRaw.Trim().StartsWith("[")) {
        $tuple = $jsonRaw.Trim() | ConvertFrom-Json
        if ($tuple.Count -ge 2) { return @{ stake = [string]$tuple[0]; state = [int]$tuple[1] } }
    }
    return $null
}

$emergencyRaw = & $cast call $staking "emergencyGovernanceEnabled()(bool)" --rpc-url $RpcUrl 2>&1 | Out-String
if ($emergencyRaw -notmatch 'true') {
    throw "emergencyGovernanceEnabled is false; use consensus admission instead"
}

$vs = Get-ValidatorState -Addr $Applicant
$stateNames = @{ 0 = "None"; 1 = "Pending"; 2 = "Active" }
$stateLabel = if ($vs) { $stateNames[$vs.state] } else { "unknown" }

Write-Host ""
Write-Host "=== Governance approveValidator (Sepolia) ===" -ForegroundColor Cyan
Write-Host "Applicant: $Applicant ($stateLabel)"
Write-Host "Staking:   $staking"
Write-Host "Governance:$gov"
Write-Host "RPC:       $RpcUrl"
Write-Host ""

if ($vs -and $vs.state -eq 2) {
    Write-Host "Already Active on L1." -ForegroundColor Green
    exit 0
}
if (-not $vs -or $vs.state -ne 1) {
    throw "Applicant must be Pending (state 1); got $stateLabel"
}
if ($CheckOnly) { exit 0 }

$signerRaw = & $cast wallet address --private-key $GovernanceSignerKey 2>&1 | Out-String
if ($signerRaw -notmatch '(0x[a-fA-F0-9]{40})') { throw "Invalid governance signer key" }
$signerAddr = $matches[1]
Write-Host "Signer:    $signerAddr" -ForegroundColor DarkGray

$calldata = (& $cast calldata "approveValidator(address)" $Applicant 2>&1 | Out-String).Trim()
$propRaw = & $cast call $gov "proposalCount()(uint256)" --rpc-url $RpcUrl 2>&1 | Out-String
$proposalId = if ($propRaw -match '\b(\d+)\b') { $matches[1] } else { throw "proposalCount failed" }

Write-Host "Submitting governance proposal $proposalId ..." -ForegroundColor Cyan
& $cast send $gov "submit(address,bytes,string)" $staking $calldata "approve validator $Applicant" `
    --private-key $GovernanceSignerKey --rpc-url $RpcUrl
if ($LASTEXITCODE -ne 0) { throw "governance submit failed" }
& $cast send $gov "vote(uint256,bool)" $proposalId true --private-key $GovernanceSignerKey --rpc-url $RpcUrl
if ($LASTEXITCODE -ne 0) { throw "governance vote failed" }

Start-Sleep -Seconds 4
$after = Get-ValidatorState -Addr $Applicant
if ($after -and $after.state -eq 2) {
    Write-Host "OK. Applicant is Active on L1." -ForegroundColor Green
} else {
    Write-Host "Proposal submitted; poll with register-validator-2-sepolia.ps1 -CheckOnly" -ForegroundColor Yellow
}
