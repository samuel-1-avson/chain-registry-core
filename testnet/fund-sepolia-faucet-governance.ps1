# Mint CREG to the new Sepolia faucet via governance (token owner = governance multisig).
#
# Requires at least one private key that is a governance signer on Sepolia.
# Set in testnet/.env.sepolia (not committed):
#   GOVERNANCE_SIGNER_KEY=0x...
# Optional second signer if threshold is 2:
#   GOVERNANCE_SIGNER_KEY_2=0x...
#
# Usage:
#   .\testnet\fund-sepolia-faucet-governance.ps1
#   .\testnet\fund-sepolia-faucet-governance.ps1 -MintCreg 500000

param(
    [UInt64]$MintCreg = 500000,
    [string]$RpcUrl = "https://ethereum-sepolia-rpc.publicnode.com",
    [string]$FaucetAddress = ""
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$faucetEnv = Join-Path $scriptDir ".env.sepolia.faucet"
$sepoliaEnv = Join-Path $scriptDir ".env.sepolia"

function Import-DotEnv {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return }
    Get-Content $Path | ForEach-Object {
        if ($_ -match '^\s*([^#\s][^=]*)\s*=\s*(.*)\s*$') {
            [Environment]::SetEnvironmentVariable($matches[1].Trim(), $matches[2].Trim().Trim('"'), "Process")
        }
    }
}

Import-DotEnv $faucetEnv
Import-DotEnv $sepoliaEnv

if ($FaucetAddress) {
    $env:FAUCET_ADDRESS = $FaucetAddress.Trim()
}
if (-not $env:FAUCET_ADDRESS) {
    throw "Run .\testnet\setup-sepolia-faucet.ps1 first (creates .env.sepolia.faucet), or pass -FaucetAddress"
}

$signerKeys = @()
if ($env:GOVERNANCE_SIGNER_KEY) { $signerKeys += $env:GOVERNANCE_SIGNER_KEY.Trim() }
if ($env:GOVERNANCE_SIGNER_KEY_2) { $signerKeys += $env:GOVERNANCE_SIGNER_KEY_2.Trim() }
if ($env:CREG_BRIDGE_KEY -and $signerKeys -notcontains $env:CREG_BRIDGE_KEY.Trim()) {
    $signerKeys += $env:CREG_BRIDGE_KEY.Trim()
}

if ($signerKeys.Count -eq 0) {
    throw @"
No governance signer keys in testnet\.env.sepolia.
Add GOVERNANCE_SIGNER_KEY=0x... (must be an address listed in Governance signers on Sepolia).
If deploy used threshold 2, also set GOVERNANCE_SIGNER_KEY_2.
"@
}

$repoRoot = Split-Path -Parent $scriptDir
$manifestPath = Join-Path $repoRoot "contracts\deployments\sepolia-latest.json"
$manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
$gov = $manifest.governance
$token = $manifest.cregToken
$faucet = $env:FAUCET_ADDRESS
$mintWei = [bigint]($MintCreg * [bigint]::Pow(10, 18))

$cast = Join-Path $scriptDir ".tools\foundry\cast.exe"
if (-not (Test-Path $cast)) { $cast = (Get-Command cast -ErrorAction Stop).Source }
$env:FOUNDRY_DISABLE_NIGHTLY_WARNING = "1"

$thresholdRaw = & $cast call $gov "threshold()(uint256)" --rpc-url $RpcUrl 2>&1 | Out-String
$threshold = if ($thresholdRaw -match '\b(\d+)\b') { [int]$matches[1] } else { 2 }

Write-Host ""
Write-Host "Governance: $gov" -ForegroundColor Cyan
Write-Host "Token:      $token"
Write-Host "Faucet:     $faucet"
Write-Host "Mint:       $MintCreg CREG ($mintWei wei)"
Write-Host "Threshold:  $threshold"
Write-Host ""

$validSigners = @()
foreach ($key in $signerKeys) {
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    $addrRaw = (& $cast wallet address --private-key $key 2>&1 | Out-String).Trim()
    $ErrorActionPreference = $prevEap
    if ($addrRaw -notmatch '(0x[a-fA-F0-9]{40})') {
        Write-Host "Skip (invalid private key in env)" -ForegroundColor DarkYellow
        continue
    }
    $addr = $matches[1]
    $isRaw = & $cast call $gov "isSigner(address)(bool)" $addr --rpc-url $RpcUrl 2>&1 | Out-String
    if ($isRaw -match 'true') {
        $validSigners += @{ Key = $key; Address = $addr }
        Write-Host "Signer OK: $addr" -ForegroundColor Green
    } else {
        Write-Host "Skip (not a governance signer): $addr" -ForegroundColor DarkYellow
    }
}

if ($validSigners.Count -eq 0) {
    throw "None of the configured keys are governance signers on $gov"
}

$calldata = & $cast calldata "mint(address,uint256)" $faucet $mintWei 2>&1 | Out-String
$calldata = $calldata.Trim()
if ($calldata -notmatch '^0x') { throw "Failed to encode mint calldata: $calldata" }

$propRaw = & $cast call $gov "proposalCount()(uint256)" --rpc-url $RpcUrl 2>&1 | Out-String
$proposalId = if ($propRaw -match '\b(\d+)\b') { $matches[1] } else { throw "proposalCount failed" }

$submitter = $validSigners[0]
Write-Host "Submitting proposal $proposalId from $($submitter.Address)..." -ForegroundColor Yellow
& $cast send $gov "submit(address,bytes,string)" $token $calldata "mint Sepolia faucet reserve" `
    --private-key $submitter.Key --rpc-url $RpcUrl
if ($LASTEXITCODE -ne 0) { throw "submit failed" }

$votesNeeded = [Math]::Min($threshold, $validSigners.Count)
for ($i = 0; $i -lt $votesNeeded; $i++) {
    $s = $validSigners[$i]
    Write-Host "Vote approve on proposal $proposalId from $($s.Address)..." -ForegroundColor Yellow
    & $cast send $gov "vote(uint256,bool)" $proposalId true --private-key $s.Key --rpc-url $RpcUrl
    if ($LASTEXITCODE -ne 0) { throw "vote failed" }
}

Start-Sleep -Seconds 3
$balRaw = & $cast call $token "balanceOf(address)(uint256)" $faucet --rpc-url $RpcUrl 2>&1 | Out-String
Write-Host ""
Write-Host "Faucet CREG balance: $($balRaw.Trim())" -ForegroundColor Green
Write-Host "Start drip service: .\testnet\start-sepolia-faucet.ps1"
Write-Host ""
