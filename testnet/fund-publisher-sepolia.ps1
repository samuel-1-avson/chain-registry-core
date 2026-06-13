# Transfer Sepolia CREG to publisher EOA (E2E-301 prep).
#
# Usage:
#   .\testnet\fund-publisher-sepolia.ps1 -FromPrivateKey 0x...deployer...
#   .\testnet\fund-publisher-sepolia.ps1   # uses DEPLOYER_KEY from testnet/.env.sepolia

param(
    [string]$RpcUrl = "https://ethereum-sepolia-rpc.publicnode.com",
    [string]$PublisherAddress = "",
    [string]$FromPrivateKey = "",
    [double]$AmountCreg = 2.0,
    [switch]$ViaGovernance
)

function Resolve-SepoliaRpc {
    param([string]$Explicit)
    if ($Explicit -and $Explicit -notmatch 'YOUR_') { return $Explicit }
    foreach ($candidate in @($env:SEPOLIA_RPC_URL, $env:CREG_ETH_RPC)) {
        if (-not $candidate) { continue }
        $c = $candidate.Trim().Trim('"')
        if ($c -match 'YOUR_|/v3/?$|/v3/\s*$') { continue }
        return $c
    }
    return "https://ethereum-sepolia-rpc.publicnode.com"
}

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir

$envFile = Join-Path $scriptDir ".env.sepolia"
if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        if ($_ -match '^\s*([^#\s][^=]*)\s*=\s*(.*)\s*$') {
            $k = $matches[1].Trim()
            $v = $matches[2].Trim().Trim('"')
            if ($v -and $v -notmatch 'YOUR_') {
                Set-Item -Path "Env:$k" -Value $v
            }
        }
    }
}

$senderKey = $FromPrivateKey
if (-not $senderKey) { $senderKey = $env:DEPLOYER_KEY }
if (-not $senderKey) {
    throw @"
No sender key. Set DEPLOYER_KEY in testnet\.env.sepolia (authority wallet from setup-sepolia-authority.ps1), or pass -FromPrivateKey.
"@
}
$RpcUrl = Resolve-SepoliaRpc -Explicit $RpcUrl

$publishEnv = Join-Path $scriptDir ".env.publish.local"
if (-not $PublisherAddress -and (Test-Path $publishEnv)) {
    Get-Content $publishEnv | ForEach-Object {
        if ($_ -match '^\s*CREG_PUBLISHER_ADDRESS\s*=\s*(.+)$') {
            $PublisherAddress = $matches[1].Trim().Trim('"')
        }
    }
}
if (-not $PublisherAddress) {
    $secretsDir = Join-Path $scriptDir "secrets"
    $pubLatest = Join-Path $secretsDir "publisher-stake-latest.key"
    $keyFile = if (Test-Path $pubLatest) { $pubLatest } else {
        Get-ChildItem -Path $secretsDir -Filter "publisher-stake-*.key" -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1 -ExpandProperty FullName
    }
    if ($keyFile) {
        $toolsCast = Join-Path $scriptDir ".tools\foundry\cast.exe"
        $castTmp = if (Test-Path $toolsCast) { $toolsCast } else { (Get-Command cast -ErrorAction Stop).Source }
        $pk = (Get-Content $keyFile -Raw).Trim()
        $pubRaw = & $castTmp wallet address --private-key $pk 2>&1 | Out-String
        if ($pubRaw -match '(0x[a-fA-F0-9]{40})') { $PublisherAddress = $matches[1] }
    }
}
if (-not $PublisherAddress) {
    throw "Set -PublisherAddress or run prepare-sepolia-publish.ps1 (creates .env.publish.local)"
}

$spec = Get-Content (Join-Path $scriptDir "chain-spec.sepolia.json") -Raw | ConvertFrom-Json
$token = $spec.contracts.creg_token
$wei = [bigint]([math]::Floor($AmountCreg * 1e18))

$toolsCast = Join-Path $scriptDir ".tools\foundry\cast.exe"
$castCmd = Get-Command cast -ErrorAction SilentlyContinue
$cast = if (Test-Path $toolsCast) { $toolsCast } elseif ($castCmd) { $castCmd.Source } else { $null }
if (-not $cast) { throw "cast not found" }
$env:FOUNDRY_DISABLE_NIGHTLY_WARNING = "1"

$deployer = (& $cast wallet address --private-key $senderKey 2>&1 | Out-String)
if ($deployer -match '(0x[a-fA-F0-9]{40})') { $deployer = $matches[1] } else { throw "bad sender address: $deployer" }

$manifestPath = Join-Path $repoRoot "contracts\deployments\sepolia-latest.json"
$gov = if (Test-Path $manifestPath) { (Get-Content $manifestPath -Raw | ConvertFrom-Json).governance } else { $null }

$balRaw = & $cast call $token "balanceOf(address)(uint256)" $deployer --rpc-url $RpcUrl 2>&1 | Out-String
$deployerBal = if ($balRaw -match '\b(\d+)\b') { [bigint]$matches[1] } else { [bigint]0 }
$useGovernance = $ViaGovernance -or ($deployerBal -lt $wei)

Write-Host "RPC:       $RpcUrl" -ForegroundColor DarkGray
Write-Host "Publisher: $PublisherAddress"
Write-Host "Token:     $token"
Write-Host "Amount:    $AmountCreg CREG ($wei wei)"

if ($useGovernance) {
    if (-not $gov) { throw "sepolia-latest.json missing; cannot mint via governance" }
    if (-not $env:GOVERNANCE_SIGNER_KEY) { throw "Set GOVERNANCE_SIGNER_KEY in .env.sepolia for -ViaGovernance" }
    $signerKey = $env:GOVERNANCE_SIGNER_KEY.Trim()
    $signerRaw = & $cast wallet address --private-key $signerKey 2>&1 | Out-String
    if ($signerRaw -notmatch '(0x[a-fA-F0-9]{40})') { throw "bad GOVERNANCE_SIGNER_KEY" }
    $signerAddr = $matches[1]
    Write-Host "Mode:      governance mint (authority CREG balance is $deployerBal wei)" -ForegroundColor Yellow
    Write-Host "Signer:    $signerAddr" -ForegroundColor Cyan
    Write-Host ""

    $calldata = (& $cast calldata "mint(address,uint256)" $PublisherAddress $wei 2>&1 | Out-String).Trim()
    $propRaw = & $cast call $gov "proposalCount()(uint256)" --rpc-url $RpcUrl 2>&1 | Out-String
    $proposalId = if ($propRaw -match '\b(\d+)\b') { $matches[1] } else { throw "proposalCount failed" }

    & $cast send $gov "submit(address,bytes,string)" $token $calldata "mint CREG to publisher for stake" `
        --private-key $signerKey --rpc-url $RpcUrl
    if ($LASTEXITCODE -ne 0) { throw "governance submit failed" }
    & $cast send $gov "vote(uint256,bool)" $proposalId true --private-key $signerKey --rpc-url $RpcUrl
    if ($LASTEXITCODE -ne 0) { throw "governance vote failed" }
    Start-Sleep -Seconds 3
} else {
    Write-Host "From:      $deployer" -ForegroundColor Cyan
    Write-Host "Mode:      transfer" -ForegroundColor DarkGray
    Write-Host ""
    & $cast send $token "transfer(address,uint256)" $PublisherAddress $wei `
        --private-key $senderKey --rpc-url $RpcUrl
    if ($LASTEXITCODE -ne 0) { throw "CREG transfer failed" }
}

$pubBal = (& $cast call $token "balanceOf(address)(uint256)" $PublisherAddress --rpc-url $RpcUrl 2>&1 | Out-String).Trim()
Write-Host ""
Write-Host "OK. Publisher CREG balance: $pubBal" -ForegroundColor Green
Write-Host ""
Write-Host "Then stake (publisher key file):"
Write-Host "  .\testnet\stake-publisher-sepolia.ps1 -PublisherKeyFile .\testnet\secrets\publisher-stake-latest.key"
Write-Host "  .\testnet\check-publisher-stake.ps1 -PublisherAddress $PublisherAddress"
