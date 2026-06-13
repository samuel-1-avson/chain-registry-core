# LEGACY ONLY — updates the OLD Sepolia deployment (0xf4c0... deployer).
# If you do not want the old deployer, use deploy-sepolia-new-authority.ps1 instead.
#
# Add GOVERNANCE_SIGNER_ADDRESS from .env.sepolia as an on-chain governance signer.
# Requires the CURRENT on-chain signer's PRIVATE KEY (legacy deployer 0xf4c0...).
#
# NOT the new GOVERNANCE_SIGNER_KEY and NOT an Ethereum address.
#
# Usage:
#   .\testnet\setup-governance-signer-sepolia.ps1
#   .\testnet\register-governance-signer-sepolia.ps1 -LegacyDeployerKey 0x<64_hex_private_key>
#   .\testnet\register-governance-signer-sepolia.ps1 -LegacyDeployerKeyFile .\path\to\deployer.key
#
# Optional: remove old signer after adding new (only if threshold allows):
#   .\testnet\register-governance-signer-sepolia.ps1 -LegacyDeployerKey 0x... -RemoveLegacySigner

param(
    [string]$LegacyDeployerKey,
    [string]$LegacyDeployerKeyFile,
    [string]$RpcUrl = "https://ethereum-sepolia-rpc.publicnode.com",
    [switch]$RemoveLegacySigner
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$envFile = Join-Path $scriptDir ".env.sepolia"

function Import-DotEnv {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return }
    Get-Content $Path | ForEach-Object {
        if ($_ -match '^\s*([^#\s][^=]*)\s*=\s*(.*)\s*$') {
            [Environment]::SetEnvironmentVariable($matches[1].Trim(), $matches[2].Trim().Trim('"'), "Process")
        }
    }
}

Import-DotEnv $envFile
$newAddr = $env:GOVERNANCE_SIGNER_ADDRESS
if (-not $newAddr) {
    throw "GOVERNANCE_SIGNER_ADDRESS missing. Run .\testnet\setup-governance-signer-sepolia.ps1 first."
}

if ($LegacyDeployerKeyFile) {
    if (-not (Test-Path $LegacyDeployerKeyFile)) { throw "Key file not found: $LegacyDeployerKeyFile" }
    $LegacyDeployerKey = (Get-Content $LegacyDeployerKeyFile -Raw).Trim()
}
if (-not $LegacyDeployerKey) {
    if ($env:DEPLOYER_KEY -and $env:DEPLOYER_KEY -notmatch 'your_|placeholder|example') {
        $LegacyDeployerKey = $env:DEPLOYER_KEY.Trim()
        Write-Host "Using DEPLOYER_KEY from .env.sepolia" -ForegroundColor DarkGray
    } else {
        throw @"
LegacyDeployerKey is required: the 32-byte private key for the CURRENT on-chain signer
(0xf4c0bdBB681A61Aa0B123E82C04b0d692F53D58e), NOT GOVERNANCE_SIGNER_KEY and NOT an address.

  -LegacyDeployerKey 0x<64 hex chars>
  -LegacyDeployerKeyFile .\path\to\deployer.key

If that deployer key is lost, this script cannot run — get CREG via transfer or ask whoever holds the old key.
"@
    }
}

function Test-LooksLikeEthereumAddress {
    param([string]$Value)
    $v = $Value.Trim()
    return ($v -match '^0x[a-fA-F0-9]{40}$')
}

function Test-LooksLikePrivateKey {
    param([string]$Value)
    $v = $Value.Trim()
    if ($v -match '^0x') { $v = $v.Substring(2) }
    return ($v.Length -eq 64 -and $v -match '^[a-fA-F0-9]{64}$')
}

if (Test-LooksLikeEthereumAddress $LegacyDeployerKey) {
    throw @"
You passed an Ethereum address ($LegacyDeployerKey). LegacyDeployerKey must be the private key
(66 chars with 0x prefix, 64 hex digits) for 0xf4c0bdBB681A61Aa0B123E82C04b0d692F53D58e.

GOVERNANCE_SIGNER_KEY in .env is the NEW signer — use it only after registration, not here.
"@
}

if (-not (Test-LooksLikePrivateKey $LegacyDeployerKey)) {
    throw "Invalid legacy private key format (expected 0x + 64 hex digits, not an address)."
}

$govSignerOnChain = "0xf4c0bdBB681A61Aa0B123E82C04b0d692F53D58e"
if ($env:GOVERNANCE_SIGNER_KEY -and ($LegacyDeployerKey.Trim() -eq $env:GOVERNANCE_SIGNER_KEY.Trim())) {
    throw @"
LegacyDeployerKey matches GOVERNANCE_SIGNER_KEY in .env.sepolia.
Register needs the OLD deployer key (controls $govSignerOnChain), not the new governance signer key.
"@
}

$repoRoot = Split-Path -Parent $scriptDir
$manifest = Get-Content (Join-Path $repoRoot "contracts\deployments\sepolia-latest.json") -Raw | ConvertFrom-Json
$gov = $manifest.governance

$cast = Join-Path $scriptDir ".tools\foundry\cast.exe"
if (-not (Test-Path $cast)) { $cast = (Get-Command cast -ErrorAction Stop).Source }
$env:FOUNDRY_DISABLE_NIGHTLY_WARNING = "1"

$legacyRaw = & $cast wallet address --private-key $LegacyDeployerKey 2>&1 | Out-String
if ($legacyRaw -notmatch '(0x[a-fA-F0-9]{40})') {
    throw "Could not derive address from legacy private key (cast failed). Check the key is valid."
}
$legacyAddr = $matches[1]

$isRaw = & $cast call $gov "isSigner(address)(bool)" $legacyAddr --rpc-url $RpcUrl 2>&1 | Out-String
if ($isRaw -notmatch 'true') {
    throw @"
Legacy key derives to $legacyAddr, which is NOT a governance signer on $gov.
Expected the private key for on-chain signer $govSignerOnChain.

If you used GOVERNANCE_SIGNER_KEY, that is the wrong key — recover the original deployer private key.
"@
}

$already = & $cast call $gov "isSigner(address)(bool)" $newAddr --rpc-url $RpcUrl 2>&1 | Out-String
if ($already -match 'true') {
    Write-Host "$newAddr is already a signer. Nothing to do." -ForegroundColor Green
    exit 0
}

Write-Host "Adding signer $newAddr via governance (legacy $legacyAddr)..." -ForegroundColor Cyan

$addCalldata = (& $cast calldata "addSigner(address)" $newAddr 2>&1 | Out-String).Trim()
$propRaw = & $cast call $gov "proposalCount()(uint256)" --rpc-url $RpcUrl 2>&1 | Out-String
$proposalId = if ($propRaw -match '\b(\d+)\b') { $matches[1] } else { throw "proposalCount failed" }

& $cast send $gov "submit(address,bytes,string)" $gov $addCalldata "add Sepolia governance signer" `
    --private-key $LegacyDeployerKey --rpc-url $RpcUrl
if ($LASTEXITCODE -ne 0) { throw "submit addSigner failed" }

& $cast send $gov "vote(uint256,bool)" $proposalId true --private-key $LegacyDeployerKey --rpc-url $RpcUrl
if ($LASTEXITCODE -ne 0) { throw "vote failed" }

Start-Sleep -Seconds 3
$check = & $cast call $gov "isSigner(address)(bool)" $newAddr --rpc-url $RpcUrl 2>&1 | Out-String
Write-Host "isSigner($newAddr): $($check.Trim())" -ForegroundColor Green

if ($RemoveLegacySigner) {
    Write-Host "Removing legacy signer $legacyAddr ..." -ForegroundColor Yellow
    $remCalldata = (& $cast calldata "removeSigner(address)" $legacyAddr 2>&1 | Out-String).Trim()
    $propRaw2 = & $cast call $gov "proposalCount()(uint256)" --rpc-url $RpcUrl 2>&1 | Out-String
    $pid2 = if ($propRaw2 -match '\b(\d+)\b') { $matches[1] } else { throw "proposalCount failed" }
    & $cast send $gov "submit(address,bytes,string)" $gov $remCalldata "remove legacy deployer signer" `
        --private-key $LegacyDeployerKey --rpc-url $RpcUrl
    if ($LASTEXITCODE -ne 0) { throw "submit removeSigner failed" }
    & $cast send $gov "vote(uint256,bool)" $pid2 true --private-key $LegacyDeployerKey --rpc-url $RpcUrl
    if ($LASTEXITCODE -ne 0) { throw "vote removeSigner failed" }
}

Write-Host ""
Write-Host "Done. Verify: .\testnet\check-governance-signer.ps1" -ForegroundColor Green
Write-Host "Then:      .\testnet\fund-sepolia-faucet-governance.ps1"
Write-Host ""
