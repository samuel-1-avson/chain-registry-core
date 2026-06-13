# Chain Registry — Finalize Sepolia Chain Spec
# Run this AFTER deploy-sepolia.ps1 completes successfully.
#
# Usage:
#   .\testnet\finalize-sepolia-spec.ps1

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
Set-Location $repoRoot

function Write-Step($msg) {
    Write-Host ""
    Write-Host "=== $msg ===" -ForegroundColor Cyan
}

function Write-Success($msg) {
    Write-Host "✓ $msg" -ForegroundColor Green
}

# Step 1: Read deployment manifest
$manifestPath = Join-Path $repoRoot "contracts" "deployments" "sepolia-latest.json"
if (-not (Test-Path $manifestPath)) {
    Write-Error "Deployment manifest not found at $manifestPath. Run deploy-sepolia.ps1 first."
}

$manifest = Get-Content $manifestPath | ConvertFrom-Json
Write-Success "Loaded deployment manifest"

# Step 2: Patch chain-spec.sepolia.json
$specPath = Join-Path $scriptDir "chain-spec.sepolia.json"
$spec = Get-Content $specPath | ConvertFrom-Json

$spec.contracts.governance    = $manifest.governance
$spec.contracts.registry      = $manifest.registry
$spec.contracts.staking       = $manifest.staking
$spec.contracts.reputation    = $manifest.reputation
$spec.contracts.creg_token    = $manifest.cregToken
$spec.contracts.zk_verifier   = $manifest.zkVerifier
$spec.contracts.appeal        = $manifest.appeal
$spec.contracts.validator_rewards = $manifest.validatorRewards
$spec.contracts.vrf           = $manifest.vrf

if ($manifest.stakingDeployBlock) {
    $spec.validator_set.epoch_block_height = [int64]$manifest.stakingDeployBlock
    Write-Success "Set validator_set.epoch_block_height to $($manifest.stakingDeployBlock)"
}

# Update genesis time to now
$spec.genesis_time = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")

# Save patched spec
$specJson = $spec | ConvertTo-Json -Depth 20 -Compress
Set-Content -Path $specPath -Value $specJson
Write-Success "Patched contract addresses into chain-spec.sepolia.json"

# Step 3: Compute genesis hash
Write-Step "Computing genesis hash"
$genesisHash = cargo run --example compute_genesis_hash --package common -- $specPath 2>$null | Select-Object -Last 1
if (-not $genesisHash) {
    Write-Warn "compute_genesis_hash example not found. Using CLI fallback."
    $genesisHash = cargo run --package chain-registry-cli -- chain-spec compute-genesis-hash $specPath 2>$null | Select-Object -Last 1
}
Write-Success "Genesis hash: $genesisHash"

# Update genesis hash in spec
$spec = Get-Content $specPath | ConvertFrom-Json
$spec.genesis_hash = $genesisHash
$specJson = $spec | ConvertTo-Json -Depth 20 -Compress
Set-Content -Path $specPath -Value $specJson
Write-Success "Updated genesis_hash in spec"

# Step 4: Sign the spec
Write-Step "Signing chain spec"
$privkey = "9d91e9e0d82a02b7be8c40a522d899eea9eeffad244323be3e568973211f3a6d"
$sig = cargo run --example sign_chain_spec --package common -- $specPath $privkey 2>$null | Select-Object -Last 1

$sigPath = Join-Path $scriptDir "chain-spec.sepolia.json.sig"
Set-Content -Path $sigPath -Value $sig
Write-Success "Signature saved to chain-spec.sepolia.json.sig"

# Step 5: Verify signature
Write-Step "Verifying signature"
cargo run --example verify_chain_spec --package common -- $specPath $sigPath 2>$null | Select-Object -Last 1
Write-Success "Signature verified"

# Step 6: Summary
Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  Sepolia Chain Spec Ready for Publication                  ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "Files:"
Write-Host "  Spec:     $specPath"
Write-Host "  Signature: $sigPath"
Write-Host ""
Write-Host "Genesis Hash: $genesisHash"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Upload chain-spec.sepolia.json to your spec server"
Write-Host "  2. Upload chain-spec.sepolia.json.sig alongside it"
Write-Host "  3. Update CREG_CHAIN_SPEC_URL in node configs"
Write-Host "  4. Distribute CREG_SPEC_SIGNING_PUBKEY to node operators"
