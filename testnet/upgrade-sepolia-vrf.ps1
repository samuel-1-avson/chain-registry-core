# Deploy fixed VRF (ISSUE-009) to Sepolia and update signed chain spec + Docker spec server.
#
# Prerequisites:
#   testnet/.env.sepolia with DEPLOYER_KEY (Sepolia ETH) and SEPOLIA_RPC_URL
#   Existing governance at CREG_GOVERNANCE_ADDR (from chain-spec.sepolia.json)
#
# Usage:
#   .\testnet\upgrade-sepolia-vrf.ps1
#   .\testnet\upgrade-sepolia-vrf.ps1 -SkipDocker
#   .\testnet\upgrade-sepolia-vrf.ps1 -SkipDeploy -Yes   # repair spec/signature only (no new VRF deploy)

param(
    [switch]$SkipDocker,
    [switch]$SkipDeploy,
    [switch]$Yes
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
Set-Location $repoRoot

$envFile = Join-Path $scriptDir ".env.sepolia"
if (-not (Test-Path $envFile)) {
    throw "Missing $envFile - run .\testnet\setup-sepolia-authority.ps1 or copy .env.sepolia.example"
}

Get-Content $envFile | ForEach-Object {
    if ($_ -match '^\s*([^#\s][^=]*)\s*=\s*(.*)\s*$') {
        [Environment]::SetEnvironmentVariable($matches[1].Trim(), $matches[2].Trim().Trim('"'), "Process")
    }
}

if (-not $env:DEPLOYER_KEY) {
    if ($env:GOVERNANCE_SIGNER_KEY) { $env:DEPLOYER_KEY = $env:GOVERNANCE_SIGNER_KEY }
    else { throw "DEPLOYER_KEY not set in .env.sepolia" }
}
if (-not $env:SEPOLIA_RPC_URL) {
    $env:SEPOLIA_RPC_URL = "https://ethereum-sepolia-rpc.publicnode.com"
}

$toolsForge = Join-Path $scriptDir ".tools\foundry\forge.exe"
$toolsCast = Join-Path $scriptDir ".tools\foundry\cast.exe"
$forge = if (Test-Path $toolsForge) { $toolsForge } elseif (Get-Command forge -ErrorAction SilentlyContinue) { (Get-Command forge).Source } else { $null }
$cast = if (Test-Path $toolsCast) { $toolsCast } elseif (Get-Command cast -ErrorAction SilentlyContinue) { (Get-Command cast).Source } else { $null }
if (-not $forge -or -not $cast) {
    throw "forge/cast not found. Run .\testnet\install-foundry.ps1"
}
$env:FOUNDRY_DISABLE_NIGHTLY_WARNING = "1"

function Write-JsonFileNoBom {
    param([string]$Path, [string]$Json)
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($Path, $Json, $utf8NoBom)
}

function Invoke-CargoLastLine {
    param(
        [string[]]$Args,
        [string]$Pattern = '^0x[0-9a-fA-F]{64}$'
    )
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $lines = @(& cargo @Args 2>&1 | ForEach-Object { "$_" })
        if ($LASTEXITCODE -ne 0) {
            throw "cargo failed:`n$($lines -join "`n")"
        }
        $match = $lines | Where-Object { $_ -match $Pattern } | Select-Object -Last 1
        if (-not $match) {
            throw "cargo output missing expected line ($Pattern):`n$($lines -join "`n")"
        }
        return $match.ToString().Trim()
    } finally {
        $ErrorActionPreference = $prev
    }
}

function Invoke-CargoSignature {
    param([string[]]$Args)
    Invoke-CargoLastLine -Args $Args -Pattern '^[0-9a-fA-F]{128}$'
}

$specPath = Join-Path $scriptDir "chain-spec.sepolia.json"
if (-not (Test-Path $specPath)) { throw "Missing $specPath" }
$spec = Get-Content $specPath -Raw | ConvertFrom-Json

$env:CREG_GOVERNANCE_ADDR = $spec.contracts.governance
$env:CREG_VRF_ADDR = $spec.contracts.vrf

Write-Host ""
Write-Host "=== Sepolia VRF upgrade (ISSUE-009) ===" -ForegroundColor Cyan
Write-Host "Governance: $($spec.contracts.governance)"
Write-Host "Current VRF: $($spec.contracts.vrf)"
Write-Host ""

$deployerRaw = & $cast wallet address --private-key $env:DEPLOYER_KEY 2>&1 | Out-String
if ($deployerRaw -notmatch '(0x[a-fA-F0-9]{40})') { throw "Invalid DEPLOYER_KEY" }
$deployer = $matches[1]
Write-Host "Deployer: $deployer"

$balance = (& $cast balance $deployer --rpc-url $env:SEPOLIA_RPC_URL 2>&1 | Out-String).Trim()
Write-Host "Balance:  $balance wei"
if ($balance -eq "0") { throw "Deployer has zero Sepolia ETH" }

if (-not $Yes) {
    Write-Host "Will deploy new VRF and update chain-spec.sepolia.json (+ signature)." -ForegroundColor Yellow
    $confirm = Read-Host "Type yes to continue"
    if ($confirm -ne "yes") { throw "Cancelled" }
}

if (-not $SkipDeploy) {
    & $forge script contracts/script/UpgradeSepoliaVRF.s.sol:UpgradeSepoliaVRF `
        --rpc-url $env:SEPOLIA_RPC_URL `
        --private-key $env:DEPLOYER_KEY `
        --broadcast `
        --chain-id 11155111 `
        -vvv
    if ($LASTEXITCODE -ne 0) { throw "VRF deployment failed" }

    $upgradePath = Join-Path $repoRoot "contracts\deployments\vrf-upgrade-latest.json"
    if (-not (Test-Path $upgradePath)) { throw "Missing $upgradePath after broadcast" }
    $upgrade = Get-Content $upgradePath -Raw | ConvertFrom-Json
    Write-Host ""
    Write-Host "New VRF: $($upgrade.vrf)" -ForegroundColor Green
} else {
    $upgrade = [PSCustomObject]@{ vrf = $spec.contracts.vrf }
    Write-Host "SkipDeploy: patching chain spec only (VRF $($upgrade.vrf))" -ForegroundColor DarkGray
}

# Patch chain spec (VRF only; preserve other contract addresses)
$spec = Get-Content $specPath -Raw | ConvertFrom-Json
$spec.contracts.vrf = $upgrade.vrf
$spec.genesis_time = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
Write-JsonFileNoBom -Path $specPath -Json ($spec | ConvertTo-Json -Depth 20 -Compress)
if ([System.IO.File]::ReadAllBytes($specPath)[0] -ne 0x7b) {
    throw "chain-spec.sepolia.json is malformed (missing leading '{') — use Write-JsonFileNoBom only"
}
Write-Host "Updated vrf in chain-spec.sepolia.json"

# Genesis hash + signature (same key as finalize-sepolia-spec.ps1)
$genesisHash = Invoke-CargoLastLine -Args @("run", "--example", "compute_genesis_hash", "--package", "common", "--", $specPath)
if (-not $genesisHash) { throw "Failed to compute genesis hash" }

$spec = Get-Content $specPath -Raw | ConvertFrom-Json
$spec.genesis_hash = $genesisHash
Write-JsonFileNoBom -Path $specPath -Json ($spec | ConvertTo-Json -Depth 20 -Compress)
Write-Host "Genesis hash: $genesisHash"

$privkey = "9d91e9e0d82a02b7be8c40a522d899eea9eeffad244323be3e568973211f3a6d"
$sigPath = Join-Path $scriptDir "chain-spec.sepolia.json.sig"
$sig = Invoke-CargoSignature -Args @("run", "--example", "sign_chain_spec", "--package", "common", "--", $specPath, $privkey)
if (-not $sig) { throw "Failed to sign chain spec" }
Write-JsonFileNoBom -Path $sigPath -Json $sig
Write-Host "Signed chain spec"

# Mirror into spec-server folder (optional standalone nginx stack)
$serverDir = Join-Path $scriptDir "spec-server"
if (Test-Path $serverDir) {
    Copy-Item -Force $specPath (Join-Path $serverDir "chain-spec.sepolia.json")
    Copy-Item -Force $sigPath (Join-Path $serverDir "chain-spec.sepolia.json.sig")
    Write-Host "Copied spec to testnet/spec-server/"
}

# Patch root .env if present
$rootEnv = Join-Path $repoRoot ".env"
if (Test-Path $rootEnv) {
    function Set-EnvLine {
        param([string[]]$Lines, [string]$Name, [string]$Value)
        $out = New-Object System.Collections.Generic.List[string]
        $replaced = $false
        foreach ($line in $Lines) {
            if ($line -match "^\s*#?\s*$([regex]::Escape($Name))\s*=") {
                if (-not $replaced) { $out.Add("$Name=$Value"); $replaced = $true }
                continue
            }
            $out.Add($line)
        }
        if (-not $replaced) { $out.Add("$Name=$Value") }
        return $out
    }
    $lines = Get-Content $rootEnv
    $lines = Set-EnvLine $lines "CREG_VRF_ADDR" $upgrade.vrf
    $lines = Set-EnvLine $lines "CREG_GENESIS_HASH" $genesisHash.Trim()
    $lines | Set-Content -Path $rootEnv -Encoding utf8
    Write-Host "Updated .env CREG_VRF_ADDR and CREG_GENESIS_HASH"
}

if (-not $SkipDocker) {
    Write-Host ""
    Write-Host "Restarting Docker spec-server + node..." -ForegroundColor Cyan
    docker compose -f docker-compose.yml up -d --force-recreate spec-server node 2>&1 | Out-Host
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "docker compose recreate failed - run manually: docker compose up -d --force-recreate spec-server node"
    } else {
        Start-Sleep -Seconds 15
        try {
            $health = Invoke-RestMethod -Uri "http://localhost:8090/v1/health" -TimeoutSec 15
            Write-Host "Node health: $($health | ConvertTo-Json -Compress)" -ForegroundColor Green
        } catch {
            Write-Warning "Health check failed: $($_.Exception.Message) - check: docker logs creg-node --tail 50"
        }
    }
}

Write-Host ""
Write-Host "On-chain VRF upgrade complete." -ForegroundColor Green
Write-Host "  New VRF:     $($upgrade.vrf)"
Write-Host "  Etherscan:   https://sepolia.etherscan.io/address/$($upgrade.vrf)"
Write-Host "  Previous:    $($upgrade.previousVrf)"
Write-Host ""
Write-Host "Registry still references the old immutable VRF address; selection uses chain-spec vrf + governance."
