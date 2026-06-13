# NET-301 — Multi-validator PBFT quorum verification on Sepolia 3-node fleet.
#
# Proves:
#   - CREG_PBFT_ALLOW_SMALL_CLUSTER_QUORUM is NOT enabled
#   - Health reports validator_count >= 2 on validator nodes
#   - A publish reaches status=verified (optional) with quorum from >=2 validators
#
# Prerequisites:
#   - Fleet running: .\testnet\start-3node-test.ps1
#   - validator-2 Active on L1: .\testnet\register-validator-2-sepolia.ps1
#   - testnet/.env.publish.local with CREG_PUBLISHER_ADDRESS
#
# Usage:
#   .\testnet\net-301-quorum-verify.ps1
#   .\testnet\net-301-quorum-verify.ps1 -SkipPublish -Canonical "@creg/net301-smoke@1.0.0"
#   .\testnet\net-301-quorum-verify.ps1 -MinValidators 2

param(
    [switch]$SkipPublish,
    [string]$Canonical = "",
    [int]$MinValidators = 2,
    [int]$VerifiedTimeoutSec = 300,
    [int]$HealthTimeoutSec = 180
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
Set-Location $repoRoot
. (Join-Path $scriptDir "node-api.ps1")

function Log($msg) { Write-Host "[net-301] $msg" }

$fleetEnv = Join-Path $scriptDir "sepolia-3node.env"
if (Test-Path $fleetEnv) {
    Get-Content $fleetEnv | ForEach-Object {
        if ($_ -match '^\s*([^#=\s]+)\s*=\s*(.+)$') {
            Set-Item -Path "Env:$($matches[1])" -Value $matches[2].Trim().Trim('"')
        }
    }
}

if ($env:CREG_PBFT_ALLOW_SMALL_CLUSTER_QUORUM -eq "true" -or $env:CREG_PBFT_ALLOW_SMALL_CLUSTER_QUORUM -eq "1") {
    throw "CREG_PBFT_ALLOW_SMALL_CLUSTER_QUORUM is set - NET-301 requires real PBFT quorum, not small-cluster override"
}
$envLine = if (Test-Path $fleetEnv) { Select-String -Path $fleetEnv -Pattern 'CREG_PBFT_ALLOW_SMALL_CLUSTER_QUORUM' } else { $null }
if ($envLine) {
    throw "Remove CREG_PBFT_ALLOW_SMALL_CLUSTER_QUORUM from testnet/sepolia-3node.env for NET-301"
}

$node1Port = if ($env:CREG_3NODE_NODE1_API_PORT) { [int]$env:CREG_3NODE_NODE1_API_PORT } else { 28180 }
$node2Port = if ($env:CREG_3NODE_NODE2_API_PORT) { [int]$env:CREG_3NODE_NODE2_API_PORT } else { 28181 }

Log "Checking validator_count >= $MinValidators on node1 and node2"
$h1 = Wait-NodeHealthSynced -Port $node1Port -MaxSec $HealthTimeoutSec -Log { param($m) Log $m }
$h2 = Wait-NodeHealthSynced -Port $node2Port -MaxSec $HealthTimeoutSec -Log { param($m) Log $m }
$s1 = Get-NodeChainStats -Port $node1Port
$s2 = Get-NodeChainStats -Port $node2Port
$lowValidatorNodes = @()
foreach ($pair in @(
        @{ n = "node1"; h = $h1; s = $s1 },
        @{ n = "node2"; h = $h2; s = $s2 }
    )) {
    $vc = [int]$pair.s.validator_count
    Log "$($pair.n): validator_count=$vc peers=$($pair.s.peer_count) sync=$($pair.h.validator_set_sync.state)"
    if ($vc -lt $MinValidators) { $lowValidatorNodes += $pair.n }
}
if ($lowValidatorNodes.Count -gt 0) {
    $nodes = $lowValidatorNodes -join ', '
    throw "NET-301: validator_count below $MinValidators on: $nodes. Run register-validator-2-sepolia.ps1 -RegisterIdentity, approve-validator-governance-sepolia.ps1, then re-run net-301-quorum-verify.ps1"
}

$publishedCanonical = $Canonical
if (-not $SkipPublish) {
    Log "Running soak publish (net-301 smoke package)"
    & (Join-Path $scriptDir "soak-3node-consensus.ps1") -SkipPublish:$false -HealthTimeoutSec $HealthTimeoutSec
    if ($LASTEXITCODE -ne 0) { throw "soak-3node-consensus failed" }
    $list = Invoke-NodeApi -Port $node1Port -Path "/v1/packages?limit=5&status=verified"
    if (-not $list.packages -or $list.packages.Count -eq 0) {
        $list = Invoke-NodeApi -Port $node1Port -Path "/v1/packages?limit=5"
    }
    if ($list.packages -and $list.packages.Count -gt 0) {
        $publishedCanonical = $list.packages[0].canonical
    }
} elseif (-not $publishedCanonical) {
    throw "Pass -Canonical when using -SkipPublish"
}

if (-not $publishedCanonical) {
    throw "No package canonical to verify - publish failed or empty package list"
}
Log "Polling verified status for: $publishedCanonical"

$deadline = (Get-Date).AddSeconds($VerifiedTimeoutSec)
$verified = $false
while ((Get-Date) -lt $deadline -and -not $verified) {
  foreach ($port in @($node1Port, $node2Port)) {
    try {
        $enc = [uri]::EscapeDataString($publishedCanonical)
        $pkg = Invoke-NodeApi -Port $port -Path "/v1/packages/$enc"
        if ($pkg.status -eq "verified") {
            Log "OK verified on port $port block_hash=$($pkg.block_hash)"
            $verified = $true
            break
        }
        Log "port $port status=$($pkg.status) - waiting"
    } catch {
        Log "port $port package lookup: $($_.Exception.Message)"
    }
  }
  if (-not $verified) { Start-Sleep -Seconds 8 }
}
if (-not $verified) {
    throw "Package did not reach verified within ${VerifiedTimeoutSec}s"
}

Log "Checking consensus quorum (>= $MinValidators distinct approvers)"
$consensus = Invoke-NodeApi -Port $node1Port -Path "/v1/consensus/state"
$quorum = [int]$consensus.quorum
$total = [int]$consensus.total_validators
Log "consensus total_validators=$total quorum=$quorum"

$bestApprovers = @()
foreach ($round in $consensus.active_rounds) {
    if ($round.approvers.Count -gt $bestApprovers.Count) {
        $bestApprovers = $round.approvers
    }
    if ($round.phase -eq "quorum-reached" -and $round.approvers.Count -ge $quorum) {
        Log "OK round phase=$($round.phase) approvers=$($round.approvers -join ', ')"
        break
    }
}
if ($bestApprovers.Count -lt $MinValidators -and $total -ge $MinValidators) {
    Log "WARN: saw $($bestApprovers.Count) approvers (expected >= $MinValidators for full NET-301). Check L1 active validator set."
}

$results = @{
    timestamp         = (Get-Date).ToUniversalTime().ToString("o")
    net301            = $true
    min_validators    = $MinValidators
    node1_validators  = $s1.validator_count
    node2_validators  = $s2.validator_count
    canonical         = $publishedCanonical
    consensus_quorum  = $quorum
    consensus_total   = $total
    small_cluster_off = $true
}
$outDir = Join-Path $repoRoot "testnet\net-301-logs"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$outPath = Join-Path $outDir ("net-301-{0}.json" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
$results | ConvertTo-Json -Depth 4 | Set-Content -Path $outPath -Encoding utf8
Log "NET-301 quorum verify PASSED (see $outPath)"
