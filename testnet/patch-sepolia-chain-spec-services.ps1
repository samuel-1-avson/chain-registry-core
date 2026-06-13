# Patch chain-spec.sepolia.json service URLs for the public lab or internet-hosted testnet,
# recompute genesis hash, and re-sign the spec.
#
# Local lab (default):
#   .\testnet\patch-sepolia-chain-spec-services.ps1
#
# Legacy single-host with ports (HTTPS host + explicit ports):
#   .\testnet\patch-sepolia-chain-spec-services.ps1 -PublicHost "testnet.example.com"
#
# Public subdomains (recommended for GCP / Let's Encrypt on :443):
#   .\testnet\patch-sepolia-chain-spec-services.ps1 -BaseDomain "testnet.example.com"
#   # => api.testnet.example.com, explorer.testnet.example.com, ...
#
# Explicit hosts (override -BaseDomain defaults):
#   .\testnet\patch-sepolia-chain-spec-services.ps1 `
#     -ApiHost "api.testnet.example.com" `
#     -ExplorerHost "explorer.testnet.example.com" `
#     -FaucetHost "faucet.testnet.example.com" `
#     -SpecHost "spec.testnet.example.com" `
#     -IpfsHost "ipfs.testnet.example.com"

param(
    [string]$PublicHost = "localhost",
    [string]$BaseDomain = "",
    [string]$ApiHost = "",
    [string]$ExplorerHost = "",
    [string]$FaucetHost = "",
    [string]$SpecHost = "",
    [string]$IpfsHost = ""
)

$ErrorActionPreference = "Stop"

function Resolve-ServiceUrl {
    param(
        [string]$HostName,
        [string]$Port,
        [string]$PathSuffix = ""
    )
    if ($HostName -eq "localhost" -or $HostName -match '^(127\.|192\.168\.|10\.)') {
        return "http://localhost:${Port}${PathSuffix}"
    }
    if ($HostName -match ':') {
        $scheme = if ($HostName -match '^https?://') { "" } else { "https://" }
        if ($HostName -notmatch '^https?://') { return "https://${HostName}${PathSuffix}" }
        return "${HostName}${PathSuffix}"
    }
    return "https://${HostName}${PathSuffix}"
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
Set-Location $repoRoot

$specPath = Join-Path $scriptDir "chain-spec.sepolia.json"
$sigPath = Join-Path $scriptDir "chain-spec.sepolia.json.sig"

if (-not (Test-Path $specPath)) {
    throw "Missing $specPath"
}

$nodeApiPort = if ($env:CREG_3NODE_NODE3_API_PORT) { $env:CREG_3NODE_NODE3_API_PORT } else { "28182" }
$ipfsPort = if ($env:CREG_3NODE_IPFS_HOST_PORT) { $env:CREG_3NODE_IPFS_HOST_PORT } else { "15001" }
$specPort = if ($env:CREG_3NODE_SPEC_HOST_PORT) { $env:CREG_3NODE_SPEC_HOST_PORT } else { "18888" }
$faucetPort = if ($env:CREG_3NODE_FAUCET_PORT) { $env:CREG_3NODE_FAUCET_PORT } else { "8082" }
$explorerPort = if ($env:CREG_3NODE_EXPLORER_PORT) { $env:CREG_3NODE_EXPLORER_PORT } else { "3017" }

$useSubdomains = $BaseDomain -or $ApiHost -or $ExplorerHost -or $FaucetHost -or $SpecHost -or $IpfsHost

if ($BaseDomain) {
    if (-not $ApiHost) { $ApiHost = "api.$BaseDomain" }
    if (-not $ExplorerHost) { $ExplorerHost = "explorer.$BaseDomain" }
    if (-not $FaucetHost) { $FaucetHost = "faucet.$BaseDomain" }
    if (-not $SpecHost) { $SpecHost = "spec.$BaseDomain" }
    if (-not $IpfsHost) { $IpfsHost = "ipfs.$BaseDomain" }
    $useSubdomains = $true
}

$spec = Get-Content $specPath -Raw | ConvertFrom-Json

# Bootnodes are overridden by CREG_P2P_SEEDS in the 3-node fleet; empty avoids dialing placeholders.
$spec.bootnodes = @()

if ($useSubdomains) {
    $spec.services = [ordered]@{
        ipfs_gateway = Resolve-ServiceUrl -HostName $IpfsHost -Port $ipfsPort
        ipfs_api     = Resolve-ServiceUrl -HostName $IpfsHost -Port $ipfsPort
        faucet       = Resolve-ServiceUrl -HostName $FaucetHost -Port $faucetPort
        explorer     = Resolve-ServiceUrl -HostName $ExplorerHost -Port $explorerPort
        metrics      = Resolve-ServiceUrl -HostName $ApiHost -Port $nodeApiPort -PathSuffix "/metrics"
    }
    $spec.signing.detached_signature_url = (Resolve-ServiceUrl -HostName $SpecHost -Port $specPort) + "/chain-spec.json.sig"
    $profileLabel = if ($BaseDomain) { "subdomains (base=$BaseDomain)" } else { "subdomains (explicit hosts)" }
} else {
    $hostBase = if ($PublicHost -eq "localhost") { "http://localhost" } else { "https://$PublicHost" }
    $spec.services = [ordered]@{
        ipfs_gateway = "$hostBase`:$ipfsPort"
        ipfs_api     = "$hostBase`:$ipfsPort"
        faucet       = "$hostBase`:$faucetPort"
        explorer     = "$hostBase`:$explorerPort"
        metrics      = "$hostBase`:$nodeApiPort/metrics"
    }
    $spec.signing.detached_signature_url = "$hostBase`:$specPort/chain-spec.json.sig"
    $profileLabel = "host=$PublicHost"
}

$spec.support.discord = "https://github.com/chain-registry/chain-registry/discussions"
$spec.support.security = "security@chain-registry.github.io"

# Phase must stay a known enum value (alpha | beta | ga).
$spec.phase = "alpha"

$specJson = $spec | ConvertTo-Json -Depth 30 -Compress
[System.IO.File]::WriteAllText($specPath, $specJson, [System.Text.UTF8Encoding]::new($false))
Write-Host "Patched services in $specPath ($profileLabel)" -ForegroundColor Green
Write-Host "  explorer: $($spec.services.explorer)" -ForegroundColor DarkGray
Write-Host "  faucet:   $($spec.services.faucet)" -ForegroundColor DarkGray
if ($useSubdomains) {
    Write-Host "  api:      $(Resolve-ServiceUrl -HostName $ApiHost -Port $nodeApiPort)" -ForegroundColor DarkGray
} else {
    Write-Host "  metrics:  $($spec.services.metrics)" -ForegroundColor DarkGray
}

Write-Host "Computing genesis hash..." -ForegroundColor Cyan
$genesisHash = cargo run -q --example compute_genesis_hash --package common -- $specPath 2>&1 | Select-Object -Last 1
if (-not $genesisHash -or $genesisHash -match "error") {
    throw "compute_genesis_hash failed: $genesisHash"
}
$spec = Get-Content $specPath -Raw | ConvertFrom-Json
$spec.genesis_hash = $genesisHash.Trim()
$specJson = $spec | ConvertTo-Json -Depth 30 -Compress
[System.IO.File]::WriteAllText($specPath, $specJson, [System.Text.UTF8Encoding]::new($false))
Write-Host "genesis_hash = $($spec.genesis_hash)" -ForegroundColor Green

Write-Host "Signing chain spec..." -ForegroundColor Cyan
$privkey = "9d91e9e0d82a02b7be8c40a522d899eea9eeffad244323be3e568973211f3a6d"
$sig = cargo run -q --example sign_chain_spec --package common -- $specPath $privkey 2>&1 | Select-Object -Last 1
Set-Content -Path $sigPath -Value $sig.Trim() -NoNewline
Write-Host "Wrote $sigPath" -ForegroundColor Green

cargo run -q --example verify_chain_spec --package common -- $specPath $sigPath 2>&1 | Select-Object -Last 3

if ($useSubdomains) {
    Write-Host ""
    Write-Host "Add to testnet/sepolia-3node.env for Caddy ingress:" -ForegroundColor Yellow
    if ($BaseDomain) {
        Write-Host "  CREG_PUBLIC_BASE_DOMAIN=$BaseDomain"
    }
    Write-Host "  CREG_PUBLIC_API_HOST=$ApiHost"
    Write-Host "  CREG_PUBLIC_EXPLORER_HOST=$ExplorerHost"
    Write-Host "  CREG_PUBLIC_FAUCET_HOST=$FaucetHost"
    Write-Host "  CREG_PUBLIC_SPEC_HOST=$SpecHost"
    Write-Host "  CREG_PUBLIC_IPFS_HOST=$IpfsHost"
    Write-Host "  CREG_PUBLIC_EXPLORER_URL=https://$ExplorerHost"
    Write-Host "  CREG_NODE_URL=https://$ApiHost"
}
