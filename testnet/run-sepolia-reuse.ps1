# Chain Registry - Option A: reuse existing Sepolia deployment (no redeploy)
#
# Prerequisites:
#   - Docker (spec server)
#   - Rust / cargo (node)
#   - contracts/deployments/sepolia-latest.json OR testnet/chain-spec.sepolia.json
#
# Usage:
#   .\testnet\run-sepolia-reuse.ps1              # verify + spec server only
#   .\testnet\run-sepolia-reuse.ps1 -StartNode   # also boot creg-node (foreground)

param(
    [string]$RpcUrl = "https://ethereum-sepolia-rpc.publicnode.com",
    [string]$SpecServerPort = "8888",
    [int]$ApiPort = 8090,
    [switch]$StartNode,
    [switch]$SkipSpecServer,
    [string]$DataDir = "./sepolia-node-data"
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
Set-Location $repoRoot

function Write-Step($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }
function Write-Ok($msg) { Write-Host "  OK $msg" -ForegroundColor Green }

function Wait-SpecServerReady {
    param(
        [int]$Port,
        [int]$MaxWaitSec = 90
    )
    $probeUrls = @(
        "http://localhost:$Port/chain-spec.json",
        "http://localhost:$Port/health"
    )
    $deadline = (Get-Date).AddSeconds($MaxWaitSec)
    while ((Get-Date) -lt $deadline) {
        foreach ($url in $probeUrls) {
            try {
                $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5
                if ($r.StatusCode -eq 200) { return }
            } catch { }
        }
        Start-Sleep -Seconds 2
    }
    throw "Spec server did not become ready on port $Port within ${MaxWaitSec}s"
}

function Test-SpecServerReady {
    param([int]$Port)
    try {
        $r = Invoke-WebRequest -Uri "http://localhost:$Port/chain-spec.json" -UseBasicParsing -TimeoutSec 5
        return ($r.StatusCode -eq 200)
    } catch {
        return $false
    }
}

function Stop-ListenerOnPort {
    param([int]$Port)
    $conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    if ($conn) {
        $listenerPid = $conn.OwningProcess | Select-Object -First 1
        Write-Host "  Stopping stale listener on port $Port (pid $listenerPid)" -ForegroundColor Yellow
        Stop-Process -Id $listenerPid -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
}

function Start-PythonSpecServerFallback {
    param(
        [string]$ServerDir,
        [int]$Port = 8888
    )
    if (Test-SpecServerReady -Port $Port) {
        Write-Ok "Spec server already serving chain-spec.json on port $Port"
        return
    }
    Stop-ListenerOnPort -Port $Port
    $python = Get-Command python -ErrorAction SilentlyContinue
    if (-not $python) {
        throw "Docker spec server failed and python is not on PATH for http.server fallback"
    }
    Write-Host "  Starting Python static spec server on port $Port (Docker fallback)" -ForegroundColor Yellow
    Start-Process -FilePath $python.Source -ArgumentList @(
        "-m", "http.server", "$Port", "--directory", $ServerDir
    ) -WorkingDirectory $ServerDir -WindowStyle Hidden | Out-Null
    Wait-SpecServerReady -Port $Port -MaxWaitSec 30
}

$specPath = Join-Path $scriptDir "chain-spec.sepolia.json"
$sigPath = Join-Path $scriptDir "chain-spec.sepolia.json.sig"
if (-not (Test-Path $specPath)) {
    Write-Error "Missing $specPath"
}
$spec = Get-Content $specPath -Raw | ConvertFrom-Json
Write-Ok "Loaded chain spec (genesis_hash=$($spec.genesis_hash))"

Write-Step "Verifying Sepolia contract bytecode"
foreach ($name in @("staking", "registry", "zk_verifier")) {
    $addr = $spec.contracts.$name
    $body = @{
        jsonrpc = "2.0"
        method  = "eth_getCode"
        params  = @($addr, "latest")
        id      = 1
    } | ConvertTo-Json
    $resp = Invoke-RestMethod -Uri $RpcUrl -Method Post -ContentType "application/json" -Body $body
    if (-not $resp.result -or $resp.result -eq "0x") {
        Write-Error "No bytecode at $name ($addr). Redeploy with deploy-sepolia.ps1 or fix chain-spec."
    }
    Write-Ok "$name $addr"
}

$specUrl = "http://localhost:$SpecServerPort/chain-spec.json"
if (-not $SkipSpecServer) {
    Write-Step "Starting local spec server on port $SpecServerPort"
    $serverDir = Join-Path $scriptDir "spec-server"
    # Do not edit spec JSON here (invalidates detached signature). Override sig URL via env.
    Copy-Item -Force $specPath (Join-Path $serverDir "chain-spec.sepolia.json")
    Copy-Item -Force $specPath (Join-Path $serverDir "chain-spec.json")
    if (Test-Path $sigPath) {
        Copy-Item -Force $sigPath (Join-Path $serverDir "chain-spec.sepolia.json.sig")
        Copy-Item -Force $sigPath (Join-Path $serverDir "chain-spec.json.sig")
    } else {
        Write-Warning "Missing signature file; node may fail spec verification"
    }
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    Push-Location $serverDir
    docker compose up -d --force-recreate 2>&1 | Out-Host
    $dockerExit = $LASTEXITCODE
    Pop-Location
    $ErrorActionPreference = $prevEap
    if ($dockerExit -ne 0) {
        Write-Warning "docker compose up failed (exit $dockerExit). Using Python http.server fallback."
        Start-PythonSpecServerFallback -ServerDir $serverDir -Port ([int]$SpecServerPort)
    }
    Write-Host "  Waiting for spec server on port $SpecServerPort..." -ForegroundColor DarkGray
    Wait-SpecServerReady -Port $SpecServerPort
    $specFetch = Invoke-WebRequest -Uri $specUrl -UseBasicParsing -TimeoutSec 30
    if ($specFetch.StatusCode -ne 200) { throw "Could not fetch $specUrl" }
    Write-Ok "Spec server: $specUrl"
}

Write-Step "Node environment (current process)"
$c = $spec.contracts
$env:CREG_CHAIN_SPEC_URL = $specUrl
$env:CREG_SPEC_SIGNATURE_URL = "http://localhost:$SpecServerPort/chain-spec.json.sig"
$env:CREG_SPEC_SIGNING_PUBKEY = $spec.signing.signing_key_pubkey_hex
# Do not set CREG_GENESIS_HASH from spec.genesis_hash: that is the canonical spec hash;
# legacy validate_genesis_hash() compares CREG_GENESIS_HASH to compute_network_identity_hash()
# from env (before apply_chain_spec). Pinning is done via signed spec + CREG_CHAIN_SPEC_URL.
Remove-Item Env:CREG_GENESIS_HASH -ErrorAction SilentlyContinue
$env:CREG_CHAIN_ID = $spec.chain_id
$env:CREG_EXPECTED_L1_CHAIN_ID = "$($spec.l1.chain_id)"
$env:CREG_ETH_RPC = $RpcUrl
$env:CREG_REGISTRY_ADDR = $c.registry
$env:CREG_STAKING_ADDR = $c.staking
$env:CREG_GOVERNANCE_ADDR = $c.governance
$env:CREG_TOKEN_ADDR = $c.creg_token
$env:CREG_TESTNET = "true"
$env:CREG_DEV_SANDBOX = "false"
$env:CREG_NODE_ID = "sepolia-local-1"
$env:CREG_DATA_DIR = (Resolve-Path (New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot $DataDir))).Path
$env:CREG_LISTEN = "0.0.0.0:$ApiPort"
$env:CREG_P2P_LISTEN = "/ip4/0.0.0.0/tcp/9011"
$env:CREG_IS_VALIDATOR = "false"
# Observer reuse: drop invalid template validator key from .env (config validates hex if set).
Remove-Item Env:CREG_VALIDATOR_KEY -ErrorAction SilentlyContinue
$env:RUST_LOG = "info,chain_registry_node=debug"

Write-Host ""
Write-Host "  CREG_CHAIN_SPEC_URL=$($env:CREG_CHAIN_SPEC_URL)"
Write-Host "  CREG_ETH_RPC=$($env:CREG_ETH_RPC)"
Write-Host "  CREG_STAKING_ADDR=$($env:CREG_STAKING_ADDR)"
Write-Host "  CREG_DATA_DIR=$($env:CREG_DATA_DIR)"
Write-Host "  API health: http://localhost:$ApiPort/v1/health"
Write-Host ""

if ($StartNode) {
    Write-Step "Starting creg-node on port $ApiPort"
    Set-Location $repoRoot
    cargo run --bin creg-node --package chain-registry-node
} else {
    Write-Host "Spec server is up. Start node with:" -ForegroundColor Yellow
    Write-Host "  .\testnet\run-sepolia-reuse.ps1 -StartNode" -ForegroundColor White
    exit 0
}
