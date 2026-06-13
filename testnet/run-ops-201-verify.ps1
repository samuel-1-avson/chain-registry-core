# OPS-201 — Sepolia Option A verification (same-machine automation)
# Mirrors docs/TESTNET_SEPOLIA_RUNBOOK.md second-operator verification steps where possible.
#
# Usage:
#   .\testnet\run-ops-201-verify.ps1
#   .\testnet\run-ops-201-verify.ps1 -SkipPublish
#   .\testnet\run-ops-201-verify.ps1 -NodeBinary .\target\release\creg-node.exe

param(
    [int]$ApiPort = 8090,
    [switch]$SkipPublish,
    [string]$NodeBinary = "",
    [int]$HealthTimeoutSec = 600,
    [int]$RestartSyncMaxSec = 120
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
. (Join-Path $scriptDir "ipfs-api.ps1")
Set-Location $repoRoot

$logDir = Join-Path $repoRoot "testnet\ops-201-logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$ts = Get-Date -Format "yyyyMMdd-HHmmss"
$logFile = Join-Path $logDir "ops-201-$ts.log"

function Log($msg) {
    $line = "[$(Get-Date -Format 'HH:mm:ss')] $msg"
    Add-Content -Path $logFile -Value $line
    Write-Host $line
}

function Wait-HealthSynced {
    param([int]$MaxSec)
    $deadline = (Get-Date).AddSeconds($MaxSec)
    $url = "http://localhost:$ApiPort/v1/health"
    while ((Get-Date) -lt $deadline) {
        try {
            $h = Invoke-RestMethod -Uri $url -TimeoutSec 10
            $sync = $h.validator_set_sync
            if ($h.status -eq "ok" -and $sync.state -eq "synced") {
                return $h
            }
            Log "  health status=$($h.status) validator_set_sync=$($sync.state)"
        } catch {
            Log "  waiting for $url ..."
        }
        Start-Sleep -Seconds 5
    }
    throw "Health did not reach synced within ${MaxSec}s (see $logFile)"
}

function Invoke-Creg {
    param(
        [Parameter(ValueFromRemainingArguments = $true)][string[]]$CregArgs,
        [string]$LogPath = ""
    )
    $cregRelease = Join-Path $repoRoot "target\release\creg.exe"
    $cregDebug = Join-Path $repoRoot "target\debug\creg.exe"
    $bin = if (Test-Path $cregRelease) { $cregRelease } elseif (Test-Path $cregDebug) { $cregDebug } else { $null }
    if ($bin) {
        $out = & $bin @CregArgs 2>&1
    } else {
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = "SilentlyContinue"
        $out = cargo run --bin creg -p chain-registry-cli -- @CregArgs 2>&1
        $ErrorActionPreference = $prevEap
    }
    if ($LogPath) {
        $out | Out-File -FilePath $LogPath -Encoding utf8
    } else {
        $out | Write-Host
    }
    return $LASTEXITCODE
}

function Stop-NodeOnPort {
    param([int]$Port)
    $conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    if ($conn) {
        $listenerPid = $conn.OwningProcess | Select-Object -First 1
        Log "Stopping process on port $Port (pid $listenerPid)"
        Stop-Process -Id $listenerPid -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
    }
}

Log "=== OPS-201 verify: spec server + node health + restart timing ==="

# Node and `creg publish` must share the same trusted-setup key files.
$zkKeysDir = Join-Path $repoRoot "circuits"
$env:CREG_ZK_KEYS_DIR = $zkKeysDir
if (-not (Test-Path (Join-Path $zkKeysDir "proving_key.bin"))) {
    Log "ZK keys missing under $zkKeysDir - first run will generate ephemeral keys (dev/testnet only)"
}

Log "Step: run-sepolia-reuse (spec server + env; Docker or Python fallback)"
$reuseLog = Join-Path $logDir "reuse-env-$ts.txt"
$reuseScript = Join-Path $scriptDir "run-sepolia-reuse.ps1"
try {
    & $reuseScript 2>&1 | Tee-Object -FilePath $reuseLog
    if ($LASTEXITCODE -ne 0) { throw "run-sepolia-reuse failed (exit $LASTEXITCODE)" }
} catch {
    Log "WARN: $($_.Exception.Message)"
    throw
}

if (-not $NodeBinary) {
    $debugBin = Join-Path $repoRoot "target\debug\creg-node.exe"
    $releaseBin = Join-Path $repoRoot "target\release\creg-node.exe"
    if (Test-Path $releaseBin) { $NodeBinary = $releaseBin }
    elseif (Test-Path $debugBin) { $NodeBinary = $debugBin }
    else {
        Log "Building creg-node (debug)..."
        cargo build --bin creg-node -p chain-registry-node 2>&1 | Tee-Object -FilePath (Join-Path $logDir "build-$ts.txt")
        $NodeBinary = $debugBin
    }
}

if (-not (Test-Path $NodeBinary)) {
    throw "Node binary not found: $NodeBinary"
}

# Observer mode (same as run-sepolia-reuse.ps1): syncs L1 validator set without CREG_VALIDATOR_KEY.
Remove-Item Env:CREG_SINGLE_VALIDATOR_MODE -ErrorAction SilentlyContinue
Remove-Item Env:CREG_PBFT_ALLOW_SMALL_CLUSTER_QUORUM -ErrorAction SilentlyContinue
Remove-Item Env:CREG_VALIDATOR_KEY -ErrorAction SilentlyContinue
$env:CREG_IS_VALIDATOR = "false"
$env:CREG_YARA_RULES_DIR = Join-Path $repoRoot "rules"
if (-not (Test-Path $env:CREG_YARA_RULES_DIR)) {
    Log "WARN: CREG_YARA_RULES_DIR missing - publish admission may fail"
}

Stop-NodeOnPort -Port $ApiPort

Log "Step: start creg-node (background)"
$nodeOut = Join-Path $logDir "node-$ts.stdout.log"
$nodeErr = Join-Path $logDir "node-$ts.stderr.log"
$nodeProc = Start-Process -FilePath $NodeBinary -WorkingDirectory $repoRoot -PassThru `
    -RedirectStandardOutput $nodeOut -RedirectStandardError $nodeErr -NoNewWindow

Log "  pid=$($nodeProc.Id) logs=$nodeOut"

try {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $health = Wait-HealthSynced -MaxSec $HealthTimeoutSec
    $sw.Stop()
    Log "OK first health synced in $($sw.Elapsed.TotalSeconds.ToString('F1'))s"

    Log "Step: chain-spec validate"
    $validateOut = Join-Path $logDir "chain-spec-validate-$ts.txt"
    $validateExit = Invoke-Creg chain-spec validate testnet/chain-spec.sepolia.json -LogPath $validateOut
    if ($validateExit -ne 0) { throw "chain-spec validate failed (exit $validateExit)" }
    Log "OK chain-spec validate"

    Log "Step: restart node (cursor / warm resync)"
    Stop-Process -Id $nodeProc.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
    $nodeProc = Start-Process -FilePath $NodeBinary -WorkingDirectory $repoRoot -PassThru `
        -RedirectStandardOutput (Join-Path $logDir "node-restart-$ts.stdout.log") `
        -RedirectStandardError (Join-Path $logDir "node-restart-$ts.stderr.log") -NoNewWindow
    $swRestart = [System.Diagnostics.Stopwatch]::StartNew()
    $null = Wait-HealthSynced -MaxSec $RestartSyncMaxSec
    $swRestart.Stop()
    Log "OK restart synced in $($swRestart.Elapsed.TotalSeconds.ToString('F1'))s (max allowed ${RestartSyncMaxSec}s)"

    if ($swRestart.Elapsed.TotalSeconds -gt 60) {
        Log "WARN: restart took >60s - investigate cursor / RPC"
    }

    $resultsPath = Join-Path $logDir "ops-201-results-$ts.json"
    @{
        timestamp           = (Get-Date).ToUniversalTime().ToString("o")
        rpc_url             = $env:CREG_ETH_RPC
        first_sync_seconds  = [math]::Round($sw.Elapsed.TotalSeconds, 1)
        restart_sync_seconds = [math]::Round($swRestart.Elapsed.TotalSeconds, 1)
        chain_spec_validate = ($validateExit -eq 0)
        publish_skipped     = [bool]$SkipPublish
        api_port            = $ApiPort
    } | ConvertTo-Json | Set-Content -Path $resultsPath -Encoding utf8
    Log "Wrote results: $resultsPath"

    $ipfs = $env:CREG_IPFS_URL
    if (-not $ipfs -or $ipfs -match '(?i)example|creg-testnet\.example') {
        $env:CREG_IPFS_URL = "http://127.0.0.1:5001"
        Log "Using local IPFS API: $($env:CREG_IPFS_URL) (override placeholder CREG_IPFS_URL)"
    }

    $publishEnv = Join-Path $scriptDir ".env.publish.local"
    if (Test-Path $publishEnv) {
        Log "Loading $publishEnv (publish addresses only)"
        Get-Content $publishEnv | ForEach-Object {
            $line = $_.Trim()
            if ($line -match '^\s*(CREG_PUBLISHER_ADDRESS|CREG_IPFS_URL)\s*=\s*(.+)$') {
                Set-Item -Path "Env:$($matches[1])" -Value $matches[2].Trim().Trim('"')
            }
        }
    }

    if (-not $SkipPublish) {
        Log "Step: E2E-301 publish smoke (benign tarball)"
        $ipfsOk = Test-CregIpfsApi -BaseUrl $env:CREG_IPFS_URL
        if (-not $ipfsOk) {
            Log "SKIP publish: IPFS not reachable at $($env:CREG_IPFS_URL) - .\testnet\start-ipfs.ps1 or docker start creg-local-ipfs"
        }
        if ($ipfsOk) {
            $smokeDir = Join-Path $repoRoot "tmp\ops-201-smoke"
            New-Item -ItemType Directory -Force -Path $smokeDir | Out-Null
            $ver = "1.0.$ts"
            $tar = Join-Path $smokeDir "pkg.tgz"
            $pkgDir = Join-Path $smokeDir "package"
            New-Item -ItemType Directory -Force -Path $pkgDir | Out-Null
            $pkgName = "@creg/ops-201-smoke"
            $pkgJson = @{
                name        = $pkgName
                version     = $ver
                description = "OPS-201 benign publish smoke"
                main        = "index.js"
            } | ConvertTo-Json -Compress
            Set-Content -Path (Join-Path $pkgDir "package.json") -Value $pkgJson -Encoding utf8
            Set-Content -Path (Join-Path $pkgDir "index.js") -Value "module.exports = () => 'ops-201-safe';"
            tar -czf $tar -C $smokeDir package 2>$null
            if (-not (Test-Path $tar)) {
                Log "SKIP publish: tar failed (install tar or use WSL)"
            } else {
                $pubKey = Join-Path $repoRoot "publisher.key"
                if (-not (Test-Path $pubKey)) {
                    Log "SKIP publish: missing publisher.key at $pubKey"
                } elseif (-not $env:CREG_PUBLISHER_ADDRESS) {
                    Log "SKIP publish: set CREG_PUBLISHER_ADDRESS (staked Sepolia publisher EVM address)"
                } else {
                    $canPublish = $true
                    $stakeCheck = Join-Path $scriptDir "check-publisher-stake.ps1"
                    if (Test-Path $stakeCheck) {
                        & $stakeCheck -PublisherAddress $env:CREG_PUBLISHER_ADDRESS -RpcUrl $env:CREG_ETH_RPC 2>&1 | ForEach-Object { Log "  $_" }
                        if ($LASTEXITCODE -ne 0) {
                            Log "SKIP publish: no on-chain stake — run cast approve + stakeAsPublisher, then .\testnet\check-publisher-stake.ps1"
                            $canPublish = $false
                        }
                    }
                    if ($canPublish) {
                        $api = "http://localhost:$ApiPort"
                        $grpc = "http://127.0.0.1:50051"
                        $publishExit = Invoke-Creg --node-url $api --grpc-url $grpc `
                            publish $tar --key-file $pubKey --publisher-address $env:CREG_PUBLISHER_ADDRESS `
                            -LogPath (Join-Path $logDir "publish-$ts.txt")
                        if ($publishExit -ne 0) {
                            Log "WARN: publish exited $publishExit - see publish log (stake / admission / IPFS)"
                        } else {
                            Log "OK publish submitted - check: Invoke-RestMethod $api/v1/public/packages"
                        }
                    }
                }
            }
        }
    }
} finally {
    if ($nodeProc -and -not $nodeProc.HasExited) {
        Log "Stopping node pid $($nodeProc.Id)"
        Stop-Process -Id $nodeProc.Id -Force -ErrorAction SilentlyContinue
    }
}

Log "=== OPS-201 verify complete. Log: $logFile ==="
Write-Host "`nResults written to $logFile" -ForegroundColor Green
