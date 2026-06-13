# Copy signed testnet/chain-spec.sepolia.json (+ .sig) into spec-server and restart nginx.
#
# Usage:
#   .\testnet\sync-sepolia-spec-server.ps1
#   .\testnet\sync-sepolia-spec-server.ps1 -NoDocker   # copy files only

param(
    [string]$SpecServerPort = "8888",
    [switch]$NoDocker
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$specPath = Join-Path $scriptDir "chain-spec.sepolia.json"
$sigPath = Join-Path $scriptDir "chain-spec.sepolia.json.sig"
$serverDir = Join-Path $scriptDir "spec-server"

if (-not (Test-Path $specPath)) { throw "Missing $specPath" }
if (-not (Test-Path $sigPath)) { throw "Missing $sigPath - run finalize-sepolia-spec.ps1" }

Copy-Item -Force $specPath (Join-Path $serverDir "chain-spec.sepolia.json")
Copy-Item -Force $specPath (Join-Path $serverDir "chain-spec.json")
Copy-Item -Force $sigPath (Join-Path $serverDir "chain-spec.sepolia.json.sig")
Copy-Item -Force $sigPath (Join-Path $serverDir "chain-spec.json.sig")

$spec = Get-Content $specPath -Raw | ConvertFrom-Json
Write-Host "Copied spec (genesis_hash=$($spec.genesis_hash), registry=$($spec.contracts.registry))" -ForegroundColor Green

if ($NoDocker) {
    Write-Host "Files updated under $serverDir - restart whatever serves port $SpecServerPort" -ForegroundColor Yellow
    exit 0
}

function Stop-ListenerOnPort([int]$Port) {
    $conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($conn) {
        # $PID is a read-only automatic variable in PowerShell; use a different name.
        $listenerPid = $conn.OwningProcess
        $name = (Get-Process -Id $listenerPid -ErrorAction SilentlyContinue).ProcessName
        Write-Host "Stopping $name on port $Port (PID $listenerPid)" -ForegroundColor Yellow
        Stop-Process -Id $listenerPid -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
}

Stop-ListenerOnPort $SpecServerPort
Push-Location $serverDir
docker compose up -d --force-recreate 2>&1 | Out-Host
$dockerExit = $LASTEXITCODE
Pop-Location
if ($dockerExit -ne 0) {
    throw "docker compose failed (exit $dockerExit). Start manually or use -NoDocker"
}

$url = "http://localhost:$SpecServerPort/chain-spec.json"
$deadline = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $deadline) {
    try {
        $r = Invoke-RestMethod -Uri $url -TimeoutSec 5
        if ($r.genesis_hash -eq $spec.genesis_hash) {
            Write-Host "Spec server OK: $url" -ForegroundColor Green
            exit 0
        }
        Write-Host "WARN: server genesis $($r.genesis_hash) != local $($spec.genesis_hash)" -ForegroundColor Yellow
    } catch { }
    Start-Sleep -Seconds 2
}
throw "Spec server did not serve updated chain-spec at $url"
