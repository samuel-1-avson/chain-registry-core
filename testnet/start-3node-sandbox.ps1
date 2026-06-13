# Start 3-node Sepolia fleet with nsjail secure image (SANDBOX-301).
# Linux container backend required (Docker Desktop WSL2 on Windows OK) — nsjail uses privileged containers.
#
# Usage:
#   .\testnet\start-3node-sandbox.ps1
#   .\testnet\start-3node-sandbox.ps1 -FreshVolumes

param(
    [switch]$FreshVolumes
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$startArgs = @{ Sandbox = $true }
if ($FreshVolumes) { $startArgs.FreshVolumes = $true }
& (Join-Path $scriptDir "start-3node-test.ps1") @startArgs
