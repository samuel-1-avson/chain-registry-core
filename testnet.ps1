param(
    [switch]$SkipExplorer,
    [switch]$SkipDeploySync,
    [switch]$SkipCleanup,
    [switch]$RunSmokeTests
)

$ErrorActionPreference = "Stop"

$scriptPath = Join-Path $PSScriptRoot "scripts\start-testnet.ps1"
& $scriptPath @PSBoundParameters
