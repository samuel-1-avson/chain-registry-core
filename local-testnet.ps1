param(
    [switch]$SkipExplorer,
    [switch]$SkipCleanup,
    [switch]$RunSmokeTests,
    [switch]$SkipPublish,
    [switch]$SkipDrip,
    [switch]$RebuildImages,
    [switch]$RebuildAppImage
)

$ErrorActionPreference = "Stop"

$scriptPath = Join-Path $PSScriptRoot "scripts\start-local-testnet.ps1"
& $scriptPath @PSBoundParameters
