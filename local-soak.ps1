param(
    [int]$DurationMinutes = 30,
    [int]$IntervalSeconds = 60,
    [switch]$SkipExplorer,
    [switch]$SkipPublish,
    [switch]$SkipDrip,
    [switch]$SkipInclusionWait,
    [int]$InclusionTimeoutSeconds = 180,
    [int]$InclusionPollSeconds = 5,
    [string]$LogDirectory = "tmp\local-soak"
)

$ErrorActionPreference = "Stop"

$scriptPath = Join-Path $PSScriptRoot "scripts\local-soak-testnet.ps1"
& $scriptPath @PSBoundParameters
