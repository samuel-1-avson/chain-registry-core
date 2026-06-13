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

$RepoRoot = Split-Path -Parent $PSScriptRoot
$EnvFile = Join-Path $RepoRoot ".env.local-testnet"
$ComposeFile = Join-Path $RepoRoot "docker-compose.local-testnet.yml"
$SmokeScript = Join-Path $PSScriptRoot "smoke-test-local-testnet.ps1"

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Args
    )

    Write-Host "> docker $($Args -join ' ')"
    & docker @Args
    if ($LASTEXITCODE -ne 0) {
        throw "docker $($Args -join ' ') failed with exit code $LASTEXITCODE"
    }
}

function Invoke-Compose {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Args
    )

    Invoke-Checked -Args (@(
        "compose",
        "--env-file", $EnvFile,
        "-f", $ComposeFile
    ) + $Args)
}

function Get-UtcStamp {
    return (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}

function Save-StatsSnapshot {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $stats = Invoke-WebRequest -Uri "http://localhost:8080/v1/chain/stats" -UseBasicParsing -TimeoutSec 10
    $stats.Content | Set-Content -LiteralPath $Path -Encoding ASCII
}

Set-Location $RepoRoot

if ($DurationMinutes -lt 1) {
    throw "DurationMinutes must be at least 1."
}
if ($IntervalSeconds -lt 5) {
    throw "IntervalSeconds must be at least 5."
}
if (-not (Test-Path $EnvFile)) {
    throw "Missing .env.local-testnet. Run ./local-testnet.ps1 first."
}
if (-not (Test-Path $SmokeScript)) {
    throw "Missing smoke script: $SmokeScript"
}

$runId = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss")
$runDir = Join-Path $RepoRoot (Join-Path $LogDirectory $runId)
New-Item -ItemType Directory -Force -Path $runDir | Out-Null

$summaryPath = Join-Path $runDir "summary.log"
$services = @(
    "node-1",
    "node-2",
    "node-3",
    "observer",
    "indexer",
    "faucet",
    "relayer"
)
if (-not $SkipExplorer) {
    $services += "web-explorer"
}

function Write-Summary {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $line = "$(Get-UtcStamp) $Message"
    Write-Host $line
    $line | Add-Content -LiteralPath $summaryPath -Encoding ASCII
}

$deadline = (Get-Date).AddMinutes($DurationMinutes)
$iteration = 0
$failed = $false

Write-Summary "Starting local soak: duration=${DurationMinutes}m interval=${IntervalSeconds}s skipExplorer=$SkipExplorer skipPublish=$SkipPublish"
Save-StatsSnapshot -Path (Join-Path $runDir "stats-start.json")

try {
    while ((Get-Date) -lt $deadline) {
        $iteration += 1
        Write-Summary "Iteration $iteration started"

        $smokeArgs = @{}
        if ($SkipExplorer) {
            $smokeArgs.SkipExplorer = $true
        }
        if ($SkipPublish) {
            $smokeArgs.SkipPublish = $true
        }
        if ($SkipDrip) {
            $smokeArgs.SkipDrip = $true
        }
        if ($SkipInclusionWait) {
            $smokeArgs.SkipInclusionWait = $true
        }
        $smokeArgs.InclusionTimeoutSeconds = $InclusionTimeoutSeconds
        $smokeArgs.InclusionPollSeconds = $InclusionPollSeconds

        & $SmokeScript @smokeArgs
        Save-StatsSnapshot -Path (Join-Path $runDir "stats-$iteration.json")
        Write-Summary "Iteration $iteration passed"

        $remaining = [int]($deadline - (Get-Date)).TotalSeconds
        if ($remaining -le 0) {
            break
        }

        Start-Sleep -Seconds ([Math]::Min($IntervalSeconds, $remaining))
    }
} catch {
    $failed = $true
    Write-Summary "FAILED: $($_.Exception.Message)"
    throw
} finally {
    Write-Summary "Collecting final chain stats and service logs"
    try {
        Save-StatsSnapshot -Path (Join-Path $runDir "stats-final.json")
    } catch {
        Write-Summary "Could not collect final stats: $($_.Exception.Message)"
    }

    try {
        Invoke-Compose -Args (@("logs", "--no-color", "--tail", "500") + $services) `
            | Set-Content -LiteralPath (Join-Path $runDir "compose-tail.log") -Encoding ASCII
    } catch {
        Write-Summary "Could not collect compose logs: $($_.Exception.Message)"
    }

    if (-not $failed) {
        Write-Summary "Local soak passed. Artifacts: $runDir"
    }
}
