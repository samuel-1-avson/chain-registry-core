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

$RepoRoot = Split-Path -Parent $PSScriptRoot
$EnvFile = Join-Path $RepoRoot ".env.local-testnet"
$EnvExample = Join-Path $RepoRoot ".env.local-testnet.example"
$ComposeFile = Join-Path $RepoRoot "docker-compose.local-testnet.yml"

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

function Wait-HttpOk {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$Url,
        [int]$TimeoutSeconds = 90
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        try {
            $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 5
            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 300) {
                Write-Host "  OK ${Name}: $Url"
                return
            }
        } catch {
            Start-Sleep -Seconds 2
        }
    } while ((Get-Date) -lt $deadline)

    throw "$Name did not become healthy at $Url within $TimeoutSeconds seconds"
}

Set-Location $RepoRoot

if (-not (Test-Path $EnvFile)) {
    if (-not (Test-Path $EnvExample)) {
        throw "Missing $EnvExample"
    }
    Copy-Item -LiteralPath $EnvExample -Destination $EnvFile
    Write-Host "Created .env.local-testnet from .env.local-testnet.example"
}

Write-Host "Checking Docker..."
Invoke-Checked @("version")

if (-not $SkipCleanup) {
    Write-Host "Resetting local testnet containers and volumes..."
    Invoke-Compose -Args @("down", "-v", "--remove-orphans")
} else {
    Write-Host "Skipping cleanup; existing local testnet volumes will be reused."
}

if ($RebuildImages) {
    Write-Host "Rebuilding local Docker images..."
    if ($RebuildAppImage) {
        Invoke-Compose -Args @("build", "app-image")
    } else {
        Write-Host "  Skipping app-image rebuild. Pass -RebuildAppImage to rebuild the Rust app image."
    }
    if (-not $SkipExplorer) {
        Invoke-Compose -Args @("build", "web-explorer-image")
    }
}

Write-Host "Starting base services..."
Invoke-Compose -Args @("up", "-d", "ipfs", "anvil", "postgres")

Write-Host "Deploying local contracts against Anvil..."
Invoke-Compose -Args @("up", "--force-recreate", "deploy-contracts")

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

Write-Host "Starting local node services..."
Invoke-Compose -Args (@("up", "-d") + $services)

Write-Host "Waiting for local endpoints..."
Wait-HttpOk -Name "node-1" -Url "http://localhost:8080/v1/health"
Wait-HttpOk -Name "observer" -Url "http://localhost:8087/v1/health"
Wait-HttpOk -Name "faucet" -Url "http://localhost:8082/health"
Wait-HttpOk -Name "relayer" -Url "http://localhost:8083/health"
Wait-HttpOk -Name "indexer" -Url "http://localhost:8084/health"
if (-not $SkipExplorer) {
    Wait-HttpOk -Name "web explorer" -Url "http://localhost:3007/"
}

Write-Host ""
Write-Host "Local testnet is running."
Write-Host "  Node API:     http://localhost:8080/v1/health"
Write-Host "  Observer:     http://localhost:8087/v1/health"
Write-Host "  Faucet:       http://localhost:8082/health"
Write-Host "  Relayer:      http://localhost:8083/health"
Write-Host "  Indexer:      http://localhost:8084/health"
if (-not $SkipExplorer) {
    Write-Host "  Web Explorer: http://localhost:3007"
}
Write-Host ""

if ($RunSmokeTests) {
    $smokePath = Join-Path $PSScriptRoot "smoke-test-local-testnet.ps1"
    if (-not (Test-Path $smokePath)) {
        throw "Missing smoke script: $smokePath"
    }

    $smokeArgs = @{}
    if ($SkipPublish) {
        $smokeArgs.SkipPublish = $true
    }
    if ($SkipDrip) {
        $smokeArgs.SkipDrip = $true
    }
    if ($SkipExplorer) {
        $smokeArgs.SkipExplorer = $true
    }

    & $smokePath @smokeArgs
}
