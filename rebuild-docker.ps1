<#
.SYNOPSIS
    Rebuild all Chain Registry Docker images from scratch.

.DESCRIPTION
    Builds the full application image (Rust node, CLI, indexer, faucet, relayer),
    the web explorer image, and tags them for docker-compose stacks.

    This is the canonical "rebuild everything in Docker" entry point on Windows.
    Expect 20-60 minutes for a cold --NoCache build depending on CPU, RAM, and
    Docker Desktop settings (8 GB+ RAM recommended).

.PARAMETER NoCache
    Pass --no-cache to docker build (ignores layer cache).

.PARAMETER SkipExplorer
    Skip the web explorer image build.

.PARAMETER SkipVerify
    Skip post-build binary smoke checks inside the new images.

.PARAMETER PruneBuilder
    Run "docker builder prune -f" before building (frees BuildKit cache).

.PARAMETER Dockerfile
    App image Dockerfile: auto (default), default (full Ubuntu), windows, or local.
    On Windows, auto selects Dockerfile.windows.

.PARAMETER LogFile
    Path for plain build output. Default: docker_build.log in repo root.

.EXAMPLE
    .\rebuild-docker.ps1

.EXAMPLE
    .\rebuild-docker.ps1 -NoCache -PruneBuilder

.EXAMPLE
    .\rebuild-docker.ps1 -SkipExplorer -SkipVerify
#>

param(
    [switch]$NoCache,
    [switch]$SkipExplorer,
    [switch]$SkipVerify,
    [switch]$PruneBuilder,
    [ValidateSet("default", "windows", "local", "auto")]
    [string]$Dockerfile = "auto",
    [string]$LogFile = "",
    [switch]$Help
)

$ErrorActionPreference = "Stop"

if ($Help) {
    Get-Help $MyInvocation.MyCommand.Path -Full
    exit 0
}

$RepoRoot = $PSScriptRoot
if (-not $RepoRoot) {
    $RepoRoot = Get-Location
}
Set-Location $RepoRoot

$AppTags = @(
    "chain-registry-app:latest",
    "chain-registry:latest"
)
$ExplorerTag = "chain-registry-web-explorer:latest"

$DockerfileMap = @{
    default = "Dockerfile"
    windows = "Dockerfile.windows"
    local   = "Dockerfile.local"
}

if ($Dockerfile -eq "auto") {
    if ($IsWindows -or $env:OS -eq "Windows_NT") {
        $Dockerfile = "windows"
    } else {
        $Dockerfile = "default"
    }
}

$DockerfilePath = $DockerfileMap[$Dockerfile]
if (-not (Test-Path -LiteralPath (Join-Path $RepoRoot $DockerfilePath))) {
    throw "Dockerfile not found: $DockerfilePath"
}

if ([string]::IsNullOrWhiteSpace($LogFile)) {
    $LogFile = Join-Path $RepoRoot "docker_build.log"
}

function Write-Step([string]$Message) {
    $stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$stamp] $Message"
}

if ($DockerfilePath -eq "Dockerfile.windows") {
    Write-Step "Using Dockerfile.windows (recommended on Windows Docker Desktop)."
} elseif ($DockerfilePath -eq "Dockerfile.local") {
    foreach ($bin in @("target/release/creg-node", "target/release/creg")) {
        if (-not (Test-Path -LiteralPath (Join-Path $RepoRoot $bin))) {
            throw "Missing $bin for Dockerfile.local. Use -Dockerfile windows for in-container builds."
        }
    }
}

function Test-DockerReady {
    Write-Step "Checking Docker..."
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        throw "Docker is not installed or not on PATH."
    }
    docker version *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "Docker CLI failed. Is Docker Desktop running?"
    }
    docker info *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "Docker daemon is not reachable. Start Docker Desktop and retry."
    }
    Write-Step "Docker is ready."
}

function Get-SourceDateEpoch {
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        return $null
    }
    try {
        $epoch = git -C $RepoRoot log -1 --pretty=%ct 2>$null
        if ($LASTEXITCODE -eq 0 -and $epoch) {
            return $epoch.Trim()
        }
    } catch {
        return $null
    }
    return $null
}

function Invoke-DockerBuild {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Args,
        [Parameter(Mandatory = $true)]
        [string]$Label,
        [int]$MaxAttempts = 3
    )

    $attempt = 1
    while ($attempt -le $MaxAttempts) {
        Write-Step "$Label (attempt $attempt of $MaxAttempts)..."
        Write-Step "  docker $($Args -join ' ')"

        $header = (
            "================================================================================`n" +
            "$Label attempt $attempt $(Get-Date -Format o)`n" +
            "docker $($Args -join ' ')`n" +
            "================================================================================"
        )
        Add-Content -LiteralPath $LogFile -Value $header -Encoding utf8

        # Docker writes progress to stderr; do not let PowerShell treat that as a terminating error.
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            & docker @Args 2>&1 | Tee-Object -FilePath $LogFile -Append
            $buildExit = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $prevEap
        }

        if ($buildExit -eq 0) {
            Write-Step "$Label succeeded."
            return
        }

        if ($attempt -ge $MaxAttempts) {
            throw "$Label failed after $MaxAttempts attempts. See $LogFile"
        }

        Write-Host "Build failed; retrying in 15 seconds..." -ForegroundColor Yellow
        Start-Sleep -Seconds 15
        $attempt++
    }
}

function Test-BuiltImage {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Image,
        [Parameter(Mandatory = $true)]
        [string]$Entrypoint,
        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    Write-Step "Verifying $Label in $Image..."
    & docker run --rm --entrypoint $Entrypoint $Image --version 2>&1 | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Verification failed for $Label ($Image)"
    }
    Write-Step "$Label OK."
}

function Test-BuiltBinary {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Image,
        [Parameter(Mandatory = $true)]
        [string]$BinaryPath,
        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    # creg-node has no --version; a full start needs a writable CREG_DATA_DIR.
    Write-Step "Verifying $Label binary in $Image..."
    & docker run --rm --entrypoint /bin/sh $Image -c "test -x $BinaryPath" 2>&1 | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Verification failed for $Label ($Image): $BinaryPath missing or not executable"
    }
    Write-Step "$Label OK."
}

$start = Get-Date
Write-Host ""
Write-Host "Chain Registry - full Docker rebuild" -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan
Write-Host "Repo:       $RepoRoot"
Write-Host "Dockerfile: $DockerfilePath"
Write-Host "No cache:   $NoCache"
Write-Host "Log file:   $LogFile"
Write-Host ""

Test-DockerReady

$env:DOCKER_BUILDKIT = "1"
$sourceDateEpoch = Get-SourceDateEpoch
if ($sourceDateEpoch) {
    $env:SOURCE_DATE_EPOCH = $sourceDateEpoch
    Write-Step "SOURCE_DATE_EPOCH=$sourceDateEpoch"
}

if ($PruneBuilder) {
    Write-Step "Pruning Docker builder cache..."
    docker builder prune -f 2>&1 | Out-Host
}

Write-Step "Pre-pulling base images..."
$baseImages = @(
    "node:20-slim",
    "ubuntu:24.04",
    "rust:1.90-slim-bookworm",
    "nginx:alpine"
)
foreach ($img in $baseImages) {
    docker pull $img 2>&1 | Out-Null
}

# --- Main app image (Rust workspace + embedded explorer dist in Dockerfile) ---
$appBuildArgs = @(
    "build",
    "-f", $DockerfilePath,
    "--progress=plain"
)
foreach ($tag in $AppTags) {
    $appBuildArgs += @("-t", $tag)
}
if ($NoCache) {
    $appBuildArgs += "--no-cache"
}
if ($sourceDateEpoch) {
    $appBuildArgs += @("--build-arg", "SOURCE_DATE_EPOCH=$sourceDateEpoch")
}
$appBuildArgs += "."

Invoke-DockerBuild -Args $appBuildArgs -Label "App image ($DockerfilePath)"

# --- Web explorer (standalone nginx image for compose stacks) ---
if (-not $SkipExplorer) {
    $explorerArgs = @(
        "build",
        "-f", "Dockerfile",
        "--progress=plain",
        "-t", $ExplorerTag
    )
    if ($NoCache) {
        $explorerArgs += "--no-cache"
    }
    $explorerArgs += "."

    Push-Location (Join-Path $RepoRoot "explorer")
    try {
        Invoke-DockerBuild -Args $explorerArgs -Label "Web explorer image"
    } finally {
        Pop-Location
    }
} else {
    Write-Step "Skipping web explorer build (-SkipExplorer)."
}

# --- Verify ---
if (-not $SkipVerify) {
    $primaryTag = $AppTags[0]
    Test-BuiltImage -Image $primaryTag -Entrypoint "/app/creg" -Label "creg CLI"
    Test-BuiltBinary -Image $primaryTag -BinaryPath "/app/creg-node" -Label "creg-node"
    if (-not $SkipExplorer) {
        Write-Step "Verifying explorer image responds..."
        $cid = docker create $ExplorerTag 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Could not create container from $ExplorerTag"
        }
        docker rm $cid | Out-Null
        Write-Step "Explorer image OK."
    }
}

$elapsed = (Get-Date) - $start
Write-Host ""
Write-Host "====================================" -ForegroundColor Green
Write-Host "Docker rebuild complete" -ForegroundColor Green
Write-Host "====================================" -ForegroundColor Green
Write-Host "Duration: $($elapsed.ToString('hh\:mm\:ss'))"
Write-Host ""
Write-Host "Images:"
docker images --format "  {{.Repository}}:{{.Tag}}  {{.Size}}" |
    Select-String -Pattern "chain-registry" |
    ForEach-Object { $_.Line }
Write-Host ""
Write-Host "Next steps:"
Write-Host "  Single validator:  docker compose up -d --build"
Write-Host "  Local 3-node:      .\local-testnet.ps1 -SkipCleanup -RebuildImages -RebuildAppImage"
Write-Host "  Config smoke:      .\test-docker.ps1 -Quick"
Write-Host "  Full log:          $LogFile"
Write-Host ""
