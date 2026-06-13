# Docker build script with retry logic and network optimizations (PowerShell version)

param(
    [string]$BuildPreset,
    [switch]$NoCache,
    [string]$Service,
    [switch]$Help
)

# Show help
if ($Help) {
    Write-Host @"
Docker Build Script for Chain Registry

Usage:
    .\build-docker.ps1 [OPTIONS]

Options:
    -BuildPreset <name> Use specific profile (testnet, faucet, etc.)
    -NoCache            Build without cache
    -Service <name>     Build specific service only
    -Help               Show this help

Examples:
    .\build-docker.ps1                           # Build default services
    .\build-docker.ps1 -BuildPreset testnet      # Build with testnet profile
    .\build-docker.ps1 -NoCache                  # Clean build
    .\build-docker.ps1 -Service node             # Build only node service
"@
    exit 0
}

# Colors
$Red = "`e[31m"
$Green = "`e[32m"
$Yellow = "`e[33m"
$NC = "`e[0m"

Write-Host "$Green Chain Registry Docker Build Script $NC"
Write-Host "===================================="

$script:UseDockerComposeV2 = $true

function Invoke-Compose {
    param(
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Args
    )

    if ($script:UseDockerComposeV2) {
        & docker compose @Args
    } else {
        & docker-compose @Args
    }
}

# Function to build with retry
function Build-WithRetry {
    param(
        [string[]]$BuildArgs
    )
    
    $maxAttempts = 3
    $attempt = 1
    
    while ($attempt -le $maxAttempts) {
        Write-Host "$Yellow Build attempt $attempt of $maxAttempts...$NC"

        Invoke-Compose build --progress=plain @BuildArgs
        if ($LASTEXITCODE -eq 0) {
            Write-Host "$Green Build successful!$NC"
            return $true
        }
        
        Write-Host "$Red Build failed. Retrying in 10 seconds...$NC"
        Start-Sleep -Seconds 10
        $attempt++
    }
    
    Write-Host "$Red Build failed after $maxAttempts attempts.$NC"
    return $false
}

# Check for required commands
function Test-CommandExists {
    param([string]$Command)
    $null = Get-Command $Command -ErrorAction SilentlyContinue
    return $?
}

if (-not (Test-CommandExists "docker")) {
    Write-Host "$Red Error: Docker is not installed$NC"
    exit 1
}

# Check for docker-compose (v1) or docker compose (v2)
$composeV2 = $false
try {
    $null = docker compose version 2>$null
    if ($LASTEXITCODE -eq 0) {
        $composeV2 = $true
    }
} catch {}

if (-not $composeV2 -and -not (Test-CommandExists "docker-compose")) {
    Write-Host "$Red Error: docker-compose is not installed$NC"
    exit 1
}

if (-not $composeV2) {
    $script:UseDockerComposeV2 = $false
}

# Show build info
Write-Host ""
Write-Host "Build Configuration:"
Write-Host "  Profile: $(if ($BuildPreset) { $BuildPreset } else { 'default' })"
Write-Host "  No Cache: $NoCache"
Write-Host "  Service: $(if ($Service) { $Service } else { 'all' })"
Write-Host ""

# Pre-pull base images to avoid timeout during build
Write-Host "$Yellow Pre-pulling base images...$NC"
docker pull node:20-slim 2>$null
docker pull ubuntu:24.04 2>$null
docker pull ipfs/kubo:v0.27.0 2>$null
docker pull ghcr.io/foundry-rs/foundry:latest 2>$null
docker pull postgres:15-alpine 2>$null
docker pull nginx:alpine 2>$null

# Build command arguments
$buildArgs = @()

if ($BuildPreset) {
    $buildArgs += "--profile $BuildPreset"
}

if ($NoCache) {
    $buildArgs += "--no-cache"
}

if ($Service) {
    $buildArgs += $Service
}

Write-Host ""
Write-Host "$Yellow Starting build...$NC"
Write-Host "Command: $(if ($script:UseDockerComposeV2) { 'docker compose' } else { 'docker-compose' }) build $buildArgs"
Write-Host ""

# Run build with retry
$buildSuccess = Build-WithRetry -BuildArgs $buildArgs

if ($buildSuccess) {
    Write-Host ""
    Write-Host "$Green ====================================$NC"
    Write-Host "$Green Build completed successfully!$NC"
    Write-Host "$Green ====================================$NC"
    Write-Host ""
    Write-Host "Next steps:"
    Write-Host "  1. Start services: docker compose up -d"
    Write-Host "  2. Check status: docker compose ps"
    Write-Host "  3. View logs: docker compose logs -f"
    Write-Host ""
    exit 0
} else {
    Write-Host ""
    Write-Host "$Red ====================================$NC"
    Write-Host "$Red Build failed!$NC"
    Write-Host "$Red ====================================$NC"
    Write-Host ""
    Write-Host "Troubleshooting:"
    Write-Host "  1. Check internet connection"
    Write-Host "  2. Try: docker system prune -f"
    Write-Host "  3. Try: .\build-docker.ps1 -NoCache"
    Write-Host "  4. Increase Docker memory limit (if on Docker Desktop)"
    Write-Host ""
    exit 1
}
