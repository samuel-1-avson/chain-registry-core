# Build Docker Image on Windows - Version 2
# Uses pre-built Rust image to avoid network issues

param(
    [switch]$NoCache,
    [switch]$Help
)

if ($Help) {
    Write-Host @"
Docker Build Script for Windows (Version 2)

This script builds the Docker image using a pre-built Rust base image
to avoid network timeout issues with rustup on Windows.

Usage:
    .\build-docker-windows-v2.ps1 [OPTIONS]

Options:
    -NoCache    Build without cache
    -Help       Show this help

Example:
    .\build-docker-windows-v2.ps1
"@
    exit 0
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Chain Registry Docker Build (Windows V2)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check Docker
Write-Host "[INFO] Checking Docker..." -ForegroundColor Yellow
try {
    $dockerVersion = docker --version 2>$null
    if ($LASTEXITCODE -ne 0) { throw "Docker not found" }
    Write-Host "[OK] Docker found: $dockerVersion" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Docker not installed or not running" -ForegroundColor Red
    exit 1
}

# Set build args
$buildArgs = ""
if ($NoCache) {
    $buildArgs = "--no-cache"
    Write-Host "[INFO] Building without cache" -ForegroundColor Yellow
}

# Build using Windows-optimized Dockerfile
Write-Host ""
Write-Host "[INFO] Building Docker image..." -ForegroundColor Yellow
Write-Host "This uses rust:1.75-bookworm as base (pre-installed Rust)" -ForegroundColor Gray
Write-Host "Estimated time: 10-20 minutes" -ForegroundColor Gray
Write-Host ""

$startTime = Get-Date

docker build -f Dockerfile.windows -t chain-registry:latest $buildArgs .

$buildResult = $LASTEXITCODE
$endTime = Get-Date
$duration = $endTime - $startTime

Write-Host ""
if ($buildResult -eq 0) {
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "BUILD SUCCESSFUL!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Image: chain-registry:latest" -ForegroundColor Cyan
    Write-Host "Duration: $($duration.ToString('mm\:ss'))" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Verify with: docker images | findstr chain-registry" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "  1. docker-compose up -d node" -ForegroundColor White
    Write-Host "  2. curl http://localhost:8080/v1/health" -ForegroundColor White
} else {
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "BUILD FAILED!" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Troubleshooting:" -ForegroundColor Yellow
    Write-Host "  1. Check Docker Desktop is running" -ForegroundColor White
    Write-Host "  2. Increase Docker memory to 8GB+" -ForegroundColor White
    Write-Host "  3. Try: docker system prune -f" -ForegroundColor White
    Write-Host "  4. Use pre-built images instead:" -ForegroundColor White
    Write-Host "     docker-compose -f docker-compose.prebuilt.yml up -d" -ForegroundColor Gray
    exit 1
}
