# Docker build script optimized for Windows (PowerShell)
# Uses alternative approaches to avoid common Windows Docker issues

param(
    [switch]$UsePrebuilt,
    [switch]$UseWindowsDockerfile,
    [switch]$NoCache,
    [switch]$Help
)

if ($Help) {
    Write-Host @"
Docker Build Script for Windows

Usage:
    .\build-docker-windows.ps1 [OPTIONS]

Options:
    -UsePrebuilt        Use pre-built images from GitHub (fastest)
    -UseWindowsDockerfile  Use Windows-optimized Dockerfile
    -NoCache            Build without cache
    -Help               Show this help

Examples:
    .\build-docker-windows.ps1 -UsePrebuilt           # Use ghcr.io images
    .\build-docker-windows.ps1 -UseWindowsDockerfile  # Build with Windows Dockerfile
    .\build-docker-windows.ps1 -NoCache               # Clean build

Note: Standard docker-compose build often fails on Windows due to Rust install.
Use -UseWindowsDockerfile or -UsePrebuilt for better results.
"@
    exit 0
}

Write-Host "========================================"
Write-Host "Chain Registry Docker Build (Windows)"
Write-Host "========================================"
Write-Host ""

# Option 1: Use pre-built images (FASTEST)
if ($UsePrebuilt) {
    Write-Host "[INFO] Using pre-built images from GitHub Container Registry..."
    Write-Host ""
    Write-Host "To use pre-built images:"
    Write-Host "1. Login to GitHub Container Registry:"
    Write-Host "   docker login ghcr.io -u YOUR_GITHUB_USERNAME"
    Write-Host ""
    Write-Host "2. Pull and run:"
    Write-Host "   docker-compose -f docker-compose.prebuilt.yml up -d"
    Write-Host ""
    Write-Host "Or update docker-compose.yml to use:"
    Write-Host "   image: ghcr.io/YOUR_USERNAME/chain-registry:minimal"
    exit 0
}

# Option 2: Use Windows-optimized Dockerfile
if ($UseWindowsDockerfile) {
    Write-Host "[INFO] Building with Windows-optimized Dockerfile..."
    Write-Host "This uses rust:1.75-bookworm instead of installing Rust via curl"
    Write-Host ""
    
    $buildCmd = "docker build"
    if ($NoCache) {
        $buildCmd += " --no-cache"
    }
    $buildCmd += " -f Dockerfile.windows -t chain-registry:windows ."
    
    Write-Host "Running: $buildCmd"
    Invoke-Expression $buildCmd
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "[SUCCESS] Build completed!"
        Write-Host "Image: chain-registry:windows"
    } else {
        Write-Host ""
        Write-Host "[ERROR] Build failed!"
        exit 1
    }
    exit 0
}

# Option 3: Try standard build with workarounds
Write-Host "[INFO] Attempting standard build with Windows workarounds..."
Write-Host ""

# Pre-pull images separately (helps with Windows networking)
Write-Host "[INFO] Pre-pulling base images..."
docker pull rust:1.75-bookworm
if ($LASTEXITCODE -ne 0) {
    Write-Host "[WARN] Failed to pull rust:1.75-bookworm, trying alternative..."
}

# Build with explicit network settings
Write-Host ""
Write-Host "[INFO] Starting build..."

$env:DOCKER_BUILDKIT = "0"  # Disable BuildKit for Windows compatibility
$env:COMPOSE_DOCKER_CLI_BUILD = "0"

$buildArgs = ""
if ($NoCache) {
    $buildArgs = "--no-cache"
}

# Try building with docker-compose
docker-compose build $buildArgs node

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "[SUCCESS] Build completed!"
} else {
    Write-Host ""
    Write-Host "[ERROR] Standard build failed!"
    Write-Host ""
    Write-Host "This is common on Windows. Try these alternatives:"
    Write-Host ""
    Write-Host "Option 1: Use Windows-optimized Dockerfile"
    Write-Host "   .\build-docker-windows.ps1 -UseWindowsDockerfile"
    Write-Host ""
    Write-Host "Option 2: Use pre-built images from GitHub"
    Write-Host "   .\build-docker-windows.ps1 -UsePrebuilt"
    Write-Host ""
    Write-Host "Option 3: Use WSL2 (recommended for development)"
    Write-Host "   wsl -d Ubuntu"
    Write-Host "   cd /mnt/f/project/chain-registry/chain-registry"
    Write-Host "   ./build-docker.sh"
    exit 1
}
