# Install creg + creg-node from GitHub Releases or build from source.
#
# Usage:
#   .\scripts\install-creg.ps1
#   .\scripts\install-creg.ps1 -Version v0.1.0-testnet
#   .\scripts\install-creg.ps1 -BuildFromSource

param(
    [string]$Version = "",
    [switch]$BuildFromSource,
    [string]$InstallDir = "$env:USERPROFILE\.creg\bin"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $repoRoot

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

if ($BuildFromSource) {
    Write-Host "Building creg + creg-node from source..." -ForegroundColor Cyan
    cargo build --release --package chain-registry-cli --package chain-registry-node
    Copy-Item "target\release\creg.exe" (Join-Path $InstallDir "creg.exe") -Force
    Copy-Item "target\release\creg-node.exe" (Join-Path $InstallDir "creg-node.exe") -Force
    Write-Host "Installed to $InstallDir" -ForegroundColor Green
    exit 0
}

if (-not $Version) {
    Write-Host "No -Version specified. Building from source (use -Version vX.Y.Z when a GitHub release exists)." -ForegroundColor Yellow
    & $MyInvocation.MyCommand.Path -BuildFromSource -InstallDir $InstallDir
    exit $LASTEXITCODE
}

$githubRepo = $env:CREG_GITHUB_REPO
if (-not $githubRepo) {
    try {
        $remote = git remote get-url origin 2>$null
        if ($remote -match 'github\.com[:/](.+?)(?:\.git)?$') {
            $githubRepo = $matches[1]
        }
    } catch { }
}
if (-not $githubRepo) {
    $githubRepo = "samuel-1-avson/chain-registry-core"
}

$asset = "chain-registry-$Version-windows-amd64.zip"
$url = "https://github.com/$githubRepo/releases/download/$Version/$asset"
$zip = Join-Path $env:TEMP $asset

Write-Host "Downloading $url ..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $url -OutFile $zip
Expand-Archive -Path $zip -DestinationPath $InstallDir -Force
Remove-Item $zip -Force

Write-Host "Installed creg + creg-node to $InstallDir" -ForegroundColor Green
Write-Host "Add to PATH: `$env:Path += ';$InstallDir'"
