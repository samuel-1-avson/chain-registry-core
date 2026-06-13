# Install Foundry cast/forge into testnet/.tools/foundry (no admin PATH required).
#
# Usage:
#   .\testnet\install-foundry.ps1
#   $env:PATH = "$PWD\testnet\.tools\foundry;$env:PATH"
#   cast --version

param(
    [string]$Version = "nightly"
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$toolsDir = Join-Path $scriptDir ".tools\foundry"
$castExe = Join-Path $toolsDir "cast.exe"

if (Test-Path $castExe) {
    Write-Host "Foundry already installed: $toolsDir" -ForegroundColor Green
    Write-Host "cast --version:"
    & $castExe --version
    Write-Host ""
    Write-Host "For this session:"
    Write-Host "  `$env:PATH = `"$toolsDir;`$env:PATH`""
    exit 0
}

New-Item -ItemType Directory -Force -Path $toolsDir | Out-Null
$zip = Join-Path $env:TEMP "foundry_$Version_windows_amd64.zip"
$url = "https://github.com/foundry-rs/foundry/releases/download/$Version/foundry_${Version}_win32_amd64.zip"

Write-Host "Downloading Foundry ($Version)..." -ForegroundColor Cyan
Write-Host "  $url"
$curl = Get-Command curl.exe -ErrorAction SilentlyContinue
if ($curl) {
    & curl.exe -fL --progress-bar -o $zip $url
    if ($LASTEXITCODE -ne 0) { throw "curl download failed (exit $LASTEXITCODE)" }
} else {
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing -TimeoutSec 600
}
if (-not (Test-Path $zip) -or (Get-Item $zip).Length -lt 1MB) {
    throw "Download incomplete. Try: winget install Foundry.Foundry  OR  https://getfoundry.sh"
}

$extract = Join-Path $env:TEMP "foundry_extract_$Version"
if (Test-Path $extract) { Remove-Item $extract -Recurse -Force }
Expand-Archive -Path $zip -DestinationPath $extract -Force

$foundCast = Get-ChildItem -Path $extract -Filter cast.exe -Recurse | Select-Object -First 1
if (-not $foundCast) {
    throw "cast.exe not found in archive. Check Foundry release layout or install manually."
}

foreach ($exe in @("cast.exe", "forge.exe", "anvil.exe", "chisel.exe")) {
    $src = Get-ChildItem -Path $extract -Filter $exe -Recurse | Select-Object -First 1
    if ($src) {
        Copy-Item -Force $src.FullName (Join-Path $toolsDir $exe)
    }
}

Remove-Item $zip -Force -ErrorAction SilentlyContinue
Remove-Item $extract -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Installed to $toolsDir" -ForegroundColor Green
& $castExe --version
Write-Host ""
Write-Host "Add to PATH for this PowerShell session:"
Write-Host "  `$env:PATH = `"$toolsDir;`$env:PATH`""
