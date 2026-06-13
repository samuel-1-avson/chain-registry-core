# DIST-301 — Verify GitHub release exists and install script URL resolves.
#
# Usage:
#   .\testnet\verify-dist-301.ps1 -Version v0.1.0-testnet
#   .\testnet\verify-dist-301.ps1 -Version v0.1.0-testnet -RunInstallSh

param(
    [string]$Version = "v0.1.0-testnet",
    [string]$GithubRepo = "",
    [switch]$RunInstallSh
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
Set-Location $repoRoot

if (-not $GithubRepo) {
    $GithubRepo = $env:CREG_GITHUB_REPO
}
if (-not $GithubRepo) {
    try {
        $remote = git remote get-url origin 2>$null
        if ($remote -match 'github\.com[:/](.+?)(?:\.git)?$') {
            $GithubRepo = $matches[1]
        }
    } catch { }
}
if (-not $GithubRepo) {
    $GithubRepo = "samuel-1-avson/chain-registry-blockchain-CREG-"
}

function Log($msg) { Write-Host "[dist-301] $msg" }

$assets = @(
    "chain-registry-$Version-linux-amd64.tar.gz",
    "chain-registry-$Version-windows-amd64.zip"
)

Log "GitHub repo: $GithubRepo"
Log "Version: $Version"

$releaseUrl = "https://api.github.com/repos/$GithubRepo/releases/tags/$Version"
try {
    $release = Invoke-RestMethod -Uri $releaseUrl -TimeoutSec 30
    Log "Release found: $($release.name) published $($release.published_at)"
    foreach ($name in $assets) {
        $asset = $release.assets | Where-Object { $_.name -eq $name }
        if ($asset) {
            Log "OK asset: $name ($([math]::Round($asset.size / 1MB, 2)) MB)"
        } else {
            Log "MISSING asset: $name"
        }
    }
} catch {
    Log "Release not found at $releaseUrl"
    Log "Create with: git tag $Version && git push origin $Version"
    Log "Workflow: .github/workflows/release-binaries.yml"
    exit 1
}

$linuxAsset = $release.assets | Where-Object { $_.name -eq "chain-registry-$Version-linux-amd64.tar.gz" }
if (-not $linuxAsset) {
    Log "MISSING linux asset for download check"
    exit 1
}
$linuxUrl = $linuxAsset.browser_download_url
try {
    if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
        curl.exe -sI -L --max-time 20 $linuxUrl | Select-Object -First 1 | ForEach-Object {
            if ($_ -match '^HTTP/\S+\s+([23]\d\d)') {
                Log "OK HEAD $linuxUrl"
            } else {
                throw "unexpected response: $_"
            }
        }
    } else {
        $head = Invoke-WebRequest -Uri $linuxUrl -Method Head -TimeoutSec 20 -MaximumRedirection 5
        if ($head.StatusCode -ge 200 -and $head.StatusCode -lt 400) {
            Log "OK HEAD $linuxUrl"
        }
    }
} catch {
    Log "HEAD failed for linux tarball: $($_.Exception.Message)"
    exit 1
}

if ($RunInstallSh) {
    if (-not (Get-Command bash -ErrorAction SilentlyContinue)) {
        Log "bash not found - skip -RunInstallSh on Windows or use Git Bash"
    } else {
        $tmpdir = Join-Path $env:TEMP "creg-dist-301-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Force -Path $tmpdir | Out-Null
        $env:INSTALL_DIR = $tmpdir
        $env:CREG_GITHUB_REPO = $GithubRepo
        Log "Running install-creg.sh --version $Version -> $tmpdir"
        bash ./scripts/install-creg.sh --version $Version
        if ($LASTEXITCODE -ne 0) { throw "install-creg.sh failed" }
        if (-not (Test-Path (Join-Path $tmpdir "creg"))) { throw "creg binary missing after install" }
        Log "OK install-creg.sh installed creg to $tmpdir"
    }
}

Log "DIST-301 verify PASSED for $Version"
