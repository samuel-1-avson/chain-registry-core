# MAL-002 — run malicious fixture suite and write launch-gate evidence JSON.
#
# Usage:
#   .\testnet\malicious-fixtures-verify.ps1

param()

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
Set-Location $repoRoot

function Log($m) { Write-Host "[mal-002] $m" }

Log "Running validator malicious fixture tests..."
cargo test -p validator malicious_fixture_suite_static_analysis --locked -- --nocapture
if ($LASTEXITCODE -ne 0) { throw "malicious fixture tests failed" }

$fixtureRoot = Join-Path $scriptDir "malicious-fixtures"
$fixtures = Get-ChildItem -Path $fixtureRoot -Directory | Where-Object { Test-Path (Join-Path $_.FullName "meta.json") }

$report = @{
    timestamp = (Get-Date).ToUniversalTime().ToString("o")
    mal002    = $true
    count     = @($fixtures).Count
    fixtures  = @(
        $fixtures | ForEach-Object {
            $meta = Get-Content (Join-Path $_.FullName "meta.json") -Raw | ConvertFrom-Json
            @{ id = $meta.id; category = $meta.category; expected = $meta.expected_findings }
        }
    )
}

$outDir = Join-Path $scriptDir "malicious-fixtures-logs"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$outPath = Join-Path $outDir ("mal-002-{0}.json" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
$report | ConvertTo-Json -Depth 6 | Set-Content -Path $outPath -Encoding utf8
Log "MAL-002 verify PASSED ($($report.count) fixtures, evidence: $outPath)"
