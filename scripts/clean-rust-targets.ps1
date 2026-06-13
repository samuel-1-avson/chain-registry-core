# Remove Rust/Cargo build trees under the chain-registry workspace (target, target-*).
# Reclaims disk from incremental artifacts, fingerprints, and debug/release outputs.
# These paths are already in .gitignore; this only deletes local build cache.
#
# Usage (from chain-registry/):
#   .\scripts\clean-rust-targets.ps1
#   .\scripts\clean-rust-targets.ps1 -WhatIf
#   .\scripts\clean-rust-targets.ps1 -Force
#
# Optional: also remove explorer frontend deps (~0.3 GB):
#   .\scripts\clean-rust-targets.ps1 -IncludeExplorerNodeModules

param(
    [switch]$WhatIf,
    [switch]$Force,
    [switch]$IncludeExplorerNodeModules
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$workspaceRoot = Split-Path -Parent $scriptDir
Set-Location $workspaceRoot

function Format-Bytes([long]$Bytes) {
    if ($Bytes -ge 1GB) { return "{0:N2} GB" -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return "{0:N2} MB" -f ($Bytes / 1MB) }
    if ($Bytes -ge 1KB) { return "{0:N2} KB" -f ($Bytes / 1KB) }
    return "$Bytes B"
}

function Get-DirectorySize([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return 0 }
    $sum = Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue |
        Measure-Object -Property Length -Sum
    if ($null -eq $sum.Sum) { return [long]0 }
    return [long]$sum.Sum
}

function Get-TargetDirectories([string]$Root) {
    Get-ChildItem -LiteralPath $Root -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -eq "target" -or $_.Name -like "target-*"
        } |
        Sort-Object Name
}

Write-Host ""
Write-Host "=== Clean Rust target directories ===" -ForegroundColor Cyan
Write-Host "Workspace: $workspaceRoot"
Write-Host ""

$targets = @(Get-TargetDirectories -Root $workspaceRoot)
$extra = @()
if ($IncludeExplorerNodeModules) {
    $nm = Join-Path $workspaceRoot "explorer\node_modules"
    if (Test-Path -LiteralPath $nm) {
        $extra += [PSCustomObject]@{ Name = "explorer\node_modules"; FullName = $nm }
    }
}

if ($targets.Count -eq 0 -and $extra.Count -eq 0) {
    Write-Host "No target/ or target-* directories found. Nothing to do." -ForegroundColor Green
    exit 0
}

$rows = @()
$totalBytes = [long]0

foreach ($dir in $targets) {
    $bytes = Get-DirectorySize -Path $dir.FullName
    $totalBytes += $bytes
    $rows += [PSCustomObject]@{
        Path = $dir.FullName
        Size = Format-Bytes $bytes
        Bytes = $bytes
    }
}

foreach ($item in $extra) {
    $bytes = Get-DirectorySize -Path $item.FullName
    $totalBytes += $bytes
    $rows += [PSCustomObject]@{
        Path = $item.FullName
        Size = Format-Bytes $bytes
        Bytes = $bytes
    }
}

$rows | Format-Table -AutoSize Path, Size
Write-Host "Total reclaimable: $(Format-Bytes $totalBytes)" -ForegroundColor Yellow
Write-Host ""

$runningNode = Get-Process -Name "creg-node" -ErrorAction SilentlyContinue
if ($runningNode) {
    Write-Host "WARN: creg-node is running (PIDs: $($runningNode.Id -join ', '))." -ForegroundColor Yellow
    Write-Host "      Stop the node first if deletion fails due to file locks." -ForegroundColor Yellow
    Write-Host ""
}

if ($WhatIf) {
    Write-Host "WhatIf: no directories were removed." -ForegroundColor Green
    exit 0
}

if (-not $Force) {
    $answer = Read-Host "Delete $($rows.Count) path(s) and free $(Format-Bytes $totalBytes)? [y/N]"
    if ($answer -notmatch '^[yY]') {
        Write-Host "Cancelled." -ForegroundColor DarkGray
        exit 0
    }
}

$failed = @()
foreach ($row in $rows) {
    $path = $row.Path
    Write-Host "Removing $path ..."
    try {
        Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
        Write-Host "  OK removed" -ForegroundColor Green
    } catch {
        Write-Host "  FAILED: $($_.Exception.Message)" -ForegroundColor Red
        $failed += $path
    }
}

Write-Host ""
if ($failed.Count -gt 0) {
    Write-Host "Some paths could not be removed (stop creg-node / close IDEs and retry):" -ForegroundColor Red
    $failed | ForEach-Object { Write-Host "  $_" }
    exit 1
}

Write-Host "Done. Freed approximately $(Format-Bytes $totalBytes)." -ForegroundColor Green
Write-Host "Rebuild when needed: cargo build --bin creg-node -p chain-registry-node" -ForegroundColor DarkGray
Write-Host ""
