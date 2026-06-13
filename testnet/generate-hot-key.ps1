# Generate a testnet secp256k1 hot key (32 bytes) for CREG_BRIDGE_KEY / FAUCET / RELAYER drills.
# Does NOT write to disk unless -OutFile is set. Never commit the output file.
#
# Usage:
#   .\testnet\generate-hot-key.ps1
#   .\testnet\generate-hot-key.ps1 -OutFile .\.env.bridge.key.fragment

param(
    [string]$OutFile = ""
)

$ErrorActionPreference = "Stop"
$bytes = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$hex = "0x" + ([BitConverter]::ToString($bytes) -replace "-", "").ToLower()

Write-Host ""
Write-Host "=== Testnet hot key (secp256k1, 32 bytes) ===" -ForegroundColor Cyan
Write-Host "Private key (add to .env.sepolia, never commit):"
Write-Host $hex -ForegroundColor Yellow
Write-Host ""

$cast = Get-Command cast -ErrorAction SilentlyContinue
if ($cast) {
    $env:FOUNDRY_DISABLE_NIGHTLY_WARNING = "1"
    $raw = (& cast wallet address --private-key $hex 2>&1 | Out-String)
    if ($raw -match '(0x[a-fA-F0-9]{40})') {
        Write-Host "Address (fund on Sepolia if bridge/faucet must send txs):"
        Write-Host $matches[1] -ForegroundColor Green
    }
} else {
    Write-Host "Install Foundry (cast) to show the matching address:" -ForegroundColor DarkGray
    Write-Host "  https://book.getfoundry.xyz/getting-started/installation"
    Write-Host "  Windows: download foundry_nightly_windows_amd64.tar.gz from GitHub releases"
    Write-Host ""
    Write-Host "Then: cast wallet address --private-key <key above>"
}

Write-Host ""
Write-Host "Next (pick one):"
Write-Host "  .\testnet\set-bridge-key-env.ps1 -PrivateKey <key above>"
Write-Host "  # or edit testnet/.env.sepolia manually, then:"
Write-Host "  .\testnet\run-sec-101-drill.ps1 -Label after"
Write-Host ""
Write-Host "Use a NEW PowerShell window for run-ops-201-verify (clears old env from drill script)."
Write-Host ""

if ($OutFile) {
    Set-Content -Path $OutFile -Value $hex -Encoding utf8 -NoNewline
    Write-Host "Wrote key to $OutFile (keep local, gitignored)" -ForegroundColor DarkGray
}
