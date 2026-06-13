# Send Sepolia ETH to the faucet wallet (gas for ERC-20 drip txs).
#
# Usage:
#   .\testnet\fund-sepolia-faucet-eth.ps1
#   .\testnet\fund-sepolia-faucet-eth.ps1 -AmountEth 0.05
#   .\testnet\fund-sepolia-faucet-eth.ps1 -FromPrivateKey 0x...

param(
    [double]$AmountEth = 0.05,
    [string]$RpcUrl = "",
    [string]$FromPrivateKey = ""
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Import-DotEnv {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return }
    Get-Content $Path | ForEach-Object {
        if ($_ -match '^\s*([^#\s][^=]*)\s*=\s*(.*)\s*$') {
            $v = $matches[2].Trim().Trim('"')
            if ($v -and $v -notmatch 'YOUR_') {
                [Environment]::SetEnvironmentVariable($matches[1].Trim(), $v, "Process")
            }
        }
    }
}

function Resolve-SepoliaRpc {
    param([string]$Explicit)
    if ($Explicit -and $Explicit -notmatch 'YOUR_') { return $Explicit }
    foreach ($candidate in @($env:SEPOLIA_RPC_URL, $env:CREG_ETH_RPC, $env:FAUCET_RPC_URL)) {
        if (-not $candidate) { continue }
        $c = $candidate.Trim().Trim('"')
        if ($c -match 'YOUR_|/v3/?$|/v3/\s*$') { continue }
        return $c
    }
    return "https://ethereum-sepolia-rpc.publicnode.com"
}

Import-DotEnv (Join-Path $scriptDir ".env.sepolia.faucet")
Import-DotEnv (Join-Path $scriptDir ".env.sepolia")
# docker-compose.yml reads FAUCET_ADDRESS from repo-root .env (creg-faucet container).
Import-DotEnv (Join-Path (Split-Path -Parent $scriptDir) ".env")

if (-not $env:FAUCET_ADDRESS) {
    throw "Missing FAUCET_ADDRESS - run .\testnet\setup-sepolia-faucet.ps1 or set it in .env"
}

$senderKey = $FromPrivateKey
if (-not $senderKey) { $senderKey = $env:DEPLOYER_KEY }
if (-not $senderKey) {
    throw "Set DEPLOYER_KEY in testnet\.env.sepolia or pass -FromPrivateKey"
}

$RpcUrl = Resolve-SepoliaRpc -Explicit $RpcUrl
$cast = Join-Path $scriptDir ".tools\foundry\cast.exe"
if (-not (Test-Path $cast)) {
    $cast = (Get-Command cast -ErrorAction Stop).Source
}
$env:FOUNDRY_DISABLE_NIGHTLY_WARNING = "1"

$faucet = $env:FAUCET_ADDRESS
$sender = (& $cast wallet address --private-key $senderKey 2>&1 | Out-String)
if ($sender -match '(0x[a-fA-F0-9]{40})') { $sender = $matches[1] } else { throw "Could not derive sender address" }

$balSender = [decimal](& $cast balance $sender --rpc-url $RpcUrl --ether 2>&1 | Out-String).Trim()
$balFaucet = [decimal](& $cast balance $faucet --rpc-url $RpcUrl --ether 2>&1 | Out-String).Trim()

Write-Host "Sender:  $sender (balance $balSender ETH)" -ForegroundColor Cyan
Write-Host "Faucet:  $faucet (balance $balFaucet ETH)" -ForegroundColor Cyan
Write-Host "Sending: $AmountEth ETH" -ForegroundColor Green

if ($balSender -lt ($AmountEth + 0.001)) {
    throw "Sender balance too low. Fund $sender on Sepolia or lower -AmountEth."
}

& $cast send $faucet --value "${AmountEth}ether" --private-key $senderKey --rpc-url $RpcUrl
if ($LASTEXITCODE -ne 0) { throw "cast send failed (exit $LASTEXITCODE)" }

$newBal = (& $cast balance $faucet --rpc-url $RpcUrl --ether 2>&1 | Out-String).Trim()
Write-Host "Done. Faucet ETH balance: $newBal" -ForegroundColor Green
Write-Host "Retry drip or refresh http://localhost:8082" -ForegroundColor DarkGray
