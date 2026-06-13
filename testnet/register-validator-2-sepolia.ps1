# On-chain validator application for node 2 of the 3-node Sepolia fleet.
#
# Node 2 uses CREG_NODE_ID=validator-2 and CREG_VALIDATOR_KEY_2 from sepolia-3node.env.
# L1 currently has only core-1 active; this script stakes/applies the second wallet so
# core-1's consensus-admission worker can approve via approveByConsensus (1-of-1 quorum).
#
# Prerequisites:
#   - testnet/sepolia-3node.env with CREG_ETH_RPC and CREG_VALIDATOR_KEY_2
#   - VALIDATOR_2_ETH_PRIVATE_KEY in the environment (or pass -EthPrivateKey)
#   - Wallet funded with Sepolia ETH and >= 100 tCREG on CREG_TOKEN_ADDR
#   - 3-node fleet running (node1 must observe admission and submit L1 tx)
#
# Usage:
#   $env:VALIDATOR_2_ETH_PRIVATE_KEY = "0x..."
#   .\testnet\register-validator-2-sepolia.ps1
#   .\testnet\register-validator-2-sepolia.ps1 -ApplyOnly
#   .\testnet\register-validator-2-sepolia.ps1 -CheckOnly

param(
    [string]$RpcUrl = "",
    [string]$EthPrivateKey = "",
    [ValidateSet("validator-2")]
    [string]$NodeId = "validator-2",
    [int]$StakeCreg = 100,
    [int]$Node2Port = 0,
    [switch]$ApplyOnly,
    [switch]$RegisterIdentity,
    [switch]$CheckOnly
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
Set-Location $repoRoot
. (Join-Path $scriptDir "node-api.ps1")

if (-not $Node2Port) {
    $Node2Port = if ($env:CREG_3NODE_NODE2_API_PORT) { [int]$env:CREG_3NODE_NODE2_API_PORT } else { 28181 }
}

function Import-DotEnv {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return }
    Get-Content $Path | ForEach-Object {
        if ($_ -match '^\s*([^#\s][^=]*)\s*=\s*(.*)\s*$') {
            [Environment]::SetEnvironmentVariable($matches[1].Trim(), $matches[2].Trim().Trim('"'), "Process")
        }
    }
}

$fleetEnv = Join-Path $scriptDir "sepolia-3node.env"
Import-DotEnv $fleetEnv

if (-not $RpcUrl) {
    $RpcUrl = $env:CREG_ETH_RPC
    if (-not $RpcUrl) { $RpcUrl = $env:SEPOLIA_RPC_URL }
}
if (-not $RpcUrl) {
    throw "Set CREG_ETH_RPC in testnet/sepolia-3node.env or pass -RpcUrl"
}

if (-not $EthPrivateKey) {
    $EthPrivateKey = $env:VALIDATOR_2_ETH_PRIVATE_KEY
}
if ($EthPrivateKey) {
    $EthPrivateKey = $EthPrivateKey.Trim()
}
if (-not $EthPrivateKey) {
    $secretKey = Join-Path $scriptDir "secrets\validator-2-latest.key"
    if (Test-Path $secretKey) {
        $EthPrivateKey = (Get-Content $secretKey -Raw).Trim()
    }
}
if (-not $EthPrivateKey) {
    throw @"
No Sepolia EVM private key for validator-2.

Quick setup (generates wallet + writes testnet/sepolia-3node.env):
  .\testnet\new-testnet-wallet.ps1 -Role validator-2

Or set for this session only:
  `$env:VALIDATOR_2_ETH_PRIVATE_KEY = "0x..."
  .\testnet\register-validator-2-sepolia.ps1

Fund the wallet with Sepolia ETH and >= $StakeCreg tCREG before applying.
Never commit the private key.
"@
}

$specPath = Join-Path $scriptDir "chain-spec.sepolia.json"
$spec = Get-Content $specPath -Raw | ConvertFrom-Json
$staking = $spec.contracts.staking
$token = $spec.contracts.creg_token

$key2 = $env:CREG_VALIDATOR_KEY_2
if (-not $key2) { throw "CREG_VALIDATOR_KEY_2 missing from testnet/sepolia-3node.env" }
$key2 = ($key2.Trim() -replace '^0x', '')
if ($key2.Length -ne 64) {
    throw "CREG_VALIDATOR_KEY_2 must be 32 bytes (64 hex chars after optional 0x prefix), got $($key2.Length)"
}

function Get-Ed25519PubkeyFromSecret {
    param([string]$SecretHex)
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $out = cargo run -q --example ed25519_pubkey_from_secret -p common -- "$SecretHex" 2>&1
    $exit = $LASTEXITCODE
    $ErrorActionPreference = $prevEap
    if ($exit -ne 0) {
        $detail = ($out | Out-String).Trim()
        throw "Failed to derive Ed25519 pubkey from CREG_VALIDATOR_KEY_2 (cargo exit $exit): $detail"
    }
    $line = ($out | Where-Object { $_ -is [string] -and $_ -match '^[0-9a-fA-F]{64}$' } | Select-Object -Last 1)
    if (-not $line) {
        $line = ($out | Select-Object -Last 1)
        if ($line -isnot [string]) { $line = $line.ToString() }
        $line = $line.Trim()
    }
    if ($line -notmatch '^[0-9a-fA-F]{64}$') {
        throw "Unexpected pubkey output from cargo: $line"
    }
    return $line.ToLower()
}

$pub2 = Get-Ed25519PubkeyFromSecret -SecretHex $key2

$toolsCast = Join-Path $scriptDir ".tools\foundry\cast.exe"
$castCmd = Get-Command cast -ErrorAction SilentlyContinue
$cast = if (Test-Path $toolsCast) { $toolsCast } elseif ($castCmd) { $castCmd.Source } else { $null }
if (-not $cast) { throw "cast not found. Run .\testnet\install-foundry.ps1" }

$env:FOUNDRY_DISABLE_NIGHTLY_WARNING = "1"

$addrRaw = & $cast wallet address --private-key $EthPrivateKey 2>&1 | Out-String
if ($addrRaw -notmatch '(0x[a-fA-F0-9]{40})') { throw "Invalid EthPrivateKey" }
$validatorAddr = $matches[1]

$wei = [bigint]($StakeCreg * [decimal]1e18)
$weiStr = $wei.ToString([System.Globalization.CultureInfo]::InvariantCulture)

function Invoke-CastSend {
    param(
        [string]$To,
        [string]$Signature,
        [string[]]$CallArgs
    )
    $invokeArgs = @("send", $To, $Signature) + $CallArgs + @(
        "--private-key", $EthPrivateKey,
        "--rpc-url", $RpcUrl
    )
    & $cast @invokeArgs
    if ($LASTEXITCODE -ne 0) {
        throw "cast send failed: $Signature $To ($($invokeArgs -join ' '))"
    }
}

function Get-ValidatorState {
    $sig = "validators(address)(uint256,uint8,uint256,uint256,uint256,uint256)"
    $jsonRaw = & $cast call $staking $sig $validatorAddr --rpc-url $RpcUrl --json 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0 -and $jsonRaw.Trim().StartsWith("[")) {
        $tuple = $jsonRaw.Trim() | ConvertFrom-Json
        if ($tuple.Count -ge 2) {
            return @{ stake = [string]$tuple[0]; state = [int]$tuple[1] }
        }
    }
    return $null
}

# ValidatorState (Staking.sol): None, Pending, Active, Unbonding, Withdrawn, Rejected, Expired
$stateNames = @{
    0 = "None"; 1 = "Pending"; 2 = "Active"; 3 = "Unbonding"
    4 = "Withdrawn"; 5 = "Rejected"; 6 = "Expired"
}

Write-Host ""
Write-Host "=== Validator-2 Sepolia registration ===" -ForegroundColor Cyan
Write-Host "EVM address:  $validatorAddr"
Write-Host "Node ID:      $NodeId"
Write-Host "Ed25519 pub:  $pub2"
Write-Host "Staking:      $staking"
Write-Host "RPC:          $RpcUrl"
Write-Host ""

$vs = Get-ValidatorState
if ($vs) {
    $name = $stateNames[$vs.state]
    if (-not $name) { $name = "state=$($vs.state)" }
    Write-Host "On-chain:     $name (stake wei $($vs.stake))" -ForegroundColor $(if ($vs.state -eq 2) { "Green" } else { "Yellow" })
}

if ($RegisterIdentity) {
    $chainId = $spec.chain_id
    if (-not $chainId) { $chainId = "creg-testnet-1" }
    $nonce = "validator-2-sepolia-$(Get-Date -Format 'yyyyMMddHHmmss')"
    $evmLower = $validatorAddr.ToLower()
    $message = "creg-validator-identity-v1`nchain_id:$chainId`nevm_address:$evmLower`nnode_id:$NodeId`ned25519_pubkey:$pub2`nnonce:$nonce"

    Write-Host "Signing identity proofs (nonce=$nonce) ..." -ForegroundColor Cyan
    $signExample = Join-Path $repoRoot "target\debug\examples\sign_validator_identity.exe"
    $signArgs = @(
        "--chain-id", $chainId, "--evm-address", $evmLower, "--node-id", $NodeId,
        "--validator-key-hex", $key2, "--nonce", $nonce
    )
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    if (Test-Path $signExample) {
        $edOut = & $signExample @signArgs 2>&1 | Out-String
    } else {
        $edOut = cargo run -q --example sign_validator_identity -p chain-registry-cli -- @signArgs 2>&1 | Out-String
    }
    $signExit = $LASTEXITCODE
    $ErrorActionPreference = $prevEap
    if ($signExit -ne 0) { throw "sign_validator_identity failed: $edOut" }
    $edJsonLine = ($edOut -split "`n" | Where-Object { $_.Trim().StartsWith("{") } | Select-Object -Last 1)
    if (-not $edJsonLine) { throw "sign_validator_identity did not emit JSON: $edOut" }
    $edJson = $edJsonLine.Trim() | ConvertFrom-Json

    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $evmSig = (& $cast wallet sign --private-key $EthPrivateKey -- $message 2>&1 | Out-String).Trim()
    $signExit = $LASTEXITCODE
    $ErrorActionPreference = $prevEap
    if ($signExit -ne 0 -or $evmSig -notmatch '^0x[a-fA-F0-9]+$') {
        throw "EVM personal_sign failed: $evmSig"
    }

    $body = @{
        evm_address         = $evmLower
        node_id             = $NodeId
        ed25519_pubkey      = $pub2
        nonce               = $nonce
        evm_signature       = $evmSig
        ed25519_signature   = $edJson.ed25519_signature
    } | ConvertTo-Json -Compress

    $node1Port = if ($env:CREG_3NODE_NODE1_API_PORT) { [int]$env:CREG_3NODE_NODE1_API_PORT } else { 28180 }
    $registerPorts = @($node1Port, $Node2Port) | Select-Object -Unique
    foreach ($port in $registerPorts) {
        Write-Host "POST /v1/validators/register on port $port ..." -ForegroundColor Cyan
        try {
            Invoke-NodeApi -Port $port -Path "/v1/validators/register" -Method POST -BodyJson $body | Out-Null
        } catch {
            throw "Identity registration failed on port ${port}: $_"
        }
    }
    $regs = Invoke-NodeApi -Port $Node2Port -Path "/v1/validators/registrations"
    Write-Host "OK. Registrations on node2: $($regs | ConvertTo-Json -Compress -Depth 6)" -ForegroundColor Green
    $regs1 = Invoke-NodeApi -Port $node1Port -Path "/v1/validators/registrations"
    Write-Host "OK. Registrations on node1: $($regs1 | ConvertTo-Json -Compress -Depth 6)" -ForegroundColor Green
    if (-not $ApplyOnly -and -not $CheckOnly) {
        Write-Host "Next: .\testnet\approve-validator-governance-sepolia.ps1 -Applicant $validatorAddr" -ForegroundColor Yellow
    }
    if (-not $ApplyOnly) { exit 0 }
}

if ($CheckOnly) { exit 0 }

$ethBalRaw = & $cast balance $validatorAddr --rpc-url $RpcUrl 2>&1 | Out-String
$ethWei = if ($ethBalRaw -match '\b(\d+)\b') { [bigint]$matches[1] } else { [bigint]0 }
$cregBalRaw = & $cast call $token "balanceOf(address)(uint256)" $validatorAddr --rpc-url $RpcUrl 2>&1 | Out-String
$cregWei = if ($cregBalRaw -match '\b(\d+)\b') { [bigint]$matches[1] } else { [bigint]0 }
Write-Host "Balances: ETH wei=$ethWei  tCREG wei=$cregWei (need >= $weiStr)" -ForegroundColor DarkGray
if ($ethWei -le 0) {
    throw "No Sepolia ETH on $validatorAddr - fund for gas before applyToBeValidator."
}
if ($cregWei -lt $wei) {
    throw "tCREG balance ($($cregWei.ToString()) wei) below stake ($weiStr wei). Send at least $StakeCreg tCREG to $validatorAddr."
}

if ($vs -and $vs.state -eq 2) {
    Write-Host "Already Active on L1. Register identity on node2 if not done yet." -ForegroundColor Green
} elseif (-not $ApplyOnly -or -not $vs -or $vs.state -eq 0) {
    if (-not $vs -or $vs.state -eq 0 -or $vs.state -eq 4) {
        Write-Host "Approving $StakeCreg tCREG for staking contract..." -ForegroundColor Cyan
        Invoke-CastSend -To $token -Signature "approve(address,uint256)" -CallArgs @($staking, $weiStr)
        Write-Host "Submitting applyToBeValidator($StakeCreg tCREG)..." -ForegroundColor Cyan
        Invoke-CastSend -To $staking -Signature "applyToBeValidator(uint256)" -CallArgs @($weiStr)
        Write-Host "Application submitted (Pending)." -ForegroundColor Green
    } elseif ($vs.state -eq 1) {
        Write-Host "Application already Pending; waiting for core-1 admission quorum." -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "=== Next steps (manual) ===" -ForegroundColor Cyan
Write-Host @"
1. Register validator identity on node 2:
   .\testnet\register-validator-2-sepolia.ps1 -RegisterIdentity

2. Admit on L1 (activeValidatorCount is 0 on this deployment; use emergency governance):
   .\testnet\approve-validator-governance-sepolia.ps1 -Applicant $validatorAddr

3. Poll until Active:
   .\testnet\register-validator-2-sepolia.ps1 -CheckOnly

4. Optional: add validator-2 to chain-spec.sepolia.json, re-sign, restart spec-server
   (bootstrap metadata). Runtime can also merge from /v1/validators/register once L1 is Active.

5. If admission stalls > APPLICATION_TIMEOUT, re-run this script after expireApplication
   or fund more tCREG and re-apply.
"@
