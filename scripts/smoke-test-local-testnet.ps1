param(
    [switch]$SkipPublish,
    [switch]$SkipExplorer,
    [switch]$SkipDrip,
    [switch]$SkipInclusionWait,
    [int]$InclusionTimeoutSeconds = 180,
    [int]$InclusionPollSeconds = 5
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Numerics

$RepoRoot = Split-Path -Parent $PSScriptRoot
$EnvFile = Join-Path $RepoRoot ".env.local-testnet"
$ComposeFile = Join-Path $RepoRoot "docker-compose.local-testnet.yml"

$TokenAddr = "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9"
$StakingAddr = "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707"
$PublisherAddr = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
$PublisherKey = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"
$FaucetKey = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
$OneCreg = "1000000000000000000"
$TwoCreg = "2000000000000000000"

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Args
    )

    Write-Host "> docker $($Args -join ' ')"
    & docker @Args
    if ($LASTEXITCODE -ne 0) {
        throw "docker $($Args -join ' ') failed with exit code $LASTEXITCODE"
    }
}

function Invoke-Compose {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Args
    )

    Invoke-Checked -Args (@(
        "compose",
        "--env-file", $EnvFile,
        "-f", $ComposeFile
    ) + $Args)
}

function Invoke-CastSend {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$CastArgs
    )

    Invoke-Compose -Args (@(
        "run", "--rm", "--no-deps",
        "--entrypoint", "cast",
        "deploy-contracts",
        "send"
    ) + $CastArgs)
}

function Get-ChainStats {
    $response = Invoke-WebRequest -Uri "http://localhost:8080/v1/chain/stats" -UseBasicParsing -TimeoutSec 10
    return $response.Content | ConvertFrom-Json
}

function New-RandomEthereumAddress {
    $bytes = New-Object byte[] 20
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return "0x$(([System.BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant())"
}

function Get-LeadingZeroBits {
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes
    )

    $zeros = 0
    foreach ($byte in $Bytes) {
        if ($byte -eq 0) {
            $zeros += 8
            continue
        }

        for ($bit = 7; $bit -ge 0; $bit--) {
            if (($byte -band (1 -shl $bit)) -eq 0) {
                $zeros += 1
            } else {
                return $zeros
            }
        }
    }
    return $zeros
}

function Find-FaucetPowNonce {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Challenge,
        [Parameter(Mandatory = $true)]
        [int]$Difficulty
    )

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        for ($nonce = 0; $nonce -lt [int64]::MaxValue; $nonce++) {
            $payload = [System.Text.Encoding]::UTF8.GetBytes("$Challenge$nonce")
            $hash = $sha.ComputeHash($payload)
            if ((Get-LeadingZeroBits -Bytes $hash) -ge $Difficulty) {
                return "$nonce"
            }
        }
    } finally {
        $sha.Dispose()
    }

    throw "Could not solve faucet proof-of-work challenge."
}

function Get-FaucetTokenBalance {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Address
    )

    $balance = Invoke-RestMethod -Uri "http://localhost:8082/api/balance/$Address" -TimeoutSec 30
    return [System.Numerics.BigInteger]::Parse([string]$balance.balance)
}

function Test-FaucetDrip {
    $recipient = New-RandomEthereumAddress
    Write-Host "Running faucet drip probe for $recipient..."

    $before = Get-FaucetTokenBalance -Address $recipient
    $response = $null

    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $challenge = Invoke-RestMethod -Uri "http://localhost:8082/api/challenge" -TimeoutSec 30
        $nonce = Find-FaucetPowNonce -Challenge $challenge.challenge -Difficulty ([int]$challenge.difficulty)
        $body = @{
            address = $recipient
            challenge = $challenge.challenge
            nonce = $nonce
        } | ConvertTo-Json -Compress

        try {
            $response = Invoke-RestMethod `
                -Uri "http://localhost:8082/api/drip" `
                -Method Post `
                -ContentType "application/json" `
                -Body $body `
                -TimeoutSec 90
            break
        } catch {
            $afterTimeout = Get-FaucetTokenBalance -Address $recipient
            if ($afterTimeout -gt $before) {
                Write-Host "  OK faucet drip: balance increased after delayed response (before=$before after=$afterTimeout)"
                return
            }

            $retryAfter = $null
            try {
                if ($_.ErrorDetails.Message) {
                    $errorPayload = $_.ErrorDetails.Message | ConvertFrom-Json
                    if ($null -ne $errorPayload.retry_after_seconds) {
                        $retryAfter = [int]$errorPayload.retry_after_seconds
                    }
                }
            } catch {
                $retryAfter = $null
            }

            if ($null -ne $retryAfter -and $attempt -lt 3) {
                $waitSeconds = [Math]::Max(1, $retryAfter + 1)
                Write-Host "  Faucet rate limited; retrying in ${waitSeconds}s..."
                Start-Sleep -Seconds $waitSeconds
                continue
            }

            throw
        }
    }

    if ($null -eq $response) {
        throw "Faucet drip failed for ${recipient}: no response after retries"
    }

    if (-not $response.success) {
        throw "Faucet drip failed for ${recipient}: $($response.message)"
    }

    $after = Get-FaucetTokenBalance -Address $recipient
    if ($after -le $before) {
        throw "Faucet drip did not increase token balance for $recipient (before=$before after=$after)"
    }

    Write-Host "  OK faucet drip: recipient=$recipient amount=$($response.amount) before=$before after=$after"
}

function Wait-ForChainInclusion {
    param(
        [Parameter(Mandatory = $true)]
        $BeforeStats
    )

    $beforeHeight = [int64]$BeforeStats.tip_height
    $beforePending = [int64]$BeforeStats.pending_tx_count
    $deadline = (Get-Date).AddSeconds($InclusionTimeoutSeconds)

    Write-Host "Waiting for package inclusion or chain progress..."
    do {
        Start-Sleep -Seconds $InclusionPollSeconds
        $stats = Get-ChainStats
        $height = [int64]$stats.tip_height
        $pending = [int64]$stats.pending_tx_count
        $packages = [int64]$stats.package_count

        Write-Host "  height=$height pending=$pending packages=$packages"
        if ($height -gt $beforeHeight -and $pending -le $beforePending) {
            return $stats
        }
    } while ((Get-Date) -lt $deadline)

    throw "Package was accepted but not included within ${InclusionTimeoutSeconds}s; check validator consensus and pending pool logs."
}

Set-Location $RepoRoot

if (-not (Test-Path $EnvFile)) {
    throw "Missing .env.local-testnet. Run ./local-testnet.ps1 first."
}

Write-Host "Running local testnet doctor..."
$doctorArgs = @(
    "run", "--rm", "--no-deps",
    "-e", "CREG_IPFS_URL=http://ipfs:5001",
    "-e", "CREG_TESTNET=true",
    "cli",
    "doctor", "--testnet",
    "--skip-drip",
    "--faucet-url", "http://faucet:8082",
    "--eth-rpc-url", "http://anvil:8545"
)
if ($SkipExplorer) {
    $doctorArgs += "--skip-explorer"
} else {
    $doctorArgs += "--explorer-url"
    $doctorArgs += "http://web-explorer"
}
Invoke-Compose -Args $doctorArgs

if ($SkipDrip) {
    Write-Host "Skipping standalone faucet drip probe."
} else {
    Test-FaucetDrip
}

if ($SkipPublish) {
    Write-Host "Skipping publisher stake and package publish smoke."
    exit 0
}

$publisherKeyPath = Join-Path $RepoRoot "publisher.key"
if (-not (Test-Path $publisherKeyPath)) {
    throw "Missing sample publisher key: $publisherKeyPath"
}

Write-Host "Funding and staking local publisher..."
Invoke-CastSend -CastArgs @(
    $TokenAddr,
    "transfer(address,uint256)",
    $PublisherAddr,
    $TwoCreg,
    "--private-key", $FaucetKey,
    "--rpc-url", "http://anvil:8545"
)
Invoke-CastSend -CastArgs @(
    $TokenAddr,
    "approve(address,uint256)",
    $StakingAddr,
    $OneCreg,
    "--private-key", $PublisherKey,
    "--rpc-url", "http://anvil:8545"
)
Invoke-CastSend -CastArgs @(
    $StakingAddr,
    "stakeAsPublisher(uint256)",
    $OneCreg,
    "--private-key", $PublisherKey,
    "--rpc-url", "http://anvil:8545"
)

Write-Host "Preparing unique smoke package..."
$smokeRoot = Join-Path $RepoRoot "tmp\local-smoke"
$packageRoot = Join-Path $smokeRoot "package"
New-Item -ItemType Directory -Force -Path $packageRoot | Out-Null

$version = "0.0.$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())"
$tarName = "creg-local-smoke-$version.tgz"
$tarPath = Join-Path $smokeRoot $tarName

@"
{
  "name": "@creg/local-smoke",
  "version": "$version",
  "description": "Generated by scripts/smoke-test-local-testnet.ps1",
  "main": "index.js"
}
"@ | Set-Content -LiteralPath (Join-Path $packageRoot "package.json") -Encoding ASCII

"module.exports = 'ok';" | Set-Content -LiteralPath (Join-Path $packageRoot "index.js") -Encoding ASCII

if (Test-Path $tarPath) {
    Remove-Item -LiteralPath $tarPath -Force
}

& tar -czf $tarPath -C $packageRoot .
if ($LASTEXITCODE -ne 0) {
    throw "tar failed while creating $tarPath"
}

Write-Host "Publishing sample package $version..."
$mountPath = "$($RepoRoot):/workspace"
$containerTarPath = "./tmp/local-smoke/$tarName"
$beforePublishStats = Get-ChainStats
Invoke-Compose -Args @(
    "run", "--rm", "--no-deps",
    "-v", $mountPath,
    "-w", "/workspace",
    "-e", "CREG_IPFS_URL=http://ipfs:5001",
    "cli",
    "publish", $containerTarPath,
    "--key-file", "./publisher.key",
    "--publisher-address", $PublisherAddr,
    "--node-url", "http://observer:8080",
    "--output", "json"
)

if (-not $SkipInclusionWait) {
    Wait-ForChainInclusion -BeforeStats $beforePublishStats | Out-Null
}

Write-Host "Checking final chain stats..."
$stats = Get-ChainStats
Write-Host ($stats | ConvertTo-Json -Compress)
Write-Host "Local smoke test passed."
