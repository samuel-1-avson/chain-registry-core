# Kubo HTTP API helpers (Windows-friendly — host port-forward can return empty replies).
# Dot-source from testnet scripts: . (Join-Path $scriptDir "ipfs-api.ps1")

function Get-CregIpfsContainerName {
    return "creg-3node-ipfs"
}

function Get-Creg3NodeFleetNetwork {
    $container = Get-CregIpfsContainerName
    $running = docker ps --format "{{.Names}}" 2>$null | Select-String -SimpleMatch $container
    if (-not $running) { return $null }
    $net = docker inspect $container --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}' 2>$null
    if ($net) { return $net.Trim() }
    return "testnet_creg-3node"
}

function Test-CregIpfsApiDocker {
    $container = Get-CregIpfsContainerName
    $running = docker ps --format "{{.Names}}" 2>$null | Select-String -SimpleMatch $container
    if (-not $running) { return $false }
    docker exec $container curl -sf -m 10 -X POST "http://127.0.0.1:5001/api/v0/version" 2>$null | Out-Null
    return ($LASTEXITCODE -eq 0)
}

function Test-CregIpfsApiHost {
    param([string]$BaseUrl = "http://127.0.0.1:5001")
    $url = "$($BaseUrl.TrimEnd('/'))/api/v0/version"
    if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
        return $false
    }
    $null = & curl.exe -sf -m 10 -X POST $url 2>$null
    return ($LASTEXITCODE -eq 0)
}

function Test-CregIpfsApi {
    param([string]$BaseUrl = "http://127.0.0.1:5001")
    if (Test-CregIpfsApiHost -BaseUrl $BaseUrl) { return $true }
    return (Test-CregIpfsApiDocker)
}

function Get-CregIpfsPublishMode {
    param([string]$HostUrl = "http://127.0.0.1:15001")
    if (Test-CregIpfsApiHost -BaseUrl $HostUrl) { return "host" }
    if (Test-CregIpfsApiDocker) { return "docker" }
    return "unreachable"
}

function Invoke-CregIpfsApiDocker {
    param(
        [string]$ApiPath,
        [ValidateSet("GET", "POST")]
        [string]$Method = "POST"
    )
    $container = Get-CregIpfsContainerName
    $pathNorm = if ($ApiPath.StartsWith("/")) { $ApiPath } else { "/$ApiPath" }
    $url = "http://127.0.0.1:5001$pathNorm"
    if ($Method -eq "GET") {
        return docker exec $container curl -sf -m 30 $url 2>&1
    }
    return docker exec $container curl -sf -m 120 -X POST $url 2>&1
}
