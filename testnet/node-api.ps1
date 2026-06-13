# Helpers for 3-node fleet HTTP APIs on Windows Docker (host port-forward can fail).
# Dot-source from testnet scripts: . (Join-Path $scriptDir "node-api.ps1")

function Get-NodeContainerName {
    param([int]$Port)
    switch ($Port) {
        { $_ -eq $(if ($env:CREG_3NODE_NODE1_API_PORT) { [int]$env:CREG_3NODE_NODE1_API_PORT } else { 28180 }) } { return "creg-3node-node1" }
        { $_ -eq $(if ($env:CREG_3NODE_NODE2_API_PORT) { [int]$env:CREG_3NODE_NODE2_API_PORT } else { 28181 }) } { return "creg-3node-node2" }
        { $_ -eq $(if ($env:CREG_3NODE_NODE3_API_PORT) { [int]$env:CREG_3NODE_NODE3_API_PORT } else { 28182 }) } { return "creg-3node-node3" }
        default {
            if ($Port -eq 28180) { return "creg-3node-node1" }
            if ($Port -eq 28181) { return "creg-3node-node2" }
            if ($Port -eq 28182) { return "creg-3node-node3" }
            return $null
        }
    }
}

function Invoke-NodeApiRaw {
    param(
        [int]$Port,
        [string]$Path,
        [ValidateSet("GET", "POST")]
        [string]$Method = "GET",
        [string]$BodyJson = ""
    )
    $pathNorm = if ($Path.StartsWith("/")) { $Path } else { "/$Path" }
    $hostUrl = "http://localhost:$Port$pathNorm"

    if ($Method -eq "GET") {
        try {
            return (Invoke-RestMethod -Uri $hostUrl -TimeoutSec 15 | ConvertTo-Json -Depth 12 -Compress)
        } catch {
            # fall through to docker
        }
    } else {
        try {
            return (Invoke-RestMethod -Uri $hostUrl -Method Post -ContentType "application/json; charset=utf-8" `
                -Body $BodyJson -TimeoutSec 60 | ConvertTo-Json -Depth 12 -Compress)
        } catch {
            # fall through to docker
        }
    }

    $container = Get-NodeContainerName -Port $Port
    if (-not $container) { throw "No docker mapping for node API port $Port" }
    $running = docker ps --format "{{.Names}}" 2>$null | Select-String -SimpleMatch $container
    if (-not $running) { throw "Node API unreachable at $hostUrl and container $container is not running" }

    $innerUrl = "http://127.0.0.1:8080$pathNorm"
    if ($Method -eq "GET") {
        $raw = docker exec $container curl -s -m 30 $innerUrl 2>&1 | Out-String
    } else {
        $tmpHost = Join-Path $env:TEMP ("creg-node-api-$([guid]::NewGuid().ToString('n')).json")
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($tmpHost, $BodyJson, $utf8NoBom)
        try {
            docker cp $tmpHost "${container}:/tmp/creg-node-api.json" | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "docker cp failed for $container" }
            $raw = docker exec $container curl -s -m 60 -w "`n%{http_code}" -X POST $innerUrl `
                -H "Content-Type: application/json" "-d@/tmp/creg-node-api.json" 2>&1 | Out-String
            $raw = $raw.TrimEnd()
            if ($raw -match "[\r\n]+(\d{3})$") {
                $code = [int]$matches[1]
                $raw = ($raw -replace "[\r\n]+\d{3}$", "").Trim()
                if ($code -ge 400) { throw "Node API HTTP $code via $container`: $raw" }
            }
        } finally {
            Remove-Item $tmpHost -Force -ErrorAction SilentlyContinue
        }
    }
    if ($LASTEXITCODE -ne 0 -or -not $raw.Trim()) {
        throw "Node API failed via docker exec ($container): $raw"
    }
    return $raw.Trim()
}

function Invoke-NodeApi {
    param(
        [int]$Port,
        [string]$Path,
        [ValidateSet("GET", "POST")]
        [string]$Method = "GET",
        [string]$BodyJson = ""
    )
    $raw = Invoke-NodeApiRaw -Port $Port -Path $Path -Method $Method -BodyJson $BodyJson
    if (-not $raw -or -not $raw.Trim()) { return $null }
    return ($raw | ConvertFrom-Json)
}

function Wait-NodeHealthSynced {
    param(
        [int]$Port,
        [int]$MaxSec = 180,
        [scriptblock]$Log = { param($m) Write-Host $m }
    )
    $deadline = (Get-Date).AddSeconds($MaxSec)
    while ((Get-Date) -lt $deadline) {
        try {
            $h = Invoke-NodeApi -Port $Port -Path "/v1/health"
            if ($h.status -eq "ok" -and $h.validator_set_sync.state -eq "synced") {
                return $h
            }
            & $Log "$Port health ok=$($h.status) sync=$($h.validator_set_sync.state)"
        } catch {
            & $Log "waiting for port $Port health ..."
        }
        Start-Sleep -Seconds 5
    }
    throw "Health not synced on port $Port within ${MaxSec}s (try docker exec fallback via node-api.ps1)"
}

function Get-NodeChainStats {
    param([int]$Port)
    return Invoke-NodeApi -Port $Port -Path "/v1/chain/stats"
}
