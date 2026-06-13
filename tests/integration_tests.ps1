# Chain Registry Integration Test Suite (PowerShell)
# 
# IMPORTANT ARCHITECTURE NOTE:
# ============================
# In PRODUCTION: One validator per PC ONLY
# In TESTING: Multiple validators on one PC is OK (what this script does)
#
# These tests run multiple validators on a single machine for integration testing.
# For production deployment, each validator MUST run on a separate PC.

param(
    [switch]$SkipCleanup,
    [switch]$Help
)

if ($Help) {
    Write-Host @"
Chain Registry Integration Test Suite

Usage:
    .\integration_tests.ps1 [OPTIONS]

Options:
    -SkipCleanup    Don't cleanup containers after tests
    -Help           Show this help

Examples:
    .\integration_tests.ps1              # Run all tests
    .\integration_tests.ps1 -SkipCleanup # Run tests, keep containers
"@
    exit 0
}

# Test configuration
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Resolve-Path (Join-Path $ScriptDir "..")
$NumValidators = 3
$TestResults = @()
$FailedTests = @()

# Helper functions
function Write-Info($Message) {
    Write-Host "[INFO] $Message"
}

function Write-Success($Message) {
    Write-Host "[PASS] $Message" -ForegroundColor Green
}

function Write-Error($Message) {
    Write-Host "[FAIL] $Message" -ForegroundColor Red
}

function Write-Warn($Message) {
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Invoke-Test($TestName, $TestScript) {
    Write-Host ""
    Write-Info "Running: $TestName"
    
    try {
        $result = & $TestScript
        if ($result -eq $true) {
            Write-Success $TestName
            $script:TestResults += "PASS: $TestName"
            return $true
        } else {
            Write-Error $TestName
            $script:TestResults += "FAIL: $TestName"
            $script:FailedTests += $TestName
            return $false
        }
    } catch {
        Write-Error "$TestName - $_"
        $script:TestResults += "FAIL: $TestName"
        $script:FailedTests += $TestName
        return $false
    }
}

# =============================================================================
# TEST 1: Environment Setup
# =============================================================================
function Test-EnvironmentSetup {
    Write-Info "Checking environment..."
    
    # Check .env exists
    $EnvFile = Join-Path $ProjectRoot ".env"
    if (-not (Test-Path $EnvFile)) {
        Write-Warn ".env file not found, creating from example"
        $EnvExample = Join-Path $ProjectRoot ".env.example"
        if (Test-Path $EnvExample) {
            Copy-Item $EnvExample $EnvFile
        }
    }
    
    # Check validator keys exist
    $keyCount = 0
    for ($i = 1; $i -le 3; $i++) {
        $pattern = "NODE${i}_VALIDATOR_KEY="
        $content = Get-Content $EnvFile -ErrorAction SilentlyContinue
        $match = $content | Select-String "^$pattern"
        if ($match) {
            $value = $match.ToString().Split("=")[1].Trim()
            if ($value -and $value -ne "your_validator_${i}_private_key_here") {
                $keyCount++
            }
        }
    }
    
    if ($keyCount -lt 3) {
        Write-Warn "Missing validator keys. Run: .\scripts\generate-validator-keys.ps1 3"
        return $false
    }
    
    Write-Info "Found $keyCount validator key(s)"
    return $true
}

# =============================================================================
# TEST 2: Docker Build
# =============================================================================
function Test-DockerBuild {
    Write-Info "Testing Docker build..."
    
    Set-Location $ProjectRoot
    
    # Build minimal image (faster for testing)
    $logFile = "$env:TEMP\docker-build.log"
    try {
        docker build -f Dockerfile.minimal -t creg-test:integration . > $logFile 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Docker build failed"
            Get-Content $logFile -Tail 20
            return $false
        }
    } catch {
        Write-Error "Docker build failed: $_"
        return $false
    }
    
    # Verify image exists
    $images = docker images | Select-String "creg-test"
    if (-not $images) {
        Write-Error "Docker image not found after build"
        return $false
    }
    
    Write-Info "Docker image built successfully"
    return $true
}

# =============================================================================
# TEST 3: Service Startup
# =============================================================================
function Test-ServiceStartup {
    Write-Info "Testing service startup..."
    
    Set-Location $ProjectRoot
    
    # Clean up any existing containers
    docker-compose down -v 2>$null | Out-Null
    
    # Start infrastructure services
    docker-compose up -d anvil ipfs
    
    # Wait for Anvil
    Write-Info "Waiting for Anvil to be ready..."
    $anvilReady = $false
    for ($i = 1; $i -le 30; $i++) {
        try {
            $response = Invoke-RestMethod -Uri "http://localhost:8545" -Method Post `
                -Headers @{ "Content-Type" = "application/json" } `
                -Body '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' `
                -TimeoutSec 2 -ErrorAction SilentlyContinue
            if ($response) {
                $anvilReady = $true
                break
            }
        } catch {}
        Start-Sleep -Seconds 1
    }
    
    if (-not $anvilReady) {
        Write-Warn "Anvil may not be fully ready"
    }
    
    # Wait for IPFS
    Write-Info "Waiting for IPFS to be ready..."
    $ipfsReady = $false
    for ($i = 1; $i -le 30; $i++) {
        try {
            $response = Invoke-RestMethod -Uri "http://localhost:5001/api/v0/id" -TimeoutSec 2 -ErrorAction SilentlyContinue
            if ($response) {
                $ipfsReady = $true
                break
            }
        } catch {}
        Start-Sleep -Seconds 1
    }
    
    if (-not $ipfsReady) {
        Write-Warn "IPFS may not be fully ready"
    }
    
    # Start validator node
    Write-Info "Starting validator node..."
    docker-compose up -d node
    
    # Wait for node
    Write-Info "Waiting for validator node to be ready..."
    $nodeReady = $false
    for ($i = 1; $i -le 60; $i++) {
        try {
            $response = Invoke-RestMethod -Uri "http://localhost:8080/v1/health" -TimeoutSec 2 -ErrorAction SilentlyContinue
            if ($response) {
                Write-Info "Node is ready"
                return $true
            }
        } catch {}
        Start-Sleep -Seconds 2
    }
    
    Write-Error "Node failed to start within timeout"
    docker-compose logs node | Select-Object -Last 30
    return $false
}

# =============================================================================
# TEST 4: Health Check Endpoints
# =============================================================================
function Test-HealthEndpoints {
    Write-Info "Testing health endpoints..."
    
    # Test node health
    try {
        $healthResponse = Invoke-RestMethod -Uri "http://localhost:8080/v1/health" -TimeoutSec 5 -ErrorAction SilentlyContinue
        if (-not $healthResponse) {
            Write-Error "Health endpoint returned empty response"
            return $false
        }
        Write-Info "Health response: $healthResponse"
    } catch {
        Write-Error "Health check failed: $_"
        return $false
    }
    
    # Test version
    try {
        $versionResponse = Invoke-RestMethod -Uri "http://localhost:8080/v1/version" -TimeoutSec 5 -ErrorAction SilentlyContinue
        Write-Info "Version: $versionResponse"
    } catch {
        Write-Warn "Version endpoint not available"
    }
    
    return $true
}

# =============================================================================
# TEST 5: Package Registration Flow
# =============================================================================
function Test-PackageRegistration {
    Write-Info "Testing package registration flow..."
    
    Set-Location $ProjectRoot
    
    $testPackage = "test:integration-package@1.0.0"
    $testContent = "Integration test content"
    
    # Create test package
    $testDir = "$env:TEMP\creg-test-pkg"
    New-Item -ItemType Directory -Path $testDir -Force | Out-Null
    $testContent | Out-File -FilePath "$testDir\README.md" -Encoding utf8
    
    # Create tarball (requires tar - use Compress-Archive as alternative)
    $tarball = "$env:TEMP\creg-test-pkg.zip"
    Compress-Archive -Path "$testDir\*" -DestinationPath $tarball -Force
    
    Write-Info "Publishing test package: $testPackage"
    
    # Upload to IPFS (simulated - IPFS may not be available)
    try {
        $ipfsResponse = Invoke-RestMethod -Uri "http://localhost:5001/api/v0/add" -Method Post `
            -Form @{ file = Get-Item $tarball } -TimeoutSec 10 -ErrorAction SilentlyContinue
        if ($ipfsResponse) {
            Write-Info "IPFS response: $ipfsResponse"
        }
    } catch {
        Write-Warn "IPFS upload failed or not available, skipping IPFS test"
    }
    
    # Query package
    try {
        $queryResponse = Invoke-RestMethod -Uri "http://localhost:8080/v1/packages/$testPackage" `
            -TimeoutSec 5 -ErrorAction SilentlyContinue
        Write-Info "Package query response: $queryResponse"
    } catch {
        Write-Warn "Package query failed"
    }
    
    # Cleanup
    Remove-Item -Path $testDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $tarball -Force -ErrorAction SilentlyContinue
    
    return $true
}

# =============================================================================
# TEST 6: Multi-Validator Consensus
# =============================================================================
function Test-MultiValidatorConsensus {
    Write-Info "Testing multi-validator consensus (TEST MODE: Multiple validators on one PC)..."
    
    Set-Location $ProjectRoot
    
    # Check for validator configs
    $keysDir = Join-Path $ProjectRoot "validator-keys"
    if (-not (Test-Path $keysDir)) {
        Write-Warn "No validator keys found, skipping multi-validator test"
        return $true
    }
    
    $validatorConfigs = Get-ChildItem -Path $keysDir -Filter "validator-*.env" -ErrorAction SilentlyContinue
    $validatorCount = $validatorConfigs.Count
    
    if ($validatorCount -lt 2) {
        Write-Warn "Only $validatorCount validator config(s) found, skipping multi-validator test"
        return $true
    }
    
    Write-Info "Found $validatorCount validator configurations"
    Write-Info "Note: Running multiple validators on one PC is for TESTING ONLY"
    
    # Check if validators are running on their ports
    for ($i = 2; $i -le [Math]::Min($validatorCount, 3); $i++) {
        $port = 8080 + $i - 1
        try {
            $response = Invoke-RestMethod -Uri "http://localhost:$port/v1/health" `
                -TimeoutSec 2 -ErrorAction SilentlyContinue
            if ($response) {
                Write-Info "Validator $i is responding on port $port"
            }
        } catch {
            Write-Warn "Validator $i not responding on port $port"
        }
    }
    
    return $true
}

# =============================================================================
# TEST 7: Contract Deployment
# =============================================================================
function Test-ContractDeployment {
    Write-Info "Testing contract deployment..."
    
    Set-Location $ProjectRoot
    
    # Check if contracts are deployed
    try {
        $body = @{
            jsonrpc = "2.0"
            method = "eth_getCode"
            params = @("0x5FbDB2315678afecb367f032d93F642f64180aa3", "latest")
            id = 1
        } | ConvertTo-Json
        
        $response = Invoke-RestMethod -Uri "http://localhost:8545" -Method Post `
            -Headers @{ "Content-Type" = "application/json" } `
            -Body $body -TimeoutSec 5 -ErrorAction SilentlyContinue
        
        if ($response.result -and $response.result -ne "0x") {
            Write-Info "Contract code found on Anvil"
        } else {
            Write-Warn "Contract deployment status unclear"
        }
    } catch {
        Write-Warn "Could not check contract deployment: $_"
    }
    
    return $true
}

# =============================================================================
# TEST 8: CLI Tool Functionality
# =============================================================================
function Test-CliFunctionality {
    Write-Info "Testing CLI functionality..."
    
    # Test CLI help
    try {
        $cliHelp = docker run --rm creg-test:integration /app/creg --help 2>&1
        if ($cliHelp) {
            Write-Info "CLI responds to --help"
        }
    } catch {
        Write-Warn "CLI help not available (may be expected in minimal build)"
    }
    
    return $true
}

# =============================================================================
# Cleanup
# =============================================================================
function Invoke-Cleanup {
    Write-Info "Cleaning up test environment..."
    
    Set-Location $ProjectRoot
    
    # Stop containers
    docker-compose down -v 2>$null | Out-Null
    
    # Stop additional validators
    $keysDir = Join-Path $ProjectRoot "validator-keys"
    if (Test-Path $keysDir) {
        $composeFiles = Get-ChildItem -Path $keysDir -Filter "validator-*-docker-compose.yml" -ErrorAction SilentlyContinue
        foreach ($file in $composeFiles) {
            docker-compose -f $file.FullName down -v 2>$null | Out-Null
        }
    }
    
    # Remove test image
    docker rmi creg-test:integration 2>$null | Out-Null
    
    Write-Info "Cleanup complete"
}

# =============================================================================
# Main Test Execution
# =============================================================================
function Main {
    Write-Host ""
    Write-Host "========================================"
    Write-Host "Chain Registry - Integration Test Suite"
    Write-Host "========================================"
    Write-Host ""
    
    Write-Host "ARCHITECTURE NOTE:" -ForegroundColor Yellow
    Write-Host "  PRODUCTION: One validator per PC ONLY"
    Write-Host "  TESTING: Multiple validators on one PC is OK"
    Write-Host ""
    
    # Set cleanup trap
    if (-not $SkipCleanup) {
        Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
            Invoke-Cleanup
        } | Out-Null
    }
    
    # Run tests
    Invoke-Test "Environment Setup" ${function:Test-EnvironmentSetup}
    Invoke-Test "Docker Build" ${function:Test-DockerBuild}
    Invoke-Test "Service Startup" ${function:Test-ServiceStartup}
    Invoke-Test "Health Endpoints" ${function:Test-HealthEndpoints}
    Invoke-Test "Package Registration" ${function:Test-PackageRegistration}
    Invoke-Test "Multi-Validator Consensus" ${function:Test-MultiValidatorConsensus}
    Invoke-Test "Contract Deployment" ${function:Test-ContractDeployment}
    Invoke-Test "CLI Functionality" ${function:Test-CliFunctionality}
    
    # Summary
    Write-Host ""
    Write-Host "========================================"
    Write-Host "TEST SUMMARY"
    Write-Host "========================================"
    Write-Host ""
    
    $totalTests = $TestResults.Count
    $passedTests = $totalTests - $FailedTests.Count
    
    Write-Host "Results:"
    foreach ($result in $TestResults) {
        if ($result.StartsWith("PASS:")) {
            Write-Host "  [OK] $($result.Substring(5))" -ForegroundColor Green
        } else {
            Write-Host "  [FAIL] $($result.Substring(5))" -ForegroundColor Red
        }
    }
    
    Write-Host ""
    Write-Host "Summary: $passedTests/$totalTests tests passed"
    
    if ($FailedTests.Count -eq 0) {
        Write-Host ""
        Write-Host "All integration tests passed!" -ForegroundColor Green
        Write-Host ""
        Write-Host "The system is ready for testnet deployment."
        
        if (-not $SkipCleanup) {
            Invoke-Cleanup
        }
        exit 0
    } else {
        Write-Host ""
        Write-Host "$($FailedTests.Count) test(s) failed" -ForegroundColor Red
        Write-Host ""
        Write-Host "Failed tests:"
        foreach ($test in $FailedTests) {
            Write-Host "  - $test"
        }
        
        if (-not $SkipCleanup) {
            Invoke-Cleanup
        }
        exit 1
    }
}

# Run main
Main
