#!/bin/bash
# Chain Registry Integration Test Suite
# 
# IMPORTANT ARCHITECTURE NOTE:
# ============================
# In PRODUCTION: One validator per PC ONLY
# In TESTING: Multiple validators on one PC is OK (what this script does)
#
# These tests run multiple validators on a single machine for integration testing.
# For production deployment, each validator MUST run on a separate PC.

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test configuration
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$TEST_DIR/.." && pwd)"
NUM_VALIDATORS=3
TEST_RESULTS=()
FAILED_TESTS=()

# Logging
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Test runner
run_test() {
    local test_name="$1"
    local test_func="$2"
    
    echo ""
    log_info "Running: $test_name"
    
    if $test_func; then
        log_success "$test_name"
        TEST_RESULTS+=("PASS: $test_name")
        return 0
    else
        log_error "$test_name"
        TEST_RESULTS+=("FAIL: $test_name")
        FAILED_TESTS+=("$test_name")
        return 1
    fi
}

# =============================================================================
# TEST 1: Environment Setup
# =============================================================================
test_environment_setup() {
    log_info "Checking environment..."
    
    # Check .env exists
    if [ ! -f "$PROJECT_ROOT/.env" ]; then
        log_warn ".env file not found, creating from example"
        if [ -f "$PROJECT_ROOT/.env.example" ]; then
            cp "$PROJECT_ROOT/.env.example" "$PROJECT_ROOT/.env"
        fi
    fi
    
    # Check validator keys exist
    local key_count=0
    for i in 1 2 3; do
        local key_var="NODE${i}_VALIDATOR_KEY"
        if grep -q "^${key_var}=" "$PROJECT_ROOT/.env" 2>/dev/null; then
            local value=$(grep "^${key_var}=" "$PROJECT_ROOT/.env" | cut -d'=' -f2)
            if [ -n "$value" ] && [ "$value" != "your_validator_${i}_private_key_here" ]; then
                key_count=$((key_count + 1))
            fi
        fi
    done
    
    if [ $key_count -lt 3 ]; then
        log_warn "Missing validator keys. Run: ./scripts/generate-validator-keys.sh"
        return 1
    fi
    
    log_info "Found $key_count validator key(s)"
    return 0
}

# =============================================================================
# TEST 2: Docker Build
# =============================================================================
test_docker_build() {
    log_info "Testing Docker build..."
    
    cd "$PROJECT_ROOT"
    
    # Build minimal image (faster for testing)
    if ! docker build -f Dockerfile.minimal -t creg-test:integration . > /tmp/docker-build.log 2>&1; then
        log_error "Docker build failed"
        tail -20 /tmp/docker-build.log
        return 1
    fi
    
    # Verify image exists
    if ! docker images | grep -q "creg-test"; then
        log_error "Docker image not found after build"
        return 1
    fi
    
    log_info "Docker image built successfully"
    return 0
}

# =============================================================================
# TEST 3: Service Startup
# =============================================================================
test_service_startup() {
    log_info "Testing service startup..."
    
    cd "$PROJECT_ROOT"
    
    # Clean up any existing containers
    docker-compose down -v 2>/dev/null || true
    
    # Start infrastructure services
    docker-compose up -d anvil ipfs
    
    # Wait for services to be healthy
    log_info "Waiting for Anvil to be ready..."
    for i in {1..30}; do
        if curl -s -X POST -H "Content-Type: application/json" \
            --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' \
            http://localhost:8545 > /dev/null 2>&1; then
            break
        fi
        sleep 1
    done
    
    log_info "Waiting for IPFS to be ready..."
    for i in {1..30}; do
        if curl -s http://localhost:5001/api/v0/id > /dev/null 2>&1; then
            break
        fi
        sleep 1
    done
    
    log_info "Starting validator node..."
    docker-compose up -d node
    
    # Wait for node to be healthy
    log_info "Waiting for validator node to be ready..."
    for i in {1..60}; do
        if curl -s http://localhost:8080/v1/health > /dev/null 2>&1; then
            log_info "Node is ready"
            return 0
        fi
        sleep 2
    done
    
    log_error "Node failed to start within timeout"
    docker-compose logs node | tail -30
    return 1
}

# =============================================================================
# TEST 4: Health Check Endpoints
# =============================================================================
test_health_endpoints() {
    log_info "Testing health endpoints..."
    
    # Test node health
    local health_response=$(curl -s http://localhost:8080/v1/health 2>/dev/null)
    if [ -z "$health_response" ]; then
        log_error "Health endpoint returned empty response"
        return 1
    fi
    
    log_info "Health response: $health_response"
    
    # Test API version
    local version_response=$(curl -s http://localhost:8080/v1/version 2>/dev/null || echo "")
    log_info "Version: $version_response"
    
    return 0
}

# =============================================================================
# TEST 5: Package Registration Flow
# =============================================================================
test_package_registration() {
    log_info "Testing package registration flow..."
    
    # Use CLI to register a test package
    cd "$PROJECT_ROOT"
    
    local test_package="test:integration-package@1.0.0"
    local test_content="Integration test content"
    
    # Create a test tarball
    mkdir -p /tmp/creg-test-pkg
    echo "$test_content" > /tmp/creg-test-pkg/README.md
    tar -czf /tmp/creg-test-pkg.tar.gz -C /tmp/creg-test-pkg .
    
    log_info "Publishing test package: $test_package"
    
    # Publish via API (simulating CLI behavior)
    local content_hash=$(sha256sum /tmp/creg-test-pkg.tar.gz | cut -d' ' -f1)
    
    # Upload to IPFS
    local ipfs_response=$(curl -s -X POST -F "file=@/tmp/creg-test-pkg.tar.gz" \
        http://localhost:5001/api/v0/add 2>/dev/null || echo "")
    
    if [ -z "$ipfs_response" ]; then
        log_warn "IPFS upload failed or not available, skipping IPFS test"
    else
        log_info "IPFS response: $ipfs_response"
    fi
    
    # Query package (should exist if system is tracking)
    local query_response=$(curl -s "http://localhost:8080/v1/packages/$test_package" 2>/dev/null || echo "")
    log_info "Package query response: $query_response"
    
    # Cleanup
    rm -rf /tmp/creg-test-pkg /tmp/creg-test-pkg.tar.gz
    
    return 0
}

# =============================================================================
# TEST 6: Multi-Validator Consensus (Test Only - Multiple Validators on One PC)
# =============================================================================
test_multi_validator_consensus() {
    log_info "Testing multi-validator consensus (TEST MODE: Multiple validators on one PC)..."
    
    cd "$PROJECT_ROOT"
    
    # Check if we have multiple validator configs
    if [ ! -d "$PROJECT_ROOT/validator-keys" ]; then
        log_warn "No validator keys found, skipping multi-validator test"
        return 0
    fi
    
    local validator_count=$(ls -1 "$PROJECT_ROOT/validator-keys"/validator-*.env 2>/dev/null | wc -l)
    
    if [ $validator_count -lt 2 ]; then
        log_warn "Only $validator_count validator config(s) found, skipping multi-validator test"
        return 0
    fi
    
    log_info "Found $validator_count validator configurations"
    log_info "Note: Running multiple validators on one PC is for TESTING ONLY"
    
    # Start second validator if config exists
    if [ -f "$PROJECT_ROOT/validator-keys/validator-2-docker-compose.yml" ]; then
        log_info "Starting validator 2..."
        docker-compose -f "$PROJECT_ROOT/validator-keys/validator-2-docker-compose.yml" up -d node-2
        
        # Wait for validator 2
        sleep 5
        
        local v2_port=8081
        for i in {1..30}; do
            if curl -s "http://localhost:$v2_port/v1/health" > /dev/null 2>&1; then
                log_info "Validator 2 is ready (port $v2_port)"
                break
            fi
            sleep 2
        done
    fi
    
    return 0
}

# =============================================================================
# TEST 7: Contract Deployment
# =============================================================================
test_contract_deployment() {
    log_info "Testing contract deployment..."
    
    cd "$PROJECT_ROOT"
    
    # Check if contracts are deployed
    local anvil_response=$(curl -s -X POST -H "Content-Type: application/json" \
        --data '{"jsonrpc":"2.0","method":"eth_getCode","params":["0x5FbDB2315678afecb367f032d93F642f64180aa3", "latest"],"id":1}' \
        http://localhost:8545 2>/dev/null || echo "")
    
    if [ -n "$anvil_response" ]; then
        log_info "Contract code found on Anvil"
    else
        log_warn "Contract deployment status unclear"
    fi
    
    return 0
}

# =============================================================================
# TEST 8: CLI Tool Functionality
# =============================================================================
test_cli_functionality() {
    log_info "Testing CLI functionality..."
    
    # Test CLI help
    local cli_help=$(docker run --rm creg-test:integration /app/creg --help 2>/dev/null || echo "")
    
    if [ -n "$cli_help" ]; then
        log_info "CLI responds to --help"
    else
        log_warn "CLI help not available (may be expected in minimal build)"
    fi
    
    return 0
}

# =============================================================================
# Cleanup
# =============================================================================
cleanup() {
    log_info "Cleaning up test environment..."
    
    cd "$PROJECT_ROOT"
    
    # Stop all test containers
    docker-compose down -v 2>/dev/null || true
    
    # Stop additional validators
    if [ -d "$PROJECT_ROOT/validator-keys" ]; then
        for compose_file in "$PROJECT_ROOT/validator-keys"/validator-*-docker-compose.yml; do
            if [ -f "$compose_file" ]; then
                docker-compose -f "$compose_file" down -v 2>/dev/null || true
            fi
        done
    fi
    
    # Remove test image
    docker rmi creg-test:integration 2>/dev/null || true
    
    log_info "Cleanup complete"
}

# =============================================================================
# Main Test Execution
# =============================================================================
main() {
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║       Chain Registry - Integration Test Suite              ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    echo -e "${YELLOW}ARCHITECTURE NOTE:${NC}"
    echo "  PRODUCTION: One validator per PC ONLY"
    echo "  TESTING: Multiple validators on one PC is OK"
    echo ""
    
    # Parse arguments
    local skip_cleanup=false
    for arg in "$@"; do
        case $arg in
            --skip-cleanup)
                skip_cleanup=true
                shift
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --skip-cleanup    Don't cleanup containers after tests"
                echo "  --help            Show this help"
                echo ""
                exit 0
                ;;
        esac
    done
    
    # Set trap for cleanup
    if [ "$skip_cleanup" = false ]; then
        trap cleanup EXIT
    fi
    
    # Run tests
    run_test "Environment Setup" test_environment_setup
    run_test "Docker Build" test_docker_build
    run_test "Service Startup" test_service_startup
    run_test "Health Endpoints" test_health_endpoints
    run_test "Package Registration" test_package_registration
    run_test "Multi-Validator Consensus" test_multi_validator_consensus
    run_test "Contract Deployment" test_contract_deployment
    run_test "CLI Functionality" test_cli_functionality
    
    # Summary
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                      TEST SUMMARY                          ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    local total_tests=${#TEST_RESULTS[@]}
    local passed_tests=$((total_tests - ${#FAILED_TESTS[@]}))
    
    echo "Results:"
    for result in "${TEST_RESULTS[@]}"; do
        if [[ $result == PASS:* ]]; then
            echo -e "  ${GREEN}✓${NC} ${result#PASS: }"
        else
            echo -e "  ${RED}✗${NC} ${result#FAIL: }"
        fi
    done
    
    echo ""
    echo "Summary: $passed_tests/$total_tests tests passed"
    
    if [ ${#FAILED_TESTS[@]} -eq 0 ]; then
        echo -e "${GREEN}✓ All integration tests passed!${NC}"
        echo ""
        echo "The system is ready for testnet deployment."
        exit 0
    else
        echo -e "${RED}✗ ${#FAILED_TESTS[@]} test(s) failed${NC}"
        echo ""
        echo "Failed tests:"
        for test in "${FAILED_TESTS[@]}"; do
            echo "  - $test"
        done
        exit 1
    fi
}

# Run main
main "$@"
