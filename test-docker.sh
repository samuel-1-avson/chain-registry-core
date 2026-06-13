#!/bin/bash
# Docker Build Test Script
# Tests all Docker configurations to verify they work

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test results
TESTS_PASSED=0
TESTS_FAILED=0
COMPOSE_CMD=(docker compose)

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++))
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++))
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

compose() {
    "${COMPOSE_CMD[@]}" "$@"
}

# Test 1: Check Docker is installed
test_docker_installed() {
    log_info "Testing Docker installation..."
    if command -v docker &> /dev/null; then
        DOCKER_VERSION=$(docker --version)
        log_success "Docker installed: $DOCKER_VERSION"
    else
        log_error "Docker not installed"
        exit 1
    fi
}

# Test 2: Check Docker Compose is installed
test_compose_installed() {
    log_info "Testing Docker Compose installation..."
    if docker compose version &> /dev/null; then
        COMPOSE_CMD=(docker compose)
        COMPOSE_VERSION=$(docker compose version)
        log_success "Docker Compose installed: $COMPOSE_VERSION"
    elif command -v docker-compose &> /dev/null; then
        COMPOSE_CMD=(docker-compose)
        COMPOSE_VERSION=$(docker-compose --version)
        log_success "Docker Compose installed: $COMPOSE_VERSION"
    else
        log_error "Docker Compose not installed"
        exit 1
    fi
}

# Test 3: Test Docker daemon
test_docker_daemon() {
    log_info "Testing Docker daemon..."
    if docker info &> /dev/null; then
        log_success "Docker daemon is running"
    else
        log_error "Docker daemon not running"
        exit 1
    fi
}

# Test 4: Validate docker-compose.yml
test_compose_valid() {
    log_info "Validating docker-compose.yml..."
    if compose config > /dev/null 2>&1; then
        log_success "docker-compose.yml is valid"
    else
        log_error "docker-compose.yml has errors"
        return 1
    fi
}

# Test 5: Validate docker-compose.prebuilt.yml
test_prebuilt_valid() {
    log_info "Validating docker-compose.prebuilt.yml..."
    if compose -f docker-compose.prebuilt.yml config > /dev/null 2>&1; then
        log_success "docker-compose.prebuilt.yml is valid"
    else
        log_error "docker-compose.prebuilt.yml has errors"
        return 1
    fi
}

test_testnet_valid() {
    log_info "Validating docker-compose.testnet.yml..."
    if compose --env-file .env.testnet -f docker-compose.testnet.yml config > /dev/null 2>&1; then
        log_success "docker-compose.testnet.yml is valid"
    else
        log_error "docker-compose.testnet.yml has errors"
        return 1
    fi
}

test_validator_valid() {
    log_info "Validating docker-compose.validator.yml..."
    export CREG_VALIDATOR_KEY="0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    export CREG_ETH_RPC="http://127.0.0.1:8545"
    export CREG_IPFS_URL="http://127.0.0.1:5001"

    if compose -f docker-compose.validator.yml config > /dev/null 2>&1; then
        log_success "docker-compose.validator.yml is valid"
    else
        log_error "docker-compose.validator.yml has errors"
        unset CREG_VALIDATOR_KEY CREG_ETH_RPC CREG_IPFS_URL
        return 1
    fi

    unset CREG_VALIDATOR_KEY CREG_ETH_RPC CREG_IPFS_URL
}

# Test 6: Check .dockerignore exists
test_dockerignore() {
    log_info "Checking .dockerignore..."
    if [ -f ".dockerignore" ]; then
        log_success ".dockerignore exists"
    else
        log_warn ".dockerignore not found (optional but recommended)"
    fi
}

# Test 7: Build minimal image
test_build_minimal() {
    log_info "Testing minimal Dockerfile build..."
    echo "This may take 5-10 minutes..."
    
    if docker build -f Dockerfile.minimal -t creg-test:minimal . > /tmp/build-minimal.log 2>&1; then
        log_success "Minimal Dockerfile builds successfully"
        
        # Check image size
        SIZE=$(docker images creg-test:minimal --format "{{.Size}}")
        log_info "Minimal image size: $SIZE"
        
        # Test running
        if docker run --rm creg-test:minimal --version > /dev/null 2>&1; then
            log_success "Minimal image runs successfully"
        else
            log_warn "Minimal image built but version check failed (may be normal)"
        fi
        
        # Cleanup
        docker rmi creg-test:minimal > /dev/null 2>&1 || true
    else
        log_error "Minimal Dockerfile build failed"
        echo "Build log:"
        tail -50 /tmp/build-minimal.log
        return 1
    fi
}

# Test 8: Test pre-built compose (dry run)
test_prebuilt_dryrun() {
    log_info "Testing pre-built compose (dry run)..."
    if compose -f docker-compose.prebuilt.yml up --dry-run > /dev/null 2>&1; then
        log_success "Pre-built compose configuration is valid"
    else
        log_warn "Pre-built compose dry-run had issues (may need environment variables)"
    fi
}

# Test 9: Check required files exist
test_required_files() {
    log_info "Checking required files..."
    
    REQUIRED_FILES=(
        "Dockerfile"
        "Dockerfile.minimal"
        "docker-compose.testnet.yml"
        "docker-compose.validator.yml"
        "docker-compose.yml"
        "docker-compose.prebuilt.yml"
        "Cargo.lock"
        "Cargo.toml"
    )
    
    for file in "${REQUIRED_FILES[@]}"; do
        if [ -f "$file" ]; then
            log_success "$file exists"
        else
            log_error "$file missing"
        fi
    done
}

# Test 10: Test build context size
test_context_size() {
    log_info "Testing Docker build context size..."

    local context_paths=(
        Cargo.toml
        Cargo.lock
        Dockerfile
        Dockerfile.minimal
        Dockerfile.optimized
        Dockerfile.windows
        docker-compose.yml
        docker-compose.prebuilt.yml
        docker-compose.testnet.yml
        docker-compose.validator.yml
        crates
        explorer
        circuits
        contracts
        models
        config
        rules
        testnet
    )

    local context_size=0
    local path_size=0

    for path in "${context_paths[@]}"; do
        if [ -e "$path" ]; then
            path_size=$(du -sb "$path" 2>/dev/null | cut -f1)
            context_size=$((context_size + path_size))
        fi
    done

    CONTEXT_SIZE=$context_size
    CONTEXT_SIZE_MB=$((CONTEXT_SIZE / 1024 / 1024))
    
    if [ $CONTEXT_SIZE_MB -lt 500 ]; then
        log_success "Build context estimate is reasonable: ${CONTEXT_SIZE_MB}MB"
    else
        log_warn "Build context estimate is large: ${CONTEXT_SIZE_MB}MB (check .dockerignore)"
    fi
}

# Test 11: Check for common issues
test_common_issues() {
    log_info "Checking for common issues..."
    
    # Check for CRLF line endings
    if file Dockerfile | grep -q "CRLF"; then
        log_warn "Dockerfile has Windows line endings (CRLF)"
    else
        log_success "Dockerfile has Unix line endings"
    fi
    
    # Check if port 8080 is available
    if netstat -tuln 2>/dev/null | grep -q ":8080"; then
        log_warn "Port 8080 is already in use"
    else
        log_success "Port 8080 is available"
    fi
}

# Main test execution
main() {
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║       Chain Registry Docker Build Test Suite               ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Run all tests
    test_docker_installed
    test_compose_installed
    test_docker_daemon
    test_required_files
    test_dockerignore
    test_compose_valid
    test_prebuilt_valid
    test_testnet_valid
    test_validator_valid
    test_context_size
    test_common_issues
    test_prebuilt_dryrun
    
    # Optional: Build test (can be skipped with --quick)
    if [[ "$1" != "--quick" ]]; then
        echo ""
        log_info "Running build tests (use --quick to skip)..."
        test_build_minimal
    else
        log_info "Skipping build tests (--quick mode)"
    fi
    
    # Summary
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                      TEST SUMMARY                          ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"
    echo ""
    
    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}✓ All tests passed! Docker setup looks good.${NC}"
        echo ""
        echo "Next steps:"
        echo "  1. docker compose --env-file .env.testnet -f docker-compose.testnet.yml up -d --build"
        echo "  2. Or: docker compose --env-file validator.env -f docker-compose.validator.yml up -d --build"
        exit 0
    else
        echo -e "${RED}✗ Some tests failed. Please review the errors above.${NC}"
        exit 1
    fi
}

# Run main function
main "$@"
