#!/bin/bash
# Docker build script with retry logic and network optimizations

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Chain Registry Docker Build Script${NC}"
echo "===================================="

COMPOSE_CMD=(docker compose)

compose() {
    "${COMPOSE_CMD[@]}" "$@"
}

# Function to build with retry
build_with_retry() {
    local max_attempts=3
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        echo -e "${YELLOW}Build attempt $attempt of $max_attempts...${NC}"

        if compose build --progress=plain "$@"; then
            echo -e "${GREEN}Build successful!${NC}"
            return 0
        fi
        
        echo -e "${RED}Build failed. Retrying in 10 seconds...${NC}"
        sleep 10
        ((attempt++))
    done
    
    echo -e "${RED}Build failed after $max_attempts attempts.${NC}"
    return 1
}

# Check for required commands
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed${NC}"
    exit 1
fi

if docker compose version &> /dev/null; then
    COMPOSE_CMD=(docker compose)
elif command -v docker-compose &> /dev/null; then
    COMPOSE_CMD=(docker-compose)
else
    echo -e "${RED}Error: docker-compose is not installed${NC}"
    exit 1
fi

# Parse arguments
PROFILE=""
NO_CACHE=""
SERVICE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --profile)
            PROFILE="--profile $2"
            shift 2
            ;;
        --no-cache)
            NO_CACHE="--no-cache"
            shift
            ;;
        --service)
            SERVICE="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --profile <name>    Use specific profile (testnet, faucet, etc.)"
            echo "  --no-cache          Build without cache"
            echo "  --service <name>    Build specific service only"
            echo "  --help              Show this help"
            echo ""
            echo "Examples:"
            echo "  $0                                    # Build default services"
            echo "  $0 --profile testnet                  # Build with testnet profile"
            echo "  $0 --no-cache                         # Clean build"
            echo "  $0 --service node                     # Build only node service"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Show build info
echo ""
echo "Build Configuration:"
echo "  Profile: ${PROFILE:-default}"
echo "  No Cache: ${NO_CACHE:-false}"
echo "  Service: ${SERVICE:-all}"
echo ""

# Pre-pull base images to avoid timeout during build
echo -e "${YELLOW}Pre-pulling base images...${NC}"
docker pull node:20-slim || true
docker pull ubuntu:24.04 || true
docker pull ipfs/kubo:v0.27.0 || true
docker pull ghcr.io/foundry-rs/foundry:latest || true
docker pull postgres:15-alpine || true
docker pull nginx:alpine || true

# Build command
BUILD_CMD="${COMPOSE_CMD[*]} $PROFILE build"

if [ -n "$NO_CACHE" ]; then
    BUILD_CMD="$BUILD_CMD --no-cache"
fi

if [ -n "$SERVICE" ]; then
    BUILD_CMD="$BUILD_CMD $SERVICE"
fi

echo ""
echo -e "${YELLOW}Starting build...${NC}"
echo "Command: $BUILD_CMD"
echo ""

# Run build with retry
if build_with_retry $PROFILE $NO_CACHE $SERVICE; then
    echo ""
    echo -e "${GREEN}====================================${NC}"
    echo -e "${GREEN}Build completed successfully!${NC}"
    echo -e "${GREEN}====================================${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Start services: docker compose up -d"
    echo "  2. Check status: docker compose ps"
    echo "  3. View logs: docker compose logs -f"
    echo ""
    exit 0
else
    echo ""
    echo -e "${RED}====================================${NC}"
    echo -e "${RED}Build failed!${NC}"
    echo -e "${RED}====================================${NC}"
    echo ""
    echo "Troubleshooting:"
    echo "  1. Check internet connection"
    echo "  2. Try: docker system prune -f"
    echo "  3. Try: ./build-docker.sh --no-cache"
    echo "  4. Increase Docker memory limit (if on Docker Desktop)"
    echo ""
    exit 1
fi
