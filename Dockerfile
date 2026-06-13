# Multi-stage build — produces a minimal runtime image (~80 MB).
# Updated for Chain Registry v0.3.0 with TUI Explorer and Enhanced Web UI
#
# Build profiles (controlled via --build-arg PROFILE=):
#   full      — (default) All features including ML/AI/ZK/WASM
#   minimal   — Fast build without ML/AI features
#
# For flaky networks pass --build-arg NETWORK_RETRIES=3

ARG PROFILE=full
ARG NETWORK_RETRIES=1

# ── Stage 1: Build Frontend ───────────────────────────────────────────────────
FROM node:20-slim AS frontend-builder
WORKDIR /explorer
COPY explorer/package*.json explorer/.npmrc* ./
RUN if [ -f package-lock.json ]; then npm ci --no-fund --no-audit || npm ci --no-fund --no-audit; else npm install --no-fund --no-audit || npm install --no-fund --no-audit; fi
COPY explorer/ ./
RUN npm run build

# ── Stage 2: Rust Toolchain ──────────────────────────────────────────────────
FROM rust:1.90-slim-bookworm AS rust-toolchain

# ── Stage 3: Build Rust Backend ───────────────────────────────────────────────
# Ubuntu 24.04 is required because ort (ONNX Runtime) 2.0.0-rc.12 prebuilt binaries
# link against glibc 2.38+ symbols (__isoc23_strtoll etc.) not present in Debian 12.
FROM ubuntu:24.04 AS builder

# Install native dependencies for:
# - OpenSSL (reqwest)
# - ZK proofs (arkworks needs build tools)
# - ML/ONNX (math libraries)
# - WASM (wasmtime dependencies)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    pkg-config \
    libssl-dev \
    build-essential \
    clang-17 \
    llvm-17 \
    llvm-17-dev \
    libclang-17-dev \
    libclang1-17 \
    cmake \
    libopenblas-dev \
    protobuf-compiler \
    libprotobuf-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# bindgen (librocksdb-sys) expects clang/llvm-config on PATH.
RUN ln -sf /usr/bin/clang-17 /usr/bin/clang && \
    ln -sf /usr/bin/llvm-config-17 /usr/bin/llvm-config

# Reuse the official Rust 1.90 toolchain while keeping the Ubuntu 24.04 builder.
COPY --from=rust-toolchain /usr/local/cargo /usr/local/cargo
COPY --from=rust-toolchain /usr/local/rustup /usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo
ENV RUSTUP_HOME=/usr/local/rustup
ENV LIBCLANG_PATH=/usr/lib/llvm-17/lib
ENV LLVM_CONFIG_PATH=/usr/bin/llvm-config-17
ENV CLANG_PATH=/usr/bin/clang-17
ENV PATH="/usr/local/cargo/bin:$PATH"
ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse
ENV CARGO_BUILD_JOBS=1
ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}
ENV CARGO_INCREMENTAL=0
# Do not set RUSTFLAGS globally — remap-path-prefix breaks librocksdb-sys bindgen/libclang.

RUN mkdir -p "$CARGO_HOME" && \
  printf '[net]\nretry = 10\ngit-fetch-with-cli = true\n\n[http]\nmultiplexing = false\ntimeout = 600\n\n[registries.crates-io]\nprotocol = "sparse"\n' > "$CARGO_HOME/config.toml"

RUN cargo --version && rustc --version && \
    test -e "${LIBCLANG_PATH}/libclang.so.1" -o -e "${LIBCLANG_PATH}/libclang.so"

WORKDIR /build

# Copy the built frontend into the expected location for rust-embed
COPY --from=frontend-builder /explorer/dist /build/explorer/dist

# Cache dependency layer separately from source.
COPY Cargo.toml ./
COPY Cargo.lock ./

# Core crates
COPY crates/common/Cargo.toml   crates/common/
COPY crates/cli/Cargo.toml      crates/cli/
COPY crates/resolver/Cargo.toml crates/resolver/
COPY crates/validator/Cargo.toml crates/validator/
COPY crates/consensus/Cargo.toml crates/consensus/
COPY crates/node/Cargo.toml     crates/node/
COPY crates/faucet/Cargo.toml   crates/faucet/
COPY crates/relayer/Cargo.toml  crates/relayer/

# Build-script inputs required for dependency caching.
COPY crates/common/build.rs     crates/common/
COPY crates/common/proto/       crates/common/proto/

# Phase 1: Advanced Validation crates
COPY crates/zk-validator/Cargo.toml     crates/zk-validator/
COPY crates/ml-validator/Cargo.toml     crates/ml-validator/
COPY crates/wasm-sandbox/Cargo.toml     crates/wasm-sandbox/

# Phase 2: Enterprise crates
COPY crates/threshold-encryption/Cargo.toml crates/threshold-encryption/
COPY crates/cross-chain/Cargo.toml        crates/cross-chain/

# Phase 3: Ecosystem crates
COPY crates/insurance/Cargo.toml        crates/insurance/
COPY crates/db-sync/Cargo.toml          crates/db-sync/
COPY crates/ipfs-pinner/Cargo.toml      crates/ipfs-pinner/
COPY crates/secrets/Cargo.toml          crates/secrets/

# Stub sources so Cargo can resolve dependencies before we copy real code.
RUN mkdir -p crates/common/src     && echo "pub fn _stub() {}" > crates/common/src/lib.rs
RUN mkdir -p crates/cli/src        && echo "fn main() {}"      > crates/cli/src/main.rs
RUN mkdir -p crates/resolver/src   && echo "pub fn _stub() {}" > crates/resolver/src/lib.rs
RUN mkdir -p crates/validator/src  && echo "pub fn _stub() {}" > crates/validator/src/lib.rs
RUN mkdir -p crates/consensus/src  && echo "pub fn _stub() {}" > crates/consensus/src/lib.rs
RUN mkdir -p crates/node/src       && echo "fn main() {}"      > crates/node/src/main.rs
RUN mkdir -p crates/relayer/src    && echo "fn main() {}"      > crates/relayer/src/main.rs

# Phase 1 stubs
RUN mkdir -p crates/zk-validator/src     && echo "pub fn _stub() {}" > crates/zk-validator/src/lib.rs
RUN mkdir -p crates/ml-validator/src     && echo "pub fn _stub() {}" > crates/ml-validator/src/lib.rs
RUN mkdir -p crates/wasm-sandbox/src     && echo "pub fn _stub() {}" > crates/wasm-sandbox/src/lib.rs

# Phase 2 stubs
RUN mkdir -p crates/threshold-encryption/src && echo "pub fn _stub() {}" > crates/threshold-encryption/src/lib.rs
RUN mkdir -p crates/cross-chain/src        && echo "pub fn _stub() {}" > crates/cross-chain/src/lib.rs

# Phase 3 stubs
RUN mkdir -p crates/insurance/src        && echo "pub fn _stub() {}" > crates/insurance/src/lib.rs
RUN mkdir -p crates/db-sync/src          && echo "pub fn _stub() {}" > crates/db-sync/src/lib.rs
RUN mkdir -p crates/ipfs-pinner/src      && echo "pub fn _stub() {}" > crates/ipfs-pinner/src/lib.rs

# Faucet stub
RUN mkdir -p crates/faucet/src           && echo "fn main() {}"      > crates/faucet/src/main.rs
RUN mkdir -p crates/secrets/src          && echo "pub fn _stub() {}" > crates/secrets/src/lib.rs

# Pre-fetch dependencies with retries so transient registry DNS issues do not
# fail the image build early.
RUN cargo fetch --locked || (sleep 5 && cargo fetch --locked) || (sleep 10 && cargo fetch --locked)

# Avoid a speculative workspace prebuild here. The stub-source phase can leave
# unusable target artifacts for librocksdb-sys before the real sources land.

# Copy real source and build properly.
COPY crates/ crates/
COPY circuits/ circuits/
COPY contracts/ contracts/
COPY models/ models/
COPY testnet/ testnet/
COPY config/ config/
COPY rules/ rules/
COPY validators/ validators/
COPY docker-compose*.yml ./

# Touch files to ensure rebuild
RUN touch crates/*/src/*.rs

# Build the node binaries with all features.
RUN env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS \
    LIBCLANG_PATH=/usr/lib/llvm-17/lib \
    LLVM_CONFIG_PATH=/usr/bin/llvm-config-17 \
    CLANG_PATH=/usr/bin/clang-17 \
    CARGO_BUILD_JOBS=1 RUST_BACKTRACE=1 \
    cargo build --release --locked --package chain-registry-node --bin creg-node --bin creg-indexer --features embedded-explorer

# Build CLI tools (includes TUI explorer)
RUN env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS \
    RUSTFLAGS="--remap-path-prefix=/build=/src" \
    cargo build --release --locked --package chain-registry-cli

# Build Faucet service (testnet)
RUN env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS \
    RUSTFLAGS="--remap-path-prefix=/build=/src" \
    cargo build --release --locked --package faucet

# Build Relayer service (sponsored testnet transactions)
RUN env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS \
    RUSTFLAGS="--remap-path-prefix=/build=/src" \
    cargo build --release --locked --package chain-registry-relayer

# ── Stage 3: Runtime ──────────────────────────────────────────────────────────
# Must match builder glibc version (Ubuntu 24.04 has glibc 2.39)
FROM ubuntu:24.04 AS runtime

# Production-hardened validator deps:
# - ca-certificates & curl: for IPFS / Eth RPC communication
# - libssl3: for crypto operations
# - libopenblas0: for ML math operations
# - strace: for Docker sandbox behavioral observation (syscall tracing)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    docker.io \
    libssl3 \
    libopenblas0 \
    strace \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binaries
COPY --from=builder /build/target/release/creg-node /app/creg-node
COPY --from=builder /build/target/release/creg-indexer /app/creg-indexer
COPY --from=builder /build/target/release/creg /app/creg
COPY --from=builder /build/target/release/faucet /app/faucet
COPY --from=builder /build/target/release/creg-relayer /app/creg-relayer

# Copy WASM validators (for wasm-sandbox)
COPY --from=builder /build/validators /app/validators

# Copy circuits (for ZK validation)
COPY --from=builder /build/circuits /app/circuits

# Copy ML models (for deep scan). These are placeholder-size today;
# replace with real ONNX weights when available.
COPY --from=builder /build/models /app/models

# Copy runtime configuration, including sandbox profiles and relayer policy examples
COPY --from=builder /build/config /app/config

# Copy YARA rules for supply-chain threat detection
COPY --from=builder /build/rules /app/rules

# Non-root user for security.
RUN useradd -r -s /bin/false creg
RUN mkdir -p /data && chown creg:creg /data
RUN chown -R creg:creg /app/circuits
ENV CREG_DATA_DIR=/data
USER creg

VOLUME ["/data"]
EXPOSE 8080 8084 50051

HEALTHCHECK --interval=20s --timeout=10s --retries=3 \
  CMD curl -f http://localhost:8080/v1/health || exit 1

ENTRYPOINT ["/app/creg-node"]
