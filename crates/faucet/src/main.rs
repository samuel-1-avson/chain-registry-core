// crates/faucet/src/main.rs
// Testnet Faucet Service - Distributes test tCREG tokens (REAL IMPLEMENTATION)
#![deny(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use alloy::{
    network::EthereumWallet,
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
    sol,
};
use axum::{
    extract::{ConnectInfo, Json, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Json as JsonResponse},
    routing::{get, post},
    Router,
};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use metrics::{counter, gauge};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio_postgres::NoTls;
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info, warn};

sol!(
    #[sol(rpc)]
    interface IERC20 {
        function transfer(address to, uint256 amount) external returns (bool);
        function balanceOf(address owner) external view returns (uint256);
    }
);

/// Faucet configuration
#[derive(Clone)]
struct FaucetConfig {
    /// Amount to distribute per request (in wei/tCREG smallest unit)
    drip_amount: u128,
    /// Amount of native ETH/testnet ETH to distribute per request (wei)
    native_drip_amount: u128,
    /// Cooldown between requests per address
    cooldown_secs: u64,
    /// Cooldown between requests per IP
    ip_cooldown_secs: u64,
    /// Maximum balance a single address can have (prevent hoarding)
    max_balance: u128,
    /// Maximum native balance a single address can have before gas drip stops
    native_max_balance: u128,
    /// Ethereum RPC URL
    rpc_url: String,
    /// Faucet private key (must have tokens to distribute)
    faucet_key: String,
    /// Test CREG token contract address
    token_contract: String,
    /// Faucet Ethereum address
    faucet_address: String,
}

impl FaucetConfig {
    async fn from_env() -> anyhow::Result<(Self, chain_registry_secrets::SecretsProvider)> {
        let secrets = chain_registry_secrets::SecretsProvider::from_env()?;
        let faucet_key = secrets
            .secp256k1_signing_key_hex(chain_registry_secrets::HotKeyRole::Faucet)
            .await?;
        let faucet_address = std::env::var("FAUCET_ADDRESS").expect("FAUCET_ADDRESS must be set");

        Ok((
            Self {
                drip_amount: env_u128("FAUCET_DRIP_AMOUNT", 1000_000_000_000_000_000_000), // 1000 tCREG
                native_drip_amount: env_u128("FAUCET_NATIVE_DRIP_AMOUNT", 100_000_000_000_000_000), // 0.1 ETH
                cooldown_secs: env_u64("FAUCET_COOLDOWN_SECS", 60), // 1 minute
                ip_cooldown_secs: env_u64("FAUCET_IP_COOLDOWN_SECS", 60),
                max_balance: env_u128("FAUCET_MAX_BALANCE", 10000_000_000_000_000_000_000), // 10k tCREG
                native_max_balance: env_u128(
                    "FAUCET_NATIVE_MAX_BALANCE",
                    1_000_000_000_000_000_000,
                ), // 1 ETH
                rpc_url: env_string("FAUCET_RPC_URL", "http://localhost:8545"),
                faucet_key,
                token_contract: std::env::var("FAUCET_TOKEN_CONTRACT")
                    .expect("FAUCET_TOKEN_CONTRACT must be set"),
                faucet_address,
            },
            secrets,
        ))
    }
}

/// Rate limiter state
struct RateLimiter {
    /// Last request time per Ethereum address
    address_last_request: DashMap<String, Instant>,
    /// Last request time per IP
    ip_last_request: DashMap<String, Instant>,
}

struct CooldownRejection {
    message: String,
    retry_after_seconds: u64,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            address_last_request: DashMap::new(),
            ip_last_request: DashMap::new(),
        }
    }

    fn check_address(&self, address: &str, cooldown: Duration) -> Result<(), CooldownRejection> {
        let normalized = address.to_lowercase();
        if let Some(last) = self.address_last_request.get(&normalized) {
            let elapsed = last.elapsed();
            if elapsed < cooldown {
                let remaining = cooldown - elapsed;
                let retry_after_seconds = remaining.as_secs().max(1);
                return Err(CooldownRejection {
                    message: format!(
                        "Please wait {} seconds before requesting again",
                        retry_after_seconds
                    ),
                    retry_after_seconds,
                });
            }
        }
        Ok(())
    }

    fn check_ip(&self, ip: &str, cooldown: Duration) -> Result<(), CooldownRejection> {
        if let Some(last) = self.ip_last_request.get(ip) {
            let elapsed = last.elapsed();
            if elapsed < cooldown {
                let remaining = cooldown - elapsed;
                let retry_after_seconds = remaining.as_secs().max(1);
                return Err(CooldownRejection {
                    message: format!("IP rate limit: wait {} seconds", retry_after_seconds),
                    retry_after_seconds,
                });
            }
        }
        Ok(())
    }

    fn record_request(&self, address: &str, ip: &str) {
        self.address_last_request
            .insert(address.to_lowercase(), Instant::now());
        self.ip_last_request.insert(ip.to_string(), Instant::now());
    }
}

// ── Postgres-backed persistent rate limiter ───────────────────────────────────
//
// Falls back to in-memory behaviour if the Postgres connection is unavailable
// so the faucet still starts when `FAUCET_PG_URL` is not set.

/// Thin wrapper that persists cooldown timestamps to a Postgres table and uses
/// the in-memory `RateLimiter` as a fast local cache.  On restart the Postgres
/// table is the source of truth, preventing cooldown bypass via container restart.
struct PersistentRateLimiter {
    memory: RateLimiter,
    pg: Option<Arc<tokio_postgres::Client>>,
}

impl PersistentRateLimiter {
    /// Connect to Postgres (if `pg_url` is non-empty) and ensure the schema
    /// exists.  Returns an instance that degrades gracefully to in-memory-only
    /// if Postgres is unreachable.
    async fn new(pg_url: &str) -> Self {
        let pg = if pg_url.is_empty() {
            info!("FAUCET_PG_URL not set — rate-limiter running in-memory only (cooldowns reset on restart)");
            None
        } else {
            match tokio_postgres::connect(pg_url, NoTls).await {
                Ok((client, connection)) => {
                    // Drive the connection on a background task.
                    tokio::spawn(async move {
                        if let Err(e) = connection.await {
                            error!("Postgres rate-limiter connection error: {}", e);
                        }
                    });

                    // Create table if it does not exist.
                    let create = client
                        .execute(
                            "CREATE TABLE IF NOT EXISTS faucet_rate_limits (\
                              key TEXT PRIMARY KEY, \
                              last_request_unix BIGINT NOT NULL\
                            )",
                            &[],
                        )
                        .await;

                    match create {
                        Ok(_) => {
                            info!("Postgres rate-limiter table ready");
                            Some(Arc::new(client))
                        }
                        Err(e) => {
                            warn!("Could not create faucet_rate_limits table: {} — falling back to in-memory", e);
                            None
                        }
                    }
                }
                Err(e) => {
                    warn!("Could not connect to Postgres for rate-limiter: {} — falling back to in-memory", e);
                    None
                }
            }
        };

        Self {
            memory: RateLimiter::new(),
            pg,
        }
    }

    /// Check cooldown: consult in-memory first; if not found, query Postgres.
    async fn check_address(
        &self,
        address: &str,
        cooldown: Duration,
    ) -> Result<(), CooldownRejection> {
        // Fast path — in-memory cache hit.
        if let Err(r) = self.memory.check_address(address, cooldown) {
            return Err(r);
        }
        // Slow path — Postgres source of truth (catches post-restart attempts).
        if let Some(pg) = &self.pg {
            let key = format!("addr:{}", address.to_lowercase());
            if let Ok(rows) = pg
                .query(
                    "SELECT last_request_unix FROM faucet_rate_limits WHERE key=$1",
                    &[&key],
                )
                .await
            {
                if let Some(row) = rows.first() {
                    let last_unix: i64 = row.get(0);
                    let now_unix = chrono::Utc::now().timestamp();
                    let elapsed_secs = (now_unix - last_unix).max(0) as u64;
                    let cooldown_secs = cooldown.as_secs();
                    if elapsed_secs < cooldown_secs {
                        let remaining = cooldown_secs - elapsed_secs;
                        return Err(CooldownRejection {
                            message: format!(
                                "Please wait {} seconds before requesting again",
                                remaining
                            ),
                            retry_after_seconds: remaining,
                        });
                    }
                }
            }
        }
        Ok(())
    }

    async fn check_ip(&self, ip: &str, cooldown: Duration) -> Result<(), CooldownRejection> {
        if let Err(r) = self.memory.check_ip(ip, cooldown) {
            return Err(r);
        }
        if let Some(pg) = &self.pg {
            let key = format!("ip:{}", ip);
            if let Ok(rows) = pg
                .query(
                    "SELECT last_request_unix FROM faucet_rate_limits WHERE key=$1",
                    &[&key],
                )
                .await
            {
                if let Some(row) = rows.first() {
                    let last_unix: i64 = row.get(0);
                    let now_unix = chrono::Utc::now().timestamp();
                    let elapsed_secs = (now_unix - last_unix).max(0) as u64;
                    let cooldown_secs = cooldown.as_secs();
                    if elapsed_secs < cooldown_secs {
                        let remaining = cooldown_secs - elapsed_secs;
                        return Err(CooldownRejection {
                            message: format!("IP rate limit: wait {} seconds", remaining),
                            retry_after_seconds: remaining,
                        });
                    }
                }
            }
        }
        Ok(())
    }

    async fn record_request(&self, address: &str, ip: &str) {
        // Update in-memory cache.
        self.memory.record_request(address, ip);
        // Persist to Postgres.
        if let Some(pg) = &self.pg {
            let now_unix = chrono::Utc::now().timestamp();
            let addr_key = format!("addr:{}", address.to_lowercase());
            let ip_key = format!("ip:{}", ip);
            let upsert = "INSERT INTO faucet_rate_limits (key, last_request_unix) \
                          VALUES ($1, $2) \
                          ON CONFLICT (key) DO UPDATE SET last_request_unix = EXCLUDED.last_request_unix";
            if let Err(e) = pg.execute(upsert, &[&addr_key, &now_unix]).await {
                warn!("Rate-limiter Postgres write failed (addr): {}", e);
            }
            if let Err(e) = pg.execute(upsert, &[&ip_key, &now_unix]).await {
                warn!("Rate-limiter Postgres write failed (ip): {}", e);
            }
        }
    }

    fn address_count(&self) -> usize {
        self.memory.address_last_request.len()
    }
}

/// Application state
struct AppState {
    config: FaucetConfig,
    rate_limiter: PersistentRateLimiter,
    /// Active PoW challenges keyed by challenge string.
    pow_challenges: DashMap<String, PowChallenge>,
    /// Faucet statistics
    stats: Mutex<FaucetStats>,
    /// Operator pause flag — set via POST /admin/pause, cleared via POST /admin/resume.
    is_paused: Arc<AtomicBool>,
}

/// A proof-of-work challenge issued to clients.
#[derive(Clone)]
struct PowChallenge {
    difficulty: u8,
    created_at: Instant,
}

/// PoW difficulty — number of leading zero bits required in SHA-256(challenge || nonce).
/// 20 bits ≈ 1M hashes ≈ ~1 second on a modern browser.
const POW_DIFFICULTY: u8 = 20;
/// Challenge validity window.
const POW_TTL: Duration = Duration::from_secs(120);

/// Serialize a u128 as a JSON string so large amounts survive the JavaScript
/// 53-bit Number precision limit without truncation.
fn serialize_u128_as_string<S: serde::Serializer>(val: &u128, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&val.to_string())
}

#[derive(Default, Serialize)]
struct FaucetStats {
    total_drips: u64,
    /// Total tCREG distributed in wei (serialised as string for JS compatibility).
    #[serde(serialize_with = "serialize_u128_as_string")]
    total_distributed: u128,
    /// Total native ETH distributed in wei (serialised as string).
    #[serde(serialize_with = "serialize_u128_as_string")]
    total_native_distributed: u128,
    unique_addresses: usize,
    last_drip: Option<DateTime<Utc>>,
}

/// Request to drip tokens
#[derive(Deserialize)]
struct DripRequest {
    address: String,
    /// The PoW challenge string returned by /api/challenge.
    challenge: Option<String>,
    /// The nonce the client found such that SHA256(challenge||nonce) has N leading zero bits.
    nonce: Option<String>,
}

/// PoW challenge response
#[derive(Serialize)]
struct ChallengeResponse {
    challenge: String,
    difficulty: u8,
    ttl_secs: u64,
}

/// Drip response
#[derive(Serialize)]
struct DripResponse {
    success: bool,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    amount: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cooldown_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_tx_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    native_tx_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_amount: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    native_amount: Option<String>,
}

impl DripResponse {
    fn error(message: impl Into<String>) -> Self {
        let msg = message.into();
        Self {
            success: false,
            message: msg.clone(),
            error: Some(msg),
            tx_hash: None,
            amount: None,
            retry_after_seconds: None,
            cooldown_seconds: None,
            token_tx_hash: None,
            native_tx_hash: None,
            token_amount: None,
            native_amount: None,
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let (config, secrets) = FaucetConfig::from_env().await?;
    secrets.warn_hot_key_if_env(
        "faucet",
        chain_registry_secrets::HotKeyRole::Faucet,
        &config.faucet_key,
        common::is_testnet_env(),
    );

    info!("╔════════════════════════════════════════════════════════╗");
    info!("║        Chain Registry Testnet Faucet (REAL)            ║");
    info!("╚════════════════════════════════════════════════════════╝");
    info!(
        "  Drip amount: {} tCREG",
        config.drip_amount / 10_u128.pow(18)
    );
    if config.native_drip_amount > 0 {
        info!(
            "  Gas drip amount: {:.4} ETH",
            config.native_drip_amount as f64 / 10_f64.powi(18)
        );
    }
    info!("  Cooldown: {} seconds", config.cooldown_secs);
    info!("  Token contract: {}", config.token_contract);
    info!("  RPC: {}", config.rpc_url);
    info!("  Faucet address: {}", config.faucet_address);

    // ── Pre-flight balance check ──────────────────────────────────────────────
    // Warn loudly at startup if the faucet wallet has no tokens.  This catches
    // the common case where Anvil was restarted (losing on-chain state) without
    // re-running deploy-contracts + sync-testnet-artifacts.
    match get_token_balance(&config, &config.faucet_address).await {
        Ok(0) => {
            let chain_id = env_u64("FAUCET_CHAIN_ID", 31337);
            let fund_hint = if chain_id == 11155111 {
                "testnet\\fund-sepolia-faucet-governance.ps1"
            } else {
                "scripts/start-testnet.ps1 (or Fund-TestnetFaucet)"
            };
            error!("╔═══════════════════════════════════════════════════════════╗");
            error!("║  FAUCET BALANCE IS ZERO — drip requests WILL FAIL         ║");
            error!("║  Fix: run {fund_hint} to fund this wallet.               ║");
            error!("╚═══════════════════════════════════════════════════════════╝");
        }
        Ok(bal) => {
            info!(
                "  Faucet token balance: {:.2} tCREG — ready to drip",
                bal as f64 / 1e18
            );
        }
        Err(e) => {
            warn!(
                "Could not read faucet token balance at startup (RPC may not be ready yet): {}",
                e
            );
        }
    }

    let pg_url = env_string("FAUCET_PG_URL", "");
    let rate_limiter = PersistentRateLimiter::new(&pg_url).await;

    let state = Arc::new(AppState {
        config,
        rate_limiter,
        pow_challenges: DashMap::new(),
        stats: Mutex::new(FaucetStats::default()),
        is_paused: Arc::new(AtomicBool::new(false)),
    });

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // ── Prometheus metrics recorder ───────────────────────────────────────────
    let prometheus_handle = metrics_exporter_prometheus::PrometheusBuilder::new()
        .install_recorder()
        .expect("failed to install Prometheus metrics recorder");

    // Pre-declare metric descriptions so they appear in /metrics even before
    // the first drip.
    metrics::describe_counter!(
        "faucet_drips_total",
        "Total number of successful drip operations"
    );
    metrics::describe_counter!("faucet_token_drips_total", "Successful tCREG token drips");
    metrics::describe_counter!(
        "faucet_native_drips_total",
        "Successful native ETH gas drips"
    );
    metrics::describe_counter!("faucet_failures_total", "Failed drip attempts");
    metrics::describe_counter!(
        "faucet_rate_limited_total",
        "Requests rejected by rate limiter"
    );
    metrics::describe_counter!(
        "faucet_pow_failures_total",
        "Requests rejected due to invalid PoW"
    );
    metrics::describe_gauge!(
        "faucet_token_balance",
        "Current faucet tCREG token balance (raw wei)"
    );
    metrics::describe_gauge!(
        "faucet_native_balance",
        "Current faucet native ETH balance (raw wei)"
    );

    // Clone config for the background balance gauge task before `state` is
    // moved into the axum router.
    let bg_config = state.config.clone();

    let app = Router::new()
        .route("/", get(index_page))
        .route("/favicon.ico", get(favicon))
        .route("/api/challenge", get(get_challenge))
        .route("/api/drip", post(handle_drip))
        .route("/api/stats", get(get_stats))
        .route("/api/balance/:address", get(get_balance))
        .route("/api/network", get(get_network_info))
        .route("/health", get(health_check))
        .route(
            "/metrics",
            get(move || {
                let handle = prometheus_handle.clone();
                async move { handle.render() }
            }),
        )
        // ── Operator admin endpoints (require FAUCET_ADMIN_TOKEN) ─────────────
        .route("/admin/pause", post(admin_pause))
        .route("/admin/resume", post(admin_resume))
        .route("/admin/status", get(admin_status))
        .layer(cors)
        .with_state(state);

    let port = env_u16("FAUCET_PORT", 8082);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    // ── Optional TLS ──────────────────────────────────────────────────────────
    #[cfg(feature = "tls")]
    {
        let tls_cert = std::env::var("FAUCET_TLS_CERT").ok();
        let tls_key = std::env::var("FAUCET_TLS_KEY").ok();

        if let (Some(cert_path), Some(key_path)) = (tls_cert, tls_key) {
            use axum_server::tls_rustls::RustlsConfig;

            let tls_config = RustlsConfig::from_pem_file(&cert_path, &key_path)
                .await
                .expect("Failed to load TLS certificate/key");

            info!("Faucet listening on https://{}", addr);

            axum_server::bind_rustls(addr, tls_config)
                .serve(app.into_make_service())
                .await?;

            return Ok(());
        }
    }

    info!("Faucet listening on http://{}", addr);

    // ── Background balance gauge updater ─────────────────────────────────────
    // Refreshes the Prometheus balance gauges every 30 seconds so Grafana always
    // shows an up-to-date faucet wallet balance without waiting for a drip.
    {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(30));
            loop {
                ticker.tick().await;
                if let Ok(bal) = get_token_balance(&bg_config, &bg_config.faucet_address).await {
                    gauge!("faucet_token_balance").set(bal as f64);
                }
                if let Ok(bal) = get_native_balance(&bg_config, &bg_config.faucet_address).await {
                    gauge!("faucet_native_balance").set(bal as f64);
                }
            }
        });
    }

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

/// HTML faucet page
async fn index_page() -> impl IntoResponse {
    Html(include_str!("faucet.html"))
}

/// Small inline favicon so browsers do not fall back to a missing default asset.
async fn favicon() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "image/svg+xml")],
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>💧</text></svg>",
    )
}

fn parse_address(value: &str, field_name: &str) -> Result<Address, String> {
    value
        .parse::<Address>()
        .map_err(|e| format!("Invalid {}: {}", field_name, e))
}

async fn execute_token_transfer(config: &FaucetConfig, to_address: &str) -> Result<String, String> {
    let signer: PrivateKeySigner = config
        .faucet_key
        .parse()
        .map_err(|e| format!("Invalid faucet private key: {}", e))?;
    let wallet = EthereumWallet::from(signer);
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_http(
            config
                .rpc_url
                .parse()
                .map_err(|e| format!("Invalid faucet RPC URL: {}", e))?,
        );

    let token_address = parse_address(&config.token_contract, "token contract")?;
    let recipient = parse_address(to_address, "recipient address")?;
    let contract = IERC20::new(token_address, &provider);

    let pending_tx = contract
        .transfer(recipient, U256::from(config.drip_amount))
        .send()
        .await
        .map_err(|e| format!("Transfer failed: {}", e))?;
    let tx_hash = pending_tx.tx_hash().to_string();

    pending_tx
        .watch()
        .await
        .map_err(|e| format!("Transfer confirmation failed: {}", e))?;

    Ok(tx_hash)
}

async fn execute_native_transfer(
    config: &FaucetConfig,
    to_address: &str,
) -> Result<String, String> {
    let signer: PrivateKeySigner = config
        .faucet_key
        .parse()
        .map_err(|e| format!("Invalid faucet private key: {}", e))?;
    let wallet = EthereumWallet::from(signer);
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_http(
            config
                .rpc_url
                .parse()
                .map_err(|e| format!("Invalid faucet RPC URL: {}", e))?,
        );

    let recipient = parse_address(to_address, "recipient address")?;
    let tx = TransactionRequest::default()
        .to(recipient)
        .value(U256::from(config.native_drip_amount));

    let pending_tx = provider
        .send_transaction(tx)
        .await
        .map_err(|e| format!("Native ETH transfer failed: {}", e))?;
    let tx_hash = pending_tx.tx_hash().to_string();

    pending_tx
        .watch()
        .await
        .map_err(|e| format!("Native ETH confirmation failed: {}", e))?;

    Ok(tx_hash)
}

async fn get_token_balance(config: &FaucetConfig, address: &str) -> Result<u128, String> {
    let holder = parse_address(address, "holder address")?;
    let token_addr = parse_address(&config.token_contract, "token contract")?;

    // Read-only provider — no wallet or nonce management needed for view calls.
    let provider = ProviderBuilder::new().on_http(
        config
            .rpc_url
            .parse()
            .map_err(|e| format!("Invalid RPC URL for balance check: {e}"))?,
    );

    let token = IERC20::new(token_addr, provider);
    let ret = token
        .balanceOf(holder)
        .call()
        .await
        .map_err(|e| format!("balanceOf({address}) call failed: {e}"))?;

    // Realistic token supplies (≤ 10^26 wei) fit well within u128 (≤ 3.4 × 10^38).
    Ok(ret._0.to::<u128>())
}

async fn get_native_balance(config: &FaucetConfig, address: &str) -> Result<u128, String> {
    let response: serde_json::Value = reqwest::Client::new()
        .post(&config.rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getBalance",
            "params": [address, "latest"],
            "id": 1
        }))
        .send()
        .await
        .map_err(|e| format!("Native balance check failed: {}", e))?
        .json()
        .await
        .map_err(|e| format!("Native balance response decode failed: {}", e))?;

    if let Some(err) = response.get("error") {
        return Err(format!("Native balance check failed: {}", err));
    }

    let result = response
        .get("result")
        .and_then(|value| value.as_str())
        .ok_or_else(|| "Native balance check failed: missing result".to_string())?;

    u128::from_str_radix(result.trim_start_matches("0x"), 16)
        .map_err(|e| format!("Failed to parse native balance: {}", e))
}

/// Issue a proof-of-work challenge. Client must find a nonce such that
/// SHA-256(challenge || nonce) has `difficulty` leading zero bits.
async fn get_challenge(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    info!(">>> get_challenge request received");
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let challenge = hex::encode(bytes);

    // Prune expired challenges periodically.
    state
        .pow_challenges
        .retain(|_, v| v.created_at.elapsed() < POW_TTL);

    state.pow_challenges.insert(
        challenge.clone(),
        PowChallenge {
            difficulty: POW_DIFFICULTY,
            created_at: Instant::now(),
        },
    );

    (
        StatusCode::OK,
        JsonResponse(ChallengeResponse {
            challenge,
            difficulty: POW_DIFFICULTY,
            ttl_secs: POW_TTL.as_secs(),
        }),
    )
}

/// Verify proof-of-work: SHA-256(challenge || nonce) must have `difficulty` leading zero bits.
fn verify_pow(challenge: &str, nonce: &str, difficulty: u8) -> bool {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(challenge.as_bytes());
    hasher.update(nonce.as_bytes());
    let hash = hasher.finalize();

    // Count leading zero bits.
    let mut leading_zeros = 0u8;
    for byte in hash.iter() {
        if *byte == 0 {
            leading_zeros += 8;
        } else {
            leading_zeros += byte.leading_zeros() as u8;
            break;
        }
        if leading_zeros >= difficulty {
            break;
        }
    }
    leading_zeros >= difficulty
}

/// Handle drip request
async fn handle_drip(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<DripRequest>,
) -> impl IntoResponse {
    // ── Operator pause check ──────────────────────────────────────────────────
    if state.is_paused.load(Ordering::Relaxed) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            JsonResponse(DripResponse::error(
                "Faucet is temporarily paused by the operator. Please try again later.",
            )),
        );
    }

    let address = request.address.to_lowercase();

    // ── PoW validation ────────────────────────────────────────────────────────
    let pow_enabled = std::env::var("FAUCET_POW_DISABLED").unwrap_or_default() != "true";
    if pow_enabled {
        let challenge = match &request.challenge {
            Some(c) => c.clone(),
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    JsonResponse(DripResponse::error(
                        "Missing proof-of-work challenge. Call GET /api/challenge first.",
                    )),
                );
            }
        };

        let nonce = match &request.nonce {
            Some(n) => n.clone(),
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    JsonResponse(DripResponse::error("Missing proof-of-work nonce.")),
                );
            }
        };

        // Look up and consume the challenge (single-use).
        let pow_entry = state.pow_challenges.remove(&challenge);
        match pow_entry {
            Some((_, pc)) if pc.created_at.elapsed() < POW_TTL => {
                if !verify_pow(&challenge, &nonce, pc.difficulty) {
                    counter!("faucet_pow_failures_total", "reason" => "invalid_solution")
                        .increment(1);
                    return (
                        StatusCode::BAD_REQUEST,
                        JsonResponse(DripResponse::error("Invalid proof-of-work solution.")),
                    );
                }
            }
            _ => {
                counter!("faucet_pow_failures_total", "reason" => "expired_or_unknown")
                    .increment(1);
                return (
                    StatusCode::BAD_REQUEST,
                    JsonResponse(DripResponse::error(
                        "Unknown or expired challenge. Request a new one.",
                    )),
                );
            }
        }
    }

    // Validate address format
    if !address.starts_with("0x") || address.len() != 42 {
        return (
            StatusCode::BAD_REQUEST,
            JsonResponse(DripResponse::error("Invalid Ethereum address format")),
        );
    }

    // Extract client IP from X-Forwarded-For / X-Real-IP headers, fallback to socket peer
    let client_ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| peer_addr.ip().to_string());

    // Check rate limits
    let cooldown = Duration::from_secs(state.config.cooldown_secs);
    if let Err(rejection) = state.rate_limiter.check_address(&address, cooldown).await {
        counter!("faucet_rate_limited_total", "reason" => "address").increment(1);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            JsonResponse(DripResponse {
                retry_after_seconds: Some(rejection.retry_after_seconds),
                cooldown_seconds: Some(state.config.cooldown_secs),
                ..DripResponse::error(rejection.message)
            }),
        );
    }

    let ip_cooldown = Duration::from_secs(state.config.ip_cooldown_secs);
    if let Err(rejection) = state.rate_limiter.check_ip(&client_ip, ip_cooldown).await {
        counter!("faucet_rate_limited_total", "reason" => "ip").increment(1);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            JsonResponse(DripResponse {
                retry_after_seconds: Some(rejection.retry_after_seconds),
                cooldown_seconds: Some(state.config.ip_cooldown_secs),
                ..DripResponse::error(rejection.message)
            }),
        );
    }

    let token_balance = get_token_balance(&state.config, &address).await.ok();
    let native_balance = if state.config.native_drip_amount > 0 {
        get_native_balance(&state.config, &address).await.ok()
    } else {
        None
    };

    let should_send_token = match token_balance {
        Some(balance) => balance < state.config.max_balance,
        None => true,
    };
    let should_send_native = if state.config.native_drip_amount == 0 {
        false
    } else {
        match native_balance {
            Some(balance) => balance < state.config.native_max_balance,
            None => true,
        }
    };

    if should_send_token {
        match get_token_balance(&state.config, &state.config.faucet_address).await {
            Ok(faucet_balance) if faucet_balance < state.config.drip_amount => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    JsonResponse(DripResponse::error(
                        "Faucet is out of tCREG. An operator must fund the faucet wallet before more token drips are possible.",
                    )),
                );
            }
            Err(err) => {
                error!("Could not read faucet token balance before drip: {}", err);
            }
            _ => {}
        }
    }

    if should_send_native {
        match get_native_balance(&state.config, &state.config.faucet_address).await {
            Ok(faucet_native) if faucet_native < state.config.native_drip_amount => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    JsonResponse(DripResponse::error(
                        "Faucet is out of testnet ETH for gas drips. Fund the faucet wallet with Sepolia ETH.",
                    )),
                );
            }
            Err(err) => {
                error!("Could not read faucet native balance before drip: {}", err);
            }
            _ => {}
        }
    }

    if !should_send_token && !should_send_native {
        let token_msg = token_balance
            .map(|balance| format!("{} tCREG", balance / 10_u128.pow(18)))
            .unwrap_or_else(|| "sufficient tCREG".to_string());
        let native_msg = native_balance
            .map(|balance| format!("{:.4} ETH", balance as f64 / 10_f64.powi(18)))
            .unwrap_or_else(|| "sufficient testnet ETH".to_string());
        return (
            StatusCode::BAD_REQUEST,
            JsonResponse(DripResponse {
                success: false,
                message: format!(
                    "Address already has enough test funds for now ({}, {}).",
                    token_msg, native_msg
                ),
                error: None,
                tx_hash: None,
                amount: None,
                retry_after_seconds: None,
                cooldown_seconds: None,
                token_tx_hash: None,
                native_tx_hash: None,
                token_amount: None,
                native_amount: None,
            }),
        );
    }

    let mut token_tx_hash = None;
    let mut native_tx_hash = None;
    let mut parts = Vec::new();
    let mut failures = Vec::new();

    if should_send_native {
        match execute_native_transfer(&state.config, &address).await {
            Ok(tx_hash) => {
                parts.push(format!(
                    "{:.4} ETH for gas",
                    state.config.native_drip_amount as f64 / 10_f64.powi(18)
                ));
                native_tx_hash = Some(tx_hash);
                counter!("faucet_native_drips_total").increment(1);
            }
            Err(err) => {
                error!("Native gas drip failed: {}", err);
                failures.push(format!("native ETH: {}", err));
                counter!("faucet_failures_total", "kind" => "native").increment(1);
            }
        }
    }

    if should_send_token {
        match execute_token_transfer(&state.config, &address).await {
            Ok(tx_hash) => {
                parts.push(format!(
                    "{} tCREG",
                    state.config.drip_amount / 10_u128.pow(18)
                ));
                token_tx_hash = Some(tx_hash);
                counter!("faucet_token_drips_total").increment(1);
            }
            Err(err) => {
                error!("Token drip failed: {}", err);
                failures.push(format!("tCREG: {}", err));
                counter!("faucet_failures_total", "kind" => "token").increment(1);
            }
        }
    }

    if token_tx_hash.is_some() || native_tx_hash.is_some() {
        state
            .rate_limiter
            .record_request(&address, &client_ip)
            .await;
        counter!("faucet_drips_total").increment(1);

        // Update stats
        let mut stats = state.stats.lock().await;
        stats.total_drips += 1;
        stats.unique_addresses = state.rate_limiter.address_count();
        if token_tx_hash.is_some() {
            stats.total_distributed = stats
                .total_distributed
                .saturating_add(state.config.drip_amount);
        }
        if native_tx_hash.is_some() {
            stats.total_native_distributed = stats
                .total_native_distributed
                .saturating_add(state.config.native_drip_amount);
        }
        stats.last_drip = Some(Utc::now());
        drop(stats);

        info!(
            "Dripped {} to {}{}{}",
            parts.join(" + "),
            address,
            token_tx_hash
                .as_ref()
                .map(|tx| format!(" (token tx: {})", tx))
                .unwrap_or_default(),
            native_tx_hash
                .as_ref()
                .map(|tx| format!(" (gas tx: {})", tx))
                .unwrap_or_default()
        );

        (
            StatusCode::OK,
            JsonResponse(DripResponse {
                success: true,
                message: if failures.is_empty() {
                    format!("Sent {}.", parts.join(" + "))
                } else {
                    format!(
                        "Sent {}. Partial issue: {}",
                        parts.join(" + "),
                        failures.join("; ")
                    )
                },
                error: None,
                tx_hash: token_tx_hash.clone().or_else(|| native_tx_hash.clone()),
                amount: Some(parts.join(" + ")),
                retry_after_seconds: None,
                cooldown_seconds: Some(state.config.cooldown_secs),
                token_tx_hash,
                native_tx_hash,
                token_amount: if should_send_token {
                    Some(format!("{}", state.config.drip_amount / 10_u128.pow(18)))
                } else {
                    None
                },
                native_amount: if should_send_native {
                    Some(format!(
                        "{:.4}",
                        state.config.native_drip_amount as f64 / 10_f64.powi(18)
                    ))
                } else {
                    None
                },
            }),
        )
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            JsonResponse(DripResponse {
                success: false,
                message: if failures.is_empty() {
                    "Faucet transfer failed for an unknown reason.".to_string()
                } else {
                    format!("Faucet transfer failed: {}", failures.join("; "))
                },
                error: Some(if failures.is_empty() {
                    "unknown_error".to_string()
                } else {
                    failures.join("; ")
                }),
                tx_hash: None,
                amount: None,
                retry_after_seconds: None,
                cooldown_seconds: None,
                token_tx_hash: None,
                native_tx_hash: None,
                token_amount: None,
                native_amount: None,
            }),
        )
    }
}

/// Get faucet statistics
async fn get_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let stats = state.stats.lock().await;

    // Get real faucet balance
    let faucet_balance = get_token_balance(&state.config, &state.config.faucet_address)
        .await
        .unwrap_or(0);
    let faucet_native_balance = get_native_balance(&state.config, &state.config.faucet_address)
        .await
        .unwrap_or(0);

    JsonResponse(serde_json::json!({
        "drip_amount": state.config.drip_amount.to_string(),
        "native_drip_amount": state.config.native_drip_amount.to_string(),
        "cooldown_seconds": state.config.cooldown_secs,
        "max_balance": state.config.max_balance.to_string(),
        "native_max_balance": state.config.native_max_balance.to_string(),
        "token_contract": state.config.token_contract,
        "faucet_address": state.config.faucet_address,
        "faucet_balance": faucet_balance.to_string(),
        "faucet_balance_formatted": format!("{:.2}", faucet_balance as f64 / 10_f64.powi(18)),
        "faucet_native_balance": faucet_native_balance.to_string(),
        "faucet_native_balance_formatted": format!("{:.4}", faucet_native_balance as f64 / 10_f64.powi(18)),
        "stats": *stats,
    }))
}

/// Get balance for address (REAL)
async fn get_balance(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(address): axum::extract::Path<String>,
) -> impl IntoResponse {
    info!(">>> get_balance request for address: {}", address);
    let token_balance = get_token_balance(&state.config, &address).await;
    let native_balance = get_native_balance(&state.config, &address).await;

    match (token_balance, native_balance) {
        (Ok(balance), Ok(native)) => JsonResponse(serde_json::json!({
            "address": address,
            "balance": balance.to_string(),
            "balance_formatted": format!("{:.2}", balance as f64 / 10_f64.powi(18)),
            "token_balance": balance.to_string(),
            "token_balance_formatted": format!("{:.2}", balance as f64 / 10_f64.powi(18)),
            "native_balance": native.to_string(),
            "native_balance_formatted": format!("{:.4}", native as f64 / 10_f64.powi(18)),
        })),
        (token_result, native_result) => JsonResponse(serde_json::json!({
            "address": address,
            "error": format!(
                "token={}, native={}",
                token_result.err().unwrap_or_else(|| "ok".to_string()),
                native_result.err().unwrap_or_else(|| "ok".to_string())
            ),
        })),
    }
}

fn chain_display_name(chain_id: u64) -> &'static str {
    match chain_id {
        11155111 => "CREG Testnet (Sepolia)",
        31337 => "CREG Testnet (Anvil)",
        _ => "CREG Testnet",
    }
}

/// Network configuration info for wallet setup and next-step guidance
async fn get_network_info(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let explorer_url = env_string("FAUCET_EXPLORER_URL", "http://localhost:3007");
    let rpc_url = env_string("FAUCET_PUBLIC_RPC_URL", "http://localhost:8545");
    let chain_id = env_u64("FAUCET_CHAIN_ID", 31337);

    JsonResponse(serde_json::json!({
        "chain_id": chain_id,
        "rpc_url": rpc_url,
        "token_contract": state.config.token_contract,
        "explorer_url": explorer_url,
        "chain_name": chain_display_name(chain_id),
        "currency": "ETH",
        "token_symbol": "tCREG",
        "native_currency_symbol": "ETH",
        "gas_note": "Gas on EVM testnets is paid in the native testnet ETH for that chain, not in ERC-20 tokens.",
    }))
}

/// Health check
async fn health_check(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match (
        get_token_balance(&state.config, &state.config.faucet_address).await,
        get_native_balance(&state.config, &state.config.faucet_address).await,
    ) {
        (Ok(faucet_balance), Ok(faucet_native_balance)) => {
            let token_ready = faucet_balance >= state.config.drip_amount;
            let native_ready = state.config.native_drip_amount == 0
                || faucet_native_balance >= state.config.native_drip_amount;
            let fully_ready = token_ready && native_ready;
            // Liveness: return 200 whenever the process can reach RPC and report
            // balances. Readiness fields (token_drips_available / native_drips_available)
            // let operators fund or tune drips without marking the container dead.
            let status_code = if token_ready || native_ready {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            };
            let status = if fully_ready {
                "healthy"
            } else if token_ready || native_ready {
                "degraded"
            } else {
                "unavailable"
            };
            let mut body = serde_json::json!({
                "status": status,
                "faucet": "online",
                "mode": "real",
                "faucet_balance": faucet_balance.to_string(),
                "faucet_native_balance": faucet_native_balance.to_string(),
                "token_drips_available": token_ready,
                "native_drips_available": native_ready,
            });
            if !token_ready {
                body["warning"] = serde_json::json!(
                    "Faucet wallet has insufficient tCREG; run testnet/fund-sepolia-faucet-governance.ps1 on Sepolia"
                );
            }
            if !native_ready {
                body["warning_native"] =
                    serde_json::json!("Faucet wallet has insufficient Sepolia ETH for gas drips");
            }
            (status_code, JsonResponse(body))
        }
        (token_result, native_result) => (
            StatusCode::SERVICE_UNAVAILABLE,
            JsonResponse(serde_json::json!({
                "status": "degraded",
                "faucet": "offline",
                "mode": "real",
                "error": format!(
                    "token={}, native={}",
                    token_result.err().unwrap_or_else(|| "ok".to_string()),
                    native_result.err().unwrap_or_else(|| "ok".to_string())
                ),
            })),
        ),
    }
}

// ── Admin endpoints ───────────────────────────────────────────────────────────

/// Verify the `Authorization: Bearer <token>` header against `FAUCET_ADMIN_TOKEN`.
/// Returns `Err((status, json))` when authentication fails so handlers can
/// `return err` immediately.
fn check_admin_auth(
    headers: &HeaderMap,
) -> Result<(), (StatusCode, axum::response::Json<serde_json::Value>)> {
    let token = std::env::var("FAUCET_ADMIN_TOKEN").unwrap_or_default();
    if token.is_empty() {
        return Err((
            StatusCode::FORBIDDEN,
            axum::response::Json(serde_json::json!({
                "error": "Admin endpoints disabled — set FAUCET_ADMIN_TOKEN to enable them"
            })),
        ));
    }
    let provided = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if provided != format!("Bearer {}", token) {
        return Err((
            StatusCode::UNAUTHORIZED,
            axum::response::Json(serde_json::json!({"error": "Unauthorized"})),
        ));
    }
    Ok(())
}

/// `POST /admin/pause` — stop accepting new drip requests.
async fn admin_pause(State(state): State<Arc<AppState>>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(e) = check_admin_auth(&headers) {
        return e;
    }
    state.is_paused.store(true, Ordering::Relaxed);
    warn!("Faucet PAUSED by operator request");
    (
        StatusCode::OK,
        axum::response::Json(serde_json::json!({"status": "paused"})),
    )
}

/// `POST /admin/resume` — re-enable drip requests after a pause.
async fn admin_resume(State(state): State<Arc<AppState>>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(e) = check_admin_auth(&headers) {
        return e;
    }
    state.is_paused.store(false, Ordering::Relaxed);
    info!("Faucet RESUMED by operator request");
    (
        StatusCode::OK,
        axum::response::Json(serde_json::json!({"status": "running"})),
    )
}

/// `GET /admin/status` — live operational snapshot (address count, pause state, stats).
async fn admin_status(State(state): State<Arc<AppState>>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(e) = check_admin_auth(&headers) {
        return e;
    }
    let stats = state.stats.lock().await;
    (
        StatusCode::OK,
        axum::response::Json(serde_json::json!({
            "is_paused": state.is_paused.load(Ordering::Relaxed),
            "address_count": state.rate_limiter.address_count(),
            "total_drips": stats.total_drips,
            "total_distributed_wei": stats.total_distributed.to_string(),
            "total_native_distributed_wei": stats.total_native_distributed.to_string(),
        })),
    )
}

// Helper functions
fn env_string(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_u128(key: &str, default: u128) -> u128 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_u16(key: &str, default: u16) -> u16 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
