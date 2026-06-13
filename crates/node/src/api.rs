// crates/node/src/api.rs
// Axum REST API — all HTTP endpoints for the chain registry node.

use alloy::primitives::{keccak256, Address};
use axum::{
    body::Body,
    extract::{Extension, Path, Query, State},
    http::{header, HeaderName, HeaderValue, Method, Request, StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use common::{PackageStatus, PublishRequest, Transaction, ValidatorIdentity};
use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey as K256VerifyingKey};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::{
    cors::{Any, CorsLayer},
    limit::RequestBodyLimitLayer,
    trace::TraceLayer,
};

use crate::consensus_admission::{accept_peer_attestation, AdmissionAttestation, AttestationStore};
use crate::{
    events::{self, sse_handler, EventBus},
    finalized_tx::FinalizedTxSender,
    normalized_validator_key,
    openapi::ApiDoc,
    rate_limit::{rate_limit_middleware, RateLimiter},
    validator_registration_status_text, SharedState, ValidatorRegistrationStatus,
};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

pub(crate) use crate::package_admission::verify_publish_sig;

/// Query parameters for GET /v1/packages
#[derive(Deserialize)]
struct ListPackagesParams {
    offset: Option<usize>,
    limit: Option<usize>,
    ecosystem: Option<String>,
    status: Option<String>,
}

// ─── Router ───────────────────────────────────────────────────────────────────

pub fn router(
    state: SharedState,
    event_bus: EventBus,
    limiter: RateLimiter,
    admission_store: Arc<AttestationStore>,
    cors_config: crate::config::CorsConfig,
    tx_sender: FinalizedTxSender,
    p2p_handle: crate::p2p::P2PHandle,
) -> Router {
    let sse_bus = Arc::clone(&event_bus);
    let ws_bus = Arc::clone(&event_bus);

    Router::new()
        .merge(public_routes(Arc::clone(&sse_bus), Arc::clone(&ws_bus)))
        .merge(publisher_routes())
        .merge(validator_routes())
        .merge(operator_routes())
        .merge(internal_routes())
        .merge(legacy_routes(sse_bus, ws_bus))
        // OpenAPI spec + Swagger UI. SwaggerUi serves both /api-docs (HTML)
        // and /v1/openapi.json (the JSON the explorer's `gen-types` consumes).
        .merge(SwaggerUi::new("/api-docs").url("/v1/openapi.json", ApiDoc::openapi()))
        .fallback(api_fallback)
        .layer(TraceLayer::new_for_http())
        .layer(RequestBodyLimitLayer::new(50 * 1024 * 1024))
        .layer(axum::middleware::from_fn(rate_limit_middleware))
        .layer(axum::extract::Extension(limiter))
        .layer(axum::extract::Extension(admission_store))
        .layer(axum::extract::Extension(event_bus))
        .layer(axum::extract::Extension(tx_sender))
        .layer(axum::extract::Extension(p2p_handle))
        .layer(build_cors_layer(&cors_config))
        .with_state(state)
}

fn public_routes(sse_bus: EventBus, ws_bus: EventBus) -> Router<SharedState> {
    Router::new()
        .route("/v1/public/health", get(health))
        .route("/v1/public/chain/stats", get(chain_stats))
        .route("/v1/public/packages", get(list_packages))
        .route("/v1/public/packages/:canonical", get(get_package))
        .route("/v1/public/packages/:canonical/proof", get(get_proof))
        .route(
            "/v1/public/packages/:canonical/intelligence",
            get(get_package_intelligence),
        )
        .route("/v1/public/blocks", get(list_blocks_paginated))
        .route("/v1/public/blocks/:height", get(get_block_by_height))
        .route("/v1/public/blocks/hash/:hash", get(get_block_by_hash))
        .route("/v1/public/transactions/:canonical", get(get_transaction))
        .route("/v1/public/publishers/:pubkey", get(get_publisher))
        .route("/v1/public/addresses/:address", get(get_address))
        .route(
            "/v1/public/addresses/:address/transactions",
            get(get_address_transactions),
        )
        .route("/v1/public/validators/:address", get(get_validator_profile))
        .route("/v1/public/bridge/status", get(bridge_status))
        .route("/v1/public/bridge/anchors", get(bridge_anchors))
        .route("/v1/public/governance/proposals", get(governance_proposals))
        .route("/v1/public/reorgs", get(reorgs))
        .route("/v1/public/richlist", get(richlist))
        .route("/v1/public/search", get(search_handler))
        .route(
            "/v1/public/events",
            get({
                let bus = Arc::clone(&sse_bus);
                move |_: ()| async move { sse_handler(axum::extract::State(bus)).await }
            }),
        )
        .route(
            "/v1/public/ws",
            get(move |ws| {
                let bus = Arc::clone(&ws_bus);
                async move { events::ws_handler(ws, axum::extract::State(bus)).await }
            }),
        )
}

fn publisher_routes() -> Router<SharedState> {
    Router::new()
        .route("/v1/publisher/packages", post(submit_package))
        .route(
            "/v1/publisher/packages/:canonical/revoke",
            post(revoke_package),
        )
        .route("/v1/publisher/rotate-key", post(rotate_publisher_key))
}

fn validator_routes() -> Router<SharedState> {
    Router::new()
        .route("/v1/validator/register", post(register_validator_identity))
        .route(
            "/v1/validator/registrations",
            get(list_validator_registrations),
        )
        .route(
            "/v1/validator/registrations/:evm_address",
            delete(delete_validator_registration),
        )
        .route("/v1/validator/consensus/vote", post(receive_vote))
        .route("/v1/validator/consensus/state", get(consensus_state))
}

fn operator_routes() -> Router<SharedState> {
    Router::new()
        .route("/v1/operator/runtime/config", get(runtime_config))
        .route("/v1/operator/nodes", get(get_nodes))
        .route("/v1/operator/p2p/status", get(p2p_status))
        .route("/v1/operator/pending", get(list_pending))
        .route("/v1/operator/metrics/history", get(metrics_history))
        .route("/v1/operator/api-boundaries", get(api_boundaries))
        .route(
            "/v1/operator/packages/:canonical/intelligence/generate",
            post(generate_package_intelligence),
        )
        .layer(axum::middleware::from_fn(private_api_acl_middleware))
}

fn internal_routes() -> Router<SharedState> {
    Router::new()
        .route(
            "/v1/internal/blocks/announce",
            post(receive_block_announcement),
        )
        .route(
            "/v1/internal/consensus/admission-attestation",
            post(receive_admission_attestation),
        )
        .route("/v1/internal/appeals/:id/audit", post(submit_audit))
        .layer(axum::middleware::from_fn(private_api_acl_middleware))
}

fn legacy_routes(sse_bus: EventBus, ws_bus: EventBus) -> Router<SharedState> {
    legacy_public_routes(sse_bus, ws_bus).merge(legacy_private_routes())
}

fn legacy_public_routes(sse_bus: EventBus, ws_bus: EventBus) -> Router<SharedState> {
    Router::new()
        // Health & chain
        .route("/v1/health", get(health))
        .route("/health", get(health))
        .route("/metrics", get(prometheus_metrics))
        .route("/rpc", post(crate::json_rpc::handle))
        .route("/jsonrpc", post(crate::json_rpc::handle))
        .route("/v1/chain/stats", get(chain_stats))
        .route("/v1/validators/register", post(register_validator_identity))
        .route(
            "/v1/validators/registrations",
            get(list_validator_registrations),
        )
        .route(
            "/v1/validators/registrations/:evm_address",
            delete(delete_validator_registration),
        )
        .route("/v1/bridge/status", get(bridge_status))
        .route("/v1/bridge/anchors", get(bridge_anchors))
        .route("/v1/governance/proposals", get(governance_proposals))
        .route("/v1/reorgs", get(reorgs))
        .route("/v1/richlist", get(richlist))
        // Packages
        .route("/v1/packages/:canonical", get(get_package))
        .route("/v1/packages", get(list_packages).post(submit_package))
        .route("/v1/packages/:canonical/revoke", post(revoke_package))
        .route("/v1/packages/:canonical/proof", get(get_proof))
        .route(
            "/v1/packages/:canonical/intelligence",
            get(get_package_intelligence),
        )
        // Blocks
        .route("/v1/blocks", get(list_blocks_paginated))
        .route("/v1/blocks/:height", get(get_block_by_height))
        .route("/v1/blocks/hash/:hash", get(get_block_by_hash))
        // Transactions
        .route("/v1/transactions/:canonical", get(get_transaction))
        // Publishers
        .route("/v1/publishers/:pubkey", get(get_publisher))
        // Addresses
        .route("/v1/addresses/:address", get(get_address))
        .route(
            "/v1/addresses/:address/transactions",
            get(get_address_transactions),
        )
        // Validator detail
        .route("/v1/validators/:address", get(get_validator_profile))
        // Consensus
        .route("/v1/consensus/vote", post(receive_vote))
        .route("/v1/consensus/state", get(consensus_state))
        .route("/v1/publishers/rotate-key", post(rotate_publisher_key))
        // Search
        .route("/v1/search", get(search_handler))
        // Event streaming - SSE & Websockets
        .route(
            "/v1/events",
            get({
                let bus = Arc::clone(&sse_bus);
                move |_: ()| async move { sse_handler(axum::extract::State(bus)).await }
            }),
        )
        .route(
            "/v1/ws",
            get(move |ws| {
                let bus = Arc::clone(&ws_bus);
                async move { events::ws_handler(ws, axum::extract::State(bus)).await }
            }),
        )
}

fn legacy_private_routes() -> Router<SharedState> {
    Router::new()
        .route("/v1/runtime/config", get(runtime_config))
        .route("/v1/nodes", get(get_nodes))
        .route("/v1/p2p/status", get(p2p_status))
        .route("/v1/metrics/history", get(metrics_history))
        .route("/v1/pending", get(list_pending))
        .route("/v1/blocks/announce", post(receive_block_announcement))
        .route(
            "/v1/consensus/admission-attestation",
            post(receive_admission_attestation),
        )
        .route("/v1/appeals/:id/audit", post(submit_audit))
        .layer(axum::middleware::from_fn(private_api_acl_middleware))
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ApiRouteCategory {
    Public,
    Publisher,
    Validator,
    Operator,
    Internal,
    LegacyAlias,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ApiRouteSecurity {
    PublicRateLimited,
    PublisherSignatureStakeAdmission,
    ValidatorIdentityProof,
    ValidatorSignatureSetMembership,
    OperatorApiKeyAcl,
    InternalApiKeyAcl,
    LegacyMixed,
}

#[derive(Debug, Clone, Copy, Serialize)]
struct ApiRouteBoundary {
    path: &'static str,
    category: ApiRouteCategory,
    security: ApiRouteSecurity,
    note: &'static str,
}

const API_ROUTE_BOUNDARIES: &[ApiRouteBoundary] = &[
    ApiRouteBoundary {
        path: "/v1/public/*",
        category: ApiRouteCategory::Public,
        security: ApiRouteSecurity::PublicRateLimited,
        note: "Read-only client, explorer, wallet, and JSON-RPC-compatible query surface.",
    },
    ApiRouteBoundary {
        path: "/v1/publisher/*",
        category: ApiRouteCategory::Publisher,
        security: ApiRouteSecurity::PublisherSignatureStakeAdmission,
        note: "Package submission and publisher key lifecycle surface.",
    },
    ApiRouteBoundary {
        path: "/v1/validator/register",
        category: ApiRouteCategory::Validator,
        security: ApiRouteSecurity::ValidatorIdentityProof,
        note: "Validator identity registration requires EVM and Ed25519 ownership proofs.",
    },
    ApiRouteBoundary {
        path: "/v1/validator/consensus/*",
        category: ApiRouteCategory::Validator,
        security: ApiRouteSecurity::ValidatorSignatureSetMembership,
        note: "Consensus endpoints require validator signatures and active-set membership.",
    },
    ApiRouteBoundary {
        path: "/v1/operator/*",
        category: ApiRouteCategory::Operator,
        security: ApiRouteSecurity::OperatorApiKeyAcl,
        note: "Operational status and diagnostics; requires X-Operator-Key or Authorization bearer ACL.",
    },
    ApiRouteBoundary {
        path: "/v1/internal/*",
        category: ApiRouteCategory::Internal,
        security: ApiRouteSecurity::InternalApiKeyAcl,
        note: "Node-to-node or local integration paths; requires X-Operator-Key or Authorization bearer ACL.",
    },
    ApiRouteBoundary {
        path: "/v1/packages, /v1/blocks, /v1/validators, /v1/consensus",
        category: ApiRouteCategory::LegacyAlias,
        security: ApiRouteSecurity::LegacyMixed,
        note: "Backward-compatible aliases retain their existing endpoint-specific security while clients migrate to grouped paths.",
    },
];

fn build_cors_layer(cors_config: &crate::config::CorsConfig) -> CorsLayer {
    let methods: Vec<Method> = cors_config
        .allowed_methods
        .iter()
        .map(|method| Method::from_bytes(method.as_bytes()).expect("validated CORS method"))
        .collect();

    let layer = CorsLayer::new()
        .allow_methods(methods)
        .allow_headers([
            header::ACCEPT,
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::ORIGIN,
            HeaderName::from_static("x-operator-key"),
        ])
        .allow_credentials(cors_config.allow_credentials);

    match cors_config.allowed_origins.as_slice() {
        [] => layer,
        [origin] if origin == "*" => layer.allow_origin(Any),
        origins => {
            let values: Vec<HeaderValue> = origins
                .iter()
                .map(|origin| HeaderValue::from_str(origin).expect("validated CORS origin"))
                .collect();
            layer.allow_origin(values)
        }
    }
}

async fn receive_admission_attestation(
    State(state): State<SharedState>,
    axum::extract::Extension(store): axum::extract::Extension<Arc<AttestationStore>>,
    Json(att): Json<AdmissionAttestation>,
) -> Response {
    // Look up chain_id + staking_addr fresh so config changes are picked up.
    let (rpc_url, staking_addr_s) = {
        let s = state.read().await;
        (s.config.eth_rpc_url.clone(), s.config.staking_addr.clone())
    };
    if staking_addr_s.trim().is_empty()
        || staking_addr_s.eq_ignore_ascii_case("0x0000000000000000000000000000000000000000")
    {
        return bad_request("admission path disabled: staking address unconfigured");
    }

    let staking_addr = match staking_addr_s.parse::<alloy::primitives::Address>() {
        Ok(a) => a,
        Err(e) => return bad_request(format!("invalid staking address: {e}")),
    };

    let chain_id = {
        use alloy::providers::Provider;
        let provider = alloy::providers::ProviderBuilder::new().on_http(match rpc_url.parse() {
            Ok(u) => u,
            Err(e) => return bad_request(format!("invalid rpc url: {e}")),
        });
        match provider.get_chain_id().await {
            Ok(id) => id,
            Err(e) => return server_err(format!("chain_id lookup failed: {e}")),
        }
    };

    match accept_peer_attestation(&store, chain_id, staking_addr, att).await {
        Ok(fresh) => Json(serde_json::json!({ "accepted": true, "new": fresh })).into_response(),
        Err(e) => bad_request(format!("rejected: {e}")),
    }
}

fn bad_request(msg: impl Into<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse { error: msg.into() }),
    )
        .into_response()
}

async fn api_fallback(uri: Uri) -> Response {
    if uri.path().starts_with("/v1/") || uri.path() == "/metrics" || uri.path() == "/health" {
        return not_found(format!("No route for {}", uri.path()));
    }

    crate::explorer::static_handler(uri).await.into_response()
}

// ─── Response helpers ─────────────────────────────────────────────────────────

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

fn not_found(msg: impl Into<String>) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse { error: msg.into() }),
    )
        .into_response()
}

fn server_err(msg: impl Into<String>) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse { error: msg.into() }),
    )
        .into_response()
}

const OPERATOR_API_KEY_ENV: &str = "CREG_OPERATOR_API_KEY";
const OPERATOR_PUBKEY_ENV: &str = "CREG_OPERATOR_PUBKEY";
const OPERATOR_KEY_HEADER: &str = "x-operator-key";

async fn private_api_acl_middleware(req: Request<Body>, next: Next) -> Response {
    let Some(secret) = configured_operator_secret() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: format!(
                    "private API is locked; set {OPERATOR_API_KEY_ENV} before exposing operator or internal routes"
                ),
            }),
        )
            .into_response();
    };

    if private_api_authorized(req.headers(), &secret) {
        return next.run(req).await;
    }

    let mut response = (
        StatusCode::UNAUTHORIZED,
        Json(ErrorResponse {
            error: "private API credentials are missing or invalid".to_string(),
        }),
    )
        .into_response();
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"chain-registry-private-api\""),
    );
    response
}

fn configured_operator_secret() -> Option<String> {
    std::env::var(OPERATOR_API_KEY_ENV)
        .ok()
        .or_else(|| std::env::var(OPERATOR_PUBKEY_ENV).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn private_api_authorized(headers: &axum::http::HeaderMap, secret: &str) -> bool {
    let header_match = headers
        .get(OPERATOR_KEY_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(|value| constant_time_eq(value.trim(), secret))
        .unwrap_or(false);
    let bearer_match = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(|value| constant_time_eq(value.trim(), secret))
        .unwrap_or(false);

    header_match || bearer_match
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

// ─── Handlers ────────────────────────────────────────────────────────────────

async fn health(State(state): State<SharedState>) -> impl IntoResponse {
    // MAL-001: surface the sandbox engine so operators/monitoring can verify
    // public validators are not running with the dev bypass. Detection is
    // cached after the first call. Read-only nodes (observer pool) proxy the
    // validator fleet status from CREG_PEERS when they have no local engine.
    let s = state.read().await;
    let mut sandbox = validator::sandbox::engine_status().await;
    if !s.config.is_validator && sandbox.engine == "none" {
        if let Some(peer_sandbox) =
            validator::sandbox::fleet_sandbox_from_peers(&s.config.peers).await
        {
            sandbox = peer_sandbox;
        }
    }
    Json(serde_json::json!({
        "status":  "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "validator_set_sync": s.validator_set_sync.clone(),
        "sandbox": sandbox,
    }))
}

async fn api_boundaries() -> impl IntoResponse {
    Json(serde_json::json!({
        "version": 1,
        "preferred_prefixes": {
            "public": "/v1/public",
            "publisher": "/v1/publisher",
            "validator": "/v1/validator",
            "operator": "/v1/operator",
            "internal": "/v1/internal"
        },
        "legacy_aliases": "enabled",
        "private_route_auth": {
            "environment": OPERATOR_API_KEY_ENV,
            "compatibility_environment": OPERATOR_PUBKEY_ENV,
            "accepted_headers": ["X-Operator-Key", "Authorization: Bearer <token>"],
            "fail_closed": true
        },
        "routes": API_ROUTE_BOUNDARIES
    }))
}

#[derive(Serialize)]
struct ChainStatsResponse {
    #[serde(flatten)]
    chain: crate::chain_store::ChainStats,
    genesis_hash: Option<String>,
    validator_count: usize,
    active_validators: usize,
    total_stake: u64,
    total_stake_native: String,
    peer_count: usize,
    bridge_status: String,
    l1_block: u64,
    pending_tx_count: usize,
    publisher_count: usize,
    finalized_height: u64,
    finalization_lag: u64,
    validator_set_source: String,
    validator_set_sync_state: String,
    validator_set_last_finalized_source_block: Option<u64>,
}

async fn chain_stats(State(state): State<SharedState>) -> impl IntoResponse {
    let s = state.read().await;
    let validators = &s.validator_set.validators;
    let total_stake: u64 = validators.iter().map(|validator| validator.stake).sum();
    let active_count = validators.iter().filter(|v| v.status != "offline").count();
    let tip = s.chain.stats().tip_height;
    let finalized = s.bridge_status.last_finalized_eth_block;
    let genesis_hash = s
        .chain
        .get_block_by_height(0)
        .ok()
        .flatten()
        .map(|b| b.hash());
    Json(ChainStatsResponse {
        chain: s.chain.stats(),
        genesis_hash,
        validator_count: validators.len(),
        active_validators: active_count,
        total_stake,
        total_stake_native: total_stake.to_string(),
        peer_count: s.p2p_status.peers.len(),
        bridge_status: if s.bridge_status.bridge_sync_status.trim().is_empty() {
            "Unknown".to_string()
        } else {
            s.bridge_status.bridge_sync_status.clone()
        },
        l1_block: finalized,
        pending_tx_count: s.pending_pool.len(),
        publisher_count: s.publisher_index.publisher_count(),
        finalized_height: finalized,
        finalization_lag: tip.saturating_sub(finalized),
        validator_set_source: s.validator_set_sync.mode.clone(),
        validator_set_sync_state: s.validator_set_sync.state.clone(),
        validator_set_last_finalized_source_block: s.validator_set_sync.last_finalized_source_block,
    })
}

#[derive(Serialize)]
struct RuntimeConfigResponse {
    version: String,
    build: String,
    chain_id: String,
    network: String,
    profile: String,
    is_testnet: bool,
    registry_address: Option<String>,
    token_contract: Option<String>,
    staking_contract: Option<String>,
    cors_allowed_origins: Vec<String>,
    cors_allowed_methods: Vec<String>,
    cors_allow_credentials: bool,
    validator_registration_mode: String,
    validator_registration_note: String,
    validator_set_source: String,
    validator_set_sync_state: String,
    validator_set_last_finalized_source_block: Option<u64>,
    node_id: String,
    validator_pubkey: Option<String>,
    /// MAL-001: sandbox engine this validator will use ("nsjail", "gvisor",
    /// "docker", "dev-bypass", "none").
    sandbox_engine: String,
    /// MAL-001: true when CREG_DEV_SANDBOX=true is active. Must be false on
    /// public validator profiles.
    sandbox_dev_bypass: bool,
}

#[derive(Deserialize)]
struct RegisterValidatorIdentityRequest {
    evm_address: String,
    node_id: String,
    ed25519_pubkey: String,
    nonce: String,
    evm_signature: String,
    ed25519_signature: String,
    alias: Option<String>,
}

fn non_zero_address(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("0x0000000000000000000000000000000000000000")
    {
        None
    } else {
        Some(trimmed.to_string())
    }
}

async fn runtime_config(State(state): State<SharedState>) -> impl IntoResponse {
    let sandbox = validator::sandbox::engine_status().await;
    let s = state.read().await;
    let chain_id = if s.config.chain_id.is_empty() {
        if s.config.is_testnet {
            "creg-testnet-1".to_string()
        } else {
            "creg-mainnet-1".to_string()
        }
    } else {
        s.config.chain_id.clone()
    };
    let network = if s.config.is_testnet {
        "testnet"
    } else {
        "mainnet"
    };
    Json(RuntimeConfigResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        build: format!("v{}", env!("CARGO_PKG_VERSION")),
        chain_id,
        network: network.to_string(),
        profile: network.to_string(),
        is_testnet: s.config.is_testnet,
        registry_address: non_zero_address(&s.config.registry_addr),
        token_contract: non_zero_address(&s.config.token_addr),
        staking_contract: non_zero_address(&s.config.staking_addr),
        cors_allowed_origins: s.config.cors.allowed_origins.clone(),
        cors_allowed_methods: s.config.cors.allowed_methods.clone(),
        cors_allow_credentials: s.config.cors.allow_credentials,
        validator_registration_mode: "staking-plus-identity-sync".to_string(),
        validator_registration_note: "Stake on-chain, register your validator EVM address, node ID, and Ed25519 pubkey with /v1/validators/register, then wait for the chain-synced validator-set worker to observe your active membership before you participate in consensus.".to_string(),
        validator_set_source: s.validator_set_sync.mode.clone(),
        validator_set_sync_state: s.validator_set_sync.state.clone(),
        validator_set_last_finalized_source_block: s
            .validator_set_sync
            .last_finalized_source_block,
        node_id: s.config.node_id.clone(),
        validator_pubkey: s.config.validator_privkey.as_ref().and_then(|pk| {
            let raw = pk.strip_prefix("0x").unwrap_or(pk.as_str());
            if let Ok(bytes) = hex::decode(raw) {
                if let Ok(sk) = ed25519_dalek::SigningKey::try_from(bytes.as_slice()) {
                    return Some(hex::encode(sk.verifying_key().as_bytes()));
                }
            }
            None
        }),
        sandbox_engine: sandbox.engine,
        sandbox_dev_bypass: sandbox.dev_bypass,
    })
}

fn validate_evm_address(value: &str) -> Result<String, String> {
    value
        .trim()
        .parse::<alloy::primitives::Address>()
        .map(|address| address.to_string().to_ascii_lowercase())
        .map_err(|_| "EVM address must be a valid 0x-prefixed address".to_string())
}

fn validate_node_id(value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Err("node_id is required".to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

fn validate_ed25519_pubkey(value: &str) -> Result<String, String> {
    let trimmed = value.trim().trim_start_matches("0x").to_ascii_lowercase();
    match hex::decode(&trimmed) {
        Ok(bytes) if bytes.len() == 32 => Ok(trimmed),
        Ok(bytes) => Err(format!(
            "Ed25519 pubkey must be 32 bytes (64 hex chars), got {} bytes",
            bytes.len()
        )),
        Err(_) => Err("Ed25519 pubkey must be valid hex".to_string()),
    }
}

fn validate_registration_nonce(value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Err("nonce is required".to_string())
    } else if trimmed.len() > 128 {
        Err("nonce must be 128 characters or fewer".to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

fn node_chain_id(config: &crate::config::NodeConfig) -> String {
    if !config.chain_id.trim().is_empty() {
        config.chain_id.clone()
    } else if config.is_testnet {
        "creg-testnet-1".to_string()
    } else {
        "creg-mainnet-1".to_string()
    }
}

fn validator_identity_registration_message(
    chain_id: &str,
    evm_address: &str,
    node_id: &str,
    ed25519_pubkey: &str,
    nonce: &str,
) -> String {
    format!(
        "creg-validator-identity-v1\nchain_id:{chain_id}\nevm_address:{evm_address}\nnode_id:{node_id}\ned25519_pubkey:{ed25519_pubkey}\nnonce:{nonce}"
    )
}

fn parse_ecdsa_signature_bytes(signature_hex: &str) -> Result<[u8; 65], String> {
    let normalized = signature_hex.trim().trim_start_matches("0x");
    let decoded =
        hex::decode(normalized).map_err(|_| "EVM signature must be valid hex".to_string())?;
    if decoded.len() != 65 {
        return Err(format!(
            "EVM signature must be 65 bytes (130 hex chars), got {} bytes",
            decoded.len()
        ));
    }
    let mut bytes = [0u8; 65];
    bytes.copy_from_slice(&decoded);
    Ok(bytes)
}

fn normalize_recovery_id(v: u8) -> Result<RecoveryId, String> {
    let normalized = match v {
        0 | 1 => v,
        27 | 28 => v - 27,
        _ => return Err(format!("Unsupported EVM signature recovery id: {v}")),
    };
    RecoveryId::from_byte(normalized)
        .ok_or_else(|| format!("Invalid EVM signature recovery id: {normalized}"))
}

fn ethereum_personal_message_digest(message: &str) -> alloy::primitives::B256 {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.as_bytes().len());
    let mut bytes = Vec::with_capacity(prefix.len() + message.len());
    bytes.extend_from_slice(prefix.as_bytes());
    bytes.extend_from_slice(message.as_bytes());
    keccak256(bytes)
}

fn recover_evm_personal_signer(message: &str, signature_hex: &str) -> Result<String, String> {
    let digest = ethereum_personal_message_digest(message);
    let bytes = parse_ecdsa_signature_bytes(signature_hex)?;
    let recovery_id = normalize_recovery_id(bytes[64])?;
    let signature = K256Signature::try_from(&bytes[..64])
        .map_err(|error| format!("Invalid EVM signature: {error}"))?;
    let verifying_key =
        K256VerifyingKey::recover_from_prehash(digest.as_slice(), &signature, recovery_id)
            .map_err(|error| format!("Failed to recover EVM signer: {error}"))?;
    let uncompressed = verifying_key.to_encoded_point(false);
    let pubkey = uncompressed.as_bytes();
    let hashed = keccak256(&pubkey[1..]);
    Ok(Address::from_slice(&hashed.as_slice()[12..])
        .to_string()
        .to_ascii_lowercase())
}

fn verify_ed25519_identity_signature(
    message: &str,
    ed25519_pubkey: &str,
    signature_hex: &str,
) -> Result<(), String> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let pubkey_bytes =
        hex::decode(ed25519_pubkey).map_err(|_| "Ed25519 pubkey must be valid hex".to_string())?;
    let verifying_key = VerifyingKey::try_from(pubkey_bytes.as_slice())
        .map_err(|error| format!("Invalid Ed25519 pubkey: {error}"))?;

    let signature_bytes = hex::decode(signature_hex.trim().trim_start_matches("0x"))
        .map_err(|_| "Ed25519 identity signature must be valid hex".to_string())?;
    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|error| format!("Invalid Ed25519 identity signature: {error}"))?;

    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|error| format!("Invalid Ed25519 identity signature: {error}"))
}

fn verify_validator_identity_proofs(
    chain_id: &str,
    evm_address: &str,
    node_id: &str,
    ed25519_pubkey: &str,
    nonce: &str,
    evm_signature: &str,
    ed25519_signature: &str,
) -> Result<(), String> {
    let message = validator_identity_registration_message(
        chain_id,
        evm_address,
        node_id,
        ed25519_pubkey,
        nonce,
    );

    let recovered = recover_evm_personal_signer(&message, evm_signature)?;
    if recovered != evm_address {
        return Err(format!(
            "EVM signature recovered {recovered}, expected {evm_address}"
        ));
    }

    verify_ed25519_identity_signature(&message, ed25519_pubkey, ed25519_signature)
}

/// Validate, verify ownership proofs, and apply a validator identity
/// registration to local state (insert + reconcile). Shared by the HTTP
/// handler and the gossip-receive path so a registration is processed
/// identically no matter how it arrives, and every node re-verifies the
/// proofs itself (trustless propagation).
pub(crate) async fn apply_validator_registration(
    state: &SharedState,
    proof: &crate::validator_registry_gossip::RegistrationProof,
) -> Result<ValidatorRegistrationStatus, (StatusCode, String)> {
    let evm_address =
        validate_evm_address(&proof.evm_address).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let node_id = validate_node_id(&proof.node_id).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let ed25519_pubkey =
        validate_ed25519_pubkey(&proof.ed25519_pubkey).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let nonce =
        validate_registration_nonce(&proof.nonce).map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let chain_id = {
        let s = state.read().await;
        node_chain_id(&s.config)
    };

    verify_validator_identity_proofs(
        &chain_id,
        &evm_address,
        &node_id,
        &ed25519_pubkey,
        &nonce,
        &proof.evm_signature,
        &proof.ed25519_signature,
    )
    .map_err(|e| (StatusCode::UNAUTHORIZED, e))?;

    let normalized_key = normalized_validator_key(&evm_address);
    let alias = proof
        .alias
        .clone()
        .unwrap_or_else(|| node_id.clone())
        .trim()
        .to_string();

    {
        let mut s = state.write().await;

        if s.validator_registrations.iter().any(|(key, registration)| {
            *key != normalized_key
                && (registration.identity.node_id == node_id
                    || registration.identity.ed25519_pubkey == ed25519_pubkey)
        }) {
            return Err((
                StatusCode::CONFLICT,
                "node_id or Ed25519 pubkey is already registered to another wallet".to_string(),
            ));
        }

        let identity = ValidatorIdentity {
            evm_address,
            node_id,
            ed25519_pubkey,
        }
        .normalized();

        let mut registration = s
            .validator_registrations
            .remove(&normalized_key)
            .unwrap_or_else(|| ValidatorRegistrationStatus {
                reputation: 100,
                ..ValidatorRegistrationStatus::default()
            });

        registration.alias = alias;
        registration.identity = identity;
        registration.registered_with_node = true;
        registration.status = validator_registration_status_text(&registration);

        let response = registration.clone();
        s.validator_registrations
            .insert(normalized_key, registration);
        drop(s);

        if let Err(error) =
            crate::validator_set_sync::reconcile_after_identity_registration(state.clone()).await
        {
            tracing::warn!(
                target: "validator_set_sync",
                "reconcile after identity registration failed: {error}"
            );
        }

        Ok(response)
    }
}

async fn register_validator_identity(
    State(state): State<SharedState>,
    Json(request): Json<RegisterValidatorIdentityRequest>,
) -> Response {
    let proof = crate::validator_registry_gossip::RegistrationProof {
        evm_address: request.evm_address,
        node_id: request.node_id,
        ed25519_pubkey: request.ed25519_pubkey,
        alias: request.alias,
        nonce: request.nonce,
        evm_signature: request.evm_signature,
        ed25519_signature: request.ed25519_signature,
    };

    match apply_validator_registration(&state, &proof).await {
        Ok(response) => {
            // Persist so the registration survives a restart, then gossip it so
            // the rest of the fleet converges from this single POST.
            let data_dir = {
                let s = state.read().await;
                s.config.data_dir.clone()
            };
            if let Err(e) = crate::validator_registry_gossip::persist(&data_dir, &proof) {
                tracing::warn!("Failed to persist validator registration: {}", e);
            }
            crate::validator_registry_gossip::broadcast(proof).await;
            (StatusCode::ACCEPTED, Json(response)).into_response()
        }
        Err((code, error)) => (code, Json(ErrorResponse { error })).into_response(),
    }
}

/// DELETE /v1/validators/registrations/:evm_address
///
/// Removes a stale validator-identity registration from this node's in-memory
/// table so the bound (node_id, ed25519_pubkey) pair is free to be reclaimed.
/// Useful when a different wallet previously claimed the same node_id and the
/// registration loop has not yet re-synced from on-chain state.
async fn delete_validator_registration(
    State(state): State<SharedState>,
    Path(evm_address): Path<String>,
) -> Response {
    let address = match validate_evm_address(&evm_address) {
        Ok(v) => v,
        Err(error) => {
            return (StatusCode::BAD_REQUEST, Json(ErrorResponse { error })).into_response();
        }
    };
    let key = normalized_validator_key(&address);

    let mut s = state.write().await;
    match s.validator_registrations.remove(&key) {
        Some(removed) => {
            // Evict the validator from the in-memory validator set so the
            // delete is immediately visible to `/v1/nodes` consumers.
            let identity = removed.identity.normalized();
            s.validator_set.validators.retain(|v| {
                v.id != identity.node_id
                    && v.pubkey != identity.ed25519_pubkey
                    && !v.eth_address.eq_ignore_ascii_case(&identity.evm_address)
            });
            Json(serde_json::json!({
                "removed": true,
                "evm_address": address,
                "node_id": removed.identity.node_id,
            }))
            .into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("no registration found for {address}"),
            }),
        )
            .into_response(),
    }
}

async fn list_validator_registrations(State(state): State<SharedState>) -> impl IntoResponse {
    let s = state.read().await;
    let mut registrations: Vec<ValidatorRegistrationStatus> =
        s.validator_registrations.values().cloned().collect();
    registrations.sort_by(|left, right| {
        left.alias
            .cmp(&right.alias)
            .then(left.identity.node_id.cmp(&right.identity.node_id))
    });
    Json(registrations)
}

// GET /v1/nodes
async fn get_nodes(State(state): State<SharedState>) -> impl IntoResponse {
    let s = state.read().await;
    let node_id = s.config.node_id.clone();

    // Convert current validator set to API response, marking "self" where appropriate.
    let mut resp = s.validator_set.validators.clone();
    for v in &mut resp {
        if v.id == node_id {
            v.status = "self".into();
        }
    }

    Json(resp)
}

// GET /v1/p2p/status
//
// Returns full peer topology when the `X-Operator-Key` header matches the
// node's configured operator pubkey (set via CREG_OPERATOR_PUBKEY env var).
// Public callers receive only aggregate counts to prevent network topology
// disclosure, which could aid targeted DDoS attacks on specific validators.
async fn p2p_status(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let s = state.read().await;

    // Operator key header allows full peer list exposure (e.g. for monitoring).
    let operator_pubkey = std::env::var("CREG_OPERATOR_PUBKEY").unwrap_or_default();
    let caller_key = headers
        .get("X-Operator-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let is_operator = !operator_pubkey.is_empty() && caller_key == operator_pubkey;

    if is_operator {
        // Full topology for authenticated operators.
        Json(serde_json::json!({
            "peer_count": s.p2p_status.peers.len(),
            "peers": s.p2p_status.peers,
            "protocols": s.p2p_status.protocols,
        }))
    } else {
        // Aggregate-only for public callers — include an empty `peers` array
        // so clients (web explorer) that access `p2pStatus.peers.length` don't
        // crash with "Cannot read properties of undefined".
        let empty_peers: Vec<String> = vec![];
        Json(serde_json::json!({
            "peer_count": s.p2p_status.peers.len(),
            "peers": empty_peers,
            "protocols": s.p2p_status.protocols,
        }))
    }
}

// GET /v1/bridge/status
async fn bridge_status(State(state): State<SharedState>) -> impl IntoResponse {
    let s = state.read().await;
    Json(s.bridge_status.clone())
}

// GET /v1/bridge/anchors
//
// Returns the persisted anchor commit journal (newest first) with real L1
// transaction hashes. Falls back to a synthesized entry from the live bridge
// status only when the journal is empty (e.g. node restarted mid-flight on
// a data dir written by an older build).
async fn bridge_anchors(State(state): State<SharedState>) -> impl IntoResponse {
    let s = state.read().await;

    let journal = crate::bridge_anchors::load(&s.config.data_dir);
    if !journal.is_empty() {
        let total = journal.len();
        return Json(serde_json::json!({
            "anchors": journal,
            "total": total,
            "proof_mode": "checkpoint-attestation",
        }));
    }

    let bs = &s.bridge_status;
    let mut anchors: Vec<serde_json::Value> = Vec::new();

    // Synthesise the latest anchor from current bridge state
    if bs.last_finalized_eth_block > 0 {
        anchors.push(serde_json::json!({
            "l2_height": s.chain.stats().tip_height,
            "l1_block": bs.last_finalized_eth_block,
            "state_root": bs.current_state_root,
            "l1_tx_hash": serde_json::Value::Null,
            "committed_at": chrono::Utc::now().to_rfc3339(),
            "gas_used": serde_json::Value::Null,
        }));
    }

    Json(serde_json::json!({
        "anchors": anchors,
        "total": anchors.len(),
    }))
}

// GET /v1/governance/proposals
//
// Governance is not yet implemented on-chain. This stub returns an empty
// list so the explorer page can render gracefully. When on-chain governance
// arrives (e.g. via a GovernanceProposal transaction variant), this handler
// will scan the chain for proposal transactions.
async fn governance_proposals(State(_state): State<SharedState>) -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({
            "error": "governance_not_enabled",
            "proposals": Vec::<serde_json::Value>::new(),
            "total": 0,
            "message": "On-chain governance is not enabled on this node. Set VITE_GOVERNANCE_ENABLED=true in the explorer when governance ships.",
        })),
    )
}

// GET /v1/metrics/history?range=1h
//
// Time-series metrics endpoint. Currently returns an empty sample set.
// When a metrics accumulator is added to the node, this will return
// historical chain stats at regular intervals.
#[derive(Deserialize)]
struct MetricsHistoryParams {
    #[serde(default = "default_metrics_range")]
    range: String,
}
fn default_metrics_range() -> String {
    "1h".to_string()
}

async fn metrics_history(
    State(_state): State<SharedState>,
    Query(params): Query<MetricsHistoryParams>,
) -> impl IntoResponse {
    Json(serde_json::json!({
        "range": params.range,
        "samples": Vec::<serde_json::Value>::new(),
        "note": "Server-side metrics accumulation is planned for Sprint 5.",
    }))
}

// GET /v1/packages?offset=0&limit=50&ecosystem=npm&status=verified
async fn list_packages(
    State(state): State<SharedState>,
    Query(params): Query<ListPackagesParams>,
) -> Response {
    let offset = params.offset.unwrap_or(0);
    let limit = params.limit.unwrap_or(50).min(200);
    let ecosystem = params.ecosystem.as_deref();
    let status_filter = params.status.as_deref().and_then(|s| match s {
        "verified" => Some(PackageStatus::Verified),
        "pending" => Some(PackageStatus::Pending),
        "revoked" => Some(PackageStatus::Revoked {
            reason: String::new(),
        }),
        _ => None,
    });

    let s = state.read().await;
    match s
        .chain
        .list_packages(offset, limit, ecosystem, status_filter.as_ref())
    {
        Ok((records, total)) => {
            #[derive(Serialize)]
            struct ListResp {
                packages: Vec<PackageSummary>,
                total: usize,
                offset: usize,
                limit: usize,
            }

            #[derive(Serialize)]
            struct PackageSummary {
                canonical: String,
                ecosystem: String,
                name: String,
                version: String,
                status: String,
                publisher: String,
                published_at: String,
                analysis_bundles: common::AnalysisBundleRefs,
                evidence_digest: String,
                deterministic_risk: common::DeterministicRiskSummary,
            }

            let packages: Vec<PackageSummary> = records
                .into_iter()
                .map(|r| PackageSummary {
                    canonical: r.id.canonical(),
                    ecosystem: r.id.ecosystem.clone(),
                    name: r.id.name.clone(),
                    version: r.id.version.clone(),
                    status: match &r.status {
                        PackageStatus::Verified => "verified".into(),
                        PackageStatus::Pending => "pending".into(),
                        PackageStatus::Revoked { .. } => "revoked".into(),
                    },
                    publisher: r.publisher_pubkey.clone(),
                    published_at: r.published_at.to_rfc3339(),
                    analysis_bundles: r.analysis_bundles.clone(),
                    evidence_digest: r.evidence_digest.clone(),
                    deterministic_risk: r.deterministic_risk.clone(),
                })
                .collect();

            Json(ListResp {
                packages,
                total,
                offset,
                limit,
            })
            .into_response()
        }
        Err(e) => server_err(format!("Failed to list packages: {}", e)),
    }
}

// GET /v1/packages/:canonical
async fn get_package(State(state): State<SharedState>, Path(canonical): Path<String>) -> Response {
    let canonical = urlencoding::decode(&canonical)
        .unwrap_or_default()
        .to_string();
    let s = state.read().await;

    // Check verified chain first.
    if let Ok(Some(record)) = s.chain.get_package(&canonical) {
        #[derive(Serialize)]
        struct PackageResp {
            canonical: String,
            status: &'static str,
            block_hash: Option<String>,
            content_hash: Option<String>,
            ipfs_cid: Option<String>,
            publisher: Option<String>,
            published_at: Option<String>,
            revocation_reason: Option<String>,
            analysis_bundles: Option<common::AnalysisBundleRefs>,
            evidence_digest: Option<String>,
            deterministic_risk: Option<common::DeterministicRiskSummary>,
        }
        let resp = PackageResp {
            canonical: record.id.canonical(),
            status: match &record.status {
                PackageStatus::Verified => "verified",
                PackageStatus::Revoked { .. } => "revoked",
                _ => "pending",
            },
            block_hash: Some(record.block_hash.clone()),
            content_hash: Some(record.content_hash.clone()),
            ipfs_cid: Some(record.ipfs_cid.clone()),
            publisher: Some(record.publisher_pubkey.clone()),
            published_at: Some(record.published_at.to_rfc3339()),
            revocation_reason: if let PackageStatus::Revoked { reason } = &record.status {
                Some(reason.clone())
            } else {
                None
            },
            analysis_bundles: Some(record.analysis_bundles.clone()),
            evidence_digest: Some(record.evidence_digest.clone()),
            deterministic_risk: Some(record.deterministic_risk.clone()),
        };
        return Json(resp).into_response();
    }

    // Check pending pool.
    if s.pending_pool.contains(&canonical) {
        return Json(serde_json::json!({
            "canonical": canonical,
            "status": "pending",
            "analysis_bundles": serde_json::Value::Null,
            "evidence_digest": serde_json::Value::Null,
            "deterministic_risk": serde_json::Value::Null
        }))
        .into_response();
    }

    not_found(format!("Package not found: {}", canonical))
}

// GET /v1/packages/:canonical/intelligence  (Lane C — non-binding deep analysis)
async fn get_package_intelligence(
    State(state): State<SharedState>,
    Path(canonical): Path<String>,
) -> Response {
    let canonical = urlencoding::decode(&canonical)
        .unwrap_or_default()
        .to_string();
    let s = state.read().await;
    let store = crate::intelligence::IntelligenceStore::new(&s.config.data_dir);

    if let Ok(Some(record)) = s.chain.get_package(&canonical) {
        let resp = store.response_for_package(&canonical, Some(&record.content_hash));
        return Json(resp).into_response();
    }

    Json(store.response_for_package(&canonical, None)).into_response()
}

// POST /v1/operator/packages/:canonical/intelligence/generate
async fn generate_package_intelligence(
    State(state): State<SharedState>,
    Path(canonical): Path<String>,
) -> Response {
    if !crate::intelligence::intelligence_enabled() {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "CREG_INTELLIGENCE_ENABLED is not set on this node"
            })),
        )
            .into_response();
    }

    let canonical = urlencoding::decode(&canonical)
        .unwrap_or_default()
        .to_string();
    let (record, data_dir, ipfs_url) = {
        let s = state.read().await;
        let Some(record) = s.chain.get_package(&canonical).ok().flatten() else {
            return not_found(format!("Package not found: {}", canonical));
        };
        let ipfs_url = if s.config.ipfs_url.is_empty() {
            None
        } else {
            Some(s.config.ipfs_url.clone())
        };
        (record, s.config.data_dir.clone(), ipfs_url)
    };

    match crate::intelligence::generate_and_store(&record, &data_dir, ipfs_url.as_deref()).await {
        Ok(report) => Json(serde_json::json!({
            "canonical": canonical,
            "status": report.status,
            "report": report,
        }))
        .into_response(),
        Err(error) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error.to_string() })),
        )
            .into_response(),
    }
}

// POST /v1/packages
async fn submit_package(
    State(state): State<SharedState>,
    Extension(p2p_handle): Extension<crate::p2p::P2PHandle>,
    Extension(event_bus): Extension<events::EventBus>,
    Json(request): Json<PublishRequest>,
) -> Response {
    let canonical = request.id.canonical();
    tracing::info!("Publish request: {}", canonical);

    let gossip_req = common::GossipMessage::PublishRequest(request.clone());
    let receipt = match crate::package_admission::admit_publish_request(
        &state,
        request.clone(),
        crate::package_admission::AdmissionOptions {
            surface: crate::package_admission::AdmissionSurface::Rest,
            verify_publisher_auth: true,
        },
    )
    .await
    {
        Ok(receipt) => receipt,
        Err(error) => return rest_admission_error(error),
    };

    // ── 3. Broadcast to P2P network ───────────────────────────────────────────
    let _ = p2p_handle
        .sender
        .send(crate::p2p::P2PCommand::Broadcast {
            topic: "creg/v1/submissions".into(),
            data: serde_json::to_vec(&gossip_req).unwrap_or_default(),
        })
        .await;
    tracing::info!(
        "{} added to pending pool ({} pending)",
        receipt.canonical,
        receipt.pending_count
    );

    events::emit(
        &event_bus,
        events::RegistryEvent::package_submitted(&receipt.canonical, &request.publisher_pubkey),
    );

    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "status":    "accepted",
            "canonical": receipt.canonical,
            "message":   "Package submitted. Validator pipeline will pick it up shortly."
        })),
    )
        .into_response()
}

fn rest_admission_error(error: crate::package_admission::AdmissionError) -> Response {
    use crate::package_admission::{AdmissionError, PublisherAdmissionError};
    tracing::error!("E2E DEBUG: Admission rejected: {:?}", error);

    let status = match &error {
        AdmissionError::InvalidPackageId(_)
        | AdmissionError::InvalidPublisherSignature(_)
        | AdmissionError::ShieldedPublishDisabled(_)
        | AdmissionError::Scanner(
            crate::admission_scan::AdmissionScanError::Rejected { .. }
            | crate::admission_scan::AdmissionScanError::ContentHashMismatch { .. },
        )
        | AdmissionError::Publisher(PublisherAdmissionError::InvalidAddress(_)) => {
            StatusCode::BAD_REQUEST
        }
        AdmissionError::Publisher(PublisherAdmissionError::Unstaked(_))
        | AdmissionError::Revoked(_) => StatusCode::FORBIDDEN,
        AdmissionError::Publisher(PublisherAdmissionError::Unavailable(_))
        | AdmissionError::Scanner(
            crate::admission_scan::AdmissionScanError::RulesUnavailable
            | crate::admission_scan::AdmissionScanError::IpfsFetch { .. }
            | crate::admission_scan::AdmissionScanError::ExtractionFailed { .. },
        ) => StatusCode::SERVICE_UNAVAILABLE,
        AdmissionError::Scanner(crate::admission_scan::AdmissionScanError::PayloadTooLarge {
            ..
        }) => StatusCode::PAYLOAD_TOO_LARGE,
        AdmissionError::AlreadyVerified(_) | AdmissionError::AlreadyPending(_) => {
            StatusCode::CONFLICT
        }
        AdmissionError::Storage(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };

    (
        status,
        Json(ErrorResponse {
            error: error.to_string(),
        }),
    )
        .into_response()
}

// POST /v1/packages/:canonical/revoke
//
// Security: the caller MUST be either a registered validator or the original
// publisher of the package.  They prove their identity by signing the message
// `"{canonical}:revoke:{reason}"` with their Ed25519 key.
#[derive(Deserialize)]
struct RevokeReq {
    reason: String,
    /// Hex-encoded Ed25519 public key of the revoker.
    revoker_pubkey: String,
    /// Hex-encoded Ed25519 signature of `"{canonical}:revoke:{reason}"`.
    signature: String,
}

async fn revoke_package(
    State(state): State<SharedState>,
    Extension(event_bus): Extension<EventBus>,
    Extension(tx_sender): Extension<FinalizedTxSender>,
    Path(canonical): Path<String>,
    Json(req): Json<RevokeReq>,
) -> Response {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let canonical = urlencoding::decode(&canonical)
        .unwrap_or_default()
        .to_string();

    // ── 1. Verify Ed25519 signature ───────────────────────────────────────────
    let sig_msg = format!("{}:revoke:{}", canonical, req.reason);
    let sig_valid: Result<(), _> = (|| {
        let pk_bytes = hex::decode(&req.revoker_pubkey)
            .map_err(|_| anyhow::anyhow!("revoker_pubkey is not valid hex"))?;
        let vk = VerifyingKey::try_from(pk_bytes.as_slice())
            .map_err(|_| anyhow::anyhow!("revoker_pubkey is not a valid Ed25519 key"))?;
        let sig_bytes = hex::decode(&req.signature)
            .map_err(|_| anyhow::anyhow!("signature is not valid hex"))?;
        let sig = Signature::try_from(sig_bytes.as_slice())
            .map_err(|_| anyhow::anyhow!("signature is not a valid Ed25519 signature"))?;
        vk.verify(sig_msg.as_bytes(), &sig)
            .map_err(|_| anyhow::anyhow!("Signature verification failed"))
    })();

    if let Err(e) = sig_valid {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: format!("Invalid revocation signature: {}", e),
            }),
        )
            .into_response();
    }

    let (is_authorised, package_record) = {
        let s = state.read().await;

        let is_validator = s
            .validator_set
            .validators
            .iter()
            .any(|v| v.pubkey == req.revoker_pubkey);
        let package_record = match s.chain.get_package(&canonical) {
            Ok(record) => record,
            Err(e) => return server_err(e.to_string()),
        };
        let is_publisher = package_record
            .as_ref()
            .map(|r| r.publisher_pubkey == req.revoker_pubkey)
            .unwrap_or(false);

        (is_validator || is_publisher, package_record)
    };

    if !is_authorised {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: format!(
                    "Revoker pubkey {} is not a registered validator or the original publisher of {}",
                    &req.revoker_pubkey[..req.revoker_pubkey.len().min(16)],
                    canonical
                ),
            }),
        )
            .into_response();
    }

    // ── 3. Queue the revocation transaction ───────────────────────────────────
    match package_record {
        Some(record) => {
            let tx = common::Transaction::Revoke {
                package_canonical: canonical.clone(),
                reason: req.reason.clone(),
                revoked_by: req.revoker_pubkey.clone(),
                evidence_hash: record.content_hash.clone(),
            };
            if tx_sender.send(tx).await.is_err() {
                return server_err("Finalized-tx channel closed".to_string());
            }
            tracing::info!(
                canonical = %canonical,
                revoker = %&req.revoker_pubkey[..req.revoker_pubkey.len().min(16)],
                reason = %req.reason,
                "Package revocation queued"
            );
            events::emit(
                &event_bus,
                events::RegistryEvent::package_revoked(
                    &canonical,
                    &req.reason,
                    &req.revoker_pubkey,
                ),
            );
            Json(serde_json::json!({
                "status": "queued",
                "message": "Revocation will be included in the next block",
                "revoked_by": req.revoker_pubkey,
            }))
            .into_response()
        }
        None => not_found(format!("Package not found: {}", canonical)),
    }
}

// GET /v1/packages/:canonical/proof  (light-client SPV proof)
async fn get_proof(State(state): State<SharedState>, Path(canonical): Path<String>) -> Response {
    let canonical = urlencoding::decode(&canonical)
        .unwrap_or_default()
        .to_string();
    let s = state.read().await;

    match crate::proof::build_proof(&canonical, &s.chain, &s.validator_set.validators) {
        Ok(Some(proof)) => Json(proof).into_response(),
        Ok(None) => not_found(format!("No proof available for: {}", canonical)),
        Err(e) => server_err(e.to_string()),
    }
}

/// Serialize a Block to JSON with top-level `hash` and `finalized` fields injected.
/// `Block` only stores `header` + `transactions`; the hash is computed on-the-fly
/// via `block.hash()`.  Clients (explorer, TUI) expect a `hash` field in the response.
///
/// Every block returned from the chain store is, by definition, finalized —
/// it was either the genesis block or survived PBFT consensus. We inject
/// `finalized: true` so the UI never labels stored blocks as "Pending".
fn block_to_json(b: &common::Block) -> serde_json::Value {
    let mut v = serde_json::to_value(b).unwrap_or_default();
    if let serde_json::Value::Object(ref mut map) = v {
        map.insert("hash".into(), serde_json::Value::String(b.hash()));
        map.insert("finalized".into(), serde_json::Value::Bool(true));
    }
    v
}

// GET /v1/blocks/:height
async fn get_block_by_height(
    State(state): State<SharedState>,
    Path(height): Path<u64>,
) -> Response {
    let s = state.read().await;
    match s.chain.get_block_by_height(height) {
        Ok(Some(b)) => Json(block_to_json(&b)).into_response(),
        Ok(None) => not_found(format!("No block at height {}", height)),
        Err(e) => server_err(e.to_string()),
    }
}

// GET /v1/blocks/hash/:hash
async fn get_block_by_hash(State(state): State<SharedState>, Path(hash): Path<String>) -> Response {
    let s = state.read().await;
    match s.chain.get_block_by_hash(&hash) {
        Ok(Some(b)) => Json(block_to_json(&b)).into_response(),
        Ok(None) => not_found(format!("No block with hash {}", hash)),
        Err(e) => server_err(e.to_string()),
    }
}

// GET /v1/blocks?offset=0&limit=20
//     /v1/blocks?before_height=H&limit=20  — cursor: heights < H
//     /v1/blocks?after_height=H&limit=20   — cursor: heights > H
//
// Returns blocks in descending height order (newest first).
// limit is capped at 100 to prevent large response payloads.
// Response includes X-Total-Height for UI pagination.
#[derive(Deserialize)]
struct ListBlocksParams {
    offset: Option<u64>,
    limit: Option<u64>,
    before_height: Option<u64>,
    after_height: Option<u64>,
}

async fn list_blocks_paginated(
    State(state): State<SharedState>,
    Query(params): Query<ListBlocksParams>,
) -> Response {
    let limit = params.limit.unwrap_or(20).min(100);

    let s = state.read().await;
    let tip = match s.chain.tip_height() {
        Ok(h) => h,
        Err(e) => return server_err(format!("Failed to read tip height: {}", e)),
    };

    // Cursor mode takes precedence over offset.
    let (offset, next_before, next_after) = if let Some(before) = params.before_height {
        // Blocks strictly below `before`, newest first → start at before-1.
        let start = before.saturating_sub(1);
        let computed_offset = tip.saturating_sub(start);
        let next_before = start.saturating_sub(limit.saturating_sub(1));
        (computed_offset, Some(next_before), None)
    } else if let Some(after) = params.after_height {
        // Blocks strictly above `after`, newest first → tip down to after+1.
        if after >= tip {
            (0, None, Some(after))
        } else {
            let window_top = tip.min(after.saturating_add(limit));
            let computed_offset = tip.saturating_sub(window_top);
            (computed_offset, None, Some(window_top))
        }
    } else {
        (params.offset.unwrap_or(0), None, None)
    };

    match s.chain.list_blocks(offset, limit) {
        Ok(blocks) => {
            let mut next_before_height = next_before;
            if next_before_height.is_none() && params.before_height.is_some() {
                next_before_height = blocks.last().map(|b| b.header.height);
            }

            let builder = axum::http::Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .header("X-Total-Height", tip.to_string())
                .header("X-Offset", offset.to_string())
                .header("X-Limit", limit.to_string());

            let blocks_with_hash: Vec<serde_json::Value> =
                blocks.iter().map(|b| block_to_json(b)).collect();
            let body = serde_json::json!({
                "blocks": blocks_with_hash,
                "tip_height": tip,
                "offset": offset,
                "limit": limit,
                "next_before_height": next_before_height,
                "next_after_height": next_after,
            });

            builder
                .body(axum::body::Body::from(
                    serde_json::to_vec(&body).unwrap_or_default(),
                ))
                .unwrap_or_else(|_| server_err("Response build error"))
        }
        Err(e) => server_err(format!("Failed to list blocks: {}", e)),
    }
}

// GET /v1/transactions/:canonical
//
// Searches on-chain blocks for a transaction matching the given canonical ID
// (e.g., "npm/express@4.18.0").  Returns the transaction plus the block height
// and hash it was included in.  Scans the most recent 200 blocks.
async fn get_transaction(
    State(state): State<SharedState>,
    Path(canonical): Path<String>,
) -> Response {
    let canonical = urlencoding::decode(&canonical)
        .unwrap_or_default()
        .to_string();
    let s = state.read().await;

    // Scan recent blocks for a matching transaction.
    let blocks = match s.chain.list_blocks(0, 200) {
        Ok(b) => b,
        Err(e) => return server_err(format!("Failed to read blocks: {}", e)),
    };

    for block in &blocks {
        for tx in &block.transactions {
            let tx_canonical = match tx {
                common::Transaction::Publish(record) => record.id.canonical(),
                common::Transaction::Revoke {
                    package_canonical, ..
                } => package_canonical.clone(),
                common::Transaction::Slash { validator_id, .. } => validator_id.clone(),
                common::Transaction::ValidatorJoin { validator_id, .. } => validator_id.clone(),
                common::Transaction::ValidatorLeave { validator_id } => validator_id.clone(),
                common::Transaction::RotatePublisherKey {
                    canonical_prefix, ..
                } => canonical_prefix.clone(),
            };

            if tx_canonical == canonical {
                return Json(serde_json::json!({
                    "transaction": tx,
                    "block_height": block.header.height,
                    "block_hash": block.hash(),
                }))
                .into_response();
            }
        }
    }

    not_found(format!("Transaction not found: {}", canonical))
}

// POST /v1/blocks/announce
//
// The proposer proves identity by signing `"{block_hash}:{height}"` with their
// Ed25519 key.  The key must belong to a registered validator.  This prevents
// anonymous nodes from injecting fake block announcements.
#[derive(Deserialize)]
struct BlockAnnounceReq {
    /// Height of the announced block.
    height: u64,
    /// Hex-encoded SHA-256 block hash.
    block_hash: String,
    /// Validator ID of the proposer.
    proposer: String,
    /// Hex-encoded Ed25519 public key of the proposer.
    proposer_pubkey: String,
    /// Hex-encoded Ed25519 signature of `"{block_hash}:{height}"`.
    signature: String,
}

async fn receive_block_announcement(
    State(state): State<SharedState>,
    Json(ann): Json<BlockAnnounceReq>,
) -> impl IntoResponse {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    // ── 1. Verify Ed25519 signature ───────────────────────────────────────────
    let sig_msg = format!("{}:{}", ann.block_hash, ann.height);
    let sig_valid: Result<(), _> = (|| {
        let pk_bytes = hex::decode(&ann.proposer_pubkey)
            .map_err(|_| anyhow::anyhow!("proposer_pubkey is not valid hex"))?;
        let vk = VerifyingKey::try_from(pk_bytes.as_slice())
            .map_err(|_| anyhow::anyhow!("proposer_pubkey is not a valid Ed25519 key"))?;
        let sig_bytes = hex::decode(&ann.signature)
            .map_err(|_| anyhow::anyhow!("signature is not valid hex"))?;
        let sig = Signature::try_from(sig_bytes.as_slice())
            .map_err(|_| anyhow::anyhow!("signature is not a valid Ed25519 signature"))?;
        vk.verify(sig_msg.as_bytes(), &sig)
            .map_err(|_| anyhow::anyhow!("Signature verification failed"))
    })();

    if let Err(e) = sig_valid {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": format!("Invalid proposer signature: {}", e) })),
        )
            .into_response();
    }

    // ── 2. Proposer must be a registered validator ────────────────────────────
    let s = state.read().await;
    let is_validator = s
        .validator_set
        .validators
        .iter()
        .any(|v| v.pubkey == ann.proposer_pubkey);

    if !is_validator {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": format!(
                    "Proposer pubkey {} is not a registered validator",
                    &ann.proposer_pubkey[..ann.proposer_pubkey.len().min(16)]
                )
            })),
        )
            .into_response();
    }

    tracing::debug!(
        proposer = %ann.proposer,
        height = ann.height,
        hash = %&ann.block_hash[..ann.block_hash.len().min(12)],
        "Block announcement accepted"
    );
    Json(serde_json::json!({ "status": "noted" })).into_response()
}

// GET /v1/publishers/:pubkey
async fn get_publisher(State(state): State<SharedState>, Path(pubkey): Path<String>) -> Response {
    let s = state.read().await;
    match s.publisher_index.get(&pubkey) {
        Some(stats) => Json(stats.clone()).into_response(),
        None => not_found(format!("Publisher not found: {}", pubkey)),
    }
}

// ─── Address endpoints ────────────────────────────────────────────────────────
//
// EVM addresses surface in multiple places: as validator evm_address, as block
// proposer_id, and as revoker_by in Revoke txs.  These handlers aggregate
// across those for per-address profile and transaction-history views.

const ADDRESS_DEFAULT_SCAN_BLOCKS: u64 = 500;
const ADDRESS_MAX_SCAN_BLOCKS: u64 = 5000;

fn is_evm_address_like(s: &str) -> bool {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    stripped.len() == 40 && stripped.chars().all(|c| c.is_ascii_hexdigit())
}

fn tx_kind_label(tx: &Transaction) -> &'static str {
    match tx {
        Transaction::Publish(_) => "publish",
        Transaction::Revoke { .. } => "revoke",
        Transaction::Slash { .. } => "slash",
        Transaction::ValidatorJoin { .. } => "validator-join",
        Transaction::ValidatorLeave { .. } => "validator-leave",
        Transaction::RotatePublisherKey { .. } => "rotate-key",
    }
}

fn tx_canonical(tx: &Transaction) -> Option<String> {
    match tx {
        Transaction::Publish(rec) => Some(rec.id.canonical()),
        Transaction::Revoke {
            package_canonical, ..
        } => Some(package_canonical.clone()),
        Transaction::RotatePublisherKey {
            canonical_prefix, ..
        } => Some(canonical_prefix.clone()),
        _ => None,
    }
}

/// True if the given tx references `addr` (case-insensitive) in any role.
fn tx_touches_address(tx: &Transaction, addr: &str) -> bool {
    match tx {
        Transaction::Revoke { revoked_by, .. } => revoked_by.to_ascii_lowercase() == addr,
        Transaction::Slash { validator_id, .. } => validator_id.to_ascii_lowercase() == addr,
        Transaction::ValidatorJoin { validator_id, .. } => {
            validator_id.to_ascii_lowercase() == addr
        }
        Transaction::ValidatorLeave { validator_id } => validator_id.to_ascii_lowercase() == addr,
        // Publish / RotatePublisherKey use ed25519 pubkeys, not EVM addresses — skip here.
        _ => false,
    }
}

// GET /v1/addresses/:address
async fn get_address(State(state): State<SharedState>, Path(address): Path<String>) -> Response {
    if !is_evm_address_like(&address) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Not a valid EVM address: {}", address),
            }),
        )
            .into_response();
    }
    let normalized = address.to_ascii_lowercase();
    let s = state.read().await;

    let registration = s
        .validator_registrations
        .get(&normalized)
        .cloned()
        .map(|r| serde_json::to_value(&r).unwrap_or(serde_json::Value::Null));

    let active = s
        .validator_set
        .validators
        .iter()
        .find(|v| v.eth_address.eq_ignore_ascii_case(&normalized))
        .cloned();

    let scan = ADDRESS_DEFAULT_SCAN_BLOCKS;
    let blocks = s.chain.list_blocks(0, scan).unwrap_or_default();
    let scanned_blocks = blocks.len() as u64;

    let mut blocks_proposed = 0u32;
    let mut tx_count = 0u32;
    for b in &blocks {
        if b.header.proposer_id.to_ascii_lowercase() == normalized {
            blocks_proposed += 1;
        }
        for tx in &b.transactions {
            if tx_touches_address(tx, &normalized) {
                tx_count += 1;
            }
        }
    }

    Json(serde_json::json!({
        "address": normalized,
        "is_validator": registration.is_some(),
        "is_active_validator": active.is_some(),
        "validator": registration,
        "active_status": active.as_ref().map(|v| v.status.clone()),
        "stake": active.as_ref().map(|v| v.stake.to_string()),
        "reputation": active.as_ref().map(|v| v.reputation),
        "blocks_proposed": blocks_proposed,
        "tx_count": tx_count,
        "scanned_blocks": scanned_blocks,
    }))
    .into_response()
}

// GET /v1/addresses/:address/transactions
#[derive(Deserialize)]
struct AddressTxParams {
    limit: Option<usize>,
    scan: Option<u64>,
}

async fn get_address_transactions(
    State(state): State<SharedState>,
    Path(address): Path<String>,
    Query(params): Query<AddressTxParams>,
) -> Response {
    if !is_evm_address_like(&address) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Not a valid EVM address: {}", address),
            }),
        )
            .into_response();
    }
    let normalized = address.to_ascii_lowercase();
    let limit = params.limit.unwrap_or(50).min(500);
    let scan = params
        .scan
        .unwrap_or(ADDRESS_DEFAULT_SCAN_BLOCKS)
        .min(ADDRESS_MAX_SCAN_BLOCKS);

    let s = state.read().await;
    let blocks = s.chain.list_blocks(0, scan).unwrap_or_default();
    let scanned_blocks = blocks.len() as u64;

    let mut results: Vec<serde_json::Value> = Vec::new();
    for b in &blocks {
        let block_hash = b.hash();
        let ts = b.header.timestamp.to_rfc3339();
        let proposer_match = b.header.proposer_id.to_ascii_lowercase() == normalized;
        if proposer_match {
            results.push(serde_json::json!({
                "block_height": b.header.height,
                "block_hash": block_hash,
                "tx_index": 0,
                "kind": "propose",
                "canonical": serde_json::Value::Null,
                "timestamp": ts,
            }));
        }
        for (idx, tx) in b.transactions.iter().enumerate() {
            if tx_touches_address(tx, &normalized) {
                results.push(serde_json::json!({
                    "block_height": b.header.height,
                    "block_hash": block_hash,
                    "tx_index": idx,
                    "kind": tx_kind_label(tx),
                    "canonical": tx_canonical(tx),
                    "timestamp": ts,
                }));
            }
        }
        if results.len() >= limit {
            break;
        }
    }
    results.truncate(limit);

    Json(serde_json::json!({
        "address": normalized,
        "transactions": results,
        "scanned_blocks": scanned_blocks,
        "total": results.len(),
    }))
    .into_response()
}

// GET /v1/validators/:address
async fn get_validator_profile(
    State(state): State<SharedState>,
    Path(address): Path<String>,
) -> Response {
    if !is_evm_address_like(&address) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Not a valid EVM address: {}", address),
            }),
        )
            .into_response();
    }
    let normalized = address.to_ascii_lowercase();
    let s = state.read().await;

    let registration = s.validator_registrations.get(&normalized).cloned();
    let active = s
        .validator_set
        .validators
        .iter()
        .find(|v| v.eth_address.eq_ignore_ascii_case(&normalized))
        .cloned();

    if registration.is_none() && active.is_none() {
        return not_found(format!("Validator not found: {}", address));
    }

    let (stake, reputation, status, in_active_set) = match active.as_ref() {
        Some(v) => (v.stake.to_string(), v.reputation, v.status.clone(), true),
        None => (
            registration
                .as_ref()
                .map(|r| r.stake.to_string())
                .unwrap_or_default(),
            registration.as_ref().map(|r| r.reputation).unwrap_or(0),
            registration
                .as_ref()
                .map(|r| r.status.clone())
                .unwrap_or_else(|| "unknown".to_string()),
            false,
        ),
    };

    let blocks = s.chain.list_blocks(0, 500).unwrap_or_default();
    let recent_proposals: Vec<serde_json::Value> = blocks
        .iter()
        .filter(|b| b.header.proposer_id.to_ascii_lowercase() == normalized)
        .take(25)
        .map(|b| block_to_json(b))
        .collect();

    Json(serde_json::json!({
        "address": normalized,
        "registration": registration,
        "in_active_set": in_active_set,
        "stake": stake,
        "reputation": reputation,
        "status": status,
        "recent_proposals": recent_proposals,
    }))
    .into_response()
}

// GET /v1/pending
async fn list_pending(State(state): State<SharedState>) -> impl IntoResponse {
    let s = state.read().await;
    Json(serde_json::json!({
        "count":    s.pending_pool.len(),
        "packages": s.pending_pool.all_canonicals()
    }))
}

// ─── Search endpoint ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct SearchParams {
    q: String,
}

#[derive(Serialize)]
struct SearchMatch {
    kind: &'static str,
    href: String,
    title: String,
    subtitle: String,
}

/// GET /v1/search?q=<query>
///
/// Smart-classifies the query string and returns matching entities:
///  - All digits → block by height
///  - 0x + 40 hex → EVM address (check validator set)
///  - 0x + 64 hex → try block by hash, then transaction
///  - Contains '@' → package canonical
///  - Otherwise → scan package names, validator aliases
async fn search_handler(
    State(state): State<SharedState>,
    Query(params): Query<SearchParams>,
) -> Response {
    let q = params.q.trim().to_string();
    if q.is_empty() {
        return Json(serde_json::json!({ "matches": Vec::<serde_json::Value>::new() }))
            .into_response();
    }

    let s = state.read().await;
    let mut matches: Vec<SearchMatch> = Vec::new();
    const MAX_RESULTS: usize = 10;

    // 1. All digits → block height
    if q.chars().all(|c| c.is_ascii_digit()) {
        if let Ok(height) = q.parse::<u64>() {
            if let Ok(Some(_)) = s.chain.get_block_by_height(height) {
                matches.push(SearchMatch {
                    kind: "block",
                    href: format!("/block/{}", height),
                    title: format!("Block #{}", height),
                    subtitle: "Block by height".into(),
                });
            }
        }
    }

    // 2. 0x + 40 hex → EVM address
    let stripped = q.strip_prefix("0x").unwrap_or(&q);
    if stripped.len() == 40 && stripped.chars().all(|c| c.is_ascii_hexdigit()) {
        let normalized = q.to_ascii_lowercase();
        matches.push(SearchMatch {
            kind: "address",
            href: format!("/address/{}", normalized),
            title: normalized.clone(),
            subtitle: "EVM address".into(),
        });
        // Check if it's a validator
        let clean = normalized
            .strip_prefix("0x")
            .unwrap_or(&normalized)
            .to_string();
        let is_validator = s.validator_registrations.contains_key(&normalized)
            || s.validator_registrations.contains_key(&clean)
            || s.validator_set
                .validators
                .iter()
                .any(|v| v.eth_address.eq_ignore_ascii_case(&normalized));
        if is_validator {
            matches.push(SearchMatch {
                kind: "validator",
                href: format!("/validator/{}", normalized),
                title: normalized.clone(),
                subtitle: "Validator".into(),
            });
        }
    }

    // 3. 0x + 64 hex → block hash or tx hash
    if stripped.len() == 64 && stripped.chars().all(|c| c.is_ascii_hexdigit()) {
        let hash_lower = q.to_ascii_lowercase();
        if let Ok(Some(block)) = s.chain.get_block_by_hash(&hash_lower) {
            matches.push(SearchMatch {
                kind: "block",
                href: format!("/block/{}", block.header.height),
                title: format!("Block #{}", block.header.height),
                subtitle: format!("hash: {}…", &hash_lower[..16]),
            });
        }
    }

    // 4. Contains '@' → package canonical
    if q.contains('@') && !q.starts_with("0x") {
        if let Ok(Some(record)) = s.chain.get_package(&q) {
            let status_str = match &record.status {
                PackageStatus::Verified => "verified",
                PackageStatus::Pending => "pending",
                PackageStatus::Revoked { .. } => "revoked",
            };
            matches.push(SearchMatch {
                kind: "package",
                href: format!("/package/{}", urlencoding::encode(&q)),
                title: record.id.canonical(),
                subtitle: format!("status: {}", status_str),
            });
        } else if s.pending_pool.contains(&q) {
            matches.push(SearchMatch {
                kind: "package",
                href: format!("/package/{}", urlencoding::encode(&q)),
                title: q.clone(),
                subtitle: "pending".into(),
            });
        }
    }

    // 5. Free text — search validator aliases and publisher index
    if matches.is_empty()
        || (!q.starts_with("0x") && !q.chars().all(|c| c.is_ascii_digit()) && !q.contains('@'))
    {
        let q_lower = q.to_ascii_lowercase();
        // Scan validator aliases
        for (key, reg) in s.validator_registrations.iter() {
            if matches.len() >= MAX_RESULTS {
                break;
            }
            if reg.alias.to_ascii_lowercase().contains(&q_lower) || key.contains(&q_lower) {
                let addr = key.clone();
                if !matches.iter().any(|m| m.href.contains(&addr)) {
                    matches.push(SearchMatch {
                        kind: "validator",
                        href: format!("/validator/{}", addr),
                        title: if reg.alias.is_empty() {
                            addr.clone()
                        } else {
                            reg.alias.clone()
                        },
                        subtitle: format!("validator: {}", addr),
                    });
                }
            }
        }
        // Scan publisher index
        for stats in s.publisher_index.all_stats() {
            if matches.len() >= MAX_RESULTS {
                break;
            }
            let pubkey = &stats.pubkey;
            if pubkey.to_ascii_lowercase().contains(&q_lower) {
                if !matches.iter().any(|m| m.href.contains(pubkey)) {
                    matches.push(SearchMatch {
                        kind: "publisher",
                        href: format!("/publisher/{}", urlencoding::encode(pubkey)),
                        title: pubkey.clone(),
                        subtitle: "publisher".into(),
                    });
                }
            }
        }
    }

    matches.truncate(MAX_RESULTS);
    Json(serde_json::json!({ "matches": matches })).into_response()
}

// POST /v1/publishers/rotate-key
#[derive(Deserialize)]
pub struct RotateKeyRequest {
    pub canonical_prefix: String,
    pub old_pubkey: String,
    pub new_pubkey: String,
    pub sig_from_old: String,
    pub sig_from_new: String,
    /// Monotonic nonce — must be strictly greater than the publisher's last
    /// rotation nonce.  Prevents replay of old rotation requests.
    #[serde(default)]
    pub nonce: u64,
}

async fn rotate_publisher_key(
    State(state): State<SharedState>,
    Extension(tx_sender): Extension<FinalizedTxSender>,
    Json(req): Json<RotateKeyRequest>,
) -> Response {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    // 1. Verify sig_from_old: old key signs new_pubkey
    let verify_sig = |pubkey_hex: &str, msg: &str, sig_hex: &str| -> anyhow::Result<()> {
        let pk_bytes = hex::decode(pubkey_hex)?;
        let sig_bytes = hex::decode(sig_hex)?;
        let vk = VerifyingKey::try_from(pk_bytes.as_slice())
            .map_err(|_| anyhow::anyhow!("bad pubkey"))?;
        let sig = Signature::try_from(sig_bytes.as_slice())
            .map_err(|_| anyhow::anyhow!("bad signature"))?;
        vk.verify(msg.as_bytes(), &sig)
            .map_err(|_| anyhow::anyhow!("signature verification failed"))
    };

    if let Err(e) = verify_sig(&req.old_pubkey, &req.new_pubkey, &req.sig_from_old) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid sig_from_old: {}", e),
            }),
        )
            .into_response();
    }
    if let Err(e) = verify_sig(&req.new_pubkey, &req.old_pubkey, &req.sig_from_new) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid sig_from_new: {}", e),
            }),
        )
            .into_response();
    }

    // 2. Replay protection: nonce must be strictly greater than the
    //    publisher's last rotation nonce, and timestamp must be recent.
    let now = chrono::Utc::now();
    {
        let s = state.read().await;
        let last_nonce = s
            .chain
            .publisher_rotation_nonce(&req.old_pubkey)
            .unwrap_or(0);
        if req.nonce <= last_nonce {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!(
                        "Rotation nonce {} must be > last nonce {}. Replay rejected.",
                        req.nonce, last_nonce
                    ),
                }),
            )
                .into_response();
        }

        // 2b. Time-lock: enforce a minimum cooldown between rotations to
        //     prevent rapid unauthorized rotation attacks.
        const ROTATION_COOLDOWN_SECS: i64 = 3600; // 1 hour
        if let Some(last_time) = s.chain.publisher_last_rotation_time(&req.old_pubkey) {
            let elapsed = now.signed_duration_since(last_time).num_seconds();
            if elapsed < ROTATION_COOLDOWN_SECS {
                let remaining = ROTATION_COOLDOWN_SECS - elapsed;
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(ErrorResponse {
                        error: format!(
                            "Key rotation cooldown: {} seconds remaining. Last rotation was {}s ago (minimum {}s).",
                            remaining, elapsed, ROTATION_COOLDOWN_SECS
                        ),
                    }),
                )
                    .into_response();
            }
        }
    }

    // 3. Verify old_pubkey owns at least one package matching the prefix.
    let has_match = state
        .read()
        .await
        .chain
        .has_publisher_for_prefix(&req.canonical_prefix, &req.old_pubkey);
    if !has_match {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: format!(
                    "old_pubkey does not own any package matching {}",
                    req.canonical_prefix
                ),
            }),
        )
            .into_response();
    }

    // 4. Queue the rotation transaction.
    let tx = common::Transaction::RotatePublisherKey {
        canonical_prefix: req.canonical_prefix.clone(),
        old_pubkey: req.old_pubkey.clone(),
        new_pubkey: req.new_pubkey.clone(),
        sig_from_old: req.sig_from_old.clone(),
        sig_from_new: req.sig_from_new.clone(),
        timestamp: now,
        nonce: req.nonce,
    };

    if tx_sender.send(tx).await.is_err() {
        return server_err("Finalized-tx channel closed".to_string());
    }

    Json(serde_json::json!({
        "status": "queued",
        "message": "Key rotation will be included in the next block"
    }))
    .into_response()
}

// GET /v1/consensus/state
//
// Returns a lightweight snapshot of the current PBFT consensus activity
// derived from the accumulated vote map and active validator set.  The TUI
// and web explorer use this to draw the PBFT gauge / consensus panel.
async fn consensus_state(State(state): State<SharedState>) -> impl IntoResponse {
    let s = state.read().await;

    let total_validators = s.validator_set.validators.len();
    // Standard BFT quorum: ⌊2n/3⌋ + 1
    let quorum = if total_validators == 0 {
        1
    } else {
        (2 * total_validators / 3) + 1
    };

    #[derive(Serialize)]
    struct VoteSummary {
        validator_id: String,
        decision: &'static str,
        reject_reason: Option<String>,
        ml_model_version: String,
        analysis_bundles: common::AnalysisBundleRefs,
        evidence_digest: String,
        deterministic_risk: common::DeterministicRiskSummary,
    }

    #[derive(Serialize)]
    struct RoundSummary {
        consensus_subject: String,
        vote_count: usize,
        approvals: usize,
        rejections: usize,
        phase: &'static str,
        /// Validator IDs that have cast a vote in this round.
        voters: Vec<String>,
        /// Subset of voters that cast Approve.
        approvers: Vec<String>,
        /// Subset of voters that cast Reject (with reason attached).
        rejecters: Vec<String>,
        votes: Vec<VoteSummary>,
        /// Milliseconds since the earliest vote in this round (round age).
        age_ms: i64,
    }

    let now = chrono::Utc::now();
    let mut active_rounds: Vec<RoundSummary> = s
        .package_rounds
        .iter()
        .map(|(consensus_subject, round)| {
            let mut approvers = Vec::new();
            let mut rejecters = Vec::new();
            let mut voters = Vec::with_capacity(round.vote_count());
            let mut votes = Vec::with_capacity(round.vote_count());
            for sig in round.signatures() {
                voters.push(sig.validator_id.clone());
                let (decision, reject_reason) = match &sig.vote {
                    common::ValidatorVote::Approve => {
                        approvers.push(sig.validator_id.clone());
                        ("approve", None)
                    }
                    common::ValidatorVote::Reject { reason } => {
                        rejecters.push(sig.validator_id.clone());
                        ("reject", Some(reason.clone()))
                    }
                };
                votes.push(VoteSummary {
                    validator_id: sig.validator_id.clone(),
                    decision,
                    reject_reason,
                    ml_model_version: sig.ml_model_version.clone(),
                    analysis_bundles: sig.analysis_bundles.clone(),
                    evidence_digest: sig.evidence_digest.clone(),
                    deterministic_risk: sig.deterministic_risk.clone(),
                });
            }
            let approvals = approvers.len();
            let rejections = rejecters.len();
            let phase = if approvals >= quorum {
                "quorum-reached"
            } else if rejections > 0 {
                "contested"
            } else {
                "collecting-votes"
            };
            let age_ms = now
                .signed_duration_since(round.first_vote_at.clone())
                .num_milliseconds();
            votes.sort_by(|left, right| left.validator_id.cmp(&right.validator_id));

            RoundSummary {
                consensus_subject: consensus_subject.clone(),
                vote_count: round.vote_count(),
                approvals,
                rejections,
                phase,
                voters,
                approvers,
                rejecters,
                votes,
                age_ms,
            }
        })
        .collect();

    // Sort descending by vote count so the most active round is first.
    active_rounds.sort_by(|a, b| b.vote_count.cmp(&a.vote_count));

    // Cap to the 10 most active rounds to keep the response bounded.
    active_rounds.truncate(10);

    #[derive(Serialize)]
    struct ValidatorSnapshot {
        id: String,
        alias: String,
        stake: u64,
        reputation: u32,
        status: String,
    }
    let validators: Vec<ValidatorSnapshot> = s
        .validator_set
        .validators
        .iter()
        .map(|v| ValidatorSnapshot {
            id: v.id.clone(),
            alias: v.alias.clone(),
            stake: v.stake,
            reputation: v.reputation,
            status: v.status.clone(),
        })
        .collect();

    Json(serde_json::json!({
        "total_validators": total_validators,
        "quorum": quorum,
        "active_rounds": active_rounds,
        "pending_count": s.pending_pool.len(),
        "validators": validators,
    }))
}

// POST /v1/consensus/vote
#[derive(Deserialize, Serialize)]
pub struct VoteMessage {
    /// Package-consensus subject identifier.
    ///
    /// Deserializes legacy `block_hash` payloads during the field rename.
    #[serde(alias = "block_hash")]
    pub consensus_subject: String,
    /// SHA-256 of the tarball bytes — bound into the signed message to prevent
    /// cross-version replay. Defaults to empty for backwards compatibility.
    #[serde(default)]
    pub content_hash: String,
    pub validator_id: String,
    pub phase: String,
    /// Hex-encoded Ed25519 signature of `gossip::canonical_vote_message(...)`.
    pub signature: String,
    /// Hex-encoded Ed25519 public key of the voting validator.
    pub validator_pubkey: String,
    /// ML model version used by this validator during deep scan.
    #[serde(default)]
    pub ml_model_version: String,
    /// Versioned analysis bundles active for this vote.
    #[serde(default)]
    pub analysis_bundles: common::AnalysisBundleRefs,
    /// Digest over deterministic evidence considered by the voting validator.
    #[serde(default)]
    pub evidence_digest: String,
    /// Compact deterministic risk summary captured when the vote was formed.
    #[serde(default)]
    pub deterministic_risk: common::DeterministicRiskSummary,
    pub approved: bool,
    pub reject_reason: Option<String>,
}

async fn receive_vote(
    State(state): State<SharedState>,
    Extension(event_bus): Extension<EventBus>,
    Json(vote): Json<VoteMessage>,
) -> Response {
    // ── Authenticate: verify the vote is from a known validator ──────────────
    {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let s = state.read().await;

        // 1. Check the claimed validator is in the active validator set
        //    AND that the supplied pubkey matches the registered pubkey.
        let validator = s
            .validator_set
            .validators
            .iter()
            .find(|v| v.id == vote.validator_id);
        let Some(validator) = validator else {
            return (
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: format!("Unknown validator: {}", vote.validator_id),
                }),
            )
                .into_response();
        };
        // Every validator must have a registered pubkey — reject if missing,
        // because an empty pubkey would allow unauthenticated vote submission.
        if validator.pubkey.is_empty() {
            return (
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: format!(
                        "Validator {} has no registered public key; \
                         vote authentication impossible",
                        vote.validator_id
                    ),
                }),
            )
                .into_response();
        }
        if vote.validator_pubkey != validator.pubkey {
            return (
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: format!(
                        "Validator pubkey mismatch for {}: expected {}, got {}",
                        vote.validator_id, validator.pubkey, vote.validator_pubkey
                    ),
                }),
            )
                .into_response();
        }

        if !common::is_consensus_grade_vote(
            &vote.ml_model_version,
            &vote.analysis_bundles,
            &vote.evidence_digest,
        ) {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Vote is missing consensus-grade scanner profile or evidence digest"
                        .into(),
                }),
            )
                .into_response();
        }

        // 2. Verify the Ed25519 signature.
        let pubkey_bytes = match hex::decode(&vote.validator_pubkey) {
            Ok(b) => b,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "Invalid validator_pubkey hex".into(),
                    }),
                )
                    .into_response()
            }
        };
        let vk = match VerifyingKey::try_from(pubkey_bytes.as_slice()) {
            Ok(k) => k,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "Invalid Ed25519 public key".into(),
                    }),
                )
                    .into_response()
            }
        };
        let sig_bytes = match hex::decode(&vote.signature) {
            Ok(b) => b,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "Invalid signature hex".into(),
                    }),
                )
                    .into_response()
            }
        };
        let sig = match Signature::try_from(sig_bytes.as_slice()) {
            Ok(s) => s,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "Invalid Ed25519 signature format".into(),
                    }),
                )
                    .into_response()
            }
        };

        // Canonical domain-separated vote message — must match exactly what
        // validator_pipeline.rs::gossip_sig produces via
        // gossip::canonical_vote_message.
        let msg = crate::gossip::canonical_vote_message(
            &vote.consensus_subject,
            &vote.content_hash,
            vote.approved,
            &vote.validator_pubkey,
            &common::scanner_profile_digest(&vote.ml_model_version, &vote.analysis_bundles),
            &vote.evidence_digest,
        );
        if vk.verify(msg.as_bytes(), &sig).is_err() {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Vote signature verification failed".into(),
                }),
            )
                .into_response();
        }
    }

    let mut s = state.write().await;

    let sig = common::ValidatorSignature {
        validator_id: vote.validator_id.clone(),
        validator_pubkey: vote.validator_pubkey.clone(),
        signature: vote.signature.clone(),
        vote: if vote.approved {
            common::ValidatorVote::Approve
        } else {
            common::ValidatorVote::Reject {
                reason: vote.reject_reason.clone().unwrap_or_default(),
            }
        },
        signed_at: chrono::Utc::now(),
        ml_model_version: vote.ml_model_version.clone(),
        analysis_bundles: vote.analysis_bundles.clone(),
        evidence_digest: vote.evidence_digest.clone(),
        deterministic_risk: vote.deterministic_risk.clone(),
    };

    s.record_package_vote(vote.consensus_subject.clone(), sig);

    events::emit(
        &event_bus,
        events::RegistryEvent::validator_voted(
            &vote.validator_id,
            &vote.consensus_subject,
            vote.approved,
        ),
    );

    Json(serde_json::json!({ "status": "accepted" })).into_response()
}

// ─── Appeals & AAA ───────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AuditSubmission {
    pub approved: bool,
    pub proof: String,
    pub rationales: Vec<validator::report::Rationale>,
}

async fn submit_audit(
    Path(id): Path<u64>,
    Json(audit): Json<AuditSubmission>,
) -> impl IntoResponse {
    tracing::info!(
        "Received AAA audit for appeal {}: approved={}",
        id,
        audit.approved
    );

    // In a production node, this would:
    // 1. Verify the AI model's signature/proof.
    // 2. Submit the submitAIVerdict() transaction to the Appeal.sol contract.
    // 3. Update the local chain store if the block producer picks it up.

    Json(serde_json::json!({
        "status":  "submitted",
        "message": "AI verdict received and queued for on-chain finalization."
    }))
}

// GET /metrics  (Prometheus text format)
async fn prometheus_metrics(State(state): State<SharedState>) -> impl IntoResponse {
    let body = crate::metrics::render(Arc::clone(&state)).await;
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        body,
    )
}

// ─── Sprint 5: Scale & Observability ──────────────────────────────────────────

/// GET /v1/reorgs — History of chain reorganizations
#[utoipa::path(
    get,
    path = "/v1/reorgs",
    tag = "Chain",
    responses(
        (status = 200, description = "Reorg history")
    )
)]
async fn reorgs(State(state): State<SharedState>) -> impl IntoResponse {
    let reorgs = state.read().await.reorgs.clone();
    Json(reorgs).into_response()
}

/// GET /v1/richlist — Top staked accounts
#[utoipa::path(
    get,
    path = "/v1/richlist",
    tag = "Diagnostics",
    responses(
        (status = 200, description = "Top accounts by stake")
    )
)]
async fn richlist(State(state): State<SharedState>) -> impl IntoResponse {
    let mut top: Vec<_> = state
        .read()
        .await
        .validator_registrations
        .values()
        .cloned()
        .collect();

    // Sort descending by stake
    top.sort_by(|a, b| b.stake.cmp(&a.stake));

    // Truncate to top 500
    top.truncate(500);

    Json(top).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus_admission::AttestationStore,
        events::new_event_bus,
        p2p::P2PHandle,
        pending_pool::PendingPool,
        publisher_index::PublisherIndex,
        rate_limit::{RateLimitConfig, RateLimiter},
        BridgeStatus, P2PStatus,
    };
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
        routing::post,
        Json, Router,
    };
    use common::proto::{registry_service_server::RegistryService, SubmitRequest};
    use common::{ChainRecord, PackageId, PackageManifest, PackageStatus};
    use ed25519_dalek::{Signer, SigningKey};
    use k256::ecdsa::SigningKey as K256SigningKey;
    use rand::rngs::OsRng;
    use serde_json::Value;
    use std::{collections::HashMap, sync::Arc};
    use tempfile::TempDir;
    use tokio::{
        net::TcpListener,
        sync::{mpsc, Mutex, RwLock},
    };
    use tonic::{Code, Request as GrpcRequest};
    use tower::ServiceExt;

    static API_ENV_LOCK: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();

    fn api_env_lock() -> &'static Mutex<()> {
        API_ENV_LOCK.get_or_init(|| Mutex::new(()))
    }

    struct EnvRestore {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvRestore {
        fn set(key: &'static str, value: impl AsRef<str>) -> Self {
            let previous = std::env::var(key).ok();
            std::env::set_var(key, value.as_ref());
            Self { key, previous }
        }

        fn remove(key: &'static str) -> Self {
            let previous = std::env::var(key).ok();
            std::env::remove_var(key);
            Self { key, previous }
        }
    }

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    fn make_keypair() -> (SigningKey, String) {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = hex::encode(sk.verifying_key().as_bytes());
        (sk, pk)
    }

    fn make_evm_keypair() -> (K256SigningKey, String) {
        let signing_key = K256SigningKey::random(&mut OsRng);
        let uncompressed = signing_key.verifying_key().to_encoded_point(false);
        let hashed = keccak256(&uncompressed.as_bytes()[1..]);
        let address = Address::from_slice(&hashed.as_slice()[12..])
            .to_string()
            .to_ascii_lowercase();
        (signing_key, address)
    }

    fn sign_evm_personal_message(signing_key: &K256SigningKey, message: &str) -> String {
        let digest = ethereum_personal_message_digest(message);
        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(digest.as_slice())
            .expect("test EVM signature should be produced");
        let mut bytes = [0u8; 65];
        bytes[..64].copy_from_slice(&signature.to_bytes());
        bytes[64] = recovery_id.to_byte() + 27;
        hex::encode(bytes)
    }

    fn identity_proof_request(
        chain_id: &str,
        evm_signing_key: &K256SigningKey,
        evm_address: &str,
        ed25519_signing_key: &SigningKey,
        ed25519_pubkey: &str,
    ) -> serde_json::Value {
        let node_id = "node-1";
        let nonce = "registration-test-nonce";
        let message = validator_identity_registration_message(
            chain_id,
            evm_address,
            node_id,
            ed25519_pubkey,
            nonce,
        );
        serde_json::json!({
            "evm_address": evm_address,
            "node_id": node_id,
            "ed25519_pubkey": ed25519_pubkey,
            "nonce": nonce,
            "evm_signature": sign_evm_personal_message(evm_signing_key, &message),
            "ed25519_signature": hex::encode(ed25519_signing_key.sign(message.as_bytes()).to_bytes()),
            "alias": "Node One",
        })
    }

    fn validator(id: &str, pubkey: &str) -> common::Validator {
        common::Validator {
            id: id.into(),
            alias: id.into(),
            pubkey: pubkey.into(),
            eth_address: String::new(),
            stake: 100,
            reputation: 100,
            status: "online".into(),
        }
    }

    fn make_vote_message(
        canonical: &str,
        content_hash: &str,
        validator_id: &str,
        signing_key: &SigningKey,
        validator_pubkey: &str,
        ml_model_version: &str,
        approved: bool,
    ) -> VoteMessage {
        let analysis_bundles = test_analysis_bundles();
        let evidence_digest = common::sha256_hex(
            format!("{canonical}:{content_hash}:{validator_id}:{ml_model_version}").as_bytes(),
        );
        let message = crate::gossip::canonical_vote_message(
            canonical,
            content_hash,
            approved,
            validator_pubkey,
            &common::scanner_profile_digest(ml_model_version, &analysis_bundles),
            &evidence_digest,
        );

        VoteMessage {
            consensus_subject: canonical.into(),
            content_hash: content_hash.into(),
            validator_id: validator_id.into(),
            phase: "commit".into(),
            signature: hex::encode(signing_key.sign(message.as_bytes()).to_bytes()),
            validator_pubkey: validator_pubkey.into(),
            ml_model_version: ml_model_version.into(),
            analysis_bundles,
            evidence_digest,
            deterministic_risk: common::DeterministicRiskSummary::default(),
            approved,
            reject_reason: None,
        }
    }

    fn test_analysis_bundles() -> common::AnalysisBundleRefs {
        common::AnalysisBundleRefs {
            policy_bundle_id: "policy-v1".into(),
            feature_schema_id: "features-v2".into(),
            expert_bundle_id: "experts-v3".into(),
            embedding_model_id: "embed-v1".into(),
            index_epoch: "2026-05-07".into(),
            threshold_profile_id: "thresholds-v1".into(),
            llm_prompt_profile_id: "prompt-v2".into(),
            osv_snapshot_epoch: "osv-off".into(),
        }
    }

    fn test_deterministic_risk() -> common::DeterministicRiskSummary {
        common::DeterministicRiskSummary {
            score: 67,
            deterministic_score: 67,
            advisory_score: 18,
            band: "elevated".into(),
            disposition: "review".into(),
            deterministic_findings: 2,
            advisory_findings: 1,
            critical_findings: 0,
            high_findings: 1,
            medium_findings: 1,
            low_findings: 0,
            reasons: vec!["[SA001] Suspicious install script".into()],
        }
    }

    fn make_request_with_sigs(
        publisher_pubkeys: Vec<String>,
        signatures: Vec<String>,
        threshold: usize,
    ) -> PublishRequest {
        PublishRequest {
            id: PackageId::new("npm", "test", "1.0.0"),
            content_hash: common::sha256_hex(b"test"),
            ipfs_cid: "bafytest".into(),
            publisher_address: "0x1111111111111111111111111111111111111111".into(),
            publisher_pubkey: publisher_pubkeys.first().cloned().unwrap_or_default(),
            signature: signatures.first().cloned().unwrap_or_default(),
            manifest: PackageManifest::default(),
            submitted_at: chrono::Utc::now(),
            shielded: false,
            key_bundle: None,
            pgp_signature: None,
            pgp_public_key: None,
            threshold,
            publisher_pubkeys,
            signatures,
        }
    }

    fn make_signed_request(publisher_address: &str) -> PublishRequest {
        let (sk, pk) = make_keypair();
        let mut req = make_request_with_sigs(vec![], vec![], 0);
        req.publisher_address = publisher_address.into();
        let msg =
            common::publish_signature_message(&req.id, &req.content_hash, &req.publisher_address);
        let sig = sk.sign(msg.as_bytes());
        req.publisher_pubkey = pk;
        req.signature = hex::encode(sig.to_bytes());
        req
    }

    async fn spawn_mock_staking_rpc(staked_balance: u64) -> String {
        async fn handle_rpc(Json(payload): Json<Value>, staked_result: String) -> Json<Value> {
            Json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": payload.get("id").cloned().unwrap_or_else(|| serde_json::json!(1)),
                "result": staked_result,
            }))
        }

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let staked_result = format!("0x{:064x}", staked_balance);
        let app = Router::new().route(
            "/",
            post({
                let staked_result = staked_result.clone();
                move |payload| handle_rpc(payload, staked_result.clone())
            }),
        );

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        format!("http://{}", addr)
    }

    async fn make_test_state(
        staked_balance: u64,
    ) -> anyhow::Result<(
        SharedState,
        TempDir,
        P2PHandle,
        FinalizedTxSender,
        crate::finalized_tx::FinalizedTxReceiver,
    )> {
        let rpc_url = spawn_mock_staking_rpc(staked_balance).await;
        let tempdir = tempfile::tempdir()?;
        let chain = crate::chain_store::ChainStore::open(tempdir.path())?;
        let (p2p_sender, _p2p_receiver) = mpsc::channel(4);
        let p2p_handle = P2PHandle { sender: p2p_sender };
        let (tx_sender, tx_receiver) = crate::finalized_tx::channel();

        let state = Arc::new(RwLock::new(crate::NodeState {
            chain,
            pending_pool: PendingPool::new(),
            publisher_index: PublisherIndex::new(),
            validator_set_bootstrap: common::ValidatorSet::default(),
            validator_set: common::ValidatorSet::default(),
            package_rounds: HashMap::new(),
            config: crate::config::NodeConfig {
                data_dir: tempdir.path().to_path_buf(),
                eth_rpc_url: rpc_url,
                staking_addr: "0x1000000000000000000000000000000000000001".into(),
                ..Default::default()
            },
            p2p_status: P2PStatus::default(),
            bridge_status: BridgeStatus::default(),
            vrf_proofs: HashMap::new(),
            decryption_shares: HashMap::new(),
            validator_registrations: HashMap::new(),
            validator_set_sync: crate::state::ValidatorSetSyncStatus::default(),
            view_change_certs: HashMap::new(),
            reorgs: Vec::new(),
            pbft_engine: crate::state::PbftEngine::new(),
        }));

        Ok((state, tempdir, p2p_handle, tx_sender, tx_receiver))
    }

    fn make_submit_request(req: &PublishRequest) -> SubmitRequest {
        let manifest_json = serde_json::to_string(&req.manifest).unwrap();
        let manifest_hash = common::sha256_hex(manifest_json.as_bytes());
        SubmitRequest {
            ecosystem: req.id.ecosystem.clone(),
            name: req.id.name.clone(),
            version: req.id.version.clone(),
            content_hash: req.content_hash.clone(),
            ipfs_cid: req.ipfs_cid.clone(),
            publisher_address: req.publisher_address.clone(),
            publisher_pubkey: req.publisher_pubkey.clone(),
            signature: req.signature.clone(),
            publisher_attestation_proof: vec![1u8],
            claimed_static_analysis_score: 0,
            claimed_sandbox_safe: false,
            publisher_pubkeys: req.publisher_pubkeys.clone(),
            signatures: req.signatures.clone(),
            threshold: req.threshold as u32,
            manifest_json,
            manifest_hash,
        }
    }

    #[test]
    fn single_sig_verifies() {
        let (sk, pk) = make_keypair();
        let req = make_request_with_sigs(vec![], vec![], 0);
        let msg =
            common::publish_signature_message(&req.id, &req.content_hash, &req.publisher_address);
        let sig = sk.sign(msg.as_bytes());

        let req = PublishRequest {
            publisher_pubkey: pk,
            signature: hex::encode(sig.to_bytes()),
            ..req
        };
        assert!(verify_publish_sig(&req).is_ok());
    }

    #[test]
    fn single_sig_rejects_bad_signature() {
        let (_sk, pk) = make_keypair();
        let req = PublishRequest {
            publisher_pubkey: pk,
            signature: "deadbeef".repeat(8),
            ..make_request_with_sigs(vec![], vec![], 0)
        };
        assert!(verify_publish_sig(&req).is_err());
    }

    #[test]
    fn multisig_2_of_3_verifies() {
        let (sk1, pk1) = make_keypair();
        let (sk2, pk2) = make_keypair();
        let (_sk3, pk3) = make_keypair();

        let publisher_address = "0x1111111111111111111111111111111111111111";

        let msg = common::publish_signature_message(
            &PackageId::new("npm", "test", "1.0.0"),
            &common::sha256_hex(b"test"),
            publisher_address,
        );
        let sig1 = sk1.sign(msg.as_bytes());
        let sig2 = sk2.sign(msg.as_bytes());

        let mut req = make_request_with_sigs(
            vec![pk1.clone(), pk2.clone(), pk3.clone()],
            vec![
                hex::encode(sig1.to_bytes()),
                hex::encode(sig2.to_bytes()),
                String::new(),
            ],
            2,
        );
        req.publisher_address = publisher_address.into();
        assert!(verify_publish_sig(&req).is_ok());
    }

    #[test]
    fn multisig_rejects_insufficient_sigs() {
        let (sk1, pk1) = make_keypair();
        let (_sk2, pk2) = make_keypair();
        let (_sk3, pk3) = make_keypair();

        let publisher_address = "0x1111111111111111111111111111111111111111";

        let msg = common::publish_signature_message(
            &PackageId::new("npm", "test", "1.0.0"),
            &common::sha256_hex(b"test"),
            publisher_address,
        );
        let sig1 = sk1.sign(msg.as_bytes());

        let mut req = make_request_with_sigs(
            vec![pk1.clone(), pk2.clone(), pk3.clone()],
            vec![hex::encode(sig1.to_bytes()), String::new(), String::new()],
            2,
        );
        req.publisher_address = publisher_address.into();
        assert!(verify_publish_sig(&req).is_err());
    }

    #[test]
    fn multisig_3_of_3_verifies() {
        let (sk1, pk1) = make_keypair();
        let (sk2, pk2) = make_keypair();
        let (sk3, pk3) = make_keypair();

        let publisher_address = "0x1111111111111111111111111111111111111111";

        let msg = common::publish_signature_message(
            &PackageId::new("npm", "test", "1.0.0"),
            &common::sha256_hex(b"test"),
            publisher_address,
        );
        let sig1 = sk1.sign(msg.as_bytes());
        let sig2 = sk2.sign(msg.as_bytes());
        let sig3 = sk3.sign(msg.as_bytes());

        let mut req = make_request_with_sigs(
            vec![pk1.clone(), pk2.clone(), pk3.clone()],
            vec![
                hex::encode(sig1.to_bytes()),
                hex::encode(sig2.to_bytes()),
                hex::encode(sig3.to_bytes()),
            ],
            3,
        );
        req.publisher_address = publisher_address.into();
        assert!(verify_publish_sig(&req).is_ok());
    }

    #[test]
    fn multisig_rejects_mismatched_counts() {
        let req = make_request_with_sigs(vec!["aa".into(), "bb".into()], vec!["cc".into()], 2);
        assert!(verify_publish_sig(&req).is_err());
    }

    #[test]
    fn validator_identity_registration_accepts_dual_ownership_proofs() {
        let (evm_key, evm_address) = make_evm_keypair();
        let (ed_key, ed_pubkey) = make_keypair();
        let message = validator_identity_registration_message(
            "creg-testnet-1",
            &evm_address,
            "node-1",
            &ed_pubkey,
            "nonce-1",
        );
        let evm_signature = sign_evm_personal_message(&evm_key, &message);
        let ed25519_signature = hex::encode(ed_key.sign(message.as_bytes()).to_bytes());

        assert!(verify_validator_identity_proofs(
            "creg-testnet-1",
            &evm_address,
            "node-1",
            &ed_pubkey,
            "nonce-1",
            &evm_signature,
            &ed25519_signature,
        )
        .is_ok());
    }

    #[test]
    fn validator_identity_registration_rejects_wrong_evm_signer() {
        let (_evm_key, evm_address) = make_evm_keypair();
        let (attacker_key, _) = make_evm_keypair();
        let (ed_key, ed_pubkey) = make_keypair();
        let message = validator_identity_registration_message(
            "creg-testnet-1",
            &evm_address,
            "node-1",
            &ed_pubkey,
            "nonce-1",
        );
        let evm_signature = sign_evm_personal_message(&attacker_key, &message);
        let ed25519_signature = hex::encode(ed_key.sign(message.as_bytes()).to_bytes());

        assert!(verify_validator_identity_proofs(
            "creg-testnet-1",
            &evm_address,
            "node-1",
            &ed_pubkey,
            "nonce-1",
            &evm_signature,
            &ed25519_signature,
        )
        .is_err());
    }

    #[test]
    fn validator_identity_registration_rejects_wrong_ed25519_signer() {
        let (evm_key, evm_address) = make_evm_keypair();
        let (_ed_key, ed_pubkey) = make_keypair();
        let (attacker_ed_key, _) = make_keypair();
        let message = validator_identity_registration_message(
            "creg-testnet-1",
            &evm_address,
            "node-1",
            &ed_pubkey,
            "nonce-1",
        );
        let evm_signature = sign_evm_personal_message(&evm_key, &message);
        let ed25519_signature = hex::encode(attacker_ed_key.sign(message.as_bytes()).to_bytes());

        assert!(verify_validator_identity_proofs(
            "creg-testnet-1",
            &evm_address,
            "node-1",
            &ed_pubkey,
            "nonce-1",
            &evm_signature,
            &ed25519_signature,
        )
        .is_err());
    }

    #[tokio::test]
    async fn rest_register_validator_identity_requires_ownership_proofs() -> anyhow::Result<()> {
        let (state, _tempdir, p2p_handle, tx_sender, _tx_receiver) = make_test_state(0).await?;
        let chain_id = {
            let s = state.read().await;
            node_chain_id(&s.config)
        };
        let (evm_key, evm_address) = make_evm_keypair();
        let (ed_key, ed_pubkey) = make_keypair();
        let event_bus = new_event_bus();
        let app = router(
            state.clone(),
            event_bus,
            RateLimiter::new(RateLimitConfig::default()),
            AttestationStore::new(),
            crate::config::CorsConfig::default(),
            tx_sender,
            p2p_handle,
        );

        let valid_request =
            identity_proof_request(&chain_id, &evm_key, &evm_address, &ed_key, &ed_pubkey);
        let response = app
            .clone()
            .oneshot(
                Request::post("/v1/validators/register")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&valid_request)?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert!(state
            .read()
            .await
            .validator_registrations
            .contains_key(&evm_address));

        let (attacker_key, _) = make_evm_keypair();
        let invalid_request =
            identity_proof_request(&chain_id, &attacker_key, &evm_address, &ed_key, &ed_pubkey);
        let response = app
            .oneshot(
                Request::post("/v1/validators/register")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&invalid_request)?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        Ok(())
    }

    #[tokio::test]
    async fn grouped_validator_register_alias_requires_ownership_proofs() -> anyhow::Result<()> {
        let (state, _tempdir, p2p_handle, tx_sender, _tx_receiver) = make_test_state(0).await?;
        let chain_id = {
            let s = state.read().await;
            node_chain_id(&s.config)
        };
        let (evm_key, evm_address) = make_evm_keypair();
        let (ed_key, ed_pubkey) = make_keypair();
        let event_bus = new_event_bus();
        let app = router(
            state.clone(),
            event_bus,
            RateLimiter::new(RateLimitConfig::default()),
            AttestationStore::new(),
            crate::config::CorsConfig::default(),
            tx_sender,
            p2p_handle,
        );

        let (attacker_key, _) = make_evm_keypair();
        let invalid_request =
            identity_proof_request(&chain_id, &attacker_key, &evm_address, &ed_key, &ed_pubkey);
        let response = app
            .clone()
            .oneshot(
                Request::post("/v1/validator/register")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&invalid_request)?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(!state
            .read()
            .await
            .validator_registrations
            .contains_key(&evm_address));

        let valid_request =
            identity_proof_request(&chain_id, &evm_key, &evm_address, &ed_key, &ed_pubkey);
        let response = app
            .oneshot(
                Request::post("/v1/validator/register")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&valid_request)?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert!(state
            .read()
            .await
            .validator_registrations
            .contains_key(&evm_address));

        Ok(())
    }

    #[tokio::test]
    async fn rest_submit_package_rejects_unstaked_publishers() -> anyhow::Result<()> {
        let (state, _tempdir, p2p_handle, tx_sender, _tx_receiver) = make_test_state(0).await?;
        let event_bus = new_event_bus();
        let app = router(
            state.clone(),
            event_bus,
            RateLimiter::new(RateLimitConfig::default()),
            AttestationStore::new(),
            crate::config::CorsConfig::default(),
            tx_sender,
            p2p_handle,
        );
        let request = make_signed_request("0x1111111111111111111111111111111111111111");
        let canonical = request.id.canonical();

        let response = app
            .oneshot(
                Request::post("/v1/packages")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&request)?))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        let body_text = String::from_utf8(body.to_vec())?;
        assert!(body_text.contains("has no on-chain stake"));
        assert!(!state.read().await.pending_pool.contains(&canonical));

        Ok(())
    }

    #[tokio::test]
    async fn grouped_publisher_packages_alias_uses_admission() -> anyhow::Result<()> {
        let (state, _tempdir, p2p_handle, tx_sender, _tx_receiver) = make_test_state(0).await?;
        let event_bus = new_event_bus();
        let app = router(
            state.clone(),
            event_bus,
            RateLimiter::new(RateLimitConfig::default()),
            AttestationStore::new(),
            crate::config::CorsConfig::default(),
            tx_sender,
            p2p_handle,
        );
        let request = make_signed_request("0x1111111111111111111111111111111111111111");
        let canonical = request.id.canonical();

        let response = app
            .oneshot(
                Request::post("/v1/publisher/packages")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&request)?))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        let body_text = String::from_utf8(body.to_vec())?;
        assert!(body_text.contains("has no on-chain stake"));
        assert!(!state.read().await.pending_pool.contains(&canonical));

        Ok(())
    }

    #[tokio::test]
    async fn rest_router_mounts_json_rpc_endpoint() -> anyhow::Result<()> {
        let (state, _tempdir, p2p_handle, tx_sender, _tx_receiver) = make_test_state(0).await?;
        let event_bus = new_event_bus();
        let app = router(
            state,
            event_bus,
            RateLimiter::new(RateLimitConfig::default()),
            AttestationStore::new(),
            crate::config::CorsConfig::default(),
            tx_sender,
            p2p_handle,
        );

        let response = app
            .oneshot(
                Request::post("/rpc")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&serde_json::json!({
                        "jsonrpc": "2.0",
                        "method": "creg_blockNumber",
                        "params": [],
                        "id": 1,
                    }))?))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        let body_json: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(body_json["result"], "0x0");
        assert_eq!(body_json["id"], 1);

        Ok(())
    }

    #[tokio::test]
    async fn rest_router_mounts_grouped_api_boundary_routes() -> anyhow::Result<()> {
        let _env_lock = api_env_lock().lock().await;
        let _api_key = EnvRestore::set(OPERATOR_API_KEY_ENV, "grouped-boundary-secret");
        let _operator_pubkey = EnvRestore::remove(OPERATOR_PUBKEY_ENV);
        let (state, _tempdir, p2p_handle, tx_sender, _tx_receiver) = make_test_state(0).await?;
        let event_bus = new_event_bus();
        let app = router(
            state,
            event_bus,
            RateLimiter::new(RateLimitConfig::default()),
            AttestationStore::new(),
            crate::config::CorsConfig::default(),
            tx_sender,
            p2p_handle,
        );

        let public_health = app
            .clone()
            .oneshot(Request::get("/v1/public/health").body(Body::empty())?)
            .await?;
        assert_eq!(public_health.status(), StatusCode::OK);

        let response = app
            .oneshot(
                Request::get("/v1/operator/api-boundaries")
                    .header(OPERATOR_KEY_HEADER, "grouped-boundary-secret")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        let body_json: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(body_json["preferred_prefixes"]["public"], "/v1/public");
        assert_eq!(
            body_json["preferred_prefixes"]["publisher"],
            "/v1/publisher"
        );
        assert_eq!(body_json["legacy_aliases"], "enabled");
        assert_eq!(body_json["private_route_auth"]["fail_closed"], true);
        assert!(body_json["routes"]
            .as_array()
            .map(|routes| routes.iter().any(|route| route["path"] == "/v1/internal/*"))
            .unwrap_or(false));

        Ok(())
    }

    #[tokio::test]
    async fn private_api_acl_fails_closed_without_operator_secret() -> anyhow::Result<()> {
        let _env_lock = api_env_lock().lock().await;
        let _api_key = EnvRestore::remove(OPERATOR_API_KEY_ENV);
        let _operator_pubkey = EnvRestore::remove(OPERATOR_PUBKEY_ENV);
        let (state, _tempdir, p2p_handle, tx_sender, _tx_receiver) = make_test_state(0).await?;
        let event_bus = new_event_bus();
        let app = router(
            state,
            event_bus,
            RateLimiter::new(RateLimitConfig::default()),
            AttestationStore::new(),
            crate::config::CorsConfig::default(),
            tx_sender,
            p2p_handle,
        );

        let response = app
            .oneshot(
                Request::get("/v1/operator/api-boundaries")
                    .header(OPERATOR_KEY_HEADER, "anything")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        let body_text = String::from_utf8(body.to_vec())?;
        assert!(body_text.contains(OPERATOR_API_KEY_ENV));

        Ok(())
    }

    #[tokio::test]
    async fn private_api_acl_protects_operator_and_internal_routes() -> anyhow::Result<()> {
        let _env_lock = api_env_lock().lock().await;
        let _api_key = EnvRestore::set(OPERATOR_API_KEY_ENV, "private-route-secret");
        let _operator_pubkey = EnvRestore::remove(OPERATOR_PUBKEY_ENV);
        let (state, _tempdir, p2p_handle, tx_sender, _tx_receiver) = make_test_state(0).await?;
        let event_bus = new_event_bus();
        let app = router(
            state,
            event_bus,
            RateLimiter::new(RateLimitConfig::default()),
            AttestationStore::new(),
            crate::config::CorsConfig::default(),
            tx_sender,
            p2p_handle,
        );

        let missing_operator_auth = app
            .clone()
            .oneshot(Request::get("/v1/operator/pending").body(Body::empty())?)
            .await?;
        assert_eq!(missing_operator_auth.status(), StatusCode::UNAUTHORIZED);

        let wrong_operator_auth = app
            .clone()
            .oneshot(
                Request::get("/v1/operator/pending")
                    .header(OPERATOR_KEY_HEADER, "wrong-secret")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(wrong_operator_auth.status(), StatusCode::UNAUTHORIZED);

        let authorized_operator = app
            .clone()
            .oneshot(
                Request::get("/v1/operator/pending")
                    .header(OPERATOR_KEY_HEADER, "private-route-secret")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(authorized_operator.status(), StatusCode::OK);

        let missing_internal_auth = app
            .clone()
            .oneshot(
                Request::post("/v1/internal/blocks/announce")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))?,
            )
            .await?;
        assert_eq!(missing_internal_auth.status(), StatusCode::UNAUTHORIZED);

        let authorized_internal_reaches_handler = app
            .oneshot(
                Request::post("/v1/internal/blocks/announce")
                    .header(header::AUTHORIZATION, "Bearer private-route-secret")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))?,
            )
            .await?;
        assert_ne!(
            authorized_internal_reaches_handler.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_ne!(
            authorized_internal_reaches_handler.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );

        Ok(())
    }

    #[tokio::test]
    async fn rest_revoke_package_queues_transaction_via_router_sender() -> anyhow::Result<()> {
        let (state, _tempdir, p2p_handle, tx_sender, tx_receiver) = make_test_state(0).await?;
        let (signing_key, publisher_pubkey) = make_keypair();
        let record = ChainRecord {
            id: PackageId::new("npm", "test", "1.0.0"),
            content_hash: common::sha256_hex(b"revocation-payload"),
            ipfs_cid: "bafyrevoketest".into(),
            publisher_pubkey: publisher_pubkey.clone(),
            block_hash: "0xabc123".into(),
            published_at: chrono::Utc::now(),
            status: PackageStatus::Verified,
            ..ChainRecord::default()
        };
        let canonical = record.id.canonical();
        {
            let s = state.read().await;
            s.chain.save_package(&record)?;
        }

        let reason = "malware detected".to_string();
        let signature = hex::encode(
            signing_key
                .sign(format!("{}:revoke:{}", canonical, reason).as_bytes())
                .to_bytes(),
        );
        let event_bus = new_event_bus();
        let app = router(
            state.clone(),
            event_bus,
            RateLimiter::new(RateLimitConfig::default()),
            AttestationStore::new(),
            crate::config::CorsConfig::default(),
            tx_sender,
            p2p_handle,
        );

        let response = app
            .oneshot(
                Request::post(format!(
                    "/v1/packages/{}/revoke",
                    urlencoding::encode(&canonical)
                ))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&serde_json::json!({
                    "reason": reason.clone(),
                    "revoker_pubkey": publisher_pubkey.clone(),
                    "signature": signature,
                }))?))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let queued_tx = tx_receiver
            .lock()
            .await
            .recv()
            .await
            .expect("revoke transaction should be queued");
        match queued_tx {
            Transaction::Revoke {
                package_canonical,
                reason: queued_reason,
                revoked_by,
                evidence_hash,
            } => {
                assert_eq!(package_canonical, canonical);
                assert_eq!(queued_reason, reason);
                assert_eq!(revoked_by, publisher_pubkey);
                assert_eq!(evidence_hash, record.content_hash);
            }
            other => panic!("expected revoke transaction, got {:?}", other),
        }

        Ok(())
    }

    #[tokio::test]
    async fn grpc_submit_package_rejects_unstaked_publishers() -> anyhow::Result<()> {
        let (state, _tempdir, _p2p_handle, _tx_sender, _tx_receiver) = make_test_state(0).await?;
        let service = crate::grpc::server::MyRegistry::new(
            state.clone(),
            Arc::new(zk_validator::ZkValidator::default()),
        );
        let publish_req = make_signed_request("0x1111111111111111111111111111111111111111");
        let canonical = publish_req.id.canonical();
        let result = service
            .submit_package(GrpcRequest::new(make_submit_request(&publish_req)))
            .await;

        let status = result.expect_err("unstaked publishers must be rejected");
        assert_eq!(status.code(), Code::PermissionDenied);
        assert!(status.message().contains("has no on-chain stake"));
        assert!(!state.read().await.pending_pool.contains(&canonical));

        Ok(())
    }

    #[tokio::test]
    async fn rest_receive_vote_preserves_ml_model_version() -> anyhow::Result<()> {
        let (state, _tempdir, p2p_handle, tx_sender, _tx_receiver) = make_test_state(0).await?;
        let (signing_key, validator_pubkey) = make_keypair();
        let canonical = "npm:test@1.0.0";
        let content_hash = common::sha256_hex(b"vote-payload");
        let ml_model_version = "creg-detect-v2.0.0";

        {
            let mut s = state.write().await;
            s.validator_set =
                common::ValidatorSet::new(vec![validator("node-1", &validator_pubkey)]);
        }

        let event_bus = new_event_bus();
        let app = router(
            state.clone(),
            event_bus,
            RateLimiter::new(RateLimitConfig::default()),
            AttestationStore::new(),
            crate::config::CorsConfig::default(),
            tx_sender,
            p2p_handle,
        );

        let vote = make_vote_message(
            canonical,
            &content_hash,
            "node-1",
            &signing_key,
            &validator_pubkey,
            ml_model_version,
            true,
        );

        let response = app
            .oneshot(
                Request::post("/v1/consensus/vote")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&vote)?))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);

        let s = state.read().await;
        let stored = s
            .package_round(canonical)
            .and_then(|round| round.signatures().first())
            .expect("vote should be stored");
        assert_eq!(stored.ml_model_version, ml_model_version);

        Ok(())
    }

    #[tokio::test]
    async fn rest_receive_vote_rejects_degraded_scanner_profile() -> anyhow::Result<()> {
        let (state, _tempdir, p2p_handle, tx_sender, _tx_receiver) = make_test_state(0).await?;
        let (signing_key, validator_pubkey) = make_keypair();
        let canonical = "npm:test@1.0.0";
        let content_hash = common::sha256_hex(b"vote-payload");

        {
            let mut s = state.write().await;
            s.validator_set =
                common::ValidatorSet::new(vec![validator("node-1", &validator_pubkey)]);
        }

        let event_bus = new_event_bus();
        let app = router(
            state.clone(),
            event_bus,
            RateLimiter::new(RateLimitConfig::default()),
            AttestationStore::new(),
            crate::config::CorsConfig::default(),
            tx_sender,
            p2p_handle,
        );

        let vote = make_vote_message(
            canonical,
            &content_hash,
            "node-1",
            &signing_key,
            &validator_pubkey,
            "degraded-no-model",
            true,
        );

        let response = app
            .oneshot(
                Request::post("/v1/consensus/vote")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&vote)?))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(state.read().await.package_round(canonical).is_none());

        Ok(())
    }

    #[tokio::test]
    async fn rest_receive_vote_replaces_duplicate_validator_entry_in_round() -> anyhow::Result<()> {
        let (state, _tempdir, p2p_handle, tx_sender, _tx_receiver) = make_test_state(0).await?;
        let (signing_key, validator_pubkey) = make_keypair();
        let canonical = "npm:test@1.0.0";
        let content_hash = common::sha256_hex(b"vote-payload");

        {
            let mut s = state.write().await;
            s.validator_set =
                common::ValidatorSet::new(vec![validator("node-1", &validator_pubkey)]);
        }

        let event_bus = new_event_bus();
        let app = router(
            state.clone(),
            event_bus,
            RateLimiter::new(RateLimitConfig::default()),
            AttestationStore::new(),
            crate::config::CorsConfig::default(),
            tx_sender,
            p2p_handle,
        );

        let approve_vote = make_vote_message(
            canonical,
            &content_hash,
            "node-1",
            &signing_key,
            &validator_pubkey,
            "creg-detect-v1.0.0",
            true,
        );
        let mut reject_vote = make_vote_message(
            canonical,
            &content_hash,
            "node-1",
            &signing_key,
            &validator_pubkey,
            "creg-detect-v2.0.0",
            false,
        );
        reject_vote.reject_reason = Some("malicious".to_string());

        for vote in [approve_vote, reject_vote] {
            let response = app
                .clone()
                .oneshot(
                    Request::post("/v1/consensus/vote")
                        .header("content-type", "application/json")
                        .body(Body::from(serde_json::to_vec(&vote)?))?,
                )
                .await?;

            assert_eq!(response.status(), StatusCode::OK);
        }

        let s = state.read().await;
        let round = s.package_round(canonical).expect("round should exist");
        assert_eq!(round.vote_count(), 1);
        let stored = round.signatures().first().expect("vote should be stored");
        assert_eq!(stored.ml_model_version, "creg-detect-v2.0.0");
        assert!(matches!(
            &stored.vote,
            common::ValidatorVote::Reject { reason } if reason == "malicious"
        ));

        Ok(())
    }

    #[tokio::test]
    async fn consensus_state_exposes_vote_metadata() -> anyhow::Result<()> {
        let (state, _tempdir, p2p_handle, tx_sender, _tx_receiver) = make_test_state(0).await?;
        let (_signing_key, validator_pubkey) = make_keypair();
        let bundles = test_analysis_bundles();
        let deterministic_risk = test_deterministic_risk();
        let canonical = "npm:test@1.0.0";

        {
            let mut s = state.write().await;
            s.validator_set =
                common::ValidatorSet::new(vec![validator("node-1", &validator_pubkey)]);
            s.record_package_vote(
                canonical,
                common::ValidatorSignature {
                    validator_id: "node-1".into(),
                    validator_pubkey,
                    signature: "vote-sig".into(),
                    vote: common::ValidatorVote::Approve,
                    signed_at: chrono::Utc::now(),
                    ml_model_version: "creg-detect-v1.0.0".into(),
                    analysis_bundles: bundles.clone(),
                    evidence_digest: "evidence-digest-1".into(),
                    deterministic_risk: deterministic_risk.clone(),
                },
            );
        }

        let event_bus = new_event_bus();
        let app = router(
            state,
            event_bus,
            RateLimiter::new(RateLimitConfig::default()),
            AttestationStore::new(),
            crate::config::CorsConfig::default(),
            tx_sender,
            p2p_handle,
        );

        let response = app
            .oneshot(Request::get("/v1/consensus/state").body(Body::empty())?)
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        let body_json: serde_json::Value = serde_json::from_slice(&body)?;
        let round = &body_json["active_rounds"][0];

        assert_eq!(round["consensus_subject"], canonical);
        assert_eq!(
            round["votes"][0]["analysis_bundles"]["policy_bundle_id"],
            bundles.policy_bundle_id
        );
        assert_eq!(round["votes"][0]["evidence_digest"], "evidence-digest-1");
        assert_eq!(
            round["votes"][0]["deterministic_risk"]["disposition"],
            deterministic_risk.disposition
        );

        Ok(())
    }

    #[tokio::test]
    async fn get_package_exposes_deterministic_risk_and_bundle_metadata() -> anyhow::Result<()> {
        let (state, _tempdir, p2p_handle, tx_sender, _tx_receiver) = make_test_state(0).await?;
        let (_signing_key, publisher_pubkey) = make_keypair();
        let bundles = test_analysis_bundles();
        let deterministic_risk = test_deterministic_risk();
        let record = ChainRecord {
            id: PackageId::new("npm", "test", "1.0.0"),
            content_hash: common::sha256_hex(b"package-detail"),
            ipfs_cid: "bafydetailmetadata".into(),
            publisher_pubkey,
            block_hash: "0xabc123".into(),
            published_at: chrono::Utc::now(),
            status: PackageStatus::Verified,
            analysis_bundles: bundles.clone(),
            evidence_digest: "detail-evidence-digest".into(),
            deterministic_risk: deterministic_risk.clone(),
            ..ChainRecord::default()
        };
        let canonical = record.id.canonical();

        {
            let s = state.read().await;
            s.chain.save_package(&record)?;
        }

        let event_bus = new_event_bus();
        let app = router(
            state,
            event_bus,
            RateLimiter::new(RateLimitConfig::default()),
            AttestationStore::new(),
            crate::config::CorsConfig::default(),
            tx_sender,
            p2p_handle,
        );

        let response = app
            .oneshot(
                Request::get(format!("/v1/packages/{}", urlencoding::encode(&canonical)))
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        let body_json: serde_json::Value = serde_json::from_slice(&body)?;

        assert_eq!(
            body_json["analysis_bundles"]["policy_bundle_id"],
            bundles.policy_bundle_id
        );
        assert_eq!(body_json["evidence_digest"], "detail-evidence-digest");
        assert_eq!(
            body_json["deterministic_risk"]["band"],
            deterministic_risk.band
        );
        assert_eq!(
            body_json["deterministic_risk"]["disposition"],
            deterministic_risk.disposition
        );

        Ok(())
    }

    #[tokio::test]
    async fn cors_defaults_block_cross_origin_preflight() -> anyhow::Result<()> {
        let (state, _tempdir, p2p_handle, tx_sender, _tx_receiver) = make_test_state(0).await?;
        let event_bus = new_event_bus();
        let app = router(
            state,
            event_bus,
            RateLimiter::new(RateLimitConfig::default()),
            AttestationStore::new(),
            crate::config::CorsConfig::default(),
            tx_sender,
            p2p_handle,
        );

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/v1/packages")
                    .header(header::ORIGIN, "http://localhost:4173")
                    .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                    .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "content-type")
                    .body(Body::empty())?,
            )
            .await?;

        assert!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none(),
            "default policy should not emit allow-origin for cross-origin requests"
        );

        Ok(())
    }

    #[tokio::test]
    async fn cors_allows_configured_origin_and_credentials() -> anyhow::Result<()> {
        let (state, _tempdir, p2p_handle, tx_sender, _tx_receiver) = make_test_state(0).await?;
        let event_bus = new_event_bus();
        let cors = crate::config::CorsConfig {
            allowed_origins: vec!["http://localhost:4173".into()],
            allowed_methods: vec![
                "GET".into(),
                "POST".into(),
                "DELETE".into(),
                "OPTIONS".into(),
            ],
            allow_credentials: true,
        };
        let app = router(
            state,
            event_bus,
            RateLimiter::new(RateLimitConfig::default()),
            AttestationStore::new(),
            cors,
            tx_sender,
            p2p_handle,
        );

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/v1/packages")
                    .header(header::ORIGIN, "http://localhost:4173")
                    .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                    .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "content-type")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|value| value.to_str().ok()),
            Some("http://localhost:4173")
        );
        assert_eq!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .and_then(|value| value.to_str().ok()),
            Some("true")
        );

        Ok(())
    }
}
