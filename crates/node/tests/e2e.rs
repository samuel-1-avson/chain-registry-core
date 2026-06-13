// crates/node/tests/e2e.rs
// End-to-end tests: spin up a real in-process node on a random port,
// submit a package, wait for it to be verified, and confirm via the API.

use axum::http::StatusCode;
use axum::{routing::post, Json, Router};
use chrono::Utc;
use common::{PackageId, PackageManifest, PublishRequest};
use serde_json::Value;
use std::{sync::Arc, time::Duration};
use tokio::net::TcpListener;
use tokio::{sync::RwLock, time::timeout};

fn make_tarball(path: &str, content: &str) -> Vec<u8> {
    let mut tar_bytes = Vec::new();
    {
        let encoder = flate2::write::GzEncoder::new(&mut tar_bytes, flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(content.as_bytes().len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(&mut header, path, content.as_bytes())
            .unwrap();
        archive.finish().unwrap();
        archive.into_inner().unwrap().finish().unwrap();
    }
    tar_bytes
}

async fn spawn_mock_staking_rpc(staked_balance: u64) -> String {
    async fn handle_rpc(Json(payload): Json<Value>, staked_result: String) -> Json<Value> {
        Json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": payload.get("id").cloned().unwrap_or_else(|| serde_json::json!(1)),
            "result": staked_result,
        }))
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
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

async fn spawn_mock_ipfs(payload: Vec<u8>, status: StatusCode) -> String {
    async fn handle_ipfs(
        payload: Vec<u8>,
        status: StatusCode,
    ) -> impl axum::response::IntoResponse {
        (status, payload)
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().route(
        "/api/v0/cat",
        post({
            let payload = payload.clone();
            move || handle_ipfs(payload.clone(), status)
        }),
    );

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    format!("http://{}", addr)
}

/// Helper: start a full node on a random port, return the base URL.
async fn start_test_node() -> (String, tokio::task::JoinHandle<()>) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error,node=debug,ml_validator=debug")
        .try_init();
    use node::{
        api,
        chain_store::ChainStore,
        config::NodeConfig,
        consensus_admission::AttestationStore,
        events::new_event_bus,
        finalized_tx,
        p2p::{P2PCommand, P2PHandle},
        pending_pool::PendingPool,
        publisher_index::PublisherIndex,
        rate_limit::{RateLimitConfig, RateLimiter},
        BridgeStatus, NodeState, P2PStatus,
    };

    let dir = tempfile::TempDir::new().expect("tempdir");
    let chain = ChainStore::open(dir.path()).expect("chain store");

    let payload = make_tarball("index.js", "console.log('hello world');");
    let ipfs_url = spawn_mock_ipfs(payload, StatusCode::OK).await;
    let rpc_url = spawn_mock_staking_rpc(1000).await;

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    let rules_dir = std::path::PathBuf::from(manifest_dir).join("../../rules");
    std::env::set_var("CREG_YARA_RULES_DIR", rules_dir.to_str().unwrap());
    std::env::set_var("CREG_DEV_SANDBOX", "true");
    std::env::set_var("CREG_TESTNET", "true");

    // Generate a validator key pair up front so we can register the node in the
    // validator set (consensus requires assigned_count >= 1 for quorum).
    let validator_signing_key = {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        SigningKey::generate(&mut OsRng)
    };
    let validator_privkey_hex = hex::encode(validator_signing_key.to_bytes());
    let validator_pubkey_hex = hex::encode(validator_signing_key.verifying_key().as_bytes());

    let config = NodeConfig {
        listen_addr: "127.0.0.1:0".into(), // OS assigns a port
        data_dir: dir.path().to_path_buf(),
        node_id: "e2e-node".into(),
        validator_privkey: Some(validator_privkey_hex),
        is_validator: true,
        peers: vec![],
        block_interval_secs: 1,
        ipfs_url,
        eth_rpc_url: rpc_url,
        staking_addr: "0x1000000000000000000000000000000000000001".into(),
        ..NodeConfig::default()
    };

    let event_bus = new_event_bus();
    let (tx_s, tx_r) = finalized_tx::channel();

    // Create a no-op P2P handle (the real P2P stack requires a live network).
    let (p2p_sender, _p2p_rx) = tokio::sync::mpsc::channel::<P2PCommand>(1);
    let p2p = P2PHandle { sender: p2p_sender };

    // Build a single-validator set so consensus can reach 1-of-1 quorum.
    let test_validator = common::Validator {
        id: "e2e-node".into(),
        alias: "E2E Test Validator".into(),
        pubkey: validator_pubkey_hex,
        eth_address: "0x1111111111111111111111111111111111111111".into(),
        stake: 1000,
        reputation: 100,
        status: "online".into(),
    };
    let validator_set = common::ValidatorSet::new(vec![test_validator]);

    let state: Arc<RwLock<NodeState>> = Arc::new(RwLock::new(NodeState {
        chain,
        pending_pool: PendingPool::new(),
        publisher_index: PublisherIndex::new(),
        validator_set_bootstrap: common::ValidatorSet::default(),
        validator_set,
        package_rounds: std::collections::HashMap::new(),
        config: config.clone(),
        p2p_status: P2PStatus::default(),
        bridge_status: BridgeStatus::default(),
        vrf_proofs: std::collections::HashMap::new(),
        decryption_shares: std::collections::HashMap::new(),
        validator_registrations: std::collections::HashMap::new(),
        validator_set_sync: node::state::ValidatorSetSyncStatus::default(),
        view_change_certs: std::collections::HashMap::new(),
        reorgs: Vec::new(),
        pbft_engine: node::state::PbftEngine::new(),
    }));

    let limiter = RateLimiter::new(RateLimitConfig::default());

    let app = api::router(
        Arc::clone(&state),
        event_bus,
        limiter,
        AttestationStore::new(),
        config.cors.clone(),
        tx_s.clone(),
        p2p.clone(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);
    std::env::set_var("CREG_NODE_URL", &url);

    let state_bp = Arc::clone(&state);
    let state_vp = Arc::clone(&state);

    let handle = tokio::spawn(async move {
        tokio::spawn(node::block_producer::run(state_bp, tx_r, p2p.clone()));
        tokio::spawn(node::validator_pipeline::run(state_vp, tx_s, p2p));
        axum::serve(listener, app).await.unwrap();
    });

    // Give the node a moment to fully start.
    tokio::time::sleep(Duration::from_millis(50)).await;

    (url, handle)
}

/// Build a minimal signed PublishRequest for testing.
fn make_request(ecosystem: &str, name: &str, version: &str) -> PublishRequest {
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    let signing_key = SigningKey::generate(&mut OsRng);
    let pubkey_hex = hex::encode(signing_key.verifying_key().as_bytes());
    let id = PackageId::new(ecosystem, name, version);

    let payload = make_tarball("index.js", "console.log('hello world');");
    let content_hash = common::sha256_hex(&payload);
    let publisher_address = "0x1111111111111111111111111111111111111111".to_string();
    let msg = common::publish_signature_message(&id, &content_hash, &publisher_address);
    let sig = signing_key.sign(msg.as_bytes());

    PublishRequest {
        id,
        content_hash,
        ipfs_cid: format!("bafyDev{}", &common::sha256_hex(b"dev")[..32]),
        publisher_address,
        publisher_pubkey: pubkey_hex,
        signature: hex::encode(sig.to_bytes()),
        manifest: PackageManifest::default(),
        submitted_at: Utc::now(),
        ..Default::default()
    }
}

#[tokio::test]
async fn e2e_health_check() {
    let (url, _handle) = start_test_node().await;
    let resp = reqwest::get(format!("{}/v1/health", url)).await.unwrap();
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn e2e_submit_and_verify_package() {
    let (url, _handle) = start_test_node().await;

    let request = make_request("npm", "e2e-test-pkg", "1.0.0");
    let canonical = request.id.canonical();

    // Submit the package.
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/packages", url))
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202, "Expected 202 Accepted");

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "accepted");

    // Wait for the validator pipeline + block producer to verify it.
    // In dev mode (no IPFS, no real tarball) this happens quickly.
    let encoded = urlencoding::encode(&canonical).to_string();
    let verified = timeout(Duration::from_secs(10), async {
        loop {
            tokio::time::sleep(Duration::from_millis(250)).await;
            let resp = reqwest::get(format!("{}/v1/packages/{}", url, encoded))
                .await
                .unwrap();
            if resp.status() == 404 {
                continue;
            }
            let body: serde_json::Value = resp.json().await.unwrap();
            match body["status"].as_str() {
                Some("verified") => return true,
                Some("revoked") => return false,
                _ => continue,
            }
        }
    })
    .await;

    assert!(verified.is_ok(), "Timed out waiting for verification");
    assert!(verified.unwrap(), "Package should be verified, not revoked");
}

#[tokio::test]
async fn e2e_duplicate_submission_rejected() {
    let (url, _handle) = start_test_node().await;
    let request = make_request("npm", "e2e-dup-pkg", "2.0.0");

    // First submission.
    let r1 = reqwest::Client::new()
        .post(format!("{}/v1/packages", url))
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(r1.status(), 202);

    // Wait for verification.
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Second submission of the same package should be rejected.
    let r2 = reqwest::Client::new()
        .post(format!("{}/v1/packages", url))
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), 409, "Duplicate should return 409 Conflict");
}

#[tokio::test]
async fn e2e_invalid_signature_rejected() {
    let (url, _handle) = start_test_node().await;
    let mut request = make_request("npm", "e2e-sig-pkg", "1.0.0");

    // Corrupt the signature.
    request.signature = "deadbeef".repeat(8);

    let resp = reqwest::Client::new()
        .post(format!("{}/v1/packages", url))
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "Invalid signature should return 400");
}

#[tokio::test]
async fn e2e_chain_stats_increase_after_verification() {
    let (url, _handle) = start_test_node().await;

    // Get baseline stats.
    let before: serde_json::Value = reqwest::get(format!("{}/v1/chain/stats", url))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let height_before = before["tip_height"].as_u64().unwrap_or(0);

    // Submit a package.
    let request = make_request("cargo", "e2e-stats-crate", "0.1.0");
    reqwest::Client::new()
        .post(format!("{}/v1/packages", url))
        .json(&request)
        .send()
        .await
        .unwrap();

    // Wait for a block to be produced (poll for up to 10 seconds).
    let height_increased = timeout(Duration::from_secs(10), async {
        loop {
            tokio::time::sleep(Duration::from_millis(250)).await;
            let after: serde_json::Value = reqwest::get(format!("{}/v1/chain/stats", url))
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            let height_after = after["tip_height"].as_u64().unwrap_or(0);
            if height_after > height_before {
                return true;
            }
        }
    })
    .await;

    assert!(
        height_increased.is_ok(),
        "Chain height should increase after verification"
    );
}

#[tokio::test]
async fn e2e_sse_receives_events() {
    let (url, _handle) = start_test_node().await;

    // Connect to SSE stream with a short timeout.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .unwrap();

    let mut resp = client
        .get(format!("{}/v1/events", url))
        .header("Accept", "text/event-stream")
        .send()
        .await
        .unwrap();

    assert!(resp.status().is_success());

    // Submit a package — should trigger a submitted event.
    let request = make_request("pypi", "e2e-sse-pkg", "1.0.0");
    reqwest::Client::new()
        .post(format!("{}/v1/packages", url))
        .json(&request)
        .send()
        .await
        .unwrap();

    // Read a few chunks from the stream and check we get event data.
    let mut received_data = false;
    for _ in 0..5 {
        match timeout(Duration::from_secs(2), resp.chunk()).await {
            Ok(Ok(Some(chunk))) => {
                let text = String::from_utf8_lossy(&chunk);
                if text.contains("data:") && text.contains("canonical") {
                    received_data = true;
                    break;
                }
            }
            _ => break,
        }
    }

    assert!(received_data, "SSE stream should deliver package events");
}

#[tokio::test]
async fn e2e_prometheus_metrics_endpoint() {
    let (url, _handle) = start_test_node().await;

    let resp = reqwest::get(format!("{}/metrics", url)).await.unwrap();
    assert!(resp.status().is_success());

    let body = resp.text().await.unwrap();
    assert!(
        body.contains("creg_chain_height"),
        "Metrics should include chain height"
    );
    assert!(
        body.contains("creg_package_count"),
        "Metrics should include package count"
    );
    assert!(
        body.contains("creg_pending_pool_size"),
        "Metrics should include pending pool size"
    );
}

#[tokio::test]
async fn e2e_legacy_private_api_acl_protection() {
    // 1. Unset operator keys to verify 503 behavior
    std::env::remove_var("CREG_OPERATOR_API_KEY");
    std::env::remove_var("CREG_OPERATOR_PUBKEY");

    let (url, _handle) = start_test_node().await;

    // A public route should still be accessible.
    let resp = reqwest::get(format!("{}/v1/health", url)).await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // Private route should be locked/unavailable.
    let resp = reqwest::get(format!("{}/v1/runtime/config", url))
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);

    // 2. Set operator key to verify authorization gate
    let secret_key = "test-operator-secret-999";
    std::env::set_var("CREG_OPERATOR_API_KEY", secret_key);

    // Request without headers -> 401 Unauthorized
    let resp = reqwest::get(format!("{}/v1/runtime/config", url))
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Request with incorrect x-operator-key header -> 401 Unauthorized
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/v1/runtime/config", url))
        .header("x-operator-key", "wrong-secret")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Request with correct x-operator-key header -> 200 OK
    let resp = client
        .get(format!("{}/v1/runtime/config", url))
        .header("x-operator-key", secret_key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // Request with correct Bearer token -> 200 OK
    let resp = client
        .get(format!("{}/v1/runtime/config", url))
        .bearer_auth(secret_key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // Cleanup
    std::env::remove_var("CREG_OPERATOR_API_KEY");
}
