use anyhow::{Context, Result};
use axum::{extract::State, routing::get, Json, Router};
use db_sync::sync_worker::{ChainStoreHandle, ChainStoreProxy, SyncConfig, SyncWorker};
use serde::Serialize;
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::RwLock;
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
struct ReadOnlyChainProxy {
    data_dir: PathBuf,
}

impl ReadOnlyChainProxy {
    fn open_store(&self) -> Result<node::chain_store::ChainStore> {
        node::chain_store::ChainStore::open_read_only(&self.data_dir)
            .with_context(|| format!("open read-only chain store at {}", self.data_dir.display()))
    }
}

impl ChainStoreProxy for ReadOnlyChainProxy {
    fn tip_height(&self) -> Result<u64> {
        let store = self.open_store()?;
        store.tip_height()
    }

    fn get_block_by_height(&self, height: u64) -> Result<Option<common::Block>> {
        let store = self.open_store()?;
        store.get_block_by_height(height)
    }
}

#[derive(Clone)]
struct AppState {
    data_dir: String,
    pg_url: String,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    data_dir: String,
    pg_url: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let data_dir = std::env::var("CREG_INDEXER_DATA_DIR")
        .or_else(|_| std::env::var("CREG_DATA_DIR"))
        .unwrap_or_else(|_| "/data".to_string());
    let pg_url = std::env::var("CREG_PG_URL")
        .context("CREG_PG_URL must be set for the dedicated indexer service")?;
    let listen_addr =
        std::env::var("CREG_INDEXER_LISTEN").unwrap_or_else(|_| "0.0.0.0:8084".to_string());
    let poll_interval_secs = std::env::var("CREG_INDEXER_POLL_INTERVAL_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(1);

    let proxy = ReadOnlyChainProxy {
        data_dir: PathBuf::from(&data_dir),
    };
    let chain_handle: ChainStoreHandle = Arc::new(RwLock::new(proxy));
    let sync_config = SyncConfig {
        poll_interval: Duration::from_secs(poll_interval_secs),
        pg_url: pg_url.clone(),
        ..Default::default()
    };

    let worker = SyncWorker::new(sync_config, chain_handle)
        .await
        .context("start dedicated indexer sync worker")?;
    tokio::spawn(worker.run());

    let app_state = AppState {
        data_dir: data_dir.clone(),
        pg_url: redact_pg_url(&pg_url),
    };

    let app = Router::new()
        .route("/health", get(health))
        .with_state(app_state);

    let addr: SocketAddr = listen_addr
        .parse()
        .with_context(|| format!("invalid CREG_INDEXER_LISTEN value: {}", listen_addr))?;

    tracing::info!(data_dir = %data_dir, addr = %addr, "Dedicated indexer started");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        data_dir: state.data_dir,
        pg_url: state.pg_url,
    })
}

fn redact_pg_url(value: &str) -> String {
    if let Some((prefix, _)) = value.rsplit_once('@') {
        if let Some((scheme, _)) = prefix.split_once("://") {
            return format!(
                "{}://***@{}",
                scheme,
                value.split('@').nth(1).unwrap_or("redacted")
            );
        }
    }
    "redacted".to_string()
}
