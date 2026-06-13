// crates/cli/src/explorer_tui.rs
// Chain Registry Console — the single supported terminal operator surface.
//
// Features:
// - Real-time blockchain data from node API
// - Multiple views: Overview, Blocks, Validators, Packages, Network, Mempool, Operator
// - Live SSE event streaming
// - Interactive navigation with vim-style keybindings
// - Beautiful UI with gradients, borders, and animations
// - Detailed drill-down views for all data types

use anyhow::Result;
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, MouseEventKind,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use futures::StreamExt;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, Cell, Clear, Gauge, List, ListItem, Paragraph, Row, Sparkline, Table, Wrap,
    },
    Frame, Terminal,
};
use serde_json::Value;
use std::{
    collections::VecDeque,
    io,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, RwLock};

#[derive(Clone, Copy)]
enum ApiRouteScope {
    Public,
    Operator,
    Validator,
}

fn operator_api_key() -> Option<String> {
    std::env::var("CREG_OPERATOR_API_KEY")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn is_legacy_fallback_status(status: reqwest::StatusCode) -> bool {
    matches!(status.as_u16(), 404 | 405 | 501)
}

fn scoped_get(
    client: &reqwest::Client,
    url: String,
    scope: ApiRouteScope,
) -> reqwest::RequestBuilder {
    let request = client.get(url);
    match scope {
        ApiRouteScope::Operator => match operator_api_key() {
            Some(api_key) => request.header("X-Operator-Key", api_key),
            None => request,
        },
        ApiRouteScope::Public | ApiRouteScope::Validator => request,
    }
}

async fn get_json_with_fallback(
    client: &reqwest::Client,
    grouped_url: String,
    legacy_url: Option<String>,
    scope: ApiRouteScope,
) -> Result<Value> {
    let grouped = scoped_get(client, grouped_url, scope).send().await?;
    if grouped.status().is_success() {
        return Ok(grouped.json().await?);
    }

    if let Some(legacy_url) = legacy_url {
        if is_legacy_fallback_status(grouped.status()) {
            let legacy = scoped_get(client, legacy_url, scope).send().await?;
            return Ok(legacy.error_for_status()?.json().await?);
        }
    }

    Ok(grouped.error_for_status()?.json().await?)
}

async fn open_stream_with_fallback(
    client: &reqwest::Client,
    grouped_url: String,
    legacy_url: Option<String>,
    scope: ApiRouteScope,
) -> Result<reqwest::Response> {
    let grouped = scoped_get(client, grouped_url, scope)
        .header("Accept", "text/event-stream")
        .send()
        .await?;
    if grouped.status().is_success() {
        return Ok(grouped);
    }

    if let Some(legacy_url) = legacy_url {
        if is_legacy_fallback_status(grouped.status()) {
            let legacy = scoped_get(client, legacy_url, scope)
                .header("Accept", "text/event-stream")
                .send()
                .await?;
            return Ok(legacy.error_for_status()?);
        }
    }

    Ok(grouped.error_for_status()?)
}

// ============================================================================
// CONSTANTS & STYLING
// ============================================================================

const TICK_RATE_MS: u64 = 100;
const REFRESH_INTERVAL_SECS: u64 = 3;
const MAX_EVENTS: usize = 200;
const MAX_BLOCKS: usize = 100;

use std::sync::atomic::{AtomicBool, Ordering};
static IS_LIGHT_THEME: AtomicBool = AtomicBool::new(false);

// Color palette for a cohesive, beautiful look
struct Theme;
impl Theme {
    fn primary() -> Color {
        if IS_LIGHT_THEME.load(Ordering::Relaxed) {
            Color::Blue
        } else {
            Color::Cyan
        }
    }
    fn secondary() -> Color {
        if IS_LIGHT_THEME.load(Ordering::Relaxed) {
            Color::Rgb(0, 0, 139)
        } else {
            Color::Blue
        }
    }
    fn success() -> Color {
        if IS_LIGHT_THEME.load(Ordering::Relaxed) {
            Color::Rgb(0, 100, 0)
        } else {
            Color::Green
        }
    }
    fn warning() -> Color {
        if IS_LIGHT_THEME.load(Ordering::Relaxed) {
            Color::Rgb(150, 100, 0)
        } else {
            Color::Yellow
        }
    }
    fn error() -> Color {
        if IS_LIGHT_THEME.load(Ordering::Relaxed) {
            Color::Rgb(139, 0, 0)
        } else {
            Color::Red
        }
    }
    fn accent() -> Color {
        if IS_LIGHT_THEME.load(Ordering::Relaxed) {
            Color::Magenta
        } else {
            Color::Magenta
        }
    }
    fn text() -> Color {
        if IS_LIGHT_THEME.load(Ordering::Relaxed) {
            Color::Black
        } else {
            Color::White
        }
    }
    fn text_dim() -> Color {
        if IS_LIGHT_THEME.load(Ordering::Relaxed) {
            Color::DarkGray
        } else {
            Color::Gray
        }
    }
    fn border() -> Color {
        if IS_LIGHT_THEME.load(Ordering::Relaxed) {
            Color::Gray
        } else {
            Color::DarkGray
        }
    }
    fn highlight() -> Color {
        if IS_LIGHT_THEME.load(Ordering::Relaxed) {
            Color::Rgb(200, 220, 255)
        } else {
            Color::LightCyan
        }
    }
}

// ============================================================================
// DATA MODELS
// ============================================================================

#[derive(Debug, Clone)]
struct BlockInfo {
    height: u64,
    hash: String,
    timestamp: String,
    proposer: String,
    tx_count: usize,
    transactions: Vec<TransactionInfo>,
    merkle_root: String,
}

#[derive(Debug, Clone)]
struct TransactionInfo {
    _id: String,
    tx_type: String,
    package_name: Option<String>,
    package_version: Option<String>,
    publisher: Option<String>,
    status: String,
}

#[derive(Debug, Clone)]
struct ValidatorInfo {
    id: String,
    alias: String,
    stake: u64,
    reputation: u8,
    status: String,
    is_active: bool,
    pub_key: String,
}

#[derive(Debug, Clone)]
struct PackageInfo {
    name: String,
    ecosystem: String,
    version: String,
    status: String,
    publisher: String,
    verified_at: Option<String>,
    content_hash: String,
}

#[derive(Debug, Clone)]
struct NetworkStats {
    tip_height: u64,
    package_count: u64,
    _block_count: u64,
    validator_count: usize,
    total_stake: u64,
    peer_count: usize,
    bridge_status: String,
    l1_block: u64,
}

#[derive(Debug, Clone)]
struct MempoolTx {
    id: String,
    tx_type: String,
    _size: usize,
    timestamp: Instant,
}

// ============================================================================
// APPLICATION STATE
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
enum View {
    Overview,
    Blocks,
    BlockDetail,
    Validators,
    ValidatorDetail,
    Packages,
    PackageDetail,
    Network,
    Mempool,
    Events,
    Operator,
    Consensus,
    Faucet,
    Help,
    Bridge,
    Metrics,
}

/// State of the Faucet pane's drip flow.
#[derive(Debug, Clone)]
enum FaucetStatus {
    /// No active request.
    Idle,
    /// PoW being solved and drip request in-flight.
    Working {
        started_at: Instant,
        message: String,
    },
    /// Drip completed; show success for a few seconds.
    Success {
        tx_hash: String,
        amount: String,
        at: Instant,
    },
    /// Drip failed.
    Failed { error: String, at: Instant },
}

#[derive(Debug, Clone)]
struct FaucetView {
    /// Base URL of the faucet service (e.g. http://localhost:8082).
    base: String,
    /// Address being edited or submitted.
    address_input: String,
    /// Whether the address input field has focus (insert mode).
    editing: bool,
    /// Current drip status.
    status: FaucetStatus,
    /// Last fetched token balance (raw wei-style string from the faucet).
    last_balance: Option<String>,
    /// Last fetched native (ETH) balance (raw wei).
    last_native_balance: Option<String>,
    /// Pre-formatted decimal tCREG balance from the faucet (e.g. "1000.00").
    last_balance_fmt: Option<String>,
    /// Pre-formatted decimal ETH balance from the faucet (e.g. "10000.0000").
    last_native_balance_fmt: Option<String>,
    /// Faucet /health: "online" | "offline" | "unknown"
    health: String,
    /// Faucet's own tCREG reserve (so operators know if it can still drip).
    faucet_token_reserve: Option<String>,
    /// Chain info from /api/network.
    network: Option<crate::faucet_client::NetworkInfo>,
}

impl FaucetView {
    fn new(base: String) -> Self {
        Self {
            base,
            address_input: String::new(),
            editing: false,
            status: FaucetStatus::Idle,
            last_balance: None,
            last_native_balance: None,
            last_balance_fmt: None,
            last_native_balance_fmt: None,
            health: "unknown".into(),
            faucet_token_reserve: None,
            network: None,
        }
    }
}

/// Live PBFT round snapshot fetched from the node or derived from stats.
#[derive(Debug, Clone)]
struct ConsensusState {
    /// Current round number (typically tip_height + 1)
    round: u64,
    /// Current PBFT phase: "PRE-PREPARE", "PREPARE", "COMMIT", "FINALIZED"
    phase: String,
    /// Proposer pubkey (truncated) for this round
    proposer: String,
    /// Number of PREPARE votes collected so far
    prepare_votes: usize,
    /// Number of COMMIT votes collected so far
    commit_votes: usize,
    /// Quorum threshold (2f+1)
    quorum: usize,
    /// Total validator set size
    total_validators: usize,
    /// When this snapshot was fetched
    fetched_at: Instant,
}

#[derive(Debug, Clone)]
struct RuntimeIdentity {
    node_id: String,
    validator_pubkey: Option<String>,
}

#[derive(Debug)]
struct App {
    // Navigation
    current_view: View,
    previous_view: Option<View>,

    // Selection indices
    selected_block: usize,
    selected_validator: usize,
    selected_package: usize,
    selected_event: usize,
    _selected_tab: usize,

    // Data
    stats: NetworkStats,
    blocks: VecDeque<BlockInfo>,
    validators: Vec<ValidatorInfo>,
    packages: Vec<PackageInfo>,
    events: VecDeque<(Instant, String, String)>, // (timestamp, type, message)
    mempool: Vec<MempoolTx>,
    peer_ids: Vec<String>,
    runtime_identity: Option<RuntimeIdentity>,

    // UI State
    _show_help: bool,
    search_query: String,
    is_searching: bool,
    _scroll_offset: usize,

    // Async
    _api_base: String,
    data_tx: mpsc::Sender<DataUpdate>,
    _last_refresh: Instant,
    tick_count: u64,

    // Consensus
    /// Latest PBFT round snapshot.
    consensus_state: Option<ConsensusState>,

    // Connection health
    /// True while the SSE stream is connected and delivering events.
    node_connected: bool,
    /// Wall-clock time the last SSE event was received.
    last_event_at: Instant,
    /// Seconds until the next reconnect attempt (shown in disconnect banner).
    reconnect_in: u64,

    // Sparkline data for TPS visualization
    tps_history: VecDeque<u64>,

    // Faucet pane state
    faucet: FaucetView,
    bridge_anchors: Vec<serde_json::Value>,
    metrics_history: Vec<serde_json::Value>,
}

#[derive(Debug)]
enum DataUpdate {
    Stats(NetworkStats),
    Block(BlockInfo),
    Validators(Vec<ValidatorInfo>),
    Packages(Vec<PackageInfo>),
    Event(String, String), // (type, message)
    MempoolSnapshot(Vec<MempoolTx>),
    Peers(Vec<String>),
    RuntimeIdentity(RuntimeIdentity),
    /// SSE stream (re-)connected successfully.
    NodeConnected,
    /// SSE stream dropped; UI should show disconnect banner.
    NodeDisconnected {
        retry_in_secs: u64,
    },
    /// Live PBFT round snapshot.
    Consensus(ConsensusState),
    /// Faucet health/reserve snapshot.
    FaucetHealth {
        healthy: bool,
        token_reserve: Option<String>,
    },
    /// Faucet network info (chain id, RPC URL, etc.).
    FaucetNetwork(crate::faucet_client::NetworkInfo),
    /// Faucet balance lookup result for the current input address.
    /// `token`/`native` are raw wei; `token_fmt`/`native_fmt` are pre-formatted
    /// decimals from the faucet (preferred for display).
    FaucetBalance {
        token: Option<String>,
        native: Option<String>,
        token_fmt: Option<String>,
        native_fmt: Option<String>,
    },
    /// Drip operation ended.
    FaucetDripResult(Result<(String, String), String>),
    /// Drip operation progress message (e.g. "solving PoW", "submitting…").
    FaucetDripProgress(String),
    /// A generic faucet-pane error (balance fetch, etc.). Renders as FaucetStatus::Failed.
    FaucetError(String),
}

impl App {
    fn new(api_base: String, data_tx: mpsc::Sender<DataUpdate>) -> Self {
        Self {
            current_view: View::Overview,
            previous_view: None,
            selected_block: 0,
            selected_validator: 0,
            selected_package: 0,
            selected_event: 0,
            _selected_tab: 0,
            stats: NetworkStats {
                tip_height: 0,
                package_count: 0,
                _block_count: 0,
                validator_count: 0,
                total_stake: 0,
                peer_count: 0,
                bridge_status: "Unknown".to_string(),
                l1_block: 0,
            },
            blocks: VecDeque::with_capacity(MAX_BLOCKS),
            validators: Vec::new(),
            packages: Vec::new(),
            events: VecDeque::with_capacity(MAX_EVENTS),
            mempool: Vec::new(),
            peer_ids: Vec::new(),
            runtime_identity: None,
            _show_help: false,
            search_query: String::new(),
            is_searching: false,
            _scroll_offset: 0,
            _api_base: api_base,
            data_tx,
            _last_refresh: Instant::now(),
            tick_count: 0,
            consensus_state: None,
            node_connected: false,
            last_event_at: Instant::now(),
            reconnect_in: 0,
            tps_history: VecDeque::with_capacity(60),
            faucet: FaucetView::new(
                std::env::var("CREG_FAUCET_URL")
                    // Use internal service name "faucet" for container-to-container comms.
                    .unwrap_or_else(|_| "http://faucet:8082".into())
                    .trim_end_matches('/')
                    .to_string(),
            ),
            bridge_anchors: Vec::new(),
            metrics_history: Vec::new(),
        }
    }

    fn selected_block(&self) -> Option<&BlockInfo> {
        self.blocks.get(self.selected_block)
    }

    fn selected_validator(&self) -> Option<&ValidatorInfo> {
        self.validators.get(self.selected_validator)
    }

    fn selected_package(&self) -> Option<&PackageInfo> {
        self.packages.get(self.selected_package)
    }

    fn displayed_validator_count(&self) -> usize {
        if self.validators.is_empty() {
            self.stats.validator_count
        } else {
            self.validators.len()
        }
    }

    fn displayed_total_stake(&self) -> u64 {
        if self.stats.total_stake > 0 || self.validators.is_empty() {
            self.stats.total_stake
        } else {
            self.validators
                .iter()
                .map(|validator| validator.stake)
                .sum()
        }
    }

    fn push_event(&mut self, event_type: String, message: String) {
        self.events
            .push_front((Instant::now(), event_type, message));
        while self.events.len() > MAX_EVENTS {
            self.events.pop_back();
        }
    }
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

pub async fn run(node_url: Option<&str>) -> Result<()> {
    let api_base = node_url
        .map(String::from)
        .unwrap_or_else(|| {
            std::env::var("CREG_NODE_URL").unwrap_or_else(|_| "http://localhost:8080".into())
        })
        .trim_end_matches('/')
        .to_string();

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Setup async channels
    let (data_tx, mut data_rx) = mpsc::channel::<DataUpdate>(1000);
    let app = Arc::new(RwLock::new(App::new(api_base.clone(), data_tx.clone())));

    // Spawn background tasks
    let app_clone = app.clone();
    let api_base_clone = api_base.clone();
    tokio::spawn(async move {
        data_fetcher_loop(app_clone, api_base_clone, data_tx.clone()).await;
    });

    // Spawn SSE event listener
    {
        let app_sse = app.clone();
        let api_sse = api_base.clone();
        let tx_sse = app.read().await.data_tx.clone();
        tokio::spawn(async move {
            sse_event_listener(app_sse, api_sse, tx_sse).await;
        });
    };

    // Main loop
    let tick_rate = Duration::from_millis(TICK_RATE_MS);
    let mut last_tick = Instant::now();

    loop {
        // Draw UI
        let app_read = app.read().await;
        terminal.draw(|f| draw_ui(f, &app_read))?;
        drop(app_read);

        // Handle events
        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if crossterm::event::poll(timeout)? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    let mut app_write = app.write().await;
                    if handle_key(&mut app_write, key.code).await {
                        break;
                    }
                }
                Event::Mouse(mouse) => {
                    let mut app_write = app.write().await;
                    handle_mouse(&mut app_write, mouse);
                }
                _ => {}
            }
        }

        // Process data updates
        while let Ok(update) = data_rx.try_recv() {
            let mut app_write = app.write().await;
            apply_data_update(&mut app_write, update);
        }

        if last_tick.elapsed() >= tick_rate {
            let mut app_write = app.write().await;
            app_write.tick_count += 1;
            last_tick = Instant::now();
            drop(app_write);
        }
    }

    // Cleanup
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}

// ============================================================================
// DATA FETCHING
// ============================================================================

async fn data_fetcher_loop(app: Arc<RwLock<App>>, api_base: String, tx: mpsc::Sender<DataUpdate>) {
    let client = reqwest::Client::new();
    let mut last_stats_refresh = Instant::now();
    let mut last_block_height: u64 = 0;
    let faucet_base = app.read().await.faucet.base.clone();
    let mut faucet_network_fetched = false;
    let mut runtime_config_fetched = false;

    loop {
        // Fetch runtime config once at startup
        if !runtime_config_fetched {
            if let Ok(identity) = fetch_runtime_config(&client, &api_base).await {
                let _ = tx.send(DataUpdate::RuntimeIdentity(identity)).await;
                runtime_config_fetched = true;
            }
        }

        // Fetch stats periodically
        if last_stats_refresh.elapsed() >= Duration::from_secs(REFRESH_INTERVAL_SECS) {
            if let Ok(stats) = fetch_stats(&client, &api_base).await {
                let _ = tx.send(DataUpdate::Stats(stats.clone())).await;

                // Fetch new blocks if height changed
                if stats.tip_height > last_block_height {
                    for h in (last_block_height.saturating_add(1)..=stats.tip_height).rev() {
                        if let Ok(block) = fetch_block(&client, &api_base, h).await {
                            let _ = tx.send(DataUpdate::Block(block)).await;
                        }
                    }
                    last_block_height = stats.tip_height;
                }
            }

            // Fetch validators
            if let Ok(validators) = fetch_validators(&client, &api_base).await {
                let _ = tx.send(DataUpdate::Validators(validators)).await;
            }

            // Fetch peers
            if let Ok(peers) = fetch_peers(&client, &api_base).await {
                let _ = tx.send(DataUpdate::Peers(peers)).await;
            }

            // Fetch pending packages
            if let Ok(packages) = fetch_pending_packages(&client, &api_base).await {
                let _ = tx.send(DataUpdate::Packages(packages)).await;
            }

            // Fetch mempool (pending pool entries for the Mempool view)
            if let Ok(mempool) = fetch_mempool(&client, &api_base).await {
                let _ = tx.send(DataUpdate::MempoolSnapshot(mempool)).await;
            }

            // Fetch consensus state (best-effort — node may not expose this endpoint)
            if let Ok(cs) = fetch_consensus_state(&client, &api_base).await {
                let _ = tx.send(DataUpdate::Consensus(cs)).await;
            }

            // Poll faucet health (best-effort; faucet may be offline).
            if let Some((healthy, reserve)) = fetch_faucet_health(&client, &faucet_base).await {
                let _ = tx
                    .send(DataUpdate::FaucetHealth {
                        healthy,
                        token_reserve: reserve,
                    })
                    .await;
            }

            // Fetch the network info once; it's static per session.
            if !faucet_network_fetched {
                if let Ok(info) = crate::faucet_client::get_network(&client, &faucet_base).await {
                    let _ = tx.send(DataUpdate::FaucetNetwork(info)).await;
                    faucet_network_fetched = true;
                }
            }

            last_stats_refresh = Instant::now();
        }

        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn fetch_stats(client: &reqwest::Client, api_base: &str) -> Result<NetworkStats> {
    let json = get_json_with_fallback(
        client,
        format!("{}/v1/public/chain/stats", api_base),
        Some(format!("{}/v1/chain/stats", api_base)),
        ApiRouteScope::Public,
    )
    .await?;

    Ok(NetworkStats {
        tip_height: json["tip_height"].as_u64().unwrap_or(0),
        package_count: json["package_count"].as_u64().unwrap_or(0),
        _block_count: json["block_count"].as_u64().unwrap_or(0),
        validator_count: json["validator_count"].as_u64().unwrap_or(0) as usize,
        total_stake: json["total_stake"].as_u64().unwrap_or(0),
        peer_count: json["peer_count"].as_u64().unwrap_or(0) as usize,
        bridge_status: json["bridge_status"]
            .as_str()
            .unwrap_or("Unknown")
            .to_string(),
        l1_block: json["l1_block"].as_u64().unwrap_or(0),
    })
}

async fn fetch_block(client: &reqwest::Client, api_base: &str, height: u64) -> Result<BlockInfo> {
    let json = get_json_with_fallback(
        client,
        format!("{}/v1/public/blocks/{}", api_base, height),
        Some(format!("{}/v1/blocks/{}", api_base, height)),
        ApiRouteScope::Public,
    )
    .await?;

    let header = &json["header"];
    let txs: Vec<TransactionInfo> = json["transactions"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .map(|t| TransactionInfo {
                    _id: t["id"]["canonical"]
                        .as_str()
                        .unwrap_or("unknown")
                        .to_string(),
                    tx_type: t["type"].as_str().unwrap_or("unknown").to_string(),
                    package_name: t["id"]["name"].as_str().map(|s| s.to_string()),
                    package_version: t["id"]["version"].as_str().map(|s| s.to_string()),
                    publisher: t["publisher_pubkey"]
                        .as_str()
                        .map(|s| s[..8.min(s.len())].to_string()),
                    status: t["status"].as_str().unwrap_or("pending").to_string(),
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(BlockInfo {
        height: header["height"].as_u64().unwrap_or(0),
        hash: json["hash"].as_str().unwrap_or("").to_string(),
        timestamp: header["timestamp"].as_str().unwrap_or("").to_string(),
        proposer: header["proposer_id"]
            .as_str()
            .unwrap_or("unknown")
            .to_string(),
        tx_count: txs.len(),
        transactions: txs,
        merkle_root: header["merkle_root"].as_str().unwrap_or("").to_string(),
    })
}

async fn fetch_validators(client: &reqwest::Client, api_base: &str) -> Result<Vec<ValidatorInfo>> {
    let json = get_json_with_fallback(
        client,
        format!("{}/v1/operator/nodes", api_base),
        Some(format!("{}/v1/nodes", api_base)),
        ApiRouteScope::Operator,
    )
    .await?;
    let validators = json.as_array().cloned().unwrap_or_default();

    Ok(validators
        .iter()
        .map(|v| ValidatorInfo {
            id: v["id"].as_str().unwrap_or("unknown").to_string(),
            alias: v["alias"].as_str().unwrap_or("").to_string(),
            stake: v["stake"].as_u64().unwrap_or(0),
            reputation: v["reputation"].as_u64().unwrap_or(50) as u8,
            status: v["status"].as_str().unwrap_or("unknown").to_string(),
            is_active: v["is_active"].as_bool().unwrap_or(false),
            pub_key: v["pubkey"].as_str().unwrap_or("").to_string(),
        })
        .collect())
}

async fn fetch_peers(client: &reqwest::Client, api_base: &str) -> Result<Vec<String>> {
    let json = get_json_with_fallback(
        client,
        format!("{}/v1/operator/p2p/status", api_base),
        Some(format!("{}/v1/p2p/status", api_base)),
        ApiRouteScope::Operator,
    )
    .await?;

    Ok(json["peers"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|p| p.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default())
}

/// Fetch packages from both the verified list and the pending pool, merge them.
///
/// `/v1/packages?limit=50` returns full package objects for finalized packages.
/// `/v1/pending` returns a bare list of canonical IDs still in the mempool.
/// We show verified packages first (richest data), then pending ones.
async fn fetch_pending_packages(
    client: &reqwest::Client,
    api_base: &str,
) -> Result<Vec<PackageInfo>> {
    let mut packages: Vec<PackageInfo> = Vec::new();

    // 1. Finalized/verified packages — full objects from the chain store.
    if let Ok(json) = get_json_with_fallback(
        client,
        format!("{}/v1/public/packages?limit=50", api_base),
        Some(format!("{}/v1/packages?limit=50", api_base)),
        ApiRouteScope::Public,
    )
    .await
    {
        if let Some(arr) = json["packages"].as_array() {
            for v in arr {
                let canonical = v["canonical"].as_str().unwrap_or_default();
                if canonical.is_empty() {
                    continue;
                }
                // canonical is e.g. "npm/express@4.18.0"
                let parts: Vec<&str> = canonical.splitn(2, '/').collect();
                let ecosystem = parts.first().copied().unwrap_or("?").to_string();
                let name_ver = parts.get(1).copied().unwrap_or(canonical);
                let (pkg_name, version) = if let Some(pos) = name_ver.rfind('@') {
                    (&name_ver[..pos], &name_ver[pos + 1..])
                } else {
                    (name_ver, "?")
                };
                packages.push(PackageInfo {
                    name: pkg_name.to_string(),
                    ecosystem,
                    version: version.to_string(),
                    status: v["status"].as_str().unwrap_or("verified").to_string(),
                    publisher: v["publisher_pubkey"]
                        .as_str()
                        .unwrap_or("")
                        .chars()
                        .take(16)
                        .collect(),
                    verified_at: v["verified_at"].as_str().map(|s| s.to_string()),
                    content_hash: v["content_hash"].as_str().unwrap_or("").to_string(),
                });
            }
        }
    }

    // 2. Pending pool — bare canonical ID strings not yet in the chain store.
    if let Ok(json) = get_json_with_fallback(
        client,
        format!("{}/v1/operator/pending", api_base),
        Some(format!("{}/v1/pending", api_base)),
        ApiRouteScope::Operator,
    )
    .await
    {
        if let Some(arr) = json["packages"].as_array() {
            for v in arr {
                let canonical = v.as_str().unwrap_or_default().to_string();
                if canonical.is_empty() {
                    continue;
                }
                // Skip if already present from the verified list.
                if packages
                    .iter()
                    .any(|p| format!("{}/{}@{}", p.ecosystem, p.name, p.version) == canonical)
                {
                    continue;
                }
                let parts: Vec<&str> = canonical.splitn(2, '/').collect();
                let ecosystem = parts.first().copied().unwrap_or("?").to_string();
                let name_ver = parts.get(1).copied().unwrap_or(&canonical);
                let (pkg_name, version) = if let Some(pos) = name_ver.rfind('@') {
                    (&name_ver[..pos], &name_ver[pos + 1..])
                } else {
                    (name_ver, "?")
                };
                packages.push(PackageInfo {
                    name: pkg_name.to_string(),
                    ecosystem,
                    version: version.to_string(),
                    status: "pending".to_string(),
                    publisher: String::new(),
                    verified_at: None,
                    content_hash: String::new(),
                });
            }
        }
    }

    Ok(packages)
}

/// Fetch pending-pool entries for the Mempool view.
///
/// Calls `/v1/pending` which returns `{count, packages: ["npm/foo@1.0", …]}`.
/// Each canonical string is parsed into a `MempoolTx` for display.
async fn fetch_mempool(client: &reqwest::Client, api_base: &str) -> Result<Vec<MempoolTx>> {
    let json = get_json_with_fallback(
        client,
        format!("{}/v1/operator/pending", api_base),
        Some(format!("{}/v1/pending", api_base)),
        ApiRouteScope::Operator,
    )
    .await?;

    let mut txs = Vec::new();
    if let Some(arr) = json["packages"].as_array() {
        let now = Instant::now();
        for v in arr {
            let canonical = v.as_str().unwrap_or_default();
            if canonical.is_empty() {
                continue;
            }
            // Parse "npm/express@4.18.0" → ecosystem + name + version
            let (ecosystem, rest) = canonical.split_once('/').unwrap_or(("unknown", canonical));
            let (_name, _version) = rest.rsplit_once('@').unwrap_or((rest, "?"));
            txs.push(MempoolTx {
                id: canonical.to_string(),
                tx_type: format!("publish({})", ecosystem),
                _size: canonical.len(), // approximate — no real size available
                timestamp: now,
            });
        }
    }
    Ok(txs)
}

/// Fetch PBFT consensus round state.
/// Tries `/v1/consensus/state`; if that returns an error or is not implemented,
/// derives a best-effort snapshot from `/v1/chain/stats` and `/v1/validators`.
async fn fetch_runtime_config(client: &reqwest::Client, api_base: &str) -> Result<RuntimeIdentity> {
    let json = get_json_with_fallback(
        client,
        format!("{}/v1/operator/runtime/config", api_base),
        Some(format!("{}/v1/runtime/config", api_base)),
        ApiRouteScope::Operator,
    )
    .await?;

    Ok(RuntimeIdentity {
        node_id: json["node_id"].as_str().unwrap_or("unknown").to_string(),
        validator_pubkey: json["validator_pubkey"].as_str().map(|s| s.to_string()),
    })
}

async fn fetch_consensus_state(client: &reqwest::Client, api_base: &str) -> Result<ConsensusState> {
    // Try the dedicated endpoint first.
    if let Ok(json) = get_json_with_fallback(
        client,
        format!("{}/v1/validator/consensus/state", api_base),
        Some(format!("{}/v1/consensus/state", api_base)),
        ApiRouteScope::Validator,
    )
    .await
    {
        let total = json["total_validators"].as_u64().unwrap_or(0) as usize;
        return Ok(ConsensusState {
            round: json["round"].as_u64().unwrap_or(0),
            phase: json["phase"].as_str().unwrap_or("UNKNOWN").to_uppercase(),
            proposer: json["proposer"]
                .as_str()
                .unwrap_or("unknown")
                .chars()
                .take(16)
                .collect::<String>()
                + "…",
            prepare_votes: json["prepare_votes"].as_u64().unwrap_or(0) as usize,
            commit_votes: json["commit_votes"].as_u64().unwrap_or(0) as usize,
            quorum: total * 2 / 3 + 1,
            total_validators: total,
            fetched_at: Instant::now(),
        });
    }

    // Fallback: derive from stats endpoint.
    let json = get_json_with_fallback(
        client,
        format!("{}/v1/public/chain/stats", api_base),
        Some(format!("{}/v1/chain/stats", api_base)),
        ApiRouteScope::Public,
    )
    .await?;

    let tip = json["tip_height"].as_u64().unwrap_or(0);
    let total = json["validator_count"].as_u64().unwrap_or(0) as usize;
    let quorum = if total > 0 { total * 2 / 3 + 1 } else { 1 };

    Ok(ConsensusState {
        round: tip.saturating_add(1),
        phase: "PREPARE".to_string(), // best-effort — no real phase data
        proposer: "(VRF-selected)".to_string(),
        prepare_votes: 0,
        commit_votes: 0,
        quorum,
        total_validators: total,
        fetched_at: Instant::now(),
    })
}

async fn sse_event_listener(
    _app: Arc<RwLock<App>>,
    api_base: String,
    tx: mpsc::Sender<DataUpdate>,
) {
    const RETRY_SECS: u64 = 5;
    let client = reqwest::Client::new();

    loop {
        let res = match open_stream_with_fallback(
            &client,
            format!("{}/v1/public/events", api_base),
            Some(format!("{}/v1/events", api_base)),
            ApiRouteScope::Public,
        )
        .await
        {
            Ok(r) => r,
            Err(_) => {
                // Connection refused / DNS failure — node is unreachable.
                let _ = tx
                    .send(DataUpdate::NodeDisconnected {
                        retry_in_secs: RETRY_SECS,
                    })
                    .await;
                tokio::time::sleep(Duration::from_secs(RETRY_SECS)).await;
                continue;
            }
        };

        // Successfully opened the stream — mark as connected.
        let _ = tx.send(DataUpdate::NodeConnected).await;

        let mut stream = res.bytes_stream();
        let mut buffer = String::new();

        while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(c) => c,
                Err(_) => break,
            };

            buffer.push_str(&String::from_utf8_lossy(&chunk));

            // Process complete SSE messages (double newline delimited)
            while let Some(pos) = buffer.find("\n\n") {
                let message = buffer[..pos].to_string();
                buffer = buffer[pos + 2..].to_string();

                let mut event_type = String::from("Event");
                let mut data = String::new();

                for line in message.lines() {
                    if let Some(t) = line.strip_prefix("event: ") {
                        event_type = t.trim().to_string();
                    } else if let Some(d) = line.strip_prefix("data: ") {
                        data = d.trim().to_string();
                    }
                }

                if !data.is_empty() {
                    // Try to extract a human-readable summary from JSON data
                    let summary = if let Ok(json) = serde_json::from_str::<Value>(&data) {
                        json["message"]
                            .as_str()
                            .or(json["type"].as_str())
                            .unwrap_or(&data)
                            .to_string()
                    } else {
                        data
                    };
                    let _ = tx.send(DataUpdate::Event(event_type, summary)).await;
                }
            }
        }

        // Stream closed — notify UI and schedule reconnect.
        let _ = tx
            .send(DataUpdate::NodeDisconnected {
                retry_in_secs: RETRY_SECS,
            })
            .await;
        tokio::time::sleep(Duration::from_secs(RETRY_SECS)).await;
    }
}

fn apply_data_update(app: &mut App, update: DataUpdate) {
    match update {
        DataUpdate::Stats(stats) => {
            app.stats = stats;
        }
        DataUpdate::Block(block) => {
            if !app.blocks.iter().any(|b| b.height == block.height) {
                // Update TPS history before moving block
                app.tps_history.push_front(block.tx_count as u64);
                while app.tps_history.len() > 60 {
                    app.tps_history.pop_back();
                }
                app.blocks.push_front(block);
                while app.blocks.len() > MAX_BLOCKS {
                    app.blocks.pop_back();
                }
            }
        }
        DataUpdate::Validators(vals) => {
            app.validators = vals;
            app.stats.validator_count = app.validators.len();
            app.stats.total_stake = app.validators.iter().map(|validator| validator.stake).sum();
        }
        DataUpdate::Packages(pkgs) => {
            app.packages = pkgs;
        }
        DataUpdate::Event(event_type, message) => {
            app.push_event(event_type, message);
        }
        DataUpdate::MempoolSnapshot(txs) => {
            app.mempool = txs;
        }
        DataUpdate::Peers(peers) => {
            app.peer_ids = peers;
        }
        DataUpdate::NodeConnected => {
            app.node_connected = true;
            app.last_event_at = Instant::now();
            app.reconnect_in = 0;
        }
        DataUpdate::NodeDisconnected { retry_in_secs } => {
            app.node_connected = false;
            app.reconnect_in = retry_in_secs;
        }
        DataUpdate::Consensus(state) => {
            app.consensus_state = Some(state);
        }
        DataUpdate::FaucetHealth {
            healthy,
            token_reserve,
        } => {
            app.faucet.health = if healthy { "online" } else { "offline" }.into();
            app.faucet.faucet_token_reserve = token_reserve;
        }
        DataUpdate::FaucetNetwork(info) => {
            app.faucet.network = Some(info);
        }
        DataUpdate::FaucetBalance {
            token,
            native,
            token_fmt,
            native_fmt,
        } => {
            let had_data =
                token.is_some() || native.is_some() || token_fmt.is_some() || native_fmt.is_some();
            app.faucet.last_balance = token.clone();
            app.faucet.last_native_balance = native.clone();
            app.faucet.last_balance_fmt = token_fmt.clone();
            app.faucet.last_native_balance_fmt = native_fmt.clone();
            // Prefer the pre-formatted decimal strings for display so the
            // Status line matches what the web explorer shows (no 18-decimal
            // wei blob). Fall back to format_wei() on the raw value if the
            // faucet omitted the formatted field.
            let display_t = token_fmt
                .clone()
                .or_else(|| token.as_deref().map(format_wei))
                .unwrap_or_else(|| "?".into());
            let display_n = native_fmt
                .clone()
                .or_else(|| native.as_deref().map(format_wei))
                .unwrap_or_else(|| "?".into());
            if matches!(app.faucet.status, FaucetStatus::Working { .. }) {
                app.faucet.status = if had_data {
                    FaucetStatus::Success {
                        tx_hash: "(balance fetched)".into(),
                        amount: format!("tCREG={} / ETH={}", display_t, display_n),
                        at: Instant::now(),
                    }
                } else {
                    FaucetStatus::Failed {
                        error: "faucet returned empty balance response".into(),
                        at: Instant::now(),
                    }
                };
            }
        }
        DataUpdate::FaucetError(error) => {
            app.faucet.status = FaucetStatus::Failed {
                error,
                at: Instant::now(),
            };
        }
        DataUpdate::FaucetDripProgress(msg) => {
            if matches!(app.faucet.status, FaucetStatus::Working { .. }) {
                if let FaucetStatus::Working { started_at, .. } = app.faucet.status {
                    app.faucet.status = FaucetStatus::Working {
                        started_at,
                        message: msg,
                    };
                }
            } else {
                app.faucet.status = FaucetStatus::Working {
                    started_at: Instant::now(),
                    message: msg,
                };
            }
        }
        DataUpdate::FaucetDripResult(result) => match result {
            Ok((tx_hash, amount)) => {
                app.faucet.status = FaucetStatus::Success {
                    tx_hash,
                    amount,
                    at: Instant::now(),
                };
            }
            Err(error) => {
                app.faucet.status = FaucetStatus::Failed {
                    error,
                    at: Instant::now(),
                };
            }
        },
        DataUpdate::RuntimeIdentity(identity) => {
            app.runtime_identity = Some(identity);
        }
    }
}

// ============================================================================
// INPUT HANDLING
// ============================================================================

async fn handle_key(app: &mut App, key: KeyCode) -> bool {
    // Handle search mode first
    if app.is_searching {
        match key {
            KeyCode::Esc => app.is_searching = false,
            KeyCode::Enter => app.is_searching = false,
            KeyCode::Char(c) => app.search_query.push(c),
            KeyCode::Backspace => {
                app.search_query.pop();
            }
            _ => {}
        }
        return false;
    }

    // Faucet address input takes precedence over global shortcuts.
    if app.current_view == View::Faucet && app.faucet.editing {
        match key {
            KeyCode::Esc => app.faucet.editing = false,
            KeyCode::Enter => app.faucet.editing = false,
            KeyCode::Backspace => {
                app.faucet.address_input.pop();
            }
            KeyCode::Char(c) => {
                if app.faucet.address_input.len() < 64 {
                    app.faucet.address_input.push(c);
                }
            }
            _ => {}
        }
        return false;
    }

    // Global shortcuts
    match key {
        KeyCode::Char('q') | KeyCode::Char('Q') => return true,
        KeyCode::Char('?') | KeyCode::Char('h') => {
            if app.current_view == View::Help {
                app.current_view = app.previous_view.unwrap_or(View::Overview);
                app.previous_view = None;
            } else {
                app.previous_view = Some(app.current_view);
                app.current_view = View::Help;
            }
            return false;
        }
        KeyCode::Char('/') => {
            app.is_searching = true;
            app.search_query.clear();
            return false;
        }
        KeyCode::Char('1') => app.current_view = View::Overview,
        KeyCode::Char('2') => app.current_view = View::Blocks,
        KeyCode::Char('3') => app.current_view = View::Validators,
        KeyCode::Char('4') => app.current_view = View::Packages,
        KeyCode::Char('5') => app.current_view = View::Network,
        KeyCode::Char('6') => app.current_view = View::Mempool,
        KeyCode::Char('7') => app.current_view = View::Events,
        KeyCode::Char('8') | KeyCode::Char('o') | KeyCode::Char('O') => {
            app.current_view = View::Operator
        }
        KeyCode::Char('9') | KeyCode::Char('c') | KeyCode::Char('C') => {
            app.current_view = View::Consensus
        }
        KeyCode::Char('0') | KeyCode::Char('F') => {
            app.current_view = View::Faucet;
        }
        KeyCode::Char('t') | KeyCode::Char('T') => {
            let current = IS_LIGHT_THEME.load(Ordering::Relaxed);
            IS_LIGHT_THEME.store(!current, Ordering::Relaxed);
            return false;
        }
        _ => {}
    }

    // View-specific navigation
    match app.current_view {
        View::Blocks | View::Overview => match key {
            KeyCode::Down | KeyCode::Char('j') => {
                if app.selected_block < app.blocks.len().saturating_sub(1) {
                    app.selected_block += 1;
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if app.selected_block > 0 {
                    app.selected_block -= 1;
                }
            }
            KeyCode::Enter | KeyCode::Char('d') => {
                if !app.blocks.is_empty() {
                    app.previous_view = Some(app.current_view);
                    app.current_view = View::BlockDetail;
                }
            }
            _ => {}
        },
        View::Validators => match key {
            KeyCode::Down | KeyCode::Char('j') => {
                if app.selected_validator < app.validators.len().saturating_sub(1) {
                    app.selected_validator += 1;
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if app.selected_validator > 0 {
                    app.selected_validator -= 1;
                }
            }
            KeyCode::Enter | KeyCode::Char('d') => {
                if !app.validators.is_empty() {
                    app.previous_view = Some(app.current_view);
                    app.current_view = View::ValidatorDetail;
                }
            }
            _ => {}
        },
        View::Packages => match key {
            KeyCode::Down | KeyCode::Char('j') => {
                if app.selected_package < app.packages.len().saturating_sub(1) {
                    app.selected_package += 1;
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if app.selected_package > 0 {
                    app.selected_package -= 1;
                }
            }
            KeyCode::Enter | KeyCode::Char('d') => {
                if !app.packages.is_empty() {
                    app.previous_view = Some(app.current_view);
                    app.current_view = View::PackageDetail;
                }
            }
            _ => {}
        },
        View::Events => match key {
            KeyCode::Down | KeyCode::Char('j') => {
                if app.selected_event < app.events.len().saturating_sub(1) {
                    app.selected_event += 1;
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if app.selected_event > 0 {
                    app.selected_event -= 1;
                }
            }
            _ => {}
        },
        View::BlockDetail | View::ValidatorDetail | View::PackageDetail => match key {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('b') => {
                app.current_view = app.previous_view.unwrap_or(View::Overview);
                app.previous_view = None;
            }
            _ => {}
        },
        View::Faucet => match key {
            KeyCode::Char('e') | KeyCode::Char('E') | KeyCode::Char('i') => {
                app.faucet.editing = true;
            }
            KeyCode::Char('a') | KeyCode::Char('A') => {
                app.faucet.address_input.clear();
                app.faucet.editing = true;
            }
            KeyCode::Char('b') | KeyCode::Char('B') => {
                let addr = app.faucet.address_input.trim().to_string();
                if !crate::faucet_client::is_valid_evm_address(&addr) {
                    app.faucet.status = FaucetStatus::Failed {
                        error: "Enter a valid 0x… address first (press 'e' to edit).".into(),
                        at: Instant::now(),
                    };
                } else {
                    app.faucet.status = FaucetStatus::Working {
                        started_at: Instant::now(),
                        message: "Fetching balance…".into(),
                    };
                    let tx = app.data_tx.clone();
                    let base = app.faucet.base.clone();
                    tokio::spawn(async move {
                        let client = reqwest::Client::new();
                        match crate::faucet_client::get_balance(&client, &base, &addr).await {
                            Ok(bal) => {
                                let _ = tx
                                    .send(DataUpdate::FaucetBalance {
                                        token: bal.balance,
                                        native: bal.native_balance,
                                        token_fmt: bal.balance_formatted,
                                        native_fmt: bal.native_balance_formatted,
                                    })
                                    .await;
                            }
                            Err(e) => {
                                let _ = tx
                                    .send(DataUpdate::FaucetError(format!(
                                        "balance fetch failed: {}",
                                        e
                                    )))
                                    .await;
                            }
                        }
                    });
                }
            }
            KeyCode::Char('d') | KeyCode::Char('D') | KeyCode::Enter => {
                let addr = app.faucet.address_input.trim().to_string();
                if !crate::faucet_client::is_valid_evm_address(&addr) {
                    app.faucet.status = FaucetStatus::Failed {
                        error: "Enter a valid 0x… address first (press 'e' to edit).".into(),
                        at: Instant::now(),
                    };
                } else if matches!(app.faucet.status, FaucetStatus::Working { .. }) {
                    // Already running — ignore
                } else {
                    app.faucet.status = FaucetStatus::Working {
                        started_at: Instant::now(),
                        message: "Requesting PoW challenge…".into(),
                    };
                    let tx = app.data_tx.clone();
                    let base = app.faucet.base.clone();
                    tokio::spawn(async move {
                        run_faucet_drip(tx, base, addr).await;
                    });
                }
            }
            _ => {}
        },
        _ => {}
    }

    false
}

fn handle_mouse(app: &mut App, mouse: crossterm::event::MouseEvent) {
    match mouse.kind {
        MouseEventKind::Down(crossterm::event::MouseButton::Left) => {
            let row = mouse.row;
            if row == 2 || row == 3 || row == 4 {
                // Approximate header area
                match mouse.column {
                    0..=12 => app.current_view = View::Overview,
                    13..=23 => app.current_view = View::Blocks,
                    24..=38 => app.current_view = View::Validators,
                    39..=51 => app.current_view = View::Packages,
                    52..=63 => app.current_view = View::Network,
                    64..=75 => app.current_view = View::Mempool,
                    76..=86 => app.current_view = View::Events,
                    87..=99 => app.current_view = View::Operator,
                    100..=113 => app.current_view = View::Consensus,
                    114..=124 => app.current_view = View::Faucet,
                    125..=136 => {
                        app.current_view = View::Overview;
                        app.is_searching = true;
                    }
                    137..=145 => app.current_view = View::Bridge,
                    146..=160 => app.current_view = View::Metrics,
                    _ => {}
                }
            } else if row >= 6 {
                // Approximate row selection based on current view
                let index = (row - 6) as usize;
                match app.current_view {
                    View::Blocks | View::Overview => {
                        if index < app.blocks.len() {
                            app.selected_block = index;
                            app.previous_view = Some(app.current_view);
                            app.current_view = View::BlockDetail;
                        }
                    }
                    View::Validators => {
                        if index < app.validators.len() {
                            app.selected_validator = index;
                            app.previous_view = Some(app.current_view);
                            app.current_view = View::ValidatorDetail;
                        }
                    }
                    View::Packages => {
                        if index < app.packages.len() {
                            app.selected_package = index;
                            app.previous_view = Some(app.current_view);
                            app.current_view = View::PackageDetail;
                        }
                    }
                    _ => {}
                }
            }
        }
        MouseEventKind::ScrollDown => match app.current_view {
            View::Blocks | View::Overview => {
                if app.selected_block < app.blocks.len().saturating_sub(1) {
                    app.selected_block += 1;
                }
            }
            View::Validators => {
                if app.selected_validator < app.validators.len().saturating_sub(1) {
                    app.selected_validator += 1;
                }
            }
            View::Events => {
                if app.selected_event < app.events.len().saturating_sub(1) {
                    app.selected_event += 1;
                }
            }
            _ => {}
        },
        MouseEventKind::ScrollUp => match app.current_view {
            View::Blocks | View::Overview => {
                if app.selected_block > 0 {
                    app.selected_block -= 1;
                }
            }
            View::Validators => {
                if app.selected_validator > 0 {
                    app.selected_validator -= 1;
                }
            }
            View::Events => {
                if app.selected_event > 0 {
                    app.selected_event -= 1;
                }
            }
            _ => {}
        },
        _ => {}
    }
}

// ============================================================================
// UI RENDERING
// ============================================================================

fn draw_ui(f: &mut Frame, app: &App) {
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(0),    // Main content
            Constraint::Length(3), // Footer
        ])
        .split(f.size());

    draw_header(f, app, main_chunks[0]);
    draw_main_content(f, app, main_chunks[1]);
    draw_footer(f, app, main_chunks[2]);

    if app.is_searching {
        draw_search_popup(f, app);
    }

    if !app.node_connected {
        draw_disconnect_banner(f, app);
    }
}

fn draw_consensus(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(" ⚙  PBFT Consensus Round ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Theme::primary()));

    let inner = block.inner(area);
    f.render_widget(block, area);

    match &app.consensus_state {
        None => {
            let msg = Paragraph::new("Fetching consensus state…")
                .style(Style::default().fg(Theme::text_dim()))
                .alignment(Alignment::Center);
            f.render_widget(msg, inner);
        }
        Some(cs) => {
            // Phase colour
            let phase_color = match cs.phase.as_str() {
                "PRE-PREPARE" => Color::Cyan,
                "PREPARE" => Color::Yellow,
                "COMMIT" => Color::Green,
                "FINALIZED" => Color::LightGreen,
                _ => Color::Gray,
            };

            // Quorum gauge for PREPARE votes
            let prepare_pct = if cs.quorum > 0 {
                (cs.prepare_votes as f64 / cs.quorum as f64 * 100.0).min(100.0) as u16
            } else {
                0
            };
            let commit_pct = if cs.quorum > 0 {
                (cs.commit_votes as f64 / cs.quorum as f64 * 100.0).min(100.0) as u16
            } else {
                0
            };

            let age_secs = cs.fetched_at.elapsed().as_secs();

            // Pre-compute display strings so we don't reference temporaries.
            let round_str = format!("#{}", cs.round);
            let val_str = format!("{}", cs.total_validators);
            let quorum_str = format!("{}", cs.quorum);
            let prepare_str = format!("{}/{} ({}%)", cs.prepare_votes, cs.quorum, prepare_pct);
            let commit_str = format!("{}/{} ({}%)", cs.commit_votes, cs.quorum, commit_pct);
            let age_str = format!("{}s ago", age_secs);

            let rows = vec![
                Row::new(vec!["Round", round_str.as_str()])
                    .style(Style::default().fg(Theme::text())),
                Row::new(vec!["Phase", cs.phase.as_str()]).style(
                    Style::default()
                        .fg(phase_color)
                        .add_modifier(Modifier::BOLD),
                ),
                Row::new(vec!["Proposer", cs.proposer.as_str()])
                    .style(Style::default().fg(Theme::accent())),
                Row::new(vec!["Validators", val_str.as_str()])
                    .style(Style::default().fg(Theme::text())),
                Row::new(vec!["Quorum (2f+1)", quorum_str.as_str()])
                    .style(Style::default().fg(Theme::text())),
                Row::new(vec!["PREPARE votes", prepare_str.as_str()]).style(Style::default().fg(
                    if prepare_pct >= 100 {
                        Color::Green
                    } else {
                        Color::Yellow
                    },
                )),
                Row::new(vec!["COMMIT votes", commit_str.as_str()]).style(Style::default().fg(
                    if commit_pct >= 100 {
                        Color::Green
                    } else {
                        Color::Yellow
                    },
                )),
                Row::new(vec!["Snapshot age", age_str.as_str()])
                    .style(Style::default().fg(Theme::text_dim())),
            ];

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(rows.len() as u16 + 2),
                    Constraint::Length(3),
                    Constraint::Length(3),
                    Constraint::Min(0),
                ])
                .split(inner);

            let table = Table::new(
                rows,
                [Constraint::Percentage(35), Constraint::Percentage(65)],
            )
            .block(Block::default().borders(Borders::NONE))
            .header(
                Row::new(vec!["Field", "Value"]).style(
                    Style::default()
                        .fg(Theme::text_dim())
                        .add_modifier(Modifier::BOLD),
                ),
            );
            f.render_widget(table, chunks[0]);

            // PREPARE progress bar
            let prepare_gauge = Gauge::default()
                .block(
                    Block::default()
                        .title(" PREPARE votes ")
                        .borders(Borders::ALL),
                )
                .gauge_style(Style::default().fg(Color::Yellow))
                .percent(prepare_pct);
            f.render_widget(prepare_gauge, chunks[1]);

            // COMMIT progress bar
            let commit_gauge = Gauge::default()
                .block(
                    Block::default()
                        .title(" COMMIT votes ")
                        .borders(Borders::ALL),
                )
                .gauge_style(Style::default().fg(Color::Green))
                .percent(commit_pct);
            f.render_widget(commit_gauge, chunks[2]);
        }
    }
}

fn draw_disconnect_banner(f: &mut Frame, app: &App) {
    let area = f.size();
    // Center a 3-row × 50-col banner at the top of the screen.
    let width: u16 = 54.min(area.width);
    let x = area.x + area.width.saturating_sub(width) / 2;
    let banner_area = Rect {
        x,
        y: area.y,
        width,
        height: 3,
    };

    let msg = if app.reconnect_in > 0 {
        format!(
            " ⚠  NODE DISCONNECTED — reconnecting in {}s ",
            app.reconnect_in
        )
    } else {
        " ⚠  NODE DISCONNECTED — reconnecting… ".to_string()
    };

    f.render_widget(Clear, banner_area);
    let banner = Paragraph::new(msg)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Red)),
        )
        .style(
            Style::default()
                .fg(Color::White)
                .bg(Color::Red)
                .add_modifier(Modifier::BOLD),
        )
        .alignment(Alignment::Center);
    f.render_widget(banner, banner_area);
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    // Title with logo-like styling
    let title = format!(
        " ⛓ CHAIN REGISTRY CONSOLE   |  Height: #{}  |  {} Packages  |  {} Peers ",
        app.stats.tip_height,
        format_number(app.stats.package_count),
        app.stats.peer_count
    );

    let header = Paragraph::new(title)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Theme::primary())),
        )
        .style(
            Style::default()
                .fg(Theme::text())
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(header, chunks[0]);

    // Status indicator
    let validator_count = app.displayed_validator_count();
    let total_stake = app.displayed_total_stake();

    let status_color = if validator_count > 0 {
        Theme::success()
    } else {
        Theme::warning()
    };

    let status_text = format!(
        " ● {} Validators  |  Total Stake: {} CREG  |  Bridge: {} ",
        validator_count,
        format_number(total_stake),
        if app.stats.bridge_status.len() > 15 {
            format!("{}..", &app.stats.bridge_status[..15])
        } else {
            app.stats.bridge_status.clone()
        }
    );

    let status = Paragraph::new(status_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(status_color)),
        )
        .style(Style::default().fg(Theme::text()))
        .alignment(Alignment::Right);
    f.render_widget(status, chunks[1]);
}

fn draw_main_content(f: &mut Frame, app: &App, area: Rect) {
    match app.current_view {
        View::Overview => draw_overview(f, app, area),
        View::Blocks => draw_blocks(f, app, area),
        View::BlockDetail => draw_block_detail(f, app, area),
        View::Validators => draw_validators(f, app, area),
        View::ValidatorDetail => draw_validator_detail(f, app, area),
        View::Packages => draw_packages(f, app, area),
        View::PackageDetail => draw_package_detail(f, app, area),
        View::Network => draw_network(f, app, area),
        View::Mempool => draw_mempool(f, app, area),
        View::Events => draw_events(f, app, area),
        View::Operator => draw_operator(f, app, area),
        View::Consensus => draw_consensus(f, app, area),
        View::Faucet => draw_faucet(f, app, area),
        View::Bridge => draw_bridge(f, app, area),
        View::Metrics => draw_metrics(f, app, area),
        View::Help => draw_help(f, app, area),
    }
}

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    let text = match app.current_view {
        View::Overview => " [←/↑/↓/→ or h/j/k/l] Navigate | [Enter/d] Detail | [1-8] Views | [o] Operator | [/] Search | [?] Help | [q] Quit ",
        View::Blocks => " [j/k] Navigate blocks | [Enter/d] Block detail | [b] Back | [?] Help | [q] Quit ",
        View::Validators => " [j/k] Navigate | [Enter/d] Validator detail | [b] Back | [?] Help | [q] Quit ",
        View::Packages => " [j/k] Navigate | [Enter/d] Package detail | [b] Back | [?] Help | [q] Quit ",
        View::Events => " [j/k] Scroll | [b] Back | [?] Help | [q] Quit ",
        View::Operator => " [1-8/o] Switch views | [q] Quit | Browser explorer at http://localhost:3007 ",
        View::Consensus => " [9/c] Consensus | [r] Refresh | [q] Quit ",
        View::Faucet => " [e] Edit address | [d/Enter] Drip | [b] Balance | [a] Clear | [Esc] Stop editing | [q] Quit ",
        View::BlockDetail | View::ValidatorDetail | View::PackageDetail => " [Esc/q/b] Back | [?] Help ",
        View::Help => " [Any key] Return ",
        _ => " [←→↑↓] Navigate | [?] Help | [q] Quit ",
    };

    let footer = Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL))
        .style(Style::default().fg(Theme::text_dim()))
        .alignment(Alignment::Center);
    f.render_widget(footer, area);
}

// ============================================================================
// VIEW: OVERVIEW
// ============================================================================

fn draw_overview(f: &mut Frame, app: &App, area: Rect) {
    let validator_count = app.displayed_validator_count();
    let total_stake = app.displayed_total_stake();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(12), // Stats cards
            Constraint::Min(10),    // Main split
            Constraint::Length(10), // Events feed
        ])
        .split(area);

    // Stats row
    let stats_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(chunks[0]);

    draw_stat_card(
        f,
        "BLOCK HEIGHT",
        &format!("#{}", app.stats.tip_height),
        Theme::primary(),
        stats_chunks[0],
    );
    draw_stat_card(
        f,
        "PACKAGES",
        &format_number(app.stats.package_count),
        Theme::success(),
        stats_chunks[1],
    );
    draw_stat_card(
        f,
        "VALIDATORS",
        &validator_count.to_string(),
        Theme::accent(),
        stats_chunks[2],
    );
    draw_stat_card(
        f,
        "TOTAL STAKE",
        &format!("{} CREG", format_number(total_stake)),
        Theme::warning(),
        stats_chunks[3],
    );

    // Main content split
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(chunks[1]);

    // Left: Recent blocks
    draw_blocks_list(f, app, main_chunks[0], true);

    // Right: Validator preview + TPS sparkline
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(main_chunks[1]);

    draw_validators_preview(f, app, right_chunks[0]);
    draw_tps_sparkline(f, app, right_chunks[1]);

    // Bottom: Event feed
    draw_event_feed(f, app, chunks[2]);
}

fn draw_stat_card(f: &mut Frame, label: &str, value: &str, color: Color, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(color));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let text = vec![
        Line::from(Span::styled(label, Style::default().fg(Theme::text_dim()))),
        Line::from(""),
        Line::from(Span::styled(
            value,
            Style::default()
                .fg(color)
                .add_modifier(Modifier::BOLD)
                .add_modifier(Modifier::UNDERLINED),
        )),
    ];

    let paragraph = Paragraph::new(text).alignment(Alignment::Center);
    f.render_widget(paragraph, inner);
}

fn draw_tps_sparkline(f: &mut Frame, app: &App, area: Rect) {
    let data: Vec<u64> = app.tps_history.iter().copied().collect();
    let max = data.iter().max().copied().unwrap_or(1).max(1);

    let sparkline = Sparkline::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" TRANSACTIONS PER BLOCK ")
                .border_style(Style::default().fg(Theme::secondary())),
        )
        .data(&data)
        .max(max)
        .style(Style::default().fg(Theme::success()));

    f.render_widget(sparkline, area);
}

fn draw_event_feed(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .events
        .iter()
        .take(8)
        .map(|(time, event_type, msg)| {
            let elapsed = time.elapsed().as_secs();
            let time_str = if elapsed < 60 {
                format!("{}s", elapsed)
            } else if elapsed < 3600 {
                format!("{}m", elapsed / 60)
            } else {
                format!("{}h", elapsed / 3600)
            };

            let color = match event_type.as_str() {
                "Block" => Theme::success(),
                "Package" => Theme::primary(),
                "Validator" => Theme::accent(),
                "Slash" => Theme::error(),
                _ => Theme::text_dim(),
            };

            let content = format!("[{:>3}] {:<10} {}", time_str, event_type, msg);
            ListItem::new(content).style(Style::default().fg(color))
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" LIVE EVENTS ")
            .border_style(Style::default().fg(Theme::success())),
    );

    f.render_widget(list, area);
}

// ============================================================================
// VIEW: BLOCKS
// ============================================================================

fn draw_blocks(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    draw_blocks_list(f, app, chunks[0], false);
    draw_block_preview(f, app, chunks[1]);
}

fn draw_blocks_list(f: &mut Frame, app: &App, area: Rect, compact: bool) {
    let query = app.search_query.to_ascii_lowercase();
    let title = if compact {
        " RECENT BLOCKS "
    } else if query.is_empty() {
        " BLOCKS (j/k to navigate, Enter for details) "
    } else {
        " BLOCKS (filtered) "
    };

    let items: Vec<ListItem> = app
        .blocks
        .iter()
        .enumerate()
        .filter(|(_i, block)| {
            if query.is_empty() {
                return true;
            }
            let height_str = block.height.to_string();
            height_str.contains(&query)
                || block.hash.to_ascii_lowercase().contains(&query)
                || block.merkle_root.to_ascii_lowercase().contains(&query)
                || block.proposer.to_ascii_lowercase().contains(&query)
        })
        .map(|(i, block)| {
            let hash_short = if block.hash.len() >= 16 {
                format!("{}..", &block.hash[..16])
            } else if block.hash.is_empty() {
                if block.merkle_root.len() >= 16 {
                    format!("{}..", &block.merkle_root[..16])
                } else {
                    block.merkle_root.clone()
                }
            } else {
                block.hash.clone()
            };

            let content = if compact {
                format!(
                    "#{:<6} {}  {} txs",
                    block.height, hash_short, block.tx_count
                )
            } else {
                let time_str = format_timestamp(&block.timestamp);
                format!(
                    "#{:<8} {:<20} {:<12} {:>6} txs  {}",
                    block.height,
                    hash_short,
                    block.proposer.chars().take(12).collect::<String>(),
                    block.tx_count,
                    time_str
                )
            };

            let style = if i == app.selected_block {
                Style::default()
                    .fg(Theme::highlight())
                    .add_modifier(Modifier::BOLD)
                    .add_modifier(Modifier::REVERSED)
            } else {
                Style::default().fg(Theme::text())
            };

            ListItem::new(content).style(style)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(Style::default().fg(Theme::primary())),
    );

    f.render_widget(list, area);
}

fn draw_block_preview(f: &mut Frame, app: &App, area: Rect) {
    let block = match app.selected_block() {
        Some(b) => b,
        None => {
            let empty = Paragraph::new("No block selected").block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" BLOCK DETAILS "),
            );
            f.render_widget(empty, area);
            return;
        }
    };

    let text = vec![
        Line::from(vec![
            Span::styled("Height: ", Style::default().fg(Theme::text_dim())),
            Span::styled(
                format!("#{}", block.height),
                Style::default()
                    .fg(Theme::primary())
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Block Hash:  ", Style::default().fg(Theme::text_dim())),
            Span::raw(&block.hash),
        ]),
        Line::from(vec![
            Span::styled("Merkle Root: ", Style::default().fg(Theme::text_dim())),
            Span::raw(&block.merkle_root),
        ]),
        Line::from(vec![
            Span::styled("Proposer: ", Style::default().fg(Theme::text_dim())),
            Span::raw(&block.proposer),
        ]),
        Line::from(vec![
            Span::styled("Transactions: ", Style::default().fg(Theme::text_dim())),
            Span::styled(
                block.tx_count.to_string(),
                Style::default().fg(Theme::success()),
            ),
        ]),
        Line::from(vec![
            Span::styled("Timestamp: ", Style::default().fg(Theme::text_dim())),
            Span::raw(format_timestamp(&block.timestamp)),
        ]),
    ];

    let paragraph = Paragraph::new(text).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" BLOCK PREVIEW ")
            .border_style(Style::default().fg(Theme::primary())),
    );

    f.render_widget(paragraph, area);
}

fn draw_block_detail(f: &mut Frame, app: &App, area: Rect) {
    let block = match app.selected_block() {
        Some(b) => b,
        None => return,
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(10), Constraint::Min(0)])
        .split(area);

    // Block header info
    let header_text = vec![
        Line::from(vec![
            Span::styled("Block #", Style::default().fg(Theme::text_dim())),
            Span::styled(
                block.height.to_string(),
                Style::default()
                    .fg(Theme::primary())
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Block Hash:  ", Style::default().fg(Theme::text_dim())),
            Span::raw(&block.hash),
        ]),
        Line::from(vec![
            Span::styled("Merkle Root: ", Style::default().fg(Theme::text_dim())),
            Span::raw(&block.merkle_root),
        ]),
        Line::from(vec![
            Span::styled("Proposer:    ", Style::default().fg(Theme::text_dim())),
            Span::styled(&block.proposer, Style::default().fg(Theme::accent())),
        ]),
        Line::from(vec![
            Span::styled("Timestamp:   ", Style::default().fg(Theme::text_dim())),
            Span::raw(format_timestamp(&block.timestamp)),
        ]),
        Line::from(vec![
            Span::styled("Transactions:", Style::default().fg(Theme::text_dim())),
            Span::styled(
                block.tx_count.to_string(),
                Style::default().fg(Theme::success()),
            ),
        ]),
    ];

    let header = Paragraph::new(header_text).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" BLOCK HEADER ")
            .border_style(Style::default().fg(Theme::primary())),
    );
    f.render_widget(header, chunks[0]);

    // Transactions table
    let rows: Vec<Row> = block
        .transactions
        .iter()
        .map(|tx| {
            Row::new(vec![
                Cell::from(tx.tx_type.clone()).style(Style::default().fg(Theme::primary())),
                Cell::from(tx.package_name.clone().unwrap_or_default()),
                Cell::from(tx.package_version.clone().unwrap_or_default()),
                Cell::from(tx.publisher.clone().unwrap_or_default()),
                Cell::from(tx.status.clone()).style(Style::default().fg(Theme::success())),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(12),
            Constraint::Percentage(30),
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Length(12),
        ],
    )
    .header(
        Row::new(vec!["Type", "Package", "Version", "Publisher", "Status"]).style(
            Style::default()
                .fg(Theme::text_dim())
                .add_modifier(Modifier::BOLD),
        ),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" TRANSACTIONS ({}) ", block.tx_count))
            .border_style(Style::default().fg(Theme::secondary())),
    );

    f.render_widget(table, chunks[1]);
}

// ============================================================================
// VIEW: VALIDATORS
// ============================================================================

fn draw_validators(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(area);

    // Validators table
    let query = app.search_query.to_ascii_lowercase();
    let rows: Vec<Row> = app
        .validators
        .iter()
        .enumerate()
        .filter(|(_i, v)| {
            if query.is_empty() {
                return true;
            }
            v.id.to_ascii_lowercase().contains(&query)
                || v.alias.to_ascii_lowercase().contains(&query)
                || v.status.to_ascii_lowercase().contains(&query)
        })
        .map(|(i, v)| {
            let status_color = match v.status.as_str() {
                "online" | "self" => Theme::success(),
                "pending" => Theme::warning(),
                _ => Theme::error(),
            };

            let style = if i == app.selected_validator {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };

            let rep_bar = render_reputation_bar(v.reputation);

            Row::new(vec![
                Cell::from(if v.alias.is_empty() {
                    v.id.clone()
                } else {
                    format!("{} ({})", v.id, v.alias)
                }),
                Cell::from(format!("{} CREG", format_number(v.stake))),
                Cell::from(rep_bar),
                Cell::from(v.status.clone()).style(Style::default().fg(status_color)),
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(30),
            Constraint::Percentage(25),
            Constraint::Percentage(30),
            Constraint::Percentage(15),
        ],
    )
    .header(
        Row::new(vec!["Validator", "Stake", "Reputation", "Status"]).style(
            Style::default()
                .fg(Theme::text_dim())
                .add_modifier(Modifier::BOLD),
        ),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" VALIDATORS (j/k to navigate, Enter for details) ")
            .border_style(Style::default().fg(Theme::accent())),
    );

    f.render_widget(table, chunks[0]);

    // Validator stats sidebar
    draw_validator_stats(f, app, chunks[1]);
}

fn draw_validators_preview(f: &mut Frame, app: &App, area: Rect) {
    let rows: Vec<Row> = app
        .validators
        .iter()
        .take(10)
        .map(|v| {
            let status_color = match v.status.as_str() {
                "online" | "self" => Theme::success(),
                _ => Theme::text_dim(),
            };

            Row::new(vec![
                Cell::from(v.id.chars().take(20).collect::<String>()),
                Cell::from(format!("{}", v.stake / 1_000_000_000)),
                Cell::from(format!("{}", v.reputation)).style(Style::default().fg(status_color)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(60),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
        ],
    )
    .header(
        Row::new(vec!["Validator", "Stake(k)", "Rep"])
            .style(Style::default().fg(Theme::text_dim())),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" TOP VALIDATORS ")
            .border_style(Style::default().fg(Theme::accent())),
    );

    f.render_widget(table, area);
}

fn draw_validator_stats(f: &mut Frame, app: &App, area: Rect) {
    let active_count = app.validators.iter().filter(|v| v.is_active).count();
    let avg_reputation = if !app.validators.is_empty() {
        app.validators
            .iter()
            .map(|v| v.reputation as u64)
            .sum::<u64>()
            / app.validators.len() as u64
    } else {
        0
    };

    let text = vec![
        Line::from(vec![
            Span::styled("Total: ", Style::default().fg(Theme::text_dim())),
            Span::styled(
                app.validators.len().to_string(),
                Style::default().fg(Theme::text()),
            ),
        ]),
        Line::from(vec![
            Span::styled("Active: ", Style::default().fg(Theme::text_dim())),
            Span::styled(
                active_count.to_string(),
                Style::default().fg(Theme::success()),
            ),
        ]),
        Line::from(vec![
            Span::styled("Avg Rep: ", Style::default().fg(Theme::text_dim())),
            Span::styled(
                format!("{}/100", avg_reputation),
                Style::default().fg(Theme::warning()),
            ),
        ]),
    ];

    let stats = Paragraph::new(text).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" STATS ")
            .border_style(Style::default().fg(Theme::accent())),
    );

    f.render_widget(stats, area);
}

fn draw_validator_detail(f: &mut Frame, app: &App, area: Rect) {
    let validator = match app.selected_validator() {
        Some(v) => v,
        None => return,
    };

    let status_color = match validator.status.as_str() {
        "online" | "self" => Theme::success(),
        "pending" => Theme::warning(),
        _ => Theme::error(),
    };

    let text = vec![
        Line::from(vec![Span::styled(
            "VALIDATOR DETAILS\n",
            Style::default()
                .fg(Theme::accent())
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled("ID:          ", Style::default().fg(Theme::text_dim())),
            Span::styled(
                &validator.id,
                Style::default()
                    .fg(Theme::text())
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Alias:       ", Style::default().fg(Theme::text_dim())),
            Span::raw(&validator.alias),
        ]),
        Line::from(vec![
            Span::styled("Public Key:  ", Style::default().fg(Theme::text_dim())),
            Span::raw(format!(
                "{}..",
                &validator.pub_key[..validator.pub_key.len().min(40)]
            )),
        ]),
        Line::from(vec![
            Span::styled("Stake:       ", Style::default().fg(Theme::text_dim())),
            Span::styled(
                format!("{} CREG", format_number(validator.stake)),
                Style::default().fg(Theme::success()),
            ),
        ]),
        Line::from(vec![
            Span::styled("Reputation:  ", Style::default().fg(Theme::text_dim())),
            Span::styled(
                format!("{}/100", validator.reputation),
                Style::default().fg(Theme::warning()),
            ),
        ]),
        Line::from(vec![
            Span::styled("Status:      ", Style::default().fg(Theme::text_dim())),
            Span::styled(&validator.status, Style::default().fg(status_color)),
        ]),
        Line::from(vec![
            Span::styled("Active:      ", Style::default().fg(Theme::text_dim())),
            Span::styled(
                if validator.is_active { "Yes" } else { "No" },
                Style::default().fg(if validator.is_active {
                    Theme::success()
                } else {
                    Theme::error()
                }),
            ),
        ]),
    ];

    let paragraph = Paragraph::new(text).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" VALIDATOR ")
            .border_style(Style::default().fg(Theme::accent())),
    );

    f.render_widget(paragraph, area);
}

fn render_reputation_bar(reputation: u8) -> String {
    let filled = (reputation / 10) as usize;
    let empty = 10 - filled;
    let bar = "█".repeat(filled) + &"░".repeat(empty);
    format!("{} {}%", bar, reputation)
}

// ============================================================================
// VIEW: PACKAGES
// ============================================================================

fn draw_packages(f: &mut Frame, app: &App, area: Rect) {
    if app.packages.is_empty() {
        let text = Paragraph::new(
            "No packages found. Packages will appear here when published to the registry.",
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" PACKAGES ({} on-chain) ", app.stats.package_count))
                .border_style(Style::default().fg(Theme::primary())),
        )
        .style(Style::default().fg(Theme::text_dim()));
        f.render_widget(text, area);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    let query = app.search_query.to_ascii_lowercase();
    let items: Vec<ListItem> = app
        .packages
        .iter()
        .enumerate()
        .filter(|(_i, pkg)| {
            if query.is_empty() {
                return true;
            }
            pkg.name.to_ascii_lowercase().contains(&query)
                || pkg.ecosystem.to_ascii_lowercase().contains(&query)
                || pkg.version.to_ascii_lowercase().contains(&query)
                || pkg.publisher.to_ascii_lowercase().contains(&query)
                || pkg.status.to_ascii_lowercase().contains(&query)
        })
        .map(|(i, pkg)| {
            let icon = match pkg.status.as_str() {
                "verified" => "✓",
                "pending" => "⏳",
                "rejected" => "✗",
                _ => "?",
            };
            let content = format!(
                "{} {:<30} {:<12} {}",
                icon, pkg.name, pkg.version, pkg.status
            );
            let style = if i == app.selected_package {
                Style::default()
                    .fg(Theme::highlight())
                    .add_modifier(Modifier::BOLD)
                    .add_modifier(Modifier::REVERSED)
            } else {
                let color = match pkg.status.as_str() {
                    "verified" => Theme::success(),
                    "pending" => Theme::warning(),
                    "rejected" => Theme::error(),
                    _ => Theme::text(),
                };
                Style::default().fg(color)
            };
            ListItem::new(content).style(style)
        })
        .collect();

    let pkg_title = if query.is_empty() {
        format!(
            " PACKAGES ({}) — j/k to navigate, Enter for details ",
            app.packages.len()
        )
    } else {
        format!(
            " PACKAGES (filtered: {}/{}) ",
            items.len(),
            app.packages.len()
        )
    };
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(pkg_title)
            .border_style(Style::default().fg(Theme::primary())),
    );
    f.render_widget(list, chunks[0]);

    // Package detail preview
    match app.selected_package() {
        Some(pkg) => {
            let text = vec![
                Line::from(vec![
                    Span::styled("Name:       ", Style::default().fg(Theme::text_dim())),
                    Span::styled(
                        &pkg.name,
                        Style::default()
                            .fg(Theme::primary())
                            .add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Version:    ", Style::default().fg(Theme::text_dim())),
                    Span::raw(&pkg.version),
                ]),
                Line::from(vec![
                    Span::styled("Ecosystem:  ", Style::default().fg(Theme::text_dim())),
                    Span::raw(&pkg.ecosystem),
                ]),
                Line::from(vec![
                    Span::styled("Status:     ", Style::default().fg(Theme::text_dim())),
                    Span::styled(
                        &pkg.status,
                        Style::default().fg(match pkg.status.as_str() {
                            "verified" => Theme::success(),
                            "pending" => Theme::warning(),
                            _ => Theme::error(),
                        }),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Publisher:  ", Style::default().fg(Theme::text_dim())),
                    Span::raw(if pkg.publisher.len() > 16 {
                        format!("{}...", &pkg.publisher[..16])
                    } else {
                        pkg.publisher.clone()
                    }),
                ]),
                Line::from(vec![
                    Span::styled("Hash:       ", Style::default().fg(Theme::text_dim())),
                    Span::raw(if pkg.content_hash.len() > 20 {
                        format!("{}...", &pkg.content_hash[..20])
                    } else {
                        pkg.content_hash.clone()
                    }),
                ]),
            ];
            let detail = Paragraph::new(text).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" PACKAGE PREVIEW ")
                    .border_style(Style::default().fg(Theme::primary())),
            );
            f.render_widget(detail, chunks[1]);
        }
        None => {
            let empty = Paragraph::new("Select a package to see details")
                .style(Style::default().fg(Theme::text_dim()))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" PACKAGE PREVIEW ")
                        .border_style(Style::default().fg(Theme::primary())),
                );
            f.render_widget(empty, chunks[1]);
        }
    }
}

fn draw_package_detail(f: &mut Frame, app: &App, area: Rect) {
    let pkg = match app.selected_package() {
        Some(p) => p,
        None => return,
    };

    let text = vec![
        Line::from(vec![Span::styled(
            "PACKAGE DETAILS\n",
            Style::default()
                .fg(Theme::primary())
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Name:         ", Style::default().fg(Theme::text_dim())),
            Span::styled(
                &pkg.name,
                Style::default()
                    .fg(Theme::text())
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Version:      ", Style::default().fg(Theme::text_dim())),
            Span::raw(&pkg.version),
        ]),
        Line::from(vec![
            Span::styled("Ecosystem:    ", Style::default().fg(Theme::text_dim())),
            Span::raw(&pkg.ecosystem),
        ]),
        Line::from(vec![
            Span::styled("Status:       ", Style::default().fg(Theme::text_dim())),
            Span::styled(
                &pkg.status,
                Style::default().fg(match pkg.status.as_str() {
                    "verified" => Theme::success(),
                    "pending" => Theme::warning(),
                    _ => Theme::error(),
                }),
            ),
        ]),
        Line::from(vec![
            Span::styled("Publisher:    ", Style::default().fg(Theme::text_dim())),
            Span::raw(&pkg.publisher),
        ]),
        Line::from(vec![
            Span::styled("Content Hash: ", Style::default().fg(Theme::text_dim())),
            Span::raw(&pkg.content_hash),
        ]),
        Line::from(vec![
            Span::styled("Verified At:  ", Style::default().fg(Theme::text_dim())),
            Span::raw(pkg.verified_at.as_deref().unwrap_or("Not yet")),
        ]),
    ];

    let paragraph = Paragraph::new(text).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" PACKAGE ")
            .border_style(Style::default().fg(Theme::primary())),
    );
    f.render_widget(paragraph, area);
}

// ============================================================================
// VIEW: NETWORK
// ============================================================================

fn draw_network(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(10), Constraint::Min(0)])
        .split(area);

    // Network stats
    let stats_text = vec![
        Line::from(vec![
            Span::styled("Connected Peers: ", Style::default().fg(Theme::text_dim())),
            Span::styled(
                app.stats.peer_count.to_string(),
                Style::default().fg(Theme::success()),
            ),
        ]),
        Line::from(vec![
            Span::styled("Bridge Status:   ", Style::default().fg(Theme::text_dim())),
            Span::styled(
                &app.stats.bridge_status,
                Style::default().fg(Theme::primary()),
            ),
        ]),
        Line::from(vec![
            Span::styled("L1 Block:        ", Style::default().fg(Theme::text_dim())),
            Span::styled(
                format!("#{}", app.stats.l1_block),
                Style::default().fg(Theme::warning()),
            ),
        ]),
    ];

    let stats = Paragraph::new(stats_text).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" NETWORK STATUS ")
            .border_style(Style::default().fg(Theme::secondary())),
    );
    f.render_widget(stats, chunks[0]);

    // Peer list
    let peers: Vec<ListItem> = app
        .peer_ids
        .iter()
        .map(|p| ListItem::new(format!("● {}", p)).style(Style::default().fg(Theme::success())))
        .collect();

    let peer_list = List::new(peers).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" CONNECTED PEERS ")
            .border_style(Style::default().fg(Theme::secondary())),
    );

    f.render_widget(peer_list, chunks[1]);
}

// ============================================================================
// VIEW: MEMPOOL
// ============================================================================

fn draw_mempool(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);

    // Header with count
    let header_text = format!(
        " {} pending transactions waiting for validator consensus",
        app.mempool.len()
    );
    let header = Paragraph::new(header_text)
        .style(Style::default().fg(Theme::text()))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" MEMPOOL ")
                .border_style(Style::default().fg(Theme::warning())),
        );
    f.render_widget(header, chunks[0]);

    if app.mempool.is_empty() {
        let empty = Paragraph::new("  No pending transactions — mempool is empty")
            .style(Style::default().fg(Theme::text_dim()))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Theme::border())),
            );
        f.render_widget(empty, chunks[1]);
        return;
    }

    // Table of mempool entries
    let header_cells = ["#", "Canonical ID", "Type", "Age"].iter().map(|h| {
        Cell::from(*h).style(
            Style::default()
                .fg(Theme::primary())
                .add_modifier(Modifier::BOLD),
        )
    });
    let table_header = Row::new(header_cells).height(1);

    let rows: Vec<Row> = app
        .mempool
        .iter()
        .enumerate()
        .map(|(i, tx)| {
            let age_secs = tx.timestamp.elapsed().as_secs();
            let age_str = if age_secs < 60 {
                format!("{}s", age_secs)
            } else if age_secs < 3600 {
                format!("{}m {}s", age_secs / 60, age_secs % 60)
            } else {
                format!("{}h {}m", age_secs / 3600, (age_secs % 3600) / 60)
            };

            let style = if i % 2 == 0 {
                Style::default().fg(Theme::text())
            } else {
                Style::default().fg(Theme::text_dim())
            };

            Row::new(vec![
                Cell::from(format!("{}", i + 1)),
                Cell::from(tx.id.clone()),
                Cell::from(tx.tx_type.clone()),
                Cell::from(age_str),
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(4),
            Constraint::Min(30),
            Constraint::Length(16),
            Constraint::Length(10),
        ],
    )
    .header(table_header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Pending Transactions ")
            .border_style(Style::default().fg(Theme::border())),
    );

    f.render_widget(table, chunks[1]);
}

// ============================================================================
// VIEW: EVENTS
// ============================================================================

fn draw_events(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .events
        .iter()
        .enumerate()
        .map(|(i, (time, event_type, msg))| {
            let elapsed = time.elapsed().as_secs();
            let time_str = if elapsed < 60 {
                format!("{}s ago", elapsed)
            } else if elapsed < 3600 {
                format!("{}m ago", elapsed / 60)
            } else {
                format!("{}h ago", elapsed / 3600)
            };

            let color = match event_type.as_str() {
                "Block" => Theme::success(),
                "Package" => Theme::primary(),
                "Validator" => Theme::accent(),
                "Slash" => Theme::error(),
                _ => Theme::text_dim(),
            };

            let style = if i == app.selected_event {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default().fg(color)
            };

            let content = format!("[{:>8}] {:<12} {}", time_str, event_type, msg);
            ListItem::new(content).style(style)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" EVENT LOG ({}) ", app.events.len()))
            .border_style(Style::default().fg(Theme::success())),
    );

    f.render_widget(list, area);
}

// ============================================================================
// VIEW: OPERATOR
// ============================================================================

fn draw_operator(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7),
            Constraint::Length(6), // Identity block
            Constraint::Length(8),
            Constraint::Min(6),
        ])
        .split(area);

    let active_validators = app
        .validators
        .iter()
        .filter(|v| v.is_active || v.status == "online" || v.status == "self")
        .count();

    let summary = Paragraph::new(vec![
        Line::from(format!("Mode: validator console")),
        Line::from(format!(
            "Validators online: {}/{}",
            active_validators,
            app.validators.len()
        )),
        Line::from(format!("Connected peers: {}", app.peer_ids.len())),
        Line::from(format!("Bridge status: {}", app.stats.bridge_status)),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Operator Summary "),
    )
    .style(Style::default().fg(Theme::text()))
    .wrap(Wrap { trim: true });
    f.render_widget(summary, chunks[0]);

    // Identity block
    let mut identity_lines = Vec::new();
    if let Some(id) = &app.runtime_identity {
        identity_lines.push(Line::from(vec![
            Span::styled("Node ID:   ", Style::default().fg(Theme::text_dim())),
            Span::styled(
                &id.node_id,
                Style::default()
                    .fg(Theme::primary())
                    .add_modifier(Modifier::BOLD),
            ),
        ]));
        identity_lines.push(Line::from(vec![
            Span::styled("Ed25519:   ", Style::default().fg(Theme::text_dim())),
            Span::styled(
                id.validator_pubkey.as_deref().unwrap_or("not configured"),
                Style::default().fg(Theme::accent()),
            ),
        ]));
        identity_lines.push(Line::from(vec![
            Span::styled("Action:    ", Style::default().fg(Theme::text_dim())),
            Span::raw("Copy these values to the Web Explorer to register your identity."),
        ]));
    } else {
        identity_lines.push(Line::from(Span::styled(
            "Fetching local node identity...",
            Style::default().fg(Theme::text_dim()),
        )));
    }

    let identity = Paragraph::new(identity_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Detected Validator Identity ")
                .border_style(Style::default().fg(Theme::primary())),
        )
        .style(Style::default().fg(Theme::text()));
    f.render_widget(identity, chunks[1]);

    let commands = Paragraph::new(vec![
        Line::from("Browser explorer:  http://localhost:3007"),
        Line::from("Node health:        creg testnet status --node-url http://localhost:8080"),
        Line::from(
            "Register ID:        creg testnet register-validator --node-id <id> --pubkey <key>",
        ),
        Line::from("Stake validator:    creg testnet stake-validator --key 0x<private-key> 100"),
        Line::from("Stake publisher:    creg testnet stake-publisher --key 0x<private-key> 100"),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Operator Commands "),
    )
    .style(Style::default().fg(Theme::text()))
    .wrap(Wrap { trim: true });
    f.render_widget(commands, chunks[2]);

    let workflow = Paragraph::new(vec![
        Line::from("This console is the operator surface for validator monitoring."),
        Line::from("Use it to inspect blocks, validator health, packages, peers, and live events."),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Operator Workflow "),
    )
    .style(Style::default().fg(Theme::text()))
    .wrap(Wrap { trim: true });
    f.render_widget(workflow, chunks[3]);
}

// ============================================================================
// VIEW: HELP
// ============================================================================

fn draw_help(f: &mut Frame, _app: &App, area: Rect) {
    let text = r#"
╔══════════════════════════════════════════════════════════════════════════════╗
║                      CHAIN REGISTRY CONSOLE - HELP                            ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  NAVIGATION                                                                  ║
║  ─────────                                                                   ║
║    ←/→ or h/l     Move between columns/tabs                                  ║
║    ↑/↓ or j/k     Navigate lists                                             ║
║    Enter or d     Open detail view                                           ║
║    Esc or b       Go back                                                    ║
║    q              Quit console                                               ║
║                                                                              ║
║  VIEW SHORTCUTS                                                              ║
║  ─────────────                                                               ║
║    1              Overview dashboard                                         ║
║    2              Blocks view                                                ║
║    3              Validators view                                            ║
║    4              Packages view                                              ║
║    5              Network status                                             ║
║    6              Mempool view                                               ║
║    7              Events log                                                 ║
║    8 / o          Operator view                                              ║
║    ? or h         Toggle this help                                           ║
║                                                                              ║
║  SEARCH & FILTER                                                             ║
║  ──────────────                                                              ║
║    /              Start search                                               ║
║    Esc            Cancel search                                              ║
║    Enter          Confirm search                                             ║
║                                                                              ║
║  MOUSE SUPPORT                                                               ║
║  ─────────────                                                               ║
║    Scroll         Navigate lists                                             ║
║    Click          Select items (where supported)                             ║
║                                                                              ║
║  PRESS ANY KEY TO RETURN...                                                  ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"#;

    let help = Paragraph::new(text)
        .block(Block::default())
        .style(Style::default().fg(Theme::primary()));

    f.render_widget(help, area);
}

// ============================================================================
// POPUPS
// ============================================================================

fn draw_search_popup(f: &mut Frame, app: &App) {
    let area = centered_rect(60, 20, f.size());

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" SEARCH ")
        .border_style(Style::default().fg(Theme::accent()));

    let text = Paragraph::new(format!("Query: {}", app.search_query))
        .block(block)
        .style(Style::default().fg(Theme::text()));

    f.render_widget(Clear, area);
    f.render_widget(text, area);
}

// ============================================================================
// UTILITIES
// ============================================================================

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn format_number(n: u64) -> String {
    let num = n as f64;
    if n >= 1_000_000_000 {
        format!("{:.2}B", num / 1_000_000_000.0)
    } else if n >= 1_000_000 {
        format!("{:.2}M", num / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}k", num / 1_000.0)
    } else {
        n.to_string()
    }
}

fn format_timestamp(ts: &str) -> String {
    // Simple formatting - in production would parse and format properly
    if ts.len() > 19 {
        ts[..19].to_string()
    } else {
        ts.to_string()
    }
}

// ============================================================================
// FAUCET PANE
// ============================================================================

/// Poll the faucet /health endpoint. Returns (healthy, token_reserve_str) or None.
async fn fetch_faucet_health(
    client: &reqwest::Client,
    base: &str,
) -> Option<(bool, Option<String>)> {
    let url = format!("{}/health", base.trim_end_matches('/'));
    let res = client
        .get(&url)
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .ok()?;
    if !res.status().is_success() {
        return Some((false, None));
    }
    let json: Value = res.json().await.ok()?;
    let healthy =
        json["status"].as_str() == Some("healthy") && json["faucet"].as_str() == Some("online");
    let reserve = json["faucet_balance"].as_str().map(|s| s.to_string());
    Some((healthy, reserve))
}

/// Drive the full PoW-guarded drip flow: fetch challenge → solve PoW → POST drip.
/// Emits progress messages and a final `FaucetDripResult` over `tx`.
async fn run_faucet_drip(tx: mpsc::Sender<DataUpdate>, base: String, address: String) {
    let client = reqwest::Client::new();

    let _ = tx
        .send(DataUpdate::FaucetDripProgress(
            "Requesting PoW challenge…".into(),
        ))
        .await;

    let challenge = match crate::faucet_client::get_challenge(&client, &base).await {
        Ok(c) => c,
        Err(e) => {
            let _ = tx
                .send(DataUpdate::FaucetDripResult(Err(format!(
                    "challenge failed: {}",
                    e
                ))))
                .await;
            return;
        }
    };

    let _ = tx
        .send(DataUpdate::FaucetDripProgress(format!(
            "Solving PoW (difficulty={})…",
            challenge.difficulty
        )))
        .await;

    // Hashing is CPU-bound; keep it off the async runtime thread.
    let challenge_for_task = challenge.challenge.clone();
    let difficulty = challenge.difficulty;
    let nonce = match tokio::task::spawn_blocking(move || {
        crate::faucet_client::solve_pow(&challenge_for_task, difficulty)
    })
    .await
    {
        Ok(n) => n,
        Err(e) => {
            let _ = tx
                .send(DataUpdate::FaucetDripResult(Err(format!(
                    "PoW solver crashed: {}",
                    e
                ))))
                .await;
            return;
        }
    };

    let _ = tx
        .send(DataUpdate::FaucetDripProgress(
            "Submitting drip request…".into(),
        ))
        .await;

    match crate::faucet_client::drip(&client, &base, &address, &challenge.challenge, &nonce).await {
        Ok(resp) if resp.success => {
            let tx_hash = resp.tx_hash.unwrap_or_else(|| "(none)".into());
            let amount = resp.amount.unwrap_or_else(|| "(unknown)".into());
            let _ = tx
                .send(DataUpdate::FaucetDripResult(Ok((tx_hash, amount))))
                .await;

            // Follow up with a balance refresh so the user sees the drip land.
            if let Ok(bal) = crate::faucet_client::get_balance(&client, &base, &address).await {
                let _ = tx
                    .send(DataUpdate::FaucetBalance {
                        token: bal.balance,
                        native: bal.native_balance,
                        token_fmt: bal.balance_formatted,
                        native_fmt: bal.native_balance_formatted,
                    })
                    .await;
            }
        }
        Ok(resp) => {
            let _ = tx
                .send(DataUpdate::FaucetDripResult(Err(resp
                    .error
                    .unwrap_or_else(|| "drip rejected".into()))))
                .await;
        }
        Err(e) => {
            let _ = tx
                .send(DataUpdate::FaucetDripResult(Err(format!(
                    "drip call failed: {}",
                    e
                ))))
                .await;
        }
    }
}

fn draw_faucet(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // title
            Constraint::Length(5), // network / health
            Constraint::Length(3), // address input
            Constraint::Length(4), // balance
            Constraint::Min(5),    // status / help
        ])
        .split(area);

    // Title
    let title = Paragraph::new(Line::from(vec![
        Span::styled(
            "⛲ Testnet Faucet",
            Style::default()
                .fg(Theme::accent())
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("   "),
        Span::styled(
            format!("[{}]", app.faucet.health),
            Style::default().fg(if app.faucet.health == "online" {
                Theme::success()
            } else {
                Theme::warning()
            }),
        ),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Theme::border())),
    )
    .alignment(Alignment::Center);
    f.render_widget(title, chunks[0]);

    // Network
    let mut net_lines: Vec<Line> = Vec::new();
    net_lines.push(Line::from(vec![
        Span::styled("Endpoint:  ", Style::default().fg(Theme::text_dim())),
        Span::styled(
            app.faucet.base.clone(),
            Style::default().fg(Theme::highlight()),
        ),
    ]));
    if let Some(net) = &app.faucet.network {
        net_lines.push(Line::from(vec![
            Span::styled("Chain:     ", Style::default().fg(Theme::text_dim())),
            Span::styled(
                format!("{} (id {})", net.chain_name, net.chain_id),
                Style::default().fg(Theme::text()),
            ),
        ]));
        net_lines.push(Line::from(vec![
            Span::styled("RPC:       ", Style::default().fg(Theme::text_dim())),
            Span::styled(net.rpc_url.clone(), Style::default().fg(Theme::text())),
        ]));
    }
    if let Some(reserve) = &app.faucet.faucet_token_reserve {
        net_lines.push(Line::from(vec![
            Span::styled("Reserve:   ", Style::default().fg(Theme::text_dim())),
            Span::styled(format_wei(reserve), Style::default().fg(Theme::primary())),
            Span::styled(" tCREG", Style::default().fg(Theme::text_dim())),
        ]));
    }
    let net_widget = Paragraph::new(net_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Network ")
            .border_style(Style::default().fg(Theme::border())),
    );
    f.render_widget(net_widget, chunks[1]);

    // Address input
    let input_style = if app.faucet.editing {
        Style::default()
            .fg(Theme::highlight())
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Theme::text())
    };
    let display = if app.faucet.address_input.is_empty() {
        if app.faucet.editing {
            "▊".to_string()
        } else {
            "(press 'e' to edit)".to_string()
        }
    } else if app.faucet.editing {
        format!("{}▊", app.faucet.address_input)
    } else {
        app.faucet.address_input.clone()
    };
    let input_title = if app.faucet.editing {
        " Recipient address (INSERT — Esc to stop) "
    } else {
        " Recipient address "
    };
    let input_border = if app.faucet.editing {
        Theme::highlight()
    } else {
        Theme::border()
    };
    let input_widget = Paragraph::new(Line::from(Span::styled(display, input_style))).block(
        Block::default()
            .borders(Borders::ALL)
            .title(input_title)
            .border_style(Style::default().fg(input_border)),
    );
    f.render_widget(input_widget, chunks[2]);

    // Balance. Prefer the faucet's pre-formatted decimal strings so the TUI
    // matches the web explorer (e.g. "1000.00" instead of "1000000000000000000000").
    // Fall back to format_wei() on the raw value only if the formatted field is
    // missing from the response.
    let token_display = app
        .faucet
        .last_balance_fmt
        .clone()
        .or_else(|| app.faucet.last_balance.as_deref().map(format_wei));
    let native_display = app
        .faucet
        .last_native_balance_fmt
        .clone()
        .or_else(|| app.faucet.last_native_balance.as_deref().map(format_wei));
    let mut bal_lines: Vec<Line> = Vec::new();
    match (&token_display, &native_display) {
        (Some(t), Some(n)) => {
            bal_lines.push(Line::from(vec![
                Span::styled("tCREG:  ", Style::default().fg(Theme::text_dim())),
                Span::styled(t.clone(), Style::default().fg(Theme::success())),
            ]));
            bal_lines.push(Line::from(vec![
                Span::styled("ETH:    ", Style::default().fg(Theme::text_dim())),
                Span::styled(n.clone(), Style::default().fg(Theme::secondary())),
            ]));
        }
        _ => {
            bal_lines.push(Line::from(Span::styled(
                "Press 'b' to fetch balance for the entered address.",
                Style::default().fg(Theme::text_dim()),
            )));
        }
    }
    let bal_widget = Paragraph::new(bal_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Balance ")
            .border_style(Style::default().fg(Theme::border())),
    );
    f.render_widget(bal_widget, chunks[3]);

    // Status
    let (status_text, status_color) = match &app.faucet.status {
        FaucetStatus::Idle => (
            "Idle. Enter a recipient address and press [d] to drip.".to_string(),
            Theme::text_dim(),
        ),
        FaucetStatus::Working {
            started_at,
            message,
        } => (
            format!(
                "⏳ {} ({}s elapsed)",
                message,
                started_at.elapsed().as_secs()
            ),
            Theme::warning(),
        ),
        FaucetStatus::Success {
            tx_hash,
            amount,
            at,
        } => (
            format!(
                "✓ Drip succeeded ({}s ago)\n  amount: {}\n  tx:     {}",
                at.elapsed().as_secs(),
                amount,
                tx_hash
            ),
            Theme::success(),
        ),
        FaucetStatus::Failed { error, at } => (
            format!("✗ Failed ({}s ago): {}", at.elapsed().as_secs(), error),
            Theme::error(),
        ),
    };
    let status_widget = Paragraph::new(status_text)
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Status ")
                .border_style(Style::default().fg(status_color)),
        )
        .style(Style::default().fg(status_color));
    f.render_widget(status_widget, chunks[4]);
}

/// Convert a wei-denominated integer string to a human-friendly 18-decimal token
/// amount with 2 decimal places of precision. Non-integer input is returned verbatim.
fn format_wei(raw: &str) -> String {
    let trimmed = raw.trim();
    let digits: String = trimmed.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return trimmed.to_string();
    }
    if digits.len() <= 18 {
        let padded = format!("{:0>18}", digits);
        let whole = "0";
        let frac = &padded[padded.len().saturating_sub(18)..];
        let frac_short = &frac[..frac.len().min(2)];
        format!("{}.{}", whole, frac_short)
    } else {
        let split = digits.len() - 18;
        let whole = &digits[..split];
        let frac = &digits[split..];
        let frac_short = &frac[..frac.len().min(2)];
        format!("{}.{}", whole, frac_short)
    }
}

fn draw_bridge(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" L1 BRIDGE ANCHORS ")
        .border_style(Style::default().fg(Theme::primary()));
    let text = vec![
        Line::from(format!("Bridge Status: {}", app.stats.bridge_status)),
        Line::from(format!("Latest L1 Block: {}", app.stats.l1_block)),
        Line::from(format!(
            "Anchor count in memory: {}",
            app.bridge_anchors.len()
        )),
    ];
    let paragraph = Paragraph::new(text)
        .block(block)
        .style(Style::default().fg(Theme::text()));
    f.render_widget(paragraph, area);
}

fn draw_metrics(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" CHAIN METRICS ")
        .border_style(Style::default().fg(Theme::success()));

    let text = vec![
        Line::from(Span::styled(
            "Live metrics tracking coming in Sprint 5",
            Style::default().fg(Theme::text_dim()),
        )),
        Line::from(format!("TPS History length: {}", app.tps_history.len())),
        Line::from(format!(
            "Metric Accumulations: {}",
            app.metrics_history.len()
        )),
    ];
    let paragraph = Paragraph::new(text).block(block);
    f.render_widget(paragraph, area);
}
