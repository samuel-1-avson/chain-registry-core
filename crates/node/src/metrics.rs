// crates/node/src/metrics.rs
// Lightweight Prometheus-compatible metrics endpoint.
// Exposed at GET /metrics — scrape with any Prometheus-compatible system.
//
// Local chain (RocksDB):
//   creg_chain_tip_height      — height index of the tip block (genesis alone => 0)
//   creg_chain_blocks_stored   — count of blocks in local storage (genesis alone => 1)
//   creg_package_count, creg_pending_pool_size, creg_publisher_count
//
// L1 validator set sync (Sepolia staking logs):
//   creg_validator_set_sync_*    — mirrors /v1/health.validator_set_sync

use crate::NodeState;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Build a Prometheus text-format metrics response.
pub async fn render(state: Arc<RwLock<NodeState>>) -> String {
    let s = state.read().await;
    let stats = s.chain.stats();
    let sync = &s.validator_set_sync;

    let mut out = String::with_capacity(2048);

    metric(
        &mut out,
        "creg_chain_tip_height",
        "Height index of the local chain tip (only genesis => 0; not Sepolia block number)",
        "gauge",
        stats.tip_height as f64,
    );

    metric(
        &mut out,
        "creg_chain_blocks_stored",
        "Blocks stored in the local chain DB (genesis at height 0 counts as 1)",
        "gauge",
        stats.block_count as f64,
    );

    // Deprecated alias: same series as creg_chain_tip_height (kept for existing dashboards).
    metric(
        &mut out,
        "creg_chain_height",
        "DEPRECATED: use creg_chain_tip_height (same value)",
        "gauge",
        stats.tip_height as f64,
    );

    metric(
        &mut out,
        "creg_block_count",
        "DEPRECATED: use creg_chain_blocks_stored (same value)",
        "gauge",
        stats.block_count as f64,
    );

    metric(
        &mut out,
        "creg_package_count",
        "Total verified packages on chain",
        "gauge",
        stats.package_count as f64,
    );

    metric(
        &mut out,
        "creg_pending_pool_size",
        "Packages currently awaiting consensus",
        "gauge",
        s.pending_pool.len() as f64,
    );

    metric(
        &mut out,
        "creg_publisher_count",
        "Unique publishers tracked",
        "gauge",
        s.publisher_index.publisher_count() as f64,
    );

    let node_id = &s.config.node_id;
    labeled_metric(
        &mut out,
        "creg_node_info",
        "Static node information",
        "gauge",
        &[
            ("node_id", node_id.as_str()),
            ("version", env!("CARGO_PKG_VERSION")),
        ],
        1.0,
    );

    metric(
        &mut out,
        "creg_validator_set_sync_enabled",
        "1 when chain-authoritative validator set sync is enabled",
        "gauge",
        if sync.enabled { 1.0 } else { 0.0 },
    );

    metric(
        &mut out,
        "creg_validator_set_sync_state_code",
        "Sync state enum: 0=disabled 1=syncing 2=reorg-replaying 3=degraded 4=synced",
        "gauge",
        validator_set_sync_state_code(&sync.state) as f64,
    );

    metric(
        &mut out,
        "creg_validator_set_sync_last_finalized_source_block",
        "Last L1 block height applied to the authoritative validator set (0 if unknown)",
        "gauge",
        sync.last_finalized_source_block.unwrap_or(0) as f64,
    );

    metric(
        &mut out,
        "creg_validator_set_sync_cursor_block",
        "L1 log cursor block height (0 if unknown)",
        "gauge",
        sync.cursor_block.unwrap_or(0) as f64,
    );

    metric(
        &mut out,
        "creg_validator_set_sync_has_error",
        "1 when validator_set_sync.last_error is set",
        "gauge",
        if sync.last_error.is_some() { 1.0 } else { 0.0 },
    );

    labeled_metric(
        &mut out,
        "creg_validator_set_sync_info",
        "Validator set sync mode and state (value is always 1 when labeled series is present)",
        "gauge",
        &[("mode", sync.mode.as_str()), ("state", sync.state.as_str())],
        1.0,
    );

    // ── Consensus / validator set health ────────────────────────────────────
    let active_validators = s
        .validator_set
        .validators
        .iter()
        .filter(|v| v.status == "online" || v.status == "self")
        .count();
    metric(
        &mut out,
        "creg_active_validators",
        "Validators currently eligible for PBFT consensus (status online/self)",
        "gauge",
        active_validators as f64,
    );
    metric(
        &mut out,
        "creg_validator_set_total",
        "Total validators in the active set (any status)",
        "gauge",
        s.validator_set.validators.len() as f64,
    );

    metric(
        &mut out,
        "creg_reorg_events_total",
        "L2 chain reorganizations recorded since start (retained window)",
        "gauge",
        s.reorgs.len() as f64,
    );

    // ── L1 checkpoint bridge ────────────────────────────────────────────────
    let bridge = &s.bridge_status;
    metric(
        &mut out,
        "creg_bridge_anchor_count",
        "Number of L2->L1 checkpoint anchors committed (persisted journal length)",
        "gauge",
        bridge.anchor_count as f64,
    );
    metric(
        &mut out,
        "creg_bridge_last_anchor_eth_block",
        "L1 block of the most recent checkpoint anchor (0 if none yet)",
        "gauge",
        bridge.last_finalized_eth_block as f64,
    );
    metric(
        &mut out,
        "creg_bridge_finalized_l1_block",
        "Most recent L1 block tagged finalized as observed by the bridge (0 if unknown)",
        "gauge",
        bridge.finalized_l1_block.unwrap_or(0) as f64,
    );

    // ── MAL-001 sandbox posture (validators) ─────────────────────────────────
    let sandbox = validator::sandbox::engine_status().await;
    metric(
        &mut out,
        "creg_sandbox_dev_bypass",
        "1 when CREG_DEV_SANDBOX=true (behavioural analysis skipped); must be 0 on public validators",
        "gauge",
        if sandbox.dev_bypass { 1.0 } else { 0.0 },
    );
    metric(
        &mut out,
        "creg_sandbox_isolated",
        "1 when the active sandbox engine runs packages with real isolation",
        "gauge",
        if sandbox.isolated { 1.0 } else { 0.0 },
    );
    labeled_metric(
        &mut out,
        "creg_sandbox_info",
        "Sandbox engine selected for behavioural analysis (value is always 1)",
        "gauge",
        &[
            ("engine", sandbox.engine.as_str()),
            ("degraded", if sandbox.degraded { "true" } else { "false" }),
        ],
        1.0,
    );

    out
}

/// Numeric encoding for alert rules (e.g. `== 4` for synced).
pub fn validator_set_sync_state_code(state: &str) -> i32 {
    match state {
        "disabled" => 0,
        "syncing" => 1,
        "reorg-replaying" => 2,
        "degraded" => 3,
        "synced" => 4,
        _ => -1,
    }
}

fn metric(buf: &mut String, name: &str, help: &str, kind: &str, value: f64) {
    buf.push_str(&format!("# HELP {} {}\n", name, help));
    buf.push_str(&format!("# TYPE {} {}\n", name, kind));
    buf.push_str(&format!("{} {}\n\n", name, value));
}

fn labeled_metric(
    buf: &mut String,
    name: &str,
    help: &str,
    kind: &str,
    labels: &[(&str, &str)],
    value: f64,
) {
    buf.push_str(&format!("# HELP {} {}\n", name, help));
    buf.push_str(&format!("# TYPE {} {}\n", name, kind));
    let label_str = labels
        .iter()
        .map(|(k, v)| format!("{}=\"{}\"", k, escape_label(v)))
        .collect::<Vec<_>>()
        .join(",");
    buf.push_str(&format!("{}{{{}}} {}\n\n", name, label_str, value));
}

fn escape_label(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validator_set_sync_state_codes() {
        assert_eq!(validator_set_sync_state_code("synced"), 4);
        assert_eq!(validator_set_sync_state_code("syncing"), 1);
        assert_eq!(validator_set_sync_state_code("unknown"), -1);
    }

    #[test]
    fn escape_label_quotes() {
        assert_eq!(escape_label(r#"a"b"#), r#"a\"b"#);
    }
}
