// crates/node/src/validator_set_sync.rs
//
// Event-driven materialized view of the on-chain validator set.
//
// Today the in-memory `ValidatorSet` is loaded once from `CREG_VALIDATOR_SET`
// (or `config/validator-set.json`) and never changes. `consensus_admission.rs`
// already drives the *other* half of the loop — every active validator
// independently signs an EIP-712 attestation and the lowest-address signer
// submits `Staking.approveByConsensus(...)` on L1, which emits
// `ValidatorApprovedByConsensus(applicant, nonce, signerCount)`. The contract
// knows. The runtime doesn't.
//
// This module closes that loop. It subscribes (today: polls) Staking.sol
// events on the L1 bridge, normalises them into `ValidatorSetDelta`s, applies
// them to the in-memory view with a finality lag, and exposes a metric so we
// can run in *shadow mode* — observing drift between chain-derived and
// file-derived sets without changing consensus behaviour.
//
// PHASING (per docs/VALIDATOR_SET_SYNC_DESIGN.md):
//   Phase 1 — shadow mode (this scaffold). Compute deltas + drift metric.
//             Does NOT mutate the active set.
//   Phase 2 — chain-authoritative with file fallback.
//   Phase 3 — chain only.
//
// What this scaffold does:
//   • Pulls staking-event logs by polling `eth_getLogs` from a cursor.
//   • Decodes each log into a `ValidatorSetDelta`.
//   • Honours `finality_lag_blocks` (head − block_height ≥ lag before applying).
//   • Persists worker cursor + observed set to `validator-set-sync.cursor.json`
//     under `CREG_DATA_DIR` (atomic write on save).
//
// What this scaffold does NOT do (intentionally — follow-up):
//   • Multi-RPC quorum.
//   • Full reorg rewind of observed_active (hash mismatch is detected; reset only).

use alloy::{
    primitives::{Address, B256, U256},
    sol,
    sol_types::SolEvent,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};

// ─── Contract event ABIs ─────────────────────────────────────────────────────
//
// These mirror the events declared in contracts/Staking.sol exactly. If the
// Solidity event signature changes, the topic0 produced by `sol!` here
// changes, and old logs decoded with this binding will silently mismatch —
// so version this module alongside Staking.sol.

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface IStakingEvents {
        event ValidatorApplied            (address indexed validator, uint256 stake);
        event ValidatorApproved           (address indexed validator);
        event ValidatorApprovedByConsensus(address indexed validator, uint256 nonce, uint256 signerCount);
        event ValidatorRejected           (address indexed validator);
        event ValidatorApplicationExpired (address indexed validator, uint256 refunded);
        event ValidatorUnbonding          (address indexed validator, uint256 unbondingAt);
        event ValidatorWithdrawn          (address indexed validator, uint256 amount);
        event ValidatorLeft               (address indexed validator);
        event Slashed                     (address indexed account,   uint256 amount, string reason);
    }
);

// ─── Delta types ─────────────────────────────────────────────────────────────

/// One observable change to the validator set, attributed to an L1 log.
///
/// Deltas are designed to be applied in `(block_height, log_index)` order
/// and to be *idempotent* — applying the same delta twice yields the same
/// state. This matters because on a crash we'll replay from the persisted
/// cursor and may double-apply the last-seen log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSetDelta {
    pub kind: DeltaKind,
    /// 0x-prefixed lowercase hex of the EVM address — the primary key.
    pub addr: String,
    pub block_height: u64,
    pub log_index: u32,
    pub tx_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeltaKind {
    /// Active set membership change: applicant was approved on-chain.
    /// Stake (in wei, decimal-string to keep U256 precision) and the EIP-712
    /// attestation count come from the event itself.
    Add {
        stake_wei: String,
        signer_count: Option<u32>,
    },
    /// `applyAsValidator` only — applicant exists but is *not* yet active.
    /// In shadow mode we simply log this; in chain-authoritative mode it
    /// would populate a `pending_applicants` map for the UI.
    Apply { stake_wei: String },
    /// Final removal — `Withdrawn`, `Left`, or stake-drained `Slashed`.
    /// The contract has marked them terminal; we drop them from the active
    /// set. Idempotent: removing an already-absent address is a no-op.
    Remove,
    /// Validator entered the unbonding window. Still possible they withdraw
    /// or rejoin; for the active set we treat as "inactive now".
    Unbond { unbonding_at: u64 },
    /// Stake was slashed. If the new stake (which we cannot derive from the
    /// event payload alone — `Slashed` only emits the slash *amount*) drops
    /// to zero, the chain will follow up with a `Slashed`-driven removal
    /// via the regular flow. We carry the amount for telemetry.
    Slash { amount_wei: String, reason: String },
    /// `Rejected` or `ApplicationExpired`. No active-set effect (applicant
    /// was never active) but useful for the UI/audit trail.
    DropApplicant,
}

// ─── Decoding ────────────────────────────────────────────────────────────────

/// What we need from an L1 log to decode a delta. Mirrors the subset of
/// `alloy::rpc::types::Log` we actually use, so tests can construct one
/// without spinning up a provider.
#[derive(Clone, Debug)]
pub struct LogView<'a> {
    pub topics: &'a [B256],
    pub data: &'a [u8],
    pub block_number: u64,
    pub log_index: u32,
    pub tx_hash: B256,
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("log has no topics — not an event")]
    NoTopics,
    #[error("unknown topic0 0x{0} — not a Staking event we track")]
    UnknownTopic(String),
    #[error("event decode failed: {0}")]
    Sol(String),
}

/// Decode one Staking event log into a `ValidatorSetDelta`. Returns
/// `Ok(None)` for events we deliberately ignore (e.g. duplicate/admin
/// events that never affect the active set). Errors are reserved for
/// malformed logs.
pub fn decode(log: LogView<'_>) -> Result<Option<ValidatorSetDelta>, DecodeError> {
    let topic0 = *log.topics.first().ok_or(DecodeError::NoTopics)?;

    // alloy's sol!-generated event types expose a `SIGNATURE_HASH` constant
    // that is the keccak256 of the canonical event signature. We dispatch on
    // that to pick the right decoder.
    let kind: DeltaKind;
    let addr: Address;

    if topic0 == IStakingEvents::ValidatorApplied::SIGNATURE_HASH {
        let ev = IStakingEvents::ValidatorApplied::decode_log_data(
            &alloy::primitives::LogData::new_unchecked(
                log.topics.to_vec(),
                log.data.to_vec().into(),
            ),
            true,
        )
        .map_err(|e| DecodeError::Sol(e.to_string()))?;
        addr = ev.validator;
        kind = DeltaKind::Apply {
            stake_wei: ev.stake.to_string(),
        };
    } else if topic0 == IStakingEvents::ValidatorApproved::SIGNATURE_HASH {
        let ev = IStakingEvents::ValidatorApproved::decode_log_data(
            &alloy::primitives::LogData::new_unchecked(
                log.topics.to_vec(),
                log.data.to_vec().into(),
            ),
            true,
        )
        .map_err(|e| DecodeError::Sol(e.to_string()))?;
        addr = ev.validator;
        kind = DeltaKind::Add {
            stake_wei: U256::ZERO.to_string(),
            signer_count: None,
        };
    } else if topic0 == IStakingEvents::ValidatorApprovedByConsensus::SIGNATURE_HASH {
        let ev = IStakingEvents::ValidatorApprovedByConsensus::decode_log_data(
            &alloy::primitives::LogData::new_unchecked(
                log.topics.to_vec(),
                log.data.to_vec().into(),
            ),
            true,
        )
        .map_err(|e| DecodeError::Sol(e.to_string()))?;
        addr = ev.validator;
        kind = DeltaKind::Add {
            stake_wei: U256::ZERO.to_string(),
            signer_count: u32::try_from(ev.signerCount).ok(),
        };
    } else if topic0 == IStakingEvents::ValidatorRejected::SIGNATURE_HASH {
        let ev = IStakingEvents::ValidatorRejected::decode_log_data(
            &alloy::primitives::LogData::new_unchecked(
                log.topics.to_vec(),
                log.data.to_vec().into(),
            ),
            true,
        )
        .map_err(|e| DecodeError::Sol(e.to_string()))?;
        addr = ev.validator;
        kind = DeltaKind::DropApplicant;
    } else if topic0 == IStakingEvents::ValidatorApplicationExpired::SIGNATURE_HASH {
        let ev = IStakingEvents::ValidatorApplicationExpired::decode_log_data(
            &alloy::primitives::LogData::new_unchecked(
                log.topics.to_vec(),
                log.data.to_vec().into(),
            ),
            true,
        )
        .map_err(|e| DecodeError::Sol(e.to_string()))?;
        addr = ev.validator;
        kind = DeltaKind::DropApplicant;
    } else if topic0 == IStakingEvents::ValidatorUnbonding::SIGNATURE_HASH {
        let ev = IStakingEvents::ValidatorUnbonding::decode_log_data(
            &alloy::primitives::LogData::new_unchecked(
                log.topics.to_vec(),
                log.data.to_vec().into(),
            ),
            true,
        )
        .map_err(|e| DecodeError::Sol(e.to_string()))?;
        addr = ev.validator;
        kind = DeltaKind::Unbond {
            unbonding_at: ev.unbondingAt.try_into().unwrap_or(u64::MAX),
        };
    } else if topic0 == IStakingEvents::ValidatorWithdrawn::SIGNATURE_HASH {
        let ev = IStakingEvents::ValidatorWithdrawn::decode_log_data(
            &alloy::primitives::LogData::new_unchecked(
                log.topics.to_vec(),
                log.data.to_vec().into(),
            ),
            true,
        )
        .map_err(|e| DecodeError::Sol(e.to_string()))?;
        addr = ev.validator;
        kind = DeltaKind::Remove;
    } else if topic0 == IStakingEvents::ValidatorLeft::SIGNATURE_HASH {
        let ev = IStakingEvents::ValidatorLeft::decode_log_data(
            &alloy::primitives::LogData::new_unchecked(
                log.topics.to_vec(),
                log.data.to_vec().into(),
            ),
            true,
        )
        .map_err(|e| DecodeError::Sol(e.to_string()))?;
        addr = ev.validator;
        kind = DeltaKind::Remove;
    } else if topic0 == IStakingEvents::Slashed::SIGNATURE_HASH {
        let ev = IStakingEvents::Slashed::decode_log_data(
            &alloy::primitives::LogData::new_unchecked(
                log.topics.to_vec(),
                log.data.to_vec().into(),
            ),
            true,
        )
        .map_err(|e| DecodeError::Sol(e.to_string()))?;
        addr = ev.account;
        kind = DeltaKind::Slash {
            amount_wei: ev.amount.to_string(),
            reason: ev.reason.clone(),
        };
    } else {
        return Err(DecodeError::UnknownTopic(hex::encode(topic0)));
    }

    Ok(Some(ValidatorSetDelta {
        kind,
        addr: format!("0x{}", hex::encode(addr.0)),
        block_height: log.block_number,
        log_index: log.log_index,
        tx_hash: format!("0x{}", hex::encode(log.tx_hash.0)),
    }))
}

// ─── Worker ──────────────────────────────────────────────────────────────────

/// Configuration for the polling worker. Most production deployments will
/// override `finality_lag_blocks` from the chain spec (Sepolia: 6, mainnet: 32).
#[derive(Clone, Debug)]
pub struct SyncConfig {
    pub eth_rpc_url: String,
    /// Additional independent L1 RPC endpoints used for quorum reads. The
    /// primary `eth_rpc_url` plus these form the endpoint set: head block
    /// height is taken conservatively (median/min) and the cursor block hash
    /// used for reorg detection must reach a strict majority before any
    /// rebuild, so a single compromised or stale RPC cannot skew membership.
    pub extra_rpc_urls: Vec<String>,
    pub staking_addr: Address,
    /// How far behind head we trail before applying a delta. 0 disables the
    /// lag (useful for local Anvil tests where reorgs do not happen).
    pub finality_lag_blocks: u64,
    /// How often we poll `eth_getLogs`. WS subscription is a follow-up.
    pub poll_interval_secs: u64,
    /// Block to start from on a fresh boot. Chain spec provides this as
    /// `validator_set.epoch_block_height`. None = start at current head.
    pub start_block: Option<u64>,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            eth_rpc_url: "http://127.0.0.1:8545".into(),
            extra_rpc_urls: Vec::new(),
            staking_addr: Address::ZERO,
            finality_lag_blocks: 6,
            poll_interval_secs: 12,
            start_block: None,
        }
    }
}

impl SyncConfig {
    /// The full ordered set of L1 RPC endpoints: primary first, then extras.
    /// De-duplicated so a misconfiguration listing the primary twice does not
    /// inflate the apparent quorum.
    fn rpc_endpoints(&self) -> Vec<String> {
        let mut endpoints = Vec::with_capacity(1 + self.extra_rpc_urls.len());
        endpoints.push(self.eth_rpc_url.clone());
        for url in &self.extra_rpc_urls {
            let url = url.trim().to_string();
            if !url.is_empty() && !endpoints.iter().any(|e| e == &url) {
                endpoints.push(url);
            }
        }
        endpoints
    }
}

/// Fan out `eth_blockNumber` to every endpoint and combine conservatively via
/// `l1_quorum::aggregate_height`. Errors only when no endpoint responds.
async fn fetch_latest_block_quorum(
    client: &reqwest::Client,
    endpoints: &[String],
) -> anyhow::Result<u64> {
    let mut heights = Vec::with_capacity(endpoints.len());
    let mut last_err: Option<String> = None;
    for ep in endpoints {
        match fetch_latest_block(client, ep).await {
            Ok(h) => heights.push(h),
            Err(e) => last_err = Some(e.to_string()),
        }
    }
    crate::l1_quorum::aggregate_height(&heights).ok_or_else(|| {
        anyhow::anyhow!(
            "no L1 RPC endpoint returned a block number ({} tried): {}",
            endpoints.len(),
            last_err.unwrap_or_else(|| "unknown error".into())
        )
    })
}

/// Fetch a block hash from the first endpoint that answers (failover). Used
/// for non-critical reads where we only need *a* hash to record the cursor.
async fn fetch_block_hash_failover(
    client: &reqwest::Client,
    endpoints: &[String],
    block_number: u64,
) -> anyhow::Result<String> {
    let mut last_err: Option<String> = None;
    for ep in endpoints {
        match fetch_block_hash(client, ep, block_number).await {
            Ok(h) => return Ok(h),
            Err(e) => last_err = Some(e.to_string()),
        }
    }
    Err(anyhow::anyhow!(
        "no L1 RPC endpoint returned block {} hash: {}",
        block_number,
        last_err.unwrap_or_else(|| "unknown error".into())
    ))
}

/// Outcome of a quorum block-hash read used for reorg detection.
enum HashQuorum {
    /// A strict majority of endpoints agree on this hash.
    Agreed(String),
    /// Endpoints responded but did not reach a majority — inconclusive, so
    /// the caller must NOT treat this as a reorg.
    NoMajority,
    /// No endpoint responded at all.
    Unavailable,
}

/// Fan out `eth_getBlockByNumber` and require a strict majority agreement on
/// the hash. Used to gate the destructive reorg rebuild so a single divergent
/// RPC cannot force it.
async fn fetch_block_hash_quorum(
    client: &reqwest::Client,
    endpoints: &[String],
    block_number: u64,
) -> HashQuorum {
    let mut hashes = Vec::with_capacity(endpoints.len());
    for ep in endpoints {
        if let Ok(h) = fetch_block_hash(client, ep, block_number).await {
            hashes.push(h);
        }
    }
    if hashes.is_empty() {
        return HashQuorum::Unavailable;
    }
    match crate::l1_quorum::majority_hash(&hashes) {
        Some(h) => HashQuorum::Agreed(h),
        None => HashQuorum::NoMajority,
    }
}

/// Fetch staking deltas from the first endpoint that succeeds (failover).
/// Logs are deterministic within the already quorum-confirmed finalized range,
/// so failover (rather than cross-endpoint set agreement) is the right trade.
async fn fetch_deltas_failover(
    client: &reqwest::Client,
    endpoints: &[String],
    staking_addr: &alloy::primitives::Address,
    from_block: u64,
    to_block: u64,
) -> anyhow::Result<Vec<ValidatorSetDelta>> {
    let mut last_err: Option<anyhow::Error> = None;
    for ep in endpoints {
        match fetch_deltas(client, ep, staking_addr, from_block, to_block).await {
            Ok(deltas) => return Ok(deltas),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no L1 RPC endpoint returned staking logs")))
}

/// Mode for the worker. See module docstring for the phasing plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncMode {
    /// Compute and emit deltas; do NOT mutate the active validator set.
    /// Drift between chain-derived and file-derived sets is exposed via
    /// `SyncWorker::observed_addresses()` for telemetry.
    Shadow,
    /// Apply the chain-derived membership view to the active validator set.
    ChainAuthoritative,
}

/// Worker state mirrored to `validator-set-sync.cursor.json` on each apply.
#[derive(Default, serde::Serialize, serde::Deserialize)]
pub struct WorkerState {
    /// Highest `(block_height, log_index)` we've consumed. None on first run.
    pub cursor: Option<(u64, u32)>,
    /// Hash of the cursor block at the time we processed it.
    pub cursor_block_hash: Option<String>,
    /// Addresses the chain says are *currently* in the active validator set.
    /// In shadow mode this is the chain-derived view; we never mutate the
    /// actual `ValidatorSet`.
    pub observed_active: HashSet<String>,
}

/// One iteration's worth of work. Pulled out as a free function so it can
/// be unit-tested without an HTTP runtime.
pub fn apply_delta(state: &mut WorkerState, delta: &ValidatorSetDelta) {
    // Idempotency guard — never advance the cursor backwards.
    if let Some((h, i)) = state.cursor {
        if (delta.block_height, delta.log_index) <= (h, i) {
            return;
        }
    }
    match &delta.kind {
        DeltaKind::Add { .. } => {
            state.observed_active.insert(delta.addr.clone());
        }
        DeltaKind::Remove | DeltaKind::Unbond { .. } => {
            state.observed_active.remove(&delta.addr);
        }
        DeltaKind::Slash { amount_wei, .. } => {
            // The event alone doesn't tell us the post-slash stake; if it
            // drains to zero the contract emits a follow-up Withdrawn/Left.
            // Until then we keep the validator in the active set.
            tracing::debug!(
                target: "validator_set_sync",
                "slash observed addr={} amount_wei={}",
                delta.addr,
                amount_wei
            );
        }
        DeltaKind::Apply { .. } | DeltaKind::DropApplicant => {
            // Applicant lifecycle — no active-set effect.
        }
    }
    state.cursor = Some((delta.block_height, delta.log_index));
}

// ─── Async polling worker ────────────────────────────────────────────────────

use crate::{normalized_validator_key, validator_registration_status_text, NodeState};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

fn active_status_for(node_id: &str, validator_id: &str) -> String {
    if validator_id == node_id {
        "self".to_string()
    } else {
        "online".to_string()
    }
}

fn validator_from_registration(
    registration: &crate::ValidatorRegistrationStatus,
    fallback_stake: u64,
    node_id: &str,
) -> Option<common::Validator> {
    let identity = registration.identity.normalized();
    if !identity.is_complete() {
        return None;
    }

    let alias = if registration.alias.trim().is_empty() {
        identity.node_id.clone()
    } else {
        registration.alias.trim().to_string()
    };

    Some(common::Validator {
        id: identity.node_id.clone(),
        alias,
        pubkey: identity.ed25519_pubkey.clone(),
        eth_address: identity.evm_address.clone(),
        stake: registration.stake.max(fallback_stake),
        reputation: registration.reputation.max(100),
        status: active_status_for(node_id, &identity.node_id),
    })
}

async fn update_sync_status<F>(state: &Arc<RwLock<NodeState>>, update: F)
where
    F: FnOnce(&mut crate::state::ValidatorSetSyncStatus),
{
    let mut s = state.write().await;
    update(&mut s.validator_set_sync);
}

async fn seed_worker_state_from_bootstrap(state: &Arc<RwLock<NodeState>>) -> WorkerState {
    let s = state.read().await;
    let observed_active = s
        .validator_set_bootstrap
        .validators
        .iter()
        .filter_map(|validator| {
            let addr = normalized_validator_key(&validator.eth_address);
            if addr.is_empty() {
                return None;
            }
            let status = validator.status.trim().to_ascii_lowercase();
            if matches!(status.as_str(), "pending" | "jailed" | "offline") {
                None
            } else {
                Some(addr)
            }
        })
        .collect();

    WorkerState {
        cursor: None,
        cursor_block_hash: None,
        observed_active,
    }
}

async fn reconcile_state_from_worker(
    state: Arc<RwLock<NodeState>>,
    worker_state: &WorkerState,
) -> anyhow::Result<()> {
    let mut s = state.write().await;
    let node_id = s.config.node_id.clone();
    let active_addresses = worker_state.observed_active.clone();

    let current_by_addr: HashMap<String, common::Validator> = s
        .validator_set
        .validators
        .iter()
        .filter_map(|validator| {
            let addr = normalized_validator_key(&validator.eth_address);
            if addr.is_empty() {
                None
            } else {
                Some((addr, validator.clone()))
            }
        })
        .collect();

    let bootstrap_by_addr: HashMap<String, common::Validator> = s
        .validator_set_bootstrap
        .validators
        .iter()
        .filter_map(|validator| {
            let addr = normalized_validator_key(&validator.eth_address);
            if addr.is_empty() {
                None
            } else {
                Some((addr, validator.clone()))
            }
        })
        .collect();

    let mut next_validators = Vec::new();
    let mut sorted_active: Vec<String> = active_addresses.iter().cloned().collect();
    sorted_active.sort();

    for addr in sorted_active {
        let mut validator = current_by_addr
            .get(&addr)
            .cloned()
            .or_else(|| bootstrap_by_addr.get(&addr).cloned())
            .or_else(|| {
                s.validator_registrations
                    .get(&addr)
                    .and_then(|registration| validator_from_registration(registration, 0, &node_id))
            });

        if let Some(existing) = validator.as_mut() {
            if let Some(registration) = s.validator_registrations.get(&addr) {
                if let Some(from_registration) =
                    validator_from_registration(registration, existing.stake, &node_id)
                {
                    existing.id = from_registration.id;
                    existing.alias = from_registration.alias;
                    existing.pubkey = from_registration.pubkey;
                    existing.stake = existing.stake.max(from_registration.stake);
                    existing.reputation = existing.reputation.max(from_registration.reputation);
                }
            }
            existing.eth_address = addr.clone();
            existing.status = active_status_for(&node_id, &existing.id);
            if existing.alias.trim().is_empty() {
                existing.alias = existing.id.clone();
            }
            next_validators.push(existing.clone());
        } else {
            tracing::warn!(
                target: "validator_set_sync",
                "active validator {} has no registered node metadata; skipping admission until identity is registered",
                addr
            );
        }
    }

    s.validator_set.validators = next_validators;

    // Record this set in the height-indexed history (effective from the next
    // block) so blocks signed under it verify correctly after a later rotation
    // (ISSUE-050). record() dedups when membership is unchanged.
    let effective_from = s.chain.tip_height().unwrap_or(0).saturating_add(1);
    let data_dir = s.config.data_dir.clone();
    if let Err(e) =
        crate::validator_set_history::record(&data_dir, effective_from, &s.validator_set)
    {
        tracing::warn!(
            target: "validator_set_sync",
            "failed to record validator-set history snapshot: {}",
            e
        );
    }

    for registration in s.validator_registrations.values_mut() {
        let key = normalized_validator_key(&registration.identity.evm_address);
        let is_active = !key.is_empty() && active_addresses.contains(&key);
        registration.admitted_to_consensus = is_active;
        registration.active = is_active;
        registration.status = validator_registration_status_text(registration);
    }

    Ok(())
}

fn cursor_reorged(worker_state: &WorkerState, current_hash: &str) -> bool {
    worker_state
        .cursor_block_hash
        .as_ref()
        .map(|saved| !saved.eq_ignore_ascii_case(current_hash))
        .unwrap_or(false)
}

async fn fetch_block_hash(
    client: &reqwest::Client,
    rpc_url: &str,
    block_number: u64,
) -> anyhow::Result<String> {
    let resp: serde_json::Value = client
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getBlockByNumber",
            "params": [format!("0x{:x}", block_number), false],
            "id": 1,
        }))
        .send()
        .await?
        .json()
        .await?;

    resp["result"]["hash"]
        .as_str()
        .map(|hash| hash.to_string())
        .ok_or_else(|| anyhow::anyhow!("eth_getBlockByNumber returned no block hash"))
}

async fn rebuild_worker_state(
    client: &reqwest::Client,
    config: &SyncConfig,
    state: &Arc<RwLock<NodeState>>,
    safe_block: u64,
) -> anyhow::Result<WorkerState> {
    let mut worker_state = seed_worker_state_from_bootstrap(state).await;
    let endpoints = config.rpc_endpoints();

    if let Some(start_block) = config.start_block {
        worker_state.cursor = Some((start_block, u32::MAX));
        worker_state.cursor_block_hash =
            Some(fetch_block_hash_failover(client, &endpoints, start_block).await?);
    }

    let from_block = match worker_state.cursor {
        Some((height, _)) => height.saturating_add(1),
        None => safe_block.saturating_sub(1000),
    };

    if from_block <= safe_block {
        let mut deltas = fetch_deltas_failover(
            client,
            &endpoints,
            &config.staking_addr,
            from_block,
            safe_block,
        )
        .await?;
        deltas.sort_by_key(|delta| (delta.block_height, delta.log_index));
        for delta in deltas {
            apply_delta(&mut worker_state, &delta);
        }
        // Advance to safe_block even if no deltas observed, so subsequent
        // polls only scan the small tail above safe_block.
        let need_advance = worker_state
            .cursor
            .map(|(h, _)| h < safe_block)
            .unwrap_or(true);
        if need_advance {
            worker_state.cursor = Some((safe_block, u32::MAX));
        }
    }

    if let Some((height, _)) = worker_state.cursor {
        worker_state.cursor_block_hash =
            Some(fetch_block_hash_failover(client, &endpoints, height).await?);
    }

    Ok(worker_state)
}

/// Run the validator-set sync worker.
///
/// Polls `eth_getLogs` against Staking.sol, decodes events into deltas,
/// and applies them to the in-memory validator set (if not in shadow mode).
pub async fn run(
    config: SyncConfig,
    mode: SyncMode,
    state: Arc<RwLock<NodeState>>,
) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let endpoints = config.rpc_endpoints();
    if endpoints.len() > 1 {
        tracing::info!(
            target: "validator_set_sync",
            "L1 quorum reads enabled across {} RPC endpoints",
            endpoints.len()
        );
    } else {
        tracing::warn!(
            target: "validator_set_sync",
            "single L1 RPC endpoint — set CREG_ETH_RPC_FALLBACKS to add quorum endpoints \
             so one stale or compromised RPC cannot skew the validator set"
        );
    }
    let mut worker_state = match load_cursor(&state).await {
        Some(saved) => saved,
        None => {
            rebuild_worker_state(&client, &config, &state, config.start_block.unwrap_or(0)).await?
        }
    };
    // Always merge bootstrap validators into observed_active. Without this,
    // a restart with a persisted cursor that contains only 1 address (e.g. the
    // on-chain genesis validator) would permanently lose the other bootstrap
    // validators from the active set, collapsing the quorum.
    {
        let bootstrap = seed_worker_state_from_bootstrap(&state).await;
        for addr in bootstrap.observed_active {
            worker_state.observed_active.insert(addr);
        }
    }
    if worker_state.cursor.is_none() {
        if let Some(start_block) = config.start_block {
            worker_state.cursor = Some((start_block, u32::MAX));
            worker_state.cursor_block_hash =
                Some(fetch_block_hash_failover(&client, &endpoints, start_block).await?);
        }
    }
    if matches!(mode, SyncMode::ChainAuthoritative) {
        reconcile_state_from_worker(Arc::clone(&state), &worker_state).await?;
    }
    save_cursor(&state, &worker_state).await?;
    let mut interval =
        tokio::time::interval(std::time::Duration::from_secs(config.poll_interval_secs));

    loop {
        interval.tick().await;
        update_sync_status(&state, |status| {
            status.enabled = true;
            status.last_poll_at = Some(Utc::now().to_rfc3339());
            if status.state != "reorg-replaying" {
                status.state = "syncing".to_string();
            }
        })
        .await;

        let latest_block = match fetch_latest_block_quorum(&client, &endpoints).await {
            Ok(b) => b,
            Err(e) => {
                update_sync_status(&state, |status| {
                    status.state = "degraded".to_string();
                    status.last_error = Some(e.to_string());
                })
                .await;
                tracing::warn!("validator_set_sync: failed to fetch latest block: {}", e);
                continue;
            }
        };

        let safe_block = latest_block.saturating_sub(config.finality_lag_blocks);
        update_sync_status(&state, |status| {
            status.last_finalized_source_block = Some(safe_block);
        })
        .await;

        if let Some((cursor_block, _)) = worker_state.cursor {
            match fetch_block_hash_quorum(&client, &endpoints, cursor_block).await {
                HashQuorum::Agreed(current_hash) => {
                    if cursor_reorged(&worker_state, &current_hash) {
                        update_sync_status(&state, |status| {
                            status.state = "reorg-replaying".to_string();
                            status.last_error = None;
                        })
                        .await;
                        tracing::warn!(
                            target: "validator_set_sync",
                            cursor_block,
                            saved_hash =
                                worker_state.cursor_block_hash.as_deref().unwrap_or("<none>"),
                            current_hash = current_hash,
                            "validator-set sync detected an L1 reorg (majority-confirmed); \
                             rebuilding authoritative view"
                        );
                        worker_state =
                            rebuild_worker_state(&client, &config, &state, safe_block).await?;
                        if matches!(mode, SyncMode::ChainAuthoritative) {
                            reconcile_state_from_worker(Arc::clone(&state), &worker_state).await?;
                        }
                        save_cursor(&state, &worker_state).await?;
                    } else if worker_state.cursor_block_hash.is_none() {
                        worker_state.cursor_block_hash = Some(current_hash);
                        save_cursor(&state, &worker_state).await?;
                    }
                }
                HashQuorum::NoMajority => {
                    // Endpoints disagree with no majority — inconclusive. Do NOT
                    // rebuild on the word of a possibly-divergent single RPC.
                    tracing::warn!(
                        target: "validator_set_sync",
                        cursor_block,
                        "L1 endpoints disagree on cursor block hash with no majority; \
                         skipping reorg check this poll"
                    );
                }
                HashQuorum::Unavailable => {}
            }
        }

        let from_block = worker_state.cursor.map(|(h, _)| h + 1).unwrap_or_else(|| {
            config
                .start_block
                .map(|height| height.saturating_add(1))
                .unwrap_or_else(|| safe_block.saturating_sub(1000))
        });

        if from_block > safe_block {
            update_sync_status(&state, |status| {
                status.state = "synced".to_string();
                status.cursor_block = worker_state.cursor.map(|(height, _)| height);
                status.cursor_log_index = worker_state.cursor.map(|(_, idx)| idx);
                status.cursor_block_hash = worker_state.cursor_block_hash.clone();
                status.last_error = None;
            })
            .await;
            continue;
        }

        match fetch_deltas_failover(
            &client,
            &endpoints,
            &config.staking_addr,
            from_block,
            safe_block,
        )
        .await
        {
            Ok(mut deltas) => {
                deltas.sort_by_key(|delta| (delta.block_height, delta.log_index));
                for delta in deltas {
                    match mode {
                        SyncMode::Shadow => {
                            tracing::info!(
                                target: "validator_set_sync",
                                "[shadow] delta: {:?} addr={} block={}",
                                delta.kind, delta.addr, delta.block_height
                            );
                            apply_delta(&mut worker_state, &delta);
                        }
                        SyncMode::ChainAuthoritative => {
                            apply_delta(&mut worker_state, &delta);
                            if let Err(e) =
                                reconcile_state_from_worker(Arc::clone(&state), &worker_state).await
                            {
                                tracing::error!("Failed to apply delta to state: {}", e);
                            }
                        }
                    }
                }
                // Advance the cursor to the safe block we just scanned, even when no
                // deltas were observed. Without this, a chain with sparse or zero
                // staking events would re-walk the full block range on every poll
                // and on every restart (defeats REM-103 cursor persistence).
                let need_advance = worker_state
                    .cursor
                    .map(|(h, _)| h < safe_block)
                    .unwrap_or(true);
                if need_advance {
                    worker_state.cursor = Some((safe_block, u32::MAX));
                }
                if let Some((height, _)) = worker_state.cursor {
                    worker_state.cursor_block_hash =
                        Some(fetch_block_hash_failover(&client, &endpoints, height).await?);
                }
                if let Err(e) = save_cursor(&state, &worker_state).await {
                    tracing::warn!("Failed to save validator set sync cursor: {}", e);
                }
                update_sync_status(&state, |status| {
                    status.state = "synced".to_string();
                    status.cursor_block = worker_state.cursor.map(|(height, _)| height);
                    status.cursor_log_index = worker_state.cursor.map(|(_, idx)| idx);
                    status.cursor_block_hash = worker_state.cursor_block_hash.clone();
                    status.last_error = None;
                })
                .await;
            }
            Err(e) => {
                update_sync_status(&state, |status| {
                    status.state = "degraded".to_string();
                    status.last_error = Some(e.to_string());
                    status.cursor_block = worker_state.cursor.map(|(height, _)| height);
                    status.cursor_log_index = worker_state.cursor.map(|(_, idx)| idx);
                    status.cursor_block_hash = worker_state.cursor_block_hash.clone();
                })
                .await;
                tracing::warn!("validator_set_sync: failed to fetch deltas: {}", e);
            }
        }
    }
}

async fn fetch_latest_block(client: &reqwest::Client, rpc_url: &str) -> anyhow::Result<u64> {
    let resp: serde_json::Value = client
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_blockNumber",
            "params": [],
            "id": 1,
        }))
        .send()
        .await?
        .json()
        .await?;

    let hex = resp["result"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("eth_blockNumber returned no result"))?;
    u64::from_str_radix(hex.trim_start_matches("0x"), 16)
        .map_err(|e| anyhow::anyhow!("invalid block number: {}", e))
}

/// Max blocks per `eth_getLogs` call. Public Sepolia RPCs often cap range (e.g. 10k–50k).
const DEFAULT_ETH_GET_LOGS_BLOCK_CHUNK: u64 = 10_000;

fn eth_get_logs_block_chunk() -> u64 {
    std::env::var("CREG_ETH_LOG_CHUNK_BLOCKS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_ETH_GET_LOGS_BLOCK_CHUNK)
}

async fn fetch_deltas(
    client: &reqwest::Client,
    rpc_url: &str,
    staking_addr: &alloy::primitives::Address,
    from_block: u64,
    to_block: u64,
) -> anyhow::Result<Vec<ValidatorSetDelta>> {
    if from_block > to_block {
        return Ok(Vec::new());
    }

    let chunk_size = eth_get_logs_block_chunk();
    let mut deltas = Vec::new();
    let mut start = from_block;
    while start <= to_block {
        let end = start
            .saturating_add(chunk_size.saturating_sub(1))
            .min(to_block);
        let mut chunk = fetch_deltas_chunk(client, rpc_url, staking_addr, start, end).await?;
        deltas.append(&mut chunk);
        start = end.saturating_add(1);
        if start <= to_block {
            // Public RPCs (e.g. Infura free tier) rate-limit bursty eth_getLogs scans.
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        }
    }
    deltas.sort_by_key(|delta| (delta.block_height, delta.log_index));
    Ok(deltas)
}

fn eth_get_logs_retryable(err: &anyhow::Error) -> bool {
    let msg = err.to_string();
    msg.contains("eth_getLogs returned no result array")
        || msg.contains("Too Many Requests")
        || msg.contains("rate limit")
        || msg.contains("429")
}

async fn fetch_deltas_chunk(
    client: &reqwest::Client,
    rpc_url: &str,
    staking_addr: &alloy::primitives::Address,
    from_block: u64,
    to_block: u64,
) -> anyhow::Result<Vec<ValidatorSetDelta>> {
    let mut delay_ms = 500u64;
    for attempt in 0..5 {
        match fetch_deltas_chunk_once(client, rpc_url, staking_addr, from_block, to_block).await {
            Ok(deltas) => return Ok(deltas),
            Err(e) if attempt < 4 && eth_get_logs_retryable(&e) => {
                tracing::debug!(
                    target: "validator_set_sync",
                    attempt = attempt + 1,
                    from_block,
                    to_block,
                    "eth_getLogs transient failure, retrying in {}ms: {}",
                    delay_ms,
                    e
                );
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                delay_ms = delay_ms.saturating_mul(2);
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!()
}

async fn fetch_deltas_chunk_once(
    client: &reqwest::Client,
    rpc_url: &str,
    staking_addr: &alloy::primitives::Address,
    from_block: u64,
    to_block: u64,
) -> anyhow::Result<Vec<ValidatorSetDelta>> {
    let topics = vec![
        format!(
            "0x{}",
            hex::encode(IStakingEvents::ValidatorApplied::SIGNATURE_HASH.0)
        ),
        format!(
            "0x{}",
            hex::encode(IStakingEvents::ValidatorApproved::SIGNATURE_HASH.0)
        ),
        format!(
            "0x{}",
            hex::encode(IStakingEvents::ValidatorApprovedByConsensus::SIGNATURE_HASH.0)
        ),
        format!(
            "0x{}",
            hex::encode(IStakingEvents::ValidatorRejected::SIGNATURE_HASH.0)
        ),
        format!(
            "0x{}",
            hex::encode(IStakingEvents::ValidatorApplicationExpired::SIGNATURE_HASH.0)
        ),
        format!(
            "0x{}",
            hex::encode(IStakingEvents::ValidatorUnbonding::SIGNATURE_HASH.0)
        ),
        format!(
            "0x{}",
            hex::encode(IStakingEvents::ValidatorWithdrawn::SIGNATURE_HASH.0)
        ),
        format!(
            "0x{}",
            hex::encode(IStakingEvents::ValidatorLeft::SIGNATURE_HASH.0)
        ),
        format!(
            "0x{}",
            hex::encode(IStakingEvents::Slashed::SIGNATURE_HASH.0)
        ),
    ];

    let resp: serde_json::Value = client
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getLogs",
            "params": [{
                "address": format!("0x{}", hex::encode(staking_addr.0)),
                "fromBlock": format!("0x{:x}", from_block),
                "toBlock": format!("0x{:x}", to_block),
                "topics": [topics],
            }],
            "id": 1,
        }))
        .send()
        .await?
        .json()
        .await?;

    if let Some(err) = resp.get("error") {
        anyhow::bail!("eth_getLogs RPC error: {}", err);
    }
    let logs = resp["result"]
        .as_array()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "eth_getLogs returned no result array (use a full-archive Sepolia RPC; set CREG_ETH_RPC or -RpcUrl)"
            )
        })?;

    let mut deltas = Vec::new();
    for log in logs {
        let topics: Vec<alloy::primitives::B256> = log["topics"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|t| t.as_str().and_then(|s| s.parse().ok()))
            .collect();
        let data_hex = log["data"].as_str().unwrap_or("0x");
        let data = hex::decode(data_hex.trim_start_matches("0x")).unwrap_or_default();
        let block_number = u64::from_str_radix(
            log["blockNumber"]
                .as_str()
                .unwrap_or("0x0")
                .trim_start_matches("0x"),
            16,
        )
        .unwrap_or(0);
        let log_index = u32::from_str_radix(
            log["logIndex"]
                .as_str()
                .unwrap_or("0x0")
                .trim_start_matches("0x"),
            16,
        )
        .unwrap_or(0);
        let tx_hash = log["transactionHash"]
            .as_str()
            .unwrap_or("0x0000000000000000000000000000000000000000000000000000000000000000")
            .parse()
            .unwrap_or(alloy::primitives::B256::ZERO);

        let log_view = LogView {
            topics: &topics,
            data: &data,
            block_number,
            log_index,
            tx_hash,
        };

        match decode(log_view) {
            Ok(Some(delta)) => deltas.push(delta),
            Ok(None) => {}
            Err(e) => tracing::warn!("Failed to decode log: {}", e),
        }
    }

    Ok(deltas)
}

// ── Cursor persistence (sidecar JSON file) ───────────────────────────────────

fn cursor_path(data_dir: &std::path::Path) -> std::path::PathBuf {
    data_dir.join("validator-set-sync.cursor.json")
}

async fn load_cursor(state: &Arc<RwLock<NodeState>>) -> Option<WorkerState> {
    let data_dir = {
        let s = state.read().await;
        s.config.data_dir.clone()
    };
    let path = cursor_path(&data_dir);
    if !path.exists() {
        return None;
    }
    let json = tokio::fs::read_to_string(&path).await.ok()?;
    serde_json::from_str(&json).ok()
}

/// Reconcile the active validator set after local identity metadata is registered.
/// L1 deltas may have been applied before `/v1/validators/register` supplied
/// node_id/pubkey for an address already present in `observed_active`.
pub async fn reconcile_after_identity_registration(
    state: Arc<RwLock<NodeState>>,
) -> anyhow::Result<()> {
    let enabled = {
        let s = state.read().await;
        s.validator_set_sync.enabled
    };
    if !enabled {
        return Ok(());
    }
    if let Some(worker_state) = load_cursor(&state).await {
        reconcile_state_from_worker(state, &worker_state).await?;
    }
    Ok(())
}

async fn save_cursor(
    state: &Arc<RwLock<NodeState>>,
    worker_state: &WorkerState,
) -> anyhow::Result<()> {
    let data_dir = {
        let s = state.read().await;
        s.config.data_dir.clone()
    };
    let path = cursor_path(&data_dir);
    let json = serde_json::to_string_pretty(worker_state)?;
    let tmp = path.with_extension("cursor.json.tmp");
    tokio::fs::write(&tmp, &json).await?;
    tokio::fs::rename(&tmp, &path).await?;
    Ok(())
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{
        chain_store::ChainStore, config::NodeConfig, pending_pool::PendingPool,
        publisher_index::PublisherIndex, BridgeStatus, P2PStatus,
    };
    use alloy::primitives::LogData;
    use alloy::sol_types::SolEvent;
    use std::{collections::HashMap, sync::Arc};
    use tempfile::TempDir;
    use tokio::sync::RwLock;

    fn b256_zero() -> B256 {
        B256::ZERO
    }

    /// Encode an event the way the wire would carry it. alloy's
    /// `encode_log_data` already produces the right topics+data split for
    /// indexed/non-indexed fields, so we just unpack it.
    fn encode<E: SolEvent>(ev: &E) -> (Vec<B256>, Vec<u8>) {
        let ld: LogData = ev.encode_log_data();
        (ld.topics().to_vec(), ld.data.to_vec())
    }

    #[test]
    fn decode_validator_applied() {
        let validator: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let ev = IStakingEvents::ValidatorApplied {
            validator,
            stake: U256::from(123u64),
        };
        let (topics, data) = encode(&ev);
        let log = LogView {
            topics: &topics,
            data: &data,
            block_number: 100,
            log_index: 0,
            tx_hash: b256_zero(),
        };
        let delta = decode(log).unwrap().unwrap();
        assert_eq!(delta.addr, "0x1111111111111111111111111111111111111111");
        assert_eq!(delta.block_height, 100);
        assert!(matches!(delta.kind, DeltaKind::Apply { ref stake_wei } if stake_wei == "123"));
    }

    #[test]
    fn decode_validator_approved_by_consensus() {
        let validator: Address = "0x2222222222222222222222222222222222222222"
            .parse()
            .unwrap();
        let ev = IStakingEvents::ValidatorApprovedByConsensus {
            validator,
            nonce: U256::from(1u64),
            signerCount: U256::from(7u64),
        };
        let (topics, data) = encode(&ev);
        let log = LogView {
            topics: &topics,
            data: &data,
            block_number: 200,
            log_index: 1,
            tx_hash: b256_zero(),
        };
        let delta = decode(log).unwrap().unwrap();
        assert!(matches!(
            delta.kind,
            DeltaKind::Add {
                signer_count: Some(7),
                ..
            }
        ));
    }

    #[test]
    fn decode_validator_unbonding() {
        let validator: Address = "0x3333333333333333333333333333333333333333"
            .parse()
            .unwrap();
        let ev = IStakingEvents::ValidatorUnbonding {
            validator,
            unbondingAt: U256::from(1_700_000_000u64),
        };
        let (topics, data) = encode(&ev);
        let log = LogView {
            topics: &topics,
            data: &data,
            block_number: 300,
            log_index: 2,
            tx_hash: b256_zero(),
        };
        let delta = decode(log).unwrap().unwrap();
        assert!(
            matches!(
                delta.kind,
                DeltaKind::Unbond {
                    unbonding_at: 1_700_000_000
                }
            ),
            "got {:?}",
            delta.kind
        );
    }

    #[test]
    fn decode_unknown_topic_errors() {
        let log = LogView {
            topics: &[B256::repeat_byte(0xab)],
            data: &[],
            block_number: 1,
            log_index: 0,
            tx_hash: b256_zero(),
        };
        let err = decode(log).expect_err("unknown topic should fail");
        assert!(matches!(err, DecodeError::UnknownTopic(_)));
    }

    #[test]
    fn decode_no_topics_errors() {
        let log = LogView {
            topics: &[],
            data: &[],
            block_number: 1,
            log_index: 0,
            tx_hash: b256_zero(),
        };
        assert!(matches!(decode(log).unwrap_err(), DecodeError::NoTopics));
    }

    fn delta(addr: &str, kind: DeltaKind, block: u64, idx: u32) -> ValidatorSetDelta {
        ValidatorSetDelta {
            kind,
            addr: addr.into(),
            block_height: block,
            log_index: idx,
            tx_hash: "0x".into(),
        }
    }

    #[test]
    fn apply_delta_adds_then_removes() {
        let mut s = WorkerState::default();
        apply_delta(
            &mut s,
            &delta(
                "0xaaaa",
                DeltaKind::Add {
                    stake_wei: "0".into(),
                    signer_count: None,
                },
                10,
                0,
            ),
        );
        assert!(s.observed_active.contains("0xaaaa"));
        apply_delta(&mut s, &delta("0xaaaa", DeltaKind::Remove, 11, 0));
        assert!(!s.observed_active.contains("0xaaaa"));
        assert_eq!(s.cursor, Some((11, 0)));
    }

    #[test]
    fn apply_delta_is_idempotent_on_replay() {
        let mut s = WorkerState::default();
        let d = delta(
            "0xaaaa",
            DeltaKind::Add {
                stake_wei: "0".into(),
                signer_count: None,
            },
            10,
            0,
        );
        apply_delta(&mut s, &d);
        apply_delta(&mut s, &d); // replay
        assert_eq!(s.observed_active.len(), 1);
        assert_eq!(s.cursor, Some((10, 0)));
    }

    #[test]
    fn apply_delta_rejects_out_of_order() {
        let mut s = WorkerState::default();
        apply_delta(&mut s, &delta("0xaaaa", DeltaKind::Remove, 20, 5));
        // Older delta arriving late — must NOT regress the cursor or undo state.
        apply_delta(
            &mut s,
            &delta(
                "0xaaaa",
                DeltaKind::Add {
                    stake_wei: "0".into(),
                    signer_count: None,
                },
                10,
                0,
            ),
        );
        assert_eq!(s.cursor, Some((20, 5)));
        assert!(!s.observed_active.contains("0xaaaa"));
    }

    #[test]
    fn unbond_marks_inactive_in_observed_view() {
        let mut s = WorkerState::default();
        apply_delta(
            &mut s,
            &delta(
                "0xbeef",
                DeltaKind::Add {
                    stake_wei: "0".into(),
                    signer_count: None,
                },
                1,
                0,
            ),
        );
        apply_delta(
            &mut s,
            &delta("0xbeef", DeltaKind::Unbond { unbonding_at: 999 }, 2, 0),
        );
        assert!(!s.observed_active.contains("0xbeef"));
    }

    #[test]
    fn slash_alone_does_not_remove_validator() {
        let mut s = WorkerState::default();
        apply_delta(
            &mut s,
            &delta(
                "0xcafe",
                DeltaKind::Add {
                    stake_wei: "0".into(),
                    signer_count: None,
                },
                1,
                0,
            ),
        );
        apply_delta(
            &mut s,
            &delta(
                "0xcafe",
                DeltaKind::Slash {
                    amount_wei: "1000".into(),
                    reason: "downtime".into(),
                },
                2,
                0,
            ),
        );
        // Slash by itself is informational; removal comes via a follow-up Withdrawn/Left.
        assert!(s.observed_active.contains("0xcafe"));
    }

    #[test]
    fn delta_serde_roundtrip() {
        let d = delta(
            "0xaaaa",
            DeltaKind::Add {
                stake_wei: "1000000000000000000".into(),
                signer_count: Some(7),
            },
            42,
            3,
        );
        let json = serde_json::to_string(&d).unwrap();
        let back: ValidatorSetDelta = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    fn validator(id: &str, pubkey: &str, eth_address: &str) -> common::Validator {
        common::Validator {
            id: id.into(),
            alias: id.into(),
            pubkey: pubkey.into(),
            eth_address: eth_address.into(),
            stake: 100,
            reputation: 100,
            status: "online".into(),
        }
    }

    async fn make_test_state(
        bootstrap: common::ValidatorSet,
    ) -> anyhow::Result<(Arc<RwLock<NodeState>>, TempDir)> {
        let tempdir = tempfile::tempdir()?;
        let chain = ChainStore::open(tempdir.path())?;

        let state = Arc::new(RwLock::new(NodeState {
            chain,
            pending_pool: PendingPool::new(),
            publisher_index: PublisherIndex::new(),
            validator_set_bootstrap: bootstrap.clone(),
            validator_set: bootstrap,
            package_rounds: HashMap::new(),
            config: NodeConfig {
                data_dir: tempdir.path().to_path_buf(),
                node_id: "node-2".into(),
                ..Default::default()
            },
            p2p_status: P2PStatus::default(),
            bridge_status: BridgeStatus::default(),
            vrf_proofs: HashMap::new(),
            decryption_shares: HashMap::new(),
            validator_registrations: HashMap::new(),
            validator_set_sync: crate::state::ValidatorSetSyncStatus {
                enabled: true,
                mode: "chain-authoritative".into(),
                state: "starting".into(),
                ..Default::default()
            },
            view_change_certs: HashMap::new(),
            reorgs: Vec::new(),
            pbft_engine: crate::state::PbftEngine::new(),
        }));

        Ok((state, tempdir))
    }

    #[tokio::test]
    async fn reconcile_authoritative_view_replaces_bootstrap_membership() {
        let bootstrap = common::ValidatorSet::new(vec![validator(
            "node-1",
            &"11".repeat(32),
            "0x1111111111111111111111111111111111111111",
        )]);
        let (state, _tempdir) = make_test_state(bootstrap).await.unwrap();

        {
            let mut s = state.write().await;
            s.validator_registrations.insert(
                "0x2222222222222222222222222222222222222222".into(),
                crate::ValidatorRegistrationStatus {
                    alias: "node-2".into(),
                    identity: common::ValidatorIdentity {
                        evm_address: "0x2222222222222222222222222222222222222222".into(),
                        node_id: "node-2".into(),
                        ed25519_pubkey: "22".repeat(32),
                    },
                    stake: 250,
                    reputation: 100,
                    ..Default::default()
                },
            );
        }

        let worker_state = WorkerState {
            cursor: Some((12, 0)),
            cursor_block_hash: Some("0xabc".into()),
            observed_active: ["0x2222222222222222222222222222222222222222".into()]
                .into_iter()
                .collect(),
        };

        reconcile_state_from_worker(Arc::clone(&state), &worker_state)
            .await
            .unwrap();

        let s = state.read().await;
        assert_eq!(s.validator_set.validators.len(), 1);
        let validator = &s.validator_set.validators[0];
        assert_eq!(validator.id, "node-2");
        assert_eq!(
            validator.eth_address,
            "0x2222222222222222222222222222222222222222"
        );
        assert_eq!(validator.status, "self");
        let registration = s
            .validator_registrations
            .get("0x2222222222222222222222222222222222222222")
            .unwrap();
        assert!(registration.active);
        assert!(registration.admitted_to_consensus);
    }

    #[tokio::test]
    async fn cursor_roundtrip_persists_block_hash() {
        let (state, _tempdir) = make_test_state(common::ValidatorSet::default())
            .await
            .unwrap();
        let worker_state = WorkerState {
            cursor: Some((42, 7)),
            cursor_block_hash: Some("0xdeadbeef".into()),
            observed_active: ["0xaaaa".into()].into_iter().collect(),
        };

        save_cursor(&state, &worker_state).await.unwrap();
        let loaded = load_cursor(&state).await.unwrap();

        assert_eq!(loaded.cursor, Some((42, 7)));
        assert_eq!(loaded.cursor_block_hash.as_deref(), Some("0xdeadbeef"));
        assert!(loaded.observed_active.contains("0xaaaa"));
    }

    #[test]
    fn cursor_hash_mismatch_flags_reorg() {
        let worker_state = WorkerState {
            cursor: Some((7, u32::MAX)),
            cursor_block_hash: Some("0x1111".into()),
            observed_active: HashSet::new(),
        };
        assert!(cursor_reorged(&worker_state, "0x2222"));
        assert!(!cursor_reorged(&worker_state, "0x1111"));
    }
}
