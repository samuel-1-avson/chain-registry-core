// crates/node/src/lib.rs
// Library target for the chain-registry-node crate (crate name: "node").
// Exposes internal subsystems so that integration tests in tests/ can spin
// up a real in-process node and drive the full publish → verify lifecycle.

// ── Public modules (used directly by integration tests) ──────────────────────
pub mod admission_scan;
pub mod api;
pub mod block_producer;
pub mod bridge_anchors;
pub mod chain_store;
pub mod config;
pub mod consensus_admission;
pub mod events;
pub mod finalized_tx;
pub mod gossip;
pub mod intelligence;
pub mod json_rpc;
pub mod l1_quorum;
pub mod openapi;
pub mod p2p;
pub mod package_admission;
pub mod pending_pool;
pub mod publisher_index;
pub mod rate_limit;
pub mod state;
pub mod validator_pipeline;
pub mod validator_registry_gossip;
pub mod validator_set_history;
pub mod validator_set_sync;

// ── Private modules required by the public ones above ────────────────────────
mod bridge;
mod db_sync_proxy;
mod explorer;
mod grpc;
mod metrics;
mod p2p_rate_limit;
mod pidlock;
mod proof;
mod sync;

// ── Re-export state types at the crate root ───────────────────────────────────
// api.rs, block_producer.rs, etc. reference these as `crate::NodeState`,
// `crate::SharedState`, etc. — they must live at the lib root.
pub use state::{
    normalized_validator_key, validator_registration_status_text, BridgeStatus, NodeState,
    P2PStatus, SharedState, ValidatorRegistrationStatus, ValidatorSetSyncStatus,
};
