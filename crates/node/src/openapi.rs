// crates/node/src/openapi.rs
// OpenAPI spec for the node's public REST surface.
//
// Kept in its own module so that adding utoipa schema derives does not
// couple to the existing 1.7k-line api.rs handler soup. The schemas here
// mirror the shapes those handlers emit today; the explorer's TypeScript
// codegen reads the resulting /v1/openapi.json.
//
// When adding a new endpoint: define its response schema here, add a stub
// handler with `#[utoipa::path]` to the per-tag modules below, then list
// the path + schema in the `ApiDoc` struct.

use utoipa::{
    openapi::security::{ApiKey, ApiKeyValue, SecurityScheme},
    Modify, OpenApi, ToSchema,
};

// ─── Shared response schemas ──────────────────────────────────────────────────

#[derive(serde::Serialize, ToSchema)]
pub struct ApiError {
    /// Human-readable error message. Intended for display.
    pub error: String,
}

#[derive(serde::Serialize, ToSchema)]
pub struct Health {
    /// Always "ok" when the node is responsive.
    #[schema(example = "ok")]
    pub status: String,
    /// Semver of the node binary (from Cargo.toml).
    #[schema(example = "0.1.0")]
    pub version: String,
}

#[derive(serde::Serialize, ToSchema)]
pub struct ChainStats {
    /// Current tip height.
    pub current_height: u64,
    /// Highest finalized height. Trails tip by the finality window.
    pub finalized_height: u64,
    /// Finalized tip hash, hex.
    pub finalized_hash: Option<String>,
    pub genesis_hash: Option<String>,
    /// Active validator count.
    pub validator_count: usize,
    /// Sum of validator stakes (native units).
    pub total_stake: u64,
    /// Connected P2P peer count.
    pub peer_count: usize,
    /// Bridge sync state. "Synced" | "Syncing" | "Unknown" | error strings.
    pub bridge_status: String,
    /// Last L1 block that the bridge read.
    pub l1_block: u64,
    pub package_count: Option<usize>,
    pub publisher_count: Option<usize>,
    pub pending_tx_count: Option<usize>,
}

#[derive(serde::Serialize, ToSchema)]
pub struct RuntimeConfig {
    pub is_testnet: bool,
    /// Registry.sol contract address on the configured L1, if set.
    pub registry_address: Option<String>,
    pub token_contract: Option<String>,
    pub staking_contract: Option<String>,
    /// Machine-readable registration flow id (e.g. "staking-plus-identity-sync").
    pub validator_registration_mode: String,
    /// Operator-facing note describing the validator onboarding flow.
    pub validator_registration_note: String,
}

#[derive(serde::Serialize, ToSchema)]
pub struct ValidatorIdentityInfo {
    pub evm_address: String,
    pub node_id: String,
    pub ed25519_pubkey: String,
}

#[derive(serde::Serialize, ToSchema)]
pub struct ValidatorRegistration {
    pub alias: String,
    pub identity: ValidatorIdentityInfo,
    pub status: String,
    pub registered_with_node: bool,
    pub reputation: i64,
    pub stake: Option<String>,
}

#[derive(serde::Serialize, ToSchema)]
pub struct BlockSummary {
    pub height: u64,
    pub hash: String,
    pub prev_hash: String,
    pub timestamp_ms: i64,
    pub producer: String,
    pub tx_count: usize,
    pub finalized: bool,
}

#[derive(serde::Serialize, ToSchema)]
pub struct BlockDetail {
    pub height: u64,
    pub hash: String,
    pub prev_hash: String,
    pub timestamp_ms: i64,
    pub producer: String,
    pub finalized: bool,
    pub signature: Option<String>,
    pub transactions: Vec<TransactionSummary>,
    /// Vote-producing validator addresses that approved this block.
    pub votes: Vec<String>,
    /// Quorum threshold this block was tested against.
    pub quorum: Option<usize>,
}

#[derive(serde::Serialize, ToSchema)]
pub struct TransactionSummary {
    pub canonical: String,
    pub publisher: String,
    pub block_height: Option<u64>,
    pub status: String,
}

#[derive(serde::Serialize, ToSchema)]
pub struct TransactionDetail {
    pub canonical: String,
    pub version: String,
    pub publisher: String,
    pub block_height: Option<u64>,
    pub included_at: Option<String>,
    pub ipfs_cid: Option<String>,
    pub payload_hash: Option<String>,
    pub status: String,
    /// Arbitrary validation metadata. Shape stabilises once the pipeline
    /// stages are finalised — for now the explorer just surfaces key/value rows.
    #[schema(value_type = Object)]
    pub validation: serde_json::Value,
}

#[derive(serde::Serialize, ToSchema)]
pub struct PackageSummary {
    pub canonical: String,
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub status: String,
    pub publisher: String,
    pub published_at: String,
    pub analysis_bundles: AnalysisBundleRefs,
    pub evidence_digest: String,
    pub deterministic_risk: DeterministicRiskSummary,
}

#[derive(serde::Serialize, ToSchema)]
pub struct AnalysisBundleRefs {
    pub policy_bundle_id: String,
    pub feature_schema_id: String,
    pub expert_bundle_id: String,
    pub embedding_model_id: String,
    pub index_epoch: String,
    pub threshold_profile_id: String,
    pub llm_prompt_profile_id: String,
    pub osv_snapshot_epoch: String,
}

#[derive(serde::Serialize, ToSchema)]
pub struct DeterministicRiskSummary {
    pub score: u8,
    pub deterministic_score: u8,
    pub advisory_score: u8,
    pub band: String,
    pub disposition: String,
    pub deterministic_findings: usize,
    pub advisory_findings: usize,
    pub critical_findings: usize,
    pub high_findings: usize,
    pub medium_findings: usize,
    pub low_findings: usize,
    pub reasons: Vec<String>,
}

#[derive(serde::Serialize, ToSchema)]
pub struct PackageList {
    pub packages: Vec<PackageSummary>,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
}

#[derive(serde::Serialize, ToSchema)]
pub struct PackageDetail {
    pub canonical: String,
    pub status: String,
    pub block_hash: Option<String>,
    pub content_hash: Option<String>,
    pub ipfs_cid: Option<String>,
    pub publisher: Option<String>,
    pub published_at: Option<String>,
    pub revocation_reason: Option<String>,
    pub analysis_bundles: Option<AnalysisBundleRefs>,
    pub evidence_digest: Option<String>,
    pub deterministic_risk: Option<DeterministicRiskSummary>,
}

#[derive(serde::Serialize, ToSchema)]
pub struct Pending {
    pub canonical: String,
    pub publisher: String,
    pub received_at: String,
    pub stage: Option<String>,
}

#[derive(serde::Serialize, ToSchema)]
pub struct PendingList {
    pub pending: Vec<Pending>,
    pub total: usize,
}

#[derive(serde::Serialize, ToSchema)]
pub struct NodeEntry {
    pub id: String,
    pub address: Option<String>,
    pub role: Option<String>,
    pub status: Option<String>,
}

#[derive(serde::Serialize, ToSchema)]
pub struct BridgeStatus {
    pub l1_chain_id: Option<u64>,
    pub bridge_contract: Option<String>,
    pub last_anchor_block: Option<u64>,
    pub last_anchor_root: Option<String>,
    pub signer_address: Option<String>,
    pub bridge_sync_status: String,
    pub last_finalized_eth_block: u64,
}

#[derive(serde::Serialize, ToSchema)]
pub struct ConsensusVote {
    pub validator_id: String,
    pub decision: String,
    pub reject_reason: Option<String>,
    pub ml_model_version: String,
    pub analysis_bundles: AnalysisBundleRefs,
    pub evidence_digest: String,
    pub deterministic_risk: DeterministicRiskSummary,
}

#[derive(serde::Serialize, ToSchema)]
pub struct ConsensusRound {
    pub consensus_subject: String,
    pub vote_count: usize,
    pub approvals: usize,
    pub rejections: usize,
    /// "collecting-votes" | "contested" | "quorum-reached".
    pub phase: String,
    pub voters: Vec<String>,
    pub approvers: Vec<String>,
    pub rejecters: Vec<String>,
    pub votes: Vec<ConsensusVote>,
    /// Milliseconds since the earliest vote in this round.
    pub age_ms: i64,
}

#[derive(serde::Serialize, ToSchema)]
pub struct ConsensusValidator {
    pub id: String,
    pub alias: String,
    pub stake: u64,
    pub reputation: u32,
    pub status: String,
}

#[derive(serde::Serialize, ToSchema)]
pub struct ConsensusState {
    pub total_validators: usize,
    pub quorum: usize,
    pub active_rounds: Vec<ConsensusRound>,
    pub pending_count: usize,
    pub validators: Vec<ConsensusValidator>,
}

#[derive(serde::Serialize, ToSchema)]
pub struct AddressProfile {
    pub address: String,
    pub is_validator: bool,
    pub is_active_validator: bool,
    pub validator: Option<ValidatorRegistration>,
    /// Status from the active validator set when applicable ("online" | "self" | "offline").
    pub active_status: Option<String>,
    pub stake: Option<String>,
    pub reputation: Option<u32>,
    /// Blocks proposed by this address within `scanned_blocks`.
    pub blocks_proposed: u32,
    /// Txs referencing this address within `scanned_blocks`.
    pub tx_count: u32,
    /// How many most-recent blocks were inspected to build this profile.
    pub scanned_blocks: u64,
}

#[derive(serde::Serialize, ToSchema)]
pub struct AddressTxRef {
    pub block_height: u64,
    pub block_hash: String,
    pub tx_index: usize,
    /// One of: "publish" | "revoke" | "slash" | "validator-join" | "validator-leave" | "rotate-key" | "propose".
    pub kind: String,
    pub canonical: Option<String>,
    pub timestamp: String,
}

#[derive(serde::Serialize, ToSchema)]
pub struct AddressTxList {
    pub address: String,
    pub transactions: Vec<AddressTxRef>,
    pub scanned_blocks: u64,
    pub total: usize,
}

#[derive(serde::Serialize, ToSchema)]
pub struct ValidatorProfile {
    pub address: String,
    pub registration: Option<ValidatorRegistration>,
    pub in_active_set: bool,
    pub stake: String,
    pub reputation: u32,
    pub status: String,
    /// Blocks proposed by this validator within the recent window (newest first).
    pub recent_proposals: Vec<BlockSummary>,
}

// ─── Path stubs ───────────────────────────────────────────────────────────────
//
// utoipa introspects these stub functions for the OpenAPI metadata. They are
// never called — axum wires the real handlers in `api.rs`. The pairing is
// maintained by convention: the stub's `path = "..."` must match the router.

pub mod paths {
    use super::*;

    /// Health probe. Returns 200 with build info when the node is live.
    #[utoipa::path(
        get,
        path = "/v1/health",
        tag = "system",
        responses((status = 200, body = Health, description = "Node is alive")),
    )]
    pub async fn health() {}

    /// Chain stats — tip height, finality, validator and peer counts.
    #[utoipa::path(
        get,
        path = "/v1/chain/stats",
        tag = "system",
        responses((status = 200, body = ChainStats)),
    )]
    pub async fn chain_stats() {}

    /// Runtime configuration — testnet flag, contract addresses, validator flow mode.
    #[utoipa::path(
        get,
        path = "/v1/runtime/config",
        tag = "system",
        responses((status = 200, body = RuntimeConfig)),
    )]
    pub async fn runtime_config() {}

    /// Paginated block list. Supports offset/limit and `before_height` / `after_height` cursors.
    ///
    /// - `before_height=H`: return blocks with height < H, newest first.
    /// - `after_height=H`: return blocks with height > H, newest first.
    /// - Omit cursors and use `offset`/`limit` for classic pagination.
    #[utoipa::path(
        get,
        path = "/v1/blocks",
        tag = "blocks",
        params(
            ("limit" = Option<usize>, Query, description = "Max blocks to return (default 20, max 100)"),
            ("offset" = Option<usize>, Query, description = "Offset into the list (ignored when cursors are set)"),
            ("before_height" = Option<u64>, Query, description = "Return blocks below this height"),
            ("after_height" = Option<u64>, Query, description = "Return blocks above this height"),
        ),
        responses((status = 200, body = [BlockSummary])),
    )]
    pub async fn list_blocks() {}

    /// Fetch a block by height.
    #[utoipa::path(
        get,
        path = "/v1/blocks/{height}",
        tag = "blocks",
        params(("height" = u64, Path, description = "Block height")),
        responses(
            (status = 200, body = BlockDetail),
            (status = 404, body = ApiError),
        ),
    )]
    pub async fn get_block_by_height() {}

    /// Fetch a block by its 0x-prefixed hash.
    #[utoipa::path(
        get,
        path = "/v1/blocks/hash/{hash}",
        tag = "blocks",
        params(("hash" = String, Path, description = "0x-prefixed block hash")),
        responses(
            (status = 200, body = BlockDetail),
            (status = 404, body = ApiError),
        ),
    )]
    pub async fn get_block_by_hash() {}

    /// Fetch a transaction by its canonical id (`name@version`) or tx hash.
    #[utoipa::path(
        get,
        path = "/v1/transactions/{canonical}",
        tag = "transactions",
        params(("canonical" = String, Path, description = "Package canonical or tx hash")),
        responses(
            (status = 200, body = TransactionDetail),
            (status = 404, body = ApiError),
        ),
    )]
    pub async fn get_transaction() {}

    /// Paginated package list.
    #[utoipa::path(
        get,
        path = "/v1/packages",
        tag = "packages",
        params(
            ("limit" = Option<usize>, Query, description = "Max packages to return (default 50, max 200)"),
            ("offset" = Option<usize>, Query, description = "Offset into the result set (default 0)"),
            ("ecosystem" = Option<String>, Query, description = "Filter by ecosystem (npm, pypi, …)"),
            ("status" = Option<String>, Query, description = "Filter by status (verified | pending | revoked)"),
        ),
        responses((status = 200, body = PackageList)),
    )]
    pub async fn list_packages() {}

    /// Fetch a package by canonical id (`<ecosystem>:<name>@<version>`).
    #[utoipa::path(
        get,
        path = "/v1/packages/{canonical}",
        tag = "packages",
        params(("canonical" = String, Path, description = "Package canonical id (`<ecosystem>:<name>@<version>`)")),
        responses(
            (status = 200, body = PackageDetail),
            (status = 404, body = ApiError),
        ),
    )]
    pub async fn get_package() {}

    /// Pending pool contents — not yet finalized txs.
    #[utoipa::path(
        get,
        path = "/v1/pending",
        tag = "transactions",
        responses((status = 200, body = PendingList)),
    )]
    pub async fn list_pending() {}

    /// Validator set as understood by this node (includes "self" marker).
    #[utoipa::path(
        get,
        path = "/v1/nodes",
        tag = "network",
        responses((status = 200, body = [NodeEntry])),
    )]
    pub async fn get_nodes() {}

    /// Bridge health + last L1 anchor commit.
    #[utoipa::path(
        get,
        path = "/v1/bridge/status",
        tag = "bridge",
        responses((status = 200, body = BridgeStatus)),
    )]
    pub async fn bridge_status() {}

    /// Validator identity registrations known to this node.
    #[utoipa::path(
        get,
        path = "/v1/validators/registrations",
        tag = "validators",
        responses((status = 200, body = [ValidatorRegistration])),
    )]
    pub async fn list_validator_registrations() {}

    /// Live PBFT round state — in-flight proposals with quorum progress.
    #[utoipa::path(
        get,
        path = "/v1/consensus/state",
        tag = "consensus",
        responses((status = 200, body = ConsensusState)),
    )]
    pub async fn consensus_state() {}

    /// Aggregate profile for an EVM address: validator identity (if any) plus
    /// recent on-chain activity counts.
    #[utoipa::path(
        get,
        path = "/v1/addresses/{address}",
        tag = "addresses",
        params(("address" = String, Path, description = "EVM address (0x…)")),
        responses(
            (status = 200, body = AddressProfile),
            (status = 400, body = ApiError),
        ),
    )]
    pub async fn get_address() {}

    /// Transactions touching an address, scanned from the most recent blocks.
    #[utoipa::path(
        get,
        path = "/v1/addresses/{address}/transactions",
        tag = "addresses",
        params(
            ("address" = String, Path, description = "EVM address"),
            ("limit" = Option<usize>, Query, description = "Max txs to return (default 50, max 500)"),
            ("scan" = Option<u64>, Query, description = "Max blocks to scan backwards (default 500, max 5000)"),
        ),
        responses(
            (status = 200, body = AddressTxList),
            (status = 400, body = ApiError),
        ),
    )]
    pub async fn get_address_transactions() {}

    /// Validator profile — registration status, active-set info, and recent block proposals.
    #[utoipa::path(
        get,
        path = "/v1/validators/{address}",
        tag = "validators",
        params(("address" = String, Path, description = "Validator EVM address")),
        responses(
            (status = 200, body = ValidatorProfile),
            (status = 404, body = ApiError),
        ),
    )]
    pub async fn get_validator_profile() {}

    /// Register the caller's validator identity (EVM address ↔ ed25519 pubkey ↔ node id).
    /// Requires an Ethereum personal-sign signature from the EVM address and
    /// an Ed25519 signature from the validator key over the same binding message.
    #[utoipa::path(
        post,
        path = "/v1/validators/register",
        tag = "validators",
        request_body(content = Object, description = "alias, evm_address, node_id, ed25519_pubkey, nonce, evm_signature, ed25519_signature"),
        responses(
            (status = 200, body = ValidatorRegistration),
            (status = 400, body = ApiError),
        ),
    )]
    pub async fn register_validator_identity() {}

    /// P2P topology — peer list, role, and connection health.
    #[utoipa::path(
        get,
        path = "/v1/p2p/status",
        tag = "network",
        responses((status = 200, body = Object)),
    )]
    pub async fn p2p_status() {}

    /// Recent L1 anchor commits — chain-id, L1 block, Merkle root, L1 tx hash.
    #[utoipa::path(
        get,
        path = "/v1/bridge/anchors",
        tag = "bridge",
        params(("limit" = Option<usize>, Query, description = "Max anchors (default 50, max 500)")),
        responses((status = 200, body = [Object])),
    )]
    pub async fn bridge_anchors() {}

    /// Governance proposal list mirrored from Governance.sol via the bridge.
    #[utoipa::path(
        get,
        path = "/v1/governance/proposals",
        tag = "governance",
        responses((status = 200, body = [Object])),
    )]
    pub async fn governance_proposals() {}

    /// Rolling metrics time-series — TPS, block time, validator count, stake, pending depth.
    #[utoipa::path(
        get,
        path = "/v1/metrics/history",
        tag = "system",
        params(
            ("series" = Option<String>, Query, description = "Comma-separated series names"),
            ("window" = Option<String>, Query, description = "Lookback window (e.g. 1h, 24h)"),
        ),
        responses((status = 200, body = Object)),
    )]
    pub async fn metrics_history() {}

    /// Detected reorgs — height, old/new tip, depth, timestamp.
    #[utoipa::path(
        get,
        path = "/v1/reorgs",
        tag = "system",
        responses((status = 200, body = [Object])),
    )]
    pub async fn reorgs() {}

    /// Top addresses by staked / native balance.
    #[utoipa::path(
        get,
        path = "/v1/richlist",
        tag = "addresses",
        params(("limit" = Option<usize>, Query, description = "Max entries (default 50, max 500)")),
        responses((status = 200, body = [Object])),
    )]
    pub async fn richlist() {}

    /// Submit a new package for inclusion — enters the pending pool and the validator pipeline.
    #[utoipa::path(
        post,
        path = "/v1/packages",
        tag = "packages",
        request_body(content = Object, description = "PublishRequest: canonical, ipfs_cid, payload_hash, publisher, signature"),
        responses(
            (status = 200, body = Object),
            (status = 400, body = ApiError),
        ),
    )]
    pub async fn submit_package() {}

    /// Revoke an existing package (operator / publisher only).
    #[utoipa::path(
        post,
        path = "/v1/packages/{canonical}/revoke",
        tag = "packages",
        params(("canonical" = String, Path, description = "Package canonical id")),
        request_body(content = Object, description = "{ reason: String, signature: String }"),
        responses(
            (status = 200, body = Object),
            (status = 400, body = ApiError),
        ),
        security(("OperatorKey" = [])),
    )]
    pub async fn revoke_package() {}

    /// Merkle proof for a package, verifiable against the current chain tip header.
    #[utoipa::path(
        get,
        path = "/v1/packages/{canonical}/proof",
        tag = "packages",
        params(("canonical" = String, Path, description = "Package canonical id")),
        responses(
            (status = 200, body = Object),
            (status = 404, body = ApiError),
        ),
    )]
    pub async fn get_proof() {}

    /// Gossip endpoint — accept a freshly-signed block from a peer.
    #[utoipa::path(
        post,
        path = "/v1/blocks/announce",
        tag = "blocks",
        request_body(content = Object, description = "Signed block payload"),
        responses(
            (status = 200, body = Object),
            (status = 400, body = ApiError),
        ),
    )]
    pub async fn receive_block_announcement() {}

    /// Publisher profile — package count, reputation, key rotation history.
    #[utoipa::path(
        get,
        path = "/v1/publishers/{pubkey}",
        tag = "addresses",
        params(("pubkey" = String, Path, description = "Publisher public key or canonical id")),
        responses(
            (status = 200, body = Object),
            (status = 404, body = ApiError),
        ),
    )]
    pub async fn get_publisher() {}

    /// Consensus vote intake — PBFT PREPARE/COMMIT vote from a validator.
    #[utoipa::path(
        post,
        path = "/v1/consensus/vote",
        tag = "consensus",
        request_body(content = Object, description = "SignedVote: consensus_subject, phase, voter, signature"),
        responses(
            (status = 200, body = Object),
            (status = 400, body = ApiError),
        ),
    )]
    pub async fn receive_vote() {}

    /// Rotate a publisher signing key — requires a signed rotation request from the old key.
    #[utoipa::path(
        post,
        path = "/v1/publishers/rotate-key",
        tag = "addresses",
        request_body(content = Object, description = "{ old_pubkey, new_pubkey, signature }"),
        responses(
            (status = 200, body = Object),
            (status = 400, body = ApiError),
        ),
    )]
    pub async fn rotate_publisher_key() {}

    /// Global smart search — classifies `q` as block height / hash / EVM address /
    /// package canonical / publisher and returns candidate matches.
    #[utoipa::path(
        get,
        path = "/v1/search",
        tag = "system",
        params(("q" = String, Query, description = "Query string (height, hash, address, canonical, or prefix)")),
        responses((status = 200, body = Object)),
    )]
    pub async fn search_handler() {}

    /// Submit an audit decision against a pending appeal (operator only).
    #[utoipa::path(
        post,
        path = "/v1/appeals/{id}/audit",
        tag = "system",
        params(("id" = String, Path, description = "Appeal id")),
        request_body(content = Object, description = "{ verdict, notes, signature }"),
        responses(
            (status = 200, body = Object),
            (status = 400, body = ApiError),
        ),
        security(("OperatorKey" = [])),
    )]
    pub async fn submit_audit() {}
}

// ─── Security schemes ─────────────────────────────────────────────────────────
//
// Most routes are public; operator endpoints gate on the `X-Operator-Key`
// header. Declared here so it's visible in Swagger UI.

struct SecurityAddon;
impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi
            .components
            .get_or_insert_with(utoipa::openapi::Components::default);
        components.add_security_scheme(
            "OperatorKey",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("X-Operator-Key"))),
        );
    }
}

// ─── Root spec ────────────────────────────────────────────────────────────────

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Chain Registry Node API",
        version = "0.1.0",
        description = "Public REST surface of a Chain Registry node. Consumed by the web explorer, TUI explorer, and CLI.",
        license(name = "Apache-2.0"),
    ),
    servers(
        (url = "/", description = "Current host"),
    ),
    tags(
        (name = "system",       description = "Health, runtime configuration, search, metrics, reorgs, appeals"),
        (name = "blocks",       description = "Block list, lookup by height or hash, gossip intake"),
        (name = "transactions", description = "Transaction lookup and pending pool"),
        (name = "packages",     description = "Package publish records, proofs, revocation"),
        (name = "validators",   description = "Validator identity registrations and profiles"),
        (name = "consensus",    description = "PBFT round state and vote intake"),
        (name = "network",      description = "Peer set and P2P topology"),
        (name = "bridge",       description = "L1 bridge anchor status and commit feed"),
        (name = "addresses",    description = "Per-address profiles, activity, publishers, rich list"),
        (name = "governance",   description = "On-chain governance proposals and votes"),
    ),
    paths(
        paths::health,
        paths::chain_stats,
        paths::runtime_config,
        paths::list_blocks,
        paths::get_block_by_height,
        paths::get_block_by_hash,
        paths::get_transaction,
        paths::list_packages,
        paths::get_package,
        paths::list_pending,
        paths::get_nodes,
        paths::bridge_status,
        paths::list_validator_registrations,
        paths::consensus_state,
        paths::get_address,
        paths::get_address_transactions,
        paths::get_validator_profile,
        paths::register_validator_identity,
        paths::p2p_status,
        paths::bridge_anchors,
        paths::governance_proposals,
        paths::metrics_history,
        paths::reorgs,
        paths::richlist,
        paths::submit_package,
        paths::revoke_package,
        paths::get_proof,
        paths::receive_block_announcement,
        paths::get_publisher,
        paths::receive_vote,
        paths::rotate_publisher_key,
        paths::search_handler,
        paths::submit_audit,
    ),
    components(schemas(
        ApiError,
        Health,
        ChainStats,
        RuntimeConfig,
        ValidatorIdentityInfo,
        ValidatorRegistration,
        BlockSummary,
        BlockDetail,
        TransactionSummary,
        TransactionDetail,
        PackageSummary,
        AnalysisBundleRefs,
        DeterministicRiskSummary,
        PackageList,
        PackageDetail,
        Pending,
        PendingList,
        NodeEntry,
        BridgeStatus,
        ConsensusVote,
        ConsensusRound,
        ConsensusValidator,
        ConsensusState,
        AddressProfile,
        AddressTxRef,
        AddressTxList,
        ValidatorProfile,
    )),
    modifiers(&SecurityAddon),
)]
pub struct ApiDoc;
