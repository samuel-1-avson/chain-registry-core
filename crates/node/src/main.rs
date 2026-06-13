// crates/node/src/main.rs
// Chain registry node â€” single binary that runs all subsystems.
#![deny(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod admission_scan;
mod api;
mod block_producer;
mod bridge;
mod bridge_anchors;
mod chain_store;
mod config;
mod consensus_admission;
mod db_sync_proxy;
mod events;
mod explorer;
mod finalized_tx;
mod gossip;
mod grpc;
mod intelligence;
mod json_rpc;
mod l1_quorum;
mod metrics;
mod openapi;
mod p2p;
mod p2p_rate_limit;
mod package_admission;
mod pending_pool;
mod pidlock;
mod proof;
mod publisher_index;
mod rate_limit;
mod state;
mod sync;
mod validator_pipeline;
mod validator_registry_gossip;
mod validator_set_history;
// Phase-1 scaffold for chain-derived validator set. Compiled and tested but
// not yet wired into runtime â€” see docs/VALIDATOR_SET_SYNC_DESIGN.md.
mod chain_spec_boot;
mod validator_set_sync;

use alloy::{
    providers::{Provider, ProviderBuilder},
    sol,
};
use anyhow::{Context, Result};
use chrono::Utc;
use common::ValidatorIdentity;
use std::{collections::HashMap, sync::Arc};
use tokio::{
    sync::RwLock,
    time::{interval, sleep, Duration},
};
use tracing_subscriber::EnvFilter;

use events::new_event_bus;
use finalized_tx::{FinalizedTxReceiver, FinalizedTxSender};
use publisher_index::PublisherIndex;
use state::{
    normalized_validator_key, validator_registration_status_text, BridgeStatus, NodeState,
    P2PStatus, SharedState, ValidatorRegistrationStatus,
};

sol!(
    #[sol(rpc)]
    interface IStakingRead {
        function validators(address)
            external
            view
            returns (
                uint256 stake,
                uint8 state,
                uint256 unbondingAt,
                uint256 slashCount,
                uint256 ejectedAt,
                uint256 appliedAt
            );
    }
);

fn staking_state_label(state: u8) -> &'static str {
    match state {
        0 => "none",
        1 => "pending",
        2 => "active",
        3 => "unbonding",
        4 => "withdrawn",
        5 => "rejected",
        6 => "expired",
        _ => "unknown",
    }
}

fn upsert_registered_validator(
    validator_set: &mut common::ValidatorSet,
    registration: &ValidatorRegistrationStatus,
) {
    let identity = registration.identity.normalized();
    if !identity.is_complete() {
        return;
    }

    let alias = if registration.alias.trim().is_empty() {
        identity.node_id.clone()
    } else {
        registration.alias.trim().to_string()
    };

    if let Some(existing) = validator_set.validators.iter_mut().find(|validator| {
        validator.id == identity.node_id
            || validator.pubkey == identity.ed25519_pubkey
            || validator.eth_address == identity.evm_address
    }) {
        existing.id = identity.node_id;
        existing.alias = alias;
        existing.pubkey = identity.ed25519_pubkey;
        existing.eth_address = identity.evm_address;
        existing.stake = registration.stake;
        existing.reputation = registration.reputation.max(existing.reputation).max(100);
        if existing.status != "self" {
            existing.status = "online".to_string();
        }
        return;
    }

    validator_set.validators.push(common::Validator {
        id: identity.node_id,
        alias,
        pubkey: identity.ed25519_pubkey,
        eth_address: identity.evm_address,
        stake: registration.stake,
        reputation: registration.reputation.max(100),
        status: "online".to_string(),
    });
}

fn remove_registered_validator(
    validator_set: &mut common::ValidatorSet,
    identity: &ValidatorIdentity,
) {
    let identity = identity.normalized();
    validator_set.validators.retain(|validator| {
        validator.id != identity.node_id
            && validator.pubkey != identity.ed25519_pubkey
            && validator.eth_address != identity.evm_address
    });
}

fn wei_to_creg_u64(value: alloy::primitives::U256) -> u64 {
    let whole_creg = value / alloy::primitives::U256::from(1_000_000_000_000_000_000u128);
    whole_creg.to_string().parse::<u64>().unwrap_or(u64::MAX)
}

/// Verify the L1 RPC reports the chain ID we expect. Operators set
/// `CREG_EXPECTED_L1_CHAIN_ID` to e.g. `11155111` (Sepolia) or `1` (mainnet)
/// to guard against silently joining the wrong settlement chain â€” a very easy
/// misconfiguration when copying contract addresses between environments.
///
/// Skipped when the env var is unset, so local Anvil dev keeps working.
async fn validate_l1_chain_id(rpc_url: &str, expected_from_spec: Option<u64>) -> Result<()> {
    let expected = if let Some(spec_id) = expected_from_spec {
        spec_id
    } else {
        match std::env::var("CREG_EXPECTED_L1_CHAIN_ID") {
            Ok(v) if !v.trim().is_empty() => v.trim().parse().map_err(|_| {
                anyhow::anyhow!(
                    "CREG_EXPECTED_L1_CHAIN_ID must be a positive integer (got {:?})",
                    v
                )
            })?,
            _ => return Ok(()),
        }
    };

    let client = reqwest::Client::new();
    let response: serde_json::Value = client
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_chainId",
            "params": [],
            "id": 1,
        }))
        .send()
        .await?
        .json()
        .await?;

    let raw = response
        .get("result")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("eth_chainId returned no result from {}", rpc_url))?;
    let observed = u64::from_str_radix(raw.trim_start_matches("0x"), 16)
        .map_err(|_| anyhow::anyhow!("eth_chainId returned non-hex value {:?}", raw))?;

    if observed != expected {
        anyhow::bail!(
            "L1 chain id mismatch â€” CREG_ETH_RPC ({}) reports chain id {} but \
             CREG_EXPECTED_L1_CHAIN_ID is {}. Refusing to start; this would \
             settle bridge transactions on the wrong network.",
            rpc_url,
            observed,
            expected
        );
    }
    tracing::info!("  L1 chain id: {} (verified)", observed);
    Ok(())
}

async fn fetch_contract_code(
    client: &reqwest::Client,
    rpc_url: &str,
    address: &str,
) -> Result<String> {
    let response: serde_json::Value = client
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getCode",
            "params": [address, "latest"],
            "id": 1,
        }))
        .send()
        .await?
        .json()
        .await?;

    if let Some(error) = response.get("error") {
        anyhow::bail!("eth_getCode failed for {}: {}", address, error);
    }

    response
        .get("result")
        .and_then(|value| value.as_str())
        .map(|value| value.to_string())
        .ok_or_else(|| anyhow::anyhow!("missing eth_getCode result for {}", address))
}

async fn validate_contract_addresses(config: &config::NodeConfig) -> Result<()> {
    let contracts = [
        ("CREG_REGISTRY_ADDR", config.registry_addr.as_str()),
        ("CREG_GOVERNANCE_ADDR", config.governance_addr.as_str()),
        ("CREG_TOKEN_ADDR", config.token_addr.as_str()),
        ("CREG_STAKING_ADDR", config.staking_addr.as_str()),
    ];

    let configured_contracts: Vec<_> = contracts
        .into_iter()
        .filter(|(_, address)| {
            let trimmed = address.trim();
            !trimmed.is_empty()
                && !trimmed.eq_ignore_ascii_case("0x0000000000000000000000000000000000000000")
        })
        .collect();

    if configured_contracts.is_empty() {
        return Ok(());
    }

    let client = reqwest::Client::new();
    for attempt in 1..=10 {
        let mut errors = Vec::new();
        for (name, address) in &configured_contracts {
            match fetch_contract_code(&client, &config.eth_rpc_url, address).await {
                Ok(code) if code != "0x" && code != "0x0" => {}
                Ok(_) => errors.push(format!("{}={} has no deployed bytecode", name, address)),
                Err(error) => {
                    errors.push(format!("{}={} validation failed: {}", name, address, error))
                }
            }
        }

        if errors.is_empty() {
            return Ok(());
        }

        if attempt == 10 {
            anyhow::bail!(
                "Configured contract address validation failed against {}: {}",
                config.eth_rpc_url,
                errors.join("; ")
            );
        }

        tracing::warn!(
            "Contract validation attempt {}/10 failed: {}. Retrying...",
            attempt,
            errors.join("; ")
        );
        sleep(Duration::from_secs(2)).await;
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(true)
        .init();

    let mut config = config::NodeConfig::load().await;

    // â”€â”€ Chain Spec Boot Validation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Replaces the "read N envs and pray" model with a single fetched, signed,
    // validated chain spec. See docs/CHAIN_SPEC_DESIGN.md.

    let spec_url = std::env::var("CREG_CHAIN_SPEC_URL").ok();
    let spec_offline = std::env::var("CREG_CHAIN_SPEC_OFFLINE").unwrap_or_default() == "true";
    let pinned_genesis_hash = std::env::var("CREG_GENESIS_HASH").ok();
    let pinned_chain_id = std::env::var("CREG_CHAIN_ID").ok();

    let chain_spec = match chain_spec_boot::resolve_chain_spec(
        spec_url.as_deref(),
        &config.data_dir,
        spec_offline,
    )
    .await
    {
        Ok(spec) => {
            tracing::info!(
                "Chain spec resolved: {} (version {})",
                spec.chain_id,
                spec.spec_version
            );
            Some(spec)
        }
        Err(e) if spec_url.is_none() => {
            tracing::warn!(
                "CREG_CHAIN_SPEC_URL not set; falling back to legacy env-based config: {}",
                e
            );
            None
        }
        Err(e) => {
            anyhow::bail!("Failed to resolve chain spec: {}", e);
        }
    };

    // If we have a spec, run the full 8-step validation.
    if let Some(spec) = &chain_spec {
        // Step 2: Verify signature (pinned pubkey from binary build)
        let pinned_pubkey = option_env!("CREG_SPEC_SIGNING_PUBKEY")
            .unwrap_or("0000000000000000000000000000000000000000000000000000000000000000");

        if pinned_pubkey.chars().all(|c| c == '0') {
            tracing::warn!(
                "CREG_SPEC_SIGNING_PUBKEY is not set â€” skipping spec signature verification (dev build)"
            );
        } else {
            let sig_url = std::env::var("CREG_SPEC_SIGNATURE_URL")
                .unwrap_or_else(|_| spec.signing.detached_signature_url.clone());
            let sig = chain_spec_boot::fetch_spec_signature(&sig_url)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to fetch spec signature: {}", e))?;
            spec.verify_signature(&sig, pinned_pubkey)
                .map_err(|e| anyhow::anyhow!("Spec signature invalid: {}", e))?;
            tracing::info!("Spec signature verified");
        }

        // Step 3: Schema validation (spec_version)
        if spec.spec_version != common::CURRENT_SPEC_VERSION {
            anyhow::bail!(
                "Unknown spec_version={}. This binary supports version {} only.",
                spec.spec_version,
                common::CURRENT_SPEC_VERSION
            );
        }

        // Step 4: Pinning checks
        if let Some(expected) = &pinned_chain_id {
            if &spec.chain_id != expected {
                anyhow::bail!(
                    "chain_id mismatch â€” CREG_CHAIN_ID={} but spec says {}. Refusing to start.",
                    expected,
                    spec.chain_id
                );
            }
        }

        let computed_genesis_hash = spec
            .compute_genesis_hash()
            .map_err(|e| anyhow::anyhow!("Failed to compute genesis hash: {}", e))?;
        if let Some(expected) = &pinned_genesis_hash {
            if &computed_genesis_hash != expected {
                anyhow::bail!(
                    "genesis_hash mismatch â€” CREG_GENESIS_HASH={} but spec computes {}. Refusing to start.",
                    expected,
                    computed_genesis_hash
                );
            }
        }
        tracing::info!("Computed genesis hash: {}", computed_genesis_hash);

        // Step 5: L1 connectivity probe (already exists; now driven by spec)
        validate_l1_chain_id(&config.eth_rpc_url, Some(spec.l1.chain_id)).await?;

        // Step 6: Contract bytecode probe (warn-only on testnet)
        // We run this after applying the spec so config has the right addresses.
        // Step 8 is applied below after legacy validation.
    } else {
        // Legacy path: use env vars only
        validate_l1_chain_id(&config.eth_rpc_url, None).await?;
    }

    // â”€â”€ Validate configuration early â€” fail fast with clear messages â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    let config_errors = config.validate();
    if !config_errors.is_empty() {
        tracing::warn!("Configuration warnings/errors:");
        for err in &config_errors {
            tracing::warn!("  âœ— {}", err);
        }
        let hard_errors: Vec<_> = config_errors
            .iter()
            .filter(|e| {
                e.contains("CREG_VALIDATOR_KEY")
                    || e.contains("CREG_BRIDGE_KEY")
                    || e.contains("CREG_VALIDATOR_SET entry")
            })
            .collect();
        if !hard_errors.is_empty() {
            anyhow::bail!(
                "Cannot start node due to configuration errors. Fix the above and restart."
            );
        }
    }

    let production_security_errors = config.validate_production_security();
    if !production_security_errors.is_empty() {
        for err in &production_security_errors {
            tracing::error!("  âœ— {}", err);
        }
        anyhow::bail!(
            "Cannot start node: unsafe environment for production (CREG_TESTNET=false). \
             Unset CREG_DEV_SANDBOX and CREG_PBFT_ALLOW_SMALL_CLUSTER_QUORUM, use CREG_SECRETS_BACKEND=vault for hot keys, \
             or set CREG_TESTNET=true for local clusters."
        );
    }

    let mal001_errors = config.validate_mal001_public_validator();
    if !mal001_errors.is_empty() {
        for err in &mal001_errors {
            tracing::error!("  ✗ {}", err);
        }
        anyhow::bail!(
            "Cannot start node: MAL-001 public-validator sandbox policy violated. \
             See docs/CREG_LIMITATIONS_PUBLIC_READINESS_PLAN.md (MAL-001)."
        );
    }
    if config.is_validator && std::env::var("CREG_PUBLIC_VALIDATOR").as_deref() == Ok("true") {
        let sandbox = validator::sandbox::engine_status().await;
        if sandbox.dev_bypass {
            anyhow::bail!(
                "MAL-001: public validator detected sandbox dev bypass at runtime (engine={}). \
                 Rebuild with the secure fleet image or unset CREG_DEV_SANDBOX.",
                sandbox.engine
            );
        }
        if !sandbox.isolated {
            anyhow::bail!(
                "MAL-001: public validator requires an isolated sandbox engine (got '{}'). \
                 Install nsjail (fleet secure image) before serving public traffic.",
                sandbox.engine
            );
        }
        tracing::info!(
            "  MAL-001: public validator sandbox engine={} isolated=true",
            sandbox.engine
        );
    }

    // Genesis-hash pin (legacy path). Always log the computed hash so operators can grab it
    // for their chain spec; if CREG_GENESIS_HASH is set, also enforce match.
    match config.validate_genesis_hash() {
        Ok(hash) => tracing::info!("  genesis hash: 0x{}", hash),
        Err(msg) => anyhow::bail!(msg),
    }

    // Apply chain spec to config (Step 8) AFTER legacy validation so env overrides win.
    if let Some(spec) = &chain_spec {
        config.apply_chain_spec(spec);
        tracing::info!("Chain spec applied to runtime config");
    }

    validate_contract_addresses(&config).await?;

    // â”€â”€ Single-node enforcement (mainnet only) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // On mainnet, acquire a PID lock in the data directory to prevent multiple
    // nodes from running on the same machine. Testnet skips this entirely.
    let _pid_lock = if config.is_testnet {
        tracing::info!("  mode:        testnet (multi-node allowed)");
        None
    } else {
        tracing::info!("  mode:        mainnet (single node enforced)");
        Some(pidlock::PidLock::acquire(&config.data_dir)?)
    };

    tracing::info!("â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—");
    tracing::info!(
        "â•‘    chain-registry node v{}        â•‘",
        env!("CARGO_PKG_VERSION")
    );
    tracing::info!("â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•");
    tracing::info!("  listen:      {}", config.listen_addr);
    tracing::info!("  data dir:    {}", config.data_dir.display());
    tracing::info!("  node id:     {}", config.node_id);
    tracing::info!("  validator:   {}", config.is_validator);
    tracing::info!("  peers:       {}", config.peers.len());

    // â”€â”€ Open persistent storage â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    let chain = chain_store::ChainStore::open(&config.data_dir)?;
    let chain_for_sync = chain.clone();
    let tip = chain.tip_height()?;
    tracing::info!("  chain tip:   height={}", tip);

    // â”€â”€ Rebuild publisher index from chain history â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    let mut publisher_index = PublisherIndex::new();
    {
        let mut blocks = Vec::new();
        for h in 0..=tip {
            if let Ok(Some(b)) = chain.get_block_by_height(h) {
                blocks.push(b);
            }
        }
        publisher_index.rebuild_from_chain(blocks.iter());
        tracing::info!("  publishers:  {}", publisher_index.publisher_count());
    }

    // â”€â”€ Event bus (broadcast channel for SSE clients) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    let event_bus = new_event_bus();

    // â”€â”€ P2P Networking (libp2p) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    let (p2p_node, p2p_handle) = p2p::P2PNode::new(&config.p2p_listen)?;

    // Make the p2p sender available to API/worker code that needs to gossip
    // validator identity registrations fleet-wide.
    validator_registry_gossip::set_gossip_sender(p2p_handle.sender.clone());

    // â”€â”€ Finalized-tx channel (created before state so API can send to it) â”€â”€â”€â”€â”€â”€â”€
    let (tx_sender, tx_receiver): (FinalizedTxSender, FinalizedTxReceiver) =
        finalized_tx::channel();
    let zk_validator = Arc::new(
        zk_validator::ZkValidator::new()
            .context("Failed to initialize ZK validator â€” ensure CREG_ZK_KEYS_DIR contains proving_key_package_v2.bin and verifying_key_package_v2.bin when CREG_PRODUCTION=true")?,
    );

    // â”€â”€ Shared state â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    let state: SharedState = Arc::new(RwLock::new(NodeState {
        chain,
        pending_pool: pending_pool::PendingPool::open(&config.data_dir),
        publisher_index,
        validator_set_bootstrap: config.validator_set.clone(),
        validator_set: config.validator_set.clone(),
        package_rounds: std::collections::HashMap::new(),
        config: config.clone(),
        p2p_status: P2PStatus::default(),
        bridge_status: BridgeStatus {
            registry_address: config.registry_addr.clone(),
            ..BridgeStatus::default()
        },
        vrf_proofs: std::collections::HashMap::new(),
        decryption_shares: std::collections::HashMap::new(),
        validator_registrations: HashMap::new(),
        validator_set_sync: crate::state::ValidatorSetSyncStatus {
            enabled: false,
            mode: "static".to_string(),
            state: "disabled".to_string(),
            ..Default::default()
        },
        view_change_certs: HashMap::new(),
        reorgs: Vec::new(),
        pbft_engine: crate::state::PbftEngine::new(),
    }));

    // Seed the validator-set history with the bootstrap set effective from
    // genesis, so blocks at early heights verify against the right set
    // (ISSUE-050). Subsequent changes are recorded by the reconcile path.
    if let Err(e) = validator_set_history::record(&config.data_dir, 0, &config.validator_set) {
        tracing::warn!("Failed to seed validator-set history: {}", e);
    }

    // Start P2P node in background
    let p2p_handle_for_seeds = p2p_handle.clone();
    let seeds = config.p2p_seeds.clone();
    let state_for_seed_redial = Arc::clone(&state);
    tokio::spawn(async move {
        let mut dialable_seeds = Vec::<libp2p::Multiaddr>::new();
        for seed in seeds {
            match seed.parse() {
                Ok(addr) => dialable_seeds.push(addr),
                Err(error) => {
                    tracing::warn!(seed = %seed, error = %error, "Ignoring invalid P2P seed multiaddr");
                }
            }
        }

        if dialable_seeds.is_empty() {
            return;
        }

        let mut seed_redial = interval(Duration::from_secs(10));
        loop {
            seed_redial.tick().await;

            for addr in &dialable_seeds {
                let _ = p2p_handle_for_seeds
                    .sender
                    .send(p2p::P2PCommand::Dial { addr: addr.clone() })
                    .await;
            }
        }
    });

    tokio::spawn(p2p_node.run(Arc::clone(&state), Arc::clone(&event_bus)));

    // â”€â”€ Validator identity registrations: restore + periodic re-broadcast â”€â”€â”€â”€â”€â”€
    // Reapply persisted registrations so a restart keeps every known validator
    // identity, then periodically re-gossip them so late-joining / restarted
    // peers converge without operator re-POSTing to each node.
    {
        let state_for_registry = Arc::clone(&state);
        let data_dir = config.data_dir.clone();
        tokio::spawn(async move {
            for proof in validator_registry_gossip::load_all(&data_dir) {
                match api::apply_validator_registration(&state_for_registry, &proof).await {
                    Ok(_) => tracing::info!(
                        "Restored persisted validator registration for {}",
                        proof.node_id
                    ),
                    Err((_, e)) => tracing::warn!(
                        "Could not restore validator registration for {}: {}",
                        proof.node_id,
                        e
                    ),
                }
            }

            let mut ticker = interval(Duration::from_secs(120));
            ticker.tick().await; // consume immediate first tick
            loop {
                ticker.tick().await;
                for proof in validator_registry_gossip::load_all(&data_dir) {
                    validator_registry_gossip::broadcast(proof).await;
                }
            }
        });
    }

    // â”€â”€ Spawn background tasks â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    tracing::info!("Starting subsystems...");

    // PostgreSQL sync worker (chain store â†’ PostgreSQL ETL)
    // Default to the dedicated `creg-indexer` service so validators do not
    // own both the consensus path and the explorer mirror path in the same
    // process. Set CREG_PG_SYNC_IN_PROCESS=true to restore the legacy mode.
    if !config.pg_url.is_empty() {
        if std::env::var("CREG_PG_SYNC_IN_PROCESS").ok().as_deref() == Some("true") {
            let sync_config = db_sync::sync_worker::SyncConfig {
                poll_interval: std::time::Duration::from_secs(1),
                pg_url: config.pg_url.clone(),
                ..Default::default()
            };
            let chain_proxy: db_sync::sync_worker::ChainStoreHandle =
                Arc::new(tokio::sync::RwLock::new(chain_for_sync));
            match db_sync::SyncWorker::new(sync_config, chain_proxy).await {
                Ok(worker) => {
                    tokio::spawn(worker.run());
                    tracing::info!("Legacy in-process PostgreSQL sync worker started");
                }
                Err(e) => {
                    tracing::warn!("Failed to start PostgreSQL sync worker: {}", e);
                }
            }
        } else {
            tracing::info!(
                "Skipping in-process PostgreSQL sync worker; run the dedicated creg-indexer service or set CREG_PG_SYNC_IN_PROCESS=true for legacy mode"
            );
        }
    }

    tokio::spawn(sync::run(Arc::clone(&state)));

    // â”€â”€ ML model existence check (T6) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    {
        let scanner = ml_validator::deep_scan::DeepScanner::default();
        if let Err(e) = scanner.validate_at_startup() {
            tracing::warn!("ML model validation: {}", e);
        }
    }

    tokio::spawn(validator_pipeline::run(
        Arc::clone(&state),
        tx_sender.clone(),
        p2p_handle.clone(),
    ));

    tokio::spawn(block_producer::run(
        Arc::clone(&state),
        tx_receiver,
        p2p_handle.clone(),
    ));

    tokio::spawn(bridge::run(Arc::clone(&state)));

    tokio::spawn(sync_validator_registrations(Arc::clone(&state)));

    let admission_store = consensus_admission::AttestationStore::new();
    tokio::spawn(consensus_admission::run(
        Arc::clone(&state),
        Arc::clone(&admission_store),
    ));

    // â”€â”€ Validator set sync (chain-authoritative with static bootstrap) â”€â”€â”€â”€â”€â”€
    {
        let start_block = chain_spec
            .as_ref()
            .map(|spec| spec.validator_set.epoch_block_height);
        // Apply L1 staking events only after a finality buffer so shallow
        // Sepolia reorgs cannot flap the validator set. Override with
        // CREG_VALIDATOR_SET_FINALITY_LAG (in L1 blocks).
        let default_finality_lag: u64 = if config.is_testnet { 2 } else { 6 };
        let finality_lag_blocks = std::env::var("CREG_VALIDATOR_SET_FINALITY_LAG")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(default_finality_lag);
        if finality_lag_blocks == 0 {
            tracing::warn!(
                "CREG_VALIDATOR_SET_FINALITY_LAG=0 — L1 staking events are applied with no \
                 finality buffer; a shallow L1 reorg can flap validator membership."
            );
        }
        // Additional independent L1 RPC endpoints for quorum reads, so one
        // stale/compromised RPC cannot skew the validator set. Comma-separated.
        let extra_rpc_urls: Vec<String> = std::env::var("CREG_ETH_RPC_FALLBACKS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let sync_config = validator_set_sync::SyncConfig {
            eth_rpc_url: config.eth_rpc_url.clone(),
            extra_rpc_urls,
            staking_addr: config.staking_addr.parse().unwrap_or_else(|_| {
                tracing::warn!("Invalid staking address; validator set sync disabled");
                alloy::primitives::Address::ZERO
            }),
            finality_lag_blocks,
            poll_interval_secs: 30,
            start_block,
        };
        {
            let mut state_guard = state.write().await;
            state_guard.validator_set_sync.enabled =
                sync_config.staking_addr != alloy::primitives::Address::ZERO;
            state_guard.validator_set_sync.mode = if state_guard.validator_set_sync.enabled {
                "chain-authoritative".to_string()
            } else {
                "static".to_string()
            };
            state_guard.validator_set_sync.state = if state_guard.validator_set_sync.enabled {
                "starting".to_string()
            } else {
                "disabled".to_string()
            };
            if !state_guard.validator_set_sync.enabled {
                state_guard.validator_set_sync.last_error = Some(
                    "validator-set sync disabled: staking contract address is invalid".to_string(),
                );
                tracing::warn!(
                    "CRITICAL: Validator set sync is disabled (static mode). \
                     This node will not participate in decentralized on-chain admission and \
                     is isolated from the public network."
                );
            }
        }
        if sync_config.staking_addr != alloy::primitives::Address::ZERO {
            tracing::info!(
                start_block = ?sync_config.start_block,
                finality_lag_blocks = sync_config.finality_lag_blocks,
                poll_interval_secs = sync_config.poll_interval_secs,
                "Validator set source: chain-authoritative"
            );
            let sync_state = Arc::clone(&state);
            tokio::spawn(async move {
                if let Err(e) = validator_set_sync::run(
                    sync_config,
                    validator_set_sync::SyncMode::ChainAuthoritative,
                    sync_state,
                )
                .await
                {
                    tracing::error!("Validator set sync worker crashed: {}", e);
                }
            });
        }
    }

    // â”€â”€ Start gRPC Server (Industrial Speed) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    let grpc_state = Arc::clone(&state);
    let watcher_bus = Arc::clone(&event_bus);
    tokio::spawn(async move {
        let addr = "0.0.0.0:50051"
            .parse()
            .expect("gRPC bind address must be valid");
        let registry = grpc::MyRegistry::new(Arc::clone(&grpc_state), Arc::clone(&zk_validator));
        let watcher = grpc::MyWatcher::new(watcher_bus);
        let explorer = grpc::MyExplorer::new(Arc::clone(&grpc_state));

        tracing::info!("gRPC API listening on {}", addr);

        tonic::transport::Server::builder()
            .add_service(
                common::proto::registry_service_server::RegistryServiceServer::new(registry),
            )
            .add_service(common::proto::watch_service_server::WatchServiceServer::new(watcher))
            .add_service(
                common::proto::explorer_service_server::ExplorerServiceServer::new(explorer),
            )
            .serve(addr)
            .await
            .expect("gRPC server failed");
    });

    // â”€â”€ Start REST API + SSE + Metrics â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    let limiter = rate_limit::RateLimiter::new(Default::default());
    rate_limit::spawn_purge_task(limiter.clone());

    let app = api::router(
        Arc::clone(&state),
        event_bus,
        limiter,
        Arc::clone(&admission_store),
        config.cors.clone(),
        tx_sender.clone(),
        p2p_handle,
    );

    // â”€â”€ Optional TLS termination â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Set CREG_TLS_CERT and CREG_TLS_KEY environment variables to enable HTTPS.
    #[cfg(feature = "tls")]
    {
        let tls_cert = std::env::var("CREG_TLS_CERT").ok();
        let tls_key = std::env::var("CREG_TLS_KEY").ok();

        if let (Some(cert_path), Some(key_path)) = (tls_cert, tls_key) {
            use axum_server::tls_rustls::RustlsConfig;

            let tls_config = RustlsConfig::from_pem_file(&cert_path, &key_path)
                .await
                .expect("Failed to load TLS certificate/key");

            let addr: std::net::SocketAddr = config
                .listen_addr
                .parse()
                .expect("listen_addr must be a valid socket address");

            tracing::info!("REST API listening on https://{}", addr);

            axum_server::bind_rustls(addr, tls_config)
                .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .await?;

            tracing::info!("Node shut down cleanly.");
            return Ok(());
        }
    }

    // â”€â”€ Plain HTTP (default) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
    tracing::info!("REST API listening on http://{}", config.listen_addr);

    // â”€â”€ Graceful shutdown on SIGINT (Ctrl-C) or SIGTERM â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    // Release the PID lock explicitly before logging clean shutdown.
    drop(_pid_lock);

    tracing::info!("Node shut down cleanly.");
    Ok(())
}

async fn sync_validator_registrations(state: SharedState) {
    let mut ticker = interval(Duration::from_secs(5));
    loop {
        ticker.tick().await;
        if let Err(error) = sync_validator_registrations_once(&state).await {
            tracing::warn!("validator registration sync failed: {}", error);
        }
    }
}

async fn sync_validator_registrations_once(state: &SharedState) -> Result<()> {
    let (rpc_url, staking_addr, registrations) = {
        let state_guard = state.read().await;
        (
            state_guard.config.eth_rpc_url.clone(),
            state_guard.config.staking_addr.clone(),
            state_guard
                .validator_registrations
                .iter()
                .map(|(key, registration)| (key.clone(), registration.clone()))
                .collect::<Vec<_>>(),
        )
    };

    if registrations.is_empty()
        || staking_addr.trim().is_empty()
        || staking_addr.eq_ignore_ascii_case("0x0000000000000000000000000000000000000000")
    {
        return Ok(());
    }

    let provider = ProviderBuilder::new().on_http(rpc_url.parse()?);
    let staking = IStakingRead::new(staking_addr.parse()?, &provider);
    let mut updates = Vec::with_capacity(registrations.len());

    for (key, registration) in registrations {
        let identity = registration.identity.normalized();
        let update = match identity.evm_address.parse() {
            Ok(address) => match staking.validators(address).call().await {
                Ok(result) => Ok((wei_to_creg_u64(result.stake), result.state)),
                Err(error) => Err(format!("staking lookup failed: {}", error)),
            },
            Err(error) => Err(format!("invalid EVM address: {}", error)),
        };
        updates.push((key, update));
    }

    let mut state_guard = state.write().await;
    for (key, update) in updates {
        let Some(mut registration) = state_guard.validator_registrations.remove(&key) else {
            continue;
        };

        registration.registered_with_node = true;
        registration.last_synced_at = Some(Utc::now().to_rfc3339());

        match update {
            Ok((stake, staking_state)) => {
                registration.last_error = None;
                registration.stake = stake;
                registration.applied_on_chain = staking_state != 0;
                registration.governance_approved = matches!(staking_state, 2 | 3 | 4);
                registration.staking_state = staking_state_label(staking_state).to_string();

                let identity = registration.identity.normalized();
                let should_admit = staking_state == 2
                    && identity.is_complete()
                    && state_guard
                        .validator_set
                        .validators
                        .iter()
                        .any(|validator| {
                            validator
                                .eth_address
                                .eq_ignore_ascii_case(&identity.evm_address)
                        });
                registration.admitted_to_consensus = should_admit;
                registration.active = should_admit;
            }
            Err(error) => {
                registration.last_error = Some(error);
            }
        }

        registration.status = validator_registration_status_text(&registration);
        state_guard
            .validator_registrations
            .insert(key, registration);
    }

    Ok(())
}

/// Returns a future that resolves when a shutdown signal is received.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c    => { tracing::info!("Received Ctrl-C â€” shutting down..."); }
        _ = terminate => { tracing::info!("Received SIGTERM â€” shutting down..."); }
    }
}
// explorer and rate_limit are declared here so they're available to api.rs
