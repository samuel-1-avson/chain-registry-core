// crates/node/src/config.rs

use axum::http::{HeaderValue, Method};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub enum NodeMode {
    /// Full mode: Store everything (500GB+, 16GB RAM)
    Full,
    /// Pruned mode: Store last 30 days (200GB, 8GB RAM)
    Pruned,
    /// Light mode: Current state only (100GB, 4-8GB RAM)
    Light,
}

impl Default for NodeMode {
    fn default() -> Self {
        NodeMode::Pruned
    }
}

#[derive(Debug, Clone)]
pub struct PruningConfig {
    /// Keep packages for X days, then archive to IPFS
    pub package_retention_days: u32,
    /// Keep full block history or just headers
    pub keep_full_blocks: bool,
    /// Prune interval (every X blocks)
    pub prune_interval: u64,
    /// Max database size before forced pruning (GB)
    pub max_db_size_gb: u32,
}

impl Default for PruningConfig {
    fn default() -> Self {
        Self {
            package_retention_days: 30,
            keep_full_blocks: false,
            prune_interval: 1000,
            max_db_size_gb: 150,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CorsConfig {
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allow_credentials: bool,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: Vec::new(),
            allowed_methods: default_cors_methods(),
            allow_credentials: false,
        }
    }
}

impl CorsConfig {
    pub fn from_env() -> Self {
        Self::from_env_values(
            &std::env::var("CREG_CORS_ALLOWED_ORIGINS").unwrap_or_default(),
            &std::env::var("CREG_CORS_ALLOWED_METHODS")
                .unwrap_or_else(|_| default_cors_methods().join(",")),
            env("CREG_CORS_ALLOW_CREDENTIALS", "false") == "true",
        )
    }

    fn from_env_values(origins_raw: &str, methods_raw: &str, allow_credentials: bool) -> Self {
        let allowed_origins = parse_csv(origins_raw)
            .into_iter()
            .map(|origin| normalize_cors_origin(&origin))
            .collect();

        let allowed_methods = {
            let parsed = parse_csv(methods_raw)
                .into_iter()
                .map(|method| method.to_ascii_uppercase())
                .collect::<Vec<_>>();
            if parsed.is_empty() {
                default_cors_methods()
            } else {
                parsed
            }
        };

        Self {
            allowed_origins,
            allowed_methods,
            allow_credentials,
        }
    }

    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        let has_wildcard = self.allowed_origins.iter().any(|origin| origin == "*");
        if has_wildcard && self.allowed_origins.len() > 1 {
            errors
                .push("CREG_CORS_ALLOWED_ORIGINS cannot combine `*` with explicit origins.".into());
        }

        if self.allow_credentials && self.allowed_origins.is_empty() {
            errors.push(
                "CREG_CORS_ALLOW_CREDENTIALS=true requires at least one explicit origin in CREG_CORS_ALLOWED_ORIGINS.".into(),
            );
        }

        if self.allow_credentials && has_wildcard {
            errors.push(
                "CREG_CORS_ALLOW_CREDENTIALS=true cannot be used with wildcard CREG_CORS_ALLOWED_ORIGINS=*; configure explicit origins instead.".into(),
            );
        }

        for origin in &self.allowed_origins {
            if origin == "*" {
                continue;
            }
            if !origin.starts_with("http://") && !origin.starts_with("https://") {
                errors.push(format!(
                    "CORS origin `{}` must start with http:// or https://",
                    origin
                ));
                continue;
            }
            if HeaderValue::from_str(origin).is_err() {
                errors.push(format!(
                    "CORS origin `{}` is not a valid header value",
                    origin
                ));
            }
        }

        for method in &self.allowed_methods {
            if Method::from_bytes(method.as_bytes()).is_err() {
                errors.push(format!(
                    "CORS method `{}` is not a valid HTTP method",
                    method
                ));
            }
        }

        errors
    }
}

#[derive(Debug, Clone, Default)]
pub struct NodeConfig {
    /// Logical chain identifier (e.g. "creg-testnet-1"). Used as part of the
    /// network identity hash so a node configured for one chain cannot
    /// silently join another.
    pub chain_id: String,
    /// HTTP bind address for the REST API.
    pub listen_addr: String,
    /// Persistent data directory (chain + pending pool).
    pub data_dir: PathBuf,
    /// P2P listen address (Multiaddr format).
    pub p2p_listen: String,
    /// Bootstrap peers for Kademlia discovery.
    pub p2p_seeds: Vec<String>,
    /// Ethereum RPC URL for the bridge.
    pub eth_rpc_url: String,
    /// Registry contract address on Ethereum.
    pub registry_addr: String,
    /// Governance contract address used to execute privileged registry actions.
    pub governance_addr: String,
    /// Test token contract address used by wallet and faucet flows.
    pub token_addr: String,
    /// Staking contract address used by publisher and validator staking.
    pub staking_addr: String,
    /// Unique ID for this node (hex-encoded public key in production).
    pub node_id: String,
    /// This node's Ed25519 private key (hex). Used to sign validator votes.
    pub validator_privkey: Option<String>,
    /// Separate secp256k1 private key for Ethereum bridge operations.
    /// If unset, falls back to `validator_privkey` (legacy single-key mode).
    /// Setting a dedicated bridge key reduces blast radius: compromise of
    /// one key does not affect the other. (I4 improvement)
    pub bridge_privkey: Option<String>,
    /// Whether this node is a validator (votes on packages).
    pub is_validator: bool,
    /// Peer node URLs for gossip and consensus message forwarding.
    pub peers: Vec<String>,
    /// How often the block producer ticks (seconds).
    pub block_interval_secs: u64,
    /// How long the validator pipeline waits for PBFT vote quorum (seconds).
    pub vote_timeout_secs: u64,
    /// IPFS API base URL.
    pub ipfs_url: String,
    /// PostgreSQL connection URL for the sync worker.
    pub pg_url: String,
    /// The set of active validators (JSON-encoded).
    pub validator_set: common::ValidatorSet,
    /// Node operation mode (Full/Pruned/Light)
    pub mode: NodeMode,
    /// Pruning configuration
    pub pruning: PruningConfig,
    /// Max peers for low-bandwidth environments
    pub max_peers: usize,
    /// Browser CORS policy for the REST API.
    pub cors: CorsConfig,
    /// Testnet mode: allows multiple nodes per machine.
    /// Mainnet (false) enforces a single node per data directory via PID lock.
    pub is_testnet: bool,
}

impl NodeConfig {
    pub async fn load() -> Self {
        let mode = match env("CREG_NODE_MODE", "pruned").as_str() {
            "full" => NodeMode::Full,
            "light" => NodeMode::Light,
            _ => NodeMode::Pruned,
        };

        let pruning = PruningConfig {
            package_retention_days: env("CREG_PACKAGE_RETENTION_DAYS", "30")
                .parse()
                .unwrap_or(30),
            keep_full_blocks: env("CREG_KEEP_FULL_BLOCKS", "false") == "true",
            prune_interval: env("CREG_PRUNE_INTERVAL", "1000").parse().unwrap_or(1000),
            max_db_size_gb: env("CREG_MAX_DB_SIZE_GB", "150").parse().unwrap_or(150),
        };

        let max_peers = env("CREG_MAX_PEERS", "15").parse().unwrap_or(15);

        let mut config = Self {
            chain_id: env("CREG_CHAIN_ID", ""),
            listen_addr: env("CREG_LISTEN", "0.0.0.0:8080"),
            data_dir: PathBuf::from(env("CREG_DATA_DIR", "./data")),
            node_id: env("CREG_NODE_ID", &Uuid::new_v4().to_string()),
            validator_privkey: std::env::var("CREG_VALIDATOR_KEY").ok(),
            bridge_privkey: None,
            is_validator: env("CREG_IS_VALIDATOR", "false") == "true",
            peers: std::env::var("CREG_PEERS")
                .unwrap_or_default()
                .split(',')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect(),
            p2p_listen: env("CREG_P2P_LISTEN", "/ip4/0.0.0.0/tcp/4001"),
            p2p_seeds: std::env::var("CREG_P2P_SEEDS")
                .unwrap_or_default()
                .split(',')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect(),
            eth_rpc_url: env("CREG_ETH_RPC", "http://127.0.0.1:8545"),
            registry_addr: env(
                "CREG_REGISTRY_ADDR",
                "0x0000000000000000000000000000000000000000",
            ),
            governance_addr: env(
                "CREG_GOVERNANCE_ADDR",
                "0x0000000000000000000000000000000000000000",
            ),
            token_addr: env(
                "CREG_TOKEN_ADDR",
                "0x0000000000000000000000000000000000000000",
            ),
            staking_addr: env(
                "CREG_STAKING_ADDR",
                "0x0000000000000000000000000000000000000000",
            ),
            block_interval_secs: env("CREG_BLOCK_INTERVAL", "5").parse().unwrap_or(5),
            vote_timeout_secs: env("CREG_VOTE_TIMEOUT_SECS", "10").parse().unwrap_or(10),
            ipfs_url: env("CREG_IPFS_URL", "http://127.0.0.1:5001"),
            pg_url: env("CREG_PG_URL", ""),
            validator_set: serde_json::from_str(&env("CREG_VALIDATOR_SET", "{\"validators\":[]}"))
                .unwrap_or_else(|_| common::ValidatorSet::new(vec![])),
            mode,
            pruning,
            max_peers,
            cors: CorsConfig::from_env(),
            is_testnet: env("CREG_TESTNET", "false") == "true",
        };

        if let Ok(secrets) = chain_registry_secrets::SecretsProvider::from_env() {
            if let Ok(Some(bk)) = secrets
                .try_secp256k1_signing_key_hex(chain_registry_secrets::HotKeyRole::Bridge)
                .await
            {
                config.bridge_privkey = Some(bk);
            }
            if config.validator_privkey.is_none() {
                if let Ok(Some(vk)) = secrets
                    .try_secp256k1_signing_key_hex(
                        chain_registry_secrets::HotKeyRole::ValidatorEd25519,
                    )
                    .await
                {
                    config.validator_privkey = Some(vk);
                }
            }
        }

        config
    }

    /// Validate the configuration and return a list of human-readable errors.
    /// Call this at startup before opening any resources.
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        let is_zero_like = |value: &str| {
            let trimmed = value.trim();
            trimmed.is_empty()
                || trimmed.eq_ignore_ascii_case("0x0000000000000000000000000000000000000000")
        };

        // A validator node must have a signing key.
        if self.is_validator && self.validator_privkey.is_none() {
            errors.push(
                "CREG_IS_VALIDATOR=true but CREG_VALIDATOR_KEY is not set. \
                 Generate a key with `creg keygen` and set CREG_VALIDATOR_KEY."
                    .into(),
            );
        }

        // Validate the key is proper hex if set (strip optional 0x prefix).
        if let Some(key) = &self.validator_privkey {
            let raw = key.strip_prefix("0x").unwrap_or(key.as_str());
            match hex::decode(raw) {
                Ok(bytes) if bytes.len() == 32 => {}
                Ok(bytes) => errors.push(format!(
                    "CREG_VALIDATOR_KEY must be 32 bytes (64 hex chars), got {} bytes",
                    bytes.len()
                )),
                Err(_) => errors.push("CREG_VALIDATOR_KEY is not valid hex".into()),
            }
        }

        // Validate the dedicated bridge key if set (I4). Strip optional 0x prefix.
        if let Some(key) = &self.bridge_privkey {
            let raw = key.strip_prefix("0x").unwrap_or(key.as_str());
            match hex::decode(raw) {
                Ok(bytes) if bytes.len() == 32 => {}
                Ok(bytes) => errors.push(format!(
                    "CREG_BRIDGE_KEY must be 32 bytes (64 hex chars), got {} bytes",
                    bytes.len()
                )),
                Err(_) => errors.push("CREG_BRIDGE_KEY is not valid hex".into()),
            }
        }

        // Warn if using the null registry address (bridge will not work).
        if is_zero_like(&self.registry_addr) {
            errors.push(
                "CREG_REGISTRY_ADDR is the zero address. \
                 Deploy Registry.sol and set CREG_REGISTRY_ADDR for Ethereum bridging."
                    .into(),
            );
        }

        if self.bridge_privkey.is_some() && is_zero_like(&self.governance_addr) {
            errors.push(
                "CREG_GOVERNANCE_ADDR is the zero address. \
                 Set CREG_GOVERNANCE_ADDR so the bridge can execute rollup settlement via Governance.sol."
                    .into(),
            );
        }

        if is_zero_like(&self.token_addr) {
            errors.push(
                "CREG_TOKEN_ADDR is not set. Wallet balances, faucet wiring, and staking UI will be unavailable until testnet artifacts are synced."
                    .into(),
            );
        }

        if is_zero_like(&self.staking_addr) {
            errors.push(
                "CREG_STAKING_ADDR is not set. Validator and publisher staking flows will be unavailable until testnet artifacts are synced."
                    .into(),
            );
        }

        // Validate IPFS URL is a parseable HTTP endpoint.
        if self.ipfs_url.is_empty() {
            errors.push(
                "CREG_IPFS_URL is empty. Set it to the IPFS API endpoint \
                 (e.g. http://127.0.0.1:5001) for package pinning and validation."
                    .into(),
            );
        } else if !self.ipfs_url.starts_with("http://") && !self.ipfs_url.starts_with("https://") {
            errors.push(format!(
                "CREG_IPFS_URL ({}) must start with http:// or https://",
                self.ipfs_url
            ));
        }

        errors.extend(self.cors.validate());

        // Block interval sanity check.
        if self.block_interval_secs == 0 {
            errors.push("CREG_BLOCK_INTERVAL must be > 0 seconds".into());
        }

        // Validator-set pubkey sanity. An entry with an empty / zero pubkey can
        // never have its votes verified, so it would silently disable quorum
        // for that validator and skew the active count. Reject at boot.
        for v in &self.validator_set.validators {
            let trimmed = v.pubkey.trim().trim_start_matches("0x");
            if trimmed.is_empty() || trimmed.chars().all(|c| c == '0') {
                errors.push(format!(
                    "CREG_VALIDATOR_SET entry id='{}' has empty/zero pubkey — \
                     this validator could never be verified by peers. Fix the validator-set \
                     entry or remove it.",
                    v.id
                ));
                continue;
            }
            match hex::decode(trimmed) {
                Ok(bytes) if bytes.len() == 32 => {}
                Ok(bytes) => errors.push(format!(
                    "CREG_VALIDATOR_SET entry id='{}' pubkey must be 32 bytes (64 hex chars), got {} bytes",
                    v.id,
                    bytes.len()
                )),
                Err(_) => errors.push(format!(
                    "CREG_VALIDATOR_SET entry id='{}' pubkey is not valid hex",
                    v.id
                )),
            }
        }

        errors
    }

    /// MAL-001: public validators (CREG_PUBLIC_VALIDATOR=true) must not run the
    /// behavioural-sandbox dev bypass and must use an isolated engine (nsjail, etc.).
    pub fn validate_mal001_public_validator(&self) -> Vec<String> {
        if !self.is_validator {
            return Vec::new();
        }
        if std::env::var("CREG_PUBLIC_VALIDATOR").as_deref() != Ok("true") {
            return Vec::new();
        }

        let mut errors = Vec::new();
        if std::env::var("CREG_DEV_SANDBOX").as_deref() == Ok("true") {
            errors.push(
                "MAL-001: CREG_DEV_SANDBOX=true is forbidden when CREG_PUBLIC_VALIDATOR=true — \
                 public validators must run a real sandbox (nsjail). Use docker-compose.fleet-sandbox.yml \
                 or unset CREG_PUBLIC_VALIDATOR for local-only dev."
                    .into(),
            );
        }
        errors
    }

    /// Reject unsafe development bypasses when `CREG_TESTNET` is not true.
    pub fn validate_production_security(&self) -> Vec<String> {
        if self.is_testnet {
            return Vec::new();
        }

        let mut errors = Vec::new();

        if std::env::var("CREG_DEV_SANDBOX").as_deref() == Ok("true") {
            errors.push(
                "CREG_DEV_SANDBOX=true is not allowed when CREG_TESTNET=false — \
                 behavioural sandbox bypass must not run on production networks."
                    .into(),
            );
        }

        if std::env::var("CREG_PBFT_ALLOW_SMALL_CLUSTER_QUORUM").as_deref() == Ok("true") {
            errors.push(
                "CREG_PBFT_ALLOW_SMALL_CLUSTER_QUORUM=true is not allowed when CREG_TESTNET=false — \
                 relaxed PBFT quorum weakens BFT guarantees. Use a full validator set or enable testnet mode."
                    .into(),
            );
        }

        errors.extend(chain_registry_secrets::validate_production_secrets_policy(
            self.is_testnet,
        ));

        errors
    }

    /// SHA-256 over a canonical encoding of the node's network-identity inputs:
    ///   chain_id | registry | governance | staking | token | (id:pubkey)*
    ///
    /// Two nodes with the same hash agree on what network they are joining.
    /// Mutable state (stake, reputation, online status) is intentionally NOT
    /// included — we want this hash stable across the lifetime of the chain.
    /// All addresses and pubkeys are lower-cased before hashing so case
    /// differences in env files do not produce false mismatches.
    pub fn compute_network_identity_hash(&self) -> String {
        let mut validators: Vec<&common::Validator> =
            self.validator_set.validators.iter().collect();
        validators.sort_by(|a, b| a.id.cmp(&b.id));

        let mut buf = String::new();
        buf.push_str(self.chain_id.trim());
        buf.push('|');
        buf.push_str(&self.registry_addr.trim().to_lowercase());
        buf.push('|');
        buf.push_str(&self.governance_addr.trim().to_lowercase());
        buf.push('|');
        buf.push_str(&self.staking_addr.trim().to_lowercase());
        buf.push('|');
        buf.push_str(&self.token_addr.trim().to_lowercase());
        for v in validators {
            buf.push('|');
            buf.push_str(v.id.trim());
            buf.push(':');
            buf.push_str(
                v.pubkey
                    .trim()
                    .trim_start_matches("0x")
                    .to_lowercase()
                    .as_str(),
            );
        }
        common::sha256_hex(buf.as_bytes())
    }

    /// Pure helper: verify `expected` matches `compute_network_identity_hash()`.
    /// `None` (or an empty/whitespace value) skips the check. Case-insensitive,
    /// `0x` prefix optional. Always returns the computed hash so callers can
    /// log it.
    pub fn validate_genesis_hash_value(&self, expected: Option<&str>) -> Result<String, String> {
        let computed = self.compute_network_identity_hash();
        let expected = match expected.map(str::trim).filter(|s| !s.is_empty()) {
            Some(v) => v,
            None => return Ok(computed),
        };
        let normalized = expected.trim_start_matches("0x").to_lowercase();
        if normalized != computed {
            return Err(format!(
                "genesis hash mismatch — CREG_GENESIS_HASH={} but computed network identity hash is {}. \
                 Refusing to start; this node is configured for a different chain than expected. \
                 Re-check CREG_CHAIN_ID, contract addresses, and CREG_VALIDATOR_SET against your chain spec.",
                expected, computed
            ));
        }
        Ok(computed)
    }

    /// Reads `CREG_GENESIS_HASH` from the environment and delegates to
    /// `validate_genesis_hash_value`. Always returns the computed hash so the
    /// caller can log it at startup.
    pub fn validate_genesis_hash(&self) -> Result<String, String> {
        let raw = std::env::var("CREG_GENESIS_HASH").ok();
        self.validate_genesis_hash_value(raw.as_deref())
    }

    /// Apply a resolved chain spec, with env vars taking precedence.
    pub fn apply_chain_spec(&mut self, spec: &common::ChainSpec) {
        if self.chain_id.is_empty() {
            self.chain_id = spec.chain_id.clone();
        }
        if self.p2p_seeds.is_empty() {
            self.p2p_seeds = spec.p2p_seeds();
        }
        // Contract addresses from spec (unless explicitly set via env to non-zero)
        let zero = "0x0000000000000000000000000000000000000000".to_string();
        if self.registry_addr == zero || self.registry_addr.is_empty() {
            if let Some(addr) = spec.contract("registry") {
                self.registry_addr = addr.clone();
            }
        }
        if self.staking_addr == zero || self.staking_addr.is_empty() {
            if let Some(addr) = spec.contract("staking") {
                self.staking_addr = addr.clone();
            }
        }
        if self.governance_addr == zero || self.governance_addr.is_empty() {
            if let Some(addr) = spec.contract("governance") {
                self.governance_addr = addr.clone();
            }
        }
        if self.token_addr == zero || self.token_addr.is_empty() {
            if let Some(addr) = spec.contract("creg_token") {
                self.token_addr = addr.clone();
            }
        }
        // Block interval from spec (unless env override is non-default)
        if self.block_interval_secs == 5 && spec.consensus_params.block_time_seconds != 5 {
            self.block_interval_secs = spec.consensus_params.block_time_seconds;
        }
        if std::env::var("CREG_VOTE_TIMEOUT_SECS").is_err()
            && spec.consensus_params.vote_timeout_ms > 0
        {
            self.vote_timeout_secs = spec.consensus_params.vote_timeout_ms.div_ceil(1000).max(1);
        }
        // Validator set from spec (unless env override is non-empty)
        if self.validator_set.validators.is_empty() {
            self.validator_set = spec.to_runtime_validator_set();
        }
    }
}

fn default_cors_methods() -> Vec<String> {
    vec!["GET", "POST", "DELETE", "OPTIONS"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn parse_csv(raw: &str) -> Vec<String> {
    let mut values = Vec::new();
    for value in raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if !values.iter().any(|existing| existing == value) {
            values.push(value.to_string());
        }
    }
    values
}

fn normalize_cors_origin(origin: &str) -> String {
    let trimmed = origin.trim();
    if trimmed == "*" {
        return "*".to_string();
    }

    trimmed.trim_end_matches('/').to_string()
}

fn env(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config() -> NodeConfig {
        NodeConfig {
            chain_id: "creg-test-1".into(),
            listen_addr: "127.0.0.1:8080".into(),
            data_dir: PathBuf::from("./data"),
            p2p_listen: "/ip4/0.0.0.0/tcp/4001".into(),
            p2p_seeds: vec![],
            eth_rpc_url: "http://127.0.0.1:8545".into(),
            registry_addr: "0x0165878A594ca255338adfa4d48449f69242Eb8F".into(),
            governance_addr: "0x5FbDB2315678afecb367f032d93F642f64180aa3".into(),
            token_addr: "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9".into(),
            staking_addr: "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9".into(),
            node_id: "node-test".into(),
            validator_privkey: None,
            bridge_privkey: None,
            is_validator: false,
            peers: vec![],
            block_interval_secs: 5,
            vote_timeout_secs: 10,
            ipfs_url: "http://127.0.0.1:5001".into(),
            pg_url: String::new(),
            validator_set: common::ValidatorSet::new(vec![]),
            mode: NodeMode::Pruned,
            pruning: PruningConfig::default(),
            max_peers: 15,
            cors: CorsConfig::default(),
            is_testnet: true,
        }
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

    #[test]
    fn production_security_env_guards() {
        std::env::set_var("CREG_DEV_SANDBOX", "true");
        std::env::set_var("CREG_PBFT_ALLOW_SMALL_CLUSTER_QUORUM", "true");
        std::env::set_var("CREG_SECRETS_BACKEND", "env");

        let mut prod = base_config();
        prod.is_testnet = false;
        let prod_errors = prod.validate_production_security();
        assert!(
            prod_errors.iter().any(|e| e.contains("CREG_DEV_SANDBOX")),
            "{prod_errors:?}"
        );
        assert!(
            prod_errors
                .iter()
                .any(|e| e.contains("CREG_PBFT_ALLOW_SMALL_CLUSTER_QUORUM")),
            "{prod_errors:?}"
        );
        assert!(
            prod_errors
                .iter()
                .any(|e| e.contains("CREG_SECRETS_BACKEND")),
            "{prod_errors:?}"
        );

        let testnet = base_config();
        assert!(
            testnet.validate_production_security().is_empty(),
            "testnet should allow dev bypass env vars"
        );

        std::env::remove_var("CREG_DEV_SANDBOX");
        std::env::remove_var("CREG_PBFT_ALLOW_SMALL_CLUSTER_QUORUM");
        std::env::remove_var("CREG_SECRETS_BACKEND");
    }

    #[test]
    fn mal001_public_validator_rejects_dev_sandbox() {
        std::env::set_var("CREG_DEV_SANDBOX", "true");
        std::env::set_var("CREG_PUBLIC_VALIDATOR", "true");

        let mut validator = base_config();
        validator.is_validator = true;
        let errors = validator.validate_mal001_public_validator();
        assert!(errors.iter().any(|e| e.contains("MAL-001")), "{errors:?}");

        std::env::remove_var("CREG_PUBLIC_VALIDATOR");
        assert!(
            validator.validate_mal001_public_validator().is_empty(),
            "without CREG_PUBLIC_VALIDATOR local dev bypass is allowed"
        );

        let observer = base_config();
        assert!(observer.validate_mal001_public_validator().is_empty());

        std::env::remove_var("CREG_DEV_SANDBOX");
    }

    #[test]
    fn rejects_empty_pubkey() {
        let mut cfg = base_config();
        cfg.validator_set = common::ValidatorSet::new(vec![validator("node-1", "")]);
        let errors = cfg.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("node-1") && e.contains("empty/zero pubkey")),
            "expected empty-pubkey error, got: {:?}",
            errors
        );
    }

    #[test]
    fn rejects_zero_pubkey() {
        let mut cfg = base_config();
        cfg.validator_set = common::ValidatorSet::new(vec![validator(
            "node-zero",
            "0000000000000000000000000000000000000000000000000000000000000000",
        )]);
        let errors = cfg.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("node-zero") && e.contains("empty/zero pubkey")),
            "expected zero-pubkey error, got: {:?}",
            errors
        );
    }

    #[test]
    fn rejects_short_pubkey() {
        let mut cfg = base_config();
        cfg.validator_set = common::ValidatorSet::new(vec![validator("node-short", "deadbeef")]);
        let errors = cfg.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("node-short") && e.contains("32 bytes")),
            "expected length error, got: {:?}",
            errors
        );
    }

    #[test]
    fn accepts_valid_pubkey() {
        let mut cfg = base_config();
        cfg.validator_set = common::ValidatorSet::new(vec![validator(
            "node-ok",
            "808704b7245921ce7fa3d923bccd0cc30cea91885bc639e92ba4e4c20fcfe6bd",
        )]);
        let errors = cfg.validate();
        assert!(
            !errors.iter().any(|e| e.contains("node-ok")),
            "expected no errors for valid pubkey, got: {:?}",
            errors
        );
    }

    fn pk(prefix: &str) -> String {
        // Build a 32-byte hex string by repeating the prefix and zero-padding.
        let mut s = String::from(prefix);
        while s.len() < 64 {
            s.push('0');
        }
        s.truncate(64);
        s
    }

    #[test]
    fn identity_hash_is_deterministic() {
        let cfg = base_config();
        let h1 = cfg.compute_network_identity_hash();
        let h2 = cfg.compute_network_identity_hash();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64, "sha256 hex must be 64 chars, got {}", h1);
    }

    #[test]
    fn identity_hash_orders_validators_by_id() {
        let mut cfg_a = base_config();
        cfg_a.validator_set = common::ValidatorSet::new(vec![
            validator("alpha", &pk("aa")),
            validator("beta", &pk("bb")),
        ]);
        let mut cfg_b = base_config();
        cfg_b.validator_set = common::ValidatorSet::new(vec![
            validator("beta", &pk("bb")),
            validator("alpha", &pk("aa")),
        ]);
        assert_eq!(
            cfg_a.compute_network_identity_hash(),
            cfg_b.compute_network_identity_hash(),
            "validator order in CREG_VALIDATOR_SET must not affect the network identity hash"
        );
    }

    #[test]
    fn identity_hash_is_case_insensitive_for_addrs_and_keys() {
        let mut cfg_lower = base_config();
        cfg_lower.registry_addr = "0xdc64a140aa3e981100a9beca4e685f962f0cf6c9".into();
        cfg_lower.validator_set =
            common::ValidatorSet::new(vec![validator("node-1", &pk("aabb").to_lowercase())]);
        let mut cfg_upper = base_config();
        cfg_upper.registry_addr = "0xDC64A140AA3E981100A9BECA4E685F962F0CF6C9".into();
        cfg_upper.validator_set =
            common::ValidatorSet::new(vec![validator("node-1", &pk("AABB").to_uppercase())]);
        assert_eq!(
            cfg_lower.compute_network_identity_hash(),
            cfg_upper.compute_network_identity_hash()
        );
    }

    #[test]
    fn identity_hash_changes_with_chain_id() {
        let mut cfg = base_config();
        let h1 = cfg.compute_network_identity_hash();
        cfg.chain_id = "creg-mainnet".into();
        let h2 = cfg.compute_network_identity_hash();
        assert_ne!(h1, h2, "different chain_id must produce a different hash");
    }

    #[test]
    fn identity_hash_changes_when_validator_pubkey_changes() {
        let mut cfg = base_config();
        cfg.validator_set = common::ValidatorSet::new(vec![validator("node-1", &pk("11"))]);
        let h1 = cfg.compute_network_identity_hash();
        cfg.validator_set = common::ValidatorSet::new(vec![validator("node-1", &pk("22"))]);
        let h2 = cfg.compute_network_identity_hash();
        assert_ne!(h1, h2);
    }

    #[test]
    fn validate_genesis_hash_value_passes_when_unset() {
        let cfg = base_config();
        let computed = cfg
            .validate_genesis_hash_value(None)
            .expect("None should pass");
        assert_eq!(computed, cfg.compute_network_identity_hash());
        assert_eq!(
            cfg.validate_genesis_hash_value(Some("")).unwrap(),
            cfg.validate_genesis_hash_value(Some("   ")).unwrap()
        );
    }

    #[test]
    fn validate_genesis_hash_value_passes_on_match() {
        let cfg = base_config();
        let computed = cfg.compute_network_identity_hash();
        // Pass with and without 0x prefix, mixed case.
        cfg.validate_genesis_hash_value(Some(&computed))
            .expect("exact match");
        cfg.validate_genesis_hash_value(Some(&format!("0x{}", computed)))
            .expect("0x-prefixed match");
        cfg.validate_genesis_hash_value(Some(&computed.to_uppercase()))
            .expect("uppercase match");
    }

    #[test]
    fn validate_genesis_hash_value_rejects_mismatch() {
        let cfg = base_config();
        let bogus = "0".repeat(64);
        let err = cfg
            .validate_genesis_hash_value(Some(&bogus))
            .expect_err("mismatch must error");
        assert!(err.contains("genesis hash mismatch"));
        assert!(err.contains(&bogus));
    }

    #[test]
    fn cors_defaults_are_safe() {
        let cfg = base_config();
        assert!(cfg.cors.allowed_origins.is_empty());
        assert!(!cfg.cors.allow_credentials);
        assert_eq!(
            cfg.cors.allowed_methods,
            vec!["GET", "POST", "DELETE", "OPTIONS"]
        );
        assert!(cfg.cors.validate().is_empty());
    }

    #[test]
    fn cors_rejects_wildcard_with_credentials() {
        let mut cfg = base_config();
        cfg.cors = CorsConfig {
            allowed_origins: vec!["*".into()],
            allowed_methods: default_cors_methods(),
            allow_credentials: true,
        };

        let errors = cfg.validate();
        assert!(
            errors
                .iter()
                .any(|error| error.contains("cannot be used with wildcard")),
            "expected wildcard+credentials validation error, got: {:?}",
            errors
        );
    }

    #[test]
    fn cors_from_env_values_normalizes_origins_and_methods() {
        let cors = CorsConfig::from_env_values(
            " https://explorer.example.com/ , http://localhost:4173 ",
            "get,post,options",
            true,
        );

        assert_eq!(
            cors.allowed_origins,
            vec![
                "https://explorer.example.com".to_string(),
                "http://localhost:4173".to_string()
            ]
        );
        assert_eq!(cors.allowed_methods, vec!["GET", "POST", "OPTIONS"]);
        assert!(cors.allow_credentials);
        assert!(cors.validate().is_empty());
    }
}
