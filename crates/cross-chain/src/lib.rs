//! Cross-Chain Package Verification
//!
//! **Product status (Phase 3 / decision D4):** Configuration and client scaffolding only.
//! On-chain `CrossChainRegistry` remains **Planned** (ISSUE-005/006 open). Sepolia chain specs
//! ship with `feature_flags.cross_chain: false`. Do not enable multi-chain UI or production
//! traffic until **SEC-302a/b** land and tests are green, or an explicit product sign-off.
//!
//! This crate provides multi-chain support for Chain Registry,
//! enabling package verification to be shared across multiple L1/L2 chains.
//!
//! # Features
//!
//! - Multi-chain registry client
//! - Bridge message encoding/decoding
//! - Cross-chain transaction monitoring
//! - Chain selection and fallback
//!
//! # Example
//!
//! ```rust
//! use cross_chain::MultiChainClient;
//!
//! // Build a client across multiple chains. These are placeholder/testnet
//! // configs; override addresses via CREG_CHAIN_<NAME>_* env vars.
//! let client = MultiChainClient::new(vec![
//!     MultiChainClient::arbitrum(),
//!     MultiChainClient::optimism(),
//! ]);
//!
//! assert!(client.list_chains().len() >= 2);
//! ```

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use tracing::warn;

/// Environment variable prefix for overriding contract addresses per chain.
/// Example: CREG_CHAIN_ARBITRUM_REGISTRY=0x1234...
const ENV_PREFIX: &str = "CREG_CHAIN";

/// The Ethereum null address used as a placeholder in unconfigured chains.
const NULL_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

/// Returns `true` if `addr` is non-empty and not the null address.
fn is_real_address(addr: &str) -> bool {
    !addr.is_empty() && addr != NULL_ADDRESS
}

/// Chain configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    /// Chain name
    pub name: String,
    /// Chain ID
    pub chain_id: u64,
    /// LayerZero chain ID
    pub layerzero_id: u16,
    /// RPC URLs
    pub rpc_urls: Vec<String>,
    /// Explorer URL
    pub explorer: String,
    /// Contract addresses
    pub contracts: ContractAddresses,
}

/// Contract addresses for a chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractAddresses {
    /// Registry contract
    pub registry: String,
    /// Cross-chain registry
    pub cross_chain: String,
    /// ZK verifier
    pub zk_verifier: Option<String>,
}

/// Multi-chain client
pub struct MultiChainClient {
    chains: HashMap<String, ChainConfig>,
}

impl MultiChainClient {
    /// Create new multi-chain client.
    ///
    /// Logs a warning for any chain whose contract addresses are empty.
    /// In validator mode, consider calling [`validate_configs`] at startup
    /// to reject configurations with missing addresses.
    pub fn new(configs: Vec<ChainConfig>) -> Self {
        let chains: HashMap<String, ChainConfig> =
            configs.into_iter().map(|c| (c.name.clone(), c)).collect();

        for (name, cfg) in &chains {
            if !is_real_address(&cfg.contracts.registry) {
                warn!(
                    "Cross-chain config for '{}': registry contract address is not set \
                     (got {:?}). Override via CREG_CHAIN_{}_REGISTRY env var.",
                    name,
                    cfg.contracts.registry,
                    name.to_uppercase()
                );
            }
            if !is_real_address(&cfg.contracts.cross_chain) {
                warn!(
                    "Cross-chain config for '{}': cross_chain contract address is not set \
                     (got {:?}). Override via CREG_CHAIN_{}_CROSS_CHAIN env var.",
                    name,
                    cfg.contracts.cross_chain,
                    name.to_uppercase()
                );
            }
        }

        Self { chains }
    }

    /// Validate that all configured chains have real (non-zero, non-empty) contract
    /// addresses.
    ///
    /// Returns a list of human-readable error strings. An empty vec means all chains
    /// are properly configured and ready for on-chain operations.
    ///
    /// # Example
    /// ```
    /// # use cross_chain::MultiChainClient;
    /// let client = MultiChainClient::new(vec![MultiChainClient::arbitrum()]);
    /// let errors = client.validate_configs();
    /// // Arbitrum uses placeholder zero-addresses by default — errors will be non-empty
    /// // until real addresses are provided via CREG_CHAIN_ARBITRUM_REGISTRY etc.
    /// assert!(!errors.is_empty());
    /// ```
    pub fn validate_configs(&self) -> Vec<String> {
        let mut errors = Vec::new();
        for (name, cfg) in &self.chains {
            if !is_real_address(&cfg.contracts.registry) {
                errors.push(format!(
                    "{}: registry address is not configured (got {:?}). \
                     Set CREG_CHAIN_{}_REGISTRY to a real contract address.",
                    name,
                    cfg.contracts.registry,
                    name.to_uppercase()
                ));
            }
            if !is_real_address(&cfg.contracts.cross_chain) {
                errors.push(format!(
                    "{}: cross_chain address is not configured (got {:?}). \
                     Set CREG_CHAIN_{}_CROSS_CHAIN to a real contract address.",
                    name,
                    cfg.contracts.cross_chain,
                    name.to_uppercase()
                ));
            }
        }
        errors
    }

    /// Returns `true` only if every configured chain has real, non-zero contract
    /// addresses. Use this as a pre-flight guard before making any on-chain calls.
    pub fn is_operational(&self) -> bool {
        self.validate_configs().is_empty()
    }

    /// Get chain config by name
    pub fn get_chain(&self, name: &str) -> Option<&ChainConfig> {
        self.chains.get(name)
    }

    /// List all supported chains
    pub fn list_chains(&self) -> Vec<&String> {
        self.chains.keys().collect()
    }

    /// Load a chain config from environment variables, falling back to built-in defaults.
    ///
    /// Environment variables checked (example for chain "arbitrum"):
    ///   - `CREG_CHAIN_ARBITRUM_REGISTRY`
    ///   - `CREG_CHAIN_ARBITRUM_CROSS_CHAIN`
    ///   - `CREG_CHAIN_ARBITRUM_ZK_VERIFIER`
    fn env_override(mut cfg: ChainConfig) -> ChainConfig {
        let upper = cfg.name.to_uppercase();
        if let Ok(v) = std::env::var(format!("{}_{}_REGISTRY", ENV_PREFIX, upper)) {
            cfg.contracts.registry = v;
        }
        if let Ok(v) = std::env::var(format!("{}_{}_CROSS_CHAIN", ENV_PREFIX, upper)) {
            cfg.contracts.cross_chain = v;
        }
        if let Ok(v) = std::env::var(format!("{}_{}_ZK_VERIFIER", ENV_PREFIX, upper)) {
            cfg.contracts.zk_verifier = Some(v);
        }
        cfg
    }

    /// Arbitrum configuration (testnet / placeholder addresses — override via env).
    pub fn arbitrum() -> ChainConfig {
        Self::env_override(ChainConfig {
            name: "arbitrum".to_string(),
            chain_id: 42161,
            layerzero_id: 110,
            rpc_urls: vec!["https://arb1.arbitrum.io/rpc".to_string()],
            explorer: "https://arbiscan.io".to_string(),
            contracts: ContractAddresses {
                registry: "0x0000000000000000000000000000000000000000".to_string(),
                cross_chain: "0x0000000000000000000000000000000000000000".to_string(),
                zk_verifier: None,
            },
        })
    }

    /// Optimism configuration (testnet / placeholder addresses — override via env).
    pub fn optimism() -> ChainConfig {
        Self::env_override(ChainConfig {
            name: "optimism".to_string(),
            chain_id: 10,
            layerzero_id: 111,
            rpc_urls: vec!["https://mainnet.optimism.io".to_string()],
            explorer: "https://optimistic.etherscan.io".to_string(),
            contracts: ContractAddresses {
                registry: "0x0000000000000000000000000000000000000000".to_string(),
                cross_chain: "0x0000000000000000000000000000000000000000".to_string(),
                zk_verifier: None,
            },
        })
    }

    /// Polygon configuration (testnet / placeholder addresses — override via env).
    pub fn polygon() -> ChainConfig {
        Self::env_override(ChainConfig {
            name: "polygon".to_string(),
            chain_id: 137,
            layerzero_id: 109,
            rpc_urls: vec!["https://polygon-rpc.com".to_string()],
            explorer: "https://polygonscan.com".to_string(),
            contracts: ContractAddresses {
                registry: "0x0000000000000000000000000000000000000000".to_string(),
                cross_chain: "0x0000000000000000000000000000000000000000".to_string(),
                zk_verifier: None,
            },
        })
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Cross-chain message ordering & replay protection
// ────────────────────────────────────────────────────────────────────────────

/// A cross-chain verification message with a monotonic sequence number.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrossChainMessage {
    /// Globally unique message identifier.
    pub id: String,
    /// Source chain name (e.g. "arbitrum").
    pub source_chain: String,
    /// Destination chain name.
    pub dest_chain: String,
    /// Monotonically increasing per-source sequence number.
    pub sequence: u64,
    /// The payload — canonical package ID being synced.
    pub canonical: String,
    /// SHA-256 hash of the payload for integrity checking.
    pub payload_hash: String,
    /// Unix timestamp (seconds) when the message was created.
    pub timestamp: u64,
}

/// Tracks per-chain sequence numbers and rejects duplicates / out-of-order
/// messages.  Holds a sliding window of recently delivered message IDs for
/// replay protection.
pub struct MessageOrderer {
    /// Next expected sequence number per source chain.
    next_sequence: HashMap<String, u64>,
    /// Messages that arrived ahead of sequence, keyed by (source, seq).
    pending: HashMap<(String, u64), CrossChainMessage>,
    /// Set of message IDs that have been delivered (replay protection).
    delivered: HashSet<String>,
    /// Insertion-order queue used by `prune_delivered` to evict only the
    /// *oldest* message IDs, not the entire set.  Without this, pruning
    /// clears all replay protection and previously-delivered IDs can be
    /// replayed.
    delivered_order: VecDeque<String>,
    /// Outbound sequence counter per destination chain.
    outbound_seq: HashMap<String, u64>,
}

impl MessageOrderer {
    pub fn new() -> Self {
        Self {
            next_sequence: HashMap::new(),
            pending: HashMap::new(),
            delivered: HashSet::new(),
            delivered_order: VecDeque::new(),
            outbound_seq: HashMap::new(),
        }
    }

    /// Assign the next outbound sequence number for `dest_chain` and return it.
    pub fn next_outbound_seq(&mut self, dest_chain: &str) -> u64 {
        let seq = self.outbound_seq.entry(dest_chain.to_string()).or_insert(0);
        let current = *seq;
        *seq += 1;
        current
    }

    /// Ingest an incoming message.
    ///
    /// Returns a `Vec` of messages that are now deliverable in-order
    /// (may be empty if the message is out-of-order and buffered, or a
    /// duplicate/replay).
    pub fn ingest(&mut self, msg: CrossChainMessage) -> Vec<CrossChainMessage> {
        // Replay protection: reject already-delivered IDs.
        if self.delivered.contains(&msg.id) {
            warn!(
                "Duplicate cross-chain message {} from {} (seq {})",
                msg.id, msg.source_chain, msg.sequence
            );
            return Vec::new();
        }

        let expected = *self
            .next_sequence
            .entry(msg.source_chain.clone())
            .or_insert(0);

        if msg.sequence < expected {
            // Already processed — silently drop.
            return Vec::new();
        }

        // Buffer this message (even if it's the expected one — we'll drain below).
        self.pending
            .insert((msg.source_chain.clone(), msg.sequence), msg.clone());

        // Drain as many consecutive messages as possible.
        let source = msg.source_chain.clone();
        let mut deliverable = Vec::new();
        let mut seq = expected;
        while let Some(m) = self.pending.remove(&(source.clone(), seq)) {
            self.delivered.insert(m.id.clone());
            self.delivered_order.push_back(m.id.clone());
            deliverable.push(m);
            seq += 1;
        }
        self.next_sequence.insert(source, seq);

        deliverable
    }

    /// Number of out-of-order messages currently buffered.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Prune the delivered set to bound memory.  Call periodically.
    ///
    /// Evicts the *oldest* delivered IDs first (FIFO order), retaining the
    /// most-recently delivered entries for replay protection.  Previously
    /// the entire set was cleared at once, which would allow any message
    /// delivered before the prune to be replayed.
    pub fn prune_delivered(&mut self, max_entries: usize) {
        while self.delivered.len() > max_entries {
            if let Some(oldest) = self.delivered_order.pop_front() {
                self.delivered.remove(&oldest);
            } else {
                // Queue and set are out of sync — clear both defensively.
                self.delivered.clear();
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_config() {
        let arbitrum = MultiChainClient::arbitrum();
        assert_eq!(arbitrum.chain_id, 42161);
        assert_eq!(arbitrum.layerzero_id, 110);
    }

    #[test]
    fn test_multi_chain_client() {
        let client = MultiChainClient::new(vec![
            MultiChainClient::arbitrum(),
            MultiChainClient::optimism(),
        ]);

        assert_eq!(client.list_chains().len(), 2);
        assert!(client.get_chain("arbitrum").is_some());
        assert!(client.get_chain("optimism").is_some());
    }

    #[test]
    fn test_validate_configs_reports_placeholder_addresses() {
        // Empty string → not configured
        let client = MultiChainClient::new(vec![ChainConfig {
            name: "test-chain".to_string(),
            chain_id: 1,
            layerzero_id: 1,
            rpc_urls: vec![],
            explorer: String::new(),
            contracts: ContractAddresses {
                registry: "".to_string(),
                cross_chain: "0xabc".to_string(),
                zk_verifier: None,
            },
        }]);
        let errors = client.validate_configs();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("registry"));

        // Zero address → also not configured
        let client2 = MultiChainClient::new(vec![ChainConfig {
            name: "zero-chain".to_string(),
            chain_id: 2,
            layerzero_id: 2,
            rpc_urls: vec![],
            explorer: String::new(),
            contracts: ContractAddresses {
                registry: NULL_ADDRESS.to_string(),
                cross_chain: NULL_ADDRESS.to_string(),
                zk_verifier: None,
            },
        }]);
        let errors2 = client2.validate_configs();
        assert_eq!(errors2.len(), 2, "both zero addresses should be flagged");
        assert!(!client2.is_operational());

        // Real addresses → no errors
        let client3 = MultiChainClient::new(vec![ChainConfig {
            name: "real-chain".to_string(),
            chain_id: 3,
            layerzero_id: 3,
            rpc_urls: vec![],
            explorer: String::new(),
            contracts: ContractAddresses {
                registry: "0xCAfEcAfEcafECaFECaFecaFecaFECafECAFECAFE".to_string(),
                cross_chain: "0xDeADbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF".to_string(),
                zk_verifier: None,
            },
        }]);
        assert!(client3.validate_configs().is_empty());
        assert!(client3.is_operational());
    }

    #[test]
    fn test_default_l2_chains_are_not_operational() {
        // The built-in chain configs use zero-address placeholders that must be
        // overridden via env vars before any on-chain operations can proceed.
        let client = MultiChainClient::new(vec![
            MultiChainClient::arbitrum(),
            MultiChainClient::optimism(),
            MultiChainClient::polygon(),
        ]);
        let errors = client.validate_configs();
        assert!(
            !errors.is_empty(),
            "default chain configs must report missing addresses"
        );
        assert!(
            !client.is_operational(),
            "default chain configs must not be considered operational"
        );
    }

    fn make_msg(source: &str, seq: u64) -> CrossChainMessage {
        CrossChainMessage {
            id: format!("{}-{}", source, seq),
            source_chain: source.to_string(),
            dest_chain: "local".to_string(),
            sequence: seq,
            canonical: format!("npm:pkg@{}", seq),
            payload_hash: "abc".to_string(),
            timestamp: 1000 + seq,
        }
    }

    #[test]
    fn test_in_order_delivery() {
        let mut orderer = MessageOrderer::new();
        let delivered = orderer.ingest(make_msg("arb", 0));
        assert_eq!(delivered.len(), 1);
        let delivered = orderer.ingest(make_msg("arb", 1));
        assert_eq!(delivered.len(), 1);
        assert_eq!(orderer.pending_count(), 0);
    }

    #[test]
    fn test_out_of_order_buffering() {
        let mut orderer = MessageOrderer::new();
        // Send seq 2 first — should be buffered.
        let delivered = orderer.ingest(make_msg("arb", 2));
        assert!(delivered.is_empty());
        assert_eq!(orderer.pending_count(), 1);

        // Send seq 1 — still buffered.
        let delivered = orderer.ingest(make_msg("arb", 1));
        assert!(delivered.is_empty());
        assert_eq!(orderer.pending_count(), 2);

        // Send seq 0 — should drain all three.
        let delivered = orderer.ingest(make_msg("arb", 0));
        assert_eq!(delivered.len(), 3);
        assert_eq!(delivered[0].sequence, 0);
        assert_eq!(delivered[1].sequence, 1);
        assert_eq!(delivered[2].sequence, 2);
        assert_eq!(orderer.pending_count(), 0);
    }

    #[test]
    fn test_replay_rejected() {
        let mut orderer = MessageOrderer::new();
        orderer.ingest(make_msg("arb", 0));
        // Replay same message — should be rejected.
        let delivered = orderer.ingest(make_msg("arb", 0));
        assert!(delivered.is_empty());
    }

    #[test]
    fn test_outbound_sequence() {
        let mut orderer = MessageOrderer::new();
        assert_eq!(orderer.next_outbound_seq("arb"), 0);
        assert_eq!(orderer.next_outbound_seq("arb"), 1);
        assert_eq!(orderer.next_outbound_seq("opt"), 0);
    }
}
