// crates/common/src/chain_spec.rs
// Chain Spec — single source of truth for network identity.
//
// Fetched over HTTPS at boot, Ed25519-signed, JCS-canonicalized.
// See docs/CHAIN_SPEC_DESIGN.md for the full specification.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Schema version. Node refuses unknown versions.
pub const CURRENT_SPEC_VERSION: i32 = 1;

/// Domain separator for spec signature verification.
pub const SPEC_SIGNATURE_DOMAIN: &str = "creg-chain-spec-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct ChainSpec {
    pub spec_version: i32,
    pub chain_id: String,
    pub network: Network,
    pub phase: Phase,
    pub genesis_time: String, // RFC3339
    pub genesis_hash: String, // 0x-hex(32)
    pub consensus_params: ConsensusParams,
    pub feature_flags: FeatureFlags,
    pub l1: L1Config,
    pub contracts: BTreeMap<String, String>, // name → address
    pub bootnodes: Vec<Bootnode>,
    pub validator_set: ValidatorSetSpec,
    pub services: Services,
    #[serde(default, skip_serializing_if = "Support::is_empty")]
    pub support: Support,
    pub signing: Signing,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Network {
    Testnet,
    Staging,
    Mainnet,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Alpha,
    Beta,
    #[serde(rename = "gA")]
    GA,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConsensusParams {
    pub block_time_seconds: u64,
    pub vote_timeout_ms: u64,
    pub quorum_percentage: u8,
    pub min_validator_stake_wei: String,
    pub min_publisher_stake_wei: String,
    pub unbonding_period_seconds: u64,
    pub slash_penalty_low_bp: u16,
    pub slash_penalty_medium_bp: u16,
    pub slash_penalty_critical_bp: u16,
    pub max_validators: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FeatureFlags {
    pub zk_validation: bool,
    pub ml_validation: bool,
    pub wasm_sandbox: bool,
    pub private_registries: bool,
    pub cross_chain: bool,
    pub insurance: bool,
    pub threshold_encryption: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct L1Config {
    pub name: String,
    pub chain_id: u64,
    pub block_explorer: String,
    pub min_finality_blocks: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Bootnode {
    pub id: String,
    pub operator: String,
    pub region: String,
    pub multiaddr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidatorSetSpec {
    pub version: u64,
    pub last_updated: String,
    pub epoch_block_height: u64,
    pub validators: Vec<ValidatorSpecEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidatorSpecEntry {
    pub id: String,
    pub alias: String,
    pub pubkey: String,      // Ed25519 pubkey hex
    pub eth_address: String, // secp256k1 address
    pub stake: u64,
    pub reputation: u32,
    pub status: String, // active | pending | jailed
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Services {
    pub ipfs_gateway: String,
    pub ipfs_api: String,
    pub faucet: String,
    pub explorer: String,
    pub metrics: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Support {
    pub matrix: Option<String>,
    pub discord: Option<String>,
    pub issues: Option<String>,
    pub security: Option<String>,
}

impl Support {
    pub fn is_empty(&self) -> bool {
        self.matrix.is_none()
            && self.discord.is_none()
            && self.issues.is_none()
            && self.security.is_none()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Signing {
    pub signature_algorithm: String,
    pub signing_key_pubkey_hex: String,
    pub detached_signature_url: String,
}

// ── Genesis hash computation ─────────────────────────────────────────────────

impl ChainSpec {
    /// Compute the genesis hash per the design doc:
    /// sha256( canonical_json( { chain_id, genesis_time, consensus_params,
    ///                            feature_flags, l1.chain_id, contracts,
    ///                            validator_set } ) )
    ///
    /// canonical_json = JCS (RFC 8785): keys sorted, no whitespace, UTF-8 NFC.
    pub fn compute_genesis_hash(&self) -> anyhow::Result<String> {
        let canonical = GenesisHashPayload {
            chain_id: &self.chain_id,
            genesis_time: &self.genesis_time,
            consensus_params: &self.consensus_params,
            feature_flags: &self.feature_flags,
            l1: L1HashPayload {
                chain_id: self.l1.chain_id,
            },
            contracts: &self.contracts,
            validator_set: ValidatorSetHashPayload {
                version: self.validator_set.version,
                validators: self
                    .validator_set
                    .validators
                    .iter()
                    .map(|v| {
                        (
                            v.id.clone(),
                            v.pubkey.clone(),
                            v.eth_address.clone(),
                            v.stake,
                        )
                    })
                    .collect(),
            },
        };

        let jcs = to_jcs_canonical_json(&canonical)?;
        let hash = Sha256::digest(&jcs);
        Ok(format!("0x{}", hex::encode(hash)))
    }

    /// Verify the spec's Ed25519 signature.
    pub fn verify_signature(&self, signature_hex: &str, pubkey_hex: &str) -> anyhow::Result<()> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let pubkey_bytes = hex::decode(pubkey_hex.trim_start_matches("0x"))
            .map_err(|_| anyhow::anyhow!("invalid pubkey hex"))?;
        let pubkey = VerifyingKey::from_bytes(
            &pubkey_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("pubkey must be 32 bytes"))?,
        )
        .map_err(|e| anyhow::anyhow!("invalid verifying key: {}", e))?;

        let sig_bytes = hex::decode(signature_hex.trim_start_matches("0x"))
            .map_err(|_| anyhow::anyhow!("invalid signature hex"))?;
        let signature = Signature::from_bytes(
            &sig_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("signature must be 64 bytes"))?,
        );

        let message = format!(
            "{}|{}",
            SPEC_SIGNATURE_DOMAIN,
            self.canonical_json_for_signing()?
        );

        pubkey
            .verify(message.as_bytes(), &signature)
            .map_err(|_| anyhow::anyhow!("spec signature verification failed"))
    }

    /// Return a JCS-canonicalized JSON string of the full spec (for signing).
    fn canonical_json_for_signing(&self) -> anyhow::Result<String> {
        let bytes = to_jcs_canonical_json(self)?;
        String::from_utf8(bytes)
            .map_err(|e| anyhow::anyhow!("JCS output is not valid UTF-8: {}", e))
    }

    /// Convert the spec's validator set to the runtime `common::ValidatorSet`.
    pub fn to_runtime_validator_set(&self) -> crate::ValidatorSet {
        let validators = self
            .validator_set
            .validators
            .iter()
            .map(|v| crate::Validator {
                id: v.id.clone(),
                alias: v.alias.clone(),
                pubkey: v.pubkey.clone(),
                eth_address: v.eth_address.clone(),
                stake: v.stake,
                reputation: v.reputation,
                status: v.status.clone(),
            })
            .collect();
        crate::ValidatorSet::new(validators)
    }

    /// Extract p2p seed multiaddrs from bootnodes.
    pub fn p2p_seeds(&self) -> Vec<String> {
        self.bootnodes.iter().map(|b| b.multiaddr.clone()).collect()
    }

    /// Get a contract address by name, or default if missing.
    pub fn contract(&self, name: &str) -> Option<&String> {
        self.contracts.get(name)
    }
}

// ── Internal helper structs for hash computation ─────────────────────────────

#[derive(Serialize)]
struct GenesisHashPayload<'a> {
    chain_id: &'a str,
    genesis_time: &'a str,
    consensus_params: &'a ConsensusParams,
    feature_flags: &'a FeatureFlags,
    l1: L1HashPayload,
    contracts: &'a BTreeMap<String, String>,
    validator_set: ValidatorSetHashPayload,
}

#[derive(Serialize)]
struct L1HashPayload {
    chain_id: u64,
}

#[derive(Serialize)]
struct ValidatorSetHashPayload {
    version: u64,
    validators: Vec<(String, String, String, u64)>, // (id, pubkey, eth_address, stake)
}

// ── Manual JCS canonicalization ──────────────────────────────────────────────
//
// JCS (RFC 8785) requires: keys sorted lexicographically, no whitespace,
// compact JSON encoding. We implement this manually via serde_json::Value
// to avoid depending on the unmaintained serde_jcs crate.

pub fn to_jcs_canonical_json<T: Serialize>(value: &T) -> anyhow::Result<Vec<u8>> {
    let value = serde_json::to_value(value)
        .map_err(|e| anyhow::anyhow!("serialization to Value failed: {}", e))?;
    let mut output = Vec::new();
    write_jcs_value(&mut output, &value)?;
    Ok(output)
}

fn write_jcs_value(w: &mut Vec<u8>, value: &serde_json::Value) -> anyhow::Result<()> {
    use serde_json::Value;
    match value {
        Value::Null => w.extend_from_slice(b"null"),
        Value::Bool(b) => w.extend_from_slice(if *b { b"true" } else { b"false" }),
        Value::Number(n) => {
            let s = n.to_string();
            w.extend_from_slice(s.as_bytes());
        }
        Value::String(s) => write_jcs_string(w, s),
        Value::Array(arr) => {
            w.push(b'[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    w.push(b',');
                }
                write_jcs_value(w, item)?;
            }
            w.push(b']');
        }
        Value::Object(map) => {
            w.push(b'{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    w.push(b',');
                }
                write_jcs_string(w, key);
                w.push(b':');
                write_jcs_value(w, &map[*key])?;
            }
            w.push(b'}');
        }
    }
    Ok(())
}

fn write_jcs_string(w: &mut Vec<u8>, s: &str) {
    w.push(b'"');
    for ch in s.chars() {
        match ch {
            '"' => w.extend_from_slice(b"\\\""),
            '\\' => w.extend_from_slice(b"\\\\"),
            '\u{0008}' => w.extend_from_slice(b"\\b"),
            '\u{000C}' => w.extend_from_slice(b"\\f"),
            '\n' => w.extend_from_slice(b"\\n"),
            '\r' => w.extend_from_slice(b"\\r"),
            '\t' => w.extend_from_slice(b"\\t"),
            c if c < '\u{0010}' => {
                w.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            c => {
                let mut buf = [0u8; 4];
                w.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    w.push(b'"');
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_spec() -> ChainSpec {
        ChainSpec {
            spec_version: 1,
            chain_id: "creg-testnet-1".into(),
            network: Network::Testnet,
            phase: Phase::Alpha,
            genesis_time: "2026-05-01T00:00:00Z".into(),
            genesis_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                .into(),
            consensus_params: ConsensusParams {
                block_time_seconds: 5,
                vote_timeout_ms: 10000,
                quorum_percentage: 67,
                min_validator_stake_wei: "100000000000000000000".into(),
                min_publisher_stake_wei: "1000000000000000000".into(),
                unbonding_period_seconds: 86400,
                slash_penalty_low_bp: 200,
                slash_penalty_medium_bp: 1000,
                slash_penalty_critical_bp: 3000,
                max_validators: 50,
            },
            feature_flags: FeatureFlags {
                zk_validation: true,
                ml_validation: true,
                wasm_sandbox: true,
                private_registries: true,
                cross_chain: false,
                insurance: false,
                threshold_encryption: false,
            },
            l1: L1Config {
                name: "sepolia".into(),
                chain_id: 11155111,
                block_explorer: "https://sepolia.etherscan.io".into(),
                min_finality_blocks: 6,
            },
            contracts: {
                let mut m = BTreeMap::new();
                m.insert(
                    "registry".into(),
                    "0xD8a5a9b31c3C0232E196d518E89Fd8bF83AcAd43".into(),
                );
                m.insert(
                    "staking".into(),
                    "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707".into(),
                );
                m
            },
            bootnodes: vec![Bootnode {
                id: "bootnode-1".into(),
                operator: "core-team".into(),
                region: "eu-central".into(),
                multiaddr: "/dns4/bootnode-1.creg-testnet.example/tcp/9000/p2p/12D3KooWREPLACEME"
                    .into(),
            }],
            validator_set: ValidatorSetSpec {
                version: 1,
                last_updated: "2026-05-01T00:00:00Z".into(),
                epoch_block_height: 0,
                validators: vec![ValidatorSpecEntry {
                    id: "core-1".into(),
                    alias: "Core Validator 1".into(),
                    pubkey: "0000000000000000000000000000000000000000000000000000000000000001"
                        .into(),
                    eth_address: "0x0000000000000000000000000000000000000001".into(),
                    stake: 100,
                    reputation: 100,
                    status: "active".into(),
                }],
            },
            services: Services {
                ipfs_gateway: "https://ipfs.creg-testnet.example".into(),
                ipfs_api: "https://ipfs-api.creg-testnet.example".into(),
                faucet: "https://faucet.creg-testnet.example".into(),
                explorer: "https://explorer.creg-testnet.example".into(),
                metrics: "https://metrics.creg-testnet.example".into(),
            },
            support: Support::default(),
            signing: Signing {
                signature_algorithm: "ed25519".into(),
                signing_key_pubkey_hex:
                    "0000000000000000000000000000000000000000000000000000000000000000".into(),
                detached_signature_url: "https://testnet.creg-testnet.example/chain-spec.json.sig"
                    .into(),
            },
        }
    }

    #[test]
    fn test_genesis_hash_is_deterministic() {
        let spec = test_spec();
        let h1 = spec.compute_genesis_hash().unwrap();
        let h2 = spec.compute_genesis_hash().unwrap();
        assert_eq!(h1, h2);
        assert!(h1.starts_with("0x"));
        assert_eq!(h1.len(), 66); // 0x + 64 hex chars
    }

    #[test]
    fn test_jcs_sorts_keys() {
        let mut map = serde_json::Map::new();
        map.insert("z".into(), serde_json::Value::String("last".into()));
        map.insert("a".into(), serde_json::Value::String("first".into()));
        let value = serde_json::Value::Object(map);
        let jcs = to_jcs_canonical_json(&value).unwrap();
        let s = String::from_utf8(jcs).unwrap();
        // Keys must be sorted: a before z
        let a_pos = s.find("\"a\"").unwrap();
        let z_pos = s.find("\"z\"").unwrap();
        assert!(a_pos < z_pos);
    }

    #[test]
    fn test_to_runtime_validator_set() {
        let spec = test_spec();
        let vs = spec.to_runtime_validator_set();
        assert_eq!(vs.validators.len(), 1);
        assert_eq!(vs.validators[0].id, "core-1");
    }

    #[test]
    fn test_p2p_seeds() {
        let spec = test_spec();
        let seeds = spec.p2p_seeds();
        assert_eq!(seeds.len(), 1);
        assert!(seeds[0].contains("bootnode-1"));
    }

    // ── Sepolia chain-spec ↔ on-chain Staking.sol drift guard ────────────────
    //
    // The published Sepolia chain spec is informational for some fields but is
    // read by operators and surfaced in the UI. It MUST match the deployed
    // (immutable) Staking.sol constants. These expected values mirror
    // contracts/Staking.sol; update both together if the contract ever changes
    // on a new deployment. This test fails the build if the JSON drifts.
    mod sepolia_onchain_drift {
        use super::super::ChainSpec;

        // contracts/Staking.sol — Sepolia deployment.
        const ONCHAIN_UNBONDING_SECONDS: u64 = 14 * 24 * 60 * 60; // UNBONDING_PERIOD = 14 days
        const ONCHAIN_MIN_VALIDATOR_STAKE_WEI: &str = "100000000000000000000"; // minValidatorStake = 100 CREG
        const ONCHAIN_MIN_PUBLISHER_STAKE_WEI: &str = "1000000000000000000"; // minPublisherStake = 1 CREG
        const ONCHAIN_SLASH_LOW_BP: u16 = 200; // SLASH_LOW_PCT = 2%
        const ONCHAIN_SLASH_MEDIUM_BP: u16 = 1000; // SLASH_MEDIUM_PCT = 10%
        const ONCHAIN_SLASH_CRITICAL_BP: u16 = 3000; // SLASH_CRITICAL_PCT = 30%

        // Compile-time embed of the canonical published Sepolia spec.
        const SEPOLIA_SPEC_JSON: &str = include_str!("../../../testnet/chain-spec.sepolia.json");

        #[test]
        fn sepolia_spec_matches_onchain_staking_constants() {
            let spec: ChainSpec = serde_json::from_str(SEPOLIA_SPEC_JSON)
                .expect("testnet/chain-spec.sepolia.json must parse");
            let p = &spec.consensus_params;

            assert_eq!(
                p.unbonding_period_seconds, ONCHAIN_UNBONDING_SECONDS,
                "chain-spec unbonding_period_seconds drifted from Staking.sol UNBONDING_PERIOD (14 days)"
            );
            assert_eq!(
                p.min_validator_stake_wei, ONCHAIN_MIN_VALIDATOR_STAKE_WEI,
                "chain-spec min_validator_stake_wei drifted from Staking.sol minValidatorStake"
            );
            assert_eq!(
                p.min_publisher_stake_wei, ONCHAIN_MIN_PUBLISHER_STAKE_WEI,
                "chain-spec min_publisher_stake_wei drifted from Staking.sol minPublisherStake"
            );
            assert_eq!(
                p.slash_penalty_low_bp, ONCHAIN_SLASH_LOW_BP,
                "chain-spec slash_penalty_low_bp drifted from Staking.sol SLASH_LOW_PCT"
            );
            assert_eq!(
                p.slash_penalty_medium_bp, ONCHAIN_SLASH_MEDIUM_BP,
                "chain-spec slash_penalty_medium_bp drifted from Staking.sol SLASH_MEDIUM_PCT"
            );
            assert_eq!(
                p.slash_penalty_critical_bp, ONCHAIN_SLASH_CRITICAL_BP,
                "chain-spec slash_penalty_critical_bp drifted from Staking.sol SLASH_CRITICAL_PCT"
            );
        }
    }
}
