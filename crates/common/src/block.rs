// crates/common/src/block.rs

use crate::{sha256_hex, ChainRecord};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A single block in the package registry blockchain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
    /// Ed25519 signatures from PBFT Commit phase over the block hash.
    #[serde(default)]
    pub pbft_signatures: Vec<BlockSignature>,
}

impl Block {
    /// Compute the block hash over the serialized header.
    pub fn hash(&self) -> String {
        let header_bytes =
            serde_json::to_vec(&self.header).expect("BlockHeader must be serializable");
        sha256_hex(&header_bytes)
    }

    /// Genesis block — the first block in the chain with no parent.
    pub fn genesis() -> Self {
        Self {
            header: BlockHeader {
                height: 0,
                prev_hash: "0".repeat(64),
                merkle_root: "0".repeat(64),
                proposer_id: "genesis".into(),
                timestamp: DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
                    .expect("genesis timestamp must be valid")
                    .with_timezone(&Utc),
                validator_set_hash: "0".repeat(64),
                vrf_output: None,
                vrf_proof: None,
            },
            transactions: vec![],
            pbft_signatures: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub height: u64,
    /// Hash of the previous block — links the chain.
    pub prev_hash: String,
    /// Merkle root of all transaction hashes in this block.
    pub merkle_root: String,
    /// ID of the validator node that proposed this block.
    pub proposer_id: String,
    pub timestamp: DateTime<Utc>,
    /// Hash of the current active validator set (detects set changes).
    pub validator_set_hash: String,
    /// VRF output (hex) used for proposer selection.
    #[serde(default)]
    pub vrf_output: Option<String>,
    /// VRF proof (hex signature) proving the proposer's legitimacy.
    #[serde(default)]
    pub vrf_proof: Option<String>,
}

/// A signature from a validator explicitly voting for a block in PBFT.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockSignature {
    pub validator_id: String,
    /// Hex-encoded Ed25519 public key.
    pub pubkey: String,
    /// Hex-encoded Ed25519 signature over the block hash.
    pub signature: String,
}

/// Every action recorded on the chain is a Transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Transaction {
    /// A new package accepted by consensus.
    Publish(ChainRecord),
    /// A previously accepted package has been revoked.
    Revoke {
        package_canonical: String,
        reason: String,
        revoked_by: String,
        evidence_hash: String,
    },
    /// A validator's stake was slashed for bad behaviour.
    Slash {
        validator_id: String,
        amount: u64,
        reason: String,
    },
    /// A new validator joined the active set.
    ValidatorJoin {
        validator_id: String,
        pubkey: String,
        stake: u64,
    },
    /// A validator left the active set.
    ValidatorLeave { validator_id: String },
    /// A publisher rotated their Ed25519 signing key.
    RotatePublisherKey {
        canonical_prefix: String,
        old_pubkey: String,
        new_pubkey: String,
        sig_from_old: String,
        sig_from_new: String,
        timestamp: DateTime<Utc>,
        /// Monotonic nonce — must be strictly greater than the last
        /// rotation nonce for this publisher.  Prevents replay attacks.
        #[serde(default)]
        nonce: u64,
    },
}

/// Computes the Merkle root of a list of transaction hashes.
/// Returns a fixed "empty" hash for an empty list.
pub fn merkle_root(txs: &[Transaction]) -> String {
    if txs.is_empty() {
        return sha256_hex(b"empty");
    }
    let mut hashes: Vec<String> = txs
        .iter()
        .map(|tx| {
            sha256_hex(
                serde_json::to_vec(tx)
                    .expect("transaction must be serializable")
                    .as_slice(),
            )
        })
        .collect();

    while hashes.len() > 1 {
        if hashes.len() % 2 != 0 {
            let last = hashes.last().expect("hashes is non-empty").clone();
            hashes.push(last);
        }
        hashes = hashes
            .chunks(2)
            .map(|pair| sha256_hex(format!("{}{}", pair[0], pair[1]).as_bytes()))
            .collect();
    }
    hashes.remove(0)
}
