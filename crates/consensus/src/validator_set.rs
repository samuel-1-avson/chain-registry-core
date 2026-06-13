// crates/consensus/src/validator_set.rs
// Active validator set — tracks who can vote on a block.

use common::sha256_hex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub id: String,
    /// Ed25519 public key (hex-encoded) — used for VRF proofs and block signing.
    pub pubkey: String,
    /// Ethereum-style address (0x-prefixed, 20-byte hex) derived from the
    /// validator's secp256k1/ECDSA key.  Used for cross-referencing on-chain
    /// contract votes and slashing evidence.  `None` for legacy validators
    /// that have not yet registered an ECDSA key.
    pub eth_address: Option<String>,
    /// Staked tokens — slashed on bad behaviour.
    pub stake: u64,
    /// Reputation score 0–100. Starts at 50 for new validators.
    pub reputation: u8,
    pub is_active: bool,
}

#[derive(Debug, Clone)]
pub struct ValidatorSet {
    pub(crate) validators: HashMap<String, ValidatorInfo>,
}

impl ValidatorSet {
    pub fn new() -> Self {
        Self {
            validators: HashMap::new(),
        }
    }

    pub fn add(&mut self, info: ValidatorInfo) {
        self.validators.insert(info.id.clone(), info);
    }

    pub fn remove(&mut self, id: &str) {
        if let Some(v) = self.validators.get_mut(id) {
            v.is_active = false;
        }
    }

    pub fn is_member(&self, id: &str) -> bool {
        self.validators
            .get(id)
            .map(|v| v.is_active)
            .unwrap_or(false)
    }

    pub fn len(&self) -> usize {
        self.validators.values().filter(|v| v.is_active).count()
    }

    pub fn active_ids(&self) -> Vec<String> {
        self.validators
            .values()
            .filter(|v| v.is_active)
            .map(|v| v.id.clone())
            .collect()
    }

    /// Slash a validator's stake by `amount`. If stake drops to zero,
    /// they are removed from the active set.
    pub fn slash(&mut self, id: &str, amount: u64, reason: &str) {
        if let Some(v) = self.validators.get_mut(id) {
            tracing::warn!("Slashing {} by {} stake. Reason: {}", id, amount, reason);
            v.stake = v.stake.saturating_sub(amount);
            v.reputation = v.reputation.saturating_sub(10);
            if v.stake == 0 {
                v.is_active = false;
                tracing::warn!("Validator {} removed from active set (stake depleted)", id);
            }
        }
    }

    /// Reward good behaviour with a small reputation boost.
    pub fn reward(&mut self, id: &str) {
        if let Some(v) = self.validators.get_mut(id) {
            v.reputation = v.reputation.saturating_add(1).min(100);
        }
    }

    /// Hash of the current active set — embedded in every block header
    /// so any change to validators is immediately visible on-chain.
    pub fn set_hash(&self) -> String {
        let mut ids = self.active_ids();
        ids.sort();
        sha256_hex(ids.join(",").as_bytes())
    }
}

impl From<common::ValidatorSet> for ValidatorSet {
    fn from(common_vs: common::ValidatorSet) -> Self {
        let mut vs = Self::new();
        for v in common_vs.validators {
            vs.add(ValidatorInfo {
                id: v.id.clone(),
                pubkey: v.pubkey.clone(),
                eth_address: Some(v.eth_address.clone()),
                stake: v.stake,
                reputation: v.reputation.try_into().unwrap_or(100),
                is_active: v.status == "online" || v.status == "self",
            });
        }
        vs
    }
}
