// crates/node/src/publisher_index.rs
// An in-memory index of per-publisher statistics, rebuilt from the chain
// at startup and updated as new blocks arrive.
// This is what backs GET /v1/publishers/:pubkey in the REST API,
// which the validator reputation stage queries.

use chrono::{DateTime, Utc};
use common::{Block, Transaction};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Aggregated stats for a single publisher (keyed by Ed25519 pubkey hex).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PublisherStats {
    pub pubkey: String,
    /// Total packages ever submitted (including revoked).
    pub total_packages: u32,
    /// Packages that reached Verified status.
    pub verified_count: u32,
    /// Packages that were later revoked.
    pub revoked_count: u32,
    /// Stake in wei (managed by Validator/Publisher slashes and on-chain syncing).
    pub stake_wei: u64,
    /// Wall-clock time of first-ever submission.
    pub first_seen_at: Option<DateTime<Utc>>,
    /// Days since first_seen_at (convenience field for reputation stage).
    pub first_seen_days: u32,
}

pub struct PublisherIndex {
    stats: HashMap<String, PublisherStats>,
    /// Reverse map: canonical package ID → publisher pubkey.
    /// Required for correct revocation attribution.
    canonical_to_pubkey: HashMap<String, String>,
}

impl PublisherIndex {
    pub fn new() -> Self {
        Self {
            stats: HashMap::new(),
            canonical_to_pubkey: HashMap::new(),
        }
    }

    /// Rebuild the index by replaying every block from the chain store.
    pub fn rebuild_from_chain<'a>(&mut self, blocks: impl Iterator<Item = &'a Block>) {
        self.stats.clear();
        self.canonical_to_pubkey.clear();
        for block in blocks {
            self.apply_block(block);
        }
        tracing::info!(
            "Publisher index built: {} publishers, {} package mappings",
            self.stats.len(),
            self.canonical_to_pubkey.len(),
        );
    }

    /// Apply a single newly-arrived block to the index.
    pub fn apply_block(&mut self, block: &Block) {
        for tx in &block.transactions {
            self.apply_tx(tx, block.header.timestamp);
        }
    }

    fn apply_tx(&mut self, tx: &Transaction, timestamp: DateTime<Utc>) {
        match tx {
            Transaction::Publish(record) => {
                let pubkey = record.publisher_pubkey.clone();
                let canonical = record.id.canonical();

                // Record the canonical → pubkey mapping for future revocations.
                self.canonical_to_pubkey.insert(canonical, pubkey.clone());

                let entry = self
                    .stats
                    .entry(pubkey.clone())
                    .or_insert_with(|| PublisherStats {
                        pubkey: pubkey.clone(),
                        ..Default::default()
                    });

                entry.total_packages += 1;
                entry.verified_count += 1; // publish tx means it was verified
                if entry.first_seen_at.is_none() {
                    entry.first_seen_at = Some(timestamp);
                }
                entry.first_seen_days = entry
                    .first_seen_at
                    .map(|t| (Utc::now() - t).num_days().max(0) as u32)
                    .unwrap_or(0);
            }

            Transaction::Revoke {
                package_canonical, ..
            } => {
                // Look up the correct publisher via the reverse index.
                if let Some(pubkey) = self.canonical_to_pubkey.get(package_canonical).cloned() {
                    if let Some(stats) = self.stats.get_mut(&pubkey) {
                        stats.verified_count = stats.verified_count.saturating_sub(1);
                        stats.revoked_count += 1;
                        tracing::info!(
                            "Publisher {} penalised: revocation of {}",
                            &pubkey[..std::cmp::min(16, pubkey.len())],
                            package_canonical,
                        );
                    }
                } else {
                    tracing::warn!(
                        "Revocation for '{}' has no known publisher in index",
                        package_canonical,
                    );
                }
            }

            Transaction::Slash {
                validator_id,
                amount,
                ..
            } => {
                // Slashes reduce effective stake. Map validator_id to publisher.
                if let Some(stats) = self.stats.get_mut(validator_id) {
                    stats.stake_wei = stats.stake_wei.saturating_sub(*amount);
                }
            }

            Transaction::RotatePublisherKey {
                canonical_prefix,
                old_pubkey,
                new_pubkey,
                ..
            } => {
                // Update canonical → pubkey reverse mappings.
                let keys_to_update: Vec<String> = self
                    .canonical_to_pubkey
                    .iter()
                    .filter(|(canonical, pubkey)| {
                        canonical.starts_with(canonical_prefix) && *pubkey == old_pubkey
                    })
                    .map(|(canonical, _)| canonical.clone())
                    .collect();
                for canonical in keys_to_update {
                    self.canonical_to_pubkey
                        .insert(canonical, new_pubkey.clone());
                }
                // Migrate aggregated stats to the new pubkey.
                if let Some(mut stats) = self.stats.remove(old_pubkey) {
                    stats.pubkey = new_pubkey.clone();
                    self.stats.insert(new_pubkey.clone(), stats);
                }
            }

            _ => {} // ValidatorJoin / ValidatorLeave don't affect publisher index.
        }
    }

    pub fn get(&self, pubkey: &str) -> Option<&PublisherStats> {
        self.stats.get(pubkey)
    }

    pub fn publisher_count(&self) -> usize {
        self.stats.len()
    }

    pub fn all_stats(&self) -> Vec<&PublisherStats> {
        self.stats.values().collect()
    }
}
