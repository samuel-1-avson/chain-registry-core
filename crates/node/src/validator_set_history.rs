// crates/node/src/validator_set_history.rs
//
// Height-indexed history of the active validator set (ISSUE-050).
//
// Block signatures must be verified against the validator set that was active
// AT THE BLOCK'S HEIGHT, not the current set. Otherwise, after a membership
// rotation, a node re-verifying or reorg-recovering older blocks counts only
// the signers still in today's set and can wrongly reject a block that had a
// valid quorum when it was produced.
//
// This module records a snapshot whenever the set changes (effective from the
// next block height) and lets the sync/verify path look up the set active at
// any height. It is persisted to disk so the history survives restarts.
//
// SAFETY / SCOPE: lookups are ADDITIVE — callers fall back to the current set
// when no snapshot covers a height, so behaviour is never stricter than before.
// A node syncing historical heights it never witnessed (e.g. from genesis
// across a past rotation) has no snapshot for them and falls back to current,
// exactly as before. Full reconstruction of pre-join history from L1 staking
// events is a larger follow-up.

use std::path::{Path, PathBuf};

use common::ValidatorSet;
use serde::{Deserialize, Serialize};

const HISTORY_FILE: &str = "validator-set-history.json";

/// Maximum snapshots retained. Sets are small; this bounds unbounded growth
/// from frequent reconciles. Oldest snapshots are dropped first (older history
/// simply falls back to the current set, which is safe).
const MAX_SNAPSHOTS: usize = 512;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorSetSnapshot {
    /// First block height for which this set is authoritative.
    pub effective_from_height: u64,
    pub validators: ValidatorSet,
}

fn history_path(data_dir: &Path) -> PathBuf {
    data_dir.join(HISTORY_FILE)
}

/// Load all snapshots (ascending `effective_from_height`). Empty if missing.
pub fn load(data_dir: &Path) -> Vec<ValidatorSetSnapshot> {
    let mut snaps: Vec<ValidatorSetSnapshot> = match std::fs::read(history_path(data_dir)) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    snaps.sort_by_key(|s| s.effective_from_height);
    snaps
}

/// Sorted, lowercased pubkey list — the membership identity used to decide
/// whether the set actually changed (ignores ordering / status churn).
fn membership_key(set: &ValidatorSet) -> Vec<String> {
    let mut keys: Vec<String> = set
        .validators
        .iter()
        .map(|v| v.pubkey.to_ascii_lowercase())
        .collect();
    keys.sort();
    keys
}

/// Select the snapshot active at `height`: the one with the greatest
/// `effective_from_height <= height`. Pure; unit-tested.
pub fn select_at(snapshots: &[ValidatorSetSnapshot], height: u64) -> Option<&ValidatorSetSnapshot> {
    snapshots
        .iter()
        .filter(|s| s.effective_from_height <= height)
        .max_by_key(|s| s.effective_from_height)
}

/// Return the validator set active at `height` from the on-disk history, or
/// `None` to signal the caller should use its current set (no regression).
pub fn set_at(data_dir: &Path, height: u64) -> Option<ValidatorSet> {
    let snapshots = load(data_dir);
    let snap = select_at(&snapshots, height)?;
    if snap.validators.validators.is_empty() {
        None
    } else {
        Some(snap.validators.clone())
    }
}

/// Record `set` as effective from `effective_from_height`, but only if its
/// membership differs from the most recent snapshot (dedup). Atomic write.
pub fn record(
    data_dir: &Path,
    effective_from_height: u64,
    set: &ValidatorSet,
) -> anyhow::Result<()> {
    if set.validators.is_empty() {
        return Ok(());
    }
    let mut snapshots = load(data_dir);

    if let Some(last) = snapshots.last() {
        if membership_key(&last.validators) == membership_key(set) {
            return Ok(()); // unchanged membership — nothing to record
        }
    }

    // If a snapshot already exists for this exact height, replace it (a later
    // reconcile at the same tip supersedes the earlier one).
    snapshots.retain(|s| s.effective_from_height != effective_from_height);
    snapshots.push(ValidatorSetSnapshot {
        effective_from_height,
        validators: set.clone(),
    });
    snapshots.sort_by_key(|s| s.effective_from_height);
    if snapshots.len() > MAX_SNAPSHOTS {
        let overflow = snapshots.len() - MAX_SNAPSHOTS;
        snapshots.drain(0..overflow);
    }

    let bytes = serde_json::to_vec_pretty(&snapshots)?;
    std::fs::create_dir_all(data_dir).ok();
    let path = history_path(data_dir);
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &bytes)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::Validator;

    fn validator(id: &str, pubkey: &str) -> Validator {
        Validator {
            id: id.into(),
            alias: id.into(),
            pubkey: pubkey.into(),
            eth_address: format!("0x{}", id),
            stake: 100,
            reputation: 100,
            status: "online".into(),
        }
    }

    fn set(pubkeys: &[&str]) -> ValidatorSet {
        ValidatorSet::new(
            pubkeys
                .iter()
                .enumerate()
                .map(|(i, pk)| validator(&format!("n{i}"), pk))
                .collect(),
        )
    }

    #[test]
    fn select_at_picks_latest_not_after_height() {
        let snaps = vec![
            ValidatorSetSnapshot {
                effective_from_height: 0,
                validators: set(&["aa"]),
            },
            ValidatorSetSnapshot {
                effective_from_height: 10,
                validators: set(&["aa", "bb"]),
            },
            ValidatorSetSnapshot {
                effective_from_height: 20,
                validators: set(&["bb", "cc"]),
            },
        ];
        assert_eq!(select_at(&snaps, 5).unwrap().effective_from_height, 0);
        assert_eq!(select_at(&snaps, 10).unwrap().effective_from_height, 10);
        assert_eq!(select_at(&snaps, 19).unwrap().effective_from_height, 10);
        assert_eq!(select_at(&snaps, 100).unwrap().effective_from_height, 20);
    }

    #[test]
    fn record_dedupes_unchanged_membership() {
        let dir = tempfile::tempdir().expect("tempdir");
        record(dir.path(), 0, &set(&["aa"])).expect("record 0");
        // Same membership at a later height → no new snapshot.
        record(dir.path(), 5, &set(&["aa"])).expect("record 5 same");
        assert_eq!(load(dir.path()).len(), 1);

        // Changed membership → new snapshot.
        record(dir.path(), 6, &set(&["aa", "bb"])).expect("record 6 changed");
        let snaps = load(dir.path());
        assert_eq!(snaps.len(), 2);
        assert_eq!(snaps[1].effective_from_height, 6);
    }

    #[test]
    fn set_at_returns_none_when_empty_and_some_otherwise() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(set_at(dir.path(), 1).is_none());
        record(dir.path(), 0, &set(&["aa", "bb"])).expect("record");
        let got = set_at(dir.path(), 50).expect("set present");
        assert_eq!(got.validators.len(), 2);
    }
}
