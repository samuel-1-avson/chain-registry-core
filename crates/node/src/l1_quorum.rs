// crates/node/src/l1_quorum.rs
//
// Quorum/aggregation helpers for reading L1 (Sepolia) from MULTIPLE RPC
// endpoints instead of trusting a single provider. A single compromised,
// censoring, or merely stale RPC must not be able to skew the validator-set
// view or force a destructive reorg rebuild.
//
// This module holds the *pure* aggregation logic so it can be unit-tested
// without a network. The async orchestration (fan-out across endpoints) lives
// in `validator_set_sync.rs`, which calls these helpers.
//
// Trust model:
//   * Block height — `aggregate_height` is deliberately conservative. With 3+
//     endpoints it takes the median (one outlier in either direction cannot
//     move it). With 2 it takes the minimum (a stale/lying-high RPC cannot
//     push the head forward; trailing slightly is safe because a finality lag
//     is applied on top). With 1 it degrades to that single value.
//   * Block hash — `majority_hash` requires a STRICT majority. Reorg detection
//     keys off this: if endpoints disagree with no majority, the caller must
//     treat the result as inconclusive and NOT rebuild, so one bad RPC cannot
//     trigger a spurious validator-set rebuild.

use std::collections::HashMap;

/// Combine per-endpoint head block numbers into a single conservative height.
///
/// * 0 values  → `None` (all endpoints failed; caller should mark degraded).
/// * 1 value   → that value (single-endpoint behaviour).
/// * 2 values  → the minimum (do not let one endpoint race the head forward).
/// * 3+ values → the median (resists a single high or low outlier).
pub fn aggregate_height(values: &[u64]) -> Option<u64> {
    match values.len() {
        0 => None,
        1 => Some(values[0]),
        2 => Some(values[0].min(values[1])),
        _ => {
            let mut sorted = values.to_vec();
            sorted.sort_unstable();
            Some(sorted[sorted.len() / 2])
        }
    }
}

/// Return the block hash agreed by a STRICT majority of responders
/// (case-insensitive), or `None` when there is no majority (tie, even split,
/// or empty). Comparison is normalised to lowercase; the returned value is the
/// normalised form.
pub fn majority_hash(hashes: &[String]) -> Option<String> {
    if hashes.is_empty() {
        return None;
    }
    let mut counts: HashMap<String, usize> = HashMap::new();
    for h in hashes {
        *counts.entry(h.trim().to_ascii_lowercase()).or_default() += 1;
    }
    let (best, count) = counts.into_iter().max_by_key(|(_, c)| *c)?;
    if count * 2 > hashes.len() {
        Some(best)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_height_handles_small_sets() {
        assert_eq!(aggregate_height(&[]), None);
        assert_eq!(aggregate_height(&[100]), Some(100));
        // Two endpoints: take the minimum so a high outlier cannot push us ahead.
        assert_eq!(aggregate_height(&[100, 105]), Some(100));
    }

    #[test]
    fn aggregate_height_takes_median_with_three_or_more() {
        // A single high liar (999) is ignored by the median.
        assert_eq!(aggregate_height(&[100, 101, 999]), Some(101));
        // A single low/stale endpoint (1) is ignored too.
        assert_eq!(aggregate_height(&[1, 100, 101]), Some(100));
        assert_eq!(aggregate_height(&[100, 100, 100, 100, 999]), Some(100));
    }

    #[test]
    fn majority_hash_requires_strict_majority() {
        let two_one = vec!["0xAA".to_string(), "0xaa".to_string(), "0xbb".to_string()];
        assert_eq!(majority_hash(&two_one), Some("0xaa".to_string()));

        // Even split → no majority → inconclusive.
        let split = vec!["0xaa".to_string(), "0xbb".to_string()];
        assert_eq!(majority_hash(&split), None);

        // Single responder is trivially a majority of itself.
        assert_eq!(
            majority_hash(&["0xaa".to_string()]),
            Some("0xaa".to_string())
        );

        assert_eq!(majority_hash(&[]), None);
    }

    #[test]
    fn majority_hash_no_winner_on_three_way_tie() {
        let tie = vec!["0xaa".to_string(), "0xbb".to_string(), "0xcc".to_string()];
        assert_eq!(majority_hash(&tie), None);
    }
}
