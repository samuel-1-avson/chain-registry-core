// crates/node/src/bridge_anchors.rs
// Persistent journal of L2 → L1 anchor commits.
//
// Every successful `submitRollupBatch` settlement is recorded here with its
// L1 transaction hash so the anchor history survives restarts and the
// explorer Bridge tab can show real, verifiable commits instead of a
// synthesized placeholder. The journal is a JSON file in CREG_DATA_DIR —
// small (capped), append-mostly, and human-inspectable.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Maximum number of anchor records retained on disk (newest first).
const MAX_ANCHORS: usize = 500;

const ANCHORS_FILE: &str = "bridge_anchors.json";

/// One L2 → L1 anchor commit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnchorRecord {
    /// First L2 height included in this batch.
    pub l2_height_start: u64,
    /// Last L2 height included in this batch (shown as `l2_height` in the UI).
    pub l2_height: u64,
    /// L1 transaction hash of the governance transaction that executed
    /// `submitRollupBatch` (the vote that met the threshold).
    pub l1_tx_hash: Option<String>,
    /// L1 block number the anchor transaction was included in.
    pub l1_block: Option<u64>,
    /// State root before this batch (`latestStateRoot` at submit time).
    pub prev_root: String,
    /// State root after this batch — `SHA-256(prev_root || data_root)`.
    pub state_root: String,
    /// Merkle root over the batch's verified Publish transactions.
    pub data_root: String,
    /// Number of verified Publish transactions in the batch.
    pub tx_count: u64,
    /// Governance proposal id used to settle the batch.
    pub proposal_id: String,
    /// RFC 3339 timestamp of the commit.
    pub committed_at: String,
    /// Trust model of this anchor. `"checkpoint-attestation"` — the Groth16
    /// batch circuit only proves the batch is non-empty; roots are computed
    /// off-chain and trusted from the bridge operator, so this is a
    /// checkpoint, not a validity proof.
    pub proof_mode: String,
}

fn anchors_path(data_dir: &Path) -> PathBuf {
    data_dir.join(ANCHORS_FILE)
}

/// Load the anchor journal (newest first). Missing file → empty list.
pub fn load(data_dir: &Path) -> Vec<AnchorRecord> {
    let path = anchors_path(data_dir);
    match std::fs::read(&path) {
        Ok(bytes) => match serde_json::from_slice::<Vec<AnchorRecord>>(&bytes) {
            Ok(anchors) => anchors,
            Err(e) => {
                tracing::warn!(
                    "Could not parse {} ({}) — starting with empty anchor journal",
                    path.display(),
                    e
                );
                Vec::new()
            }
        },
        Err(_) => Vec::new(),
    }
}

/// Append a new anchor record (kept newest-first) and persist atomically
/// (write to a temp file, then rename).
pub fn append(data_dir: &Path, record: AnchorRecord) -> Result<usize> {
    let mut anchors = load(data_dir);
    anchors.insert(0, record);
    anchors.truncate(MAX_ANCHORS);

    let path = anchors_path(data_dir);
    let tmp_path = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(&anchors).context("serialize anchor journal")?;
    std::fs::create_dir_all(data_dir).ok();
    std::fs::write(&tmp_path, &bytes).with_context(|| format!("write {}", tmp_path.display()))?;
    std::fs::rename(&tmp_path, &path)
        .with_context(|| format!("rename {} → {}", tmp_path.display(), path.display()))?;
    Ok(anchors.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(height: u64) -> AnchorRecord {
        AnchorRecord {
            l2_height_start: height,
            l2_height: height,
            l1_tx_hash: Some(format!("0x{:064x}", height)),
            l1_block: Some(1000 + height),
            prev_root: "0x00".into(),
            state_root: format!("0x{:064x}", height + 1),
            data_root: "0xdd".into(),
            tx_count: 1,
            proposal_id: height.to_string(),
            committed_at: chrono::Utc::now().to_rfc3339(),
            proof_mode: "checkpoint-attestation".into(),
        }
    }

    #[test]
    fn append_and_load_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(load(dir.path()).is_empty());

        append(dir.path(), record(1)).expect("append 1");
        append(dir.path(), record(2)).expect("append 2");

        let anchors = load(dir.path());
        assert_eq!(anchors.len(), 2);
        // Newest first.
        assert_eq!(anchors[0].l2_height, 2);
        assert_eq!(anchors[1].l2_height, 1);
        assert_eq!(anchors[0].proof_mode, "checkpoint-attestation");
    }

    #[test]
    fn journal_is_capped() {
        let dir = tempfile::tempdir().expect("tempdir");
        for h in 0..(MAX_ANCHORS as u64 + 10) {
            append(dir.path(), record(h)).expect("append");
        }
        let anchors = load(dir.path());
        assert_eq!(anchors.len(), MAX_ANCHORS);
        // Newest retained.
        assert_eq!(anchors[0].l2_height, MAX_ANCHORS as u64 + 9);
    }
}
