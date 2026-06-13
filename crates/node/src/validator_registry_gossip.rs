// crates/node/src/validator_registry_gossip.rs
//
// Fleet-wide propagation + persistence of validator identity registrations.
//
// Problem this solves: registrations used to be applied only on the single
// node that received the `/v1/validators/register` POST. Operators had to
// re-POST the same proof to every fleet node and the observer pool, and a
// missed node showed up as `active_validators: 1` even though L1 said the
// validator was Active (the documented drift incident).
//
// Fix: a successful registration is (a) persisted to disk so it survives
// restarts, and (b) gossiped to peers carrying its original ownership proofs.
// Every receiver re-verifies the proofs before applying, so propagation is
// trustless. A periodic re-broadcast lets late-joining / restarted nodes
// converge without operator action.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::p2p::P2PCommand;

/// Gossip topic for validator identity registrations.
pub const REGISTRATION_TOPIC: &str = "creg/v1/validators";

const REGISTRATIONS_FILE: &str = "validator-registrations.json";

/// A validator identity registration plus the ownership proofs needed for any
/// node to re-verify it. Serializable for both the on-disk journal and the
/// gossip wire format.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistrationProof {
    pub evm_address: String,
    pub node_id: String,
    pub ed25519_pubkey: String,
    pub alias: Option<String>,
    pub nonce: String,
    pub evm_signature: String,
    pub ed25519_signature: String,
}

impl RegistrationProof {
    pub fn into_gossip(self) -> common::GossipMessage {
        common::GossipMessage::ValidatorRegistration {
            evm_address: self.evm_address,
            node_id: self.node_id,
            ed25519_pubkey: self.ed25519_pubkey,
            alias: self.alias,
            nonce: self.nonce,
            evm_signature: self.evm_signature,
            ed25519_signature: self.ed25519_signature,
        }
    }
}

// ── Gossip sender (set once at startup) ──────────────────────────────────────

static GOSSIP_SENDER: OnceLock<mpsc::Sender<P2PCommand>> = OnceLock::new();

/// Install the p2p command sender so API/worker code can broadcast
/// registrations. Called once during node startup. Idempotent.
pub fn set_gossip_sender(sender: mpsc::Sender<P2PCommand>) {
    let _ = GOSSIP_SENDER.set(sender);
}

/// Broadcast a registration proof to peers. Best-effort: a missing sender
/// (e.g. p2p disabled in tests) or full channel is logged, not fatal.
pub async fn broadcast(proof: RegistrationProof) {
    let Some(sender) = GOSSIP_SENDER.get() else {
        return;
    };
    let msg = proof.into_gossip();
    let data = match serde_json::to_vec(&msg) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!("Failed to serialize validator registration gossip: {}", e);
            return;
        }
    };
    if let Err(e) = sender
        .send(P2PCommand::Broadcast {
            topic: REGISTRATION_TOPIC.to_string(),
            data,
        })
        .await
    {
        tracing::debug!("Failed to enqueue validator registration broadcast: {}", e);
    }
}

// ── On-disk journal ──────────────────────────────────────────────────────────

fn registrations_path(data_dir: &Path) -> PathBuf {
    data_dir.join(REGISTRATIONS_FILE)
}

/// Load all persisted registration proofs (empty if none/unreadable).
pub fn load_all(data_dir: &Path) -> Vec<RegistrationProof> {
    match std::fs::read(registrations_path(data_dir)) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Persist a registration proof, replacing any prior entry for the same EVM
/// address (case-insensitive). Atomic write (temp file + rename).
pub fn persist(data_dir: &Path, proof: &RegistrationProof) -> anyhow::Result<()> {
    let mut all = load_all(data_dir);
    let key = proof.evm_address.trim().to_ascii_lowercase();
    all.retain(|p| p.evm_address.trim().to_ascii_lowercase() != key);
    all.push(proof.clone());

    let bytes = serde_json::to_vec_pretty(&all)?;
    std::fs::create_dir_all(data_dir).ok();
    let path = registrations_path(data_dir);
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &bytes)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proof(addr: &str, node: &str) -> RegistrationProof {
        RegistrationProof {
            evm_address: addr.into(),
            node_id: node.into(),
            ed25519_pubkey: "ab".repeat(32),
            alias: Some(node.into()),
            nonce: "1".into(),
            evm_signature: "0xsig".into(),
            ed25519_signature: "0xsig".into(),
        }
    }

    #[test]
    fn persist_dedupes_by_evm_address_case_insensitive() {
        let dir = tempfile::tempdir().expect("tempdir");
        persist(dir.path(), &proof("0xAbC", "node-1")).expect("persist 1");
        // Same address, different case + updated node id → replaces.
        persist(dir.path(), &proof("0xabc", "node-1-renamed")).expect("persist 2");
        persist(dir.path(), &proof("0xDEF", "node-2")).expect("persist 3");

        let all = load_all(dir.path());
        assert_eq!(
            all.len(),
            2,
            "duplicate EVM address must not create two rows"
        );
        let renamed = all
            .iter()
            .find(|p| p.evm_address.eq_ignore_ascii_case("0xabc"))
            .expect("addr present");
        assert_eq!(renamed.node_id, "node-1-renamed");
    }

    #[test]
    fn load_all_empty_when_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(load_all(dir.path()).is_empty());
    }
}
