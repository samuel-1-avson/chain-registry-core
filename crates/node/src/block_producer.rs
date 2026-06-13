// crates/node/src/block_producer.rs
// Produces new blocks on a fixed interval by draining the finalized-tx channel.

use crate::{finalized_tx, NodeState};
use chrono::Utc;
use common::{merkle_root, Block, BlockHeader, Transaction};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};

pub async fn run(
    state: Arc<RwLock<NodeState>>,
    rx: finalized_tx::FinalizedTxReceiver,
    p2p_handle: crate::p2p::P2PHandle,
) {
    let block_interval = {
        let s = state.read().await;
        s.config.block_interval_secs
    };

    let mut ticker = interval(Duration::from_secs(block_interval));
    // How long the chain tip may stall before the next-ranked proposer is
    // allowed to step in. Each elapsed window promotes one more fallback rank,
    // so a single offline proposer no longer halts block production.
    let fallback_window_secs = std::env::var("CREG_PROPOSER_FALLBACK_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(block_interval.saturating_mul(2).max(1));
    tracing::info!(
        "Block producer started (interval: {}s, proposer fallback window: {}s)",
        block_interval,
        fallback_window_secs
    );

    let mut last_seen_tip: u64 = {
        let s = state.read().await;
        s.chain.tip_height().unwrap_or(0)
    };
    let mut tip_unchanged_since = std::time::Instant::now();

    loop {
        ticker.tick().await;

        // Track how long the tip has been stalled. Re-reading every tick means
        // blocks produced by peers reset the timer too, so fallback only
        // engages during a genuine production stall.
        let current_tip = {
            let s = state.read().await;
            s.chain.tip_height().unwrap_or(last_seen_tip)
        };
        if current_tip != last_seen_tip {
            last_seen_tip = current_tip;
            tip_unchanged_since = std::time::Instant::now();
        }
        let stall_secs = tip_unchanged_since.elapsed().as_secs();
        let allowed_fallback_rank = (stall_secs / fallback_window_secs) as usize;

        // Drain everything the validator pipeline has finalised since last tick.
        let txs: Vec<Transaction> = finalized_tx::drain(&rx).await;
        if txs.is_empty() {
            tracing::debug!("Block producer: no new transactions");
            continue;
        }

        match produce_block(
            Arc::clone(&state),
            txs,
            p2p_handle.clone(),
            allowed_fallback_rank,
        )
        .await
        {
            Ok(block) => {
                let bh = block.hash();
                tracing::info!(
                    "[PBFT] Proposer created block {} at height {} ({} tx) — starting round",
                    &bh[..bh.len().min(12)],
                    block.header.height,
                    block.transactions.len()
                );

                // Broadcast PbftPrePrepare to start the consensus round
                let msg = common::GossipMessage::PbftPrePrepare { block };
                match serde_json::to_vec(&msg) {
                    Ok(data) => {
                        let _ = p2p_handle
                            .sender
                            .send(crate::p2p::P2PCommand::Broadcast {
                                topic: "creg/v1/blocks".into(),
                                data,
                            })
                            .await;
                    }
                    Err(e) => {
                        tracing::error!("Failed to serialize PbftPrePrepare gossip: {}", e);
                    }
                }
            }
            Err(e) => tracing::error!("Block production failed: {}", e),
        }
    }
}

async fn produce_block(
    state: Arc<RwLock<NodeState>>,
    txs: Vec<Transaction>,
    p2p: crate::p2p::P2PHandle,
    allowed_fallback_rank: usize,
) -> anyhow::Result<Block> {
    // ── Read-only snapshot of state needed for VRF selection ────────────────
    let (tip_height, prev_hash, node_id, privkey, our_pubkey, validator_set_hash) = {
        let s = state.read().await;
        let tip_height = s.chain.tip_height()?;
        let prev_hash = s.chain.tip_hash()?;
        let node_id = s.config.node_id.clone();
        let privkey = s.config.validator_privkey.clone();
        let our_pubkey = s
            .validator_set
            .validators
            .iter()
            .find(|v| v.id == node_id)
            .map(|v| v.pubkey.clone());

        // Compute a deterministic hash of the validator set so light clients
        // and bridge code can detect membership changes between blocks.
        // Input: sorted validator IDs concatenated with NUL separators.
        let mut sorted_ids: Vec<&str> = s
            .validator_set
            .validators
            .iter()
            .map(|v| v.id.as_str())
            .collect();
        sorted_ids.sort_unstable();
        let mut hasher = Sha256::new();
        for id in &sorted_ids {
            hasher.update(id.as_bytes());
            hasher.update(b"\0");
        }
        let validator_set_hash = hex::encode(hasher.finalize());

        (
            tip_height,
            prev_hash,
            node_id,
            privkey,
            our_pubkey,
            validator_set_hash,
        )
    };

    let epoch_seed = prev_hash.clone();

    // Build active set, injecting any cached VRF proofs from peers.
    let mut active: Vec<consensus::vrf::VrfValidator> = {
        let s = state.read().await;
        s.validator_set
            .validators
            .iter()
            .filter(|v| v.status == "online" || v.status == "self")
            .map(|v| {
                let (vrf_output, vrf_proof) = s
                    .vrf_proofs
                    .get(&v.id)
                    .cloned()
                    .map(|(o, p)| (Some(o), Some(p)))
                    .unwrap_or((None, None));
                consensus::vrf::VrfValidator {
                    id: v.id.clone(),
                    pubkey: v.pubkey.clone(),
                    vrf_output,
                    vrf_proof,
                }
            })
            .collect()
    };

    let (vrf_output, vrf_proof) = if !active.is_empty() {
        if let Some(ref privkey) = privkey {
            let (out, prf) = consensus::vrf::prove(epoch_seed.as_bytes(), privkey)?;
            // Inject our own proof into the active set.
            for v in &mut active {
                if v.id == node_id {
                    v.vrf_output = Some(out.clone());
                    v.vrf_proof = Some(prf.clone());
                }
            }

            // Broadcast our VRF proof so peers can include it in their selection.
            let gossip_msg = common::GossipMessage::VrfProof {
                validator_id: node_id.clone(),
                pubkey: our_pubkey.unwrap_or_default(),
                epoch_seed: epoch_seed.clone(),
                output: out.clone(),
                proof: prf.clone(),
            };
            match serde_json::to_vec(&gossip_msg) {
                Ok(data) => {
                    let _ = p2p
                        .sender
                        .send(crate::p2p::P2PCommand::Broadcast {
                            topic: "creg/v1/vrf-proofs".into(),
                            data,
                        })
                        .await;
                }
                Err(e) => {
                    tracing::warn!("Failed to serialize VRF proof gossip: {}", e);
                }
            }

            // Determine our position in the deterministic proposer ordering.
            // Rank 0 is the primary proposer and always proceeds. A higher
            // rank may only propose once the tip has stalled long enough to
            // promote that rank (proposer-failure fallback for liveness).
            let ranking = consensus::vrf::rank_proposers(&active, &epoch_seed);
            if ranking.is_empty() {
                anyhow::bail!("No active validators to select proposer");
            }
            let effective_rank = allowed_fallback_rank.min(ranking.len().saturating_sub(1));
            match ranking.iter().position(|id| id == &node_id) {
                Some(0) => {}
                Some(rank) if rank == effective_rank => {
                    tracing::warn!(
                        "Proposer fallback engaged: tip stalled, node {} stepping in as rank-{} proposer (primary appears offline)",
                        node_id,
                        rank
                    );
                }
                Some(rank) => {
                    anyhow::bail!(
                        "Node {} is proposer rank {} for this epoch; not its turn yet (allowed fallback rank {})",
                        node_id,
                        rank,
                        effective_rank
                    );
                }
                None => {
                    anyhow::bail!(
                        "Node {} is not in the active proposer set for this epoch",
                        node_id
                    );
                }
            }
            (Some(out), Some(prf))
        } else {
            (None, None)
        }
    } else {
        // Dev/test fallback when no validator set is configured.
        (None, None)
    };

    // ── Write the new block ────────────────────────────────────────────────
    let mut s = state.write().await;
    let header = BlockHeader {
        height: tip_height + 1,
        prev_hash,
        merkle_root: merkle_root(&txs),
        proposer_id: node_id.clone(),
        timestamp: Utc::now(),
        validator_set_hash,
        vrf_output,
        vrf_proof,
    };

    let block = Block {
        header,
        transactions: txs,
        pbft_signatures: vec![],
    };

    // Instead of inserting immediately, start the PBFT round
    let vs = s.validator_set.clone();
    s.pbft_engine.start_round(block.clone(), vs.into())?;

    let bh = block.hash();
    let mut prep_cmd = None;
    let mut commit_cmd = None;

    if let Some(ref privkey_hex) = privkey {
        if let Ok(pk_bytes) = hex::decode(privkey_hex) {
            if let Ok(sk) = ed25519_dalek::SigningKey::try_from(pk_bytes.as_slice()) {
                use ed25519_dalek::Signer;

                // 1. Proposer casts its own PREPARE vote
                let prep_msg_str = consensus::pbft::pbft_signature_message("prepare", &bh);
                let prep_sig = hex::encode(sk.sign(prep_msg_str.as_bytes()).to_bytes());
                let pubkey = hex::encode(sk.verifying_key().as_bytes());

                let prep_sig_obj = common::BlockSignature {
                    validator_id: node_id.clone(),
                    pubkey: pubkey.clone(),
                    signature: prep_sig.clone(),
                };

                let prepare_quorum_reached = s
                    .pbft_engine
                    .prepare(&bh, &node_id, prep_sig_obj)
                    .unwrap_or(false);

                let prep_msg = common::GossipMessage::PbftPrepare {
                    block_hash: bh.clone(),
                    validator_id: node_id.clone(),
                    signature: prep_sig,
                };
                if let Ok(data) = serde_json::to_vec(&prep_msg) {
                    prep_cmd = Some(crate::p2p::P2PCommand::Broadcast {
                        topic: "creg/v1/blocks".into(),
                        data,
                    });
                }

                // 2. Proposer casts its own COMMIT vote if prepare quorum reached
                if prepare_quorum_reached {
                    let commit_msg_str = consensus::pbft::pbft_signature_message("commit", &bh);
                    let commit_sig = hex::encode(sk.sign(commit_msg_str.as_bytes()).to_bytes());

                    let commit_sig_obj = common::BlockSignature {
                        validator_id: node_id.clone(),
                        pubkey,
                        signature: commit_sig.clone(),
                    };

                    let commit_quorum_reached = s
                        .pbft_engine
                        .commit(&bh, &node_id, commit_sig_obj)
                        .unwrap_or(false);

                    let commit_msg = common::GossipMessage::PbftCommit {
                        block_hash: bh.clone(),
                        validator_id: node_id.clone(),
                        signature: commit_sig,
                    };
                    if let Ok(data) = serde_json::to_vec(&commit_msg) {
                        commit_cmd = Some(crate::p2p::P2PCommand::Broadcast {
                            topic: "creg/v1/blocks".into(),
                            data,
                        });
                    }

                    if commit_quorum_reached {
                        tracing::info!(
                            "[PBFT Proposer] Block {} finalised locally by proposer quorum",
                            &bh[..12]
                        );
                        if let Some(final_block) = s.pbft_engine.get_finalised_block(&bh) {
                            match s.chain.insert_block_with_outcome(&final_block) {
                                Ok(outcome) => {
                                    if let Some(replaced) = outcome.replaced_hash {
                                        s.record_reorg(1, vec![replaced], outcome.hash.clone());
                                    }
                                }
                                Err(e) => {
                                    tracing::error!(
                                        "[PBFT Proposer] Failed to insert finalised block: {}",
                                        e
                                    );
                                }
                            }
                            s.publisher_index.apply_block(&final_block);
                        }
                    }
                }
            }
        }
    }

    // Proofs are epoch-specific (seed = prev_hash); clear cache for next round.
    s.vrf_proofs.clear();

    drop(s);

    if let Some(cmd) = prep_cmd {
        let _ = p2p.sender.send(cmd).await;
    }
    if let Some(cmd) = commit_cmd {
        let _ = p2p.sender.send(cmd).await;
    }

    Ok(block)
}
