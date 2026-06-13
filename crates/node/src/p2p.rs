// crates/node/src/p2p.rs
// Real decentralized P2P layer using libp2p with rate limiting.

use anyhow::Result;
use futures::StreamExt;
use libp2p::{
    gossipsub, identify, kad, noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Swarm,
};
use std::time::Duration;
use tokio::sync::mpsc;

use crate::p2p_rate_limit::{P2PRateLimitConfig, P2PRateLimiter};

fn gossipsub_heartbeat_interval() -> Duration {
    if cfg!(test) {
        Duration::from_millis(250)
    } else {
        Duration::from_secs(10)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VoteValidationError {
    Malformed,
    UnknownValidator,
    MissingValidatorPubkey,
    ValidatorPubkeyMismatch,
    InvalidValidatorPubkeyHex,
    InvalidValidatorPubkey,
    MissingConsensusEvidence,
    InvalidSignatureHex,
    InvalidSignatureFormat,
    SignatureVerificationFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PbftValidationError {
    UnknownValidator,
    MissingValidatorPubkey,
    SignatureVerificationFailed,
}

fn validate_pbft_phase_message(
    validator_set: &common::ValidatorSet,
    phase: &str,
    block_hash: &str,
    validator_id: &str,
    signature_hex: &str,
) -> Result<common::BlockSignature, PbftValidationError> {
    let validator = validator_set
        .validators
        .iter()
        .find(|validator| validator.id == validator_id)
        .ok_or(PbftValidationError::UnknownValidator)?;

    if validator.pubkey.is_empty() {
        return Err(PbftValidationError::MissingValidatorPubkey);
    }

    consensus::pbft::verify_pbft_phase_signature(
        phase,
        block_hash,
        &validator.pubkey,
        signature_hex,
    )
    .map_err(|_| PbftValidationError::SignatureVerificationFailed)?;

    Ok(common::BlockSignature {
        validator_id: validator_id.to_string(),
        pubkey: validator.pubkey.clone(),
        signature: signature_hex.to_string(),
    })
}

fn report_pbft_validation_failure(
    phase: &str,
    validator_id: &str,
    block_hash: &str,
    error: PbftValidationError,
) {
    tracing::warn!(
        phase = phase,
        validator_id = validator_id,
        block_hash = block_hash,
        ?error,
        "P2P: rejected invalid PBFT gossip signature"
    );
}

fn validate_vote_gossip_message(
    message: &[u8],
    validator_set: &common::ValidatorSet,
) -> Result<crate::gossip::VoteGossip, VoteValidationError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let vote = serde_json::from_slice::<crate::gossip::VoteGossip>(message)
        .map_err(|_| VoteValidationError::Malformed)?;

    let validator = validator_set
        .validators
        .iter()
        .find(|validator| validator.id == vote.validator_id)
        .ok_or(VoteValidationError::UnknownValidator)?;

    if validator.pubkey.is_empty() {
        return Err(VoteValidationError::MissingValidatorPubkey);
    }

    if vote.validator_pubkey != validator.pubkey {
        return Err(VoteValidationError::ValidatorPubkeyMismatch);
    }

    if !common::is_consensus_grade_vote(
        &vote.ml_model_version,
        &vote.analysis_bundles,
        &vote.evidence_digest,
    ) {
        return Err(VoteValidationError::MissingConsensusEvidence);
    }

    let pubkey_bytes = hex::decode(&vote.validator_pubkey)
        .map_err(|_| VoteValidationError::InvalidValidatorPubkeyHex)?;
    let verifying_key = VerifyingKey::try_from(pubkey_bytes.as_slice())
        .map_err(|_| VoteValidationError::InvalidValidatorPubkey)?;

    let signature_bytes =
        hex::decode(&vote.signature).map_err(|_| VoteValidationError::InvalidSignatureHex)?;
    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|_| VoteValidationError::InvalidSignatureFormat)?;

    let message = crate::gossip::canonical_vote_message(
        &vote.consensus_subject,
        &vote.content_hash,
        vote.approved,
        &vote.validator_pubkey,
        &common::scanner_profile_digest(&vote.ml_model_version, &vote.analysis_bundles),
        &vote.evidence_digest,
    );

    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|_| VoteValidationError::SignatureVerificationFailed)?;

    Ok(vote)
}

fn vote_gossip_to_signature(vote: &crate::gossip::VoteGossip) -> common::ValidatorSignature {
    common::ValidatorSignature {
        validator_id: vote.validator_id.clone(),
        validator_pubkey: vote.validator_pubkey.clone(),
        signature: vote.signature.clone(),
        vote: if vote.approved {
            common::ValidatorVote::Approve
        } else {
            common::ValidatorVote::Reject {
                reason: vote.reject_reason.clone().unwrap_or_default(),
            }
        },
        signed_at: chrono::Utc::now(),
        ml_model_version: vote.ml_model_version.clone(),
        analysis_bundles: vote.analysis_bundles.clone(),
        evidence_digest: vote.evidence_digest.clone(),
        deterministic_risk: vote.deterministic_risk.clone(),
    }
}

async fn record_validated_vote_gossip(
    state: &crate::SharedState,
    vote: &crate::gossip::VoteGossip,
) {
    let mut state = state.write().await;
    state.record_package_vote(
        vote.consensus_subject.clone(),
        vote_gossip_to_signature(vote),
    );
}

fn report_validation_result(
    swarm: &mut Swarm<Behaviour>,
    message_id: &gossipsub::MessageId,
    propagation_source: &PeerId,
    acceptance: gossipsub::MessageAcceptance,
) {
    if let Err(error) = swarm
        .behaviour_mut()
        .gossipsub
        .report_message_validation_result(message_id, propagation_source, acceptance)
    {
        tracing::warn!(
            message_id = %message_id,
            peer = %propagation_source,
            error = %error,
            "P2P: failed to report gossipsub message validation result"
        );
    }
}

/// Combined P2P behaviour.
#[derive(NetworkBehaviour)]
pub struct Behaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub identify: identify::Behaviour,
}

pub struct P2PNode {
    pub swarm: Swarm<Behaviour>,
    pub peer_id: PeerId,
    pub receiver: mpsc::Receiver<P2PCommand>,
    pub rate_limiter: P2PRateLimiter,
}

#[derive(Clone)]
pub struct P2PHandle {
    pub sender: mpsc::Sender<P2PCommand>,
}

pub enum P2PCommand {
    Broadcast { topic: String, data: Vec<u8> },
    Dial { addr: Multiaddr },
    IdentifyStorage { cid: String },
}

impl P2PNode {
    pub fn new(listen_addr: &str) -> Result<(Self, P2PHandle)> {
        let (sender, receiver) = mpsc::channel(100);
        let mut swarm = libp2p::SwarmBuilder::with_new_identity()
            // ... (rest of the SwarmBuilder remains the same)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_dns()?
            .with_behaviour(|key| {
                // ── Gossipsub ────────────────────────────────────────────────
                let message_id_fn = |message: &gossipsub::Message| {
                    let mut s = std::collections::hash_map::DefaultHasher::new();
                    std::hash::Hash::hash(&message.data, &mut s);
                    gossipsub::MessageId::from(std::hash::Hasher::finish(&s).to_string())
                };

                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(gossipsub_heartbeat_interval())
                    .validate_messages()
                    .validation_mode(gossipsub::ValidationMode::Strict)
                    .message_id_fn(message_id_fn)
                    .build()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )?;

                // ── Kademlia ─────────────────────────────────────────────────
                let peer_id = key.public().to_peer_id();
                let store = kad::store::MemoryStore::new(peer_id);
                let kademlia = kad::Behaviour::new(peer_id, store);

                // ── Identify ─────────────────────────────────────────────────
                let identify = identify::Behaviour::new(identify::Config::new(
                    "/creg/1.0.0".into(),
                    key.public(),
                ));

                Ok(Behaviour {
                    gossipsub,
                    kademlia,
                    identify,
                })
            })?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        let peer_id = *swarm.local_peer_id();
        swarm.listen_on(listen_addr.parse()?)?;

        let rate_limiter = P2PRateLimiter::new(P2PRateLimitConfig::default());

        Ok((
            Self {
                swarm,
                peer_id,
                receiver,
                rate_limiter,
            },
            P2PHandle { sender },
        ))
    }

    pub async fn run(
        mut self,
        state: crate::SharedState,
        event_bus: crate::events::EventBus,
    ) -> Result<()> {
        let mut status_ticker = tokio::time::interval(Duration::from_secs(5));
        let votes_topic = gossipsub::IdentTopic::new("creg/v1/votes");
        let blocks_topic = gossipsub::IdentTopic::new("creg/v1/blocks");
        let submissions_topic = gossipsub::IdentTopic::new("creg/v1/submissions");
        let vrf_proofs_topic = gossipsub::IdentTopic::new("creg/v1/vrf-proofs");
        let validators_topic =
            gossipsub::IdentTopic::new(crate::validator_registry_gossip::REGISTRATION_TOPIC);

        self.swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&votes_topic)?;
        self.swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&blocks_topic)?;
        self.swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&submissions_topic)?;
        self.swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&vrf_proofs_topic)?;
        self.swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&validators_topic)?;

        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => match event {
                    SwarmEvent::Behaviour(BehaviourEvent::Kademlia(kad::Event::OutboundQueryProgressed { result, .. })) => {
                        match result {
                            kad::QueryResult::Bootstrap(Ok(_)) => {
                                tracing::info!("Kademlia bootstrap successful");
                            }
                            _ => {}
                        }
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                        propagation_source: peer_id,
                        message_id: id,
                        message,
                    })) => {
                        tracing::debug!("Got Gossipsub message {} from {}", id, peer_id);

                        // Parse topic and check rate limits
                        let topic_str = message.topic.as_str();

                        // Retrieve active validators and their stakes
                        let active_validators: Vec<(String, u64)> = {
                            if let Ok(s) = state.try_read() {
                                s.validator_set.validators
                                    .iter()
                                    .map(|v| (v.id.clone(), v.stake))
                                    .collect()
                            } else {
                                vec![]
                            }
                        };

                        // Apply rate limiting based on message type
                        let allowed = if topic_str.contains("votes") {
                            self.rate_limiter.check_vote(peer_id, &active_validators)
                        } else if topic_str.contains("blocks") {
                            self.rate_limiter.check_block(peer_id, &active_validators)
                        } else {
                            self.rate_limiter.check_general(peer_id, &active_validators)
                        };

                        if !allowed {
                            report_validation_result(
                                &mut self.swarm,
                                &id,
                                &peer_id,
                                gossipsub::MessageAcceptance::Ignore,
                            );
                            tracing::warn!(
                                "P2P Rate limit: Dropping message {} from {} on topic {}",
                                id, peer_id, topic_str
                            );
                            continue;
                        }

                        // Reject oversized messages before deserializing to prevent
                        // OOM attacks: rate limiting is per-message-count, not per-byte,
                        // so without this a single 100 MB gossip message passes the
                        // rate limiter but exhausts the node's heap during JSON parsing.
                        const MAX_MESSAGE_BYTES: usize = 1024 * 1024; // 1 MiB
                        if message.data.len() > MAX_MESSAGE_BYTES {
                            report_validation_result(
                                &mut self.swarm,
                                &id,
                                &peer_id,
                                gossipsub::MessageAcceptance::Ignore,
                            );
                            tracing::warn!(
                                "P2P: Dropping oversized message {} from {} ({} bytes > {} limit)",
                                id, peer_id, message.data.len(), MAX_MESSAGE_BYTES
                            );
                            continue;
                        }

                        if !topic_str.contains("votes") {
                            report_validation_result(
                                &mut self.swarm,
                                &id,
                                &peer_id,
                                gossipsub::MessageAcceptance::Accept,
                            );
                        }

                        // Forward message to the node's internal event bus
                        if topic_str.contains("submissions") {
                            if let Ok(common::GossipMessage::PublishRequest(req)) = serde_json::from_slice(&message.data) {
                                let canonical = req.id.canonical();
                                let ipfs_url = {
                                    let s = state.read().await;
                                    s.config.ipfs_url.clone()
                                };
                                match crate::admission_scan::run_pre_mempool_yara_gate(&req, &ipfs_url).await {
                                    Ok(()) => {
                                        let mut s = state.write().await;
                                        if !s.pending_pool.contains(&canonical) {
                                            s.pending_pool.insert(req.clone());
                                            tracing::info!("Received {} via gossip", canonical);
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            "P2P: dropping submission {} before mempool: {}",
                                            canonical,
                                            e
                                        );
                                    }
                                }
                            }
                            continue;
                        }

                        if topic_str.contains("vrf-proofs") {
                            if let Ok(common::GossipMessage::VrfProof { validator_id, pubkey, epoch_seed, output, proof }) = serde_json::from_slice(&message.data) {
                                let mut s = state.write().await;
                                let current_seed = match s.chain.tip_hash() {
                                    Ok(h) => h,
                                    Err(_) => continue,
                                };
                                // Only accept proofs for the current epoch seed
                                if epoch_seed == current_seed {
                                    if let Err(e) = consensus::vrf::verify(epoch_seed.as_bytes(), &pubkey, &output, &proof) {
                                        tracing::debug!("Dropped invalid VRF proof from {}: {}", validator_id, e);
                                    } else {
                                        s.vrf_proofs.insert(validator_id.clone(), (output.clone(), proof.clone()));
                                        tracing::debug!("Accepted VRF proof from {} for epoch {}", validator_id, &epoch_seed[..epoch_seed.len().min(12)]);
                                    }
                                }
                            }
                            continue;
                        }

                        // ── Validator identity registrations ───────────────────
                        // A peer gossips a registration (with ownership proofs)
                        // so one POST propagates fleet-wide. We re-verify the
                        // proofs locally before applying — never trust the sender
                        // — and persist so a restart keeps the binding.
                        if topic_str.contains("validators") {
                            if let Ok(common::GossipMessage::ValidatorRegistration {
                                evm_address, node_id, ed25519_pubkey, alias, nonce, evm_signature, ed25519_signature,
                            }) = serde_json::from_slice(&message.data) {
                                let proof = crate::validator_registry_gossip::RegistrationProof {
                                    evm_address, node_id, ed25519_pubkey, alias, nonce, evm_signature, ed25519_signature,
                                };
                                match crate::api::apply_validator_registration(&state, &proof).await {
                                    Ok(status) => {
                                        let data_dir = { let s = state.read().await; s.config.data_dir.clone() };
                                        if let Err(e) = crate::validator_registry_gossip::persist(&data_dir, &proof) {
                                            tracing::warn!("Failed to persist gossiped validator registration: {}", e);
                                        }
                                        tracing::info!("Applied gossiped validator registration for {} ({})", proof.node_id, status.status);
                                    }
                                    Err((_, e)) => {
                                        tracing::debug!("Dropped gossiped validator registration for {}: {}", proof.node_id, e);
                                    }
                                }
                            }
                            continue;
                        }

                        // ── View-change certificates ───────────────────────────
                        // A validator broadcasts a ViewChange message when its local
                        // round times out.  We verify the Ed25519 signature and
                        // accumulate the certificate.  A view-change is only logged
                        // as ready once ⌊n/3⌋+1 certificates are seen for the same
                        // (block_hash, new_view) pair — preventing a single Byzantine
                        // node from forcing a view-change unilaterally.
                        if topic_str.contains("view-change") {
                            if let Ok(common::GossipMessage::ViewChange { block_hash, new_view, validator_id, signature }) = serde_json::from_slice(&message.data) {
                                // Verify Ed25519 signature: message = "{block_hash}:view_change:{new_view}"
                                let msg = format!("{}:view_change:{}", block_hash, new_view);
                                let sig_valid: bool = (|| -> Option<bool> {
                                    // Look up the validator's pubkey from the set
                                    let s = state.try_read().ok()?;
                                    let pubkey_hex = s.validator_set.validators
                                        .iter()
                                        .find(|v| v.id == validator_id)
                                        .map(|v| v.pubkey.clone())?;
                                    let pk_bytes = hex::decode(&pubkey_hex).ok()?;
                                    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
                                    let vk = VerifyingKey::try_from(pk_bytes.as_slice()).ok()?;
                                    let sig_bytes = hex::decode(&signature).ok()?;
                                    let sig = Signature::try_from(sig_bytes.as_slice()).ok()?;
                                    vk.verify(msg.as_bytes(), &sig).ok()?;
                                    Some(true)
                                })().unwrap_or(false);

                                if !sig_valid {
                                    tracing::warn!(
                                        validator_id = %validator_id,
                                        peer = %peer_id,
                                        "P2P: dropping ViewChange with invalid signature"
                                    );
                                    continue;
                                }

                                let mut s = state.write().await;
                                let n = s.validator_set.validators.len();
                                let threshold = n / 3 + 1;

                                let count = {
                                    let by_view = s.view_change_certs
                                        .entry(block_hash.clone())
                                        .or_default()
                                        .entry(new_view)
                                        .or_default();
                                    by_view.insert(validator_id.clone());
                                    by_view.len()
                                };

                                tracing::debug!(
                                    block_hash = %&block_hash[..block_hash.len().min(12)],
                                    new_view,
                                    validator_id = %validator_id,
                                    count,
                                    threshold,
                                    "ViewChange certificate received"
                                );

                                if count >= threshold {
                                    tracing::warn!(
                                        block_hash = %&block_hash[..block_hash.len().min(12)],
                                        new_view,
                                        count,
                                        threshold,
                                        "[PBFT] ViewChange quorum reached — view-change to view {} is authorised",
                                        new_view
                                    );
                                }
                            }
                            continue;
                        }

                        // Votes: gate propagation on application-level validation.
                        // gossipsub strict mode authenticates the relaying peer, but
                        // vote authenticity depends on the validator-set identity and
                        // Ed25519 signature inside the payload.
                        if topic_str.contains("votes") {
                            let validation = {
                                let s = state.read().await;
                                validate_vote_gossip_message(&message.data, &s.validator_set)
                            };

                            match validation {
                                Ok(vote) => {
                                    report_validation_result(
                                        &mut self.swarm,
                                        &id,
                                        &peer_id,
                                        gossipsub::MessageAcceptance::Accept,
                                    );

                                    record_validated_vote_gossip(&state, &vote).await;

                                    crate::events::emit(&event_bus, crate::events::RegistryEvent {
                                        kind: crate::events::EventKind::ValidatorVoted,
                                        ts: chrono::Utc::now().to_rfc3339(),
                                        payload: serde_json::json!({
                                            "validator_id": vote.validator_id,
                                            "consensus_subject": vote.consensus_subject,
                                            "approved": vote.approved,
                                        }),
                                    });
                                }
                                Err(error) => {
                                    report_validation_result(
                                        &mut self.swarm,
                                        &id,
                                        &peer_id,
                                        gossipsub::MessageAcceptance::Reject,
                                    );
                                    tracing::warn!(
                                        peer = %peer_id,
                                        reason = ?error,
                                        "P2P: rejecting gossip vote before mesh propagation"
                                    );
                                }
                            }
                            continue;
                        }

                        // ── PBFT Block Consensus ───────────────────────────────────────────────
                        if topic_str.contains("blocks") {
                            if let Ok(msg) = serde_json::from_slice::<common::GossipMessage>(&message.data) {
                                match msg {
                                    common::GossipMessage::PbftPrePrepare { block } => {
                                        let mut s = state.write().await;
                                        let vs = s.validator_set.clone();
                                        if let Err(e) = s.pbft_engine.start_round(block.clone(), vs.into()) {
                                            tracing::warn!("Failed to start PBFT round: {}", e);
                                        } else {
                                            // Sign the block and broadcast PREPARE
                                            if let Some(our_id) = s.config.node_id.clone().into() {
                                                if let Some(our_privkey_hex) = &s.config.validator_privkey {
                                                    let bh = block.hash();
                                                    if let Ok(pk_bytes) = hex::decode(our_privkey_hex) {
                                                        if let Ok(sk) = ed25519_dalek::SigningKey::try_from(pk_bytes.as_slice()) {
                                                            use ed25519_dalek::Signer;
                                                            let message = consensus::pbft::pbft_signature_message("prepare", &bh);
                                                            let signature = hex::encode(sk.sign(message.as_bytes()).to_bytes());
                                                            let pubkey = hex::encode(sk.verifying_key().as_bytes());

                                                            let sig_obj = common::BlockSignature { validator_id: our_id.clone(), pubkey: pubkey.clone(), signature: signature.clone() };
                                                            let _ = s.pbft_engine.prepare(&bh, &our_id, sig_obj);

                                                            let prep_msg = common::GossipMessage::PbftPrepare { block_hash: bh, validator_id: our_id, signature };
                                                            if let Ok(data) = serde_json::to_vec(&prep_msg) {
                                                                let topic = libp2p::gossipsub::IdentTopic::new("creg/v1/blocks");
                                                                let _ = self.swarm.behaviour_mut().gossipsub.publish(topic, data);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    common::GossipMessage::PbftPrepare { block_hash, validator_id, signature } => {
                                        let sig = {
                                            let s = state.read().await;
                                            match validate_pbft_phase_message(
                                                &s.validator_set,
                                                "prepare",
                                                &block_hash,
                                                &validator_id,
                                                &signature,
                                            ) {
                                                Ok(sig) => sig,
                                                Err(error) => {
                                                    report_pbft_validation_failure(
                                                        "prepare",
                                                        &validator_id,
                                                        &block_hash,
                                                        error,
                                                    );
                                                    continue;
                                                }
                                            }
                                        };
                                        let mut s = state.write().await;
                                        if let Ok(true) = s.pbft_engine.prepare(&block_hash, &validator_id, sig) {
                                            // Broadcast PbftCommit
                                            if let Some(our_id) = s.config.node_id.clone().into() {
                                                if let Some(our_privkey_hex) = &s.config.validator_privkey {
                                                    if let Ok(pk_bytes) = hex::decode(our_privkey_hex) {
                                                        if let Ok(sk) = ed25519_dalek::SigningKey::try_from(pk_bytes.as_slice()) {
                                                            use ed25519_dalek::Signer;
                                                            let message = consensus::pbft::pbft_signature_message("commit", &block_hash);
                                                            let commit_sig = hex::encode(sk.sign(message.as_bytes()).to_bytes());
                                                            let pubkey = hex::encode(sk.verifying_key().as_bytes());

                                                            let sig_obj = common::BlockSignature { validator_id: our_id.clone(), pubkey: pubkey.clone(), signature: commit_sig.clone() };
                                                            let _ = s.pbft_engine.commit(&block_hash, &our_id, sig_obj);

                                                            let commit_msg = common::GossipMessage::PbftCommit { block_hash: block_hash.clone(), validator_id: our_id, signature: commit_sig };
                                                            if let Ok(data) = serde_json::to_vec(&commit_msg) {
                                                                let topic = libp2p::gossipsub::IdentTopic::new("creg/v1/blocks");
                                                                let _ = self.swarm.behaviour_mut().gossipsub.publish(topic, data);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    common::GossipMessage::PbftCommit { block_hash, validator_id, signature } => {
                                        let sig = {
                                            let s = state.read().await;
                                            match validate_pbft_phase_message(
                                                &s.validator_set,
                                                "commit",
                                                &block_hash,
                                                &validator_id,
                                                &signature,
                                            ) {
                                                Ok(sig) => sig,
                                                Err(error) => {
                                                    report_pbft_validation_failure(
                                                        "commit",
                                                        &validator_id,
                                                        &block_hash,
                                                        error,
                                                    );
                                                    continue;
                                                }
                                            }
                                        };
                                        let mut s = state.write().await;
                                        if let Ok(true) = s.pbft_engine.commit(&block_hash, &validator_id, sig) {
                                            // Finalized!
                                            tracing::info!("[PBFT] Block {} finalised by quorum", &block_hash[..12]);
                                            if let Some(final_block) = s.pbft_engine.get_finalised_block(&block_hash) {
                                                match s.chain.insert_block_with_outcome(&final_block) {
                                                    Ok(outcome) => {
                                                        if let Some(replaced) = outcome.replaced_hash {
                                                            s.record_reorg(1, vec![replaced], outcome.hash.clone());
                                                        }
                                                    }
                                                    Err(e) => {
                                                        tracing::error!("[PBFT] Failed to insert finalised block: {}", e);
                                                    }
                                                }
                                                s.publisher_index.apply_block(&final_block);
                                                let data_dir = s.config.data_dir.clone();
                                                let ipfs_url = if s.config.ipfs_url.is_empty() {
                                                    None
                                                } else {
                                                    Some(s.config.ipfs_url.clone())
                                                };
                                                crate::intelligence::schedule_for_block(
                                                    &final_block,
                                                    data_dir,
                                                    ipfs_url,
                                                );
                                            }
                                        }
                                    }
                                    _ => {
                                        crate::events::emit(&event_bus, crate::events::RegistryEvent {
                                            kind: crate::events::EventKind::BlockProduced,
                                            ts: chrono::Utc::now().to_rfc3339(),
                                            payload: serde_json::json!({ "p2p_message": String::from_utf8_lossy(&message.data).to_string() }),
                                        });
                                    }
                                }
                            }
                        }
                    }
                    SwarmEvent::NewListenAddr { address, .. } => {
                        tracing::info!("P2P node listening on {}", address);
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                        tracing::info!("P2P Connection established with {} at {:?}", peer_id, endpoint);
                    }
                    SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                        tracing::error!("P2P Outgoing connection error to {:?}: {}", peer_id, error);
                    }
                    _ => {}
                },

                // ── Periodically update SharedState with peer list ────────────
                _ = status_ticker.tick() => {
                    let peers: Vec<String> = self.swarm.connected_peers()
                        .map(|p| p.to_string())
                        .collect();
                    let mut s = state.write().await;
                    s.p2p_status.peers = peers;
                    s.p2p_status.protocols = vec!["Identify".into(), "Ping".into(), "Kademlia".into()];
                }

                // ── Identify Storage Responsibility (Sharding) ───────────────
                command = self.receiver.recv() => {
                    if let Some(cmd) = command {
                        match cmd {
                            P2PCommand::Broadcast { topic, data } => {
                                let t = gossipsub::IdentTopic::new(topic);
                                if let Err(e) = self.swarm.behaviour_mut().gossipsub.publish(t, data) {
                                    tracing::error!("P2P broadcast failed: {}", e);
                                }
                            }
                            P2PCommand::Dial { addr } => {
                                tracing::info!("P2P Dialing {}...", addr);
                                if let Err(e) = self.swarm.dial(addr) {
                                    tracing::error!("P2P dial failed: {}", e);
                                }
                            }
                            P2PCommand::IdentifyStorage { cid } => {
                                let is_responsible = self.is_responsible_for(&cid);
                                tracing::info!("Storage check for {}: Responsible={}", cid, is_responsible);
                                // Logic to trigger Pinning/Pruning would happen here
                            }
                        }
                    }
                }
            }
        }
    }

    /// Determines if this node is among the 'N' closest nodes to a CID.
    /// This is the core of our 'Masterless Sharding' for 500MB+ packages.
    ///
    /// Uses a Kademlia-style XOR distance over 8 bytes of the peer ID vs the
    /// SHA-256 of the CID.  The single-byte XOR used previously was biased
    /// (only 256 distinct distances) and collapsed entirely for small networks
    /// where collisions are common.
    pub fn is_responsible_for(&self, cid: &str) -> bool {
        use sha2::{Digest, Sha256};

        let local_bytes = self.peer_id.to_bytes();
        if local_bytes.len() < 8 {
            return false;
        }

        // Hash the CID to get a uniformly distributed key.
        let cid_hash = Sha256::digest(cid.as_bytes());

        // XOR-distance over the first 8 bytes, interpreted as a big-endian u64.
        // This gives 2^64 distinct distance values, matching Kademlia semantics.
        let mut local_arr = [0u8; 8];
        local_arr.copy_from_slice(&local_bytes[..8]);
        let mut cid_arr = [0u8; 8];
        cid_arr.copy_from_slice(&cid_hash[..8]);

        let distance = u64::from_be_bytes(local_arr) ^ u64::from_be_bytes(cid_arr);

        // Threshold: u64::MAX / 8 ≈ top-12.5% of the keyspace → ~7-10 nodes
        // in a 64-node network. Overridable via `CREG_SHARD_THRESHOLD_PCT` (1-100).
        let pct: u64 = std::env::var("CREG_SHARD_THRESHOLD_PCT")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(12)
            .clamp(1, 100);
        let threshold = u64::MAX / 100 * pct;
        distance < threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::{collections::HashMap, sync::Arc};
    use tokio::sync::RwLock;

    fn validator(id: &str, signing_key: &SigningKey) -> common::Validator {
        common::Validator {
            id: id.into(),
            alias: id.into(),
            pubkey: hex::encode(signing_key.verifying_key().as_bytes()),
            eth_address: String::new(),
            stake: 100,
            reputation: 100,
            status: "online".into(),
        }
    }

    fn signed_vote(
        validator_id: &str,
        signing_key: &SigningKey,
        validator_pubkey: String,
    ) -> crate::gossip::VoteGossip {
        let analysis_bundles = common::AnalysisBundleRefs {
            policy_bundle_id: "policy-v1".into(),
            feature_schema_id: "features-v1".into(),
            expert_bundle_id: "experts-v1".into(),
            embedding_model_id: "embeddings-v1".into(),
            index_epoch: "index-epoch-1".into(),
            threshold_profile_id: "thresholds-v1".into(),
            llm_prompt_profile_id: "llm-prompt-v1".into(),
            osv_snapshot_epoch: "osv-off".into(),
        };
        let evidence_digest = common::sha256_hex(b"p2p-test-evidence");
        let ml_model_version = "creg-detect-v1.0.0".to_string();
        let message = crate::gossip::canonical_vote_message(
            "npm/pkg@1.0.0",
            "deadbeef",
            true,
            &validator_pubkey,
            &common::scanner_profile_digest(&ml_model_version, &analysis_bundles),
            &evidence_digest,
        );

        crate::gossip::VoteGossip {
            consensus_subject: "npm/pkg@1.0.0".into(),
            content_hash: "deadbeef".into(),
            validator_id: validator_id.into(),
            validator_pubkey,
            ml_model_version,
            analysis_bundles,
            evidence_digest,
            deterministic_risk: common::DeterministicRiskSummary::default(),
            phase: "commit".into(),
            approved: true,
            reject_reason: None,
            signature: hex::encode(signing_key.sign(message.as_bytes()).to_bytes()),
        }
    }

    async fn make_test_state(
        validator_set: common::ValidatorSet,
    ) -> anyhow::Result<crate::SharedState> {
        let tempdir = tempfile::tempdir()?;
        let chain = crate::chain_store::ChainStore::open(tempdir.path())?;

        Ok(Arc::new(RwLock::new(crate::NodeState {
            chain,
            pending_pool: crate::pending_pool::PendingPool::new(),
            publisher_index: crate::publisher_index::PublisherIndex::new(),
            validator_set_bootstrap: validator_set.clone(),
            validator_set,
            package_rounds: HashMap::new(),
            config: crate::config::NodeConfig {
                data_dir: tempdir.keep(),
                ..Default::default()
            },
            p2p_status: crate::P2PStatus::default(),
            bridge_status: crate::BridgeStatus::default(),
            vrf_proofs: HashMap::new(),
            decryption_shares: HashMap::new(),
            validator_registrations: HashMap::new(),
            validator_set_sync: crate::state::ValidatorSetSyncStatus::default(),
            view_change_certs: HashMap::new(),
            reorgs: Vec::new(),
            pbft_engine: crate::state::PbftEngine::new(),
        })))
    }

    #[test]
    fn validate_vote_gossip_accepts_known_validator() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let validator_set = common::ValidatorSet::new(vec![validator("node-1", &signing_key)]);
        let vote = signed_vote(
            "node-1",
            &signing_key,
            hex::encode(signing_key.verifying_key().as_bytes()),
        );

        let result =
            validate_vote_gossip_message(&serde_json::to_vec(&vote).unwrap(), &validator_set)
                .unwrap();

        assert_eq!(result.validator_id, "node-1");
    }

    #[test]
    fn validate_vote_gossip_rejects_malformed_payload() {
        let validator_set = common::ValidatorSet::default();

        let error = validate_vote_gossip_message(br#"not-json"#, &validator_set).unwrap_err();

        assert_eq!(error, VoteValidationError::Malformed);
    }

    #[test]
    fn validate_vote_gossip_rejects_invalid_signature() {
        let validator_key = SigningKey::from_bytes(&[7u8; 32]);
        let attacker_key = SigningKey::from_bytes(&[8u8; 32]);
        let validator_set = common::ValidatorSet::new(vec![validator("node-1", &validator_key)]);
        let vote = signed_vote(
            "node-1",
            &attacker_key,
            hex::encode(validator_key.verifying_key().as_bytes()),
        );

        let error =
            validate_vote_gossip_message(&serde_json::to_vec(&vote).unwrap(), &validator_set)
                .unwrap_err();

        assert_eq!(error, VoteValidationError::SignatureVerificationFailed);
    }

    #[tokio::test]
    async fn validated_gossip_vote_updates_package_round_state() -> anyhow::Result<()> {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let validator_set = common::ValidatorSet::new(vec![validator("node-1", &signing_key)]);
        let vote = signed_vote(
            "node-1",
            &signing_key,
            hex::encode(signing_key.verifying_key().as_bytes()),
        );
        let state = make_test_state(validator_set).await?;

        record_validated_vote_gossip(&state, &vote).await;

        let state = state.read().await;
        let round = state
            .package_round(&vote.consensus_subject)
            .expect("validated gossip vote should update package round state");

        assert_eq!(round.vote_count(), 1);
        assert_eq!(round.signatures()[0].validator_id, "node-1");
        assert_eq!(round.signatures()[0].ml_model_version, "creg-detect-v1.0.0");

        Ok(())
    }

    fn reserve_listen_addr() -> String {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
            .expect("should reserve a loopback port for the p2p test");
        let port = listener
            .local_addr()
            .expect("reserved listener should have a local address")
            .port();
        drop(listener);
        format!("/ip4/127.0.0.1/tcp/{}", port)
    }

    #[tokio::test]
    async fn gossipsub_vote_broadcast_updates_peer_round_state() -> anyhow::Result<()> {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let validator_set = common::ValidatorSet::new(vec![validator("node-1", &signing_key)]);
        let vote = signed_vote(
            "node-1",
            &signing_key,
            hex::encode(signing_key.verifying_key().as_bytes()),
        );

        let listen_addr_a = reserve_listen_addr();
        let listen_addr_b = reserve_listen_addr();
        let (node_a, handle_a) = P2PNode::new(&listen_addr_a)?;
        let (node_b, _handle_b) = P2PNode::new(&listen_addr_b)?;
        let state_a = make_test_state(validator_set.clone()).await?;
        let state_b = make_test_state(validator_set).await?;
        let event_bus_a = crate::events::new_event_bus();
        let event_bus_b = crate::events::new_event_bus();

        let task_a = tokio::spawn(node_a.run(state_a, event_bus_a));
        let task_b = tokio::spawn(node_b.run(state_b.clone(), event_bus_b));

        tokio::time::sleep(Duration::from_millis(200)).await;
        handle_a
            .sender
            .send(P2PCommand::Dial {
                addr: listen_addr_b.parse()?,
            })
            .await?;

        tokio::time::sleep(Duration::from_secs(1)).await;
        handle_a
            .sender
            .send(P2PCommand::Broadcast {
                topic: "creg/v1/votes".into(),
                data: serde_json::to_vec(&vote)?,
            })
            .await?;

        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let maybe_round = {
                    let state = state_b.read().await;
                    state.package_round(&vote.consensus_subject).cloned()
                };

                if let Some(round) = maybe_round {
                    assert_eq!(round.vote_count(), 1);
                    assert_eq!(round.signatures()[0].validator_id, "node-1");
                    break;
                }

                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("gossipsub vote should reach the peer within the timeout");

        task_a.abort();
        task_b.abort();
        let _ = task_a.await;
        let _ = task_b.await;

        Ok(())
    }
}
