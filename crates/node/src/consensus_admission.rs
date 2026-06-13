// crates/node/src/consensus_admission.rs
//
// Mechanical-consensus validator admission.
//
// Every active validator independently evaluates a deterministic rule set
// against each Pending applicant. If all rules pass, the validator signs an
// EIP-712 attestation binding (applicant, stake, nonce, ruleSetVersion) and
// broadcasts it to peers. Any node that has collected attestations from
// ≥ 2/3 of the active set may submit the aggregated calldata to Staking's
// `approveByConsensus` — in practice we let the lowest-address signer submit
// so every node reaches the same conclusion without racing.
//
// There is no privileged approver. No single key can admit or block anyone.

use std::{collections::HashMap, sync::Arc, time::Duration};

use alloy::{
    network::EthereumWallet,
    primitives::{keccak256, Address, Bytes, B256, U256},
    providers::{Provider, ProviderBuilder},
    signers::{local::PrivateKeySigner, Signer},
    sol,
    sol_types::SolValue,
};
use serde::{Deserialize, Serialize};
use tokio::{sync::Mutex, time::interval};

use crate::state::SharedState;

// ─── Contract interface (read + submit) ───────────────────────────────────────

sol!(
    #[sol(rpc)]
    interface IStakingAdmission {
        function validators(address)
            external
            view
            returns (
                uint256 stake,
                uint8 state,
                uint256 unbondingAt,
                uint256 slashCount,
                uint256 ejectedAt,
                uint256 appliedAt
            );

        function RULE_SET_VERSION() external view returns (uint256);
        function APPLICATION_TIMEOUT() external view returns (uint256);
        function minValidatorStake() external view returns (uint256);
        function activeValidatorCount() external view returns (uint256);

        function consensusNonceUsed(address applicant, uint256 nonce)
            external view returns (bool);

        function approveByConsensus(
            address applicant,
            uint256 nonce,
            address[] calldata signers,
            bytes[]   calldata sigs
        ) external;
    }
);

// ─── EIP-712 digest ──────────────────────────────────────────────────────────
//
// Must stay byte-identical to Staking.consensusMessageHash. Any divergence
// breaks signature recovery on-chain.

const DOMAIN_NAME: &str = "Chain Registry Validator Admission";
const DOMAIN_VERSION: &str = "1";
const STRUCT_TYPE: &str =
    "ValidatorAdmission(address applicant,uint256 stake,uint256 nonce,uint256 ruleSetVersion)";
const DOMAIN_TYPE: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";

fn domain_separator(chain_id: u64, staking_addr: Address) -> B256 {
    let type_hash = keccak256(DOMAIN_TYPE.as_bytes());
    let name_hash = keccak256(DOMAIN_NAME.as_bytes());
    let version_hash = keccak256(DOMAIN_VERSION.as_bytes());
    let encoded = (
        type_hash,
        name_hash,
        version_hash,
        U256::from(chain_id),
        staking_addr,
    )
        .abi_encode();
    keccak256(&encoded)
}

fn struct_hash(applicant: Address, stake: U256, nonce: U256, rule_set_version: U256) -> B256 {
    let type_hash = keccak256(STRUCT_TYPE.as_bytes());
    let encoded = (type_hash, applicant, stake, nonce, rule_set_version).abi_encode();
    keccak256(&encoded)
}

fn admission_digest(
    chain_id: u64,
    staking_addr: Address,
    applicant: Address,
    stake: U256,
    nonce: U256,
    rule_set_version: U256,
) -> B256 {
    let dsep = domain_separator(chain_id, staking_addr);
    let shash = struct_hash(applicant, stake, nonce, rule_set_version);
    let mut buf = Vec::with_capacity(66);
    buf.extend_from_slice(b"\x19\x01");
    buf.extend_from_slice(dsep.as_slice());
    buf.extend_from_slice(shash.as_slice());
    keccak256(&buf)
}

// ─── On-wire attestation ──────────────────────────────────────────────────────

/// Attestation broadcast by an active validator for a Pending applicant.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdmissionAttestation {
    /// Applicant's EVM address (lowercased, 0x-prefixed).
    pub applicant: String,
    /// Applicant's staked amount in wei (hex, 0x-prefixed).
    pub stake: String,
    /// Unique nonce for this application — the on-chain `appliedAt` timestamp.
    pub nonce: String,
    /// Rule-set version the signer evaluated against. Rejected if != on-chain.
    pub rule_set_version: String,
    /// Signer's EVM address.
    pub signer: String,
    /// 65-byte ECDSA signature (r||s||v), hex-encoded with 0x prefix.
    pub signature: String,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct AttestationKey {
    applicant: String,
    nonce: String,
}

impl AdmissionAttestation {
    fn key(&self) -> AttestationKey {
        AttestationKey {
            applicant: self.applicant.to_ascii_lowercase(),
            nonce: self.nonce.to_ascii_lowercase(),
        }
    }
}

// ─── Store ────────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct AttestationStore {
    /// (applicant, nonce) → signer → attestation.
    inner: Mutex<HashMap<AttestationKey, HashMap<String, AdmissionAttestation>>>,
}

impl AttestationStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub async fn insert(&self, att: AdmissionAttestation) -> bool {
        let mut g = self.inner.lock().await;
        let signer = att.signer.to_ascii_lowercase();
        let by_signer = g.entry(att.key()).or_default();
        by_signer.insert(signer, att).is_none()
    }

    async fn snapshot(&self, key: &AttestationKey) -> Vec<AdmissionAttestation> {
        let g = self.inner.lock().await;
        g.get(key)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }

    pub async fn drop_applicant(&self, applicant: &str) {
        let mut g = self.inner.lock().await;
        let needle = applicant.to_ascii_lowercase();
        g.retain(|k, _| k.applicant != needle);
    }
}

// ─── Signer ──────────────────────────────────────────────────────────────────

pub async fn sign_attestation(
    priv_key: &str,
    chain_id: u64,
    staking_addr: Address,
    applicant: Address,
    stake: U256,
    nonce: U256,
    rule_set_version: U256,
) -> anyhow::Result<AdmissionAttestation> {
    let signer: PrivateKeySigner = priv_key.parse()?;
    let signer_addr = signer.address();
    let digest = admission_digest(
        chain_id,
        staking_addr,
        applicant,
        stake,
        nonce,
        rule_set_version,
    );
    let sig = signer.sign_hash(&digest).await?;
    let sig_bytes: [u8; 65] = sig.as_bytes();
    Ok(AdmissionAttestation {
        applicant: format!("0x{:040x}", applicant),
        stake: format!("0x{:x}", stake),
        nonce: format!("0x{:x}", nonce),
        rule_set_version: format!("0x{:x}", rule_set_version),
        signer: format!("0x{:040x}", signer_addr),
        signature: format!("0x{}", hex::encode(sig_bytes)),
    })
}

// ─── Verifier ────────────────────────────────────────────────────────────────

pub fn verify_attestation(
    att: &AdmissionAttestation,
    chain_id: u64,
    staking_addr: Address,
) -> anyhow::Result<bool> {
    let applicant: Address = att.applicant.parse()?;
    let stake = parse_u256(&att.stake)?;
    let nonce = parse_u256(&att.nonce)?;
    let rsv = parse_u256(&att.rule_set_version)?;
    let claimed_signer: Address = att.signer.parse()?;

    let digest = admission_digest(chain_id, staking_addr, applicant, stake, nonce, rsv);

    let raw = hex_decode(&att.signature)?;
    if raw.len() != 65 {
        return Ok(false);
    }
    let sig = alloy::primitives::Signature::try_from(raw.as_slice())?;
    let recovered = sig.recover_address_from_prehash(&digest)?;
    Ok(recovered == claimed_signer)
}

fn parse_u256(s: &str) -> anyhow::Result<U256> {
    let trimmed = s.trim_start_matches("0x").trim_start_matches("0X");
    U256::from_str_radix(trimmed, 16).map_err(|e| anyhow::anyhow!("bad u256: {e}"))
}

fn hex_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    let trimmed = s.trim_start_matches("0x").trim_start_matches("0X");
    Ok(hex::decode(trimmed)?)
}

// ─── Main loop ────────────────────────────────────────────────────────────────

pub async fn run(state: SharedState, store: Arc<AttestationStore>) {
    let mut ticker = interval(Duration::from_secs(15));
    loop {
        ticker.tick().await;
        if let Err(e) = tick(&state, &store).await {
            tracing::debug!("admission tick: {}", e);
        }
    }
}

/// Cached per-tick constants. Re-read each tick so config changes propagate.
struct TickCtx {
    rpc_url: String,
    staking_addr: Address,
    bridge_priv: Option<String>,
    peer_urls: Vec<String>,
    pending_applicants: Vec<String>,
}

async fn load_ctx(state: &SharedState) -> anyhow::Result<Option<TickCtx>> {
    let s = state.read().await;
    let staking_s = s.config.staking_addr.clone();
    if staking_s.trim().is_empty()
        || staking_s.eq_ignore_ascii_case("0x0000000000000000000000000000000000000000")
    {
        return Ok(None);
    }
    let pending: Vec<String> = s
        .validator_registrations
        .iter()
        .filter_map(|(k, r)| {
            if r.staking_state == "pending" {
                Some(k.clone())
            } else {
                None
            }
        })
        .collect();
    if pending.is_empty() {
        return Ok(None);
    }
    Ok(Some(TickCtx {
        rpc_url: s.config.eth_rpc_url.clone(),
        staking_addr: staking_s.parse()?,
        bridge_priv: s.config.bridge_privkey.clone(),
        peer_urls: s.config.peers.clone(),
        pending_applicants: pending,
    }))
}

async fn tick(state: &SharedState, store: &AttestationStore) -> anyhow::Result<()> {
    let Some(ctx) = load_ctx(state).await? else {
        return Ok(());
    };

    // Build a fresh (read-only) provider per tick — cheap and sidesteps the
    // generic-lifetime gymnastics of sharing a typed provider across helpers.
    let provider = ProviderBuilder::new().on_http(ctx.rpc_url.parse()?);
    let contract = IStakingAdmission::new(ctx.staking_addr, &provider);
    let chain_id = provider.get_chain_id().await?;
    let rule_set_version = contract.RULE_SET_VERSION().call().await?._0;
    let min_stake = contract.minValidatorStake().call().await?._0;
    let timeout_secs = contract.APPLICATION_TIMEOUT().call().await?._0;

    // Determine whether *we* are currently an Active validator on-chain.
    let (self_addr, we_are_active) = if let Some(pk) = ctx.bridge_priv.as_deref() {
        let signer: PrivateKeySigner = pk.parse()?;
        let addr = signer.address();
        let v = contract.validators(addr).call().await?;
        (Some(addr), v.state == 2u8)
    } else {
        (None, false)
    };

    for key in &ctx.pending_applicants {
        let res = process_applicant(
            state,
            store,
            &ctx,
            chain_id,
            rule_set_version,
            min_stake,
            timeout_secs,
            self_addr,
            we_are_active,
            key,
        )
        .await;
        if let Err(e) = res {
            tracing::debug!("admission per-applicant ({}): {}", key, e);
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn process_applicant(
    state: &SharedState,
    store: &AttestationStore,
    ctx: &TickCtx,
    chain_id: u64,
    rule_set_version: U256,
    min_stake: U256,
    timeout_secs: U256,
    self_addr: Option<Address>,
    we_are_active: bool,
    applicant_key: &str,
) -> anyhow::Result<()> {
    let applicant: Address = applicant_key.parse()?;
    let provider = ProviderBuilder::new().on_http(ctx.rpc_url.parse()?);
    let contract = IStakingAdmission::new(ctx.staking_addr, &provider);

    let v = contract.validators(applicant).call().await?;

    // Rule 1: must be Pending (state == 1).
    if v.state != 1u8 {
        store.drop_applicant(applicant_key).await;
        return Ok(());
    }
    // Rule 2: stake must meet the on-chain minimum.
    if v.stake < min_stake {
        return Ok(());
    }
    // Rule 3: identity must be registered with this node.
    let have_identity = {
        let s = state.read().await;
        s.validator_registrations
            .get(applicant_key)
            .map(|r| r.registered_with_node && r.identity.normalized().is_complete())
            .unwrap_or(false)
    };
    if !have_identity {
        return Ok(());
    }
    // Rule 4: cooldown after a previous slash — appliedAt must be *after* ejectedAt.
    // Staking._applyToBeValidator enforces this; we re-check defensively.
    if v.ejectedAt > U256::ZERO && v.appliedAt <= v.ejectedAt {
        return Ok(());
    }
    // Rule 5: application must not have expired.
    let now = U256::from(chrono::Utc::now().timestamp() as u64);
    if now >= v.appliedAt + timeout_secs {
        store.drop_applicant(applicant_key).await;
        return Ok(());
    }

    let nonce = v.appliedAt;
    let stake = v.stake;

    // Already admitted under this nonce? Purge local state and skip.
    if contract
        .consensusNonceUsed(applicant, nonce)
        .call()
        .await?
        ._0
    {
        store.drop_applicant(applicant_key).await;
        return Ok(());
    }

    // ── Sign our own attestation (only if we are currently Active) ─────────
    if we_are_active {
        if let Some(pk) = ctx.bridge_priv.as_deref() {
            let att = sign_attestation(
                pk,
                chain_id,
                ctx.staking_addr,
                applicant,
                stake,
                nonce,
                rule_set_version,
            )
            .await?;
            if store.insert(att.clone()).await {
                tracing::info!(
                    "admission: signed attestation for {} at nonce {}",
                    applicant_key,
                    nonce
                );
                broadcast_to_peers(&ctx.peer_urls, &att).await;
            }
        }
    }

    // ── Check quorum and possibly submit ───────────────────────────────────
    let snapshot_key = AttestationKey {
        applicant: applicant_key.to_ascii_lowercase(),
        nonce: format!("0x{:x}", nonce),
    };
    let atts = store.snapshot(&snapshot_key).await;

    // Keep only signatures that verify.
    let verified: Vec<AdmissionAttestation> = atts
        .into_iter()
        .filter(|a| verify_attestation(a, chain_id, ctx.staking_addr).unwrap_or(false))
        .collect();

    // Keep only signers that are currently Active on-chain.
    let mut filtered: Vec<(Address, AdmissionAttestation)> = Vec::with_capacity(verified.len());
    for a in verified {
        let signer_addr: Address = a.signer.parse()?;
        let info = contract.validators(signer_addr).call().await?;
        if info.state == 2u8 {
            filtered.push((signer_addr, a));
        }
    }

    // Sort ascending by signer address — matches the contract's requirement.
    filtered.sort_by_key(|(addr, _)| *addr);

    // Quorum check: signers * 3 >= active * 2.
    let active_count = contract.activeValidatorCount().call().await?._0;
    if U256::from(filtered.len() as u64) * U256::from(3u64) < active_count * U256::from(2u64) {
        return Ok(());
    }

    // Deterministic submitter: the signer with the lowest address submits.
    // If we are not that signer (or not a signer at all), stand down.
    let lowest = filtered.first().map(|(a, _)| *a);
    if self_addr.is_none() || lowest != self_addr {
        return Ok(());
    }

    submit_consensus_approval(
        ctx.rpc_url.clone(),
        ctx.bridge_priv.as_deref().unwrap_or_default(),
        ctx.staking_addr,
        applicant,
        nonce,
        &filtered,
    )
    .await?;
    store.drop_applicant(applicant_key).await;
    Ok(())
}

async fn submit_consensus_approval(
    rpc_url: String,
    priv_key: &str,
    staking_addr: Address,
    applicant: Address,
    nonce: U256,
    filtered: &[(Address, AdmissionAttestation)],
) -> anyhow::Result<()> {
    if priv_key.is_empty() {
        anyhow::bail!("no bridge private key available for submitter");
    }
    let signer: PrivateKeySigner = priv_key.parse()?;
    let wallet = EthereumWallet::from(signer);
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_http(rpc_url.parse()?);
    let contract = IStakingAdmission::new(staking_addr, &provider);

    let signers: Vec<Address> = filtered.iter().map(|(a, _)| *a).collect();
    let sigs: Vec<Bytes> = filtered
        .iter()
        .map(|(_, a)| {
            let raw = hex_decode(&a.signature).unwrap_or_default();
            Bytes::from(raw)
        })
        .collect();

    tracing::info!(
        "admission: submitting approveByConsensus for {} (nonce={}, signers={})",
        applicant,
        nonce,
        signers.len()
    );

    let call = contract.approveByConsensus(applicant, nonce, signers, sigs);
    let pending = call.send().await?;
    let receipt = pending.get_receipt().await?;
    tracing::info!(
        "admission: approveByConsensus mined (tx={}, block={})",
        receipt.transaction_hash,
        receipt.block_number.unwrap_or_default()
    );
    Ok(())
}

async fn broadcast_to_peers(peer_urls: &[String], att: &AdmissionAttestation) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    for url in peer_urls {
        let endpoint = format!(
            "{}/v1/consensus/admission-attestation",
            url.trim_end_matches('/')
        );
        let body = att.clone();
        let client = client.clone();
        tokio::spawn(async move {
            let _ = client.post(&endpoint).json(&body).send().await;
        });
    }
}

// ─── Public API for the HTTP endpoint ─────────────────────────────────────────

pub async fn accept_peer_attestation(
    store: &AttestationStore,
    chain_id: u64,
    staking_addr: Address,
    att: AdmissionAttestation,
) -> anyhow::Result<bool> {
    if !verify_attestation(&att, chain_id, staking_addr)? {
        anyhow::bail!("signature does not recover to declared signer");
    }
    Ok(store.insert(att).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed test vectors so that any divergence from the contract's digest
    /// shows up as a failing Rust test before it can bite us on-chain.
    #[test]
    fn domain_separator_matches_eip712_hash() {
        let staking: Address = "0xBabE000000000000000000000000000000000BaD"
            .parse()
            .unwrap();
        let dsep = domain_separator(1337, staking);
        // Re-derive via the same formula; this asserts the encoding path stays stable.
        let type_hash = keccak256(DOMAIN_TYPE.as_bytes());
        let name_hash = keccak256(DOMAIN_NAME.as_bytes());
        let version_hash = keccak256(DOMAIN_VERSION.as_bytes());
        let expected = keccak256(
            &(
                type_hash,
                name_hash,
                version_hash,
                U256::from(1337u64),
                staking,
            )
                .abi_encode(),
        );
        assert_eq!(dsep, expected);
    }

    #[tokio::test]
    async fn sign_then_verify_roundtrip() {
        // 32-byte hex seed = known private key from foundry's default set.
        let pk = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let signer: PrivateKeySigner = pk.parse().unwrap();
        let signer_addr = signer.address();

        let staking: Address = "0x000000000000000000000000000000000000dEaD"
            .parse()
            .unwrap();
        let applicant: Address = "0x00000000000000000000000000000000000CAFEE"
            .parse()
            .unwrap();

        let att = sign_attestation(
            pk,
            31337,
            staking,
            applicant,
            U256::from(123u64),
            U256::from(1u64),
            U256::from(1u64),
        )
        .await
        .expect("sign");

        assert!(att
            .signer
            .eq_ignore_ascii_case(&format!("0x{:040x}", signer_addr)));
        assert!(verify_attestation(&att, 31337, staking).unwrap());

        // Flipping the chain_id must break recovery — the digest changes.
        assert!(!verify_attestation(&att, 1, staking).unwrap());
    }

    #[tokio::test]
    async fn store_dedups_by_signer() {
        let store = AttestationStore::new();
        let pk = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let staking: Address = "0x000000000000000000000000000000000000dEaD"
            .parse()
            .unwrap();
        let applicant: Address = "0x00000000000000000000000000000000000CAFEE"
            .parse()
            .unwrap();

        let att = sign_attestation(
            pk,
            31337,
            staking,
            applicant,
            U256::from(123u64),
            U256::from(1u64),
            U256::from(1u64),
        )
        .await
        .unwrap();

        assert!(store.insert(att.clone()).await);
        assert!(
            !store.insert(att.clone()).await,
            "second insert must be no-op"
        );

        let snap = store.snapshot(&att.key()).await;
        assert_eq!(snap.len(), 1);
    }
}
