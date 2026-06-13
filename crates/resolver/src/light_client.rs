// crates/resolver/src/light_client.rs
// Light client verification for the CLI resolver.
//
// Instead of trusting the chain node's verdict blindly, the light client:
//   1. Fetches the block header that contains the package record.
//   2. Verifies the block hash matches the header contents.
//   3. Verifies the prev_hash chain back to the genesis hash (or a known checkpoint).
//   4. Verifies the Merkle inclusion proof that the package transaction
//      is actually inside the claimed block.
//
// This provides cryptographic assurance that the verdict is genuine without
// downloading the full chain — the same security model as Bitcoin SPV wallets.

use anyhow::{bail, Context, Result};
use common::{sha256_hex, Block, BlockHeader};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ── Checkpoint ────────────────────────────────────────────────────────────────

/// A known-good (height, hash) pair hardcoded or loaded from config.
/// Light clients verify that the fetched chain reaches back to this checkpoint.
/// Updated with each software release.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub height: u64,
    pub hash: String,
}

impl Checkpoint {
    /// Hardcoded genesis checkpoint — always valid.
    pub fn genesis() -> Self {
        Self {
            height: 0,
            hash: Block::genesis().hash(),
        }
    }
}

// ── Merkle inclusion proof ────────────────────────────────────────────────────

/// A Merkle inclusion proof: a path of sibling hashes from the transaction
/// leaf up to the Merkle root stored in the block header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Hash of the transaction being proven.
    pub tx_hash: String,
    /// Sibling hashes from leaf to root, with side indicators.
    pub path: Vec<MerkleStep>,
    /// The Merkle root the path should produce (must match block header).
    pub expected_root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleStep {
    pub sibling_hash: String,
    pub is_right: bool, // true = sibling is on the right side
}

impl MerkleProof {
    /// Verify the proof: walk the path and check the computed root
    /// matches `expected_root`.
    pub fn verify(&self) -> bool {
        let mut current = self.tx_hash.clone();

        for step in &self.path {
            current = if step.is_right {
                sha256_hex(format!("{}{}", current, step.sibling_hash).as_bytes())
            } else {
                sha256_hex(format!("{}{}", step.sibling_hash, current).as_bytes())
            };
        }

        current == self.expected_root
    }
}

/// Compute a deterministic hash of the active validator set matching node's block_producer logic.
pub fn compute_validator_set_hash(validators: &[common::Validator]) -> String {
    let mut sorted_ids: Vec<&str> = validators.iter().map(|v| v.id.as_str()).collect();
    sorted_ids.sort_unstable();
    let mut hasher = Sha256::new();
    for id in &sorted_ids {
        hasher.update(id.as_bytes());
        hasher.update(b"\0");
    }
    hex::encode(hasher.finalize())
}

/// Verify that a block header is backed by a valid quorum of Ed25519 signatures from active validators.
pub fn verify_pbft_consensus(
    block_hash: &str,
    block_header: &BlockHeader,
    active_validators: &[common::Validator],
    pbft_signatures: &[common::BlockSignature],
) -> Result<()> {
    // 1. Verify that the active validator set matches the validator_set_hash committed in the header
    let computed_hash = compute_validator_set_hash(active_validators);
    if computed_hash != block_header.validator_set_hash {
        bail!(
            "Validator set hash mismatch: header has {}, computed {}",
            block_header.validator_set_hash,
            computed_hash
        );
    }

    // 2. Compute quorum threshold
    let n = active_validators.len();
    if n == 0 {
        bail!("Active validator set is empty");
    }

    let allow_small_cluster_quorum = std::env::var("CREG_PBFT_ALLOW_SMALL_CLUSTER_QUORUM")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    let quorum = match n {
        3 if allow_small_cluster_quorum => 2,
        _ => (2 * n / 3) + 1,
    };

    // 3. Verify signatures
    let validator_pubkeys: std::collections::HashMap<String, String> = active_validators
        .iter()
        .map(|v| {
            (
                v.id.clone(),
                v.pubkey.trim_start_matches("0x").to_ascii_lowercase(),
            )
        })
        .collect();

    let mut seen_validators = std::collections::HashSet::new();
    let message = format!("creg-pbft-v1:commit:{}", block_hash);

    for sig in pbft_signatures {
        let expected_pubkey = match validator_pubkeys.get(&sig.validator_id) {
            Some(pk) => pk,
            None => continue,
        };

        let clean_sig_pubkey = sig.pubkey.trim_start_matches("0x").to_ascii_lowercase();
        if clean_sig_pubkey != *expected_pubkey {
            continue;
        }

        if !seen_validators.insert(sig.validator_id.clone()) {
            continue;
        }

        let pubkey_bytes = hex::decode(expected_pubkey).map_err(|e| {
            anyhow::anyhow!(
                "Invalid validator pubkey hex for {}: {}",
                sig.validator_id,
                e
            )
        })?;
        let verifying_key = VerifyingKey::try_from(pubkey_bytes.as_slice()).map_err(|e| {
            anyhow::anyhow!("Invalid validator pubkey for {}: {}", sig.validator_id, e)
        })?;

        let signature_bytes = hex::decode(sig.signature.trim_start_matches("0x")).map_err(|e| {
            anyhow::anyhow!("Invalid signature hex from {}: {}", sig.validator_id, e)
        })?;
        let signature = Signature::try_from(signature_bytes.as_slice()).map_err(|e| {
            anyhow::anyhow!("Invalid signature format from {}: {}", sig.validator_id, e)
        })?;

        verifying_key
            .verify(message.as_bytes(), &signature)
            .map_err(|e| {
                anyhow::anyhow!(
                    "Cryptographic signature verification failed for {}: {}",
                    sig.validator_id,
                    e
                )
            })?;
    }

    let approvals = seen_validators.len();
    if approvals < quorum {
        bail!(
            "Insufficient PBFT consensus signatures: got {} valid, need {} (quorum for validator set size {})",
            approvals,
            quorum,
            n
        );
    }

    Ok(())
}

// ── Block header verification ─────────────────────────────────────────────────

fn hash_prefix(value: &str) -> &str {
    &value[..value.len().min(12)]
}

/// Verify that a block header is self-consistent:
/// - The hash of the header bytes equals the claimed block hash.
/// - The height is monotonically increasing from the previous header.
pub fn verify_header(
    header: &BlockHeader,
    expected_hash: &str,
    expected_height: u64,
) -> Result<()> {
    let computed = sha256_hex(&serde_json::to_vec(header).context("Failed to serialise header")?);

    if computed != expected_hash {
        bail!(
            "Block header hash mismatch at height {}: expected {} got {}",
            expected_height,
            hash_prefix(expected_hash),
            hash_prefix(&computed)
        );
    }

    if header.height != expected_height {
        bail!(
            "Block height mismatch: expected {} got {}",
            expected_height,
            header.height
        );
    }

    Ok(())
}

// ── Chain verification ────────────────────────────────────────────────────────

/// Verify a chain of headers from `checkpoint` up to `tip`.
/// Returns an error if any link in the chain is broken.
pub fn verify_header_chain(
    headers: &[(BlockHeader, String)], // (header, hash) pairs in ascending height order
    checkpoint: &Checkpoint,
) -> Result<()> {
    if headers.is_empty() {
        return Ok(());
    }

    // The first header must chain back to the checkpoint.
    let (first_header, first_hash) = &headers[0];
    verify_header(first_header, first_hash, checkpoint.height + 1)?;
    if first_header.prev_hash != checkpoint.hash {
        bail!(
            "Chain break at height {}: expected prev={} got={}",
            first_header.height,
            hash_prefix(&checkpoint.hash),
            hash_prefix(&first_header.prev_hash)
        );
    }

    // Verify each subsequent link.
    for window in headers.windows(2) {
        let (prev_header, prev_hash) = &window[0];
        let (next_header, next_hash) = &window[1];

        verify_header(next_header, next_hash, prev_header.height + 1)?;

        if next_header.prev_hash != *prev_hash {
            bail!(
                "Chain break at height {}: expected prev={} got={}",
                next_header.height,
                hash_prefix(prev_hash),
                hash_prefix(&next_header.prev_hash)
            );
        }
    }

    Ok(())
}

// ── Light client verdict ──────────────────────────────────────────────────────

/// Response from the chain node's light-client endpoint.
#[derive(Debug, Serialize, Deserialize)]
pub struct LightClientResponse {
    /// The package's status string.
    pub status: String,
    /// The block hash that contains this package record.
    pub block_hash: String,
    /// The block header at that height.
    pub block_header: BlockHeader,
    /// Merkle inclusion proof for the package transaction.
    pub proof: MerkleProof,
    /// Header chain from the node's latest checkpoint to the package block.
    pub header_chain: Vec<(BlockHeader, String)>,
    /// Ed25519 signatures from PBFT Commit phase over the block hash.
    #[serde(default)]
    pub pbft_signatures: Vec<common::BlockSignature>,
    /// Active validator set at the block height (or current).
    #[serde(default)]
    pub active_validators: Vec<common::Validator>,
}

/// Fetch and cryptographically verify a package verdict using SPV-style proof.
/// Returns `true` if the package is genuinely verified on chain.
pub async fn verify_package(
    canonical: &str,
    node_url: &str,
    checkpoint: &Checkpoint,
) -> Result<bool> {
    let encoded = urlencoding::encode(canonical);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()?;

    let grouped_url = format!(
        "{}/v1/public/packages/{}/proof",
        node_url.trim_end_matches('/'),
        encoded
    );
    let legacy_url = format!(
        "{}/v1/packages/{}/proof",
        node_url.trim_end_matches('/'),
        encoded
    );

    let response = client
        .get(&grouped_url)
        .send()
        .await
        .context("Failed to reach chain node for light-client proof")?;

    let response = if matches!(
        response.status(),
        StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED | StatusCode::NOT_IMPLEMENTED
    ) {
        client
            .get(&legacy_url)
            .send()
            .await
            .context("Failed to reach legacy light-client proof endpoint")?
    } else {
        response
    };

    let resp: LightClientResponse = response
        .error_for_status()
        .context("Node returned an error for light-client proof")?
        .json()
        .await
        .context("Invalid JSON from light-client proof endpoint")?;

    if resp.status != "verified" {
        return Ok(false);
    }

    // 1. Verify the Merkle proof — package tx is inside the block.
    if !resp.proof.verify() {
        bail!("Merkle proof verification failed for {}", canonical);
    }

    // 2. Verify the Merkle root matches the block header.
    if resp.proof.expected_root != resp.block_header.merkle_root {
        bail!("Merkle root mismatch in block header for {}", canonical);
    }

    // 3. Verify the proof block itself and bind it to the verified header chain.
    verify_header(
        &resp.block_header,
        &resp.block_hash,
        resp.block_header.height,
    )?;

    // Verify PBFT consensus validator signatures and quorums.
    verify_pbft_consensus(
        &resp.block_hash,
        &resp.block_header,
        &resp.active_validators,
        &resp.pbft_signatures,
    )?;

    let relevant_headers: Vec<(BlockHeader, String)> = resp
        .header_chain
        .iter()
        .filter(|(header, _)| header.height > checkpoint.height)
        .cloned()
        .collect();

    if resp.block_header.height > checkpoint.height && relevant_headers.is_empty() {
        bail!(
            "Header chain for {} omitted the terminal block after checkpoint {}",
            canonical,
            checkpoint.height
        );
    }

    if let Some((terminal_header, terminal_hash)) = relevant_headers.last() {
        if terminal_hash != &resp.block_hash || terminal_header.height != resp.block_header.height {
            bail!(
                "Header chain terminal entry does not match proof block for {}",
                canonical
            );
        }
        verify_header_chain(&relevant_headers, checkpoint)?;
    } else if resp.block_header.height != checkpoint.height || resp.block_hash != checkpoint.hash {
        bail!(
            "Checkpoint {} does not match proof block {} for {}",
            checkpoint.height,
            resp.block_header.height,
            canonical
        );
    }

    tracing::info!(
        "Light-client verification passed for {} (block {})",
        canonical,
        hash_prefix(&resp.block_hash)
    );

    Ok(true)
}

// ── Light client endpoint on the node side ─────────────────────────────────
// GET /v1/packages/:canonical/proof → LightClientResponse
// This is served by the node's REST API (api.rs).
// The proof is built here so the node and resolver share the same logic.

/// Build a Merkle inclusion proof for a transaction at `tx_index` within `block`.
pub fn build_merkle_proof(block: &Block, tx_index: usize) -> Result<MerkleProof> {
    let n = block.transactions.len();
    if tx_index >= n {
        bail!(
            "tx_index {} out of range (block has {} transactions)",
            tx_index,
            n
        );
    }

    // Compute all leaf hashes.
    let leaves: Vec<String> = block
        .transactions
        .iter()
        .map(|tx| sha256_hex(&serde_json::to_vec(tx).unwrap_or_default()))
        .collect();

    let tx_hash = leaves[tx_index].clone();
    let expected_root = block.header.merkle_root.clone();

    // Walk up the tree collecting sibling hashes.
    let mut path = Vec::new();
    let mut idx = tx_index;
    let mut level = leaves.clone();

    while level.len() > 1 {
        // Pad to even length.
        if level.len() % 2 != 0 {
            level.push(
                level
                    .last()
                    .ok_or_else(|| anyhow::anyhow!("Empty merkle level during proof construction"))?
                    .clone(),
            );
        }

        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        path.push(MerkleStep {
            sibling_hash: level[sibling_idx].clone(),
            is_right: idx % 2 == 0,
        });

        // Build next level.
        level = level
            .chunks(2)
            .map(|pair| sha256_hex(format!("{}{}", pair[0], pair[1]).as_bytes()))
            .collect();
        idx /= 2;
    }

    Ok(MerkleProof {
        tx_hash,
        path,
        expected_root,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_proof_verifies() {
        use chrono::Utc;
        use common::{Block, BlockHeader, ChainRecord, PackageId, PackageStatus, Transaction};

        // Build a block with 4 transactions.
        let txs: Vec<Transaction> = (0..4)
            .map(|i| {
                Transaction::Publish(ChainRecord {
                    id: PackageId::new("npm", format!("pkg-{}", i), "1.0.0"),
                    content_hash: sha256_hex(format!("pkg-{}", i).as_bytes()),
                    ipfs_cid: format!("bafytest{}", i),
                    publisher_pubkey: "pub".into(),
                    block_hash: "0".repeat(64),
                    published_at: Utc::now(),
                    validator_signatures: vec![],
                    status: PackageStatus::Verified,
                    ..Default::default()
                })
            })
            .collect();

        let block = Block {
            header: BlockHeader {
                height: 1,
                prev_hash: "0".repeat(64),
                merkle_root: common::merkle_root(&txs),
                proposer_id: "test".into(),
                timestamp: Utc::now(),
                validator_set_hash: "dev".into(),
                vrf_output: None,
                vrf_proof: None,
            },
            transactions: txs,
            pbft_signatures: vec![],
        };

        // Build and verify a proof for tx index 2.
        let proof = build_merkle_proof(&block, 2).unwrap();
        assert!(proof.verify(), "Merkle proof should verify");

        // Tamper with the tx hash — should fail.
        let mut bad_proof = proof.clone();
        bad_proof.tx_hash = sha256_hex(b"tampered");
        assert!(!bad_proof.verify(), "Tampered proof should fail");
    }

    #[test]
    fn header_chain_verifies() {
        let genesis = Checkpoint::genesis();
        // An empty chain (nothing after checkpoint) is trivially valid.
        verify_header_chain(&[], &genesis).unwrap();
    }

    #[test]
    fn header_chain_verifies_single_header() {
        use chrono::Utc;

        let genesis = Checkpoint::genesis();
        let block = Block {
            header: BlockHeader {
                height: 1,
                prev_hash: genesis.hash.clone(),
                merkle_root: sha256_hex(b"leaf"),
                proposer_id: "validator-1".into(),
                timestamp: Utc::now(),
                validator_set_hash: "dev".into(),
                vrf_output: None,
                vrf_proof: None,
            },
            transactions: vec![],
            pbft_signatures: vec![],
        };

        verify_header_chain(&[(block.header.clone(), block.hash())], &genesis).unwrap();
    }

    #[test]
    fn header_chain_rejects_tampered_first_hash() {
        use chrono::Utc;

        let genesis = Checkpoint::genesis();
        let header = BlockHeader {
            height: 1,
            prev_hash: genesis.hash.clone(),
            merkle_root: sha256_hex(b"leaf"),
            proposer_id: "validator-1".into(),
            timestamp: Utc::now(),
            validator_set_hash: "dev".into(),
            vrf_output: None,
            vrf_proof: None,
        };

        assert!(verify_header_chain(&[(header, "bad-hash".into())], &genesis).is_err());
    }

    #[test]
    fn checkpoint_genesis_hash_stable() {
        let c1 = Checkpoint::genesis();
        let c2 = Checkpoint::genesis();
        assert_eq!(c1.hash, c2.hash, "Genesis hash must be deterministic");
    }

    #[test]
    fn test_pbft_consensus_verification() {
        use common::{BlockSignature, Validator};
        use ed25519_dalek::{Signer, SigningKey};

        // Create keys for 3 validators
        let keys: Vec<SigningKey> = (0..3)
            .map(|i| SigningKey::from_bytes(&[i as u8 + 1; 32]))
            .collect();

        let validators: Vec<Validator> = keys
            .iter()
            .enumerate()
            .map(|(i, key)| Validator {
                id: format!("val-{}", i),
                alias: format!("val-{}", i),
                pubkey: hex::encode(key.verifying_key().as_bytes()),
                eth_address: String::new(),
                stake: 100,
                reputation: 100,
                status: "online".into(),
            })
            .collect();

        // Calculate expected validator set hash
        let val_set_hash = compute_validator_set_hash(&validators);

        let mut block_header = BlockHeader {
            height: 1,
            prev_hash: "0".repeat(64),
            merkle_root: "0".repeat(64),
            proposer_id: "val-0".into(),
            timestamp: chrono::Utc::now(),
            validator_set_hash: val_set_hash.clone(),
            vrf_output: None,
            vrf_proof: None,
        };

        let block_hash =
            "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1231234".to_string();
        let message = format!("creg-pbft-v1:commit:{}", block_hash);

        // Sign the block hash
        let pbft_signatures: Vec<BlockSignature> = keys
            .iter()
            .enumerate()
            .map(|(i, key)| {
                let signature = key.sign(message.as_bytes());
                BlockSignature {
                    validator_id: format!("val-{}", i),
                    pubkey: hex::encode(key.verifying_key().as_bytes()),
                    signature: hex::encode(signature.to_bytes()),
                }
            })
            .collect();

        // Standard quorum of 3 validators is (2*3/3)+1 = 3.
        // If CREG_PBFT_ALLOW_SMALL_CLUSTER_QUORUM=false (default): we need all 3 signatures.
        std::env::set_var("CREG_PBFT_ALLOW_SMALL_CLUSTER_QUORUM", "false");

        // 3/3 signatures should pass
        assert!(
            verify_pbft_consensus(&block_hash, &block_header, &validators, &pbft_signatures)
                .is_ok()
        );

        // 2/3 signatures should fail
        assert!(verify_pbft_consensus(
            &block_hash,
            &block_header,
            &validators,
            &pbft_signatures[..2]
        )
        .is_err());

        // Enable small cluster quorum (threshold becomes 2 for size 3)
        std::env::set_var("CREG_PBFT_ALLOW_SMALL_CLUSTER_QUORUM", "true");
        assert!(verify_pbft_consensus(
            &block_hash,
            &block_header,
            &validators,
            &pbft_signatures[..2]
        )
        .is_ok());
        assert!(verify_pbft_consensus(
            &block_hash,
            &block_header,
            &validators,
            &pbft_signatures[..1]
        )
        .is_err());

        // Mismatched validator set hash should fail
        block_header.validator_set_hash = "wrong-hash".to_string();
        assert!(
            verify_pbft_consensus(&block_hash, &block_header, &validators, &pbft_signatures)
                .is_err()
        );
    }
}
