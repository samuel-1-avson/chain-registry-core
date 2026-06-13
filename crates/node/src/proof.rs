// crates/node/src/proof.rs
// Builds and serves Merkle inclusion proofs for the light-client endpoint.
// GET /v1/packages/:canonical/proof → LightClientResponse

use crate::chain_store::ChainStore;
use anyhow::{bail, Result};
use common::{BlockHeader, PackageStatus, Transaction};
use resolver::light_client::{build_merkle_proof, LightClientResponse};

/// Build a full light-client proof response for a given package canonical ID.
/// Returns None if the package is not found or not verified.
pub fn build_proof(
    canonical: &str,
    chain: &ChainStore,
    active_validators: &[common::Validator],
) -> Result<Option<LightClientResponse>> {
    // Find the ChainRecord.
    let record = match chain.get_package(canonical)? {
        Some(r) => r,
        None => return Ok(None),
    };

    if !matches!(record.status, PackageStatus::Verified) {
        return Ok(None);
    }

    // Find the block that contains the Publish transaction for this package.
    let block_hash = &record.block_hash;
    let block = match chain.get_block_by_hash(block_hash)? {
        Some(b) => b,
        None => {
            tracing::warn!(
                "Block {} not found for package {}",
                &block_hash[..12],
                canonical
            );
            return Ok(None);
        }
    };

    // Locate the transaction index within the block.
    let tx_index = block
        .transactions
        .iter()
        .position(|tx| matches!(tx, Transaction::Publish(r) if r.id.canonical() == canonical));

    let tx_index = match tx_index {
        Some(i) => i,
        None => bail!(
            "Package {} not found in block {}",
            canonical,
            &block_hash[..12]
        ),
    };

    // Build the Merkle proof.
    let proof = build_merkle_proof(&block, tx_index)?;

    // Build the header chain from genesis to this block for light-client verification.
    // In production this would only return headers from the last known checkpoint.
    // For now we return the full chain (efficient for a registry with few blocks).
    let mut header_chain: Vec<(BlockHeader, String)> = Vec::new();
    for h in 1..block.header.height {
        if let Ok(Some(b)) = chain.get_block_by_height(h) {
            header_chain.push((b.header.clone(), b.hash()));
        }
    }
    // Include the package block itself.
    header_chain.push((block.header.clone(), block.hash()));

    Ok(Some(LightClientResponse {
        status: "verified".into(),
        block_hash: block.hash(),
        block_header: block.header,
        proof,
        header_chain,
        pbft_signatures: block.pbft_signatures,
        active_validators: active_validators.to_vec(),
    }))
}
