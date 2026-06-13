//! # PostgreSQL Sync Worker for Chain Registry
//!
//! This crate implements an ETL pipeline that mirrors finalized on-chain data
//! from sled into PostgreSQL. It enables fast queries, search, and analytics
//! without hitting the embedded chain database.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────┐     poll      ┌─────────────┐     UPSERT     ┌─────────────┐
//! │  sled DB    │ ◄──────────── │  SyncWorker │ ─────────────► │  PostgreSQL │
//! └─────────────┘   every 1s    └─────────────┘   in batches   └─────────────┘
//! ```
//!
//! The sync worker:
//! 1. Polls `chain_store` for new blocks every 1 second
//! 2. Extracts `Publish`, `Revoke`, `Slash`, `RotatePublisherKey` transactions
//! 3. Applies idempotent UPSERTs to PostgreSQL tables
//! 4. Tracks sync cursor (`last_synced_height`) in a `sync_state` table
//!
//! ## PostgreSQL Schema
//!
//! Tables managed by this crate:
//! - `packages` — mirror of verified package records
//! - `validator_votes` — per-package validator signatures
//! - `blocks` — block headers for explorer queries
//! - `publisher_stats` — aggregated publisher metrics
//! - `sync_state` — cursor tracking

use anyhow::{Context, Result};
use common::{Block, ChainRecord, PackageStatus, Transaction};
use sqlx::{postgres::PgQueryResult, PgPool};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

pub mod schema;
pub mod sync_worker;

pub use sync_worker::{ChainStoreProxy, SyncWorker};

/// Connection string validation helper.
pub fn validate_connection_string(url: &str) -> Result<()> {
    if !url.starts_with("postgres://") {
        anyhow::bail!("PostgreSQL URL must start with postgres://");
    }
    Ok(())
}

/// Idempotently apply a block's transactions to PostgreSQL.
pub async fn apply_block(pool: &PgPool, block: &Block) -> Result<()> {
    let mut tx = pool.begin().await.context("begin PG transaction")?;

    for transaction in &block.transactions {
        match transaction {
            Transaction::Publish(record) => {
                upsert_package(&mut *tx, record).await?;
                for sig in &record.validator_signatures {
                    upsert_validator_vote(&mut *tx, &record.id.canonical(), sig).await?;
                }
            }
            Transaction::Revoke {
                package_canonical,
                reason,
                ..
            } => {
                sqlx::query(
                    "UPDATE packages SET status = 'revoked', revocation_reason = $1 WHERE canonical = $2"
                )
                .bind(reason)
                .bind(package_canonical)
                .execute(&mut *tx)
                .await?;
            }
            Transaction::RotatePublisherKey {
                canonical_prefix,
                old_pubkey,
                new_pubkey,
                timestamp,
                ..
            } => {
                sqlx::query(
                    "UPDATE packages SET publisher_pubkey = $1, updated_at = $2 WHERE canonical LIKE $3 AND publisher_pubkey = $4"
                )
                .bind(new_pubkey)
                .bind(timestamp)
                .bind(format!("{}%", canonical_prefix))
                .bind(old_pubkey)
                .execute(&mut *tx)
                .await?;
            }
            _ => {} // ValidatorJoin / ValidatorLeave / Slash handled by aggregator later
        }
    }

    // Record block header for explorer queries
    sqlx::query(
        "INSERT INTO blocks (height, hash, prev_hash, merkle_root, proposer_id, timestamp)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (height) DO NOTHING",
    )
    .bind(block.header.height as i64)
    .bind(&block.hash())
    .bind(&block.header.prev_hash)
    .bind(&block.header.merkle_root)
    .bind(&block.header.proposer_id)
    .bind(block.header.timestamp)
    .execute(&mut *tx)
    .await?;

    tx.commit().await.context("commit PG transaction")?;
    Ok(())
}

async fn upsert_package<'e, E>(executor: E, record: &ChainRecord) -> Result<()>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let status_str = match &record.status {
        PackageStatus::Verified => "verified",
        PackageStatus::Pending => "pending",
        PackageStatus::Revoked { .. } => "revoked",
    };
    let findings_json = serde_json::to_value(&record.findings).unwrap_or_default();

    sqlx::query(
        "INSERT INTO packages (
            canonical, ecosystem, name, version, status, content_hash,
            ipfs_cid, publisher_pubkey, block_hash, published_at,
            shielded, findings, access_count, last_accessed
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
        ON CONFLICT (canonical) DO UPDATE SET
            status = EXCLUDED.status,
            content_hash = EXCLUDED.content_hash,
            ipfs_cid = EXCLUDED.ipfs_cid,
            publisher_pubkey = EXCLUDED.publisher_pubkey,
            block_hash = EXCLUDED.block_hash,
            findings = EXCLUDED.findings,
            updated_at = NOW()",
    )
    .bind(record.id.canonical())
    .bind(&record.id.ecosystem)
    .bind(&record.id.name)
    .bind(&record.id.version)
    .bind(status_str)
    .bind(&record.content_hash)
    .bind(&record.ipfs_cid)
    .bind(&record.publisher_pubkey)
    .bind(&record.block_hash)
    .bind(record.published_at)
    .bind(record.shielded)
    .bind(findings_json)
    .bind(record.access_count as i32)
    .bind(record.last_accessed)
    .execute(executor)
    .await?;

    Ok(())
}

async fn upsert_validator_vote<'e, E>(
    executor: E,
    canonical: &str,
    sig: &common::ValidatorSignature,
) -> Result<()>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let vote_str = match &sig.vote {
        common::ValidatorVote::Approve => "approve",
        common::ValidatorVote::Reject { .. } => "reject",
    };
    let reason = match &sig.vote {
        common::ValidatorVote::Approve => None,
        common::ValidatorVote::Reject { reason } => Some(reason.clone()),
    };

    sqlx::query(
        "INSERT INTO validator_votes (
            canonical, validator_id, validator_pubkey, signature, vote, reason, signed_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (canonical, validator_id) DO UPDATE SET
            signature = EXCLUDED.signature,
            vote = EXCLUDED.vote,
            reason = EXCLUDED.reason,
            signed_at = EXCLUDED.signed_at",
    )
    .bind(canonical)
    .bind(&sig.validator_id)
    .bind(&sig.validator_pubkey)
    .bind(&sig.signature)
    .bind(vote_str)
    .bind(reason)
    .bind(sig.signed_at)
    .execute(executor)
    .await?;

    Ok(())
}
