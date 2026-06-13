//! Background sync worker: sled → PostgreSQL.

use anyhow::{Context, Result};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::time::{interval, Duration};
use tracing::{info, warn};

use crate::{apply_block, schema};

/// Shared chain store handle used by the sync worker.
pub type ChainStoreHandle = Arc<tokio::sync::RwLock<dyn ChainStoreProxy>>;

/// Thin proxy so the sync worker can call `get_block_by_height` without knowing
/// the concrete `ChainStore` type.
pub trait ChainStoreProxy: Send + Sync {
    fn tip_height(&self) -> anyhow::Result<u64>;
    fn get_block_by_height(&self, height: u64) -> anyhow::Result<Option<common::Block>>;
}

// NOTE: The concrete `ChainStoreProxy` implementation lives in the `node`
// crate (e.g. `node/src/db_sync_proxy.rs`) to avoid a circular dependency
// between `db-sync` and `node`.

/// Configuration for the sync worker.
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// How often to poll for new blocks (default: 1 second).
    pub poll_interval: Duration,
    /// PostgreSQL connection URL.
    pub pg_url: String,
    /// Maximum number of connections in the pool (default: 10).
    pub pg_max_connections: u32,
    /// Minimum number of idle connections to keep open (default: 2).
    pub pg_min_connections: u32,
    /// Timeout before an idle connection is reaped (default: 300 s).
    pub pg_idle_timeout: Duration,
    /// Maximum time to wait for a connection from the pool (default: 10 s).
    pub pg_acquire_timeout: Duration,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(1),
            pg_url: std::env::var("CREG_PG_URL")
                .unwrap_or_else(|_| "postgres://localhost/chain_registry".into()),
            pg_max_connections: 10,
            pg_min_connections: 2,
            pg_idle_timeout: Duration::from_secs(300),
            pg_acquire_timeout: Duration::from_secs(10),
        }
    }
}

/// The sync worker continuously mirrors new blocks into PostgreSQL.
pub struct SyncWorker {
    pool: PgPool,
    chain: ChainStoreHandle,
    config: SyncConfig,
}

impl SyncWorker {
    /// Create a new sync worker and ensure the PostgreSQL schema exists.
    pub async fn new(config: SyncConfig, chain: ChainStoreHandle) -> Result<Self> {
        crate::validate_connection_string(&config.pg_url)?;

        let pool = PgPoolOptions::new()
            .max_connections(config.pg_max_connections)
            .min_connections(config.pg_min_connections)
            .idle_timeout(config.pg_idle_timeout)
            .acquire_timeout(config.pg_acquire_timeout)
            .connect(&config.pg_url)
            .await
            .context("connect to PostgreSQL")?;

        // Bootstrap schema - execute statements individually for better error handling
        Self::bootstrap_schema(&pool)
            .await
            .context("bootstrap PG schema")?;

        info!("PostgreSQL sync worker connected");
        Ok(Self {
            pool,
            chain,
            config,
        })
    }

    /// Execute schema initialization statements.
    async fn bootstrap_schema(pool: &PgPool) -> Result<()> {
        // sync_state table
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS sync_state (
                id              INT PRIMARY KEY DEFAULT 1,
                last_height     BIGINT NOT NULL DEFAULT 0,
                updated_at      TIMESTAMPTZ DEFAULT NOW()
            )",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "INSERT INTO sync_state (id, last_height) VALUES (1, 0)
             ON CONFLICT (id) DO NOTHING",
        )
        .execute(pool)
        .await?;

        // packages table
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS packages (
                canonical        TEXT PRIMARY KEY,
                ecosystem        TEXT NOT NULL,
                name             TEXT NOT NULL,
                version          TEXT NOT NULL,
                status           TEXT NOT NULL CHECK (status IN ('verified', 'pending', 'revoked')),
                content_hash     TEXT NOT NULL,
                ipfs_cid         TEXT NOT NULL,
                publisher_pubkey TEXT NOT NULL,
                block_hash       TEXT NOT NULL,
                published_at     TIMESTAMPTZ NOT NULL,
                shielded         BOOLEAN DEFAULT FALSE,
                findings         JSONB DEFAULT '[]',
                access_count     INT DEFAULT 0,
                last_accessed    TIMESTAMPTZ,
                revocation_reason TEXT,
                created_at       TIMESTAMPTZ DEFAULT NOW(),
                updated_at       TIMESTAMPTZ DEFAULT NOW()
            )",
        )
        .execute(pool)
        .await?;

        // Backfill legacy local/testnet schemas that predate the dedicated indexer.
        sqlx::query(
            "ALTER TABLE packages ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'verified'",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "ALTER TABLE packages ADD COLUMN IF NOT EXISTS content_hash TEXT NOT NULL DEFAULT ''",
        )
        .execute(pool)
        .await?;
        sqlx::query("ALTER TABLE packages ADD COLUMN IF NOT EXISTS shielded BOOLEAN DEFAULT FALSE")
            .execute(pool)
            .await?;
        sqlx::query("ALTER TABLE packages ADD COLUMN IF NOT EXISTS findings JSONB DEFAULT '[]'")
            .execute(pool)
            .await?;
        sqlx::query("ALTER TABLE packages ADD COLUMN IF NOT EXISTS access_count INT DEFAULT 0")
            .execute(pool)
            .await?;
        sqlx::query("ALTER TABLE packages ADD COLUMN IF NOT EXISTS last_accessed TIMESTAMPTZ")
            .execute(pool)
            .await?;

        // Add revocation_reason column if missing (migration)
        sqlx::query("ALTER TABLE packages ADD COLUMN IF NOT EXISTS revocation_reason TEXT")
            .execute(pool)
            .await?;

        sqlx::query("UPDATE packages SET status = 'verified' WHERE status IS NULL")
            .execute(pool)
            .await?;
        sqlx::query("UPDATE packages SET content_hash = '' WHERE content_hash IS NULL")
            .execute(pool)
            .await?;
        sqlx::query("UPDATE packages SET shielded = FALSE WHERE shielded IS NULL")
            .execute(pool)
            .await?;
        sqlx::query("UPDATE packages SET findings = '[]'::jsonb WHERE findings IS NULL")
            .execute(pool)
            .await?;
        sqlx::query("UPDATE packages SET access_count = 0 WHERE access_count IS NULL")
            .execute(pool)
            .await?;

        // Create indexes
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_packages_ecosystem ON packages(ecosystem)")
            .execute(pool)
            .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_packages_publisher ON packages(publisher_pubkey)",
        )
        .execute(pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_packages_status ON packages(status)")
            .execute(pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_packages_name ON packages(name)")
            .execute(pool)
            .await?;

        // validator_votes table
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS validator_votes (
                id               BIGSERIAL PRIMARY KEY,
                canonical        TEXT NOT NULL,
                validator_id     TEXT NOT NULL,
                validator_pubkey TEXT NOT NULL,
                signature        TEXT NOT NULL,
                vote             TEXT NOT NULL CHECK (vote IN ('approve', 'reject')),
                reason           TEXT,
                signed_at        TIMESTAMPTZ NOT NULL,
                created_at       TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE (canonical, validator_id)
            )",
        )
        .execute(pool)
        .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_votes_canonical ON validator_votes(canonical)")
            .execute(pool)
            .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_votes_validator ON validator_votes(validator_id)",
        )
        .execute(pool)
        .await?;

        // blocks table
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS blocks (
                height           BIGINT PRIMARY KEY,
                hash             TEXT NOT NULL UNIQUE,
                prev_hash        TEXT NOT NULL,
                merkle_root      TEXT NOT NULL,
                proposer_id      TEXT NOT NULL,
                timestamp        TIMESTAMPTZ NOT NULL,
                created_at       TIMESTAMPTZ DEFAULT NOW()
            )",
        )
        .execute(pool)
        .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_blocks_hash ON blocks(hash)")
            .execute(pool)
            .await?;

        // publisher_stats table
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS publisher_stats (
                pubkey           TEXT PRIMARY KEY,
                total_packages   INT DEFAULT 0,
                verified_count   INT DEFAULT 0,
                revoked_count    INT DEFAULT 0,
                stake_wei        BIGINT DEFAULT 0,
                first_seen_at    TIMESTAMPTZ,
                first_seen_days  INT DEFAULT 0,
                updated_at       TIMESTAMPTZ DEFAULT NOW()
            )",
        )
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Start the background sync loop.
    pub async fn run(self) {
        let mut ticker = interval(self.config.poll_interval);
        loop {
            ticker.tick().await;
            if let Err(e) = self.tick().await {
                warn!("Sync worker error: {}", e);
            }
        }
    }

    async fn tick(&self) -> Result<()> {
        let tip = {
            let chain = self.chain.read().await;
            chain.tip_height().context("read tip height")?
        };

        let last_synced: i64 =
            sqlx::query_scalar("SELECT last_height FROM sync_state WHERE id = 1")
                .fetch_one(&self.pool)
                .await
                .context("fetch sync cursor")?;

        let last_synced = last_synced as u64;
        if tip <= last_synced {
            return Ok(());
        }

        info!("Syncing blocks {} → {}", last_synced + 1, tip);

        for height in (last_synced + 1)..=tip {
            let block = {
                let chain = self.chain.read().await;
                chain
                    .get_block_by_height(height)
                    .with_context(|| format!("read block {}", height))?
            };

            if let Some(block) = block {
                crate::apply_block(&self.pool, &block)
                    .await
                    .with_context(|| format!("apply block {}", height))?;

                sqlx::query(
                    "UPDATE sync_state SET last_height = $1, updated_at = NOW() WHERE id = 1",
                )
                .bind(height as i64)
                .execute(&self.pool)
                .await
                .context("update sync cursor")?;
            } else {
                warn!("Block {} missing during sync", height);
                break;
            }
        }

        Ok(())
    }
}
