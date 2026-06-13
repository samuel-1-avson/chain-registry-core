-- Canonical Chain Registry mirror schema (matches crates/db-sync/src/schema.rs INIT_SQL)
-- Sync cursor tracking
CREATE TABLE IF NOT EXISTS sync_state (
    id              INT PRIMARY KEY DEFAULT 1,
    last_height     BIGINT NOT NULL DEFAULT 0,
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO sync_state (id, last_height) VALUES (1, 0)
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS packages (
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
);

ALTER TABLE packages ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'verified';
ALTER TABLE packages ADD COLUMN IF NOT EXISTS content_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE packages ADD COLUMN IF NOT EXISTS shielded BOOLEAN DEFAULT FALSE;
ALTER TABLE packages ADD COLUMN IF NOT EXISTS findings JSONB DEFAULT '[]';
ALTER TABLE packages ADD COLUMN IF NOT EXISTS access_count INT DEFAULT 0;
ALTER TABLE packages ADD COLUMN IF NOT EXISTS last_accessed TIMESTAMPTZ;
ALTER TABLE packages ADD COLUMN IF NOT EXISTS revocation_reason TEXT;

CREATE INDEX IF NOT EXISTS idx_packages_ecosystem ON packages(ecosystem);
CREATE INDEX IF NOT EXISTS idx_packages_publisher  ON packages(publisher_pubkey);
CREATE INDEX IF NOT EXISTS idx_packages_status     ON packages(status);
CREATE INDEX IF NOT EXISTS idx_packages_name       ON packages(name);

CREATE TABLE IF NOT EXISTS validator_votes (
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
);

CREATE INDEX IF NOT EXISTS idx_votes_canonical    ON validator_votes(canonical);
CREATE INDEX IF NOT EXISTS idx_votes_validator    ON validator_votes(validator_id);

CREATE TABLE IF NOT EXISTS blocks (
    height           BIGINT PRIMARY KEY,
    hash             TEXT NOT NULL UNIQUE,
    prev_hash        TEXT NOT NULL,
    merkle_root      TEXT NOT NULL,
    proposer_id      TEXT NOT NULL,
    timestamp        TIMESTAMPTZ NOT NULL,
    created_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_blocks_hash ON blocks(hash);

CREATE TABLE IF NOT EXISTS publisher_stats (
    pubkey           TEXT PRIMARY KEY,
    total_packages   INT DEFAULT 0,
    verified_count   INT DEFAULT 0,
    revoked_count    INT DEFAULT 0,
    stake_wei        BIGINT DEFAULT 0,
    first_seen_at    TIMESTAMPTZ,
    first_seen_days  INT DEFAULT 0,
    updated_at       TIMESTAMPTZ DEFAULT NOW()
);
