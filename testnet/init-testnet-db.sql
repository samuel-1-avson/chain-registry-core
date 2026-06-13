-- DEPRECATED: prefer chain-registry/migrations/001_db_sync_bootstrap.sql (+ 002_testnet_extras.sql).
-- This file duplicates core tables with different names (validator_signatures, chain_blocks).
-- Initialize testnet database schema
-- Chain Registry Testnet PostgreSQL Schema

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Packages table
CREATE TABLE IF NOT EXISTS packages (
    id SERIAL PRIMARY KEY,
    canonical TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'verified',
    content_hash TEXT NOT NULL DEFAULT '',
    ipfs_cid TEXT NOT NULL,
    publisher_pubkey TEXT NOT NULL,
    block_hash TEXT NOT NULL,
    published_at TIMESTAMPTZ NOT NULL,
    shielded BOOLEAN DEFAULT FALSE,
    findings JSONB DEFAULT '[]',
    access_count INTEGER DEFAULT 0,
    last_accessed TIMESTAMPTZ,
    revocation_reason TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for packages
CREATE INDEX IF NOT EXISTS idx_packages_canonical ON packages(canonical);
CREATE INDEX IF NOT EXISTS idx_packages_name ON packages(name);
CREATE INDEX IF NOT EXISTS idx_packages_publisher ON packages(publisher_pubkey);
CREATE INDEX IF NOT EXISTS idx_packages_status ON packages(status);
CREATE INDEX IF NOT EXISTS idx_packages_published_at ON packages(published_at);

-- Validator signatures/votes
CREATE TABLE IF NOT EXISTS validator_signatures (
    id SERIAL PRIMARY KEY,
    canonical TEXT NOT NULL,
    validator_id TEXT NOT NULL,
    validator_pubkey TEXT NOT NULL,
    signature TEXT NOT NULL,
    vote TEXT NOT NULL, -- 'approve', 'reject', 'abstain'
    reason TEXT,
    signed_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for signatures
CREATE INDEX IF NOT EXISTS idx_sigs_canonical ON validator_signatures(canonical);
CREATE INDEX IF NOT EXISTS idx_sigs_validator ON validator_signatures(validator_id);
CREATE INDEX IF NOT EXISTS idx_sigs_signed_at ON validator_signatures(signed_at);

-- Chain blocks
CREATE TABLE IF NOT EXISTS chain_blocks (
    id SERIAL PRIMARY KEY,
    height BIGINT NOT NULL UNIQUE,
    block_hash TEXT NOT NULL UNIQUE,
    parent_hash TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    proposer TEXT NOT NULL,
    tx_count INTEGER DEFAULT 0,
    data JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for blocks
CREATE INDEX IF NOT EXISTS idx_blocks_height ON chain_blocks(height);
CREATE INDEX IF NOT EXISTS idx_blocks_hash ON chain_blocks(block_hash);
CREATE INDEX IF NOT EXISTS idx_blocks_proposer ON chain_blocks(proposer);

-- Pending transactions
CREATE TABLE IF NOT EXISTS pending_tx (
    id SERIAL PRIMARY KEY,
    tx_hash TEXT NOT NULL UNIQUE,
    tx_type TEXT NOT NULL, -- 'publish', 'revoke', 'stake', etc.
    sender TEXT NOT NULL,
    data JSONB NOT NULL,
    status TEXT DEFAULT 'pending', -- 'pending', 'included', 'failed'
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pending_tx_status ON pending_tx(status);
CREATE INDEX IF NOT EXISTS idx_pending_tx_sender ON pending_tx(sender);

-- Faucet drips (for tracking)
CREATE TABLE IF NOT EXISTS faucet_drips (
    id SERIAL PRIMARY KEY,
    recipient TEXT NOT NULL,
    amount NUMERIC NOT NULL,
    tx_hash TEXT,
    ip_address INET,
    user_agent TEXT,
    dripped_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_faucet_recipient ON faucet_drips(recipient);
CREATE INDEX IF NOT EXISTS idx_faucet_dripped_at ON faucet_drips(dripped_at);

-- Testnet metrics
CREATE TABLE IF NOT EXISTS testnet_metrics (
    id SERIAL PRIMARY KEY,
    metric_name TEXT NOT NULL,
    metric_value NUMERIC NOT NULL,
    recorded_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert initial testnet marker
INSERT INTO testnet_metrics (metric_name, metric_value) 
VALUES ('testnet_initialized', 1)
ON CONFLICT DO NOTHING;

-- Create update trigger for updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply triggers
DROP TRIGGER IF EXISTS update_packages_updated_at ON packages;
CREATE TRIGGER update_packages_updated_at 
    BEFORE UPDATE ON packages 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_pending_tx_updated_at ON pending_tx;
CREATE TRIGGER update_pending_tx_updated_at 
    BEFORE UPDATE ON pending_tx 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Comments for documentation
COMMENT ON TABLE packages IS 'Published packages on the testnet';
COMMENT ON TABLE validator_signatures IS 'Validator votes on packages';
COMMENT ON TABLE chain_blocks IS 'Chain blocks for explorer';
COMMENT ON TABLE faucet_drips IS 'Testnet faucet distribution log';

-- =============================================================================
-- Data Retention & Partitioning (T-12)
-- =============================================================================

-- Retention policy: clean up old faucet drips (keep 30 days)
CREATE OR REPLACE FUNCTION cleanup_old_faucet_drips()
RETURNS void AS $$
BEGIN
    DELETE FROM faucet_drips WHERE dripped_at < NOW() - INTERVAL '30 days';
END;
$$ LANGUAGE plpgsql;

-- Retention policy: clean up old pending_tx that are resolved (keep 7 days)
CREATE OR REPLACE FUNCTION cleanup_resolved_pending_tx()
RETURNS void AS $$
BEGIN
    DELETE FROM pending_tx 
    WHERE status IN ('included', 'failed') 
      AND updated_at < NOW() - INTERVAL '7 days';
END;
$$ LANGUAGE plpgsql;

-- Block archival: archive blocks older than 90 days to a separate table
CREATE TABLE IF NOT EXISTS chain_blocks_archive (
    LIKE chain_blocks INCLUDING ALL
);

CREATE OR REPLACE FUNCTION archive_old_blocks()
RETURNS void AS $$
BEGIN
    INSERT INTO chain_blocks_archive 
    SELECT * FROM chain_blocks 
    WHERE created_at < NOW() - INTERVAL '90 days'
    ON CONFLICT DO NOTHING;
    
    DELETE FROM chain_blocks 
    WHERE created_at < NOW() - INTERVAL '90 days';
END;
$$ LANGUAGE plpgsql;

-- Height-based index for efficient range queries on blocks
CREATE INDEX IF NOT EXISTS idx_blocks_created_at ON chain_blocks(created_at);
CREATE INDEX IF NOT EXISTS idx_faucet_retention ON faucet_drips(dripped_at);

COMMENT ON FUNCTION cleanup_old_faucet_drips IS 'Run periodically: SELECT cleanup_old_faucet_drips()';
COMMENT ON FUNCTION cleanup_resolved_pending_tx IS 'Run periodically: SELECT cleanup_resolved_pending_tx()';
COMMENT ON FUNCTION archive_old_blocks IS 'Run weekly: SELECT archive_old_blocks()';
