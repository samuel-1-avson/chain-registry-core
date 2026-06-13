-- Optional tables for testnet faucet/metrics (do not duplicate db-sync core tables)

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

CREATE TABLE IF NOT EXISTS testnet_metrics (
    id SERIAL PRIMARY KEY,
    metric_name TEXT NOT NULL,
    metric_value NUMERIC NOT NULL,
    recorded_at TIMESTAMPTZ DEFAULT NOW()
);
