# Database Schema

## Source of truth

**Canonical schema:** `chain-registry/crates/db-sync/src/schema.rs` (`INIT_SQL`)

Applied automatically by:

- `creg-indexer` / `db-sync` sync worker on startup
- `chain-registry/migrations/001_db_sync_bootstrap.sql` (same DDL for manual ops)

## Tables (db-sync)

| Table | Purpose |
|-------|---------|
| `sync_state` | Last mirrored block height |
| `packages` | Package records (PK: `canonical`) |
| `validator_votes` | Per-package validator votes |
| `blocks` | Block headers (PK: `height`) |
| `publisher_stats` | Aggregated publisher metrics |

## Legacy testnet SQL

`chain-registry/testnet/init-testnet-db.sql` historically defined overlapping tables (`validator_signatures`, `chain_blocks`, etc.). **Do not use both bootstraps on the same database.**

For new environments:

1. Run `migrations/001_db_sync_bootstrap.sql`
2. Optionally run `migrations/002_testnet_extras.sql` for faucet/metrics tables

## Node read path

The validator node serves REST from **RocksDB**, not PostgreSQL. PG is a **mirror** for analytics/explorer indexing.
