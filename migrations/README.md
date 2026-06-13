# PostgreSQL migrations (`db-sync`)

Canonical schema for the indexer / `db-sync` service. Apply in order:

1. `001_db_sync_bootstrap.sql` — core tables
2. `002_testnet_extras.sql` — testnet-only extensions

Legacy bootstrap SQL in `testnet/init-testnet-db.sql` is deprecated; new environments should use these files only.
