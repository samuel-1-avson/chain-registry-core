// crates/node/src/db_sync_proxy.rs
// Bridges the concrete ChainStore to the db-sync worker trait.

use db_sync::sync_worker::ChainStoreProxy;

impl ChainStoreProxy for crate::chain_store::ChainStore {
    fn tip_height(&self) -> anyhow::Result<u64> {
        Ok(self.tip_height()?)
    }

    fn get_block_by_height(&self, height: u64) -> anyhow::Result<Option<common::Block>> {
        Ok(self.get_block_by_height(height)?)
    }
}
