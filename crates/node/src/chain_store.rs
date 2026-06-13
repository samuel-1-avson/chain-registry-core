// crates/node/src/chain_store.rs
// Persistent storage for the blockchain using RocksDB.
// Stores blocks by height and by hash, and a package index by canonical ID.
// Replaced sled for better write amplification, compaction, and snapshot support.

use anyhow::{Context, Result};
use common::{Block, ChainRecord, PackageStatus};
use rocksdb::{ColumnFamilyDescriptor, Options, DB};
use semver;
use sled;
use std::path::Path;
use std::sync::Arc;

const CF_BLOCKS_BY_HASH: &str = "blocks_by_hash";
const CF_BLOCKS_BY_HEIGHT: &str = "blocks_by_height";
const CF_PACKAGES: &str = "packages";

#[derive(Clone)]
pub struct ChainStore {
    db: Arc<DB>,
}

impl ChainStore {
    pub fn open(data_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(data_dir)?;

        let db_path = data_dir.join("chain.rocksdb");

        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        // Tuning for write-heavy workload (block insertion + package indexing).
        opts.set_write_buffer_size(64 * 1024 * 1024); // 64 MB memtable
        opts.set_max_write_buffer_number(3);
        opts.set_target_file_size_base(64 * 1024 * 1024);
        opts.set_level_compaction_dynamic_level_bytes(true);
        opts.set_max_background_jobs(4);

        let cf_opts = Options::default();
        let cfs = vec![
            ColumnFamilyDescriptor::new(CF_BLOCKS_BY_HASH, cf_opts.clone()),
            ColumnFamilyDescriptor::new(CF_BLOCKS_BY_HEIGHT, cf_opts.clone()),
            ColumnFamilyDescriptor::new(CF_PACKAGES, cf_opts),
        ];

        let db = DB::open_cf_descriptors(&opts, &db_path, cfs).context("Failed to open RocksDB")?;

        let store = Self { db: Arc::new(db) };

        // Write the genesis block if the chain is empty.
        if store.tip_height()? == 0 && store.block_count() == 0 {
            let genesis = Block::genesis();
            store.insert_block(&genesis)?;
            tracing::info!("Chain initialised with genesis block");
        }

        Ok(store)
    }

    pub fn open_read_only(data_dir: &Path) -> Result<Self> {
        let db_path = data_dir.join("chain.rocksdb");
        if !db_path.exists() {
            anyhow::bail!(
                "Chain database not found at {}. Start a node with CREG_DATA_DIR={} first.",
                db_path.display(),
                data_dir.display()
            );
        }

        let opts = Options::default();
        let cfs = vec![CF_BLOCKS_BY_HASH, CF_BLOCKS_BY_HEIGHT, CF_PACKAGES];
        let db = DB::open_cf_for_read_only(&opts, &db_path, cfs, false)
            .context("Failed to open RocksDB in read-only mode")?;

        Ok(Self { db: Arc::new(db) })
    }

    /// Migrate data from a legacy sled database into this RocksDB store.
    /// Call once at startup if the sled directory still exists.
    pub fn migrate_from_sled(&self, sled_dir: &Path) -> Result<u64> {
        let sled_db_path = sled_dir.join("chain.db");
        if !sled_db_path.exists() {
            return Ok(0);
        }
        tracing::info!("Migrating data from sled → RocksDB ...");

        let sled_db = sled::open(&sled_db_path).context("open legacy sled DB")?;
        let mut migrated = 0u64;

        // Migrate blocks_by_hash
        if let Ok(tree) = sled_db.open_tree("blocks_by_hash") {
            let cf = self
                .db
                .cf_handle(CF_BLOCKS_BY_HASH)
                .context("cf blocks_by_hash")?;
            for item in tree.iter() {
                let (k, v) = item?;
                self.db.put_cf(&cf, &k, &v)?;
                migrated += 1;
            }
        }

        // Migrate blocks_by_height
        if let Ok(tree) = sled_db.open_tree("blocks_by_height") {
            let cf = self
                .db
                .cf_handle(CF_BLOCKS_BY_HEIGHT)
                .context("cf blocks_by_height")?;
            for item in tree.iter() {
                let (k, v) = item?;
                self.db.put_cf(&cf, &k, &v)?;
                migrated += 1;
            }
        }

        // Migrate packages
        if let Ok(tree) = sled_db.open_tree("packages") {
            let cf = self.db.cf_handle(CF_PACKAGES).context("cf packages")?;
            for item in tree.iter() {
                let (k, v) = item?;
                self.db.put_cf(&cf, &k, &v)?;
                migrated += 1;
            }
        }

        tracing::info!("Migrated {} records from sled → RocksDB", migrated);
        Ok(migrated)
    }

    // ── Block operations ─────────────────────────────────────────────────────

    /// Insert a block, detecting whether it replaces a different block that
    /// was already finalized at the same height (i.e. a fork / reorg).
    ///
    /// Returns the outcome so callers can record a `ReorgEvent` when a
    /// replacement happened instead of silently overwriting history.
    pub fn insert_block_with_outcome(&self, block: &Block) -> Result<BlockInsertOutcome> {
        let new_hash = block.hash();
        let replaced_hash = match self.get_block_by_height(block.header.height)? {
            Some(existing) => {
                let existing_hash = existing.hash();
                if existing_hash != new_hash {
                    Some(existing_hash)
                } else {
                    None
                }
            }
            None => None,
        };
        self.insert_block(block)?;
        Ok(BlockInsertOutcome {
            hash: new_hash,
            replaced_hash,
        })
    }

    /// Remove the height index for every block above `height`, returning the
    /// hashes of the abandoned blocks (highest first). The blocks themselves
    /// remain retrievable by hash so abandoned forks stay inspectable in the
    /// explorer; only the canonical height → hash mapping is rewound.
    ///
    /// Callers MUST rebuild derived state (package index, publisher index)
    /// afterwards via `rebuild_package_index` + `PublisherIndex::rebuild_from_chain`.
    pub fn rollback_to_height(&self, height: u64) -> Result<Vec<String>> {
        let tip = self.tip_height()?;
        if tip <= height {
            return Ok(vec![]);
        }
        let cf_height = self
            .db
            .cf_handle(CF_BLOCKS_BY_HEIGHT)
            .context("cf blocks_by_height")?;

        let mut abandoned = Vec::new();
        let mut batch = rocksdb::WriteBatch::default();
        for h in ((height + 1)..=tip).rev() {
            if let Some(hash_bytes) = self.db.get_cf(&cf_height, h.to_be_bytes())? {
                abandoned.push(String::from_utf8_lossy(&hash_bytes).to_string());
            }
            batch.delete_cf(&cf_height, h.to_be_bytes());
        }
        self.db.write(batch)?;
        tracing::warn!(
            "Chain rolled back from height {} to {} ({} blocks abandoned)",
            tip,
            height,
            abandoned.len()
        );
        Ok(abandoned)
    }

    /// Rebuild the package index (CF_PACKAGES) by replaying every canonical
    /// block from genesis to the current tip. Required after a reorg rewind so
    /// records indexed from abandoned blocks don't linger.
    pub fn rebuild_package_index(&self) -> Result<()> {
        let cf_pkg = self.db.cf_handle(CF_PACKAGES).context("cf packages")?;

        // Clear the existing index.
        let keys: Vec<Box<[u8]>> = self
            .db
            .iterator_cf(&cf_pkg, rocksdb::IteratorMode::Start)
            .filter_map(|item| item.ok().map(|(k, _)| k))
            .collect();
        let mut batch = rocksdb::WriteBatch::default();
        for key in keys {
            batch.delete_cf(&cf_pkg, key);
        }
        self.db.write(batch)?;

        // Replay the canonical chain. insert_block re-indexes Publish /
        // Revoke / RotatePublisherKey transactions idempotently.
        let tip = self.tip_height()?;
        for h in 0..=tip {
            if let Some(block) = self.get_block_by_height(h)? {
                self.insert_block(&block)?;
            }
        }
        tracing::info!("Package index rebuilt from canonical chain (tip {})", tip);
        Ok(())
    }

    pub fn insert_block(&self, block: &Block) -> Result<()> {
        let hash = block.hash();
        let bytes = serde_json::to_vec(block)?;
        let height_key = block.header.height.to_be_bytes();

        let cf_hash = self
            .db
            .cf_handle(CF_BLOCKS_BY_HASH)
            .context("cf blocks_by_hash")?;
        let cf_height = self
            .db
            .cf_handle(CF_BLOCKS_BY_HEIGHT)
            .context("cf blocks_by_height")?;
        let cf_pkg = self.db.cf_handle(CF_PACKAGES).context("cf packages")?;

        // Use a WriteBatch for atomicity.
        let mut batch = rocksdb::WriteBatch::default();
        batch.put_cf(&cf_hash, hash.as_bytes(), &bytes);
        batch.put_cf(&cf_height, height_key, hash.as_bytes());

        // Index every Publish transaction into the package tree.
        for tx in &block.transactions {
            if let common::Transaction::Publish(record) = tx {
                // Update block_hash to the real finalized hash before persisting.
                let mut rec = record.clone();
                rec.block_hash = hash.clone();
                let rec_bytes = serde_json::to_vec(&rec)?;
                batch.put_cf(&cf_pkg, rec.id.canonical().as_bytes(), &rec_bytes);
            }
            if let common::Transaction::Revoke {
                package_canonical,
                reason,
                ..
            } = tx
            {
                if let Some(existing) = self.db.get_cf(&cf_pkg, package_canonical.as_bytes())? {
                    if let Ok(mut rec) = serde_json::from_slice::<ChainRecord>(&existing) {
                        rec.status = PackageStatus::Revoked {
                            reason: reason.clone(),
                        };
                        let updated = serde_json::to_vec(&rec)?;
                        batch.put_cf(&cf_pkg, package_canonical.as_bytes(), &updated);
                    }
                }
            }
            if let common::Transaction::RotatePublisherKey {
                canonical_prefix,
                old_pubkey,
                new_pubkey,
                ..
            } = tx
            {
                let prefix = canonical_prefix.as_bytes();
                let iter = self.db.prefix_iterator_cf(&cf_pkg, prefix);
                for item in iter {
                    let (key_bytes, val_bytes) = item?;
                    if !key_bytes.starts_with(prefix) {
                        break;
                    }
                    if let Ok(mut rec) = serde_json::from_slice::<ChainRecord>(&val_bytes) {
                        if rec.publisher_pubkey == *old_pubkey {
                            rec.publisher_pubkey = new_pubkey.clone();
                            if let Ok(updated) = serde_json::to_vec(&rec) {
                                batch.put_cf(&cf_pkg, &*key_bytes, &updated);
                            }
                        }
                    }
                }
            }
        }

        self.db.write(batch)?;

        tracing::info!(
            "Block {} inserted (height {})",
            &hash[..hash.len().min(12)],
            block.header.height
        );
        Ok(())
    }

    pub fn get_block_by_hash(&self, hash: &str) -> Result<Option<Block>> {
        let cf = self
            .db
            .cf_handle(CF_BLOCKS_BY_HASH)
            .context("cf blocks_by_hash")?;
        match self.db.get_cf(&cf, hash.as_bytes())? {
            None => Ok(None),
            Some(b) => Ok(Some(serde_json::from_slice(&b)?)),
        }
    }

    pub fn get_block_by_height(&self, height: u64) -> Result<Option<Block>> {
        let cf = self
            .db
            .cf_handle(CF_BLOCKS_BY_HEIGHT)
            .context("cf blocks_by_height")?;
        match self.db.get_cf(&cf, height.to_be_bytes())? {
            None => Ok(None),
            Some(hash_bytes) => {
                let hash = std::str::from_utf8(&hash_bytes)?;
                self.get_block_by_hash(hash)
            }
        }
    }

    /// Return up to `limit` blocks in descending height order starting from
    /// `tip_height - offset`.  Used for paginated API responses.
    pub fn list_blocks(&self, offset: u64, limit: u64) -> Result<Vec<Block>> {
        let tip = self.tip_height()?;
        if tip == 0 {
            return Ok(vec![]);
        }
        let start_height = tip.saturating_sub(offset);
        let mut blocks = Vec::with_capacity(limit as usize);
        let mut height = start_height;
        while blocks.len() < limit as usize {
            match self.get_block_by_height(height)? {
                Some(b) => blocks.push(b),
                None => break,
            }
            if height == 0 {
                break;
            }
            height -= 1;
        }
        Ok(blocks)
    }

    pub fn tip_height(&self) -> Result<u64> {
        let cf = self
            .db
            .cf_handle(CF_BLOCKS_BY_HEIGHT)
            .context("cf blocks_by_height")?;
        let mut iter = self.db.raw_iterator_cf(&cf);
        iter.seek_to_last();
        if iter.valid() {
            if let Some(key) = iter.key() {
                let bytes: [u8; 8] = key.try_into().unwrap_or([0; 8]);
                return Ok(u64::from_be_bytes(bytes));
            }
        }
        Ok(0)
    }

    pub fn tip_hash(&self) -> Result<String> {
        let height = self.tip_height()?;
        match self.get_block_by_height(height)? {
            Some(b) => Ok(b.hash()),
            None => Ok("0".repeat(64)),
        }
    }

    // ── Package index ─────────────────────────────────────────────────────────

    pub fn get_package(&self, canonical: &str) -> Result<Option<ChainRecord>> {
        let cf = self.db.cf_handle(CF_PACKAGES).context("cf packages")?;
        match self.db.get_cf(&cf, canonical.as_bytes())? {
            None => Ok(None),
            Some(b) => {
                let record: ChainRecord = serde_json::from_slice(&b)?;
                Ok(Some(record))
            }
        }
    }

    /// Mark a package as accessed and update metadata.
    pub fn mark_accessed(&self, canonical: &str) -> Result<()> {
        if let Some(mut record) = self.get_package(canonical)? {
            record.access_count += 1;
            record.last_accessed = Some(chrono::Utc::now());
            self.save_package(&record)?;
        }
        Ok(())
    }

    pub fn save_package(&self, record: &ChainRecord) -> Result<()> {
        let cf = self.db.cf_handle(CF_PACKAGES).context("cf packages")?;
        let bytes = serde_json::to_vec(record)?;
        self.db
            .put_cf(&cf, record.id.canonical().as_bytes(), &bytes)?;
        Ok(())
    }

    /// Find the latest verified version of a package in a given ecosystem.
    pub fn get_latest_version(&self, ecosystem: &str, name: &str) -> Result<Option<ChainRecord>> {
        let cf = self.db.cf_handle(CF_PACKAGES).context("cf packages")?;
        let prefix = format!("{}:{}", ecosystem, name);
        let mut latest: Option<ChainRecord> = None;

        for item in self.db.prefix_iterator_cf(&cf, prefix.as_bytes()) {
            let (key, bytes) = item?;
            if !key.starts_with(prefix.as_bytes()) {
                break;
            }
            let record: ChainRecord = serde_json::from_slice(&bytes)?;

            if record.status == PackageStatus::Verified {
                let is_newer = match &latest {
                    None => true,
                    Some(current) => {
                        // Parse as semver for correct ordering (e.g., 9.0.0 < 10.0.0).
                        // Fall back to string comparison if either version is non-semver.
                        let new_ver = semver::Version::parse(&record.id.version);
                        let cur_ver = semver::Version::parse(&current.id.version);
                        match (new_ver, cur_ver) {
                            (Ok(nv), Ok(cv)) => nv > cv,
                            _ => record.id.version > current.id.version,
                        }
                    }
                };
                if is_newer {
                    latest = Some(record);
                }
            }
        }
        Ok(latest)
    }

    pub fn package_count(&self) -> usize {
        let cf = match self.db.cf_handle(CF_PACKAGES) {
            Some(cf) => cf,
            None => return 0,
        };
        let mut count = 0usize;
        let mut iter = self.db.raw_iterator_cf(&cf);
        iter.seek_to_first();
        while iter.valid() {
            count += 1;
            iter.next();
        }
        count
    }

    /// Check whether `publisher_pubkey` owns at least one package with the given prefix.
    pub fn has_publisher_for_prefix(&self, prefix: &str, publisher_pubkey: &str) -> bool {
        let cf = match self.db.cf_handle(CF_PACKAGES) {
            Some(cf) => cf,
            None => return false,
        };
        for item in self.db.prefix_iterator_cf(&cf, prefix.as_bytes()) {
            let Ok((key, bytes)) = item else { continue };
            if !key.starts_with(prefix.as_bytes()) {
                break;
            }
            if let Ok(record) = serde_json::from_slice::<ChainRecord>(&bytes) {
                if record.publisher_pubkey == publisher_pubkey {
                    return true;
                }
            }
        }
        false
    }

    /// Return the last-used rotation nonce for the given publisher pubkey.
    /// Returns 0 if no rotation has been recorded.
    pub fn publisher_rotation_nonce(&self, pubkey: &str) -> Option<u64> {
        // Scan all blocks in reverse for the most recent RotatePublisherKey
        // transaction matching this pubkey.  A dedicated CF would be more
        // efficient at scale, but this is correct for now.
        let tip = self.tip_height().ok()?;
        for h in (0..=tip).rev() {
            if let Ok(Some(block)) = self.get_block_by_height(h) {
                for tx in &block.transactions {
                    if let common::Transaction::RotatePublisherKey {
                        old_pubkey, nonce, ..
                    } = tx
                    {
                        if old_pubkey == pubkey {
                            return Some(*nonce);
                        }
                    }
                }
            }
        }
        Some(0)
    }

    /// Return the timestamp of the most recent key rotation by this pubkey.
    /// Used to enforce a cooldown period between rotations.
    pub fn publisher_last_rotation_time(
        &self,
        pubkey: &str,
    ) -> Option<chrono::DateTime<chrono::Utc>> {
        let tip = self.tip_height().ok()?;
        for h in (0..=tip).rev() {
            if let Ok(Some(block)) = self.get_block_by_height(h) {
                for tx in &block.transactions {
                    if let common::Transaction::RotatePublisherKey { old_pubkey, .. } = tx {
                        if old_pubkey == pubkey {
                            return Some(block.header.timestamp);
                        }
                    }
                }
            }
        }
        None
    }

    // ── Chain stats ───────────────────────────────────────────────────────────

    /// List packages with pagination and optional filters.
    ///
    /// Returns `(records, total_matching)` where `total_matching` is the count
    /// of all records that pass the filters (before offset/limit).
    pub fn list_packages(
        &self,
        offset: usize,
        limit: usize,
        ecosystem: Option<&str>,
        status: Option<&PackageStatus>,
    ) -> Result<(Vec<ChainRecord>, usize)> {
        let cf = self.db.cf_handle(CF_PACKAGES).context("cf packages")?;
        let mut matching = Vec::new();

        let iter_box: Box<dyn Iterator<Item = Result<(Box<[u8]>, Box<[u8]>), rocksdb::Error>>> =
            if let Some(eco) = ecosystem {
                Box::new(
                    self.db
                        .prefix_iterator_cf(&cf, format!("{}:", eco).as_bytes()),
                )
            } else {
                Box::new(self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start))
            };

        for item in iter_box {
            let (key, bytes) = item?;
            if let Some(eco) = ecosystem {
                let prefix = format!("{}:", eco);
                if !key.starts_with(prefix.as_bytes()) {
                    break;
                }
            }
            let record: ChainRecord = serde_json::from_slice(&bytes)?;

            if let Some(st) = status {
                let matches = match (st, &record.status) {
                    (PackageStatus::Verified, PackageStatus::Verified) => true,
                    (PackageStatus::Pending, PackageStatus::Pending) => true,
                    (PackageStatus::Revoked { .. }, PackageStatus::Revoked { .. }) => true,
                    _ => false,
                };
                if !matches {
                    continue;
                }
            }

            matching.push(record);
        }

        let total = matching.len();
        let page: Vec<ChainRecord> = matching.into_iter().skip(offset).take(limit).collect();
        Ok((page, total))
    }

    fn block_count(&self) -> usize {
        let cf = match self.db.cf_handle(CF_BLOCKS_BY_HEIGHT) {
            Some(cf) => cf,
            None => return 0,
        };
        let mut count = 0usize;
        let mut iter = self.db.raw_iterator_cf(&cf);
        iter.seek_to_first();
        while iter.valid() {
            count += 1;
            iter.next();
        }
        count
    }

    pub fn stats(&self) -> ChainStats {
        ChainStats {
            tip_height: self.tip_height().unwrap_or(0),
            tip_hash: self.tip_hash().unwrap_or_default(),
            package_count: self.package_count(),
            block_count: self.block_count(),
        }
    }
}

/// Result of `insert_block_with_outcome`.
#[derive(Clone, Debug)]
pub struct BlockInsertOutcome {
    /// Hash of the inserted block.
    pub hash: String,
    /// Hash of a *different* block that previously occupied the same height,
    /// if any. `Some(_)` means a fork replaced finalized history and the
    /// caller should record a reorg event.
    pub replaced_hash: Option<String>,
}

#[derive(serde::Serialize)]
pub struct ChainStats {
    pub tip_height: u64,
    pub tip_hash: String,
    pub package_count: usize,
    pub block_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use common::{
        merkle_root, AnalysisBundleRefs, Block, BlockHeader, ChainRecord, DeterministicRiskSummary,
        PackageId, Transaction,
    };

    fn publish_record(name: &str) -> ChainRecord {
        ChainRecord {
            id: PackageId::new("npm", name, "1.0.0"),
            content_hash: common::sha256_hex(name.as_bytes()),
            ipfs_cid: "bafytestcid".into(),
            publisher_pubkey: "publisher-pubkey".into(),
            block_hash: String::new(),
            published_at: Utc::now(),
            validator_signatures: vec![],
            status: PackageStatus::Verified,
            shielded: false,
            key_bundle: None,
            pgp_fingerprint: None,
            findings: vec![],
            analysis_bundles: AnalysisBundleRefs::default(),
            evidence_digest: String::new(),
            deterministic_risk: DeterministicRiskSummary::default(),
            access_count: 0,
            last_accessed: None,
            threshold: 0,
            publisher_pubkeys: vec![],
            manifest: None,
        }
    }

    fn block(height: u64, prev_hash: &str, proposer: &str, packages: &[&str]) -> Block {
        let transactions: Vec<Transaction> = packages
            .iter()
            .map(|name| Transaction::Publish(publish_record(name)))
            .collect();
        Block {
            header: BlockHeader {
                height,
                prev_hash: prev_hash.to_string(),
                merkle_root: merkle_root(&transactions),
                proposer_id: proposer.into(),
                timestamp: Utc::now(),
                validator_set_hash: "test".into(),
                vrf_output: None,
                vrf_proof: None,
            },
            transactions,
            pbft_signatures: vec![],
        }
    }

    #[test]
    fn insert_block_with_outcome_detects_replacement() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ChainStore::open(dir.path()).expect("open");
        let genesis_hash = store.tip_hash().expect("tip hash");

        let block_a = block(1, &genesis_hash, "node-a", &["pkg-a"]);
        let outcome_a = store.insert_block_with_outcome(&block_a).expect("insert a");
        assert!(outcome_a.replaced_hash.is_none(), "first insert is no fork");

        // Re-inserting the identical block is not a replacement.
        let outcome_same = store
            .insert_block_with_outcome(&block_a)
            .expect("re-insert");
        assert!(outcome_same.replaced_hash.is_none());

        // A different block at the same height is a fork replacement.
        let block_b = block(1, &genesis_hash, "node-b", &["pkg-b"]);
        let outcome_b = store.insert_block_with_outcome(&block_b).expect("insert b");
        assert_eq!(outcome_b.replaced_hash, Some(block_a.hash()));
        assert_eq!(store.tip_hash().expect("tip"), block_b.hash());
    }

    #[test]
    fn rollback_and_rebuild_drop_abandoned_packages() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ChainStore::open(dir.path()).expect("open");
        let genesis_hash = store.tip_hash().expect("tip hash");

        let block1 = block(1, &genesis_hash, "node-a", &["kept"]);
        store.insert_block(&block1).expect("insert 1");
        let block2 = block(2, &block1.hash(), "node-a", &["abandoned"]);
        store.insert_block(&block2).expect("insert 2");

        assert!(store
            .get_package("npm:abandoned@1.0.0")
            .expect("get")
            .is_some());

        // Rewind to height 1: block 2 is abandoned but stays readable by hash.
        let abandoned = store.rollback_to_height(1).expect("rollback");
        assert_eq!(abandoned, vec![block2.hash()]);
        assert_eq!(store.tip_height().expect("tip"), 1);
        assert!(store
            .get_block_by_hash(&block2.hash())
            .expect("by hash")
            .is_some());

        // Rebuilding the package index removes records from abandoned blocks.
        store.rebuild_package_index().expect("rebuild");
        assert!(store.get_package("npm:kept@1.0.0").expect("get").is_some());
        assert!(store
            .get_package("npm:abandoned@1.0.0")
            .expect("get")
            .is_none());
    }
}
