// crates/node/src/pending_pool.rs
// Pending pool for packages submitted but not yet finalized through PBFT.
// Persisted to `<data_dir>/pending_pool.json` so restarts do not drop submissions.

use chrono::{DateTime, Duration, Utc};
use common::PublishRequest;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub struct PendingEntry {
    pub request: PublishRequest,
    pub received_at: DateTime<Utc>,
    /// How many times the validator pipeline has attempted this package.
    pub attempt_count: u32,
    /// Set to true once the validator pipeline has picked this up.
    pub in_progress: bool,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedEntry {
    request: PublishRequest,
    received_at: DateTime<Utc>,
    attempt_count: u32,
    in_progress: bool,
}

pub struct PendingPool {
    entries: HashMap<String, PendingEntry>,
    path: Option<PathBuf>,
}

impl PendingPool {
    /// In-memory pool (tests only).
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            path: None,
        }
    }

    /// Load from disk when present; new submissions are persisted after each mutation.
    pub fn open(data_dir: &Path) -> Self {
        let path = data_dir.join("pending_pool.json");
        let mut pool = Self {
            entries: HashMap::new(),
            path: Some(path.clone()),
        };

        if !path.exists() {
            return pool;
        }

        match std::fs::read_to_string(&path) {
            Ok(raw) => match serde_json::from_str::<HashMap<String, PersistedEntry>>(&raw) {
                Ok(map) => {
                    let count = map.len();
                    for (key, persisted) in map {
                        pool.entries.insert(
                            key,
                            PendingEntry {
                                request: persisted.request,
                                received_at: persisted.received_at,
                                attempt_count: persisted.attempt_count,
                                // Stuck in_progress entries become eligible again after restart.
                                in_progress: false,
                            },
                        );
                    }
                    tracing::info!(
                        "[PendingPool] Restored {} pending package(s) from {}",
                        count,
                        path.display()
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        "[PendingPool] Ignoring corrupt pending pool at {}: {}",
                        path.display(),
                        error
                    );
                }
            },
            Err(error) => {
                tracing::warn!(
                    "[PendingPool] Could not read pending pool at {}: {}",
                    path.display(),
                    error
                );
            }
        }

        pool
    }

    fn persist(&self) {
        let Some(path) = &self.path else {
            return;
        };

        let snapshot: HashMap<String, PersistedEntry> = self
            .entries
            .iter()
            .map(|(key, entry)| {
                (
                    key.clone(),
                    PersistedEntry {
                        request: entry.request.clone(),
                        received_at: entry.received_at,
                        attempt_count: entry.attempt_count,
                        in_progress: entry.in_progress,
                    },
                )
            })
            .collect();

        let encoded = match serde_json::to_string_pretty(&snapshot) {
            Ok(json) => json,
            Err(error) => {
                tracing::warn!("[PendingPool] Failed to serialize pending pool: {}", error);
                return;
            }
        };

        let tmp = path.with_extension("json.tmp");
        if let Err(error) = std::fs::write(&tmp, &encoded) {
            tracing::warn!(
                "[PendingPool] Failed to write pending pool temp file {}: {}",
                tmp.display(),
                error
            );
            return;
        }
        if let Err(error) = std::fs::rename(&tmp, path) {
            tracing::warn!(
                "[PendingPool] Failed to commit pending pool {}: {}",
                path.display(),
                error
            );
            let _ = std::fs::remove_file(&tmp);
        }
    }

    /// Add a new submission.
    ///
    /// Returns `false` (and logs a warning) if the exact same content hash
    /// is already pending — prevents duplicate work and resubmission spam.
    /// If the same canonical exists but with a *different* content hash
    /// (i.e. a resubmission with changed content), it replaces the old entry.
    pub fn insert(&mut self, request: PublishRequest) -> bool {
        let key = request.id.canonical();

        if let Some(existing) = self.entries.get(&key) {
            if existing.request.content_hash == request.content_hash {
                tracing::warn!(
                    "[PendingPool] Duplicate submission ignored for {} (same content hash)",
                    key
                );
                return false;
            }
            tracing::info!(
                "[PendingPool] Replacing pending entry for {} (new content hash)",
                key
            );
        }

        tracing::info!("[PendingPool] Inserting package: {}", key);
        self.entries.insert(
            key,
            PendingEntry {
                request,
                received_at: Utc::now(),
                attempt_count: 0,
                in_progress: false,
            },
        );
        self.persist();
        true
    }

    pub fn contains(&self, canonical: &str) -> bool {
        self.entries.contains_key(canonical)
    }

    pub fn get(&self, canonical: &str) -> Option<&PendingEntry> {
        self.entries.get(canonical)
    }

    /// Remove a package from the pool (after it's been verified or rejected).
    pub fn remove(&mut self, canonical: &str) -> Option<PendingEntry> {
        let removed = self.entries.remove(canonical);
        if removed.is_some() {
            self.persist();
        }
        removed
    }

    /// Returns entries ready for validation (not in progress, or stuck > 5 min).
    pub fn ready_for_validation(&mut self) -> Vec<PublishRequest> {
        let cutoff = Utc::now() - Duration::minutes(5);
        let eligible: Vec<_> = self
            .entries
            .values_mut()
            .filter(|e| !e.in_progress || e.received_at < cutoff)
            .collect();

        if !eligible.is_empty() {
            tracing::info!(
                "[PendingPool] Found {} eligible packages for validation",
                eligible.len()
            );
        }

        let requests: Vec<PublishRequest> = eligible
            .into_iter()
            .map(|e| {
                e.in_progress = true;
                e.attempt_count += 1;
                e.request.clone()
            })
            .collect();

        if !requests.is_empty() {
            self.persist();
        }

        requests
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn all_canonicals(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::package::{PackageId, PackageManifest};
    use tempfile::tempdir;

    fn sample_request(name: &str, hash: &str) -> PublishRequest {
        PublishRequest {
            id: PackageId::new("npm", name, "1.0.0"),
            content_hash: hash.into(),
            ipfs_cid: "QmTest".into(),
            publisher_address: "0x38371A715Bd36142766EB026e61de061b45C9b00".into(),
            publisher_pubkey: "0437e4adac481519cd6ae66907294c40cfcbf0bdeadd47806f6233be4bd5f82d"
                .into(),
            signature: "sig".into(),
            manifest: PackageManifest::default(),
            submitted_at: Utc::now(),
            shielded: false,
            key_bundle: None,
            pgp_signature: None,
            pgp_public_key: None,
            threshold: 0,
            publisher_pubkeys: vec![],
            signatures: vec![],
        }
    }

    #[test]
    fn open_persists_and_reloads_after_restart() {
        let dir = tempdir().unwrap();
        let canonical = "npm:pkg@1.0.0";

        {
            let mut pool = PendingPool::open(dir.path());
            assert!(pool.insert(sample_request("pkg", "hash-a")));
            assert_eq!(pool.len(), 1);
        }

        let pool = PendingPool::open(dir.path());
        assert!(pool.contains(canonical));
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn remove_clears_persisted_entry() {
        let dir = tempdir().unwrap();
        let canonical = "npm:pkg@1.0.0";

        let mut pool = PendingPool::open(dir.path());
        pool.insert(sample_request("pkg", "hash-a"));
        pool.remove(canonical);

        let pool = PendingPool::open(dir.path());
        assert!(!pool.contains(canonical));
    }
}
