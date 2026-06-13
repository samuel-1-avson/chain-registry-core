//! Content-hash–based threat intelligence matching.
//!
//! Maintains a JSON-backed database of SHA-256 hashes of known-malicious
//! package contents.  Validators share newly discovered malicious hashes
//! via network consensus; this module looks up the per-file content hashes
//! against that database.
//!
//! No ML training required — the database grows organically as the
//! validator network flags packages.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::OnceLock;
use tracing::{debug, info, warn};

/// Compiled-in seed database.  Provides a baseline of well-known malicious
/// package hashes so validators are not completely blind on first boot.
/// Operators should supplement this with a full threat database via
/// `CREG_THREAT_DB_PATH` or the `record_threat` API.
const SEED_THREATS_JSON: &str = include_str!("bootstrap_threats.json");

/// Minimum useful DB size below which we emit a persistent warning.
const MIN_USEFUL_DB_SIZE: usize = 100;

/// Default path for the known-malicious hash database.
const DEFAULT_DB_PATH: &str = "data/known_malicious_hashes.json";

/// A single entry in the threat intel database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEntry {
    /// Human-readable label (e.g. "ua-parser-js@0.7.29 postinstall backdoor").
    pub label: String,
    /// Threat level (1–5).
    pub threat_level: u8,
    /// Source of the intelligence (e.g. "socket.dev", "validator-consensus").
    pub source: String,
}

/// The in-memory threat intel database.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThreatDatabase {
    /// Map from SHA-256 hex hash → threat entry.
    pub entries: HashMap<String, ThreatEntry>,
}

/// Result of a threat-intel lookup.
#[derive(Debug, Clone)]
pub struct ThreatIntelResult {
    /// Matching entries: hash → entry.
    pub matches: Vec<(String, ThreatEntry)>,
}

impl ThreatIntelResult {
    pub fn is_empty(&self) -> bool {
        self.matches.is_empty()
    }

    /// Convert to a malicious probability (0.0 – 1.0).
    pub fn to_probability(&self) -> f32 {
        if self.matches.is_empty() {
            return 0.0;
        }
        let max_threat: u8 = self
            .matches
            .iter()
            .map(|(_, e)| e.threat_level)
            .max()
            .unwrap_or(0);
        match max_threat {
            5 => 0.99,
            4 => 0.90,
            3 => 0.70,
            2 => 0.40,
            _ => 0.20,
        }
    }
}

/// Database path, overridable via `CREG_THREAT_DB_PATH`.
fn db_path() -> PathBuf {
    std::env::var("CREG_THREAT_DB_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_DB_PATH))
}

/// Loaded database singleton.
static THREAT_DB: OnceLock<ThreatDatabase> = OnceLock::new();

/// Parse the compiled-in seed database, returning an empty database on
/// parse failure (should never happen — the file is checked at compile time).
fn seed_database() -> ThreatDatabase {
    match serde_json::from_str::<ThreatDatabase>(SEED_THREATS_JSON) {
        Ok(db) => {
            info!(
                "Loaded {} compiled-in seed threat-intel entries",
                db.entries.len()
            );
            db
        }
        Err(e) => {
            warn!(
                "Failed to parse compiled-in seed_threats.json: {} — proceeding without seeds",
                e
            );
            ThreatDatabase::default()
        }
    }
}

fn load_database() -> ThreatDatabase {
    // Always start from the compiled-in seed so validators are not blind on
    // first boot before an operator-supplied database is deployed.
    let mut db = seed_database();
    let path = db_path();

    if !path.exists() {
        warn!(
            path = %path.display(),
            seed_entries = db.entries.len(),
            "Threat intel database not found — running on seed data only. \
             Set CREG_THREAT_DB_PATH or use `record_threat` to populate a full database. \
             The validator will accept packages that would be blocked by a complete database."
        );
        return db;
    }

    match std::fs::read_to_string(&path) {
        Ok(json) => match serde_json::from_str::<ThreatDatabase>(&json) {
            Ok(on_disk) => {
                // Merge: on-disk entries take precedence over seed entries so
                // that operators can override or retract seed entries.
                let added = on_disk.entries.len();
                db.entries.extend(on_disk.entries);
                info!(
                    path = %path.display(),
                    seed_entries = db.entries.len() - added,
                    disk_entries = added,
                    total = db.entries.len(),
                    "Threat intel database loaded"
                );
            }
            Err(e) => {
                warn!(
                    path = %path.display(),
                    error = %e,
                    "Failed to parse threat intel database — falling back to seed entries only"
                );
            }
        },
        Err(e) => {
            warn!(
                path = %path.display(),
                error = %e,
                "Failed to read threat intel database — falling back to seed entries only"
            );
        }
    }

    if db.entries.len() < MIN_USEFUL_DB_SIZE {
        warn!(
            entries = db.entries.len(),
            minimum = MIN_USEFUL_DB_SIZE,
            "Threat intel database is below minimum useful size. \
             Many malicious packages will go undetected. \
             Obtain a full database from your threat-intelligence provider."
        );
    }

    db
}

fn get_db() -> &'static ThreatDatabase {
    THREAT_DB.get_or_init(load_database)
}

/// Compute the SHA-256 hash of content.
pub fn sha256_hex(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// Check extracted package files against the threat intel database.
///
/// `files` is a list of `(relative_path, file_content)` pairs.
/// Also checks the hash of the entire tarball.
pub fn check(tarball_bytes: &[u8], files: &[(String, String)]) -> ThreatIntelResult {
    let db = get_db();
    let mut matches = Vec::new();

    // Check whole-tarball hash.
    let tarball_hash = sha256_hex(tarball_bytes);
    if let Some(entry) = db.entries.get(&tarball_hash) {
        debug!(
            "Threat intel: tarball hash {} matches '{}'",
            &tarball_hash[..16],
            entry.label
        );
        matches.push((tarball_hash, entry.clone()));
    }

    // Check individual file hashes.
    let mut seen = HashSet::new();
    for (path, content) in files {
        let hash = sha256_hex(content.as_bytes());
        if seen.contains(&hash) {
            continue;
        }
        seen.insert(hash.clone());

        if let Some(entry) = db.entries.get(&hash) {
            debug!(
                "Threat intel: file '{}' hash {} matches '{}'",
                path,
                &hash[..16],
                entry.label
            );
            matches.push((hash, entry.clone()));
        }
    }

    ThreatIntelResult { matches }
}

/// Add a new entry to the on-disk database.
///
/// Called when the network reaches consensus that a package is malicious.
pub fn record_threat(hash: &str, entry: ThreatEntry) -> Result<(), String> {
    let path = db_path();

    // Load current database (may differ from cached singleton).
    let mut db: ThreatDatabase = if path.exists() {
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_default()
    } else {
        ThreatDatabase::default()
    };

    db.entries.insert(hash.to_string(), entry);

    // Ensure parent directory exists.
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir: {e}"))?;
    }

    let json = serde_json::to_string_pretty(&db).map_err(|e| format!("serialize: {e}"))?;
    std::fs::write(&path, json).map_err(|e| format!("write: {e}"))?;

    info!(
        "Recorded threat intel entry: hash={}",
        &hash[..16.min(hash.len())]
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hex_deterministic() {
        let h1 = sha256_hex(b"hello world");
        let h2 = sha256_hex(b"hello world");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // 256 bits = 64 hex chars
    }

    #[test]
    fn test_sha256_hex_known_digest() {
        // SHA-256 of empty input is well-known
        let h = sha256_hex(b"");
        assert_eq!(
            h,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_hex_different_inputs() {
        assert_ne!(sha256_hex(b"aaa"), sha256_hex(b"bbb"));
    }

    #[test]
    fn test_threat_intel_result_empty() {
        let r = ThreatIntelResult { matches: vec![] };
        assert!(r.is_empty());
        assert_eq!(r.to_probability(), 0.0);
    }

    #[test]
    fn test_threat_intel_result_probability_level_5() {
        let r = ThreatIntelResult {
            matches: vec![(
                "abc".into(),
                ThreatEntry {
                    label: "test".into(),
                    threat_level: 5,
                    source: "test".into(),
                },
            )],
        };
        assert!(!r.is_empty());
        assert!((r.to_probability() - 0.99).abs() < 0.01);
    }

    #[test]
    fn test_threat_intel_result_probability_level_3() {
        let r = ThreatIntelResult {
            matches: vec![(
                "abc".into(),
                ThreatEntry {
                    label: "test".into(),
                    threat_level: 3,
                    source: "test".into(),
                },
            )],
        };
        assert!((r.to_probability() - 0.70).abs() < 0.01);
    }

    #[test]
    fn test_check_no_match_empty_db() {
        // With default empty database, nothing should match.
        let tarball = b"some tarball bytes";
        let files = vec![("index.js".to_string(), "console.log('safe')".to_string())];
        let result = check(tarball, &files);
        assert!(result.is_empty());
    }

    #[test]
    fn test_check_deduplicates_files() {
        // If two files have identical content, only one hash lookup occurs.
        let tarball = b"tarball";
        let files = vec![
            ("a.js".to_string(), "same content".to_string()),
            ("b.js".to_string(), "same content".to_string()),
        ];
        let result = check(tarball, &files);
        // No match expected (empty default DB), but no panic either.
        assert!(result.is_empty());
    }

    #[test]
    fn test_record_and_read_threat() {
        // Use a temp file to test record_threat round-trip.
        let dir = std::env::temp_dir().join("creg_test_threat_intel");
        let _ = std::fs::create_dir_all(&dir);
        let db_path = dir.join("test_db.json");
        // Clean up any previous run.
        let _ = std::fs::remove_file(&db_path);

        std::env::set_var("CREG_THREAT_DB_PATH", db_path.to_str().unwrap());

        let entry = ThreatEntry {
            label: "evil-pkg@1.0.0".into(),
            threat_level: 5,
            source: "unit-test".into(),
        };
        record_threat(
            "deadbeef00112233deadbeef00112233deadbeef00112233deadbeef00112233",
            entry,
        )
        .unwrap();

        // Read back and verify.
        let json = std::fs::read_to_string(&db_path).unwrap();
        let db: ThreatDatabase = serde_json::from_str(&json).unwrap();
        assert_eq!(db.entries.len(), 1);
        assert!(db
            .entries
            .contains_key("deadbeef00112233deadbeef00112233deadbeef00112233deadbeef00112233"));

        // Cleanup.
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_dir(&dir);
        std::env::remove_var("CREG_THREAT_DB_PATH");
    }
}
