//! OSV.dev vulnerability database client.
//!
//! Queries Google's Open Source Vulnerability database to check if a
//! package version has known CVEs/advisories.  Free API, no rate limits,
//! covers npm, PyPI, crates.io, Go, Maven, and more.
//!
//! Results are cached in-process to avoid redundant lookups.

use serde::{Deserialize, Serialize};
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::Duration;
use tracing::{debug, warn};

/// OSV API endpoint.
const OSV_API_URL: &str = "https://api.osv.dev/v1/query";

/// Timeout for OSV queries.
const OSV_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum cache entries to prevent unbounded memory growth.
const MAX_CACHE_SIZE: usize = 5000;

/// In-process LRU cache: `"ecosystem:name@version"` → `OsvResult`.
/// Evicts the least-recently-used entry when capacity is reached, avoiding
/// the thundering-herd that occurs when the entire cache is cleared at once.
static OSV_CACHE: std::sync::LazyLock<Mutex<lru::LruCache<String, OsvResult>>> =
    std::sync::LazyLock::new(|| {
        Mutex::new(lru::LruCache::new(
            NonZeroUsize::new(MAX_CACHE_SIZE).unwrap(),
        ))
    });

/// Information about a package to query against OSV.
#[derive(Debug, Clone)]
pub struct PackageInfo {
    /// Package name as used in the ecosystem (e.g. "lodash", "requests").
    pub name: String,
    /// Package version string (e.g. "4.17.21").
    pub version: String,
    /// Ecosystem identifier: "npm", "PyPI", "crates.io", "Go", "Maven", etc.
    pub ecosystem: String,
}

/// A single vulnerability found by OSV.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvVulnerability {
    /// OSV identifier (e.g. "GHSA-xxxx-yyyy-zzzz", "CVE-2024-1234").
    pub id: String,
    /// Human-readable summary.
    pub summary: String,
    /// Severity if available.
    pub severity: Option<String>,
}

/// Result of an OSV query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvResult {
    /// Whether the query succeeded.
    pub queried: bool,
    /// Known vulnerabilities for this package+version.
    pub vulnerabilities: Vec<OsvVulnerability>,
}

impl OsvResult {
    pub(crate) fn unavailable() -> Self {
        Self {
            queried: false,
            vulnerabilities: Vec::new(),
        }
    }
}

/// Query body for the OSV API.
#[derive(Serialize)]
struct OsvQuery {
    package: OsvPackage,
    version: String,
}

#[derive(Serialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

/// Response from the OSV API.
#[derive(Deserialize)]
struct OsvResponse {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Deserialize)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    database_specific: Option<serde_json::Value>,
}

/// Stable cache key for snapshot entries and in-process LRU cache.
pub fn cache_key(info: &PackageInfo) -> String {
    format!(
        "{}:{}@{}",
        map_ecosystem(&info.ecosystem),
        info.name,
        info.version
    )
}

/// Map our ecosystem strings to OSV ecosystem identifiers.
pub fn map_ecosystem(ecosystem: &str) -> String {
    let lower = ecosystem.to_lowercase();
    match lower.as_str() {
        "npm" => "npm".to_string(),
        "pypi" | "python" => "PyPI".to_string(),
        "crates.io" | "cargo" | "rust" => "crates.io".to_string(),
        "go" | "golang" => "Go".to_string(),
        "maven" | "java" => "Maven".to_string(),
        "rubygems" | "ruby" => "RubyGems".to_string(),
        "nuget" | "dotnet" => "NuGet".to_string(),
        "packagist" | "php" => "Packagist".to_string(),
        _ => ecosystem.to_string(),
    }
}

/// Query OSV for known vulnerabilities. Returns cached result if available.
///
/// This function is safe to call from async contexts — it uses a blocking
/// HTTP client with a short timeout and graceful degradation.
pub fn query(info: &PackageInfo) -> OsvResult {
    // Check if OSV queries are disabled.
    if std::env::var("CREG_OSV_DISABLED").unwrap_or_default() == "true" {
        return OsvResult::unavailable();
    }

    let key = cache_key(info);

    // Cache lookup — `mut` required because LruCache::get updates LRU order.
    if let Ok(mut cache) = OSV_CACHE.lock() {
        if let Some(cached) = cache.get(&key) {
            debug!("OSV cache hit for {}", key);
            return cached.clone();
        }
    }

    let osv_ecosystem = map_ecosystem(&info.ecosystem);
    let body = OsvQuery {
        package: OsvPackage {
            name: info.name.clone(),
            ecosystem: osv_ecosystem,
        },
        version: info.version.clone(),
    };

    let result = match reqwest::blocking::Client::builder()
        .timeout(OSV_TIMEOUT)
        .build()
    {
        Ok(client) => match client.post(OSV_API_URL).json(&body).send() {
            Ok(resp) => {
                if resp.status().is_success() {
                    match resp.json::<OsvResponse>() {
                        Ok(osv_resp) => {
                            let vulns: Vec<OsvVulnerability> = osv_resp
                                .vulns
                                .into_iter()
                                .map(|v| {
                                    let severity = v
                                        .database_specific
                                        .as_ref()
                                        .and_then(|db| db.get("severity"))
                                        .and_then(|s| s.as_str())
                                        .map(String::from);
                                    OsvVulnerability {
                                        id: v.id,
                                        summary: v.summary.unwrap_or_else(|| "No summary".into()),
                                        severity,
                                    }
                                })
                                .collect();

                            debug!("OSV returned {} vulnerabilities for {}", vulns.len(), key);

                            OsvResult {
                                queried: true,
                                vulnerabilities: vulns,
                            }
                        }
                        Err(e) => {
                            warn!("Failed to parse OSV response: {}", e);
                            OsvResult::unavailable()
                        }
                    }
                } else {
                    debug!("OSV returned status {} for {}", resp.status(), key);
                    OsvResult {
                        queried: true,
                        vulnerabilities: Vec::new(),
                    }
                }
            }
            Err(e) => {
                warn!("OSV query failed for {}: {}", key, e);
                OsvResult::unavailable()
            }
        },
        Err(e) => {
            warn!("Failed to create HTTP client for OSV: {}", e);
            OsvResult::unavailable()
        }
    };

    // Cache the result — LRU automatically evicts the least-recently-used
    // entry at capacity, avoiding the thundering-herd caused by clearing
    // the whole HashMap at once.
    if let Ok(mut cache) = OSV_CACHE.lock() {
        cache.put(key, result.clone());
    }

    result
}

/// Convert OSV results to a threat probability boost (0.0 – 1.0).
///
/// Known CVEs don't necessarily mean the package is malicious, but they
/// do increase the risk score.
pub fn vulns_to_probability(result: &OsvResult) -> f32 {
    if result.vulnerabilities.is_empty() {
        return 0.0;
    }

    let has_critical = result.vulnerabilities.iter().any(|v| {
        v.severity
            .as_deref()
            .map(|s| s.eq_ignore_ascii_case("CRITICAL"))
            .unwrap_or(false)
    });

    let has_high = result.vulnerabilities.iter().any(|v| {
        v.severity
            .as_deref()
            .map(|s| s.eq_ignore_ascii_case("HIGH"))
            .unwrap_or(false)
    });

    if has_critical {
        0.60
    } else if has_high {
        0.40
    } else if result.vulnerabilities.len() > 3 {
        0.35
    } else {
        0.20
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_vuln(id: &str, severity: Option<&str>) -> OsvVulnerability {
        OsvVulnerability {
            id: id.to_string(),
            summary: format!("Summary for {id}"),
            severity: severity.map(String::from),
        }
    }

    #[test]
    fn test_vulns_to_probability_empty() {
        let result = OsvResult {
            queried: true,
            vulnerabilities: vec![],
        };
        assert_eq!(vulns_to_probability(&result), 0.0);
    }

    #[test]
    fn test_vulns_to_probability_critical() {
        let result = OsvResult {
            queried: true,
            vulnerabilities: vec![make_vuln("CVE-2024-0001", Some("CRITICAL"))],
        };
        assert!((vulns_to_probability(&result) - 0.60).abs() < 0.01);
    }

    #[test]
    fn test_vulns_to_probability_high() {
        let result = OsvResult {
            queried: true,
            vulnerabilities: vec![make_vuln("CVE-2024-0002", Some("HIGH"))],
        };
        assert!((vulns_to_probability(&result) - 0.40).abs() < 0.01);
    }

    #[test]
    fn test_vulns_to_probability_many_low() {
        let result = OsvResult {
            queried: true,
            vulnerabilities: vec![
                make_vuln("CVE-1", Some("LOW")),
                make_vuln("CVE-2", Some("LOW")),
                make_vuln("CVE-3", Some("LOW")),
                make_vuln("CVE-4", Some("LOW")),
            ],
        };
        assert!((vulns_to_probability(&result) - 0.35).abs() < 0.01);
    }

    #[test]
    fn test_vulns_to_probability_single_medium() {
        let result = OsvResult {
            queried: true,
            vulnerabilities: vec![make_vuln("CVE-2024-0003", Some("MEDIUM"))],
        };
        assert!((vulns_to_probability(&result) - 0.20).abs() < 0.01);
    }

    #[test]
    fn test_map_ecosystem_normalization() {
        assert_eq!(map_ecosystem("npm"), "npm");
        assert_eq!(map_ecosystem("PyPI"), "PyPI");
        assert_eq!(map_ecosystem("python"), "PyPI");
        assert_eq!(map_ecosystem("cargo"), "crates.io");
        assert_eq!(map_ecosystem("rust"), "crates.io");
        assert_eq!(map_ecosystem("golang"), "Go");
        assert_eq!(map_ecosystem("ruby"), "RubyGems");
        assert_eq!(map_ecosystem("dotnet"), "NuGet");
        assert_eq!(map_ecosystem("php"), "Packagist");
        assert_eq!(map_ecosystem("unknown"), "unknown");
    }

    #[test]
    fn test_osv_disabled_env() {
        std::env::set_var("CREG_OSV_DISABLED", "true");
        let info = PackageInfo {
            name: "lodash".into(),
            version: "4.17.21".into(),
            ecosystem: "npm".into(),
        };
        let result = query(&info);
        assert!(!result.queried);
        std::env::remove_var("CREG_OSV_DISABLED");
    }

    #[test]
    fn test_unavailable_result() {
        let r = OsvResult::unavailable();
        assert!(!r.queried);
        assert!(r.vulnerabilities.is_empty());
    }
}
