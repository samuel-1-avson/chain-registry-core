// crates/validator/src/typosquat.rs
// Levenshtein-distance based typosquatting detector.
// Checks if a package name is suspiciously close to a popular package name
// and flags it as a potential typosquat attack.
//
// ## Dataset lifecycle
//
// 1. **Compile-time baseline** — `data/typosquat.json` is baked into the
//    binary via `include_str!`.  Always available, never stale by more than
//    one release cycle.
//
// 2. **Runtime refresh** — on each validation run `maybe_refresh()` is
//    called once.  When `CREG_TYPOSQUAT_URL` is set it fetches a fresh JSON
//    file from that URL and *merges* it into the runtime dataset (new
//    packages are added; compile-time entries are never removed).  Fetch
//    failures log a warning and fall back to the compile-time baseline so
//    detection never silently disappears.

use once_cell::sync::Lazy;
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

/// How long to reuse a successfully fetched runtime dataset before re-fetching.
const REFRESH_TTL: Duration = Duration::from_secs(3600); // 1 hour

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct TyposquatDataset {
    version: u32,
    packages: HashMap<String, Vec<String>>,
}

impl TyposquatDataset {
    /// Merge `other` into `self` — new packages from `other` are appended;
    /// existing compile-time entries are preserved.
    fn merge_from(&mut self, other: &TyposquatDataset) {
        for (ecosystem, names) in &other.packages {
            let entry = self.packages.entry(ecosystem.clone()).or_default();
            for name in names {
                if !entry.contains(name) {
                    entry.push(name.clone());
                }
            }
        }
        // Bump version to the higher of the two.
        if other.version > self.version {
            self.version = other.version;
        }
    }
}

/// Compiled-in typosquat dataset (loaded from data/typosquat.json at build time).
///
/// Initialization failures are fatal — the `Lazy` will produce an empty dataset
/// AND log a `tracing::error!` so the failure appears in production logs.  Use
/// `CREG_TYPOSQUAT_DISABLED=1` to suppress detection in environments where the
/// dataset is intentionally absent.
static BASELINE: Lazy<TyposquatDataset> = Lazy::new(|| {
    let json = include_str!("../data/typosquat.json");
    match serde_json::from_str::<TyposquatDataset>(json) {
        Ok(ds) => {
            if ds.packages.is_empty() {
                tracing::error!(
                    "typosquat.json parsed successfully but contains no packages; \
                     typosquat detection will be a no-op. \
                     Check data/typosquat.json for missing 'packages' key."
                );
            }
            ds
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                "typosquat.json is malformed — typosquat detection DISABLED. \
                 Rebuild the validator crate after fixing data/typosquat.json."
            );
            TyposquatDataset {
                version: 0,
                packages: HashMap::new(),
            }
        }
    }
});

/// Runtime-refreshed dataset.  `None` until the first successful fetch.
/// Protected by a Mutex so concurrent validators don't race on refresh.
struct RuntimeState {
    dataset: Option<TyposquatDataset>,
    last_fetched: Option<Instant>,
}

static RUNTIME: Lazy<Mutex<RuntimeState>> = Lazy::new(|| {
    Mutex::new(RuntimeState {
        dataset: None,
        last_fetched: None,
    })
});

/// Fetch a fresh typosquat dataset from `url` and merge it with the
/// compile-time baseline.  Returns the merged result on success.
async fn fetch_and_merge(url: &str) -> Option<TyposquatDataset> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .ok()?;

    let resp = client
        .get(url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| {
            tracing::warn!(url, error = %e, "Typosquat dataset fetch failed — using compile-time baseline");
        })
        .ok()?;

    if !resp.status().is_success() {
        tracing::warn!(
            url,
            status = %resp.status(),
            "Typosquat dataset fetch returned non-200 — using compile-time baseline"
        );
        return None;
    }

    let remote: TyposquatDataset = resp
        .json()
        .await
        .map_err(|e| {
            tracing::warn!(url, error = %e, "Typosquat dataset JSON parse failed — using compile-time baseline");
        })
        .ok()?;

    // Merge remote additions on top of the compile-time baseline.
    let mut merged = BASELINE.clone();
    merged.merge_from(&remote);
    tracing::info!(
        url,
        remote_version = remote.version,
        merged_version = merged.version,
        "Typosquat dataset refreshed successfully"
    );
    Some(merged)
}

/// Refresh the runtime typosquat dataset if `CREG_TYPOSQUAT_URL` is set and
/// either no dataset has been fetched yet or the TTL has expired.
///
/// Failures log a warning but do **not** return an error — the compile-time
/// baseline is always available as a fallback.  This is called once per
/// validation run from the validator pipeline.
pub async fn maybe_refresh() {
    let url = match std::env::var("CREG_TYPOSQUAT_URL") {
        Ok(v) if !v.is_empty() => v,
        _ => return, // URL not configured — compile-time baseline is sufficient
    };

    // Check if a refresh is needed without holding the lock across the await.
    let needs_refresh = {
        let state = RUNTIME.lock().unwrap_or_else(|e| e.into_inner());
        match state.last_fetched {
            None => true,
            Some(t) => t.elapsed() >= REFRESH_TTL,
        }
    };

    if !needs_refresh {
        return;
    }

    let fresh = fetch_and_merge(&url).await;

    let mut state = RUNTIME.lock().unwrap_or_else(|e| e.into_inner());
    state.last_fetched = Some(Instant::now());
    if let Some(merged) = fresh {
        state.dataset = Some(merged);
    }
    // If fetch failed, keep the previous dataset (or None → fall back to BASELINE).
}

/// Borrow the active dataset.  Uses the runtime-fetched dataset when available,
/// otherwise falls back to the compile-time baseline.
fn active_packages() -> std::sync::MutexGuard<'static, RuntimeState> {
    RUNTIME.lock().unwrap_or_else(|e| e.into_inner())
}

/// Result of a typosquat check.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TyposquatMatch {
    pub candidate: String, // the package being checked
    pub target: String,    // the popular package it resembles
    pub distance: usize,   // edit distance
    pub ecosystem: String,
}

fn normalise(name: &str) -> String {
    name.to_lowercase()
        .trim_start_matches('@')
        .split('/')
        .last()
        .unwrap_or(name)
        .replace(['-', '_', '.'], "")
}

/// Check whether `name` in `ecosystem` looks like a typosquat of a popular package.
/// Returns `Some(match)` if a suspiciously close name is found.
///
/// Prefers the runtime-refreshed dataset when one has been loaded; falls back
/// to the compile-time baseline automatically.
pub fn check(name: &str, ecosystem: &str) -> Option<TyposquatMatch> {
    let guard = active_packages();
    let dataset = guard.dataset.as_ref().unwrap_or(&*BASELINE);
    let candidates = dataset.packages.get(ecosystem)?;

    let normalised = normalise(name);

    for popular in candidates {
        let pop_norm = normalise(popular);
        // Skip exact matches — those are the real packages.
        if normalised == pop_norm {
            return None;
        }

        let dist = strsim::levenshtein(&normalised, &pop_norm);

        // Flag if within edit distance threshold.
        let min_len = normalised.len().min(pop_norm.len());
        let threshold = if min_len < 5 {
            0
        } else if min_len < 8 {
            1
        } else {
            2
        };

        if dist > 0 && dist <= threshold {
            return Some(TyposquatMatch {
                candidate: name.to_string(),
                target: popular.clone(),
                distance: dist,
                ecosystem: ecosystem.to_string(),
            });
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match_not_flagged() {
        assert!(check("express", "npm").is_none());
        assert!(check("requests", "pypi").is_none());
    }

    #[test]
    fn obvious_typosquat_flagged() {
        // "expres" is edit distance 1 from "express"
        let m = check("expres", "npm");
        assert!(m.is_some());
        assert_eq!(m.unwrap().target, "express");
    }

    #[test]
    fn scoped_package_checked_correctly() {
        // "@scope/expres" should still be caught
        let m = check("@scope/expres", "npm");
        assert!(m.is_some());
    }

    #[test]
    fn unrelated_package_not_flagged() {
        assert!(check("my-totally-unique-lib-xyz", "npm").is_none());
    }

    #[test]
    fn levenshtein_basic() {
        assert_eq!(strsim::levenshtein("kitten", "sitting"), 3);
        assert_eq!(strsim::levenshtein("", "abc"), 3);
        assert_eq!(strsim::levenshtein("abc", "abc"), 0);
        assert_eq!(strsim::levenshtein("abc", "ab"), 1);
    }

    #[test]
    fn merge_adds_new_entries() {
        let mut base = TyposquatDataset {
            version: 1,
            packages: {
                let mut m = HashMap::new();
                m.insert("npm".into(), vec!["react".into()]);
                m
            },
        };
        let remote = TyposquatDataset {
            version: 2,
            packages: {
                let mut m = HashMap::new();
                m.insert("npm".into(), vec!["react".into(), "lodash".into()]);
                m.insert("pypi".into(), vec!["requests".into()]);
                m
            },
        };
        base.merge_from(&remote);
        assert_eq!(base.version, 2);
        assert_eq!(base.packages["npm"].len(), 2); // "react" deduplicated, "lodash" added
        assert!(base.packages["npm"].contains(&"lodash".to_string()));
        assert!(base.packages.contains_key("pypi"));
    }
}
