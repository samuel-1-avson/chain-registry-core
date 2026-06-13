// `creg osv-snapshot build` — build a pinned OSV snapshot for validator consensus.
//
// Usage:
//   creg osv-snapshot build --epoch osv-2026-06-07 -o data/osv_snapshot.json packages.txt
//   creg osv-snapshot build --epoch osv-2026-06-07 npm:lodash@4.17.20 pypi:requests@2.28.0
//
// Package list format (one per line or CLI arg): `ecosystem:name@version`
// Lines starting with `#` and blank lines are ignored.

use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::thread;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use chrono::Utc;
use ml_validator::osv_client::{self, PackageInfo};
use ml_validator::{OsvSnapshot, SCHEMA_V1};

pub fn run_build(
    epoch: &str,
    output: Option<&Path>,
    packages_file: Option<&Path>,
    inline_packages: &[String],
    delay_ms: u64,
) -> Result<()> {
    let epoch = epoch.trim();
    if epoch.is_empty() {
        bail!("--epoch must not be empty");
    }

    let mut keys = Vec::new();
    if let Some(path) = packages_file {
        let file = std::fs::File::open(path)
            .with_context(|| format!("open package list {}", path.display()))?;
        for line in io::BufReader::new(file).lines() {
            let line = line?;
            if let Some(info) = parse_package_line(&line) {
                keys.push(info);
            }
        }
    }

    for line in inline_packages {
        if let Some(info) = parse_package_line(line) {
            keys.push(info);
        }
    }

    if keys.is_empty() && packages_file.is_none() {
        for line in io::stdin().lock().lines() {
            let line = line?;
            if let Some(info) = parse_package_line(&line) {
                keys.push(info);
            }
        }
    }

    if keys.is_empty() {
        bail!("no packages to query; pass package keys as args or via --packages / stdin");
    }

    let mut entries: HashMap<String, Vec<osv_client::OsvVulnerability>> = HashMap::new();
    let delay = Duration::from_millis(delay_ms);

    eprintln!("Querying OSV for {} package(s)...", keys.len());
    for (idx, info) in keys.iter().enumerate() {
        let key = osv_client::cache_key(info);
        eprintln!("[{}/{}] {}", idx + 1, keys.len(), key);
        let result = osv_client::query(info);
        if result.queried && !result.vulnerabilities.is_empty() {
            entries.insert(key, result.vulnerabilities);
        }
        if delay > Duration::ZERO && idx + 1 < keys.len() {
            thread::sleep(delay);
        }
    }

    let snapshot = OsvSnapshot {
        epoch: epoch.to_string(),
        schema: SCHEMA_V1.to_string(),
        source: "creg osv-snapshot build".into(),
        built_at: Utc::now().to_rfc3339(),
        entries,
    };

    let json = serde_json::to_string_pretty(&snapshot).context("serialize OSV snapshot JSON")?;

    match output {
        Some(path) if path.as_os_str() == "-" => {
            io::stdout()
                .write_all(json.as_bytes())
                .context("write snapshot to stdout")?;
        }
        Some(path) => {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)
                        .with_context(|| format!("create {}", parent.display()))?;
                }
            }
            std::fs::write(path, &json)
                .with_context(|| format!("write snapshot to {}", path.display()))?;
            eprintln!(
                "Wrote {} entries to {}",
                snapshot.entries.len(),
                path.display()
            );
        }
        None => {
            print!("{json}");
        }
    }

    Ok(())
}

fn parse_package_line(line: &str) -> Option<PackageInfo> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let (ecosystem, rest) = line.split_once(':')?;
    let (name, version) = rest.rsplit_once('@')?;
    if ecosystem.is_empty() || name.is_empty() || version.is_empty() {
        return None;
    }

    Some(PackageInfo {
        name: name.to_string(),
        version: version.to_string(),
        ecosystem: ecosystem.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_package_line_accepts_canonical_key() {
        let info = parse_package_line("npm:lodash@4.17.20").unwrap();
        assert_eq!(info.ecosystem, "npm");
        assert_eq!(info.name, "lodash");
        assert_eq!(info.version, "4.17.20");
    }

    #[test]
    fn parse_package_line_skips_comments() {
        assert!(parse_package_line("# npm:foo@1").is_none());
        assert!(parse_package_line("").is_none());
    }
}
