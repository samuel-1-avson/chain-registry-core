// crates/cli/src/search.rs
// `creg search <query>` — full-text search across registered packages.

use anyhow::{Context, Result};
use colored::Colorize;

pub async fn run(
    query: &str,
    ecosystem: Option<&str>,
    node_url: Option<&str>,
    json: bool,
) -> Result<()> {
    let base = node_url.map(String::from).unwrap_or_else(|| {
        std::env::var("CREG_NODE_URL").unwrap_or_else(|_| "http://localhost:8080".into())
    });

    // Build query string
    let mut qp = format!("q={}", urlencoding::encode(query));
    if let Some(eco) = ecosystem {
        qp.push_str(&format!("&ecosystem={}", urlencoding::encode(eco)));
    }
    let url = build_search_url(&base, &qp);

    let client = reqwest::Client::new();
    let resp = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .context("Failed to reach registry node")?;

    if resp.status() == 404 {
        // Node doesn't implement /v1/search — fall back to listing all
        // packages and filtering client-side.
        return search_via_pending_list(query, ecosystem, &base, json).await;
    }

    if !resp.status().is_success() {
        anyhow::bail!("Search failed: HTTP {}", resp.status());
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .context("Failed to parse search response")?;
    let records = extract_records(&body);

    if json {
        println!("{}", serde_json::to_string_pretty(&records)?);
        return Ok(());
    }

    if records.is_empty() {
        println!("{} No packages found matching '{}'", "ℹ".blue(), query);
        return Ok(());
    }

    println!(
        "{} {} result(s) for '{}'",
        "→".cyan(),
        records.len(),
        query.bold()
    );
    println!("{}", "─".repeat(60).dimmed());
    print_records(&records);
    Ok(())
}

fn build_search_url(base: &str, query_params: &str) -> String {
    format!("{}/v1/search?{}", base.trim_end_matches('/'), query_params)
}

async fn search_via_pending_list(
    query: &str,
    ecosystem: Option<&str>,
    base: &str,
    json: bool,
) -> Result<()> {
    // Fetch pending pool list and chain stats, combine and filter.
    let client = reqwest::Client::new();

    let pending_url = format!("{}/v1/operator/pending", base.trim_end_matches('/'));
    let pending_resp = client
        .get(&pending_url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .context("Failed to reach pending pool endpoint")?;

    let pending_resp = if matches!(pending_resp.status().as_u16(), 401 | 403 | 404 | 405 | 501) {
        client
            .get(format!("{}/v1/pending", base.trim_end_matches('/')))
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .context("Failed to reach legacy pending pool endpoint")?
    } else {
        pending_resp
    };

    let mut results: Vec<serde_json::Value> = Vec::new();

    if pending_resp.status().is_success() {
        if let Ok(data) = pending_resp.json::<serde_json::Value>().await {
            if let Some(packages) = data.get("packages").and_then(|p| p.as_array()) {
                for canonical in packages {
                    let canonical_str = canonical.as_str().unwrap_or("");
                    if matches_query(canonical_str, query, ecosystem) {
                        results.push(serde_json::json!({
                            "canonical": canonical_str,
                            "status": "pending"
                        }));
                    }
                }
            }
        }
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&results)?);
        return Ok(());
    }

    if results.is_empty() {
        println!(
            "{} No packages found matching '{}' (searched pending pool)",
            "ℹ".blue(),
            query
        );
        println!("  Tip: The node may not support full-text search. Results are from the pending pool only.");
        return Ok(());
    }

    println!(
        "{} {} result(s) for '{}' (pending pool)",
        "→".cyan(),
        results.len(),
        query.bold()
    );
    println!("{}", "─".repeat(60).dimmed());
    print_records(&results);
    Ok(())
}

fn matches_query(canonical: &str, query: &str, ecosystem: Option<&str>) -> bool {
    let q = query.to_lowercase();
    if !canonical.to_lowercase().contains(&q) {
        return false;
    }
    if let Some(eco) = ecosystem {
        return canonical.starts_with(&format!("{}/", eco));
    }
    true
}

fn extract_records(body: &serde_json::Value) -> Vec<serde_json::Value> {
    body.get("matches")
        .and_then(|matches| matches.as_array())
        .cloned()
        .or_else(|| body.as_array().cloned())
        .unwrap_or_default()
}

fn print_records(records: &[serde_json::Value]) {
    for r in records {
        let canonical = r.get("canonical").and_then(|v| v.as_str()).unwrap_or("?");
        let status = r
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let publisher = r.get("publisher").and_then(|v| v.as_str()).unwrap_or("");
        let published = r
            .get("published_at")
            .and_then(|v| v.as_str())
            .map(|s| s.get(..10).unwrap_or(s))
            .unwrap_or("");

        let status_colored = match status {
            "verified" => status.green(),
            "revoked" => status.red(),
            "pending" => status.yellow(),
            _ => status.dimmed(),
        };

        if publisher.is_empty() {
            println!(
                "  {} [{}] {}",
                canonical.white().bold(),
                status_colored,
                published.dimmed()
            );
        } else {
            println!(
                "  {} [{}] {} by {}",
                canonical.white().bold(),
                status_colored,
                published.dimmed(),
                format!("{}...", &publisher[..publisher.len().min(12)]).dimmed()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{build_search_url, extract_records, matches_query};

    #[test]
    fn build_search_url_uses_grouped_route() {
        assert_eq!(
            build_search_url("http://localhost:8080/", "q=express"),
            "http://localhost:8080/v1/search?q=express"
        );
    }

    #[test]
    fn extract_records_reads_grouped_search_payload() {
        let body = serde_json::json!({
            "matches": [
                { "canonical": "npm/express@4.18.0", "status": "verified" }
            ]
        });

        let records = extract_records(&body);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["canonical"], "npm/express@4.18.0");
    }

    #[test]
    fn extract_records_supports_legacy_array_payloads() {
        let body = serde_json::json!([
            { "canonical": "cargo/serde@1.0.0", "status": "verified" }
        ]);

        let records = extract_records(&body);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["canonical"], "cargo/serde@1.0.0");
    }

    #[test]
    fn matches_query_uses_slash_ecosystem_prefix() {
        assert!(matches_query("npm/express@4.18.0", "express", Some("npm")));
        assert!(!matches_query("cargo/serde@1.0.0", "serde", Some("npm")));
    }
}
