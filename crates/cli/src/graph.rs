// crates/cli/src/graph.rs
// `creg graph <package>` — ASCII/TUI dependency tree with risk scores per node.

use anyhow::Result;
use colored::Colorize;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
struct PackageNode {
    canonical: String,
    status: String,
    risk_score: u8,
    deps: Vec<String>,
}

pub async fn run(
    package: &str,
    ecosystem: Option<&str>,
    depth: u32,
    node_url: Option<&str>,
    json: bool,
) -> Result<()> {
    let base = node_url.map(String::from).unwrap_or_else(|| {
        std::env::var("CREG_NODE_URL").unwrap_or_else(|_| "http://localhost:8080".into())
    });

    let canonical = build_canonical(package, ecosystem);

    println!(
        "{} Building dependency graph for {} (depth {})",
        "→".cyan(),
        canonical.bold(),
        depth
    );

    let mut visited = HashSet::new();
    let mut graph: HashMap<String, PackageNode> = HashMap::new();

    resolve_deps(&canonical, &base, depth, 0, &mut visited, &mut graph).await;

    if json {
        let nodes: Vec<_> = graph.values().collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "root": canonical,
                "nodes": nodes.iter().map(|n| serde_json::json!({
                    "canonical": n.canonical,
                    "status": n.status,
                    "risk_score": n.risk_score,
                    "deps": n.deps,
                })).collect::<Vec<_>>()
            }))?
        );
        return Ok(());
    }

    // Render ASCII tree
    println!();
    render_tree(&canonical, &graph, "", true, &mut HashSet::new());

    // Summary
    let total = graph.len();
    let revoked = graph.values().filter(|n| n.status == "revoked").count();
    let high_risk = graph.values().filter(|n| n.risk_score >= 70).count();
    let verified = graph.values().filter(|n| n.status == "verified").count();

    println!();
    println!("{}", "─".repeat(52).dimmed());
    println!("  Total packages:  {}", total);
    println!("  {} Verified:   {}", "✓".green(), verified);
    if revoked > 0 {
        println!("  {} Revoked:    {}", "✗".red(), revoked.to_string().red());
    }
    if high_risk > 0 {
        println!(
            "  {} High risk:  {}",
            "⚠".yellow(),
            high_risk.to_string().yellow()
        );
    }

    Ok(())
}

fn build_canonical(package: &str, ecosystem: Option<&str>) -> String {
    if package.contains(':') {
        return package.to_string();
    }
    let eco = ecosystem.unwrap_or("npm");
    let (name, ver) = if let Some(idx) = package.rfind('@') {
        (&package[..idx], &package[idx + 1..])
    } else {
        (package, "latest")
    };
    format!("{}:{}@{}", eco, name, ver)
}

async fn resolve_deps(
    canonical: &str,
    base: &str,
    max_depth: u32,
    cur_depth: u32,
    visited: &mut HashSet<String>,
    graph: &mut HashMap<String, PackageNode>,
) {
    if visited.contains(canonical) || cur_depth > max_depth {
        return;
    }
    visited.insert(canonical.to_string());

    let client = reqwest::Client::new();
    let url = format!(
        "{}/v1/packages/{}",
        base.trim_end_matches('/'),
        urlencoding::encode(canonical)
    );

    let record = match client
        .get(&url)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r.json::<serde_json::Value>().await.ok(),
        _ => None,
    };

    let status = record
        .as_ref()
        .and_then(|r| r.get("status"))
        .and_then(|s| s.as_str())
        .unwrap_or("unknown")
        .to_string();

    // Derive a simple risk score from status
    let risk_score: u8 = match status.as_str() {
        "verified" => 10,
        "pending" => 50,
        "revoked" => 95,
        _ => 60,
    };

    // Extract declared dependencies from manifest field if present
    let deps: Vec<String> = record
        .as_ref()
        .and_then(|r| r.get("manifest"))
        .and_then(|m| m.get("dependencies"))
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let node = PackageNode {
        canonical: canonical.to_string(),
        status,
        risk_score,
        deps: deps.clone(),
    };
    graph.insert(canonical.to_string(), node);

    if cur_depth < max_depth {
        // Use a boxed future to allow recursion
        for dep in deps {
            Box::pin(resolve_deps(
                &dep,
                base,
                max_depth,
                cur_depth + 1,
                visited,
                graph,
            ))
            .await;
        }
    }
}

fn render_tree(
    canonical: &str,
    graph: &HashMap<String, PackageNode>,
    prefix: &str,
    is_last: bool,
    rendered: &mut HashSet<String>,
) {
    let connector = if is_last { "└── " } else { "├── " };
    let child_prefix = format!("{}{}", prefix, if is_last { "    " } else { "│   " });

    let node = graph.get(canonical);
    let status = node
        .as_ref()
        .map(|n| n.status.as_str())
        .unwrap_or("unknown");
    let risk = node.as_ref().map(|n| n.risk_score).unwrap_or(0);

    let status_icon = match status {
        "verified" => "✓".green(),
        "revoked" => "✗".red(),
        "pending" => "⏳".yellow(),
        _ => "?".dimmed(),
    };

    let risk_color = if risk >= 70 {
        format!("risk:{}", risk).red()
    } else if risk >= 40 {
        format!("risk:{}", risk).yellow()
    } else {
        format!("risk:{}", risk).green()
    };

    let already = rendered.contains(canonical);
    let cycle_note = if already {
        " (already shown)".dimmed().to_string()
    } else {
        String::new()
    };

    println!(
        "{}{}{} {} [{}]{}",
        prefix,
        connector.dimmed(),
        status_icon,
        canonical.white().bold(),
        risk_color,
        cycle_note,
    );

    if already {
        return;
    }
    rendered.insert(canonical.to_string());

    if let Some(node) = node {
        let deps: Vec<_> = node.deps.iter().collect();
        for (i, dep) in deps.iter().enumerate() {
            let last = i == deps.len() - 1;
            render_tree(dep, graph, &child_prefix, last, rendered);
        }
    }
}
