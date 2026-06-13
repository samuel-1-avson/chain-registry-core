// crates/cli/src/blocks.rs
// `creg blocks` — non-interactive chain explorer command.

use anyhow::{Context, Result};
use colored::Colorize;
use serde_json::Value;

pub async fn run(node_url: Option<&str>, limit: usize) -> Result<()> {
    let api_base = node_url
        .map(String::from)
        .unwrap_or_else(|| {
            std::env::var("CREG_NODE_URL").unwrap_or_else(|_| "http://localhost:8080".into())
        })
        .trim_end_matches('/')
        .to_string();

    let client = reqwest::Client::new();

    // 1. Get chain stats
    let stats: Value = client
        .get(format!("{}/v1/chain/stats", api_base))
        .send()
        .await?
        .json()
        .await
        .context("Failed to fetch chain stats")?;

    let tip = stats["tip_height"].as_u64().unwrap_or(0);
    let pkg_count = stats["package_count"].as_u64().unwrap_or(0);

    println!(
        "\n{} {} {}",
        "⛓".bold(),
        "Chain Registry Explorer".bold(),
        "⛓".bold()
    );
    println!(
        "{} Height: {} | Verified Packages: {}\n",
        "→".cyan(),
        tip.to_string().yellow(),
        pkg_count.to_string().yellow()
    );

    println!(
        "{:<8} {:<18} {:<10} {:<30}",
        "HEIGHT", "PROPOSER", "TXS", "CONTENT / EVENTS"
    );
    println!("{}", "─".repeat(80).dimmed());

    // 2. Fetch blocks
    let start = tip.saturating_sub(limit as u64 - 1);
    for h in (start..=tip).rev() {
        if let Ok(res) = client
            .get(format!("{}/v1/blocks/{}", api_base, h))
            .send()
            .await
        {
            if let Ok(block) = res.json::<Value>().await {
                render_block(&block);
            }
        }
    }

    Ok(())
}

fn render_block(block: &Value) {
    let height = block["header"]["height"].as_u64().unwrap_or(0);
    let proposer = block["header"]["proposer_id"].as_str().unwrap_or("?");
    let txs = block["transactions"].as_array();
    let tx_count = txs.map(|v| v.len()).unwrap_or(0);

    let height_str = format!("#{}", height).white().bold();

    print!(
        "{:<16} {:<18} {:<10} ",
        height_str,
        proposer.dimmed(),
        tx_count
    );

    if let Some(tx_list) = txs {
        if tx_list.is_empty() {
            println!("{}", "Empty Block".dimmed());
        } else {
            for (i, tx) in tx_list.iter().enumerate() {
                if i > 0 {
                    print!("\n{:<44} ", "");
                }
                render_tx(tx);
            }
            println!();
        }
    } else {
        println!();
    }
}

fn render_tx(tx: &Value) {
    let tx_type = tx["type"].as_str().unwrap_or("unknown");
    match tx_type {
        "publish" => {
            let eco = tx["id"]["ecosystem"].as_str().unwrap_or("?");
            let name = tx["id"]["name"].as_str().unwrap_or("?");
            let ver = tx["id"]["version"].as_str().unwrap_or("?");
            let canonical = format!("{}:{}@{}", eco, name, ver);
            let status = tx["status"].as_str().unwrap_or("?");
            let color_status = if status == "Verified" {
                "Verified".green()
            } else {
                status.yellow()
            };
            print!("{} {} [{}]", "📦".cyan(), canonical.bold(), color_status);
        }
        "revoke" => {
            let canonical = tx["package_canonical"].as_str().unwrap_or("?");
            let reason = tx["reason"].as_str().unwrap_or("?");
            print!(
                "{} {} {} ({})",
                "⚡".red(),
                "REVOKED".red().bold(),
                canonical,
                reason.dimmed()
            );
        }
        _ => {
            print!("{} {}", "❓".dimmed(), tx_type.dimmed());
        }
    }
}
