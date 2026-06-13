// crates/cli/src/watch.rs
// `creg watch` — streams live registry events from the SSE endpoint
// and renders them as formatted terminal output.
//
// Usage:
//   creg watch                      — all events
//   creg watch --filter verified    — only verified packages
//   creg watch --filter pkg:express — only events for a specific package

use anyhow::Result;
use colored::Colorize;

pub async fn run(filter: Option<&str>, node_url: Option<&str>, ci_mode: bool) -> Result<()> {
    let url = format!(
        "{}/v1/events",
        node_url
            .map(String::from)
            .unwrap_or_else(|| {
                std::env::var("CREG_NODE_URL").unwrap_or_else(|_| "http://localhost:8080".into())
            })
            .trim_end_matches('/')
    );

    if ci_mode {
        println!(
            "{} CI mode — watching for Critical security events (exits 1 on Critical)",
            "⚠".yellow().bold()
        );
    }
    println!(
        "{} Connecting to event stream at {}",
        "→".cyan(),
        url.dimmed()
    );
    if let Some(f) = filter {
        println!("{} Filter: {}", "→".cyan(), f.yellow());
    }
    println!("{}", "─".repeat(60).dimmed());

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .build()?;

    let mut retry_count = 0u32;
    let max_retries = 10u32;

    'reconnect: loop {
        let mut response = match client
            .get(&url)
            .header("Accept", "text/event-stream")
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                retry_count = 0;
                r
            }
            Ok(r) => {
                eprintln!("{} Server returned {}", "✗".red(), r.status());
                if retry_count >= max_retries {
                    break;
                }
                let delay = std::cmp::min(1u64 << retry_count, 30);
                retry_count += 1;
                eprintln!(
                    "{} Reconnecting in {}s... ({}/{})",
                    "↻".yellow(),
                    delay,
                    retry_count,
                    max_retries
                );
                tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
                continue 'reconnect;
            }
            Err(e) => {
                eprintln!("{} Connection failed: {}", "✗".red(), e);
                if retry_count >= max_retries {
                    break;
                }
                let delay = std::cmp::min(1u64 << retry_count, 30);
                retry_count += 1;
                eprintln!(
                    "{} Reconnecting in {}s... ({}/{})",
                    "↻".yellow(),
                    delay,
                    retry_count,
                    max_retries
                );
                tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
                continue 'reconnect;
            }
        };

        let mut buffer = String::new();

        loop {
            // Read chunks from the SSE stream.
            let chunk = match response.chunk().await {
                Ok(Some(c)) => c,
                Ok(None) => {
                    eprintln!("{} Stream closed by server.", "⚠".yellow());
                    if retry_count >= max_retries {
                        break 'reconnect;
                    }
                    let delay = std::cmp::min(1u64 << retry_count, 30);
                    retry_count += 1;
                    eprintln!(
                        "{} Reconnecting in {}s... ({}/{})",
                        "↻".yellow(),
                        delay,
                        retry_count,
                        max_retries
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
                    continue 'reconnect;
                }
                Err(e) => {
                    eprintln!("{} Stream error: {}", "✗".red(), e);
                    if retry_count >= max_retries {
                        break 'reconnect;
                    }
                    let delay = std::cmp::min(1u64 << retry_count, 30);
                    retry_count += 1;
                    eprintln!(
                        "{} Reconnecting in {}s... ({}/{})",
                        "↻".yellow(),
                        delay,
                        retry_count,
                        max_retries
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
                    continue 'reconnect;
                }
            };

            buffer.push_str(&String::from_utf8_lossy(&chunk));

            // SSE messages are separated by double newlines.
            while let Some(end) = buffer.find("\n\n") {
                let message = buffer[..end].to_string();
                buffer = buffer[end + 2..].to_string();

                if let Some(event) = parse_sse(&message) {
                    if should_display(&event, filter) {
                        render_event(&event);
                        if ci_mode && is_critical_event(&event) {
                            eprintln!(
                                "{} Critical security event detected — exiting with code 1 (CI mode)",
                                "✗".red().bold()
                            );
                            std::process::exit(1);
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

#[derive(Debug)]
struct SseEvent {
    kind: String,
    data: serde_json::Value,
}

fn parse_sse(raw: &str) -> Option<SseEvent> {
    let mut kind = String::new();
    let mut data = String::new();

    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("event: ") {
            kind = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("data: ") {
            data = rest.trim().to_string();
        } else if line.starts_with(':') {
            // SSE comment / heartbeat — skip.
        }
    }

    if kind.is_empty() || data.is_empty() {
        return None;
    }

    let json: serde_json::Value = serde_json::from_str(&data).ok()?;
    Some(SseEvent { kind, data: json })
}

fn is_critical_event(event: &SseEvent) -> bool {
    // In CI mode, any rejected or revoked package event is critical.
    matches!(event.kind.as_str(), "PackageRejected" | "PackageRevoked")
}

fn should_display(event: &SseEvent, filter: Option<&str>) -> bool {
    let Some(f) = filter else { return true };
    let canonical = event
        .data
        .get("canonical")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if f.starts_with("pkg:") {
        return canonical.contains(&f[4..]);
    }
    // Filter by event kind.
    event.kind.to_lowercase().contains(&f.to_lowercase())
}

fn render_event(event: &SseEvent) {
    let ts = event
        .data
        .get("ts")
        .and_then(|v| v.as_str())
        .map(|s| &s[11..19]) // HH:MM:SS
        .unwrap_or("?");

    let canonical = event
        .data
        .get("canonical")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    match event.kind.as_str() {
        "PackageVerified" => {
            let block = event
                .data
                .get("block_hash")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let validators = event
                .data
                .get("validator_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            println!(
                "{} {} {} {} {} {} {}",
                ts.dimmed(),
                "✓ VERIFIED ".green().bold(),
                canonical.white().bold(),
                "block".dimmed(),
                block.dimmed(),
                "validators".dimmed(),
                validators.to_string().dimmed(),
            );
        }

        "PackageSubmitted" => {
            let publisher = event
                .data
                .get("publisher_pubkey")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            println!(
                "{} {} {} {}",
                ts.dimmed(),
                "↑ SUBMITTED".cyan(),
                canonical.white(),
                format!("by {}...", publisher).dimmed(),
            );
        }

        "PackageRejected" => {
            let reason = event
                .data
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown reason");
            println!(
                "{} {} {} {}",
                ts.dimmed(),
                "✗ REJECTED ".red().bold(),
                canonical.white(),
                format!("({})", reason).red().dimmed(),
            );
        }

        "PackageRevoked" => {
            let reason = event
                .data
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            println!(
                "{} {} {} {}",
                ts.dimmed(),
                "⊘ REVOKED  ".red().bold(),
                canonical.white().bold(),
                format!("— {}", reason).red(),
            );
        }

        "BlockProduced" => {
            let height = event
                .data
                .get("height")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let hash = event
                .data
                .get("hash")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let tx_count = event
                .data
                .get("tx_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            println!(
                "{} {} {} {} {}",
                ts.dimmed(),
                "▣ BLOCK    ".purple(),
                format!("#{}", height).white(),
                hash.dimmed(),
                format!("({} tx)", tx_count).dimmed(),
            );
        }

        "ValidatorVoted" => {
            let vid = event
                .data
                .get("validator_id")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let approved = event
                .data
                .get("approved")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let icon = if approved { "✓".green() } else { "✗".red() };
            println!(
                "{} {} {} {} {}",
                ts.dimmed(),
                "◈ VOTE     ".yellow(),
                icon,
                vid.dimmed(),
                format!("on {}", canonical).dimmed(),
            );
        }

        other => {
            println!("{} {} {:?}", ts.dimmed(), other.dimmed(), event.data);
        }
    }
}
