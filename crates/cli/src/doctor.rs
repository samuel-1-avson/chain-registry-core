// crates/cli/src/doctor.rs
// `creg doctor` — checks local prerequisites and can probe the full bootstrap testnet.

use anyhow::{Context, Result};
use colored::Colorize;
use rand::RngCore;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

const DOCTOR_HTTP_TIMEOUT_SECS: u64 = 10;
const FAUCET_DRIP_TIMEOUT_SECS: u64 = 60;

pub struct DoctorOptions<'a> {
    pub node_url: Option<&'a str>,
    pub json: bool,
    pub testnet: bool,
    pub faucet_url: Option<&'a str>,
    pub eth_rpc_url: Option<&'a str>,
    pub explorer_url: Option<&'a str>,
    pub skip_explorer: bool,
    pub skip_drip: bool,
    pub recipient: Option<&'a str>,
}

#[derive(Serialize)]
struct DoctorReport {
    mode: &'static str,
    ok: bool,
    node_url: String,
    ipfs_url: String,
    faucet_url: Option<String>,
    eth_rpc_url: Option<String>,
    explorer_url: Option<String>,
    checks: Vec<DoctorCheck>,
}

#[derive(Serialize)]
struct DoctorCheck {
    name: String,
    required: bool,
    status: &'static str,
    message: String,
}

impl DoctorCheck {
    fn pass(name: impl Into<String>, required: bool, message: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            required,
            status: "pass",
            message: message.into(),
        }
    }

    fn fail(name: impl Into<String>, required: bool, message: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            required,
            status: "fail",
            message: message.into(),
        }
    }

    fn skipped(name: impl Into<String>, required: bool, message: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            required,
            status: "skipped",
            message: message.into(),
        }
    }

    fn is_failure(&self) -> bool {
        self.required && self.status == "fail"
    }
}

#[derive(Deserialize)]
struct NodeHealthResponse {
    status: String,
    version: Option<String>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct ChainStatsResponse {
    tip_height: Option<u64>,
    block_count: Option<u64>,
    package_count: Option<u64>,
    validator_count: Option<u64>,
    total_stake: Option<u64>,
    peer_count: Option<u64>,
    bridge_status: Option<String>,
    l1_block: Option<u64>,
}

#[derive(Deserialize)]
struct RuntimeConfigResponse {
    is_testnet: bool,
    registry_address: Option<String>,
    token_contract: Option<String>,
    staking_contract: Option<String>,
    validator_registration_mode: Option<String>,
}

#[derive(Deserialize)]
struct FaucetHealthResponse {
    status: String,
    mode: Option<String>,
    faucet_balance: Option<String>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct FaucetNetworkResponse {
    chain_id: u64,
    rpc_url: String,
    token_contract: String,
    explorer_url: String,
}

#[derive(Deserialize)]
struct FaucetChallengeResponse {
    challenge: String,
    difficulty: u8,
}

#[derive(Deserialize)]
struct FaucetDripResponse {
    success: bool,
    message: String,
    tx_hash: Option<String>,
    amount: Option<String>,
}

#[derive(Deserialize)]
struct FaucetBalanceResponse {
    balance: String,
}

#[derive(Debug, Clone)]
pub struct FaucetDripOutcome {
    pub recipient: String,
    pub amount: Option<String>,
    pub tx_hash: Option<String>,
    pub balance_before: u128,
    pub balance_after: u128,
}

fn append_fleet_consensus_checks(checks: &mut Vec<DoctorCheck>) {
    let yara_dir = std::env::var("CREG_YARA_RULES_DIR").unwrap_or_else(|_| "rules".to_string());
    let yara_ok = std::path::Path::new(&yara_dir).is_dir()
        && std::fs::read_dir(&yara_dir)
            .map(|mut entries| entries.next().is_some())
            .unwrap_or(false);
    checks.push(if yara_ok {
        DoctorCheck::pass(
            "YARA rules directory",
            false,
            format!("{yara_dir} contains rule files"),
        )
    } else {
        DoctorCheck::fail(
            "YARA rules directory",
            false,
            format!(
                "CREG_YARA_RULES_DIR={yara_dir} is missing or empty — validators may disagree on scans"
            ),
        )
    });

    let bundles = validator::bundle::AnalysisBundleSet::current();
    let refs = bundles.to_refs();
    let scanner_version = ml_validator::DeepScanner::default().model_version();
    if scanner_version.starts_with("degraded") {
        checks.push(DoctorCheck::fail(
            "Scanner version",
            true,
            format!("degraded scanner profile: {scanner_version}"),
        ));
    } else if refs.is_consensus_complete() {
        let digest = common::scanner_profile_digest(&scanner_version, &refs);
        checks.push(DoctorCheck::pass(
            "Scanner profile bundles",
            false,
            format!(
                "scanner={scanner_version} digest={}… osv_epoch={}",
                &digest[..digest.len().min(16)],
                refs.osv_snapshot_epoch
            ),
        ));
    } else {
        checks.push(DoctorCheck::fail(
            "Scanner profile bundles",
            true,
            "analysis bundle env vars are incomplete — votes may be excluded from quorum",
        ));
    }

    let llm_enabled = std::env::var("CREG_LLM_ENABLED")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    checks.push(if llm_enabled {
        DoctorCheck::fail(
            "LLM advisory lane",
            false,
            "CREG_LLM_ENABLED=true can produce non-deterministic evidence across fleet nodes",
        )
    } else {
        DoctorCheck::pass("LLM advisory lane", false, "disabled or unset")
    });

    if let Ok(raw) = std::env::var("CREG_VOTE_TIMEOUT_SECS") {
        match raw.parse::<u64>() {
            Ok(secs) if secs >= 5 => checks.push(DoctorCheck::pass(
                "Vote timeout",
                false,
                format!("CREG_VOTE_TIMEOUT_SECS={secs}"),
            )),
            Ok(secs) => checks.push(DoctorCheck::fail(
                "Vote timeout",
                false,
                format!("CREG_VOTE_TIMEOUT_SECS={secs} is very low for multi-validator quorum"),
            )),
            Err(_) => checks.push(DoctorCheck::fail(
                "Vote timeout",
                false,
                format!("CREG_VOTE_TIMEOUT_SECS={raw} is not a valid integer"),
            )),
        }
    } else {
        checks.push(DoctorCheck::pass(
            "Vote timeout",
            false,
            "unset (defaults to chain-spec vote_timeout_ms or 10s)",
        ));
    }
}

pub async fn run(options: DoctorOptions<'_>) -> Result<()> {
    if options.testnet {
        run_testnet(options).await
    } else {
        run_basic(options).await
    }
}

async fn run_basic(options: DoctorOptions<'_>) -> Result<()> {
    let node = resolve_node_url(options.node_url);
    let ipfs = resolve_ipfs_url();

    let mut checks = Vec::new();

    let (node_ok, node_msg) = check_node(&node).await;
    checks.push(if node_ok {
        DoctorCheck::pass("Chain node", true, node_msg)
    } else {
        DoctorCheck::fail("Chain node", true, node_msg)
    });

    let (sync_ok, sync_msg) = check_chain_sync(&node).await;
    checks.push(if sync_ok {
        DoctorCheck::pass("Chain sync", false, sync_msg)
    } else {
        DoctorCheck::fail("Chain sync", false, sync_msg)
    });

    let (ipfs_ok, ipfs_msg) = check_ipfs(&ipfs).await;
    checks.push(if ipfs_ok {
        DoctorCheck::pass("IPFS daemon", true, ipfs_msg)
    } else {
        DoctorCheck::fail("IPFS daemon", true, ipfs_msg)
    });

    let (key_ok, key_msg) = check_publisher_key();
    checks.push(if key_ok {
        DoctorCheck::pass("Publisher key", false, key_msg)
    } else {
        DoctorCheck::fail("Publisher key", false, key_msg)
    });

    let (nsjail_ok, nsjail_msg) = check_nsjail();
    checks.push(if nsjail_ok {
        DoctorCheck::pass("nsjail sandbox", false, nsjail_msg)
    } else {
        DoctorCheck::fail("nsjail sandbox", false, nsjail_msg)
    });

    let (gpg_ok, gpg_msg) = check_gpg();
    checks.push(if gpg_ok {
        DoctorCheck::pass("GnuPG", false, gpg_msg)
    } else {
        DoctorCheck::fail("GnuPG", false, gpg_msg)
    });

    let (cfg_ok, cfg_msg) = check_config_file();
    checks.push(if cfg_ok {
        DoctorCheck::pass("Config file", false, cfg_msg)
    } else {
        DoctorCheck::fail("Config file", false, cfg_msg)
    });

    let dev_sandbox = std::env::var("CREG_DEV_SANDBOX").as_deref() == Ok("true");
    checks.push(if dev_sandbox {
        DoctorCheck::fail(
            "Dev sandbox bypass",
            false,
            "CREG_DEV_SANDBOX=true — nsjail bypassed (dev only!)",
        )
    } else {
        DoctorCheck::pass("Dev sandbox bypass", false, "not set (production mode)")
    });

    let small_cluster_quorum =
        std::env::var("CREG_PBFT_ALLOW_SMALL_CLUSTER_QUORUM").as_deref() == Ok("true");
    checks.push(if small_cluster_quorum {
        DoctorCheck::fail(
            "PBFT small-cluster quorum",
            false,
            "CREG_PBFT_ALLOW_SMALL_CLUSTER_QUORUM=true — relaxed quorum (dev/single-node only)",
        )
    } else {
        DoctorCheck::pass(
            "PBFT small-cluster quorum",
            false,
            "not set (standard ⌊2n/3⌋+1 quorum)",
        )
    });

    let testnet_mode = std::env::var("CREG_TESTNET").as_deref() == Ok("true");
    if !testnet_mode && (dev_sandbox || small_cluster_quorum) {
        checks.push(DoctorCheck::fail(
            "Production safety",
            false,
            "CREG_TESTNET=false with dev bypass env vars — node startup will refuse this combination",
        ));
    } else if !testnet_mode {
        checks.push(DoctorCheck::pass(
            "Production safety",
            false,
            "CREG_TESTNET=false and no dev bypass env vars detected",
        ));
    } else {
        checks.push(DoctorCheck::skipped(
            "Production safety",
            false,
            "CREG_TESTNET=true (testnet mode)",
        ));
    }

    append_fleet_consensus_checks(&mut checks);

    let report = DoctorReport {
        mode: "basic",
        ok: !checks.iter().any(DoctorCheck::is_failure),
        node_url: node,
        ipfs_url: ipfs,
        faucet_url: None,
        eth_rpc_url: None,
        explorer_url: None,
        checks,
    };

    finish_report("creg doctor — system health check", report, options.json)
}

async fn run_testnet(options: DoctorOptions<'_>) -> Result<()> {
    let node = resolve_node_url(options.node_url);
    let ipfs = resolve_ipfs_url();
    let faucet = options
        .faucet_url
        .map(str::to_string)
        .or_else(|| std::env::var("CREG_FAUCET_URL").ok())
        .unwrap_or_else(|| "http://127.0.0.1:8082".to_string());
    let eth_rpc = options
        .eth_rpc_url
        .map(str::to_string)
        .or_else(|| std::env::var("CREG_ETH_RPC").ok())
        .unwrap_or_else(|| "http://127.0.0.1:8545".to_string());
    let explorer = options
        .explorer_url
        .map(str::to_string)
        .or_else(|| std::env::var("CREG_EXPLORER_URL").ok())
        .unwrap_or_else(|| "http://127.0.0.1:3007".to_string());

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(DOCTOR_HTTP_TIMEOUT_SECS))
        .build()?;

    let mut checks = Vec::new();

    let node_health_url = format!("{}/v1/health", node.trim_end_matches('/'));
    let node_health = match get_json::<NodeHealthResponse>(&client, &node_health_url).await {
        Ok(health) if health.status.eq_ignore_ascii_case("ok") => {
            let version = health
                .version
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            checks.push(DoctorCheck::pass(
                "Node health",
                true,
                format!("{} — status=ok version={}", node, version),
            ));
            Some(health)
        }
        Ok(health) => {
            checks.push(DoctorCheck::fail(
                "Node health",
                true,
                format!("{} returned status={}.", node, health.status),
            ));
            Some(health)
        }
        Err(error) => {
            checks.push(DoctorCheck::fail(
                "Node health",
                true,
                format!("Could not reach {}: {}", node, error),
            ));
            None
        }
    };

    let chain_stats_url = format!("{}/v1/chain/stats", node.trim_end_matches('/'));
    let chain_stats = match get_json::<ChainStatsResponse>(&client, &chain_stats_url).await {
        Ok(stats) => {
            let validator_count = stats.validator_count.unwrap_or(0);
            let ok = stats.tip_height.is_some() && validator_count > 0;
            let message = format!(
                "tip_height={} block_count={} validator_count={} total_stake={} peer_count={} packages={} bridge_status={} l1_block={}",
                stats.tip_height.unwrap_or(0),
                stats.block_count.unwrap_or(0),
                validator_count,
                stats.total_stake.unwrap_or(0),
                stats.peer_count.unwrap_or(0),
                stats.package_count.unwrap_or(0),
                stats.bridge_status.clone().unwrap_or_else(|| "unknown".to_string()),
                stats.l1_block.unwrap_or(0)
            );
            checks.push(if ok {
                DoctorCheck::pass("Chain stats", true, message)
            } else {
                DoctorCheck::fail("Chain stats", true, message)
            });
            Some(stats)
        }
        Err(error) => {
            checks.push(DoctorCheck::fail(
                "Chain stats",
                true,
                format!("Could not read chain stats: {}", error),
            ));
            None
        }
    };

    let runtime_config_url = format!("{}/v1/runtime/config", node.trim_end_matches('/'));
    let runtime_config = match get_json::<RuntimeConfigResponse>(&client, &runtime_config_url).await
    {
        Ok(config) => {
            let token = config.token_contract.clone().unwrap_or_default();
            let staking = config.staking_contract.clone().unwrap_or_default();
            let registry = config.registry_address.clone().unwrap_or_default();
            let ok = config.is_testnet
                && !is_zero_like_address(&token)
                && !is_zero_like_address(&staking)
                && !is_zero_like_address(&registry);
            let message = format!(
                "is_testnet={} token={} staking={} registry={} mode={}",
                config.is_testnet,
                display_address(&token),
                display_address(&staking),
                display_address(&registry),
                config
                    .validator_registration_mode
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string())
            );
            checks.push(if ok {
                DoctorCheck::pass("Runtime config", true, message)
            } else {
                DoctorCheck::fail("Runtime config", true, message)
            });
            Some(config)
        }
        Err(error) => {
            checks.push(DoctorCheck::fail(
                "Runtime config",
                true,
                format!("Could not read runtime config: {}", error),
            ));
            None
        }
    };

    let eth_chain_id =
        match rpc_hex_u64(&client, &eth_rpc, "eth_chainId", serde_json::json!([])).await {
            Ok(chain_id) => {
                let block_number =
                    rpc_hex_u64(&client, &eth_rpc, "eth_blockNumber", serde_json::json!([]))
                        .await
                        .unwrap_or(0);
                checks.push(DoctorCheck::pass(
                    "Ethereum RPC",
                    true,
                    format!("{} — chain_id={} block={}", eth_rpc, chain_id, block_number),
                ));
                Some(chain_id)
            }
            Err(error) => {
                checks.push(DoctorCheck::fail(
                    "Ethereum RPC",
                    true,
                    format!("Could not query {}: {}", eth_rpc, error),
                ));
                None
            }
        };

    if let Some(config) = &runtime_config {
        let mut contract_failures = Vec::new();
        for (label, address) in [
            ("token", config.token_contract.as_deref()),
            ("staking", config.staking_contract.as_deref()),
            ("registry", config.registry_address.as_deref()),
        ] {
            let Some(address) = address else {
                contract_failures.push(format!("{}=missing", label));
                continue;
            };
            if is_zero_like_address(address) {
                contract_failures.push(format!("{}=zero-address", label));
                continue;
            }
            match rpc_get_code(&client, &eth_rpc, address).await {
                Ok(code) if code != "0x" && code != "0x0" => {}
                Ok(_) => contract_failures.push(format!("{}={} has no bytecode", label, address)),
                Err(error) => contract_failures
                    .push(format!("{}={} lookup failed: {}", label, address, error)),
            }
        }

        checks.push(if contract_failures.is_empty() {
            DoctorCheck::pass(
                "Contract bytecode",
                true,
                "token/staking/registry bytecode present",
            )
        } else {
            DoctorCheck::fail("Contract bytecode", true, contract_failures.join("; "))
        });
    } else {
        checks.push(DoctorCheck::fail(
            "Contract bytecode",
            true,
            "Skipped because runtime config did not load",
        ));
    }

    // TX-014: CREG_TESTNET flag check — running multiple nodes on the same machine
    // requires PID-lock to be disabled via CREG_TESTNET=true (docker compose sets this).
    {
        let creg_testnet = std::env::var("CREG_TESTNET").as_deref() == Ok("true");
        checks.push(if creg_testnet {
            DoctorCheck::pass(
                "CREG_TESTNET flag",
                true,
                "CREG_TESTNET=true — PID lock disabled, multiple nodes can share this machine",
            )
        } else {
            DoctorCheck::fail(
                "CREG_TESTNET flag",
                true,
                "CREG_TESTNET not set — starting two nodes on the same machine will fail with a \
                 PID lock error. Set CREG_TESTNET=true or use docker compose (which sets it \
                 automatically).",
            )
        });
    }

    let faucet_health_url = format!("{}/health", faucet.trim_end_matches('/'));
    let faucet_health = match get_json::<FaucetHealthResponse>(&client, &faucet_health_url).await {
        Ok(health) => {
            let ok = health.status.eq_ignore_ascii_case("healthy");
            let message = format!(
                "status={} mode={} faucet_balance={}",
                health.status,
                health.mode.clone().unwrap_or_else(|| "unknown".to_string()),
                health
                    .faucet_balance
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string())
            );
            checks.push(if ok {
                DoctorCheck::pass("Faucet health", true, message)
            } else {
                DoctorCheck::fail("Faucet health", true, message)
            });
            Some(health)
        }
        Err(error) => {
            checks.push(DoctorCheck::fail(
                "Faucet health",
                true,
                format!("Could not reach {}: {}", faucet, error),
            ));
            None
        }
    };

    let faucet_network_url = format!("{}/api/network", faucet.trim_end_matches('/'));
    let faucet_network = match get_json::<FaucetNetworkResponse>(&client, &faucet_network_url).await
    {
        Ok(network) => {
            let message = format!(
                "chain_id={} rpc_url={} token={} explorer={}",
                network.chain_id,
                network.rpc_url,
                display_address(&network.token_contract),
                network.explorer_url
            );
            checks.push(DoctorCheck::pass("Faucet network", true, message));
            Some(network)
        }
        Err(error) => {
            checks.push(DoctorCheck::fail(
                "Faucet network",
                true,
                format!("Could not read faucet network config: {}", error),
            ));
            None
        }
    };

    if let (Some(network), Some(chain_id), Some(config)) =
        (&faucet_network, eth_chain_id, &runtime_config)
    {
        let token_matches = normalize_address(config.token_contract.as_deref().unwrap_or_default())
            == normalize_address(&network.token_contract);
        let chain_matches = network.chain_id == chain_id;
        let ok = token_matches && chain_matches;
        let message = format!(
            "faucet_token={} node_token={} faucet_chain_id={} rpc_chain_id={}",
            display_address(&network.token_contract),
            display_address(config.token_contract.as_deref().unwrap_or_default()),
            network.chain_id,
            chain_id
        );
        checks.push(if ok {
            DoctorCheck::pass("Address consistency", true, message)
        } else {
            DoctorCheck::fail("Address consistency", true, message)
        });
    } else {
        checks.push(DoctorCheck::fail(
            "Address consistency",
            true,
            "Could not compare faucet and runtime addresses because a prerequisite check failed",
        ));
    }

    let (ipfs_ok, ipfs_msg) = check_ipfs(&ipfs).await;
    checks.push(if ipfs_ok {
        DoctorCheck::pass("IPFS daemon", true, ipfs_msg)
    } else {
        DoctorCheck::fail("IPFS daemon", true, ipfs_msg)
    });

    if options.skip_explorer {
        checks.push(DoctorCheck::skipped(
            "Explorer",
            false,
            "Skipped by --skip-explorer",
        ));
    } else {
        let explorer_url = explorer.trim_end_matches('/').to_string();
        match client.get(&explorer_url).send().await {
            Ok(response) if response.status().is_success() => checks.push(DoctorCheck::pass(
                "Explorer",
                true,
                format!("{} — HTTP {}", explorer_url, response.status()),
            )),
            Ok(response) => checks.push(DoctorCheck::fail(
                "Explorer",
                true,
                format!("{} returned HTTP {}", explorer_url, response.status()),
            )),
            Err(error) => checks.push(DoctorCheck::fail(
                "Explorer",
                true,
                format!("Could not reach {}: {}", explorer_url, error),
            )),
        }
    }

    if options.skip_drip {
        checks.push(DoctorCheck::skipped(
            "Faucet drip probe",
            false,
            "Skipped by --skip-drip",
        ));
    } else {
        let recipient = options
            .recipient
            .map(str::to_string)
            .unwrap_or_else(random_ethereum_address);
        match run_faucet_drip_probe(&client, &faucet, &recipient).await {
            Ok(outcome) => checks.push(DoctorCheck::pass(
                "Faucet drip probe",
                true,
                format_drip_outcome(&outcome),
            )),
            Err(error) => checks.push(DoctorCheck::fail(
                "Faucet drip probe",
                true,
                format!("{}", error),
            )),
        }
    }

    let report = DoctorReport {
        mode: "testnet",
        ok: !checks.iter().any(DoctorCheck::is_failure),
        node_url: node,
        ipfs_url: ipfs,
        faucet_url: Some(faucet),
        eth_rpc_url: Some(eth_rpc),
        explorer_url: if options.skip_explorer {
            None
        } else {
            Some(explorer)
        },
        checks,
    };

    let _ = node_health;
    let _ = chain_stats;
    let _ = faucet_health;

    finish_report(
        "creg doctor — testnet end-to-end check",
        report,
        options.json,
    )
}

fn print_check(label: &str, note: &str) {
    if note.is_empty() {
        print!("  {:<24} ", label);
    } else {
        print!("  {:<24} {} ", label, note.dimmed());
    }
}

fn print_result(status: &str, msg: &str) {
    match status {
        "pass" => println!("{} {}", "✓".green(), msg),
        "skipped" => println!("{} {}", "•".yellow(), msg.yellow()),
        _ => println!("{} {}", "✗".red(), msg.red()),
    }
}

fn finish_report(title: &str, report: DoctorReport, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("{}", title.bold());
        println!("{}", "─".repeat(52).dimmed());
        for check in &report.checks {
            let note = if check.required { "" } else { "(optional)" };
            print_check(&check.name, note);
            print_result(check.status, &check.message);
        }
        println!("{}", "─".repeat(52).dimmed());
        if report.ok {
            println!("{} All checks passed.", "✓".green().bold());
        } else {
            println!(
                "{} Some required checks failed. See above for details.",
                "⚠".yellow().bold()
            );
        }
    }

    if !report.ok {
        std::process::exit(1);
    }

    Ok(())
}

fn resolve_node_url(node_url: Option<&str>) -> String {
    node_url.map(String::from).unwrap_or_else(|| {
        std::env::var("CREG_NODE_URL").unwrap_or_else(|_| "http://localhost:8080".into())
    })
}

fn resolve_ipfs_url() -> String {
    std::env::var("CREG_IPFS_URL").unwrap_or_else(|_| "http://127.0.0.1:5001".into())
}

fn is_zero_like_address(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.is_empty() || trimmed.eq_ignore_ascii_case("0x0000000000000000000000000000000000000000")
}

fn normalize_address(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn display_address(value: &str) -> String {
    if is_zero_like_address(value) {
        "<unset>".to_string()
    } else {
        value.to_string()
    }
}

async fn get_json<T: DeserializeOwned>(client: &reqwest::Client, url: &str) -> Result<T> {
    client
        .get(url)
        .send()
        .await
        .with_context(|| format!("GET {} failed", url))?
        .error_for_status()
        .with_context(|| format!("GET {} returned an error status", url))?
        .json::<T>()
        .await
        .with_context(|| format!("Could not decode JSON from {}", url))
}

async fn rpc_hex_u64(
    client: &reqwest::Client,
    rpc_url: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<u64> {
    let value = rpc_call(client, rpc_url, method, params).await?;
    let hex_value = value
        .as_str()
        .with_context(|| format!("{} did not return a hex string", method))?;
    u64::from_str_radix(hex_value.trim_start_matches("0x"), 16)
        .with_context(|| format!("Could not parse {} response: {}", method, hex_value))
}

async fn rpc_get_code(client: &reqwest::Client, rpc_url: &str, address: &str) -> Result<String> {
    let value = rpc_call(
        client,
        rpc_url,
        "eth_getCode",
        serde_json::json!([address, "latest"]),
    )
    .await?;
    value
        .as_str()
        .map(str::to_string)
        .context("eth_getCode did not return a string")
}

async fn rpc_call(
    client: &reqwest::Client,
    rpc_url: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value> {
    let response = client
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1,
        }))
        .send()
        .await
        .with_context(|| format!("RPC {} call to {} failed", method, rpc_url))?
        .error_for_status()
        .with_context(|| {
            format!(
                "RPC {} call to {} returned an error status",
                method, rpc_url
            )
        })?
        .json::<serde_json::Value>()
        .await
        .with_context(|| format!("Could not decode RPC {} response", method))?;

    if let Some(error) = response.get("error") {
        anyhow::bail!("RPC {} returned error: {}", method, error);
    }

    response
        .get("result")
        .cloned()
        .context("RPC response missing result field")
}

fn random_ethereum_address() -> String {
    let mut bytes = [0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    if bytes.iter().all(|byte| *byte == 0) {
        bytes[0] = 1;
    }
    format!("0x{}", hex::encode(bytes))
}

pub fn default_faucet_url() -> String {
    std::env::var("CREG_FAUCET_URL").unwrap_or_else(|_| "http://127.0.0.1:8082".to_string())
}

pub async fn faucet_drip_probe(
    faucet_url: &str,
    recipient: Option<&str>,
) -> Result<FaucetDripOutcome> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(FAUCET_DRIP_TIMEOUT_SECS))
        .build()?;
    let recipient = recipient
        .map(str::to_string)
        .unwrap_or_else(random_ethereum_address);
    run_faucet_drip_probe(&client, faucet_url, &recipient).await
}

pub fn format_drip_outcome(outcome: &FaucetDripOutcome) -> String {
    format!(
        "recipient={} amount={} tx_hash={} balance_before={} balance_after={}",
        outcome.recipient,
        outcome
            .amount
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        outcome
            .tx_hash
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        outcome.balance_before,
        outcome.balance_after
    )
}

async fn run_faucet_drip_probe(
    client: &reqwest::Client,
    faucet_url: &str,
    recipient: &str,
) -> Result<FaucetDripOutcome> {
    let before = faucet_balance(client, faucet_url, recipient)
        .await
        .unwrap_or(0);
    let challenge: FaucetChallengeResponse = get_json(
        client,
        &format!("{}/api/challenge", faucet_url.trim_end_matches('/')),
    )
    .await?;
    let nonce = solve_pow(&challenge.challenge, challenge.difficulty);

    let drip_url = format!("{}/api/drip", faucet_url.trim_end_matches('/'));
    let response = client
        .post(&drip_url)
        .timeout(Duration::from_secs(FAUCET_DRIP_TIMEOUT_SECS))
        .json(&serde_json::json!({
            "address": recipient,
            "challenge": challenge.challenge,
            "nonce": nonce,
        }))
        .send()
        .await
        .with_context(|| {
            format!(
                "Faucet drip request failed for {} via {} after {}s",
                recipient, drip_url, FAUCET_DRIP_TIMEOUT_SECS
            )
        })?;

    let status = response.status();
    let body = response
        .text()
        .await
        .with_context(|| format!("Could not read faucet drip response body from {}", drip_url))?;
    let response = serde_json::from_str::<FaucetDripResponse>(&body).with_context(|| {
        format!(
            "Could not decode faucet drip response from {} (status {}): {}",
            drip_url, status, body
        )
    })?;

    if !response.success {
        anyhow::bail!(
            "faucet drip failed for {} (status {}): {}",
            recipient,
            status,
            response.message
        );
    }

    let after = faucet_balance(client, faucet_url, recipient).await?;
    if after <= before {
        anyhow::bail!(
            "faucet drip did not increase balance for {} (before={}, after={})",
            recipient,
            before,
            after
        );
    }

    Ok(FaucetDripOutcome {
        recipient: recipient.to_string(),
        amount: response.amount,
        tx_hash: response.tx_hash,
        balance_before: before,
        balance_after: after,
    })
}

async fn faucet_balance(client: &reqwest::Client, faucet_url: &str, address: &str) -> Result<u128> {
    let response: FaucetBalanceResponse = get_json(
        client,
        &format!(
            "{}/api/balance/{}",
            faucet_url.trim_end_matches('/'),
            address
        ),
    )
    .await?;
    response
        .balance
        .parse::<u128>()
        .with_context(|| format!("Could not parse faucet balance for {}", address))
}

fn solve_pow(challenge: &str, difficulty: u8) -> String {
    let mut nonce = 0u64;
    loop {
        let nonce_str = nonce.to_string();
        let mut hasher = Sha256::new();
        hasher.update(challenge.as_bytes());
        hasher.update(nonce_str.as_bytes());
        let hash = hasher.finalize();

        let mut leading_zeros = 0u8;
        for byte in hash {
            if byte == 0 {
                leading_zeros += 8;
            } else {
                leading_zeros += byte.leading_zeros() as u8;
                break;
            }
            if leading_zeros >= difficulty {
                break;
            }
        }

        if leading_zeros >= difficulty {
            return nonce_str;
        }

        nonce = nonce.saturating_add(1);
    }
}

async fn check_node(node: &str) -> (bool, String) {
    let url = format!("{}/v1/health", node.trim_end_matches('/'));
    let start = Instant::now();

    match reqwest::Client::new()
        .get(&url)
        .timeout(Duration::from_secs(5))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => {
            let latency = start.elapsed().as_millis();
            (true, format!("{} — {}ms", node, latency))
        }
        Ok(r) => (false, format!("{} returned HTTP {}", node, r.status())),
        Err(e) => (false, format!("Cannot reach {} — {}", node, e)),
    }
}

async fn check_chain_sync(node: &str) -> (bool, String) {
    let url = format!("{}/v1/chain/stats", node.trim_end_matches('/'));
    match reqwest::Client::new()
        .get(&url)
        .timeout(Duration::from_secs(5))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => match r.json::<serde_json::Value>().await {
            Ok(v) => {
                let height = v.get("tip_height").and_then(|h| h.as_u64()).unwrap_or(0);
                let pkgs = v.get("package_count").and_then(|p| p.as_u64()).unwrap_or(0);
                (true, format!("height={} packages={}", height, pkgs))
            }
            Err(_) => (false, "Could not parse chain stats response".into()),
        },
        _ => (false, "Could not reach chain stats endpoint".into()),
    }
}

async fn check_ipfs(ipfs: &str) -> (bool, String) {
    let url = format!("{}/api/v0/id", ipfs.trim_end_matches('/'));
    match reqwest::Client::new()
        .post(&url)
        .timeout(Duration::from_secs(5))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => match r.json::<serde_json::Value>().await {
            Ok(v) => {
                let id = v.get("ID").and_then(|i| i.as_str()).unwrap_or("unknown");
                (true, format!("{} — peer {}", ipfs, &id[..id.len().min(12)]))
            }
            Err(_) => (true, format!("{} — reachable", ipfs)),
        },
        Ok(r) => (false, format!("{} returned HTTP {}", ipfs, r.status())),
        Err(e) => (
            false,
            format!(
                "IPFS daemon not running at {} — start with 'ipfs daemon'. Error: {}",
                ipfs, e
            ),
        ),
    }
}

fn check_publisher_key() -> (bool, String) {
    // Check env var first, then config file default location.
    if let Ok(path) = std::env::var("CREG_PUBLISHER_KEY") {
        let p = std::path::Path::new(&path);
        if p.exists() {
            return (true, format!("found at {}", path));
        }
        return (
            false,
            format!("CREG_PUBLISHER_KEY set but file not found: {}", path),
        );
    }

    // Config default: ~/.creg/publisher.key
    let default = dirs::home_dir()
        .unwrap_or_default()
        .join(".creg")
        .join("publisher.key");

    if default.exists() {
        return (true, format!("found at {}", default.display()));
    }

    (false, "No publisher key found. Run: creg keygen".into())
}

fn check_nsjail() -> (bool, String) {
    match which::which("nsjail") {
        Ok(p) => (true, format!("found at {}", p.display())),
        Err(_) => (
            false,
            "nsjail not in PATH — sandbox will use WASM fallback".into(),
        ),
    }
}

fn check_gpg() -> (bool, String) {
    match which::which("gpg") {
        Ok(p) => {
            // Get gpg version
            let ver = std::process::Command::new("gpg")
                .arg("--version")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .and_then(|s| s.lines().next().map(String::from))
                .unwrap_or_else(|| "unknown version".into());
            (true, format!("{} — {}", p.display(), ver.trim()))
        }
        Err(_) => (false, "gpg not in PATH — PGP signing unavailable".into()),
    }
}

fn check_config_file() -> (bool, String) {
    let cfg_path = dirs::home_dir()
        .unwrap_or_default()
        .join(".creg")
        .join("config.toml");

    if cfg_path.exists() {
        (true, format!("found at {}", cfg_path.display()))
    } else {
        (
            false,
            format!(
                "not found at {} — run: creg config init",
                cfg_path.display()
            ),
        )
    }
}
