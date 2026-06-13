// crates/cli/src/testnet.rs
// Testnet utilities and commands

use crate::doctor;
use anyhow::{bail, Context, Result};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Testnet configuration
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestnetConfig {
    pub network: String,
    pub chain_id: u64,
    pub rpc_url: String,
    pub token_contract: String,
    pub staking_contract: String,
    pub faucet_url: String,
    pub node_url: String,
}

impl Default for TestnetConfig {
    fn default() -> Self {
        Self {
            network: "testnet".to_string(),
            chain_id: 31337,
            rpc_url: "http://localhost:8545".to_string(),
            token_contract: std::env::var("TESTNET_TOKEN_ADDR").unwrap_or_default(),
            staking_contract: std::env::var("TESTNET_STAKING_ADDR").unwrap_or_default(),
            faucet_url: "http://localhost:8082".to_string(),
            node_url: "http://localhost:8080".to_string(),
        }
    }
}

/// Request test tokens from faucet
pub async fn drip(address: &str, faucet_url: Option<&str>) -> Result<()> {
    let url = faucet_url
        .map(str::to_string)
        .unwrap_or_else(doctor::default_faucet_url);

    // Validate address
    if !address.starts_with("0x") || address.len() != 42 {
        bail!("Invalid Ethereum address format. Expected: 0x... (42 chars)");
    }

    println!(
        "{} Requesting test tokens for {}",
        "💧".cyan(),
        address.cyan()
    );
    println!("  Faucet: {}", url);

    let outcome = doctor::faucet_drip_probe(&url, Some(address))
        .await
        .with_context(|| format!("Failed to request test tokens from {}", url))?;

    println!("\n{} Test tokens received!", "✓".green().bold());
    if let Some(amount) = &outcome.amount {
        println!("  Amount: {}", amount.yellow());
    }
    if let Some(tx_hash) = &outcome.tx_hash {
        println!("  Transaction: {}", tx_hash.dimmed());
    }
    println!(
        "  Balance delta: {} -> {}",
        outcome.balance_before.to_string().dimmed(),
        outcome.balance_after.to_string().green()
    );
    println!(
        "\n{} You can now stake tokens and use the testnet.",
        "💡".yellow()
    );
    println!("  Stake as publisher: creg testnet stake-publisher 1 --key 0x...");
    println!("  Stake as validator: creg testnet stake-validator 100 --key 0x...");

    Ok(())
}

/// Check testnet status
pub async fn status(node_url: Option<&str>) -> Result<()> {
    let url = node_url.unwrap_or("http://localhost:8080");
    let client = reqwest::Client::new();

    println!("{}", "Chain Registry Testnet Status".bold().underline());
    println!();

    // Check node
    match client.get(format!("{}/v1/health", url)).send().await {
        Ok(resp) if resp.status().is_success() => {
            println!("{} Node: {}", "●".green(), "Online".green());

            // Try to get chain info
            if let Ok(info) = client.get(format!("{}/v1/chain/stats", url)).send().await {
                if let Ok(data) = info.json::<serde_json::Value>().await {
                    if let Some(tip) = data["tip_height"].as_u64() {
                        println!("  Chain tip: {}", tip.to_string().cyan());
                    }
                }
            }
        }
        _ => println!("{} Node: {}", "●".red(), "Offline".red()),
    }

    // Check faucet
    match client.get("http://localhost:8082/health").send().await {
        Ok(resp) if resp.status().is_success() => {
            println!("{} Faucet: {}", "●".green(), "Online".green());

            // Get faucet stats
            if let Ok(stats) = client.get("http://localhost:8082/api/stats").send().await {
                if let Ok(data) = stats.json::<serde_json::Value>().await {
                    if let Some(amount) = data["drip_amount"].as_str() {
                        let amt = amount.parse::<u128>().unwrap_or(0) / 10u128.pow(18);
                        println!("  Drip amount: {} tCREG", amt.to_string().cyan());
                    }
                    if let Some(cd) = data["cooldown_seconds"].as_u64() {
                        println!("  Cooldown: {} seconds", cd.to_string().cyan());
                    }
                }
            }
        }
        _ => println!("{} Faucet: {}", "●".red(), "Offline".red()),
    }

    // Check explorer
    match client.get("http://localhost:3000").send().await {
        Ok(resp) if resp.status().is_success() => {
            println!("{} Explorer: {}", "●".green(), "Online".green());
        }
        _ => println!("{} Explorer: {}", "●".red(), "Offline".red()),
    }

    println!();
    println!("{}", "URLs:".bold());
    println!("  Node:    http://localhost:8080");
    println!("  Faucet:  http://localhost:8082");
    println!("  Explorer: http://localhost:3000");

    Ok(())
}

/// Stake as publisher on testnet
pub async fn stake_publisher(amount_eth: f64, key: &str, rpc_url: Option<&str>) -> Result<()> {
    let rpc = rpc_url.unwrap_or("http://localhost:8545");
    let staking = std::env::var("TESTNET_STAKING_ADDR")
        .context("TESTNET_STAKING_ADDR not set. Run scripts/start-testnet.ps1 first.")?;

    if amount_eth < 1.0 {
        bail!("Minimum publisher stake on testnet is 1 tCREG");
    }

    let wei = (amount_eth * 1e18) as u128;

    println!("{} Staking {} tCREG as publisher", "💰".cyan(), amount_eth);
    println!("  Contract: {}", staking.dimmed());
    println!("  Network:  {} (Testnet)", rpc.dimmed());

    // First approve token spend
    println!("\n  Approving token spend...");
    let approve_status = std::process::Command::new("cast")
        .args([
            "send",
            &std::env::var("TESTNET_TOKEN_ADDR")?,
            "approve(address,uint256)",
            &staking,
            &wei.to_string(),
            "--private-key",
            key,
            "--rpc-url",
            rpc,
        ])
        .status()
        .context("Failed to approve tokens. Is Foundry installed?")?;

    if !approve_status.success() {
        bail!("Token approval failed");
    }

    // Then stake
    println!("  Staking tokens...");
    let stake_status = std::process::Command::new("cast")
        .args([
            "send",
            &staking,
            "stakeAsPublisher(uint256)",
            &wei.to_string(),
            "--private-key",
            key,
            "--rpc-url",
            rpc,
        ])
        .status()
        .context("Failed to stake tokens")?;

    if stake_status.success() {
        println!("\n{}", "✓ Stake successful!".green().bold());
        println!("  You can now publish packages on the testnet.");
        println!("\n{} Next steps:", "💡".yellow());
        println!("  1. Generate publisher key: creg keygen publisher");
        println!("  2. Publish a package: creg publish <tarball> --key ~/.creg/publisher.key");
    } else {
        bail!("Stake transaction failed");
    }

    Ok(())
}

/// Stake as validator on testnet
pub async fn stake_validator(amount_eth: f64, key: &str, rpc_url: Option<&str>) -> Result<()> {
    let rpc = rpc_url.unwrap_or("http://localhost:8545");
    let staking = std::env::var("TESTNET_STAKING_ADDR")
        .context("TESTNET_STAKING_ADDR not set. Run scripts/start-testnet.ps1 first.")?;

    if amount_eth < 100.0 {
        bail!("Minimum validator stake on testnet is 100 tCREG");
    }

    let wei = (amount_eth * 1e18) as u128;

    println!("{} Staking {} tCREG as validator", "🔐".cyan(), amount_eth);
    println!("  Contract: {}", staking.dimmed());
    println!("  Network:  {} (Testnet)", rpc.dimmed());

    // First approve token spend
    println!("\n  Approving token spend...");
    let approve_status = std::process::Command::new("cast")
        .args([
            "send",
            &std::env::var("TESTNET_TOKEN_ADDR")?,
            "approve(address,uint256)",
            &staking,
            &wei.to_string(),
            "--private-key",
            key,
            "--rpc-url",
            rpc,
        ])
        .status()
        .context("Failed to approve tokens")?;

    if !approve_status.success() {
        bail!("Token approval failed");
    }

    // Then apply as validator
    println!("  Applying as validator...");
    let stake_status = std::process::Command::new("cast")
        .args([
            "send",
            &staking,
            "applyToBeValidator(uint256)",
            &wei.to_string(),
            "--private-key",
            key,
            "--rpc-url",
            rpc,
        ])
        .status()
        .context("Failed to apply as validator")?;

    if stake_status.success() {
        println!("\n{}", "✓ Validator application submitted!".green().bold());
        println!("  Your stake is pending activation by the operator.");
        println!("\n{} Next steps:", "💡".yellow());
        println!("  1. Generate validator key: creg keygen validator");
        println!("  2. Start validator node:");
        println!("     CREG_IS_VALIDATOR=true CREG_VALIDATOR_KEY=<key> creg-node");
    } else {
        bail!("Validator application failed");
    }

    Ok(())
}

/// Reset testnet (clear local data)
pub fn reset(data_dir: Option<PathBuf>) -> Result<()> {
    let dir = data_dir.unwrap_or_else(|| PathBuf::from("./testnet-data"));

    println!("{} Testnet Reset", "⚠️".yellow().bold());
    println!();
    println!("This will delete all local testnet data:");
    println!("  - {}", dir.display());
    println!();
    println!("Docker volumes must be reset separately:");
    println!("  docker compose --env-file .env.testnet -f docker-compose.testnet.yml down -v");
    println!();

    // In a real implementation, we'd ask for confirmation here
    // For now, just show what would happen
    println!("{}", "To reset manually:".yellow());
    println!("  1. Stop all testnet services");
    println!("  2. Delete data directory: rm -rf {}", dir.display());
    println!("  3. Reset Docker volumes");
    println!("  4. Redeploy contracts: .\\scripts\\start-testnet.ps1");

    Ok(())
}

/// Show testnet documentation
pub fn docs() {
    println!(
        "{}",
        r#"
╔══════════════════════════════════════════════════════════════════════════╗
║                     Chain Registry Testnet Guide                         ║
╚══════════════════════════════════════════════════════════════════════════╝

QUICK START
───────────
1. Start the testnet:
    .\\scripts\\start-testnet.ps1

2. Deploy contracts (first time only):
    Included in the startup script

3. Get test tokens:
   creg testnet drip 0xYourAddress

    The CLI automatically fetches a PoW challenge, solves it, and submits the
    correct faucet request payload for the current testnet faucet.

4. Stake and participate:
    creg testnet stake-publisher 1 --key 0xYourPrivateKey
    creg testnet stake-validator 100 --key 0xYourPrivateKey

FAUCET
──────
The faucet distributes 1000 tCREG per request with a 1-minute cooldown.
Web UI: http://localhost:8082
CLI:    creg testnet drip 0xYourAddress

STAKING REQUIREMENTS (Testnet)
──────────────────────────────
• Publisher: 1 tCREG
• Validator: 100 tCREG
• Unbonding: 14 days

USEFUL COMMANDS
───────────────
# Check testnet status
  creg testnet status

# Get your token balance
  cast balance 0xYourAddress --rpc-url http://localhost:8545
  cast call $TESTNET_TOKEN_ADDR "balanceOf(address)" 0xYourAddress \
    --rpc-url http://localhost:8545

# Stake tokens directly with cast
    cast send $TESTNET_STAKING_ADDR "stakeAsPublisher(uint256)" 1000000000000000000 \
    --private-key 0xYourKey --rpc-url http://localhost:8545

# View contract information
  cast call $TESTNET_STAKING_ADDR "getPublisherStake(address)" 0xYourAddress \
    --rpc-url http://localhost:8545

PRE-FUNDED ANVIL ACCOUNTS
─────────────────────────
Account #0: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 (10,000 ETH)
  Private Key: 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

Account #1: 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 (Faucet, 1,000,000 tCREG)
  Private Key: 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d

RESET TESTNET
─────────────
To completely reset the testnet:

    docker compose --env-file .env.testnet -f docker-compose.testnet.yml down -v
  rm -rf testnet/artifacts
    .\\scripts\\start-testnet.ps1

DIFFERENCES FROM MAINNET
────────────────────────
• Uses test tCREG tokens with no real value
• Production-like staking thresholds for validator lifecycle testing
• Fast block times (2 seconds)
• Local faucet funding for testing
• Local Ethereum (Anvil) instead of real network

TROUBLESHOOTING
───────────────
• Node won't start: Check CREG_VALIDATOR_KEY is set correctly
• Faucet offline: Verify Anvil is running and contracts deployed
• Cannot stake: Ensure you have tCREG (not ETH) and have approved the staking contract

For more help: https://github.com/your-org/chain-registry/docs/TESTNET.md
"#
        .cyan()
    );
}
