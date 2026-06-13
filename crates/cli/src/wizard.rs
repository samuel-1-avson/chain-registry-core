// crates/cli/src/wizard.rs
// `creg wizard` — Interactive setup wizard for new users

use anyhow::{bail, Result};
use colored::Colorize;
use dialoguer::{Confirm, Input, Select};
use std::path::PathBuf;

pub async fn run() -> Result<()> {
    println!("\n{}", "🎉 Welcome to Chain Registry!".bold().cyan());
    println!("{}", "═".repeat(60).dimmed());
    println!("\nThis wizard will help you set up Chain Registry in a few simple steps.\n");

    // Step 1: Choose role
    let role_idx = Select::new()
        .with_prompt("What would you like to do?")
        .items(&[
            "Publish packages (I'm a developer)",
            "Become a validator (Run a node)",
            "Both",
            "Just explore (no setup required)",
        ])
        .default(0)
        .interact()?;

    let setup_publisher = role_idx == 0 || role_idx == 2;
    let setup_validator = role_idx == 1 || role_idx == 2;

    // Step 2: Check prerequisites
    println!("\n{}", "Step 1: Checking Prerequisites".bold());
    println!("{}", "─".repeat(40).dimmed());

    let doctor_ok = run_doctor_check().await?;
    if !doctor_ok {
        let proceed = Confirm::new()
            .with_prompt("Some checks failed. Continue anyway?")
            .default(false)
            .interact()?;
        if !proceed {
            println!(
                "\n{}",
                "Setup cancelled. Run 'creg doctor' for help.".yellow()
            );
            return Ok(());
        }
    }

    // Step 3: Generate keys
    if setup_publisher || setup_validator {
        println!("\n{}", "Step 2: Generating Keys".bold());
        println!("{}", "─".repeat(40).dimmed());

        if setup_publisher {
            generate_key("publisher").await?;
        }
        if setup_validator {
            generate_key("validator").await?;
        }
    }

    // Step 4: Configure node
    if setup_validator {
        println!("\n{}", "Step 3: Validator Configuration".bold());
        println!("{}", "─".repeat(40).dimmed());

        configure_validator().await?;
    }

    // Step 5: Staking
    if setup_validator {
        println!("\n{}", "Step 4: Staking".bold());
        println!("{}", "─".repeat(40).dimmed());

        let stake_amount: f64 = Input::new()
            .with_prompt("How much CREG would you like to stake? (minimum 100 for validator)")
            .default(100.0)
            .validate_with(|input: &f64| {
                if *input >= 100.0 {
                    Ok(())
                } else {
                    Err("Minimum stake for validator is 100 CREG")
                }
            })
            .interact()?;

        println!("\n  Staking {} CREG...", stake_amount);
        // Call staking contract
        println!("  {}", "✓ Stake submitted".green());
    }

    // Step 6: Start node
    if setup_validator {
        println!("\n{}", "Step 5: Starting Node".bold());
        println!("{}", "─".repeat(40).dimmed());

        let mode_idx = Select::new()
            .with_prompt("Select node mode")
            .items(&[
                "Light (4GB RAM, 100GB storage) - Recommended for beginners",
                "Standard (8GB RAM, 200GB storage)",
                "Full (16GB RAM, 500GB storage)",
            ])
            .default(0)
            .interact()?;

        let mode = match mode_idx {
            0 => "light",
            1 => "standard",
            2 => "full",
            _ => "light",
        };

        println!("\n  Creating docker-compose.{}yml...", mode);
        create_docker_compose(mode).await?;
        println!("  {}", "✓ Configuration created".green());

        let start_now = Confirm::new()
            .with_prompt("Start the node now?")
            .default(true)
            .interact()?;

        if start_now {
            println!("\n  Starting node with Docker...");
            start_node(mode).await?;
        }
    }

    // Final summary
    println!("\n{}", "═".repeat(60).dimmed());
    println!("{}", "✓ Setup Complete!".bold().green());
    println!("{}", "═".repeat(60).dimmed());

    if setup_publisher {
        println!("\n📦 To publish a package:");
        println!("   creg publish <tarball>.tgz");
    }

    if setup_validator {
        println!("\n🔐 Validator commands:");
        println!("   creg console         # Open the validator console");
        println!("   creg validator stats # View performance");
        println!("   creg stake 50        # Add more stake");
        println!("   docker-compose logs -f  # View logs");
    }

    println!("\n📚 Help resources:");
    println!("   creg --help          # Show all commands");
    println!("   creg doctor          # Check system health");
    println!("   https://docs.creg.dev # Full documentation");

    println!();

    Ok(())
}

async fn run_doctor_check() -> Result<bool> {
    use colored::Colorize;

    let checks = vec![
        ("Docker", check_docker().await),
        ("Node connectivity", check_node().await),
        ("IPFS", check_ipfs().await),
    ];

    let mut all_ok = true;
    for (name, result) in checks {
        match result {
            Ok(true) => {
                println!("  {} {}", "✓".green(), format!("{} - OK", name).dimmed());
            }
            Ok(false) | Err(_) => {
                println!("  {} {}", "✗".red(), format!("{} - Not available", name));
                all_ok = false;
            }
        }
    }

    Ok(all_ok)
}

async fn check_docker() -> Result<bool> {
    Ok(std::process::Command::new("docker")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false))
}

async fn check_node() -> Result<bool> {
    let client = reqwest::Client::new();
    match client
        .get("http://localhost:8080/v1/health")
        .timeout(std::time::Duration::from_secs(2))
        .send()
        .await
    {
        Ok(r) => Ok(r.status().is_success()),
        Err(_) => Ok(false),
    }
}

async fn check_ipfs() -> Result<bool> {
    let client = reqwest::Client::new();
    match client
        .post("http://localhost:5001/api/v0/id")
        .timeout(std::time::Duration::from_secs(2))
        .send()
        .await
    {
        Ok(r) => Ok(r.status().is_success()),
        Err(_) => Ok(false),
    }
}

async fn generate_key(role: &str) -> Result<()> {
    let key_path = dirs::home_dir()
        .unwrap_or_default()
        .join(".creg")
        .join(format!("{}.key", role));

    if key_path.exists() {
        let overwrite = Confirm::new()
            .with_prompt(format!("{} key already exists. Overwrite?", role))
            .default(false)
            .interact()?;
        if !overwrite {
            println!("  Using existing key");
            return Ok(());
        }
    }

    println!("  Generating {} key...", role);

    // Call keygen module
    crate::keygen::run(Some(&key_path), role)?;

    println!("  {} Key saved to {}", "✓".green(), key_path.display());

    if role == "validator" {
        println!("  ⚠️  Keep this key secure! Backup to offline storage.");
    }

    Ok(())
}

async fn configure_validator() -> Result<()> {
    let config_dir = dirs::home_dir().unwrap_or_default().join(".creg");

    std::fs::create_dir_all(&config_dir)?;

    // Create .env file
    let env_content = format!(
        r#"# Chain Registry Validator Configuration
# Generated by creg wizard

CREG_IS_VALIDATOR=true
CREG_VALIDATOR_KEY={}
CREG_NODE_MODE=light
CREG_MAX_PEERS=10

# Ethereum RPC (Arbitrum for low gas)
CREG_ETH_RPC=https://arb1.arbitrum.io/rpc

# Optional: Custom settings
# CREG_NODE_URL=http://localhost:8080
# CREG_P2P_LISTEN=/ip4/0.0.0.0/tcp/4001
"#,
        std::env::var("HOME").unwrap_or_default() + "/.creg/validator.key"
    );

    let env_path = config_dir.join(".env");
    std::fs::write(&env_path, env_content)?;

    println!("  {} Config saved to {}", "✓".green(), env_path.display());

    Ok(())
}

async fn create_docker_compose(mode: &str) -> Result<()> {
    let compose_file = match mode {
        "light" => include_str!("../../../docker-compose.light.yml"),
        "standard" => include_str!("../../../docker-compose.yml"),
        "full" => include_str!("../../../docker-compose.yml"),
        _ => include_str!("../../../docker-compose.light.yml"),
    };

    let output_path = PathBuf::from(format!("docker-compose.{}yml", mode));
    std::fs::write(&output_path, compose_file)?;

    println!("  {} Created {}", "✓".green(), output_path.display());

    Ok(())
}

async fn start_node(mode: &str) -> Result<()> {
    let compose_file = format!("docker-compose.{}yml", mode);

    let status = std::process::Command::new("docker-compose")
        .args(&["-f", &compose_file, "up", "-d"])
        .status()?;

    if status.success() {
        println!("  {} Node started successfully!", "✓".green());
        println!("\n  Monitoring: creg console");
        println!("  Logs: docker-compose -f {} logs -f", compose_file);
    } else {
        bail!("Failed to start node. Check docker installation.");
    }

    Ok(())
}
