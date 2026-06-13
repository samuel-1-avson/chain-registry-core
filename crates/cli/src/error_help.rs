// crates/cli/src/error_help.rs
// Context-aware error messages with suggestions

use colored::Colorize;

pub fn print_error_with_help(error: &str) {
    eprintln!("\n{} {}", "✗ Error:".red().bold(), error);

    // Parse error and provide contextual help
    if error.contains("connection refused") || error.contains("Cannot reach") {
        print_node_connection_help();
    } else if error.contains("private key") || error.contains("key not found") {
        print_key_help();
    } else if error.contains("stake") || error.contains("insufficient") {
        print_stake_help();
    } else if error.contains("ipfs") || error.contains("IPFS") {
        print_ipfs_help();
    } else if error.contains("docker") || error.contains("Docker") {
        print_docker_help();
    } else {
        print_general_help();
    }
}

fn print_node_connection_help() {
    eprintln!("\n{}", "Possible solutions:".bold());
    eprintln!("  1. Start your local node:");
    eprintln!("     {}", "docker-compose up -d".cyan());
    eprintln!();
    eprintln!("  2. Check node status:");
    eprintln!("     {}", "creg doctor".cyan());
    eprintln!();
    eprintln!("  3. Use a public node (read-only):");
    eprintln!(
        "     {}",
        "export CREG_NODE_URL=https://node.creg.dev".cyan()
    );
    eprintln!();
    eprintln!("  4. Run the setup wizard:");
    eprintln!("     {}", "creg init".cyan());
}

fn print_key_help() {
    eprintln!("\n{}", "Key Setup Required:".bold());
    eprintln!("  1. Generate a new key:");
    eprintln!("     {}", "creg keygen publisher".cyan());
    eprintln!("     {}", "creg keygen validator".cyan());
    eprintln!();
    eprintln!("  2. Or set environment variable:");
    eprintln!("     {}", "export CREG_PUBLISHER_KEY=/path/to/key".cyan());
    eprintln!();
    eprintln!("  3. Run the setup wizard:");
    eprintln!("     {}", "creg init".cyan());
}

fn print_stake_help() {
    eprintln!("\n{}", "Staking Information:".bold());
    eprintln!("  • Publisher minimum: 1 CREG");
    eprintln!("  • Validator minimum: 100 CREG");
    eprintln!();
    eprintln!("  1. Stake as publisher:");
    eprintln!("     {}", "creg stake 1 --key-file /path/to/key".cyan());
    eprintln!();
    eprintln!("  2. Stake as validator:");
    eprintln!(
        "     {}",
        "creg stake 100 --role validator --key-file /path/to/key".cyan()
    );
    eprintln!();
    eprintln!("  3. Check your balance:");
    eprintln!("     {}", "cast balance $ADDRESS --rpc-url $RPC".cyan());
}

fn print_ipfs_help() {
    eprintln!("\n{}", "IPFS Setup Required:".bold());
    eprintln!("  1. Install IPFS:");
    eprintln!(
        "     {}",
        "https://docs.ipfs.io/install/".cyan().underline()
    );
    eprintln!();
    eprintln!("  2. Start IPFS daemon:");
    eprintln!("     {}", "ipfs daemon".cyan());
    eprintln!();
    eprintln!("  3. Or use public gateway (slower):");
    eprintln!("     {}", "export CREG_IPFS_URL=https://ipfs.io".cyan());
}

fn print_docker_help() {
    eprintln!("\n{}", "Docker Required:".bold());
    eprintln!("  1. Install Docker:");
    eprintln!(
        "     {}",
        "https://docs.docker.com/get-docker/".cyan().underline()
    );
    eprintln!();
    eprintln!("  2. Start Docker Desktop");
    eprintln!();
    eprintln!("  3. Verify installation:");
    eprintln!("     {}", "docker --version".cyan());
}

fn print_general_help() {
    eprintln!("\n{}", "Need help?".bold());
    eprintln!("  • Run the setup wizard: {}", "creg init".cyan());
    eprintln!("  • Check system health: {}", "creg doctor".cyan());
    eprintln!(
        "  • View documentation: {}",
        "https://docs.creg.dev".cyan().underline()
    );
    eprintln!("  • Get command help: {}", "creg --help".cyan());
}

#[allow(dead_code)]
pub fn print_progress(operation: &str, current: usize, total: usize) {
    let width = 40;
    let filled = (current * width) / total;
    let empty = width - filled;

    let bar: String = format!("[{}{}]", "█".repeat(filled), "░".repeat(empty));

    let percent = (current * 100) / total;

    eprint!(
        "\r  {} {} {}% ({}/{})",
        operation.dimmed(),
        bar.cyan(),
        percent,
        current,
        total
    );

    if current == total {
        eprintln!(); // New line when complete
    }
}

#[allow(dead_code)]
pub fn print_success(message: &str) {
    println!("  {} {}", "✓".green().bold(), message);
}

#[allow(dead_code)]
pub fn print_warning(message: &str) {
    println!("  {} {}", "⚠".yellow().bold(), message);
}

#[allow(dead_code)]
pub fn print_info(message: &str) {
    println!("  {} {}", "→".blue(), message.dimmed());
}
