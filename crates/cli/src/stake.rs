// crates/cli/src/stake.rs
// `creg stake` — stakes tokens on the Staking contract so a publisher
// can submit packages or a validator can join the consensus set.

use anyhow::{bail, Context, Result};

#[derive(Debug, Clone, PartialEq)]
pub enum StakeRole {
    Publisher,
    Validator,
}

/// Stake CREG tokens via the Staking smart contract.
///
/// The Staking contract custodies **ERC-20 CREG**, not native ETH, so this runs
/// the same two-step flow used on Sepolia: `approve(staking, amount)` on the
/// token contract, then `stakeAsPublisher(uint256)` / `applyToBeValidator(uint256)`
/// on the staking contract. Requires Foundry `cast` and a funded secp256k1 EOA key
/// (NOT an Ed25519 `creg keygen` key).
pub async fn run(
    amount_tokens: f64,
    role: StakeRole,
    key_path: Option<&std::path::Path>,
    rpc_url: Option<&str>,
    staking_addr: Option<&str>,
    token_addr: Option<&str>,
) -> Result<()> {
    let rpc = rpc_url.unwrap_or("http://127.0.0.1:8545");

    if amount_tokens <= 0.0 {
        bail!("Stake amount must be greater than 0");
    }

    let min_tokens = match role {
        StakeRole::Publisher => 1.0,
        StakeRole::Validator => 100.0,
    };

    if amount_tokens < min_tokens {
        bail!(
            "Minimum stake for {:?} is {} CREG (you specified {} CREG)",
            role,
            min_tokens,
            amount_tokens
        );
    }

    let staking = resolve_addr(
        staking_addr,
        &[
            "CREG_STAKING_ADDR",
            "STAKING_CONTRACT_ADDR",
            "TESTNET_STAKING_ADDR",
        ],
    )
    .context("Staking contract address required. Pass --staking-addr or set CREG_STAKING_ADDR.")?;

    let token = resolve_addr(token_addr, &["CREG_TOKEN_ADDR", "TESTNET_TOKEN_ADDR"]).context(
        "CREG token address required for the ERC-20 approve step. \
         Pass --token-addr or set CREG_TOKEN_ADDR.",
    )?;

    // Use string-based decimal-to-wei conversion to avoid float precision loss.
    let wei = eth_to_wei_str(amount_tokens);
    let stake_sig = match role {
        StakeRole::Publisher => "stakeAsPublisher(uint256)",
        StakeRole::Validator => "applyToBeValidator(uint256)",
    };

    println!("\n  Staking {} CREG as {:?}", amount_tokens, role);
    println!("  Token:     {}", token);
    println!("  Staking:   {}", staking);
    println!("  Network:   {}", rpc);
    println!(
        "  Flow:      approve({}, {}) then {}",
        staking, wei, stake_sig
    );

    // If a key file was provided, read the private key and send both transactions.
    if let Some(kp) = key_path {
        let key = std::fs::read_to_string(kp)
            .with_context(|| format!("Cannot read key file: {}", kp.display()))?;
        let key = key.trim();

        if crate::keygen::looks_like_creg_ed25519_secret_hex(key) {
            crate::keygen::print_ed25519_derived_eth_warning();
            bail!(
                "The key file looks like a CREG Ed25519 secret from `creg keygen`.\n\
                 `creg stake` sends transactions with `cast` and needs a standard Ethereum\n\
                 wallet private key (32-byte secp256k1), not your Ed25519 validator/publisher key.\n\
                 Fund and use a separate EOA, or run the printed `cast send` with --private-key $EOA_KEY.\n\
                 See docs/WALLET_KEY_DERIVATION.md."
            );
        }

        // Step 1 — approve the staking contract to pull `wei` CREG.
        println!("\n  [1/2] Approving token spend...");
        let approve = std::process::Command::new("cast")
            .args([
                "send",
                &token,
                "approve(address,uint256)",
                &staking,
                &wei,
                "--private-key",
                key,
                "--rpc-url",
                rpc,
            ])
            .status()
            .context("cast not found — install Foundry: https://getfoundry.sh")?;
        if !approve.success() {
            bail!("Token approval failed (exit code {:?})", approve.code());
        }

        // Step 2 — stake / apply.
        println!("  [2/2] Sending stake transaction...");
        let staked = std::process::Command::new("cast")
            .args([
                "send",
                &staking,
                stake_sig,
                &wei,
                "--private-key",
                key,
                "--rpc-url",
                rpc,
            ])
            .status()
            .context("cast not found — install Foundry: https://getfoundry.sh")?;

        if staked.success() {
            println!("\n  ✓ Stake transaction confirmed.");
            match role {
                StakeRole::Publisher => {
                    println!("    You can now publish packages with: creg publish <tarball>");
                }
                StakeRole::Validator => {
                    println!(
                        "    Validator application submitted; pending operator/consensus admission.\n\
                         Set CREG_IS_VALIDATOR=true and start creg-node to join consensus."
                    );
                }
            }
        } else {
            bail!("Stake transaction failed (exit code {:?})", staked.code());
        }
    } else {
        // No key — print the two cast commands for the user to run manually.
        println!("\n  No key file provided. Run these two commands to stake:\n");
        println!("  # 1. Approve the staking contract to pull your CREG");
        println!(
            "  cast send {} \"approve(address,uint256)\" {} {} \\",
            token, staking, wei
        );
        println!("    --private-key $YOUR_EOA_KEY --rpc-url {}\n", rpc);
        println!("  # 2. Stake");
        println!("  cast send {} \"{}\" {} \\", staking, stake_sig, wei);
        println!("    --private-key $YOUR_EOA_KEY --rpc-url {}", rpc);
    }

    Ok(())
}

/// Resolve a contract address from an explicit CLI value or a list of fallback
/// environment variables, skipping empty values and the zero address.
fn resolve_addr(explicit: Option<&str>, env_keys: &[&str]) -> Result<String> {
    if let Some(addr) = explicit {
        if !addr.is_empty() && addr != "0x0000000000000000000000000000000000000000" {
            return Ok(addr.to_string());
        }
    }
    for key in env_keys {
        if let Ok(val) = std::env::var(key) {
            if !val.is_empty() && val != "0x0000000000000000000000000000000000000000" {
                return Ok(val);
            }
        }
    }
    bail!("contract address not provided")
}

/// Convert ETH amount to wei string without float precision loss.
fn eth_to_wei_str(eth: f64) -> String {
    let s = format!("{:.18}", eth);
    let parts: Vec<&str> = s.split('.').collect();
    let integer = parts[0];
    let fraction = if parts.len() > 1 {
        parts[1]
    } else {
        "000000000000000000"
    };
    let fraction = &format!("{:0<18}", fraction)[..18];
    let combined = format!("{}{}", integer, fraction);
    // Strip leading zeros but keep at least "0"
    let trimmed = combined.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Parse "0.01eth" / "1ETH" / "1000000000000000000wei" → f64 ETH.
pub fn parse_amount(s: &str) -> Result<f64> {
    let s = s.trim().to_lowercase();
    if let Some(rest) = s.strip_suffix("wei") {
        let wei: u128 = rest.trim().parse().context("Invalid wei amount")?;
        return Ok(wei as f64 / 1e18);
    }
    if let Some(rest) = s.strip_suffix("eth") {
        let eth: f64 = rest.trim().parse().context("Invalid ETH amount")?;
        return Ok(eth);
    }
    // Plain number — assume ETH.
    s.parse::<f64>()
        .context("Invalid amount — use '0.01eth' or '1000wei'")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_eth() {
        assert!((parse_amount("1eth").unwrap() - 1.0).abs() < 1e-9);
        assert!((parse_amount("0.01ETH").unwrap() - 0.01).abs() < 1e-9);
    }

    #[test]
    fn parse_wei() {
        let eth = parse_amount("1000000000000000000wei").unwrap();
        assert!((eth - 1.0).abs() < 1e-9);
    }

    #[test]
    fn parse_plain() {
        assert!((parse_amount("2.5").unwrap() - 2.5).abs() < 1e-9);
    }

    #[test]
    fn publisher_min_stake() {
        // 0.001 CREG should fail for publisher (min 1 CREG)
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(run(0.001, StakeRole::Publisher, None, None, None, None))
            .unwrap_err();
    }
}
