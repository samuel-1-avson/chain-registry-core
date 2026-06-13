// crates/cli/src/faucet_client.rs
// Thin HTTP client for the testnet faucet service (see crates/faucet).
// Used by the TUI's Faucet pane to let operators drip tCREG to an address
// without leaving the terminal.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Deserialize)]
pub struct Challenge {
    pub challenge: String,
    pub difficulty: u8,
    #[serde(default)]
    #[allow(dead_code)]
    pub ttl_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NetworkInfo {
    #[serde(default)]
    pub chain_id: u64,
    #[serde(default)]
    pub chain_name: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub native_currency_symbol: String,
    #[serde(default)]
    pub rpc_url: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub token_contract: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DripResponse {
    pub success: bool,
    #[serde(default)]
    pub tx_hash: Option<String>,
    #[serde(default)]
    pub amount: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct BalanceResponse {
    #[serde(default)]
    pub balance: Option<String>,
    #[serde(default)]
    pub native_balance: Option<String>,
    #[serde(default)]
    pub balance_formatted: Option<String>,
    #[serde(default)]
    pub native_balance_formatted: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct DripRequestBody {
    address: String,
    challenge: String,
    nonce: String,
}

pub async fn get_challenge(client: &reqwest::Client, base: &str) -> Result<Challenge> {
    let url = format!("{}/api/challenge", base.trim_end_matches('/'));
    let res = client.get(&url).send().await?;
    if !res.status().is_success() {
        return Err(anyhow!("challenge HTTP {}", res.status()));
    }
    Ok(res.json::<Challenge>().await?)
}

pub async fn get_network(client: &reqwest::Client, base: &str) -> Result<NetworkInfo> {
    let url = format!("{}/api/network", base.trim_end_matches('/'));
    Ok(client
        .get(&url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

pub async fn get_balance(
    client: &reqwest::Client,
    base: &str,
    address: &str,
) -> Result<BalanceResponse> {
    let url = format!(
        "{}/api/balance/{}",
        base.trim_end_matches('/'),
        address.trim_start_matches("0x")
    );
    let res = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await?
        .error_for_status()?;
    // Read as text first so we can surface the raw body in the Err message
    // if the JSON shape is unexpected. The faucet has returned different
    // shapes in the past (e.g. `{"error":"..."}` on failure).
    let body = res.text().await?;
    serde_json::from_str::<BalanceResponse>(&body).map_err(|e| {
        anyhow!(
            "balance parse failed ({}): body={}",
            e,
            truncate(&body, 200)
        )
    })
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}

pub async fn drip(
    client: &reqwest::Client,
    base: &str,
    address: &str,
    challenge: &str,
    nonce: &str,
) -> Result<DripResponse> {
    let url = format!("{}/api/drip", base.trim_end_matches('/'));
    let body = DripRequestBody {
        address: address.to_string(),
        challenge: challenge.to_string(),
        nonce: nonce.to_string(),
    };
    let res = client.post(&url).json(&body).send().await?;
    let status = res.status();
    let parsed: DripResponse = res
        .json()
        .await
        .map_err(|e| anyhow!("drip response parse failed ({}): {}", status, e))?;
    Ok(parsed)
}

/// Solve the faucet PoW: find a nonce such that
/// SHA-256(challenge || nonce) has `difficulty` leading zero bits.
/// Blocking CPU work — callers should run it on a blocking task.
pub fn solve_pow(challenge: &str, difficulty: u8) -> String {
    let mut nonce: u64 = 0;
    loop {
        let candidate = nonce.to_string();
        if pow_matches(challenge, &candidate, difficulty) {
            return candidate;
        }
        nonce += 1;
    }
}

fn pow_matches(challenge: &str, nonce: &str, difficulty: u8) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(challenge.as_bytes());
    hasher.update(nonce.as_bytes());
    let digest = hasher.finalize();
    leading_zero_bits(&digest) >= difficulty
}

fn leading_zero_bits(bytes: &[u8]) -> u8 {
    let mut count: u8 = 0;
    for b in bytes {
        if *b == 0 {
            count = count.saturating_add(8);
            if count == u8::MAX {
                return count;
            }
        } else {
            count = count.saturating_add(b.leading_zeros() as u8);
            return count;
        }
    }
    count
}

/// Basic EIP-55-ish validation: 0x + 40 hex chars.
pub fn is_valid_evm_address(s: &str) -> bool {
    let s = s.trim();
    let hex = s.strip_prefix("0x").unwrap_or(s);
    hex.len() == 40 && hex.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leading_zero_bits_on_zero_byte() {
        assert_eq!(leading_zero_bits(&[0x00, 0xFF]), 8);
        assert_eq!(leading_zero_bits(&[0x0F, 0xFF]), 4);
        assert_eq!(leading_zero_bits(&[0x80]), 0);
        assert_eq!(leading_zero_bits(&[0xFF]), 0);
    }

    #[test]
    fn solve_pow_low_difficulty() {
        let nonce = solve_pow("deadbeef", 4);
        assert!(pow_matches("deadbeef", &nonce, 4));
    }

    #[test]
    fn address_validation() {
        assert!(is_valid_evm_address(
            "0xf4c0bdbb681a61aa0b123e82c04b0d692f53d58e"
        ));
        assert!(is_valid_evm_address(
            "f4c0bdbb681a61aa0b123e82c04b0d692f53d58e"
        ));
        assert!(!is_valid_evm_address("0xf4c0"));
        assert!(!is_valid_evm_address(
            "0xZZZZbdbb681a61aa0b123e82c04b0d692f53d58e"
        ));
    }
}
