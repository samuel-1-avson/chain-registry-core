use crate::{extract_vault_field, normalize_secp256k1_hex, HotKeyRole};
use anyhow::{bail, Context, Result};
use reqwest::Client;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct VaultSecretsBackend {
    addr: String,
    token: String,
    client: Client,
}

impl VaultSecretsBackend {
    pub fn from_env() -> Result<Self> {
        let addr = std::env::var("VAULT_ADDR")
            .or_else(|_| std::env::var("CREG_VAULT_ADDR"))
            .context("VAULT_ADDR or CREG_VAULT_ADDR must be set when CREG_SECRETS_BACKEND=vault")?;
        let token = std::env::var("VAULT_TOKEN")
            .or_else(|_| std::env::var("CREG_VAULT_TOKEN"))
            .context(
                "VAULT_TOKEN or CREG_VAULT_TOKEN must be set when CREG_SECRETS_BACKEND=vault",
            )?;
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("failed to build Vault HTTP client")?;
        Ok(Self {
            addr,
            token,
            client,
        })
    }

    pub async fn secp256k1_signing_key_hex(&self, role: HotKeyRole) -> Result<String> {
        let path = std::env::var(role.vault_path_env())
            .unwrap_or_else(|_| role.default_vault_path().to_string());
        let data = self.read_kv2_secret(&path).await?;
        let raw = extract_vault_field(&data, role).with_context(|| {
            format!(
                "no recognized key field in Vault secret {path} (tried {:?})",
                role.vault_field_candidates()
            )
        })?;
        normalize_secp256k1_hex(&raw, role)
    }

    async fn read_kv2_secret(&self, path: &str) -> Result<serde_json::Value> {
        let path = path.trim().trim_start_matches('/');
        let url = format!("{}/v1/{}", self.addr.trim_end_matches('/'), path);
        let resp = self
            .client
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .with_context(|| format!("Vault GET {url} failed"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Vault GET {url} returned {status}: {body}");
        }

        let json: serde_json::Value = resp
            .json()
            .await
            .context("Vault response is not valid JSON")?;
        json.get("data")
            .and_then(|d| d.get("data"))
            .cloned()
            .context("Vault KV v2 response missing data.data")
    }
}
