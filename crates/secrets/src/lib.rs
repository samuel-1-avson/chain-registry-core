//! Hot secp256k1 secret loading for bridge, faucet, and relayer (SEC-301b).
//!
//! See `docs/adr/ADR-KMS-HOT-KEYS.md`.

mod env;
mod vault;

use anyhow::{bail, Context, Result};
use std::fmt;

pub use env::EnvSecretsBackend;
pub use vault::VaultSecretsBackend;

/// Services that use Ethereum secp256k1 signing keys from this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HotKeyRole {
    Bridge,
    Faucet,
    Relayer,
    /// Ed25519 validator key stored as hex in Vault (node only).
    ValidatorEd25519,
}

impl HotKeyRole {
    pub fn env_var(self) -> &'static str {
        match self {
            Self::Bridge => "CREG_BRIDGE_KEY",
            Self::Faucet => "FAUCET_PRIVATE_KEY",
            Self::Relayer => "RELAYER_PRIVATE_KEY",
            Self::ValidatorEd25519 => "CREG_VALIDATOR_KEY",
        }
    }

    pub fn default_vault_path(self) -> &'static str {
        match self {
            Self::Bridge => "secret/data/creg/bridge",
            Self::Faucet => "secret/data/creg/faucet",
            Self::Relayer => "secret/data/creg/relayer",
            Self::ValidatorEd25519 => "secret/data/creg/validator",
        }
    }

    pub fn vault_path_env(self) -> &'static str {
        match self {
            Self::Bridge => "CREG_VAULT_SECRET_PATH_BRIDGE",
            Self::Faucet => "CREG_VAULT_SECRET_PATH_FAUCET",
            Self::Relayer => "CREG_VAULT_SECRET_PATH_RELAYER",
            Self::ValidatorEd25519 => "CREG_VAULT_SECRET_PATH_VALIDATOR",
        }
    }

    fn vault_field_candidates(self) -> &'static [&'static str] {
        match self {
            Self::Bridge => &["private_key", "bridge_key", "key"],
            Self::Faucet => &["private_key", "faucet_key", "key"],
            Self::Relayer => &["private_key", "relayer_key", "key"],
            Self::ValidatorEd25519 => &["validator_key", "private_key", "key"],
        }
    }
}

/// Secret backend selected at process startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretsBackend {
    Env,
    Vault,
}

impl fmt::Display for SecretsBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Env => write!(f, "env"),
            Self::Vault => write!(f, "vault"),
        }
    }
}

/// Loads hot keys from environment variables or HashiCorp Vault KV v2.
#[derive(Debug, Clone)]
pub struct SecretsProvider {
    backend: SecretsBackend,
    env: EnvSecretsBackend,
    vault: Option<VaultSecretsBackend>,
}

impl SecretsProvider {
    /// Build from `CREG_SECRETS_BACKEND` (`env` default, or `vault`).
    pub fn from_env() -> Result<Self> {
        let backend = parse_backend(std::env::var("CREG_SECRETS_BACKEND").ok().as_deref())?;
        let env = EnvSecretsBackend;
        let vault = if backend == SecretsBackend::Vault {
            Some(VaultSecretsBackend::from_env()?)
        } else {
            None
        };
        Ok(Self {
            backend,
            env,
            vault,
        })
    }

    pub fn backend(&self) -> SecretsBackend {
        self.backend
    }

    /// Load a 32-byte secp256k1 private key as hex (optional `0x` prefix).
    pub async fn secp256k1_signing_key_hex(&self, role: HotKeyRole) -> Result<String> {
        match self.backend {
            SecretsBackend::Env => self.env.secp256k1_signing_key_hex(role),
            SecretsBackend::Vault => {
                let vault = self
                    .vault
                    .as_ref()
                    .context("vault backend not initialized")?;
                vault.secp256k1_signing_key_hex(role).await
            }
        }
    }

    /// Optional load: returns `None` if the role's secret is not configured.
    pub async fn try_secp256k1_signing_key_hex(&self, role: HotKeyRole) -> Result<Option<String>> {
        if self.backend == SecretsBackend::Env {
            match std::env::var(role.env_var()) {
                Err(_) => return Ok(None),
                Ok(v) if v.trim().is_empty() => return Ok(None),
                Ok(_) => {}
            }
        }
        match self.secp256k1_signing_key_hex(role).await {
            Ok(key) => Ok(Some(key)),
            Err(e) => {
                let msg = e.to_string();
                if self.backend == SecretsBackend::Vault
                    && (msg.contains("404") || msg.contains("not found"))
                {
                    Ok(None)
                } else if self.backend == SecretsBackend::Env {
                    Ok(None)
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Emit SEC-101b warning when the active backend is env and not testnet.
    pub fn warn_hot_key_if_env(
        &self,
        service: &str,
        role: HotKeyRole,
        key_hex: &str,
        testnet_mode: bool,
    ) {
        if self.backend == SecretsBackend::Env {
            common::warn_hot_key_from_env(service, role.env_var(), key_hex, testnet_mode);
        }
    }
}

fn parse_backend(raw: Option<&str>) -> Result<SecretsBackend> {
    match raw.unwrap_or("env").trim().to_ascii_lowercase().as_str() {
        "" | "env" | "environment" => Ok(SecretsBackend::Env),
        "vault" | "hashicorp" | "hashicorp-vault" => Ok(SecretsBackend::Vault),
        other => bail!("unsupported CREG_SECRETS_BACKEND={other:?} (use 'env' or 'vault')"),
    }
}

/// Production gate: plaintext env hot keys are not allowed off testnet (ADR SEC-301).
pub fn validate_production_secrets_policy(is_testnet: bool) -> Vec<String> {
    if is_testnet {
        return Vec::new();
    }

    let mut errors = Vec::new();
    let backend = match std::env::var("CREG_SECRETS_BACKEND") {
        Ok(v) => v,
        Err(_) => return errors, // default env — check below
    };
    let backend = backend.trim().to_ascii_lowercase();
    if backend.is_empty() || backend == "env" || backend == "environment" {
        errors.push(
            "CREG_SECRETS_BACKEND=env (or unset) is not allowed when CREG_TESTNET=false — \
             configure HashiCorp Vault (CREG_SECRETS_BACKEND=vault) for production hot keys."
                .into(),
        );
    }
    errors
}

pub(crate) fn normalize_secp256k1_hex(key: &str, role: HotKeyRole) -> Result<String> {
    let raw = key.trim().trim_start_matches("0x");
    let bytes = hex::decode(raw).with_context(|| format!("{} is not valid hex", role.env_var()))?;
    if bytes.len() != 32 {
        bail!(
            "{} must be 32 bytes (64 hex chars), got {} bytes",
            role.env_var(),
            bytes.len()
        );
    }
    Ok(format!("0x{}", hex::encode(bytes)))
}

pub(crate) fn extract_vault_field(data: &serde_json::Value, role: HotKeyRole) -> Option<String> {
    let override_field = std::env::var("CREG_VAULT_SECRET_FIELD").ok();
    if let Some(name) = override_field {
        if let Some(v) = data.get(&name).and_then(|v| v.as_str()) {
            return Some(v.to_string());
        }
    }
    for field in role.vault_field_candidates() {
        if let Some(v) = data.get(field).and_then(|v| v.as_str()) {
            return Some(v.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_rejects_env_backend_off_testnet() {
        std::env::set_var("CREG_SECRETS_BACKEND", "env");
        let errs = validate_production_secrets_policy(false);
        assert!(!errs.is_empty());
        std::env::remove_var("CREG_SECRETS_BACKEND");
    }

    #[test]
    fn production_allows_vault_backend_off_testnet() {
        std::env::set_var("CREG_SECRETS_BACKEND", "vault");
        let errs = validate_production_secrets_policy(false);
        assert!(errs.is_empty());
        std::env::remove_var("CREG_SECRETS_BACKEND");
    }

    #[test]
    fn extract_vault_field_prefers_role_specific() {
        let data = serde_json::json!({
            "bridge_key": "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
        });
        let key = extract_vault_field(&data, HotKeyRole::Bridge).unwrap();
        assert!(key.starts_with("0x59"));
    }
}
