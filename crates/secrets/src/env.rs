use crate::{normalize_secp256k1_hex, HotKeyRole};
use anyhow::{bail, Context, Result};

#[derive(Debug, Clone, Copy, Default)]
pub struct EnvSecretsBackend;

impl EnvSecretsBackend {
    pub fn secp256k1_signing_key_hex(&self, role: HotKeyRole) -> Result<String> {
        let raw = std::env::var(role.env_var())
            .with_context(|| format!("{} is not set", role.env_var()))?;
        if raw.trim().is_empty() {
            bail!("{} is empty", role.env_var());
        }
        normalize_secp256k1_hex(&raw, role)
    }
}
