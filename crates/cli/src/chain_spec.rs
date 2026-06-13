use anyhow::{bail, Context, Result};
use clap::Subcommand;
use std::path::{Path, PathBuf};

#[derive(Subcommand)]
pub enum ChainSpecCommands {
    /// Validate a local chain-spec.json file (JSON schema, genesis hash, optional signature).
    Validate {
        #[arg(value_name = "FILE")]
        path: String,
        /// Detached Ed25519 signature file (hex). Defaults to `<FILE>.sig` when present.
        #[arg(long, short = 's', value_name = "FILE")]
        signature: Option<String>,
        /// Signing pubkey (hex). Defaults to `signing.signing_key_pubkey_hex` in the spec.
        #[arg(long, value_name = "HEX")]
        pubkey: Option<String>,
        /// Fail if no signature file is found (strict mode for CI / release checks).
        #[arg(long)]
        require_signature: bool,
        /// Skip signature verification even when a `.sig` file exists.
        #[arg(long)]
        skip_signature: bool,
    },
    /// Compute and print the genesis hash for a spec file.
    ComputeGenesisHash {
        #[arg(value_name = "FILE")]
        path: String,
    },
    /// Diff the live spec against your cached copy.
    Diff,
}

pub async fn run(cmd: ChainSpecCommands) -> Result<()> {
    match cmd {
        ChainSpecCommands::Validate {
            path,
            signature,
            pubkey,
            require_signature,
            skip_signature,
        } => validate_spec(
            &path,
            signature.as_deref(),
            pubkey.as_deref(),
            require_signature,
            skip_signature,
        ),
        ChainSpecCommands::ComputeGenesisHash { path } => {
            let spec = load_spec(&path)?;
            let hash = spec.compute_genesis_hash()?;
            println!("{}", hash);
            Ok(())
        }
        ChainSpecCommands::Diff => {
            let cache_dir = dirs::cache_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
            let cache_path = cache_dir.join("creg").join("chain-spec.cached.json");
            if !cache_path.exists() {
                anyhow::bail!("No cached spec found at {}", cache_path.display());
            }
            let cached = std::fs::read_to_string(&cache_path)?;
            let spec: common::ChainSpec = serde_json::from_str(&cached)?;
            let hash = spec.compute_genesis_hash()?;
            println!("Cached spec: {} (genesis_hash: {})", spec.chain_id, hash);
            // TODO: fetch live spec and diff
            Ok(())
        }
    }
}

fn load_spec(path: &str) -> Result<common::ChainSpec> {
    let json = std::fs::read_to_string(path).with_context(|| format!("read spec file {}", path))?;
    serde_json::from_str(&json).map_err(|e| anyhow::anyhow!("Invalid spec JSON in {}: {}", path, e))
}

fn normalize_hash(hex: &str) -> String {
    hex.trim().trim_start_matches("0x").to_lowercase()
}

fn default_signature_path(spec_path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.sig", spec_path.display()))
}

fn resolve_signature_path(spec_path: &str, signature: Option<&str>) -> Option<PathBuf> {
    if let Some(p) = signature {
        return Some(PathBuf::from(p));
    }
    let sibling = default_signature_path(Path::new(spec_path));
    if sibling.is_file() {
        Some(sibling)
    } else {
        None
    }
}

/// Structural validation used by `creg chain-spec validate` (SEC-203).
pub fn validate_spec(
    path: &str,
    signature: Option<&str>,
    pubkey: Option<&str>,
    require_signature: bool,
    skip_signature: bool,
) -> Result<()> {
    let spec = load_spec(path)?;

    if spec.spec_version != common::CURRENT_SPEC_VERSION {
        bail!(
            "Unknown spec_version {} (this binary supports {})",
            spec.spec_version,
            common::CURRENT_SPEC_VERSION
        );
    }

    if spec.chain_id.trim().is_empty() {
        bail!("chain_id must not be empty");
    }

    if spec.signing.signing_key_pubkey_hex.trim().is_empty() {
        bail!("signing.signing_key_pubkey_hex must not be empty");
    }

    let computed = spec.compute_genesis_hash()?;
    let embedded = spec.genesis_hash.trim();
    if !embedded.is_empty() {
        if normalize_hash(embedded) != normalize_hash(&computed) {
            bail!(
                "genesis_hash mismatch: spec declares {} but compute_genesis_hash() yields {}",
                embedded,
                computed
            );
        }
    }

    let sig_path = resolve_signature_path(path, signature);
    match (&sig_path, require_signature, skip_signature) {
        (_, true, true) => {
            bail!("--require-signature and --skip-signature cannot be used together")
        }
        (None, true, _) => {
            bail!(
                "signature required but no file found (use --signature or place {} next to the spec)",
                default_signature_path(Path::new(path)).display()
            );
        }
        (Some(p), _, false) => {
            let sig_hex = std::fs::read_to_string(p)
                .with_context(|| format!("read signature file {}", p.display()))?
                .trim()
                .to_string();
            let pubkey_hex = pubkey
                .map(str::to_string)
                .unwrap_or_else(|| spec.signing.signing_key_pubkey_hex.clone());
            spec.verify_signature(&sig_hex, &pubkey_hex)
                .with_context(|| format!("signature verification failed ({})", p.display()))?;
            println!("✓ Ed25519 signature valid ({})", p.display());
        }
        _ => {}
    }

    println!("✓ Spec is valid");
    println!("  chain_id:      {}", spec.chain_id);
    println!("  network:       {:?}", spec.network);
    println!("  genesis_hash:  {}", computed);
    println!("  validators:    {}", spec.validator_set.validators.len());
    println!("  l1.chain_id:   {}", spec.l1.chain_id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn minimal_unsigned_spec_json() -> String {
        r#"{
  "spec_version": 1,
  "chain_id": "test-1",
  "network": "testnet",
  "phase": "alpha",
  "genesis_time": "2026-01-01T00:00:00Z",
  "genesis_hash": "",
  "consensus_params": {
    "block_time_seconds": 5,
    "vote_timeout_ms": 10000,
    "quorum_percentage": 67,
    "min_validator_stake_wei": "100000000000000000000",
    "min_publisher_stake_wei": "1000000000000000000",
    "unbonding_period_seconds": 86400,
    "slash_penalty_low_bp": 200,
    "slash_penalty_medium_bp": 1000,
    "slash_penalty_critical_bp": 3000,
    "max_validators": 50
  },
  "feature_flags": {
    "zk_validation": true,
    "ml_validation": false,
    "wasm_sandbox": true,
    "private_registries": false,
    "cross_chain": false,
    "insurance": false,
    "threshold_encryption": false
  },
  "l1": {
    "name": "sepolia",
    "chain_id": 11155111,
    "block_explorer": "https://sepolia.etherscan.io",
    "min_finality_blocks": 6
  },
  "contracts": {
    "registry": "0x0000000000000000000000000000000000000001"
  },
  "bootnodes": [],
  "validator_set": {
    "version": 1,
    "last_updated": "2026-01-01T00:00:00Z",
    "epoch_block_height": 0,
    "validators": [
      {
        "id": "v1",
        "alias": "v1",
        "pubkey": "0437e4adac481519cd6ae66907294c40cfcbf0bdeadd47806f6233be4bd5f82d",
        "eth_address": "0x38371A715Bd36142766EB026e61de061b45C9b00",
        "stake": 100,
        "reputation": 100,
        "status": "active"
      }
    ]
  },
  "services": {
    "ipfs_gateway": "https://example.com",
    "ipfs_api": "https://example.com",
    "faucet": "https://example.com",
    "explorer": "https://example.com",
    "metrics": "https://example.com"
  },
  "signing": {
    "signature_algorithm": "ed25519",
    "signing_key_pubkey_hex": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "detached_signature_url": "https://example.com/chain-spec.json.sig"
  }
}"#
        .to_string()
    }

    #[test]
    fn validate_rejects_genesis_hash_mismatch() {
        let mut file = NamedTempFile::new().unwrap();
        let mut json = minimal_unsigned_spec_json();
        json = json.replace("\"genesis_hash\": \"\"", "\"genesis_hash\": \"0xdeadbeef\"");
        file.write_all(json.as_bytes()).unwrap();
        let err =
            validate_spec(file.path().to_str().unwrap(), None, None, false, true).unwrap_err();
        assert!(err.to_string().contains("genesis_hash mismatch"));
    }

    #[test]
    fn validate_passes_without_signature_when_not_required() {
        let mut file = NamedTempFile::new().unwrap();
        let json = minimal_unsigned_spec_json();
        file.write_all(json.as_bytes()).unwrap();
        let spec = load_spec(file.path().to_str().unwrap()).unwrap();
        let hash = spec.compute_genesis_hash().unwrap();
        let mut file2 = NamedTempFile::new().unwrap();
        let json2 = minimal_unsigned_spec_json().replace(
            "\"genesis_hash\": \"\"",
            &format!("\"genesis_hash\": \"{}\"", hash),
        );
        file2.write_all(json2.as_bytes()).unwrap();
        validate_spec(file2.path().to_str().unwrap(), None, None, false, true).unwrap();
    }
}
