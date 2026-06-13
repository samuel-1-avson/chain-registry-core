// crates/cli/src/multisig.rs
// Multi-sig publish — collect M-of-N Ed25519 partial signatures before submitting.
//
// Workflow:
//   1. creg multisig init <tarball>       → writes a .creg-multisig.json session file
//   2. creg multisig sign <session.json>  → co-signer adds their signature
//   3. creg multisig submit <session.json>→ once M sigs collected, submits to chain
//
// INTEGRITY: Each session file carries an HMAC-SHA256 over its stable fields.
// Key = CREG_SESSION_HMAC_KEY env var if set, otherwise the content_hash itself
// (self-MAC).  Detects accidental corruption and basic tampering when the file
// is passed between co-signers.

use anyhow::{bail, Context, Result};
use colored::Colorize;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::Path;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MultisigSession {
    /// Package canonical name
    pub canonical: String,
    /// Content hash (sha256 hex)
    pub content_hash: String,
    /// IPFS CID
    pub ipfs_cid: String,
    /// Publisher EVM address with active on-chain stake.
    #[serde(default)]
    pub publisher_address: String,
    /// Minimum signatures required
    pub threshold: usize,
    /// Collected signatures: (pubkey_hex, signature_hex)
    pub signatures: Vec<(String, String)>,
    /// Ecosystem
    pub ecosystem: String,
    /// Package version
    pub version: String,
    /// HMAC-SHA256 over the stable session fields (hex).
    /// Key = CREG_SESSION_HMAC_KEY env var, or the content_hash if unset.
    #[serde(default)]
    pub mac: String,
}

impl MultisigSession {
    /// Compute the HMAC over stable fields:
    ///   `canonical || content_hash || ipfs_cid || threshold || ecosystem || version`
    fn compute_mac(&self) -> String {
        let key =
            std::env::var("CREG_SESSION_HMAC_KEY").unwrap_or_else(|_| self.content_hash.clone());
        let msg = format!(
            "{}{}{}{}{}{}{}",
            self.canonical,
            self.content_hash,
            self.ipfs_cid,
            self.publisher_address,
            self.threshold,
            self.ecosystem,
            self.version,
        );
        let mut mac =
            HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
        mac.update(msg.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    pub fn is_ready(&self) -> bool {
        self.signatures.len() >= self.threshold
    }

    /// Load and verify the session file's MAC.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read session file: {}", path.display()))?;
        let session: Self = serde_json::from_str(&raw).context("Invalid multisig session file")?;

        // Verify integrity if a MAC is present.
        if !session.mac.is_empty() {
            let expected = session.compute_mac();
            if session.mac != expected {
                bail!(
                    "Session file MAC mismatch — file may have been tampered with.\n  \
                     Expected: {}\n  Got:      {}",
                    &expected[..16],
                    &session.mac[..16.min(session.mac.len())]
                );
            }
        } else {
            eprintln!(
                "{} Session file has no integrity MAC. Consider re-creating it with \
                 the current version of creg.",
                "⚠".yellow()
            );
        }

        Ok(session)
    }

    /// Serialize to JSON, embedding a fresh MAC over the stable fields.
    pub fn save(&self, path: &Path) -> Result<()> {
        let mut with_mac = self.clone();
        with_mac.mac = with_mac.compute_mac();
        let content = serde_json::to_string_pretty(&with_mac)?;
        std::fs::write(path, content)
            .with_context(|| format!("Cannot write session file: {}", path.display()))
    }
}

fn package_id_from_session(session: &MultisigSession) -> Result<common::PackageId> {
    let (ecosystem, rest) = session
        .canonical
        .split_once(':')
        .context("Invalid multisig session canonical package id")?;
    let (name, version) = rest
        .rsplit_once('@')
        .context("Invalid multisig session canonical package version")?;
    Ok(common::PackageId::new(ecosystem, name, version))
}

/// Initialize a new multisig session from a tarball.
pub async fn init(
    tarball_path: &Path,
    threshold: usize,
    publisher_address: &str,
    _node_url: Option<&str>,
    output: &Path,
) -> Result<()> {
    let publisher_address = crate::publish::canonicalize_publisher_address(publisher_address)?;

    let ipfs_url =
        std::env::var("CREG_IPFS_URL").unwrap_or_else(|_| "http://127.0.0.1:5001".into());

    println!(
        "{} Initializing multisig publish session (threshold: {}/N)...",
        "→".cyan(),
        threshold
    );

    let tarball_bytes = tokio::fs::read(tarball_path)
        .await
        .context("Failed to read tarball")?;
    let content_hash = common::sha256_hex(&tarball_bytes);

    // Pin to IPFS
    println!("{} Uploading to IPFS...", "→".cyan());
    let add_url = format!("{}/api/v0/add", ipfs_url.trim_end_matches('/'));
    let form = reqwest::multipart::Form::new().part(
        "file",
        reqwest::multipart::Part::bytes(tarball_bytes).file_name("package.tgz"),
    );

    let resp = reqwest::Client::new()
        .post(&add_url)
        .multipart(form)
        .timeout(std::time::Duration::from_secs(120))
        .send()
        .await
        .context("IPFS upload failed")?;

    #[derive(serde::Deserialize)]
    struct IpfsResp {
        #[serde(rename = "Hash")]
        hash: String,
    }
    let ipfs_resp: IpfsResp = resp.json().await.context("IPFS response parse error")?;
    let ipfs_cid = ipfs_resp.hash;

    // Detect package identity from tarball name
    let stem = tarball_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("package");

    // Try to parse name@version pattern, e.g. "express-4.18.2" or "express@4.18.2"
    let (name, version) = if let Some(at_pos) = stem.rfind('@') {
        (&stem[..at_pos], &stem[at_pos + 1..])
    } else if let Some(dash_pos) = stem.rfind('-').filter(|&p| {
        stem[p + 1..]
            .chars()
            .next()
            .map_or(false, |c| c.is_ascii_digit())
    }) {
        (&stem[..dash_pos], &stem[dash_pos + 1..])
    } else {
        (stem, "0.0.0")
    };

    // Infer ecosystem from extension or env var
    let ecosystem = std::env::var("CREG_ECOSYSTEM").unwrap_or_else(|_| {
        let ext = tarball_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        match ext {
            "crate" => "cargo",
            "whl" | "tar" => "pip",
            "jar" => "maven",
            "gem" => "gem",
            _ => "npm",
        }
        .to_string()
    });

    let session = MultisigSession {
        canonical: format!("{}:{}@{}", ecosystem, name, version),
        content_hash: content_hash.clone(),
        ipfs_cid: ipfs_cid.clone(),
        publisher_address: publisher_address.clone(),
        threshold,
        signatures: vec![],
        ecosystem,
        version: version.to_string(),
        mac: String::new(), // computed and embedded by save()
    };

    session.save(output)?;

    println!("{} Multisig session initialized:", "✓".green());
    println!("  File:         {}", output.display());
    println!("  Content hash: {}", &content_hash[..16]);
    println!("  IPFS CID:     {}", ipfs_cid);
    println!("  Address:      {}", publisher_address);
    println!("  Threshold:    {}/N", threshold);
    println!("\n  Share {} with each co-signer.", output.display());
    println!(
        "  Each co-signer runs: creg multisig sign {}",
        output.display()
    );

    Ok(())
}

/// Add a co-signer's signature to the session.
pub fn sign(session_path: &Path, privkey_hex: &str) -> Result<()> {
    use ed25519_dalek::{Signer, SigningKey};

    let mut session = MultisigSession::load(session_path)?;

    let privkey_bytes = hex::decode(privkey_hex.trim()).context("Invalid private key hex")?;
    let signing_key =
        SigningKey::try_from(privkey_bytes.as_slice()).context("Invalid Ed25519 private key")?;
    let pubkey = signing_key.verifying_key();
    let pubkey_hex = hex::encode(pubkey.as_bytes());

    // Check for duplicate signer
    if session.signatures.iter().any(|(pk, _)| pk == &pubkey_hex) {
        println!("{} This key has already signed this session.", "ℹ".blue());
        return Ok(());
    }

    if session.publisher_address.trim().is_empty() {
        bail!(
            "Multisig session is missing publisher_address. Re-create it with --publisher-address."
        );
    }

    // Sign: message = canonical || content_hash || publisher_address
    let package_id = package_id_from_session(&session)?;
    let msg = common::publish_signature_message(
        &package_id,
        &session.content_hash,
        &session.publisher_address,
    );
    let signature = signing_key.sign(msg.as_bytes());
    let sig_hex = hex::encode(signature.to_bytes());

    session.signatures.push((pubkey_hex.clone(), sig_hex));
    session.save(session_path)?;

    println!(
        "{} Signature added ({}/{} collected):",
        "✓".green(),
        session.signatures.len(),
        session.threshold
    );
    println!("  Signer: {}...", &pubkey_hex[..16]);
    if session.is_ready() {
        println!(
            "\n  {} Threshold reached! Run: creg multisig submit {}",
            "✓".green().bold(),
            session_path.display()
        );
    } else {
        println!(
            "  {} more signature(s) needed.",
            session.threshold - session.signatures.len()
        );
    }

    Ok(())
}

/// Submit the package once M signatures are collected.
pub async fn submit(
    session_path: &Path,
    manifest_path: Option<&Path>,
    node_url: Option<&str>,
) -> Result<()> {
    let session = MultisigSession::load(session_path)?;

    if !session.is_ready() {
        anyhow::bail!(
            "Only {}/{} signatures collected. Need {} more.",
            session.signatures.len(),
            session.threshold,
            session.threshold - session.signatures.len()
        );
    }

    let base = node_url.map(String::from).unwrap_or_else(|| {
        std::env::var("CREG_NODE_URL").unwrap_or_else(|_| "http://localhost:8080".into())
    });

    println!(
        "{} Submitting multisig package ({}/{} signatures)...",
        "→".cyan(),
        session.signatures.len(),
        session.threshold
    );

    // Build a publish request using the first signer as the primary publisher
    // and the new first-class multi-sig fields.
    let (primary_pubkey, primary_sig) = session
        .signatures
        .first()
        .context("No signatures in session")?;

    let manifest: common::PackageManifest = match manifest_path {
        Some(p) => serde_json::from_str(&std::fs::read_to_string(p)?)?,
        None => common::PackageManifest::default(),
    };

    let (publisher_pubkeys, signatures): (Vec<String>, Vec<String>) =
        session.signatures.iter().cloned().unzip();
    let package_id = package_id_from_session(&session)?;

    let request = common::PublishRequest {
        id: package_id,
        content_hash: session.content_hash.clone(),
        ipfs_cid: session.ipfs_cid.clone(),
        publisher_address: session.publisher_address.clone(),
        publisher_pubkey: primary_pubkey.clone(),
        signature: primary_sig.clone(),
        manifest,
        submitted_at: chrono::Utc::now(),
        shielded: false,
        key_bundle: None,
        pgp_signature: None,
        pgp_public_key: None,
        publisher_pubkeys,
        signatures,
        threshold: session.threshold,
        ..Default::default()
    };

    let url = format!("{}/v1/publisher/packages", base.trim_end_matches('/'));
    let resp = reqwest::Client::new()
        .post(&url)
        .json(&request)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .context("Failed to reach registry node")?;

    if resp.status().is_success() {
        println!(
            "{} Multisig package submitted successfully!",
            "✓".green().bold()
        );
        println!(
            "  Run: creg status {} to track verification.",
            session.canonical
        );
    } else {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Submission failed: {}", body);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, SigningKey, Verifier};
    use rand::rngs::OsRng;

    fn scoped_session() -> MultisigSession {
        MultisigSession {
            canonical: "npm:@scope/pkg@1.2.3".into(),
            content_hash: common::sha256_hex(b"scoped-package"),
            ipfs_cid: "bafytestscopedpkg".into(),
            publisher_address: "0x1111111111111111111111111111111111111111".into(),
            threshold: 2,
            signatures: Vec::new(),
            ecosystem: "npm".into(),
            version: "1.2.3".into(),
            mac: String::new(),
        }
    }

    #[test]
    fn package_id_from_session_preserves_scoped_package_names() {
        let package_id = package_id_from_session(&scoped_session()).expect("valid scoped session");

        assert_eq!(package_id.ecosystem, "npm");
        assert_eq!(package_id.name, "@scope/pkg");
        assert_eq!(package_id.version, "1.2.3");
        assert_eq!(package_id.canonical(), "npm:@scope/pkg@1.2.3");
    }

    #[test]
    fn sign_uses_scoped_package_canonical_message() {
        let dir = tempfile::tempdir().expect("tempdir");
        let session_path = dir.path().join("session.json");
        let session = scoped_session();
        session.save(&session_path).expect("save session");

        let signing_key = SigningKey::generate(&mut OsRng);
        let privkey_hex = hex::encode(signing_key.to_bytes());

        sign(&session_path, &privkey_hex).expect("sign session");

        let signed = MultisigSession::load(&session_path).expect("load signed session");
        assert_eq!(signed.signatures.len(), 1);

        let package_id = package_id_from_session(&signed).expect("parse scoped package id");
        let message = common::publish_signature_message(
            &package_id,
            &signed.content_hash,
            &signed.publisher_address,
        );
        let signature_hex = &signed.signatures[0].1;
        let signature_bytes: [u8; 64] = hex::decode(signature_hex)
            .expect("signature hex")
            .try_into()
            .expect("ed25519 signature length");
        let signature = Signature::from_bytes(&signature_bytes);

        signing_key
            .verifying_key()
            .verify(message.as_bytes(), &signature)
            .expect("signature must verify against scoped canonical payload");
    }
}
