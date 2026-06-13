// Chain Spec Signature Generator
// Usage:
//   cargo run --example sign_chain_spec -- <spec.json> <privkey_hex>
//
// Outputs the hex-encoded Ed25519 detached signature to stdout.

use common::chain_spec::{to_jcs_canonical_json, ChainSpec, SPEC_SIGNATURE_DOMAIN};
use ed25519_dalek::{Signer, SigningKey};
use std::fs;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: sign_chain_spec <spec.json> <privkey_hex>");
        std::process::exit(1);
    }

    let spec_json = fs::read_to_string(&args[1])?;
    let spec: ChainSpec = serde_json::from_str(&spec_json)?;

    let privkey_hex = args[2].trim_start_matches("0x");
    let privkey_bytes = hex::decode(privkey_hex)?;
    let signing_key = SigningKey::from_bytes(
        &privkey_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("private key must be 32 bytes"))?,
    );

    let jcs = to_jcs_canonical_json(&spec)?;
    let message = format!("{}|{}", SPEC_SIGNATURE_DOMAIN, String::from_utf8(jcs)?);
    let signature = signing_key.sign(message.as_bytes());

    println!("{}", hex::encode(signature.to_bytes()));
    Ok(())
}
