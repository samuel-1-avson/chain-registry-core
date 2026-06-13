// Chain Spec Signature Verifier
// Usage:
//   cargo run --example verify_chain_spec -- <spec.json> <signature_hex>

use common::chain_spec::ChainSpec;
use std::fs;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: verify_chain_spec <spec.json> <signature_hex_or_sig_file>");
        std::process::exit(1);
    }

    let spec_json = fs::read_to_string(&args[1])?;
    let spec: ChainSpec = serde_json::from_str(&spec_json)?;

    let sig_input = &args[2];
    let sig_hex = if sig_input.ends_with(".sig") {
        fs::read_to_string(sig_input)?.trim().to_string()
    } else {
        sig_input.clone()
    };

    let pubkey = &spec.signing.signing_key_pubkey_hex;
    spec.verify_signature(&sig_hex, pubkey)?;
    println!("Signature VALID for pubkey {}", pubkey);
    Ok(())
}
