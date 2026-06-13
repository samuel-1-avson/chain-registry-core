use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signer, SigningKey};

#[derive(Debug, Default)]
struct Args {
    chain_id: String,
    evm_address: String,
    node_id: String,
    validator_key_hex: String,
    nonce: String,
}

fn main() -> Result<()> {
    let args = parse_args()?;
    let validator_key_hex = args
        .validator_key_hex
        .strip_prefix("0x")
        .unwrap_or(args.validator_key_hex.as_str());
    let key_bytes = hex::decode(validator_key_hex).context("validator key must be hex")?;
    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("validator key must be exactly 32 bytes"))?;
    let signing_key = SigningKey::from_bytes(&key_array);
    let ed25519_pubkey = hex::encode(signing_key.verifying_key().as_bytes());

    let message = validator_identity_registration_message(
        &args.chain_id,
        &args.evm_address.to_ascii_lowercase(),
        &args.node_id,
        &ed25519_pubkey,
        &args.nonce,
    );
    let signature = signing_key.sign(message.as_bytes());

    println!(
        "{}",
        serde_json::json!({
            "message": message,
            "ed25519_pubkey": ed25519_pubkey,
            "ed25519_signature": hex::encode(signature.to_bytes()),
        })
    );

    Ok(())
}

fn validator_identity_registration_message(
    chain_id: &str,
    evm_address: &str,
    node_id: &str,
    ed25519_pubkey: &str,
    nonce: &str,
) -> String {
    format!(
        "creg-validator-identity-v1\nchain_id:{chain_id}\nevm_address:{evm_address}\nnode_id:{node_id}\ned25519_pubkey:{ed25519_pubkey}\nnonce:{nonce}"
    )
}

fn parse_args() -> Result<Args> {
    let mut parsed = Args::default();
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--chain-id" => parsed.chain_id = required_value(&mut args, "--chain-id")?,
            "--evm-address" => parsed.evm_address = required_value(&mut args, "--evm-address")?,
            "--node-id" => parsed.node_id = required_value(&mut args, "--node-id")?,
            "--validator-key-hex" => {
                parsed.validator_key_hex = required_value(&mut args, "--validator-key-hex")?
            }
            "--nonce" => parsed.nonce = required_value(&mut args, "--nonce")?,
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => bail!("unknown argument: {other}"),
        }
    }

    if parsed.chain_id.is_empty()
        || parsed.evm_address.is_empty()
        || parsed.node_id.is_empty()
        || parsed.validator_key_hex.is_empty()
        || parsed.nonce.is_empty()
    {
        print_usage();
        bail!("missing required argument");
    }

    Ok(parsed)
}

fn required_value(args: &mut impl Iterator<Item = String>, name: &str) -> Result<String> {
    args.next()
        .filter(|value| !value.trim().is_empty())
        .with_context(|| format!("{name} requires a value"))
}

fn print_usage() {
    eprintln!(
        "Usage: cargo run -p chain-registry-cli --example sign_validator_identity -- \\
  --chain-id creg-testnet-1 \\
  --evm-address 0x... \\
  --node-id validator-1 \\
  --validator-key-hex <32-byte-ed25519-private-key-hex> \\
  --nonce <unique-nonce>"
    );
}
