// Chain Spec Genesis Hash Computer
// Usage:
//   cargo run --example compute_genesis_hash -- <spec.json>

use common::chain_spec::ChainSpec;
use std::fs;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: compute_genesis_hash <spec.json>");
        std::process::exit(1);
    }

    let spec_json = fs::read_to_string(&args[1])?;
    let spec: ChainSpec = serde_json::from_str(&spec_json)?;
    let hash = spec.compute_genesis_hash()?;
    println!("{}", hash);
    Ok(())
}
