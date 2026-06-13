// crates/common/build.rs
// Compiles the node.proto schema into Rust code.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/node.proto"], &["proto"])?;
    Ok(())
}
