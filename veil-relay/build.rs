// Build script — compile protobuf definitions into Rust types.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    prost_build::compile_protos(&["proto/veil.proto"], &["proto/"])?;
    Ok(())
}
