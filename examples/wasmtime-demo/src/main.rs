//! Thin CLI over [`wasmtime_demo::run_demo`]: load the
//! `crypto-demo` component (path from argument 1, defaulting to the
//! repository's build location) and print the summary its `run` export
//! returns.

use std::path::PathBuf;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("examples/crypto-demo/build/crypto-demo.component.wasm"));

    let summary = wasmtime_demo::run_demo(&path).await?;
    println!("crypto-demo (Wasmtime / RustCrypto host) result:");
    println!("  {summary}");
    Ok(())
}
