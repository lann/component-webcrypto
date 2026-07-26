//! End-to-end integration test: build the `crypto-demo` guest component, run
//! it under the Wasmtime host, and assert every check passes.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Run `program` with `args` in `dir`, panicking (with the captured output)
/// if it fails.
fn run(dir: &Path, program: &str, args: &[&str]) {
    let output = Command::new(program)
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|err| panic!("failed to spawn {program}: {err}"));
    assert!(
        output.status.success(),
        "{program} {} failed:\n{}\n{}",
        args.join(" "),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// Build the guest core module and wrap it into a component, returning the
/// component path.
fn build_component(workspace_root: &Path) -> PathBuf {
    run(
        workspace_root,
        "cargo",
        &[
            "build",
            "--release",
            "-p",
            "crypto-demo",
            "--target",
            "wasm32-unknown-unknown",
        ],
    );
    let component = workspace_root.join("examples/crypto-demo/build/crypto-demo.component.wasm");
    std::fs::create_dir_all(component.parent().unwrap())
        .expect("failed to create the component build directory");
    run(
        workspace_root,
        "wasm-tools",
        &[
            "component",
            "new",
            "target/wasm32-unknown-unknown/release/crypto_demo.wasm",
            "-o",
            component.to_str().unwrap(),
        ],
    );
    component
}

#[tokio::test(flavor = "multi_thread")]
async fn crypto_demo_all_checks_pass() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let component = build_component(&workspace_root);

    let summary = wasmtime_webcrypto_demo::run_demo(&component)
        .await
        .expect("run_demo failed");
    // The summary's declared count must agree with the checks it lists —
    // derived, not maintained (the guest is the single source of truth).
    let (count, names) = summary
        .split_once(" checks passed: ")
        .unwrap_or_else(|| panic!("unexpected summary shape: {summary}"));
    let declared: usize = count
        .parse()
        .unwrap_or_else(|_| panic!("unexpected summary shape: {summary}"));
    let listed = names.split(", ").count();
    assert!(
        declared > 0 && declared == listed,
        "summary declares {declared} checks but lists {listed}: {summary}"
    );
}
