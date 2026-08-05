//! End-to-end integration test: build the `crypto-demo` guest component, run
//! it under the Wasmtime host, and assert every check passes.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Once;

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

/// Build the guest component through `just demo::build-component` — the single
/// definition of that build — and return the component path. The build runs
/// once per test binary: the tests run in parallel, and a concurrent
/// rebuild's `wasm-tools component new -o` truncates the component file in
/// place while another test may be loading it.
fn build_component(workspace_root: &Path) -> PathBuf {
    static BUILD: Once = Once::new();
    BUILD.call_once(|| run(workspace_root, "just", &["build-component"]));
    workspace_root.join("examples/crypto-demo/build/crypto-demo.component.wasm")
}

#[tokio::test(flavor = "multi_thread")]
async fn crypto_demo_all_checks_pass() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let component = build_component(&workspace_root);

    let summary = wasmtime_demo::run_demo(&component)
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

/// With a tiny per-call buffer limit every check's input overflows: the
/// operation drains its stream (the feeder completes) and reports the
/// recoverable limit error, which the guest surfaces as a check failure —
/// pinning the end-to-end path of `WasiWebcryptoCtx`'s buffering limits.
#[tokio::test(flavor = "multi_thread")]
async fn tiny_buffer_limit_fails_recoverably() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let component = build_component(&workspace_root);

    let mut ctx = polymorph_webcrypto_wasmtime::WasiWebcryptoCtx::new();
    ctx.set_per_call_buffer_limit(Some(4));
    let err = wasmtime_demo::run_demo_with(&component, ctx)
        .await
        .expect_err("a 4-byte buffer limit must fail the demo's checks");
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("per-call buffer limit"),
        "expected the recoverable limit error, got: {rendered}"
    );
}

/// Every check — including the eight-lane `concurrent-seal-open` — completes
/// under a pool that admits only two operations at a time.
///
/// This is the deadlock-shaped concurrency test on the Wasmtime host (#103):
/// the guest drives its operations the way the making-progress rule
/// requires, so completion is the host's obligation — FIFO admission must
/// advance, and an operation's capacity must free when its output is
/// drained. A regression in either direction does not fail this test, it
/// hangs it, which is what the timeout converts into a failure.
///
/// The per-call limit is sized above the demo's largest payload (~24 KiB),
/// so nothing overflows; the pool is two reservations, so the concurrent
/// check contends four deep.
#[tokio::test(flavor = "multi_thread")]
async fn checks_complete_under_a_contended_pool() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let component = build_component(&workspace_root);

    let mut ctx = polymorph_webcrypto_wasmtime::WasiWebcryptoCtx::new();
    ctx.set_per_call_buffer_limit(Some(32 * 1024));
    ctx.set_total_buffer_limit(Some(64 * 1024));
    let summary = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        wasmtime_demo::run_demo_with(&component, ctx),
    )
    .await
    .expect("the demo deadlocked against the contended pool")
    .expect("run_demo_with failed");
    assert!(
        summary.contains("concurrent-seal-open"),
        "the concurrent check must have run: {summary}"
    );
}
