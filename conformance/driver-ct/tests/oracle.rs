//! The mutation-testing oracle: run both conformance suites through the
//! ct driver and require zero failing cases.
//!
//! Inert under a plain `just test` — it skips unless the environment names
//! prebuilt guest components — because it exists for the weekly mutation
//! run (`just mutants`), where `cargo test` must carry the whole verdict:
//! cargo-mutants knows nothing but the test exit status, so the case
//! failures that are normally the aggregation step's business to gate
//! become this test's assertion. The driver binary is rebuilt per mutant
//! (Cargo builds it for this test), so the mutated crypto is what runs.
//!
//! The guests are prebuilt and referenced by absolute path: guest wasm is
//! compiled from unmutated sources once, before the mutation run — the
//! subject under mutation is the host stack (lann-webcrypto-core +
//! lann-webcrypto-wasmtime), which the wasm calls into.

/// The environment variables naming the prebuilt guest components
/// (absolute paths), and the suite each one carries.
const GUESTS: [(&str, &str); 2] = [
    ("CONFORMANCE_ORACLE_SHARED_GUEST", "shared"),
    ("CONFORMANCE_ORACLE_SIGNING_GUEST", "signing"),
];

#[test]
fn conformance_suites_pass() {
    if GUESTS
        .iter()
        .any(|(var, _)| std::env::var_os(var).is_none())
    {
        eprintln!(
            "skipping the conformance oracle: set {} and {} to prebuilt guest \
             components (the `just mutants` recipe does)",
            GUESTS[0].0, GUESTS[1].0
        );
        return;
    }

    for (var, suite) in GUESTS {
        let guest = std::env::var(var).unwrap();
        // JSONL output: the exit code carries the verdict (nonzero on any
        // failing case), and the emitted results double as the "the suite
        // actually ran cases" check — an empty run must not pass.
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_ct-driver"))
            .args([guest.as_str(), "--jobs", "8", "--jsonl"])
            .output()
            .expect("spawning the driver");
        let cases = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count();
        assert!(cases > 0, "{suite}: the suite ran no cases");
        assert!(
            output.status.success(),
            "{suite}: failing case(s) (driver exit {:?}); stderr:\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}
