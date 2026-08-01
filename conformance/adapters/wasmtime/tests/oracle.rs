//! The mutation-testing oracle: run both conformance suites through this
//! adapter and require zero failing cases.
//!
//! Inert under a plain `just test` — it skips unless the environment names
//! prebuilt guest components — because it exists for the weekly mutation
//! run (`just mutants`), where `cargo test` must carry the whole verdict:
//! cargo-mutants knows nothing but the test exit status, so the case
//! failures that are normally the conformance *runner's* business to gate
//! become this test's assertion. The adapter binary is rebuilt per mutant
//! (Cargo builds it for this test), so the mutated crypto is what runs.
//!
//! The guests are prebuilt and referenced by absolute path: guest wasm is
//! compiled from unmutated sources once, before the mutation run — the
//! subject under mutation is the host stack (lann-webcrypto-core + lann-webcrypto-wasmtime),
//! which the wasm calls into.

use conformance_report::{Outcome, ResultsFile};

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
        let out = std::env::temp_dir().join(format!(
            "conformance-oracle-{}-{suite}.json",
            std::process::id()
        ));
        let status = std::process::Command::new(env!("CARGO_BIN_EXE_conformance-adapter-wasmtime"))
            .args(["--guest", &guest, "--suite", suite, "--out"])
            .arg(&out)
            .status()
            .expect("spawning the adapter");
        assert!(status.success(), "{suite}: the adapter itself failed");

        let results: ResultsFile =
            serde_json::from_str(&std::fs::read_to_string(&out).expect("reading results"))
                .expect("parsing results");
        let _ = std::fs::remove_file(&out);
        let failed: Vec<&str> = results
            .results
            .iter()
            .filter(|case| case.outcome == Outcome::Fail)
            .map(|case| case.name.as_str())
            .collect();
        assert!(
            !results.results.is_empty(),
            "{suite}: the suite ran no cases"
        );
        assert!(
            failed.is_empty(),
            "{suite}: {} failing case(s), e.g. {:?}",
            failed.len(),
            &failed[..failed.len().min(5)]
        );
    }
}
