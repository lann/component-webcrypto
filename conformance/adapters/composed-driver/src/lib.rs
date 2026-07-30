//! `conformance-composed-driver`: the CLI driver component for the
//! composed conformance target.
//!
//! It imports the conformance guest's exported `conformance:webcrypto/tests`
//! interface and exports an async `wasi:cli/run` (via the `wasip3` crate), so
//! the fully composed component — conformance guest + `guest-webcrypto`
//! provider + this driver — runs under a plain `wasmtime run -S cli`.
//!
//! The composition fixes the implementation under test, so the target's
//! `missing-features` declaration is fixed with it: the in-guest provider
//! serves every feature the shared suite exercises, and deliberately does
//! not export `ecdsa-sign` (class D) — which is why the signing suite,
//! whose world imports that interface, never runs composed at all.
//!
//! It materializes the cases, runs every one, and prints the results JSON
//! (the same shape the other adapters write) on stdout, which must carry
//! ONLY the JSON; diagnostics go to stderr. Case failures never affect the
//! exit status; only harness errors do.

mod bindings {
    wit_bindgen::generate!({
        path: "../../guest/wit",
        inline: "
            package conformance:composed-driver;
            world driver {
                import conformance:webcrypto/tests@0.1.0;
            }
        ",
        generate_all,
    });
}

use bindings::conformance::webcrypto::tests::{all, Outcome as GuestOutcome};
use conformance_report::{CaseResult, Outcome, ResultsFile};

struct Component;

impl wasip3::exports::cli::run::Guest for Component {
    async fn run() -> Result<(), ()> {
        // The provider's one gap is class D's ecdsa-sign, which nothing in
        // the shared suite is tagged with (the exclusion is structural —
        // see the module doc); declared for the runner's cross-check
        // against targets.toml.
        let missing_features: Vec<String> = vec!["ecdsa-sign".to_string()];
        let cases = all(&missing_features);
        let mut results = Vec::with_capacity(cases.len());
        for case in &cases {
            let (outcome, detail) = match case.run().await {
                GuestOutcome::Pass => (Outcome::Pass, String::new()),
                GuestOutcome::Fail(detail) => (Outcome::Fail, detail),
                GuestOutcome::Skipped(detail) => (Outcome::Skipped, detail),
            };
            results.push(CaseResult {
                name: case.name(),
                features: case.features(),
                outcome,
                detail,
            });
        }

        let total = results.len();
        let failed = results
            .iter()
            .filter(|r| r.outcome == Outcome::Fail)
            .count();
        let output = ResultsFile {
            target: "composed".into(),
            suite: "shared".into(),
            missing_features,
            results,
        };
        match serde_json::to_string_pretty(&output) {
            Ok(json) => {
                println!("{json}");
                eprintln!("composed conformance: {total} cases, {failed} failed");
                Ok(())
            }
            Err(err) => {
                eprintln!("serializing results failed: {err}");
                Err(())
            }
        }
    }
}

wasip3::cli::command::export!(Component);
