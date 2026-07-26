//! `conformance-composed-driver`: the CLI driver component for the
//! composed conformance target.
//!
//! It imports the conformance guest's exported `conformance:webcrypto/tests`
//! interface and exports an async `wasi:cli/run` (via the `wasip3` crate), so
//! the fully composed component — conformance guest + `guest-webcrypto`
//! provider + this driver — runs under a plain `wasmtime run -S cli`.
//!
//! It calls `run-all` and prints the results JSON (the same shape the other
//! adapters write) on stdout, which must carry ONLY the JSON; diagnostics go
//! to stderr. Test failures never affect the exit status; only harness
//! errors do.

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

use bindings::conformance::webcrypto::tests;

/// One test result, as serialized into the results JSON.
#[derive(serde::Serialize)]
struct JsonResult {
    id: String,
    passed: bool,
    detail: String,
}

/// The results shape the conformance runner consumes.
#[derive(serde::Serialize)]
struct Output {
    target: &'static str,
    results: Vec<JsonResult>,
}

struct Component;

impl wasip3::exports::cli::run::Guest for Component {
    async fn run() -> Result<(), ()> {
        let results = tests::run_all().await;
        let total = results.len();
        let failed = results.iter().filter(|r| !r.passed).count();

        let output = Output {
            target: "composed",
            results: results
                .into_iter()
                .map(|result| JsonResult {
                    id: result.id,
                    passed: result.passed,
                    detail: result.detail,
                })
                .collect(),
        };
        match serde_json::to_string_pretty(&output) {
            Ok(json) => {
                println!("{json}");
                eprintln!("composed conformance: {total} tests, {failed} failed");
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
