//! The CLI driver component for the fully in-guest crypto demo.
//!
//! It imports the `crypto-demo` guest's exported `demo:webcrypto-demo/demo`
//! interface and exports an async `wasi:cli/run` (via the `wasip3` crate), so
//! the fully composed component — crypto-demo guest + `polymorph-webcrypto-guest-provider`
//! provider + this driver — runs under a plain `wasmtime run -S cli`.
//!
//! It drives the demo's checks to completion and prints the summary (or the
//! failure) on stdout/stderr.

mod bindings {
    wit_bindgen::generate!({
        path: "../crypto-demo/wit",
        inline: "
            package demo:crypto-demo-driver;
            world driver {
                import demo:webcrypto-demo/demo@0.1.0;
            }
        ",
        generate_all,
    });
}

use bindings::demo::webcrypto_demo::demo;

struct Component;

impl wasip3::exports::cli::run::Guest for Component {
    async fn run() -> Result<(), ()> {
        match demo::run().await {
            Ok(summary) => {
                println!("{summary}");
                println!("OK: crypto-demo finished.");
                Ok(())
            }
            Err(err) => {
                eprintln!("crypto-demo failed: {err}");
                Err(())
            }
        }
    }
}

wasip3::cli::command::export!(Component);
