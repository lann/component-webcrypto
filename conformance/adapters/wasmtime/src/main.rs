//! `conformance-adapter-wasmtime`: runs the conformance guest under the
//! Wasmtime host, with the `lann:webcrypto` imports satisfied by
//! [`wasmtime_webcrypto`]'s RustCrypto implementation, and writes the
//! per-test results as JSON.
//!
//! Usage: `conformance-adapter-wasmtime --guest <component> --out <json>`.
//!
//! Test failures are data for the runner to classify, so they never affect
//! the exit status; only harness errors (loading, instantiating, or calling
//! the guest) exit nonzero.

use std::path::PathBuf;

use anyhow::Context as _;

/// One test result, as serialized into the results file.
#[derive(serde::Serialize)]
struct JsonResult {
    id: String,
    passed: bool,
    detail: String,
}

/// The results-file shape the conformance runner consumes.
#[derive(serde::Serialize)]
struct Output {
    target: &'static str,
    results: Vec<JsonResult>,
}

/// The Wasmtime harness: engine and linker setup, guest instantiation, and
/// the `run-all` call. Scoped to keep `wasmtime::error::Context` (needed by
/// `wasmtime::Result` values) apart from `anyhow::Context`.
mod harness {
    use std::path::Path;

    use wasmtime::component::{Accessor, Component, HasData, Linker, ResourceTable};
    use wasmtime::error::Context as _;
    use wasmtime::{Config, Engine, Store};
    use wasmtime_webcrypto::{WasiWebcryptoCtx, WasiWebcryptoCtxView, WasiWebcryptoView};

    use super::JsonResult;

    mod bindings {
        wasmtime::component::bindgen!({
            path: "../../guest/wit",
            world: "conformance-guest",
            imports: {
                default: async | store | trappable,
            },
            exports: {
                default: async,
            },
            with: {
                "lann:webcrypto/mac.mac-key": wasmtime_webcrypto::MacKey,
                "lann:webcrypto/aead.aead-key": wasmtime_webcrypto::AeadKey,
            },
        });
    }

    /// The store state: the WebCrypto host context plus the resource table
    /// its keys live in.
    struct Ctx {
        webcrypto: WasiWebcryptoCtx,
        table: ResourceTable,
    }

    impl HasData for Ctx {
        type Data<'a> = &'a mut Self;
    }

    impl WasiWebcryptoView for Ctx {
        fn webcrypto(&mut self) -> WasiWebcryptoCtxView<'_> {
            WasiWebcryptoCtxView {
                ctx: &mut self.webcrypto,
                table: &mut self.table,
            }
        }
    }

    /// Instantiate the conformance guest at `guest_path` and call its
    /// exported async `run-all`.
    pub async fn run_guest(guest_path: &Path) -> wasmtime::Result<Vec<JsonResult>> {
        let mut config = Config::new();
        config.wasm_component_model(true);
        config.wasm_component_model_async(true);
        let engine = Engine::new(&config)?;
        let component = Component::from_file(&engine, guest_path)
            .with_context(|| format!("loading component {}", guest_path.display()))?;

        let mut linker: Linker<Ctx> = Linker::new(&engine);
        wasmtime_webcrypto::add_to_linker(&mut linker)?;

        let mut store = Store::new(
            &engine,
            Ctx {
                webcrypto: WasiWebcryptoCtx::new(),
                table: ResourceTable::new(),
            },
        );
        let guest =
            bindings::ConformanceGuest::instantiate_async(&mut store, &component, &linker).await?;

        let results = store
            .run_concurrent(async move |accessor: &Accessor<Ctx>| {
                guest
                    .conformance_webcrypto_tests()
                    .call_run_all(accessor)
                    .await
            })
            .await??;

        Ok(results
            .into_iter()
            .map(|result| JsonResult {
                id: result.id,
                passed: result.passed,
                detail: result.detail,
            })
            .collect())
    }
}

fn parse_args() -> anyhow::Result<(PathBuf, PathBuf)> {
    let mut guest = None;
    let mut out = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--guest" => guest = Some(PathBuf::from(args.next().context("--guest needs a value")?)),
            "--out" => out = Some(PathBuf::from(args.next().context("--out needs a value")?)),
            other => anyhow::bail!("unknown argument {other:?}"),
        }
    }
    Ok((
        guest.context("--guest <component> is required")?,
        out.context("--out <json> is required")?,
    ))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let (guest_path, out_path) = parse_args()?;

    let results = harness::run_guest(&guest_path).await?;
    let total = results.len();
    let failed = results.iter().filter(|r| !r.passed).count();

    let output = Output {
        target: "wasmtime",
        results,
    };
    let json = serde_json::to_string_pretty(&output)?;
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&out_path, json).with_context(|| format!("writing {}", out_path.display()))?;

    println!(
        "wasmtime conformance: {total} tests, {failed} failed -> {}",
        out_path.display()
    );
    Ok(())
}
