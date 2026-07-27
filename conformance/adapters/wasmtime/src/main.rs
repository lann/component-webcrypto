//! `conformance-adapter-wasmtime`: runs a conformance guest under the
//! Wasmtime host, with the `lann:webcrypto` imports satisfied by
//! [`wasmtime_webcrypto`]'s RustCrypto implementation, and writes the
//! per-case results as JSON — or, in `--lock-out` mode, writes the suite
//! lockfile (case names and feature tags) the runner validates results
//! against.
//!
//! Usage:
//!   conformance-adapter-wasmtime --guest <component> \
//!       --suite <shared|signing> --out <json> \
//!       [--missing-features <feature,...>] [--only <substring>]
//!   conformance-adapter-wasmtime --guest <component> --lock-out <lock>
//!
//! Case failures are data for the runner to gate on, so they never affect
//! the exit status; only harness errors (loading, instantiating, or calling
//! the guest) exit nonzero.

use std::path::PathBuf;

use anyhow::Context as _;

/// One case result, as serialized into the results file.
#[derive(serde::Serialize)]
struct JsonResult {
    name: String,
    features: Vec<String>,
    outcome: &'static str,
    detail: String,
}

/// The results-file shape the conformance runner consumes.
#[derive(serde::Serialize)]
struct Output {
    target: &'static str,
    suite: String,
    #[serde(rename = "missing-features")]
    missing_features: Vec<String>,
    results: Vec<JsonResult>,
}

/// One enumerated case: name and feature tags (the lockfile's line).
struct LockEntry {
    name: String,
    features: Vec<String>,
}

/// The Wasmtime harness: engine and linker setup, guest instantiation, and
/// the per-case drive. Scoped to keep `wasmtime::error::Context` (needed by
/// `wasmtime::Result` values) apart from `anyhow::Context`.
mod harness {
    use std::path::Path;

    use wasmtime::component::{Accessor, Component, HasData, Linker, ResourceTable};
    use wasmtime::error::Context as _;
    use wasmtime::{Config, Engine, Store};
    use wasmtime_webcrypto::{WasiWebcryptoCtx, WasiWebcryptoCtxView, WasiWebcryptoView};

    use super::{JsonResult, LockEntry};

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
        });
    }

    use bindings::exports::conformance::webcrypto::tests::Outcome;

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

    /// Instantiate the conformance guest at `guest_path`, materialize its
    /// cases for a target missing `missing`, and drive each case whose
    /// name contains `only` (every case when `only` is `None`). Returns
    /// results, or just the enumeration when `enumerate_only` is set.
    pub async fn run_guest(
        guest_path: &Path,
        missing: &[String],
        only: Option<&str>,
        enumerate_only: bool,
    ) -> wasmtime::Result<(Vec<LockEntry>, Vec<JsonResult>)> {
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

        let tests = guest.conformance_webcrypto_tests();
        let case_iface = tests.test_case();

        // Materialize and enumerate the cases (sync exports, store-style
        // calls), then drive the selected cases' async `run` methods under
        // one concurrent scope.
        let cases = tests.call_all(&mut store, missing).await?;
        let mut entries = Vec::with_capacity(cases.len());
        for case in &cases {
            let name = case_iface.call_name(&mut store, *case).await?;
            let features = case_iface.call_features(&mut store, *case).await?;
            entries.push(LockEntry { name, features });
        }

        let to_run: Vec<_> = if enumerate_only {
            Vec::new()
        } else {
            cases
                .iter()
                .zip(&entries)
                .filter(|(_, entry)| only.is_none_or(|only| entry.name.contains(only)))
                .map(|(case, entry)| (*case, entry.name.clone(), entry.features.clone()))
                .collect()
        };
        let results = store
            .run_concurrent(async move |accessor: &Accessor<Ctx>| {
                let mut results = Vec::with_capacity(to_run.len());
                for (case, name, features) in to_run {
                    let (outcome, detail) = match case_iface.call_run(accessor, case).await? {
                        Outcome::Pass => ("pass", String::new()),
                        Outcome::Fail(detail) => ("fail", detail),
                        Outcome::Skipped(detail) => ("skipped", detail),
                    };
                    results.push(JsonResult {
                        name,
                        features,
                        outcome,
                        detail,
                    });
                }
                Ok::<_, wasmtime::Error>(results)
            })
            .await??;

        for case in cases {
            case.resource_drop_async(&mut store).await?;
        }
        Ok((entries, results))
    }
}

struct Args {
    guest: PathBuf,
    suite: Option<String>,
    out: Option<PathBuf>,
    lock_out: Option<PathBuf>,
    missing: Vec<String>,
    only: Option<String>,
}

fn parse_args() -> anyhow::Result<Args> {
    let mut guest = None;
    let mut suite = None;
    let mut out = None;
    let mut lock_out = None;
    let mut missing = Vec::new();
    let mut only = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--guest" => guest = Some(PathBuf::from(args.next().context("--guest needs a value")?)),
            "--suite" => suite = Some(args.next().context("--suite needs a value")?),
            "--out" => out = Some(PathBuf::from(args.next().context("--out needs a value")?)),
            "--lock-out" => {
                lock_out = Some(PathBuf::from(
                    args.next().context("--lock-out needs a value")?,
                ))
            }
            "--missing-features" => missing.extend(
                args.next()
                    .context("--missing-features needs a value")?
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(str::to_string),
            ),
            "--only" => only = Some(args.next().context("--only needs a value")?),
            other => anyhow::bail!("unknown argument {other:?}"),
        }
    }
    let args = Args {
        guest: guest.context("--guest <component> is required")?,
        suite,
        out,
        lock_out,
        missing,
        only,
    };
    if args.out.is_some() && args.suite.is_none() {
        anyhow::bail!("--out requires --suite <shared|signing>");
    }
    if args.out.is_none() && args.lock_out.is_none() {
        anyhow::bail!("nothing to do: pass --out (with --suite) and/or --lock-out");
    }
    Ok(args)
}

/// Render the lockfile: TOML, one inline table per case (name, then any
/// feature tags), in suite order.
fn render_lock(entries: &[LockEntry]) -> String {
    let mut lock = String::from(
        "# The conformance suite's cases, one per line (name, plus the feature tags\n\
         # it exercises), in suite order. Generated by `just update-conformance-lock`;\n\
         # do not edit. The runner validates every results file against this\n\
         # inventory, so case changes must land here intentionally.\n\
         cases = [\n",
    );
    for entry in entries {
        lock.push_str(&format!("    {{ name = {:?}", entry.name));
        if !entry.features.is_empty() {
            lock.push_str(&format!(", features = {:?}", entry.features));
        }
        lock.push_str(" },\n");
    }
    lock.push_str("]\n");
    lock
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = parse_args()?;

    let enumerate_only = args.out.is_none();
    let (entries, results) = harness::run_guest(
        &args.guest,
        &args.missing,
        args.only.as_deref(),
        enumerate_only,
    )
    .await?;

    if let Some(lock_path) = &args.lock_out {
        if let Some(parent) = lock_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(lock_path, render_lock(&entries))
            .with_context(|| format!("writing {}", lock_path.display()))?;
        println!(
            "wasmtime conformance: {} cases -> {}",
            entries.len(),
            lock_path.display()
        );
    }

    if let Some(out_path) = &args.out {
        let total = results.len();
        let failed = results.iter().filter(|r| r.outcome == "fail").count();
        let skipped = results.iter().filter(|r| r.outcome == "skipped").count();
        let output = Output {
            target: "wasmtime",
            suite: args.suite.expect("checked in parse_args"),
            missing_features: args.missing.clone(),
            results,
        };
        let json = serde_json::to_string_pretty(&output)?;
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(out_path, json)
            .with_context(|| format!("writing {}", out_path.display()))?;
        println!(
            "wasmtime conformance: {total} cases, {failed} failed, {skipped} skipped -> {}",
            out_path.display()
        );
    }
    Ok(())
}
