//! `conformance-adapter-wasmtime`: runs a conformance guest under the
//! Wasmtime host, with the `lann:webcrypto` imports satisfied by
//! [`lann_webcrypto_wasmtime`]'s RustCrypto implementation, and writes the
//! per-case results as JSON — or, in `--lock-out` mode, writes the suite
//! lockfile (case names and feature tags) the runner validates results
//! against. See `--help` for the flags.
//!
//! Case failures are data for the runner to gate on, so they never affect
//! the exit status; only harness errors (loading, instantiating, or calling
//! the guest) exit nonzero.

use std::path::PathBuf;

use anyhow::Context as _;
use clap::Parser;
use conformance_report::{CaseResult, LockCase, Outcome, ResultsFile};

/// The Wasmtime harness: guest instantiation and the per-case drive. Scoped
/// to keep `wasmtime::error::Context` (needed by `wasmtime::Result` values)
/// apart from `anyhow::Context`.
mod harness {
    use std::path::Path;

    use lann_webcrypto_wasmtime::standalone::{self, Ctx};
    use lann_webcrypto_wasmtime::WasiWebcryptoCtx;
    use wasmtime::component::Accessor;

    use super::{CaseResult, LockCase, Outcome};

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

    use bindings::exports::conformance::webcrypto::tests::Outcome as GuestOutcome;

    /// Instantiate the conformance guest at `guest_path`, materialize its
    /// cases for a target missing `missing`, and drive each case whose
    /// name contains `only` (every case when `only` is `None`). Returns
    /// results, or just the enumeration when `enumerate_only` is set.
    pub async fn run_guest(
        guest_path: &Path,
        missing: &[String],
        only: Option<&str>,
        enumerate_only: bool,
    ) -> wasmtime::Result<(Vec<LockCase>, Vec<CaseResult>)> {
        let (component, linker, mut store) = standalone::load(guest_path, WasiWebcryptoCtx::new())?;
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
            entries.push(LockCase { name, features });
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
                        GuestOutcome::Pass => (Outcome::Pass, String::new()),
                        GuestOutcome::Fail(detail) => (Outcome::Fail, detail),
                        GuestOutcome::Skipped(detail) => (Outcome::Skipped, detail),
                    };
                    results.push(CaseResult {
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

#[derive(Parser)]
#[command(
    about = "Runs a conformance guest under the Wasmtime host and writes results JSON \
             and/or the suite lockfile."
)]
#[command(group = clap::ArgGroup::new("action").required(true).multiple(true).args(["out", "lock_out"]))]
struct Args {
    /// The conformance guest component to instantiate.
    #[arg(long)]
    guest: PathBuf,
    /// The suite name recorded in the results file.
    #[arg(long)]
    suite: Option<String>,
    /// Where to write the results JSON.
    #[arg(long, requires = "suite")]
    out: Option<PathBuf>,
    /// Where to write the suite lockfile (case names + feature tags).
    #[arg(long)]
    lock_out: Option<PathBuf>,
    /// Features the target declares missing (comma-separated).
    #[arg(long = "missing-features", value_delimiter = ',')]
    missing: Vec<String>,
    /// Run only the cases whose name contains this substring.
    #[arg(long)]
    only: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

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
        std::fs::write(lock_path, conformance_report::render_lock(&entries))
            .with_context(|| format!("writing {}", lock_path.display()))?;
        println!(
            "wasmtime conformance: {} cases -> {}",
            entries.len(),
            lock_path.display()
        );
    }

    if let Some(out_path) = &args.out {
        let total = results.len();
        let failed = results
            .iter()
            .filter(|r| r.outcome == Outcome::Fail)
            .count();
        let skipped = results
            .iter()
            .filter(|r| r.outcome == Outcome::Skipped)
            .count();
        let output = ResultsFile {
            target: "wasmtime".into(),
            suite: args.suite.expect("clap enforces --out requires --suite"),
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
