//! component-test host-embed driver: runs the ported conformance suite
//! (conformance-guest-ct) against the wasmtime-impl RustCrypto host.
//!
//! Usage: ct-driver <suite.wasm> [--jsonl] [--missing f1,f2,...]
//! [--jobs N] [--cases-per-instance N] [--target key] [--only substring]
//! [--enumerate]

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{bail, Result};
use component_test_runner::{CtCtx, OutputMode, Runner, RunnerView};
use polymorph_webcrypto_wasmtime::{
    add_to_linker_with_options, LinkOptions, WasiWebcryptoCtx, WasiWebcryptoCtxView,
    WasiWebcryptoView,
};
use wasmtime_wasi::{ResourceTable, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

/// Store data: WASI + the runner's diagnostic sink + the SUT context.
struct Data {
    wasi: WasiCtx,
    table: ResourceTable,
    ct: CtCtx,
    webcrypto: WasiWebcryptoCtx,
}

impl WasiView for Data {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

impl WasiWebcryptoView for Data {
    fn webcrypto(&mut self) -> WasiWebcryptoCtxView<'_> {
        WasiWebcryptoCtxView {
            ctx: &mut self.webcrypto,
            table: &mut self.table,
        }
    }
}

impl RunnerView for Data {
    fn ct(&mut self) -> &mut CtCtx {
        &mut self.ct
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode> {
    let mut suite: Option<PathBuf> = None;
    let mut mode = OutputMode::Human;
    let mut missing: Vec<String> = Vec::new();
    let mut cases_per_instance: usize = 0; // cheap pure-compute corpus: single instance
    let mut jobs: usize = 1;
    let mut target: String = "wasmtime-rustcrypto".into();
    let mut only: Option<String> = None;
    let mut enumerate = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--missing" => {
                let list = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--missing needs a list"))?;
                missing.extend(list.split(',').filter(|s| !s.is_empty()).map(String::from));
            }
            "--target" => {
                target = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--target needs a value"))?;
            }
            "--jobs" => {
                let v = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--jobs needs a number"))?;
                jobs = v.parse::<usize>()?.max(1);
            }
            "--cases-per-instance" => {
                let v = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--cases-per-instance needs a number"))?;
                cases_per_instance = v.parse()?;
            }
            "--only" => {
                only = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--only needs a substring"))?,
                );
            }
            "--jsonl" => mode = OutputMode::Jsonl,
            "--enumerate" => enumerate = true,
            _ if suite.is_none() => suite = Some(PathBuf::from(arg)),
            other => bail!("unexpected argument `{other}`"),
        }
    }
    let suite = suite.ok_or_else(|| {
        anyhow::anyhow!(
            "usage: ct-driver <suite.wasm> [--jsonl] [--missing f1,f2,...] \
             [--jobs N] [--cases-per-instance N] [--target key] [--only substring] \
             [--enumerate]"
        )
    })?;
    let suite_name = suite
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("suite")
        .to_string();

    let runner = Runner::with_data(
        &suite,
        || Data {
            wasi: WasiCtxBuilder::new().inherit_stderr().build(),
            table: ResourceTable::new(),
            ct: CtCtx::default(),
            webcrypto: WasiWebcryptoCtx::default(),
        },
        |linker| {
            // The full-support target: every gated interface enabled.
            let mut options = LinkOptions::default();
            options
                .sha1_checked(true)
                .rsa_sign(true)
                .rsa_oaep_decrypt(true);
            add_to_linker_with_options(linker, &options)
        },
    )
    .map_err(|e| anyhow::anyhow!("{e:#}"))?;

    // The suite's full case enumeration (one name per line): the
    // `lock --leaves` input that pins the generated rows' leaves.
    if enumerate {
        let names = wasmtime_wasi::runtime::in_tokio(runner.enumerate())
            .map_err(|e| anyhow::anyhow!("{e:#}"))?;
        for name in names {
            println!("{name}");
        }
        return Ok(ExitCode::SUCCESS);
    }

    let summary = wasmtime_wasi::runtime::in_tokio(runner.run_suite_opts(
        &suite_name,
        &target,
        mode,
        &missing,
        cases_per_instance,
        jobs,
        only.as_deref(),
        component_test_runner::DEFAULT_CASE_EXECUTION_BUDGET_SECS,
        component_test_runner::DEFAULT_CASE_TIMEOUT_SECS,
    ))
    .map_err(|e| anyhow::anyhow!("{e:#}"))?;

    Ok(if summary.failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}
