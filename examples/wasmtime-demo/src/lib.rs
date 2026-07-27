//! Wasmtime host for the `crypto-demo` component, backed by
//! [`wasmtime_webcrypto`]'s RustCrypto implementation of `lann:webcrypto`.
//!
//! It is the non-browser counterpart to the jco (browser WebCrypto) host: it
//! loads the same `crypto-demo` component and invokes the component's
//! exported async `run`. The component drives every check itself through the
//! standard `lann:webcrypto` interfaces, so this host provisions nothing
//! beyond [`wasmtime_webcrypto::add_to_linker`].

use std::path::Path;

use wasmtime::component::{Accessor, Component, HasData, Linker, ResourceTable};
use wasmtime::error::Context as _;
use wasmtime::{Config, Engine, Store};
use wasmtime_webcrypto::{WasiWebcryptoCtx, WasiWebcryptoCtxView, WasiWebcryptoView};
mod bindings {
    wasmtime::component::bindgen!({
        path: "../crypto-demo/wit",
        world: "crypto-demo",
        imports: {
            default: async | store | trappable,
        },
        exports: {
            default: async,
        },
    });
}

/// The store state: the WebCrypto host context plus the resource table its
/// keys and computations live in.
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

fn engine() -> anyhow::Result<Engine> {
    let mut config = Config::new();
    config.wasm_component_model(true);
    config.wasm_component_model_async(true);
    Ok(Engine::new(&config)?)
}

/// Instantiate the `crypto-demo` component at `component_path` with the
/// `lann:webcrypto` imports satisfied by [`wasmtime_webcrypto`], call its
/// exported async `run`, and return the summary string it produces.
///
/// A check failure reported by the guest (its `result<string, string>` `err`
/// case) is mapped into the returned error.
pub async fn run_demo(component_path: &Path) -> anyhow::Result<String> {
    run_demo_with(component_path, WasiWebcryptoCtx::new()).await
}

/// Like [`run_demo`], with a caller-provided [`WasiWebcryptoCtx`] (e.g. to
/// exercise its buffering limits).
pub async fn run_demo_with(
    component_path: &Path,
    webcrypto: WasiWebcryptoCtx,
) -> anyhow::Result<String> {
    let engine = engine()?;
    let component = Component::from_file(&engine, component_path)
        .with_context(|| format!("loading component {}", component_path.display()))?;

    let mut linker: Linker<Ctx> = Linker::new(&engine);
    // Shared `lann:webcrypto` imports — the component's only ones.
    wasmtime_webcrypto::add_to_linker(&mut linker)?;

    let mut store = Store::new(
        &engine,
        Ctx {
            webcrypto,
            table: ResourceTable::new(),
        },
    );
    let demo = bindings::CryptoDemo::instantiate_async(&mut store, &component, &linker).await?;

    let result = store
        .run_concurrent(async move |accessor: &Accessor<Ctx>| {
            demo.demo_webcrypto_demo_demo().call_run(accessor).await
        })
        .await??;

    result.map_err(|err| anyhow::anyhow!("demo returned error: {err}"))
}
