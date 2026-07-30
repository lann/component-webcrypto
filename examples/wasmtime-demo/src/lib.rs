//! Wasmtime host for the `crypto-demo` component, backed by
//! [`wasmtime_webcrypto`]'s RustCrypto implementation of `lann:webcrypto`.
//!
//! It is the non-browser counterpart to the jco (browser WebCrypto) host: it
//! loads the same `crypto-demo` component and invokes the component's
//! exported async `run`. The component drives every check itself through the
//! standard `lann:webcrypto` interfaces, so this host provisions nothing
//! beyond [`wasmtime_webcrypto::standalone`]'s canned embedding.

use std::path::Path;

use wasmtime::component::Accessor;
use wasmtime_webcrypto::standalone::{self, Ctx};
use wasmtime_webcrypto::WasiWebcryptoCtx;

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
    let (component, linker, mut store) = standalone::load(component_path, webcrypto)?;
    let demo = bindings::CryptoDemo::instantiate_async(&mut store, &component, &linker).await?;

    let result = store
        .run_concurrent(async move |accessor: &Accessor<Ctx>| {
            demo.demo_webcrypto_demo_demo().call_run(accessor).await
        })
        .await??;

    result.map_err(|err| anyhow::anyhow!("demo returned error: {err}"))
}
