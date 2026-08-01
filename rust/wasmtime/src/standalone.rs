//! Ready-made embedding for hosts whose component imports only
//! `lann:webcrypto`: the canonical store state and the engine/linker/store
//! setup this repository's drivers share (the demo host and the
//! conformance adapter), so the engine configuration the async imports
//! require has one definition.
//!
//! Hosts with store state of their own implement [`WasiWebcryptoView`] on
//! their own type and call [`add_to_linker`](crate::add_to_linker)
//! directly instead.

use std::path::Path;

use wasmtime::component::{Component, HasData, Linker, ResourceTable};
use wasmtime::error::Context as _;
use wasmtime::{Config, Engine, Store};

use crate::{WasiWebcryptoCtx, WasiWebcryptoCtxView, WasiWebcryptoView};

/// The store state: the WebCrypto host context plus the resource table its
/// keys and computations live in.
pub struct Ctx {
    /// The WebCrypto host context.
    pub webcrypto: WasiWebcryptoCtx,
    /// The table the host's resources live in.
    pub table: ResourceTable,
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

/// An engine configured for the component-model async ABI the
/// `lann:webcrypto` imports use.
pub fn engine() -> wasmtime::Result<Engine> {
    let mut config = Config::new();
    config.wasm_component_model(true);
    config.wasm_component_model_async(true);
    Engine::new(&config)
}

/// Load the component at `path` and prepare everything an instantiation
/// needs: a linker with the `lann:webcrypto` imports added, and a store
/// whose state carries `webcrypto`.
pub fn load(
    path: &Path,
    webcrypto: WasiWebcryptoCtx,
) -> wasmtime::Result<(Component, Linker<Ctx>, Store<Ctx>)> {
    let engine = engine()?;
    let component = Component::from_file(&engine, path)
        .with_context(|| format!("loading component {}", path.display()))?;
    let mut linker: Linker<Ctx> = Linker::new(&engine);
    // The canned embedding is the demo and conformance-adapter path, and
    // the conformance manifest declares the wasmtime target missing no
    // features — so the `@unstable`-gated interfaces are all served here,
    // unlike `add_to_linker`'s default.
    crate::add_to_linker_with_options(
        &mut linker,
        crate::LinkOptions::default()
            .chacha20_poly1305(true)
            .xchacha20_poly1305(true),
    )?;
    let store = Store::new(
        &engine,
        Ctx {
            webcrypto,
            table: ResourceTable::new(),
        },
    );
    Ok((component, linker, store))
}
