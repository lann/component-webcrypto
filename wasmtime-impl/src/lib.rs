//! Wasmtime host implementation of the `lann:webcrypto` interfaces, backed by
//! the pure-Rust [RustCrypto](https://github.com/RustCrypto) crates.
//!
//! This crate factors the host-agnostic part of the Wasmtime WebCrypto host
//! out of the demo binaries so any host can satisfy the `lann:webcrypto`
//! imports with one call to [`add_to_linker`]. It is a wasip3 (component-model
//! async) implementation modeled after [`wasmtime_wasi_http::p3`]: a host
//! embeds a [`WasiWebcryptoCtx`] in its store state, implements
//! [`WasiWebcryptoView`] to expose it alongside the store's [`ResourceTable`],
//! and calls [`add_to_linker`] to satisfy the `types`, `mac`, `aead`, `hmac-sha2`,
//! and `aes-gcm` imports with HMAC-SHA-2 and AES-GCM implementations.
//!
//! [`wasmtime_wasi_http::p3`]: https://docs.rs/wasmtime-wasi-http

pub mod bindings;
mod host;

use wasmtime::component::{HasData, Linker, ResourceTable};

/// The `algorithm-name` reported by HMAC keys and computations
/// (WebCrypto's `KeyAlgorithm.name`).
pub(crate) const HMAC_NAME: &str = "HMAC";

/// The `algorithm-name` reported by AES-GCM keys (WebCrypto's
/// `KeyAlgorithm.name`).
pub(crate) const AES_GCM_NAME: &str = "AES-GCM";

/// Configuration and per-store state for the WebCrypto host.
///
/// This is intentionally minimal (mirroring `wasmtime_wasi_http`'s
/// `WasiHttpCtx`); it exists so hosts have a stable place to grow
/// configuration without changing the [`WasiWebcryptoView`] shape. There are
/// no knobs yet.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct WasiWebcryptoCtx {}

impl WasiWebcryptoCtx {
    /// Create a new, default context.
    pub fn new() -> Self {
        Self::default()
    }
}

/// A borrowed view into a host's [`WasiWebcryptoCtx`] and its
/// [`ResourceTable`].
///
/// Returned by [`WasiWebcryptoView::webcrypto`], this is the [`HasData::Data`]
/// the generated host bindings operate on.
pub struct WasiWebcryptoCtxView<'a> {
    /// Mutable reference to the WebCrypto host context.
    pub ctx: &'a mut WasiWebcryptoCtx,
    /// Mutable reference to the table used to manage host resources.
    pub table: &'a mut ResourceTable,
}

/// A trait that provides access to the [`WasiWebcryptoCtx`] host state.
///
/// Implement this for your store's data type so [`add_to_linker`] can wire the
/// `lann:webcrypto` imports onto your linker.
pub trait WasiWebcryptoView: Send {
    /// Return a [`WasiWebcryptoCtxView`] from a mutable reference to `self`.
    fn webcrypto(&mut self) -> WasiWebcryptoCtxView<'_>;
}

/// The type for which this crate implements the `lann:webcrypto` interfaces.
/// Used as the [`HasData`] marker for the generated bindings.
pub struct WasiWebcrypto;

impl HasData for WasiWebcrypto {
    type Data<'a> = WasiWebcryptoCtxView<'a>;
}

/// Backing type for the `mac.mac-key` resource.
///
/// Holds the raw key material, the SHA-2 variant the key is bound to, and
/// the key's extractability; `sign`/`verify` are one-shot and stateless per
/// call, so the key carries no per-operation state. `extractable` gates
/// `%export` only — the material necessarily lives host-side either way.
pub struct MacKey {
    /// The raw key material, retained for `sign`/`verify` and (when
    /// extractable) `%export`.
    pub(crate) raw: Vec<u8>,
    /// The SHA-2 variant this key is bound to.
    pub(crate) variant: crate::host::HmacVariant,
    /// Whether `%export` may return the raw material.
    pub(crate) extractable: bool,
}

/// Backing type for the `aead.aead-key` resource.
///
/// Holds the ready-to-use AES-GCM cipher alongside the raw key material
/// (for `%export` on extractable keys). `seal`/`open` are stateless per call,
/// so the key carries no per-operation state.
pub struct AeadKey {
    /// The AES-GCM cipher keyed by `raw`, dispatching on key size.
    pub(crate) cipher: crate::host::AesGcmCipher,
    /// The raw key material, retained for `%export` on extractable keys.
    pub(crate) raw: Vec<u8>,
    /// Whether `%export` may return the raw material.
    pub(crate) extractable: bool,
}

/// Add the `lann:webcrypto` interfaces implemented by this crate (`types`,
/// `mac`, `aead`, `hmac-sha2`, and `aes-gcm`) to the provided [`Linker`].
///
/// The store's data type `T` must implement [`WasiWebcryptoView`]. The
/// engine's [`Config`](wasmtime::Config) must have
/// `wasm_component_model_async` enabled, since the key-minting and
/// stream-carrying functions use the component-model async ABI.
///
/// # Example
///
/// ```no_run
/// use wasmtime::component::{Linker, ResourceTable};
/// use wasmtime::{Engine, Result};
/// use wasmtime_webcrypto::{
///     add_to_linker, WasiWebcryptoCtx, WasiWebcryptoCtxView, WasiWebcryptoView,
/// };
///
/// struct MyState {
///     webcrypto: WasiWebcryptoCtx,
///     table: ResourceTable,
/// }
///
/// impl WasiWebcryptoView for MyState {
///     fn webcrypto(&mut self) -> WasiWebcryptoCtxView<'_> {
///         WasiWebcryptoCtxView {
///             ctx: &mut self.webcrypto,
///             table: &mut self.table,
///         }
///     }
/// }
///
/// fn wire(linker: &mut Linker<MyState>) -> Result<()> {
///     add_to_linker(linker)
/// }
/// ```
pub fn add_to_linker<T>(linker: &mut Linker<T>) -> wasmtime::Result<()>
where
    T: WasiWebcryptoView + 'static,
{
    bindings::webcrypto::types::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::mac::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::aead::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::hmac_sha2::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::aes_gcm::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    Ok(())
}
