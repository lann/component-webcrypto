//! Wasmtime host implementation of the `lann:webcrypto` interfaces, backed by
//! the pure-Rust [RustCrypto](https://github.com/RustCrypto) crates.
//!
//! This crate factors the host-agnostic part of the Wasmtime WebCrypto host
//! out of the demo binaries so any host can satisfy the `lann:webcrypto`
//! imports with one call to [`add_to_linker`]. It is a wasip3 (component-model
//! async) implementation modeled after [`wasmtime_wasi_http::p3`]: a host
//! embeds a [`WasiWebcryptoCtx`] in its store state, implements
//! [`WasiWebcryptoView`] to expose it alongside the store's [`ResourceTable`],
//! and calls [`add_to_linker`] to satisfy the `types`, `mac`, `aead`, `hmac`,
//! and `aes-gcm` imports with HMAC-SHA-256 and AES-256-GCM implementations.
//!
//! [`wasmtime_wasi_http::p3`]: https://docs.rs/wasmtime-wasi-http

pub mod bindings;
mod host;

use hmac::Hmac;
use sha2::Sha256;
use wasmtime::component::{HasData, Linker, ResourceTable};

/// The incremental HMAC-SHA-256 state backing a `mac` computation.
pub(crate) type HmacSha256 = Hmac<Sha256>;

/// The algorithm name reported by HMAC-SHA-256 keys and computations.
pub(crate) const HMAC_SHA_256: &str = "HMAC-SHA-256";

/// The algorithm name reported by AES-256-GCM keys.
pub(crate) const AES_256_GCM: &str = "AES-256-GCM";

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
/// Holds the raw key material and the key's extractability. The algorithm is
/// fixed at creation (currently always HMAC-SHA-256); `extractable` gates
/// `%export` only — the material necessarily lives host-side either way.
pub struct MacKey {
    /// The raw key material, retained for `start` and (when extractable)
    /// `%export`.
    pub(crate) raw: Vec<u8>,
    /// Whether `%export` may return the raw material.
    pub(crate) extractable: bool,
    /// The algorithm this key is bound to, e.g. `"HMAC-SHA-256"`.
    pub(crate) algorithm: &'static str,
}

/// Backing type for the `mac.mac` resource: one in-progress MAC computation.
///
/// Wraps the incremental RustCrypto HMAC state; `absorb` updates it and
/// `finalize`/`verify` consume it (removing the table entry, so
/// use-after-finalize is unrepresentable, matching the WIT contract).
pub struct MacComputation {
    /// The incremental HMAC state, updated by each absorbed stream.
    pub(crate) hmac: HmacSha256,
    /// The algorithm of the key this computation was started from.
    pub(crate) algorithm: &'static str,
}

/// Backing type for the `aead.aead-key` resource.
///
/// Holds the ready-to-use AES-256-GCM cipher alongside the raw key material
/// (for `%export` on extractable keys). `seal`/`open` are stateless per call,
/// so the key carries no per-operation state.
pub struct AeadKey {
    /// The AES-256-GCM cipher keyed by `raw`.
    pub(crate) cipher: aes_gcm::Aes256Gcm,
    /// The raw key material, retained for `%export` on extractable keys.
    pub(crate) raw: Vec<u8>,
    /// Whether `%export` may return the raw material.
    pub(crate) extractable: bool,
    /// The algorithm this key is bound to, e.g. `"AES-256-GCM"`.
    pub(crate) algorithm: &'static str,
}

/// Add the `lann:webcrypto` interfaces implemented by this crate (`types`,
/// `mac`, `aead`, `hmac`, and `aes-gcm`) to the provided [`Linker`].
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
    bindings::webcrypto::hmac::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::aes_gcm::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    Ok(())
}
