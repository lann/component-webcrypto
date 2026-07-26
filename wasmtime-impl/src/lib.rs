//! Wasmtime host implementation of the `lann:webcrypto` interfaces, backed by
//! the pure-Rust [RustCrypto](https://github.com/RustCrypto) crates.
//!
//! This crate factors the host-agnostic part of the Wasmtime WebCrypto host
//! out of the demo binaries so any host can satisfy the `lann:webcrypto`
//! imports with one call to [`add_to_linker`]. It is an async (component-model
//! async) implementation modeled after [`wasmtime_wasi_http::p3`]: a host
//! embeds a [`WasiWebcryptoCtx`] in its store state, implements
//! [`WasiWebcryptoView`] to expose it alongside the store's [`ResourceTable`],
//! and calls [`add_to_linker`] to satisfy the `types`, `bytes`, `mac`,
//! `aead`, `digest`, `signature`, and the minting interfaces
//! imports with HMAC-SHA-2, AES-GCM, ChaCha20-Poly1305, and SHA-2
//! implementations.
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

/// The `algorithm-name` reported by ChaCha20-Poly1305 keys (the spelling of
/// the WICG WebCrypto proposal; the algorithm is not in the W3C registry).
pub(crate) const CHACHA20_POLY1305_NAME: &str = "ChaCha20-Poly1305";

/// The `algorithm-name` reported by XChaCha20-Poly1305 keys.
pub(crate) const XCHACHA20_POLY1305_NAME: &str = "XChaCha20-Poly1305";

/// The `algorithm-name` reported by Ed25519 keys (WebCrypto's
/// `KeyAlgorithm.name`, per the Secure Curves registry entry).
pub(crate) const ED25519_NAME: &str = "Ed25519";

/// The `algorithm-name` reported by ECDSA keys (WebCrypto's
/// `KeyAlgorithm.name`).
pub(crate) const ECDSA_NAME: &str = "ECDSA";

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
    /// extractable) `%export`; zeroized on drop.
    pub(crate) raw: zeroize::Zeroizing<Vec<u8>>,
    /// The SHA-2 variant this key is bound to.
    pub(crate) variant: crate::host::Sha2,
    /// Whether `%export` may return the raw material.
    pub(crate) extractable: bool,
}

/// Backing type for the `aead.aead-key` resource.
///
/// Holds the ready-to-use cipher alongside the raw key material
/// (for `%export` on extractable keys). `seal`/`open` are stateless per call,
/// so the key carries no per-operation state.
pub struct AeadKey {
    /// The cipher keyed by `raw`, bound to its algorithm at minting.
    pub(crate) cipher: crate::host::AeadCipher,
    /// The raw key material, retained for `%export` on extractable keys;
    /// zeroized on drop.
    pub(crate) raw: zeroize::Zeroizing<Vec<u8>>,
    /// Whether `%export` may return the raw material.
    pub(crate) extractable: bool,
}

/// Backing type for the `aead-internal-nonce.internal-nonce-key` resource.
///
/// Like [`AeadKey`], but the nonce is generated here per `seal` (the SP
/// 800-38D §8.2.2 RBG-based construction) and carried in the sealed output.
/// The key tracks its seal count to enforce the WIT nonce budget
/// (`error.key-exhausted`) for 12-byte-nonce algorithms.
pub struct InternalNonceKey {
    /// The cipher keyed by `raw`, bound to its algorithm at minting.
    pub(crate) cipher: crate::host::AeadCipher,
    /// The raw key material, retained for `export-key` on extractable keys;
    /// zeroized on drop.
    pub(crate) raw: zeroize::Zeroizing<Vec<u8>>,
    /// Whether `export-key` may return the raw material.
    pub(crate) extractable: bool,
    /// The number of `seal` invocations so far, counted against the
    /// algorithm's nonce budget.
    pub(crate) sealed: u64,
}

/// Backing type for the `digest.digest` resource.
///
/// A digest holds no key material — just the SHA-2 variant it is bound to;
/// `compute` is one-shot and stateless per call, so the resource is
/// reusable and carries no per-operation state.
pub struct Digest {
    /// The SHA-2 variant this digest is bound to.
    pub(crate) variant: crate::host::Sha2,
}

/// Backing type for the `signature.verifying-key` resource.
///
/// Public material only — verification is secret-free, and there is no
/// extractability gate (`%export` always succeeds).
pub struct VerifyingKey {
    /// The public key, bound to its algorithm (and, for ECDSA, its
    /// curve/digest variant) at minting.
    pub(crate) public: crate::host::SigPublic,
}

/// Backing type for the `signature.signing-key` resource.
///
/// `sign` is one-shot and stateless per call, so the key carries no
/// per-operation state. `extractable` gates `%export` only.
pub struct SigningKey {
    /// The private key, bound to its algorithm (and, for ECDSA, its
    /// curve/digest variant) at minting.
    pub(crate) private: crate::host::SigPrivate,
    /// Whether `%export` may return the private material.
    pub(crate) extractable: bool,
}

// Debug is implemented by hand for every key-holding type so that key
// material can never reach logs: only the algorithm binding and
// extractability are printed, with the material redacted. (Deriving `Debug`
// on these types would print `raw`/`private` bytes.)

impl std::fmt::Debug for MacKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MacKey")
            .field("variant", &self.variant)
            .field("extractable", &self.extractable)
            .field("raw", &"<redacted>")
            .finish()
    }
}

impl std::fmt::Debug for AeadKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AeadKey")
            .field("algorithm", &self.cipher.name())
            .field("extractable", &self.extractable)
            .field("raw", &"<redacted>")
            .finish()
    }
}

impl std::fmt::Debug for InternalNonceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InternalNonceKey")
            .field("algorithm", &self.cipher.name())
            .field("extractable", &self.extractable)
            .field("sealed", &self.sealed)
            .field("raw", &"<redacted>")
            .finish()
    }
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("algorithm", &self.private.name())
            .field("extractable", &self.extractable)
            .field("private", &"<redacted>")
            .finish()
    }
}

impl std::fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Public material is not secret, but printing it wholesale is
        // rarely useful; identify the key by algorithm only.
        f.debug_struct("VerifyingKey")
            .field("algorithm", &self.public.name())
            .finish()
    }
}

/// Add the `lann:webcrypto` interfaces implemented by this crate — `types`,
/// `bytes`, the primitive kinds (`mac`, `aead`, `digest`, `signature`), and
/// the algorithm minting interfaces — to the provided [`Linker`].
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
    bindings::webcrypto::bytes::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::mac::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::aead::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::aead_internal_nonce::add_to_linker::<_, WasiWebcrypto>(
        linker,
        T::webcrypto,
    )?;
    bindings::webcrypto::digest::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::hmac_sha2::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::aes_gcm::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::chacha20_poly1305::add_to_linker::<_, WasiWebcrypto>(
        linker,
        T::webcrypto,
    )?;
    bindings::webcrypto::xchacha20_poly1305::add_to_linker::<_, WasiWebcrypto>(
        linker,
        T::webcrypto,
    )?;
    bindings::webcrypto::aes_gcm_internal_nonce::add_to_linker::<_, WasiWebcrypto>(
        linker,
        T::webcrypto,
    )?;
    bindings::webcrypto::xchacha20_poly1305_internal_nonce::add_to_linker::<_, WasiWebcrypto>(
        linker,
        T::webcrypto,
    )?;
    bindings::webcrypto::sha2::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::signature::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::ed25519_verify::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::ed25519_sign::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::ecdsa_verify::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::ecdsa_sign::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    Ok(())
}
