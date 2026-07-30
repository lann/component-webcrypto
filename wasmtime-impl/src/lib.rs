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
mod limits;
mod streams;

use wasmtime::component::{HasData, Linker, ResourceTable};

/// Configuration and per-store state for the WebCrypto host.
///
/// This is intentionally minimal (mirroring `wasmtime_wasi_http`'s
/// `WasiHttpCtx`); it exists so hosts have a stable place to grow
/// configuration without changing the [`WasiWebcryptoView`] shape.
///
/// # Input-buffering limits
///
/// Every stream-taking operation buffers its whole input host-side (the
/// single-message contract), and the component-model async ABI lets a guest
/// run many calls concurrently — so without limits a guest could make the
/// host retain unbounded memory. Two limits bound that retention (wasmtime's
/// per-call lift budget, [`Store::set_hostcall_fuel`], bounds each stream
/// *delivery*; these bound what operations *accumulate*):
///
/// - **Per call** ([`set_per_call_buffer_limit`]): the most one operation
///   may buffer. Inputs beyond it are drained and discarded (the WIT drain
///   rule holds) and the operation fails with a recoverable `error.other`.
///   Defaults to ¼ of the store's hostcall fuel at admission time.
/// - **Total** ([`set_total_buffer_limit`]): the admission pool. Each
///   operation reserves its per-call bound before draining and waits
///   (FIFO) for capacity when the pool is full, releasing when its buffers
///   are gone — including the returned output stream. Defaults to 1× the
///   store's hostcall fuel, so untouched configurations retain at most the
///   embedder's one configured number, at a default concurrency of four
///   operations.
///
/// Admission shares one pool per context, so an operation may wait on
/// *unrelated* operations' completion. The package states the caller's side
/// of this as the making-progress rule (see the `mac-key` docs): feed each
/// in-flight operation's input, and drain each returned stream as it becomes
/// available, without waiting on another operation. A caller that defers
/// either can deadlock against the bound, and no implementation can rescue
/// it.
///
/// What is bounded is what this host *accumulates*: the stream buffers, and
/// the output stream until its bytes are read or dropped. What is not
/// bounded is the `list<u8>` parameters — `aad`, `nonce`, and the minting
/// interfaces' `raw` — which the canonical ABI lifts before the host
/// function runs, so they are already in host memory when admission is
/// reached. Bounding those needs a hold *before* the call starts, which the
/// component model provides to a component callee (`backpressure.{inc,dec}`)
/// and does not expose to a host import; the in-guest provider, being a
/// component, uses it.
///
/// The pool's budget is resolved **once**, at the first operation that
/// buffers, and belongs to the pool from then on. Changing
/// [`Store::set_hostcall_fuel`] afterwards therefore retunes the per-call
/// limit but not the pool. The alternative — re-reading the ceiling per
/// acquisition — leaves the pool enforcing nothing of its own: every
/// waiter judges one shared counter against its own ceiling, so acquirers
/// configured differently disagree about how full the pool is, and a
/// release cannot tell whether the next waiter fits without borrowing a
/// ceiling from whoever happened to be releasing. Configure the limits
/// before the first crypto call.
///
/// Cloning the context gives the clone its own pool, since the pool is
/// parameterized by the budget the context carries.
///
/// [`set_per_call_buffer_limit`]: WasiWebcryptoCtx::set_per_call_buffer_limit
/// [`set_total_buffer_limit`]: WasiWebcryptoCtx::set_total_buffer_limit
/// [`Store::set_hostcall_fuel`]: wasmtime::Store::set_hostcall_fuel
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct WasiWebcryptoCtx {
    /// The most one operation may buffer, in bytes; `None` defaults to ¼ of
    /// the store's hostcall fuel.
    per_call_buffer_limit: Option<u64>,
    /// The admission pool, in bytes; `None` defaults to the store's
    /// hostcall fuel.
    total_buffer_limit: Option<u64>,
    /// The admission pool, created on first use with the budget resolved
    /// from this context and the store's hostcall fuel.
    pool: std::sync::OnceLock<std::sync::Arc<crate::limits::BufferPool>>,
}

/// Cloning a context gives the clone its **own** admission pool.
///
/// The pool bounds aggregate retention against a ceiling that each context
/// carries separately, so sharing one pool between contexts configured
/// differently would let the larger ceiling admit against the smaller
/// context's accounting — exceeding the bound it was asked to enforce.
/// Independent pools keep each context's limit meaning what it says; a
/// single bound across several contexts is not something this type can
/// express.
impl Clone for WasiWebcryptoCtx {
    fn clone(&self) -> Self {
        Self {
            per_call_buffer_limit: self.per_call_buffer_limit,
            total_buffer_limit: self.total_buffer_limit,
            pool: std::sync::OnceLock::new(),
        }
    }
}

impl WasiWebcryptoCtx {
    /// Create a new, default context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the most one operation may buffer, in bytes. `None` (the
    /// default) derives ¼ of the store's hostcall fuel at admission time.
    pub fn set_per_call_buffer_limit(&mut self, limit: Option<u64>) {
        self.per_call_buffer_limit = limit;
    }

    /// Set the total input-buffering admission pool, in bytes. `None` (the
    /// default) derives the store's hostcall fuel at admission time.
    pub fn set_total_buffer_limit(&mut self, limit: Option<u64>) {
        self.total_buffer_limit = limit;
    }

    /// The effective `(per-call, total)` limits given the store's hostcall
    /// fuel, clamped so a reservation always fits an empty pool and no
    /// limit is zero.
    pub(crate) fn buffer_limits(&self, hostcall_fuel: u64) -> (u64, u64) {
        let total = self.total_buffer_limit.unwrap_or(hostcall_fuel).max(1);
        let per_call = self
            .per_call_buffer_limit
            .unwrap_or(hostcall_fuel / 4)
            .clamp(1, total);
        (per_call, total)
    }

    /// The admission pool, created on first use with `total` as its budget.
    /// Later calls reuse the pool that exists: the budget is the pool's, not
    /// each acquisition's.
    pub(crate) fn pool(&self, total: u64) -> &std::sync::Arc<crate::limits::BufferPool> {
        self.pool.get_or_init(|| crate::limits::pool(total))
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
/// Holds the shared core's HMAC key material (raw bytes zeroized on drop,
/// the bound SHA-2 variant, and extractability); `sign`/`verify` are
/// one-shot and stateless per call, so the key carries no per-operation
/// state. `extractable` gates `export-key` only — the material necessarily
/// lives host-side either way.
#[derive(Debug)]
pub struct MacKey {
    pub(crate) material: webcrypto_impl_core::MacKeyMaterial,
}

/// Backing type for the `aead.aead-key` resource.
///
/// Holds the shared core's AEAD key material (the ready-to-use cipher bound
/// to its algorithm at minting, raw bytes zeroized on drop, and
/// extractability). `seal`/`open` are stateless per call, so the key
/// carries no per-operation state.
#[derive(Debug)]
pub struct AeadKey {
    pub(crate) material: webcrypto_impl_core::AeadKeyMaterial,
}

/// Backing type for the `aead-internal-nonce.internal-nonce-key` resource.
///
/// Like [`AeadKey`], but the nonce is generated here per `seal` (the SP
/// 800-38D §8.2.2 RBG-based construction) and carried in the sealed output.
/// The key tracks its seal count to enforce the WIT nonce budget
/// (`error.key-exhausted`) for 12-byte-nonce algorithms.
#[derive(Debug)]
pub struct InternalNonceKey {
    pub(crate) material: webcrypto_impl_core::AeadKeyMaterial,
    /// The number of `seal` invocations so far, counted against the
    /// algorithm's nonce budget.
    pub(crate) sealed: u64,
}

/// Backing type for the `digest.digest` resource.
///
/// A digest holds no key material — just the SHA-2 variant it is bound to;
/// `compute` is one-shot and stateless per call, so the resource is
/// reusable and carries no per-operation state.
#[derive(Debug)]
pub struct Digest {
    /// The SHA-2 variant this digest is bound to.
    pub(crate) variant: webcrypto_impl_core::Sha2,
}

/// Backing type for the `signature.verifying-key` resource.
///
/// Public material only — verification is secret-free, and there is no
/// extractability gate (`%export` always succeeds).
#[derive(Debug)]
pub struct VerifyingKey {
    /// The public key, bound to its algorithm (and, for ECDSA, its
    /// curve/digest variant) at minting.
    pub(crate) public: webcrypto_impl_core::SigPublic,
}

/// Backing type for the `signature.signing-key` resource.
///
/// `sign` is one-shot and stateless per call, so the key carries no
/// per-operation state. `extractable` gates `%export` only.
#[derive(Debug)]
pub struct SigningKey {
    pub(crate) material: webcrypto_impl_core::SigningKeyMaterial,
}

// `Debug` derives on the key-holding types print through the shared
// core's material types, whose hand-written `Debug` impls redact all key
// material — a key reaching a log line cannot leak (asserted by the
// `debug_redacts_key_material` tests here and in the core).

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
