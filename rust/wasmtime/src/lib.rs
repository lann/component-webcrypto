//! Wasmtime host implementation of the `lann:webcrypto` interfaces, backed by
//! the pure-Rust [RustCrypto](https://github.com/RustCrypto) crates.
//!
//! This crate factors the host-agnostic part of the Wasmtime WebCrypto host
//! out of the demo binaries so any host can satisfy the `lann:webcrypto`
//! imports with one call to [`add_to_linker`]. It is an async (component-model
//! async) implementation modeled after [`wasmtime_wasi_http::p3`]: a host
//! embeds a [`WasiWebcryptoCtx`] in its store state, implements
//! [`WasiWebcryptoView`] to expose it alongside the store's [`ResourceTable`],
//! and calls [`add_to_linker`] to satisfy the full `lann:webcrypto`
//! package surface with RustCrypto implementations.
//!
//! [`wasmtime_wasi_http::p3`]: https://docs.rs/wasmtime-wasi-http

pub mod bindings;
mod host;
mod limits;
pub mod standalone;
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
///   may buffer. Inputs beyond it are drained and discarded (this host
///   drains to completion rather than exercising the streaming contract's
///   early-close-on-error permission) and the operation fails with a
///   recoverable `error.other`.
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
/// # Minted-resource retention
///
/// Minted resources — keys, IKM, passwords, derivations, options, digests —
/// live in the store's table until the guest drops them, so unbounded
/// minting is unbounded host retention even with every operation bounded.
/// A third limit bounds it:
///
/// - **Retention** ([`set_retention_limit`]): the retention pool. Every
///   mint charges a fixed per-resource floor (which bounds resource
///   *count*) plus its variable-length material bytes, holds the charge for
///   the resource's lifetime, and releases it when the resource drops.
///   Defaults to 16 MiB.
///
/// Retention admission is fail-fast, never waiting: its capacity frees only
/// when the guest drops a resource, which may never happen. A mint past the
/// budget fails with a recoverable `error.other` — drop resources and
/// retry. The `*-options.new` constructors, whose WIT signatures carry no
/// error channel, trap instead, the same class as a table-push failure.
///
/// What is bounded is what this host *accumulates*: the stream buffers, the
/// output stream until its bytes are read or dropped, and minted resources.
/// What is not bounded is the `list<u8>` parameters — `aad`, `nonce`, and
/// the minting interfaces' `raw` — which the canonical ABI lifts before the
/// host function runs, so they are already in host memory when admission is
/// reached. Bounding those needs a hold *before* the call starts, which the
/// component model provides to a component callee (`backpressure.{inc,dec}`)
/// and does not expose to a host import. (The in-guest provider, which could
/// use it, deliberately does not: it has essentially one caller, so its
/// instance memory limit is its bound — see lann-webcrypto-guest-provider's `buffer` module.)
/// Also outside the pools: each operation's transient working set — in
/// `seal`/`open` the buffered input and the constructed output coexist
/// until the input drops, so peak use briefly reaches about twice the
/// reservation plus the tag, and `derive-bits` builds its full output
/// before the ABI lifts it.
///
/// Each pool's budget is resolved **once**, at its first use, and belongs
/// to the pool from then on (see `limits.rs` for why the budget is the
/// pool's, not each acquirer's). Configure the limits before the first
/// crypto call; changing them afterwards retunes the per-call limit but
/// not the pools.
///
/// Cloning the context gives the clone its own pools, since the pools are
/// parameterized by the budgets the context carries.
///
/// [`set_per_call_buffer_limit`]: WasiWebcryptoCtx::set_per_call_buffer_limit
/// [`set_total_buffer_limit`]: WasiWebcryptoCtx::set_total_buffer_limit
/// [`set_retention_limit`]: WasiWebcryptoCtx::set_retention_limit
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
    /// The minted-resource retention pool, in bytes; `None` defaults to
    /// [`DEFAULT_RETENTION_LIMIT`].
    retention_limit: Option<u64>,
    /// The admission pool, created on first use with the budget resolved
    /// from this context and the store's hostcall fuel.
    pool: std::sync::OnceLock<std::sync::Arc<crate::limits::BufferPool>>,
    /// The retention pool, created on first mint with the budget resolved
    /// from this context.
    retention_pool: std::sync::OnceLock<std::sync::Arc<crate::limits::BufferPool>>,
}

/// The default minted-resource retention budget, in bytes. A constant
/// rather than a share of the store's hostcall fuel: mints must resolve it
/// in contexts that have no store access.
const DEFAULT_RETENTION_LIMIT: u64 = 16 * 1024 * 1024;

/// Cloning a context gives the clone its **own** pools.
///
/// The pools bound aggregate retention against ceilings that each context
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
            retention_limit: self.retention_limit,
            pool: std::sync::OnceLock::new(),
            retention_pool: std::sync::OnceLock::new(),
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

    /// Set the minted-resource retention pool, in bytes: the most the
    /// guest's live resources (keys, derivations, options, …) may retain
    /// host-side, charged per mint and released per drop. `None` (the
    /// default) is 16 MiB. A limit below the per-resource floor admits no
    /// mint at all.
    pub fn set_retention_limit(&mut self, limit: Option<u64>) {
        self.retention_limit = limit;
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

    /// The effective retention limit, floored so the pool is never empty by
    /// construction.
    pub(crate) fn retention_limit_bytes(&self) -> u64 {
        self.retention_limit
            .unwrap_or(DEFAULT_RETENTION_LIMIT)
            .max(1)
    }

    /// Charge one mint's retention (the per-resource floor plus
    /// `material_bytes`) against the retention pool, fail-fast: `None` when
    /// the budget cannot fit the charge now. The reservation releases when
    /// dropped — it travels in the minted resource.
    pub(crate) fn charge_retention(
        &self,
        material_bytes: usize,
    ) -> Option<crate::limits::Reservation> {
        let pool = self
            .retention_pool
            .get_or_init(|| crate::limits::pool(self.retention_limit_bytes()));
        crate::limits::charge(pool, material_bytes)
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

/// A resource this host mints: a payload plus the retention reservation
/// charged for it (see [`WasiWebcryptoCtx`], "Minted-resource retention").
/// [`minted_resources!`] implements it, placing the reservation in a
/// private field so it releases exactly when the resource leaves the
/// store's table.
pub(crate) trait Minted: Sized {
    /// What a mint computes; any other fields take their declared
    /// defaults.
    type Payload;

    /// The variable-length bytes the resource retains beyond the
    /// per-resource floor, measured for the retention charge.
    fn payload_bytes(payload: &Self::Payload) -> usize;

    /// Assemble the resource around its charged reservation.
    fn minted(payload: Self::Payload, retention: crate::limits::Reservation) -> Self;
}

/// Declare the minted resource types: the `#[payload]` field, any
/// defaulted extra fields, and the hidden retention reservation, with the
/// [`Minted`] impl assembling them. `#[payload(retains = method)]` names
/// the payload method measuring the retention charge's variable part (the
/// default is floor-only); anything more complex than a method call
/// belongs on the payload type, not in a declaration.
macro_rules! minted_resources {
    ($(
        $(#[$attr:meta])*
        pub struct $name:ident {
            #[payload $((retains = $measure:ident))?]
            $(#[$pattr:meta])*
            $payload:ident: $pty:ty
            $(, $(#[$fattr:meta])* $field:ident: $fty:ty = $default:expr)* $(,)?
        }
    )*) => {$(
        $(#[$attr])*
        pub struct $name {
            $(#[$pattr])*
            pub(crate) $payload: $pty,
            $($(#[$fattr])* pub(crate) $field: $fty,)*
            _retention: crate::limits::Reservation,
        }

        impl Minted for $name {
            type Payload = $pty;

            fn payload_bytes(payload: &Self::Payload) -> usize {
                let _ = payload;
                0 $(+ payload.$measure())?
            }

            fn minted(payload: Self::Payload, retention: crate::limits::Reservation) -> Self {
                Self {
                    $payload: payload,
                    $($field: $default,)*
                    _retention: retention,
                }
            }
        }
    )*};
}

minted_resources! {
    /// A `mac-key-options` resource: mint-time policy under construction.
    /// Constructed with the WIT defaults (nothing granted), mutated by the
    /// setters, consumed by a mint.
    #[derive(Debug)]
    pub struct MacKeyOptions {
        #[payload]
        policy: lann_webcrypto_core::MacPolicy,
    }

    /// An `aead-key-options` resource. See [`MacKeyOptions`].
    #[derive(Debug)]
    pub struct AeadKeyOptions {
        #[payload]
        policy: lann_webcrypto_core::AeadPolicy,
    }

    /// A `cipher-key-options` resource. See [`MacKeyOptions`].
    #[derive(Debug)]
    pub struct CipherKeyOptions {
        #[payload]
        policy: lann_webcrypto_core::CipherPolicy,
    }

    /// An `internal-nonce-key-options` resource. See [`MacKeyOptions`].
    #[derive(Debug)]
    pub struct InternalNonceKeyOptions {
        #[payload]
        policy: lann_webcrypto_core::InternalNoncePolicy,
    }

    /// A `signing-key-options` resource. See [`MacKeyOptions`].
    #[derive(Debug)]
    pub struct SigningKeyOptions {
        #[payload]
        policy: lann_webcrypto_core::SigningPolicy,
    }

    /// A `kw-key-options` resource. See [`MacKeyOptions`].
    #[derive(Debug)]
    pub struct KwKeyOptions {
        #[payload]
        policy: lann_webcrypto_core::KwPolicy,
    }

    /// A `decryption-key-options` resource. See [`MacKeyOptions`].
    #[derive(Debug)]
    pub struct DecryptionKeyOptions {
        #[payload]
        policy: lann_webcrypto_core::TransportPolicy,
    }

    /// Backing type for the `public-encryption.encryption-key` resource.
    ///
    /// Public material only — encryption and wrapping are grant-free, and
    /// there is no extractability gate (the exports are unconditional).
    #[derive(Debug)]
    pub struct EncryptionKey {
        #[payload]
        material: lann_webcrypto_core::EncryptionKeyMaterial,
    }

    /// Backing type for the `public-encryption.decryption-key` resource.
    ///
    /// `decrypt`/`unwrap` are one-shot and stateless per call, so the key
    /// carries no per-operation state. The mint-time policy gates the two
    /// operations and the private exports.
    #[derive(Debug)]
    pub struct DecryptionKey {
        #[payload]
        material: lann_webcrypto_core::DecryptionKeyMaterial,
    }

    /// Backing type for the `key-wrap.kw-key` resource: the AES-KW
    /// key-encryption key's material.
    #[derive(Debug)]
    pub struct KwKey {
        #[payload(retains = byte_len)]
        material: lann_webcrypto_core::KwKeyMaterial,
    }

    /// Backing type for the `wrapping.wrap-input` resource: one key's
    /// serialized material awaiting encryption under a wrapping key,
    /// consumed by the wrap operations.
    #[derive(Debug)]
    pub struct WrapInput {
        #[payload(retains = byte_len)]
        material: lann_webcrypto_core::WrapInputMaterial,
    }

    /// Backing type for the `wrapping.unwrap-input` resource: decrypted
    /// key material awaiting a typed mint, consumed by the unwrap mints.
    #[derive(Debug)]
    pub struct UnwrapInput {
        #[payload(retains = byte_len)]
        material: lann_webcrypto_core::UnwrapInputMaterial,
    }

    /// A `derive-options` resource. See [`MacKeyOptions`].
    #[derive(Debug)]
    pub struct DeriveOptions {
        #[payload]
        policy: lann_webcrypto_core::DerivePolicy,
    }

    /// An `agreement-key-options` resource. See [`MacKeyOptions`].
    #[derive(Debug)]
    pub struct AgreementKeyOptions {
        #[payload]
        policy: lann_webcrypto_core::AgreementPolicy,
    }

    /// Backing type for the `key-agreement.public-key` resource: public
    /// material only, exchangeable and secret-free.
    #[derive(Debug)]
    pub struct AgreementPublicKey {
        #[payload]
        material: lann_webcrypto_core::AgreementPublicMaterial,
    }

    /// Backing type for the `key-agreement.secret-key` resource. `agree` is
    /// one-shot and stateless per call; the derivation state lives in the
    /// `derive-input` it mints.
    #[derive(Debug)]
    pub struct AgreementSecretKey {
        #[payload]
        material: lann_webcrypto_core::AgreementSecretMaterial,
    }

    /// Backing type for the `hkdf.ikm` resource: input keying material, never
    /// readable through the API under any grant.
    #[derive(Debug)]
    pub struct Ikm {
        #[payload(retains = byte_len)]
        material: lann_webcrypto_core::IkmMaterial,
    }

    /// Backing type for the `pbkdf2.password` resource: a password, never
    /// readable through the API under any grant.
    #[derive(Debug)]
    pub struct Password {
        #[payload(retains = byte_len)]
        material: lann_webcrypto_core::PasswordMaterial,
    }

    /// Backing type for the `derivation.derive-input` resource: a
    /// parameterized derivation, run eagerly (the extract step runs at
    /// `prepare`, so this retains the PRK rather than the base secret).
    #[derive(Debug)]
    pub struct DeriveInput {
        #[payload(retains = byte_len)]
        material: lann_webcrypto_core::DeriveInputMaterial,
    }

    /// Backing type for the `mac.mac-key` resource.
    ///
    /// Holds the shared core's HMAC key material (raw bytes zeroized on drop,
    /// the bound SHA-2 variant, and extractability); `sign`/`verify` are
    /// one-shot and stateless per call, so the key carries no per-operation
    /// state. `extractable` gates `export-key-raw` only — the material necessarily
    /// lives host-side either way.
    #[derive(Debug)]
    pub struct MacKey {
        #[payload(retains = byte_len)]
        material: lann_webcrypto_core::MacKeyMaterial,
    }

    /// Backing type for the `aead.aead-key` resource.
    ///
    /// Holds the shared core's AEAD key material (the ready-to-use cipher bound
    /// to its algorithm at minting, raw bytes zeroized on drop, and
    /// extractability). `seal`/`open` are stateless per call, so the key
    /// carries no per-operation state.
    #[derive(Debug)]
    pub struct AeadKey {
        #[payload(retains = byte_len)]
        material: lann_webcrypto_core::AeadKeyMaterial,
    }

    /// Backing type for the `cipher.cipher-key` resource: the unauthenticated
    /// AES modes' key material.
    pub struct CipherKey {
        #[payload(retains = byte_len)]
        material: lann_webcrypto_core::CipherKeyMaterial,
    }

    /// Backing type for the `aead-internal-nonce.internal-nonce-key` resource.
    ///
    /// Like [`AeadKey`], but the nonce is generated here per `seal` (the SP
    /// 800-38D §8.2.2 RBG-based construction) and carried in the sealed output.
    /// The key tracks its seal count to enforce the WIT nonce budget
    /// (`error.key-exhausted`) for 12-byte-nonce algorithms.
    #[derive(Debug)]
    pub struct InternalNonceKey {
        #[payload(retains = byte_len)]
        material: lann_webcrypto_core::AeadKeyMaterial,
        /// The number of `seal` invocations so far, counted against the
        /// algorithm's nonce budget.
        sealed: u64 = 0,
    }

    /// Backing type for the `digest.digest` resource.
    ///
    /// A digest holds no key material — just the algorithm it is bound to
    /// (a SHA-2 variant, or checked SHA-1 in a collision posture); `compute`
    /// is one-shot and stateless per call, so the resource is reusable and
    /// carries no per-operation state.
    #[derive(Debug)]
    pub struct Digest {
        #[payload]
        /// The digest algorithm this resource is bound to.
        variant: lann_webcrypto_core::DigestKind,
    }

    /// Backing type for the `signature.verifying-key` resource.
    ///
    /// Public material only — verification is secret-free, and there is no
    /// extractability gate (`%export` always succeeds).
    #[derive(Debug)]
    pub struct VerifyingKey {
        #[payload]
        /// The public key, bound to its algorithm (and, for ECDSA, its
        /// curve/digest variant) at minting.
        public: lann_webcrypto_core::SigPublic,
    }

    /// Backing type for the `signature.signing-key` resource.
    ///
    /// `sign` is one-shot and stateless per call, so the key carries no
    /// per-operation state. `extractable` gates `%export` only.
    #[derive(Debug)]
    pub struct SigningKey {
        #[payload]
        material: lann_webcrypto_core::SigningKeyMaterial,
    }
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
/// use lann_webcrypto_wasmtime::{
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
///
/// The `@unstable`-gated interfaces — the ChaCha family, `sha1-checked`,
/// the RSA signing pair, and RSA-OAEP decryption-key minting (see
/// `wit/README.md`, "Stability gates") — are
/// **not** added: a guest whose world imports them
/// fails to instantiate against this default. Opt in with
/// [`add_to_linker_with_options`].
pub fn add_to_linker<T>(linker: &mut Linker<T>) -> wasmtime::Result<()>
where
    T: WasiWebcryptoView + 'static,
{
    add_to_linker_with_options(linker, &LinkOptions::default())
}

/// Which `@unstable`-gated interfaces [`add_to_linker_with_options`] adds.
/// Every flag defaults to off; this host implements all of them, so a flag
/// is embedder policy, not capability.
#[derive(Clone, Debug, Default)]
pub struct LinkOptions {
    chacha20_poly1305: bool,
    xchacha20_poly1305: bool,
    sha1_checked: bool,
    rsa_sign: bool,
    rsa_oaep_decrypt: bool,
}

impl LinkOptions {
    /// Serve `lann:webcrypto/chacha20-poly1305`.
    pub fn chacha20_poly1305(&mut self, enabled: bool) -> &mut Self {
        self.chacha20_poly1305 = enabled;
        self
    }

    /// Serve `lann:webcrypto/xchacha20-poly1305` and
    /// `lann:webcrypto/xchacha20-poly1305-internal-nonce`.
    pub fn xchacha20_poly1305(&mut self, enabled: bool) -> &mut Self {
        self.xchacha20_poly1305 = enabled;
        self
    }

    /// Serve `lann:webcrypto/sha1-checked`.
    pub fn sha1_checked(&mut self, enabled: bool) -> &mut Self {
        self.sha1_checked = enabled;
        self
    }

    /// Serve `lann:webcrypto/rsassa-pkcs1-v15-sign` and
    /// `lann:webcrypto/rsa-pss-sign`.
    pub fn rsa_sign(&mut self, enabled: bool) -> &mut Self {
        self.rsa_sign = enabled;
        self
    }

    /// Serve `lann:webcrypto/rsa-oaep-decrypt`.
    pub fn rsa_oaep_decrypt(&mut self, enabled: bool) -> &mut Self {
        self.rsa_oaep_decrypt = enabled;
        self
    }
}

/// [`add_to_linker`], with the `@unstable`-gated interfaces `options`
/// selects also served.
pub fn add_to_linker_with_options<T>(
    linker: &mut Linker<T>,
    options: &LinkOptions,
) -> wasmtime::Result<()>
where
    T: WasiWebcryptoView + 'static,
{
    bindings::webcrypto::types::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::bytes::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::mac::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::aead::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::wrapping::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::key_wrap::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::aes_kw::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::aead_internal_nonce::add_to_linker::<_, WasiWebcrypto>(
        linker,
        T::webcrypto,
    )?;
    bindings::webcrypto::digest::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::derivation::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::key_agreement::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::x25519::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::ecdh::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::hkdf::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::hkdf_sha2::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::hkdf_sha1::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::pbkdf2::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::pbkdf2_sha2::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::pbkdf2_sha1::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::hmac_sha2::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::hmac_sha1::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::aes_gcm::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::cipher::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::aes_cbc::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::aes_ctr::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    // The generated `add_to_linker`s for the gated interfaces consult
    // their `LinkOptions` and add nothing when the flag is off.
    bindings::webcrypto::chacha20_poly1305::add_to_linker::<_, WasiWebcrypto>(
        linker,
        bindings::webcrypto::chacha20_poly1305::LinkOptions::default()
            .chacha20_poly1305(options.chacha20_poly1305),
        T::webcrypto,
    )?;
    bindings::webcrypto::xchacha20_poly1305::add_to_linker::<_, WasiWebcrypto>(
        linker,
        bindings::webcrypto::xchacha20_poly1305::LinkOptions::default()
            .xchacha20_poly1305(options.xchacha20_poly1305),
        T::webcrypto,
    )?;
    bindings::webcrypto::aes_gcm_internal_nonce::add_to_linker::<_, WasiWebcrypto>(
        linker,
        T::webcrypto,
    )?;
    bindings::webcrypto::xchacha20_poly1305_internal_nonce::add_to_linker::<_, WasiWebcrypto>(
        linker,
        bindings::webcrypto::xchacha20_poly1305_internal_nonce::LinkOptions::default()
            .xchacha20_poly1305(options.xchacha20_poly1305),
        T::webcrypto,
    )?;
    bindings::webcrypto::sha2::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::sha1_checked::add_to_linker::<_, WasiWebcrypto>(
        linker,
        bindings::webcrypto::sha1_checked::LinkOptions::default()
            .sha1_checked(options.sha1_checked),
        T::webcrypto,
    )?;
    bindings::webcrypto::signature::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::ed25519_verify::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::ed25519_sign::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::ecdsa_verify::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::ecdsa_sign::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::rsa::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::rsassa_pkcs1_v15_verify::add_to_linker::<_, WasiWebcrypto>(
        linker,
        T::webcrypto,
    )?;
    bindings::webcrypto::rsa_pss_verify::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::rsassa_pkcs1_v15_sign::add_to_linker::<_, WasiWebcrypto>(
        linker,
        bindings::webcrypto::rsassa_pkcs1_v15_sign::LinkOptions::default()
            .rsa_sign(options.rsa_sign),
        T::webcrypto,
    )?;
    bindings::webcrypto::rsa_pss_sign::add_to_linker::<_, WasiWebcrypto>(
        linker,
        bindings::webcrypto::rsa_pss_sign::LinkOptions::default().rsa_sign(options.rsa_sign),
        T::webcrypto,
    )?;
    bindings::webcrypto::public_encryption::add_to_linker::<_, WasiWebcrypto>(
        linker,
        T::webcrypto,
    )?;
    bindings::webcrypto::rsa_oaep_encrypt::add_to_linker::<_, WasiWebcrypto>(linker, T::webcrypto)?;
    bindings::webcrypto::rsa_oaep_decrypt::add_to_linker::<_, WasiWebcrypto>(
        linker,
        bindings::webcrypto::rsa_oaep_decrypt::LinkOptions::default()
            .rsa_oaep_decrypt(options.rsa_oaep_decrypt),
        T::webcrypto,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::WasiWebcryptoCtx;

    /// The untouched defaults derive from the store's hostcall fuel — ¼
    /// per call, 1× total — floored at 1 when the derivation rounds to
    /// zero.
    #[test]
    fn buffer_limits_default_derivation() {
        let ctx = WasiWebcryptoCtx::new();
        assert_eq!(ctx.buffer_limits(8), (2, 8));
        assert_eq!(ctx.buffer_limits(0), (1, 1));
    }

    /// The setters govern the derived limits, with per-call clamped into
    /// the pool's bound.
    #[test]
    fn buffer_limits_reflect_configuration() {
        let mut ctx = WasiWebcryptoCtx::new();
        ctx.set_per_call_buffer_limit(Some(16));
        ctx.set_total_buffer_limit(Some(64));
        assert_eq!(ctx.buffer_limits(1024), (16, 64));
        ctx.set_per_call_buffer_limit(Some(128));
        assert_eq!(ctx.buffer_limits(1024), (64, 64));
    }

    /// A clone carries the configured limits but gets its own pools (the
    /// `Clone` impl's contract: budgets are per-context).
    #[test]
    fn clone_preserves_limits_with_a_fresh_pool() {
        let mut ctx = WasiWebcryptoCtx::new();
        ctx.set_per_call_buffer_limit(Some(3));
        ctx.set_total_buffer_limit(Some(9));
        ctx.set_retention_limit(Some(crate::limits::RETENTION_FLOOR * 3 / 2));
        let pool = ctx.pool(9).clone();
        let charge = ctx.charge_retention(0).expect("within the fresh budget");
        let clone = ctx.clone();
        assert_eq!(clone.buffer_limits(1024), (3, 9));
        assert_eq!(
            clone.retention_limit_bytes(),
            crate::limits::RETENTION_FLOOR * 3 / 2
        );
        assert!(!std::sync::Arc::ptr_eq(&pool, clone.pool(9)));
        // The clone's retention pool is fresh: the original's outstanding
        // charge does not count against it.
        assert!(clone.charge_retention(0).is_some());
        assert!(ctx.charge_retention(0).is_none(), "the original is spent");
        drop(charge);
    }

    /// Minting charges the retention pool and dropping the reservation
    /// releases it, with the budget resolved once at first charge.
    #[test]
    fn retention_charges_release_on_drop() {
        let mut ctx = WasiWebcryptoCtx::new();
        ctx.set_retention_limit(Some(crate::limits::RETENTION_FLOOR * 2));
        let first = ctx.charge_retention(0).expect("floor fits");
        let second = ctx.charge_retention(0).expect("two floors fit");
        assert!(ctx.charge_retention(0).is_none(), "budget is spent");
        drop(first);
        let third = ctx.charge_retention(0).expect("released capacity readmits");
        drop((second, third));
        // Raising the limit after the pool resolved does not retune it.
        ctx.set_retention_limit(Some(1_000_000));
        assert!(ctx.charge_retention(1_000).is_none());
    }
}
