//! Host trait implementations for the `lann:webcrypto` imports.
//!
//! Following the split the generated bindings produce (and mirroring
//! `wasmtime_wasi_http::p3`), the store-free traits are implemented for the
//! [`WasiWebcryptoCtxView`] "data" type, while the traits whose methods need
//! the async `Accessor` are implemented for the [`WasiWebcrypto`] `HasData`
//! marker.
//!
//! The cryptography itself lives in `webcrypto-impl-core`, shared verbatim
//! with the in-guest provider; this module contributes only what is
//! host-specific — stream plumbing, buffer-limit admission, the resource
//! table, and the bindings glue converting the generated types to the
//! core's.

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::channel::oneshot;
use wasmtime::component::{
    Accessor, AsAccessor as _, Destination, Resource, Source, StreamConsumer, StreamProducer,
    StreamReader, StreamResult, VecBuffer,
};
use wasmtime::{Result, StoreContextMut};
use webcrypto_impl_core::{
    served_sha2, AeadKeyMaterial, MacKeyMaterial, SigPublic, SigningKeyMaterial, HMAC_NAME,
};

use crate::bindings::webcrypto::aead::{self, HostAeadKey, HostAeadKeyWithStore};
use crate::bindings::webcrypto::aead_internal_nonce::{
    self, HostInternalNonceKey, HostInternalNonceKeyWithStore,
};
use crate::bindings::webcrypto::digest::{HostDigest, HostDigestWithStore};
use crate::bindings::webcrypto::mac::{self, HostMacKey, HostMacKeyWithStore};
use crate::bindings::webcrypto::types::{self, Error};
use crate::bindings::webcrypto::{
    aes_gcm as aes_gcm_iface, aes_gcm_internal_nonce as aes_gcm_in_iface, bytes as bytes_iface,
    chacha20_poly1305 as chacha_iface, digest as digest_iface, ecdsa_sign as ecdsa_sign_iface,
    ecdsa_verify as ecdsa_verify_iface, ed25519_sign as ed25519_sign_iface,
    ed25519_verify as ed25519_verify_iface, hmac_sha2 as hmac_sha2_iface, sha2 as sha2_iface,
    signature as signature_iface, xchacha20_poly1305 as xchacha_iface,
    xchacha20_poly1305_internal_nonce as xchacha_in_iface,
};
use crate::limits::Reservation;
use crate::{
    AeadKey, Digest, InternalNonceKey, MacKey, SigningKey, VerifyingKey, WasiWebcrypto,
    WasiWebcryptoCtxView,
};

// --- bindings glue -------------------------------------------------------------

impl From<webcrypto_impl_core::Error> for Error {
    fn from(err: webcrypto_impl_core::Error) -> Self {
        use webcrypto_impl_core::Error as CoreError;
        match err {
            CoreError::InvalidKey(msg) => Self::InvalidKey(msg),
            CoreError::InvalidNonce(msg) => Self::InvalidNonce(msg),
            CoreError::AuthenticationFailed => Self::AuthenticationFailed,
            CoreError::NotExtractable => Self::NotExtractable,
            CoreError::Unsupported(msg) => Self::Unsupported(msg),
            CoreError::KeyExhausted => Self::KeyExhausted,
            CoreError::Other(msg) => Self::Other(msg),
        }
    }
}

/// The core's variant for a generated `sha2-variant`.
fn core_sha2_variant(variant: sha2_iface::Sha2Variant) -> webcrypto_impl_core::Sha2Variant {
    use sha2_iface::Sha2Variant;
    use webcrypto_impl_core::Sha2Variant as Core;
    match variant {
        Sha2Variant::Sha224 => Core::Sha224,
        Sha2Variant::Sha256 => Core::Sha256,
        Sha2Variant::Sha384 => Core::Sha384,
        Sha2Variant::Sha512 => Core::Sha512,
        Sha2Variant::Sha512224 => Core::Sha512224,
        Sha2Variant::Sha512256 => Core::Sha512256,
    }
}

/// The core's variant for a generated `aes-variant`.
fn core_aes_variant(variant: aes_gcm_iface::AesVariant) -> webcrypto_impl_core::AesVariant {
    use aes_gcm_iface::AesVariant;
    use webcrypto_impl_core::AesVariant as Core;
    match variant {
        AesVariant::Aes128 => Core::Aes128,
        AesVariant::Aes192 => Core::Aes192,
        AesVariant::Aes256 => Core::Aes256,
    }
}

/// The core's variant for a generated `ecdsa-variant`.
fn core_ecdsa_variant(
    variant: ecdsa_verify_iface::EcdsaVariant,
) -> webcrypto_impl_core::EcdsaVariant {
    use ecdsa_verify_iface::EcdsaVariant;
    use webcrypto_impl_core::EcdsaVariant as Core;
    match variant {
        EcdsaVariant::P256Sha256 => Core::P256Sha256,
        EcdsaVariant::P384Sha384 => Core::P384Sha384,
    }
}

/// Render an entropy failure as the trap-shaped host error for key or nonce
/// generation: the host treats a failing random source as an operational
/// host fault, never a guest-visible WIT error.
fn rng_trap(what: &str) -> impl Fn(webcrypto_impl_core::RngError) -> wasmtime::Error + '_ {
    move |err| wasmtime::Error::msg(format!("{what} failed: {err}"))
}

// --- types -------------------------------------------------------------------

impl types::Host for WasiWebcryptoCtxView<'_> {}

// --- bytes ---------------------------------------------------------------------

impl bytes_iface::Host for WasiWebcryptoCtxView<'_> {
    fn constant_time_equal(&mut self, a: Vec<u8>, b: Vec<u8>) -> Result<bool> {
        Ok(webcrypto_impl_core::constant_time_equal(&a, &b))
    }
}

// --- stream plumbing ---------------------------------------------------------

/// A [`StreamConsumer`] that drains every byte of a `stream<u8>` into a
/// buffer, handing the completed buffer back through `done_tx` when the
/// stream ends.
///
/// Dropping the consumer is how Wasmtime signals end-of-stream (the writer
/// dropped its end), so `Drop` is the sole completion point. If a host-side
/// pipe error occurs, the buffer is never delivered — the channel closes
/// unsent and [`drain_stream`] surfaces an error — so a partial buffer can
/// never be mistaken for the complete input.
struct ByteCollector {
    buf: Vec<u8>,
    /// The per-call buffering cap: bytes beyond it are drained (the WIT
    /// drain rule holds) but discarded, and the operation reports the
    /// overflow instead of a result.
    cap: usize,
    overflowed: bool,
    failed: bool,
    done_tx: Option<oneshot::Sender<std::result::Result<Vec<u8>, InputOverflow>>>,
}

/// Marker for an input stream that exceeded the per-call buffering cap.
#[derive(Debug, PartialEq)]
struct InputOverflow;

impl<D: Send + 'static> StreamConsumer<D> for ByteCollector {
    type Item = u8;

    fn poll_consume(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        mut store: StoreContextMut<D>,
        mut source: Source<'_, u8>,
        finish: bool,
    ) -> Poll<Result<StreamResult>> {
        let this = self.get_mut(); // safe: ByteCollector is Unpin

        let available = source.remaining(&mut store);
        if available > 0 {
            if !this.overflowed && this.buf.len().saturating_add(available) > this.cap {
                // Over the per-call cap: stop retaining (free what we
                // held), keep draining-and-discarding below.
                this.overflowed = true;
                this.buf = Vec::new();
            }
            let mut chunk = Vec::with_capacity(available);
            if let Err(err) = source.read(&mut store, &mut chunk) {
                // Never let `Drop` deliver a partial buffer as if it were
                // the complete input.
                this.failed = true;
                return Poll::Ready(Err(err));
            }
            if !this.overflowed {
                this.buf.extend_from_slice(&chunk);
            }
            return Poll::Ready(Ok(StreamResult::Completed));
        }

        // No bytes available. When `finish` is set the writer cancelled its
        // pending write; the stream itself remains open, so keep the buffer
        // and keep collecting — `Drop` is the completion point.
        if finish {
            return Poll::Ready(Ok(StreamResult::Cancelled));
        }

        // Otherwise this is a zero-length write, which is legal. Report it
        // consumed rather than parking: `StreamConsumer` permits
        // `Ready(Completed)` with nothing taken when nothing was available,
        // provided the next call can accept an item — unconditionally true
        // here, since this collector either buffers or, past the cap,
        // drains and discards.
        //
        // `Pending` would be wrong, not merely slower. The contract requires
        // arming `cx`'s waker before parking, and this consumer has nothing
        // to arm it from: it awaits no external event, so a parked poll is
        // never resumed. The writer would never receive `COMPLETED`,
        // `drain_stream`'s completion signal would never fire, and the
        // admission `Reservation` held across the call would starve every
        // other operation in the store.
        Poll::Ready(Ok(StreamResult::Completed))
    }
}

impl Drop for ByteCollector {
    fn drop(&mut self) {
        if !self.failed {
            if let Some(tx) = self.done_tx.take() {
                let _ = tx.send(if self.overflowed {
                    Err(InputOverflow)
                } else {
                    Ok(std::mem::take(&mut self.buf))
                });
            }
        }
    }
}

/// Drain an entire `stream<u8>` into a buffer, resolving once the stream ends
/// (its writer dropped). The outer `Result` is a host-side pipe error (the
/// consumer torn down without delivering the complete input); the inner one
/// reports an input that exceeded the admitted per-call buffering cap as
/// the WIT's recoverable operational error.
async fn drain_stream<T: Send>(
    accessor: &Accessor<T, WasiWebcrypto>,
    data: StreamReader<u8>,
    cap: usize,
) -> Result<std::result::Result<Vec<u8>, Error>> {
    let (done_tx, done_rx) = oneshot::channel();
    accessor.with(|access| {
        data.pipe(
            access,
            ByteCollector {
                buf: Vec::new(),
                cap,
                overflowed: false,
                failed: false,
                done_tx: Some(done_tx),
            },
        )
    })?;
    Ok(done_rx
        .await
        .map_err(|_| wasmtime::Error::msg("input stream ended without completing"))?
        .map_err(|InputOverflow| {
            Error::Other(format!(
                "input exceeds the per-call buffer limit ({cap} bytes); see \
                 WasiWebcryptoCtx::set_per_call_buffer_limit and \
                 Store::set_hostcall_fuel"
            ))
        }))
}

/// Admit one stream-draining operation against the context's buffer limits
/// (waiting FIFO for pool capacity), returning the reservation guard and
/// the operation's buffering cap.
async fn admit_input<T: Send>(
    accessor: &Accessor<T, WasiWebcrypto>,
) -> Result<(Reservation, usize)> {
    let (pool, per_call) = accessor.as_accessor().with(|mut access| {
        let fuel = wasmtime::AsContextMut::as_context_mut(&mut access).hostcall_fuel() as u64;
        let view = access.get();
        let (per_call, total) = view.ctx.buffer_limits(fuel);
        Ok::<_, wasmtime::Error>((view.ctx.pool(total).clone(), per_call))
    })?;
    let reservation = pool.admit(per_call).await;
    Ok((reservation, usize::try_from(per_call).unwrap_or(usize::MAX)))
}

/// A host-produced output stream that carries the operation's buffer-pool
/// [`Reservation`]: the reservation releases only when the output bytes have
/// been handed off (or the stream is dropped), so pool capacity tracks the
/// bytes the host actually retains.
struct GuardedOutput {
    data: Option<Vec<u8>>,
    _reservation: Reservation,
}

impl GuardedOutput {
    fn new(data: Vec<u8>, reservation: Reservation) -> Self {
        Self {
            data: (!data.is_empty()).then_some(data),
            _reservation: reservation,
        }
    }
}

impl<D> StreamProducer<D> for GuardedOutput {
    type Item = u8;
    type Buffer = VecBuffer<u8>;

    fn poll_produce<'a>(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _store: StoreContextMut<'a, D>,
        mut dst: Destination<'a, Self::Item, Self::Buffer>,
        _finish: bool,
    ) -> Poll<Result<StreamResult>> {
        let this = self.get_mut();
        match this.data.take() {
            // Hand the whole buffer over but stay alive (`Completed`): we
            // are polled again once it has drained, and only then drop —
            // releasing the reservation after the bytes have left.
            Some(bytes) => {
                dst.set_buffer(bytes.into());
                Poll::Ready(Ok(StreamResult::Completed))
            }
            None => Poll::Ready(Ok(StreamResult::Dropped)),
        }
    }
}

// --- mac ---------------------------------------------------------------------

impl mac::Host for WasiWebcryptoCtxView<'_> {}

impl HostMacKey for WasiWebcryptoCtxView<'_> {
    fn algorithm_name(&mut self, self_: Resource<MacKey>) -> Result<String> {
        self.table.get(&self_)?;
        Ok(HMAC_NAME.to_string())
    }

    fn algorithm_hash(&mut self, self_: Resource<MacKey>) -> Result<Option<String>> {
        Ok(Some(
            self.table.get(&self_)?.material.hash_name().to_string(),
        ))
    }

    fn algorithm_length(&mut self, self_: Resource<MacKey>) -> Result<u32> {
        Ok(self.table.get(&self_)?.material.length_bits())
    }
}

impl<T: Send> HostMacKeyWithStore<T> for WasiWebcrypto {
    async fn sign(
        accessor: &Accessor<T, Self>,
        self_: Resource<MacKey>,
        data: StreamReader<u8>,
    ) -> Result<std::result::Result<Vec<u8>, Error>> {
        let (_reservation, cap) = admit_input(accessor).await?;
        // Buffer the whole stream, then fold it into the HMAC state; the
        // result is chunking-invariant either way.
        //
        // The WIT `err` case exists for operational keystore failures; this
        // implementation holds the material in-process, so it never errs.
        let bytes = match drain_stream(accessor, data, cap).await? {
            Ok(bytes) => bytes,
            Err(err) => return Ok(Err(err)),
        };
        accessor.with(|mut access| {
            let key = access.get().table.get(&self_)?;
            Ok(Ok(key.material.sign(&bytes)))
        })
    }

    async fn verify(
        accessor: &Accessor<T, Self>,
        self_: Resource<MacKey>,
        data: StreamReader<u8>,
        tag: Vec<u8>,
    ) -> Result<std::result::Result<(), Error>> {
        let (_reservation, cap) = admit_input(accessor).await?;
        let bytes = match drain_stream(accessor, data, cap).await? {
            Ok(bytes) => bytes,
            Err(err) => return Ok(Err(err)),
        };
        accessor.with(|mut access| {
            let key = access.get().table.get(&self_)?;
            Ok(key.material.verify(&bytes, &tag).map_err(Error::from))
        })
    }

    async fn export_key(
        accessor: &Accessor<T, Self>,
        self_: Resource<MacKey>,
    ) -> Result<std::result::Result<Vec<u8>, Error>> {
        accessor.with(|mut access| {
            let key = access.get().table.get(&self_)?;
            Ok(key.material.export().map_err(Error::from))
        })
    }

    async fn drop(accessor: &Accessor<T, Self>, rep: Resource<MacKey>) -> Result<()> {
        accessor.with(|mut access| {
            access.get().table.delete(rep)?;
            Ok(())
        })
    }
}

// --- aead --------------------------------------------------------------------

impl aead::Host for WasiWebcryptoCtxView<'_> {}

impl HostAeadKey for WasiWebcryptoCtxView<'_> {
    fn algorithm_name(&mut self, self_: Resource<AeadKey>) -> Result<String> {
        Ok(self.table.get(&self_)?.material.name().to_string())
    }

    fn algorithm_length(&mut self, self_: Resource<AeadKey>) -> Result<u32> {
        Ok(self.table.get(&self_)?.material.length_bits())
    }

    fn nonce_size(&mut self, self_: Resource<AeadKey>) -> Result<u32> {
        Ok(self.table.get(&self_)?.material.nonce_len() as u32)
    }

    fn tag_size(&mut self, self_: Resource<AeadKey>) -> Result<u32> {
        Ok(self.table.get(&self_)?.material.tag_len() as u32)
    }
}

impl<T: Send> HostAeadKeyWithStore<T> for WasiWebcrypto {
    async fn seal(
        accessor: &Accessor<T, Self>,
        self_: Resource<AeadKey>,
        nonce: Vec<u8>,
        aad: Vec<u8>,
        plaintext: StreamReader<u8>,
    ) -> Result<std::result::Result<StreamReader<u8>, Error>> {
        let (reservation, cap) = admit_input(accessor).await?;
        // Per the WIT contract, the input stream is fully drained even when
        // the call resolves with an error, so the caller's writer always
        // completes.
        let msg = match drain_stream(accessor, plaintext, cap).await? {
            Ok(msg) => msg,
            Err(err) => return Ok(Err(err)),
        };
        let sealed = accessor.with(|mut access| {
            let key = access.get().table.get(&self_)?;
            Ok::<_, wasmtime::Error>(key.material.seal(&nonce, &aad, &msg))
        })?;
        let sealed = match sealed {
            Ok(sealed) => sealed,
            Err(err) => return Ok(Err(err.into())),
        };
        let reader = accessor
            .with(|access| StreamReader::new(access, GuardedOutput::new(sealed, reservation)))?;
        Ok(Ok(reader))
    }

    async fn open(
        accessor: &Accessor<T, Self>,
        self_: Resource<AeadKey>,
        nonce: Vec<u8>,
        aad: Vec<u8>,
        ciphertext: StreamReader<u8>,
    ) -> Result<std::result::Result<StreamReader<u8>, Error>> {
        let (reservation, cap) = admit_input(accessor).await?;
        // Per the WIT contract, the input stream is fully drained even when
        // the call resolves with an error, so the caller's writer always
        // completes. Buffering the whole message is inherent to `open`: no
        // unverified plaintext may be observable.
        let msg = match drain_stream(accessor, ciphertext, cap).await? {
            Ok(msg) => msg,
            Err(err) => return Ok(Err(err)),
        };
        let opened = accessor.with(|mut access| {
            let key = access.get().table.get(&self_)?;
            Ok::<_, wasmtime::Error>(key.material.open(&nonce, &aad, &msg))
        })?;
        let opened = match opened {
            Ok(opened) => opened,
            Err(err) => return Ok(Err(err.into())),
        };
        let reader = accessor
            .with(|access| StreamReader::new(access, GuardedOutput::new(opened, reservation)))?;
        Ok(Ok(reader))
    }

    async fn export_key(
        accessor: &Accessor<T, Self>,
        self_: Resource<AeadKey>,
    ) -> Result<std::result::Result<Vec<u8>, Error>> {
        accessor.with(|mut access| {
            let key = access.get().table.get(&self_)?;
            Ok(key.material.export().map_err(Error::from))
        })
    }

    async fn drop(accessor: &Accessor<T, Self>, rep: Resource<AeadKey>) -> Result<()> {
        accessor.with(|mut access| {
            access.get().table.delete(rep)?;
            Ok(())
        })
    }
}

// --- digest --------------------------------------------------------------------

impl digest_iface::Host for WasiWebcryptoCtxView<'_> {}

impl HostDigest for WasiWebcryptoCtxView<'_> {
    fn algorithm_name(&mut self, self_: Resource<Digest>) -> Result<String> {
        Ok(self.table.get(&self_)?.variant.hash_name().to_string())
    }
}

impl<T: Send> HostDigestWithStore<T> for WasiWebcrypto {
    async fn compute(
        accessor: &Accessor<T, Self>,
        self_: Resource<Digest>,
        data: StreamReader<u8>,
    ) -> Result<std::result::Result<Vec<u8>, Error>> {
        let (_reservation, cap) = admit_input(accessor).await?;
        let variant = accessor
            .with(|mut access| Ok::<_, wasmtime::Error>(access.get().table.get(&self_)?.variant))?;
        // Buffer the whole stream, then hash it; the result is
        // chunking-invariant either way.
        //
        // The WIT `err` case exists for operational failures (e.g. an
        // external digest engine); this implementation computes in-process,
        // so it never errs.
        let bytes = match drain_stream(accessor, data, cap).await? {
            Ok(bytes) => bytes,
            Err(err) => return Ok(Err(err)),
        };
        Ok(Ok(variant.digest(&bytes)))
    }

    async fn drop(accessor: &Accessor<T, Self>, rep: Resource<Digest>) -> Result<()> {
        accessor.with(|mut access| {
            access.get().table.delete(rep)?;
            Ok(())
        })
    }
}

// --- sha2 (digest minting) ---------------------------------------------------

impl sha2_iface::Host for WasiWebcryptoCtxView<'_> {
    fn make_digest(
        &mut self,
        variant: sha2_iface::Sha2Variant,
    ) -> Result<std::result::Result<Resource<Digest>, Error>> {
        let variant = match served_sha2(core_sha2_variant(variant)) {
            Ok(variant) => variant,
            Err(err) => return Ok(Err(err.into())),
        };
        Ok(Ok(self.table.push(Digest { variant })?))
    }
}

// --- hmac-sha2 (key minting) -----------------------------------------------------

impl hmac_sha2_iface::Host for WasiWebcryptoCtxView<'_> {}

impl<T: Send> hmac_sha2_iface::HostWithStore<T> for WasiWebcrypto {
    async fn import_key(
        accessor: &Accessor<T, Self>,
        variant: hmac_sha2_iface::Sha2Variant,
        raw: Vec<u8>,
        extractable: bool,
    ) -> Result<std::result::Result<Resource<MacKey>, Error>> {
        let material = match MacKeyMaterial::import(core_sha2_variant(variant), raw, extractable) {
            Ok(material) => material,
            Err(err) => return Ok(Err(err.into())),
        };
        accessor.with(|mut access| Ok(Ok(access.get().table.push(MacKey { material })?)))
    }

    async fn generate_key(
        accessor: &Accessor<T, Self>,
        variant: hmac_sha2_iface::Sha2Variant,
        extractable: bool,
    ) -> Result<std::result::Result<Resource<MacKey>, Error>> {
        let material = match MacKeyMaterial::generate(core_sha2_variant(variant), extractable)
            .map_err(rng_trap("random key generation"))?
        {
            Ok(material) => material,
            Err(err) => return Ok(Err(err.into())),
        };
        accessor.with(|mut access| Ok(Ok(access.get().table.push(MacKey { material })?)))
    }
}

// --- aes-gcm (key minting) -------------------------------------------------------

impl aes_gcm_iface::Host for WasiWebcryptoCtxView<'_> {}

impl<T: Send> aes_gcm_iface::HostWithStore<T> for WasiWebcrypto {
    async fn import_key(
        accessor: &Accessor<T, Self>,
        variant: aes_gcm_iface::AesVariant,
        raw: Vec<u8>,
        extractable: bool,
    ) -> Result<std::result::Result<Resource<AeadKey>, Error>> {
        let material =
            match AeadKeyMaterial::import_aes_gcm(core_aes_variant(variant), raw, extractable) {
                Ok(material) => material,
                Err(err) => return Ok(Err(err.into())),
            };
        accessor.with(|mut access| Ok(Ok(access.get().table.push(AeadKey { material })?)))
    }

    async fn generate_key(
        accessor: &Accessor<T, Self>,
        variant: aes_gcm_iface::AesVariant,
        extractable: bool,
    ) -> Result<std::result::Result<Resource<AeadKey>, Error>> {
        let material =
            match AeadKeyMaterial::generate_aes_gcm(core_aes_variant(variant), extractable)
                .map_err(rng_trap("random key generation"))?
            {
                Ok(material) => material,
                Err(err) => return Ok(Err(err.into())),
            };
        accessor.with(|mut access| Ok(Ok(access.get().table.push(AeadKey { material })?)))
    }
}

// --- chacha20-poly1305 / xchacha20-poly1305 (key minting) ---------------------

impl chacha_iface::Host for WasiWebcryptoCtxView<'_> {}
impl xchacha_iface::Host for WasiWebcryptoCtxView<'_> {}

impl<T: Send> chacha_iface::HostWithStore<T> for WasiWebcrypto {
    async fn import_key(
        accessor: &Accessor<T, Self>,
        raw: Vec<u8>,
        extractable: bool,
    ) -> Result<std::result::Result<Resource<AeadKey>, Error>> {
        let material = match AeadKeyMaterial::import_chacha20_poly1305(raw, extractable) {
            Ok(material) => material,
            Err(err) => return Ok(Err(err.into())),
        };
        accessor.with(|mut access| Ok(Ok(access.get().table.push(AeadKey { material })?)))
    }

    async fn generate_key(
        accessor: &Accessor<T, Self>,
        extractable: bool,
    ) -> Result<std::result::Result<Resource<AeadKey>, Error>> {
        let material = AeadKeyMaterial::generate_chacha20_poly1305(extractable)
            .map_err(rng_trap("random key generation"))?;
        accessor.with(|mut access| Ok(Ok(access.get().table.push(AeadKey { material })?)))
    }
}

impl<T: Send> xchacha_iface::HostWithStore<T> for WasiWebcrypto {
    async fn import_key(
        accessor: &Accessor<T, Self>,
        raw: Vec<u8>,
        extractable: bool,
    ) -> Result<std::result::Result<Resource<AeadKey>, Error>> {
        let material = match AeadKeyMaterial::import_xchacha20_poly1305(raw, extractable) {
            Ok(material) => material,
            Err(err) => return Ok(Err(err.into())),
        };
        accessor.with(|mut access| Ok(Ok(access.get().table.push(AeadKey { material })?)))
    }

    async fn generate_key(
        accessor: &Accessor<T, Self>,
        extractable: bool,
    ) -> Result<std::result::Result<Resource<AeadKey>, Error>> {
        let material = AeadKeyMaterial::generate_xchacha20_poly1305(extractable)
            .map_err(rng_trap("random key generation"))?;
        accessor.with(|mut access| Ok(Ok(access.get().table.push(AeadKey { material })?)))
    }
}

// --- aead-internal-nonce -------------------------------------------------------

impl aead_internal_nonce::Host for WasiWebcryptoCtxView<'_> {}

impl HostInternalNonceKey for WasiWebcryptoCtxView<'_> {
    fn algorithm_name(&mut self, self_: Resource<InternalNonceKey>) -> Result<String> {
        Ok(self.table.get(&self_)?.material.name().to_string())
    }

    fn algorithm_length(&mut self, self_: Resource<InternalNonceKey>) -> Result<u32> {
        Ok(self.table.get(&self_)?.material.length_bits())
    }

    fn seals_remaining(&mut self, self_: Resource<InternalNonceKey>) -> Result<Option<u64>> {
        let key = self.table.get(&self_)?;
        Ok(key
            .material
            .nonce_budget()
            .map(|budget| budget.saturating_sub(key.sealed)))
    }
}

impl<T: Send> HostInternalNonceKeyWithStore<T> for WasiWebcrypto {
    async fn seal(
        accessor: &Accessor<T, Self>,
        self_: Resource<InternalNonceKey>,
        aad: Vec<u8>,
        plaintext: StreamReader<u8>,
    ) -> Result<std::result::Result<StreamReader<u8>, Error>> {
        let (reservation, cap) = admit_input(accessor).await?;
        // Per the WIT contract, the input stream is fully drained even when
        // the call resolves with an error, so the caller's writer always
        // completes.
        let msg = match drain_stream(accessor, plaintext, cap).await? {
            Ok(msg) => msg,
            Err(err) => return Ok(Err(err)),
        };
        let sealed = accessor.with(|mut access| {
            let key = access.get().table.get_mut(&self_)?;
            // Count this invocation against the algorithm's nonce budget
            // before drawing the nonce, per the minting interfaces'
            // SHOULD-enforce contract.
            match key.material.nonce_budget() {
                Some(budget) if key.sealed >= budget => {
                    return Ok(Err(Error::KeyExhausted));
                }
                _ => key.sealed += 1,
            }
            key.material
                .seal_internal(&aad, &msg)
                .map_err(rng_trap("nonce generation"))
                .map(|sealed| sealed.map_err(Error::from))
        })?;
        let sealed = match sealed {
            Ok(sealed) => sealed,
            Err(err) => return Ok(Err(err)),
        };
        let reader = accessor
            .with(|access| StreamReader::new(access, GuardedOutput::new(sealed, reservation)))?;
        Ok(Ok(reader))
    }

    async fn open(
        accessor: &Accessor<T, Self>,
        self_: Resource<InternalNonceKey>,
        aad: Vec<u8>,
        sealed: StreamReader<u8>,
    ) -> Result<std::result::Result<StreamReader<u8>, Error>> {
        let (reservation, cap) = admit_input(accessor).await?;
        // Per the WIT contract, the input stream is fully drained even when
        // the call resolves with an error, and buffering the whole message
        // is inherent to `open`: no unverified plaintext may be observable.
        let msg = match drain_stream(accessor, sealed, cap).await? {
            Ok(msg) => msg,
            Err(err) => return Ok(Err(err)),
        };
        let opened = accessor.with(|mut access| {
            let key = access.get().table.get(&self_)?;
            Ok::<_, wasmtime::Error>(key.material.open_internal(&aad, &msg))
        })?;
        let opened = match opened {
            Ok(opened) => opened,
            Err(err) => return Ok(Err(err.into())),
        };
        let reader = accessor
            .with(|access| StreamReader::new(access, GuardedOutput::new(opened, reservation)))?;
        Ok(Ok(reader))
    }

    async fn export_key(
        accessor: &Accessor<T, Self>,
        self_: Resource<InternalNonceKey>,
    ) -> Result<std::result::Result<Vec<u8>, Error>> {
        accessor.with(|mut access| {
            let key = access.get().table.get(&self_)?;
            Ok(key.material.export().map_err(Error::from))
        })
    }

    async fn drop(accessor: &Accessor<T, Self>, rep: Resource<InternalNonceKey>) -> Result<()> {
        accessor.with(|mut access| {
            access.get().table.delete(rep)?;
            Ok(())
        })
    }
}

// --- aes-gcm-internal-nonce (key minting) ----------------------------------------

impl aes_gcm_in_iface::Host for WasiWebcryptoCtxView<'_> {}

impl<T: Send> aes_gcm_in_iface::HostWithStore<T> for WasiWebcrypto {
    async fn import_key(
        accessor: &Accessor<T, Self>,
        variant: aes_gcm_iface::AesVariant,
        raw: Vec<u8>,
        extractable: bool,
    ) -> Result<std::result::Result<Resource<InternalNonceKey>, Error>> {
        let material =
            match AeadKeyMaterial::import_aes_gcm(core_aes_variant(variant), raw, extractable) {
                Ok(material) => material,
                Err(err) => return Ok(Err(err.into())),
            };
        accessor.with(|mut access| {
            Ok(Ok(access.get().table.push(InternalNonceKey {
                material,
                sealed: 0,
            })?))
        })
    }

    async fn generate_key(
        accessor: &Accessor<T, Self>,
        variant: aes_gcm_iface::AesVariant,
        extractable: bool,
    ) -> Result<std::result::Result<Resource<InternalNonceKey>, Error>> {
        let material =
            match AeadKeyMaterial::generate_aes_gcm(core_aes_variant(variant), extractable)
                .map_err(rng_trap("random key generation"))?
            {
                Ok(material) => material,
                Err(err) => return Ok(Err(err.into())),
            };
        accessor.with(|mut access| {
            Ok(Ok(access.get().table.push(InternalNonceKey {
                material,
                sealed: 0,
            })?))
        })
    }
}

// --- xchacha20-poly1305-internal-nonce (key minting) ------------------------------

impl xchacha_in_iface::Host for WasiWebcryptoCtxView<'_> {}

impl<T: Send> xchacha_in_iface::HostWithStore<T> for WasiWebcrypto {
    async fn import_key(
        accessor: &Accessor<T, Self>,
        raw: Vec<u8>,
        extractable: bool,
    ) -> Result<std::result::Result<Resource<InternalNonceKey>, Error>> {
        let material = match AeadKeyMaterial::import_xchacha20_poly1305(raw, extractable) {
            Ok(material) => material,
            Err(err) => return Ok(Err(err.into())),
        };
        accessor.with(|mut access| {
            Ok(Ok(access.get().table.push(InternalNonceKey {
                material,
                sealed: 0,
            })?))
        })
    }

    async fn generate_key(
        accessor: &Accessor<T, Self>,
        extractable: bool,
    ) -> Result<std::result::Result<Resource<InternalNonceKey>, Error>> {
        let material = AeadKeyMaterial::generate_xchacha20_poly1305(extractable)
            .map_err(rng_trap("random key generation"))?;
        accessor.with(|mut access| {
            Ok(Ok(access.get().table.push(InternalNonceKey {
                material,
                sealed: 0,
            })?))
        })
    }
}

// --- signature -----------------------------------------------------------------

impl signature_iface::Host for WasiWebcryptoCtxView<'_> {}

impl signature_iface::HostVerifyingKey for WasiWebcryptoCtxView<'_> {
    fn algorithm_name(&mut self, self_: Resource<VerifyingKey>) -> Result<String> {
        Ok(self.table.get(&self_)?.public.name().to_string())
    }

    fn algorithm_curve(&mut self, self_: Resource<VerifyingKey>) -> Result<Option<String>> {
        Ok(self.table.get(&self_)?.public.curve().map(str::to_string))
    }

    fn algorithm_hash(&mut self, self_: Resource<VerifyingKey>) -> Result<Option<String>> {
        Ok(self.table.get(&self_)?.public.hash().map(str::to_string))
    }
}

impl<T: Send> signature_iface::HostVerifyingKeyWithStore<T> for WasiWebcrypto {
    async fn verify(
        accessor: &Accessor<T, Self>,
        self_: Resource<VerifyingKey>,
        data: StreamReader<u8>,
        sig: Vec<u8>,
    ) -> Result<std::result::Result<(), Error>> {
        let (_reservation, cap) = admit_input(accessor).await?;
        let bytes = match drain_stream(accessor, data, cap).await? {
            Ok(bytes) => bytes,
            Err(err) => return Ok(Err(err)),
        };
        accessor.with(|mut access| {
            let key = access.get().table.get(&self_)?;
            Ok(key.public.verify(&bytes, &sig).map_err(Error::from))
        })
    }

    async fn export_key(
        accessor: &Accessor<T, Self>,
        self_: Resource<VerifyingKey>,
    ) -> Result<Vec<u8>> {
        accessor.with(|mut access| {
            let key = access.get().table.get(&self_)?;
            Ok(key.public.export())
        })
    }

    async fn drop(accessor: &Accessor<T, Self>, rep: Resource<VerifyingKey>) -> Result<()> {
        accessor.with(|mut access| {
            access.get().table.delete(rep)?;
            Ok(())
        })
    }
}

impl signature_iface::HostSigningKey for WasiWebcryptoCtxView<'_> {
    fn algorithm_name(&mut self, self_: Resource<SigningKey>) -> Result<String> {
        Ok(self.table.get(&self_)?.material.name().to_string())
    }

    fn algorithm_curve(&mut self, self_: Resource<SigningKey>) -> Result<Option<String>> {
        Ok(self.table.get(&self_)?.material.curve().map(str::to_string))
    }

    fn algorithm_hash(&mut self, self_: Resource<SigningKey>) -> Result<Option<String>> {
        Ok(self.table.get(&self_)?.material.hash().map(str::to_string))
    }

    fn extractable(&mut self, self_: Resource<SigningKey>) -> Result<bool> {
        Ok(self.table.get(&self_)?.material.extractable())
    }
}

impl<T: Send> signature_iface::HostSigningKeyWithStore<T> for WasiWebcrypto {
    async fn sign(
        accessor: &Accessor<T, Self>,
        self_: Resource<SigningKey>,
        data: StreamReader<u8>,
    ) -> Result<std::result::Result<Vec<u8>, Error>> {
        let (_reservation, cap) = admit_input(accessor).await?;
        let bytes = match drain_stream(accessor, data, cap).await? {
            Ok(bytes) => bytes,
            Err(err) => return Ok(Err(err)),
        };
        // The WIT `err` case exists for operational keystore failures; this
        // implementation holds the material in-process, so it never errs.
        accessor.with(|mut access| {
            let key = access.get().table.get(&self_)?;
            Ok(Ok(key.material.sign(&bytes)))
        })
    }

    async fn export_key(
        accessor: &Accessor<T, Self>,
        self_: Resource<SigningKey>,
    ) -> Result<std::result::Result<Vec<u8>, Error>> {
        accessor.with(|mut access| {
            let key = access.get().table.get(&self_)?;
            Ok(key.material.export().map_err(Error::from))
        })
    }

    async fn drop(accessor: &Accessor<T, Self>, rep: Resource<SigningKey>) -> Result<()> {
        accessor.with(|mut access| {
            access.get().table.delete(rep)?;
            Ok(())
        })
    }
}

// --- ed25519 (key minting) -----------------------------------------------------

impl ed25519_verify_iface::Host for WasiWebcryptoCtxView<'_> {}
impl ed25519_sign_iface::Host for WasiWebcryptoCtxView<'_> {}

impl<T: Send> ed25519_verify_iface::HostWithStore<T> for WasiWebcrypto {
    async fn import_verifying_key(
        accessor: &Accessor<T, Self>,
        raw: Vec<u8>,
    ) -> Result<std::result::Result<Resource<VerifyingKey>, Error>> {
        let public = match SigPublic::import_ed25519(&raw) {
            Ok(public) => public,
            Err(err) => return Ok(Err(err.into())),
        };
        accessor.with(|mut access| Ok(Ok(access.get().table.push(VerifyingKey { public })?)))
    }
}

impl<T: Send> ed25519_sign_iface::HostWithStore<T> for WasiWebcrypto {
    async fn import_signing_key(
        accessor: &Accessor<T, Self>,
        raw: Vec<u8>,
        extractable: bool,
    ) -> Result<std::result::Result<Resource<SigningKey>, Error>> {
        let material = match SigningKeyMaterial::import_ed25519_seed(&raw, extractable) {
            Ok(material) => material,
            Err(err) => return Ok(Err(err.into())),
        };
        accessor.with(|mut access| Ok(Ok(access.get().table.push(SigningKey { material })?)))
    }

    async fn generate_key(
        accessor: &Accessor<T, Self>,
        extractable: bool,
    ) -> Result<std::result::Result<(Resource<SigningKey>, Resource<VerifyingKey>), Error>> {
        let material = SigningKeyMaterial::generate_ed25519(extractable)
            .map_err(rng_trap("random key generation"))?;
        let public = material.public();
        accessor.with(|mut access| {
            let table = access.get().table;
            let signing = table.push(SigningKey { material })?;
            let verifying = table.push(VerifyingKey { public })?;
            Ok(Ok((signing, verifying)))
        })
    }
}

// --- ecdsa (key minting) ---------------------------------------------------------

impl ecdsa_verify_iface::Host for WasiWebcryptoCtxView<'_> {}
impl ecdsa_sign_iface::Host for WasiWebcryptoCtxView<'_> {}

impl<T: Send> ecdsa_verify_iface::HostWithStore<T> for WasiWebcrypto {
    async fn import_verifying_key(
        accessor: &Accessor<T, Self>,
        variant: ecdsa_verify_iface::EcdsaVariant,
        raw: Vec<u8>,
    ) -> Result<std::result::Result<Resource<VerifyingKey>, Error>> {
        let public = match SigPublic::import_ecdsa(core_ecdsa_variant(variant), &raw) {
            Ok(public) => public,
            Err(err) => return Ok(Err(err.into())),
        };
        accessor.with(|mut access| Ok(Ok(access.get().table.push(VerifyingKey { public })?)))
    }
}

impl<T: Send> ecdsa_sign_iface::HostWithStore<T> for WasiWebcrypto {
    async fn import_signing_key(
        accessor: &Accessor<T, Self>,
        variant: ecdsa_verify_iface::EcdsaVariant,
        raw: Vec<u8>,
        extractable: bool,
    ) -> Result<std::result::Result<Resource<SigningKey>, Error>> {
        let material = match SigningKeyMaterial::import_ecdsa_scalar(
            core_ecdsa_variant(variant),
            &raw,
            extractable,
        ) {
            Ok(material) => material,
            Err(err) => return Ok(Err(err.into())),
        };
        accessor.with(|mut access| Ok(Ok(access.get().table.push(SigningKey { material })?)))
    }

    async fn generate_key(
        accessor: &Accessor<T, Self>,
        variant: ecdsa_verify_iface::EcdsaVariant,
        extractable: bool,
    ) -> Result<std::result::Result<(Resource<SigningKey>, Resource<VerifyingKey>), Error>> {
        let material = SigningKeyMaterial::generate_ecdsa(core_ecdsa_variant(variant), extractable)
            .map_err(rng_trap("random key generation"))?;
        let public = material.public();
        accessor.with(|mut access| {
            let table = access.get().table;
            let signing = table.push(SigningKey { material })?;
            let verifying = table.push(VerifyingKey { public })?;
            Ok(Ok((signing, verifying)))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::ByteCollector;
    use crate::MacKey;
    use futures::channel::oneshot;
    use webcrypto_impl_core::{MacKeyMaterial, Sha2Variant};

    /// `Debug` on key-holding types never prints key material: the bytes
    /// are redacted (in the shared core's material types, which these
    /// resource types derive through), so a key reaching a log line cannot
    /// leak.
    #[test]
    fn debug_redacts_key_material() {
        let key = MacKey {
            material: MacKeyMaterial::import(Sha2Variant::Sha256, vec![0xAB; 32], true).unwrap(),
        };
        let rendered = format!("{key:?}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(!rendered.contains("171"), "{rendered}"); // 0xAB
        assert!(!rendered.to_lowercase().contains("ab, ab"), "{rendered}");
    }

    /// Dropping the collector (Wasmtime's end-of-stream notification)
    /// delivers the collected buffer.
    #[test]
    fn byte_collector_drop_delivers_buffer() {
        let (done_tx, mut done_rx) = oneshot::channel();
        drop(ByteCollector {
            buf: b"collected".to_vec(),
            cap: usize::MAX,
            overflowed: false,
            failed: false,
            done_tx: Some(done_tx),
        });
        assert_eq!(done_rx.try_recv(), Ok(Some(Ok(b"collected".to_vec()))));
    }

    /// An over-cap collector delivers the overflow marker, not the (already
    /// discarded) buffer.
    #[test]
    fn byte_collector_overflow_delivers_marker() {
        let (done_tx, mut done_rx) = oneshot::channel();
        drop(ByteCollector {
            buf: Vec::new(),
            cap: 4,
            overflowed: true,
            failed: false,
            done_tx: Some(done_tx),
        });
        assert_eq!(done_rx.try_recv(), Ok(Some(Err(super::InputOverflow))));
    }

    /// After a pipe error, dropping the collector must NOT deliver the
    /// partial buffer as if it were the complete input: the channel closes
    /// unsent, which `drain_stream` maps to an error.
    #[test]
    fn byte_collector_drop_after_failure_delivers_nothing() {
        let (done_tx, mut done_rx) =
            oneshot::channel::<std::result::Result<Vec<u8>, super::InputOverflow>>();
        drop(ByteCollector {
            buf: b"partial".to_vec(),
            cap: usize::MAX,
            overflowed: false,
            failed: true,
            done_tx: Some(done_tx),
        });
        assert!(done_rx.try_recv().is_err());
    }
}
