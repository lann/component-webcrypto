//! Host trait implementations for the `lann:webcrypto` imports.
//!
//! Following the split the generated bindings produce (and mirroring
//! `wasmtime_wasi_http::p3`), the store-free traits are implemented for the
//! [`WasiWebcryptoCtxView`] "data" type, while the traits whose methods need
//! the async `Accessor` are implemented for the [`WasiWebcrypto`] `HasData`
//! marker.

use std::pin::Pin;
use std::task::{Context, Poll};

use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use futures::channel::oneshot;
use wasmtime::component::{Accessor, Resource, Source, StreamConsumer, StreamReader, StreamResult};
use wasmtime::{Result, StoreContextMut};

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
use crate::{
    AeadKey, Digest, InternalNonceKey, MacKey, SigningKey, VerifyingKey, WasiWebcrypto,
    WasiWebcryptoCtxView, AES_GCM_NAME, CHACHA20_POLY1305_NAME, ECDSA_NAME, ED25519_NAME,
    HMAC_NAME, XCHACHA20_POLY1305_NAME,
};

// --- types -------------------------------------------------------------------

impl types::Host for WasiWebcryptoCtxView<'_> {}

// --- bytes ---------------------------------------------------------------------

impl bytes_iface::Host for WasiWebcryptoCtxView<'_> {
    fn constant_time_equal(&mut self, a: Vec<u8>, b: Vec<u8>) -> Result<bool> {
        use subtle::ConstantTimeEq as _;
        // `ct_eq` on slices short-circuits only on length (which is not
        // secret); the contents are compared in constant time.
        Ok(a.ct_eq(&b).into())
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
    failed: bool,
    done_tx: Option<oneshot::Sender<Vec<u8>>>,
}

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
            let mut chunk = Vec::with_capacity(available);
            if let Err(err) = source.read(&mut store, &mut chunk) {
                // Never let `Drop` deliver a partial buffer as if it were
                // the complete input.
                this.failed = true;
                return Poll::Ready(Err(err));
            }
            this.buf.extend_from_slice(&chunk);
            return Poll::Ready(Ok(StreamResult::Completed));
        }

        // No bytes available. When `finish` is set the writer cancelled its
        // pending write; the stream itself remains open, so keep the buffer
        // and keep collecting — `Drop` is the completion point.
        if finish {
            Poll::Ready(Ok(StreamResult::Cancelled))
        } else {
            Poll::Pending
        }
    }
}

impl Drop for ByteCollector {
    fn drop(&mut self) {
        if !self.failed {
            if let Some(tx) = self.done_tx.take() {
                let _ = tx.send(std::mem::take(&mut self.buf));
            }
        }
    }
}

/// Drain an entire `stream<u8>` into a buffer, resolving once the stream ends
/// (its writer dropped). Fails if the consumer was torn down without
/// delivering the complete input (a host-side pipe error).
async fn drain_stream<T: Send>(
    accessor: &Accessor<T, WasiWebcrypto>,
    data: StreamReader<u8>,
) -> Result<Vec<u8>> {
    let (done_tx, done_rx) = oneshot::channel();
    accessor.with(|access| {
        data.pipe(
            access,
            ByteCollector {
                buf: Vec::new(),
                failed: false,
                done_tx: Some(done_tx),
            },
        )
    })?;
    done_rx
        .await
        .map_err(|_| wasmtime::Error::msg("input stream ended without completing"))
}

// --- mac ---------------------------------------------------------------------

impl mac::Host for WasiWebcryptoCtxView<'_> {}

/// The served SHA-2 variants an HMAC [`MacKey`] can be bound to. Only the
/// WIT `sha2-variant` cases this implementation serves appear here: the
/// truncated variants are declined at minting (see the WIT `sha2-variant`
/// doc).
#[derive(Clone, Copy)]
pub(crate) enum Sha2 {
    Sha256,
    Sha384,
    Sha512,
}

impl Sha2 {
    /// The hash name (WebCrypto's `HmacKeyAlgorithm.hash`).
    fn hash_name(self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
        }
    }

    /// The underlying hash's block length in bytes (the length of a
    /// generated key, per WebCrypto's `generateKey` default).
    fn block_len(self) -> usize {
        match self {
            Self::Sha256 => 64,
            Self::Sha384 | Self::Sha512 => 128,
        }
    }

    /// One-shot digest of `data`.
    fn digest(self, data: &[u8]) -> Vec<u8> {
        fn hash<D: sha2::Digest>(data: &[u8]) -> Vec<u8> {
            D::digest(data).to_vec()
        }
        match self {
            Self::Sha256 => hash::<sha2::Sha256>(data),
            Self::Sha384 => hash::<sha2::Sha384>(data),
            Self::Sha512 => hash::<sha2::Sha512>(data),
        }
    }

    /// One-shot HMAC over `data` with `key` material.
    fn sign(self, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        fn tag<M: hmac::Mac + hmac::digest::KeyInit>(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
            // HMAC accepts key material of any length, so this cannot fail
            // for a key that was accepted at import/generation time.
            let mut hmac = <M as hmac::Mac>::new_from_slice(key)
                .map_err(|err| wasmtime::Error::msg(format!("HMAC key setup failed: {err}")))?;
            hmac.update(data);
            Ok(hmac.finalize().into_bytes().to_vec())
        }
        match self {
            Self::Sha256 => tag::<hmac::Hmac<sha2::Sha256>>(key, data),
            Self::Sha384 => tag::<hmac::Hmac<sha2::Sha384>>(key, data),
            Self::Sha512 => tag::<hmac::Hmac<sha2::Sha512>>(key, data),
        }
    }

    /// One-shot constant-time HMAC verification of `tag` over `data`.
    fn verify(self, key: &[u8], data: &[u8], tag: &[u8]) -> Result<std::result::Result<(), Error>> {
        fn check<M: hmac::Mac + hmac::digest::KeyInit>(
            key: &[u8],
            data: &[u8],
            tag: &[u8],
        ) -> Result<std::result::Result<(), Error>> {
            let mut hmac = <M as hmac::Mac>::new_from_slice(key)
                .map_err(|err| wasmtime::Error::msg(format!("HMAC key setup failed: {err}")))?;
            hmac.update(data);
            // `verify_slice` compares in constant time, per the WIT contract.
            Ok(hmac
                .verify_slice(tag)
                .map_err(|_| Error::AuthenticationFailed))
        }
        match self {
            Self::Sha256 => check::<hmac::Hmac<sha2::Sha256>>(key, data, tag),
            Self::Sha384 => check::<hmac::Hmac<sha2::Sha384>>(key, data, tag),
            Self::Sha512 => check::<hmac::Hmac<sha2::Sha512>>(key, data, tag),
        }
    }
}

impl HostMacKey for WasiWebcryptoCtxView<'_> {
    fn algorithm_name(&mut self, self_: Resource<MacKey>) -> Result<String> {
        self.table.get(&self_)?;
        Ok(HMAC_NAME.to_string())
    }

    fn algorithm_hash(&mut self, self_: Resource<MacKey>) -> Result<Option<String>> {
        Ok(Some(
            self.table.get(&self_)?.variant.hash_name().to_string(),
        ))
    }

    fn algorithm_length(&mut self, self_: Resource<MacKey>) -> Result<u32> {
        Ok(self.table.get(&self_)?.raw.len() as u32 * 8)
    }
}

impl<T: Send> HostMacKeyWithStore<T> for WasiWebcrypto {
    async fn sign(
        accessor: &Accessor<T, Self>,
        self_: Resource<MacKey>,
        data: StreamReader<u8>,
    ) -> Result<std::result::Result<Vec<u8>, Error>> {
        let (variant, raw) = accessor.with(|mut access| {
            let key = access.get().table.get(&self_)?;
            Ok::<_, wasmtime::Error>((key.variant, key.raw.clone()))
        })?;
        // Buffer the whole stream, then fold it into the HMAC state; the
        // result is chunking-invariant either way.
        //
        // The WIT `err` case exists for operational keystore failures; this
        // implementation holds the material in-process, so it never errs.
        let bytes = drain_stream(accessor, data).await?;
        Ok(Ok(variant.sign(&raw, &bytes)?))
    }

    async fn verify(
        accessor: &Accessor<T, Self>,
        self_: Resource<MacKey>,
        data: StreamReader<u8>,
        tag: Vec<u8>,
    ) -> Result<std::result::Result<(), Error>> {
        let (variant, raw) = accessor.with(|mut access| {
            let key = access.get().table.get(&self_)?;
            Ok::<_, wasmtime::Error>((key.variant, key.raw.clone()))
        })?;
        let bytes = drain_stream(accessor, data).await?;
        variant.verify(&raw, &bytes, &tag)
    }

    async fn export_key(
        accessor: &Accessor<T, Self>,
        self_: Resource<MacKey>,
    ) -> Result<std::result::Result<Vec<u8>, Error>> {
        accessor.with(|mut access| {
            let view = access.get();
            let key = view.table.get(&self_)?;
            Ok(if key.extractable {
                Ok(key.raw.clone())
            } else {
                Err(Error::NotExtractable)
            })
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

/// The cipher backing an [`AeadKey`], bound to its algorithm at minting.
/// Only the WIT variant cases this implementation serves appear here:
/// AES-192 is declined at minting (see the WIT `aes-variant` doc).
#[derive(Clone)]
// Each AES variant is an expanded key schedule; the size skew between the
// AES-128 and AES-256 schedules is inherent and both live briefly per call.
#[allow(clippy::large_enum_variant)]
pub(crate) enum AeadCipher {
    Aes128Gcm(Aes128Gcm),
    Aes256Gcm(Aes256Gcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
    XChaCha20Poly1305(XChaCha20Poly1305),
}

impl AeadCipher {
    /// The algorithm name reported by `aead-key.algorithm-name`.
    fn name(&self) -> &'static str {
        match self {
            Self::Aes128Gcm(_) | Self::Aes256Gcm(_) => AES_GCM_NAME,
            Self::ChaCha20Poly1305(_) => CHACHA20_POLY1305_NAME,
            Self::XChaCha20Poly1305(_) => XCHACHA20_POLY1305_NAME,
        }
    }

    /// The key length in bits (WebCrypto's `AesKeyAlgorithm.length`).
    fn length_bits(&self) -> u32 {
        match self {
            Self::Aes128Gcm(_) => 128,
            Self::Aes256Gcm(_) | Self::ChaCha20Poly1305(_) | Self::XChaCha20Poly1305(_) => 256,
        }
    }

    /// The nonce length this cipher's algorithm specifies.
    fn nonce_len(&self) -> usize {
        match self {
            Self::XChaCha20Poly1305(_) => 24,
            _ => 12,
        }
    }

    /// The tag length every algorithm this implementation serves trails
    /// its ciphertext with.
    fn tag_len(&self) -> usize {
        16
    }

    /// The internal-nonce seal budget for this cipher's algorithm: the WIT
    /// contract's 2^32-invocation bound for 12-byte-nonce algorithms (SP
    /// 800-38D SS8.2.2's repeat-probability bound); `none` for 24-byte
    /// nonces, whose repeat probability is negligible at any realistic
    /// count.
    fn nonce_budget(&self) -> Option<u64> {
        match self.nonce_len() {
            12 => Some(1 << 32),
            _ => None,
        }
    }

    /// Validate a nonce's length, rendering the WIT `invalid-nonce` error
    /// for anything but the algorithm's nonce length.
    fn check_nonce(&self, nonce: &[u8]) -> std::result::Result<(), Error> {
        if nonce.len() == self.nonce_len() {
            Ok(())
        } else {
            Err(Error::InvalidNonce(format!(
                "{} requires a {}-byte nonce, got {} bytes",
                self.name(),
                self.nonce_len(),
                nonce.len()
            )))
        }
    }

    fn encrypt(&self, nonce: &[u8], payload: Payload<'_, '_>) -> aes_gcm::aead::Result<Vec<u8>> {
        match self {
            Self::Aes128Gcm(c) => c.encrypt(aes_gcm::Nonce::from_slice(nonce), payload),
            Self::Aes256Gcm(c) => c.encrypt(aes_gcm::Nonce::from_slice(nonce), payload),
            Self::ChaCha20Poly1305(c) => {
                c.encrypt(chacha20poly1305::Nonce::from_slice(nonce), payload)
            }
            Self::XChaCha20Poly1305(c) => {
                c.encrypt(chacha20poly1305::XNonce::from_slice(nonce), payload)
            }
        }
    }

    fn decrypt(&self, nonce: &[u8], payload: Payload<'_, '_>) -> aes_gcm::aead::Result<Vec<u8>> {
        match self {
            Self::Aes128Gcm(c) => c.decrypt(aes_gcm::Nonce::from_slice(nonce), payload),
            Self::Aes256Gcm(c) => c.decrypt(aes_gcm::Nonce::from_slice(nonce), payload),
            Self::ChaCha20Poly1305(c) => {
                c.decrypt(chacha20poly1305::Nonce::from_slice(nonce), payload)
            }
            Self::XChaCha20Poly1305(c) => {
                c.decrypt(chacha20poly1305::XNonce::from_slice(nonce), payload)
            }
        }
    }
}

impl HostAeadKey for WasiWebcryptoCtxView<'_> {
    fn algorithm_name(&mut self, self_: Resource<AeadKey>) -> Result<String> {
        Ok(self.table.get(&self_)?.cipher.name().to_string())
    }

    fn algorithm_length(&mut self, self_: Resource<AeadKey>) -> Result<u32> {
        Ok(self.table.get(&self_)?.cipher.length_bits())
    }

    fn nonce_size(&mut self, self_: Resource<AeadKey>) -> Result<u32> {
        Ok(self.table.get(&self_)?.cipher.nonce_len() as u32)
    }

    fn tag_size(&mut self, self_: Resource<AeadKey>) -> Result<u32> {
        Ok(self.table.get(&self_)?.cipher.tag_len() as u32)
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
        let cipher = accessor.with(|mut access| {
            Ok::<_, wasmtime::Error>(access.get().table.get(&self_)?.cipher.clone())
        })?;
        // Per the WIT contract, the input stream is fully drained even when
        // the call resolves with an error, so the caller's writer always
        // completes.
        let msg = drain_stream(accessor, plaintext).await?;
        if let Err(err) = cipher.check_nonce(&nonce) {
            return Ok(Err(err));
        }
        let sealed = match cipher.encrypt(
            &nonce,
            Payload {
                msg: &msg,
                aad: &aad,
            },
        ) {
            Ok(sealed) => sealed,
            Err(_) => {
                return Ok(Err(Error::Other(format!(
                    "{} encryption failed",
                    cipher.name()
                ))))
            }
        };
        let reader = accessor.with(|access| StreamReader::new(access, sealed))?;
        Ok(Ok(reader))
    }

    async fn open(
        accessor: &Accessor<T, Self>,
        self_: Resource<AeadKey>,
        nonce: Vec<u8>,
        aad: Vec<u8>,
        ciphertext: StreamReader<u8>,
    ) -> Result<std::result::Result<StreamReader<u8>, Error>> {
        let cipher = accessor.with(|mut access| {
            Ok::<_, wasmtime::Error>(access.get().table.get(&self_)?.cipher.clone())
        })?;
        // Per the WIT contract, the input stream is fully drained even when
        // the call resolves with an error, so the caller's writer always
        // completes. Buffering the whole message is inherent to `open`: no
        // unverified plaintext may be observable.
        let msg = drain_stream(accessor, ciphertext).await?;
        if let Err(err) = cipher.check_nonce(&nonce) {
            return Ok(Err(err));
        }
        // Any decryption failure — truncated input, bad tag, wrong key,
        // wrong associated data — reports `authentication-failed` with no
        // detail, per the WIT contract.
        let opened = match cipher.decrypt(
            &nonce,
            Payload {
                msg: &msg,
                aad: &aad,
            },
        ) {
            Ok(opened) => opened,
            Err(_) => return Ok(Err(Error::AuthenticationFailed)),
        };
        let reader = accessor.with(|access| StreamReader::new(access, opened))?;
        Ok(Ok(reader))
    }

    async fn export_key(
        accessor: &Accessor<T, Self>,
        self_: Resource<AeadKey>,
    ) -> Result<std::result::Result<Vec<u8>, Error>> {
        accessor.with(|mut access| {
            let view = access.get();
            let key = view.table.get(&self_)?;
            Ok(if key.extractable {
                Ok(key.raw.clone())
            } else {
                Err(Error::NotExtractable)
            })
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
    ) -> Result<Vec<u8>> {
        let variant = accessor
            .with(|mut access| Ok::<_, wasmtime::Error>(access.get().table.get(&self_)?.variant))?;
        // Buffer the whole stream, then hash it; the result is
        // chunking-invariant either way.
        let bytes = drain_stream(accessor, data).await?;
        Ok(variant.digest(&bytes))
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
        let variant = match served_sha2(variant) {
            Ok(variant) => variant,
            Err(err) => return Ok(Err(err)),
        };
        Ok(Ok(self.table.push(Digest { variant })?))
    }
}

// --- hmac-sha2 (key minting) -----------------------------------------------------

impl hmac_sha2_iface::Host for WasiWebcryptoCtxView<'_> {}

/// The served [`Sha2`] for a WIT `sha2-variant`, or `unsupported` for one
/// this implementation declines (the truncated variants; see the WIT
/// `sha2-variant` doc). Shared by the `sha2` and `hmac-sha2` minting paths.
fn served_sha2(variant: sha2_iface::Sha2Variant) -> std::result::Result<Sha2, Error> {
    use sha2_iface::Sha2Variant;
    match variant {
        Sha2Variant::Sha256 => Ok(Sha2::Sha256),
        Sha2Variant::Sha384 => Ok(Sha2::Sha384),
        Sha2Variant::Sha512 => Ok(Sha2::Sha512),
        Sha2Variant::Sha224 | Sha2Variant::Sha512224 | Sha2Variant::Sha512256 => Err(
            Error::Unsupported(format!("{variant:?} is not served by this implementation")),
        ),
    }
}

impl<T: Send> hmac_sha2_iface::HostWithStore<T> for WasiWebcrypto {
    async fn import_key(
        accessor: &Accessor<T, Self>,
        variant: hmac_sha2_iface::Sha2Variant,
        raw: Vec<u8>,
        extractable: bool,
    ) -> Result<std::result::Result<Resource<MacKey>, Error>> {
        let variant = match served_sha2(variant) {
            Ok(variant) => variant,
            Err(err) => return Ok(Err(err)),
        };
        // RFC 2104 accepts any non-empty key length (longer-than-block keys
        // are hashed first); an empty key is rejected as `invalid-key`.
        if raw.is_empty() {
            return Ok(Err(Error::InvalidKey(
                "HMAC key material must be non-empty".into(),
            )));
        }
        let key = MacKey {
            raw,
            variant,
            extractable,
        };
        accessor.with(|mut access| Ok(Ok(access.get().table.push(key)?)))
    }

    async fn generate_key(
        accessor: &Accessor<T, Self>,
        variant: hmac_sha2_iface::Sha2Variant,
        extractable: bool,
    ) -> Result<std::result::Result<Resource<MacKey>, Error>> {
        let variant = match served_sha2(variant) {
            Ok(variant) => variant,
            Err(err) => return Ok(Err(err)),
        };
        let mut raw = vec![0u8; variant.block_len()];
        getrandom::fill(&mut raw)
            .map_err(|err| wasmtime::Error::msg(format!("random key generation failed: {err}")))?;
        let key = MacKey {
            raw,
            variant,
            extractable,
        };
        accessor.with(|mut access| Ok(Ok(access.get().table.push(key)?)))
    }
}

// --- aes-gcm (key minting) -------------------------------------------------------

impl aes_gcm_iface::Host for WasiWebcryptoCtxView<'_> {}

/// Build an [`AeadKey`] from raw material declared as `variant`, rendering
/// the WIT `invalid-key` error when the material's length disagrees with
/// the declared variant, or `unsupported` for a variant this implementation
/// does not serve (AES-192; see the WIT `aes-variant` doc).
fn new_aes_gcm_key(
    variant: aes_gcm_iface::AesVariant,
    raw: Vec<u8>,
    extractable: bool,
) -> std::result::Result<AeadKey, Error> {
    use aes_gcm_iface::AesVariant;
    let expected = match variant {
        AesVariant::Aes128 => 16,
        AesVariant::Aes192 => {
            return Err(Error::Unsupported(
                "AES-192 is not served by this implementation".into(),
            ))
        }
        AesVariant::Aes256 => 32,
    };
    if raw.len() != expected {
        return Err(Error::InvalidKey(format!(
            "{variant:?} requires {expected} bytes of key material, got {} bytes",
            raw.len()
        )));
    }
    let cipher = match variant {
        AesVariant::Aes128 => {
            AeadCipher::Aes128Gcm(Aes128Gcm::new_from_slice(&raw).expect("length checked"))
        }
        AesVariant::Aes192 => unreachable!("rejected above"),
        AesVariant::Aes256 => {
            AeadCipher::Aes256Gcm(Aes256Gcm::new_from_slice(&raw).expect("length checked"))
        }
    };
    Ok(AeadKey {
        cipher,
        raw,
        extractable,
    })
}

impl<T: Send> aes_gcm_iface::HostWithStore<T> for WasiWebcrypto {
    async fn import_key(
        accessor: &Accessor<T, Self>,
        variant: aes_gcm_iface::AesVariant,
        raw: Vec<u8>,
        extractable: bool,
    ) -> Result<std::result::Result<Resource<AeadKey>, Error>> {
        let key = match new_aes_gcm_key(variant, raw, extractable) {
            Ok(key) => key,
            Err(err) => return Ok(Err(err)),
        };
        accessor.with(|mut access| Ok(Ok(access.get().table.push(key)?)))
    }

    async fn generate_key(
        accessor: &Accessor<T, Self>,
        variant: aes_gcm_iface::AesVariant,
        extractable: bool,
    ) -> Result<std::result::Result<Resource<AeadKey>, Error>> {
        use aes_gcm_iface::AesVariant;
        let len = match variant {
            AesVariant::Aes128 => 16,
            AesVariant::Aes192 => {
                return Ok(Err(Error::Unsupported(
                    "AES-192 is not served by this implementation".into(),
                )))
            }
            AesVariant::Aes256 => 32,
        };
        let mut raw = vec![0u8; len];
        getrandom::fill(&mut raw)
            .map_err(|err| wasmtime::Error::msg(format!("random key generation failed: {err}")))?;
        let key = new_aes_gcm_key(variant, raw, extractable)
            .map_err(|_| wasmtime::Error::msg("generated key material was rejected"))?;
        accessor.with(|mut access| Ok(Ok(access.get().table.push(key)?)))
    }
}

// --- chacha20-poly1305 / xchacha20-poly1305 (key minting) ---------------------

impl chacha_iface::Host for WasiWebcryptoCtxView<'_> {}
impl xchacha_iface::Host for WasiWebcryptoCtxView<'_> {}

/// The length in bytes of a ChaCha20-Poly1305 key (either construction).
const CHACHA_KEY_LEN: usize = 32;

/// Validate ChaCha key material (32 bytes for either construction),
/// rendering the WIT `invalid-key` error otherwise.
fn check_chacha_key(name: &str, raw: &[u8]) -> std::result::Result<(), Error> {
    if raw.len() == CHACHA_KEY_LEN {
        Ok(())
    } else {
        Err(Error::InvalidKey(format!(
            "{name} requires {CHACHA_KEY_LEN} bytes of key material, got {} bytes",
            raw.len()
        )))
    }
}

/// Build an IETF ChaCha20-Poly1305 [`AeadKey`] from raw material.
fn new_chacha_key(raw: Vec<u8>, extractable: bool) -> std::result::Result<AeadKey, Error> {
    check_chacha_key(CHACHA20_POLY1305_NAME, &raw)?;
    let cipher = AeadCipher::ChaCha20Poly1305(
        ChaCha20Poly1305::new_from_slice(&raw).expect("length checked"),
    );
    Ok(AeadKey {
        cipher,
        raw,
        extractable,
    })
}

/// Build an XChaCha20-Poly1305 [`AeadKey`] from raw material.
fn new_xchacha_key(raw: Vec<u8>, extractable: bool) -> std::result::Result<AeadKey, Error> {
    check_chacha_key(XCHACHA20_POLY1305_NAME, &raw)?;
    let cipher = AeadCipher::XChaCha20Poly1305(
        XChaCha20Poly1305::new_from_slice(&raw).expect("length checked"),
    );
    Ok(AeadKey {
        cipher,
        raw,
        extractable,
    })
}

impl<T: Send> chacha_iface::HostWithStore<T> for WasiWebcrypto {
    async fn import_key(
        accessor: &Accessor<T, Self>,
        raw: Vec<u8>,
        extractable: bool,
    ) -> Result<std::result::Result<Resource<AeadKey>, Error>> {
        let key = match new_chacha_key(raw, extractable) {
            Ok(key) => key,
            Err(err) => return Ok(Err(err)),
        };
        accessor.with(|mut access| Ok(Ok(access.get().table.push(key)?)))
    }

    async fn generate_key(
        accessor: &Accessor<T, Self>,
        extractable: bool,
    ) -> Result<std::result::Result<Resource<AeadKey>, Error>> {
        let mut raw = vec![0u8; CHACHA_KEY_LEN];
        getrandom::fill(&mut raw)
            .map_err(|err| wasmtime::Error::msg(format!("random key generation failed: {err}")))?;
        let key = new_chacha_key(raw, extractable)
            .map_err(|_| wasmtime::Error::msg("generated key material was rejected"))?;
        accessor.with(|mut access| Ok(Ok(access.get().table.push(key)?)))
    }
}

impl<T: Send> xchacha_iface::HostWithStore<T> for WasiWebcrypto {
    async fn import_key(
        accessor: &Accessor<T, Self>,
        raw: Vec<u8>,
        extractable: bool,
    ) -> Result<std::result::Result<Resource<AeadKey>, Error>> {
        let key = match new_xchacha_key(raw, extractable) {
            Ok(key) => key,
            Err(err) => return Ok(Err(err)),
        };
        accessor.with(|mut access| Ok(Ok(access.get().table.push(key)?)))
    }

    async fn generate_key(
        accessor: &Accessor<T, Self>,
        extractable: bool,
    ) -> Result<std::result::Result<Resource<AeadKey>, Error>> {
        let mut raw = vec![0u8; CHACHA_KEY_LEN];
        getrandom::fill(&mut raw)
            .map_err(|err| wasmtime::Error::msg(format!("random key generation failed: {err}")))?;
        let key = new_xchacha_key(raw, extractable)
            .map_err(|_| wasmtime::Error::msg("generated key material was rejected"))?;
        accessor.with(|mut access| Ok(Ok(access.get().table.push(key)?)))
    }
}

// --- aead-internal-nonce -------------------------------------------------------

impl aead_internal_nonce::Host for WasiWebcryptoCtxView<'_> {}

impl HostInternalNonceKey for WasiWebcryptoCtxView<'_> {
    fn algorithm_name(&mut self, self_: Resource<InternalNonceKey>) -> Result<String> {
        Ok(self.table.get(&self_)?.cipher.name().to_string())
    }

    fn algorithm_length(&mut self, self_: Resource<InternalNonceKey>) -> Result<u32> {
        Ok(self.table.get(&self_)?.cipher.length_bits())
    }

    fn seals_remaining(&mut self, self_: Resource<InternalNonceKey>) -> Result<Option<u64>> {
        let key = self.table.get(&self_)?;
        Ok(key
            .cipher
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
        let cipher = accessor.with(|mut access| {
            Ok::<_, wasmtime::Error>(access.get().table.get(&self_)?.cipher.clone())
        })?;
        // Per the WIT contract, the input stream is fully drained even when
        // the call resolves with an error, so the caller's writer always
        // completes.
        let msg = drain_stream(accessor, plaintext).await?;
        // Count this invocation against the algorithm's nonce budget before
        // drawing the nonce, per the minting interfaces' SHOULD-enforce
        // contract.
        let exhausted = accessor.with(|mut access| {
            let key = access.get().table.get_mut(&self_)?;
            Ok::<_, wasmtime::Error>(match key.cipher.nonce_budget() {
                Some(budget) if key.sealed >= budget => true,
                _ => {
                    key.sealed += 1;
                    false
                }
            })
        })?;
        if exhausted {
            return Ok(Err(Error::KeyExhausted));
        }
        // The SP 800-38D SS8.2.2 RBG-based construction: a fresh random
        // nonce per seal, carried as the sealed message's prefix
        // (`nonce || ciphertext || tag`, per the minting interface docs).
        let mut sealed = vec![0u8; cipher.nonce_len()];
        getrandom::fill(&mut sealed)
            .map_err(|err| wasmtime::Error::msg(format!("nonce generation failed: {err}")))?;
        let body = match cipher.encrypt(
            &sealed,
            Payload {
                msg: &msg,
                aad: &aad,
            },
        ) {
            Ok(body) => body,
            Err(_) => {
                return Ok(Err(Error::Other(format!(
                    "{} encryption failed",
                    cipher.name()
                ))))
            }
        };
        sealed.extend(body);
        let reader = accessor.with(|access| StreamReader::new(access, sealed))?;
        Ok(Ok(reader))
    }

    async fn open(
        accessor: &Accessor<T, Self>,
        self_: Resource<InternalNonceKey>,
        aad: Vec<u8>,
        sealed: StreamReader<u8>,
    ) -> Result<std::result::Result<StreamReader<u8>, Error>> {
        let cipher = accessor.with(|mut access| {
            Ok::<_, wasmtime::Error>(access.get().table.get(&self_)?.cipher.clone())
        })?;
        // Per the WIT contract, the input stream is fully drained even when
        // the call resolves with an error, and buffering the whole message
        // is inherent to `open`: no unverified plaintext may be observable.
        let msg = drain_stream(accessor, sealed).await?;
        // Any failure -- input too short to carry the wire format, a bad
        // tag, wrong key, wrong associated data -- reports
        // `authentication-failed` with no detail, per the WIT contract.
        if msg.len() < cipher.nonce_len() {
            return Ok(Err(Error::AuthenticationFailed));
        }
        let (nonce, body) = msg.split_at(cipher.nonce_len());
        let opened = match cipher.decrypt(
            nonce,
            Payload {
                msg: body,
                aad: &aad,
            },
        ) {
            Ok(opened) => opened,
            Err(_) => return Ok(Err(Error::AuthenticationFailed)),
        };
        let reader = accessor.with(|access| StreamReader::new(access, opened))?;
        Ok(Ok(reader))
    }

    async fn export_key(
        accessor: &Accessor<T, Self>,
        self_: Resource<InternalNonceKey>,
    ) -> Result<std::result::Result<Vec<u8>, Error>> {
        accessor.with(|mut access| {
            let view = access.get();
            let key = view.table.get(&self_)?;
            Ok(if key.extractable {
                Ok(key.raw.clone())
            } else {
                Err(Error::NotExtractable)
            })
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

/// Wrap a caller-nonce [`AeadKey`] build as an [`InternalNonceKey`] (the
/// cipher and validation are identical; only the nonce discipline differs).
fn into_internal_nonce_key(key: AeadKey) -> InternalNonceKey {
    InternalNonceKey {
        cipher: key.cipher,
        raw: key.raw,
        extractable: key.extractable,
        sealed: 0,
    }
}

impl<T: Send> aes_gcm_in_iface::HostWithStore<T> for WasiWebcrypto {
    async fn import_key(
        accessor: &Accessor<T, Self>,
        variant: aes_gcm_iface::AesVariant,
        raw: Vec<u8>,
        extractable: bool,
    ) -> Result<std::result::Result<Resource<InternalNonceKey>, Error>> {
        let key = match new_aes_gcm_key(variant, raw, extractable) {
            Ok(key) => into_internal_nonce_key(key),
            Err(err) => return Ok(Err(err)),
        };
        accessor.with(|mut access| Ok(Ok(access.get().table.push(key)?)))
    }

    async fn generate_key(
        accessor: &Accessor<T, Self>,
        variant: aes_gcm_iface::AesVariant,
        extractable: bool,
    ) -> Result<std::result::Result<Resource<InternalNonceKey>, Error>> {
        use aes_gcm_iface::AesVariant;
        let len = match variant {
            AesVariant::Aes128 => 16,
            AesVariant::Aes192 => {
                return Ok(Err(Error::Unsupported(
                    "AES-192 is not served by this implementation".into(),
                )))
            }
            AesVariant::Aes256 => 32,
        };
        let mut raw = vec![0u8; len];
        getrandom::fill(&mut raw)
            .map_err(|err| wasmtime::Error::msg(format!("random key generation failed: {err}")))?;
        let key = new_aes_gcm_key(variant, raw, extractable)
            .map(into_internal_nonce_key)
            .map_err(|_| wasmtime::Error::msg("generated key material was rejected"))?;
        accessor.with(|mut access| Ok(Ok(access.get().table.push(key)?)))
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
        let key = match new_xchacha_key(raw, extractable) {
            Ok(key) => into_internal_nonce_key(key),
            Err(err) => return Ok(Err(err)),
        };
        accessor.with(|mut access| Ok(Ok(access.get().table.push(key)?)))
    }

    async fn generate_key(
        accessor: &Accessor<T, Self>,
        extractable: bool,
    ) -> Result<std::result::Result<Resource<InternalNonceKey>, Error>> {
        let mut raw = vec![0u8; CHACHA_KEY_LEN];
        getrandom::fill(&mut raw)
            .map_err(|err| wasmtime::Error::msg(format!("random key generation failed: {err}")))?;
        let key = new_xchacha_key(raw, extractable)
            .map(into_internal_nonce_key)
            .map_err(|_| wasmtime::Error::msg("generated key material was rejected"))?;
        accessor.with(|mut access| Ok(Ok(access.get().table.push(key)?)))
    }
}

// --- signature -----------------------------------------------------------------

impl signature_iface::Host for WasiWebcryptoCtxView<'_> {}

/// The public key backing a [`VerifyingKey`], bound to its algorithm (and,
/// for ECDSA, its curve/digest variant) at minting.
pub(crate) enum SigPublic {
    Ed25519(ed25519_dalek::VerifyingKey),
    EcdsaP256(p256::ecdsa::VerifyingKey),
    EcdsaP384(p384::ecdsa::VerifyingKey),
}

impl SigPublic {
    /// The registry algorithm name (`verifying-key.algorithm-name`).
    fn name(&self) -> &'static str {
        match self {
            Self::Ed25519(_) => ED25519_NAME,
            Self::EcdsaP256(_) | Self::EcdsaP384(_) => ECDSA_NAME,
        }
    }

    /// The registry curve name (`verifying-key.algorithm-curve`).
    fn curve(&self) -> Option<&'static str> {
        match self {
            Self::Ed25519(_) => None,
            Self::EcdsaP256(_) => Some("P-256"),
            Self::EcdsaP384(_) => Some("P-384"),
        }
    }

    /// The mint-bound digest name (`verifying-key.algorithm-hash`).
    fn hash(&self) -> Option<&'static str> {
        match self {
            Self::Ed25519(_) => None,
            Self::EcdsaP256(_) => Some("SHA-256"),
            Self::EcdsaP384(_) => Some("SHA-384"),
        }
    }

    /// The public key material in the minting interface's documented form:
    /// raw 32 bytes for Ed25519, an uncompressed SEC1 point for ECDSA.
    fn export(&self) -> Vec<u8> {
        match self {
            Self::Ed25519(key) => key.to_bytes().to_vec(),
            Self::EcdsaP256(key) => key.to_encoded_point(false).as_bytes().to_vec(),
            Self::EcdsaP384(key) => key.to_encoded_point(false).as_bytes().to_vec(),
        }
    }

    /// One-shot verification of `sig` over `data`; the ECDSA signature
    /// format is fixed-width `r ‖ s` (IEEE P1363).
    fn verify(&self, data: &[u8], sig: &[u8]) -> std::result::Result<(), Error> {
        use p256::ecdsa::signature::Verifier as _;
        let ok = match self {
            Self::Ed25519(key) => ed25519_dalek::Signature::from_slice(sig)
                .and_then(|sig| key.verify_strict(data, &sig))
                .is_ok(),
            Self::EcdsaP256(key) => p256::ecdsa::Signature::from_slice(sig)
                .and_then(|sig| key.verify(data, &sig))
                .is_ok(),
            Self::EcdsaP384(key) => p384::ecdsa::Signature::from_slice(sig)
                .and_then(|sig| key.verify(data, &sig))
                .is_ok(),
        };
        if ok {
            Ok(())
        } else {
            Err(Error::AuthenticationFailed)
        }
    }
}

/// The private key backing a [`SigningKey`], bound to its algorithm (and,
/// for ECDSA, its curve/digest variant) at minting.
pub(crate) enum SigPrivate {
    Ed25519(ed25519_dalek::SigningKey),
    EcdsaP256(p256::ecdsa::SigningKey),
    EcdsaP384(p384::ecdsa::SigningKey),
}

impl SigPrivate {
    /// The corresponding [`SigPublic`].
    fn public(&self) -> SigPublic {
        match self {
            Self::Ed25519(key) => SigPublic::Ed25519(key.verifying_key()),
            Self::EcdsaP256(key) => SigPublic::EcdsaP256(*key.verifying_key()),
            Self::EcdsaP384(key) => SigPublic::EcdsaP384(*key.verifying_key()),
        }
    }

    /// One-shot signature over `data`: 64 bytes for Ed25519 (RFC 8032),
    /// fixed-width `r ‖ s` (IEEE P1363, RFC 6979 deterministic) for ECDSA.
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        use p256::ecdsa::signature::Signer as _;
        match self {
            Self::Ed25519(key) => {
                use ed25519_dalek::Signer as _;
                key.sign(data).to_bytes().to_vec()
            }
            Self::EcdsaP256(key) => {
                let sig: p256::ecdsa::Signature = key.sign(data);
                sig.to_bytes().to_vec()
            }
            Self::EcdsaP384(key) => {
                let sig: p384::ecdsa::Signature = key.sign(data);
                sig.to_bytes().to_vec()
            }
        }
    }

    /// The private key material in the minting interface's documented form:
    /// the 32-byte RFC 8032 seed for Ed25519, the raw big-endian scalar for
    /// ECDSA.
    fn export(&self) -> Vec<u8> {
        match self {
            Self::Ed25519(key) => key.to_bytes().to_vec(),
            Self::EcdsaP256(key) => key.to_bytes().to_vec(),
            Self::EcdsaP384(key) => key.to_bytes().to_vec(),
        }
    }
}

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
        let bytes = drain_stream(accessor, data).await?;
        accessor.with(|mut access| {
            let key = access.get().table.get(&self_)?;
            Ok(key.public.verify(&bytes, &sig))
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
    fn verifying_key(&mut self, self_: Resource<SigningKey>) -> Result<Resource<VerifyingKey>> {
        let public = self.table.get(&self_)?.private.public();
        Ok(self.table.push(VerifyingKey { public })?)
    }

    fn algorithm_name(&mut self, self_: Resource<SigningKey>) -> Result<String> {
        Ok(self.table.get(&self_)?.private.public().name().to_string())
    }

    fn algorithm_curve(&mut self, self_: Resource<SigningKey>) -> Result<Option<String>> {
        Ok(self
            .table
            .get(&self_)?
            .private
            .public()
            .curve()
            .map(str::to_string))
    }

    fn algorithm_hash(&mut self, self_: Resource<SigningKey>) -> Result<Option<String>> {
        Ok(self
            .table
            .get(&self_)?
            .private
            .public()
            .hash()
            .map(str::to_string))
    }

    fn extractable(&mut self, self_: Resource<SigningKey>) -> Result<bool> {
        Ok(self.table.get(&self_)?.extractable)
    }
}

impl<T: Send> signature_iface::HostSigningKeyWithStore<T> for WasiWebcrypto {
    async fn sign(
        accessor: &Accessor<T, Self>,
        self_: Resource<SigningKey>,
        data: StreamReader<u8>,
    ) -> Result<std::result::Result<Vec<u8>, Error>> {
        let bytes = drain_stream(accessor, data).await?;
        // The WIT `err` case exists for operational keystore failures; this
        // implementation holds the material in-process, so it never errs.
        accessor.with(|mut access| {
            let key = access.get().table.get(&self_)?;
            Ok(Ok(key.private.sign(&bytes)))
        })
    }

    async fn export_key(
        accessor: &Accessor<T, Self>,
        self_: Resource<SigningKey>,
    ) -> Result<std::result::Result<Vec<u8>, Error>> {
        accessor.with(|mut access| {
            let key = access.get().table.get(&self_)?;
            Ok(if key.extractable {
                Ok(key.private.export())
            } else {
                Err(Error::NotExtractable)
            })
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

/// Parse a 32-byte RFC 8032 public key, rendering `invalid-key` for wrong
/// lengths and non-canonical point encodings.
fn parse_ed25519_public(raw: &[u8]) -> std::result::Result<SigPublic, Error> {
    let bytes: &[u8; 32] = raw.try_into().map_err(|_| {
        Error::InvalidKey(format!(
            "Ed25519 public keys are 32 bytes, got {}",
            raw.len()
        ))
    })?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(bytes)
        .map_err(|err| Error::InvalidKey(format!("invalid Ed25519 public key: {err}")))?;
    Ok(SigPublic::Ed25519(key))
}

impl<T: Send> ed25519_verify_iface::HostWithStore<T> for WasiWebcrypto {
    async fn import_verifying_key(
        accessor: &Accessor<T, Self>,
        raw: Vec<u8>,
    ) -> Result<std::result::Result<Resource<VerifyingKey>, Error>> {
        let public = match parse_ed25519_public(&raw) {
            Ok(public) => public,
            Err(err) => return Ok(Err(err)),
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
        let seed: &[u8; 32] = match raw.as_slice().try_into() {
            Ok(seed) => seed,
            Err(_) => {
                return Ok(Err(Error::InvalidKey(format!(
                    "Ed25519 private keys are 32-byte seeds, got {} bytes",
                    raw.len()
                ))))
            }
        };
        let key = SigningKey {
            private: SigPrivate::Ed25519(ed25519_dalek::SigningKey::from_bytes(seed)),
            extractable,
        };
        accessor.with(|mut access| Ok(Ok(access.get().table.push(key)?)))
    }

    async fn generate_key(
        accessor: &Accessor<T, Self>,
        extractable: bool,
    ) -> Result<std::result::Result<Resource<SigningKey>, Error>> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed)
            .map_err(|err| wasmtime::Error::msg(format!("random key generation failed: {err}")))?;
        let key = SigningKey {
            private: SigPrivate::Ed25519(ed25519_dalek::SigningKey::from_bytes(&seed)),
            extractable,
        };
        accessor.with(|mut access| Ok(Ok(access.get().table.push(key)?)))
    }
}

// --- ecdsa (key minting) ---------------------------------------------------------

impl ecdsa_verify_iface::Host for WasiWebcryptoCtxView<'_> {}
impl ecdsa_sign_iface::Host for WasiWebcryptoCtxView<'_> {}

/// Parse an uncompressed SEC1 point for the declared variant, rendering
/// `invalid-key` for anything else (including compressed encodings, per the
/// WIT contract).
fn parse_ecdsa_public(
    variant: ecdsa_verify_iface::EcdsaVariant,
    raw: &[u8],
) -> std::result::Result<SigPublic, Error> {
    use ecdsa_verify_iface::EcdsaVariant;
    let expected = match variant {
        EcdsaVariant::P256Sha256 => 65,
        EcdsaVariant::P384Sha384 => 97,
    };
    if raw.len() != expected || raw[0] != 0x04 {
        return Err(Error::InvalidKey(format!(
            "{variant:?} public keys are uncompressed SEC1 points ({expected} bytes, leading 0x04)"
        )));
    }
    match variant {
        EcdsaVariant::P256Sha256 => p256::ecdsa::VerifyingKey::from_sec1_bytes(raw)
            .map(SigPublic::EcdsaP256)
            .map_err(|err| Error::InvalidKey(format!("invalid P-256 public key: {err}"))),
        EcdsaVariant::P384Sha384 => p384::ecdsa::VerifyingKey::from_sec1_bytes(raw)
            .map(SigPublic::EcdsaP384)
            .map_err(|err| Error::InvalidKey(format!("invalid P-384 public key: {err}"))),
    }
}

/// Parse a raw big-endian scalar for the declared variant, rendering
/// `invalid-key` for wrong lengths and out-of-range scalars.
fn parse_ecdsa_private(
    variant: ecdsa_verify_iface::EcdsaVariant,
    raw: &[u8],
) -> std::result::Result<SigPrivate, Error> {
    use ecdsa_verify_iface::EcdsaVariant;
    match variant {
        EcdsaVariant::P256Sha256 => p256::ecdsa::SigningKey::from_slice(raw)
            .map(SigPrivate::EcdsaP256)
            .map_err(|err| Error::InvalidKey(format!("invalid P-256 private key: {err}"))),
        EcdsaVariant::P384Sha384 => p384::ecdsa::SigningKey::from_slice(raw)
            .map(SigPrivate::EcdsaP384)
            .map_err(|err| Error::InvalidKey(format!("invalid P-384 private key: {err}"))),
    }
}

impl<T: Send> ecdsa_verify_iface::HostWithStore<T> for WasiWebcrypto {
    async fn import_verifying_key(
        accessor: &Accessor<T, Self>,
        variant: ecdsa_verify_iface::EcdsaVariant,
        raw: Vec<u8>,
    ) -> Result<std::result::Result<Resource<VerifyingKey>, Error>> {
        let public = match parse_ecdsa_public(variant, &raw) {
            Ok(public) => public,
            Err(err) => return Ok(Err(err)),
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
        let private = match parse_ecdsa_private(variant, &raw) {
            Ok(private) => private,
            Err(err) => return Ok(Err(err)),
        };
        let key = SigningKey {
            private,
            extractable,
        };
        accessor.with(|mut access| Ok(Ok(access.get().table.push(key)?)))
    }

    async fn generate_key(
        accessor: &Accessor<T, Self>,
        variant: ecdsa_verify_iface::EcdsaVariant,
        extractable: bool,
    ) -> Result<std::result::Result<Resource<SigningKey>, Error>> {
        use ecdsa_verify_iface::EcdsaVariant;
        // Rejection-sample the scalar range with fresh randomness (the
        // probability of a retry is negligible for these curves).
        let scalar_len = match variant {
            EcdsaVariant::P256Sha256 => 32,
            EcdsaVariant::P384Sha384 => 48,
        };
        let private = loop {
            let mut raw = vec![0u8; scalar_len];
            getrandom::fill(&mut raw).map_err(|err| {
                wasmtime::Error::msg(format!("random key generation failed: {err}"))
            })?;
            if let Ok(private) = parse_ecdsa_private(variant, &raw) {
                break private;
            }
        };
        let key = SigningKey {
            private,
            extractable,
        };
        accessor.with(|mut access| Ok(Ok(access.get().table.push(key)?)))
    }
}

#[cfg(test)]
mod tests {
    use super::ByteCollector;
    use futures::channel::oneshot;

    /// Dropping the collector (Wasmtime's end-of-stream notification)
    /// delivers the collected buffer.
    #[test]
    fn byte_collector_drop_delivers_buffer() {
        let (done_tx, mut done_rx) = oneshot::channel();
        drop(ByteCollector {
            buf: b"collected".to_vec(),
            failed: false,
            done_tx: Some(done_tx),
        });
        assert_eq!(done_rx.try_recv(), Ok(Some(b"collected".to_vec())));
    }

    /// After a pipe error, dropping the collector must NOT deliver the
    /// partial buffer as if it were the complete input: the channel closes
    /// unsent, which `drain_stream` maps to an error.
    #[test]
    fn byte_collector_drop_after_failure_delivers_nothing() {
        let (done_tx, mut done_rx) = oneshot::channel::<Vec<u8>>();
        drop(ByteCollector {
            buf: b"partial".to_vec(),
            failed: true,
            done_tx: Some(done_tx),
        });
        assert!(done_rx.try_recv().is_err());
    }
}
