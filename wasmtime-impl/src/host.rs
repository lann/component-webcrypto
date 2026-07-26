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
use crate::bindings::webcrypto::digest::{HostDigest, HostDigestWithStore};
use crate::bindings::webcrypto::mac::{self, HostMacKey, HostMacKeyWithStore};
use crate::bindings::webcrypto::types::{self, Error};
use crate::bindings::webcrypto::{
    aes_gcm as aes_gcm_iface, bytes as bytes_iface, chacha20_poly1305 as chacha_iface,
    digest as digest_iface, hmac_sha2 as hmac_sha2_iface, sha2 as sha2_iface,
};
use crate::{
    AeadKey, Digest, MacKey, WasiWebcrypto, WasiWebcryptoCtxView, AES_GCM_NAME,
    CHACHA20_POLY1305_NAME, HMAC_NAME, XCHACHA20_POLY1305_NAME,
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
struct ByteCollector {
    buf: Vec<u8>,
    done_tx: Option<oneshot::Sender<Vec<u8>>>,
}

impl ByteCollector {
    fn finish(&mut self) {
        if let Some(tx) = self.done_tx.take() {
            let _ = tx.send(std::mem::take(&mut self.buf));
        }
    }
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
            source.read(&mut store, &mut chunk)?;
            this.buf.extend_from_slice(&chunk);
            return Poll::Ready(Ok(StreamResult::Completed));
        }

        // No bytes available. When `finish` is set the stream is ending, so
        // hand the collected buffer back; `Drop` covers a normal
        // end-of-stream.
        if finish {
            this.finish();
            Poll::Ready(Ok(StreamResult::Cancelled))
        } else {
            Poll::Pending
        }
    }
}

impl Drop for ByteCollector {
    fn drop(&mut self) {
        self.finish();
    }
}

/// Drain an entire `stream<u8>` into a buffer, resolving once the stream ends
/// (its writer dropped).
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
                done_tx: Some(done_tx),
            },
        )
    })?;
    Ok(done_rx.await.unwrap_or_default())
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
    ) -> Result<Vec<u8>> {
        let (variant, raw) = accessor.with(|mut access| {
            let key = access.get().table.get(&self_)?;
            Ok::<_, wasmtime::Error>((key.variant, key.raw.clone()))
        })?;
        // Buffer the whole stream, then fold it into the HMAC state; the
        // result is chunking-invariant either way.
        let bytes = drain_stream(accessor, data).await?;
        variant.sign(&raw, &bytes)
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

    async fn export(
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

    async fn export(
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

// --- chacha20-poly1305 (key minting) -----------------------------------------

impl chacha_iface::Host for WasiWebcryptoCtxView<'_> {}

/// The length in bytes of a ChaCha20-Poly1305 key (either variant).
const CHACHA_KEY_LEN: usize = 32;

/// Build an [`AeadKey`] from raw material declared as `variant`, rendering
/// the WIT `invalid-key` error when the material is not the 32 bytes both
/// variants require.
fn new_chacha_key(
    variant: chacha_iface::ChachaVariant,
    raw: Vec<u8>,
    extractable: bool,
) -> std::result::Result<AeadKey, Error> {
    use chacha_iface::ChachaVariant;
    if raw.len() != CHACHA_KEY_LEN {
        return Err(Error::InvalidKey(format!(
            "{variant:?} requires {CHACHA_KEY_LEN} bytes of key material, got {} bytes",
            raw.len()
        )));
    }
    let cipher = match variant {
        ChachaVariant::Chacha20Poly1305 => AeadCipher::ChaCha20Poly1305(
            ChaCha20Poly1305::new_from_slice(&raw).expect("length checked"),
        ),
        ChachaVariant::Xchacha20Poly1305 => AeadCipher::XChaCha20Poly1305(
            XChaCha20Poly1305::new_from_slice(&raw).expect("length checked"),
        ),
    };
    Ok(AeadKey {
        cipher,
        raw,
        extractable,
    })
}

impl<T: Send> chacha_iface::HostWithStore<T> for WasiWebcrypto {
    async fn import_key(
        accessor: &Accessor<T, Self>,
        variant: chacha_iface::ChachaVariant,
        raw: Vec<u8>,
        extractable: bool,
    ) -> Result<std::result::Result<Resource<AeadKey>, Error>> {
        let key = match new_chacha_key(variant, raw, extractable) {
            Ok(key) => key,
            Err(err) => return Ok(Err(err)),
        };
        accessor.with(|mut access| Ok(Ok(access.get().table.push(key)?)))
    }

    async fn generate_key(
        accessor: &Accessor<T, Self>,
        variant: chacha_iface::ChachaVariant,
        extractable: bool,
    ) -> Result<std::result::Result<Resource<AeadKey>, Error>> {
        let mut raw = vec![0u8; CHACHA_KEY_LEN];
        getrandom::fill(&mut raw)
            .map_err(|err| wasmtime::Error::msg(format!("random key generation failed: {err}")))?;
        let key = new_chacha_key(variant, raw, extractable)
            .map_err(|_| wasmtime::Error::msg("generated key material was rejected"))?;
        accessor.with(|mut access| Ok(Ok(access.get().table.push(key)?)))
    }
}
