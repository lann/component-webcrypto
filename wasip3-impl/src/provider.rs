//! The exported `lann:webcrypto` resources and key-minting functions, backed
//! by RustCrypto (`hmac`/`sha2` for HMAC-SHA-2, `aes-gcm` for AES-GCM).
//!
//! - [`MacKey`] holds raw HMAC key material; `sign` and `verify` are
//!   one-shot HMAC computations over the key's SHA-2 variant, stateless per call.
//! - [`AeadKey`] holds raw AES key material plus its schedule; `seal` and
//!   `open` are stateless per call.
//!
//! Byte `stream`s are the only bulk data path: incoming streams are drained
//! to completion (even when the operation resolves with an error, per the WIT
//! contract for `seal`/`open`), and outgoing streams are fed from a detached
//! task (`wit_bindgen::spawn`) after the export returns.

use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};

use crate::exports::lann::webcrypto::aead::{Guest as AeadGuest, GuestAeadKey};
use crate::exports::lann::webcrypto::aes_gcm::{AesVariant, Guest as AesGcmGuest};
use crate::exports::lann::webcrypto::bytes::Guest as BytesGuest;
use crate::exports::lann::webcrypto::digest::{self, Guest as DigestGuest, GuestDigest};
use crate::exports::lann::webcrypto::hmac_sha2::Guest as HmacSha2Guest;
use crate::exports::lann::webcrypto::mac::{self, Guest as MacGuest, GuestMacKey};
use crate::exports::lann::webcrypto::sha2::{Guest as Sha2Guest, Sha2Variant};
use crate::lann::webcrypto::types::Error;

/// The `algorithm-name` reported by HMAC keys and computations
/// (WebCrypto's `KeyAlgorithm.name`).
const HMAC_NAME: &str = "HMAC";

/// The `algorithm-name` reported by AES-GCM keys (WebCrypto's
/// `KeyAlgorithm.name`).
const AES_GCM_NAME: &str = "AES-GCM";

/// The AES-GCM nonce length this implementation accepts, per the `aes-gcm`
/// WIT contract (12-byte nonces, 16-byte tags).
const GCM_NONCE_LEN: usize = 12;

pub struct Component;

// --- stream plumbing ---------------------------------------------------------

/// Drain an entire `stream<u8>` into a buffer, resolving once the stream ends
/// (its writer dropped).
async fn drain_stream(mut data: wit_bindgen::StreamReader<u8>) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let (status, batch) = data.read(Vec::with_capacity(8 * 1024)).await;
        out.extend(batch);
        if matches!(
            status,
            wit_bindgen::StreamResult::Dropped | wit_bindgen::StreamResult::Cancelled
        ) {
            break;
        }
    }
    out
}

/// Return `bytes` as a `stream<u8>`, fed by a detached task after the caller
/// returns the reader.
fn stream_of(bytes: Vec<u8>) -> wit_bindgen::StreamReader<u8> {
    let (mut tx, rx) = crate::wit_stream::new();
    wit_bindgen::spawn_local(async move {
        let _ = tx.write_all(bytes).await;
        drop(tx);
    });
    rx
}

// --- mac ---------------------------------------------------------------------

impl MacGuest for Component {
    type MacKey = MacKey;
}

/// An exported `mac-key`: raw HMAC key material bound to a SHA-2 variant.
pub struct MacKey {
    raw: Vec<u8>,
    variant: Sha2,
    extractable: bool,
}

/// The served SHA-2 variants a [`MacKey`] can be bound to. Only the WIT
/// `sha2-variant` cases this implementation serves appear here: the
/// truncated variants are declined at minting (see the WIT `sha2-variant`
/// doc).
#[derive(Clone, Copy)]
enum Sha2 {
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
    fn sign(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        fn tag<M: hmac::Mac + hmac::digest::KeyInit>(key: &[u8], data: &[u8]) -> Vec<u8> {
            // HMAC accepts key material of any length, so this cannot fail
            // for a key that was accepted at import/generation time.
            let mut hmac =
                <M as hmac::Mac>::new_from_slice(key).expect("HMAC accepts any key length");
            hmac.update(data);
            hmac.finalize().into_bytes().to_vec()
        }
        match self {
            Self::Sha256 => tag::<hmac::Hmac<sha2::Sha256>>(key, data),
            Self::Sha384 => tag::<hmac::Hmac<sha2::Sha384>>(key, data),
            Self::Sha512 => tag::<hmac::Hmac<sha2::Sha512>>(key, data),
        }
    }

    /// One-shot constant-time HMAC verification of `tag` over `data`.
    fn verify(self, key: &[u8], data: &[u8], tag: &[u8]) -> Result<(), Error> {
        fn check<M: hmac::Mac + hmac::digest::KeyInit>(
            key: &[u8],
            data: &[u8],
            tag: &[u8],
        ) -> Result<(), Error> {
            let mut hmac =
                <M as hmac::Mac>::new_from_slice(key).expect("HMAC accepts any key length");
            hmac.update(data);
            // `verify_slice` compares in constant time, per the WIT contract.
            hmac.verify_slice(tag)
                .map_err(|_| Error::AuthenticationFailed)
        }
        match self {
            Self::Sha256 => check::<hmac::Hmac<sha2::Sha256>>(key, data, tag),
            Self::Sha384 => check::<hmac::Hmac<sha2::Sha384>>(key, data, tag),
            Self::Sha512 => check::<hmac::Hmac<sha2::Sha512>>(key, data, tag),
        }
    }
}

impl GuestMacKey for MacKey {
    async fn sign(&self, data: wit_bindgen::StreamReader<u8>) -> Vec<u8> {
        // Buffer the whole stream, then fold it into the HMAC state; the
        // result is chunking-invariant either way.
        let bytes = drain_stream(data).await;
        self.variant.sign(&self.raw, &bytes)
    }

    async fn verify(&self, data: wit_bindgen::StreamReader<u8>, tag: Vec<u8>) -> Result<(), Error> {
        let bytes = drain_stream(data).await;
        self.variant.verify(&self.raw, &bytes, &tag)
    }

    fn algorithm_name(&self) -> String {
        HMAC_NAME.to_string()
    }

    fn algorithm_hash(&self) -> Option<String> {
        Some(self.variant.hash_name().to_string())
    }

    fn algorithm_length(&self) -> u32 {
        self.raw.len() as u32 * 8
    }

    async fn export(&self) -> Result<Vec<u8>, Error> {
        if self.extractable {
            Ok(self.raw.clone())
        } else {
            Err(Error::NotExtractable)
        }
    }
}

// --- aead --------------------------------------------------------------------

impl AeadGuest for Component {
    type AeadKey = AeadKey;
}

/// An exported `aead-key`: raw AES key material, bound to AES-GCM, with its
/// expanded key schedule.
pub struct AeadKey {
    raw: Vec<u8>,
    extractable: bool,
    cipher: AesGcmCipher,
}

/// The AES-GCM cipher backing an [`AeadKey`], dispatching on key size. Only
/// the WIT `aes-variant` cases this implementation serves appear here:
/// AES-192 is declined at minting (see the WIT `aes-variant` doc).
enum AesGcmCipher {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
}

impl AesGcmCipher {
    /// The key length in bits (WebCrypto's `AesKeyAlgorithm.length`).
    fn length_bits(&self) -> u32 {
        match self {
            Self::Aes128(_) => 128,
            Self::Aes256(_) => 256,
        }
    }

    fn encrypt(&self, nonce: &[u8], payload: Payload<'_, '_>) -> Result<Vec<u8>, aes_gcm::Error> {
        let nonce = Nonce::from_slice(nonce);
        match self {
            Self::Aes128(cipher) => cipher.encrypt(nonce, payload),
            Self::Aes256(cipher) => cipher.encrypt(nonce, payload),
        }
    }

    fn decrypt(&self, nonce: &[u8], payload: Payload<'_, '_>) -> Result<Vec<u8>, aes_gcm::Error> {
        let nonce = Nonce::from_slice(nonce);
        match self {
            Self::Aes128(cipher) => cipher.decrypt(nonce, payload),
            Self::Aes256(cipher) => cipher.decrypt(nonce, payload),
        }
    }
}

/// Validate an AES-GCM nonce length, rendering the WIT `invalid-nonce` error
/// for anything but 12 bytes.
fn check_gcm_nonce(nonce: &[u8]) -> Result<(), Error> {
    if nonce.len() == GCM_NONCE_LEN {
        Ok(())
    } else {
        Err(Error::InvalidNonce(format!(
            "AES-GCM requires a {GCM_NONCE_LEN}-byte nonce, got {} bytes",
            nonce.len()
        )))
    }
}

impl GuestAeadKey for AeadKey {
    async fn seal(
        &self,
        nonce: Vec<u8>,
        aad: Vec<u8>,
        plaintext: wit_bindgen::StreamReader<u8>,
    ) -> Result<wit_bindgen::StreamReader<u8>, Error> {
        // Per the WIT contract, the input stream is fully drained even when
        // the call resolves with an error, so the caller's writer always
        // completes.
        let msg = drain_stream(plaintext).await;
        check_gcm_nonce(&nonce)?;
        let sealed = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &msg,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Other("AES-GCM encryption failed".into()))?;
        Ok(stream_of(sealed))
    }

    async fn open(
        &self,
        nonce: Vec<u8>,
        aad: Vec<u8>,
        ciphertext: wit_bindgen::StreamReader<u8>,
    ) -> Result<wit_bindgen::StreamReader<u8>, Error> {
        // Like `seal`: fully drain the input first. Buffering the whole
        // message is inherent to `open`: no unverified plaintext may be
        // observable.
        let msg = drain_stream(ciphertext).await;
        check_gcm_nonce(&nonce)?;
        // Any decryption failure — truncated input, bad tag, wrong key,
        // wrong associated data — reports `authentication-failed` with no
        // detail, per the WIT contract.
        let opened = self
            .cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &msg,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::AuthenticationFailed)?;
        Ok(stream_of(opened))
    }

    fn algorithm_name(&self) -> String {
        AES_GCM_NAME.to_string()
    }

    fn algorithm_length(&self) -> u32 {
        self.cipher.length_bits()
    }

    async fn export(&self) -> Result<Vec<u8>, Error> {
        if self.extractable {
            Ok(self.raw.clone())
        } else {
            Err(Error::NotExtractable)
        }
    }
}

// --- digest --------------------------------------------------------------------

impl DigestGuest for Component {
    type Digest = Digest;
}

/// An exported `digest`: no key material, just the SHA-2 variant it is
/// bound to. `compute` is one-shot and stateless per call, so the resource
/// is reusable.
pub struct Digest {
    variant: Sha2,
}

impl GuestDigest for Digest {
    async fn compute(&self, data: wit_bindgen::StreamReader<u8>) -> Vec<u8> {
        // Buffer the whole stream, then hash it; the result is
        // chunking-invariant either way.
        let bytes = drain_stream(data).await;
        self.variant.digest(&bytes)
    }

    fn algorithm_name(&self) -> String {
        self.variant.hash_name().to_string()
    }
}

// --- bytes ---------------------------------------------------------------------

impl BytesGuest for Component {
    fn constant_time_equal(a: Vec<u8>, b: Vec<u8>) -> bool {
        use subtle::ConstantTimeEq as _;
        // `ct_eq` on slices short-circuits only on length (which is not
        // secret); the contents are compared in constant time.
        a.ct_eq(&b).into()
    }
}

// --- sha2 (digest minting) ---------------------------------------------------

impl Sha2Guest for Component {
    fn make_digest(variant: Sha2Variant) -> Result<digest::Digest, Error> {
        let variant = served_sha2(variant)?;
        Ok(digest::Digest::new(Digest { variant }))
    }
}

// --- hmac-sha2 (key minting) -----------------------------------------------------

/// The served [`Sha2`] for a WIT `sha2-variant`, or `unsupported` for one
/// this implementation declines (the truncated variants; see the WIT
/// `sha2-variant` doc). Shared by the `sha2` and `hmac-sha2` minting paths.
fn served_sha2(variant: Sha2Variant) -> Result<Sha2, Error> {
    match variant {
        Sha2Variant::Sha256 => Ok(Sha2::Sha256),
        Sha2Variant::Sha384 => Ok(Sha2::Sha384),
        Sha2Variant::Sha512 => Ok(Sha2::Sha512),
        Sha2Variant::Sha224 | Sha2Variant::Sha512224 | Sha2Variant::Sha512256 => Err(
            Error::Unsupported(format!("{variant:?} is not served by this implementation")),
        ),
    }
}

impl HmacSha2Guest for Component {
    async fn import_key(
        variant: Sha2Variant,
        raw: Vec<u8>,
        extractable: bool,
    ) -> Result<mac::MacKey, Error> {
        let variant = served_sha2(variant)?;
        // RFC 2104 accepts any non-empty key length (longer-than-block keys
        // are hashed first); an empty key is rejected as `invalid-key`.
        if raw.is_empty() {
            return Err(Error::InvalidKey(
                "HMAC key material must be non-empty".into(),
            ));
        }
        Ok(mac::MacKey::new(MacKey {
            raw,
            variant,
            extractable,
        }))
    }

    async fn generate_key(variant: Sha2Variant, extractable: bool) -> Result<mac::MacKey, Error> {
        let variant = served_sha2(variant)?;
        let mut raw = vec![0u8; variant.block_len()];
        getrandom::fill(&mut raw).expect("WASI random source is always available");
        Ok(mac::MacKey::new(MacKey {
            raw,
            variant,
            extractable,
        }))
    }
}

// --- aes-gcm (key minting) -------------------------------------------------------

/// The raw key length in bytes for a served AES variant, or `unsupported`
/// for one this implementation declines (AES-192; see the WIT `aes-variant`
/// doc).
fn variant_len(variant: AesVariant) -> Result<usize, Error> {
    match variant {
        AesVariant::Aes128 => Ok(16),
        AesVariant::Aes192 => Err(Error::Unsupported(
            "AES-192 is not served by this implementation".into(),
        )),
        AesVariant::Aes256 => Ok(32),
    }
}

/// Build an [`AeadKey`] from raw material declared as `variant`, rendering
/// the WIT `invalid-key` error when the material's length disagrees with
/// the declared variant, or `unsupported` for a declined variant.
fn new_aes_gcm_key(variant: AesVariant, raw: Vec<u8>, extractable: bool) -> Result<AeadKey, Error> {
    let expected = variant_len(variant)?;
    if raw.len() != expected {
        return Err(Error::InvalidKey(format!(
            "{variant:?} requires {expected} bytes of key material, got {} bytes",
            raw.len()
        )));
    }
    let cipher = match variant {
        AesVariant::Aes128 => {
            AesGcmCipher::Aes128(Aes128Gcm::new_from_slice(&raw).expect("length checked"))
        }
        AesVariant::Aes192 => unreachable!("rejected above"),
        AesVariant::Aes256 => {
            AesGcmCipher::Aes256(Aes256Gcm::new_from_slice(&raw).expect("length checked"))
        }
    };
    Ok(AeadKey {
        raw,
        extractable,
        cipher,
    })
}

impl AesGcmGuest for Component {
    async fn import_key(
        variant: AesVariant,
        raw: Vec<u8>,
        extractable: bool,
    ) -> Result<crate::exports::lann::webcrypto::aead::AeadKey, Error> {
        let key = new_aes_gcm_key(variant, raw, extractable)?;
        Ok(crate::exports::lann::webcrypto::aead::AeadKey::new(key))
    }

    async fn generate_key(
        variant: AesVariant,
        extractable: bool,
    ) -> Result<crate::exports::lann::webcrypto::aead::AeadKey, Error> {
        let mut raw = vec![0u8; variant_len(variant)?];
        getrandom::fill(&mut raw).expect("WASI random source is always available");
        let key = new_aes_gcm_key(variant, raw, extractable)
            .expect("generated key material always matches the variant");
        Ok(crate::exports::lann::webcrypto::aead::AeadKey::new(key))
    }
}
