//! The exported `lann:webcrypto` resources and key-minting functions, backed
//! by RustCrypto (`hmac`/`sha2` for HMAC-SHA-2 and SHA-2, `aes-gcm` for
//! AES-GCM, `chacha20poly1305` for ChaCha20-Poly1305).
//!
//! - [`MacKey`] holds raw HMAC key material; `sign` and `verify` are
//!   one-shot HMAC computations over the key's SHA-2 variant, stateless per call.
//! - [`AeadKey`] holds raw key material plus its ready-to-use cipher; `seal`
//!   and `open` are stateless per call.
//!
//! Byte `stream`s are the only bulk data path: incoming streams are drained
//! to completion (even when the operation resolves with an error, per the WIT
//! contract for `seal`/`open`), and outgoing streams are fed from a detached
//! task (`wit_bindgen::spawn`) after the export returns.

use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};

use crate::exports::lann::webcrypto::aead::{Guest as AeadGuest, GuestAeadKey};
use crate::exports::lann::webcrypto::aead_internal_nonce::{
    Guest as AeadInternalNonceGuest, GuestInternalNonceKey,
};
use crate::exports::lann::webcrypto::aes_gcm::{AesVariant, Guest as AesGcmGuest};
use crate::exports::lann::webcrypto::aes_gcm_internal_nonce::Guest as AesGcmInternalNonceGuest;
use crate::exports::lann::webcrypto::bytes::Guest as BytesGuest;
use crate::exports::lann::webcrypto::chacha20_poly1305::Guest as ChaChaPoly1305Guest;
use crate::exports::lann::webcrypto::digest::{self, Guest as DigestGuest, GuestDigest};
use crate::exports::lann::webcrypto::ecdsa_verify::{EcdsaVariant, Guest as EcdsaVerifyGuest};
use crate::exports::lann::webcrypto::ed25519_sign::Guest as Ed25519SignGuest;
use crate::exports::lann::webcrypto::ed25519_verify::Guest as Ed25519VerifyGuest;
use crate::exports::lann::webcrypto::hmac_sha2::Guest as HmacSha2Guest;
use crate::exports::lann::webcrypto::mac::{self, Guest as MacGuest, GuestMacKey};
use crate::exports::lann::webcrypto::sha2::{Guest as Sha2Guest, Sha2Variant};
use crate::exports::lann::webcrypto::signature::{
    self as signature_iface, Guest as SignatureGuest, GuestSigningKey, GuestVerifyingKey,
};
use crate::exports::lann::webcrypto::xchacha20_poly1305::Guest as XChaChaPoly1305Guest;
use crate::exports::lann::webcrypto::xchacha20_poly1305_internal_nonce::Guest as XChachaInternalNonceGuest;
use crate::lann::webcrypto::types::Error;

/// The `algorithm-name` reported by HMAC keys and computations
/// (WebCrypto's `KeyAlgorithm.name`).
const HMAC_NAME: &str = "HMAC";

/// The `algorithm-name` reported by AES-GCM keys (WebCrypto's
/// `KeyAlgorithm.name`).
const AES_GCM_NAME: &str = "AES-GCM";

/// The `algorithm-name` reported by ChaCha20-Poly1305 keys (the spelling of
/// the WICG WebCrypto proposal; the algorithm is not in the W3C registry).
const CHACHA20_POLY1305_NAME: &str = "ChaCha20-Poly1305";

/// The `algorithm-name` reported by XChaCha20-Poly1305 keys.
const XCHACHA20_POLY1305_NAME: &str = "XChaCha20-Poly1305";

/// The `algorithm-name` reported by Ed25519 keys (WebCrypto's
/// `KeyAlgorithm.name`, per the Secure Curves registry entry).
const ED25519_NAME: &str = "Ed25519";

/// The `algorithm-name` reported by ECDSA keys (WebCrypto's
/// `KeyAlgorithm.name`).
const ECDSA_NAME: &str = "ECDSA";

/// The length in bytes of a ChaCha20-Poly1305 key (either variant).
const CHACHA_KEY_LEN: usize = 32;

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
    /// Raw key material; zeroized on drop.
    raw: zeroize::Zeroizing<Vec<u8>>,
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
    async fn sign(&self, data: wit_bindgen::StreamReader<u8>) -> Result<Vec<u8>, Error> {
        // Buffer the whole stream, then fold it into the HMAC state; the
        // result is chunking-invariant either way.
        //
        // The WIT `err` case exists for operational keystore failures; this
        // implementation holds the material in-process, so it never errs.
        let bytes = drain_stream(data).await;
        Ok(self.variant.sign(&self.raw, &bytes))
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

    async fn export_key(&self) -> Result<Vec<u8>, Error> {
        if self.extractable {
            Ok(self.raw.to_vec())
        } else {
            Err(Error::NotExtractable)
        }
    }
}

// --- aead --------------------------------------------------------------------

impl AeadGuest for Component {
    type AeadKey = AeadKey;
}

/// An exported `aead-key`: raw key material, bound to its algorithm at
/// minting, with its ready-to-use cipher.
pub struct AeadKey {
    /// Raw key material; zeroized on drop.
    raw: zeroize::Zeroizing<Vec<u8>>,
    extractable: bool,
    cipher: AeadCipher,
}

/// The cipher backing an [`AeadKey`], bound to its algorithm at minting.
/// Only the WIT variant cases this implementation serves appear here:
/// AES-192 is declined at minting (see the WIT `aes-variant` doc).
enum AeadCipher {
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
    fn check_nonce(&self, nonce: &[u8]) -> Result<(), Error> {
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

    fn encrypt(&self, nonce: &[u8], payload: Payload<'_, '_>) -> Result<Vec<u8>, aes_gcm::Error> {
        match self {
            Self::Aes128Gcm(cipher) => cipher.encrypt(aes_gcm::Nonce::from_slice(nonce), payload),
            Self::Aes256Gcm(cipher) => cipher.encrypt(aes_gcm::Nonce::from_slice(nonce), payload),
            Self::ChaCha20Poly1305(cipher) => {
                cipher.encrypt(chacha20poly1305::Nonce::from_slice(nonce), payload)
            }
            Self::XChaCha20Poly1305(cipher) => {
                cipher.encrypt(chacha20poly1305::XNonce::from_slice(nonce), payload)
            }
        }
    }

    fn decrypt(&self, nonce: &[u8], payload: Payload<'_, '_>) -> Result<Vec<u8>, aes_gcm::Error> {
        match self {
            Self::Aes128Gcm(cipher) => cipher.decrypt(aes_gcm::Nonce::from_slice(nonce), payload),
            Self::Aes256Gcm(cipher) => cipher.decrypt(aes_gcm::Nonce::from_slice(nonce), payload),
            Self::ChaCha20Poly1305(cipher) => {
                cipher.decrypt(chacha20poly1305::Nonce::from_slice(nonce), payload)
            }
            Self::XChaCha20Poly1305(cipher) => {
                cipher.decrypt(chacha20poly1305::XNonce::from_slice(nonce), payload)
            }
        }
    }
}

impl GuestAeadKey for AeadKey {
    fn nonce_size(&self) -> u32 {
        self.cipher.nonce_len() as u32
    }

    fn tag_size(&self) -> u32 {
        self.cipher.tag_len() as u32
    }

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
        self.cipher.check_nonce(&nonce)?;
        let sealed = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &msg,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Other(format!("{} encryption failed", self.cipher.name())))?;
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
        self.cipher.check_nonce(&nonce)?;
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
        self.cipher.name().to_string()
    }

    fn algorithm_length(&self) -> u32 {
        self.cipher.length_bits()
    }

    async fn export_key(&self) -> Result<Vec<u8>, Error> {
        if self.extractable {
            Ok(self.raw.to_vec())
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
    async fn compute(&self, data: wit_bindgen::StreamReader<u8>) -> Result<Vec<u8>, Error> {
        // Buffer the whole stream, then hash it; the result is
        // chunking-invariant either way.
        //
        // The WIT `err` case exists for operational failures (e.g. an
        // external digest engine); this implementation computes in-process,
        // so it never errs.
        let bytes = drain_stream(data).await;
        Ok(self.variant.digest(&bytes))
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
            raw: zeroize::Zeroizing::new(raw),
            variant,
            extractable,
        }))
    }

    async fn generate_key(variant: Sha2Variant, extractable: bool) -> Result<mac::MacKey, Error> {
        let variant = served_sha2(variant)?;
        let mut raw = vec![0u8; variant.block_len()];
        getrandom::fill(&mut raw).expect("WASI random source is always available");
        Ok(mac::MacKey::new(MacKey {
            raw: zeroize::Zeroizing::new(raw),
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
            AeadCipher::Aes128Gcm(Aes128Gcm::new_from_slice(&raw).expect("length checked"))
        }
        AesVariant::Aes192 => unreachable!("rejected above"),
        AesVariant::Aes256 => {
            AeadCipher::Aes256Gcm(Aes256Gcm::new_from_slice(&raw).expect("length checked"))
        }
    };
    Ok(AeadKey {
        raw: zeroize::Zeroizing::new(raw),
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

// --- chacha20-poly1305 / xchacha20-poly1305 (key minting) ---------------------

/// Validate ChaCha key material (32 bytes for either construction),
/// rendering the WIT `invalid-key` error otherwise.
fn check_chacha_key(name: &str, raw: &[u8]) -> Result<(), Error> {
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
fn new_chacha_key(raw: Vec<u8>, extractable: bool) -> Result<AeadKey, Error> {
    check_chacha_key(CHACHA20_POLY1305_NAME, &raw)?;
    let cipher = AeadCipher::ChaCha20Poly1305(
        ChaCha20Poly1305::new_from_slice(&raw).expect("length checked"),
    );
    Ok(AeadKey {
        raw: zeroize::Zeroizing::new(raw),
        extractable,
        cipher,
    })
}

/// Build an XChaCha20-Poly1305 [`AeadKey`] from raw material.
fn new_xchacha_key(raw: Vec<u8>, extractable: bool) -> Result<AeadKey, Error> {
    check_chacha_key(XCHACHA20_POLY1305_NAME, &raw)?;
    let cipher = AeadCipher::XChaCha20Poly1305(
        XChaCha20Poly1305::new_from_slice(&raw).expect("length checked"),
    );
    Ok(AeadKey {
        raw: zeroize::Zeroizing::new(raw),
        extractable,
        cipher,
    })
}

impl ChaChaPoly1305Guest for Component {
    async fn import_key(
        raw: Vec<u8>,
        extractable: bool,
    ) -> Result<crate::exports::lann::webcrypto::aead::AeadKey, Error> {
        let key = new_chacha_key(raw, extractable)?;
        Ok(crate::exports::lann::webcrypto::aead::AeadKey::new(key))
    }

    async fn generate_key(
        extractable: bool,
    ) -> Result<crate::exports::lann::webcrypto::aead::AeadKey, Error> {
        let mut raw = vec![0u8; CHACHA_KEY_LEN];
        getrandom::fill(&mut raw).expect("WASI random source is always available");
        let key =
            new_chacha_key(raw, extractable).expect("generated key material is always 32 bytes");
        Ok(crate::exports::lann::webcrypto::aead::AeadKey::new(key))
    }
}

impl XChaChaPoly1305Guest for Component {
    async fn import_key(
        raw: Vec<u8>,
        extractable: bool,
    ) -> Result<crate::exports::lann::webcrypto::aead::AeadKey, Error> {
        let key = new_xchacha_key(raw, extractable)?;
        Ok(crate::exports::lann::webcrypto::aead::AeadKey::new(key))
    }

    async fn generate_key(
        extractable: bool,
    ) -> Result<crate::exports::lann::webcrypto::aead::AeadKey, Error> {
        let mut raw = vec![0u8; CHACHA_KEY_LEN];
        getrandom::fill(&mut raw).expect("WASI random source is always available");
        let key =
            new_xchacha_key(raw, extractable).expect("generated key material is always 32 bytes");
        Ok(crate::exports::lann::webcrypto::aead::AeadKey::new(key))
    }
}

// --- aead-internal-nonce -------------------------------------------------------

impl AeadInternalNonceGuest for Component {
    type InternalNonceKey = InternalNonceKey;
}

/// An exported `internal-nonce-key`: like [`AeadKey`], but the nonce is
/// generated here per `seal` (the SP 800-38D SS8.2.2 RBG-based construction)
/// and carried as the sealed message's prefix. The key tracks its seal
/// count to enforce the WIT nonce budget (`error.key-exhausted`) for
/// 12-byte-nonce algorithms.
pub struct InternalNonceKey {
    /// Raw key material; zeroized on drop.
    raw: zeroize::Zeroizing<Vec<u8>>,
    extractable: bool,
    cipher: AeadCipher,
    /// `seal` invocations so far, counted against the nonce budget.
    /// A `Cell` because exports take `&self` (wasm is single-threaded).
    sealed: std::cell::Cell<u64>,
}

/// Wrap a caller-nonce [`AeadKey`] build as an [`InternalNonceKey`] (the
/// cipher and validation are identical; only the nonce discipline differs).
fn into_internal_nonce_key(key: AeadKey) -> InternalNonceKey {
    InternalNonceKey {
        raw: key.raw,
        extractable: key.extractable,
        cipher: key.cipher,
        sealed: std::cell::Cell::new(0),
    }
}

impl GuestInternalNonceKey for InternalNonceKey {
    fn seals_remaining(&self) -> Option<u64> {
        self.cipher
            .nonce_budget()
            .map(|budget| budget.saturating_sub(self.sealed.get()))
    }

    async fn seal(
        &self,
        aad: Vec<u8>,
        plaintext: wit_bindgen::StreamReader<u8>,
    ) -> Result<wit_bindgen::StreamReader<u8>, Error> {
        // Per the WIT contract, the input stream is fully drained even when
        // the call resolves with an error, so the caller's writer always
        // completes.
        let msg = drain_stream(plaintext).await;
        // Count this invocation against the algorithm's nonce budget, per
        // the minting interfaces' SHOULD-enforce contract.
        if let Some(budget) = self.cipher.nonce_budget() {
            if self.sealed.get() >= budget {
                return Err(Error::KeyExhausted);
            }
        }
        self.sealed.set(self.sealed.get() + 1);
        // The SP 800-38D SS8.2.2 RBG-based construction: a fresh random
        // nonce per seal, carried as the sealed message's prefix
        // (`nonce || ciphertext || tag`, per the minting interface docs).
        let mut sealed = vec![0u8; self.cipher.nonce_len()];
        getrandom::fill(&mut sealed).expect("WASI random source is always available");
        let body = self
            .cipher
            .encrypt(
                &sealed,
                Payload {
                    msg: &msg,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Other(format!("{} encryption failed", self.cipher.name())))?;
        sealed.extend(body);
        Ok(stream_of(sealed))
    }

    async fn open(
        &self,
        aad: Vec<u8>,
        sealed: wit_bindgen::StreamReader<u8>,
    ) -> Result<wit_bindgen::StreamReader<u8>, Error> {
        // Like `seal`: fully drain the input first; buffering the whole
        // message is inherent to `open` (no unverified plaintext may be
        // observable).
        let msg = drain_stream(sealed).await;
        // Any failure -- input too short to carry the wire format, a bad
        // tag, wrong key, wrong associated data -- reports
        // `authentication-failed` with no detail, per the WIT contract.
        if msg.len() < self.cipher.nonce_len() {
            return Err(Error::AuthenticationFailed);
        }
        let (nonce, body) = msg.split_at(self.cipher.nonce_len());
        let opened = self
            .cipher
            .decrypt(
                nonce,
                Payload {
                    msg: body,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::AuthenticationFailed)?;
        Ok(stream_of(opened))
    }

    fn algorithm_name(&self) -> String {
        self.cipher.name().to_string()
    }

    fn algorithm_length(&self) -> u32 {
        self.cipher.length_bits()
    }

    async fn export_key(&self) -> Result<Vec<u8>, Error> {
        if self.extractable {
            Ok(self.raw.to_vec())
        } else {
            Err(Error::NotExtractable)
        }
    }
}

// --- aes-gcm-internal-nonce (key minting) ----------------------------------------

impl AesGcmInternalNonceGuest for Component {
    async fn import_key(
        variant: AesVariant,
        raw: Vec<u8>,
        extractable: bool,
    ) -> Result<crate::exports::lann::webcrypto::aead_internal_nonce::InternalNonceKey, Error> {
        let key = into_internal_nonce_key(new_aes_gcm_key(variant, raw, extractable)?);
        Ok(crate::exports::lann::webcrypto::aead_internal_nonce::InternalNonceKey::new(key))
    }

    async fn generate_key(
        variant: AesVariant,
        extractable: bool,
    ) -> Result<crate::exports::lann::webcrypto::aead_internal_nonce::InternalNonceKey, Error> {
        let mut raw = vec![0u8; variant_len(variant)?];
        getrandom::fill(&mut raw).expect("WASI random source is always available");
        let key = into_internal_nonce_key(
            new_aes_gcm_key(variant, raw, extractable)
                .expect("generated key material always matches the variant"),
        );
        Ok(crate::exports::lann::webcrypto::aead_internal_nonce::InternalNonceKey::new(key))
    }
}

// --- xchacha20-poly1305-internal-nonce (key minting) ------------------------------

impl XChachaInternalNonceGuest for Component {
    async fn import_key(
        raw: Vec<u8>,
        extractable: bool,
    ) -> Result<crate::exports::lann::webcrypto::aead_internal_nonce::InternalNonceKey, Error> {
        let key = into_internal_nonce_key(new_xchacha_key(raw, extractable)?);
        Ok(crate::exports::lann::webcrypto::aead_internal_nonce::InternalNonceKey::new(key))
    }

    async fn generate_key(
        extractable: bool,
    ) -> Result<crate::exports::lann::webcrypto::aead_internal_nonce::InternalNonceKey, Error> {
        let mut raw = vec![0u8; CHACHA_KEY_LEN];
        getrandom::fill(&mut raw).expect("WASI random source is always available");
        let key = into_internal_nonce_key(
            new_xchacha_key(raw, extractable).expect("generated key material is always 32 bytes"),
        );
        Ok(crate::exports::lann::webcrypto::aead_internal_nonce::InternalNonceKey::new(key))
    }
}

// --- signature -----------------------------------------------------------------

impl SignatureGuest for Component {
    type VerifyingKey = VerifyingKey;
    type SigningKey = SigningKey;
}

/// An exported `verifying-key`: public material bound to its algorithm
/// (and, for ECDSA, its curve/digest variant) at minting.
pub struct VerifyingKey {
    public: SigPublic,
}

/// The public key backing a [`VerifyingKey`]. ECDSA arms exist for
/// *verification only* — secret-free, so exempt from the timing-channel
/// classes; ECDSA signing is class D and this provider never mints it.
enum SigPublic {
    Ed25519(ed25519_dalek::VerifyingKey),
    EcdsaP256(p256::ecdsa::VerifyingKey),
    EcdsaP384(p384::ecdsa::VerifyingKey),
}

impl SigPublic {
    fn name(&self) -> &'static str {
        match self {
            Self::Ed25519(_) => ED25519_NAME,
            Self::EcdsaP256(_) | Self::EcdsaP384(_) => ECDSA_NAME,
        }
    }

    fn curve(&self) -> Option<&'static str> {
        match self {
            Self::Ed25519(_) => None,
            Self::EcdsaP256(_) => Some("P-256"),
            Self::EcdsaP384(_) => Some("P-384"),
        }
    }

    fn hash(&self) -> Option<&'static str> {
        match self {
            Self::Ed25519(_) => None,
            Self::EcdsaP256(_) => Some("SHA-256"),
            Self::EcdsaP384(_) => Some("SHA-384"),
        }
    }
}

impl GuestVerifyingKey for VerifyingKey {
    async fn verify(&self, data: wit_bindgen::StreamReader<u8>, sig: Vec<u8>) -> Result<(), Error> {
        use p256::ecdsa::signature::Verifier as _;
        let bytes = drain_stream(data).await;
        let ok = match &self.public {
            SigPublic::Ed25519(key) => ed25519_dalek::Signature::from_slice(&sig)
                .and_then(|sig| key.verify_strict(&bytes, &sig))
                .is_ok(),
            SigPublic::EcdsaP256(key) => p256::ecdsa::Signature::from_slice(&sig)
                .and_then(|sig| key.verify(&bytes, &sig))
                .is_ok(),
            SigPublic::EcdsaP384(key) => p384::ecdsa::Signature::from_slice(&sig)
                .and_then(|sig| key.verify(&bytes, &sig))
                .is_ok(),
        };
        if ok {
            Ok(())
        } else {
            Err(Error::AuthenticationFailed)
        }
    }

    fn algorithm_name(&self) -> String {
        self.public.name().to_string()
    }

    fn algorithm_curve(&self) -> Option<String> {
        self.public.curve().map(str::to_string)
    }

    fn algorithm_hash(&self) -> Option<String> {
        self.public.hash().map(str::to_string)
    }

    async fn export_key(&self) -> Vec<u8> {
        match &self.public {
            SigPublic::Ed25519(key) => key.to_bytes().to_vec(),
            SigPublic::EcdsaP256(key) => key.to_encoded_point(false).as_bytes().to_vec(),
            SigPublic::EcdsaP384(key) => key.to_encoded_point(false).as_bytes().to_vec(),
        }
    }
}

/// An exported `signing-key`. This provider mints only Ed25519 signing keys
/// (constant-time by construction); ECDSA signing is class D and its
/// interface is not exported, so no ECDSA arm exists here.
pub struct SigningKey {
    private: ed25519_dalek::SigningKey,
    extractable: bool,
}

impl GuestSigningKey for SigningKey {
    async fn sign(&self, data: wit_bindgen::StreamReader<u8>) -> Result<Vec<u8>, Error> {
        use ed25519_dalek::Signer as _;
        // The WIT `err` case exists for operational keystore failures; this
        // implementation holds the material in-process, so it never errs.
        let bytes = drain_stream(data).await;
        Ok(self.private.sign(&bytes).to_bytes().to_vec())
    }

    fn verifying_key(&self) -> signature_iface::VerifyingKey {
        signature_iface::VerifyingKey::new(VerifyingKey {
            public: SigPublic::Ed25519(self.private.verifying_key()),
        })
    }

    fn algorithm_name(&self) -> String {
        ED25519_NAME.to_string()
    }

    fn algorithm_curve(&self) -> Option<String> {
        None
    }

    fn algorithm_hash(&self) -> Option<String> {
        None
    }

    fn extractable(&self) -> bool {
        self.extractable
    }

    async fn export_key(&self) -> Result<Vec<u8>, Error> {
        if self.extractable {
            Ok(self.private.to_bytes().to_vec())
        } else {
            Err(Error::NotExtractable)
        }
    }
}

// --- ed25519 (key minting) -----------------------------------------------------

impl Ed25519VerifyGuest for Component {
    async fn import_verifying_key(raw: Vec<u8>) -> Result<signature_iface::VerifyingKey, Error> {
        let bytes: &[u8; 32] = raw.as_slice().try_into().map_err(|_| {
            Error::InvalidKey(format!(
                "Ed25519 public keys are 32 bytes, got {} bytes",
                raw.len()
            ))
        })?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .map_err(|err| Error::InvalidKey(format!("invalid Ed25519 public key: {err}")))?;
        Ok(signature_iface::VerifyingKey::new(VerifyingKey {
            public: SigPublic::Ed25519(key),
        }))
    }
}

impl Ed25519SignGuest for Component {
    async fn import_signing_key(
        raw: Vec<u8>,
        extractable: bool,
    ) -> Result<signature_iface::SigningKey, Error> {
        let seed: &[u8; 32] = raw.as_slice().try_into().map_err(|_| {
            Error::InvalidKey(format!(
                "Ed25519 private keys are 32-byte seeds, got {} bytes",
                raw.len()
            ))
        })?;
        Ok(signature_iface::SigningKey::new(SigningKey {
            private: ed25519_dalek::SigningKey::from_bytes(seed),
            extractable,
        }))
    }

    async fn generate_key(extractable: bool) -> Result<signature_iface::SigningKey, Error> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("WASI random source is always available");
        Ok(signature_iface::SigningKey::new(SigningKey {
            private: ed25519_dalek::SigningKey::from_bytes(&seed),
            extractable,
        }))
    }
}

// --- ecdsa (verification-key minting only; signing is class D) ------------------

impl EcdsaVerifyGuest for Component {
    async fn import_verifying_key(
        variant: EcdsaVariant,
        raw: Vec<u8>,
    ) -> Result<signature_iface::VerifyingKey, Error> {
        let expected = match variant {
            EcdsaVariant::P256Sha256 => 65,
            EcdsaVariant::P384Sha384 => 97,
        };
        if raw.len() != expected || raw[0] != 0x04 {
            return Err(Error::InvalidKey(format!(
                "{variant:?} public keys are uncompressed SEC1 points ({expected} bytes, leading 0x04)"
            )));
        }
        let public = match variant {
            EcdsaVariant::P256Sha256 => p256::ecdsa::VerifyingKey::from_sec1_bytes(&raw)
                .map(SigPublic::EcdsaP256)
                .map_err(|err| Error::InvalidKey(format!("invalid P-256 public key: {err}")))?,
            EcdsaVariant::P384Sha384 => p384::ecdsa::VerifyingKey::from_sec1_bytes(&raw)
                .map(SigPublic::EcdsaP384)
                .map_err(|err| Error::InvalidKey(format!("invalid P-384 public key: {err}")))?,
        };
        Ok(signature_iface::VerifyingKey::new(VerifyingKey { public }))
    }
}
