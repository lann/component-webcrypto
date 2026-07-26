//! The exported `lann:webcrypto` resources and key-minting functions, backed
//! by RustCrypto (`hmac`/`sha2` for HMAC-SHA-256, `aes-gcm` for AES-GCM).
//!
//! - [`MacKey`] holds raw HMAC key material; `sign` and `verify` are
//!   one-shot HMAC-SHA-256 computations, stateless per call.
//! - [`AeadKey`] holds raw AES key material plus its schedule; `seal` and
//!   `open` are stateless per call.
//!
//! Byte `stream`s are the only bulk data path: incoming streams are drained
//! to completion (even when the operation resolves with an error, per the WIT
//! contract for `seal`/`open`), and outgoing streams are fed from a detached
//! task (`wit_bindgen::spawn`) after the export returns.

use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use hmac::Mac as _;

use crate::exports::lann::webcrypto::aead::{Guest as AeadGuest, GuestAeadKey};
use crate::exports::lann::webcrypto::aes_gcm::{AesVariant, Guest as AesGcmGuest};
use crate::exports::lann::webcrypto::hmac::Guest as HmacGuest;
use crate::exports::lann::webcrypto::mac::{self, Guest as MacGuest, GuestMacKey};
use crate::lann::webcrypto::types::Error;

/// The HMAC-SHA-256 state backing one `sign`/`verify` call.
type HmacSha256 = hmac::Hmac<sha2::Sha256>;

/// The `algorithm-name` reported by HMAC-SHA-256 keys and computations
/// (WebCrypto's `KeyAlgorithm.name`).
const HMAC_NAME: &str = "HMAC";

/// The `algorithm-hash` reported by HMAC-SHA-256 keys and computations
/// (WebCrypto's `HmacKeyAlgorithm.hash`).
const HMAC_SHA256_HASH: &str = "SHA-256";

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

/// An exported `mac-key`: raw HMAC key material bound to HMAC-SHA-256.
pub struct MacKey {
    raw: Vec<u8>,
    extractable: bool,
}

impl MacKey {
    /// Build the HMAC state for this key's material, folding in one entire
    /// drained stream.
    async fn hmac_over(&self, data: wit_bindgen::StreamReader<u8>) -> HmacSha256 {
        // HMAC accepts key material of any length, so this cannot fail for a
        // key that was accepted at import/generation time.
        let mut hmac = <HmacSha256 as hmac::Mac>::new_from_slice(&self.raw)
            .expect("HMAC accepts any key length");
        hmac.update(&drain_stream(data).await);
        hmac
    }
}

impl GuestMacKey for MacKey {
    async fn sign(&self, data: wit_bindgen::StreamReader<u8>) -> Vec<u8> {
        self.hmac_over(data).await.finalize().into_bytes().to_vec()
    }

    async fn verify(&self, data: wit_bindgen::StreamReader<u8>, tag: Vec<u8>) -> Result<(), Error> {
        // `verify_slice` compares in constant time, per the WIT contract.
        self.hmac_over(data)
            .await
            .verify_slice(&tag)
            .map_err(|_| Error::AuthenticationFailed)
    }

    fn algorithm_name(&self) -> String {
        HMAC_NAME.to_string()
    }

    fn algorithm_hash(&self) -> Option<String> {
        Some(HMAC_SHA256_HASH.to_string())
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

// --- hmac (key minting) --------------------------------------------------------

impl HmacGuest for Component {
    async fn import_hmac_sha256_key(raw: Vec<u8>, extractable: bool) -> Result<mac::MacKey, Error> {
        // RFC 2104 accepts any non-empty key length (longer-than-block keys
        // are hashed first); an empty key is rejected as `invalid-key`.
        if raw.is_empty() {
            return Err(Error::InvalidKey(
                "HMAC key material must be non-empty".into(),
            ));
        }
        Ok(mac::MacKey::new(MacKey { raw, extractable }))
    }

    async fn generate_hmac_sha256_key(extractable: bool) -> mac::MacKey {
        let mut raw = vec![0u8; 32];
        getrandom::fill(&mut raw).expect("WASI random source is always available");
        mac::MacKey::new(MacKey { raw, extractable })
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
