//! The `aead-key` / `internal-nonce-key` material: an algorithm-bound cipher
//! plus raw key bytes, with the caller-nonce and internal-nonce seal/open
//! operations, validation, and the extractability gate.

use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use zeroize::Zeroizing;

use crate::{
    random_bytes, AesVariant, Error, RngError, AES_GCM_NAME, CHACHA20_POLY1305_NAME,
    XCHACHA20_POLY1305_NAME,
};

/// The length in bytes of a ChaCha20-Poly1305 key (either construction).
const CHACHA_KEY_LEN: usize = 32;

/// The cipher backing an [`AeadKeyMaterial`], bound to its algorithm at
/// minting. Only the WIT variant cases the Rust implementations serve
/// appear here: AES-192 is declined at minting (see the WIT `aes-variant`
/// doc).
#[derive(Clone)]
// Each AES variant is an expanded key schedule; the size skew between the
// AES-128 and AES-256 schedules is inherent and both live briefly per call.
#[allow(clippy::large_enum_variant)]
enum AeadCipher {
    Aes128Gcm(Aes128Gcm),
    Aes256Gcm(Aes256Gcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
    XChaCha20Poly1305(XChaCha20Poly1305),
}

impl AeadCipher {
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

/// The material behind an `aead.aead-key` or
/// `aead-internal-nonce.internal-nonce-key` resource: the ready-to-use
/// cipher bound to its algorithm at minting, the raw key bytes (zeroized on
/// drop), and the key's extractability.
///
/// The internal-nonce seal *bookkeeping* (the invocation count against
/// [`nonce_budget`](Self::nonce_budget)) deliberately lives in each
/// implementation, whose interior-mutability needs differ.
#[derive(Clone)]
pub struct AeadKeyMaterial {
    /// The cipher keyed by `raw`, bound to its algorithm at minting.
    cipher: AeadCipher,
    /// The raw key material, retained for `export-key` on extractable keys;
    /// zeroized on drop.
    raw: Zeroizing<Vec<u8>>,
    /// Whether `export-key` may return the raw material.
    extractable: bool,
}

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

impl AeadKeyMaterial {
    /// Import raw key material as the declared AES-GCM variant, per the
    /// `aes-gcm.import-key` contract: material whose length disagrees with
    /// the variant is `invalid-key`; AES-192 is `unsupported`.
    pub fn import_aes_gcm(
        variant: AesVariant,
        raw: Vec<u8>,
        extractable: bool,
    ) -> Result<Self, Error> {
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
        Ok(Self {
            cipher,
            raw: Zeroizing::new(raw),
            extractable,
        })
    }

    /// Generate a fresh random key of the declared AES-GCM variant. The
    /// inner error is `unsupported` for AES-192; the outer channel is
    /// entropy failure.
    pub fn generate_aes_gcm(
        variant: AesVariant,
        extractable: bool,
    ) -> Result<Result<Self, Error>, RngError> {
        let len = match variant {
            AesVariant::Aes128 => 16,
            AesVariant::Aes192 => {
                return Ok(Err(Error::Unsupported(
                    "AES-192 is not served by this implementation".into(),
                )))
            }
            AesVariant::Aes256 => 32,
        };
        Ok(Ok(Self::import_aes_gcm(
            variant,
            random_bytes(len)?,
            extractable,
        )
        .expect("generated key material always matches the variant")))
    }

    /// Import raw key material as an IETF ChaCha20-Poly1305 key (exactly 32
    /// bytes; anything else is `invalid-key`).
    pub fn import_chacha20_poly1305(raw: Vec<u8>, extractable: bool) -> Result<Self, Error> {
        check_chacha_key(CHACHA20_POLY1305_NAME, &raw)?;
        let cipher = AeadCipher::ChaCha20Poly1305(
            ChaCha20Poly1305::new_from_slice(&raw).expect("length checked"),
        );
        Ok(Self {
            cipher,
            raw: Zeroizing::new(raw),
            extractable,
        })
    }

    /// Generate a fresh random IETF ChaCha20-Poly1305 key.
    pub fn generate_chacha20_poly1305(extractable: bool) -> Result<Self, RngError> {
        Ok(
            Self::import_chacha20_poly1305(random_bytes(CHACHA_KEY_LEN)?, extractable)
                .expect("generated key material is always 32 bytes"),
        )
    }

    /// Import raw key material as an XChaCha20-Poly1305 key (exactly 32
    /// bytes; anything else is `invalid-key`).
    pub fn import_xchacha20_poly1305(raw: Vec<u8>, extractable: bool) -> Result<Self, Error> {
        check_chacha_key(XCHACHA20_POLY1305_NAME, &raw)?;
        let cipher = AeadCipher::XChaCha20Poly1305(
            XChaCha20Poly1305::new_from_slice(&raw).expect("length checked"),
        );
        Ok(Self {
            cipher,
            raw: Zeroizing::new(raw),
            extractable,
        })
    }

    /// Generate a fresh random XChaCha20-Poly1305 key.
    pub fn generate_xchacha20_poly1305(extractable: bool) -> Result<Self, RngError> {
        Ok(
            Self::import_xchacha20_poly1305(random_bytes(CHACHA_KEY_LEN)?, extractable)
                .expect("generated key material is always 32 bytes"),
        )
    }

    /// The algorithm name (`algorithm-name` on either key resource).
    pub fn name(&self) -> &'static str {
        match &self.cipher {
            AeadCipher::Aes128Gcm(_) | AeadCipher::Aes256Gcm(_) => AES_GCM_NAME,
            AeadCipher::ChaCha20Poly1305(_) => CHACHA20_POLY1305_NAME,
            AeadCipher::XChaCha20Poly1305(_) => XCHACHA20_POLY1305_NAME,
        }
    }

    /// The key length in bits (WebCrypto's `AesKeyAlgorithm.length`).
    pub fn length_bits(&self) -> u32 {
        match &self.cipher {
            AeadCipher::Aes128Gcm(_) => 128,
            AeadCipher::Aes256Gcm(_)
            | AeadCipher::ChaCha20Poly1305(_)
            | AeadCipher::XChaCha20Poly1305(_) => 256,
        }
    }

    /// The nonce length in bytes this key's algorithm specifies
    /// (`aead-key.nonce-size`, and the internal-nonce wire prefix).
    pub fn nonce_len(&self) -> usize {
        match &self.cipher {
            AeadCipher::XChaCha20Poly1305(_) => 24,
            _ => 12,
        }
    }

    /// The tag length in bytes every served algorithm trails its ciphertext
    /// with (`aead-key.tag-size`).
    pub fn tag_len(&self) -> usize {
        16
    }

    /// The internal-nonce seal budget for this key's algorithm: the WIT
    /// contract's 2^32-invocation bound for 12-byte-nonce algorithms (SP
    /// 800-38D §8.2.2's repeat-probability bound); `none` for 24-byte
    /// nonces, whose repeat probability is negligible at any realistic
    /// count.
    pub fn nonce_budget(&self) -> Option<u64> {
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

    /// Encrypt and authenticate `msg` under the caller's `nonce` with `aad`,
    /// returning `ciphertext ‖ tag` (the `aead-key.seal` contract minus the
    /// stream transport: nonce validation renders `invalid-nonce`,
    /// encryption failure `other`).
    pub fn seal(&self, nonce: &[u8], aad: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
        self.check_nonce(nonce)?;
        self.cipher
            .encrypt(nonce, Payload { msg, aad })
            .map_err(|_| Error::Other(format!("{} encryption failed", self.name())))
    }

    /// Decrypt and verify `msg` (`ciphertext ‖ tag`) under the caller's
    /// `nonce` and `aad` (the `aead-key.open` contract minus the stream
    /// transport). Any decryption failure — truncated input, bad tag, wrong
    /// key, wrong associated data — reports `authentication-failed` with no
    /// detail, per the WIT contract.
    pub fn open(&self, nonce: &[u8], aad: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
        self.check_nonce(nonce)?;
        self.cipher
            .decrypt(nonce, Payload { msg, aad })
            .map_err(|_| Error::AuthenticationFailed)
    }

    /// Encrypt and authenticate `msg` under a fresh random nonce with `aad`,
    /// returning the self-contained `nonce ‖ ciphertext ‖ tag` wire format
    /// (the SP 800-38D §8.2.2 RBG-based construction; the
    /// `internal-nonce-key.seal` contract minus the stream transport and
    /// the budget bookkeeping, which stays with the caller). The inner
    /// error is `other` on encryption failure; the outer channel is entropy
    /// failure.
    pub fn seal_internal(
        &self,
        aad: &[u8],
        msg: &[u8],
    ) -> Result<Result<Vec<u8>, Error>, RngError> {
        let mut sealed = vec![0u8; self.nonce_len()];
        getrandom::fill(&mut sealed)?;
        let body = match self.cipher.encrypt(&sealed, Payload { msg, aad }) {
            Ok(body) => body,
            Err(_) => {
                return Ok(Err(Error::Other(format!(
                    "{} encryption failed",
                    self.name()
                ))))
            }
        };
        sealed.extend(body);
        Ok(Ok(sealed))
    }

    /// Decrypt and verify a sealed message (`nonce ‖ ciphertext ‖ tag`)
    /// under `aad` (the `internal-nonce-key.open` contract minus the stream
    /// transport). Any failure — input too short to carry the wire format,
    /// a bad tag, wrong key, wrong associated data — reports
    /// `authentication-failed` with no detail, per the WIT contract.
    pub fn open_internal(&self, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, Error> {
        if sealed.len() < self.nonce_len() {
            return Err(Error::AuthenticationFailed);
        }
        let (nonce, body) = sealed.split_at(self.nonce_len());
        self.cipher
            .decrypt(nonce, Payload { msg: body, aad })
            .map_err(|_| Error::AuthenticationFailed)
    }

    /// The raw material, or `not-extractable` (the `export-key` contract on
    /// either key resource).
    ///
    /// The copy returned is *not* protected: see the note on
    /// [`crate`](crate#exported-material).
    pub fn export(&self) -> Result<Vec<u8>, Error> {
        if self.extractable {
            Ok(self.raw.to_vec())
        } else {
            Err(Error::NotExtractable)
        }
    }
}

// Debug is implemented by hand so key material can never reach logs: only
// the algorithm binding and extractability are printed, with the material
// redacted.
impl std::fmt::Debug for AeadKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AeadKeyMaterial")
            .field("algorithm", &self.name())
            .field("extractable", &self.extractable)
            .field("raw", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_import_validates_variant_and_length() {
        match AeadKeyMaterial::import_aes_gcm(AesVariant::Aes192, vec![0; 24], true) {
            Err(Error::Unsupported(_)) => {}
            _ => panic!("expected unsupported"),
        }
        match AeadKeyMaterial::import_aes_gcm(AesVariant::Aes256, vec![0; 16], true) {
            Err(Error::InvalidKey(msg)) => assert_eq!(
                msg,
                "Aes256 requires 32 bytes of key material, got 16 bytes"
            ),
            _ => panic!("expected invalid-key"),
        }
    }

    #[test]
    fn caller_nonce_round_trip_and_failures() {
        let key = AeadKeyMaterial::import_aes_gcm(AesVariant::Aes256, vec![1; 32], false).unwrap();
        let nonce = [2u8; 12];
        let sealed = key.seal(&nonce, b"aad", b"plaintext").unwrap();
        assert_eq!(sealed.len(), b"plaintext".len() + key.tag_len());
        assert_eq!(key.open(&nonce, b"aad", &sealed).unwrap(), b"plaintext");
        assert_eq!(
            key.open(&nonce, b"other aad", &sealed),
            Err(Error::AuthenticationFailed)
        );
        match key.seal(&[0; 16], b"", b"") {
            Err(Error::InvalidNonce(msg)) => {
                assert_eq!(msg, "AES-GCM requires a 12-byte nonce, got 16 bytes")
            }
            _ => panic!("expected invalid-nonce"),
        }
        assert_eq!(key.export(), Err(Error::NotExtractable));
    }

    #[test]
    fn internal_nonce_round_trip_and_wire_format() {
        let key = AeadKeyMaterial::generate_xchacha20_poly1305(true).unwrap();
        assert_eq!(key.nonce_len(), 24);
        assert_eq!(key.nonce_budget(), None);
        let sealed = key.seal_internal(b"aad", b"msg").unwrap().unwrap();
        assert_eq!(sealed.len(), 24 + 3 + 16);
        assert_eq!(key.open_internal(b"aad", &sealed).unwrap(), b"msg");
        // Too short to carry the wire format: fails closed.
        assert_eq!(
            key.open_internal(b"aad", &sealed[..10]),
            Err(Error::AuthenticationFailed)
        );
    }

    #[test]
    fn twelve_byte_nonce_algorithms_carry_the_budget() {
        let key = AeadKeyMaterial::generate_chacha20_poly1305(true).unwrap();
        assert_eq!(key.nonce_budget(), Some(1 << 32));
        let key = AeadKeyMaterial::generate_aes_gcm(AesVariant::Aes128, true)
            .unwrap()
            .unwrap();
        assert_eq!(key.nonce_budget(), Some(1 << 32));
        assert_eq!(key.length_bits(), 128);
    }
}
