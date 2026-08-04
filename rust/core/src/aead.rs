//! The `aead-key` material: an algorithm-bound cipher plus raw key bytes,
//! with the seal/open operations, validation, and the extractability gate.

use aes_gcm::aead::{Aead as _, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use zeroize::Zeroizing;

use crate::{
    aes192_unsupported, not_permitted, random_bytes, AeadPolicy, AesVariant, Error, RngError,
    AES_GCM_NAME,
};

/// The cipher backing an [`AeadKeyMaterial`], bound to its algorithm at
/// minting. Only the WIT variant cases the Rust implementations serve
/// appear here: AES-192 is declined at minting (see the WIT `aes-variant`
/// doc).
// Each AES variant is an expanded key schedule; the size skew between the
// AES-128 and AES-256 schedules is inherent and both live briefly per call.
#[allow(clippy::large_enum_variant)]
enum AeadCipher {
    Aes128Gcm(Aes128Gcm),
    Aes256Gcm(Aes256Gcm),
}

impl AeadCipher {
    fn encrypt(&self, nonce: &[u8], payload: Payload<'_, '_>) -> aes_gcm::aead::Result<Vec<u8>> {
        match self {
            Self::Aes128Gcm(c) => c.encrypt(aes_gcm::Nonce::from_slice(nonce), payload),
            Self::Aes256Gcm(c) => c.encrypt(aes_gcm::Nonce::from_slice(nonce), payload),
        }
    }

    fn decrypt(&self, nonce: &[u8], payload: Payload<'_, '_>) -> aes_gcm::aead::Result<Vec<u8>> {
        match self {
            Self::Aes128Gcm(c) => c.decrypt(aes_gcm::Nonce::from_slice(nonce), payload),
            Self::Aes256Gcm(c) => c.decrypt(aes_gcm::Nonce::from_slice(nonce), payload),
        }
    }
}

/// The material behind an `aead.aead-key` resource: the ready-to-use
/// cipher bound to its algorithm at minting, the raw key bytes (zeroized on
/// drop), and the key's extractability.
pub struct AeadKeyMaterial {
    /// The cipher keyed by `raw`, bound to its algorithm at minting.
    cipher: AeadCipher,
    /// The raw key material, retained for `export-key-raw` on extractable keys;
    /// zeroized on drop.
    raw: Zeroizing<Vec<u8>>,
    /// The mint-time policy: usages and extractability.
    policy: AeadPolicy,
}

impl AeadKeyMaterial {
    /// Import raw key material as the declared AES-GCM variant, per the
    /// `aes-gcm.import-key-raw` contract: material whose length disagrees with
    /// the variant is `invalid-key`; AES-192 is `unsupported`.
    pub fn import_aes_gcm(
        variant: AesVariant,
        raw: Vec<u8>,
        policy: AeadPolicy,
    ) -> Result<Self, Error> {
        policy.check_useful()?;
        let expected = variant.served_key_len()?;
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
            AesVariant::Aes192 => unreachable!("declined by served_key_len"),
            AesVariant::Aes256 => {
                AeadCipher::Aes256Gcm(Aes256Gcm::new_from_slice(&raw).expect("length checked"))
            }
        };
        Ok(Self {
            cipher,
            raw: Zeroizing::new(raw),
            policy,
        })
    }

    /// Import an RFC 7517 `oct` JWK as an AES-GCM key of the declared
    /// variant, per the `aes-gcm.import-key-jwk` contract: the JWK's
    /// material-bearing fields are validated (`alg` against the variant's
    /// `A*GCM` name), then the decoded material is subject to
    /// [`import_aes_gcm`](Self::import_aes_gcm)'s contract.
    pub fn import_aes_gcm_jwk(
        variant: AesVariant,
        jwk: &str,
        policy: AeadPolicy,
    ) -> Result<Self, Error> {
        let alg = match variant {
            AesVariant::Aes128 => "A128GCM",
            AesVariant::Aes192 => return Err(aes192_unsupported()),
            AesVariant::Aes256 => "A256GCM",
        };
        let raw = crate::jwk::parse_oct(jwk, alg, policy.extractable)?;
        Self::import_aes_gcm(variant, raw, policy)
    }

    /// The key as an `oct` JWK (the `aead-key.export-key-jwk` contract):
    /// the same extractability gate as [`export`](Self::export).
    pub fn export_jwk(&self) -> Result<String, Error> {
        let alg = match &self.cipher {
            AeadCipher::Aes128Gcm(_) => "A128GCM",
            AeadCipher::Aes256Gcm(_) => "A256GCM",
        };
        Ok(crate::jwk::build_oct(&self.export()?, alg))
    }

    /// Generate a fresh random key of the declared AES-GCM variant. The
    /// inner error is `unsupported` for AES-192; the outer channel is
    /// entropy failure.
    pub fn generate_aes_gcm(
        variant: AesVariant,
        policy: AeadPolicy,
    ) -> Result<Result<Self, Error>, RngError> {
        if let Err(err) = policy.check_useful() {
            return Ok(Err(err));
        }
        let len = match variant.served_key_len() {
            Ok(len) => len,
            Err(err) => return Ok(Err(err)),
        };
        Ok(Ok(Self::import_aes_gcm(
            variant,
            random_bytes(len)?,
            policy,
        )
        .expect("generated key material always matches the variant")))
    }

    /// The algorithm name (`algorithm-name` on the key resource).
    pub fn name(&self) -> &'static str {
        AES_GCM_NAME
    }

    /// The key length in bits (WebCrypto's `AesKeyAlgorithm.length`).
    pub fn length_bits(&self) -> u32 {
        match &self.cipher {
            AeadCipher::Aes128Gcm(_) => 128,
            AeadCipher::Aes256Gcm(_) => 256,
        }
    }

    /// The material's length in bytes.
    pub fn byte_len(&self) -> usize {
        self.raw.len()
    }

    /// The nonce length in bytes this key's algorithm specifies
    /// (`aead-key.nonce-size`).
    pub fn nonce_len(&self) -> usize {
        12
    }

    /// The default tag length in bytes every served algorithm trails its
    /// ciphertext with when `seal` is called with no explicit tag size
    /// (`aead-key.tag-size`).
    pub fn tag_len(&self) -> usize {
        16
    }

    /// Resolve and validate a per-call tag size for this key's algorithm:
    /// GCM accepts [`crate::gcm::GCM_TAG_SIZES`]. `None` is the algorithm
    /// default.
    fn check_tag_size(&self, tag_size: Option<u8>) -> Result<usize, Error> {
        crate::gcm::check_tag_size(tag_size)
    }

    /// Validate a caller nonce's length for this key's algorithm, rendering
    /// the WIT `invalid-nonce` error: GCM accepts 12 to 128 bytes inclusive
    /// (the `aes-gcm` minting contract's portable window).
    fn check_nonce(&self, nonce: &[u8]) -> Result<(), Error> {
        if (12..=128).contains(&nonce.len()) {
            Ok(())
        } else {
            Err(Error::InvalidNonce(format!(
                "AES-GCM nonces are 12 to 128 bytes inclusive, got {} bytes",
                nonce.len()
            )))
        }
    }

    /// Whether `(nonce, tag_len)` is the standard GCM parameter point the
    /// `aes-gcm` crate serves; anything else routes to the general path
    /// ([`crate::gcm`]).
    fn is_standard_point(&self, nonce: &[u8], tag_len: usize) -> bool {
        nonce.len() == self.nonce_len() && tag_len == 16
    }

    /// The general-path AES cipher, keyed from this key's material.
    fn general_gcm(&self) -> crate::gcm::GcmAes {
        crate::gcm::GcmAes::new(&self.raw).expect("AES key length fixed at minting")
    }

    /// Encrypt and authenticate `msg` under the caller's `nonce` with `aad`
    /// and a `tag_size`-byte tag (`None` = the algorithm default),
    /// returning `ciphertext ‖ tag` (the `aead-key.seal` contract minus the
    /// stream transport: nonce validation renders `invalid-nonce`, an
    /// unserved tag size `unsupported`, encryption failure `other`).
    pub fn seal(
        &self,
        nonce: &[u8],
        aad: &[u8],
        tag_size: Option<u8>,
        msg: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if !self.policy.seal {
            return Err(not_permitted("seal"));
        }
        self.seal_checked(nonce, aad, tag_size, msg)
    }

    /// The seal computation behind both `seal` and `wrap`, after their
    /// respective grant checks.
    fn seal_checked(
        &self,
        nonce: &[u8],
        aad: &[u8],
        tag_size: Option<u8>,
        msg: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.check_nonce(nonce)?;
        let tag_len = self.check_tag_size(tag_size)?;
        if self.is_standard_point(nonce, tag_len) {
            self.cipher
                .encrypt(nonce, Payload { msg, aad })
                .map_err(|_| Error::Other(format!("{} encryption failed", self.name())))
        } else {
            Ok(self.general_gcm().seal(nonce, aad, tag_len, msg))
        }
    }

    /// Decrypt and verify `msg` (`ciphertext ‖ tag`, with a `tag_size`-byte
    /// tag; `None` = the algorithm default) under the caller's `nonce` and
    /// `aad` (the `aead-key.open` contract minus the stream transport). Any
    /// decryption failure — truncated input, bad tag, wrong key, wrong
    /// associated data — reports `authentication-failed` with no detail,
    /// per the WIT contract.
    pub fn open(
        &self,
        nonce: &[u8],
        aad: &[u8],
        tag_size: Option<u8>,
        msg: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if !self.policy.open {
            return Err(not_permitted("open"));
        }
        self.open_checked(nonce, aad, tag_size, msg)
    }

    /// The open computation behind both `open` and `unwrap`, after their
    /// respective grant checks.
    fn open_checked(
        &self,
        nonce: &[u8],
        aad: &[u8],
        tag_size: Option<u8>,
        msg: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.check_nonce(nonce)?;
        let tag_len = self.check_tag_size(tag_size)?;
        if self.is_standard_point(nonce, tag_len) {
            self.cipher
                .decrypt(nonce, Payload { msg, aad })
                .map_err(|_| Error::AuthenticationFailed)
        } else {
            self.general_gcm().open(nonce, aad, tag_len, msg)
        }
    }

    /// Encrypt and authenticate serialized key material (the
    /// `aead-key.wrap` contract): `seal`'s computation exactly — for
    /// raw-format input, byte-identical to sealing the exported bytes —
    /// behind the `wrap` grant.
    pub fn wrap(
        &self,
        nonce: &[u8],
        aad: &[u8],
        tag_size: Option<u8>,
        input: crate::WrapInputMaterial,
    ) -> Result<Vec<u8>, Error> {
        if !self.policy.wrap {
            return Err(not_permitted("wrap"));
        }
        self.seal_checked(nonce, aad, tag_size, &input.into_bytes())
    }

    /// Decrypt and verify wrapped key material into an unwrap intermediate
    /// (the `aead-key.unwrap` contract, verified eagerly): any decryption
    /// failure reports `authentication-failed` with no detail.
    pub fn unwrap_wrapped(
        &self,
        nonce: &[u8],
        aad: &[u8],
        tag_size: Option<u8>,
        wrapped: &[u8],
    ) -> Result<crate::UnwrapInputMaterial, Error> {
        if !self.policy.unwrap {
            return Err(not_permitted("unwrap"));
        }
        self.open_checked(nonce, aad, tag_size, wrapped)
            .map(crate::UnwrapInputMaterial::new)
    }

    /// Whether the key material may be exported (the `extractable` getter
    /// on the key resource).
    pub fn extractable(&self) -> bool {
        self.policy.extractable
    }

    /// Whether the key permits `seal` (`can-seal` on the key resource).
    pub fn can_seal(&self) -> bool {
        self.policy.seal
    }

    /// Whether the key permits `open` (`can-open`).
    pub fn can_open(&self) -> bool {
        self.policy.open
    }

    /// Whether the key permits `wrap` (`aead-key.can-wrap`).
    pub fn can_wrap(&self) -> bool {
        self.policy.wrap
    }

    /// Whether the key permits unwrapping (`aead-key.can-unwrap`).
    pub fn can_unwrap(&self) -> bool {
        self.policy.unwrap
    }

    /// The raw material, or `not-extractable` (the `export-key-raw` contract on
    /// the key resource).
    ///
    /// The copy returned is *not* protected: see the note on
    /// [`crate`](crate#exported-material).
    pub fn export(&self) -> Result<Vec<u8>, Error> {
        if self.policy.extractable {
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
            .field("policy", &self.policy)
            .field("raw", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A full grant, non-extractable.
    fn ap() -> AeadPolicy {
        AeadPolicy {
            seal: true,
            open: true,
            wrap: true,
            unwrap: true,
            extractable: false,
        }
    }

    /// A full grant, extractable.
    fn xp() -> AeadPolicy {
        AeadPolicy {
            extractable: true,
            ..ap()
        }
    }

    #[test]
    fn aes_import_validates_variant_and_length() {
        match AeadKeyMaterial::import_aes_gcm(AesVariant::Aes192, vec![0; 24], xp()) {
            Err(Error::Unsupported(_)) => {}
            _ => panic!("expected unsupported"),
        }
        match AeadKeyMaterial::import_aes_gcm(AesVariant::Aes256, vec![0; 16], xp()) {
            Err(Error::InvalidKey(msg)) => assert_eq!(
                msg,
                "Aes256 requires 32 bytes of key material, got 16 bytes"
            ),
            _ => panic!("expected invalid-key"),
        }
    }

    #[test]
    fn caller_nonce_round_trip_and_failures() {
        let key = AeadKeyMaterial::import_aes_gcm(AesVariant::Aes256, vec![1; 32], ap()).unwrap();
        let nonce = [2u8; 12];
        let sealed = key.seal(&nonce, b"aad", None, b"plaintext").unwrap();
        assert_eq!(sealed.len(), b"plaintext".len() + key.tag_len());
        assert_eq!(
            key.open(&nonce, b"aad", None, &sealed).unwrap(),
            b"plaintext"
        );
        assert_eq!(
            key.open(&nonce, b"other aad", None, &sealed),
            Err(Error::AuthenticationFailed)
        );
        match key.seal(&[], b"", None, b"") {
            Err(Error::InvalidNonce(msg)) => {
                assert_eq!(
                    msg,
                    "AES-GCM nonces are 12 to 128 bytes inclusive, got 0 bytes"
                )
            }
            _ => panic!("expected invalid-nonce"),
        }
        for len in [11usize, 129] {
            assert!(matches!(
                key.seal(&vec![0u8; len], b"", None, b""),
                Err(Error::InvalidNonce(_))
            ));
            assert!(matches!(
                key.open(&vec![0u8; len], b"", None, &sealed),
                Err(Error::InvalidNonce(_))
            ));
        }
        assert_eq!(key.export(), Err(Error::NotExtractable));
    }

    /// The full GCM parameter space on one key: a non-standard nonce
    /// length routes to the general path and round-trips, a truncated tag
    /// round-trips and fails at the wrong declared size, and out-of-set
    /// sizes are declined.
    #[test]
    fn full_parameter_space_on_one_key() {
        let key = AeadKeyMaterial::import_aes_gcm(AesVariant::Aes256, vec![1; 32], ap()).unwrap();
        let sealed = key.seal(&[7u8; 16], b"aad", None, b"msg").unwrap();
        assert_eq!(key.open(&[7u8; 16], b"aad", None, &sealed).unwrap(), b"msg");
        assert_eq!(
            key.open(&[8u8; 16], b"aad", None, &sealed),
            Err(Error::AuthenticationFailed)
        );

        let short = key.seal(&[7u8; 12], b"aad", Some(4), b"msg").unwrap();
        assert_eq!(short.len(), 3 + 4);
        assert_eq!(
            key.open(&[7u8; 12], b"aad", Some(4), &short).unwrap(),
            b"msg"
        );
        assert_eq!(
            key.open(&[7u8; 12], b"aad", None, &short),
            Err(Error::AuthenticationFailed)
        );
        assert!(matches!(
            key.seal(&[7u8; 12], b"", Some(5), b""),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn generated_key_reports_its_parameters() {
        let key = AeadKeyMaterial::generate_aes_gcm(AesVariant::Aes128, xp())
            .unwrap()
            .unwrap();
        assert_eq!(key.length_bits(), 128);
        assert_eq!(key.nonce_len(), 12);
        assert_eq!(key.tag_len(), 16);
        assert_eq!(key.name(), AES_GCM_NAME);
    }
}
