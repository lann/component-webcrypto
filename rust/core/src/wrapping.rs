//! The wrapping intermediates (`wrapping.wrap-input` / `unwrap-input`), the
//! `key-wrap.kw-key` material (AES-KW, RFC 3394), and the unwrap mints:
//! the decrypt-then-mint half of key wrapping, shared by both Rust
//! implementations so the wire formats, domains, and error cases cannot
//! diverge.
//!
//! Both Rust implementations decrypt and verify eagerly at `unwrap` (the
//! WIT's verification-timing latitude exists for platform hosts whose
//! `unwrapKey` is atomic), so an [`UnwrapInputMaterial`] always holds
//! verified-or-unauthenticated-by-kind plaintext, never wrapped bytes.
//!
//! The load-bearing rules here:
//!
//! - An unwrap mint's `invalid-key` message never carries the decrypted
//!   bytes (the WIT error contract: error strings never carry material the
//!   caller does not already hold) — every parse failure is redacted to a
//!   fixed message by [`redact_invalid_key`].
//! - The JWK-reading unwrap mints validate `use`/`key_ops` in the caller's
//!   stead (the WIT JWK contract), via [`crate::jwk::check_unwrap_members`].
//! - AES-KW pads JWK-formatted input with ASCII spaces to a multiple of 8
//!   (keyed on the [`WrapFormat`] the intermediate carries) and folds every
//!   malformed-length `unwrap` input into `authentication-failed`,
//!   indistinguishable from an ICV failure.

use aes::{Aes128, Aes256};
use aes_kw::Kek;
use zeroize::Zeroizing;

use crate::jwk::{check_unwrap_members, UseFamily};
use crate::{
    not_permitted, random_bytes, AeadKeyMaterial, AeadPolicy, AesVariant, AgreementPolicy,
    AgreementSecretMaterial, CipherKeyMaterial, CipherMode, CipherPolicy, DeriveInputMaterial,
    DerivePolicy, Error, IkmMaterial, KwPolicy, MacKeyMaterial, MacPolicy, PasswordMaterial,
    RngError, Sha2Variant, SigningKeyMaterial, SigningPolicy, AES_KW_NAME,
};

/// The serialization a `wrap-input` was constructed with
/// (`to-wrap-input-raw`/`-jwk`/`-pkcs8`). Format-specific wrapping rules
/// key on it: AES-KW space-pads `Jwk` input and nothing else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WrapFormat {
    Raw,
    Jwk,
    Pkcs8,
}

/// The material behind a `wrapping.wrap-input` resource: one key's
/// serialized material awaiting encryption under a wrapping key, plus the
/// format chosen at construction. Consumed by value by the wrap
/// operations, on failure as on success.
pub struct WrapInputMaterial {
    format: WrapFormat,
    bytes: Zeroizing<Vec<u8>>,
}

impl WrapInputMaterial {
    /// Box serialized key material for wrapping. Callers construct this
    /// from the material's own export operations, so the extractability
    /// gate has already run.
    pub fn new(format: WrapFormat, bytes: Vec<u8>) -> Self {
        Self {
            format,
            bytes: Zeroizing::new(bytes),
        }
    }

    /// The serialized material's length in bytes (retention accounting).
    pub fn byte_len(&self) -> usize {
        self.bytes.len()
    }

    /// Consume into the format tag and the serialized bytes.
    fn into_parts(self) -> (WrapFormat, Zeroizing<Vec<u8>>) {
        (self.format, self.bytes)
    }

    /// Consume into the bytes alone (the AEAD and cipher wrap operations,
    /// which apply no format-specific rule).
    pub(crate) fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        self.bytes
    }
}

// Debug is implemented by hand so key material can never reach logs.
impl std::fmt::Debug for WrapInputMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WrapInputMaterial")
            .field("format", &self.format)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

/// The material behind a `wrapping.unwrap-input` resource: decrypted key
/// material awaiting a typed mint. Consumed by value by exactly one mint,
/// on failure as on success.
pub struct UnwrapInputMaterial {
    bytes: Zeroizing<Vec<u8>>,
}

impl UnwrapInputMaterial {
    /// Box decrypted material for a typed mint.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }

    /// Box already-zeroizing decrypted material for a typed mint (the
    /// `public-encryption` unwrap path, whose decrypt buffer is
    /// zeroizing from birth).
    #[cfg(not(target_family = "wasm"))]
    pub(crate) fn from_zeroizing(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self { bytes }
    }

    /// The decrypted material's length in bytes (retention accounting).
    pub fn byte_len(&self) -> usize {
        self.bytes.len()
    }

    /// Consume into the decrypted bytes.
    fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        self.bytes
    }
}

// Debug is implemented by hand so key material can never reach logs.
impl std::fmt::Debug for UnwrapInputMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnwrapInputMaterial")
            .field("bytes", &"<redacted>")
            .finish()
    }
}

/// The keyed AES-KW key-encryption key.
// The size skew between the AES-128 and AES-256 key schedules is inherent.
#[allow(clippy::large_enum_variant)]
enum KwKek {
    Aes128(Kek<Aes128>),
    Aes256(Kek<Aes256>),
}

/// The material behind a `key-wrap.kw-key` resource: the keyed AES-KW
/// cipher, the raw key bytes (zeroized on drop), and the mint-time policy.
pub struct KwKeyMaterial {
    kek: KwKek,
    raw: Zeroizing<Vec<u8>>,
    policy: KwPolicy,
}

/// The fixed message every out-of-domain `kw-key.wrap` input renders: the
/// error string never describes the material itself beyond its length
/// class.
const KW_WRAP_DOMAIN: &str =
    "AES-KW wraps serialized material of a multiple of 8 bytes, at least 16";

impl KwKeyMaterial {
    /// Import raw key material as the declared AES variant (the
    /// `aes-kw.import-key-raw` contract): material whose length disagrees
    /// with the variant is `invalid-key`; AES-192 is `unsupported`.
    pub fn import(variant: AesVariant, raw: Vec<u8>, policy: KwPolicy) -> Result<Self, Error> {
        policy.check_useful()?;
        use aes::cipher::generic_array::GenericArray;
        type Make = fn(&[u8]) -> KwKek;
        let (expected, make): (usize, Make) = match variant {
            AesVariant::Aes128 => (16, |raw| {
                KwKek::Aes128(Kek::new(GenericArray::from_slice(raw)))
            }),
            AesVariant::Aes192 => {
                return Err(Error::Unsupported(
                    "AES-192 is not served by this implementation".into(),
                ))
            }
            AesVariant::Aes256 => (32, |raw| {
                KwKek::Aes256(Kek::new(GenericArray::from_slice(raw)))
            }),
        };
        if raw.len() != expected {
            return Err(Error::InvalidKey(format!(
                "{variant:?} requires {expected} bytes of key material, got {} bytes",
                raw.len()
            )));
        }
        Ok(Self {
            kek: make(&raw),
            raw: Zeroizing::new(raw),
            policy,
        })
    }

    /// Import an RFC 7517 `oct` JWK (the `aes-kw.import-key-jwk` contract):
    /// `alg`, when present, must name the declared variant
    /// (`A128KW`/`A192KW`/`A256KW`); the decoded material is then subject
    /// to [`import`](Self::import)'s contract.
    pub fn import_jwk(variant: AesVariant, jwk: &str, policy: KwPolicy) -> Result<Self, Error> {
        let raw = crate::jwk::parse_oct(jwk, Self::jwk_alg(variant)?, policy.extractable)?;
        Self::import(variant, raw, policy)
    }

    /// Generate a fresh random key of the declared variant. The inner
    /// error is `unsupported` for AES-192; the outer channel is entropy
    /// failure.
    pub fn generate(
        variant: AesVariant,
        policy: KwPolicy,
    ) -> Result<Result<Self, Error>, RngError> {
        if let Err(err) = policy.check_useful() {
            return Ok(Err(err));
        }
        let len = match variant {
            AesVariant::Aes128 => 16,
            AesVariant::Aes192 => {
                return Ok(Err(Error::Unsupported(
                    "AES-192 is not served by this implementation".into(),
                )))
            }
            AesVariant::Aes256 => 32,
        };
        Ok(Ok(Self::import(variant, random_bytes(len)?, policy)
            .expect(
                "generated key material always matches the variant",
            )))
    }

    /// The registered JOSE `alg` for the declared variant, or the AES-192
    /// decline.
    fn jwk_alg(variant: AesVariant) -> Result<&'static str, Error> {
        match variant {
            AesVariant::Aes128 => Ok("A128KW"),
            AesVariant::Aes192 => Err(Error::Unsupported(
                "AES-192 is not served by this implementation".into(),
            )),
            AesVariant::Aes256 => Ok("A256KW"),
        }
    }

    /// Encrypt serialized key material (the `kw-key.wrap` contract):
    /// JWK-formatted input is first padded with ASCII spaces (0x20) to a
    /// multiple of 8; input outside RFC 3394's domain (a multiple of 8
    /// bytes, at least 16) fails `invalid-key`.
    pub fn wrap(&self, input: WrapInputMaterial) -> Result<Vec<u8>, Error> {
        if !self.policy.wrap {
            return Err(not_permitted("wrap"));
        }
        let (format, bytes) = input.into_parts();
        let mut payload = bytes;
        if format == WrapFormat::Jwk && !payload.len().is_multiple_of(8) {
            let pad = 8 - payload.len() % 8;
            payload.extend(std::iter::repeat_n(0x20u8, pad));
        }
        if payload.is_empty() || !payload.len().is_multiple_of(8) || payload.len() < 16 {
            return Err(Error::InvalidKey(format!(
                "{KW_WRAP_DOMAIN}; got {} bytes",
                payload.len()
            )));
        }
        let mut out = vec![0u8; payload.len() + 8];
        let result = match &self.kek {
            KwKek::Aes128(kek) => kek.wrap(&payload, &mut out),
            KwKek::Aes256(kek) => kek.wrap(&payload, &mut out),
        };
        result.map_err(|_| Error::Other("AES-KW wrapping failed".into()))?;
        Ok(out)
    }

    /// Decrypt and integrity-check wrapped key material (the
    /// `kw-key.unwrap` contract). Every failure — input outside the
    /// wrapped-form domain (a multiple of 8 bytes, at least 24) or a bad
    /// ICV — reports `authentication-failed` with no detail.
    pub fn unwrap(&self, wrapped: &[u8]) -> Result<UnwrapInputMaterial, Error> {
        if !self.policy.unwrap {
            return Err(not_permitted("unwrap"));
        }
        if wrapped.len() < 24 || !wrapped.len().is_multiple_of(8) {
            return Err(Error::AuthenticationFailed);
        }
        let mut out = Zeroizing::new(vec![0u8; wrapped.len() - 8]);
        let result = match &self.kek {
            KwKek::Aes128(kek) => kek.unwrap(wrapped, &mut out),
            KwKek::Aes256(kek) => kek.unwrap(wrapped, &mut out),
        };
        result.map_err(|_| Error::AuthenticationFailed)?;
        Ok(UnwrapInputMaterial { bytes: out })
    }

    /// The registry `algorithm-name`, `"AES-KW"`.
    pub fn name(&self) -> &'static str {
        AES_KW_NAME
    }

    /// The key length in bits.
    pub fn length_bits(&self) -> u32 {
        (self.raw.len() * 8) as u32
    }

    /// The material's length in bytes.
    pub fn byte_len(&self) -> usize {
        self.raw.len()
    }

    /// Whether the key material may be exported (the `extractable` getter).
    pub fn extractable(&self) -> bool {
        self.policy.extractable
    }

    /// Whether the key permits `wrap` (`can-wrap`).
    pub fn can_wrap(&self) -> bool {
        self.policy.wrap
    }

    /// Whether the key permits `unwrap` (`can-unwrap`).
    pub fn can_unwrap(&self) -> bool {
        self.policy.unwrap
    }

    /// The raw material, behind the extractability gate.
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

    /// The key as an `oct` JWK, behind the same gate as
    /// [`export`](Self::export).
    pub fn export_jwk(&self) -> Result<String, Error> {
        let alg = if self.raw.len() == 16 {
            "A128KW"
        } else {
            "A256KW"
        };
        Ok(crate::jwk::build_oct(&self.export()?, alg))
    }
}

// Debug is implemented by hand so key material can never reach logs.
impl std::fmt::Debug for KwKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KwKeyMaterial")
            .field("algorithm", &self.name())
            .field("policy", &self.policy)
            .field("raw", &"<redacted>")
            .finish()
    }
}

/// Mint a `kw-key` from a parameterized derivation (the `aes-kw.derive-key`
/// contract, following `aes-gcm.derive-key`).
pub fn derive_kw_key(
    variant: AesVariant,
    input: &DeriveInputMaterial,
    policy: KwPolicy,
) -> Result<KwKeyMaterial, Error> {
    policy.check_useful()?;
    let bits = match variant {
        AesVariant::Aes128 => 128,
        AesVariant::Aes192 => {
            return Err(Error::Unsupported(
                "AES-192 is not served by this implementation".into(),
            ))
        }
        AesVariant::Aes256 => 256,
    };
    let raw = input.derive_for_key(bits, policy.extractable)?;
    KwKeyMaterial::import(variant, raw.to_vec(), policy)
}

/// Redact an unwrap mint's `invalid-key` message to a fixed string: the
/// parse input is decrypted material the caller must never see, and the
/// reused import paths' diagnostics echo values from it.
fn redact_invalid_key<T>(what: &str, result: Result<T, Error>) -> Result<T, Error> {
    result.map_err(|err| match err {
        Error::InvalidKey(_) => {
            Error::InvalidKey(format!("unwrapped material is not a valid {what}"))
        }
        other => other,
    })
}

/// Decode an unwrap input as UTF-8 JWK text, with the fixed message on
/// failure.
fn unwrap_jwk_text(what: &str, bytes: &[u8]) -> Result<String, Error> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| Error::InvalidKey(format!("unwrapped material is not a valid {what}")))
}

/// One JWK-reading unwrap mint's shared prelude: grants first (the import
/// paths' ordering), then UTF-8, then the unwrap-path `use`/`key_ops`
/// checks against the mint's granted usages.
fn unwrap_jwk_prelude(
    what: &str,
    check_useful: Result<(), Error>,
    input: UnwrapInputMaterial,
    granted: &[&'static str],
    family: UseFamily,
) -> Result<String, Error> {
    check_useful?;
    let bytes = input.into_bytes();
    let text = unwrap_jwk_text(what, &bytes)?;
    check_unwrap_members(&text, granted, family)?;
    Ok(text)
}

/// `hmac-sha2.unwrap-key-raw`.
pub fn unwrap_mac_key(
    variant: Sha2Variant,
    input: UnwrapInputMaterial,
    policy: MacPolicy,
) -> Result<MacKeyMaterial, Error> {
    redact_invalid_key(
        "HMAC key",
        MacKeyMaterial::import(variant, input.into_bytes().to_vec(), policy),
    )
}

/// `hmac-sha1.unwrap-key-raw`.
pub fn unwrap_mac_key_sha1(
    input: UnwrapInputMaterial,
    policy: MacPolicy,
) -> Result<MacKeyMaterial, Error> {
    redact_invalid_key(
        "HMAC key",
        MacKeyMaterial::import_sha1(input.into_bytes().to_vec(), policy),
    )
}

/// `hmac-sha2.unwrap-key-jwk`.
pub fn unwrap_mac_key_jwk(
    variant: Sha2Variant,
    input: UnwrapInputMaterial,
    policy: MacPolicy,
) -> Result<MacKeyMaterial, Error> {
    let text = unwrap_jwk_prelude(
        "HMAC JWK",
        policy.check_useful(),
        input,
        &policy.webcrypto_usages(),
        UseFamily::Sig,
    )?;
    redact_invalid_key(
        "HMAC JWK",
        MacKeyMaterial::import_jwk(variant, &text, policy),
    )
}

/// `hmac-sha1.unwrap-key-jwk`.
pub fn unwrap_mac_key_jwk_sha1(
    input: UnwrapInputMaterial,
    policy: MacPolicy,
) -> Result<MacKeyMaterial, Error> {
    let text = unwrap_jwk_prelude(
        "HMAC JWK",
        policy.check_useful(),
        input,
        &policy.webcrypto_usages(),
        UseFamily::Sig,
    )?;
    redact_invalid_key("HMAC JWK", MacKeyMaterial::import_jwk_sha1(&text, policy))
}

/// `aes-gcm.unwrap-key-raw`.
pub fn unwrap_aes_gcm_key(
    variant: AesVariant,
    input: UnwrapInputMaterial,
    policy: AeadPolicy,
) -> Result<AeadKeyMaterial, Error> {
    redact_invalid_key(
        "AES-GCM key",
        AeadKeyMaterial::import_aes_gcm(variant, input.into_bytes().to_vec(), policy),
    )
}

/// `aes-gcm.unwrap-key-jwk`.
pub fn unwrap_aes_gcm_key_jwk(
    variant: AesVariant,
    input: UnwrapInputMaterial,
    policy: AeadPolicy,
) -> Result<AeadKeyMaterial, Error> {
    let text = unwrap_jwk_prelude(
        "AES-GCM JWK",
        policy.check_useful(),
        input,
        &policy.webcrypto_usages(),
        UseFamily::Enc,
    )?;
    redact_invalid_key(
        "AES-GCM JWK",
        AeadKeyMaterial::import_aes_gcm_jwk(variant, &text, policy),
    )
}

/// `aes-cbc.unwrap-key-raw` / `aes-ctr.unwrap-key-raw`.
pub fn unwrap_cipher_key(
    mode: CipherMode,
    variant: AesVariant,
    input: UnwrapInputMaterial,
    policy: CipherPolicy,
) -> Result<CipherKeyMaterial, Error> {
    redact_invalid_key(
        "AES key",
        CipherKeyMaterial::import(mode, variant, input.into_bytes().to_vec(), policy),
    )
}

/// `aes-cbc.unwrap-key-jwk` / `aes-ctr.unwrap-key-jwk`.
pub fn unwrap_cipher_key_jwk(
    mode: CipherMode,
    variant: AesVariant,
    input: UnwrapInputMaterial,
    policy: CipherPolicy,
) -> Result<CipherKeyMaterial, Error> {
    let text = unwrap_jwk_prelude(
        "AES JWK",
        policy.check_useful(),
        input,
        &policy.webcrypto_usages(),
        UseFamily::Enc,
    )?;
    redact_invalid_key(
        "AES JWK",
        CipherKeyMaterial::import_jwk(mode, variant, &text, policy),
    )
}

/// `aes-kw.unwrap-key-raw`.
pub fn unwrap_kw_key(
    variant: AesVariant,
    input: UnwrapInputMaterial,
    policy: KwPolicy,
) -> Result<KwKeyMaterial, Error> {
    redact_invalid_key(
        "AES-KW key",
        KwKeyMaterial::import(variant, input.into_bytes().to_vec(), policy),
    )
}

/// `aes-kw.unwrap-key-jwk`.
pub fn unwrap_kw_key_jwk(
    variant: AesVariant,
    input: UnwrapInputMaterial,
    policy: KwPolicy,
) -> Result<KwKeyMaterial, Error> {
    let text = unwrap_jwk_prelude(
        "AES-KW JWK",
        policy.check_useful(),
        input,
        &policy.webcrypto_usages(),
        UseFamily::Enc,
    )?;
    redact_invalid_key(
        "AES-KW JWK",
        KwKeyMaterial::import_jwk(variant, &text, policy),
    )
}

/// `ed25519-sign.unwrap-signing-key-pkcs8`.
pub fn unwrap_ed25519_signing_key_pkcs8(
    input: UnwrapInputMaterial,
    policy: SigningPolicy,
) -> Result<SigningKeyMaterial, Error> {
    redact_invalid_key(
        "Ed25519 PKCS#8 key",
        SigningKeyMaterial::import_ed25519_pkcs8(&input.into_bytes(), policy),
    )
}

/// `ed25519-sign.unwrap-signing-key-jwk`.
pub fn unwrap_ed25519_signing_key_jwk(
    input: UnwrapInputMaterial,
    policy: SigningPolicy,
) -> Result<SigningKeyMaterial, Error> {
    let text = unwrap_jwk_prelude(
        "Ed25519 JWK",
        policy.check_useful(),
        input,
        &policy.webcrypto_usages(),
        UseFamily::Sig,
    )?;
    redact_invalid_key(
        "Ed25519 JWK",
        SigningKeyMaterial::import_ed25519_jwk(&text, policy),
    )
}

/// `ecdsa-sign.unwrap-signing-key-pkcs8`. Class D: like the imports it
/// reuses, compiled only where ECDSA signing is (see the crate doc).
#[cfg(not(target_family = "wasm"))]
pub fn unwrap_ecdsa_signing_key_pkcs8(
    variant: crate::EcdsaVariant,
    input: UnwrapInputMaterial,
    policy: SigningPolicy,
) -> Result<SigningKeyMaterial, Error> {
    redact_invalid_key(
        "ECDSA PKCS#8 key",
        SigningKeyMaterial::import_ecdsa_pkcs8(variant, &input.into_bytes(), policy),
    )
}

/// `ecdsa-sign.unwrap-signing-key-jwk`. Class D, as above.
#[cfg(not(target_family = "wasm"))]
pub fn unwrap_ecdsa_signing_key_jwk(
    variant: crate::EcdsaVariant,
    input: UnwrapInputMaterial,
    policy: SigningPolicy,
) -> Result<SigningKeyMaterial, Error> {
    let text = unwrap_jwk_prelude(
        "ECDSA JWK",
        policy.check_useful(),
        input,
        &policy.webcrypto_usages(),
        UseFamily::Sig,
    )?;
    redact_invalid_key(
        "ECDSA JWK",
        SigningKeyMaterial::import_ecdsa_jwk(variant, &text, policy),
    )
}

/// `rsassa-pkcs1-v15-sign.unwrap-signing-key-pkcs8`. Class D: like the
/// imports it reuses, compiled only where RSA signing is (see the crate
/// doc).
#[cfg(not(target_family = "wasm"))]
pub fn unwrap_rsassa_signing_key_pkcs8(
    variant: crate::RsaVariant,
    input: UnwrapInputMaterial,
    policy: SigningPolicy,
) -> Result<SigningKeyMaterial, Error> {
    redact_invalid_key(
        "RSA PKCS#8 key",
        SigningKeyMaterial::import_rsassa_pkcs8(variant, &input.into_bytes(), policy),
    )
}

/// `rsassa-pkcs1-v15-sign.unwrap-signing-key-jwk`. Class D, as above.
#[cfg(not(target_family = "wasm"))]
pub fn unwrap_rsassa_signing_key_jwk(
    variant: crate::RsaVariant,
    input: UnwrapInputMaterial,
    policy: SigningPolicy,
) -> Result<SigningKeyMaterial, Error> {
    let text = unwrap_jwk_prelude(
        "RSA JWK",
        policy.check_useful(),
        input,
        &policy.webcrypto_usages(),
        UseFamily::Sig,
    )?;
    redact_invalid_key(
        "RSA JWK",
        SigningKeyMaterial::import_rsassa_jwk(variant, &text, policy),
    )
}

/// `rsa-pss-sign.unwrap-signing-key-pkcs8`. Class D, as above.
#[cfg(not(target_family = "wasm"))]
pub fn unwrap_pss_signing_key_pkcs8(
    variant: crate::RsaVariant,
    input: UnwrapInputMaterial,
    policy: SigningPolicy,
) -> Result<SigningKeyMaterial, Error> {
    redact_invalid_key(
        "RSA PKCS#8 key",
        SigningKeyMaterial::import_pss_pkcs8(variant, &input.into_bytes(), policy),
    )
}

/// `rsa-pss-sign.unwrap-signing-key-jwk`. Class D, as above.
#[cfg(not(target_family = "wasm"))]
pub fn unwrap_pss_signing_key_jwk(
    variant: crate::RsaVariant,
    input: UnwrapInputMaterial,
    policy: SigningPolicy,
) -> Result<SigningKeyMaterial, Error> {
    let text = unwrap_jwk_prelude(
        "RSA JWK",
        policy.check_useful(),
        input,
        &policy.webcrypto_usages(),
        UseFamily::Sig,
    )?;
    redact_invalid_key(
        "RSA JWK",
        SigningKeyMaterial::import_pss_jwk(variant, &text, policy),
    )
}

/// `rsa-oaep-decrypt.unwrap-decryption-key-pkcs8`. Class D: like the
/// imports it reuses, compiled only where RSA private-key operations are
/// (see the crate doc).
#[cfg(not(target_family = "wasm"))]
pub fn unwrap_oaep_decryption_key_pkcs8(
    variant: crate::RsaVariant,
    input: UnwrapInputMaterial,
    policy: crate::TransportPolicy,
) -> Result<crate::DecryptionKeyMaterial, Error> {
    redact_invalid_key(
        "RSA PKCS#8 key",
        crate::DecryptionKeyMaterial::import_oaep_pkcs8(variant, &input.into_bytes(), policy),
    )
}

/// `rsa-oaep-decrypt.unwrap-decryption-key-jwk`. Class D, as above.
#[cfg(not(target_family = "wasm"))]
pub fn unwrap_oaep_decryption_key_jwk(
    variant: crate::RsaVariant,
    input: UnwrapInputMaterial,
    policy: crate::TransportPolicy,
) -> Result<crate::DecryptionKeyMaterial, Error> {
    let text = unwrap_jwk_prelude(
        "RSA JWK",
        policy.check_useful(),
        input,
        &policy.webcrypto_usages(),
        UseFamily::Enc,
    )?;
    redact_invalid_key(
        "RSA JWK",
        crate::DecryptionKeyMaterial::import_oaep_jwk(variant, &text, policy),
    )
}

/// `x25519.unwrap-secret-key-jwk`.
pub fn unwrap_x25519_secret_key_jwk(
    input: UnwrapInputMaterial,
    policy: AgreementPolicy,
) -> Result<AgreementSecretMaterial, Error> {
    let text = unwrap_jwk_prelude(
        "X25519 JWK",
        policy.check_useful(),
        input,
        &policy.webcrypto_usages(),
        UseFamily::Enc,
    )?;
    redact_invalid_key(
        "X25519 JWK",
        AgreementSecretMaterial::import_x25519_jwk(&text, policy),
    )
}

/// `x25519.unwrap-secret-key-pkcs8`.
pub fn unwrap_x25519_secret_key_pkcs8(
    input: UnwrapInputMaterial,
    policy: AgreementPolicy,
) -> Result<AgreementSecretMaterial, Error> {
    redact_invalid_key(
        "X25519 PKCS#8 key",
        AgreementSecretMaterial::import_x25519_pkcs8(&input.into_bytes(), policy),
    )
}

/// `ecdh.unwrap-secret-key-jwk`.
pub fn unwrap_ecdh_secret_key_jwk(
    variant: crate::EcdhVariant,
    input: UnwrapInputMaterial,
    policy: AgreementPolicy,
) -> Result<AgreementSecretMaterial, Error> {
    let text = unwrap_jwk_prelude(
        "ECDH JWK",
        policy.check_useful(),
        input,
        &policy.webcrypto_usages(),
        UseFamily::Enc,
    )?;
    redact_invalid_key(
        "ECDH JWK",
        AgreementSecretMaterial::import_ecdh_jwk(variant, &text, policy),
    )
}

/// `ecdh.unwrap-secret-key-pkcs8`.
pub fn unwrap_ecdh_secret_key_pkcs8(
    variant: crate::EcdhVariant,
    input: UnwrapInputMaterial,
    policy: AgreementPolicy,
) -> Result<AgreementSecretMaterial, Error> {
    redact_invalid_key(
        "ECDH PKCS#8 key",
        AgreementSecretMaterial::import_ecdh_pkcs8(variant, &input.into_bytes(), policy),
    )
}

/// `hkdf.unwrap-ikm`: the `import-ikm` contract over decrypted bytes.
pub fn unwrap_ikm(input: UnwrapInputMaterial, policy: DerivePolicy) -> Result<IkmMaterial, Error> {
    IkmMaterial::import(input.into_bytes().to_vec(), policy)
}

/// `pbkdf2.unwrap-password`: the `import-password` contract over decrypted
/// bytes.
pub fn unwrap_password(
    input: UnwrapInputMaterial,
    policy: DerivePolicy,
) -> Result<PasswordMaterial, Error> {
    PasswordMaterial::import(input.into_bytes().to_vec(), policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding_macro::hexupper;

    fn kw_policy() -> KwPolicy {
        KwPolicy {
            wrap: true,
            unwrap: true,
            extractable: true,
        }
    }

    // RFC 3394 §4.1: 128-bit key data with a 128-bit KEK.
    #[test]
    fn rfc3394_known_answer_128() {
        let kek = KwKeyMaterial::import(
            AesVariant::Aes128,
            hexupper!("000102030405060708090A0B0C0D0E0F").to_vec(),
            kw_policy(),
        )
        .unwrap();
        let wrapped = kek
            .wrap(WrapInputMaterial::new(
                WrapFormat::Raw,
                hexupper!("00112233445566778899AABBCCDDEEFF").to_vec(),
            ))
            .unwrap();
        assert_eq!(
            wrapped,
            hexupper!("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5").to_vec()
        );
        let back = kek.unwrap(&wrapped).unwrap();
        assert_eq!(
            back.into_bytes().to_vec(),
            hexupper!("00112233445566778899AABBCCDDEEFF").to_vec()
        );
    }

    // RFC 3394 §4.6: 256-bit key data with a 256-bit KEK.
    #[test]
    fn rfc3394_known_answer_256() {
        let kek = KwKeyMaterial::import(
            AesVariant::Aes256,
            hexupper!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F").to_vec(),
            kw_policy(),
        )
        .unwrap();
        let wrapped = kek
            .wrap(WrapInputMaterial::new(
                WrapFormat::Raw,
                hexupper!("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
                    .to_vec(),
            ))
            .unwrap();
        assert_eq!(
            wrapped,
            hexupper!(
                "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43B\
                 FB988B9B7A02DD21"
            )
            .to_vec()
        );
    }

    #[test]
    fn kw_domains_and_verdicts() {
        let kek = KwKeyMaterial::import(AesVariant::Aes256, vec![7; 32], kw_policy()).unwrap();
        // Wrap domain: not a multiple of 8, or under 16 bytes.
        for bad in [vec![1u8; 20], vec![1u8; 8], vec![]] {
            match kek.wrap(WrapInputMaterial::new(WrapFormat::Raw, bad)) {
                Err(Error::InvalidKey(msg)) => assert!(msg.starts_with(KW_WRAP_DOMAIN), "{msg}"),
                other => panic!("expected invalid-key, got {other:?}"),
            }
        }
        // Unwrap domain folds into authentication-failed…
        for bad in [vec![1u8; 16], vec![1u8; 20], vec![]] {
            assert!(matches!(kek.unwrap(&bad), Err(Error::AuthenticationFailed)));
        }
        // …as does a bad ICV.
        let mut wrapped = kek
            .wrap(WrapInputMaterial::new(WrapFormat::Raw, vec![9; 16]))
            .unwrap();
        wrapped[0] ^= 1;
        assert!(matches!(
            kek.unwrap(&wrapped),
            Err(Error::AuthenticationFailed)
        ));
    }

    #[test]
    fn kw_jwk_padding_round_trips() {
        let kek = KwKeyMaterial::import(AesVariant::Aes128, vec![3; 16], kw_policy()).unwrap();
        let hmac = MacKeyMaterial::import(
            Sha2Variant::Sha256,
            vec![5; 20],
            MacPolicy {
                sign: true,
                verify: true,
                extractable: true,
            },
        )
        .unwrap();
        let jwk = hmac.export_jwk().unwrap();
        assert!(
            !jwk.len().is_multiple_of(8),
            "pick a length that needs padding"
        );
        let wrapped = kek
            .wrap(WrapInputMaterial::new(
                WrapFormat::Jwk,
                jwk.clone().into_bytes(),
            ))
            .unwrap();
        // The wrapped form carries the padded length.
        assert_eq!(wrapped.len(), jwk.len().div_ceil(8) * 8 + 8);
        // The mint's parse tolerates the trailing spaces.
        let minted = unwrap_mac_key_jwk(
            Sha2Variant::Sha256,
            kek.unwrap(&wrapped).unwrap(),
            MacPolicy {
                sign: true,
                verify: false,
                extractable: true,
            },
        )
        .unwrap();
        assert_eq!(minted.export().unwrap(), vec![5; 20]);
    }

    #[test]
    fn kw_grants_and_gates() {
        let wrap_only = KwKeyMaterial::import(
            AesVariant::Aes128,
            vec![1; 16],
            KwPolicy {
                wrap: true,
                unwrap: false,
                extractable: false,
            },
        )
        .unwrap();
        assert!(wrap_only.can_wrap());
        assert!(!wrap_only.can_unwrap());
        assert_eq!(
            wrap_only.unwrap(&[0; 24]).err(),
            Some(Error::NotPermitted(
                "this key does not permit unwrap".into()
            ))
        );
        assert_eq!(wrap_only.export(), Err(Error::NotExtractable));
        assert!(matches!(
            KwKeyMaterial::import(AesVariant::Aes128, vec![1; 16], KwPolicy::default()),
            Err(Error::NotPermitted(_))
        ));
        assert!(matches!(
            KwKeyMaterial::import(AesVariant::Aes192, vec![1; 24], kw_policy()),
            Err(Error::Unsupported(_))
        ));
        assert!(matches!(
            KwKeyMaterial::import(AesVariant::Aes128, vec![1; 20], kw_policy()),
            Err(Error::InvalidKey(_))
        ));
    }

    #[test]
    fn unwrap_mint_messages_are_redacted() {
        // A JWK whose alg mismatches would normally echo the alg value;
        // through the unwrap mint the message is fixed.
        let jwk = crate::jwk::build_oct(&[1; 32], "A256GCM");
        let input = UnwrapInputMaterial::new(jwk.into_bytes());
        match unwrap_mac_key_jwk(
            Sha2Variant::Sha256,
            input,
            MacPolicy {
                sign: true,
                verify: false,
                extractable: false,
            },
        ) {
            Err(Error::InvalidKey(msg)) => {
                assert_eq!(msg, "unwrapped material is not a valid HMAC JWK")
            }
            other => panic!("expected invalid-key, got {other:?}"),
        }
        // Non-UTF-8 bytes fail the same fixed way.
        let input = UnwrapInputMaterial::new(vec![0xff; 16]);
        match unwrap_mac_key_jwk(
            Sha2Variant::Sha256,
            input,
            MacPolicy {
                sign: true,
                verify: false,
                extractable: false,
            },
        ) {
            Err(Error::InvalidKey(msg)) => {
                assert_eq!(msg, "unwrapped material is not a valid HMAC JWK")
            }
            other => panic!("expected invalid-key, got {other:?}"),
        }
    }

    #[test]
    fn unwrap_jwk_checks_use_and_key_ops() {
        let policy = MacPolicy {
            sign: true,
            verify: true,
            extractable: false,
        };
        // key_ops missing a granted usage.
        let jwk =
            r#"{"kty":"oct","k":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA","key_ops":["sign"]}"#;
        assert!(matches!(
            unwrap_mac_key_jwk(
                Sha2Variant::Sha256,
                UnwrapInputMaterial::new(jwk.as_bytes().to_vec()),
                policy
            ),
            Err(Error::InvalidKey(_))
        ));
        // Wrong use family.
        let jwk = r#"{"kty":"oct","k":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA","use":"enc"}"#;
        assert!(matches!(
            unwrap_mac_key_jwk(
                Sha2Variant::Sha256,
                UnwrapInputMaterial::new(jwk.as_bytes().to_vec()),
                policy
            ),
            Err(Error::InvalidKey(_))
        ));
        // Conforming members mint.
        let jwk = r#"{"kty":"oct","k":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA","use":"sig","key_ops":["sign","verify"]}"#;
        assert!(unwrap_mac_key_jwk(
            Sha2Variant::Sha256,
            UnwrapInputMaterial::new(jwk.as_bytes().to_vec()),
            policy
        )
        .is_ok());
    }

    #[test]
    fn kdf_secrets_unwrap() {
        let policy = DerivePolicy {
            derive_bits: true,
            derive_key: true,
        };
        let ikm = unwrap_ikm(UnwrapInputMaterial::new(vec![1; 32]), policy).unwrap();
        assert_eq!(ikm.byte_len(), 32);
        let password = unwrap_password(UnwrapInputMaterial::new(vec![2; 8]), policy).unwrap();
        assert_eq!(password.byte_len(), 8);
    }
}
