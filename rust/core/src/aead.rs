//! The `aead-key` / `internal-nonce-key` material: an algorithm-bound cipher
//! plus raw key bytes, with the caller-nonce and internal-nonce seal/open
//! operations, validation, and the extractability gate.

use aes_gcm::aead::{Aead as _, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use zeroize::Zeroizing;

use crate::{
    aes192_unsupported, not_permitted, random_bytes, AeadPolicy, AesVariant, Error, RngError,
    AES_GCM_NAME, CHACHA20_POLY1305_NAME, XCHACHA20_POLY1305_NAME,
};

/// The length in bytes of a ChaCha20-Poly1305 key (either construction).
const CHACHA_KEY_LEN: usize = 32;

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
/// The internal-nonce seal *count* deliberately lives in each
/// implementation, whose interior-mutability needs differ; the budget
/// *decisions* over that count ([`check_budget`](Self::check_budget),
/// [`seals_remaining`](Self::seals_remaining)) live here so the two
/// implementations cannot diverge on them.
pub struct AeadKeyMaterial {
    /// The cipher keyed by `raw`, bound to its algorithm at minting.
    cipher: AeadCipher,
    /// The raw key material, retained for `export-key-raw` on extractable keys;
    /// zeroized on drop.
    raw: Zeroizing<Vec<u8>>,
    /// The mint-time policy: usages and extractability (internal-nonce
    /// mintings widen their narrower vocabulary into this one).
    policy: AeadPolicy,
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

/// Import 32 bytes of key material for either ChaCha construction.
fn import_chacha_like<C: KeyInit>(
    name: &'static str,
    wrap: fn(C) -> AeadCipher,
    raw: Vec<u8>,
    policy: AeadPolicy,
) -> Result<AeadKeyMaterial, Error> {
    policy.check_useful()?;
    check_chacha_key(name, &raw)?;
    let cipher = wrap(C::new_from_slice(&raw).expect("length checked"));
    Ok(AeadKeyMaterial {
        cipher,
        raw: Zeroizing::new(raw),
        policy,
    })
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
    /// ChaCha20-Poly1305 exports the W3C Modern Algorithms proposal's
    /// registered `alg`, `"C20P"`; XChaCha, with no registered JWK form,
    /// is `unsupported`.
    pub fn export_jwk(&self) -> Result<String, Error> {
        let alg = match &self.cipher {
            AeadCipher::Aes128Gcm(_) => "A128GCM",
            AeadCipher::Aes256Gcm(_) => "A256GCM",
            AeadCipher::ChaCha20Poly1305(_) => "C20P",
            AeadCipher::XChaCha20Poly1305(_) => {
                return Err(Error::Unsupported(format!(
                    "{} has no registered JWK form",
                    self.name()
                )))
            }
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

    /// Import raw key material as an IETF ChaCha20-Poly1305 key (exactly 32
    /// bytes; anything else is `invalid-key`).
    pub fn import_chacha20_poly1305(raw: Vec<u8>, policy: AeadPolicy) -> Result<Self, Error> {
        import_chacha_like(
            CHACHA20_POLY1305_NAME,
            AeadCipher::ChaCha20Poly1305,
            raw,
            policy,
        )
    }

    /// Import an RFC 7517 `oct` JWK as an IETF ChaCha20-Poly1305 key, per
    /// the `chacha20-poly1305.import-key-jwk` contract: `alg`, when
    /// present, must be the proposal's registered `"C20P"` (any other is
    /// `invalid-key`), then the decoded material is subject to
    /// [`import_chacha20_poly1305`](Self::import_chacha20_poly1305)'s
    /// contract.
    pub fn import_chacha20_poly1305_jwk(jwk: &str, policy: AeadPolicy) -> Result<Self, Error> {
        let raw = crate::jwk::parse_oct(jwk, "C20P", policy.extractable)?;
        Self::import_chacha20_poly1305(raw, policy)
    }

    /// Generate a fresh random IETF ChaCha20-Poly1305 key.
    pub fn generate_chacha20_poly1305(policy: AeadPolicy) -> Result<Result<Self, Error>, RngError> {
        if let Err(err) = policy.check_useful() {
            return Ok(Err(err));
        }
        Ok(Ok(Self::import_chacha20_poly1305(
            random_bytes(CHACHA_KEY_LEN)?,
            policy,
        )
        .expect("generated key material is always 32 bytes")))
    }

    /// Import raw key material as an XChaCha20-Poly1305 key (exactly 32
    /// bytes; anything else is `invalid-key`).
    pub fn import_xchacha20_poly1305(raw: Vec<u8>, policy: AeadPolicy) -> Result<Self, Error> {
        import_chacha_like(
            XCHACHA20_POLY1305_NAME,
            AeadCipher::XChaCha20Poly1305,
            raw,
            policy,
        )
    }

    /// Generate a fresh random XChaCha20-Poly1305 key.
    pub fn generate_xchacha20_poly1305(
        policy: AeadPolicy,
    ) -> Result<Result<Self, Error>, RngError> {
        if let Err(err) = policy.check_useful() {
            return Ok(Err(err));
        }
        Ok(Ok(Self::import_xchacha20_poly1305(
            random_bytes(CHACHA_KEY_LEN)?,
            policy,
        )
        .expect("generated key material is always 32 bytes")))
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

    /// The material's length in bytes.
    pub fn byte_len(&self) -> usize {
        self.raw.len()
    }

    /// The nonce length in bytes this key's algorithm specifies
    /// (`aead-key.nonce-size`, and the internal-nonce wire prefix).
    pub fn nonce_len(&self) -> usize {
        match &self.cipher {
            AeadCipher::XChaCha20Poly1305(_) => 24,
            _ => 12,
        }
    }

    /// The default tag length in bytes every served algorithm trails its
    /// ciphertext with when `seal` is called with no explicit tag size
    /// (`aead-key.tag-size`).
    pub fn tag_len(&self) -> usize {
        16
    }

    /// Resolve and validate a per-call tag size for this key's algorithm:
    /// GCM accepts [`crate::gcm::GCM_TAG_SIZES`]; the ChaCha constructions
    /// fix 16. `None` is the algorithm default.
    fn check_tag_size(&self, tag_size: Option<u8>) -> Result<usize, Error> {
        match &self.cipher {
            AeadCipher::Aes128Gcm(_) | AeadCipher::Aes256Gcm(_) => {
                crate::gcm::check_tag_size(tag_size)
            }
            AeadCipher::ChaCha20Poly1305(_) | AeadCipher::XChaCha20Poly1305(_) => match tag_size {
                None | Some(16) => Ok(16),
                Some(size) => Err(Error::Unsupported(format!(
                    "{} tags are always 16 bytes, got a tag size of {size}",
                    self.name()
                ))),
            },
        }
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

    /// Whether a key that has already sealed `sealed` times may seal again,
    /// per the minting interfaces' SHOULD-enforce contract:
    /// `key-exhausted` once the algorithm's nonce budget is spent.
    pub fn check_budget(&self, sealed: u64) -> Result<(), Error> {
        match self.nonce_budget() {
            Some(budget) if sealed >= budget => Err(Error::KeyExhausted),
            _ => Ok(()),
        }
    }

    /// The remaining nonce budget after `sealed` seals (the
    /// `seals-remaining` getter); `none` when no budget is enforced.
    pub fn seals_remaining(&self, sealed: u64) -> Option<u64> {
        self.nonce_budget()
            .map(|budget| budget.saturating_sub(sealed))
    }

    /// Validate a caller nonce's length for this key's algorithm, rendering
    /// the WIT `invalid-nonce` error: GCM accepts any non-empty nonce (the
    /// `aes-gcm` minting contract); the ChaCha constructions accept exactly
    /// their standard length.
    fn check_nonce(&self, nonce: &[u8]) -> Result<(), Error> {
        match &self.cipher {
            AeadCipher::Aes128Gcm(_) | AeadCipher::Aes256Gcm(_) => {
                if nonce.is_empty() {
                    Err(Error::InvalidNonce(
                        "AES-GCM requires a non-empty nonce".into(),
                    ))
                } else {
                    Ok(())
                }
            }
            AeadCipher::ChaCha20Poly1305(_) | AeadCipher::XChaCha20Poly1305(_) => {
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
        }
    }

    /// Whether `(nonce, tag_len)` is the standard GCM parameter point the
    /// `aes-gcm` crate serves; anything else routes to the general path
    /// ([`crate::gcm`]).
    fn is_standard_point(&self, nonce: &[u8], tag_len: usize) -> bool {
        nonce.len() == self.nonce_len() && tag_len == 16
    }

    /// The general-path AES cipher, keyed from this key's material. Only
    /// reachable for the AES variants: `check_nonce`/`check_tag_size` bound
    /// the ChaCha constructions to the standard point, which never routes
    /// here.
    fn general_gcm(&self) -> crate::gcm::GcmAes {
        debug_assert!(matches!(
            self.cipher,
            AeadCipher::Aes128Gcm(_) | AeadCipher::Aes256Gcm(_)
        ));
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
        if !self.policy.seal {
            return Ok(Err(not_permitted("seal")));
        }
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
        if !self.policy.open {
            return Err(not_permitted("open"));
        }
        if sealed.len() < self.nonce_len() {
            return Err(Error::AuthenticationFailed);
        }
        let (nonce, body) = sealed.split_at(self.nonce_len());
        self.cipher
            .decrypt(nonce, Payload { msg: body, aad })
            .map_err(|_| Error::AuthenticationFailed)
    }

    /// Whether the key material may be exported (the `extractable` getter
    /// on either key resource).
    pub fn extractable(&self) -> bool {
        self.policy.extractable
    }

    /// Whether the key permits `seal` (`can-seal` on either key resource).
    pub fn can_seal(&self) -> bool {
        self.policy.seal
    }

    /// Whether the key permits `open` (`can-open`).
    pub fn can_open(&self) -> bool {
        self.policy.open
    }

    /// Whether the key permits wrapping (`aead-key.can-wrap`; recorded
    /// vocabulary, no operation yet).
    pub fn can_wrap(&self) -> bool {
        self.policy.wrap
    }

    /// Whether the key permits unwrapping (`aead-key.can-unwrap`).
    pub fn can_unwrap(&self) -> bool {
        self.policy.unwrap
    }

    /// The raw material, or `not-extractable` (the `export-key-raw` contract on
    /// either key resource).
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
                assert_eq!(msg, "AES-GCM requires a non-empty nonce")
            }
            _ => panic!("expected invalid-nonce"),
        }
        assert_eq!(key.export(), Err(Error::NotExtractable));
    }

    /// The full GCM parameter space on one key: a non-standard nonce
    /// length routes to the general path and round-trips, a truncated tag
    /// round-trips and fails at the wrong declared size, and out-of-set
    /// sizes are declined. ChaCha keys stay bound to the standard point.
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

        let chacha = AeadKeyMaterial::generate_chacha20_poly1305(ap())
            .unwrap()
            .unwrap();
        assert!(chacha.seal(&[0u8; 12], b"", Some(16), b"x").is_ok());
        assert!(matches!(
            chacha.seal(&[0u8; 12], b"", Some(12), b"x"),
            Err(Error::Unsupported(_))
        ));
        assert!(matches!(
            chacha.seal(&[0u8; 16], b"", None, b"x"),
            Err(Error::InvalidNonce(_))
        ));
    }

    #[test]
    fn internal_nonce_round_trip_and_wire_format() {
        let key = AeadKeyMaterial::generate_xchacha20_poly1305(xp())
            .unwrap()
            .unwrap();
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
        let key = AeadKeyMaterial::generate_chacha20_poly1305(xp())
            .unwrap()
            .unwrap();
        assert_eq!(key.nonce_budget(), Some(1 << 32));
        let key = AeadKeyMaterial::generate_aes_gcm(AesVariant::Aes128, xp())
            .unwrap()
            .unwrap();
        assert_eq!(key.nonce_budget(), Some(1 << 32));
        assert_eq!(key.length_bits(), 128);
    }

    /// The budget decision both implementations delegate here: counting
    /// stays with them, exhaustion and the remaining-budget arithmetic do
    /// not.
    #[test]
    fn budget_decisions_follow_the_seal_count() {
        let budgeted = AeadKeyMaterial::generate_chacha20_poly1305(xp())
            .unwrap()
            .unwrap();
        assert_eq!(budgeted.check_budget(0), Ok(()));
        assert_eq!(budgeted.check_budget((1 << 32) - 1), Ok(()));
        assert_eq!(budgeted.check_budget(1 << 32), Err(Error::KeyExhausted));
        assert_eq!(budgeted.seals_remaining(1), Some((1 << 32) - 1));
        assert_eq!(budgeted.seals_remaining(u64::MAX), Some(0));

        let unbudgeted = AeadKeyMaterial::generate_xchacha20_poly1305(xp())
            .unwrap()
            .unwrap();
        assert_eq!(unbudgeted.check_budget(u64::MAX), Ok(()));
        assert_eq!(unbudgeted.seals_remaining(u64::MAX), None);
    }
}
