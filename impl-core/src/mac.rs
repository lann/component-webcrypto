//! The `mac-key` material: HMAC key bytes bound to a SHA-2 variant, with the
//! one-shot sign/verify operations and the extractability gate.

use zeroize::Zeroizing;

use crate::{
    hash::Sha2, not_permitted, random_bytes, served_sha2, Error, MacPolicy, RngError, Sha2Variant,
};

/// The material behind a `mac.mac-key` resource: raw HMAC key bytes
/// (zeroized on drop), the SHA-2 variant the key is bound to, and its
/// extractability.
#[derive(Clone)]
pub struct MacKeyMaterial {
    /// The raw key material, retained for `sign`/`verify` and (when
    /// extractable) `export-key`; zeroized on drop.
    raw: Zeroizing<Vec<u8>>,
    /// The SHA-2 variant this key is bound to.
    variant: Sha2,
    /// The mint-time policy: usages and extractability.
    policy: MacPolicy,
}

impl MacKeyMaterial {
    /// Import raw key material as an HMAC key over the declared variant,
    /// per the `hmac-sha2.import-key` contract: any non-empty length is
    /// accepted (RFC 2104; longer-than-block keys are hashed first), empty
    /// material is `invalid-key`, and unserved variants are `unsupported`.
    pub fn import(variant: Sha2Variant, raw: Vec<u8>, policy: MacPolicy) -> Result<Self, Error> {
        policy.check_useful()?;
        let variant = served_sha2(variant)?;
        if raw.is_empty() {
            return Err(Error::InvalidKey(
                "HMAC key material must be non-empty".into(),
            ));
        }
        Ok(Self {
            raw: Zeroizing::new(raw),
            variant,
            policy,
        })
    }

    /// Import an RFC 7517 `oct` JWK as an HMAC key over the declared
    /// variant, per the `hmac-sha2.import-key-jwk` contract: the JWK's
    /// material-bearing fields are validated (`alg` against the variant's
    /// `HS*` name), then the decoded material is subject to
    /// [`import`](Self::import)'s contract.
    pub fn import_jwk(variant: Sha2Variant, jwk: &str, policy: MacPolicy) -> Result<Self, Error> {
        let alg = match served_sha2(variant)? {
            Sha2::Sha256 => "HS256",
            Sha2::Sha384 => "HS384",
            Sha2::Sha512 => "HS512",
        };
        let raw = crate::jwk::parse_oct(jwk, alg, policy.extractable)?;
        Self::import(variant, raw, policy)
    }

    /// The key as an `oct` JWK (the `mac-key.export-key-jwk` contract):
    /// the same extractability gate as [`export`](Self::export).
    pub fn export_jwk(&self) -> Result<String, Error> {
        let alg = match self.variant {
            Sha2::Sha256 => "HS256",
            Sha2::Sha384 => "HS384",
            Sha2::Sha512 => "HS512",
        };
        Ok(crate::jwk::build_oct(&self.export()?, alg))
    }

    /// Generate a fresh random HMAC key over the declared variant, per the
    /// `hmac-sha2.generate-key` contract: `length` is the key length in
    /// bits, `None` meaning the underlying hash's block size (WebCrypto's
    /// `generateKey` default). The inner error is `invalid-key` for a zero
    /// length, and `unsupported` for an unserved variant or a length that
    /// is not a multiple of 8 (sub-byte lengths are not served); the outer
    /// channel is entropy failure.
    pub fn generate(
        variant: Sha2Variant,
        length: Option<u32>,
        policy: MacPolicy,
    ) -> Result<Result<Self, Error>, RngError> {
        if let Err(err) = policy.check_useful() {
            return Ok(Err(err));
        }
        let variant = match served_sha2(variant) {
            Ok(variant) => variant,
            Err(err) => return Ok(Err(err)),
        };
        let byte_len = match length {
            None => variant.block_len(),
            Some(0) => {
                return Ok(Err(Error::InvalidKey(
                    "HMAC key length must be non-zero".into(),
                )))
            }
            Some(bits) if bits % 8 != 0 => {
                return Ok(Err(Error::Unsupported(format!(
                "HMAC key length {bits} is not a multiple of 8; sub-byte lengths are not served",
            ))))
            }
            Some(bits) => bits as usize / 8,
        };
        Ok(Ok(Self {
            raw: Zeroizing::new(random_bytes(byte_len)?),
            variant,
            policy,
        }))
    }

    /// Compute the tag over `data` (the `mac-key.sign` contract). Fails
    /// `not-permitted` on a key minted without the `sign` usage.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        if !self.policy.sign {
            return Err(not_permitted("sign"));
        }
        Ok(self.variant.hmac_sign(&self.raw, data))
    }

    /// Verify `tag` over `data` in constant time, failing closed with
    /// `authentication-failed` (the `mac-key.verify` contract).
    pub fn verify(&self, data: &[u8], tag: &[u8]) -> Result<(), Error> {
        if !self.policy.verify {
            return Err(not_permitted("verify"));
        }
        self.variant.hmac_verify(&self.raw, data, tag)
    }

    /// The bound digest's registry name (`mac-key.algorithm-hash`).
    pub fn hash_name(&self) -> &'static str {
        self.variant.hash_name()
    }

    /// The key length in bits (`mac-key.algorithm-length`).
    ///
    /// `import-key` accepts any non-empty length, so the bit count can
    /// exceed `u32`. The getter is total in the WIT, so it saturates rather
    /// than trapping.
    pub fn length_bits(&self) -> u32 {
        length_bits(self.raw.len())
    }

    /// Whether the key material may be exported (`mac-key.extractable`).
    pub fn extractable(&self) -> bool {
        self.policy.extractable
    }

    /// Whether the key permits `sign` (`mac-key.can-sign`).
    pub fn can_sign(&self) -> bool {
        self.policy.sign
    }

    /// Whether the key permits `verify` (`mac-key.can-verify`).
    pub fn can_verify(&self) -> bool {
        self.policy.verify
    }

    /// The raw material, or `not-extractable` (the `mac-key.export-key`
    /// contract).
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

/// The bit count of `len` bytes, saturating at `u32::MAX`.
fn length_bits(len: usize) -> u32 {
    u32::try_from(len.saturating_mul(8)).unwrap_or(u32::MAX)
}

// Debug is implemented by hand so key material can never reach logs: only
// the algorithm binding and extractability are printed, with the material
// redacted.
impl std::fmt::Debug for MacKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MacKeyMaterial")
            .field("variant", &self.variant)
            .field("policy", &self.policy)
            .field("raw", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A full grant, non-extractable.
    fn mp() -> MacPolicy {
        MacPolicy {
            sign: true,
            verify: true,
            extractable: false,
        }
    }

    /// A full grant, extractable.
    fn xp() -> MacPolicy {
        MacPolicy {
            extractable: true,
            ..mp()
        }
    }

    #[test]
    fn usage_denial_is_enforced_and_reported() {
        let sign_only = MacPolicy {
            sign: true,
            ..Default::default()
        };
        let key = MacKeyMaterial::import(Sha2Variant::Sha256, vec![7; 20], sign_only).unwrap();
        assert!(key.can_sign());
        assert!(!key.can_verify());
        let tag = key.sign(b"data").unwrap();
        assert!(matches!(
            key.verify(b"data", &tag),
            Err(Error::NotPermitted(_))
        ));

        let verify_only = MacPolicy {
            verify: true,
            ..Default::default()
        };
        let key = MacKeyMaterial::import(Sha2Variant::Sha256, vec![7; 20], verify_only).unwrap();
        assert!(matches!(key.sign(b"data"), Err(Error::NotPermitted(_))));
        key.verify(b"data", &tag).unwrap();

        // The untouched default grants nothing, so it cannot mint.
        assert!(matches!(
            MacKeyMaterial::import(Sha2Variant::Sha256, vec![7; 20], MacPolicy::default()),
            Err(Error::NotPermitted(_))
        ));
    }

    #[test]
    fn empty_key_is_invalid() {
        match MacKeyMaterial::import(Sha2Variant::Sha256, Vec::new(), xp()) {
            Err(Error::InvalidKey(msg)) => {
                assert_eq!(msg, "HMAC key material must be non-empty")
            }
            _ => panic!("expected invalid-key"),
        }
    }

    #[test]
    fn extractability_gates_export() {
        let key = MacKeyMaterial::import(Sha2Variant::Sha256, vec![7; 20], mp()).unwrap();
        assert_eq!(key.export(), Err(Error::NotExtractable));
        let key = MacKeyMaterial::import(Sha2Variant::Sha256, vec![7; 20], xp()).unwrap();
        assert_eq!(key.export().unwrap(), vec![7; 20]);
        assert_eq!(key.length_bits(), 160);
    }

    #[test]
    fn generated_key_has_block_size_material() {
        let key = MacKeyMaterial::generate(Sha2Variant::Sha384, None, xp())
            .unwrap()
            .unwrap();
        assert_eq!(key.export().unwrap().len(), 128);
    }

    #[test]
    fn generated_key_honors_requested_length() {
        let key = MacKeyMaterial::generate(Sha2Variant::Sha256, Some(256), xp())
            .unwrap()
            .unwrap();
        assert_eq!(key.export().unwrap().len(), 32);
        assert_eq!(key.length_bits(), 256);
    }

    #[test]
    fn generated_key_rejects_zero_and_sub_byte_lengths() {
        assert!(matches!(
            MacKeyMaterial::generate(Sha2Variant::Sha256, Some(0), xp()).unwrap(),
            Err(Error::InvalidKey(_))
        ));
        assert!(matches!(
            MacKeyMaterial::generate(Sha2Variant::Sha256, Some(250), xp()).unwrap(),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn length_saturates_instead_of_wrapping() {
        assert_eq!(length_bits(0), 0);
        assert_eq!(length_bits(20), 160);
        // A key of 512 MiB is the first length whose bit count leaves u32.
        assert_eq!(length_bits(1 << 29), u32::MAX);
        assert_eq!(length_bits(usize::MAX), u32::MAX);
    }

    #[test]
    fn debug_redacts_key_material() {
        let key = MacKeyMaterial::import(Sha2Variant::Sha256, vec![0xAB; 32], xp()).unwrap();
        let rendered = format!("{key:?}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(!rendered.contains("171"), "{rendered}"); // 0xAB
    }
}
