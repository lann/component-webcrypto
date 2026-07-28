//! The `mac-key` material: HMAC key bytes bound to a SHA-2 variant, with the
//! one-shot sign/verify operations and the extractability gate.

use zeroize::Zeroizing;

use crate::{hash::Sha2, random_bytes, served_sha2, Error, RngError, Sha2Variant};

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
    /// Whether `export-key` may return the raw material.
    extractable: bool,
}

impl MacKeyMaterial {
    /// Import raw key material as an HMAC key over the declared variant,
    /// per the `hmac-sha2.import-key` contract: any non-empty length is
    /// accepted (RFC 2104; longer-than-block keys are hashed first), empty
    /// material is `invalid-key`, and unserved variants are `unsupported`.
    pub fn import(variant: Sha2Variant, raw: Vec<u8>, extractable: bool) -> Result<Self, Error> {
        let variant = served_sha2(variant)?;
        if raw.is_empty() {
            return Err(Error::InvalidKey(
                "HMAC key material must be non-empty".into(),
            ));
        }
        Ok(Self {
            raw: Zeroizing::new(raw),
            variant,
            extractable,
        })
    }

    /// Generate a fresh random HMAC key over the declared variant, with the
    /// underlying hash's block size of key material (WebCrypto's
    /// `generateKey` default). The inner error is `unsupported` for an
    /// unserved variant; the outer channel is entropy failure.
    pub fn generate(
        variant: Sha2Variant,
        extractable: bool,
    ) -> Result<Result<Self, Error>, RngError> {
        let variant = match served_sha2(variant) {
            Ok(variant) => variant,
            Err(err) => return Ok(Err(err)),
        };
        Ok(Ok(Self {
            raw: Zeroizing::new(random_bytes(variant.block_len())?),
            variant,
            extractable,
        }))
    }

    /// Compute the tag over `data` (the `mac-key.sign` contract).
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        self.variant.hmac_sign(&self.raw, data)
    }

    /// Verify `tag` over `data` in constant time, failing closed with
    /// `authentication-failed` (the `mac-key.verify` contract).
    pub fn verify(&self, data: &[u8], tag: &[u8]) -> Result<(), Error> {
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

    /// The raw material, or `not-extractable` (the `mac-key.export-key`
    /// contract).
    pub fn export(&self) -> Result<Vec<u8>, Error> {
        if self.extractable {
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
            .field("extractable", &self.extractable)
            .field("raw", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_key_is_invalid() {
        match MacKeyMaterial::import(Sha2Variant::Sha256, Vec::new(), true) {
            Err(Error::InvalidKey(msg)) => {
                assert_eq!(msg, "HMAC key material must be non-empty")
            }
            _ => panic!("expected invalid-key"),
        }
    }

    #[test]
    fn extractability_gates_export() {
        let key = MacKeyMaterial::import(Sha2Variant::Sha256, vec![7; 20], false).unwrap();
        assert_eq!(key.export(), Err(Error::NotExtractable));
        let key = MacKeyMaterial::import(Sha2Variant::Sha256, vec![7; 20], true).unwrap();
        assert_eq!(key.export().unwrap(), vec![7; 20]);
        assert_eq!(key.length_bits(), 160);
    }

    #[test]
    fn generated_key_has_block_size_material() {
        let key = MacKeyMaterial::generate(Sha2Variant::Sha384, true)
            .unwrap()
            .unwrap();
        assert_eq!(key.export().unwrap().len(), 128);
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
        let key = MacKeyMaterial::import(Sha2Variant::Sha256, vec![0xAB; 32], true).unwrap();
        let rendered = format!("{key:?}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(!rendered.contains("171"), "{rendered}"); // 0xAB
    }
}
