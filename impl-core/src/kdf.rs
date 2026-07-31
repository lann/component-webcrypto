//! HKDF (RFC 5869): the shared derivation core behind the `derivation` and
//! `hkdf` interfaces.
//!
//! The `derive-input` resource's semantics — a parameterized derivation,
//! realized eagerly — are implemented here as [`DeriveInputMaterial`]:
//! `prepare` runs HKDF-Extract immediately, so the input retains the PRK
//! and the bound `info`, and the IKM is never copied out of its own
//! resource. That is the eager-realization guidance from the WIT made
//! concrete: an input's existence does not extend the pre-image's
//! residency.

use hkdf::Hkdf;
use sha2::{Sha256, Sha384, Sha512};
use zeroize::Zeroizing;

use crate::hash::{served_sha2, Sha2};
use crate::policy::{not_permitted, DerivePolicy};
use crate::{Error, Sha2Variant};

/// The `hkdf.ikm` resource's material: bytes that no operation returns.
#[derive(Debug)]
pub struct IkmMaterial {
    raw: Zeroizing<Vec<u8>>,
    policy: DerivePolicy,
}

impl IkmMaterial {
    /// Import input keying material, per the `hkdf.import-ikm` contract:
    /// empty material is `invalid-key`, a grantless policy is
    /// `not-permitted`.
    pub fn import(raw: Vec<u8>, policy: DerivePolicy) -> Result<Self, Error> {
        policy.check_useful()?;
        if raw.is_empty() {
            return Err(Error::InvalidKey(
                "HKDF input keying material must be non-empty".into(),
            ));
        }
        Ok(Self {
            raw: Zeroizing::new(raw),
            policy,
        })
    }

    pub fn policy(&self) -> DerivePolicy {
        self.policy
    }
}

/// The extracted PRK, held per hash so `expand` needs no re-dispatch.
enum Prk {
    Sha256(Hkdf<Sha256>),
    Sha384(Hkdf<Sha384>),
    Sha512(Hkdf<Sha512>),
}

impl std::fmt::Debug for Prk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hash = match self {
            Prk::Sha256(_) => "SHA-256",
            Prk::Sha384(_) => "SHA-384",
            Prk::Sha512(_) => "SHA-512",
        };
        f.debug_struct("Prk").field("hash", &hash).finish()
    }
}

/// A `derivation.derive-input` minted by `hkdf.prepare`/`prepare-from`:
/// the PRK (extract already run), the bound `info`, and the grants copied
/// from the pre-image.
#[derive(Debug)]
pub struct DeriveInputMaterial {
    prk: Prk,
    info: Vec<u8>,
    policy: DerivePolicy,
}

impl DeriveInputMaterial {
    /// Parameterize a derivation over imported IKM (`hkdf.prepare`):
    /// HKDF-Extract with `salt`, `info` bound for expand, grants copied.
    pub fn prepare(
        variant: Sha2Variant,
        ikm: &IkmMaterial,
        salt: &[u8],
        info: Vec<u8>,
    ) -> Result<Self, Error> {
        Ok(Self {
            prk: extract(variant, salt, &ikm.raw)?,
            info,
            policy: ikm.policy,
        })
    }

    /// Parameterize a derivation over another derivation's output
    /// (`hkdf.prepare-from`): the upstream input is realized at its
    /// natural length — which, this core serving only KDF sources today,
    /// no upstream has, so this fails `error.other` exactly as the
    /// platform's `deriveKey(… → "HKDF")` does. The signature is the
    /// chaining contract; agreement sources make it succeed.
    pub fn prepare_from(
        variant: Sha2Variant,
        upstream: &DeriveInputMaterial,
        salt: &[u8],
        info: Vec<u8>,
    ) -> Result<Self, Error> {
        if !upstream.policy.derive_key {
            return Err(not_permitted("derive-key"));
        }
        let ikm = upstream.natural_output()?;
        Ok(Self {
            prk: extract(variant, salt, &ikm)?,
            info,
            policy: upstream.policy,
        })
    }

    pub fn policy(&self) -> DerivePolicy {
        self.policy
    }

    /// The derived bits at `length_bits` (the `derive-input.derive-bits`
    /// contract): requires the `derive-bits` grant, a multiple of 8, and —
    /// this input being a KDF's — an explicit length.
    pub fn derive_bits(&self, length_bits: Option<u32>) -> Result<Zeroizing<Vec<u8>>, Error> {
        if !self.policy.derive_bits {
            return Err(not_permitted("derive-bits"));
        }
        let Some(bits) = length_bits else {
            return Err(Error::Other(
                "a KDF's output length is a caller choice: derive-bits from an HKDF \
                 input requires an explicit length"
                    .into(),
            ));
        };
        self.output(bits)
    }

    /// The derived bits for a `derive-key` mint: grant-checked for
    /// `derive-key` (and for `derive-bits` when the mint requests an
    /// extractable key — an exportable key is bits disclosure by other
    /// means), then expanded at the target's length.
    pub fn derive_for_key(
        &self,
        length_bits: u32,
        extractable: bool,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        if !self.policy.derive_key {
            return Err(not_permitted("derive-key"));
        }
        if extractable && !self.policy.derive_bits {
            return Err(Error::NotPermitted(
                "minting an extractable key requires the derive-bits grant: an \
                 exportable key is bits disclosure by other means"
                    .into(),
            ));
        }
        self.output(length_bits)
    }

    /// HKDF-Expand at `bits`, enforcing the byte-multiple rule and RFC
    /// 5869's 255·HashLen bound (which `expand` reports).
    fn output(&self, bits: u32) -> Result<Zeroizing<Vec<u8>>, Error> {
        if bits == 0 || !bits.is_multiple_of(8) {
            return Err(Error::Other(format!(
                "derive length must be a non-zero multiple of 8 bits, got {bits}"
            )));
        }
        let mut okm = Zeroizing::new(vec![0u8; (bits / 8) as usize]);
        let expanded = match &self.prk {
            Prk::Sha256(hk) => hk.expand(&self.info, &mut okm),
            Prk::Sha384(hk) => hk.expand(&self.info, &mut okm),
            Prk::Sha512(hk) => hk.expand(&self.info, &mut okm),
        };
        expanded.map_err(|_| {
            Error::Other(format!(
                "HKDF output length {} exceeds RFC 5869's 255 blocks of the hash",
                bits / 8
            ))
        })?;
        Ok(okm)
    }

    /// The natural output length, in bits, of the source this input was
    /// parameterized from. A KDF has none: its output length is a caller
    /// choice, per the WIT `derive-bits` doc.
    fn natural_output(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        Err(Error::Other(
            "a KDF input has no natural output length: chaining realizes the upstream \
             at its natural length, which only agreement sources define"
                .into(),
        ))
    }
}

/// Mint an HMAC key from a parameterized derivation (the
/// `hmac-sha2.derive-key` contract): the input realized at the effective
/// generate-key length, then subject to the import contract.
pub fn derive_mac_key(
    input: &DeriveInputMaterial,
    variant: Sha2Variant,
    length: Option<u32>,
    policy: crate::MacPolicy,
) -> Result<crate::MacKeyMaterial, Error> {
    policy.check_useful()?;
    let bits = crate::mac::hmac_length_bits(variant, length)?;
    let okm = input.derive_for_key(bits, policy.extractable)?;
    crate::MacKeyMaterial::import(variant, okm.to_vec(), policy)
}

/// Mint an AES-GCM key from a parameterized derivation (the
/// `aes-gcm.derive-key` contract): the input realized at the variant's key
/// length, then subject to the import contract (which declines AES-192).
pub fn derive_aes_gcm_key(
    input: &DeriveInputMaterial,
    variant: crate::AesVariant,
    policy: crate::AeadPolicy,
) -> Result<crate::AeadKeyMaterial, Error> {
    policy.check_useful()?;
    let bits = match variant {
        crate::AesVariant::Aes128 => 128,
        crate::AesVariant::Aes192 => 192,
        crate::AesVariant::Aes256 => 256,
    };
    let okm = input.derive_for_key(bits, policy.extractable)?;
    crate::AeadKeyMaterial::import_aes_gcm(variant, okm.to_vec(), policy)
}

/// HKDF-Extract with `salt` over `ikm`, per the declared variant.
fn extract(variant: Sha2Variant, salt: &[u8], ikm: &[u8]) -> Result<Prk, Error> {
    let salt = (!salt.is_empty()).then_some(salt);
    Ok(match served_sha2(variant)? {
        Sha2::Sha256 => Prk::Sha256(Hkdf::new(salt, ikm)),
        Sha2::Sha384 => Prk::Sha384(Hkdf::new(salt, ikm)),
        Sha2::Sha512 => Prk::Sha512(Hkdf::new(salt, ikm)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_both() -> DerivePolicy {
        DerivePolicy {
            derive_bits: true,
            derive_key: true,
        }
    }

    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 5869 A.1: basic SHA-256 case.
    #[test]
    fn rfc5869_case_1() {
        let ikm = IkmMaterial::import(vec![0x0b; 22], policy_both()).unwrap();
        let input = DeriveInputMaterial::prepare(
            Sha2Variant::Sha256,
            &ikm,
            &unhex("000102030405060708090a0b0c"),
            unhex("f0f1f2f3f4f5f6f7f8f9"),
        )
        .unwrap();
        let okm = input.derive_bits(Some(42 * 8)).unwrap();
        assert_eq!(
            okm.as_slice(),
            unhex(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
                 34007208d5b887185865"
            )
            .as_slice()
        );
    }

    /// RFC 5869 A.3: zero-length salt and info.
    #[test]
    fn rfc5869_case_3() {
        let ikm = IkmMaterial::import(vec![0x0b; 22], policy_both()).unwrap();
        let input =
            DeriveInputMaterial::prepare(Sha2Variant::Sha256, &ikm, &[], Vec::new()).unwrap();
        let okm = input.derive_bits(Some(42 * 8)).unwrap();
        assert_eq!(
            okm.as_slice(),
            unhex(
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
                 9d201395faa4b61a96c8"
            )
            .as_slice()
        );
    }

    /// Grants gate exactly their operations, and the extractable-key mint
    /// requires both (the cap rule).
    #[test]
    fn grants_gate_operations() {
        let bits_only = DerivePolicy {
            derive_bits: true,
            derive_key: false,
        };
        let key_only = DerivePolicy {
            derive_bits: false,
            derive_key: true,
        };

        let ikm = IkmMaterial::import(vec![1; 32], bits_only).unwrap();
        let input =
            DeriveInputMaterial::prepare(Sha2Variant::Sha256, &ikm, &[], Vec::new()).unwrap();
        assert!(input.derive_bits(Some(256)).is_ok());
        assert!(matches!(
            input.derive_for_key(256, false),
            Err(Error::NotPermitted(_))
        ));

        let ikm = IkmMaterial::import(vec![1; 32], key_only).unwrap();
        let input =
            DeriveInputMaterial::prepare(Sha2Variant::Sha256, &ikm, &[], Vec::new()).unwrap();
        assert!(matches!(
            input.derive_bits(Some(256)),
            Err(Error::NotPermitted(_))
        ));
        assert!(input.derive_for_key(256, false).is_ok());
        assert!(
            matches!(input.derive_for_key(256, true), Err(Error::NotPermitted(_))),
            "an extractable key from a bits-less input is the laundering the cap rule closes"
        );
    }

    /// The contract's parameter errors: no length for a KDF input, sub-byte
    /// and zero lengths, the RFC 5869 output bound, empty IKM, a grantless
    /// policy, and KDF-from-KDF chaining.
    #[test]
    fn contract_errors() {
        assert!(matches!(
            IkmMaterial::import(Vec::new(), policy_both()),
            Err(Error::InvalidKey(_))
        ));
        assert!(matches!(
            IkmMaterial::import(vec![1], DerivePolicy::default()),
            Err(Error::NotPermitted(_))
        ));

        let ikm = IkmMaterial::import(vec![1; 32], policy_both()).unwrap();
        let input =
            DeriveInputMaterial::prepare(Sha2Variant::Sha256, &ikm, &[], Vec::new()).unwrap();
        assert!(matches!(input.derive_bits(None), Err(Error::Other(_))));
        assert!(matches!(input.derive_bits(Some(0)), Err(Error::Other(_))));
        assert!(matches!(input.derive_bits(Some(12)), Err(Error::Other(_))));
        assert!(matches!(
            input.derive_bits(Some(255 * 32 * 8 + 8)),
            Err(Error::Other(_))
        ));
        assert!(input.derive_bits(Some(255 * 32 * 8)).is_ok());

        assert!(matches!(
            DeriveInputMaterial::prepare_from(Sha2Variant::Sha256, &input, &[], Vec::new()),
            Err(Error::Other(_)),
        ));

        assert!(matches!(
            DeriveInputMaterial::prepare(Sha2Variant::Sha224, &ikm, &[], Vec::new()),
            Err(Error::Unsupported(_))
        ));
    }
}
