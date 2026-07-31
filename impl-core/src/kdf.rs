//! The KDFs (HKDF, RFC 5869; PBKDF2, RFC 8018): the shared derivation core
//! behind the `derivation`, `hkdf`, and `pbkdf2` interfaces.
//!
//! The `derive-input` resource's semantics — a parameterized derivation —
//! are implemented here as [`DeriveInputMaterial`], which runs each
//! derivation as early as the KDF's structure permits. HKDF's `prepare` runs HKDF-Extract
//! immediately, so the input retains the PRK and the bound `info`, never
//! the IKM. PBKDF2 has no extract step — its whole cost is per-block and
//! length-dependent — so the most its `prepare` can shed is the raw
//! password: the input retains the PRF's *keyed state* (the HMAC key
//! schedule), which is password-equivalent in sensitivity, like the PRK,
//! but is not the password bytes. Either way, an input's existence does
//! not keep the base-secret resource's raw bytes in memory.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
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

/// The `pbkdf2.password` resource's material: bytes that no operation
/// returns.
#[derive(Debug)]
pub struct PasswordMaterial {
    raw: Zeroizing<Vec<u8>>,
    policy: DerivePolicy,
}

impl PasswordMaterial {
    /// Import a password, per the `pbkdf2.import-password` contract:
    /// empty passwords are accepted (deliberately asymmetric with
    /// [`IkmMaterial::import`] — see the WIT doc), a grantless policy is
    /// `not-permitted`.
    pub fn import(raw: Vec<u8>, policy: DerivePolicy) -> Result<Self, Error> {
        policy.check_useful()?;
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

/// The PBKDF2 PRF: HMAC keyed by the password (the key schedule computed
/// at `prepare`, the raw password dropped), held per hash.
enum PbkdfPrf {
    Sha256(Hmac<Sha256>),
    Sha384(Hmac<Sha384>),
    Sha512(Hmac<Sha512>),
}

impl std::fmt::Debug for PbkdfPrf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hash = match self {
            PbkdfPrf::Sha256(_) => "SHA-256",
            PbkdfPrf::Sha384(_) => "SHA-384",
            PbkdfPrf::Sha512(_) => "SHA-512",
        };
        f.debug_struct("PbkdfPrf").field("hash", &hash).finish()
    }
}

/// A parameterized derivation, run as far as its KDF's structure
/// permits (see the module doc).
#[derive(Debug)]
enum Realized {
    /// HKDF after extract: the PRK and the `info` bound for expand.
    Hkdf { prk: Prk, info: Vec<u8> },
    /// PBKDF2 after the PRF key schedule: the keyed HMAC, the salt, and
    /// the iteration count.
    Pbkdf2 {
        prf: PbkdfPrf,
        salt: Vec<u8>,
        iterations: u32,
    },
}

/// A `derivation.derive-input` minted by `hkdf.prepare`/`prepare-from` or
/// `pbkdf2.prepare`, with the grants copied from the base secret.
#[derive(Debug)]
pub struct DeriveInputMaterial {
    realized: Realized,
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
            realized: Realized::Hkdf {
                prk: extract(variant, salt, &ikm.raw)?,
                info,
            },
            policy: ikm.policy,
        })
    }

    /// Parameterize a PBKDF2 derivation (`pbkdf2.prepare`): the PRF's key
    /// schedule runs now (the input retains keyed state, not the
    /// password), salt and iteration count are bound, and a zero
    /// iteration count fails `error.other` — the platform's
    /// `OperationError`, checked here so a misparameterized input cannot
    /// mint.
    pub fn prepare_pbkdf2(
        variant: Sha2Variant,
        password: &PasswordMaterial,
        salt: Vec<u8>,
        iterations: u32,
    ) -> Result<Self, Error> {
        if iterations == 0 {
            return Err(Error::Other(
                "PBKDF2 requires a positive iteration count".into(),
            ));
        }
        let keyed = "HMAC accepts any key length";
        let prf = match served_sha2(variant)? {
            Sha2::Sha256 => PbkdfPrf::Sha256(Hmac::new_from_slice(&password.raw).expect(keyed)),
            Sha2::Sha384 => PbkdfPrf::Sha384(Hmac::new_from_slice(&password.raw).expect(keyed)),
            Sha2::Sha512 => PbkdfPrf::Sha512(Hmac::new_from_slice(&password.raw).expect(keyed)),
        };
        Ok(Self {
            realized: Realized::Pbkdf2 {
                prf,
                salt,
                iterations,
            },
            policy: password.policy,
        })
    }

    /// Parameterize a derivation over another derivation's output
    /// (`hkdf.prepare-from`): the upstream derivation runs at its
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
            realized: Realized::Hkdf {
                prk: extract(variant, salt, &ikm)?,
                info,
            },
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
                "a KDF's output length is a caller choice: derive-bits from a KDF \
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
        match &self.realized {
            Realized::Hkdf { prk, info } => {
                let expanded = match prk {
                    Prk::Sha256(hk) => hk.expand(info, &mut okm),
                    Prk::Sha384(hk) => hk.expand(info, &mut okm),
                    Prk::Sha512(hk) => hk.expand(info, &mut okm),
                };
                expanded.map_err(|_| {
                    Error::Other(format!(
                        "HKDF output length {} exceeds RFC 5869's 255 blocks of the hash",
                        bits / 8
                    ))
                })?;
            }
            Realized::Pbkdf2 {
                prf,
                salt,
                iterations,
            } => match prf {
                PbkdfPrf::Sha256(mac) => pbkdf2_blocks(mac, salt, *iterations, &mut okm),
                PbkdfPrf::Sha384(mac) => pbkdf2_blocks(mac, salt, *iterations, &mut okm),
                PbkdfPrf::Sha512(mac) => pbkdf2_blocks(mac, salt, *iterations, &mut okm),
            },
        }
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
/// `hmac-sha2.derive-key` contract): the derivation run at the effective
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
/// `aes-gcm.derive-key` contract): the derivation run at the variant's key
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

/// RFC 8018 §5.2: fill `out` with PBKDF2 blocks
/// `T_i = U_1 ^ … ^ U_c`, `U_1 = PRF(P, S ‖ INT(i))`, `U_j = PRF(P, U_{j-1})`,
/// using the already-keyed PRF (cloning it per invocation reuses the key
/// schedule; the password itself is not retained).
fn pbkdf2_blocks<M: Mac + Clone>(prf: &M, salt: &[u8], iterations: u32, out: &mut [u8]) {
    let hash_len = M::output_size();
    for (index, chunk) in out.chunks_mut(hash_len).enumerate() {
        let block = (index as u32) + 1;
        let mut mac = prf.clone();
        mac.update(salt);
        mac.update(&block.to_be_bytes());
        let mut u = mac.finalize().into_bytes();
        let mut t = u.clone();
        for _ in 1..iterations {
            let mut mac = prf.clone();
            mac.update(&u);
            u = mac.finalize().into_bytes();
            for (t_byte, u_byte) in t.iter_mut().zip(u.iter()) {
                *t_byte ^= u_byte;
            }
        }
        chunk.copy_from_slice(&t[..chunk.len()]);
    }
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

    /// RFC 7914 §11: PBKDF2-HMAC-SHA-256 known answers (c = 1 and a
    /// two-block output, exercising the block loop and the XOR fold).
    #[test]
    fn rfc7914_pbkdf2_vectors() {
        let password = PasswordMaterial::import(b"passwd".to_vec(), policy_both()).unwrap();
        let input = DeriveInputMaterial::prepare_pbkdf2(
            Sha2Variant::Sha256,
            &password,
            b"salt".to_vec(),
            1,
        )
        .unwrap();
        let okm = input.derive_bits(Some(64 * 8)).unwrap();
        assert_eq!(
            okm.as_slice(),
            unhex(
                "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc\
                 49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
            )
            .as_slice()
        );
    }

    /// PBKDF2 contract errors: zero iterations at prepare, empty password
    /// accepted (the documented asymmetry with IKM), grantless refused,
    /// and KDF-from-KDF chaining fails for PBKDF2 inputs too.
    #[test]
    fn pbkdf2_contract() {
        assert!(matches!(
            PasswordMaterial::import(vec![1], DerivePolicy::default()),
            Err(Error::NotPermitted(_))
        ));
        let empty = PasswordMaterial::import(Vec::new(), policy_both()).unwrap();
        let input = DeriveInputMaterial::prepare_pbkdf2(
            Sha2Variant::Sha256,
            &empty,
            vec![1, 2, 3, 4],
            4096,
        )
        .unwrap();
        assert!(input.derive_bits(Some(256)).is_ok());

        let password = PasswordMaterial::import(b"p".to_vec(), policy_both()).unwrap();
        assert!(matches!(
            DeriveInputMaterial::prepare_pbkdf2(Sha2Variant::Sha256, &password, Vec::new(), 0),
            Err(Error::Other(_))
        ));
        assert!(matches!(
            DeriveInputMaterial::prepare_pbkdf2(Sha2Variant::Sha224, &password, Vec::new(), 1),
            Err(Error::Unsupported(_))
        ));

        let input =
            DeriveInputMaterial::prepare_pbkdf2(Sha2Variant::Sha256, &password, Vec::new(), 1)
                .unwrap();
        assert!(matches!(
            DeriveInputMaterial::prepare_from(Sha2Variant::Sha256, &input, &[], Vec::new()),
            Err(Error::Other(_))
        ));
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
