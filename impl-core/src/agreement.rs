//! X25519 key agreement (RFC 7748): the shared core behind the
//! `key-agreement` and `x25519` interfaces.
//!
//! `agree` runs the Montgomery-ladder scalar multiplication eagerly — the
//! WIT pins the all-zero contributory check at `agree`, which requires the
//! shared secret to have been computed there — and hands the result to the
//! derivation core as an agreed [`DeriveInputMaterial`] with a natural
//! output length, the property no KDF source has.

use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::policy::{AgreementPolicy, DerivePolicy};
use crate::{DeriveInputMaterial, Error, RngError};

/// The registry name every key this module mints is bound to.
const ALGORITHM: &str = "X25519";

/// The `key-agreement.public-key` resource's material.
#[derive(Debug)]
pub struct AgreementPublicMaterial {
    public: PublicKey,
}

impl AgreementPublicMaterial {
    /// Import a raw 32-byte u-coordinate, per the `x25519.import-public-key-raw`
    /// contract: any 32-byte string is accepted (degenerate keys surface at
    /// `agree`); any other length is `invalid-key`.
    pub fn import(raw: &[u8]) -> Result<Self, Error> {
        let bytes: [u8; 32] = raw.try_into().map_err(|_| {
            Error::InvalidKey(format!(
                "X25519 public keys are 32-byte u-coordinates, got {} bytes",
                raw.len()
            ))
        })?;
        Ok(Self {
            public: PublicKey::from(bytes),
        })
    }

    /// The registry algorithm name (`public-key.algorithm-name`).
    pub fn name(&self) -> &'static str {
        ALGORITHM
    }

    /// The raw u-coordinate (`public-key.export-key-raw`).
    ///
    /// The copy returned is *not* protected — public material, so unlike
    /// the key exports there is nothing to protect.
    pub fn export(&self) -> Vec<u8> {
        self.public.as_bytes().to_vec()
    }

    /// The RFC 8037 OKP public JWK (`public-key.export-key-jwk`).
    pub fn export_jwk(&self) -> String {
        crate::jwk::build_okp_public("X25519", self.public.as_bytes())
    }
}

/// The `key-agreement.secret-key` resource's material.
pub struct AgreementSecretMaterial {
    secret: StaticSecret,
    policy: AgreementPolicy,
}

impl std::fmt::Debug for AgreementSecretMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgreementSecretMaterial")
            .field("algorithm", &ALGORITHM)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl AgreementSecretMaterial {
    /// Import an RFC 8037 OKP private JWK, per the
    /// `x25519.import-secret-key-jwk` contract. This implementation takes
    /// the MAY: a JWK whose `x` is not `d`'s public key is rejected
    /// `invalid-key` — it can check (the platform-backed hosts cannot),
    /// and a mismatched pair is never what a caller meant.
    pub fn import_jwk(jwk: &str, policy: AgreementPolicy) -> Result<Self, Error> {
        policy.check_useful()?;
        let okp = crate::jwk::parse_okp_private(jwk, "X25519", policy.extractable)?;
        let d: [u8; 32] = okp.d.as_slice().try_into().map_err(|_| {
            Error::InvalidKey(format!(
                "X25519 private keys are 32-byte scalars, got {} bytes",
                okp.d.len()
            ))
        })?;
        let secret = StaticSecret::from(d);
        if okp.x.as_slice() != PublicKey::from(&secret).as_bytes() {
            return Err(Error::InvalidKey(
                "JWK `x` is not the public key of `d`".into(),
            ));
        }
        Ok(Self { secret, policy })
    }

    /// Generate a fresh key pair, per the `x25519.generate-key` contract.
    #[allow(
        clippy::result_large_err,
        reason = "matches the other generate paths' RngError-outer shape"
    )]
    pub fn generate(
        policy: AgreementPolicy,
    ) -> Result<Result<(Self, AgreementPublicMaterial), Error>, RngError> {
        if let Err(err) = policy.check_useful() {
            return Ok(Err(err));
        }
        let mut bytes = Zeroizing::new([0u8; 32]);
        crate::fill_random(bytes.as_mut())?;
        let secret = StaticSecret::from(*bytes);
        let public = AgreementPublicMaterial {
            public: PublicKey::from(&secret),
        };
        Ok(Ok((Self { secret, policy }, public)))
    }

    /// The shared secret with `peer`, as an agreed derive input
    /// (`secret-key.agree`): the DH runs now, and an all-zero result — a
    /// small-order peer — fails `invalid-key`, in constant time
    /// (`was_contributory` is a constant-time comparison in dalek).
    pub fn agree(&self, peer: &AgreementPublicMaterial) -> Result<DeriveInputMaterial, Error> {
        let shared = self.secret.diffie_hellman(&peer.public);
        if !shared.was_contributory() {
            return Err(Error::InvalidKey(
                "the shared secret is all-zero: the peer public key is a small-order point".into(),
            ));
        }
        Ok(DeriveInputMaterial::agreed(
            Zeroizing::new(shared.as_bytes().to_vec()),
            self.derive_policy(),
        ))
    }

    /// The registry algorithm name (`secret-key.algorithm-name`).
    pub fn name(&self) -> &'static str {
        ALGORITHM
    }

    pub fn policy(&self) -> AgreementPolicy {
        self.policy
    }

    /// The grants agreed inputs carry (`derive-input`'s slice of the
    /// mint policy).
    fn derive_policy(&self) -> DerivePolicy {
        DerivePolicy {
            derive_bits: self.policy.derive_bits,
            derive_key: self.policy.derive_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::build_okp_private;

    fn policy_all() -> AgreementPolicy {
        AgreementPolicy {
            derive_bits: true,
            derive_key: true,
            extractable: false,
        }
    }

    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 7748 §6.1: Alice and Bob's published key pairs agree on the
    /// published shared secret, in both directions and through the JWK
    /// import path.
    #[test]
    fn rfc7748_alice_and_bob() {
        let alice_d = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
        let alice_x = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
        let bob_d = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
        let bob_x = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
        let shared = unhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        let alice = AgreementSecretMaterial::import_jwk(
            &build_okp_private("X25519", &unhex(alice_x), &unhex(alice_d)),
            policy_all(),
        )
        .unwrap();
        let bob = AgreementSecretMaterial::import_jwk(
            &build_okp_private("X25519", &unhex(bob_x), &unhex(bob_d)),
            policy_all(),
        )
        .unwrap();
        let bob_public = AgreementPublicMaterial::import(&unhex(bob_x)).unwrap();
        let alice_public = AgreementPublicMaterial::import(&unhex(alice_x)).unwrap();

        let a = alice.agree(&bob_public).unwrap();
        let b = bob.agree(&alice_public).unwrap();
        assert_eq!(a.derive_bits(None).unwrap().as_slice(), shared.as_slice());
        assert_eq!(b.derive_bits(None).unwrap().as_slice(), shared.as_slice());
    }

    /// A small-order peer fails the contributory check at `agree`.
    #[test]
    fn small_order_peer_fails_at_agree() {
        let (secret, _) = AgreementSecretMaterial::generate(policy_all())
            .unwrap()
            .unwrap();
        // The identity point (u = 0) is the canonical small-order case.
        let low = AgreementPublicMaterial::import(&[0u8; 32]).unwrap();
        assert!(matches!(secret.agree(&low), Err(Error::InvalidKey(_)),));
    }

    /// Import contract: mismatched `x` rejected (the MAY this
    /// implementation takes), wrong lengths rejected, grantless refused.
    #[test]
    fn import_contract() {
        let alice_d = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let bob_x = unhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        assert!(matches!(
            AgreementSecretMaterial::import_jwk(
                &build_okp_private("X25519", &bob_x, &alice_d),
                policy_all(),
            ),
            Err(Error::InvalidKey(_))
        ));
        assert!(matches!(
            AgreementSecretMaterial::import_jwk(
                &build_okp_private("X25519", &bob_x, &alice_d[..31]),
                policy_all(),
            ),
            Err(Error::InvalidKey(_))
        ));
        assert!(matches!(
            AgreementSecretMaterial::import_jwk(
                &build_okp_private("X25519", &bob_x, &alice_d),
                AgreementPolicy::default(),
            ),
            Err(Error::NotPermitted(_))
        ));
        assert!(matches!(
            AgreementPublicMaterial::import(&[1u8; 31]),
            Err(Error::InvalidKey(_))
        ));
    }

    /// Agreed inputs carry the natural-length semantics: `none` is the
    /// whole secret, truncation takes a prefix, and over-length fails —
    /// the §26.3.1 behavior no KDF input can exhibit.
    #[test]
    fn agreed_input_natural_length() {
        let (a, _) = AgreementSecretMaterial::generate(policy_all())
            .unwrap()
            .unwrap();
        let (_, b_public) = AgreementSecretMaterial::generate(policy_all())
            .unwrap()
            .unwrap();
        let input = a.agree(&b_public).unwrap();
        let whole = input.derive_bits(None).unwrap();
        assert_eq!(whole.len(), 32);
        let prefix = input.derive_bits(Some(128)).unwrap();
        assert_eq!(prefix.as_slice(), &whole[..16]);
        assert!(matches!(input.derive_bits(Some(264)), Err(Error::Other(_))));
    }
}
