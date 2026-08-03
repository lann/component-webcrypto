//! Key agreement — X25519 (RFC 7748) and ECDH over the NIST prime-order
//! curves (SP 800-56A): the shared core behind the `key-agreement`,
//! `x25519`, and `ecdh` interfaces.
//!
//! `agree` runs the scalar multiplication eagerly — the WIT pins the
//! all-zero contributory check at `agree`, which requires the shared
//! secret to have been computed there — and hands the result to the
//! derivation core as an agreed [`DeriveInputMaterial`] with a natural
//! output length, the property no KDF source has. The contributory check
//! itself exists only on the X25519 arms: the ECDH imports reject points
//! not on the curve, and a valid point times a valid scalar on a
//! prime-order curve cannot be the point at infinity (the WIT `ecdh`
//! doc's contract).

use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::policy::{AgreementPolicy, DerivePolicy};
use crate::{DeriveInputMaterial, EcdhVariant, Error, RngError};

/// The registry name X25519 keys are bound to.
const X25519_NAME: &str = "X25519";

/// The registry name ECDH keys are bound to, curve-independently
/// (WebCrypto's `KeyAlgorithm.name`).
const ECDH_NAME: &str = "ECDH";

/// The served curve of an ECDH variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EcdhCurve {
    P256,
    P384,
}

/// Resolve a WIT `ecdh-variant` to its served curve, declining P-521
/// (`unsupported`, per the enum's doc).
fn served_curve(variant: EcdhVariant) -> Result<EcdhCurve, Error> {
    match variant {
        EcdhVariant::P256 => Ok(EcdhCurve::P256),
        EcdhVariant::P384 => Ok(EcdhCurve::P384),
        EcdhVariant::P521 => Err(Error::Unsupported(
            "ECDH P-521 is not served by this implementation".into(),
        )),
    }
}

/// The registry curve name for a served curve.
fn curve_name(curve: EcdhCurve) -> &'static str {
    match curve {
        EcdhCurve::P256 => "P-256",
        EcdhCurve::P384 => "P-384",
    }
}

/// The curve's field size in bytes: the length of a coordinate, a scalar,
/// and the agreed shared secret.
fn field_len(curve: EcdhCurve) -> usize {
    match curve {
        EcdhCurve::P256 => 32,
        EcdhCurve::P384 => 48,
    }
}

/// Stamp one body per served ECDH curve, dispatching on [`EcdhCurve`].
/// Within the body, `$c` aliases the curve's crate, `$mint` is the curve's
/// `EcdhP256`/`EcdhP384` constructor of `$enum`, and `$name` binds the
/// registry curve name.
macro_rules! per_curve {
    ($curve:expr, $enum:ident, |$c:ident, $mint:ident, $name:ident| $body:expr) => {
        match $curve {
            EcdhCurve::P256 => {
                use p256 as $c;
                let $mint = $enum::EcdhP256;
                let $name = "P-256";
                $body
            }
            EcdhCurve::P384 => {
                use p384 as $c;
                let $mint = $enum::EcdhP384;
                let $name = "P-384";
                $body
            }
        }
    };
}

/// The `key-agreement.public-key` resource's material, bound to its
/// algorithm (and, for ECDH, its curve) at minting.
pub enum AgreementPublicMaterial {
    X25519(PublicKey),
    EcdhP256(p256::PublicKey),
    EcdhP384(p384::PublicKey),
}

impl AgreementPublicMaterial {
    /// Import a raw 32-byte u-coordinate, per the `x25519.import-public-key-raw`
    /// contract: any 32-byte string is accepted (degenerate keys surface at
    /// `agree`); any other length is `invalid-key`.
    pub fn import_x25519(raw: &[u8]) -> Result<Self, Error> {
        let bytes: [u8; 32] = raw.try_into().map_err(|_| {
            Error::InvalidKey(format!(
                "X25519 public keys are 32-byte u-coordinates, got {} bytes",
                raw.len()
            ))
        })?;
        Ok(Self::X25519(PublicKey::from(bytes)))
    }

    /// Import an X25519 public key from a SubjectPublicKeyInfo (the
    /// `x25519.import-public-key-spki` contract): the embedded coordinate
    /// is admitted exactly as the raw import admits it.
    pub fn import_x25519_spki(spki: &[u8]) -> Result<Self, Error> {
        let raw = crate::der8410::parse_rfc8410_spki(crate::der8410::OID_X25519, "X25519", spki)?;
        Self::import_x25519(&raw)
    }

    /// Import an X25519 public key from an RFC 8037 OKP public JWK (the
    /// `x25519.import-public-key-jwk` contract).
    pub fn import_x25519_jwk(jwk: &str) -> Result<Self, Error> {
        let raw = crate::jwk::parse_okp_public(jwk, "X25519", None)?;
        Self::import_x25519(&raw)
    }

    /// Import an uncompressed SEC1 point for the declared variant,
    /// rendering `invalid-key` for anything else — including compressed
    /// encodings and points not on the curve (the
    /// `ecdh.import-public-key-raw` contract).
    pub fn import_ecdh(variant: EcdhVariant, raw: &[u8]) -> Result<Self, Error> {
        let curve = served_curve(variant)?;
        let expected = 1 + 2 * field_len(curve);
        if raw.len() != expected || raw[0] != 0x04 {
            return Err(Error::InvalidKey(format!(
                "ECDH {} public keys are uncompressed SEC1 points ({expected} bytes, leading 0x04)",
                curve_name(curve)
            )));
        }
        per_curve!(curve, Self, |c, mint, name| {
            c::PublicKey::from_sec1_bytes(raw)
                .map(mint)
                .map_err(|err| Error::InvalidKey(format!("invalid {name} public key: {err}")))
        })
    }

    /// Import an ECDH public key from a SubjectPublicKeyInfo (the
    /// `ecdh.import-public-key-spki` contract): the encoded curve must
    /// match the declared variant's.
    pub fn import_ecdh_spki(variant: EcdhVariant, spki: &[u8]) -> Result<Self, Error> {
        use spki::DecodePublicKey as _;
        let curve = served_curve(variant)?;
        per_curve!(curve, Self, |c, mint, name| {
            c::PublicKey::from_public_key_der(spki)
                .map(mint)
                .map_err(|err| Error::InvalidKey(format!("invalid {name} spki: {err}")))
        })
    }

    /// Import an ECDH public key from an EC public JWK (the
    /// `ecdh.import-public-key-jwk` contract): the JWK's `crv` must match
    /// the declared variant's curve, and the encoded point is admitted
    /// exactly as the raw import admits it.
    pub fn import_ecdh_jwk(variant: EcdhVariant, jwk: &str) -> Result<Self, Error> {
        let curve = served_curve(variant)?;
        let parsed = crate::jwk::parse_ec(jwk, curve_name(curve), false, false, None)?;
        let point =
            crate::jwk::ec_point(curve_name(curve), field_len(curve), &parsed.x, &parsed.y)?;
        Self::import_ecdh(variant, &point)
    }

    /// The registry algorithm name (`public-key.algorithm-name`).
    pub fn name(&self) -> &'static str {
        match self {
            Self::X25519(_) => X25519_NAME,
            Self::EcdhP256(_) | Self::EcdhP384(_) => ECDH_NAME,
        }
    }

    /// The key's algorithm and, for ECDH, its curve — the pair `agree`'s
    /// mismatch check compares and its error message names.
    fn describe(&self) -> &'static str {
        match self {
            Self::X25519(_) => "X25519",
            Self::EcdhP256(_) => "ECDH P-256",
            Self::EcdhP384(_) => "ECDH P-384",
        }
    }

    /// The public key material in the minting interface's documented form:
    /// the raw u-coordinate for X25519, an uncompressed SEC1 point for
    /// ECDH (`public-key.export-key-raw`).
    ///
    /// The copy returned is *not* protected — public material, so unlike
    /// the key exports there is nothing to protect.
    pub fn export(&self) -> Vec<u8> {
        match self {
            Self::X25519(public) => public.as_bytes().to_vec(),
            Self::EcdhP256(public) => public.to_encoded_point(false).as_bytes().to_vec(),
            Self::EcdhP384(public) => public.to_encoded_point(false).as_bytes().to_vec(),
        }
    }

    /// The public JWK (`public-key.export-key-jwk`): RFC 8037 OKP for
    /// X25519, RFC 7518 EC for ECDH.
    pub fn export_jwk(&self) -> String {
        match self {
            Self::X25519(public) => crate::jwk::build_okp_public("X25519", public.as_bytes()),
            Self::EcdhP256(public) => {
                let point = public.to_encoded_point(false);
                crate::jwk::build_ec_public("P-256", point.x().unwrap(), point.y().unwrap())
            }
            Self::EcdhP384(public) => {
                let point = public.to_encoded_point(false);
                crate::jwk::build_ec_public("P-384", point.x().unwrap(), point.y().unwrap())
            }
        }
    }

    /// The SubjectPublicKeyInfo form (`public-key.export-key-spki`).
    pub fn export_spki(&self) -> Vec<u8> {
        use spki::EncodePublicKey as _;
        match self {
            Self::X25519(public) => {
                crate::der8410::rfc8410_spki(crate::der8410::OID_X25519, public.as_bytes())
            }
            Self::EcdhP256(public) => public
                .to_public_key_der()
                .expect("valid key encodes")
                .into_vec(),
            Self::EcdhP384(public) => public
                .to_public_key_der()
                .expect("valid key encodes")
                .into_vec(),
        }
    }
}

// Public material is not secret, but printing it wholesale is rarely
// useful; identify the key by algorithm only.
impl std::fmt::Debug for AgreementPublicMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgreementPublicMaterial")
            .field("algorithm", &self.describe())
            .finish()
    }
}

/// The private key backing an [`AgreementSecretMaterial`].
enum AgreementSecret {
    X25519(StaticSecret),
    EcdhP256(p256::SecretKey),
    EcdhP384(p384::SecretKey),
}

/// The `key-agreement.secret-key` resource's material.
pub struct AgreementSecretMaterial {
    secret: AgreementSecret,
    policy: AgreementPolicy,
}

impl std::fmt::Debug for AgreementSecretMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgreementSecretMaterial")
            .field("algorithm", &self.describe())
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
    pub fn import_x25519_jwk(jwk: &str, policy: AgreementPolicy) -> Result<Self, Error> {
        policy.check_useful()?;
        let okp = crate::jwk::parse_okp_private(jwk, "X25519", policy.extractable, None)?;
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
        Ok(Self {
            secret: AgreementSecret::X25519(secret),
            policy,
        })
    }

    /// Import a static X25519 secret key from an RFC 8410 PKCS#8
    /// PrivateKeyInfo (the `x25519.import-secret-key-pkcs8` contract): the
    /// scalar is clamped at use per RFC 7748, like the JWK import's `d`.
    pub fn import_x25519_pkcs8(pkcs8_der: &[u8], policy: AgreementPolicy) -> Result<Self, Error> {
        policy.check_useful()?;
        let scalar =
            crate::der8410::parse_rfc8410_pkcs8(crate::der8410::OID_X25519, "X25519", pkcs8_der)?;
        Ok(Self {
            secret: AgreementSecret::X25519(StaticSecret::from(*scalar)),
            policy,
        })
    }

    /// Generate a fresh X25519 key pair, per the `x25519.generate-key`
    /// contract.
    #[allow(
        clippy::result_large_err,
        reason = "matches the other generate paths' RngError-outer shape"
    )]
    pub fn generate_x25519(
        policy: AgreementPolicy,
    ) -> Result<Result<(Self, AgreementPublicMaterial), Error>, RngError> {
        if let Err(err) = policy.check_useful() {
            return Ok(Err(err));
        }
        let mut bytes = Zeroizing::new([0u8; 32]);
        crate::fill_random(bytes.as_mut())?;
        let secret = StaticSecret::from(*bytes);
        let public = AgreementPublicMaterial::X25519(PublicKey::from(&secret));
        Ok(Ok((
            Self {
                secret: AgreementSecret::X25519(secret),
                policy,
            },
            public,
        )))
    }

    /// Import an EC private JWK for the declared variant, per the
    /// `ecdh.import-secret-key-jwk` contract: `d` must be the field-size
    /// scalar in `[1, n-1]`. This implementation takes the MAY: a JWK
    /// whose `x`/`y` are not the public point of `d` is rejected
    /// `invalid-key`.
    pub fn import_ecdh_jwk(
        variant: EcdhVariant,
        jwk: &str,
        policy: AgreementPolicy,
    ) -> Result<Self, Error> {
        policy.check_useful()?;
        let curve = served_curve(variant)?;
        let parsed = crate::jwk::parse_ec(jwk, curve_name(curve), true, policy.extractable, None)?;
        let d = parsed.d.as_ref().expect("private parse carries d");
        let len = field_len(curve);
        if d.len() != len {
            return Err(Error::InvalidKey(format!(
                "ECDH {} private keys are {len}-byte scalars, got {} bytes",
                curve_name(curve),
                d.len()
            )));
        }
        let secret = per_curve!(curve, AgreementSecret, |c, mint, name| {
            c::SecretKey::from_slice(d)
                .map(mint)
                .map_err(|err| Error::InvalidKey(format!("invalid {name} private key: {err}")))
        })?;
        let key = Self { secret, policy };
        let expected = crate::jwk::ec_point(curve_name(curve), len, &parsed.x, &parsed.y)?;
        if key.public().export() != expected {
            return Err(Error::InvalidKey(
                "JWK `x`/`y` are not the public point of `d`".into(),
            ));
        }
        Ok(key)
    }

    /// Import an ECDH secret key from a PKCS#8 PrivateKeyInfo (the
    /// `ecdh.import-secret-key-pkcs8` contract): the encoded curve must
    /// match the declared variant's; an embedded public key is validated
    /// by the decoder and never trusted on its own.
    pub fn import_ecdh_pkcs8(
        variant: EcdhVariant,
        pkcs8_der: &[u8],
        policy: AgreementPolicy,
    ) -> Result<Self, Error> {
        use pkcs8::DecodePrivateKey as _;
        policy.check_useful()?;
        let curve = served_curve(variant)?;
        let secret = per_curve!(curve, AgreementSecret, |c, mint, name| {
            c::SecretKey::from_pkcs8_der(pkcs8_der)
                .map(mint)
                .map_err(|err| Error::InvalidKey(format!("invalid {name} pkcs8: {err}")))
        })?;
        Ok(Self { secret, policy })
    }

    /// Generate a fresh ECDH key pair on the declared variant's curve by
    /// rejection-sampling the scalar range with fresh randomness (the
    /// probability of a retry is negligible for these curves).
    #[allow(
        clippy::result_large_err,
        reason = "matches the other generate paths' RngError-outer shape"
    )]
    pub fn generate_ecdh(
        variant: EcdhVariant,
        policy: AgreementPolicy,
    ) -> Result<Result<(Self, AgreementPublicMaterial), Error>, RngError> {
        if let Err(err) = policy.check_useful() {
            return Ok(Err(err));
        }
        let curve = match served_curve(variant) {
            Ok(curve) => curve,
            Err(err) => return Ok(Err(err)),
        };
        let scalar_len = field_len(curve);
        // Bound the retries, for `generate_ecdsa`'s reason: a rejection
        // arrives as `InvalidKey` whether the draw was out of range (draw
        // again) or the sampled length no longer matches the curve (can
        // never succeed), so an unbounded loop would hang on the latter.
        const ATTEMPTS: usize = 8;
        for _ in 0..ATTEMPTS {
            let mut raw = Zeroizing::new(vec![0u8; scalar_len]);
            crate::fill_random(&mut raw)?;
            let secret = per_curve!(curve, AgreementSecret, |c, mint, _name| {
                c::SecretKey::from_slice(&raw).map(mint)
            });
            if let Ok(secret) = secret {
                let key = Self { secret, policy };
                let public = key.public();
                return Ok(Ok((key, public)));
            }
        }
        unreachable!(
            "{ATTEMPTS} rejection-sampled {scalar_len}-byte {} scalars were all \
             rejected; the sampled length no longer matches the curve",
            curve_name(curve)
        )
    }

    /// The public half, recomputed from the secret. Internal: the WIT
    /// deliberately exposes no secret-to-public derive (see
    /// `wit/README.md`, "Design notes"); this backs `generate-key`'s pair
    /// and the JWK imports' consistency checks.
    fn public(&self) -> AgreementPublicMaterial {
        match &self.secret {
            AgreementSecret::X25519(secret) => {
                AgreementPublicMaterial::X25519(PublicKey::from(secret))
            }
            AgreementSecret::EcdhP256(secret) => {
                AgreementPublicMaterial::EcdhP256(secret.public_key())
            }
            AgreementSecret::EcdhP384(secret) => {
                AgreementPublicMaterial::EcdhP384(secret.public_key())
            }
        }
    }

    /// The secret key as a private JWK (`secret-key.export-key-jwk`) — RFC
    /// 8037 OKP for X25519, RFC 7518 EC for ECDH — behind the
    /// extractability gate.
    ///
    /// The copy returned is *not* protected: see the note on
    /// [`crate`](crate#exported-material).
    pub fn export_jwk(&self) -> Result<String, Error> {
        if !self.policy.extractable {
            return Err(Error::NotExtractable);
        }
        Ok(match &self.secret {
            AgreementSecret::X25519(secret) => crate::jwk::build_okp_private(
                "X25519",
                PublicKey::from(secret).as_bytes(),
                secret.as_bytes(),
            ),
            AgreementSecret::EcdhP256(secret) => {
                let point = secret.public_key().to_encoded_point(false);
                let d = Zeroizing::new(secret.to_bytes());
                crate::jwk::build_ec_private("P-256", point.x().unwrap(), point.y().unwrap(), &d)
            }
            AgreementSecret::EcdhP384(secret) => {
                let point = secret.public_key().to_encoded_point(false);
                let d = Zeroizing::new(secret.to_bytes());
                crate::jwk::build_ec_private("P-384", point.x().unwrap(), point.y().unwrap(), &d)
            }
        })
    }

    /// The secret key as a PKCS#8 PrivateKeyInfo
    /// (`secret-key.export-key-pkcs8`), behind the same gate.
    pub fn export_pkcs8(&self) -> Result<Vec<u8>, Error> {
        use pkcs8::EncodePrivateKey as _;
        if !self.policy.extractable {
            return Err(Error::NotExtractable);
        }
        Ok(match &self.secret {
            AgreementSecret::X25519(secret) => {
                crate::der8410::rfc8410_pkcs8(crate::der8410::OID_X25519, secret.as_bytes())
                    .to_vec()
            }
            AgreementSecret::EcdhP256(secret) => secret
                .to_pkcs8_der()
                .expect("valid key encodes")
                .as_bytes()
                .to_vec(),
            AgreementSecret::EcdhP384(secret) => secret
                .to_pkcs8_der()
                .expect("valid key encodes")
                .as_bytes()
                .to_vec(),
        })
    }

    /// The shared secret with `peer`, as an agreed derive input
    /// (`secret-key.agree`). An algorithm- or curve-mismatched peer fails
    /// `invalid-key` (the `key-agreement` kind's derive-time check). On
    /// the X25519 arm the DH runs now and an all-zero result — a
    /// small-order peer — fails `invalid-key`, in constant time
    /// (`was_contributory` is a constant-time comparison in dalek); the
    /// ECDH arms need no such check (see the module doc).
    pub fn agree(&self, peer: &AgreementPublicMaterial) -> Result<DeriveInputMaterial, Error> {
        let shared: Zeroizing<Vec<u8>> = match (&self.secret, peer) {
            (AgreementSecret::X25519(secret), AgreementPublicMaterial::X25519(public)) => {
                let shared = secret.diffie_hellman(public);
                if !shared.was_contributory() {
                    return Err(Error::InvalidKey(
                        "the shared secret is all-zero: the peer public key is a small-order point"
                            .into(),
                    ));
                }
                Zeroizing::new(shared.as_bytes().to_vec())
            }
            (AgreementSecret::EcdhP256(secret), AgreementPublicMaterial::EcdhP256(public)) => {
                let shared =
                    p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
                Zeroizing::new(shared.raw_secret_bytes().to_vec())
            }
            (AgreementSecret::EcdhP384(secret), AgreementPublicMaterial::EcdhP384(public)) => {
                let shared =
                    p384::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
                Zeroizing::new(shared.raw_secret_bytes().to_vec())
            }
            (_, peer) => {
                return Err(Error::InvalidKey(format!(
                    "algorithm mismatch: an {} secret key cannot agree with an {} peer",
                    self.describe(),
                    peer.describe()
                )))
            }
        };
        Ok(DeriveInputMaterial::agreed(shared, self.derive_policy()))
    }

    /// The registry algorithm name (`secret-key.algorithm-name`).
    pub fn name(&self) -> &'static str {
        match &self.secret {
            AgreementSecret::X25519(_) => X25519_NAME,
            AgreementSecret::EcdhP256(_) | AgreementSecret::EcdhP384(_) => ECDH_NAME,
        }
    }

    /// See [`AgreementPublicMaterial::describe`].
    fn describe(&self) -> &'static str {
        match &self.secret {
            AgreementSecret::X25519(_) => "X25519",
            AgreementSecret::EcdhP256(_) => "ECDH P-256",
            AgreementSecret::EcdhP384(_) => "ECDH P-384",
        }
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
    use crate::jwk::{build_ec_private, build_ec_public, build_okp_private};
    use hex_literal::hex;

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

        let alice = AgreementSecretMaterial::import_x25519_jwk(
            &build_okp_private("X25519", &unhex(alice_x), &unhex(alice_d)),
            policy_all(),
        )
        .unwrap();
        let bob = AgreementSecretMaterial::import_x25519_jwk(
            &build_okp_private("X25519", &unhex(bob_x), &unhex(bob_d)),
            policy_all(),
        )
        .unwrap();
        let bob_public = AgreementPublicMaterial::import_x25519(&unhex(bob_x)).unwrap();
        let alice_public = AgreementPublicMaterial::import_x25519(&unhex(alice_x)).unwrap();

        let a = alice.agree(&bob_public).unwrap();
        let b = bob.agree(&alice_public).unwrap();
        assert_eq!(a.derive_bits(None).unwrap().as_slice(), shared.as_slice());
        assert_eq!(b.derive_bits(None).unwrap().as_slice(), shared.as_slice());
    }

    /// A small-order peer fails the contributory check at `agree`.
    #[test]
    fn small_order_peer_fails_at_agree() {
        let (secret, _) = AgreementSecretMaterial::generate_x25519(policy_all())
            .unwrap()
            .unwrap();
        // The identity point (u = 0) is the canonical small-order case.
        let low = AgreementPublicMaterial::import_x25519(&[0u8; 32]).unwrap();
        assert!(matches!(secret.agree(&low), Err(Error::InvalidKey(_)),));
    }

    /// Import contract: mismatched `x` rejected (the MAY this
    /// implementation takes), wrong lengths rejected, grantless refused.
    #[test]
    fn import_contract() {
        let alice_d = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let bob_x = unhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        assert!(matches!(
            AgreementSecretMaterial::import_x25519_jwk(
                &build_okp_private("X25519", &bob_x, &alice_d),
                policy_all(),
            ),
            Err(Error::InvalidKey(_))
        ));
        assert!(matches!(
            AgreementSecretMaterial::import_x25519_jwk(
                &build_okp_private("X25519", &bob_x, &alice_d[..31]),
                policy_all(),
            ),
            Err(Error::InvalidKey(_))
        ));
        assert!(matches!(
            AgreementSecretMaterial::import_x25519_jwk(
                &build_okp_private("X25519", &bob_x, &alice_d),
                AgreementPolicy::default(),
            ),
            Err(Error::NotPermitted(_))
        ));
        assert!(matches!(
            AgreementPublicMaterial::import_x25519(&[1u8; 31]),
            Err(Error::InvalidKey(_))
        ));
    }

    /// The DER forms round-trip: spki for the public key, pkcs8 for the
    /// secret (behind the extractability gate).
    #[test]
    fn der_format_round_trips() {
        let xp = AgreementPolicy {
            extractable: true,
            ..policy_all()
        };
        let alice_d = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_x = unhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let secret = AgreementSecretMaterial::import_x25519_jwk(
            &build_okp_private("X25519", &alice_x, &alice_d),
            xp,
        )
        .unwrap();
        let p8 = secret.export_pkcs8().unwrap();
        let back = AgreementSecretMaterial::import_x25519_pkcs8(&p8, xp).unwrap();
        assert_eq!(back.export_jwk().unwrap(), secret.export_jwk().unwrap());

        let public = AgreementPublicMaterial::import_x25519(&alice_x).unwrap();
        let spki = public.export_spki();
        assert_eq!(
            AgreementPublicMaterial::import_x25519_spki(&spki)
                .unwrap()
                .export(),
            alice_x
        );
        assert_eq!(
            AgreementPublicMaterial::import_x25519_jwk(&public.export_jwk())
                .unwrap()
                .export(),
            alice_x
        );

        let sealed = AgreementSecretMaterial::import_x25519_pkcs8(&p8, policy_all()).unwrap();
        assert_eq!(sealed.export_jwk(), Err(Error::NotExtractable));
        assert_eq!(sealed.export_pkcs8(), Err(Error::NotExtractable));
    }

    /// Agreed inputs carry the natural-length semantics: `none` is the
    /// whole secret, truncation takes a prefix, and over-length fails —
    /// the §26.3.1 behavior no KDF input can exhibit.
    #[test]
    fn agreed_input_natural_length() {
        let (a, _) = AgreementSecretMaterial::generate_x25519(policy_all())
            .unwrap()
            .unwrap();
        let (_, b_public) = AgreementSecretMaterial::generate_x25519(policy_all())
            .unwrap()
            .unwrap();
        let input = a.agree(&b_public).unwrap();
        let whole = input.derive_bits(None).unwrap();
        assert_eq!(whole.len(), 32);
        let prefix = input.derive_bits(Some(128)).unwrap();
        assert_eq!(prefix.as_slice(), &whole[..16]);
        assert!(matches!(input.derive_bits(Some(264)), Err(Error::Other(_))));
    }

    /// Wycheproof `ecdh_secp256r1_ecpoint_test.json` tcId 1 (normal case):
    /// the raw-point import and the scalar's JWK import agree on the
    /// published shared secret, which is the x-coordinate — the natural
    /// output length.
    #[test]
    fn ecdh_p256_known_answer() {
        let public = hex!(
            "0462d5bd3372af75fe85a040715d0f502428e07046868b0bfdfa61d731afe44f26"
            "ac333a93a9e70a81cd5a95b5bf8d13990eb741c8c38872b4a07d275a014e30cf"
        );
        let private = hex!("0612465c89a023ab17855b0a6bcebfd3febb53aef84138647b5352e02c10c346");
        let shared = hex!("53020d908b0219328b658b525f26780e3ae12bcd952bb25a93bc0895e1714285");

        let peer = AgreementPublicMaterial::import_ecdh(EcdhVariant::P256, &public).unwrap();
        let secret = ecdh_secret_from_scalar(EcdhVariant::P256, &private);
        let input = secret.agree(&peer).unwrap();
        let bits = input.derive_bits(None).unwrap();
        assert_eq!(bits.as_slice(), shared.as_slice());
        assert_eq!(bits.len(), 32);
    }

    /// Wycheproof `ecdh_secp384r1_ecpoint_test.json` tcId 1 (normal case).
    #[test]
    fn ecdh_p384_known_answer() {
        let public = hex!(
            "04790a6e059ef9a5940163183d4a7809135d29791643fc43a2f17ee8bf677ab84f"
            "791b64a6be15969ffa012dd9185d8796d9b954baa8a75e82df711b3b56eadff6"
            "b0f668c3b26b4b1aeb308a1fcc1c680d329a6705025f1c98a0b5e5bfcb163caa"
        );
        let private = hex!(
            "766e61425b2da9f846c09fc3564b93a6f8603b7392c785165bf20da948c49fd1"
            "fb1dee4edd64356b9f21c588b75dfd81"
        );
        let shared = hex!(
            "6461defb95d996b24296f5a1832b34db05ed031114fbe7d98d098f93859866e4"
            "de1e229da71fef0c77fe49b249190135"
        );

        let peer = AgreementPublicMaterial::import_ecdh(EcdhVariant::P384, &public).unwrap();
        let secret = ecdh_secret_from_scalar(EcdhVariant::P384, &private);
        let input = secret.agree(&peer).unwrap();
        let bits = input.derive_bits(None).unwrap();
        assert_eq!(bits.as_slice(), shared.as_slice());
        assert_eq!(bits.len(), 48);
    }

    /// Build an ECDH secret through the JWK import, deriving the mandatory
    /// public coordinates from the scalar (test plumbing; the WIT surface
    /// deliberately has no bare-scalar import).
    fn ecdh_secret_from_scalar(variant: EcdhVariant, scalar: &[u8]) -> AgreementSecretMaterial {
        let (x, y, crv) = match variant {
            EcdhVariant::P256 => {
                let secret = p256::SecretKey::from_slice(scalar).unwrap();
                let point = secret.public_key().to_encoded_point(false);
                (
                    point.x().unwrap().to_vec(),
                    point.y().unwrap().to_vec(),
                    "P-256",
                )
            }
            EcdhVariant::P384 => {
                let secret = p384::SecretKey::from_slice(scalar).unwrap();
                let point = secret.public_key().to_encoded_point(false);
                (
                    point.x().unwrap().to_vec(),
                    point.y().unwrap().to_vec(),
                    "P-384",
                )
            }
            EcdhVariant::P521 => unreachable!("unserved"),
        };
        AgreementSecretMaterial::import_ecdh_jwk(
            variant,
            &build_ec_private(crv, &x, &y, scalar),
            policy_all(),
        )
        .unwrap()
    }

    /// The `agree` mismatch check: X25519 × ECDH and P-256 × P-384 both
    /// fail `invalid-key`, in either order of key and peer.
    #[test]
    fn agree_rejects_mismatched_peers() {
        let (x_secret, x_public) = AgreementSecretMaterial::generate_x25519(policy_all())
            .unwrap()
            .unwrap();
        let (p256_secret, p256_public) =
            AgreementSecretMaterial::generate_ecdh(EcdhVariant::P256, policy_all())
                .unwrap()
                .unwrap();
        let (p384_secret, p384_public) =
            AgreementSecretMaterial::generate_ecdh(EcdhVariant::P384, policy_all())
                .unwrap()
                .unwrap();

        assert!(matches!(
            x_secret.agree(&p256_public),
            Err(Error::InvalidKey(_))
        ));
        assert!(matches!(
            p256_secret.agree(&x_public),
            Err(Error::InvalidKey(_))
        ));
        assert!(matches!(
            p256_secret.agree(&p384_public),
            Err(Error::InvalidKey(_))
        ));
        assert!(matches!(
            p384_secret.agree(&p256_public),
            Err(Error::InvalidKey(_))
        ));
    }

    /// ECDH import strictness: off-curve points, compressed encodings,
    /// wrong lengths, and out-of-range scalars all fail `invalid-key`;
    /// P-521 is declined `unsupported` on every minting path.
    #[test]
    fn ecdh_import_contract() {
        // (0, 0) is not on P-256 (b != 0), deterministically.
        let mut off_curve = vec![0u8; 65];
        off_curve[0] = 0x04;
        assert!(matches!(
            AgreementPublicMaterial::import_ecdh(EcdhVariant::P256, &off_curve),
            Err(Error::InvalidKey(_))
        ));
        // A compressed encoding of a valid point is rejected by shape.
        let (_, public) = AgreementSecretMaterial::generate_ecdh(EcdhVariant::P256, policy_all())
            .unwrap()
            .unwrap();
        let AgreementPublicMaterial::EcdhP256(inner) = &public else {
            unreachable!()
        };
        let compressed = inner.to_encoded_point(true);
        assert!(matches!(
            AgreementPublicMaterial::import_ecdh(EcdhVariant::P256, compressed.as_bytes()),
            Err(Error::InvalidKey(_))
        ));
        // A P-384 point is not a P-256 point (wrong length).
        let (_, p384_public) =
            AgreementSecretMaterial::generate_ecdh(EcdhVariant::P384, policy_all())
                .unwrap()
                .unwrap();
        assert!(matches!(
            AgreementPublicMaterial::import_ecdh(EcdhVariant::P256, &p384_public.export()),
            Err(Error::InvalidKey(_))
        ));
        // The zero scalar is out of range.
        let point = public.export();
        let (x, y) = (&point[1..33], &point[33..]);
        assert!(matches!(
            AgreementSecretMaterial::import_ecdh_jwk(
                EcdhVariant::P256,
                &build_ec_private("P-256", x, y, &[0u8; 32]),
                policy_all(),
            ),
            Err(Error::InvalidKey(_))
        ));
        // A mismatched public point is rejected (the MAY this
        // implementation takes).
        let other_scalar = hex!("0612465c89a023ab17855b0a6bcebfd3febb53aef84138647b5352e02c10c346");
        assert!(matches!(
            AgreementSecretMaterial::import_ecdh_jwk(
                EcdhVariant::P256,
                &build_ec_private("P-256", x, y, &other_scalar),
                policy_all(),
            ),
            Err(Error::InvalidKey(_))
        ));
        // P-521 declines everywhere.
        assert!(matches!(
            AgreementPublicMaterial::import_ecdh(EcdhVariant::P521, &off_curve),
            Err(Error::Unsupported(_))
        ));
        assert!(matches!(
            AgreementSecretMaterial::generate_ecdh(EcdhVariant::P521, policy_all()).unwrap(),
            Err(Error::Unsupported(_))
        ));
    }

    /// The ECDH formats round-trip: raw/spki/jwk for the public key,
    /// pkcs8/jwk for the secret (behind the extractability gate), on both
    /// served curves.
    #[test]
    fn ecdh_format_round_trips() {
        let xp = AgreementPolicy {
            extractable: true,
            ..policy_all()
        };
        for variant in [EcdhVariant::P256, EcdhVariant::P384] {
            let (secret, public) = AgreementSecretMaterial::generate_ecdh(variant, xp)
                .unwrap()
                .unwrap();
            let raw = public.export();
            assert_eq!(
                AgreementPublicMaterial::import_ecdh(variant, &raw)
                    .unwrap()
                    .export(),
                raw
            );
            assert_eq!(
                AgreementPublicMaterial::import_ecdh_spki(variant, &public.export_spki())
                    .unwrap()
                    .export(),
                raw
            );
            assert_eq!(
                AgreementPublicMaterial::import_ecdh_jwk(variant, &public.export_jwk())
                    .unwrap()
                    .export(),
                raw
            );

            let p8 = secret.export_pkcs8().unwrap();
            let back = AgreementSecretMaterial::import_ecdh_pkcs8(variant, &p8, xp).unwrap();
            assert_eq!(back.export_jwk().unwrap(), secret.export_jwk().unwrap());
            let via_jwk = AgreementSecretMaterial::import_ecdh_jwk(
                variant,
                &secret.export_jwk().unwrap(),
                xp,
            )
            .unwrap();
            assert_eq!(via_jwk.export_pkcs8().unwrap(), p8);

            let sealed =
                AgreementSecretMaterial::import_ecdh_pkcs8(variant, &p8, policy_all()).unwrap();
            assert_eq!(sealed.export_jwk(), Err(Error::NotExtractable));
            assert_eq!(sealed.export_pkcs8(), Err(Error::NotExtractable));

            // The curve is part of the format: the pkcs8 and JWK imports
            // reject the other curve's material.
            let other = match variant {
                EcdhVariant::P256 => EcdhVariant::P384,
                _ => EcdhVariant::P256,
            };
            assert!(matches!(
                AgreementSecretMaterial::import_ecdh_pkcs8(other, &p8, xp),
                Err(Error::InvalidKey(_))
            ));
            assert!(matches!(
                AgreementPublicMaterial::import_ecdh_jwk(other, &public.export_jwk()),
                Err(Error::InvalidKey(_))
            ));
            assert!(matches!(
                AgreementPublicMaterial::import_ecdh_spki(other, &public.export_spki()),
                Err(Error::InvalidKey(_))
            ));
        }
    }

    /// ECDH agreed inputs carry the natural length (the curve's field
    /// size) with the same truncation semantics as X25519's.
    #[test]
    fn ecdh_agreed_input_natural_length() {
        let (a, _) = AgreementSecretMaterial::generate_ecdh(EcdhVariant::P384, policy_all())
            .unwrap()
            .unwrap();
        let (_, b_public) = AgreementSecretMaterial::generate_ecdh(EcdhVariant::P384, policy_all())
            .unwrap()
            .unwrap();
        let input = a.agree(&b_public).unwrap();
        let whole = input.derive_bits(None).unwrap();
        assert_eq!(whole.len(), 48);
        let prefix = input.derive_bits(Some(128)).unwrap();
        assert_eq!(prefix.as_slice(), &whole[..16]);
        assert!(matches!(input.derive_bits(Some(392)), Err(Error::Other(_))));
    }

    /// A public EC JWK carrying `"ext": false` is rejected, and a public
    /// import never accepts a private JWK (`d` present) — the package-wide
    /// JWK contract's public-form rules.
    #[test]
    fn ecdh_public_jwk_contract() {
        let xp = AgreementPolicy {
            extractable: true,
            ..policy_all()
        };
        let (secret, public) = AgreementSecretMaterial::generate_ecdh(EcdhVariant::P256, xp)
            .unwrap()
            .unwrap();
        assert!(matches!(
            AgreementPublicMaterial::import_ecdh_jwk(
                EcdhVariant::P256,
                &secret.export_jwk().unwrap()
            ),
            Err(Error::InvalidKey(_))
        ));
        let point = public.export();
        let jwk = build_ec_public("P-256", &point[1..33], &point[33..]);
        let sealed = jwk.replacen('{', "{\"ext\":false,", 1);
        assert!(matches!(
            AgreementPublicMaterial::import_ecdh_jwk(EcdhVariant::P256, &sealed),
            Err(Error::InvalidKey(_))
        ));
    }
}
