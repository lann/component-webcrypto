//! The `signature` key material: public verification keys (every target)
//! and private signing keys — Ed25519 on every target, ECDSA only on
//! non-wasm targets (class D; see the crate doc).

use zeroize::Zeroizing;

use crate::{
    not_permitted, EcdsaVariant, Error, RngError, RsaVariant, SigningPolicy, ECDSA_NAME,
    ED25519_NAME, RSASSA_PKCS1_V15_NAME, RSA_PSS_NAME,
};

/// The P-521 decline every ECDSA minting path renders (see the WIT
/// `ecdsa-variant` doc: declared, served by no implementation here).
fn p521_unsupported() -> Error {
    Error::Unsupported("ECDSA P-521 is not served by this implementation".into())
}

/// The mint-bound digest of an ECDSA variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcdsaHash {
    Sha256,
    Sha384,
    Sha512,
}

impl EcdsaHash {
    /// The registry digest name (`algorithm-hash`).
    fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
        }
    }
}

/// The served curve of an ECDSA variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EcdsaCurve {
    P256,
    P384,
}

/// Split a WIT `ecdsa-variant` into its served curve and hash, declining
/// P-521 (`unsupported`, per the enum's doc).
fn variant_parts(variant: EcdsaVariant) -> Result<(EcdsaCurve, EcdsaHash), Error> {
    Ok(match variant {
        EcdsaVariant::P256Sha256 => (EcdsaCurve::P256, EcdsaHash::Sha256),
        EcdsaVariant::P256Sha384 => (EcdsaCurve::P256, EcdsaHash::Sha384),
        EcdsaVariant::P256Sha512 => (EcdsaCurve::P256, EcdsaHash::Sha512),
        EcdsaVariant::P384Sha256 => (EcdsaCurve::P384, EcdsaHash::Sha256),
        EcdsaVariant::P384Sha384 => (EcdsaCurve::P384, EcdsaHash::Sha384),
        EcdsaVariant::P384Sha512 => (EcdsaCurve::P384, EcdsaHash::Sha512),
        EcdsaVariant::P521Sha512 => return Err(p521_unsupported()),
    })
}

/// Stamp one body per served curve, dispatching on [`EcdsaCurve`]. Within
/// the body, `$ec` aliases the curve's `ecdsa` crate module, `$mint` is
/// the curve's `EcdsaP256`/`EcdsaP384` constructor of `$enum`, and `$name`
/// binds the registry curve name.
macro_rules! per_curve {
    ($curve:expr, $enum:ident, |$ec:ident, $mint:ident, $name:ident| $body:expr) => {
        match $curve {
            EcdsaCurve::P256 => {
                use p256::ecdsa as $ec;
                let $mint = $enum::EcdsaP256;
                let $name = "P-256";
                $body
            }
            EcdsaCurve::P384 => {
                use p384::ecdsa as $ec;
                let $mint = $enum::EcdsaP384;
                let $name = "P-384";
                $body
            }
        }
    };
}

/// Stamp a match over [`SigPublic`] whose two ECDSA arms come from one
/// body, expanded once per served curve. The optional binders hand the
/// body the per-curve pieces: `mod $ec` aliases the curve's `ecdsa` crate
/// module, and `curve $name` binds the registry curve name. The RSA arm
/// is single (both schemes share one key type) and stamps as written.
macro_rules! sig_public_match {
    ($scrutinee:expr,
     Ed25519($ed:pat) => $ed_body:expr,
     Ecdsa($key:pat, $hash:pat $(, mod $ec:ident)? $(, curve $name:ident)?) => $ec_body:expr,
     Rsa($rsa_key:pat, $scheme:pat) => $rsa_body:expr $(,)?
    ) => {
        match $scrutinee {
            SigPublic::Ed25519($ed) => $ed_body,
            SigPublic::EcdsaP256($key, $hash) => {
                $(use p256::ecdsa as $ec;)?
                $(let $name = "P-256";)?
                $ec_body
            }
            SigPublic::EcdsaP384($key, $hash) => {
                $(use p384::ecdsa as $ec;)?
                $(let $name = "P-384";)?
                $ec_body
            }
            SigPublic::Rsa($rsa_key, $scheme) => $rsa_body,
        }
    };
}

/// [`sig_public_match!`]'s counterpart over [`SigPrivate`]: the stamped
/// ECDSA arms carry the class-D cfg, so they are structurally absent from
/// wasm builds (see [`SigPrivate`]).
macro_rules! sig_private_match {
    ($scrutinee:expr,
     Ed25519($ed:pat) => $ed_body:expr,
     Ecdsa($key:pat, $hash:pat $(, mod $ec:ident)? $(, curve $name:ident)?) => $ec_body:expr $(,)?
    ) => {
        match $scrutinee {
            SigPrivate::Ed25519($ed) => $ed_body,
            #[cfg(not(target_family = "wasm"))]
            SigPrivate::EcdsaP256($key, $hash) => {
                $(use p256::ecdsa as $ec;)?
                $(let $name = "P-256";)?
                $ec_body
            }
            #[cfg(not(target_family = "wasm"))]
            SigPrivate::EcdsaP384($key, $hash) => {
                $(use p384::ecdsa as $ec;)?
                $(let $name = "P-384";)?
                $ec_body
            }
        }
    };
}

/// The RSA signature parameterization bound to a verifying key at mint:
/// the padding scheme, its digest (which is also PSS's MGF1 digest, as
/// WebCrypto fixes it), and — for PSS — the salt length in bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RsaScheme {
    /// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) under the variant's digest.
    Pkcs1V15(RsaVariant),
    /// RSA-PSS (RFC 8017 §8.1) under the variant's digest, with the salt
    /// length in bytes.
    Pss(RsaVariant, u32),
}

impl RsaScheme {
    /// The scheme's mint-bound digest.
    fn variant(self) -> RsaVariant {
        match self {
            Self::Pkcs1V15(variant) | Self::Pss(variant, _) => variant,
        }
    }
}

/// The algorithm behind a signature key, shared by the public and private
/// halves so the `algorithm-name`/`-curve`/`-hash` getters have one table.
#[derive(Clone, Copy)]
enum SigAlg {
    Ed25519,
    P256(EcdsaHash),
    P384(EcdsaHash),
    Rsa(RsaScheme),
}

impl SigAlg {
    /// The registry algorithm name (`algorithm-name`).
    fn name(self) -> &'static str {
        match self {
            Self::Ed25519 => ED25519_NAME,
            Self::P256(_) | Self::P384(_) => ECDSA_NAME,
            Self::Rsa(RsaScheme::Pkcs1V15(_)) => RSASSA_PKCS1_V15_NAME,
            Self::Rsa(RsaScheme::Pss(..)) => RSA_PSS_NAME,
        }
    }

    /// The registry curve name (`algorithm-curve`).
    fn curve(self) -> Option<&'static str> {
        match self {
            Self::Ed25519 | Self::Rsa(_) => None,
            Self::P256(_) => Some("P-256"),
            Self::P384(_) => Some("P-384"),
        }
    }

    /// The mint-bound digest name (`algorithm-hash`).
    fn hash(self) -> Option<&'static str> {
        match self {
            Self::Ed25519 => None,
            Self::P256(hash) | Self::P384(hash) => Some(hash.name()),
            Self::Rsa(scheme) => Some(rsa_hash_name(scheme.variant())),
        }
    }
}

/// The public key behind a `signature.verifying-key` resource, bound to its
/// algorithm (and, for ECDSA and RSA, its digest parameterization) at
/// minting. Verification is secret-free, so every arm exists on every
/// target.
pub enum SigPublic {
    Ed25519(ed25519_dalek::VerifyingKey),
    EcdsaP256(p256::ecdsa::VerifyingKey, EcdsaHash),
    EcdsaP384(p384::ecdsa::VerifyingKey, EcdsaHash),
    Rsa(rsa::RsaPublicKey, RsaScheme),
}

impl SigPublic {
    /// Import a 32-byte RFC 8032 public key, rendering `invalid-key` for
    /// wrong lengths and encodings the algorithm rejects (the
    /// `ed25519-verify.import-verifying-key-raw` contract).
    pub fn import_ed25519(raw: &[u8]) -> Result<Self, Error> {
        let bytes: &[u8; 32] = raw.try_into().map_err(|_| {
            Error::InvalidKey(format!(
                "Ed25519 public keys are 32 bytes, got {} bytes",
                raw.len()
            ))
        })?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .map_err(|err| Error::InvalidKey(format!("invalid Ed25519 public key: {err}")))?;
        Ok(Self::Ed25519(key))
    }

    /// Import an uncompressed SEC1 point for the declared variant,
    /// rendering `invalid-key` for anything else — including compressed
    /// encodings and points not on the curve (the
    /// `ecdsa-verify.import-verifying-key-raw` contract).
    pub fn import_ecdsa(variant: EcdsaVariant, raw: &[u8]) -> Result<Self, Error> {
        let (curve, hash) = variant_parts(variant)?;
        let expected = match curve {
            EcdsaCurve::P256 => 65,
            EcdsaCurve::P384 => 97,
        };
        if raw.len() != expected || raw[0] != 0x04 {
            return Err(Error::InvalidKey(format!(
                "{variant:?} public keys are uncompressed SEC1 points ({expected} bytes, leading 0x04)"
            )));
        }
        per_curve!(curve, SigPublic, |ec, mint, name| {
            ec::VerifyingKey::from_sec1_bytes(raw)
                .map(|key| mint(key, hash))
                .map_err(|err| Error::InvalidKey(format!("invalid {name} public key: {err}")))
        })
    }

    /// Import an Ed25519 public key from a SubjectPublicKeyInfo (the
    /// `ed25519-verify.import-verifying-key-spki` contract): the embedded
    /// point is subject to the raw import's strict criterion.
    pub fn import_ed25519_spki(spki: &[u8]) -> Result<Self, Error> {
        let raw = crate::der8410::parse_rfc8410_spki(crate::der8410::OID_ED25519, "Ed25519", spki)?;
        Self::import_ed25519(&raw)
    }

    /// Import an Ed25519 public key from an OKP public JWK (the
    /// `ed25519-verify.import-verifying-key-jwk` contract).
    pub fn import_ed25519_jwk(jwk: &str) -> Result<Self, Error> {
        let raw = crate::jwk::parse_okp_public(jwk, "Ed25519", Some(ED25519_JWK_ALGS))?;
        Self::import_ed25519(&raw)
    }

    /// Import an ECDSA public key from a SubjectPublicKeyInfo (the
    /// `ecdsa-verify.import-verifying-key-spki` contract): the encoded
    /// curve must match the declared variant's.
    pub fn import_ecdsa_spki(variant: EcdsaVariant, spki: &[u8]) -> Result<Self, Error> {
        use spki::DecodePublicKey as _;
        let (curve, hash) = variant_parts(variant)?;
        per_curve!(curve, SigPublic, |ec, mint, name| {
            ec::VerifyingKey::from_public_key_der(spki)
                .map(|key| mint(key, hash))
                .map_err(|err| Error::InvalidKey(format!("invalid {name} spki: {err}")))
        })
    }

    /// Import an ECDSA public key from an EC public JWK (the
    /// `ecdsa-verify.import-verifying-key-jwk` contract): the JWK's `crv`
    /// must match the declared variant's curve.
    pub fn import_ecdsa_jwk(variant: EcdsaVariant, jwk: &str) -> Result<Self, Error> {
        let (curve, _) = variant_parts(variant)?;
        let parsed = crate::jwk::parse_ec(
            jwk,
            curve_name(curve),
            false,
            false,
            Some(ec_jwk_algs(curve)),
        )?;
        Self::import_ecdsa(variant, &ec_point(curve, &parsed.x, &parsed.y)?)
    }

    /// Import an RSASSA-PKCS1-v1_5 public key from a SubjectPublicKeyInfo
    /// (the `rsassa-pkcs1-v15-verify.import-verifying-key-spki` contract):
    /// admission follows the WIT `rsa` family contract.
    pub fn import_rsassa_spki(variant: RsaVariant, spki: &[u8]) -> Result<Self, Error> {
        let (n, e) = decode_rsa_spki(spki)?;
        Ok(Self::Rsa(admit_rsa(n, e)?, RsaScheme::Pkcs1V15(variant)))
    }

    /// Import an RSASSA-PKCS1-v1_5 public key from an RSA public JWK (the
    /// `rsassa-pkcs1-v15-verify.import-verifying-key-jwk` contract): a
    /// present `alg` must be the variant's JOSE alg.
    pub fn import_rsassa_jwk(variant: RsaVariant, jwk: &str) -> Result<Self, Error> {
        let parsed = crate::jwk::parse_rsa_public(jwk, Some(rsassa_jwk_algs(variant)))?;
        let key = admit_rsa(
            rsa::BigUint::from_bytes_be(&parsed.n),
            rsa::BigUint::from_bytes_be(&parsed.e),
        )?;
        Ok(Self::Rsa(key, RsaScheme::Pkcs1V15(variant)))
    }

    /// Import an RSA-PSS public key from a SubjectPublicKeyInfo (the
    /// `rsa-pss-verify.import-verifying-key-spki` contract): admission
    /// follows the WIT `rsa` family contract, and `salt_length` (bytes)
    /// binds at mint.
    pub fn import_pss_spki(
        variant: RsaVariant,
        salt_length: u32,
        spki: &[u8],
    ) -> Result<Self, Error> {
        let (n, e) = decode_rsa_spki(spki)?;
        Ok(Self::Rsa(
            admit_rsa(n, e)?,
            RsaScheme::Pss(variant, salt_length),
        ))
    }

    /// Import an RSA-PSS public key from an RSA public JWK (the
    /// `rsa-pss-verify.import-verifying-key-jwk` contract): a present
    /// `alg` must be the variant's JOSE alg, and `salt_length` (bytes)
    /// binds at mint.
    pub fn import_pss_jwk(variant: RsaVariant, salt_length: u32, jwk: &str) -> Result<Self, Error> {
        let parsed = crate::jwk::parse_rsa_public(jwk, Some(pss_jwk_algs(variant)))?;
        let key = admit_rsa(
            rsa::BigUint::from_bytes_be(&parsed.n),
            rsa::BigUint::from_bytes_be(&parsed.e),
        )?;
        Ok(Self::Rsa(key, RsaScheme::Pss(variant, salt_length)))
    }

    /// The key's algorithm tag.
    fn alg(&self) -> SigAlg {
        match self {
            Self::Ed25519(_) => SigAlg::Ed25519,
            Self::EcdsaP256(_, hash) => SigAlg::P256(*hash),
            Self::EcdsaP384(_, hash) => SigAlg::P384(*hash),
            Self::Rsa(_, scheme) => SigAlg::Rsa(*scheme),
        }
    }

    /// The registry algorithm name (`verifying-key.algorithm-name`).
    pub fn name(&self) -> &'static str {
        self.alg().name()
    }

    /// The registry curve name (`verifying-key.algorithm-curve`).
    pub fn curve(&self) -> Option<&'static str> {
        self.alg().curve()
    }

    /// The mint-bound digest name (`verifying-key.algorithm-hash`).
    pub fn hash(&self) -> Option<&'static str> {
        self.alg().hash()
    }

    /// The key's length in bits (`verifying-key.algorithm-length`): the
    /// RSA modulus length. `None` for Ed25519 and ECDSA, whose key size
    /// is fixed by the algorithm or curve.
    pub fn length(&self) -> Option<u32> {
        sig_public_match!(self,
            Ed25519(_) => None,
            Ecdsa(_, _) => None,
            Rsa(key, _) => {
                use rsa::traits::PublicKeyParts as _;
                Some(key.n().bits() as u32)
            },
        )
    }

    /// The public key material in the minting interface's documented form —
    /// raw 32 bytes for Ed25519, an uncompressed SEC1 point for ECDSA — or
    /// `unsupported` for the RSA family, which has no raw public form (the
    /// `verifying-key.export-key-raw` contract).
    pub fn export(&self) -> Result<Vec<u8>, Error> {
        sig_public_match!(self,
            Ed25519(key) => Ok(key.to_bytes().to_vec()),
            Ecdsa(key, _) => Ok(key.to_encoded_point(false).as_bytes().to_vec()),
            Rsa(_, _) => Err(Error::Unsupported(
                "RSA public keys have no raw form".into(),
            )),
        )
    }

    /// The public key as a SubjectPublicKeyInfo
    /// (`verifying-key.export-key-spki`).
    pub fn export_spki(&self) -> Vec<u8> {
        use spki::EncodePublicKey as _;
        sig_public_match!(self,
            Ed25519(key) => {
                crate::der8410::rfc8410_spki(crate::der8410::OID_ED25519, key.as_bytes())
            },
            Ecdsa(key, _) => key
                .to_public_key_der()
                .expect("valid key encodes")
                .into_vec(),
            Rsa(key, _) => key
                .to_public_key_der()
                .expect("valid key encodes")
                .into_vec(),
        )
    }

    /// The public key as a JWK (`verifying-key.export-key-jwk`).
    pub fn export_jwk(&self) -> String {
        sig_public_match!(self,
            Ed25519(key) => crate::jwk::build_okp_public("Ed25519", key.as_bytes()),
            Ecdsa(key, _, curve name) => {
                let point = key.to_encoded_point(false);
                crate::jwk::build_ec_public(name, point.x().unwrap(), point.y().unwrap())
            },
            Rsa(key, _) => {
                use rsa::traits::PublicKeyParts as _;
                crate::jwk::build_rsa_public(&key.n().to_bytes_be(), &key.e().to_bytes_be())
            },
        )
    }

    /// One-shot verification of `sig` over `data`, failing closed with
    /// `authentication-failed` (the `verifying-key.verify` contract): the
    /// ECDSA signature format is fixed-width `r ‖ s` (IEEE P1363),
    /// Ed25519 uses `verify_strict` semantics per the `ed25519-verify`
    /// criterion, and the RSA schemes verify under the mint-bound
    /// parameterization (byte-exact EMSA-PKCS1-v1_5; PSS with the minted
    /// salt length).
    pub fn verify(&self, data: &[u8], sig: &[u8]) -> Result<(), Error> {
        use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
        let ok = sig_public_match!(self,
            Ed25519(key) => ed25519_dalek::Signature::from_slice(sig)
                .and_then(|sig| key.verify_strict(data, &sig))
                .is_ok(),
            // Verify under the mint-bound digest via the prehash path: its
            // bits2field conversion applies FIPS 186-5's leftmost-bits rule
            // for digests wider or narrower than the curve.
            Ecdsa(key, hash, mod ec) => ec::Signature::from_slice(sig)
                .map_err(|_| ())
                .and_then(|sig| {
                    key.verify_prehash(&ecdsa_digest(*hash, data), &sig)
                        .map_err(|_| ())
                })
                .is_ok(),
            Rsa(key, scheme) => {
                let hashed = rsa_digest(scheme.variant(), data);
                match *scheme {
                    RsaScheme::Pkcs1V15(variant) => {
                        key.verify(pkcs1v15_scheme(variant), &hashed, sig)
                    }
                    RsaScheme::Pss(variant, salt) => {
                        key.verify(pss_scheme(variant, salt), &hashed, sig)
                    }
                }
                .is_ok()
            },
        );
        if ok {
            Ok(())
        } else {
            Err(Error::AuthenticationFailed)
        }
    }
}

/// The mint-bound digest over `data`, as prehash bytes.
fn ecdsa_digest(hash: EcdsaHash, data: &[u8]) -> Vec<u8> {
    use sha2::Digest as _;
    match hash {
        EcdsaHash::Sha256 => sha2::Sha256::digest(data).to_vec(),
        EcdsaHash::Sha384 => sha2::Sha384::digest(data).to_vec(),
        EcdsaHash::Sha512 => sha2::Sha512::digest(data).to_vec(),
    }
}

/// The mint-bound digest over `data` for an RSA variant, as prehash bytes.
fn rsa_digest(variant: RsaVariant, data: &[u8]) -> Vec<u8> {
    use sha2::Digest as _;
    match variant {
        RsaVariant::Sha256 => sha2::Sha256::digest(data).to_vec(),
        RsaVariant::Sha384 => sha2::Sha384::digest(data).to_vec(),
        RsaVariant::Sha512 => sha2::Sha512::digest(data).to_vec(),
    }
}

/// The registry digest name of an RSA variant (`algorithm-hash`).
fn rsa_hash_name(variant: RsaVariant) -> &'static str {
    match variant {
        RsaVariant::Sha256 => "SHA-256",
        RsaVariant::Sha384 => "SHA-384",
        RsaVariant::Sha512 => "SHA-512",
    }
}

/// The variant's EMSA-PKCS1-v1_5 verification scheme (its DigestInfo
/// prefix comes from the digest's OID).
fn pkcs1v15_scheme(variant: RsaVariant) -> rsa::Pkcs1v15Sign {
    match variant {
        RsaVariant::Sha256 => rsa::Pkcs1v15Sign::new::<sha2::Sha256>(),
        RsaVariant::Sha384 => rsa::Pkcs1v15Sign::new::<sha2::Sha384>(),
        RsaVariant::Sha512 => rsa::Pkcs1v15Sign::new::<sha2::Sha512>(),
    }
}

/// The variant's EMSA-PSS verification scheme with the mint-bound salt
/// length in bytes: MGF1 under the message digest, and the salt length
/// checked exactly.
fn pss_scheme(variant: RsaVariant, salt_length: u32) -> rsa::Pss {
    let salt = salt_length as usize;
    match variant {
        RsaVariant::Sha256 => rsa::Pss::new_with_salt::<sha2::Sha256>(salt),
        RsaVariant::Sha384 => rsa::Pss::new_with_salt::<sha2::Sha384>(salt),
        RsaVariant::Sha512 => rsa::Pss::new_with_salt::<sha2::Sha512>(salt),
    }
}

/// Decode an `rsaEncryption` SubjectPublicKeyInfo down to its (n, e) pair,
/// rendering `invalid-key` for malformed DER and for any other SPKI
/// algorithm — including `id-RSASSA-PSS`, per the WIT `rsa` family
/// contract. The decode stops at the integers rather than going through
/// `rsa`'s `DecodePublicKey`, whose construction enforces the crate's
/// 4096-bit default ceiling; [`admit_rsa`] applies the family window.
fn decode_rsa_spki(spki_der: &[u8]) -> Result<(rsa::BigUint, rsa::BigUint), Error> {
    use der::Decode as _;
    let info = spki::SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|err| Error::InvalidKey(format!("invalid RSA spki: {err}")))?;
    if info.algorithm.oid != rsa::pkcs1::ALGORITHM_OID {
        return Err(Error::InvalidKey(format!(
            "SPKI algorithm must be rsaEncryption, got {}",
            info.algorithm.oid
        )));
    }
    let body = info.subject_public_key.as_bytes().ok_or_else(|| {
        Error::InvalidKey("invalid RSA spki: the key bit string has unused bits".into())
    })?;
    let key = rsa::pkcs1::RsaPublicKey::from_der(body)
        .map_err(|err| Error::InvalidKey(format!("invalid RSA spki: {err}")))?;
    Ok((
        rsa::BigUint::from_bytes_be(key.modulus.as_bytes()),
        rsa::BigUint::from_bytes_be(key.public_exponent.as_bytes()),
    ))
}

/// Admit an RSA public (n, e) pair per the WIT `rsa` family contract —
/// the 1024–16384-bit modulus window and the odd-and-at-least-3 exponent
/// floor — then construct the key with the window as the explicit
/// ceiling (the `rsa` crate's default construction paths enforce a
/// 4096-bit maximum). Bounds the crate itself still enforces — an
/// exponent above its 2^33−1 ceiling, an even modulus — also render
/// `invalid-key`, the WIT's implementation-defined latitude for large
/// exponents.
fn admit_rsa(n: rsa::BigUint, e: rsa::BigUint) -> Result<rsa::RsaPublicKey, Error> {
    let bits = n.bits();
    if !(1024..=16384).contains(&bits) {
        return Err(Error::InvalidKey(format!(
            "RSA moduli are 1024-16384 bits, got {bits} bits"
        )));
    }
    let e_is_odd = e.to_bytes_be().last().is_some_and(|byte| byte & 1 == 1);
    if !e_is_odd || e < rsa::BigUint::from(3u32) {
        return Err(Error::InvalidKey(
            "RSA public exponents must be odd and at least 3".into(),
        ));
    }
    rsa::RsaPublicKey::new_with_max_size(n, e, 16384)
        .map_err(|err| Error::InvalidKey(format!("invalid RSA public key: {err}")))
}

/// The JWK `alg` value an RSASSA-PKCS1-v1_5 import accepts: the variant's
/// JOSE alg (the WIT import rule).
fn rsassa_jwk_algs(variant: RsaVariant) -> &'static [&'static str] {
    match variant {
        RsaVariant::Sha256 => &["RS256"],
        RsaVariant::Sha384 => &["RS384"],
        RsaVariant::Sha512 => &["RS512"],
    }
}

/// The JWK `alg` value an RSA-PSS import accepts: the variant's JOSE alg
/// (the WIT import rule).
fn pss_jwk_algs(variant: RsaVariant) -> &'static [&'static str] {
    match variant {
        RsaVariant::Sha256 => &["PS256"],
        RsaVariant::Sha384 => &["PS384"],
        RsaVariant::Sha512 => &["PS512"],
    }
}

/// The registry curve name for a served curve.
fn curve_name(curve: EcdsaCurve) -> &'static str {
    match curve {
        EcdsaCurve::P256 => "P-256",
        EcdsaCurve::P384 => "P-384",
    }
}

/// The JWK `alg` values an Ed25519 import accepts: WebCrypto's algorithm
/// name and JOSE's EdDSA (w3c/webcrypto#401's import rule).
const ED25519_JWK_ALGS: &[&str] = &["Ed25519", "EdDSA"];

/// The JWK `alg` values an EC JWK import accepts for a served curve: the
/// JOSE signature alg the curve pairs with (curve-determined, so it does
/// not vary with the variant's mint-bound hash — WebCrypto's import rule).
fn ec_jwk_algs(curve: EcdsaCurve) -> &'static [&'static str] {
    match curve {
        EcdsaCurve::P256 => &["ES256"],
        EcdsaCurve::P384 => &["ES384"],
    }
}

/// Assemble an uncompressed SEC1 point from JWK coordinates, validating
/// their lengths for the curve.
fn ec_point(curve: EcdsaCurve, x: &[u8], y: &[u8]) -> Result<Vec<u8>, Error> {
    let len = match curve {
        EcdsaCurve::P256 => 32,
        EcdsaCurve::P384 => 48,
    };
    crate::jwk::ec_point(curve_name(curve), len, x, y)
}

// Public material is not secret, but printing it wholesale is rarely
// useful; identify the key by algorithm only.
impl std::fmt::Debug for SigPublic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigPublic")
            .field("algorithm", &self.name())
            .finish()
    }
}

/// The private key backing a [`SigningKeyMaterial`]. The ECDSA arms exist
/// only on non-wasm targets: ECDSA signing is class D (per-signature secret
/// nonce; small timing leaks are key-recovering), so its code is
/// structurally absent from every wasm build (see the crate doc).
enum SigPrivate {
    Ed25519(ed25519_dalek::SigningKey),
    #[cfg(not(target_family = "wasm"))]
    EcdsaP256(p256::ecdsa::SigningKey, EcdsaHash),
    #[cfg(not(target_family = "wasm"))]
    EcdsaP384(p384::ecdsa::SigningKey, EcdsaHash),
}

impl SigPrivate {
    /// The key's algorithm tag.
    fn alg(&self) -> SigAlg {
        match self {
            Self::Ed25519(_) => SigAlg::Ed25519,
            #[cfg(not(target_family = "wasm"))]
            Self::EcdsaP256(_, hash) => SigAlg::P256(*hash),
            #[cfg(not(target_family = "wasm"))]
            Self::EcdsaP384(_, hash) => SigAlg::P384(*hash),
        }
    }
}

/// The material behind a `signature.signing-key` resource: the private key
/// bound to its algorithm at minting, and the key's extractability.
pub struct SigningKeyMaterial {
    private: SigPrivate,
    /// Whether `export-key-raw` may return the private material.
    policy: SigningPolicy,
}

impl SigningKeyMaterial {
    /// Import a 32-byte RFC 8032 seed, rendering `invalid-key` for wrong
    /// lengths (the `ed25519-sign.import-signing-key` contract).
    pub fn import_ed25519_seed(raw: &[u8], policy: SigningPolicy) -> Result<Self, Error> {
        let seed: &[u8; 32] = raw.try_into().map_err(|_| {
            Error::InvalidKey(format!(
                "Ed25519 private keys are 32-byte seeds, got {} bytes",
                raw.len()
            ))
        })?;
        Ok(Self {
            private: SigPrivate::Ed25519(ed25519_dalek::SigningKey::from_bytes(seed)),
            policy,
        })
    }

    /// Generate a fresh random Ed25519 signing key.
    pub fn generate_ed25519(policy: SigningPolicy) -> Result<Result<Self, Error>, RngError> {
        if let Err(err) = policy.check_useful() {
            return Ok(Err(err));
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut())?;
        Ok(Ok(Self {
            private: SigPrivate::Ed25519(ed25519_dalek::SigningKey::from_bytes(&seed)),
            policy,
        }))
    }

    /// Import a raw big-endian scalar for the declared variant, rendering
    /// `invalid-key` for wrong lengths and out-of-range scalars (the
    /// `ecdsa-sign.import-signing-key` contract).
    #[cfg(not(target_family = "wasm"))]
    pub fn import_ecdsa_scalar(
        variant: EcdsaVariant,
        raw: &[u8],
        policy: SigningPolicy,
    ) -> Result<Self, Error> {
        let (curve, hash) = variant_parts(variant)?;
        let private = per_curve!(curve, SigPrivate, |ec, mint, name| {
            ec::SigningKey::from_slice(raw)
                .map(|key| mint(key, hash))
                .map_err(|err| Error::InvalidKey(format!("invalid {name} private key: {err}")))
        })?;
        Ok(Self { private, policy })
    }

    /// Import a signing key from a PKCS#8 PrivateKeyInfo (the
    /// `ecdsa-sign.import-signing-key-pkcs8` contract): the encoded curve
    /// must match the declared variant's; an embedded public key is
    /// validated by the decoder and never trusted on its own.
    #[cfg(not(target_family = "wasm"))]
    pub fn import_ecdsa_pkcs8(
        variant: EcdsaVariant,
        pkcs8_der: &[u8],
        policy: SigningPolicy,
    ) -> Result<Self, Error> {
        use pkcs8::DecodePrivateKey as _;
        policy.check_useful()?;
        let (curve, hash) = variant_parts(variant)?;
        let private = per_curve!(curve, SigPrivate, |ec, mint, name| {
            ec::SigningKey::from_pkcs8_der(pkcs8_der)
                .map(|key| mint(key, hash))
                .map_err(|err| Error::InvalidKey(format!("invalid {name} pkcs8: {err}")))
        })?;
        Ok(Self { private, policy })
    }

    /// Import a signing key from an EC private JWK (the
    /// `ecdsa-sign.import-signing-key-jwk` contract). This implementation
    /// takes the MAY: a JWK whose `x`/`y` are not the public point of `d`
    /// is rejected `invalid-key`.
    #[cfg(not(target_family = "wasm"))]
    pub fn import_ecdsa_jwk(
        variant: EcdsaVariant,
        jwk: &str,
        policy: SigningPolicy,
    ) -> Result<Self, Error> {
        policy.check_useful()?;
        let (curve, _) = variant_parts(variant)?;
        let parsed = crate::jwk::parse_ec(
            jwk,
            curve_name(curve),
            true,
            policy.extractable,
            Some(ec_jwk_algs(curve)),
        )?;
        let d = parsed.d.as_ref().expect("private parse carries d");
        let key = Self::import_ecdsa_scalar(variant, d, policy)?;
        let expected = ec_point(curve, &parsed.x, &parsed.y)?;
        if key
            .public()
            .export()
            .expect("EC public keys have a raw form")
            != expected
        {
            return Err(Error::InvalidKey(
                "JWK `x`/`y` are not the public point of `d`".into(),
            ));
        }
        Ok(key)
    }

    /// Import a signing key from an RFC 8410 PKCS#8 PrivateKeyInfo (the
    /// `ed25519-sign.import-signing-key-pkcs8` contract). A v2 public
    /// key, when present, is ignored: the key's identity is the seed's.
    pub fn import_ed25519_pkcs8(pkcs8_der: &[u8], policy: SigningPolicy) -> Result<Self, Error> {
        policy.check_useful()?;
        let seed =
            crate::der8410::parse_rfc8410_pkcs8(crate::der8410::OID_ED25519, "Ed25519", pkcs8_der)?;
        Self::import_ed25519_seed(&*seed, policy)
    }

    /// Import a signing key from an RFC 8037 OKP private JWK (the
    /// `ed25519-sign.import-signing-key-jwk` contract). This
    /// implementation takes the MAY: a JWK whose `x` is not the public
    /// key of `d` is rejected `invalid-key`.
    pub fn import_ed25519_jwk(jwk: &str, policy: SigningPolicy) -> Result<Self, Error> {
        policy.check_useful()?;
        let okp = crate::jwk::parse_okp_private(
            jwk,
            "Ed25519",
            policy.extractable,
            Some(ED25519_JWK_ALGS),
        )?;
        let key = Self::import_ed25519_seed(&okp.d, policy)?;
        if key
            .public()
            .export()
            .expect("Ed25519 public keys have a raw form")
            != okp.x
        {
            return Err(Error::InvalidKey(
                "JWK `x` is not the public key of `d`".into(),
            ));
        }
        Ok(key)
    }

    /// Generate a fresh random ECDSA signing key of the declared variant by
    /// rejection-sampling the scalar range with fresh randomness (the
    /// probability of a retry is negligible for these curves).
    #[cfg(not(target_family = "wasm"))]
    pub fn generate_ecdsa(
        variant: EcdsaVariant,
        policy: SigningPolicy,
    ) -> Result<Result<Self, Error>, RngError> {
        if let Err(err) = policy.check_useful() {
            return Ok(Err(err));
        }
        let scalar_len = match variant_parts(variant) {
            Ok((EcdsaCurve::P256, _)) => 32,
            Ok((EcdsaCurve::P384, _)) => 48,
            Err(err) => return Ok(Err(err)),
        };
        // Bound the retries. Both rejections `import_ecdsa_scalar` can
        // report — an out-of-range scalar and a length mismatch — arrive as
        // `InvalidKey`, so the loop cannot tell "draw again" from "this can
        // never succeed" by matching. Unbounded retrying therefore couples
        // it to the invariant that `scalar_len` matches the variant: true
        // today, and an infinite loop inside a host call if a future variant
        // breaks it. A draw is rejected with probability under 2^-32 for
        // these curves, so exhausting eight attempts is not sampling luck —
        // it is that invariant failing, and saying so beats hanging.
        const ATTEMPTS: usize = 8;
        for _ in 0..ATTEMPTS {
            let mut raw = Zeroizing::new(vec![0u8; scalar_len]);
            getrandom::fill(&mut raw)?;
            if let Ok(key) = Self::import_ecdsa_scalar(variant, &raw, policy) {
                return Ok(Ok(key));
            }
        }
        unreachable!(
            "{ATTEMPTS} rejection-sampled {scalar_len}-byte {variant:?} scalars were all \
             rejected; the sampled length no longer matches the curve"
        )
    }

    /// One-shot signature over `data` (the `signing-key.sign` contract):
    /// 64 bytes for Ed25519 (RFC 8032), fixed-width `r ‖ s` (IEEE P1363,
    /// RFC 6979 deterministic) for ECDSA.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        if !self.policy.sign {
            return Err(not_permitted("sign"));
        }
        Ok(sig_private_match!(&self.private,
            Ed25519(key) => {
                use ed25519_dalek::Signer as _;
                key.sign(data).to_bytes().to_vec()
            },
            Ecdsa(key, hash, mod ec) => {
                use p256::ecdsa::signature::hazmat::PrehashSigner as _;
                // Deterministic (RFC 6979-style HMAC-DRBG over the curve's
                // digest) and verify-compatible with any conforming
                // verifier. The exact bytes are deliberately not part of
                // any contract: the WIT records that RFC 6979 and
                // randomized-k implementations both verify while differing
                // in bytes, and cross-hash variants differ from the RFC's
                // published vectors in their nonce-derivation hash.
                let sig: ec::Signature = key
                    .sign_prehash(&ecdsa_digest(*hash, data))
                    .expect("prehash length is a digest's; signing cannot fail");
                sig.to_bytes().to_vec()
            },
        ))
    }

    /// The corresponding [`SigPublic`]. There is no WIT derive contract —
    /// the package's `generate-key` functions return the pair instead —
    /// but this core holds the private material, so hosts use this to mint
    /// the public half at generation.
    pub fn public(&self) -> SigPublic {
        match &self.private {
            SigPrivate::Ed25519(key) => SigPublic::Ed25519(key.verifying_key()),
            #[cfg(not(target_family = "wasm"))]
            SigPrivate::EcdsaP256(key, hash) => SigPublic::EcdsaP256(*key.verifying_key(), *hash),
            #[cfg(not(target_family = "wasm"))]
            SigPrivate::EcdsaP384(key, hash) => SigPublic::EcdsaP384(*key.verifying_key(), *hash),
        }
    }

    /// The registry algorithm name (`signing-key.algorithm-name`).
    pub fn name(&self) -> &'static str {
        self.private.alg().name()
    }

    /// The registry curve name (`signing-key.algorithm-curve`).
    pub fn curve(&self) -> Option<&'static str> {
        self.private.alg().curve()
    }

    /// The mint-bound digest name (`signing-key.algorithm-hash`).
    pub fn hash(&self) -> Option<&'static str> {
        self.private.alg().hash()
    }

    /// The key's length in bits (`signing-key.algorithm-length`): `None`
    /// for every algorithm with a signing half here — the Ed25519 and
    /// ECDSA key sizes are fixed by the algorithm or curve.
    pub fn length(&self) -> Option<u32> {
        None
    }

    /// Whether the private material may be exported — mint-time recorded
    /// policy for future format exports (`signing-key.extractable`).
    pub fn extractable(&self) -> bool {
        self.policy.extractable
    }

    /// Whether the key permits `sign` (`signing-key.can-sign`).
    pub fn can_sign(&self) -> bool {
        self.policy.sign
    }

    /// The private key material — the 32-byte RFC 8032 seed for Ed25519,
    /// the raw big-endian scalar for ECDSA — or `not-extractable`. No WIT
    /// operation reaches this today (signing keys have no export); it
    /// stays for the unit tests that pin the known answers.
    ///
    /// The copy returned is *not* protected: see the note on
    /// [`crate`](crate#exported-material).
    pub fn export(&self) -> Result<Vec<u8>, Error> {
        if !self.policy.extractable {
            return Err(Error::NotExtractable);
        }
        Ok(sig_private_match!(&self.private,
            Ed25519(key) => key.to_bytes().to_vec(),
            Ecdsa(key, _) => key.to_bytes().to_vec(),
        ))
    }

    /// The private key as a JWK (the `signing-key.export-key-jwk`
    /// contract), behind the extractability gate.
    ///
    /// The copy returned is *not* protected: see the note on
    /// [`crate`](crate#exported-material).
    pub fn export_jwk(&self) -> Result<String, Error> {
        if !self.policy.extractable {
            return Err(Error::NotExtractable);
        }
        Ok(sig_private_match!(&self.private,
            Ed25519(key) => crate::jwk::build_okp_private(
                "Ed25519",
                key.verifying_key().as_bytes(),
                &key.to_bytes(),
            ),
            Ecdsa(key, _, curve name) => {
                let point = key.verifying_key().to_encoded_point(false);
                crate::jwk::build_ec_private(
                    name,
                    point.x().unwrap(),
                    point.y().unwrap(),
                    &key.to_bytes(),
                )
            },
        ))
    }

    /// The private key as a PKCS#8 PrivateKeyInfo (the
    /// `signing-key.export-key-pkcs8` contract), behind the same gate:
    /// the RFC 8410 v1 form for Ed25519, the SEC1 body for ECDSA.
    pub fn export_pkcs8(&self) -> Result<Vec<u8>, Error> {
        if !self.policy.extractable {
            return Err(Error::NotExtractable);
        }
        Ok(sig_private_match!(&self.private,
            Ed25519(key) => {
                crate::der8410::rfc8410_pkcs8(crate::der8410::OID_ED25519, &key.to_bytes()).to_vec()
            },
            Ecdsa(key, _) => {
                use pkcs8::EncodePrivateKey as _;
                key.to_pkcs8_der()
                    .expect("valid key encodes")
                    .to_bytes()
                    .to_vec()
            },
        ))
    }
}

// Debug is implemented by hand so key material can never reach logs: only
// the algorithm binding and extractability are printed, with the material
// redacted.
impl std::fmt::Debug for SigningKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKeyMaterial")
            .field("algorithm", &self.name())
            .field("policy", &self.policy)
            .field("private", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A signing grant, non-extractable.
    fn sp() -> SigningPolicy {
        SigningPolicy {
            sign: true,
            extractable: false,
        }
    }

    /// A signing grant, extractable.
    fn xp() -> SigningPolicy {
        SigningPolicy {
            extractable: true,
            ..sp()
        }
    }

    /// Pins seed import, public derivation, signing determinism (RFC 8032),
    /// verification, and seed-form export together.
    #[test]
    fn ed25519_sign_verify_round_trip() {
        let seed = [0x42u8; 32];
        let key = SigningKeyMaterial::import_ed25519_seed(&seed, xp()).unwrap();
        let sig = key.sign(b"message").unwrap();
        assert_eq!(sig.len(), 64);
        assert_eq!(
            sig,
            key.sign(b"message").unwrap(),
            "Ed25519 signing is deterministic"
        );
        let public = key.public();
        assert!(public.verify(b"message", &sig).is_ok());
        assert_eq!(
            public.verify(b"tampered", &sig),
            Err(Error::AuthenticationFailed)
        );
        assert_eq!(key.export().unwrap(), seed.to_vec());
    }

    #[test]
    fn ed25519_seed_length_is_validated() {
        match SigningKeyMaterial::import_ed25519_seed(&[0; 16], xp()) {
            Err(Error::InvalidKey(msg)) => {
                assert_eq!(msg, "Ed25519 private keys are 32-byte seeds, got 16 bytes")
            }
            _ => panic!("expected invalid-key"),
        }
    }

    /// The SEC1 shape guard renders the curated diagnostic for each of its
    /// clauses alone — wrong length with the right leading byte, and the
    /// right length with a compressed-point leading byte — rather than
    /// deferring to the curve library's own rejection text.
    #[test]
    fn ecdsa_public_shape_is_validated_with_the_sec1_message() {
        let wrong_length = vec![0x04u8; 64];
        let mut compressed_prefix = vec![0x02u8];
        compressed_prefix.extend_from_slice(&[0u8; 64]);
        for raw in [wrong_length, compressed_prefix] {
            match SigPublic::import_ecdsa(EcdsaVariant::P256Sha256, &raw) {
                Err(Error::InvalidKey(msg)) => assert_eq!(
                    msg,
                    "P256Sha256 public keys are uncompressed SEC1 points \
                     (65 bytes, leading 0x04)"
                ),
                other => panic!("expected the shape diagnostic, got {other:?}"),
            }
        }
    }

    /// A P-256 EC public JWK from the RFC 6979 A.2.5 key, with the given
    /// coordinate lengths and an optional `alg` member.
    fn ec_public_jwk(x_len: usize, y_len: usize, alg: Option<&str>) -> String {
        use data_encoding::BASE64URL_NOPAD;
        use data_encoding_macro::hexlower;

        let x = hexlower!("60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6");
        let y = hexlower!("7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299");
        let alg = alg
            .map(|alg| format!(r#","alg":"{alg}""#))
            .unwrap_or_default();
        format!(
            r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}"{alg}}}"#,
            BASE64URL_NOPAD.encode(&x[..x_len]),
            BASE64URL_NOPAD.encode(&y[..y_len]),
        )
    }

    /// The EC JWK `alg` policy: the curve-paired JOSE alg is accepted, and
    /// any other value is refused with the allowlist diagnostic.
    #[test]
    fn ec_jwk_alg_policy() {
        SigPublic::import_ecdsa_jwk(EcdsaVariant::P256Sha256, &ec_public_jwk(32, 32, None))
            .unwrap();
        SigPublic::import_ecdsa_jwk(
            EcdsaVariant::P256Sha256,
            &ec_public_jwk(32, 32, Some("ES256")),
        )
        .unwrap();
        match SigPublic::import_ecdsa_jwk(
            EcdsaVariant::P256Sha256,
            &ec_public_jwk(32, 32, Some("ES384")),
        ) {
            Err(Error::InvalidKey(msg)) => {
                assert_eq!(msg, r#"JWK alg is "ES384", not one of ["ES256"]"#)
            }
            other => panic!("expected the alg diagnostic, got {other:?}"),
        }
    }

    /// The EC JWK coordinate-length guard renders its diagnostic for each
    /// clause alone — one short coordinate at a time — rather than
    /// deferring to the curve library's rejection of the assembled point.
    #[test]
    fn ec_jwk_coordinate_lengths_are_validated_with_the_message() {
        for (x_len, y_len, got) in [(31, 32, "31/32"), (32, 31, "32/31")] {
            match SigPublic::import_ecdsa_jwk(
                EcdsaVariant::P256Sha256,
                &ec_public_jwk(x_len, y_len, None),
            ) {
                Err(Error::InvalidKey(msg)) => assert_eq!(
                    msg,
                    format!("P-256 JWK coordinates are 32 bytes each, got {got}")
                ),
                other => panic!("expected the length diagnostic, got {other:?}"),
            }
        }
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn ecdsa_sign_verify_round_trip() {
        for variant in [EcdsaVariant::P256Sha256, EcdsaVariant::P384Sha384] {
            let key = SigningKeyMaterial::generate_ecdsa(variant, sp())
                .unwrap()
                .unwrap();
            assert_eq!(key.export(), Err(Error::NotExtractable));
            let sig = key.sign(b"message").unwrap();
            let public = key.public();
            assert!(public.verify(b"message", &sig).is_ok());
            assert_eq!(
                public.verify(b"tampered", &sig),
                Err(Error::AuthenticationFailed)
            );
        }
    }

    /// RFC 6979 A.2.5 (P-256 + SHA-256, message "sample"): the known
    /// answers the conformance tests deliberately do not carry — their
    /// browser targets could only realize private-key import via
    /// private-only PKCS#8, whose platform behavior is unspecified
    /// (w3c/webcrypto#356) — pinned here for both Rust implementations
    /// instead: deterministic signature bytes, scalar export identity,
    /// and the derived public point.
    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn ecdsa_rfc6979_known_answers() {
        use data_encoding_macro::hexlower;

        let scalar = hexlower!("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
        let key = SigningKeyMaterial::import_ecdsa_scalar(EcdsaVariant::P256Sha256, &scalar, xp())
            .unwrap();

        // Deterministic signature: exact r ‖ s reproduction.
        let expected = hexlower!(
            "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716\
             f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
        );
        assert_eq!(key.sign(b"sample").unwrap(), expected);

        // Scalar export identity.
        assert_eq!(key.export().unwrap(), scalar);

        // Derived public point (uncompressed SEC1).
        let point = hexlower!(
            "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29f\
             b67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d44622\
             99"
        );
        assert_eq!(key.public().export().unwrap(), point);
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn ecdsa_scalar_range_is_validated() {
        // Zero and the curve order are out of [1, n-1].
        match SigningKeyMaterial::import_ecdsa_scalar(EcdsaVariant::P256Sha256, &[0; 32], xp()) {
            Err(Error::InvalidKey(_)) => {}
            _ => panic!("expected invalid-key for the zero scalar"),
        }
    }

    /// The P-256 × SHA-384 cross variant: deterministic per key/message,
    /// self-verifying, and genuinely bound — the same public point minted
    /// under SHA-256 must reject the SHA-384 signature. (Byte-exactness
    /// against RFC 6979's published cross-hash vectors is deliberately
    /// unpinned: the WIT records that signature bytes differ across
    /// conforming implementations.)
    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn ecdsa_cross_variant_binds_the_hash() {
        use data_encoding_macro::hexlower;
        let scalar = hexlower!("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
        let key = SigningKeyMaterial::import_ecdsa_scalar(EcdsaVariant::P256Sha384, &scalar, xp())
            .unwrap();
        let sig = key.sign(b"sample").unwrap();
        assert_eq!(sig, key.sign(b"sample").unwrap(), "deterministic");
        let public = key.public();
        assert_eq!(public.hash(), Some("SHA-384"));
        assert!(public.verify(b"sample", &sig).is_ok());
        let sha256 =
            SigPublic::import_ecdsa(EcdsaVariant::P256Sha256, &public.export().unwrap()).unwrap();
        assert_eq!(
            sha256.verify(b"sample", &sig),
            Err(Error::AuthenticationFailed)
        );
    }

    /// SPKI and JWK forms round-trip for both signature families, and the
    /// wrong-curve/wrong-algorithm forms are rejected.
    #[test]
    fn public_format_round_trips() {
        let ed = SigningKeyMaterial::import_ed25519_seed(&[0x42; 32], xp()).unwrap();
        let public = ed.public();
        let spki = public.export_spki();
        assert_eq!(
            SigPublic::import_ed25519_spki(&spki)
                .unwrap()
                .export()
                .unwrap(),
            public.export().unwrap()
        );
        let jwk = public.export_jwk();
        assert_eq!(
            SigPublic::import_ed25519_jwk(&jwk)
                .unwrap()
                .export()
                .unwrap(),
            public.export().unwrap()
        );
        assert!(matches!(
            SigPublic::import_ed25519_spki(b"garbage"),
            Err(Error::InvalidKey(_))
        ));

        #[cfg(not(target_family = "wasm"))]
        {
            let ec = SigningKeyMaterial::generate_ecdsa(EcdsaVariant::P384Sha384, sp())
                .unwrap()
                .unwrap();
            let public = ec.public();
            let spki = public.export_spki();
            let back = SigPublic::import_ecdsa_spki(EcdsaVariant::P384Sha384, &spki).unwrap();
            assert_eq!(back.export().unwrap(), public.export().unwrap());
            // The wrong declared curve is rejected.
            assert!(matches!(
                SigPublic::import_ecdsa_spki(EcdsaVariant::P256Sha256, &spki),
                Err(Error::InvalidKey(_))
            ));
            let jwk = public.export_jwk();
            let back = SigPublic::import_ecdsa_jwk(EcdsaVariant::P384Sha384, &jwk).unwrap();
            assert_eq!(back.export().unwrap(), public.export().unwrap());
        }
    }

    /// Private imports round-trip through the private exports, mismatched
    /// JWK publics are rejected (the MAY this implementation takes), and
    /// the extractability gate holds.
    #[test]
    fn private_format_round_trips_and_gates() {
        let ed = SigningKeyMaterial::import_ed25519_seed(&[7; 32], xp()).unwrap();
        let p8 = ed.export_pkcs8().unwrap();
        let back = SigningKeyMaterial::import_ed25519_pkcs8(&p8, xp()).unwrap();
        assert_eq!(back.export().unwrap(), ed.export().unwrap());
        let jwk = ed.export_jwk().unwrap();
        let back = SigningKeyMaterial::import_ed25519_jwk(&jwk, xp()).unwrap();
        assert_eq!(back.export().unwrap(), ed.export().unwrap());
        // A JWK whose x is not d's public key is rejected.
        let other = SigningKeyMaterial::import_ed25519_seed(&[8; 32], xp()).unwrap();
        let mismatched =
            crate::jwk::build_okp_private("Ed25519", &other.public().export().unwrap(), &[7; 32]);
        assert!(matches!(
            SigningKeyMaterial::import_ed25519_jwk(&mismatched, xp()),
            Err(Error::InvalidKey(_))
        ));
        // The gate: non-extractable keys export nothing.
        let sealed = SigningKeyMaterial::import_ed25519_seed(&[7; 32], sp()).unwrap();
        assert_eq!(sealed.export_jwk(), Err(Error::NotExtractable));
        assert_eq!(sealed.export_pkcs8(), Err(Error::NotExtractable));

        #[cfg(not(target_family = "wasm"))]
        {
            let ec = SigningKeyMaterial::generate_ecdsa(EcdsaVariant::P256Sha256, xp())
                .unwrap()
                .unwrap();
            let p8 = ec.export_pkcs8().unwrap();
            let back = SigningKeyMaterial::import_ecdsa_pkcs8(EcdsaVariant::P256Sha256, &p8, xp())
                .unwrap();
            assert_eq!(back.export().unwrap(), ec.export().unwrap());
            let jwk = ec.export_jwk().unwrap();
            let back =
                SigningKeyMaterial::import_ecdsa_jwk(EcdsaVariant::P256Sha256, &jwk, xp()).unwrap();
            assert_eq!(back.export().unwrap(), ec.export().unwrap());
        }
    }

    #[test]
    fn debug_redacts_private_material() {
        let key = SigningKeyMaterial::import_ed25519_seed(&[0xAB; 32], xp()).unwrap();
        let rendered = format!("{key:?}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(!rendered.contains("171"), "{rendered}"); // 0xAB
    }

    // ---- RSA ----

    use data_encoding_macro::hexlower;

    /// The 2048-bit rsaEncryption SPKI (e = 65537) shared by Wycheproof
    /// `rsa_signature_2048_sha256_test.json` (group 1) and the
    /// `rsa_pss_2048_sha256_mgf1_{0,32}` files.
    fn rsa_2048_spki() -> Vec<u8> {
        hexlower!(
            "30820122300d06092a864886f70d01010105000382010f003082010a02820101\
             00a2b451a07d0aa5f96e455671513550514a8a5b462ebef717094fa1fee82224\
             e637f9746d3f7cafd31878d80325b6ef5a1700f65903b469429e89d6eac88450\
             97b5ab393189db92512ed8a7711a1253facd20f79c15e8247f3d3e42e46e48c9\
             8e254a2fe9765313a03eff8f17e1a029397a1fa26a8dce26f490ed81299615d9\
             814c22da610428e09c7d9658594266f5c021d0fceca08d945a12be82de4d1ece\
             6b4c03145b5d3495d4ed5411eb878daf05fd7afc3e09ada0f1126422f590975a\
             1969816f48698bcbba1b4d9cae79d460d8f9f85e7975005d9bc22c4e5ac0f7c1\
             a45d12569a62807d3b9a02e5a530e773066f453d1f5b4c2e9cf7820283f742b9\
             d50203010001"
        )
        .to_vec()
    }

    /// Wycheproof `rsa_signature_2048_sha256_test.json` tcId 1: a valid
    /// RSASSA-PKCS1-v1_5 SHA-256 signature over the empty message.
    fn rsa_2048_v15_sig_tc1() -> Vec<u8> {
        hexlower!(
            "840f5dac53106dd1f9c57219224cf51289290c42f20466875ba8e830ac5690e5\
             41536fcc8ab03b731f82bf66d83f194e7e180b3963ec7a2f3f7904a7ce49aed4\
             7da4d4b79421eaf937d301b3e696169297b797c32c076a12be4de0b58e003c51\
             23051a84a10c62f8dac2f42a8640008eb3c7cccd6760ff5b51b6897639225828\
             45f048fb8150e5a7a6ca2eccc7bdc85349ad5b26c52137a79fa3fe5c29ab5cd7\
             615013219c1941b6708e9c3c23feff5febaf0c8ebca5750b54e3e6e99a3e876b\
             396f27860b7f3ec4e9191703c6332d944f6f69751167680c79c4f6b57f1cc875\
             5d24b6ec158ccdbacdb23107a33cb6b332516c13274d1f9dccc21dced869e486"
        )
        .to_vec()
    }

    /// Wycheproof `rsa_pss_2048_sha256_mgf1_32_test.json` tcId 1 (sLen 32):
    /// a valid RSA-PSS SHA-256 signature over the empty message.
    fn rsa_2048_pss32_sig_tc1() -> Vec<u8> {
        hexlower!(
            "4f01e0c12b08625ecac89a69231906edf826380f37c959a96690d046316d68ff\
             ce9d5c471694fcebfc6b45534864689256e4fc81c78e583f675d0c94b4496474\
             51e81beff01a11a516d5e5ce3f1a910437cb8a3a5096b19fb15f4524a35b23d8\
             9cdba12cf5b71aac1047b28c562df7c5542c34ce23a182cf7e0e231934b17294\
             799d44877a1d68ef1b8f073619b7618e6b7c22db20030d98cf591ffc3d4da5f5\
             8613ecd5ecfc3b40a1d02f40891ca43695cd4c088b05a8054c89c595a47e2748\
             16f35384226f74459ee63e25a1bfc03c360490552ec38343f8ace502f065303b\
             00bc0ec320711b211fde92e57feb9013c3609342495ec0d7cabdec21e54acc38"
        )
        .to_vec()
    }

    /// Wycheproof `rsa_pss_2048_sha256_mgf1_0_test.json` tcId 1 (sLen 0):
    /// a valid RSA-PSS SHA-256 signature over the empty message, under the
    /// same key as the sLen-32 file.
    fn rsa_2048_pss0_sig_tc1() -> Vec<u8> {
        hexlower!(
            "20081f8894a1330c4d503f642880e3c30e398fc6235c24f1be752e2d49cd9493\
             ac0cf999e275c4f89ff08f0d9ba4e264a332525a616d336bd9e822f41ab3f4fa\
             e2f48ec66c2e52642ed93b7cb944396fbaa727cbfdfc1f20aace99a6f2a74475\
             c338f8d9f22a38cb5bc51752076503b3aef1e65e5a8f8583d9ae7378ded038cf\
             516898ad06beb90a42b85764526fcea44f74258fa4efb1da253d337f65619181\
             ceb832dfe285ce78ae6b15f204e23bab274e87445d9f5df97f41dc8e3a97736b\
             62591d075744b2552f90bcf1b1393e1e7627ef1f985f2bbabd52e43a35d0ddf4\
             c67126e391f922ef7b1bb1911cd6e1b303cb2910dd70672bbfb62ea4eaad725c"
        )
        .to_vec()
    }

    /// The 2048-bit e = 3 rsaEncryption SPKI of Wycheproof
    /// `rsa_signature_2048_sha256_test.json` group 2.
    fn rsa_2048_e3_spki() -> Vec<u8> {
        hexlower!(
            "30820120300d06092a864886f70d01010105000382010d003082010802820101\
             0090a5d7aba2c8dc828e616fc1fc45c7c52130c8589dcbe2913da187572f6c23\
             217b89a5186b6f90cbe053abfb0885a91f141dbe106ce6ad303904a5941df26c\
             ed10478cb56a7bd6cf1313c4966d9cf7c4509d9dc63566aa323e110af219f339\
             8c04e79bb486de8703793473136f5c9051af24bd2c0208ea1bf9321a3e8f24af\
             00aaca1216842eab248d58cf46ac786c49fd3ca8557e9b53993a4b9718cdc5c4\
             74bf1cfe58c07ad97b2c5acb7d86accc0fc7bed147adb2e77b8697d801509481\
             17714b806ff76f9d88147d84e93987b724bf4870429e85a7a7b51486a78d8a88\
             f1688f60e215d43d06221e2b993b5c12a607b80e9e0122472b29945f76b55737\
             c1020103"
        )
        .to_vec()
    }

    /// Wycheproof `rsa_signature_2048_sha256_test.json` tcId 258 ("small
    /// signature", valid) over the message `"3670"`, under the e = 3 key.
    fn rsa_2048_e3_sig_tc258() -> Vec<u8> {
        hexlower!(
            "0000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000\
             000000000000000000000989e7ff72e67e680bd21d5f966e4ad8a48c3592dbac\
             c4a2f035b4ef4d17a2f25f8a9fef7e78eb99d76d68629ed02d67c43c4b7ec8c3\
             badc32e3d0a524c326537739b0fde156723b27c23ae2b09895e470c64d700f5c"
        )
        .to_vec()
    }

    /// The id-RSASSA-PSS SubjectPublicKeyInfo (algorithm
    /// 1.2.840.113549.1.1.10 with PSS parameters) carried by Wycheproof
    /// `rsa_pss_2048_sha256_mgf1_32_params_test.json`.
    fn rsa_pss_params_spki() -> Vec<u8> {
        hexlower!(
            "30820156304106092a864886f70d01010a3034a00f300d060960864801650304\
             02010500a11c301a06092a864886f70d010108300d0609608648016503040201\
             0500a2030201200382010f003082010a0282010100a2b451a07d0aa5f96e4556\
             71513550514a8a5b462ebef717094fa1fee82224e637f9746d3f7cafd31878d8\
             0325b6ef5a1700f65903b469429e89d6eac8845097b5ab393189db92512ed8a7\
             711a1253facd20f79c15e8247f3d3e42e46e48c98e254a2fe9765313a03eff8f\
             17e1a029397a1fa26a8dce26f490ed81299615d9814c22da610428e09c7d9658\
             594266f5c021d0fceca08d945a12be82de4d1ece6b4c03145b5d3495d4ed5411\
             eb878daf05fd7afc3e09ada0f1126422f590975a1969816f48698bcbba1b4d9c\
             ae79d460d8f9f85e7975005d9bc22c4e5ac0f7c1a45d12569a62807d3b9a02e5\
             a530e773066f453d1f5b4c2e9cf7820283f742b9d50203010001"
        )
        .to_vec()
    }

    /// The 8192-bit rsaEncryption SPKI of Wycheproof
    /// `rsa_signature_8192_sha256_test.json`.
    fn rsa_8192_spki() -> Vec<u8> {
        hexlower!(
            "30820422300d06092a864886f70d01010105000382040f003082040a02820401\
             00dced8ed038581210fe2ccadbaa0728450b2bbb2066ca51ad97c2c1e53839df\
             d9870aa9b82c5029c1864ed48c019e408029b73603c605617be2e823c6f1bee4\
             154ac7900d7bfd7a8c05bbacd4807a0a1855066ebf7f04225a3d7dfd3d16d546\
             746c738a311d0fba6a32f00febf968d619bbe275eac61b80dec34927aef1b29b\
             96ba42967002c33f406bf47209d005b5d2c6d4ffaf63011bf415c3cab548faef\
             be855754cc885c64e3c74a3f11d1dd2ef3ca88de746cc245cba25c2ab1b62802\
             76265afaedfa24d21ac49e5101290f3a5330e362e6b2897e400839768f67d6ad\
             c443e1b51b19403925efa575f030e28668406fa52440ec9965c73fbd89374964\
             058f7acf354decbf6c79d23a7f35d1a296ba0f6ae36117e26ccfb56c453b859a\
             7ba12accb706559c146b245f9d222b5b7c2e158090c0946484c3893365e9bc81\
             8a265be8664f53ec6e779b5d73709f082bd943c2fc97731afd44609fc2bd37fa\
             b7e92b1715a52aa25115f2af31207aefd497c3bd061eb1a2b0559b9c6b1b2861\
             ad565e9be71091895abb94956f5d862f3a60e0cb9fd37dcb7c218e3a82ebc288\
             edaf3b64c1d8b80e71867b60465c0455d69d3bfadb9b8e4d1241c79f2ea8e6a3\
             b12af6877c1a06b051c8b12b023611a1b0e8e0823632bc16d1698133895df698\
             301f5472b4cbbe4dadbc4fab4617e825d829837f0dc6257dfb370486fe790781\
             45d616a34925d12031e67971e91fcadc302b7a6bea614b7c68d93c54a0692c7b\
             a6080a3522a052fc161b77305e8140d19196c4fd69d35e2cf72438804330411b\
             c8597c52ac834e914156ebaa65ffd71123946d195a0348fe61644e6dd0bc13c8\
             9ffb8400832312e0949f7cfa12bf7802d1eda352b34bc3c34edea995548590ad\
             59b249c4674ce1063de9e84cd1d1c4cc9b31def87b39010a1ab344319a630cbb\
             db74896758138cd8506730f34228798dcba116c01c204353353ceca3ee594917\
             44d04336e5218e6d43361d5c9ac619340599884f82634a64101713c1f2368a7c\
             0ee8d9af80e539caec7cc07545d91c8b03c8aac7556ea169675e5aed7efb71a2\
             36710e570b48b7bc922c1b619acd8aecd9c9a991216d67bc324697d8a190c75a\
             a23b5fe032aedae8cb90af0692f061a69346c9b9684cb77209886745d55bde82\
             53bde37821f68364a25e706092962ee1c57adf45af7efc93bc8b5e61524c0589\
             68f69e81d901bd63630de3b1856d77878ecf845efde3d0ac3ed39a9570d228c1\
             924c01b72c2b46d0b4c84e0af1f2e9f894a3ad4a0a7845f7f71224d4f14bafdb\
             f4b0b854a70e873a8a1e18ed25eb7e0af22d3e9346174aa03fdf73f5c9a3f7b3\
             526bd42d9fb59734f344aacc910c127d30890279de5e54974805d8870374b47b\
             95bb6bde71ab5c41e9596ec2ec20e588dcd81240452c9614ade0f7c4c35e9e8c\
             a90203010001"
        )
        .to_vec()
    }

    /// Wycheproof `rsa_signature_8192_sha256_test.json` tcId 1: a valid
    /// RSASSA-PKCS1-v1_5 SHA-256 signature over the empty message.
    fn rsa_8192_sig_tc1() -> Vec<u8> {
        hexlower!(
            "621f3710d76cff557ad5e8158c8266d3053e5dadf6054cf3314758285b4524cf\
             d806e75fd55664bf5fa9f9e0ffe50c058a891cc1aaa6f949cfc8ef7d27b6fc04\
             6b298fb27b3f9591fa3b5aeb4c15f791ff00ef9e95eca768fb3910cf0c81ef62\
             910df7c47514141a881004d69e58925ea87409d45354ba1ed66cd0eeb927be2e\
             42476f576142bf2b62dc084d015ca9dbb861357beaa94ab3635349c93401116b\
             9f1c73461225371977054b9f2e2591c566b9139d8b96fd57d3e47cde1756309c\
             a18e602a09eb5e1de19c91c9d6de659995e8e611fcc62320fff6ee54ee725831\
             32d1d9f9a44ad19949b372a8ec567fee0fde3463115e3ade7e918b8f490924b3\
             f1bf7a3a218ec64dc3f1d0dcf16c8f4324265a737ec37fa48f10d78fce936a05\
             3dd96c69ad3b698ed2a12d4500fb4254933208667c6d187ad70f296830936ba5\
             b7ff2ce6cb6e9479b563d586ba33d32955b881e2b69715ec1a2e8dddbff47b08\
             606a3c0db0b1e58dc7c8e118d16c5ee691babc6605a7f7475162c47c06c93d9b\
             5c4f6a6904ddf7c6cdf45f9958daf87b0d45b629b5b6a7c258d1c7f230d2e341\
             39efe808bbcc8f8eab49fee2b51ce640c124cc115826eecfe3c0409ead85eb08\
             e57b0f451f7a4621b1b7ef3f7f110fb71c57ae1ce1f4de151dc4d6b924de3bf7\
             f39fa5f784b9fc91a0d7c9700711dec27ab9ec0eacc64f826f6f5597f6eaf522\
             b256705bc3591884b0508beb6d80a9849e8156841459ecc96c6e2a1235668078\
             f4d77bad7ff3b727c4442f6605266650bcab399234617f035555e87f08f8846d\
             22720151fc9955390532f3c701bc861d83e00da003f734ddd2b9576712b91140\
             ad9a42097fc47f789bfcd873b34ab8090879d0bc28ccdef234ab34f23f6c574a\
             a019e45b542c4282bd836a2635fbe8261f110dccf9e70980a54c910dfb4da064\
             41900ead072db6e0283393a6c118ee8b0327759519dde55d36b72a920292900a\
             8e68b744d2bd151c734f37a4062708afae1fc23ea0c473d65429810878ff5042\
             f8b9fd98407cd4aa44cad32494355f912c5370d94f3bfe266f899a5fe05010a3\
             f84ab8e6f86206e1936dfeffd4c8d07bf58df9d863d9db032070e228e6a4ba07\
             58e60ef81e5656d3ae82da6c7bc88f7c806e2aedea7a2f9df4f022dba15bcc1a\
             3ec83a267b8d03e4843546d0977adee28cf0ac97fda8420b90c01178bf67c45d\
             4383d5e00f43f70672c867fc73312210dc7ca01bcdbde276c43caaab8f67d663\
             8bfb8dba298d7a81d829ab67e687c443f19e16606334d6abb2712e93a4488746\
             97bfe3af41548c96e434a909bd33ec08ecbbbaa319b7ebb3bc33b6be9a52a3f1\
             d10767471a31a1a97f1aff983f8236287eb804b1877bcb6dc2ddfa5d0f55541a\
             b6c13292b4c4af5a24f4382f0605975a5953f8a3696bfe8652b31722aa2a556a"
        )
        .to_vec()
    }

    /// Wycheproof `rsa_signature_2048_sha256_test.json` group 1 `keyJwk` (alg RS256).
    const RSA_2048_RS256_JWK: &str = r#"{"alg":"RS256","e":"AQAB","kid":"none","kty":"RSA","n":"orRRoH0KpfluRVZxUTVQUUqKW0YuvvcXCU-h_ugiJOY3-XRtP3yv0xh42AMltu9aFwD2WQO0aUKeidbqyIRQl7WrOTGJ25JRLtincRoSU_rNIPecFegkfz0-QuRuSMmOJUov6XZTE6A-_48X4aApOXofomqNzib0kO2BKZYV2YFMItphBCjgnH2WWFlCZvXAIdD87KCNlFoSvoLeTR7Oa0wDFFtdNJXU7VQR64eNrwX9evw-Ca2g8RJkIvWQl1oZaYFvSGmLy7obTZyuedRg2Pn4Xnl1AF2bwixOWsD3waRdElaaYoB9O5oC5aUw53MGb0U9H1tMLpz3ggKD90K51Q"}"#;

    /// Wycheproof `rsa_pss_2048_sha256_mgf1_32_test.json` `publicKeyJwk` (alg PS256).
    const RSA_2048_PS256_JWK: &str = r#"{"kty":"RSA","alg":"PS256","n":"orRRoH0KpfluRVZxUTVQUUqKW0YuvvcXCU-h_ugiJOY3-XRtP3yv0xh42AMltu9aFwD2WQO0aUKeidbqyIRQl7WrOTGJ25JRLtincRoSU_rNIPecFegkfz0-QuRuSMmOJUov6XZTE6A-_48X4aApOXofomqNzib0kO2BKZYV2YFMItphBCjgnH2WWFlCZvXAIdD87KCNlFoSvoLeTR7Oa0wDFFtdNJXU7VQR64eNrwX9evw-Ca2g8RJkIvWQl1oZaYFvSGmLy7obTZyuedRg2Pn4Xnl1AF2bwixOWsD3waRdElaaYoB9O5oC5aUw53MGb0U9H1tMLpz3ggKD90K51Q","e":"AQAB","kid":"none"}"#;

    /// A synthetic RSA modulus of `bits` length for admission-only checks:
    /// top bit set, odd (an actual factorization is irrelevant — admission
    /// looks only at the value bounds).
    fn synthetic_n(bits: usize) -> Vec<u8> {
        assert_eq!(bits % 8, 0);
        let mut n = vec![0u8; bits / 8];
        n[0] = 0x80;
        *n.last_mut().unwrap() |= 1;
        n
    }

    /// Wycheproof `rsa_signature_2048_sha256_test.json` tcId 1: the SPKI
    /// and JWK imports agree, the signature verifies, tampered data is
    /// rejected, and the getters report the scheme.
    #[test]
    fn rsassa_2048_known_answer() {
        let sig = rsa_2048_v15_sig_tc1();
        for key in [
            SigPublic::import_rsassa_spki(RsaVariant::Sha256, &rsa_2048_spki()).unwrap(),
            SigPublic::import_rsassa_jwk(RsaVariant::Sha256, RSA_2048_RS256_JWK).unwrap(),
        ] {
            assert!(key.verify(b"", &sig).is_ok());
            assert_eq!(
                key.verify(b"tampered", &sig),
                Err(Error::AuthenticationFailed)
            );
            assert_eq!(key.name(), "RSASSA-PKCS1-v1_5");
            assert_eq!(key.hash(), Some("SHA-256"));
            assert_eq!(key.curve(), None);
            assert_eq!(key.length(), Some(2048));
        }
    }

    /// Wycheproof `rsa_pss_2048_sha256_mgf1_32_test.json` tcId 1 (sLen 32):
    /// the SPKI and JWK imports agree and verify, and the getters report
    /// the scheme.
    #[test]
    fn pss_2048_known_answer() {
        let sig = rsa_2048_pss32_sig_tc1();
        for key in [
            SigPublic::import_pss_spki(RsaVariant::Sha256, 32, &rsa_2048_spki()).unwrap(),
            SigPublic::import_pss_jwk(RsaVariant::Sha256, 32, RSA_2048_PS256_JWK).unwrap(),
        ] {
            assert!(key.verify(b"", &sig).is_ok());
            assert_eq!(
                key.verify(b"tampered", &sig),
                Err(Error::AuthenticationFailed)
            );
            assert_eq!(key.name(), "RSA-PSS");
            assert_eq!(key.hash(), Some("SHA-256"));
            assert_eq!(key.curve(), None);
            assert_eq!(key.length(), Some(2048));
        }
    }

    /// Wycheproof `rsa_signature_8192_sha256_test.json` tcId 1: an
    /// 8192-bit key — beyond the `rsa` crate's 4096-bit default
    /// construction ceiling — is admitted and verifies.
    #[test]
    fn rsassa_8192_known_answer() {
        let key = SigPublic::import_rsassa_spki(RsaVariant::Sha256, &rsa_8192_spki()).unwrap();
        assert_eq!(key.length(), Some(8192));
        assert!(key.verify(b"", &rsa_8192_sig_tc1()).is_ok());
    }

    /// Wycheproof `rsa_signature_2048_sha256_test.json` tcId 258 (group 2,
    /// e = 3, "small signature", valid): the guaranteed-import exponent 3
    /// imports and verifies.
    #[test]
    fn rsassa_e3_key_imports_and_verifies() {
        let key = SigPublic::import_rsassa_spki(RsaVariant::Sha256, &rsa_2048_e3_spki()).unwrap();
        assert!(key.verify(b"3670", &rsa_2048_e3_sig_tc258()).is_ok());
    }

    /// The family modulus window: 768 bits (below) and 16392 bits (above)
    /// both reject `invalid-key` naming the window.
    #[test]
    fn rsa_modulus_window() {
        for bits in [768usize, 16392] {
            let jwk = crate::jwk::build_rsa_public(&synthetic_n(bits), &[1, 0, 1]);
            match SigPublic::import_rsassa_jwk(RsaVariant::Sha256, &jwk) {
                Err(Error::InvalidKey(msg)) => assert_eq!(
                    msg,
                    format!("RSA moduli are 1024-16384 bits, got {bits} bits")
                ),
                other => panic!("expected the window diagnostic, got {other:?}"),
            }
        }
        // Both window edges import.
        for bits in [1024usize, 16384] {
            let jwk = crate::jwk::build_rsa_public(&synthetic_n(bits), &[1, 0, 1]);
            let key = SigPublic::import_rsassa_jwk(RsaVariant::Sha256, &jwk).unwrap();
            assert_eq!(key.length(), Some(bits as u32));
        }
    }

    /// The family exponent floor: e = 1 (odd but small) and e = 4 (even)
    /// reject `invalid-key`; e = 3 and e = 65537 import.
    #[test]
    fn rsa_exponent_admission() {
        let n = synthetic_n(1024);
        for e in [&[1u8][..], &[4]] {
            let jwk = crate::jwk::build_rsa_public(&n, e);
            match SigPublic::import_rsassa_jwk(RsaVariant::Sha256, &jwk) {
                Err(Error::InvalidKey(msg)) => {
                    assert_eq!(msg, "RSA public exponents must be odd and at least 3")
                }
                other => panic!("expected the exponent diagnostic, got {other:?}"),
            }
        }
        for e in [&[3u8][..], &[1, 0, 1]] {
            let jwk = crate::jwk::build_rsa_public(&n, e);
            SigPublic::import_rsassa_jwk(RsaVariant::Sha256, &jwk).unwrap();
        }
    }

    /// An SPKI whose algorithm is `id-RSASSA-PSS` (with PSS parameters)
    /// rejects `invalid-key` on both RSA minting paths, per the family
    /// contract. The key material is Wycheproof
    /// `rsa_pss_2048_sha256_mgf1_32_params_test.json`'s.
    #[test]
    fn rsa_pss_params_spki_is_rejected() {
        let spki = rsa_pss_params_spki();
        for result in [
            SigPublic::import_rsassa_spki(RsaVariant::Sha256, &spki),
            SigPublic::import_pss_spki(RsaVariant::Sha256, 32, &spki),
        ] {
            match result {
                Err(Error::InvalidKey(msg)) => assert_eq!(
                    msg,
                    "SPKI algorithm must be rsaEncryption, got 1.2.840.113549.1.1.10"
                ),
                other => panic!("expected the algorithm diagnostic, got {other:?}"),
            }
        }
    }

    /// The mint-bound PSS salt length genuinely binds: the sLen-0 and
    /// sLen-32 Wycheproof signatures (same key, same digest) each verify
    /// only under their own salt length, and the cross verdict is
    /// `authentication-failed` — a non-verifying signature, not an error
    /// case.
    #[test]
    fn pss_salt_length_binds() {
        let salt0 = SigPublic::import_pss_spki(RsaVariant::Sha256, 0, &rsa_2048_spki()).unwrap();
        let salt32 = SigPublic::import_pss_spki(RsaVariant::Sha256, 32, &rsa_2048_spki()).unwrap();
        let sig0 = rsa_2048_pss0_sig_tc1();
        let sig32 = rsa_2048_pss32_sig_tc1();
        assert!(salt0.verify(b"", &sig0).is_ok());
        assert!(salt32.verify(b"", &sig32).is_ok());
        assert_eq!(salt0.verify(b"", &sig32), Err(Error::AuthenticationFailed));
        assert_eq!(salt32.verify(b"", &sig0), Err(Error::AuthenticationFailed));
    }

    /// The RSA JWK `alg` policy: each import accepts only its own scheme's
    /// JOSE alg for the declared variant, so the RS/PS families and the
    /// digests cross-reject; a JWK carrying private members is refused.
    #[test]
    fn rsa_jwk_contract() {
        // The RS256-tagged JWK is not a PSS key…
        assert!(matches!(
            SigPublic::import_pss_jwk(RsaVariant::Sha256, 32, RSA_2048_RS256_JWK),
            Err(Error::InvalidKey(_))
        ));
        // …the PS256-tagged JWK is not a PKCS#1 v1.5 key…
        assert!(matches!(
            SigPublic::import_rsassa_jwk(RsaVariant::Sha256, RSA_2048_PS256_JWK),
            Err(Error::InvalidKey(_))
        ));
        // …and RS256 is not RS384.
        match SigPublic::import_rsassa_jwk(RsaVariant::Sha384, RSA_2048_RS256_JWK) {
            Err(Error::InvalidKey(msg)) => {
                assert_eq!(msg, r#"JWK alg is "RS256", not one of ["RS384"]"#)
            }
            other => panic!("expected the alg diagnostic, got {other:?}"),
        }
        // A private-member JWK is refused toward the private import.
        let private = r#"{"kty":"RSA","n":"gAE","e":"AQAB","d":"AQID"}"#;
        match SigPublic::import_rsassa_jwk(RsaVariant::Sha256, private) {
            Err(Error::InvalidKey(msg)) => {
                assert_eq!(msg, "JWK carries `d`; import it as a private key")
            }
            other => panic!("expected the private-member diagnostic, got {other:?}"),
        }
    }

    /// The RSA export surface: no raw form (`unsupported`), the SPKI
    /// round-trips byte-exactly (DER is canonical), and the JWK export
    /// re-imports to the same key.
    #[test]
    fn rsa_exports() {
        let spki = rsa_2048_spki();
        let key = SigPublic::import_rsassa_spki(RsaVariant::Sha256, &spki).unwrap();
        match key.export() {
            Err(Error::Unsupported(msg)) => {
                assert_eq!(msg, "RSA public keys have no raw form")
            }
            other => panic!("expected unsupported, got {other:?}"),
        }
        assert_eq!(key.export_spki(), spki);
        let jwk = key.export_jwk();
        let back = SigPublic::import_rsassa_jwk(RsaVariant::Sha256, &jwk).unwrap();
        assert_eq!(back.export_spki(), spki);
        assert!(back.verify(b"", &rsa_2048_v15_sig_tc1()).is_ok());
    }

    /// `signing-key.algorithm-length` is `none` for every algorithm with
    /// a signing half here.
    #[test]
    fn signing_key_length_is_none() {
        let ed = SigningKeyMaterial::import_ed25519_seed(&[7; 32], sp()).unwrap();
        assert_eq!(ed.length(), None);
        #[cfg(not(target_family = "wasm"))]
        {
            let ec = SigningKeyMaterial::generate_ecdsa(EcdsaVariant::P256Sha256, sp())
                .unwrap()
                .unwrap();
            assert_eq!(ec.length(), None);
        }
    }
}
