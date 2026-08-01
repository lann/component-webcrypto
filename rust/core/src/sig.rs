//! The `signature` key material: public verification keys (every target)
//! and private signing keys — Ed25519 on every target, ECDSA only on
//! non-wasm targets (class D; see the crate doc).

use zeroize::Zeroizing;

use crate::{
    not_permitted, EcdsaVariant, Error, RngError, SigningPolicy, ECDSA_NAME, ED25519_NAME,
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

/// The algorithm behind a signature key, shared by the public and private
/// halves so the `algorithm-name`/`-curve`/`-hash` getters have one table.
#[derive(Clone, Copy)]
enum SigAlg {
    Ed25519,
    P256(EcdsaHash),
    P384(EcdsaHash),
}

impl SigAlg {
    /// The registry algorithm name (`algorithm-name`).
    fn name(self) -> &'static str {
        match self {
            Self::Ed25519 => ED25519_NAME,
            Self::P256(_) | Self::P384(_) => ECDSA_NAME,
        }
    }

    /// The registry curve name (`algorithm-curve`).
    fn curve(self) -> Option<&'static str> {
        match self {
            Self::Ed25519 => None,
            Self::P256(_) => Some("P-256"),
            Self::P384(_) => Some("P-384"),
        }
    }

    /// The mint-bound digest name (`algorithm-hash`).
    fn hash(self) -> Option<&'static str> {
        match self {
            Self::Ed25519 => None,
            Self::P256(hash) | Self::P384(hash) => Some(hash.name()),
        }
    }
}

/// The public key behind a `signature.verifying-key` resource, bound to its
/// algorithm (and, for ECDSA, its curve/digest variant) at minting.
/// Verification is secret-free, so every arm exists on every target.
pub enum SigPublic {
    Ed25519(ed25519_dalek::VerifyingKey),
    EcdsaP256(p256::ecdsa::VerifyingKey, EcdsaHash),
    EcdsaP384(p384::ecdsa::VerifyingKey, EcdsaHash),
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
        match curve {
            EcdsaCurve::P256 => p256::ecdsa::VerifyingKey::from_sec1_bytes(raw)
                .map(|key| Self::EcdsaP256(key, hash))
                .map_err(|err| Error::InvalidKey(format!("invalid P-256 public key: {err}"))),
            EcdsaCurve::P384 => p384::ecdsa::VerifyingKey::from_sec1_bytes(raw)
                .map(|key| Self::EcdsaP384(key, hash))
                .map_err(|err| Error::InvalidKey(format!("invalid P-384 public key: {err}"))),
        }
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
        match curve {
            EcdsaCurve::P256 => p256::ecdsa::VerifyingKey::from_public_key_der(spki)
                .map(|key| Self::EcdsaP256(key, hash))
                .map_err(|err| Error::InvalidKey(format!("invalid P-256 spki: {err}"))),
            EcdsaCurve::P384 => p384::ecdsa::VerifyingKey::from_public_key_der(spki)
                .map(|key| Self::EcdsaP384(key, hash))
                .map_err(|err| Error::InvalidKey(format!("invalid P-384 spki: {err}"))),
        }
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

    /// The key's algorithm tag.
    fn alg(&self) -> SigAlg {
        match self {
            Self::Ed25519(_) => SigAlg::Ed25519,
            Self::EcdsaP256(_, hash) => SigAlg::P256(*hash),
            Self::EcdsaP384(_, hash) => SigAlg::P384(*hash),
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

    /// The public key material in the minting interface's documented form:
    /// raw 32 bytes for Ed25519, an uncompressed SEC1 point for ECDSA.
    pub fn export(&self) -> Vec<u8> {
        match self {
            Self::Ed25519(key) => key.to_bytes().to_vec(),
            Self::EcdsaP256(key, _) => key.to_encoded_point(false).as_bytes().to_vec(),
            Self::EcdsaP384(key, _) => key.to_encoded_point(false).as_bytes().to_vec(),
        }
    }

    /// The public key as a SubjectPublicKeyInfo
    /// (`verifying-key.export-key-spki`).
    pub fn export_spki(&self) -> Vec<u8> {
        use spki::EncodePublicKey as _;
        match self {
            Self::Ed25519(key) => {
                crate::der8410::rfc8410_spki(crate::der8410::OID_ED25519, key.as_bytes())
            }
            Self::EcdsaP256(key, _) => key
                .to_public_key_der()
                .expect("valid key encodes")
                .into_vec(),
            Self::EcdsaP384(key, _) => key
                .to_public_key_der()
                .expect("valid key encodes")
                .into_vec(),
        }
    }

    /// The public key as a JWK (`verifying-key.export-key-jwk`).
    pub fn export_jwk(&self) -> String {
        match self {
            Self::Ed25519(key) => crate::jwk::build_okp_public("Ed25519", key.as_bytes()),
            Self::EcdsaP256(key, _) => {
                let point = key.to_encoded_point(false);
                crate::jwk::build_ec_public("P-256", point.x().unwrap(), point.y().unwrap())
            }
            Self::EcdsaP384(key, _) => {
                let point = key.to_encoded_point(false);
                crate::jwk::build_ec_public("P-384", point.x().unwrap(), point.y().unwrap())
            }
        }
    }

    /// One-shot verification of `sig` over `data`, failing closed with
    /// `authentication-failed` (the `verifying-key.verify` contract): the
    /// ECDSA signature format is fixed-width `r ‖ s` (IEEE P1363), and
    /// Ed25519 uses `verify_strict` semantics per the `ed25519-verify`
    /// criterion.
    pub fn verify(&self, data: &[u8], sig: &[u8]) -> Result<(), Error> {
        use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
        /// Verify under the mint-bound digest via the prehash path: its
        /// bits2field conversion applies FIPS 186-5's leftmost-bits rule
        /// for digests wider or narrower than the curve.
        macro_rules! ecdsa_verify {
            ($key:expr, $hash:expr, $sigty:ty, $sig:expr, $data:expr) => {
                <$sigty>::from_slice($sig)
                    .map_err(|_| ())
                    .and_then(|sig| {
                        $key.verify_prehash(&ecdsa_digest(*$hash, $data), &sig)
                            .map_err(|_| ())
                    })
                    .is_ok()
            };
        }
        let ok = match self {
            Self::Ed25519(key) => ed25519_dalek::Signature::from_slice(sig)
                .and_then(|sig| key.verify_strict(data, &sig))
                .is_ok(),
            Self::EcdsaP256(key, hash) => {
                ecdsa_verify!(key, hash, p256::ecdsa::Signature, sig, data)
            }
            Self::EcdsaP384(key, hash) => {
                ecdsa_verify!(key, hash, p384::ecdsa::Signature, sig, data)
            }
        };
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
    if x.len() != len || y.len() != len {
        return Err(Error::InvalidKey(format!(
            "{} JWK coordinates are {len} bytes each, got {}/{}",
            curve_name(curve),
            x.len(),
            y.len()
        )));
    }
    let mut point = Vec::with_capacity(1 + 2 * len);
    point.push(0x04);
    point.extend_from_slice(x);
    point.extend_from_slice(y);
    Ok(point)
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
        let private = match curve {
            EcdsaCurve::P256 => p256::ecdsa::SigningKey::from_slice(raw)
                .map(|key| SigPrivate::EcdsaP256(key, hash))
                .map_err(|err| Error::InvalidKey(format!("invalid P-256 private key: {err}")))?,
            EcdsaCurve::P384 => p384::ecdsa::SigningKey::from_slice(raw)
                .map(|key| SigPrivate::EcdsaP384(key, hash))
                .map_err(|err| Error::InvalidKey(format!("invalid P-384 private key: {err}")))?,
        };
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
        let private = match curve {
            EcdsaCurve::P256 => p256::ecdsa::SigningKey::from_pkcs8_der(pkcs8_der)
                .map(|key| SigPrivate::EcdsaP256(key, hash))
                .map_err(|err| Error::InvalidKey(format!("invalid P-256 pkcs8: {err}")))?,
            EcdsaCurve::P384 => p384::ecdsa::SigningKey::from_pkcs8_der(pkcs8_der)
                .map(|key| SigPrivate::EcdsaP384(key, hash))
                .map_err(|err| Error::InvalidKey(format!("invalid P-384 pkcs8: {err}")))?,
        };
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
        if key.public().export() != expected {
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
        if key.public().export() != okp.x {
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
        #[cfg(not(target_family = "wasm"))]
        macro_rules! ecdsa_sign {
            ($key:expr, $hash:expr, $sigty:ty, $data:expr) => {{
                use p256::ecdsa::signature::hazmat::PrehashSigner as _;
                // Deterministic (RFC 6979-style HMAC-DRBG over the curve's
                // digest) and verify-compatible with any conforming
                // verifier. The exact bytes are deliberately not part of
                // any contract: the WIT records that RFC 6979 and
                // randomized-k implementations both verify while differing
                // in bytes, and cross-hash variants differ from the RFC's
                // published vectors in their nonce-derivation hash.
                let sig: $sigty = $key
                    .sign_prehash(&ecdsa_digest(*$hash, $data))
                    .expect("prehash length is a digest's; signing cannot fail");
                sig.to_bytes().to_vec()
            }};
        }
        Ok(match &self.private {
            SigPrivate::Ed25519(key) => {
                use ed25519_dalek::Signer as _;
                key.sign(data).to_bytes().to_vec()
            }
            #[cfg(not(target_family = "wasm"))]
            SigPrivate::EcdsaP256(key, hash) => {
                ecdsa_sign!(key, hash, p256::ecdsa::Signature, data)
            }
            #[cfg(not(target_family = "wasm"))]
            SigPrivate::EcdsaP384(key, hash) => {
                ecdsa_sign!(key, hash, p384::ecdsa::Signature, data)
            }
        })
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
        Ok(match &self.private {
            SigPrivate::Ed25519(key) => key.to_bytes().to_vec(),
            #[cfg(not(target_family = "wasm"))]
            SigPrivate::EcdsaP256(key, _) => key.to_bytes().to_vec(),
            #[cfg(not(target_family = "wasm"))]
            SigPrivate::EcdsaP384(key, _) => key.to_bytes().to_vec(),
        })
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
        Ok(match &self.private {
            SigPrivate::Ed25519(key) => crate::jwk::build_okp_private(
                "Ed25519",
                key.verifying_key().as_bytes(),
                &key.to_bytes(),
            ),
            #[cfg(not(target_family = "wasm"))]
            SigPrivate::EcdsaP256(key, _) => {
                let point = key.verifying_key().to_encoded_point(false);
                crate::jwk::build_ec_private(
                    "P-256",
                    point.x().unwrap(),
                    point.y().unwrap(),
                    &key.to_bytes(),
                )
            }
            #[cfg(not(target_family = "wasm"))]
            SigPrivate::EcdsaP384(key, _) => {
                let point = key.verifying_key().to_encoded_point(false);
                crate::jwk::build_ec_private(
                    "P-384",
                    point.x().unwrap(),
                    point.y().unwrap(),
                    &key.to_bytes(),
                )
            }
        })
    }

    /// The private key as a PKCS#8 PrivateKeyInfo (the
    /// `signing-key.export-key-pkcs8` contract), behind the same gate:
    /// the RFC 8410 v1 form for Ed25519, the SEC1 body for ECDSA.
    pub fn export_pkcs8(&self) -> Result<Vec<u8>, Error> {
        if !self.policy.extractable {
            return Err(Error::NotExtractable);
        }
        Ok(match &self.private {
            SigPrivate::Ed25519(key) => {
                crate::der8410::rfc8410_pkcs8(crate::der8410::OID_ED25519, &key.to_bytes()).to_vec()
            }
            #[cfg(not(target_family = "wasm"))]
            SigPrivate::EcdsaP256(key, _) => {
                use pkcs8::EncodePrivateKey as _;
                key.to_pkcs8_der()
                    .expect("valid key encodes")
                    .to_bytes()
                    .to_vec()
            }
            #[cfg(not(target_family = "wasm"))]
            SigPrivate::EcdsaP384(key, _) => {
                use pkcs8::EncodePrivateKey as _;
                key.to_pkcs8_der()
                    .expect("valid key encodes")
                    .to_bytes()
                    .to_vec()
            }
        })
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
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        use hex_literal::hex;

        let x = hex!("60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6");
        let y = hex!("7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299");
        let alg = alg
            .map(|alg| format!(r#","alg":"{alg}""#))
            .unwrap_or_default();
        format!(
            r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}"{alg}}}"#,
            URL_SAFE_NO_PAD.encode(&x[..x_len]),
            URL_SAFE_NO_PAD.encode(&y[..y_len]),
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
        use hex_literal::hex;

        let scalar = hex!("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
        let key = SigningKeyMaterial::import_ecdsa_scalar(EcdsaVariant::P256Sha256, &scalar, xp())
            .unwrap();

        // Deterministic signature: exact r ‖ s reproduction.
        let expected = hex!(
            "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
            "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
        );
        assert_eq!(key.sign(b"sample").unwrap(), expected);

        // Scalar export identity.
        assert_eq!(key.export().unwrap(), scalar);

        // Derived public point (uncompressed SEC1).
        let point = hex!(
            "04"
            "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
            "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
        );
        assert_eq!(key.public().export(), point);
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
        use hex_literal::hex;
        let scalar = hex!("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
        let key = SigningKeyMaterial::import_ecdsa_scalar(EcdsaVariant::P256Sha384, &scalar, xp())
            .unwrap();
        let sig = key.sign(b"sample").unwrap();
        assert_eq!(sig, key.sign(b"sample").unwrap(), "deterministic");
        let public = key.public();
        assert_eq!(public.hash(), Some("SHA-384"));
        assert!(public.verify(b"sample", &sig).is_ok());
        let sha256 = SigPublic::import_ecdsa(EcdsaVariant::P256Sha256, &public.export()).unwrap();
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
            SigPublic::import_ed25519_spki(&spki).unwrap().export(),
            public.export()
        );
        let jwk = public.export_jwk();
        assert_eq!(
            SigPublic::import_ed25519_jwk(&jwk).unwrap().export(),
            public.export()
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
            assert_eq!(back.export(), public.export());
            // The wrong declared curve is rejected.
            assert!(matches!(
                SigPublic::import_ecdsa_spki(EcdsaVariant::P256Sha256, &spki),
                Err(Error::InvalidKey(_))
            ));
            let jwk = public.export_jwk();
            let back = SigPublic::import_ecdsa_jwk(EcdsaVariant::P384Sha384, &jwk).unwrap();
            assert_eq!(back.export(), public.export());
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
            crate::jwk::build_okp_private("Ed25519", other.public().export().as_slice(), &[7; 32]);
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
}
