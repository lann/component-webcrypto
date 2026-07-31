//! The `signature` key material: public verification keys (every target)
//! and private signing keys — Ed25519 on every target, ECDSA only on
//! non-wasm targets (class D; see the crate doc).

use zeroize::Zeroizing;

use crate::{EcdsaVariant, Error, RngError, ECDSA_NAME, ED25519_NAME};

/// The P-521 decline every ECDSA minting path renders (see the WIT
/// `ecdsa-variant` doc: declared, served by no implementation here).
fn p521_unsupported() -> Error {
    Error::Unsupported("ECDSA P-521 is not served by this implementation".into())
}

/// The algorithm behind a signature key, shared by the public and private
/// halves so the `algorithm-name`/`-curve`/`-hash` getters have one table.
#[derive(Clone, Copy)]
enum SigAlg {
    Ed25519,
    P256,
    P384,
}

impl SigAlg {
    /// The registry algorithm name (`algorithm-name`).
    fn name(self) -> &'static str {
        match self {
            Self::Ed25519 => ED25519_NAME,
            Self::P256 | Self::P384 => ECDSA_NAME,
        }
    }

    /// The registry curve name (`algorithm-curve`).
    fn curve(self) -> Option<&'static str> {
        match self {
            Self::Ed25519 => None,
            Self::P256 => Some("P-256"),
            Self::P384 => Some("P-384"),
        }
    }

    /// The mint-bound digest name (`algorithm-hash`).
    fn hash(self) -> Option<&'static str> {
        match self {
            Self::Ed25519 => None,
            Self::P256 => Some("SHA-256"),
            Self::P384 => Some("SHA-384"),
        }
    }
}

/// The public key behind a `signature.verifying-key` resource, bound to its
/// algorithm (and, for ECDSA, its curve/digest variant) at minting.
/// Verification is secret-free, so every arm exists on every target.
pub enum SigPublic {
    Ed25519(ed25519_dalek::VerifyingKey),
    EcdsaP256(p256::ecdsa::VerifyingKey),
    EcdsaP384(p384::ecdsa::VerifyingKey),
}

impl SigPublic {
    /// Import a 32-byte RFC 8032 public key, rendering `invalid-key` for
    /// wrong lengths and encodings the algorithm rejects (the
    /// `ed25519-verify.import-verifying-key` contract).
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
    /// `ecdsa-verify.import-verifying-key` contract).
    pub fn import_ecdsa(variant: EcdsaVariant, raw: &[u8]) -> Result<Self, Error> {
        let expected = match variant {
            EcdsaVariant::P256Sha256 => 65,
            EcdsaVariant::P384Sha384 => 97,
            EcdsaVariant::P521Sha512 => return Err(p521_unsupported()),
        };
        if raw.len() != expected || raw[0] != 0x04 {
            return Err(Error::InvalidKey(format!(
                "{variant:?} public keys are uncompressed SEC1 points ({expected} bytes, leading 0x04)"
            )));
        }
        match variant {
            EcdsaVariant::P256Sha256 => p256::ecdsa::VerifyingKey::from_sec1_bytes(raw)
                .map(Self::EcdsaP256)
                .map_err(|err| Error::InvalidKey(format!("invalid P-256 public key: {err}"))),
            EcdsaVariant::P384Sha384 => p384::ecdsa::VerifyingKey::from_sec1_bytes(raw)
                .map(Self::EcdsaP384)
                .map_err(|err| Error::InvalidKey(format!("invalid P-384 public key: {err}"))),
            EcdsaVariant::P521Sha512 => Err(p521_unsupported()),
        }
    }

    /// The key's algorithm tag.
    fn alg(&self) -> SigAlg {
        match self {
            Self::Ed25519(_) => SigAlg::Ed25519,
            Self::EcdsaP256(_) => SigAlg::P256,
            Self::EcdsaP384(_) => SigAlg::P384,
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
            Self::EcdsaP256(key) => key.to_encoded_point(false).as_bytes().to_vec(),
            Self::EcdsaP384(key) => key.to_encoded_point(false).as_bytes().to_vec(),
        }
    }

    /// One-shot verification of `sig` over `data`, failing closed with
    /// `authentication-failed` (the `verifying-key.verify` contract): the
    /// ECDSA signature format is fixed-width `r ‖ s` (IEEE P1363), and
    /// Ed25519 uses `verify_strict` semantics per the `ed25519-verify`
    /// criterion.
    pub fn verify(&self, data: &[u8], sig: &[u8]) -> Result<(), Error> {
        use p256::ecdsa::signature::Verifier as _;
        let ok = match self {
            Self::Ed25519(key) => ed25519_dalek::Signature::from_slice(sig)
                .and_then(|sig| key.verify_strict(data, &sig))
                .is_ok(),
            Self::EcdsaP256(key) => p256::ecdsa::Signature::from_slice(sig)
                .and_then(|sig| key.verify(data, &sig))
                .is_ok(),
            Self::EcdsaP384(key) => p384::ecdsa::Signature::from_slice(sig)
                .and_then(|sig| key.verify(data, &sig))
                .is_ok(),
        };
        if ok {
            Ok(())
        } else {
            Err(Error::AuthenticationFailed)
        }
    }
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
    EcdsaP256(p256::ecdsa::SigningKey),
    #[cfg(not(target_family = "wasm"))]
    EcdsaP384(p384::ecdsa::SigningKey),
}

impl SigPrivate {
    /// The key's algorithm tag.
    fn alg(&self) -> SigAlg {
        match self {
            Self::Ed25519(_) => SigAlg::Ed25519,
            #[cfg(not(target_family = "wasm"))]
            Self::EcdsaP256(_) => SigAlg::P256,
            #[cfg(not(target_family = "wasm"))]
            Self::EcdsaP384(_) => SigAlg::P384,
        }
    }
}

/// The material behind a `signature.signing-key` resource: the private key
/// bound to its algorithm at minting, and the key's extractability.
pub struct SigningKeyMaterial {
    private: SigPrivate,
    /// Whether `export-key` may return the private material.
    extractable: bool,
}

impl SigningKeyMaterial {
    /// Import a 32-byte RFC 8032 seed, rendering `invalid-key` for wrong
    /// lengths (the `ed25519-sign.import-signing-key` contract).
    pub fn import_ed25519_seed(raw: &[u8], extractable: bool) -> Result<Self, Error> {
        let seed: &[u8; 32] = raw.try_into().map_err(|_| {
            Error::InvalidKey(format!(
                "Ed25519 private keys are 32-byte seeds, got {} bytes",
                raw.len()
            ))
        })?;
        Ok(Self {
            private: SigPrivate::Ed25519(ed25519_dalek::SigningKey::from_bytes(seed)),
            extractable,
        })
    }

    /// Generate a fresh random Ed25519 signing key.
    pub fn generate_ed25519(extractable: bool) -> Result<Self, RngError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut())?;
        Ok(Self {
            private: SigPrivate::Ed25519(ed25519_dalek::SigningKey::from_bytes(&seed)),
            extractable,
        })
    }

    /// Import a raw big-endian scalar for the declared variant, rendering
    /// `invalid-key` for wrong lengths and out-of-range scalars (the
    /// `ecdsa-sign.import-signing-key` contract).
    #[cfg(not(target_family = "wasm"))]
    pub fn import_ecdsa_scalar(
        variant: EcdsaVariant,
        raw: &[u8],
        extractable: bool,
    ) -> Result<Self, Error> {
        let private = match variant {
            EcdsaVariant::P256Sha256 => p256::ecdsa::SigningKey::from_slice(raw)
                .map(SigPrivate::EcdsaP256)
                .map_err(|err| Error::InvalidKey(format!("invalid P-256 private key: {err}")))?,
            EcdsaVariant::P384Sha384 => p384::ecdsa::SigningKey::from_slice(raw)
                .map(SigPrivate::EcdsaP384)
                .map_err(|err| Error::InvalidKey(format!("invalid P-384 private key: {err}")))?,
            EcdsaVariant::P521Sha512 => return Err(p521_unsupported()),
        };
        Ok(Self {
            private,
            extractable,
        })
    }

    /// Generate a fresh random ECDSA signing key of the declared variant by
    /// rejection-sampling the scalar range with fresh randomness (the
    /// probability of a retry is negligible for these curves).
    #[cfg(not(target_family = "wasm"))]
    pub fn generate_ecdsa(
        variant: EcdsaVariant,
        extractable: bool,
    ) -> Result<Result<Self, Error>, RngError> {
        let scalar_len = match variant {
            EcdsaVariant::P256Sha256 => 32,
            EcdsaVariant::P384Sha384 => 48,
            EcdsaVariant::P521Sha512 => return Ok(Err(p521_unsupported())),
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
            if let Ok(key) = Self::import_ecdsa_scalar(variant, &raw, extractable) {
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
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        match &self.private {
            SigPrivate::Ed25519(key) => {
                use ed25519_dalek::Signer as _;
                key.sign(data).to_bytes().to_vec()
            }
            #[cfg(not(target_family = "wasm"))]
            SigPrivate::EcdsaP256(key) => {
                use p256::ecdsa::signature::Signer as _;
                let sig: p256::ecdsa::Signature = key.sign(data);
                sig.to_bytes().to_vec()
            }
            #[cfg(not(target_family = "wasm"))]
            SigPrivate::EcdsaP384(key) => {
                use p384::ecdsa::signature::Signer as _;
                let sig: p384::ecdsa::Signature = key.sign(data);
                sig.to_bytes().to_vec()
            }
        }
    }

    /// The corresponding [`SigPublic`]. There is no WIT derive contract —
    /// the package's `generate-key` functions return the pair instead —
    /// but this core holds the private material, so hosts use this to mint
    /// the public half at generation.
    pub fn public(&self) -> SigPublic {
        match &self.private {
            SigPrivate::Ed25519(key) => SigPublic::Ed25519(key.verifying_key()),
            #[cfg(not(target_family = "wasm"))]
            SigPrivate::EcdsaP256(key) => SigPublic::EcdsaP256(*key.verifying_key()),
            #[cfg(not(target_family = "wasm"))]
            SigPrivate::EcdsaP384(key) => SigPublic::EcdsaP384(*key.verifying_key()),
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

    /// Whether `export-key` may return the private material
    /// (`signing-key.extractable`).
    pub fn extractable(&self) -> bool {
        self.extractable
    }

    /// The private key material in the minting interface's documented form
    /// — the 32-byte RFC 8032 seed for Ed25519, the raw big-endian scalar
    /// for ECDSA — or `not-extractable` (the `signing-key.export-key`
    /// contract).
    ///
    /// The copy returned is *not* protected: see the note on
    /// [`crate`](crate#exported-material).
    pub fn export(&self) -> Result<Vec<u8>, Error> {
        if !self.extractable {
            return Err(Error::NotExtractable);
        }
        Ok(match &self.private {
            SigPrivate::Ed25519(key) => key.to_bytes().to_vec(),
            #[cfg(not(target_family = "wasm"))]
            SigPrivate::EcdsaP256(key) => key.to_bytes().to_vec(),
            #[cfg(not(target_family = "wasm"))]
            SigPrivate::EcdsaP384(key) => key.to_bytes().to_vec(),
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
            .field("extractable", &self.extractable)
            .field("private", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins seed import, public derivation, signing determinism (RFC 8032),
    /// verification, and seed-form export together.
    #[test]
    fn ed25519_sign_verify_round_trip() {
        let seed = [0x42u8; 32];
        let key = SigningKeyMaterial::import_ed25519_seed(&seed, true).unwrap();
        let sig = key.sign(b"message");
        assert_eq!(sig.len(), 64);
        assert_eq!(
            sig,
            key.sign(b"message"),
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
        match SigningKeyMaterial::import_ed25519_seed(&[0; 16], true) {
            Err(Error::InvalidKey(msg)) => {
                assert_eq!(msg, "Ed25519 private keys are 32-byte seeds, got 16 bytes")
            }
            _ => panic!("expected invalid-key"),
        }
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn ecdsa_sign_verify_round_trip() {
        for variant in [EcdsaVariant::P256Sha256, EcdsaVariant::P384Sha384] {
            let key = SigningKeyMaterial::generate_ecdsa(variant, false)
                .unwrap()
                .unwrap();
            assert_eq!(key.export(), Err(Error::NotExtractable));
            let sig = key.sign(b"message");
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
        let key = SigningKeyMaterial::import_ecdsa_scalar(EcdsaVariant::P256Sha256, &scalar, true)
            .unwrap();

        // Deterministic signature: exact r ‖ s reproduction.
        let expected = hex!(
            "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
            "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
        );
        assert_eq!(key.sign(b"sample"), expected);

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
        match SigningKeyMaterial::import_ecdsa_scalar(EcdsaVariant::P256Sha256, &[0; 32], true) {
            Err(Error::InvalidKey(_)) => {}
            _ => panic!("expected invalid-key for the zero scalar"),
        }
    }

    #[test]
    fn debug_redacts_private_material() {
        let key = SigningKeyMaterial::import_ed25519_seed(&[0xAB; 32], true).unwrap();
        let rendered = format!("{key:?}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(!rendered.contains("171"), "{rendered}"); // 0xAB
    }
}
