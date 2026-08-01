//! The [`HpkeCrypto`] provider backed by `lann:webcrypto` imports.
//!
//! hpke-rs's provider trait is synchronous and byte-oriented; the
//! `lann:webcrypto` imports are async and handle-oriented. Every provider
//! method therefore runs its import calls under [`wit_bindgen::block_on`],
//! which is legal only because this component's exports are sync-lifted
//! (a sync task may block on `waitable-set.wait`).
//!
//! Mappings the package surface forces (see the experiment README for the
//! full findings list):
//!
//! - `kdf_extract`/`kdf_expand` map to `hmac-sha2`, not to the `hkdf-*`
//!   interfaces: HPKE's labeled KDF concatenates a prefix onto the secret
//!   IKM and consumes raw PRKs, neither of which the handle-oriented HKDF
//!   surface can express. Extract is one HMAC; expand is the RFC 5869
//!   `T(i)` loop.
//! - `secret_to_public` maps to DH with the X25519 base point:
//!   `X25519(sk, 9)` *is* the public key, so the package's deliberate
//!   absence of a secret→public derivation costs nothing here.
//! - Raw secret scalars have no import format by design; they enter as
//!   PKCS#8 by prepending the fixed RFC 8410 DER prefix.
//! - The package has no random-bytes interface (yet); the PRNG harvests
//!   host entropy by hashing freshly generated, exported X25519 keys.

use hpke_rs_crypto::error::Error;
use hpke_rs_crypto::types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs_crypto::{HpkeCrypto, HpkeTestRng};
use lann_webcrypto_guest::aes_gcm::AesVariant;
use lann_webcrypto_guest::bindings::key_agreement::AgreementKeyOptions;
use lann_webcrypto_guest::bindings::sha2::Sha2Variant;
use lann_webcrypto_guest::bindings::x25519;
use lann_webcrypto_guest::{
    aes_gcm, chacha20_poly1305, hmac_sha2, sha2, Aead, AeadKeyOptions, MacKeyOptions,
};
use wit_bindgen::block_on;
use zeroize::Zeroize;

/// SHA-256's output length in bytes (the only KDF hash this provider
/// serves: the experiment's suites all use HKDF-SHA-256).
const HASH_LEN: usize = 32;

/// The RFC 8410 PKCS#8 `PrivateKeyInfo` prefix for an X25519 key: a
/// 32-byte scalar follows it. `x25519.import-secret-key-pkcs8` is the
/// package's only non-JWK door for a bare scalar.
const PKCS8_X25519_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
];

/// The X25519 base point (u = 9): `X25519(sk, 9)` is `sk`'s public key.
const X25519_BASE_POINT: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

fn pkcs8_from_scalar(sk: &[u8]) -> Vec<u8> {
    let mut der = Vec::with_capacity(PKCS8_X25519_PREFIX.len() + sk.len());
    der.extend_from_slice(&PKCS8_X25519_PREFIX);
    der.extend_from_slice(sk);
    der
}

fn scalar_from_pkcs8(der: &[u8]) -> Result<Vec<u8>, Error> {
    if der.len() == PKCS8_X25519_PREFIX.len() + 32 && der[..16] == PKCS8_X25519_PREFIX {
        Ok(der[16..].to_vec())
    } else {
        Err(Error::CryptoLibraryError(format!(
            "unexpected PKCS#8 shape ({} bytes) from export-key-pkcs8",
            der.len()
        )))
    }
}

/// Full-grant agreement key options: the provider immediately extracts
/// every shared secret as bits (hpke-rs's trait traffics in bytes), so
/// both derive grants are always needed.
fn agreement_options(extractable: bool) -> AgreementKeyOptions {
    let options = AgreementKeyOptions::new();
    options.can_derive_bits(true);
    options.can_derive_key(true);
    options.extractable(extractable);
    options
}

fn crypto_err(context: &str, err: impl std::fmt::Display) -> Error {
    Error::CryptoLibraryError(format!("{context}: {err}"))
}

fn require_x25519(alg: KemAlgorithm) -> Result<(), Error> {
    if alg == KemAlgorithm::DhKem25519 {
        Ok(())
    } else {
        Err(Error::UnknownKemAlgorithm)
    }
}

fn require_hkdf_sha256(alg: KdfAlgorithm) -> Result<(), Error> {
    if alg == KdfAlgorithm::HkdfSha256 {
        Ok(())
    } else {
        Err(Error::UnknownKdfAlgorithm)
    }
}

/// The HMAC key standing in for an HKDF salt. HMAC pads keys shorter than
/// the block size with zeros, so every all-zero salt (hpke-rs uses both
/// `[]` and `[0]`) is equivalent to 32 zero bytes — which, unlike the
/// empty string, `hmac-sha2.import-key-raw` accepts.
fn hmac_key_for_salt(salt: &[u8]) -> Vec<u8> {
    if salt.iter().all(|&b| b == 0) {
        vec![0u8; HASH_LEN]
    } else {
        salt.to_vec()
    }
}

async fn hmac_sha256_key(key: Vec<u8>) -> Result<lann_webcrypto_guest::Mac, Error> {
    hmac_sha2::import_key_raw(
        Sha2Variant::Sha256,
        key,
        MacKeyOptions {
            sign: true,
            verify: false,
            extractable: false,
        },
    )
    .await
    .map_err(|e| crypto_err("hmac import", e))
}

async fn aead_key(alg: AeadAlgorithm, key: &[u8]) -> Result<Aead, Error> {
    let options = AeadKeyOptions {
        seal: true,
        open: true,
        ..Default::default()
    };
    let key = key.to_vec();
    match alg {
        AeadAlgorithm::Aes128Gcm => aes_gcm::import_key_raw(AesVariant::Aes128, key, options).await,
        AeadAlgorithm::Aes256Gcm => aes_gcm::import_key_raw(AesVariant::Aes256, key, options).await,
        AeadAlgorithm::ChaCha20Poly1305 => chacha20_poly1305::import_key_raw(key, options).await,
        AeadAlgorithm::HpkeExport => return Err(Error::UnknownAeadAlgorithm),
    }
    .map_err(|e| crypto_err("aead key import", e))
}

/// Fill `dest` with host-derived entropy: hash (SHA-256, host-side) the
/// PKCS#8 export of a freshly generated X25519 key per 32-byte block. The
/// hash removes the scalar's clamping bias; each block draws a fresh key.
/// This stands in for the random-bytes interface the package does not have
/// yet; it panics (traps) on failure, since the RNG traits are infallible.
fn host_entropy(dest: &mut [u8]) {
    for chunk in dest.chunks_mut(HASH_LEN) {
        let block: Vec<u8> = block_on(async {
            let (secret, _public) = x25519::generate_key(agreement_options(true))
                .await
                .map_err(|e| crypto_err("entropy generate-key", format!("{e:?}")))?;
            let pkcs8 = secret
                .export_key_pkcs8()
                .await
                .map_err(|e| crypto_err("entropy export", format!("{e:?}")))?;
            let digest = sha2::make_digest(Sha2Variant::Sha256)
                .map_err(|e| crypto_err("entropy hash", e))?;
            digest
                .compute(&pkcs8[..])
                .await
                .map_err(|e| crypto_err("entropy hash", e))
        })
        .expect("host entropy harvest failed");
        chunk.copy_from_slice(&block[..chunk.len()]);
    }
}

/// The provider PRNG: host entropy for real randomness, plus the seeded
/// buffer `HpkeTestRng` requires (drained first), which is what makes the
/// RFC 9180 known-answer tests' deterministic encapsulation reachable.
#[derive(Debug, Default, Zeroize)]
pub struct WebcryptoPrng {
    test_bytes: Vec<u8>,
}

impl rand::TryRng for WebcryptoPrng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        host_entropy(dst);
        Ok(())
    }
}

impl rand::TryCryptoRng for WebcryptoPrng {}

impl HpkeTestRng for WebcryptoPrng {
    type Error = core::convert::Infallible;

    fn try_fill_test_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        if self.test_bytes.len() >= dest.len() {
            // Drain seeded bytes from the front, like a test vector reader.
            let remaining = self.test_bytes.split_off(dest.len());
            dest.copy_from_slice(&self.test_bytes);
            self.test_bytes.zeroize();
            self.test_bytes = remaining;
            Ok(())
        } else {
            // Unseeded (or exhausted): fall back to real entropy so
            // ordinary operation works with the test feature compiled in.
            host_entropy(dest);
            Ok(())
        }
    }

    fn seed(&mut self, seed: &[u8]) {
        self.test_bytes = seed.to_vec();
    }
}

/// The `lann:webcrypto`-backed crypto provider for [`hpke_rs::Hpke`].
#[derive(Debug)]
pub struct WebcryptoProvider;

impl HpkeCrypto for WebcryptoProvider {
    type HpkePrng = WebcryptoPrng;

    fn name() -> String {
        "lann-webcrypto".into()
    }

    fn supports_kdf(alg: KdfAlgorithm) -> Result<(), Error> {
        require_hkdf_sha256(alg)
    }

    fn supports_kem(alg: KemAlgorithm) -> Result<(), Error> {
        require_x25519(alg)
    }

    fn supports_aead(alg: AeadAlgorithm) -> Result<(), Error> {
        match alg {
            AeadAlgorithm::Aes128Gcm
            | AeadAlgorithm::Aes256Gcm
            | AeadAlgorithm::ChaCha20Poly1305 => Ok(()),
            AeadAlgorithm::HpkeExport => Err(Error::UnknownAeadAlgorithm),
        }
    }

    fn prng() -> Self::HpkePrng {
        WebcryptoPrng::default()
    }

    /// HKDF-Extract (RFC 5869): one HMAC keyed by the salt.
    fn kdf_extract(alg: KdfAlgorithm, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, Error> {
        require_hkdf_sha256(alg)?;
        block_on(async {
            let mac = hmac_sha256_key(hmac_key_for_salt(salt)).await?;
            mac.sign(ikm).await.map_err(|e| crypto_err("hmac sign", e))
        })
    }

    /// HKDF-Expand (RFC 5869): the `T(i) = HMAC(prk, T(i-1) ‖ info ‖ i)`
    /// loop, keyed once by the PRK.
    fn kdf_expand(
        alg: KdfAlgorithm,
        prk: &[u8],
        info: &[u8],
        output_size: usize,
    ) -> Result<Vec<u8>, Error> {
        require_hkdf_sha256(alg)?;
        if output_size > 255 * HASH_LEN {
            return Err(Error::HpkeInvalidOutputLength);
        }
        block_on(async {
            let mac = hmac_sha256_key(prk.to_vec()).await?;
            let mut out = Vec::with_capacity(output_size);
            let mut t: Vec<u8> = Vec::new();
            let mut counter: u8 = 1;
            while out.len() < output_size {
                let mut block = t;
                block.extend_from_slice(info);
                block.push(counter);
                t = mac
                    .sign(&block[..])
                    .await
                    .map_err(|e| crypto_err("hmac sign", e))?;
                out.extend_from_slice(&t);
                counter = counter.wrapping_add(1);
            }
            out.truncate(output_size);
            Ok(out)
        })
    }

    /// X25519: import the scalar (PKCS#8-wrapped) and the peer point,
    /// `agree`, and extract the shared secret at its natural length.
    fn dh(alg: KemAlgorithm, pk: &[u8], sk: &[u8]) -> Result<Vec<u8>, Error> {
        require_x25519(alg)?;
        if sk.len() != 32 {
            return Err(Error::KemInvalidSecretKey);
        }
        block_on(async {
            let secret =
                x25519::import_secret_key_pkcs8(pkcs8_from_scalar(sk), agreement_options(false))
                    .await
                    .map_err(|_| Error::KemInvalidSecretKey)?;
            let peer = x25519::import_public_key_raw(pk.to_vec())
                .await
                .map_err(|_| Error::KemInvalidPublicKey)?;
            let shared = secret
                .agree(&peer)
                .await
                .map_err(|e| crypto_err("agree", format!("{e:?}")))?;
            shared
                .derive_bits(None)
                .await
                .map_err(|e| crypto_err("derive-bits", format!("{e:?}")))
        })
    }

    fn secret_to_public(alg: KemAlgorithm, sk: &[u8]) -> Result<Vec<u8>, Error> {
        Self::dh(alg, &X25519_BASE_POINT, sk)
    }

    fn kem_key_gen(
        alg: KemAlgorithm,
        _prng: &mut Self::HpkePrng,
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        require_x25519(alg)?;
        block_on(async {
            let (secret, public) = x25519::generate_key(agreement_options(true))
                .await
                .map_err(|e| crypto_err("generate-key", format!("{e:?}")))?;
            let pkcs8 = secret
                .export_key_pkcs8()
                .await
                .map_err(|e| crypto_err("export-key-pkcs8", format!("{e:?}")))?;
            let sk = scalar_from_pkcs8(&pkcs8)?;
            let pk = public
                .export_key_raw()
                .await
                .map_err(|e| crypto_err("export-key-raw", format!("{e:?}")))?;
            Ok((pk, sk))
        })
    }

    fn kem_key_gen_derand(alg: KemAlgorithm, _seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
        // Only the seed-keyed KEMs (X-Wing, ML-KEM) reach this; DHKEM key
        // derivation goes through kdf_* + secret_to_public.
        require_x25519(alg)?;
        Err(Error::UnsupportedKemOperation)
    }

    fn kem_encaps(
        alg: KemAlgorithm,
        _pk_r: &[u8],
        _prng: &mut Self::HpkePrng,
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        // DHKEM encapsulation is composed by hpke-rs from dh/kdf_*; only
        // the seed-keyed KEMs call this.
        require_x25519(alg)?;
        Err(Error::UnsupportedKemOperation)
    }

    fn kem_decaps(alg: KemAlgorithm, _ct: &[u8], _sk_r: &[u8]) -> Result<Vec<u8>, Error> {
        require_x25519(alg)?;
        Err(Error::UnsupportedKemOperation)
    }

    fn dh_validate_sk(alg: KemAlgorithm, sk: &[u8]) -> Result<Vec<u8>, Error> {
        require_x25519(alg)?;
        // Any 32-byte string is a valid X25519 scalar (clamped at use).
        if sk.len() == 32 {
            Ok(sk.to_vec())
        } else {
            Err(Error::KemInvalidSecretKey)
        }
    }

    fn aead_seal(
        alg: AeadAlgorithm,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        msg: &[u8],
    ) -> Result<Vec<u8>, Error> {
        block_on(async {
            let key = aead_key(alg, key).await?;
            key.seal(nonce, aad, msg)
                .await
                .map_err(|e| crypto_err("seal", e))
        })
    }

    fn aead_open(
        alg: AeadAlgorithm,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        msg: &[u8],
    ) -> Result<Vec<u8>, Error> {
        block_on(async {
            let key = aead_key(alg, key).await?;
            let opened = key.open(nonce, aad, msg).await.map_err(|e| match e {
                lann_webcrypto_guest::Error::AuthenticationFailed => Error::AeadOpenError,
                lann_webcrypto_guest::Error::InvalidNonce(detail) => {
                    Error::CryptoLibraryError(format!("invalid nonce: {detail}"))
                }
                other => crypto_err("open", other),
            })?;
            Ok(opened.collect().await)
        })
    }
}
