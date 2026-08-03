//! `ecdh` key creation (SP 800-56A ECDH over the NIST prime-order curves).
//!
//! Keys minted here drive [`AgreementSecretKey::agree`], whose result
//! chains into the KDFs (see
//! [`hkdf_sha2::prepare_from`](crate::hkdf_sha2::prepare_from)), exactly as
//! X25519's do. The shared secret is the x-coordinate of the agreed point,
//! so its natural length is the curve's field size: 32 bytes for P-256, 48
//! bytes for P-384. Unlike X25519's deliberately permissive raw import,
//! public imports are strict — a point not on the declared variant's curve
//! fails at import as [`Error::InvalidKey`](crate::Error::InvalidKey).
//!
//! [`AgreementSecretKey::agree`]: crate::AgreementSecretKey::agree

use crate::{bindings, AgreementKeyOptions, AgreementPublicKey, AgreementSecretKey, Error};

pub use crate::bindings::ecdh::EcdhVariant;

/// Import a peer's public key as an uncompressed SEC1 point (`04 ‖ x ‖ y`;
/// 65 bytes for P-256, 97 bytes for P-384).
pub async fn import_public_key_raw(
    variant: EcdhVariant,
    raw: impl Into<Vec<u8>>,
) -> Result<AgreementPublicKey, Error> {
    Ok(AgreementPublicKey::from_raw(
        bindings::ecdh::import_public_key_raw(variant, raw.into()).await?,
    ))
}

/// Import a peer's public key from an X.509 SubjectPublicKeyInfo (DER)
/// whose encoded curve matches the declared variant's.
pub async fn import_public_key_spki(
    variant: EcdhVariant,
    spki: impl Into<Vec<u8>>,
) -> Result<AgreementPublicKey, Error> {
    Ok(AgreementPublicKey::from_raw(
        bindings::ecdh::import_public_key_spki(variant, spki.into()).await?,
    ))
}

/// Import a peer's public key from an EC public JWK (as JSON text) whose
/// `crv` matches the declared variant's curve.
pub async fn import_public_key_jwk(
    variant: EcdhVariant,
    jwk: impl Into<String>,
) -> Result<AgreementPublicKey, Error> {
    Ok(AgreementPublicKey::from_raw(
        bindings::ecdh::import_public_key_jwk(variant, jwk.into()).await?,
    ))
}

/// Import a static secret key from a PKCS#8 PrivateKeyInfo (DER) whose
/// encoded curve matches the declared variant's.
pub async fn import_secret_key_pkcs8(
    variant: EcdhVariant,
    pkcs8: impl Into<Vec<u8>>,
    options: AgreementKeyOptions,
) -> Result<AgreementSecretKey, Error> {
    Ok(AgreementSecretKey::from_raw(
        bindings::ecdh::import_secret_key_pkcs8(variant, pkcs8.into(), options.lower()).await?,
    ))
}

/// Import a static secret key from an EC private JWK (as JSON text) whose
/// `crv` matches the declared variant's curve.
pub async fn import_secret_key_jwk(
    variant: EcdhVariant,
    jwk: impl Into<String>,
    options: AgreementKeyOptions,
) -> Result<AgreementSecretKey, Error> {
    Ok(AgreementSecretKey::from_raw(
        bindings::ecdh::import_secret_key_jwk(variant, jwk.into(), options.lower()).await?,
    ))
}

/// Generate a fresh random keypair on the declared variant's curve,
/// returning both halves.
pub async fn generate_key(
    variant: EcdhVariant,
    options: AgreementKeyOptions,
) -> Result<(AgreementSecretKey, AgreementPublicKey), Error> {
    let (secret, public) = bindings::ecdh::generate_key(variant, options.lower()).await?;
    Ok((
        AgreementSecretKey::from_raw(secret),
        AgreementPublicKey::from_raw(public),
    ))
}
