//! `x25519` key creation (RFC 7748 §5, the X25519 function).
//!
//! Keys minted here drive [`AgreementSecretKey::agree`], whose result
//! chains into the KDFs (see
//! [`hkdf_sha2::prepare_from`](crate::hkdf_sha2::prepare_from)). Peer
//! imports are deliberately permissive — a degenerate (small-order) peer
//! surfaces at `agree`, the operation that computes the secret, as
//! [`Error::InvalidKey`](crate::Error::InvalidKey).
//!
//! [`AgreementSecretKey::agree`]: crate::AgreementSecretKey::agree

use crate::{bindings, AgreementKeyOptions, AgreementPublicKey, AgreementSecretKey, Error};

/// Import a peer's raw 32-byte public key (RFC 7748's little-endian
/// u-coordinate).
pub async fn import_public_key_raw(raw: impl Into<Vec<u8>>) -> Result<AgreementPublicKey, Error> {
    Ok(AgreementPublicKey::from_raw(
        bindings::x25519::import_public_key_raw(raw.into()).await?,
    ))
}

/// Import a peer's public key from an X.509 SubjectPublicKeyInfo (DER).
pub async fn import_public_key_spki(spki: impl Into<Vec<u8>>) -> Result<AgreementPublicKey, Error> {
    Ok(AgreementPublicKey::from_raw(
        bindings::x25519::import_public_key_spki(spki.into()).await?,
    ))
}

/// Import a peer's public key from an RFC 8037 OKP JWK (as JSON text).
pub async fn import_public_key_jwk(jwk: impl Into<String>) -> Result<AgreementPublicKey, Error> {
    Ok(AgreementPublicKey::from_raw(
        bindings::x25519::import_public_key_jwk(jwk.into()).await?,
    ))
}

/// Import a secret key from a PKCS#8 PrivateKeyInfo (DER).
pub async fn import_secret_key_pkcs8(
    pkcs8: impl Into<Vec<u8>>,
    options: AgreementKeyOptions,
) -> Result<AgreementSecretKey, Error> {
    Ok(AgreementSecretKey::from_raw(
        bindings::x25519::import_secret_key_pkcs8(pkcs8.into(), options.lower()).await?,
    ))
}

/// Import a secret key from an RFC 8037 OKP private JWK (as JSON text).
pub async fn import_secret_key_jwk(
    jwk: impl Into<String>,
    options: AgreementKeyOptions,
) -> Result<AgreementSecretKey, Error> {
    Ok(AgreementSecretKey::from_raw(
        bindings::x25519::import_secret_key_jwk(jwk.into(), options.lower()).await?,
    ))
}

/// Generate a fresh random keypair, returning both halves.
pub async fn generate_key(
    options: AgreementKeyOptions,
) -> Result<(AgreementSecretKey, AgreementPublicKey), Error> {
    let (secret, public) = bindings::x25519::generate_key(options.lower()).await?;
    Ok((
        AgreementSecretKey::from_raw(secret),
        AgreementPublicKey::from_raw(public),
    ))
}
