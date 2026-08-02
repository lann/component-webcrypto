//! `chacha20-poly1305` key creation (IETF construction, caller-nonce; see
//! [`Aead`]'s nonce warning).

use crate::{bindings, Aead, AeadKeyOptions, Error};

/// Import 32 bytes of raw key material.
pub async fn import_key_raw(
    raw: impl Into<Vec<u8>>,
    options: AeadKeyOptions,
) -> Result<Aead, Error> {
    Ok(Aead::from_raw(
        bindings::chacha20_poly1305::import_key_raw(raw.into(), options.lower()).await?,
    ))
}

/// Import an RFC 7517 `oct` JSON Web Key (as JSON text). `alg`, when
/// present, must be the W3C Modern Algorithms proposal's registered
/// `"C20P"`; any other value fails [`Error::InvalidKey`]. See the WIT
/// `mac-key.export-key-jwk` doc for the package-wide JWK contract.
pub async fn import_key_jwk(
    jwk: impl Into<String>,
    options: AeadKeyOptions,
) -> Result<Aead, Error> {
    Ok(Aead::from_raw(
        bindings::chacha20_poly1305::import_key_jwk(jwk.into(), options.lower()).await?,
    ))
}

/// Generate a fresh random 256-bit key.
pub async fn generate_key(options: AeadKeyOptions) -> Result<Aead, Error> {
    Ok(Aead::from_raw(
        bindings::chacha20_poly1305::generate_key(options.lower()).await?,
    ))
}
