//! `aes-cbc` key creation (the unauthenticated AES-CBC mode; prefer
//! [`aes_gcm`](crate::aes_gcm) — see [`CipherKey`]'s warning).

use crate::{bindings, CipherKey, CipherKeyOptions, Error};

pub use crate::bindings::aes_cbc::AesVariant;

/// Import raw key material as the declared AES variant.
pub async fn import_key_raw(
    variant: AesVariant,
    raw: impl Into<Vec<u8>>,
    options: CipherKeyOptions,
) -> Result<CipherKey, Error> {
    Ok(CipherKey::from_raw(
        bindings::aes_cbc::import_key_raw(variant, raw.into(), options.lower()).await?,
    ))
}

/// Import an RFC 7517 `oct` JSON Web Key (as JSON text) as a AES-CBC key
/// of the declared variant. See the WIT `mac-key.export-key-jwk` doc for
/// the package-wide JWK contract.
pub async fn import_key_jwk(
    variant: AesVariant,
    jwk: impl Into<String>,
    options: CipherKeyOptions,
) -> Result<CipherKey, Error> {
    Ok(CipherKey::from_raw(
        bindings::aes_cbc::import_key_jwk(variant, jwk.into(), options.lower()).await?,
    ))
}

/// Generate a fresh random key of the declared AES variant.
pub async fn generate_key(
    variant: AesVariant,
    options: CipherKeyOptions,
) -> Result<CipherKey, Error> {
    Ok(CipherKey::from_raw(
        bindings::aes_cbc::generate_key(variant, options.lower()).await?,
    ))
}

/// Mint an AES-CBC key of the declared variant from a parameterized
/// derivation. See [`aes_gcm::derive_key`](crate::aes_gcm::derive_key)
/// for the grant contracts.
pub async fn derive_key(
    variant: AesVariant,
    input: &crate::DeriveInput,
    options: CipherKeyOptions,
) -> Result<CipherKey, Error> {
    Ok(CipherKey::from_raw(
        bindings::aes_cbc::derive_key(variant, input.as_raw(), options.lower()).await?,
    ))
}
