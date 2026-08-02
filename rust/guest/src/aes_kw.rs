//! `aes-kw` key creation (RFC 3394 / NIST SP 800-38F KW): dedicated
//! key-wrapping keys for the `key-wrap` kind.

use crate::{bindings, Error, KwKey, KwKeyOptions, UnwrapInput};

pub use crate::bindings::aes_kw::AesVariant;

/// Import raw key material as the declared AES variant.
pub async fn import_key_raw(
    variant: AesVariant,
    raw: impl Into<Vec<u8>>,
    options: KwKeyOptions,
) -> Result<KwKey, Error> {
    Ok(KwKey::from_raw(
        bindings::aes_kw::import_key_raw(variant, raw.into(), options.lower()).await?,
    ))
}

/// Import an RFC 7517 `oct` JSON Web Key (as JSON text; `alg`, when
/// present, must name the declared variant) as an AES-KW key.
pub async fn import_key_jwk(
    variant: AesVariant,
    jwk: impl Into<String>,
    options: KwKeyOptions,
) -> Result<KwKey, Error> {
    Ok(KwKey::from_raw(
        bindings::aes_kw::import_key_jwk(variant, jwk.into(), options.lower()).await?,
    ))
}

/// Generate a fresh random key of the declared AES variant.
pub async fn generate_key(variant: AesVariant, options: KwKeyOptions) -> Result<KwKey, Error> {
    Ok(KwKey::from_raw(
        bindings::aes_kw::generate_key(variant, options.lower()).await?,
    ))
}

/// Mint an AES-KW key of the declared variant from a parameterized
/// derivation (the `aes-gcm.derive-key` contract, minting a `kw-key`).
pub async fn derive_key(
    variant: AesVariant,
    input: &crate::DeriveInput,
    options: KwKeyOptions,
) -> Result<KwKey, Error> {
    Ok(KwKey::from_raw(
        bindings::aes_kw::derive_key(variant, input.as_raw(), options.lower()).await?,
    ))
}

/// Mint an AES-KW key from unwrapped key material read as raw bytes.
/// Consumes the [`UnwrapInput`].
pub async fn unwrap_key_raw(
    variant: AesVariant,
    input: UnwrapInput,
    options: KwKeyOptions,
) -> Result<KwKey, Error> {
    Ok(KwKey::from_raw(
        bindings::aes_kw::unwrap_key_raw(variant, input.into_raw(), options.lower()).await?,
    ))
}

/// Mint an AES-KW key from unwrapped key material read as an `oct` JWK.
/// Consumes the [`UnwrapInput`].
pub async fn unwrap_key_jwk(
    variant: AesVariant,
    input: UnwrapInput,
    options: KwKeyOptions,
) -> Result<KwKey, Error> {
    Ok(KwKey::from_raw(
        bindings::aes_kw::unwrap_key_jwk(variant, input.into_raw(), options.lower()).await?,
    ))
}
