//! `aes-gcm` key creation (caller-nonce — see [`Aead`]'s nonce warning).

use crate::{bindings, Aead, AeadKeyOptions, Error};

pub use crate::bindings::aes_gcm::AesVariant;

/// Import raw key material as the declared AES variant.
pub async fn import_key_raw(
    variant: AesVariant,
    raw: impl Into<Vec<u8>>,
    options: AeadKeyOptions,
) -> Result<Aead, Error> {
    Ok(Aead::from_raw(
        bindings::aes_gcm::import_key_raw(variant, raw.into(), options.lower()).await?,
    ))
}

/// Import an RFC 7517 `oct` JSON Web Key (as JSON text) as an AES-GCM key
/// of the declared variant. See the WIT `mac-key.export-key-jwk` doc for
/// the package-wide JWK contract.
pub async fn import_key_jwk(
    variant: AesVariant,
    jwk: impl Into<String>,
    options: AeadKeyOptions,
) -> Result<Aead, Error> {
    Ok(Aead::from_raw(
        bindings::aes_gcm::import_key_jwk(variant, jwk.into(), options.lower()).await?,
    ))
}

/// Generate a fresh random key of the declared AES variant.
pub async fn generate_key(variant: AesVariant, options: AeadKeyOptions) -> Result<Aead, Error> {
    Ok(Aead::from_raw(
        bindings::aes_gcm::generate_key(variant, options.lower()).await?,
    ))
}

/// Mint an AES-GCM key of the declared variant from a parameterized
/// derivation: the derivation runs at the variant's key length and the
/// result is subject to [`import_key_raw`]'s contract.
///
/// Requires the input's [`derive_key`](crate::DeriveOptions::derive_key)
/// grant — and, for an *extractable* key,
/// [`derive_bits`](crate::DeriveOptions::derive_bits) too; refusals fail
/// [`Error::NotPermitted`].
pub async fn derive_key(
    variant: AesVariant,
    input: &crate::DeriveInput,
    options: AeadKeyOptions,
) -> Result<Aead, Error> {
    Ok(Aead::from_raw(
        bindings::aes_gcm::derive_key(variant, input.as_raw(), options.lower()).await?,
    ))
}

/// Mint an AES-GCM key of the declared variant from unwrapped key
/// material read as raw bytes, subject to [`import_key_raw`]'s contract.
/// Consumes the [`UnwrapInput`](crate::UnwrapInput).
pub async fn unwrap_key_raw(
    variant: AesVariant,
    input: crate::UnwrapInput,
    options: AeadKeyOptions,
) -> Result<Aead, Error> {
    Ok(Aead::from_raw(
        bindings::aes_gcm::unwrap_key_raw(variant, input.into_raw(), options.lower()).await?,
    ))
}

/// Mint an AES-GCM key from unwrapped key material read as an `oct` JWK,
/// subject to [`import_key_jwk`]'s contract plus the unwrap-path
/// `use`/`key_ops` checks. Consumes the [`UnwrapInput`](crate::UnwrapInput).
pub async fn unwrap_key_jwk(
    variant: AesVariant,
    input: crate::UnwrapInput,
    options: AeadKeyOptions,
) -> Result<Aead, Error> {
    Ok(Aead::from_raw(
        bindings::aes_gcm::unwrap_key_jwk(variant, input.into_raw(), options.lower()).await?,
    ))
}
