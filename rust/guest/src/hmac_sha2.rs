//! `hmac-sha2` key creation.

use crate::{bindings, Error, Mac, MacKeyOptions};

pub use crate::bindings::sha2::Sha2Variant;

/// Import raw key material as an HMAC key over `variant`.
pub async fn import_key_raw(
    variant: Sha2Variant,
    raw: impl Into<Vec<u8>>,
    options: MacKeyOptions,
) -> Result<Mac, Error> {
    Ok(Mac::from_raw(
        bindings::hmac_sha2::import_key_raw(variant, raw.into(), options.lower()).await?,
    ))
}

/// Import an RFC 7517 `oct` JSON Web Key (as JSON text) as an HMAC key
/// over `variant`. See the WIT `mac-key.export-key-jwk` doc for the
/// package-wide JWK contract.
pub async fn import_key_jwk(
    variant: Sha2Variant,
    jwk: impl Into<String>,
    options: MacKeyOptions,
) -> Result<Mac, Error> {
    Ok(Mac::from_raw(
        bindings::hmac_sha2::import_key_jwk(variant, jwk.into(), options.lower()).await?,
    ))
}

/// Generate a fresh random HMAC key over `variant`.
///
/// `length` is the key length in bits; `None` means the underlying hash's
/// block size (WebCrypto's `generateKey` default).
pub async fn generate_key(
    variant: Sha2Variant,
    length: Option<u32>,
    options: MacKeyOptions,
) -> Result<Mac, Error> {
    Ok(Mac::from_raw(
        bindings::hmac_sha2::generate_key(variant, length, options.lower()).await?,
    ))
}

/// Mint an HMAC key over `variant` from a parameterized derivation: the
/// derivation runs at `length` bits (`None` means the hash's block size,
/// the `generate_key` default) and the result is subject to
/// [`import_key_raw`]'s contract.
///
/// Requires the input's [`derive_key`](crate::DeriveOptions::derive_key)
/// grant — and, for an *extractable* key, [`derive_bits`] too (an
/// exportable key is bits disclosure by other means); refusals fail
/// [`Error::NotPermitted`].
///
/// [`derive_bits`]: crate::DeriveOptions::derive_bits
pub async fn derive_key(
    variant: Sha2Variant,
    input: &crate::DeriveInput,
    length: Option<u32>,
    options: MacKeyOptions,
) -> Result<Mac, Error> {
    Ok(Mac::from_raw(
        bindings::hmac_sha2::derive_key(variant, input.as_raw(), length, options.lower()).await?,
    ))
}

/// Mint an HMAC key over the declared SHA-2 variant from unwrapped key
/// material read as raw bytes. Consumes the
/// [`UnwrapInput`](crate::UnwrapInput).
pub async fn unwrap_key_raw(
    variant: Sha2Variant,
    input: crate::UnwrapInput,
    options: MacKeyOptions,
) -> Result<Mac, Error> {
    Ok(Mac::from_raw(
        bindings::hmac_sha2::unwrap_key_raw(variant, input.into_raw(), options.lower()).await?,
    ))
}

/// Mint an HMAC key from unwrapped key material read as an `oct` JWK,
/// with the unwrap-path `use`/`key_ops` checks. Consumes the
/// [`UnwrapInput`](crate::UnwrapInput).
pub async fn unwrap_key_jwk(
    variant: Sha2Variant,
    input: crate::UnwrapInput,
    options: MacKeyOptions,
) -> Result<Mac, Error> {
    Ok(Mac::from_raw(
        bindings::hmac_sha2::unwrap_key_jwk(variant, input.into_raw(), options.lower()).await?,
    ))
}
