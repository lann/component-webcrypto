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
