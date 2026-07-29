//! `hmac-sha2` key creation.

use crate::{bindings, Error, Mac};

pub use crate::bindings::sha2::Sha2Variant;

/// Import raw key material as an HMAC key over `variant`.
pub async fn import_key(
    variant: Sha2Variant,
    raw_material: Vec<u8>,
    extractable: bool,
) -> Result<Mac, Error> {
    Ok(Mac::from_raw(
        bindings::hmac_sha2::import_key(variant, raw_material, extractable).await?,
    ))
}

/// Generate a fresh random HMAC key over `variant`.
///
/// `length` is the key length in bits; `None` means the underlying hash's
/// block size (WebCrypto's `generateKey` default).
pub async fn generate_key(
    variant: Sha2Variant,
    length: Option<u32>,
    extractable: bool,
) -> Result<Mac, Error> {
    Ok(Mac::from_raw(
        bindings::hmac_sha2::generate_key(variant, length, extractable).await?,
    ))
}
