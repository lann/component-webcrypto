//! `hmac-sha1` key creation: HMAC over SHA-1, for interoperability with
//! SHA-1-committed constructions (TOTP, WPA2). HMAC's security rests on
//! the PRF property, which SHA-1's collision breaks do not reach; prefer
//! [`hmac_sha2`](crate::hmac_sha2) in new designs.

use crate::{bindings, Error, Mac, MacKeyOptions};

/// Import raw key material as an HMAC-SHA-1 key.
pub async fn import_key_raw(raw: impl Into<Vec<u8>>, options: MacKeyOptions) -> Result<Mac, Error> {
    Ok(Mac::from_raw(
        bindings::hmac_sha1::import_key_raw(raw.into(), options.lower()).await?,
    ))
}

/// Import an RFC 7517 `oct` JSON Web Key (as JSON text; `alg` `"HS1"`) as
/// an HMAC-SHA-1 key.
pub async fn import_key_jwk(jwk: impl Into<String>, options: MacKeyOptions) -> Result<Mac, Error> {
    Ok(Mac::from_raw(
        bindings::hmac_sha1::import_key_jwk(jwk.into(), options.lower()).await?,
    ))
}

/// Generate a fresh random HMAC-SHA-1 key. `length` is the key length in
/// bits; `None` means SHA-1's block size, 512 bits.
pub async fn generate_key(length: Option<u32>, options: MacKeyOptions) -> Result<Mac, Error> {
    Ok(Mac::from_raw(
        bindings::hmac_sha1::generate_key(length, options.lower()).await?,
    ))
}

/// Mint an HMAC-SHA-1 key from a parameterized derivation. See
/// [`hmac_sha2::derive_key`](crate::hmac_sha2::derive_key) for the
/// `length` and grant contracts.
pub async fn derive_key(
    input: &crate::DeriveInput,
    length: Option<u32>,
    options: MacKeyOptions,
) -> Result<Mac, Error> {
    Ok(Mac::from_raw(
        bindings::hmac_sha1::derive_key(input.as_raw(), length, options.lower()).await?,
    ))
}
