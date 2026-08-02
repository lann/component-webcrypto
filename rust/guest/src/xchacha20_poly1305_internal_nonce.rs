//! `xchacha20-poly1305-internal-nonce` key creation — the recommended
//! internal-nonce algorithm.

use crate::{bindings, AeadInternalNonce, Error, InternalNonceKeyOptions};

/// Import 32 bytes of raw key material as an internal-nonce key.
pub async fn import_key_raw(
    raw: impl Into<Vec<u8>>,
    options: InternalNonceKeyOptions,
) -> Result<AeadInternalNonce, Error> {
    Ok(AeadInternalNonce::from_raw(
        bindings::xchacha20_poly1305_internal_nonce::import_key_raw(raw.into(), options.lower())
            .await?,
    ))
}

/// Generate a fresh random internal-nonce key.
pub async fn generate_key(options: InternalNonceKeyOptions) -> Result<AeadInternalNonce, Error> {
    Ok(AeadInternalNonce::from_raw(
        bindings::xchacha20_poly1305_internal_nonce::generate_key(options.lower()).await?,
    ))
}
