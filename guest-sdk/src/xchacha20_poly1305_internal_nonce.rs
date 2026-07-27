//! `xchacha20-poly1305-internal-nonce` key creation — the recommended
//! internal-nonce algorithm.

use crate::{bindings, AeadInternalNonce, Error};

/// Import 32 bytes of raw key material as an internal-nonce key.
pub async fn import_key(
    raw_material: Vec<u8>,
    extractable: bool,
) -> Result<AeadInternalNonce, Error> {
    Ok(AeadInternalNonce::from_raw(
        bindings::xchacha20_poly1305_internal_nonce::import_key(raw_material, extractable).await?,
    ))
}

/// Generate a fresh random internal-nonce key.
pub async fn generate_key(extractable: bool) -> Result<AeadInternalNonce, Error> {
    Ok(AeadInternalNonce::from_raw(
        bindings::xchacha20_poly1305_internal_nonce::generate_key(extractable).await?,
    ))
}
