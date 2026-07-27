//! `aes-gcm-internal-nonce` key creation.

use crate::{bindings, AeadInternalNonce, Error};

pub use crate::bindings::aes_gcm::AesVariant;

/// Import raw key material as an internal-nonce AES-GCM key.
pub async fn import_key(
    variant: AesVariant,
    raw_material: Vec<u8>,
    extractable: bool,
) -> Result<AeadInternalNonce, Error> {
    Ok(AeadInternalNonce::from_raw(
        bindings::aes_gcm_internal_nonce::import_key(variant, raw_material, extractable).await?,
    ))
}

/// Generate a fresh random internal-nonce AES-GCM key.
pub async fn generate_key(
    variant: AesVariant,
    extractable: bool,
) -> Result<AeadInternalNonce, Error> {
    Ok(AeadInternalNonce::from_raw(
        bindings::aes_gcm_internal_nonce::generate_key(variant, extractable).await?,
    ))
}
