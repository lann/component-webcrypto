//! `aes-gcm-internal-nonce` key creation.

use crate::{bindings, AeadInternalNonce, Error, InternalNonceKeyOptions};

pub use crate::bindings::aes_gcm::AesVariant;

/// Import raw key material as an internal-nonce AES-GCM key.
pub async fn import_key_raw(
    variant: AesVariant,
    raw_material: Vec<u8>,
    options: InternalNonceKeyOptions,
) -> Result<AeadInternalNonce, Error> {
    Ok(AeadInternalNonce::from_raw(
        bindings::aes_gcm_internal_nonce::import_key_raw(variant, raw_material, options.lower())
            .await?,
    ))
}

/// Generate a fresh random internal-nonce AES-GCM key.
pub async fn generate_key(
    variant: AesVariant,
    options: InternalNonceKeyOptions,
) -> Result<AeadInternalNonce, Error> {
    Ok(AeadInternalNonce::from_raw(
        bindings::aes_gcm_internal_nonce::generate_key(variant, options.lower()).await?,
    ))
}
