//! `aes-gcm` key creation (caller-nonce; prefer
//! [`aes_gcm_internal_nonce`](crate::aes_gcm_internal_nonce) — see
//! [`Aead`]'s nonce warning).

use crate::{bindings, Aead, Error};

pub use crate::bindings::aes_gcm::AesVariant;

/// Import raw key material as the declared AES variant.
pub async fn import_key(
    variant: AesVariant,
    raw_material: Vec<u8>,
    extractable: bool,
) -> Result<Aead, Error> {
    Ok(Aead::from_raw(
        bindings::aes_gcm::import_key(variant, raw_material, extractable).await?,
    ))
}

/// Generate a fresh random key of the declared AES variant.
pub async fn generate_key(variant: AesVariant, extractable: bool) -> Result<Aead, Error> {
    Ok(Aead::from_raw(
        bindings::aes_gcm::generate_key(variant, extractable).await?,
    ))
}
