//! `xchacha20-poly1305` key creation (extended-nonce construction,
//! caller-nonce; see [`Aead`]'s nonce warning).

use crate::{bindings, Aead, AeadKeyOptions, Error};

/// Import 32 bytes of raw key material.
pub async fn import_key_raw(raw_material: Vec<u8>, options: AeadKeyOptions) -> Result<Aead, Error> {
    Ok(Aead::from_raw(
        bindings::xchacha20_poly1305::import_key_raw(raw_material, options.lower()).await?,
    ))
}

/// Generate a fresh random 256-bit key.
pub async fn generate_key(options: AeadKeyOptions) -> Result<Aead, Error> {
    Ok(Aead::from_raw(
        bindings::xchacha20_poly1305::generate_key(options.lower()).await?,
    ))
}
