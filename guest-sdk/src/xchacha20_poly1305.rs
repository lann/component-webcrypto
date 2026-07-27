//! `xchacha20-poly1305` key creation (extended-nonce construction,
//! caller-nonce; see [`Aead`]'s nonce warning).

use crate::{bindings, Aead, Error};

/// Import 32 bytes of raw key material.
pub async fn import_key(raw_material: Vec<u8>, extractable: bool) -> Result<Aead, Error> {
    Ok(Aead::from_raw(
        bindings::xchacha20_poly1305::import_key(raw_material, extractable).await?,
    ))
}

/// Generate a fresh random 256-bit key.
pub async fn generate_key(extractable: bool) -> Result<Aead, Error> {
    Ok(Aead::from_raw(
        bindings::xchacha20_poly1305::generate_key(extractable).await?,
    ))
}
