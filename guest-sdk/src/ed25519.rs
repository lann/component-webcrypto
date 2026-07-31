//! `ed25519-verify` / `ed25519-sign` key creation.

use crate::{bindings, Error, SigningKey, VerifyingKey};

/// Import a 32-byte raw public key.
pub async fn import_verifying_key(raw_material: Vec<u8>) -> Result<VerifyingKey, Error> {
    Ok(VerifyingKey::from_raw(
        bindings::ed25519_verify::import_verifying_key(raw_material).await?,
    ))
}

/// Generate a fresh random signing key, returning both halves.
pub async fn generate_key(extractable: bool) -> Result<(SigningKey, VerifyingKey), Error> {
    let (signing, verifying) = bindings::ed25519_sign::generate_key(extractable).await?;
    Ok((
        SigningKey::from_raw(signing),
        VerifyingKey::from_raw(verifying),
    ))
}
