//! `ecdsa-verify` / `ecdsa-sign` key creation.

use crate::{bindings, Error, SigningKey, VerifyingKey};

pub use crate::bindings::ecdsa_verify::EcdsaVariant;

/// Import a public key as an uncompressed SEC1 point.
pub async fn import_verifying_key(
    variant: EcdsaVariant,
    raw_material: Vec<u8>,
) -> Result<VerifyingKey, Error> {
    Ok(VerifyingKey::from_raw(
        bindings::ecdsa_verify::import_verifying_key(variant, raw_material).await?,
    ))
}

/// Import a raw scalar as a signing key of the declared variant.
pub async fn import_signing_key(
    variant: EcdsaVariant,
    raw_material: Vec<u8>,
    extractable: bool,
) -> Result<SigningKey, Error> {
    Ok(SigningKey::from_raw(
        bindings::ecdsa_sign::import_signing_key(variant, raw_material, extractable).await?,
    ))
}

/// Generate a fresh random signing key of the declared variant.
pub async fn generate_key(variant: EcdsaVariant, extractable: bool) -> Result<SigningKey, Error> {
    Ok(SigningKey::from_raw(
        bindings::ecdsa_sign::generate_key(variant, extractable).await?,
    ))
}
