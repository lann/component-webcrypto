//! `rsassa-pkcs1-v15-verify` key creation (RFC 8017 §8.2).

use crate::{bindings, Error, VerifyingKey};

pub use crate::bindings::rsassa_pkcs1_v15_verify::RsaVariant;

/// Import a public key as an X.509 SubjectPublicKeyInfo (DER). The
/// declared variant binds the digest at mint; admission follows the RSA
/// family contract (see the WIT `rsa` interface).
pub async fn import_verifying_key_spki(
    variant: RsaVariant,
    spki: impl Into<Vec<u8>>,
) -> Result<VerifyingKey, Error> {
    Ok(VerifyingKey::from_raw(
        bindings::rsassa_pkcs1_v15_verify::import_verifying_key_spki(variant, spki.into()).await?,
    ))
}

/// Import a public key as an RSA public JWK (`kty: "RSA"`, with `n` and
/// `e`, as JSON text). An `alg` member, when present, must be the
/// variant's JOSE alg (`"RS256"`, `"RS384"`, or `"RS512"`). See the WIT
/// `mac-key.export-key-jwk` doc for the package-wide JWK contract.
pub async fn import_verifying_key_jwk(
    variant: RsaVariant,
    jwk: impl Into<String>,
) -> Result<VerifyingKey, Error> {
    Ok(VerifyingKey::from_raw(
        bindings::rsassa_pkcs1_v15_verify::import_verifying_key_jwk(variant, jwk.into()).await?,
    ))
}
