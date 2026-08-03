//! `rsa-pss-verify` key creation (RFC 8017 §8.1).

use crate::{bindings, Error, VerifyingKey};

pub use crate::bindings::rsa_pss_verify::RsaVariant;

/// Import a public key as an X.509 SubjectPublicKeyInfo (DER). The
/// declared variant binds the digest at mint, and `salt_length` — the PSS
/// salt length in bytes — binds there too: the minted key verifies exactly
/// one PSS parameterization, and a signature made under any other salt
/// length fails [`Error::AuthenticationFailed`]. Admission follows the RSA
/// family contract (see the WIT `rsa` interface).
pub async fn import_verifying_key_spki(
    variant: RsaVariant,
    salt_length: u32,
    spki: impl Into<Vec<u8>>,
) -> Result<VerifyingKey, Error> {
    Ok(VerifyingKey::from_raw(
        bindings::rsa_pss_verify::import_verifying_key_spki(variant, salt_length, spki.into())
            .await?,
    ))
}

/// Import a public key as an RSA public JWK (`kty: "RSA"`, with `n` and
/// `e`, as JSON text); see [`import_verifying_key_spki`] for
/// `salt_length`. An `alg` member, when present, must be the variant's
/// JOSE alg (`"PS256"`, `"PS384"`, or `"PS512"`). See the WIT
/// `mac-key.export-key-jwk` doc for the package-wide JWK contract.
pub async fn import_verifying_key_jwk(
    variant: RsaVariant,
    salt_length: u32,
    jwk: impl Into<String>,
) -> Result<VerifyingKey, Error> {
    Ok(VerifyingKey::from_raw(
        bindings::rsa_pss_verify::import_verifying_key_jwk(variant, salt_length, jwk.into())
            .await?,
    ))
}
