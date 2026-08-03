//! `rsassa-pkcs1-v15-verify` key creation (RFC 8017 §8.2), plus —
//! behind the `rsa-sign` cargo feature — `rsassa-pkcs1-v15-sign`.

use crate::{bindings, Error, VerifyingKey};
#[cfg(feature = "rsa-sign")]
use crate::{SigningKey, SigningKeyOptions};

pub use crate::bindings::rsassa_pkcs1_v15_verify::RsaVariant;

#[cfg(feature = "rsa-sign")]
pub use crate::bindings::rsassa_pkcs1_v15_sign::RsaModulus;

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

/// Generate a fresh signing key pair of the declared variant and modulus
/// length, returning both halves. The public exponent is 65537; it is
/// not a parameter.
#[cfg(feature = "rsa-sign")]
pub async fn generate_key(
    variant: RsaVariant,
    modulus: RsaModulus,
    options: SigningKeyOptions,
) -> Result<(SigningKey, VerifyingKey), Error> {
    let (signing, verifying) =
        bindings::rsassa_pkcs1_v15_sign::generate_key(variant, modulus, options.lower()).await?;
    Ok((
        SigningKey::from_raw(signing),
        VerifyingKey::from_raw(verifying),
    ))
}

/// Import a signing key as a PKCS#8 PrivateKeyInfo (DER, with the CRT
/// parameters). Admission follows the RSA family contract plus the
/// signing window — a 2048–8192-bit modulus (see the WIT
/// `rsassa-pkcs1-v15-sign` interface). Returns only the signing key;
/// supply the public half to [`import_verifying_key_spki`] if you need
/// it.
#[cfg(feature = "rsa-sign")]
pub async fn import_signing_key_pkcs8(
    variant: RsaVariant,
    pkcs8: impl Into<Vec<u8>>,
    options: SigningKeyOptions,
) -> Result<SigningKey, Error> {
    Ok(SigningKey::from_raw(
        bindings::rsassa_pkcs1_v15_sign::import_signing_key_pkcs8(
            variant,
            pkcs8.into(),
            options.lower(),
        )
        .await?,
    ))
}

/// Import a signing key as an RSA private JWK (`kty: "RSA"`, with `n`,
/// `e`, `d`, and the CRT members, as JSON text), subject to
/// [`import_signing_key_pkcs8`]'s admission. An `alg` member, when
/// present, must be the variant's JOSE alg (`"RS256"`, `"RS384"`, or
/// `"RS512"`).
#[cfg(feature = "rsa-sign")]
pub async fn import_signing_key_jwk(
    variant: RsaVariant,
    jwk: impl Into<String>,
    options: SigningKeyOptions,
) -> Result<SigningKey, Error> {
    Ok(SigningKey::from_raw(
        bindings::rsassa_pkcs1_v15_sign::import_signing_key_jwk(
            variant,
            jwk.into(),
            options.lower(),
        )
        .await?,
    ))
}
