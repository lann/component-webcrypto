//! `rsa-pss-verify` key creation (RFC 8017 §8.1), plus — behind the
//! `rsa-sign` cargo feature — `rsa-pss-sign`.

use crate::{bindings, Error, VerifyingKey};
#[cfg(feature = "rsa-sign")]
use crate::{SigningKey, SigningKeyOptions};

pub use crate::bindings::rsa_pss_verify::RsaVariant;

#[cfg(feature = "rsa-sign")]
pub use crate::bindings::rsa_pss_sign::RsaModulus;

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

/// Generate a fresh signing key pair of the declared variant and modulus
/// length, returning both halves. The public exponent is 65537; it is
/// not a parameter. Keys minted here sign with the salt length equal to
/// the digest length (the JOSE `PS*` profile); it is not a parameter
/// either.
#[cfg(feature = "rsa-sign")]
pub async fn generate_key(
    variant: RsaVariant,
    modulus: RsaModulus,
    options: SigningKeyOptions,
) -> Result<(SigningKey, VerifyingKey), Error> {
    let (signing, verifying) =
        bindings::rsa_pss_sign::generate_key(variant, modulus, options.lower()).await?;
    Ok((
        SigningKey::from_raw(signing),
        VerifyingKey::from_raw(verifying),
    ))
}

/// Import a signing key as a PKCS#8 PrivateKeyInfo (DER, with the CRT
/// parameters). Admission follows the RSA family contract plus the
/// signing window — a 2048–8192-bit modulus (see the WIT `rsa-pss-sign`
/// interface). Returns only the signing key; supply the public half to
/// [`import_verifying_key_spki`] if you need it.
#[cfg(feature = "rsa-sign")]
pub async fn import_signing_key_pkcs8(
    variant: RsaVariant,
    pkcs8: impl Into<Vec<u8>>,
    options: SigningKeyOptions,
) -> Result<SigningKey, Error> {
    Ok(SigningKey::from_raw(
        bindings::rsa_pss_sign::import_signing_key_pkcs8(variant, pkcs8.into(), options.lower())
            .await?,
    ))
}

/// Import a signing key as an RSA private JWK (`kty: "RSA"`, with `n`,
/// `e`, `d`, and the CRT members, as JSON text), subject to
/// [`import_signing_key_pkcs8`]'s admission. An `alg` member, when
/// present, must be the variant's JOSE alg (`"PS256"`, `"PS384"`, or
/// `"PS512"`).
#[cfg(feature = "rsa-sign")]
pub async fn import_signing_key_jwk(
    variant: RsaVariant,
    jwk: impl Into<String>,
    options: SigningKeyOptions,
) -> Result<SigningKey, Error> {
    Ok(SigningKey::from_raw(
        bindings::rsa_pss_sign::import_signing_key_jwk(variant, jwk.into(), options.lower())
            .await?,
    ))
}
