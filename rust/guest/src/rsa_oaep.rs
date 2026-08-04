//! `rsa-oaep-encrypt` key creation (RFC 8017 §7.1) — the public half of
//! key transport — plus, behind the `rsa-oaep-decrypt` cargo feature,
//! `rsa-oaep-decrypt`.
//!
//! The declared variant binds the digest at mint; the MGF1 digest is the
//! same digest. Admission tightens the RSA family contract on both ends:
//! the modulus must be 2048–8192 bits (see the WIT `rsa-oaep-encrypt`
//! interface). The plaintext bound follows from the mint: modulus bytes
//! minus twice the digest length minus 2.

use crate::{bindings, EncryptionKey, Error};
#[cfg(feature = "rsa-oaep-decrypt")]
use crate::{DecryptionKey, DecryptionKeyOptions};

pub use crate::bindings::rsa_oaep_encrypt::RsaVariant;

#[cfg(feature = "rsa-oaep-decrypt")]
pub use crate::bindings::rsa_oaep_decrypt::RsaModulus;

/// Import a public key as an X.509 SubjectPublicKeyInfo (DER). Admission
/// follows the RSA family contract (see the WIT `rsa` interface) plus the
/// 2048–8192-bit window.
pub async fn import_encryption_key_spki(
    variant: RsaVariant,
    spki: impl Into<Vec<u8>>,
) -> Result<EncryptionKey, Error> {
    Ok(EncryptionKey::from_raw(
        bindings::rsa_oaep_encrypt::import_encryption_key_spki(variant, spki.into()).await?,
    ))
}

/// Import a public key as an RSA public JWK (`kty: "RSA"`, with `n` and
/// `e`, as JSON text). An `alg` member, when present, must be the
/// variant's JOSE alg (`"RSA-OAEP-256"`, `"RSA-OAEP-384"`, or
/// `"RSA-OAEP-512"`). See the WIT `mac-key.export-key-jwk` doc for the
/// package-wide JWK contract.
pub async fn import_encryption_key_jwk(
    variant: RsaVariant,
    jwk: impl Into<String>,
) -> Result<EncryptionKey, Error> {
    Ok(EncryptionKey::from_raw(
        bindings::rsa_oaep_encrypt::import_encryption_key_jwk(variant, jwk.into()).await?,
    ))
}

/// Generate a fresh key pair of the declared variant and modulus length,
/// returning both halves. The public exponent is 65537; it is not a
/// parameter.
#[cfg(feature = "rsa-oaep-decrypt")]
pub async fn generate_key(
    variant: RsaVariant,
    modulus: RsaModulus,
    options: DecryptionKeyOptions,
) -> Result<(DecryptionKey, EncryptionKey), Error> {
    let (decryption, encryption) =
        bindings::rsa_oaep_decrypt::generate_key(variant, modulus, options.lower()).await?;
    Ok((
        DecryptionKey::from_raw(decryption),
        EncryptionKey::from_raw(encryption),
    ))
}

/// Import a decryption key as a PKCS#8 PrivateKeyInfo (DER, with the CRT
/// parameters). Admission follows the RSA family contract plus the
/// 2048–8192-bit window (see the WIT `rsa-oaep-decrypt` interface).
/// Returns only the decryption key; supply the public half to
/// [`import_encryption_key_spki`] if you need it.
#[cfg(feature = "rsa-oaep-decrypt")]
pub async fn import_decryption_key_pkcs8(
    variant: RsaVariant,
    pkcs8: impl Into<Vec<u8>>,
    options: DecryptionKeyOptions,
) -> Result<DecryptionKey, Error> {
    Ok(DecryptionKey::from_raw(
        bindings::rsa_oaep_decrypt::import_decryption_key_pkcs8(
            variant,
            pkcs8.into(),
            options.lower(),
        )
        .await?,
    ))
}

/// Import a decryption key as a full-CRT RSA private JWK (`kty: "RSA"`,
/// with `n`, `e`, `d`, and the CRT members, as JSON text), subject to
/// [`import_decryption_key_pkcs8`]'s admission. An `alg` member, when
/// present, must be the variant's JOSE alg (`"RSA-OAEP-256"`,
/// `"RSA-OAEP-384"`, or `"RSA-OAEP-512"`).
#[cfg(feature = "rsa-oaep-decrypt")]
pub async fn import_decryption_key_jwk(
    variant: RsaVariant,
    jwk: impl Into<String>,
    options: DecryptionKeyOptions,
) -> Result<DecryptionKey, Error> {
    Ok(DecryptionKey::from_raw(
        bindings::rsa_oaep_decrypt::import_decryption_key_jwk(variant, jwk.into(), options.lower())
            .await?,
    ))
}
