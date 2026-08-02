//! `hkdf-sha2` derivation parameterization (RFC 5869 over the SHA-2
//! family).
//!
//! This module mints no keys: `prepare` yields a
//! [`DeriveInput`](crate::DeriveInput), consumed through
//! [`DeriveInput::derive_bits`](crate::DeriveInput::derive_bits) or a
//! target interface's `derive_key` (e.g.
//! [`hmac_sha2::derive_key`](crate::hmac_sha2::derive_key)).

use crate::{bindings, DeriveInput, Error, Ikm};

pub use crate::bindings::sha2::Sha2Variant;

/// Parameterize an HKDF derivation over imported keying material:
/// HKDF-Extract runs with `salt`, and `info` is bound for the expand step.
///
/// An empty `salt` means the RFC's default (a hash-length block of
/// zeros). The grants are copied from `input`.
pub async fn prepare(
    variant: Sha2Variant,
    input: &Ikm,
    salt: impl Into<Vec<u8>>,
    info: impl Into<Vec<u8>>,
) -> Result<DeriveInput, Error> {
    Ok(DeriveInput::from_raw(
        bindings::hkdf_sha2::prepare(variant, input.as_raw(), salt.into(), info.into()).await?,
    ))
}

/// Parameterize an HKDF derivation over another derivation's output —
/// the chaining step, e.g. from an [`AgreementSecretKey::agree`]
/// (WebCrypto's `deriveKey(ECDH → HKDF)` shape).
///
/// The upstream derivation runs at its natural output length, so only
/// sources that have one chain: an agreement's shared secret does; KDF
/// sources fail [`Error::Other`], as the platform does. Requires the
/// upstream input's [`derive_key`](crate::DeriveOptions::derive_key)
/// grant.
///
/// [`AgreementSecretKey::agree`]: crate::AgreementSecretKey::agree
pub async fn prepare_from(
    variant: Sha2Variant,
    input: &DeriveInput,
    salt: impl Into<Vec<u8>>,
    info: impl Into<Vec<u8>>,
) -> Result<DeriveInput, Error> {
    Ok(DeriveInput::from_raw(
        bindings::hkdf_sha2::prepare_from(variant, input.as_raw(), salt.into(), info.into())
            .await?,
    ))
}
