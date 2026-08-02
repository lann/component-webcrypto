//! `hkdf-sha1` derivation parameterization: HKDF over SHA-1, for
//! compatibility with existing protocols that fix it. The construction is
//! not affected by SHA-1's collision attacks (HKDF relies on HMAC's PRF
//! property), but prefer [`hkdf_sha2`](crate::hkdf_sha2) where the
//! protocol is yours to choose.
//!
//! The [`Ikm`](crate::Ikm) resource and its import stay
//! [`hkdf`](crate::hkdf)'s, so one imported secret can parameterize
//! derivations over either hash family.

use crate::{bindings, DeriveInput, Error, Ikm};

/// Parameterize an HKDF-SHA-1 derivation over imported keying material.
/// See [`hkdf_sha2::prepare`](crate::hkdf_sha2::prepare) for the `salt`
/// and `info` contracts.
pub async fn prepare(
    input: &Ikm,
    salt: impl Into<Vec<u8>>,
    info: impl Into<Vec<u8>>,
) -> Result<DeriveInput, Error> {
    Ok(DeriveInput::from_raw(
        bindings::hkdf_sha1::prepare(input.as_raw(), salt.into(), info.into()).await?,
    ))
}

/// Chain an HKDF-SHA-1 derivation from another derivation's output. See
/// [`hkdf_sha2::prepare_from`](crate::hkdf_sha2::prepare_from).
pub async fn prepare_from(
    input: &DeriveInput,
    salt: impl Into<Vec<u8>>,
    info: impl Into<Vec<u8>>,
) -> Result<DeriveInput, Error> {
    Ok(DeriveInput::from_raw(
        bindings::hkdf_sha1::prepare_from(input.as_raw(), salt.into(), info.into()).await?,
    ))
}
