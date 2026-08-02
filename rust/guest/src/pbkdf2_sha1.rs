//! `pbkdf2-sha1` derivation parameterization: PBKDF2 over HMAC-SHA-1, for
//! compatibility with existing password databases that fix it. The
//! construction is not affected by SHA-1's collision attacks (PBKDF2
//! relies on HMAC's PRF property), but prefer
//! [`pbkdf2_sha2`](crate::pbkdf2_sha2) where the parameters are yours to
//! choose.
//!
//! The [`Password`](crate::Password) resource and its import stay
//! [`pbkdf2`](crate::pbkdf2)'s, so one imported password can parameterize
//! derivations over either hash family.

use crate::{bindings, DeriveInput, Error, Password};

/// Parameterize a PBKDF2-HMAC-SHA-1 derivation over an imported password.
/// See [`pbkdf2_sha2::prepare`](crate::pbkdf2_sha2::prepare) for the
/// `salt` and `iterations` contracts.
pub async fn prepare(
    input: &Password,
    salt: impl Into<Vec<u8>>,
    iterations: u32,
) -> Result<DeriveInput, Error> {
    Ok(DeriveInput::from_raw(
        bindings::pbkdf2_sha1::prepare(input.as_raw(), salt.into(), iterations).await?,
    ))
}
