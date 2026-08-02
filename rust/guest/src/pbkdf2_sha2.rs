//! `pbkdf2-sha2` derivation parameterization (RFC 8018 over
//! HMAC-SHA-2).
//!
//! This module mints no keys: `prepare` yields a
//! [`DeriveInput`](crate::DeriveInput), consumed through
//! [`DeriveInput::derive_bits`](crate::DeriveInput::derive_bits) or a
//! target interface's `derive_key`.

use crate::{bindings, DeriveInput, Error, Password};

pub use crate::bindings::sha2::Sha2Variant;

/// Parameterize a PBKDF2 derivation over an imported password.
///
/// `salt` should be a per-password random value (RFC 8018 recommends at
/// least 8 bytes; NIST SP 800-132 at least 16). `iterations` is the work
/// factor — choose it as high as the deployment tolerates; a zero count
/// fails [`Error::Other`]. The grants are copied from `input`.
pub async fn prepare(
    variant: Sha2Variant,
    input: &Password,
    salt: impl Into<Vec<u8>>,
    iterations: u32,
) -> Result<DeriveInput, Error> {
    Ok(DeriveInput::from_raw(
        bindings::pbkdf2_sha2::prepare(variant, input.as_raw(), salt.into(), iterations).await?,
    ))
}
