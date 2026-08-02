//! `pbkdf2` base-secret import (RFC 8018).
//!
//! This module mints no keys and runs no derivation: it imports the
//! password that [`pbkdf2_sha2`](crate::pbkdf2_sha2) and
//! [`pbkdf2_sha1`](crate::pbkdf2_sha1) parameterize into
//! [`DeriveInput`](crate::DeriveInput)s.

use crate::{bindings, DeriveOptions, Error, Password};

/// Import a password.
///
/// Empty passwords are accepted — deliberately asymmetric with
/// [`hkdf::import_ikm`](crate::hkdf::import_ikm), whose material is a
/// cryptographic secret with no legitimate empty form, where a password is
/// end-user input the platform also accepts empty. A policy with no grant
/// enabled fails [`Error::NotPermitted`].
pub async fn import_password(
    raw: impl Into<Vec<u8>>,
    options: DeriveOptions,
) -> Result<Password, Error> {
    Ok(Password::from_raw(
        bindings::pbkdf2::import_password(raw.into(), options.lower()).await?,
    ))
}

/// Mint a password from unwrapped bytes, subject to [`import_password`]'s
/// contract. Consumes the [`UnwrapInput`](crate::UnwrapInput).
pub async fn unwrap_password(
    input: crate::UnwrapInput,
    options: DeriveOptions,
) -> Result<Password, Error> {
    Ok(Password::from_raw(
        bindings::pbkdf2::unwrap_password(input.into_raw(), options.lower()).await?,
    ))
}
