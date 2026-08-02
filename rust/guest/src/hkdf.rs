//! `hkdf` base-secret import (RFC 5869).
//!
//! This module mints no keys and runs no derivation: it imports the input
//! keying material that [`hkdf_sha2`](crate::hkdf_sha2) and
//! [`hkdf_sha1`](crate::hkdf_sha1) parameterize into
//! [`DeriveInput`](crate::DeriveInput)s.

use crate::{bindings, DeriveOptions, Error, Ikm};

/// Import input keying material.
///
/// IKM is a cryptographic secret (a shared secret, a master key) — for a
/// human-chosen password, use [`pbkdf2::import_password`](crate::pbkdf2::import_password)
/// instead. Empty material fails [`Error::InvalidKey`]; a policy with no
/// grant enabled fails [`Error::NotPermitted`].
pub async fn import_ikm(raw: impl Into<Vec<u8>>, options: DeriveOptions) -> Result<Ikm, Error> {
    Ok(Ikm::from_raw(
        bindings::hkdf::import_ikm(raw.into(), options.lower()).await?,
    ))
}
