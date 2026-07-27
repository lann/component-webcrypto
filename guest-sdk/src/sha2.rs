//! `sha2` digest creation.

use crate::{bindings, Digest, Error};

pub use crate::bindings::sha2::Sha2Variant;

/// Mint a digest bound to the declared SHA-2 variant.
pub fn make_digest(variant: Sha2Variant) -> Result<Digest, Error> {
    Ok(Digest::from_raw(bindings::sha2::make_digest(variant)?))
}
