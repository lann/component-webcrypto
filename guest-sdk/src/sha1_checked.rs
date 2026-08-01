//! `sha1-checked` digest creation: SHA-1 with sha1dc collision detection.
//! This package never mints plain SHA-1; each constructor binds a
//! collision posture (see the WIT `sha1-checked` docs).

use crate::{bindings, Digest, Error};

/// Mint a checked SHA-1 digest that fails `compute` with the
/// `collision-detected` extension condition (see [`crate::extension`])
/// for input carrying a collision attack pattern.
pub fn make_rejecting_digest() -> Result<Digest, Error> {
    Ok(Digest::from_raw(
        bindings::sha1_checked::make_rejecting_digest()?,
    ))
}

/// Mint a checked SHA-1 digest that returns the deterministic sha1dc safe
/// hash for input carrying a collision attack pattern.
pub fn make_mitigating_digest() -> Result<Digest, Error> {
    Ok(Digest::from_raw(
        bindings::sha1_checked::make_mitigating_digest()?,
    ))
}
