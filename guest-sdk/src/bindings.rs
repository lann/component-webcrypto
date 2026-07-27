//! The generated bindings for the full `lann:webcrypto` import surface.
//!
//! The newtype wrappers cover the common cases; these are the escape hatch
//! for callers driving the streams themselves and for passing resources
//! through a consumer's own interfaces (via [`Mac::into_raw`](crate::Mac::into_raw)
//! and friends).

pub use crate::generated::lann::webcrypto::{
    aead, aead_internal_nonce, aes_gcm, aes_gcm_internal_nonce, bytes, chacha20_poly1305, digest,
    ecdsa_sign, ecdsa_verify, ed25519_sign, ed25519_verify, hmac_sha2, mac, sha2, signature, types,
    xchacha20_poly1305, xchacha20_poly1305_internal_nonce,
};
