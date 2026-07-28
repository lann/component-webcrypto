//! The shared RustCrypto core of the two Rust implementations of
//! `lann:webcrypto`: `wasmtime-impl` (native host) and `guest-impl` (in-guest
//! wasm component).
//!
//! Everything algorithm-shaped lives here exactly once — cipher and digest
//! dispatch, key-material validation and generation, error rendering, the
//! internal-nonce wire format, and signature parsing/verification — so the
//! two implementations cannot drift apart behaviorally. What stays in each
//! implementation is only what genuinely differs: bindings glue (each side's
//! generated types), stream plumbing, resource-table wiring, and the
//! internal-nonce seal *bookkeeping* (a `u64` behind the host's resource
//! table vs. a `Cell` in the single-threaded guest).
//!
//! Two conventions keep the split honest:
//!
//! - [`Error`] mirrors the WIT `types.error` variant case for case; each
//!   implementation converts it into its generated error type with a
//!   mechanical `From`. Operations here return the exact error cases and
//!   message strings the WIT contracts specify.
//! - Fallible randomness is a *separate channel* from WIT errors: operations
//!   that draw randomness return `Result<Result<T, Error>, RngError>` (or
//!   `Result<T, RngError>` when no WIT error is possible), because the two
//!   implementations disagree on what an entropy failure means — the host
//!   surfaces it as a trap-shaped host error, the guest treats WASI random
//!   as infallible.
//!
//! ## Class-D policy: ECDSA signing is not compiled for wasm
//!
//! ECDSA signing handles a per-signature secret nonce whose timing leakage
//! is key-recovering — class D in guest-impl's timing-channel
//! classification. The load-bearing enforcement is the in-guest provider's
//! world, which never exports `ecdsa-sign`: a composition that needs it
//! fails at `wac plug` time. This crate adds a second layer — the ECDSA
//! arms of the private-key type exist only on non-wasm targets
//! (`#[cfg(not(target_family = "wasm"))]`), so nothing in a wasm build
//! *calls* a signing implementation.
//!
//! The signing code is nonetheless *compiled* for wasm: verification needs
//! `p256`/`p384` with `features = ["ecdsa"]`, and cargo unifies features
//! across a build, so no target-gated dependency removes it. Its absence
//! from the final `.wasm` therefore rests on dead-code elimination. The
//! world is the guarantee; the `cfg` is defence in depth.

mod aead;
mod hash;
mod mac;
mod sig;

pub use aead::AeadKeyMaterial;
pub use hash::{served_sha2, Sha2};
pub use mac::MacKeyMaterial;
pub use sig::{SigPublic, SigningKeyMaterial};

/// A failure of the platform's random source, surfaced separately from WIT
/// errors so each implementation can decide what it means (the host traps,
/// the guest treats WASI random as infallible).
pub type RngError = getrandom::Error;

/// The WIT `types.error` variant, mirrored case for case. Implementations
/// convert values of this type into their generated error types with a
/// mechanical `From`; the message strings carried here are the ones the WIT
/// contracts specify, shared verbatim by both implementations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// WIT `invalid-key(string)`.
    InvalidKey(String),
    /// WIT `invalid-nonce(string)`.
    InvalidNonce(String),
    /// WIT `authentication-failed`.
    AuthenticationFailed,
    /// WIT `not-extractable`.
    NotExtractable,
    /// WIT `unsupported(string)`.
    Unsupported(String),
    /// WIT `key-exhausted`.
    KeyExhausted,
    /// WIT `other(string)`.
    Other(String),
}

/// The WIT `sha2.sha2-variant` cases. Variant names match the generated
/// bindings' so `{:?}` renders identically in error messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sha2Variant {
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha512224,
    Sha512256,
}

/// The WIT `aes.aes-variant` cases. Variant names match the generated
/// bindings' so `{:?}` renders identically in error messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesVariant {
    Aes128,
    Aes192,
    Aes256,
}

/// The WIT `ecdsa-verify.ecdsa-variant` cases. Variant names match the
/// generated bindings' so `{:?}` renders identically in error messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdsaVariant {
    P256Sha256,
    P384Sha384,
}

/// The `algorithm-name` reported by HMAC keys (WebCrypto's
/// `KeyAlgorithm.name`).
pub const HMAC_NAME: &str = "HMAC";

/// The `algorithm-name` reported by AES-GCM keys (WebCrypto's
/// `KeyAlgorithm.name`).
pub const AES_GCM_NAME: &str = "AES-GCM";

/// The `algorithm-name` reported by ChaCha20-Poly1305 keys (the spelling of
/// the WICG WebCrypto proposal; the algorithm is not in the W3C registry).
pub const CHACHA20_POLY1305_NAME: &str = "ChaCha20-Poly1305";

/// The `algorithm-name` reported by XChaCha20-Poly1305 keys.
pub const XCHACHA20_POLY1305_NAME: &str = "XChaCha20-Poly1305";

/// The `algorithm-name` reported by Ed25519 keys (WebCrypto's
/// `KeyAlgorithm.name`, per the Secure Curves registry entry).
pub const ED25519_NAME: &str = "Ed25519";

/// The `algorithm-name` reported by ECDSA keys (WebCrypto's
/// `KeyAlgorithm.name`).
pub const ECDSA_NAME: &str = "ECDSA";

/// Whether `a` and `b` are equal, in time independent of their *contents*
/// (necessarily dependent on their lengths) — the `bytes.constant-time-equal`
/// contract.
pub fn constant_time_equal(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq as _;
    // `ct_eq` on slices short-circuits only on length (which is not
    // secret); the contents are compared in constant time.
    a.ct_eq(b).into()
}

/// `len` bytes of fresh randomness. Callers wrap the buffer in its
/// key-material type promptly.
pub(crate) fn random_bytes(len: usize) -> Result<Vec<u8>, RngError> {
    let mut raw = vec![0u8; len];
    getrandom::fill(&mut raw)?;
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_equal_matches_plain_equality() {
        assert!(constant_time_equal(b"", b""));
        assert!(constant_time_equal(b"abc", b"abc"));
        assert!(!constant_time_equal(b"abc", b"abd"));
        assert!(!constant_time_equal(b"abc", b"abcd"));
    }
}
