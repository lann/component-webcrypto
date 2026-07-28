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
//! classification, which the in-guest provider enforces by never exporting
//! `ecdsa-sign`. This crate enforces the same policy one level deeper: the
//! ECDSA arms of the private-key type exist only on non-wasm targets
//! (`#[cfg(not(target_family = "wasm"))]`), so class-D signing code is
//! structurally absent from every wasm build rather than merely unexported.

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

/// What a stream-draining loop should do with one read's status.
///
/// The two Rust implementations consume `stream<u8>` through different
/// runtimes — the Wasmtime host through `StreamConsumer`, the in-guest
/// provider through `wit_bindgen::StreamReader` — but the *policy* is one
/// contract, and they disagreed about it: the guest treated a cancelled read
/// as end-of-input, ending the operation over a prefix while the host kept
/// collecting. Deciding it here, once, is the point of this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrainStep {
    /// Keep the bytes just read and read again: the stream is still open.
    Continue,
    /// The writer dropped its end. The input is complete.
    Complete,
}

/// The action for a read that ended with the writer's handle dropped
/// (`dropped`) and/or with the read itself cancelled (`cancelled`).
///
/// Cancellation is not end-of-input. It reports that *this read* transferred
/// nothing, not that the stream ended, so treating it as the end yields a
/// tag, signature or ciphertext over a prefix the caller never finished
/// sending — and leaves the stream undrained, which the WIT's drain rule
/// forbids. Only a dropped writer ends a stream.
pub fn drain_step(dropped: bool, cancelled: bool) -> DrainStep {
    let _ = cancelled;
    if dropped {
        DrainStep::Complete
    } else {
        DrainStep::Continue
    }
}

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
/// key-material type (which zeroizes on drop) promptly.
pub(crate) fn random_bytes(len: usize) -> Result<Vec<u8>, RngError> {
    let mut raw = vec![0u8; len];
    getrandom::fill(&mut raw)?;
    Ok(raw)
}

#[cfg(test)]
mod drain_tests {
    use super::{drain_step, DrainStep};

    /// A dropped writer is the only end-of-input.
    #[test]
    fn only_a_dropped_writer_completes() {
        assert_eq!(drain_step(true, false), DrainStep::Complete);
        assert_eq!(drain_step(true, true), DrainStep::Complete);
    }

    /// A cancelled read transferred nothing; the stream is still open, so
    /// the loop must read again rather than deliver the prefix collected so
    /// far as if it were the whole input.
    #[test]
    fn a_cancelled_read_is_not_end_of_input() {
        assert_eq!(drain_step(false, true), DrainStep::Continue);
    }

    /// An ordinary completed read continues.
    #[test]
    fn a_completed_read_continues() {
        assert_eq!(drain_step(false, false), DrainStep::Continue);
    }
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
