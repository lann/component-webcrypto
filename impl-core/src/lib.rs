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
//!
//! # Exported material
//!
//! Key material lives in [`zeroize::Zeroizing`], which scrubs the buffer on
//! drop. The `export_key_raw` operations are the one place it leaves that
//! protection, and they return a plain `Vec<u8>`.
//!
//! An extractable key's bytes are bound for guest memory, which the runtime
//! allocates and frees and this crate cannot scrub: the material is
//! unprotected from this call onward whatever the return type says. Every
//! caller lowers the buffer across the boundary in the expression that
//! receives it and keeps nothing.

mod aead;
mod agreement;
mod der8410;
mod gcm;
mod hash;
mod jwk;
mod kdf;
mod mac;
mod policy;
mod sig;

pub use aead::AeadKeyMaterial;
pub use agreement::{AgreementPublicMaterial, AgreementSecretMaterial};
pub use hash::{served_sha2, Sha2};
pub use kdf::{
    derive_aes_gcm_key, derive_mac_key, DeriveInputMaterial, IkmMaterial, PasswordMaterial,
};
pub use mac::MacKeyMaterial;
pub use policy::{
    not_permitted, AeadPolicy, AgreementPolicy, DerivePolicy, InternalNoncePolicy, MacPolicy,
    SigningPolicy,
};
pub use sig::{SigPublic, SigningKeyMaterial};

/// A failure of the platform's random source, surfaced separately from WIT
/// errors so each implementation can decide what it means (the host traps,
/// the guest treats WASI random as infallible).
pub type RngError = getrandom::Error;

/// The WIT `types.error` variant, mirrored case for case. Implementations
/// convert values of this type into their generated error types with the
/// mechanical `From` that [`impl_conversions!`] defines; the message strings
/// carried here are the ones the WIT contracts specify, shared verbatim by
/// both implementations.
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
    /// WIT `not-permitted(string)`.
    NotPermitted(String),
    /// WIT `unsupported(string)`.
    Unsupported(String),
    /// WIT `key-exhausted`.
    KeyExhausted,
    /// WIT `other(string)`.
    Other(String),
}

/// Define the mechanical bindings glue both implementations need:
/// `From<Error>` into the generated error type, and `From` from each
/// generated variant enum into this crate's, matching case for case.
///
/// Invoked once per implementation with its own generated types (each
/// `generate!`/`bindgen!` expansion produces distinct enums). The matches
/// are exhaustive on both sides, so a case added to the WIT or to this
/// crate is a compile error at the invocation rather than a silent drift.
#[macro_export]
macro_rules! impl_conversions {
    (
        error: $error:path,
        sha2: $sha2:path,
        aes: $aes:path,
        ecdsa: $ecdsa:path $(,)?
    ) => {
        impl From<$crate::Error> for $error {
            fn from(err: $crate::Error) -> Self {
                match err {
                    $crate::Error::InvalidKey(msg) => Self::InvalidKey(msg),
                    $crate::Error::InvalidNonce(msg) => Self::InvalidNonce(msg),
                    $crate::Error::AuthenticationFailed => Self::AuthenticationFailed,
                    $crate::Error::NotExtractable => Self::NotExtractable,
                    $crate::Error::NotPermitted(msg) => Self::NotPermitted(msg),
                    $crate::Error::Unsupported(msg) => Self::Unsupported(msg),
                    $crate::Error::KeyExhausted => Self::KeyExhausted,
                    $crate::Error::Other(msg) => Self::Other(msg),
                }
            }
        }

        impl From<$sha2> for $crate::Sha2Variant {
            fn from(variant: $sha2) -> Self {
                match variant {
                    <$sha2>::Sha224 => Self::Sha224,
                    <$sha2>::Sha256 => Self::Sha256,
                    <$sha2>::Sha384 => Self::Sha384,
                    <$sha2>::Sha512 => Self::Sha512,
                    <$sha2>::Sha512224 => Self::Sha512224,
                    <$sha2>::Sha512256 => Self::Sha512256,
                }
            }
        }

        impl From<$aes> for $crate::AesVariant {
            fn from(variant: $aes) -> Self {
                match variant {
                    <$aes>::Aes128 => Self::Aes128,
                    <$aes>::Aes192 => Self::Aes192,
                    <$aes>::Aes256 => Self::Aes256,
                }
            }
        }

        impl From<$ecdsa> for $crate::EcdsaVariant {
            fn from(variant: $ecdsa) -> Self {
                match variant {
                    <$ecdsa>::P256Sha256 => Self::P256Sha256,
                    <$ecdsa>::P256Sha384 => Self::P256Sha384,
                    <$ecdsa>::P256Sha512 => Self::P256Sha512,
                    <$ecdsa>::P384Sha256 => Self::P384Sha256,
                    <$ecdsa>::P384Sha384 => Self::P384Sha384,
                    <$ecdsa>::P384Sha512 => Self::P384Sha512,
                    <$ecdsa>::P521Sha512 => Self::P521Sha512,
                }
            }
        }
    };
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
    P256Sha384,
    P256Sha512,
    P384Sha256,
    P384Sha384,
    P384Sha512,
    /// Declared in the WIT, served by no implementation of this package
    /// (see the `ecdsa-variant` doc): every minting path declines it
    /// `unsupported`.
    P521Sha512,
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

/// Fill a caller-owned (typically already-zeroizing) buffer with fresh
/// randomness.
pub(crate) fn fill_random(buf: &mut [u8]) -> Result<(), RngError> {
    getrandom::fill(buf)
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
