//! Raw `bindgen!` output for the `lann:webcrypto` package.
//!
//! The crate implements the `types` and `bytes` interfaces, the `mac`,
//! `aead`, `digest`, and `signature` primitive-kind interfaces (the
//! `mac-key`, `aead-key`, `digest`, `verifying-key`, and `signing-key`
//! resources), and the `hmac-sha2` / `aes-gcm` / `chacha20-poly1305` /
//! `sha2` / `ed25519-verify` / `ed25519-sign` / `ecdsa-verify` /
//! `ecdsa-sign` minting interfaces. See [`crate`] for the public API built
//! on top of these bindings.

#[allow(missing_docs, reason = "generated code")]
mod generated {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "imports",
        imports: {
            // The async WIT functions (key minting, `%export`, `sign`,
            // `verify`, `seal`, `open`, and every resource drop)
            // need all three: `async` for the component-model async ABI,
            // `store` for `Accessor` access to the `ResourceTable` (and the
            // `…WithStore` traits that host the async methods), and
            // `trappable` so the host functions can return `wasmtime::Result`
            // and surface host errors as traps.
            default: async | store | trappable,
            // The synchronous WIT functions are bound synchronously (still
            // `trappable`, but not `async`): the algorithm getters only
            // touch the `ResourceTable`, which the sync `Host` traits reach
            // through the `WasiWebcryptoCtxView` data type.
            "lann:webcrypto/mac@0.1.0.[method]mac-key.algorithm-name": trappable,
            "lann:webcrypto/mac@0.1.0.[method]mac-key.algorithm-hash": trappable,
            "lann:webcrypto/mac@0.1.0.[method]mac-key.algorithm-length": trappable,
            "lann:webcrypto/aead@0.1.0.[method]aead-key.algorithm-name": trappable,
            "lann:webcrypto/aead@0.1.0.[method]aead-key.algorithm-length": trappable,
            "lann:webcrypto/digest@0.1.0.[method]digest.algorithm-name": trappable,
            "lann:webcrypto/sha2@0.1.0.make-digest": trappable,
            "lann:webcrypto/bytes@0.1.0.constant-time-equal": trappable,
            "lann:webcrypto/signature@0.1.0.[method]verifying-key.algorithm-name": trappable,
            "lann:webcrypto/signature@0.1.0.[method]verifying-key.algorithm-curve": trappable,
            "lann:webcrypto/signature@0.1.0.[method]verifying-key.algorithm-hash": trappable,
            "lann:webcrypto/signature@0.1.0.[method]signing-key.algorithm-name": trappable,
            "lann:webcrypto/signature@0.1.0.[method]signing-key.algorithm-curve": trappable,
            "lann:webcrypto/signature@0.1.0.[method]signing-key.algorithm-hash": trappable,
            "lann:webcrypto/signature@0.1.0.[method]signing-key.extractable": trappable,
            "lann:webcrypto/signature@0.1.0.[method]signing-key.verifying-key": trappable,
        },
        with: {
            "lann:webcrypto/mac.mac-key": crate::MacKey,
            "lann:webcrypto/aead.aead-key": crate::AeadKey,
            "lann:webcrypto/digest.digest": crate::Digest,
            "lann:webcrypto/signature.verifying-key": crate::VerifyingKey,
            "lann:webcrypto/signature.signing-key": crate::SigningKey,
        },
    });
}

pub use self::generated::lann::*;
