//! Raw `bindgen!` output for the `lann:webcrypto` package.
//!
//! The crate implements the `types` interface, the `mac` interface (the
//! `mac-key` resource), the `aead` interface (the `aead-key` resource), and
//! the `hmac-sha2` / `aes-gcm` key-minting interfaces. See [`crate`] for the
//! public API built on top of these bindings.

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
        },
        with: {
            "lann:webcrypto/mac.mac-key": crate::MacKey,
            "lann:webcrypto/aead.aead-key": crate::AeadKey,
        },
    });
}

pub use self::generated::lann::*;
