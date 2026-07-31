//! Raw `bindgen!` output for the `lann:webcrypto` package.
//!
//! The crate implements the full package surface — every interface the
//! `imports` world below names. See [`crate`] for the public API built on
//! top of these bindings.

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
            "lann:webcrypto/mac@0.1.0.[method]mac-key.extractable": trappable,
            "lann:webcrypto/mac@0.1.0.[method]mac-key.can-sign": trappable,
            "lann:webcrypto/mac@0.1.0.[method]mac-key.can-verify": trappable,
            "lann:webcrypto/mac@0.1.0.[constructor]mac-key-options": trappable,
            "lann:webcrypto/mac@0.1.0.[method]mac-key-options.can-sign": trappable,
            "lann:webcrypto/mac@0.1.0.[method]mac-key-options.can-verify": trappable,
            "lann:webcrypto/mac@0.1.0.[method]mac-key-options.extractable": trappable,
            "lann:webcrypto/aead@0.1.0.[method]aead-key.algorithm-name": trappable,
            "lann:webcrypto/aead@0.1.0.[method]aead-key.algorithm-length": trappable,
            "lann:webcrypto/aead@0.1.0.[method]aead-key.nonce-size": trappable,
            "lann:webcrypto/aead@0.1.0.[method]aead-key.tag-size": trappable,
            "lann:webcrypto/aead@0.1.0.[method]aead-key.extractable": trappable,
            "lann:webcrypto/aead@0.1.0.[method]aead-key.can-seal": trappable,
            "lann:webcrypto/aead@0.1.0.[method]aead-key.can-open": trappable,
            "lann:webcrypto/aead@0.1.0.[method]aead-key.can-wrap": trappable,
            "lann:webcrypto/aead@0.1.0.[method]aead-key.can-unwrap": trappable,
            "lann:webcrypto/aead@0.1.0.[constructor]aead-key-options": trappable,
            "lann:webcrypto/aead@0.1.0.[method]aead-key-options.can-seal": trappable,
            "lann:webcrypto/aead@0.1.0.[method]aead-key-options.can-open": trappable,
            "lann:webcrypto/aead@0.1.0.[method]aead-key-options.can-wrap": trappable,
            "lann:webcrypto/aead@0.1.0.[method]aead-key-options.can-unwrap": trappable,
            "lann:webcrypto/aead@0.1.0.[method]aead-key-options.extractable": trappable,
            "lann:webcrypto/aead-internal-nonce@0.1.0.[method]internal-nonce-key.algorithm-name": trappable,
            "lann:webcrypto/aead-internal-nonce@0.1.0.[method]internal-nonce-key.algorithm-length": trappable,
            "lann:webcrypto/aead-internal-nonce@0.1.0.[method]internal-nonce-key.seals-remaining": trappable,
            "lann:webcrypto/aead-internal-nonce@0.1.0.[method]internal-nonce-key.extractable": trappable,
            "lann:webcrypto/aead-internal-nonce@0.1.0.[method]internal-nonce-key.can-seal": trappable,
            "lann:webcrypto/aead-internal-nonce@0.1.0.[method]internal-nonce-key.can-open": trappable,
            "lann:webcrypto/aead-internal-nonce@0.1.0.[constructor]internal-nonce-key-options": trappable,
            "lann:webcrypto/aead-internal-nonce@0.1.0.[method]internal-nonce-key-options.can-seal": trappable,
            "lann:webcrypto/aead-internal-nonce@0.1.0.[method]internal-nonce-key-options.can-open": trappable,
            "lann:webcrypto/aead-internal-nonce@0.1.0.[method]internal-nonce-key-options.extractable": trappable,
            "lann:webcrypto/derivation@0.1.0.[constructor]derive-options": trappable,
            "lann:webcrypto/derivation@0.1.0.[method]derive-options.can-derive-bits": trappable,
            "lann:webcrypto/derivation@0.1.0.[method]derive-options.can-derive-key": trappable,
            "lann:webcrypto/derivation@0.1.0.[method]derive-input.can-derive-bits": trappable,
            "lann:webcrypto/derivation@0.1.0.[method]derive-input.can-derive-key": trappable,
            "lann:webcrypto/key-agreement@0.1.0.[constructor]agreement-key-options": trappable,
            "lann:webcrypto/key-agreement@0.1.0.[method]agreement-key-options.can-derive-bits": trappable,
            "lann:webcrypto/key-agreement@0.1.0.[method]agreement-key-options.can-derive-key": trappable,
            "lann:webcrypto/key-agreement@0.1.0.[method]agreement-key-options.extractable": trappable,
            "lann:webcrypto/key-agreement@0.1.0.[method]public-key.algorithm-name": trappable,
            "lann:webcrypto/key-agreement@0.1.0.[method]secret-key.algorithm-name": trappable,
            "lann:webcrypto/key-agreement@0.1.0.[method]secret-key.can-derive-bits": trappable,
            "lann:webcrypto/key-agreement@0.1.0.[method]secret-key.can-derive-key": trappable,
            "lann:webcrypto/key-agreement@0.1.0.[method]secret-key.extractable": trappable,
            "lann:webcrypto/hkdf@0.1.0.[method]ikm.can-derive-bits": trappable,
            "lann:webcrypto/hkdf@0.1.0.[method]ikm.can-derive-key": trappable,
            "lann:webcrypto/pbkdf2@0.1.0.[method]password.can-derive-bits": trappable,
            "lann:webcrypto/pbkdf2@0.1.0.[method]password.can-derive-key": trappable,
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
            "lann:webcrypto/signature@0.1.0.[method]signing-key.can-sign": trappable,
            "lann:webcrypto/signature@0.1.0.[constructor]signing-key-options": trappable,
            "lann:webcrypto/signature@0.1.0.[method]signing-key-options.can-sign": trappable,
            "lann:webcrypto/signature@0.1.0.[method]signing-key-options.extractable": trappable,
        },
        with: {
            "lann:webcrypto/mac.mac-key": crate::MacKey,
            "lann:webcrypto/mac.mac-key-options": crate::MacKeyOptions,
            "lann:webcrypto/derivation.derive-options": crate::DeriveOptions,
            "lann:webcrypto/derivation.derive-input": crate::DeriveInput,
            "lann:webcrypto/hkdf.ikm": crate::Ikm,
            "lann:webcrypto/pbkdf2.password": crate::Password,
            "lann:webcrypto/key-agreement.agreement-key-options": crate::AgreementKeyOptions,
            "lann:webcrypto/key-agreement.public-key": crate::AgreementPublicKey,
            "lann:webcrypto/key-agreement.secret-key": crate::AgreementSecretKey,
            "lann:webcrypto/aead.aead-key-options": crate::AeadKeyOptions,
            "lann:webcrypto/aead-internal-nonce.internal-nonce-key-options": crate::InternalNonceKeyOptions,
            "lann:webcrypto/signature.signing-key-options": crate::SigningKeyOptions,
            "lann:webcrypto/aead.aead-key": crate::AeadKey,
            "lann:webcrypto/aead-internal-nonce.internal-nonce-key": crate::InternalNonceKey,
            "lann:webcrypto/digest.digest": crate::Digest,
            "lann:webcrypto/signature.verifying-key": crate::VerifyingKey,
            "lann:webcrypto/signature.signing-key": crate::SigningKey,
        },
    });
}

pub use self::generated::lann::*;
