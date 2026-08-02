//! `lann-webcrypto-guest-provider`: a wasm **component** that runs RustCrypto *in-guest*
//! and exports the `lann:webcrypto` package surface.
//!
//! This is the third implementation alongside the `lann-webcrypto-wasmtime` (RustCrypto,
//! native) and `webcrypto-jco` (browser Web Crypto) hosts. Unlike those two — which
//! satisfy the guest's imports host-side — this one is itself a component: the
//! cryptography runs entirely inside wasm, and key generation draws on the
//! WASI random imports the standard library links in.
//!
//! Because it exports the package surface and needs no crypto capability from
//! the host, it can be composed (`wac plug`) with any consumer component that
//! imports these interfaces, producing a single self-contained component — the
//! `just test-webcrypto-composed` recipe plugs it under the `crypto-demo`
//! guest and runs the result under the `wasmtime` CLI.
//!
//! The exported resources live in the [`provider`] module.

wit_bindgen::generate!({
    path: "wit",
    world: "provider",
    features: ["chacha20-poly1305", "xchacha20-poly1305", "sha1-checked"],
    generate_all,
});

mod buffer;
mod provider;

use provider::Component;
export!(Component);
