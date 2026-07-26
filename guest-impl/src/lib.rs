//! `guest-webcrypto`: a wasm **component** that runs RustCrypto *in-guest*
//! and exports the `lann:webcrypto` package surface.
//!
//! This is the third implementation alongside the `wasmtime-impl` (RustCrypto,
//! native) and `jco-impl` (browser Web Crypto) hosts. Unlike those two — which
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
    generate_all,
});

mod provider;

use provider::Component;
export!(Component);
