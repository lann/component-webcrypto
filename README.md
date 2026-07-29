# `lann:webcrypto`

A WebCrypto-flavored WIT package plus multiple implementations that run the
*same* guest component: a Wasmtime host backed by RustCrypto, a jco host
backed by the browser Web Crypto API, and an in-guest wasm component
(RustCrypto compiled to wasm, composable via `wac plug`). A sibling of
[`lann:webrtc-datachannels`](https://github.com/lann/webrtc-datachannels),
following the same architecture.

## Design

The package ([`wit/webcrypto.wit`](wit/webcrypto.wit)) is layered by *primitive
kind*, not by algorithm:

- **Generic primitive interfaces** (`mac`, `aead`, `digest`, `signature`;
  later `stream-aead`, …) each own the algorithm-agnostic resources. Adding
  an algorithm never touches them.
- **Algorithm interfaces** (`hmac-sha2`, `aes-gcm`, `chacha20-poly1305`,
  `sha2`, `ed25519-verify`/`-sign`, `ecdsa-verify`/`-sign`) contain only
  *key minting* (`import-*`/`generate-*`). Everything else hangs off the key
  resource, so a key can never be used with the wrong algorithm. Signature
  minting splits the public and private halves into separate interfaces, so
  a provider can serve verification for an algorithm whose signing it
  declines to host. A signing key cannot yield its public half — the public
  key comes from `generate-key`, which returns the pair, or from
  `import-verifying-key` — so keys a provider can only *use* (an unspecified
  platform import path, a keystore-resident non-extractable key) remain
  representable.
- **Keys are resources — capabilities.** A world importing only `mac` can use
  key handles it is granted but cannot mint keys; only a world importing
  `hmac` can. `extractable: false` keys refuse `export-key`; on the jco host
  that flag is the platform `CryptoKey`'s own, so the platform enforces it.
  Every gated key resource also reports its `extractable` flag as a getter, so
  a holder can ask the question without taking the answer — and because a key
  resource need not have been minted by the component holding it. Export is
  fallible even where no gate applies: a provider may hold a key as a handle
  it can *use* but not *read*.
- **Byte `stream`s are the only bulk data path** (no buffer-taking `update`
  functions), so implementations have exactly one ingestion path and results
  are chunking-invariant. On Wasmtime the host consumes bytes directly from
  guest memory (`StreamConsumer`); between composed components a stream write
  is a direct memory-to-memory copy.
- **`aead` is honest about being a single-message primitive**: `open` resolves
  only after the whole ciphertext is drained and verified — `ok(stream)` *is*
  the authentication statement, and unverified plaintext is never observable.
  The returned stream still lets plaintext live outside the caller's linear
  memory (the practical ceiling moves from wasm32's 4 GiB to host RAM).
  Truly unbounded content belongs to a future segmented `stream-aead`
  primitive kind (libsodium-`secretstream`-style), not to a relaxation of
  `open`.
- **Operations are one-shot calls on immutable keys** (`sign`/`verify`,
  `seal`/`open`): there is no stateful computation object to misuse, so the
  `error` variant carries no misuse cases — incrementality comes from the
  streams, not from resource state.
- **`crypto.subtle` fidelity is measured, not assumed.** The
  `componentize-sdk` library re-exposes the package as `crypto.subtle`, and
  the vendored WebCryptoAPI web-platform-tests run through it in CI —
  WPT → shim → WIT → implementation — so the platform's own test suite
  meters what the interface shape preserves. Where the shape deliberately
  deviates (the AES-GCM nonce contract), the deviation is a recorded
  ruling, not an accident; see AGENTS.md, "WPT fidelity is a first-class
  design constraint".

Current algorithms: **SHA-2 digests** (SHA-256/384/512), **HMAC-SHA-2**
(SHA-256/384/512), **AES-GCM** (128/256-bit keys, 12-byte nonces), and
**ChaCha20-Poly1305** (both the RFC 8439 construction and XChaCha20-Poly1305
with 24-byte nonces; browsers implement neither, so the jco host declines
them) — the AEADs share 16-byte tags and the `ciphertext ‖ tag` wire format
(`crypto.subtle`'s, which RustCrypto produces identically) — plus
**Ed25519** and **ECDSA** (P-256/SHA-256, P-384/SHA-384; fixed-width
`r ‖ s` signatures, WebCrypto's format; the in-guest provider serves ECDSA
*verification only* — signing is class D) and the
`bytes.constant-time-equal` utility. The variant enums also declare cases no
implementation here serves (`aes192`, the truncated SHA-2 variants) — each
algorithm's spec closes its set — which fail `unsupported`; a composition
needing one must supply its own provider.

## Layout

```
wit/                    # the lann:webcrypto package (defined once, here)
impl-core/              # shared RustCrypto core of both Rust
                        #   implementations (crate: webcrypto-impl-core);
                        #   ECDSA signing is compiled out of wasm builds
wasmtime-impl/          # Wasmtime host crate (RustCrypto); add_to_linker +
                        #   WasiWebcryptoView; crate: wasmtime-webcrypto
jco-impl/               # jco host library: webcrypto.js, browser-compatible
                        #   Web Crypto API only (crypto.subtle /
                        #   getRandomValues); no dependencies
guest-impl/            # in-guest wasm component: RustCrypto in wasm,
                        #   EXPORTS the package surface, composable via
                        #   `wac plug` — see its README for the wasm
                        #   timing-channel classification & export policy
guest-sdk/              # guest-side Rust library over the lann:webcrypto
                        #   imports (crate: lann-webcrypto-guest): typed
                        #   wrappers and a byte-source abstraction, so
                        #   consumers need not hand-roll stream plumbing
componentize-sdk/       # WebCrypto-subset library (crypto.subtle) for JS
                        #   guests built with componentize-js, backed by the
                        #   lann:webcrypto imports; the JS counterpart of
                        #   guest-sdk
examples/
  crypto-demo/          # guest component: RFC 4231 + NIST GCM known-answer
                        #   vectors, chunked streams, error taxonomy,
                        #   extractability — one check per behavior
  demo-driver/          # CLI driver for the fully in-guest composed demo
  wasmtime-demo/        # thin native host + the integration test
  jco-demo/             # Node 24+ driver: transpiles crypto-demo with jco
                        #   against the jco-impl host and runs it
  componentize-demo/    # JS guest (componentize-js) exercising the
                        #   componentize-sdk library; drives through the
                        #   same demo interface and composed pipeline
conformance/            # cross-implementation conformance tests: vendored
                        #   Wycheproof vectors + translation policy, a shared
                        #   conformance guest (vectors under chunking
                        #   schedules, plus API-contract probes), per-target
                        #   adapters, and a runner rendering matrix.md
timing-lab/             # dudect-style statistical timing tests of the
                        #   composed in-guest provider (non-gating; see its
                        #   README for methodology and detection limits)
```

Demo components pull the shared package in through `wit/deps/lann-webcrypto`
symlinks back to the root `wit/`, so there is a single copy to edit.

## Build & run

Prerequisites: Rust (via rustup; the toolchain and wasm target are pinned in
`rust-toolchain.toml`), `wasm-tools`, and — for the jco host — Node 24+ (jco's
async ABI uses JSPI). `./scripts/setup.sh` installs the rest.

```sh
just test                    # Rust tests, incl. the guest-under-Wasmtime integration test
just demo-wasmtime           # run the guest under the Wasmtime (RustCrypto) host
just test-node               # transpile and run the same guest under the jco host
just test-webcrypto-composed # compose guest + in-guest provider + driver (wac plug)
                             #   and run the whole thing under `wasmtime run`
just test-webcrypto-componentize-wpt # the WPT WebCryptoAPI suites against the
                             #   componentize-sdk JS guest library, via its
                             #   published runner component (no componentize-js
                             #   toolchain needed — see componentize-sdk/wpt/)
just test-webcrypto-componentize # the composed pipeline with the JS demo guest
                             #   (needs the componentize-js CLI — see
                             #   componentize-sdk/README.md)
just wpt-parity              # the WPT suites against the platform's own
                             #   crypto.subtle and through the jco round trip;
                             #   holds the round trip to the platform's pass set
                             #   (see componentize-sdk/wpt/README.md)
just conformance             # the Wycheproof-derived conformance tests over the
                             #   enabled targets; renders conformance/matrix.md
just conformance-web         # serve the conformance results viewer locally
                             #   (published with the public crates' rustdoc at
                             #   https://lann.github.io/component-webcrypto/)
just timing-lab              # dudect-style timing tests of the composed in-guest
                             #   provider (statistical; not part of `just ci`)
just ci                      # everything CI runs
```

All three implementations run identical guest components. The conformance
tests (Wycheproof HMAC-SHA-256, AES-GCM, and ChaCha20-Poly1305 vectors and
NIST CAVP SHA-2 vectors under multiple stream-chunking schedules, plus
API-contract probes) gate the wasmtime, composed, and jco-node
targets everywhere, and the jco-browser target in CI (locally, opt in
with `CONFORMANCE_BROWSER=1`; needs Chrome/Chromium 137+); the
`crypto-demo` guest additionally covers the jco host end to end.

A note on the in-guest provider: wasm offers no portable constant-time
guarantees, so [`guest-impl/README.md`](guest-impl/README.md) classifies
algorithms by how exploitable their timing channels are in wasm (classes A–D)
and enforces the policy structurally — class D algorithms (e.g. RSA
private-key ops) are simply never exported by it, so compositions that need
them fail at `wac plug` time instead of running quietly degraded.

## Findings

- **jco component-model-async guest-heap corruption.** Running the full
  shared conformance suite in one instance under jco (JSPI, Node 24) corrupts the
  guest's heap — surfacing as `memory access out of bounds` in dlmalloc
  during async event delivery — while the *identical* guest binary runs the
  full suite clean under Wasmtime, both natively and fully composed. The
  trigger involves many drain-input-then-reject stream operations followed
  by async imports returning `result<list<u8>>`; failure is deterministic
  per case window but layout-dependent (a superset window can pass while
  its subset fails), i.e. the corruption is planted silently and detonates
  elsewhere. Diagnosed here, fixed upstream (jco #1768, released in 1.26.0);
  the jco-node conformance target gates again since the fix.
- **Streams-only interfaces make delivery schedules part of the contract.**
  Running every vector under multiple chunking schedules (whole / 1-byte /
  block-straddling) tests a claim a buffer-based API could
  never even express — and precisely this suite shape is what surfaced the
  runtime bug above.
