# `lann:webcrypto`

A WebCrypto-flavored WIT package plus multiple implementations that run the
*same* guest component: a Wasmtime host backed by RustCrypto, a jco host
backed by the browser Web Crypto API, and an in-guest wasm component
(RustCrypto compiled to wasm, composable via `wac plug`). A sibling of
[`lann:webrtc-datachannels`](https://github.com/lann/webrtc-datachannels),
following the same architecture.

## Design

The package ([`wit/`](wit/), documented in
[`wit/README.md`](wit/README.md)) is layered by *primitive kind*, not by
algorithm:

- **Generic primitive interfaces** (`mac`, `aead`,
  `digest`, `signature`, `derivation`, …) each own the
  algorithm-agnostic resources. Adding an algorithm never touches them.
- **Algorithm interfaces** (`hmac-sha2`, `aes-gcm`, `sha2`,
  `ed25519-verify`/`-sign`, …) contain only
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
  Content beyond that contract is out of scope; `open` is never relaxed to
  stream unverified plaintext.
- **Operations are one-shot calls on immutable keys** (`sign`/`verify`,
  `seal`/`open`): there is no stateful computation object to misuse, so the
  `error` variant carries no misuse cases — incrementality comes from the
  streams, not from resource state.
- **`crypto.subtle` fidelity is measured, not assumed.** The
  `webcrypto-componentize` library re-exposes the package as `crypto.subtle`, and
  the vendored WebCryptoAPI web-platform-tests run through it in CI —
  WPT → shim → WIT → implementation — so the platform's own test suite
  meters what the interface shape preserves. Any deviation the shape forced
  would be a recorded ruling, not an accident (the set is currently empty);
  see AGENTS.md, "WPT fidelity is a first-class design constraint".

Current algorithms: **SHA-2** digests, **HMAC** (SHA-2 and SHA-1),
**AES-GCM**, **AES-CBC** and **AES-CTR**, **AES-KW** key wrapping,
**HKDF** and **PBKDF2** (minting `derive-input`s the key-minting
interfaces consume), **X25519** and **ECDH** key agreement, **Ed25519**,
**ECDSA** (P-256 and P-384, each with SHA-256/384/512),
**RSASSA-PKCS1-v1_5** and **RSA-PSS**, and **RSA-OAEP**. Three surfaces
are gated `@unstable` (see [`wit/README.md`](wit/README.md), "Stability
gates"): the collision-detecting `sha1-checked` digest, RSA signing
(`rsa-sign`), and RSA-OAEP decryption (`rsa-oaep-decrypt`). The in-guest
provider withholds the timing-unsafe operations — ECDSA and RSA signing,
both RSA-OAEP halves — while signature *verification* is served
everywhere (see rust/guest-provider/README.md). The
AEAD wire format is `ciphertext ‖ tag` (`crypto.subtle`'s, which
RustCrypto produces identically). The variant enums also declare cases no
implementation here serves (`aes192`, the truncated SHA-2 variants) — each
algorithm's spec closes its set — which fail `unsupported`; a composition
needing one must supply its own provider. The exact per-interface contracts
and the package-wide ones (streaming, key options, errors, extractability)
are specified in [`wit/README.md`](wit/README.md) and the WIT doc comments.

## Layout

```
wit/                    # the lann:webcrypto package (defined once, here)
rust/                   # the Rust crates (dir = crate name minus the
                        #   `lann-webcrypto-` family root)
  core/                 # shared RustCrypto core of both Rust
                        #   implementations; ECDSA signing is compiled out
                        #   of wasm builds
  wasmtime/             # Wasmtime host crate (RustCrypto); add_to_linker +
                        #   WasiWebcryptoView
  guest/                # guest-side Rust library over the lann:webcrypto
                        #   imports: typed wrappers and a byte-source
                        #   abstraction, so consumers need not hand-roll
                        #   stream plumbing
  guest-provider/       # in-guest wasm component: RustCrypto in wasm,
                        #   EXPORTS the package surface, composable via
                        #   `wac plug` — see its README for the wasm
                        #   timing-channel classification & export policy
js/                     # the JS packages (dir = npm name minus the
                        #   `@lann/webcrypto-` family root)
  jco/                  # jco host library: webcrypto.js,
                        #   browser-compatible Web Crypto API only
                        #   (crypto.subtle / getRandomValues); no
                        #   dependencies
  componentize/         # WebCrypto-subset library (crypto.subtle) for JS
                        #   guests built with componentize-js, backed by the
                        #   lann:webcrypto imports; the JS counterpart of
                        #   rust/guest
examples/
  crypto-demo/          # guest component: known-answer vectors, chunked
                        #   streams, error taxonomy, extractability —
                        #   one check per behavior, across the package's
                        #   primitive kinds
  demo-driver/          # CLI driver for the fully in-guest composed demo
  wasmtime-demo/        # thin native host + the integration test
  jco-demo/             # Node 24+ driver: transpiles crypto-demo with jco
                        #   against the webcrypto-jco host and runs it
  componentize-demo/    # JS guest (componentize-js) exercising the
                        #   webcrypto-componentize library; drives through the
                        #   same demo interface and composed pipeline
conformance/            # cross-implementation conformance tests: vendored
                        #   Wycheproof vectors + translation policy, suite
                        #   components on the lann:component-test guest SDK
                        #   (vectors under chunking schedules, plus
                        #   API-contract probes), and its driver/aggregation
                        #   stack rendering driver-ct/matrix.md
timing-lab/             # dudect-style statistical timing tests of the
                        #   composed in-guest provider (non-gating; see its
                        #   README for methodology and detection limits)
experiments/            # quarantined exploratory consumers of the package
                        #   (own workspace, no CI, no stability,
                        #   delete-at-will — see experiments/README.md)
```

Components that name the package in their own WIT pull it in through
`wit/deps/lann-webcrypto` symlinks back to the root `wit/`, so there is a
single copy to edit; guests built on `lann-webcrypto-guest` reach it through that
crate's bindings instead.

## Build & run

Prerequisites: Rust (via rustup; the toolchain and wasm target are pinned in
`rust-toolchain.toml`), `wasm-tools`, and — for the jco host — Node 24+
(jco's async ABI uses JSPI). `./scripts/setup.sh` installs the rest. The
[lann/component-test](https://github.com/lann/component-test) test stack is
an ordinary git dependency pinned by rev in the root `Cargo.toml`
(enforced by `Cargo.lock`); cargo fetches it — no sibling checkout needed.

```sh
just test                    # Rust tests, incl. the guest-under-Wasmtime integration test
just demo::wasmtime          # run the guest under the Wasmtime (RustCrypto) host
just demo::test-node         # transpile and run the same guest under the jco host
just demo::test-composed     # compose guest + in-guest provider + driver (wac plug)
                             #   and run the whole thing under `wasmtime run`
just wpt::test               # the WPT WebCryptoAPI suites against the
                             #   webcrypto-componentize JS guest library, via its
                             #   published runner component (no componentize-js
                             #   toolchain needed — see js/componentize/wpt/)
just componentize::test      # the composed pipeline with the JS demo guest
                             #   (needs the componentize-js CLI — see
                             #   js/componentize/README.md)
just wpt::parity             # the WPT suites against the platform's own
                             #   crypto.subtle and through the jco round trip;
                             #   holds the round trip to the platform's pass set
                             #   (see js/componentize/wpt/README.md)
just wpt::parity-firefox     # the same two legs in headless Firefox against
just wpt::parity-chromium    #   (or Chromium, or WebKit) that engine's own
just wpt::parity-webkit      #   pinned loss set (Playwright engines; gate in
                             #   CI — WebKit on macOS, the mobile-Safari proxy)
just wpt::web                # serve the browser WPT parity page locally: the
                             #   same two legs run live in your browser
just conformance-ct::all     # the Wycheproof-derived conformance tests over the
                             #   enabled targets (component-test stack);
                             #   renders conformance/driver-ct/matrix.md
just timing-lab::run         # dudect-style timing tests of the composed in-guest
                             #   provider (statistical; not part of `just ci`)
just ci                      # everything CI runs
```

All implementations run identical suite components. The conformance
tests (the vendored Wycheproof/CAVP/speccheck vectors — see
[`conformance/vectors/README.md`](conformance/vectors/README.md) — under
multiple stream-chunking schedules, plus API-contract probes) gate the
wasmtime-rustcrypto and jco-node targets everywhere; the
`crypto-demo` guest additionally covers the jco host end to end.

A note on the in-guest provider: wasm offers no portable constant-time
guarantees, so [`rust/guest-provider/README.md`](rust/guest-provider/README.md) classifies
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
