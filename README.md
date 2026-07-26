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

- **Generic primitive interfaces** (`mac`, `aead`, `digest`; later
  `stream-aead`, …) each own the algorithm-agnostic resources. Adding an
  algorithm never touches them.
- **Algorithm interfaces** (`hmac-sha2`, `aes-gcm`, `chacha20-poly1305`,
  `sha2`) contain only *key minting*
  (`import-*`/`generate-*`). Everything else hangs off the key resource, so a
  key can never be used with the wrong algorithm.
- **Keys are resources — capabilities.** A world importing only `mac` can use
  key handles it is granted but cannot mint keys; only a world importing
  `hmac` can. `extractable: false` keys refuse `export` (on the jco host the
  platform `CryptoKey` itself enforces this).
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

Current algorithms: **SHA-2 digests** (SHA-256/384/512), **HMAC-SHA-2**
(SHA-256/384/512), **AES-GCM** (128/256-bit keys, 12-byte nonces), and
**ChaCha20-Poly1305** (both the RFC 8439 construction and XChaCha20-Poly1305
with 24-byte nonces; browsers implement neither, so the jco host declines
them) — the AEADs share 16-byte tags and the `ciphertext ‖ tag` wire format
(`crypto.subtle`'s, which RustCrypto produces identically) — plus the
`bytes.constant-time-equal` utility. The variant enums also declare cases no
implementation here serves (`aes192`, the truncated SHA-2 variants) — each
algorithm's spec closes its set — which fail `unsupported`; a composition
needing one must supply its own provider.

## Layout

```
wit/                    # the lann:webcrypto package (defined once, here)
wasmtime-impl/          # Wasmtime host crate (RustCrypto); add_to_linker +
                        #   WasiWebcryptoView; crate: wasmtime-webcrypto
jco-impl/               # jco host library: webcrypto.js, browser-compatible
                        #   Web Crypto API only (crypto.subtle /
                        #   getRandomValues); no dependencies
wasip3-impl/            # in-guest wasm component: RustCrypto in wasm,
                        #   EXPORTS the package surface, composable via
                        #   `wac plug` — see its README for the wasm
                        #   timing-channel classification & export policy
examples/
  crypto-demo/          # guest component: RFC 4231 + NIST GCM known-answer
                        #   vectors, chunked streams, error taxonomy,
                        #   extractability — one check per behavior
  demo-driver/          # CLI driver for the fully in-guest composed demo
  wasmtime-demo/        # thin native host + the integration test
  jco-demo/             # Node 24+ driver: transpiles crypto-demo with jco
                        #   against the jco-impl host and runs it
conformance/            # cross-implementation conformance suite: vendored
                        #   Wycheproof vectors + translation policy, a shared
                        #   conformance guest (vectors under chunking
                        #   schedules, plus API-contract probes), per-target
                        #   adapters, and a runner rendering matrix.md
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
just conformance             # the Wycheproof-derived conformance corpus over the
                             #   enabled targets; renders conformance/matrix.md
just ci                      # everything CI runs
```

All three implementations run identical guest components. The conformance
suite (Wycheproof HMAC-SHA-256, AES-GCM, and ChaCha20-Poly1305 vectors and
NIST CAVP SHA-2 vectors under multiple stream-chunking schedules, plus
API-contract probes) gates the wasmtime and
wasip3-guest targets; the `crypto-demo` guest additionally covers the jco
host end to end.

A note on the in-guest provider: wasm offers no portable constant-time
guarantees, so [`wasip3-impl/README.md`](wasip3-impl/README.md) classifies
algorithms by how exploitable their timing channels are in wasm (classes A–D)
and enforces the policy structurally — class D algorithms (e.g. RSA
private-key ops) are simply never exported by it, so compositions that need
them fail at `wac plug` time instead of running quietly degraded.

## Findings

- **jco component-model-async guest-heap corruption.** Running the full
  conformance corpus in one instance under jco (JSPI, Node 24) corrupts the
  guest's heap — surfacing as `memory access out of bounds` in dlmalloc
  during async event delivery — while the *identical* guest binary runs the
  full corpus clean under Wasmtime, both natively and fully composed. The
  trigger involves many drain-input-then-reject stream operations followed
  by async imports returning `result<list<u8>>`; failure is deterministic
  per corpus window but layout-dependent (a superset window can pass while
  its subset fails), i.e. the corruption is planted silently and detonates
  elsewhere. The jco conformance targets are non-gating until the upstream
  fix lands (see the `conformance` justfile recipe); the diagnosis and
  bisection log live with the jco checkout (`GUEST-HEAP-CORRUPTION-DEBUG.md`).
- **Streams-only interfaces make delivery schedules part of the contract.**
  Running every vector under multiple chunking schedules (whole / 1-byte /
  block-straddling) tests a claim a buffer-based API could
  never even express — and precisely this corpus shape is what surfaced the
  runtime bug above.
