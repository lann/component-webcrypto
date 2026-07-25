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

- **Generic primitive interfaces** (`mac`, `aead`; later `digest`,
  `stream-aead`, …) each own the algorithm-agnostic resources. Adding an
  algorithm never touches them.
- **Algorithm interfaces** (`hmac`, `aes-gcm`) contain only *key minting*
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
- **Consuming statics** (`finalize`/`verify` take `this`) make
  use-after-finalize unrepresentable rather than a runtime error.

Current algorithms: **HMAC-SHA-256** and **AES-256-GCM** (12-byte nonces,
16-byte tags, `ciphertext ‖ tag` — the `crypto.subtle` wire format, which
RustCrypto's `aes-gcm` produces identically).

## Layout

```
wit/                    # the lann:webcrypto package (defined once, here)
wasmtime-impl/          # Wasmtime host crate (RustCrypto); add_to_linker +
                        #   WasiWebcryptoView; crate: wasmtime-webcrypto
jco-impl/               # jco host (Node 24+), browser-compatible Web Crypto
                        #   API only (crypto.subtle / getRandomValues)
wasip3-impl/            # in-guest wasm component: RustCrypto in wasm,
                        #   EXPORTS the package surface, composable via
                        #   `wac plug` — see its README for the wasm
                        #   timing-channel classification & export policy
examples/
  crypto-demo/          # guest component: RFC 4231 + NIST GCM known-answer
                        #   vectors, chunked streams, error taxonomy,
                        #   extractability — 13 checks, one per behavior
  demo-driver/          # CLI driver for the fully in-guest composed demo
  wasmtime-demo/        # thin native host + the integration test
conformance/            # cross-implementation conformance suite: vendored
                        #   Wycheproof vectors + translation policy, a shared
                        #   conformance guest (584 tests incl. chunking
                        #   schedules and API-contract probes), per-target
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
suite (584 tests: Wycheproof HMAC-SHA-256 and AES-GCM vectors under multiple
stream-chunking schedules, plus API-contract probes) gates the wasmtime and
wasip3-guest targets; the 13-check `crypto-demo` additionally covers the jco
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
  during async event delivery — while the *identical* guest binary runs all
  584 tests clean under Wasmtime, both natively and fully composed. The
  trigger involves many drain-input-then-reject stream operations followed
  by async imports returning `result<list<u8>>`; failure is deterministic
  per corpus window but layout-dependent (a superset window can pass while
  its subset fails), i.e. the corruption is planted silently and detonates
  elsewhere. The jco conformance targets are non-gating until the upstream
  fix lands (see the `conformance` justfile recipe); the diagnosis and
  bisection log live with the jco checkout (`GUEST-HEAP-CORRUPTION-DEBUG.md`).
- **Streams-only interfaces make delivery schedules part of the contract.**
  Running every vector under multiple chunking schedules (whole / 1-byte /
  block-straddling / split-absorb) tests a claim a buffer-based API could
  never even express — and precisely this corpus shape is what surfaced the
  runtime bug above.
