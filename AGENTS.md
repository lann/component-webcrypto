# AGENTS.md

Guidance for automated agents (and humans) working in this repository.

## What this repository is

`lann:webcrypto`: a WIT interface plus multiple implementations that run the
*same* guest component against real cryptography: a Wasmtime host (RustCrypto)
and a jco host (browser Web Crypto API). It is a sibling of
`lann:webrtc-datachannels` and deliberately mirrors its architecture — prefer
clarity and correctness over features, and keep the implementations
behaviourally in sync (the conformance suite and the `crypto-demo` guest's
checks are the cross-implementation gate).
See [`README.md`](README.md) for the design.

Before designing WIT or touching async/stream plumbing, consult
[`lann/wasm-component-starter`](https://github.com/lann/wasm-component-starter)
(especially `OUTLINE.md`) — treat it as a living knowledge base and re-read it
rather than relying on a cached summary.

## Repository layout

```
wit/                    # lann:webcrypto package: types (structural),
                        #   mac/aead (generic primitive resources),
                        #   hmac-sha2/aes-gcm (key-minting algorithm interfaces)
wasmtime-impl/          # Wasmtime host crate, modeled after
                        #   wasmtime_wasi_http::p3; add_to_linker +
                        #   WasiWebcryptoView; crate: wasmtime-webcrypto
jco-impl/               # jco host LIBRARY: webcrypto.js implements the
                        #   imports over the browser-compatible Web Crypto
                        #   API ONLY; no dependencies, no demo code
wasip3-impl/            # wasm COMPONENT: RustCrypto in-guest, EXPORTS the
                        #   package surface; composable via `wac plug`;
                        #   crate: wasip3-webcrypto — see its README for the
                        #   timing-channel classification and export policy
examples/
  crypto-demo/          # guest component exercising mac + aead end to end
    wit/deps/lann-webcrypto -> ../../../wit    # symlink to the root package
  demo-driver/          # CLI driver (async wasi:cli/run) for the composed
                        #   fully in-guest demo
  wasmtime-demo/        # thin native host over wasmtime-impl's add_to_linker
                        #   + the integration test (tests/demo.rs)
  jco-demo/             # Node 24+ driver for the jco host: transpiles
                        #   crypto-demo with jco (the --async-*/--map flags
                        #   live in its package.json) and runs it against
                        #   jco-impl/webcrypto.js
conformance/            # cross-implementation conformance suite — see
                        #   conformance/README.md for its architecture and
                        #   the rationale for how it deliberately diverges
                        #   from the WebRTC sibling's suite
  vectors/              #   vendored Wycheproof JSON + the translation policy
  guest/                #   the shared conformance guest (vectors compiled in)
  adapters/             #   per-target drivers: wasmtime, wasip3-driver (for
                        #     the composed target), jco (Node + browser;
                        #     currently blocked on an upstream jco bug — see
                        #     the `conformance` justfile recipe)
  runner/               #   classifies results against manifests.toml and
                        #     renders conformance/matrix.md
  manifests.toml        #   per-target expectations (policy-driven)
scripts/setup.sh        # one-shot dependency setup (idempotent; used by CI)
```

### WIT is organized by ownership — one copy of the shared package

The **`lann:webcrypto`** package is defined exactly once, at the root
[`wit/`](wit). Components pull it in through `wit/deps/lann-webcrypto`
**symlinks** back to the root. Do not copy the package into a component or
replace those symlinks with real directories.

The layering is a design invariant, not a convention:

- **Generic primitive-kind interfaces** (`mac`, `aead`) own the
  algorithm-agnostic resources. Adding an algorithm must not change them.
- **Algorithm interfaces** (`hmac-sha2`, `aes-gcm`) contain only key minting;
  operations hang off the key resources, which are capabilities (see the WIT
  doc comments for the exact contracts, including extractability and the
  "input streams are fully drained even on error" rule for `seal`/`open`).
- Operations are **one-shot calls on immutable key resources** (`sign`/
  `verify`, `seal`/`open`) — no stateful computation objects — so misuse is
  unrepresentable and the `error` variant carries no misuse cases. Keep it
  that way.

Changing an interface identifier means updating everyone who names it as a
string: the guest bindings (`examples/crypto-demo/src/lib.rs`), the host
bindgen configs (`wasmtime-impl/src/bindings.rs`,
`examples/wasmtime-demo/src/lib.rs`), the wasip3 provider world and bindings
(`wasip3-impl/`), the driver's inline world
(`examples/demo-driver/src/lib.rs`), and the `jco transpile`
`--async-exports`/`--async-imports`/`--map` flags in `examples/jco-demo/package.json`.

### The wasip3 provider's timing-channel policy

`wasip3-impl/README.md` carries the timing-channel classification (classes
A–D) and this provider's policy: only class A–C algorithms are exported,
always via constant-time-variant implementations; class D algorithm
interfaces (RSA private-key ops, ECDSA signing, …) are **never** exported by
the in-guest provider, so compositions requiring them fail at `wac plug`
time. Secret-free operations (hashing public data, signature *verification*)
are exempt from the classes. Keep the classification table in sync when
adding algorithms, and keep class D out of the provider's world.

### The jco host must stay browser-compatible

`jco-impl/webcrypto.js` uses only `globalThis.crypto.subtle` and
`globalThis.crypto.getRandomValues`. No `node:crypto`, no Node-only APIs: the
same file must be loadable in a browser unchanged. Node is just the current
runner (24+ for JSPI).

## Build & run

Prerequisites: Rust via rustup (toolchain + wasm target pinned in
`rust-toolchain.toml`), `wasm-tools`, `just`, and Node 24+ with npm for the
jco path. Run `./scripts/setup.sh` once (idempotent; `SKIP_NODE=1` to skip the
npm install).

The [`justfile`](justfile) is the single entry point; run `just` to list
recipes. `.github/workflows/ci.yml` runs the same recipes.

### Checks to run before committing

Run the recipes that cover what you changed, and fix anything they report.
`just check` is the fast gate; `just ci` mirrors CI exactly.

| Recipe | Run it when you change… |
| --- | --- |
| `just fmt-check` | any Rust source (formatting). |
| `just clippy` | any Rust source (lints the guest on its wasm target too). |
| `just validate-wit` | any `.wit` file. |
| `just test` | any Rust host/guest code (includes the guest-under-Wasmtime integration test). |
| `just build-component` | the `crypto-demo` guest or its WIT. |
| `just test-webcrypto-composed` | the `wasip3-impl` provider, the demo driver, or any WIT (composes guest + provider + driver with `wac plug` and runs under `wasmtime`). |
| `just conformance` | any host/guest behavior the suite asserts — the WIT surface, an implementation, the conformance guest/vectors/translation policy, or manifests. Gates on the wasmtime and wasip3-guest targets; the jco targets are temporarily non-gating (upstream jco runtime bug — run `just conformance-jco-node` to check a fix). |
| `just transpile` | anything affecting the component's interfaces, or the jco flags in `examples/jco-demo/package.json`. |
| `just test-node` | the jco host (`webcrypto.js`) or the component it runs. |
| `just check` | broad Rust/WIT changes — the quick gate for most commits. |
| `just ci` | anything touching the guest, jco host, or WIT. |

Behavioral changes must keep all three implementations in sync: the
conformance suite (`just conformance`) is the gate for the wasmtime and
wasip3-guest targets, and the same guest component must report every check
passing under `just test` (Wasmtime), `just test-node` (jco), and
`just test-webcrypto-composed` (in-guest). The jco conformance targets
rejoin the gate when the upstream jco runtime fix lands (see the
`conformance` recipe); until then `just test-node` is the jco behavioral
gate. When adding behavior, extend the conformance corpus (vectors or
probes), not just the demo guest — an algorithm interface is not done until
its vector suite exists (see conformance/README.md, "Growing the corpus").

## Code comments and docs

Code comments describe **what** something is or does, not the process by which
it was arrived at. Rationale like "we removed X because Y" belongs in commit
messages or PR descriptions, not in source files.

Docs state invariants, not inventories. Never embed values a build or test
run computes — corpus sizes, check counts, probe indexes. If a number
matters, a gate asserts it (e.g. the demo harness's expected-summary check);
if it doesn't, omit it. Machine-derived counts belong only in generated
artifacts like `conformance/matrix.md`.

## Direction (designed, not yet built)

- `digest` primitive kind (mac minus keys) and more algorithms per kind — each
  is a new key-minting interface plus constructors, never a generic change.
  ChaCha20-Poly1305 is the planned next AEAD and the recommended one for the
  in-guest provider (class A + B).
- `stream-aead`: a segmented AEAD primitive kind (libsodium
  `secretstream`-style) for unbounded content with O(segment) memory;
  single-message `aead.open` deliberately buffers-and-verifies and must not be
  relaxed to stream unverified plaintext. Design decisions already settled:
  prefer libsodium's `secretstream_xchacha20poly1305` as the first wire
  format (well-specified, vectors exist, per-segment WebCrypto calls give the
  browser host a path) with an AES-GCM-segmented variant later; segment size
  is a constructor parameter with a sane default (it is on-the-wire — both
  peers must agree); `open` releases each segment only after its tag
  verifies, and truncation/tampering ends the stream with an error.
- A `signature` primitive kind whose `verify` (secret-free — e.g. JWT
  validation) is exportable by the in-guest provider even for algorithms whose
  `sign` is class D.
- A timing lab (dudect-style statistical tests of the composed provider under
  wasmtime, targeting class B/C surfaces) and a cross-implementation
  conformance suite, both following the sibling repository's lab shape.
- A FIPS 140-3 profile, kept *possible* (not implemented): everything needed
  is additive — an internal-nonce seal (`seal-internal-nonce`, since SP
  800-38D forbids externally supplied GCM encryption IVs in approved mode; a
  FIPS provider offers caller-nonce `seal` only as a non-approved service), a
  `module` interface for ISO 19790's mandatory services (show version, show
  status, self-test, zeroization) plus approved-service indication, and
  wrapped key export. Do not reintroduce WIT contracts that *mandate*
  non-approved behavior (the HMAC import doc deliberately permits
  policy-based rejection of short keys for this reason); a FIPS profile is
  then just a provider exporting only approved algorithm interfaces —
  enforced at `wac plug` time like the timing-channel class D policy.
