# AGENTS.md

Guidance for automated agents (and humans) working in this repository.

## What this repository is

`lann:webcrypto`: a WIT interface plus multiple implementations that run the
*same* guest component against real cryptography: a Wasmtime host (RustCrypto)
and a jco host (browser Web Crypto API). It is a sibling of
`lann:webrtc-datachannels` and deliberately mirrors its architecture — prefer
clarity and correctness over features, and keep the implementations
behaviourally in sync (the `crypto-demo` guest's 13 checks are the current
cross-implementation gate; a conformance suite is planned but not yet built).
See [`README.md`](README.md) for the design.

Before designing WIT or touching async/stream plumbing, consult
[`lann/wasm-component-starter`](https://github.com/lann/wasm-component-starter)
(especially `OUTLINE.md`) — treat it as a living knowledge base and re-read it
rather than relying on a cached summary.

## Repository layout

```
wit/                    # lann:webcrypto package: types (structural),
                        #   mac/aead (generic primitive resources),
                        #   hmac/aes-gcm (key-minting algorithm interfaces)
wasmtime-impl/          # Wasmtime host crate, modeled after
                        #   wasmtime_wasi_http::p3; add_to_linker +
                        #   WasiWebcryptoView; crate: wasmtime-webcrypto
jco-impl/               # jco host: webcrypto.js implements the imports over
                        #   the browser-compatible Web Crypto API ONLY
examples/
  crypto-demo/          # guest component exercising mac + aead end to end
    wit/deps/lann-webcrypto -> ../../../wit    # symlink to the root package
  wasmtime-demo/        # thin native host over wasmtime-impl's add_to_linker
                        #   + the integration test (tests/demo.rs)
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
- **Algorithm interfaces** (`hmac`, `aes-gcm`) contain only key minting;
  operations hang off the key resources, which are capabilities (see the WIT
  doc comments for the exact contracts, including extractability and the
  "input streams are fully drained even on error" rule for `seal`/`open`).
- `finalize`/`verify` are consuming statics: misuse is unrepresentable, so the
  `error` variant carries no misuse cases. Keep it that way.

Changing an interface identifier means updating everyone who names it as a
string: the guest bindings (`examples/crypto-demo/src/lib.rs`), the host
bindgen configs (`wasmtime-impl/src/bindings.rs`,
`examples/wasmtime-demo/src/lib.rs`), and the `jco transpile`
`--async-exports`/`--async-imports`/`--map` flags in `jco-impl/package.json`.

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
| `just transpile` | anything affecting the component's interfaces, or the jco flags in `jco-impl/package.json`. |
| `just test-node` | the jco host (`webcrypto.js`) or the component it runs. |
| `just check` | broad Rust/WIT changes — the quick gate for most commits. |
| `just ci` | anything touching the guest, jco host, or WIT. |

Behavioral changes must keep both hosts in sync: the same guest component must
report the same `13 checks passed` under `just test` (Wasmtime) and
`just test-node` (jco). When adding behavior, extend the guest's checks — it
is the cross-implementation gate until a conformance suite exists.

## Code comments

Code comments describe **what** something is or does, not the process by which
it was arrived at. Rationale like "we removed X because Y" belongs in commit
messages or PR descriptions, not in source files.

## Direction (designed, not yet built)

- `digest` primitive kind (mac minus keys) and more algorithms per kind — each
  is a new key-minting interface plus constructors, never a generic change.
- `stream-aead`: a segmented AEAD primitive kind (libsodium
  `secretstream`-style) for unbounded content with O(segment) memory;
  single-message `aead.open` deliberately buffers-and-verifies and must not be
  relaxed to stream unverified plaintext.
- A `wasip3-impl` in-guest provider component (RustCrypto compiled to wasm,
  exporting the package surface, composable via `wac plug`) and a
  cross-implementation conformance suite, both following the sibling
  repository's shape.
