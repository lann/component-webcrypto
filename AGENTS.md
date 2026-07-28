# AGENTS.md

Guidance for automated agents (and humans) working in this repository.

## What this repository is

`lann:webcrypto`: a WIT interface plus multiple implementations that run the
*same* guest component against real cryptography: a Wasmtime host (RustCrypto)
and a jco host (browser Web Crypto API). It is a sibling of
`lann:webrtc-datachannels` and deliberately mirrors its architecture — prefer
clarity and correctness over features, and keep the implementations
behaviourally in sync (the conformance tests and the `crypto-demo` guest's
checks are the cross-implementation gate).
See [`README.md`](README.md) for the design.

Before designing WIT or touching async/stream plumbing, consult
[`lann/wasm-component-starter`](https://github.com/lann/wasm-component-starter)
(especially `OUTLINE.md`) — treat it as a living knowledge base and re-read it
rather than relying on a cached summary.

## Repository layout

```
wit/                    # the lann:webcrypto package, one file per layer:
                        #   webcrypto.wit holds the stable layer (structural
                        #   types, the generic primitive kinds, bytes);
                        #   family files (aes/chacha/sha2/hmac/ed25519/
                        #   ecdsa.wit) hold the minting interfaces and grow
                        #   as algorithms are added
impl-core/              # the shared RustCrypto core of both Rust
                        #   implementations: cipher/digest dispatch, key
                        #   validation and generation, error rendering, the
                        #   internal-nonce wire format, signature keys (ECDSA
                        #   signing is compiled out of wasm builds — class D);
                        #   crate: webcrypto-impl-core
wasmtime-impl/          # Wasmtime host crate, modeled after
                        #   wasmtime_wasi_http::p3; add_to_linker +
                        #   WasiWebcryptoView; crate: wasmtime-webcrypto
jco-impl/               # jco host LIBRARY: webcrypto.js implements the
                        #   imports over the browser-compatible Web Crypto
                        #   API ONLY; no dependencies, no demo code
guest-impl/            # wasm COMPONENT: RustCrypto in-guest, EXPORTS the
                        #   package surface; composable via `wac plug`;
                        #   crate: guest-webcrypto — see its README for the
                        #   timing-channel classification and export policy
guest-sdk/              # guest-side Rust library over the lann:webcrypto
                        #   imports: typed wrappers with a byte-source
                        #   abstraction, so consumers do not re-implement
                        #   the feed-a-stream-and-await plumbing; the Rust
                        #   counterpart of componentize-sdk;
                        #   crate: lann-webcrypto-guest
componentize-sdk/       # JS guest library for componentize-js (dicej's
                        #   ComponentizeJS reboot): webcrypto.js exposes a
                        #   crypto.subtle subset (HMAC-SHA-256 + AES-256-GCM,
                        #   raw keys) over the lann:webcrypto imports; the
                        #   toolchain revision is pinned in
                        #   componentize-js.rev; wpt/ vendors the
                        #   WebCryptoAPI web-platform-tests and gates in CI,
                        #   componentizing its runner from the tree with a
                        #   digest-pinned componentize-js build
                        #   (wpt/component.sh, componentize-js.sha256); the
                        #   run's census is pinned by wpt/expected.js
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
  componentize-demo/    # JS guest (componentize-js) exercising the
                        #   componentize-sdk library; exports the same demo
                        #   interface as crypto-demo, composed and run via
                        #   `just test-webcrypto-componentize` (not in ci)
conformance/            # cross-implementation conformance tests — see
                        #   conformance/README.md for its architecture and
                        #   the rationale for how it deliberately diverges
                        #   from the WebRTC sibling's machinery
  vectors/              #   vendored Wycheproof JSON + the translation
                        #     policy; its README records the upstream
                        #     revision each file came from
  harness/              #   the world-independent half of both guests:
                        #     probe table, error rendering, feature
                        #     validation (crate: conformance-harness)
  guest/                #   the shared conformance guest (vectors compiled
                        #     in; self-describing cases with feature tags,
                        #     pinned by its tests.lock)
  signing-guest/        #   host-only guest for surfaces the in-guest
                        #     provider does not export (ecdsa-sign)
  adapters/             #   per-target drivers: wasmtime, composed-driver (for
                        #     the composed target), jco (Node gates everywhere;
                        #     the browser target gates in CI, locally opt-in
                        #     via CONFORMANCE_BROWSER=1 with Chrome installed)
                        #     — jco reads its missing-features from targets.toml
  runner/               #   aggregates results: validates them against
                        #     targets.toml + the suite lockfiles, renders
                        #     conformance/matrix.md + the viewer data
  web/                  #   results viewer: static page (collapsing
                        #     cross-target tree + a live "test this
                        #     browser" run); serve with `just conformance-web`
  targets.toml          #   suite facts (required features) + target facts
                        #     (missing features, optionality)
timing-lab/             # dudect-style statistical timing tests of the
                        #   composed in-guest provider (non-gating; see its
                        #   README for methodology and detection limits)
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
- **Algorithm interfaces** (`hmac-sha2`, `aes-gcm`, `chacha20-poly1305`,
  `sha2`, `ed25519-verify`/`-sign`, `ecdsa-verify`/`-sign`) contain only minting;
  operations hang off the key resources, which are capabilities (see the WIT
  doc comments for the exact contracts, including extractability and the
  "input streams are fully drained even on error" rule for `seal`/`open`).
- Operations are **one-shot calls on immutable key resources** (`sign`/
  `verify`, `seal`/`open`) — no stateful computation objects — so misuse is
  unrepresentable and the `error` variant carries no misuse cases. Keep it
  that way.
- A key resource must not promise material the provider may not hold. A
  `signing-key` therefore cannot yield its public half: `generate-key`
  returns the pair, importers use `import-verifying-key`. Browser WebCrypto
  has no derive operation (recovering the point from a private-only import
  is an unspecified spec gap, w3c/webcrypto#356) and keystore-resident keys
  sign without yielding anything else, so an infallible derive would make
  those keys unservable. A *fallible* per-algorithm derive remains possible
  additively (semver-minor) if a seed-only-import need ever materializes.

Two evolution rules govern the package surface. Adding a **resource method**
is a semver-minor package bump: new methods are subtyping-compatible for
existing compositions, but providers must update to serve them. Adding a
**`types.error` case** is always semver-major: the variant sits in return
position, so a new case flows toward consumers whose bindings cannot
represent it — there is no compatible path for variant growth. Before
proposing an error case, check whether the fail-closed design maps the
condition onto an existing one (it usually does); `other(string)` carries
operational conditions indefinitely, never semantic conditions callers must
branch on.

Changing an interface identifier means updating everyone who names it as a
string: the guest bindings (`examples/crypto-demo/src/lib.rs`), the host
bindgen configs (`wasmtime-impl/src/bindings.rs`,
`examples/wasmtime-demo/src/lib.rs`), the in-guest provider world and bindings
(`guest-impl/`), the driver's inline world
(`examples/demo-driver/src/lib.rs`), and the `jco transpile`
`--async-exports`/`--async-imports`/`--map` flags in `examples/jco-demo/package.json`.

### The in-guest provider's timing-channel policy

`guest-impl/README.md` carries the timing-channel classification (classes
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
`.github/workflows/timing-lab.yml` runs the timing lab weekly — schedule-only,
because a statistical experiment cannot gate pull requests (see
timing-lab/README.md, "Automation").

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
| `just test-webcrypto-composed` | the `guest-impl` provider, the demo driver, or any WIT (composes guest + provider + driver with `wac plug` and runs under `wasmtime`). |
| `just test-webcrypto-componentize-wpt` | the `componentize-sdk` library, its `wpt/` harness or vendored files, the in-guest provider, or any WIT. Gates in CI. The runner is componentized from your tree in seconds; the componentize-js build it needs is downloaded and digest-verified (`componentize-sdk/wpt/component.sh`), never compiled here. Changing `componentize-sdk/componentize-js.rev` triggers the `componentize-js-toolchain` workflow; this check then fails until that publishes *and* `just update-toolchain-digest` records the new digests. Intentional changes to the test census also need `just update-wpt-expectations`. |
| `just conformance` | any host/guest behavior the tests assert — the WIT surface, an implementation, the conformance guest/vectors/translation policy, or targets.toml. Intentional case changes also need `just update-conformance-lock`. Gates on the wasmtime, composed, and jco-node targets (Node 24+); jco-browser additionally gates in CI (the Actions runner ships Chrome) — locally, opt in with `CONFORMANCE_BROWSER=1` (needs Chrome/Chromium 137+). |
| `just transpile` | anything affecting the component's interfaces, or the jco flags in `examples/jco-demo/package.json`. |
| `just test-node` | the jco host (`webcrypto.js`) or the component it runs. |
| `just check` | broad Rust/WIT changes — the quick gate for most commits. |
| `just ci` | anything touching the guest, jco host, or WIT. |

Behavioral changes must keep all three implementations in sync: the
conformance tests (`just conformance`) gate the wasmtime, composed, and
jco-node targets, and the same guest component must report every check
passing under `just test` (Wasmtime), `just test-node` (jco), and
`just test-webcrypto-composed` (in-guest). When adding behavior, extend the
conformance suites (vectors or
probes), not just the demo guest — an algorithm interface is not done until
its vector cases exist (see conformance/README.md, "Growing the suites").

## Check the rationale before implementing it

Requests arrive with a reason attached — this is inefficient, this leaks, this
type would make the mistake unrepresentable. The reason is a claim about the
code, and it can be false while the request still points at something real.
Establish that it holds before writing the change, and if it does not, say so
first.

What this guards against is silent repair: noticing the premise is wrong,
quietly designing around it, and shipping something that works. Working code
then reads as confirmation of reasoning that was never tested, and the next
decision builds on it. A contradiction turned up while researching is a result
to report, not an obstacle to route around.

Two claims usually need separating, because a request tends to fuse them: what
is wrong with the code now, and what the proposed remedy fixes. They are often
both true of *different* problems. A wrapper type that makes an unsafe read
impossible does not thereby remove a redundant copy — and adopting it can
preserve the copy untouched while appearing to answer the complaint. Name which
property the change actually buys.

## Code comments and docs

Code comments describe **what** something is or does, not the process by which
it was arrived at. Rationale like "we removed X because Y" belongs in commit
messages or PR descriptions, not in source files.

A comment defending the *presence* of ordinary code is the same mistake in a
subtler form. Conventional things — a `Debug` impl, a prefixed error string,
a derived trait, an attribute the API guidelines call for — need no defence;
explaining why one is there implies it is unusual and sends the reader
looking for a catch that is not there. Comment what a reader could not
predict: an invariant, a hazard, a deliberate departure from the obvious
choice, a constraint imposed from outside the file.

The giveaway is the shape of the sentence. "Without this, a consumer
cannot…", "otherwise a caller has no indication…", "this is not merely…" are
answers to an objection, and the place to answer an objection is where it was
raised — the pull request. "This holds because…", "X must be Y since…" state
what is true of the code as it stands, which is what survives once the
discussion is forgotten. If a comment would read oddly to someone who never
saw the change that introduced it, it is in the wrong place.

Guards are the exception that proves it. A test, a lockfile, an assertion
exists *because* of the failure it prevents, so saying what it catches
describes what it is — and reads the same to someone who never saw it added.

Docs state invariants, not inventories. Never embed values a build or test
run computes — case counts, check counts, probe indexes. If a number
matters, a gate asserts it (e.g. the demo harness's expected-summary check);
if it doesn't, omit it. Machine-derived counts belong only in generated
artifacts like `conformance/matrix.md`.

## Tracking open findings in GitHub issues

Open review findings and design decisions live in this repository's GitHub
issue tracker (`gh issue list`), not in a TODO file. Before starting work
that touches an area, search the open issues — some encode contract
decisions (e.g. stream-failure semantics) that the change should resolve,
not work around.

Close issues through PRs. When a PR fully resolves an issue, put a standard
closing-keyword line (e.g. `Fixes #N`, `Closes #N`) in the PR description so
the merge closes it automatically and the cross-reference is recorded. When
a PR resolves only part of an issue, do not close it: tick the resolved
checklist items and leave a comment naming the PR, so the issue always
reflects what actually remains. File new issues for new findings rather
than adding TODO comments or files. Issue numbers are never reused, so
closed numbers remain stable references.

## Direction (designed, not yet built)

- More algorithms per kind — each is a new minting interface plus
  constructors, never a generic change.
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
- More `signature` algorithms (RSA-PSS/RSASSA-PKCS1-v1_5 need an
  `algorithm-length` getter — semver-minor; see the evolution rules in the
  WIT section — and SPKI/PKCS#8 formats); the
  per-algorithm `-verify`/`-sign` minting split already carries the class-D
  policy (the in-guest provider exports `ecdsa-verify` but not `ecdsa-sign`).
- Extending the timing lab (`timing-lab/`) toward the class B/C surfaces'
  fine-grained leaks (its README documents the current detection limits).
- A FIPS 140-3 profile, kept *possible* (not implemented): everything needed
  is additive — the `aead-internal-nonce` primitive kind carries the
  approved-mode seal (SP 800-38D forbids externally supplied GCM encryption
  IVs in approved mode, so a FIPS provider exports `aes-gcm-internal-nonce`
  but not `aes-gcm`, and offers caller-nonce sealing only as a non-approved
  service), a `module` interface for ISO 19790's mandatory services (show
  version, show status, self-test, zeroization) plus approved-service
  indication, and wrapped key export. Do not reintroduce WIT contracts that
  *mandate* non-approved behavior (the HMAC import doc deliberately permits
  policy-based rejection of short keys, and the internal-nonce import docs
  permit policy-based rejection of imported material, for this reason); a
  FIPS profile is then just a provider exporting only approved algorithm
  interfaces — enforced at `wac plug` time like the timing-channel class D
  policy.
