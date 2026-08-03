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
rust/                   # the Rust library surface (directory = crate name
                        # minus the `lann-webcrypto-` family root)
  core/                 # lann-webcrypto-core: the shared RustCrypto core of
                        #   both Rust implementations: cipher/digest
                        #   dispatch, key validation and generation, error
                        #   rendering, the internal-nonce wire format,
                        #   signature keys (ECDSA signing is compiled out of
                        #   wasm builds — class D)
  wasmtime/             # lann-webcrypto-wasmtime: Wasmtime host crate,
                        #   modeled after wasmtime_wasi_http::p3;
                        #   add_to_linker + WasiWebcryptoView
  guest/                # lann-webcrypto-guest: guest-side Rust library over
                        #   the lann:webcrypto imports: typed wrappers with
                        #   a byte-source abstraction, so consumers do not
                        #   re-implement the feed-a-stream-and-await
                        #   plumbing; the Rust counterpart of
                        #   @lann/webcrypto-componentize
  guest-provider/       # lann-webcrypto-guest-provider: wasm COMPONENT,
                        #   RustCrypto in-guest, EXPORTS the package
                        #   surface; composable via `wac plug`; buffer.rs
                        #   makes input buffering fallible, so allocation
                        #   failure is the operation's error rather than the
                        #   instance's trap; the instance memory limit the
                        #   embedder sets is the retention bound,
                        #   deliberately (see the module doc); see its
                        #   README for the timing-channel classification and
                        #   export policy
js/                     # the JS library surface (directory = npm name minus
                        # the `@lann/webcrypto-` family root)
  jco/                  # @lann/webcrypto-jco: jco host LIBRARY.
                        #   webcrypto.js implements the imports over the
                        #   browser-compatible Web Crypto API ONLY; no
                        #   runtime dependencies, no demo code.
                        #   wit/world.wit names the interfaces it serves;
                        #   `jco-transpile` derives their definitions from
                        #   it and interface-check.js asserts the host
                        #   against them (`just typecheck-jco`); test/
                        #   covers the admission subsystem conformance
                        #   cannot reach
  componentize/         # @lann/webcrypto-componentize: JS guest library for
                        #   componentize-js (dicej's ComponentizeJS reboot):
                        #   webcrypto.js exposes a crypto.subtle subset
                        #   (HMAC-SHA-256, AES-256-GCM, the derive model:
                        #   HKDF/PBKDF2/X25519 with deriveBits/deriveKey;
                        #   raw and jwk keys) over the lann:webcrypto
                        #   imports; the toolchain revision is pinned in
                        #   componentize-js.rev; interface-check.js asserts
                        #   the exported subset against the SubtleCrypto and
                        #   CryptoKey definitions TypeScript ships
                        #   (`just typecheck-webcrypto-componentize`); wpt/
                        #   vendors the WebCryptoAPI web-platform-tests and
                        #   gates in CI, componentizing its runner from the
                        #   tree with a digest-pinned componentize-js build
                        #   (wpt/component.sh, componentize-js.sha256); the
                        #   run's census is pinned by wpt/expected.js;
                        #   wpt/web/ is the browser parity page on the
                        #   Pages site (serve with `just wpt-web`)
examples/
  crypto-demo/          # guest component exercising the primitive kinds end
                        #   to end (reaches lann:webcrypto via lann-webcrypto-guest)
  demo-driver/          # CLI driver (async wasi:cli/run) for the composed
                        #   fully in-guest demo
  wasmtime-demo/        # thin native host over lann-webcrypto-wasmtime's add_to_linker
                        #   + the integration test (tests/demo.rs)
  jco-demo/             # Node 24+ driver for the jco host: transpiles
                        #   crypto-demo with jco (one wildcard --map; async
                        #   is read from the component) and runs it against
                        #   js/jco/webcrypto.js
  componentize-demo/    # JS guest (componentize-js) exercising the
                        #   webcrypto-componentize library; exports the same demo
                        #   interface as crypto-demo, composed and run via
                        #   `just test-webcrypto-componentize` (gates in CI)
conformance/            # cross-implementation conformance tests — see
                        #   conformance/README.md for its architecture and
                        #   the rationale for how it deliberately diverges
                        #   from the WebRTC sibling's machinery
  vectors/              #   vendored Wycheproof JSON + the translation
                        #     policy; its README records the upstream
                        #     revision each file came from
  harness/              #   the world-independent half of both guests:
                        #     probe table, feature names, error rendering,
                        #     assertion helpers, stream delivery, feature
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
  report/               #   the results-file and lockfile wire shapes the Rust
                        #     adapters serialize and the runner deserializes
                        #     (crate: conformance-report)
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
  returns the pair, importers use `import-verifying-key-raw`. Browser WebCrypto
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
represent it — there is no compatible path for variant growth. The variant
is therefore designed never to need growth: the closed cases carry the
generic kinds' universal conditions, `other(string)` carries operational
conditions (never semantic conditions callers must branch on), and
`extension(extension-error)` carries named algorithm- and feature-specific
conditions by (`origin`, `name`) pair — see `wit/README.md`, "Error
contract". Before proposing a closed case, check whether the fail-closed
design maps the condition onto an existing one (it usually does) and
whether the condition is interface-specific (then it is an extension
condition, not a case).

The evolution rules describe the cost of a change, not a prohibition — and
they bind only once the package has external consumers, which it does not
yet. Until then, a shape regret is fixed *in place* (signatures change,
names change, the error variant may grow), never designed around
additively: working around a constraint that does not yet bind produces
the wart without buying the compatibility. What ends this regime is
publishing the package for consumption; the change that does so should say
it does.

The ChaCha interfaces and `sha1-checked` are additionally gated
`@unstable` (features `chacha20-poly1305`, `xchacha20-poly1305`, and
`sha1-checked` — see `wit/README.md`,
"Stability gates"): tooling hides them unless the feature is enabled, and
only test builds enable them by default. The conformance guest, the demo
and WPT componentize-js builds (`--features`), the jco `types` script
(`--feature`), the timing lab, and the standalone Wasmtime embedding all
opt in; the library surfaces default off — the guest SDK behind its
`chacha` and `sha1-checked` cargo features, the Wasmtime host behind
`add_to_linker_with_options`'s `LinkOptions` (plain `add_to_linker` serves
no gated interface). A world line importing or exporting a gated interface
carries the same gate. Adding a WIT-resolving build without the flags
silently drops the interfaces rather than erroring, so a "missing
import/export" for a ChaCha interface usually means a missing feature
flag.

Changing an interface identifier means updating everyone who names it as a
string: the guest bindings (`examples/crypto-demo/src/lib.rs`), the host
bindgen configs (`rust/wasmtime/src/bindings.rs`,
`examples/wasmtime-demo/src/lib.rs`), the in-guest provider world and bindings
(`rust/guest-provider/`), the driver's inline world
(`examples/demo-driver/src/lib.rs`), and the camelCased named export in
`js/jco/webcrypto.js` (the transpile invocations carry one wildcard
`--map` and enumerate nothing per interface; async-ness is read from the
component — see the conventions note in that file's header).

### The in-guest provider's timing-channel policy

`rust/guest-provider/README.md` carries the timing-channel classification (classes
A–D) and this provider's policy: only class A–C algorithms are exported,
always via constant-time-variant implementations; class D algorithm
interfaces (RSA private-key ops, ECDSA signing, …) are **never** exported by
the in-guest provider, so compositions requiring them fail at `wac plug`
time. Secret-free operations (hashing public data, signature *verification*)
are exempt from the classes. Keep the classification table in sync when
adding algorithms, and keep class D out of the provider's world.

`just class-d-composition` (a dependency of `just conformance`) gates that
last sentence: it asserts the conformance signing guest, whose world imports
`ecdsa-sign`, does not compose with the provider. Adding a class-D export
turns that composition green and fails the gate. The failure mode it guards
against is subtle — see rust/guest-provider/README.md, "What the failure looks like":
`wac plug` tolerates imports it cannot satisfy, so the composition breaks
only because the provider exports the *generic* interface owning the key
resource that the withheld minting interface mints.

### The jco host must stay browser-compatible

`js/jco/webcrypto.js` uses only `globalThis.crypto.subtle` and
`globalThis.crypto.getRandomValues`. No `node:crypto`, no Node-only APIs: the
same file must be loadable in a browser unchanged. Node is just the current
runner (24+ for JSPI).

### WPT fidelity is a first-class design constraint

`js/componentize/webcrypto.js` re-exposes the package as `crypto.subtle`,
and the WPT harness (`js/componentize/wpt/`) runs the platform's own test
suite through it. That round trip — WPT → shim → WIT → implementation — is
the repository's instrument for a question the conformance suites cannot
ask: whether `crypto.subtle`'s observable semantics survive the WIT shape.
Its coverage is first-class, like the conformance vectors: growing the
package surface includes vendoring the WPT groups that observe it.

A WPT-observable behavior the shim does not exhibit is one of two things,
and the difference is the signal:

- **Unserved**: the WIT carries the semantics; the shim does not serve them
  yet (for example algorithms beyond its documented set). Backlog, not a
  design problem.
- **WIT-forced**: no shim could express the behavior through the interface
  shape. Keeping the set small is the goal, and every member must be a
  recorded ruling, never a silent consequence of whatever shape was
  convenient. The set is currently empty; the historical members were
  each resolved rather than kept — the fixed AES-GCM IV/tag contract by
  carrying both as per-call `aead-key.seal`/`open` parameters, the
  ChaCha JWK decline by serving the proposal's alg-less `oct` form, and
  the empty-HKDF-IKM rejection by accepting empty KDF secrets
  package-wide (its recorded rationale did not survive scrutiny).

The shim header's deviations list is the registry: every deviation appears
there with its classification, so the WIT-forced set — the true cost of the
interface shape, in platform-conformance terms — is enumerable at a glance.
When designing or changing WIT, read the WPT groups for the affected
algorithm the way you read Wycheproof: they define what a platform
observes, including the exact `DOMException` names the shim must reconstruct
from `types.error` (`mapWitError`), which bounds how much an error-variant
design may collapse.

## Build & run

Prerequisites: Rust via rustup (toolchain + wasm target pinned in
`rust-toolchain.toml`), `wasm-tools`, `just`, and Node 24+ with npm for the
jco path. Run `./scripts/setup.sh` once (idempotent; `SKIP_NODE=1` to skip the
npm install).

The [`justfile`](justfile) is the single entry point; run `just` to list
recipes. `.github/workflows/ci.yml` runs the same recipes.
`.github/workflows/timing-lab.yml` runs the weekly lab — the timing lab and
the mutation run (`just mutants`) — schedule-only, because a statistical
experiment cannot gate pull requests (see timing-lab/README.md,
"Automation") and a full mutation run costs hours.

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
| `just test-webcrypto-composed` | the `lann-webcrypto-guest-provider` provider, the demo driver, or any WIT (composes guest + provider + driver with `wac plug` and runs under `wasmtime`). |
| `just typecheck-webcrypto-componentize` | the `webcrypto-componentize` library. Asserts its exported surface against the Web Cryptography API definitions TypeScript ships; no component build, nothing generated. |
| `just test-webcrypto-componentize` | the `webcrypto-componentize` library, the componentize-demo guest, the in-guest provider, or any WIT. Gates in CI. Componentizes the JS demo guest from your tree (with the downloaded, digest-verified componentize-js — see the WPT row for the pin mechanics), composes it with the in-guest provider and driver, and runs it under `wasmtime`. The behavioral gate on the shim's checks the WPT census cannot observe (the SHA-1 collision postures, the extension-error transport). |
| `just test-webcrypto-componentize-wpt` | the `webcrypto-componentize` library, its `wpt/` harness or vendored files, the in-guest provider, or any WIT. Gates in CI. The runner is componentized from your tree in seconds; the componentize-js build it needs is downloaded and digest-verified (`js/componentize/wpt/component.sh`), never compiled here. Changing `js/componentize/componentize-js.rev` triggers the `componentize-js-toolchain` workflow; this check then fails until that publishes *and* `just update-toolchain-digest` records the new digests. Intentional changes to the test census also need `just update-wpt-expectations`. |
| `just conformance` | any host/guest behavior the tests assert — the WIT surface, an implementation, the conformance guest/vectors/translation policy, or targets.toml. Intentional case changes also need `just update-conformance-lock`. Gates on the wasmtime, composed, and jco-node targets (Node 24+); jco-browser additionally gates in CI (the Actions runner ships Chrome) — locally, opt in with `CONFORMANCE_BROWSER=1` (needs Chrome/Chromium 137+). |
| `just transpile` | anything affecting the component's interfaces, or the transpile flags in `examples/jco-demo/package.json`. |
| `just test-jco-host` | the jco host's input-buffering admission subsystem (`configure`, the admission queue). Runs `webcrypto.js` directly under `node --test`; the conformance suite cannot reach this code, since its workers each run their cases sequentially against their own host instance. |
| `just typecheck-jco` | the jco host (`webcrypto.js`), its world, or any WIT. Regenerates the interface definitions and type-checks the host against them; no component build. |
| `just test-node` | the jco host (`webcrypto.js`) or the component it runs. |
| `just wpt-parity` | the `webcrypto-componentize` library, its `wpt/` harness or vendored files, the jco host, or any WIT. Gates in CI (the jco job). Runs the vendored WPT suites against the platform's own `crypto.subtle` and through the jco-transpiled shim, holding the round trip to the baseline's pass set; the known losses are pinned in `js/componentize/wpt/parity/losses.js`. Intentional loss-set changes need `just update-wpt-parity`. Needs Node 24+ and the pinned componentize-js (downloaded, like the composed WPT gate). |
| `just wpt-parity-firefox` | the same surfaces as `just wpt-parity`. Gates in CI (the jco job); locally opt-in via WPT_PARITY_FIREFOX=1. The same two legs run in headless Firefox (Playwright's pinned build, Gecko's JSPI pref) against the engine's own ratchet, `js/componentize/wpt/parity/losses-firefox.js` — loss sets are per-engine facts, so intentional changes need `just update-wpt-parity-firefox`. Needs Playwright Firefox (`cd js/componentize/wpt/parity && npx playwright-core install --with-deps firefox`). |
| `just wpt-parity-chromium` | the same surfaces as `just wpt-parity`. Gates in CI (the jco job); locally opt-in via WPT_PARITY_CHROMIUM=1. Like the Firefox row, in Playwright's pinned Chromium against `js/componentize/wpt/parity/losses-chromium.js`; intentional changes need `just update-wpt-parity-chromium`. |
| `just wpt-parity-webkit` | the same surfaces as `just wpt-parity`. Gates in CI as its own macOS job pair (no componentize-js toolchain exists for darwin, so an ubuntu job builds the page artifacts and hands them over). The ratchet `js/componentize/wpt/parity/losses-webkit.js` is recorded from Playwright WebKit on macOS — Apple's crypto backend, the mobile-Safari proxy; the Linux port serves less and crashes, so record intentional changes without a mac via `just update-wpt-parity-webkit-from-ci` (the CI job's records artifact) or optimistically via `just predict-wpt-parity-webkit` (the Chromium delta; a miss fails the next run, never mispins) — `just update-wpt-parity-webkit` needs a mac. |
| `just check` | broad Rust/WIT changes — the quick gate for most commits. |
| `just ci` | anything touching the guest, jco host, or WIT. |

Behavioral changes must keep all three implementations in sync: the
conformance tests (`just conformance`) gate the wasmtime, composed, and
jco-node targets, and the same guest component must report every check
passing under `just test` (Wasmtime), `just test-node` (jco), and
`just test-webcrypto-composed` (in-guest). When adding behavior, extend the
conformance suites (vectors or
probes), not just the demo guest — an algorithm interface is not done until
its vector cases exist (see conformance/README.md, "Growing the suites")
and the WPT groups observing it are vendored with their in-subset tests
passing (see "WPT fidelity is a first-class design constraint" above).

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

## WIT doc comments

Every WIT comment is a doc comment: bindings generators project it into
library documentation, so its audience is the package's *consumers* — from
experienced cryptographic engineers to junior general software engineers —
not this repository's contributors.

- **Package-wide contracts live in [`wit/README.md`](wit/README.md)**, not
  in doc comments: the streaming contract, the key-options contract,
  extractability, getter conventions, the JWK contract, the error
  contract, the timing-channel policy, design notes, and the terminology
  glossary. A doc comment states what is specific to its item and links to
  the README section by name (e.g. ``see `README.md`, "Streaming
  contract"``) for the rest. Never restate a shared contract in full at a
  use site; never let a package-wide contract live only inside one item's
  doc.
- **Order within a doc comment**: basic usage first; then the
  crypto-safety-critical contracts (as a `Security:` bulleted block when
  there is more than one point — the bullets themselves visually bracket
  the section); then other details. The highest-impact caveat (nonce
  uniqueness, verify semantics, unverified-plaintext rules) must never
  sit mid-paragraph behind mechanics.
- **Use Simplified Technical English as guidance**: short sentences,
  active voice, one instruction per sentence, consistent terms. Dense
  security terminology buries the contract it is meant to convey.
- **Terminology** (mint, capability, unrepresentable, IKM, …) is defined
  once in `wit/README.md`'s glossary — brief descriptions linking to
  authoritative web sources (Wikipedia, RFCs, the W3C spec) — and doc
  comments rely on it rather than re-explaining terms inline.
- **No repository-internal content on the package surface**: doc comments
  must not name this repository's implementations, shims, test harnesses,
  issues, or design history. Implementation-specific facts are phrased
  neutrally ("providers in attacker-observable timing domains…"); design
  rationale goes to `wit/README.md`'s "Design notes" or the issue tracker.
  The "answers to an objection" rule below applies with extra force here:
  a consumer never saw the review that prompted the sentence.

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

## Sizing pull requests

Three factors decide how much lands in one PR. They pull in different
directions, so they bind in this order.

1. **Necessity.** Changes that cannot land separately without leaving `main`
   worse between them — a stated contract the tree violates, a fix that
   activates a latent defect elsewhere, a gate red until the counterpart
   arrives — go in one PR, whatever that does to its size. This repository
   has a standing instance: the conformance suites gate all implementations
   against one behavior, so a change to the package surface is co-dependent
   across the WIT, every implementation, and the SDKs *by construction*.
   Name the co-dependence in the description; a reviewer who cannot see why
   the pieces are inseparable will reasonably ask for the split.

2. **Cohesion.** One decision per PR: the description should be a single
   ruling plus its consequences, however many files those touch. "And also"
   is the tell that two PRs are sharing a branch. Cohesion caps what a PR
   may contain — it never forces changes together. One decision whose
   consequences land safely apart (say, in two implementations that do not
   gate each other) is two PRs, not one.

3. **Review time.** Within what the first two allow, smaller is better: the
   budget being spent is a human's attention on the diff. The converse also
   holds and is not an exception — many *nearly identical* changes (a getter
   added to every key resource, a signature migrated across its call sites)
   are one PR, not many, because near-identical diffs review sublinearly:
   the reviewer verifies the pattern once and scans the instances, while a
   PR apiece pays full cost in CI and context each time and lets the pattern
   drift between them. The test is textual similarity of the diffs, not
   thematic similarity of the work — two subsystems getting "the same
   treatment" through different mechanisms are two PRs.

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

- WPT platform parity through the jco path: the measuring harness exists
  (`just wpt-parity` — see js/componentize/wpt/README.md, "The parity
  gate") and pins the loss set; what remains is driving that set down.
  Growing toward parity is tiered — first behaviors the WIT already
  carries but the shim does not serve (more hashes, the usages model),
  then additive WIT
  surface (the RSA family and public-key wrapping — see the
  bullets below), and only
  then any future WIT-forced deviations, each of which needs an explicit
  ruling (the historical example, the GCM IV/tag contract, was resolved
  by enriching the `aead` kind with per-call parameters). Class D is not implicated: the crypto runs host-side on the
  platform. A browser leg exists as the live parity page on the Pages
  site (js/componentize/wpt/web/ — see that README's "The browser parity
  page"), and gating Firefox, Chromium, and WebKit legs run in CI, each
  against its own pinned loss set (`just wpt-parity-firefox` /
  `-chromium` / `-webkit`; the WebKit leg runs on a macOS runner, where
  Playwright's WebKit uses Apple's crypto backend — the mobile-Safari
  proxy).
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
- Platform-backed key storage, so a guest can keep a *non-extractable* key
  across instantiations instead of exporting and re-importing material (see
  the design issue). Browser WebCrypto already supports it: `CryptoKey` has
  structured-clone steps that carry `[[extractable]]` and `[[handle]]` into
  IndexedDB without exposing material. Two consequences already reach the
  stable surface. A retrieved key is a *handle*, so it may be usable and
  unreadable at once — every WebCrypto export operation can fail with
  "key material cannot be accessed" where sign and verify cannot, which is
  why `verifying-key.export-key-raw` is fallible. And loading is a minting path
  whose caller supplied no `extractable` argument, which is why every gated
  key resource exposes an `extractable` getter. Storage is also the first
  place where the implementations may differ in *capability* rather than in
  algorithm coverage — jco has IndexedDB, the in-guest provider has no store
  at all and would decline the interface at `wac plug` time — so expect an
  optional target capability in `conformance/targets.toml`.
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
