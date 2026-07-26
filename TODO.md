# TODO

Open items from a whole-repo review, ordered by how hard each becomes to fix
later. Amend this file as part of any change that fixes, obsoletes, or
invalidates an item: delete the item (don't mark it done) and prune empty
sections. See AGENTS.md ("Maintaining TODO.md").

## WIT (pre-freeze: cheap now, breaking later)

- **Nonce-misuse resistance: internal-nonce seal.** Caller-supplied nonces are
  the top real-world AEAD footgun and the API's only defense is a doc comment.
  Add a `seal-internal-nonce` (nonce chosen by the implementation, returned or
  prefixed) as the recommended path, keeping caller-nonce `seal` for interop.
  Also required eventually by the FIPS direction (SP 800-38D forbids
  caller-supplied GCM encryption IVs in approved mode).

## Implementation hardening

- **Zeroize key material.** Key structs in `wasmtime-impl` and `guest-impl`
  hold raw material in plain `Vec<u8>`, clone it on export, and drop it
  without scrubbing. Adopt `zeroize` (`ZeroizeOnDrop`) on the key types;
  consider plaintext buffers too. Retrofitting gets harder once the structs
  are public API.
- **jco internals coupling.** `webcrypto.js` throws bare `{ tag: ... }`
  literals and sniffs three stream shapes in `collectByteStream`; both depend
  on undocumented jco conventions. Isolate behind small helpers and note the
  jco version they were validated against.

## Testing & CI

- **jco-browser in CI.** The browser target needs Chromium and is manual
  today. Add a scheduled (non-gating) CI job with Chromium so browser
  conformance regressions surface without anyone remembering to run it.
- **Bleeding-edge canary.** The project is pinned to a pre-stabilization
  async ABI (wasmtime, wit-bindgen, jco). Add a scheduled, non-gating CI job
  building against their latest releases so ABI breakage is a notification,
  not an ambush during feature work.
- **Supply-chain gating.** No `cargo audit`/`cargo deny` (or npm equivalent)
  runs in CI. For a crypto project this should exist before the dependency
  tree grows further.

## Project

- **Versioning & release policy.** Write down when `lann:webcrypto@0.1.0`
  becomes `0.2.0`, how implementations declare which package version they
  satisfy, and how the crates/npm packages version against it — this is the
  compatibility surface and it is currently implicit.
- **Guest-side convenience libraries.** Every consumer re-implements the
  feed-a-stream-and-await pattern (`futures::join!` plumbing) to MAC 20
  bytes. Publish thin guest wrappers (Rust crate, JS package) with
  `sign_bytes(&[u8])`-style helpers so the correct pattern is written once.
- **Write up the async-WIT contract patterns.** The drain-even-on-error rule,
  "`ok(stream)` is the authentication statement", and chunking-schedule
  conformance are novel contract designs for async WIT; documenting them for
  upstream adoption is direct ecosystem impact.
