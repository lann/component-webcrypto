# WPT harness for the componentize-sdk library

Runs the [web-platform-tests] WebCryptoAPI suites covering this library's
surface against `componentize-sdk/webcrypto.js` inside a componentize-js
guest, composed with the in-guest `guest-webcrypto` provider — the same
pipeline as `examples/componentize-demo`. Run it from the repository root
with:

```sh
just test-webcrypto-componentize-wpt
```

This check gates in CI, and nobody — CI or contributor — builds the
componentize-js toolchain, which compiles SpiderMonkey to wasm. The two
artifacts involved have very different costs, and are handled accordingly:

- The **runner component** takes about five seconds to componentize, so
  [`component.sh build`](component.sh) builds it from the working tree on
  every run. There is no published runner and no input lock: the check
  always exercises the tree under test, and a stale artifact is not
  representable. The in-guest provider and driver it is composed with are
  likewise built fresh, so `impl-core`/`guest-impl` changes are always
  exercised.
- The **toolchain** takes about twenty minutes, and depends on nothing but
  the revision in [`../componentize-js.rev`](../componentize-js.rev). The
  [`componentize-js-toolchain`](../../.github/workflows/componentize-js-toolchain.yml)
  workflow builds one per (revision, platform), publishes it on the rolling
  [`toolchains` release] with a build-provenance attestation, and
  `component.sh` downloads it into `target/toolchains/` on first use.

  That binary is the compiler for the component under test, so it is pinned
  by digest, not by filename: `component.sh` verifies the download and every
  later use of the cached copy against
  [`../componentize-js.sha256`](../componentize-js.sha256) and refuses to
  execute anything else. Recording a digest is a separate, manual step
  (`just update-toolchain-digest`), which verifies the attestation — subject
  digest, repository, and workflow — before writing it. So trusting a new
  toolchain is a reviewable diff, and published assets are immutable (the
  workflow uploads without `--clobber`) so a recorded digest cannot be
  invalidated underneath you.

Pushing a change to the pin triggers that workflow. Until it publishes — and
until its digests are recorded — this check fails with instructions rather
than compiling SpiderMonkey or executing an unverified binary; re-run it once
the toolchain is available and pinned. To test against a
componentize-js you built yourself, point `COMPONENTIZE_JS` at it (see
[../README.md](../README.md)).

[`toolchains` release]: https://github.com/lann/component-webcrypto/releases/tag/toolchains

## What the gate asserts

Every in-subset test must pass. Beyond that, the observed census — per group,
how many tests land in each of the four buckets — must match
[`expected.js`](expected.js) exactly.

Counting is not asserting. Subset membership is decided by matching WPT test
*names*, so without the census an upstream rename in a re-vendored file could
move a test from "must pass" to "expected to fail" with no signal, and a
suite that registered nothing at all would report `0/0 in-subset tests
passed` and gate green having tested nothing. Pinning all four buckets turns
each of those into a failure with a diff — including an out-of-subset test
that starts *passing*, which is the sign the subset definition has drifted
from what the library actually serves.

This is the WPT path's equivalent of `conformance/*/tests.lock`. Regenerate
it with `just update-wpt-expectations` when a change legitimately moves a
number, and review the diff.

[web-platform-tests]: https://github.com/web-platform-tests/wpt

## What is vendored

`vendor/` holds unmodified files from WPT revision
`8e573188890e6d0a5219711afc9bbb5dc5abbd7a` (`WebCryptoAPI/` and its
`LICENSE.md`, the 3-clause BSD license the files are distributed under):

| suite | files |
| --- | --- |
| `sign_verify/hmac` | `hmac.https.any.js` (reference), `hmac.js`, `hmac_vectors.js` |
| `encrypt_decrypt/aes_gcm` (96-bit iv) | `aes_gcm.https.any.js` (reference), `aes.js`, `aes_gcm_vectors.js`, `aes_gcm_96_iv_fixtures.js` |
| `import_export/symmetric_importKey` | `symmetric_importKey.https.any.js` (reference), `symmetric_importKey.js` |
| `generateKey` successes | `successes_HMAC.https.any.js` (reference), `successes.js` |
| shared | `util/helpers.js` |

The `.https.any.js` drivers are kept for reference; the runner invokes the
suites' entry points directly with this library's algorithms (`HMAC`,
`AES-GCM`), exactly as those drivers do among others.

## How it runs

WPT test files are classic scripts sharing globals, and the componentize-js
guest world is ES modules, so `component.sh` concatenates each suite
(helpers + vectors + test script) into a module under `build/` with an
appended `export` of its entry point — the vendored sources stay pristine.
`harness.js` supplies the small `testharness.js` surface those files use
(`promise_test` and the `assert_*` family, run sequentially), and
`runner.js` installs the library as the `crypto`/`CryptoKey` globals, drives
the suites, and classifies every result by test name:

- **in-subset** — parameters the library documents as served (HMAC-SHA-256,
  AES-256-GCM with 96-bit IVs and 128-bit tags, raw keys, non-extractable
  `generateKey` cases). These must all pass; any failure fails the run.
- **out-of-subset** — the rest of WPT's parameter sweep (other hashes and
  AES key sizes, JWK format, 32–120-bit tag lengths, wrap/unwrap usages,
  extractable `generateKey` cases, which export JWK). These are expected to
  fail with the library's documented fail-closed errors and are reported by
  count.

The classifier functions in `runner.js` are the precise, machine-readable
definition of the subset; the suite gates that every in-subset test passes
and surfaces any out-of-subset test that unexpectedly passes (the counts are
printed either way).
