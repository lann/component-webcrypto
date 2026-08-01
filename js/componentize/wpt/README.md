# WPT harness for the webcrypto-componentize library

Runs the [web-platform-tests] WebCryptoAPI suites covering this library's
surface against `js/componentize/webcrypto.js` inside a componentize-js
guest, composed with the in-guest `lann-webcrypto-guest-provider` provider — the same
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
  likewise built fresh, so `lann-webcrypto-core`/`lann-webcrypto-guest-provider` changes are always
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

The out-of-subset buckets are a to-do list, not a boundary: WPT coverage is
a first-class design constraint (see AGENTS.md, "WPT fidelity is a
first-class design constraint"), and the census is the meter of how much of
`crypto.subtle`'s observable behavior survives the WIT shape. Growing the
package surface includes vendoring the WPT groups that observe it; a test
no shim could ever move in-subset marks a WIT-forced deviation, which
belongs in the shim header's classified deviations list.

## The parity gate (jco path)

`just wpt-parity` measures those losses instead of asserting counts. The
same vendored suites run twice, ending at the same platform crypto, with
only the carrier stack differing:

```
baseline:    WPT tests ─────────────────────────────────► platform crypto.subtle
round trip:  WPT tests ► shim ► WIT ► component ABI ► jco ► platform crypto.subtle
```

`parity/baseline.mjs` runs the suite bundles directly on this Node's
`crypto.subtle`; `parity-runner.js` (componentized from the tree like the
gating runner, but ungated — it reports every result and asserts nothing
in-guest) is transpiled by jco against `js/jco/webcrypto.js` and run by
`parity/roundtrip.mjs`. Because both legs end at the identical platform
engine, the platform's own coverage cancels out: whatever it does not
implement fails both legs, with no exclusion list to maintain. Every test
the baseline passes and the round trip does not is a *loss* introduced by
the stack in the middle, and `parity/compare.mjs` holds the loss set to
[`parity/losses.js`](parity/losses.js) — a ratchet, maintained like
`expected.js`: a loss not recorded there fails the run (a regression), a
recorded loss no longer observed fails it too (progress must land as a
reviewable diff, via `just update-wpt-parity`). Which *kind* each loss is —
unserved or WIT-forced — is the shim header's deviations registry's to say.

Two properties of the comparison follow from how WPT registers tests. Test
names are outcome-dependent — a failed setup step registers a synthetic
step name in place of the real test's — so round-trip-only *failures* are
expected renames, while a round-trip-only *pass* fails the run: a pass the
baseline never measured is outside the gate's premise and marks the legs'
group tables drifting (the baseline duplicates the runner's group table,
since it cannot import a module whose `lann:webcrypto` specifiers only
resolve under componentize-js). And the baseline is recomputed per run,
never pinned, so a platform upgrade moves both legs together; the loss set
is sensitive to the platform only where the platform itself is.

[web-platform-tests]: https://github.com/web-platform-tests/wpt

## What is vendored

`vendor/` holds unmodified files from WPT revision
`8e573188890e6d0a5219711afc9bbb5dc5abbd7a` (`WebCryptoAPI/` and its
`LICENSE.md`, the 3-clause BSD license the files are distributed under):

| suite | files |
| --- | --- |
| `sign_verify/hmac` | `hmac.https.any.js` (reference), `hmac.js`, `hmac_vectors.js` |
| `encrypt_decrypt/aes_gcm` (96-bit iv) | `aes_gcm.https.any.js` (reference), `aes.js`, `aes_gcm_vectors.js`, `aes_gcm_96_iv_fixtures.js` |
| `encrypt_decrypt/aes_cbc` | `aes_cbc.https.any.js` (reference), `aes_cbc_vectors.js` (the shared `aes.js` runner) |
| `encrypt_decrypt/aes_ctr` | `aes_ctr.https.any.js` (reference), `aes_ctr_vectors.js` |
| `import_export/symmetric_importKey` | `symmetric_importKey.https.any.js` (reference), `symmetric_importKey.js` |
| `generateKey` successes | `successes_HMAC.https.any.js`, `successes_X25519.https.any.js`, `successes_Ed25519.https.any.js` (references), `successes.js` |
| `sign_verify/eddsa` (Ed25519) | `eddsa_curve25519.https.any.js`, `eddsa_small_order_points.https.any.js` (references), `eddsa.js`, `eddsa_small_order_points.js`, `eddsa_vectors.js` |
| `sign_verify/ecdsa` | `ecdsa.https.any.js` (reference), `ecdsa.js`, `ecdsa_vectors.js` |
| `import_export/okp_importKey` (Ed25519) | `okp_importKey_Ed25519.https.any.js`, `okp_importKey_failures_Ed25519.https.any.js` (references; helpers shared with the X25519 rows) |
| `import_export/ec_importKey` | `ec_importKey.https.any.js` (wrapped callable), `ec_importKey_failures_ECDSA.https.any.js` (reference), `ec_importKey_failures_fixtures.js` |
| `derive_bits_keys/cfrg_curves` (X25519) | `cfrg_curves_bits_curve25519.https.any.js`, `cfrg_curves_keys_curve25519.https.any.js` (references), `cfrg_curves_bits.js`, `cfrg_curves_keys.js`, `cfrg_curves_bits_fixtures.js` |
| `derive_bits_keys/hkdf` | `hkdf.https.any.js` (reference), `hkdf.js`, `hkdf_vectors.js` |
| `derive_bits_keys/pbkdf2` | `pbkdf2.https.any.js` (reference), `pbkdf2.js`, `pbkdf2_vectors.js` |
| `digest/digest` | `digest.https.any.js` (wrapped callable — see `component.sh`) |
| `import_export/okp_importKey` (X25519) | `okp_importKey_X25519.https.any.js`, `okp_importKey_failures_X25519.https.any.js` (references), `okp_importKey.js`, `okp_importKey_fixtures.js`, `importKey_failures.js`, `okp_importKey_failures_fixtures.js` |
| `getRandomValues` | `getRandomValues.any.js` (wrapped callable) |
| shared | `util/helpers.js` |

The `.https.any.js` drivers are kept for reference; the runner invokes the
suites' entry points directly with this library's algorithms (`HMAC`,
`AES-GCM`, `X25519`), exactly as those drivers do among others. Each
group's subset follows what the library serves (`runner.js`'s classifiers
are the authoritative definition): most groups assert their served slices
whole, the KDF groups exclude their SHA-1 and unserved-target rows, and
`sign_verify/ecdsa` stays empty-subset — every test in it needs ECDSA
signing or a generated pair, which is class D and unserved by composition
(see the shim header's deviations list), so it meters that gap.

## How it runs

WPT test files are classic scripts sharing globals, and the componentize-js
guest world is ES modules, so `component.sh` concatenates each suite
(helpers + vectors + test script) into a module under `build/` with an
appended `export` of its entry point — the vendored sources stay pristine.
`harness.js` supplies the small `testharness.js` surface those files use
(`promise_test` and the `assert_*` family, run sequentially), and
`runner.js` installs the library as the `crypto`/`CryptoKey` globals, drives
the suites, and classifies every result by test name:

- **in-subset** — parameters the library documents as served. These must
  all pass; any failure fails the run.
- **out-of-subset** — the rest of WPT's parameter sweep (other hashes and
  AES key sizes, and so on). These are expected to fail with the library's
  documented fail-closed errors and are reported by count.

The classifier functions in `runner.js` are the precise, machine-readable
definition of the subset; the suite gates that every in-subset test passes
and surfaces any out-of-subset test that unexpectedly passes (the counts are
printed either way).
