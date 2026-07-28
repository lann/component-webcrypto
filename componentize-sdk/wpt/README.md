# WPT harness for the componentize-sdk library

Runs the [web-platform-tests] WebCryptoAPI suites covering this library's
surface against `componentize-sdk/webcrypto.js` inside a componentize-js
guest, composed with the in-guest `guest-webcrypto` provider — the same
pipeline as `examples/componentize-demo`. Run it from the repository root
with:

```sh
just test-webcrypto-componentize-wpt
```

This check gates in CI, and neither CI's gating job nor contributors need
the componentize-js toolchain (building it compiles SpiderMonkey to wasm):
the componentized runner is a **release artifact**, not a checked-in file.
[`component.sh`](component.sh) owns the mechanism — it computes an input
lock (the sha256 of everything the runner is generated from: the library,
the harness and runner, the concatenated suites, the resolved WIT world, the
componentize-js revision pin) and the component is
published on this repository's rolling [`wpt-components` release] as
`wpt-runner-<lock-hash>.component.wasm`. The recipe's `ensure` step reuses a
fresh local build or downloads the published component for the current
inputs; the in-guest provider and the driver it is composed with are built
fresh every run, so changes to `impl-core`/`guest-impl` are always
exercised.

The WIT input is the `componentize-demo` world *resolved and encoded*
(`wasm-tools component embed --dummy`), not the package's source files. The
runner can only be affected by that world's import closure — `mac`, `aead`,
`digest`, `sha2`, `hmac-sha2`, `aes`, `aes-gcm` — so an interface outside it
must not invalidate a published component. Source-file hashing cannot draw
that line, since `signature` shares `webcrypto.wit` with `mac` and `aead`.
The encoding also drops doc comments, which likewise cannot change the
component. Every job that computes the lock must therefore use the same
wasm-tools, pinned in [`scripts/wasm-tools.version`](../../scripts/wasm-tools.version).

When the inputs change, CI's `wpt-component` builder job builds the new
component (restoring the componentize-js CLI from the Actions cache, so
SpiderMonkey is only recompiled when the toolchain pin changes) and
publishes it on merge to main; pull-request runs hand the built component
directly to the gating job without publishing. To build and test locally
before pushing:

```sh
just update-wpt-component   # needs the componentize-js CLI — see ../README.md
```

[`wpt-components` release]: https://github.com/lann/component-webcrypto/releases/tag/wpt-components

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
