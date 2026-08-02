# webcrypto-componentize

A WebCrypto-subset library for JavaScript guests componentized with
[componentize-js] (the wit-dylib–based reboot of ComponentizeJS), backed by
the `lann:webcrypto` interfaces. This is the JS-guest counterpart of the Rust
[`lann-webcrypto-guest`](../lann-webcrypto-guest): where `lann-webcrypto-guest` wraps the raw bindings in
ergonomic Rust newtypes, `webcrypto.js` wraps them in the API JS code already
knows — `crypto.subtle`.

[componentize-js]: https://github.com/dicej/componentize-js

## Surface

`webcrypto.js` exports `subtle` and a `crypto`-shaped
`{ subtle, getRandomValues, randomUUID }` namespace. The served surface — the
algorithms, operations, and key formats — is enumerated at the top of
`webcrypto.js`, alongside the deviations registry it gates.

Keys are `CryptoKey` objects (`type` `"secret"`, `"public"`, or
`"private"`, `algorithm`, `extractable`, `usages`) wrapping
`lann:webcrypto` key resources; usages and extractability
are enforced with WebCrypto's error vocabulary. The library maps the WIT
`types.error` variant onto that vocabulary (`authentication-failed` →
`OperationError`, `not-extractable` → `InvalidAccessError`, `invalid-key` →
`DataError`, `unsupported` → `NotSupportedError`), and `verify` is the one
place a failed verification maps back to WebCrypto's `false` verdict; every
other failure stays a thrown error, preserving the WIT surface's fail-closed
shape.

Deviations from the Web Cryptography API are documented at the top of
`webcrypto.js` (the registry: every deviation appears there with its
classification); all of them fail closed with clear errors rather than
silently differing.

Within that subset the library tracks the spec closely enough to pass the
relevant [web-platform-tests] suites: [`wpt/`](wpt) vendors the WebCryptoAPI
sign/verify, encrypt/decrypt, importKey, and generateKey tests and runs them
against this library (`just test-webcrypto-componentize-wpt`, a gating CI
check); every in-subset test must pass, and the out-of-subset remainder of
WPT's parameter sweep is reported failing closed. See
[`wpt/README.md`](wpt/README.md) for the vendoring and subset policy, and
for how the check builds its runner from the tree with a downloaded
toolchain, so neither CI nor contributors compile SpiderMonkey.

[web-platform-tests]: https://github.com/web-platform-tests/wpt

## Using it in a component

The component's world must import `lann:webcrypto/hmac-sha2@0.1.0` and
`lann:webcrypto/aes-gcm@0.1.0` (WIT elaboration pulls in their
`mac`/`aead`/`types` dependencies) — see
[`examples/componentize-demo`](../examples/componentize-demo) for a complete
world, guest, and composition. The `chacha20-poly1305` and `sha1-checked`
imports are gated
`@unstable` in the package (see `wit/README.md`, "Stability gates"), so
those world lines carry `@unstable(feature = ...)` gates and the
componentize-js invocation passes
`--features chacha20-poly1305,sha1-checked`. The
library is a single file with no
dependencies; componentize-js resolves its `lann:webcrypto/...` module
specifiers against the world at componentize time, and resolves the library
itself as a file path relative to `componentize-js componentize`'s
`--base-directory`.

Bulk data crosses the interface as `stream<u8>`: operations resolve only
once their input stream's writer is dropped, so the library feeds input and
awaits each operation concurrently, and collects `seal`/`open` output
streams concurrently with the feed (the streaming contract's closure rule
guarantees the feed settles no later than the operation, even when the
operation fails).

## Toolchain

The componentize-js CLI turns a JS guest into a component
(`just build-componentize-demo`, and the WPT check's runner); it is not
needed to *run* one. Nobody here builds it: building compiles SpiderMonkey
to wasm and needs WASI-SDK 30 and Clang 19+, so the
[`componentize-js-toolchain`](../.github/workflows/componentize-js-toolchain.yml)
workflow builds one per (revision, platform) and publishes it on the rolling
`toolchains` release, and `js/componentize/wpt/component.sh toolchain`
downloads it into `target/toolchains/` on first use — verified against the
digests in [`componentize-js.sha256`](componentize-js.sha256), since this
binary compiles the component the WPT gate tests. Changing the revision
pinned in [`componentize-js.rev`](componentize-js.rev) triggers a new build;
checks that need it fail with instructions until it is published *and*
`just update-toolchain-digest` has recorded its digests (that step verifies
the build-provenance attestation, so trusting a new binary is a reviewable
diff).

(Revisions earlier than the pin abort in SpiderMonkey's rooting assertion
whenever a *suspended* import settles with an `err` result — e.g. any failed
verification; the pin includes the upstream fix,
[dicej/componentize-js#5](https://github.com/dicej/componentize-js/pull/5).)

To use a build of your own instead — a platform with no published asset, or
a revision you are evaluating — put it on `COMPONENTIZE_JS`:

```sh
git clone https://github.com/dicej/componentize-js
cd componentize-js
git checkout "$(cat path/to/js/componentize/componentize-js.rev)"
# Needs WASI-SDK 30 on WASI_SDK_PATH; see that repository's README.
cargo install --path .
export COMPONENTIZE_JS="$(command -v componentize-js)"
```

One further upstream quirk needs no action: an async import that completes
*without* suspending resolves with the raw canonical `result` wrapper
(`{ tag, val }`) instead of the unwrapped value. The library normalizes both
settlement shapes internally (see `callImport` in `webcrypto.js`), so it
works unchanged whether or not that is fixed upstream.
