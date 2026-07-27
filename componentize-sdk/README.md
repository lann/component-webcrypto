# componentize-sdk

A WebCrypto-subset library for JavaScript guests componentized with
[componentize-js] (the wit-dylib–based reboot of ComponentizeJS), backed by
the `lann:webcrypto` interfaces. This is the JS-guest counterpart of the Rust
[`guest-sdk`](../guest-sdk): where `guest-sdk` wraps the raw bindings in
ergonomic Rust newtypes, `webcrypto.js` wraps them in the API JS code already
knows — `crypto.subtle`.

[componentize-js]: https://github.com/dicej/componentize-js

## Surface

`webcrypto.js` exports `subtle` (and a `crypto`-shaped `{ subtle }`
namespace) serving:

| method | algorithms |
| --- | --- |
| `importKey` / `exportKey` | `"raw"` format |
| `generateKey` | HMAC-SHA-256, AES-256-GCM |
| `sign` / `verify` | HMAC-SHA-256 |
| `encrypt` / `decrypt` | AES-256-GCM |

Keys are `CryptoKey` objects (`type: "secret"`, `algorithm`, `extractable`,
`usages`) wrapping `lann:webcrypto` key resources; usages and extractability
are enforced with WebCrypto's error vocabulary. The library maps the WIT
`types.error` variant onto that vocabulary (`authentication-failed` →
`OperationError`, `not-extractable` → `InvalidAccessError`, `invalid-key` →
`DataError`, `unsupported` → `NotSupportedError`), and `verify` is the one
place a failed verification maps back to WebCrypto's `false` verdict; every
other failure stays a thrown error, preserving the WIT surface's fail-closed
shape.

Deviations from the Web Cryptography API are documented at the top of
`webcrypto.js`; all of them fail closed with clear errors rather than
silently differing (fixed 12-byte GCM IVs and 128-bit tags per the
`lann:webcrypto` contract, `"raw"` keys only, the two algorithms only, and a
minimal `DOMException` stand-in, which the componentize-js runtime lacks).

Within that subset the library tracks the spec closely enough to pass the
relevant [web-platform-tests] suites: [`wpt/`](wpt) vendors the WebCryptoAPI
sign/verify, encrypt/decrypt, importKey, and generateKey tests and runs them
against this library (`just test-webcrypto-componentize-wpt`, a gating CI
check); every in-subset test must pass, and the out-of-subset remainder of
WPT's parameter sweep is reported failing closed. See
[`wpt/README.md`](wpt/README.md) for the vendoring and subset policy, and
for how the check runs a lock-keyed release-artifact component so neither CI
nor contributors need the componentize-js toolchain.

[web-platform-tests]: https://github.com/web-platform-tests/wpt

## Using it in a component

The component's world must import `lann:webcrypto/hmac-sha2@0.1.0` and
`lann:webcrypto/aes-gcm@0.1.0` (WIT elaboration pulls in their
`mac`/`aead`/`types` dependencies) — see
[`examples/componentize-demo`](../examples/componentize-demo) for a complete
world, guest, and composition. The library is a single file with no
dependencies; componentize-js resolves its `lann:webcrypto/...` module
specifiers against the world at componentize time, and resolves the library
itself as a file path relative to `componentize-js componentize`'s
`--base-directory`.

Bulk data crosses the interface as `stream<u8>`: operations resolve only
once their input stream's writer is dropped, so the library feeds input and
awaits each operation concurrently, and collects `seal`/`open` output
streams concurrently with the feed (the package's drain rule guarantees the
feed always completes, even when the operation fails).

## Toolchain

The componentize-js CLI is needed only to *(re)generate* JS guest components
(`just build-componentize-demo`, `just update-wpt-component`) — never to run
them: CI's gating WPT check downloads the runner component published on the
repository's `wpt-components` release (CI's `wpt-component` job builds and
publishes it when the inputs change) and runs it with just `wasmtime` and
`wac`, so the gating path never compiles SpiderMonkey.

Regenerating needs componentize-js at the revision pinned in
[`componentize-js.rev`](componentize-js.rev), with one runtime fix this
repository carries as
[`componentize-js-rooting-fix.patch`](componentize-js-rooting-fix.patch)
until it lands upstream: the async-import completion path unroots GC roots
out of LIFO order whenever a *suspended* import settles with an `err`
result — e.g. any failed verification — aborting the guest inside
SpiderMonkey's rooting assertion. To install:

```sh
git clone https://github.com/dicej/componentize-js
cd componentize-js
git checkout "$(cat path/to/componentize-sdk/componentize-js.rev)"
git apply path/to/componentize-sdk/componentize-js-rooting-fix.patch
# Needs WASI-SDK 30 on WASI_SDK_PATH; see that repository's README.
cargo install --path .
```

One further upstream quirk needs no action: an async import that completes
*without* suspending resolves with the raw canonical `result` wrapper
(`{ tag, val }`) instead of the unwrapped value. The library normalizes both
settlement shapes internally (see `callImport` in `webcrypto.js`), so it
works unchanged whether or not that is fixed upstream.
