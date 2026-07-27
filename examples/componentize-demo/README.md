# Example: `componentize-demo`

A JavaScript guest component, built with [componentize-js] (the
wit-dylib–based reboot of ComponentizeJS), that exercises the
WebCrypto-subset library in [`componentize-sdk/`](../../componentize-sdk)
end to end: HMAC-SHA-256 known answers (RFC 4231), AES-256-GCM known answers
(NIST GCM test case 16), round trips including the empty plaintext, and the
key-capability surface (usages, extractability, malformed-input rejection).

[componentize-js]: https://github.com/dicej/componentize-js

The guest exports the same `demo:webcrypto-demo/demo@0.1.0` entry point as
the Rust `crypto-demo` guest, so the existing `crypto-demo-driver` drives it
unchanged, and its `lann:webcrypto` imports are satisfied the same way the
composed demo's are: plugged with the in-guest `guest-webcrypto` provider via
`wac plug`, yielding one self-contained component that runs under plain
`wasmtime run`.

```
app.js  ──componentize-js──▶  componentize-demo.component.wasm
                                   │  wac plug (provider: guest_webcrypto.wasm)
                                   ▼
                              …-with-crypto.wasm
                                   │  wac plug (driver: crypto_demo_driver.wasm)
                                   ▼
                              …-composed.wasm  ──▶  wasmtime run
```

## Prerequisites

Everything in `scripts/setup.sh`, plus the patched componentize-js CLI — see
["Toolchain" in the library's README](../../componentize-sdk/README.md#toolchain)
for install steps (it is not part of the default setup: building it compiles
SpiderMonkey to wasm and needs WASI-SDK 30).

## Running

From the repository root:

```sh
just test-webcrypto-componentize
```

which componentizes `app.js` against [`wit/world.wit`](wit/world.wit)
(module specifiers resolve against the base directory, which the recipe sets
to the repository root — hence the guest's root-relative import of
`./componentize-sdk/webcrypto.js`), composes it with the provider and
driver, and runs the result under `wasmtime`. The driver prints the guest's
self-describing summary, which names every check it ran.

Point the recipe at a non-PATH CLI with
`COMPONENTIZE_JS=/path/to/componentize-js just test-webcrypto-componentize`.
