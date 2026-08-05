# Example: `componentize-demo`

A JavaScript guest component, built with [componentize-js] (the
wit-dylib–based reboot of ComponentizeJS), that exercises the
WebCrypto-subset library in [`js/componentize/`](../../webcrypto-componentize)
end to end: HMAC-SHA-256 known answers (RFC 4231), AES-256-GCM known answers
(NIST GCM test case 16), round trips including the empty plaintext, and the
key-capability surface (usages, extractability, malformed-input rejection).

[componentize-js]: https://github.com/dicej/componentize-js

The guest exports the same `demo:webcrypto-demo/demo@0.1.0` entry point as
the Rust `crypto-demo` guest, so the existing `crypto-demo-driver` drives it
unchanged, and its `polymorph:webcrypto` imports are satisfied the same way the
composed demo's are: plugged with the in-guest `polymorph-webcrypto-guest-provider` provider via
`wac plug`, yielding one self-contained component that runs under plain
`wasmtime run`.

```
app.js  ──componentize-js──▶  componentize-demo.component.wasm
                                   │  wac plug (provider: polymorph_webcrypto_guest_provider.wasm)
                                   ▼
                              …-with-crypto.wasm
                                   │  wac plug (driver: crypto_demo_driver.wasm)
                                   ▼
                              …-composed.wasm  ──▶  wasmtime run
```

## Prerequisites

Everything in `scripts/setup.sh`. The componentize-js CLI build the
recipes need is downloaded and digest-verified automatically on first use
(`component.sh toolchain`; set `COMPONENTIZE_JS` to use your own build) —
see ["Toolchain" in the library's README](../../js/componentize/README.md#toolchain).

## Running

From the repository root:

```sh
just componentize::test
```

which componentizes `app.js` against [`wit/world.wit`](wit/world.wit)
(module specifiers resolve against the base directory, which the recipe sets
to the repository root — hence the guest's root-relative import of
`./js/componentize/webcrypto.js`), composes it with the provider and
driver, and runs the result under `wasmtime`. The driver prints the guest's
self-describing summary, which names every check it ran.

Point the recipe at a non-PATH CLI with
`COMPONENTIZE_JS=/path/to/componentize-js just componentize::test`.
