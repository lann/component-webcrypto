# List the available recipes.
default:
    @just --list

# Run every CI check locally, in the same order as .github/workflows/ci.yml.
ci: fmt-check clippy validate-wit test test-webcrypto-composed build-component transpile test-node

# Run the fast pre-commit checks (fmt, clippy, WIT, Rust tests).
check: fmt-check clippy validate-wit test

# Check formatting across all crates.
fmt-check:
    cargo fmt --all -- --check

# Run clippy across all crates (the wasm crates on their wasm targets).
clippy:
    cargo clippy --workspace --exclude crypto-demo --exclude wasip3-webcrypto --exclude crypto-demo-driver --exclude conformance-guest --exclude conformance-wasip3-driver -- -D warnings
    cargo clippy -p crypto-demo --target wasm32-unknown-unknown -- -D warnings
    cargo clippy -p conformance-guest --target wasm32-unknown-unknown -- -D warnings
    cargo clippy -p wasip3-webcrypto --target wasm32-wasip2 -- -D warnings
    cargo clippy -p crypto-demo-driver --target wasm32-wasip2 -- -D warnings
    cargo clippy -p conformance-wasip3-driver --target wasm32-wasip2 -- -D warnings

# Validate WIT packages.
validate-wit:
    wasm-tools component wit wit
    wasm-tools component wit wasmtime-impl/wit
    wasm-tools component wit wasip3-impl/wit
    wasm-tools component wit examples/crypto-demo/wit
    wasm-tools component wit conformance/guest/wit

# Run the Rust tests, including the wasmtime-demo integration test (which
# builds and runs the crypto-demo guest under the Wasmtime host).
test:
    cargo test --workspace --exclude crypto-demo --exclude wasip3-webcrypto --exclude crypto-demo-driver --exclude conformance-guest --exclude conformance-wasip3-driver

# Build the crypto-demo guest component into examples/crypto-demo/build/.
build-component:
    cd jco-impl && npm run build:component

# Transpile the crypto-demo component for the Node host (runs build-component).
transpile: build-component
    cd jco-impl && npm run transpile

# Run the Node (browser-compatible WebCrypto) host. Needs Node 24+ (jco's
# async ABI uses JSPI, which Node exposes behind --experimental-wasm-jspi).
test-node: transpile
    cd jco-impl && npm test

# Run the Wasmtime (native, RustCrypto) host demo.
demo-wasmtime: build-component
    cargo run --release --bin wasmtime-webcrypto-host -- \
        examples/crypto-demo/build/crypto-demo.component.wasm

# Build the wasip3 provider component (RustCrypto entirely in-guest; it
# exports the lann:webcrypto surface) into
# target/wasm32-wasip2/release/wasip3_webcrypto.wasm.
build-wasip3-provider:
    cargo build --release -p wasip3-webcrypto --target wasm32-wasip2

# Compose the fully in-guest demo: the crypto-demo guest's lann:webcrypto
# imports are satisfied by the wasip3 provider's exports (`wac plug`), then
# the CLI driver (async wasi:cli/run) is plugged on top, yielding one
# self-contained component in target/crypto-demo-composed.wasm.
compose-demo: build-component build-wasip3-provider
    cargo build --release -p crypto-demo-driver --target wasm32-wasip2
    wac plug examples/crypto-demo/build/crypto-demo.component.wasm \
        --plug target/wasm32-wasip2/release/wasip3_webcrypto.wasm \
        -o target/crypto-demo-with-crypto.wasm
    wac plug target/wasm32-wasip2/release/crypto_demo_driver.wasm \
        --plug target/crypto-demo-with-crypto.wasm \
        -o target/crypto-demo-composed.wasm

# In-guest integration test: run the composed demo under `wasmtime` — all 13
# guest checks execute against RustCrypto running entirely inside wasm.
# Needs `wasmtime` (v47+) and `wac` on PATH.
test-webcrypto-composed: compose-demo
    timeout 120 wasmtime run -W component-model-async=y -S cli \
        target/crypto-demo-composed.wasm

# --- conformance -------------------------------------------------------------

# The whole-run safety cap (seconds) for each conformance target invocation.
conformance-timeout := "600"

# Run the cross-implementation conformance suite: build the shared conformance
# guest, run the enabled targets over the Wycheproof-derived corpus +
# API-contract probes, then classify against conformance/manifests.toml and
# render conformance/matrix.md, exiting nonzero on any fail or
# unexpected-pass.
#
# Enabled targets: wasmtime and wasip3-guest. The jco targets (jco-node,
# jco-browser) are TEMPORARILY not gating: jco's component-model-async runtime
# corrupts the guest heap under this corpus (the identical binary runs clean
# under Wasmtime); the runner reports them as "targets without results". Run
# them manually with `just conformance-jco-node` / `conformance-jco-browser`
# to check an upstream fix, and add them back here when it lands (diagnosis:
# GUEST-HEAP-CORRUPTION-DEBUG.md in the jco checkout).
conformance: conformance-wasmtime conformance-wasip3
    cargo run --release -p conformance-runner -- \
        --manifests conformance/manifests.toml \
        --results conformance/results \
        --matrix-out conformance/matrix.md

# Build the shared conformance guest component into conformance/guest/build/.
build-conformance-guest:
    cargo build --release -p conformance-guest --target wasm32-unknown-unknown
    mkdir -p conformance/guest/build
    wasm-tools component new \
        target/wasm32-unknown-unknown/release/conformance_guest.wasm \
        -o conformance/guest/build/conformance-guest.component.wasm

# Run the conformance corpus under the Wasmtime host. Writes
# conformance/results/wasmtime.json.
conformance-wasmtime: build-conformance-guest
    mkdir -p conformance/results
    timeout {{conformance-timeout}} cargo run --release -p conformance-adapter-wasmtime -- \
        --guest conformance/guest/build/conformance-guest.component.wasm \
        --out conformance/results/wasmtime.json

# Build the composed wasip3-guest conformance component: the conformance guest
# plugged with the wasip3 provider, under the CLI driver that prints the
# results JSON on stdout.
build-conformance-wasip3: build-conformance-guest build-wasip3-provider
    cargo build --release -p conformance-wasip3-driver --target wasm32-wasip2
    wac plug conformance/guest/build/conformance-guest.component.wasm \
        --plug target/wasm32-wasip2/release/wasip3_webcrypto.wasm \
        -o target/conformance-with-crypto.wasm
    wac plug target/wasm32-wasip2/release/conformance_wasip3_driver.wasm \
        --plug target/conformance-with-crypto.wasm \
        -o target/conformance-wasip3-composed.wasm

# Run the conformance corpus fully in-guest (RustCrypto in wasm). Writes
# conformance/results/wasip3-guest.json.
conformance-wasip3: build-conformance-wasip3
    mkdir -p conformance/results
    timeout {{conformance-timeout}} wasmtime run -W component-model-async=y -S cli \
        target/conformance-wasip3-composed.wasm \
        > conformance/results/wasip3-guest.json

# Run the conformance corpus under the jco host on Node (24+; JSPI). Writes
# conformance/results/jco-node.json. NOT yet part of `just conformance` — see
# that recipe's comment for the upstream jco blocker this checks for.
conformance-jco-node: build-conformance-guest
    cd conformance/adapters/jco && npm run transpile && \
        timeout {{conformance-timeout}} npm run run:node

# Run the conformance corpus under the jco host in headless Chromium (137+;
# auto-detected, or set CHROME_PATH). Writes conformance/results/jco-browser.json.
# NOT yet part of `just conformance` — same upstream jco blocker as jco-node.
conformance-jco-browser: build-conformance-guest
    cd conformance/adapters/jco && npm run transpile && \
        timeout {{conformance-timeout}} npm run run:browser
