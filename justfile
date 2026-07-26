# List the available recipes.
default:
    @just --list

# Run every CI check locally, in the same order as .github/workflows/ci.yml.
ci: fmt-check validate-wit clippy test test-webcrypto-composed conformance test-node

# Run the fast pre-commit checks (fmt, clippy, WIT, Rust tests).
check: fmt-check clippy validate-wit test

# Check formatting across all crates.
fmt-check:
    cargo fmt --all -- --check

# Run clippy across all crates (the wasm crates on their wasm targets).
clippy:
    cargo clippy --workspace --exclude crypto-demo --exclude guest-webcrypto --exclude crypto-demo-driver --exclude conformance-guest --exclude conformance-signing-guest --exclude conformance-composed-driver --exclude timing-lab -- -D warnings
    cargo clippy -p crypto-demo --target wasm32-unknown-unknown -- -D warnings
    cargo clippy -p conformance-guest --target wasm32-unknown-unknown -- -D warnings
    cargo clippy -p conformance-signing-guest --target wasm32-unknown-unknown -- -D warnings
    cargo clippy -p guest-webcrypto --target wasm32-wasip2 -- -D warnings
    cargo clippy -p crypto-demo-driver --target wasm32-wasip2 -- -D warnings
    cargo clippy -p timing-lab --target wasm32-wasip2 -- -D warnings
    cargo clippy -p conformance-composed-driver --target wasm32-wasip2 -- -D warnings

# Validate WIT packages.
validate-wit:
    wasm-tools component wit wit
    wasm-tools component wit wasmtime-impl/wit
    wasm-tools component wit guest-impl/wit
    wasm-tools component wit examples/crypto-demo/wit
    wasm-tools component wit conformance/guest/wit

# Run the Rust tests, including the wasmtime-demo integration test (which
# builds and runs the crypto-demo guest under the Wasmtime host).
test:
    cargo test --workspace --exclude crypto-demo --exclude guest-webcrypto --exclude crypto-demo-driver --exclude conformance-guest --exclude conformance-signing-guest --exclude conformance-composed-driver --exclude timing-lab

# Build the crypto-demo guest component into examples/crypto-demo/build/.
build-component:
    cd examples/jco-demo && npm run build:component

# Transpile the crypto-demo component for the Node host (runs build-component).
transpile: build-component
    cd examples/jco-demo && npm run transpile

# Run the Node (browser-compatible WebCrypto) host. Needs Node 24+ (jco's
# async ABI uses JSPI, which Node exposes behind --experimental-wasm-jspi).
test-node: transpile
    cd examples/jco-demo && npm test

# Run the Wasmtime (native, RustCrypto) host demo.
demo-wasmtime: build-component
    cargo run --release --bin wasmtime-webcrypto-host -- \
        examples/crypto-demo/build/crypto-demo.component.wasm

# Build the in-guest provider component (RustCrypto entirely in-guest; it
# exports the lann:webcrypto surface) into
# target/wasm32-wasip2/release/guest_webcrypto.wasm.
build-guest-provider:
    cargo build --release -p guest-webcrypto --target wasm32-wasip2

# Compose the fully in-guest demo: the crypto-demo guest's lann:webcrypto
# imports are satisfied by the in-guest provider's exports (`wac plug`), then
# the CLI driver (async wasi:cli/run) is plugged on top, yielding one
# self-contained component in target/crypto-demo-composed.wasm.
compose-demo: build-component build-guest-provider
    cargo build --release -p crypto-demo-driver --target wasm32-wasip2
    wac plug examples/crypto-demo/build/crypto-demo.component.wasm \
        --plug target/wasm32-wasip2/release/guest_webcrypto.wasm \
        -o target/crypto-demo-with-crypto.wasm
    wac plug target/wasm32-wasip2/release/crypto_demo_driver.wasm \
        --plug target/crypto-demo-with-crypto.wasm \
        -o target/crypto-demo-composed.wasm

# In-guest integration test: run the composed demo under `wasmtime` — the
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
# Enabled targets: wasmtime, composed, and jco-node (Node 24+ with npm
# required). jco-browser is not gating — it needs a Chromium install; run it
# manually with `just conformance-jco-browser` (the runner warns on targets
# without results rather than failing).
conformance: conformance-wasmtime conformance-composed conformance-jco-node
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

# Build the host-only signing guest component (probes for interfaces the
# in-guest provider deliberately does not export) into
# conformance/signing-guest/build/.
build-signing-guest:
    cargo build --release -p conformance-signing-guest --target wasm32-unknown-unknown
    mkdir -p conformance/signing-guest/build
    wasm-tools component new \
        target/wasm32-unknown-unknown/release/conformance_signing_guest.wasm \
        -o conformance/signing-guest/build/conformance-signing-guest.component.wasm

# Run the conformance corpus under the Wasmtime host (the shared guest plus
# the host-only signing guest). Writes conformance/results/wasmtime.json and
# wasmtime-signing.json (both target `wasmtime`; the runner merges them).
conformance-wasmtime: build-conformance-guest build-signing-guest
    mkdir -p conformance/results
    timeout {{conformance-timeout}} cargo run --release -p conformance-adapter-wasmtime -- \
        --guest conformance/guest/build/conformance-guest.component.wasm \
        --out conformance/results/wasmtime.json
    timeout {{conformance-timeout}} cargo run --release -p conformance-adapter-wasmtime -- \
        --guest conformance/signing-guest/build/conformance-signing-guest.component.wasm \
        --out conformance/results/wasmtime-signing.json

# Build the composed conformance component: the conformance guest
# plugged with the in-guest provider, under the CLI driver that prints the
# results JSON on stdout.
build-conformance-composed: build-conformance-guest build-guest-provider
    cargo build --release -p conformance-composed-driver --target wasm32-wasip2
    wac plug conformance/guest/build/conformance-guest.component.wasm \
        --plug target/wasm32-wasip2/release/guest_webcrypto.wasm \
        -o target/conformance-with-crypto.wasm
    wac plug target/wasm32-wasip2/release/conformance_composed_driver.wasm \
        --plug target/conformance-with-crypto.wasm \
        -o target/conformance-composed.wasm

# Run the conformance corpus fully in-guest (RustCrypto in wasm). Writes
# conformance/results/composed.json.
conformance-composed: build-conformance-composed
    mkdir -p conformance/results
    timeout {{conformance-timeout}} wasmtime run -W component-model-async=y -S cli \
        target/conformance-composed.wasm \
        > conformance/results/composed.json

# Run the conformance corpus under the jco host on Node (24+; JSPI). Writes
# conformance/results/jco-node.json. Part of `just conformance`.
conformance-jco-node: build-conformance-guest build-signing-guest
    cd conformance/adapters/jco && npm run transpile && npm run transpile:signing && \
        timeout {{conformance-timeout}} npm run run:node && \
        timeout {{conformance-timeout}} npm run run:node-signing

# Run the conformance corpus under the jco host in headless Chromium (137+;
# auto-detected, or set CHROME_PATH). Writes conformance/results/jco-browser.json.
# Not gating — needs a Chromium install; run it manually.
conformance-jco-browser: build-conformance-guest
    cd conformance/adapters/jco && npm run transpile && \
        timeout {{conformance-timeout}} npm run run:browser

# --- timing lab ---------------------------------------------------------------

# Compose the timing lab with the in-guest provider: the lab's lann:webcrypto
# imports are satisfied by the provider under measurement, yielding one
# self-contained component in target/timing-lab-composed.wasm.
compose-timing-lab: build-guest-provider
    cargo build --release -p timing-lab --target wasm32-wasip2
    wac plug target/wasm32-wasip2/release/timing_lab.wasm \
        --plug target/wasm32-wasip2/release/guest_webcrypto.wasm \
        -o target/timing-lab-composed.wasm

# Run the dudect-style timing lab against the composed in-guest provider.
# Statistical and environment-sensitive by nature, so deliberately NOT part
# of `just ci` — run it on a quiet machine. Set TIMING_LAB_SAMPLES to trade
# runtime for sensitivity.
timing-lab: compose-timing-lab
    wasmtime run -W component-model-async=y -S cli \
        --env TIMING_LAB_SAMPLES \
        target/timing-lab-composed.wasm
