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
    cargo clippy --workspace --exclude crypto-demo --exclude wasip3-webcrypto --exclude crypto-demo-driver -- -D warnings
    cargo clippy -p crypto-demo --target wasm32-unknown-unknown -- -D warnings
    cargo clippy -p wasip3-webcrypto --target wasm32-wasip2 -- -D warnings
    cargo clippy -p crypto-demo-driver --target wasm32-wasip2 -- -D warnings

# Validate WIT packages.
validate-wit:
    wasm-tools component wit wit
    wasm-tools component wit wasmtime-impl/wit
    wasm-tools component wit wasip3-impl/wit
    wasm-tools component wit examples/crypto-demo/wit

# Run the Rust tests, including the wasmtime-demo integration test (which
# builds and runs the crypto-demo guest under the Wasmtime host).
test:
    cargo test --workspace --exclude crypto-demo --exclude wasip3-webcrypto --exclude crypto-demo-driver

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
