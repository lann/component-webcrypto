# List the available recipes.
default:
    @just --list

# Run every CI check locally: each CI job runs exactly one job recipe below.
ci: rust-checks jco-checks

# Everything the rust-checks CI job runs, in order.
rust-checks:
    @just _step fmt-check
    @just _step validate-wit
    @just _step clippy
    @just _step test
    @just _step test-webcrypto-composed
    @just _step conformance

# Everything the jco CI job runs.
jco-checks:
    @just _step test-node

# Run one recipe, wrapped in GitHub Actions log groups (and, on failure, an
# error annotation naming the recipe) when running under Actions; a plain
# `just <recipe>` otherwise.
_step recipe:
    #!/usr/bin/env bash
    set -uo pipefail
    gha=; [ "${GITHUB_ACTIONS:-}" = "true" ] && gha=1
    [ -n "$gha" ] && echo "::group::just {{recipe}}"
    just {{recipe}}
    status=$?
    [ -n "$gha" ] && echo "::endgroup::"
    if [ $status -ne 0 ] && [ -n "$gha" ]; then
        echo "::error title=just {{recipe}} failed::exit status $status"
    fi
    exit $status

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

# Run the cross-implementation conformance tests: build the conformance
# guests, run the enabled targets over the self-describing cases, then
# aggregate — validating every results file against the target facts in
# conformance/targets.toml and the checked-in suite lockfiles — and render
# conformance/matrix.md plus the results-viewer data
# (conformance/results/matrix.json), exiting nonzero on any failure or
# transport problem.
#
# Enabled targets: wasmtime, composed, and jco-node (Node 24+ with npm
# required) — plus jco-browser under GitHub Actions (the runner image ships
# Chrome) or when opted in locally with CONFORMANCE_BROWSER=1 (needs
# Chrome/Chromium 137+; targets.toml marks it optional, so the runner warns
# on its missing results rather than failing).
conformance: _conformance-clean conformance-wasmtime conformance-composed conformance-jco-node _conformance-jco-browser-gate
    cargo run --release -p conformance-runner -- \
        --targets conformance/targets.toml \
        --results conformance/results \
        --lock shared=conformance/guest/tests.lock \
        --lock signing=conformance/signing-guest/tests.lock \
        --matrix-out conformance/matrix.md \
        --json-out conformance/results/matrix.json

# Serve the conformance results viewer (a collapsing cross-target matrix
# plus a live "test this browser" run of the suites) after a full
# conformance run. PORT overrides the port (default 8787).
conformance-web: conformance
    node conformance/web/serve.mjs

# Build the API docs for the public-facing crates: the Wasmtime host crate
# and the guest-side SDK. Both document on the host target (the SDK also
# lint-gates there), giving one rustdoc tree with a shared search index in
# target/doc.
rust-docs:
    cargo doc --no-deps -p wasmtime-webcrypto -p lann-webcrypto-guest

# Assemble the Pages site in target/conformance-site: the results viewer
# (used by the pages workflow; assumes a conformance run already produced
# results/matrix.json and the transpiled guests), the public crates' API
# docs, and the landing page linking them. The viewer's subtree mirrors the
# repository layout, which the page's relative URLs and the transpiled
# guests' relative imports both rely on.
conformance-web-site: rust-docs
    rm -rf target/conformance-site
    mkdir -p target/conformance-site/conformance/results \
        target/conformance-site/conformance/adapters/jco \
        target/conformance-site/jco-impl
    cp -r conformance/web target/conformance-site/conformance/web
    rm target/conformance-site/conformance/web/serve.mjs
    cp conformance/results/matrix.json target/conformance-site/conformance/results/
    cp -r conformance/adapters/jco/generated \
        conformance/adapters/jco/generated-signing \
        target/conformance-site/conformance/adapters/jco/
    cp jco-impl/webcrypto.js target/conformance-site/jco-impl/
    cp -r target/doc target/conformance-site/doc
    cp .github/pages/index.html target/conformance-site/index.html

# Clear stale results before a conformance run (a dependency of
# `conformance`, so month-old files never classify as current).
_conformance-clean:
    mkdir -p conformance/results
    rm -f conformance/results/*.json

# Regenerate the suite lockfiles (case names + feature tags) from the built
# guests. Run after any intentional case change — the runner rejects
# results that diverge from the checked-in locks.
update-conformance-lock: build-conformance-guest build-signing-guest
    cargo run --release -p conformance-adapter-wasmtime -- \
        --guest conformance/guest/build/conformance-guest.component.wasm \
        --lock-out conformance/guest/tests.lock
    cargo run --release -p conformance-adapter-wasmtime -- \
        --guest conformance/signing-guest/build/conformance-signing-guest.component.wasm \
        --lock-out conformance/signing-guest/tests.lock

# Run the jco-browser conformance target when gating applies: always under
# GitHub Actions, locally only with CONFORMANCE_BROWSER=1 (skips with a
# notice otherwise). The `conformance` recipe's runner pass classifies the
# results.
_conformance-jco-browser-gate:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ "${GITHUB_ACTIONS:-}" != "true" ] && [ "${CONFORMANCE_BROWSER:-}" != "1" ]; then
        echo "skipping the jco-browser conformance target (opt in with CONFORMANCE_BROWSER=1; needs Chrome/Chromium 137+)"
        exit 0
    fi
    just conformance-jco-browser

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

# Run both conformance suites under the Wasmtime host (the shared guest plus
# the host-only signing guest). Writes conformance/results/wasmtime.json and
# wasmtime-signing.json (both target `wasmtime`; the runner merges them).
conformance-wasmtime: build-conformance-guest build-signing-guest
    mkdir -p conformance/results
    timeout {{conformance-timeout}} cargo run --release -p conformance-adapter-wasmtime -- \
        --guest conformance/guest/build/conformance-guest.component.wasm \
        --suite shared --out conformance/results/wasmtime.json
    timeout {{conformance-timeout}} cargo run --release -p conformance-adapter-wasmtime -- \
        --guest conformance/signing-guest/build/conformance-signing-guest.component.wasm \
        --suite signing --out conformance/results/wasmtime-signing.json

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

# Run the shared conformance suite fully in-guest (RustCrypto in wasm). Writes
# conformance/results/composed.json.
conformance-composed: build-conformance-composed
    mkdir -p conformance/results
    timeout {{conformance-timeout}} wasmtime run -W component-model-async=y -S cli \
        target/conformance-composed.wasm \
        > conformance/results/composed.json

# Run both conformance suites under the jco host on Node (24+; JSPI). Writes
# conformance/results/jco-node.json. Part of `just conformance`.
conformance-jco-node: build-conformance-guest build-signing-guest
    cd conformance/adapters/jco && npm run transpile && npm run transpile:signing && \
        timeout {{conformance-timeout}} npm run run:node && \
        timeout {{conformance-timeout}} npm run run:node-signing

# Run both conformance suites under the jco host in headless Chromium (137+;
# auto-detected, or set CHROME_PATH). Writes conformance/results/jco-browser.json
# and jco-browser-signing.json. Gates in CI; local `just conformance` runs it
# only with CONFORMANCE_BROWSER=1.
conformance-jco-browser: build-conformance-guest build-signing-guest
    cd conformance/adapters/jco && npm run transpile && npm run transpile:signing && \
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
