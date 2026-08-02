# List the available recipes.
default:
    @just --list

# Run every CI check locally: each CI job runs exactly one job recipe below.
ci: rust-checks jco-checks componentize-checks

# Everything the rust-checks CI job runs, in order.
rust-checks:
    @just _step fmt-check
    @just _step validate-wit
    @just _step clippy
    @just _step test
    @just _step test-webcrypto-composed
    @just _step conformance

# Everything the jco CI job runs. The three WPT parity engines run in
# parallel over one shared artifact build (_wpt-parity-gates).
jco-checks:
    @just _step typecheck-jco
    @just _step test-jco-host
    @just _step test-node
    @just _step _wpt-parity-gates

# Everything the componentize CI job runs: the webcrypto-componentize JS
# guest library's behavioral checks (the composed demo) and the WPT
# WebCryptoAPI suites against it.
componentize-checks:
    @just _step typecheck-webcrypto-componentize
    @just _step test-webcrypto-componentize
    @just _step test-webcrypto-componentize-wpt

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
    cargo clippy --workspace --exclude crypto-demo --exclude lann-webcrypto-guest-provider --exclude crypto-demo-driver --exclude conformance-guest --exclude conformance-signing-guest --exclude conformance-composed-driver --exclude timing-lab -- -D warnings
    cargo clippy -p crypto-demo --target wasm32-unknown-unknown -- -D warnings
    cargo clippy -p conformance-guest --target wasm32-unknown-unknown -- -D warnings
    cargo clippy -p conformance-signing-guest --target wasm32-unknown-unknown -- -D warnings
    cargo clippy -p lann-webcrypto-guest-provider --target wasm32-wasip2 -- -D warnings
    cargo clippy -p crypto-demo-driver --target wasm32-wasip2 -- -D warnings
    cargo clippy -p timing-lab --target wasm32-wasip2 -- -D warnings
    cargo clippy -p conformance-composed-driver --target wasm32-wasip2 -- -D warnings
    # lann-webcrypto-guest's optional source adaptors are only compiled with their
    # features on, and one of them holds the only code path that can produce
    # `Error::Read` — the crate's subtlest behaviour. Nothing in the
    # workspace enables them, so without this they are never checked.
    cargo clippy -p lann-webcrypto-guest --all-features --target wasm32-wasip2 -- -D warnings

# Validate WIT packages.
validate-wit:
    # Each package is validated in both views: the default (the @unstable
    # ChaCha gates hidden — what a consumer sees without opting in) and
    # with every feature enabled.
    wasm-tools component wit wit
    wasm-tools component wit wit --all-features
    wasm-tools component wit rust/wasmtime/wit
    wasm-tools component wit rust/wasmtime/wit --all-features
    wasm-tools component wit js/jco/wit
    wasm-tools component wit js/jco/wit --all-features
    wasm-tools component wit rust/guest-provider/wit
    wasm-tools component wit rust/guest-provider/wit --all-features
    wasm-tools component wit examples/crypto-demo/wit
    wasm-tools component wit examples/crypto-demo/wit --all-features
    wasm-tools component wit js/componentize/wpt/wit
    wasm-tools component wit js/componentize/wpt/wit --all-features
    wasm-tools component wit examples/componentize-demo/wit
    wasm-tools component wit js/componentize/wpt/wit
    wasm-tools component wit conformance/guest/wit

# Run the Rust tests, including the wasmtime-demo integration test (which
# builds and runs the crypto-demo guest under the Wasmtime host).
test:
    cargo test --workspace --exclude crypto-demo --exclude crypto-demo-driver --exclude conformance-guest --exclude conformance-signing-guest --exclude conformance-composed-driver --exclude timing-lab

# Build the crypto-demo guest component into examples/crypto-demo/build/.
# The output is renamed into place: `wasm-tools component new -o` truncates
# in place, so a direct write would expose an empty or partial component to
# a concurrent reader (the wasmtime-demo tests load this path).
build-component:
    cargo build --release -p crypto-demo --target wasm32-unknown-unknown
    mkdir -p examples/crypto-demo/build
    wasm-tools component new \
        target/wasm32-unknown-unknown/release/crypto_demo.wasm \
        -o examples/crypto-demo/build/crypto-demo.component.wasm.tmp
    mv -f examples/crypto-demo/build/crypto-demo.component.wasm.tmp \
        examples/crypto-demo/build/crypto-demo.component.wasm

# Transpile the crypto-demo component for the Node host (runs build-component).
transpile: build-component
    cd examples/jco-demo && npm run transpile

# Run the Node (browser-compatible WebCrypto) host. Needs Node 24+ (jco's
# async ABI uses JSPI, which Node exposes behind --experimental-wasm-jspi).
test-node: transpile
    cd examples/jco-demo && npm test

# Run the jco host's own unit tests: the input-buffering admission subsystem,
# which the conformance suite cannot reach because its workers each run their
# cases sequentially against their own host instance.
test-jco-host:
    cd js/jco && npm test

# Type-check the jco host against the interface definitions jco-transpile
# derives from `wit/`. The definitions are generated on demand, so there is
# no checked-in copy to go stale.
typecheck-jco:
    cd js/jco && npm run typecheck

# Type-check the componentize-js guest library against the Web Cryptography
# API definitions TypeScript ships. Nothing is generated, so nothing can go
# stale; no component build.
typecheck-webcrypto-componentize:
    cd js/componentize && npm run typecheck

# Run the Wasmtime (native, RustCrypto) host demo.
demo-wasmtime: build-component
    cargo run --release --bin wasmtime-demo-host -- \
        examples/crypto-demo/build/crypto-demo.component.wasm

# Build the in-guest provider component (RustCrypto entirely in-guest; it
# exports the lann:webcrypto surface) into
# target/wasm32-wasip2/release/lann_webcrypto_guest_provider.wasm.
build-guest-provider:
    cargo build --release -p lann-webcrypto-guest-provider --target wasm32-wasip2

# Compose `guest` with the in-guest provider and plug `driver` (a
# wasm32-wasip2 bin crate) on top, yielding one self-contained component at
# target/<stem>-composed.wasm (via target/<stem>-with-crypto.wasm). Every
# composition in this file is this same two-step `wac plug`.
_compose stem guest driver: build-guest-provider
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build --release -p {{driver}} --target wasm32-wasip2
    driver_wasm="target/wasm32-wasip2/release/$(echo '{{driver}}' | tr - _).wasm"
    wac plug {{guest}} \
        --plug target/wasm32-wasip2/release/lann_webcrypto_guest_provider.wasm \
        -o target/{{stem}}-with-crypto.wasm
    wac plug "$driver_wasm" \
        --plug target/{{stem}}-with-crypto.wasm \
        -o target/{{stem}}-composed.wasm

# Compose the fully in-guest demo: the crypto-demo guest's lann:webcrypto
# imports are satisfied by the in-guest provider's exports (`wac plug`), then
# the CLI driver (async wasi:cli/run) is plugged on top, yielding one
# self-contained component in target/crypto-demo-composed.wasm.
compose-demo: build-component (_compose "crypto-demo" "examples/crypto-demo/build/crypto-demo.component.wasm" "crypto-demo-driver")

# In-guest integration test: run the composed demo under `wasmtime` — the
# guest checks execute against RustCrypto running entirely inside wasm.
# Needs `wasmtime` (v47+) and `wac` on PATH.
test-webcrypto-composed: compose-demo
    timeout 120 wasmtime run -W component-model-async=y -S cli \
        target/crypto-demo-composed.wasm

# --- componentize-js (JS guest) demo ------------------------------------------

# The componentize-js CLI (dicej's ComponentizeJS reboot) used to
# (re)generate the JS guest components. Building it compiles SpiderMonkey to
# wasm and needs WASI-SDK 30, so nobody here builds it: the
# componentize-js-toolchain workflow publishes one build per pinned revision
# and platform, and `component.sh toolchain` downloads it into
# target/toolchains on first use (set COMPONENTIZE_JS to use your own build
# instead). The pinned revision lives in js/componentize/componentize-js.rev.

# Componentize the JS WebCrypto-subset demo guest (webcrypto-componentize library +
# examples/componentize-demo app) into examples/componentize-demo/build/.
# The base directory is the repository root, so the app's module specifiers
# (./js/componentize/webcrypto.js) resolve against it.
build-componentize-demo:
    mkdir -p examples/componentize-demo/build
    "$(js/componentize/wpt/component.sh toolchain)" \
        -q -d examples/componentize-demo/wit -w componentize-demo \
        --features chacha20-poly1305,sha1-checked \
        componentize examples/componentize-demo/app.js -p . \
        -o examples/componentize-demo/build/componentize-demo.component.wasm

# Compose the fully in-guest JS demo (the `compose-demo` recipe with the JS
# guest in place of the Rust one): the JS guest's lann:webcrypto imports are
# satisfied by the in-guest provider, then the CLI driver is plugged on top.
compose-componentize-demo: build-componentize-demo (_compose "componentize-demo" "examples/componentize-demo/build/componentize-demo.component.wasm" "crypto-demo-driver")

# JS-guest integration test: run the composed JS demo under `wasmtime` — the
# WebCrypto-subset library's checks execute against RustCrypto running
# entirely inside wasm. Needs `wasmtime` (v47+) and `wac` on PATH; the
# componentize-js toolchain is downloaded (see above).
test-webcrypto-componentize: compose-componentize-demo
    timeout 120 wasmtime run -W component-model-async=y -S cli \
        target/componentize-demo-composed.wasm

# Record the digests of the published componentize-js build for the pinned
# revision, after verifying its build-provenance attestation (needs `gh`).
# Run this when componentize-js.rev changes and the toolchain workflow has
# published the new build: until its digests are recorded, every consumer
# refuses to execute it. Pass a platform to record one you are not running
# on, e.g. `just update-toolchain-digest linux-x86_64`.
update-toolchain-digest platform="":
    js/componentize/wpt/update-toolchain-digest.sh {{platform}}

# Run the vendored web-platform-tests WebCryptoAPI suites against the
# webcrypto-componentize library: every in-subset test must pass; out-of-subset
# tests are reported by count (js/componentize/wpt/README.md has the
# vendoring and subset policy). The runner is componentized from the working
# tree with the pinned componentize-js (downloaded on first use), then
# composed with a freshly built in-guest provider and driver and run under
# `wasmtime` (v47+) and `wac`, like test-webcrypto-composed.
test-webcrypto-componentize-wpt: compose-wpt-runner
    timeout 600 wasmtime run -W component-model-async=y -S cli \
        target/wpt-runner-composed.wasm

# Componentize the WPT runner from the working tree and compose it with a
# freshly built in-guest provider and driver.
compose-wpt-runner: _componentize-wpt-runner (_compose "wpt-runner" "js/componentize/wpt/build/runner.component.wasm" "crypto-demo-driver")

# Componentize the WPT runner from the working tree with the pinned
# componentize-js (downloaded on first use).
_componentize-wpt-runner:
    js/componentize/wpt/component.sh build

# Re-record js/componentize/wpt/expected.js from an actual run: run this
# when a change legitimately moves a count, and review the diff — each moved
# number is a test that appeared, vanished, or crossed the in-subset
# boundary.
update-wpt-expectations: compose-wpt-runner
    js/componentize/wpt/update-expectations.sh target/wpt-runner-composed.wasm

# --- WPT parity (jco path) ------------------------------------------------------

# Run the WPT parity gate: the vendored WPT suites run twice — directly
# against this platform's own crypto.subtle (the baseline) and through the
# componentized shim transpiled by jco against js/jco/webcrypto.js (the
# round trip) — and the comparator holds the round trip to the baseline's
# pass set, with known losses pinned in js/componentize/wpt/parity/losses.js.
# Both legs end at the same platform crypto, so the delta isolates exactly
# what the carrier stack (shim, WIT shape, component ABI, jco) loses.
# Needs Node 24+ and the pinned componentize-js (downloaded — see
# js/componentize/wpt/component.sh).
wpt-parity: _wpt-parity-artifacts _wpt-parity-node-run

# The Node engine's legs + comparator; the artifacts are already built
# (_wpt-parity-artifacts), so parallel engine runs share one build.
_wpt-parity-node-run: _wpt-parity-node-legs
    node js/componentize/wpt/parity/compare.mjs \
        js/componentize/wpt/build/parity-baseline.json \
        js/componentize/wpt/build/parity-roundtrip.json

# Re-record js/componentize/wpt/parity/losses.js from an actual run: run
# this when a change legitimately moves the loss set, and review the diff —
# every removed line is a platform behavior the round trip now preserves,
# and every added line needs a classification in the shim header's
# deviations registry.
update-wpt-parity: _wpt-parity-legs
    node js/componentize/wpt/parity/compare.mjs \
        js/componentize/wpt/build/parity-baseline.json \
        js/componentize/wpt/build/parity-roundtrip.json --update

# Run the WPT parity gate in headless Firefox: the same two legs as
# `just wpt-parity`, both executed in the browser (the round trip through
# the same worker-loadable transpile the parity page uses), held to the
# engine's own pinned loss set in js/componentize/wpt/parity/losses-firefox.js
# — a loss set is a fact about one engine's baseline, so each engine
# ratchets separately. The engine is Playwright's pinned Firefox build,
# launched with Gecko's JSPI pref; install it once with
# `cd js/componentize/wpt/parity && npx playwright-core install --with-deps firefox`.
wpt-parity-firefox: wpt-web-artifacts _wpt-parity-firefox-run

# The Firefox engine's run + comparator; the web artifacts are already
# built (wpt-web-artifacts).
_wpt-parity-firefox-run:
    cd js/componentize/wpt/parity && timeout 900 npm run -s run:firefox
    node js/componentize/wpt/parity/compare.mjs \
        js/componentize/wpt/build/parity-baseline-firefox.json \
        js/componentize/wpt/build/parity-roundtrip-firefox.json \
        --losses losses-firefox.js

# Re-record js/componentize/wpt/parity/losses-firefox.js from an actual
# run, like update-wpt-parity.
update-wpt-parity-firefox: wpt-web-artifacts
    cd js/componentize/wpt/parity && timeout 900 npm run -s run:firefox
    node js/componentize/wpt/parity/compare.mjs \
        js/componentize/wpt/build/parity-baseline-firefox.json \
        js/componentize/wpt/build/parity-roundtrip-firefox.json \
        --losses losses-firefox.js --update

# Run the WPT parity gate in headless Chromium: like wpt-parity-firefox,
# against Chromium's own pinned loss set in
# js/componentize/wpt/parity/losses-chromium.js. The engine is Playwright's
# pinned Chromium build (which ships JSPI); install it once with
# `cd js/componentize/wpt/parity && npx playwright-core install --with-deps chromium`.
wpt-parity-chromium: wpt-web-artifacts _wpt-parity-chromium-run

# The Chromium engine's run + comparator; the web artifacts are already
# built (wpt-web-artifacts).
_wpt-parity-chromium-run:
    cd js/componentize/wpt/parity && timeout 900 npm run -s run:chromium
    node js/componentize/wpt/parity/compare.mjs \
        js/componentize/wpt/build/parity-baseline-chromium.json \
        js/componentize/wpt/build/parity-roundtrip-chromium.json \
        --losses losses-chromium.js

# Re-record js/componentize/wpt/parity/losses-chromium.js from an actual
# run, like update-wpt-parity.
update-wpt-parity-chromium: wpt-web-artifacts
    cd js/componentize/wpt/parity && timeout 900 npm run -s run:chromium
    node js/componentize/wpt/parity/compare.mjs \
        js/componentize/wpt/build/parity-baseline-chromium.json \
        js/componentize/wpt/build/parity-roundtrip-chromium.json \
        --losses losses-chromium.js --update

# Run every applicable WPT parity gate, the engines in parallel over one
# shared artifact build: Node always; Firefox and Chromium always under
# GitHub Actions, locally only when opted in with WPT_PARITY_FIREFOX=1 /
# WPT_PARITY_CHROMIUM=1 (each skips with a notice otherwise — the
# Playwright browser downloads are not baseline local dependencies; see
# wpt-parity-firefox / wpt-parity-chromium for the installs). The engines
# are independent — each writes its own record files and pins its own loss
# set — so they parallelize cleanly (scripts/parallel-recipes.sh buffers
# each engine's output and prints it whole, so failures read per engine).
# (The WebKit leg is not driven from here: it needs macOS — see
# wpt-parity-webkit.)
_wpt-parity-gates:
    #!/usr/bin/env bash
    set -euo pipefail
    firefox=""; chromium=""
    if [ "${GITHUB_ACTIONS:-}" = "true" ] || [ "${WPT_PARITY_FIREFOX:-}" = "1" ]; then firefox=1; fi
    if [ "${GITHUB_ACTIONS:-}" = "true" ] || [ "${WPT_PARITY_CHROMIUM:-}" = "1" ]; then chromium=1; fi
    just _wpt-parity-artifacts
    if [ -n "$firefox" ] || [ -n "$chromium" ]; then
        just _wpt-web-transpile
    fi
    engines=(_wpt-parity-node-run)
    if [ -n "$firefox" ]; then engines+=(_wpt-parity-firefox-run); else
        echo "skipping the Firefox WPT parity gate (opt in with WPT_PARITY_FIREFOX=1; needs Playwright Firefox: cd js/componentize/wpt/parity && npx playwright-core install --with-deps firefox)"
    fi
    if [ -n "$chromium" ]; then engines+=(_wpt-parity-chromium-run); else
        echo "skipping the Chromium WPT parity gate (opt in with WPT_PARITY_CHROMIUM=1; needs Playwright Chromium: cd js/componentize/wpt/parity && npx playwright-core install --with-deps chromium)"
    fi
    scripts/parallel-recipes.sh target/wpt-parity "${engines[@]}"

# Produce both of the Node engine's parity legs' results under
# js/componentize/wpt/build/ (artifacts + legs; the update recipe's hook).
_wpt-parity-legs: _wpt-parity-artifacts _wpt-parity-node-legs

# Build what the Node engine's legs consume: componentize the ungated
# parity runner from the tree and transpile it with jco against the jco
# host.
_wpt-parity-artifacts:
    js/componentize/wpt/component.sh build-parity
    cd js/componentize/wpt/parity && npm run -s transpile

# Run the Node engine's two legs on this Node, each writing its records
# under js/componentize/wpt/build/.
_wpt-parity-node-legs:
    node js/componentize/wpt/parity/baseline.mjs \
        > js/componentize/wpt/build/parity-baseline.json
    cd js/componentize/wpt/parity && node --experimental-wasm-jspi roundtrip.mjs \
        > ../build/parity-roundtrip.json

# Run the WPT parity gate in headless WebKit: like the other browser legs,
# against WebKit's own pinned loss set in
# js/componentize/wpt/parity/losses-webkit.js. That ratchet is recorded
# from Playwright's WebKit on macOS, where it uses Apple's crypto backend
# — the closest available proxy for mobile Safari; the Linux port's
# libgcrypt backend serves less (no Ed25519/X25519) and does not match it.
# Unlike the other legs this recipe does not build the page artifacts:
# no componentize-js toolchain is published for darwin, so CI builds them
# on ubuntu (`just wpt-web-artifacts`) and hands them to the macOS job.
# No `timeout` wrapper either — macOS lacks it, and the adapter's own
# launch/load/stall watchdogs bound the run.
wpt-parity-webkit:
    cd js/componentize/wpt/parity && npm run -s run:webkit
    node js/componentize/wpt/parity/compare.mjs \
        js/componentize/wpt/build/parity-baseline-webkit.json \
        js/componentize/wpt/build/parity-roundtrip-webkit.json \
        --losses losses-webkit.js

# Re-record js/componentize/wpt/parity/losses-webkit.js from an actual
# run, like update-wpt-parity. Record from Playwright WebKit on macOS (the
# CI job's engine); a Linux-port recording would pin the wrong backend.
update-wpt-parity-webkit:
    cd js/componentize/wpt/parity && npm run -s run:webkit
    node js/componentize/wpt/parity/compare.mjs \
        js/componentize/wpt/build/parity-baseline-webkit.json \
        js/componentize/wpt/build/parity-roundtrip-webkit.json \
        --losses losses-webkit.js --update

# Build everything the browser WPT parity page (js/componentize/wpt/web/)
# loads: the suite modules under build/, the web transpile of the parity
# runner under parity/generated-web/, and the preview2-shim browser build.
wpt-web-artifacts:
    js/componentize/wpt/component.sh build-parity
    @just _wpt-web-transpile

# The web-transpile half of wpt-web-artifacts (the parity runner component
# is already built): the web transpile of the parity runner under
# parity/generated-web/ (every import a relative path, so it loads in the
# page's worker; the guard keeps that invariant honest), and the
# preview2-shim browser build those imports resolve to (vendored from the
# parity package's node_modules into web/preview2-shim/, with its license).
_wpt-web-transpile:
    #!/usr/bin/env bash
    set -euo pipefail
    (cd js/componentize/wpt/parity && npm run -s transpile:web)
    if grep -q "from '@" js/componentize/wpt/parity/generated-web/parity-runner.js; then
        echo "wpt web transpile: generated-web carries a bare module import (a wasi map in" >&2
        echo "parity/package.json's transpile:web no longer covers every wasi interface?):" >&2
        grep "from '@" js/componentize/wpt/parity/generated-web/parity-runner.js >&2
        exit 1
    fi
    rm -rf js/componentize/wpt/web/preview2-shim
    mkdir -p js/componentize/wpt/web/preview2-shim
    cp js/componentize/wpt/parity/node_modules/@bytecodealliance/preview2-shim/dist/browser/*.js \
        js/componentize/wpt/parity/node_modules/@bytecodealliance/preview2-shim/LICENSE \
        js/componentize/wpt/web/preview2-shim/

# Serve the browser WPT parity page: the same two legs as `just wpt-parity`
# run live in your browser (the round trip needs JSPI — Chrome/Chromium
# 137+). Serves the repository root, which the page's relative imports rely
# on; PORT overrides the port (default 8787).
wpt-web: wpt-web-artifacts
    @echo "the WPT parity page: http://127.0.0.1:${PORT:-8787}/js/componentize/wpt/web/"
    node conformance/web/serve.mjs

# --- conformance -------------------------------------------------------------

# The whole-run safety cap (seconds) for each conformance target invocation.
conformance-timeout := "600"

# Run the cross-implementation conformance tests: build everything the
# targets consume, run the enabled targets in parallel (their runs are
# independent — each writes only its own results files — so they
# parallelize cleanly; scripts/parallel-recipes.sh buffers each target's
# output and prints it whole), then aggregate — validating every results
# file against the target facts in conformance/targets.toml and the
# checked-in suite lockfiles — and render conformance/matrix.md plus the
# results-viewer data (conformance/results/matrix.json), exiting nonzero
# on any failure or transport problem.
#
# Enabled targets: wasmtime, composed, and jco-node (Node 24+ with npm
# required) — plus jco-browser under GitHub Actions (the runner image ships
# Chrome) or when opted in locally with CONFORMANCE_BROWSER=1 (needs
# Chrome/Chromium 137+; targets.toml marks it optional, so the runner warns
# on its missing results rather than failing).
conformance: _conformance-clean _conformance-artifacts class-d-composition
    #!/usr/bin/env bash
    set -euo pipefail
    runs=(_conformance-wasmtime-run _conformance-composed-run _conformance-jco-node-run)
    if [ "${GITHUB_ACTIONS:-}" = "true" ] || [ "${CONFORMANCE_BROWSER:-}" = "1" ]; then
        runs+=(_conformance-jco-browser-run)
    else
        echo "skipping the jco-browser conformance target (opt in with CONFORMANCE_BROWSER=1; needs Chrome/Chromium 137+)"
    fi
    scripts/parallel-recipes.sh target/conformance-logs "${runs[@]}"
    cargo run --release -p conformance-runner -- \
        --targets conformance/targets.toml \
        --results conformance/results \
        --lock shared=conformance/guest/tests.lock \
        --lock signing=conformance/signing-guest/tests.lock \
        --matrix-out conformance/matrix.md \
        --json-out conformance/results/matrix.json

# Everything the conformance targets consume, built once before the
# parallel run phase: the guest components, the composed component, the
# jco transpiles, and the adapter + runner binaries (prebuilt so the run
# phase's `cargo run`s only verify freshness).
_conformance-artifacts: build-conformance-guest build-signing-guest build-conformance-composed _conformance-jco-transpiles
    cargo build --release -p conformance-adapter-wasmtime -p conformance-runner

# Transpile both conformance guests for the jco adapters (shared by the
# jco-node and jco-browser targets, so it must not run inside their
# parallelized run recipes).
_conformance-jco-transpiles: build-conformance-guest build-signing-guest
    cd conformance/adapters/jco && npm run transpile && npm run transpile:signing

# The class-D negative-composition gate: composing a consumer whose world
# imports `ecdsa-sign` (the signing guest) with the in-guest provider must
# fail. This is what makes "class D is enforced structurally" a fact rather
# than a claim — without it, the provider could start exporting `ecdsa-sign`
# and every other check would still report green, because targets.toml
# excludes the composed target from the signing suite by declaration.
#
# The composition fails on a resource-type mismatch, not on an unsatisfied
# import: `wac plug` leaves imports it cannot satisfy in place (that is how
# the composed demo keeps its `wasi:cli` imports). `ecdsa-sign` does
# `use signature.{signing-key}`, and the provider *does* export `signature`,
# so plugging rebinds `signing-key` to the provider's own resource and
# orphans the `ecdsa-sign` import that still names the imported one. The
# enforcement therefore holds only while the provider exports the generic
# interface whose resource the withheld minting interface mints — true of
# every minting interface in the package today.
#
# Matching the message on that interface name is load-bearing: a gate that
# accepted any nonzero exit would also pass on a missing artifact or a
# changed `wac` CLI.
class-d-composition: build-signing-guest build-guest-provider
    #!/usr/bin/env bash
    set -uo pipefail
    output=$(wac plug \
        conformance/signing-guest/build/conformance-signing-guest.component.wasm \
        --plug target/wasm32-wasip2/release/lann_webcrypto_guest_provider.wasm \
        -o target/class-d-composition.wasm 2>&1)
    status=$?
    if [ $status -eq 0 ]; then
        echo "class-D gate: composing the signing guest with the in-guest provider SUCCEEDED." >&2
        echo "The provider must not export lann:webcrypto/ecdsa-sign (rust/guest-provider/wit/world.wit)." >&2
        exit 1
    fi
    if ! printf '%s' "$output" | grep -q 'lann:webcrypto/ecdsa-sign'; then
        echo "class-D gate: the composition failed, but not on ecdsa-sign:" >&2
        printf '%s\n' "$output" >&2
        exit 1
    fi
    echo "class-D gate: the signing guest does not compose with the in-guest provider (ecdsa-sign is not exported)."

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
    cargo doc --no-deps -p lann-webcrypto-wasmtime -p lann-webcrypto-guest

# Assemble the Pages site in target/conformance-site: the conformance
# results viewer, the browser WPT parity page, the public crates' API docs,
# and the landing page linking them (used by the pages workflow; assumes a
# conformance run already produced results/matrix.json and the transpiled
# guests, and `wpt-web-artifacts` already produced the WPT page's
# artifacts). Each page's subtree mirrors the repository layout, which the
# pages' relative URLs and the transpiled components' relative imports both
# rely on.
conformance-web-site: rust-docs
    rm -rf target/conformance-site
    mkdir -p target/conformance-site/conformance/results \
        target/conformance-site/conformance/adapters/jco \
        target/conformance-site/js/jco
    cp -r conformance/web target/conformance-site/conformance/web
    rm target/conformance-site/conformance/web/serve.mjs
    cp conformance/results/matrix.json target/conformance-site/conformance/results/
    cp -r conformance/adapters/jco/generated \
        conformance/adapters/jco/generated-signing \
        target/conformance-site/conformance/adapters/jco/
    cp js/jco/webcrypto.js target/conformance-site/js/jco/
    mkdir -p target/conformance-site/js/componentize/wpt/build \
        target/conformance-site/js/componentize/wpt/parity
    cp -r js/componentize/wpt/web target/conformance-site/js/componentize/wpt/web
    rm target/conformance-site/js/componentize/wpt/web/.gitignore
    cp js/componentize/wpt/groups.js js/componentize/wpt/harness.js \
        js/componentize/wpt/parity-helpers.js js/componentize/wpt/reporter.js \
        target/conformance-site/js/componentize/wpt/
    cp js/componentize/wpt/build/group-*.js \
        target/conformance-site/js/componentize/wpt/build/
    cp -r js/componentize/wpt/parity/generated-web \
        target/conformance-site/js/componentize/wpt/parity/
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

# Build a wasm32-unknown-unknown guest crate and wrap it into a component
# at `out`.
_build-guest crate out:
    cargo build --release -p {{crate}} --target wasm32-unknown-unknown
    mkdir -p "$(dirname {{out}})"
    wasm-tools component new \
        "target/wasm32-unknown-unknown/release/$(echo '{{crate}}' | tr - _).wasm" \
        -o {{out}}

# Build the shared conformance guest component into conformance/guest/build/.
build-conformance-guest: (_build-guest "conformance-guest" "conformance/guest/build/conformance-guest.component.wasm")

# Build the host-only signing guest component (probes for interfaces the
# in-guest provider deliberately does not export) into
# conformance/signing-guest/build/.
build-signing-guest: (_build-guest "conformance-signing-guest" "conformance/signing-guest/build/conformance-signing-guest.component.wasm")

# Run both conformance suites under the Wasmtime host (the shared guest plus
# the host-only signing guest). Writes conformance/results/wasmtime.json and
# wasmtime-signing.json (both target `wasmtime`; the runner merges them).
conformance-wasmtime: build-conformance-guest build-signing-guest _conformance-wasmtime-run

# The wasmtime target's run (the guests are already built).
_conformance-wasmtime-run:
    timeout {{conformance-timeout}} cargo run --release -p conformance-adapter-wasmtime -- \
        --guest conformance/guest/build/conformance-guest.component.wasm \
        --suite shared --out conformance/results/wasmtime.json
    timeout {{conformance-timeout}} cargo run --release -p conformance-adapter-wasmtime -- \
        --guest conformance/signing-guest/build/conformance-signing-guest.component.wasm \
        --suite signing --out conformance/results/wasmtime-signing.json

# Build the composed conformance component: the conformance guest
# plugged with the in-guest provider, under the CLI driver that prints the
# results JSON on stdout.
build-conformance-composed: build-conformance-guest (_compose "conformance" "conformance/guest/build/conformance-guest.component.wasm" "conformance-composed-driver")

# Run the shared conformance suite fully in-guest (RustCrypto in wasm). Writes
# conformance/results/composed.json.
conformance-composed: build-conformance-composed _conformance-composed-run

# The composed target's run (the composed component is already built).
_conformance-composed-run:
    mkdir -p conformance/results
    timeout {{conformance-timeout}} wasmtime run -W component-model-async=y -S cli \
        target/conformance-composed.wasm \
        > conformance/results/composed.json

# Run both conformance suites under the jco host on Node (24+; JSPI). Writes
# conformance/results/jco-node.json. Part of `just conformance`.
conformance-jco-node: _conformance-jco-transpiles _conformance-jco-node-run

# The jco-node target's run (the guests are already transpiled).
_conformance-jco-node-run:
    cd conformance/adapters/jco && \
        timeout {{conformance-timeout}} npm run run:node && \
        timeout {{conformance-timeout}} npm run run:node-signing

# Run both conformance suites under the jco host in headless Chromium (137+;
# auto-detected, or set CHROME_PATH). Writes conformance/results/jco-browser.json
# and jco-browser-signing.json. Gates in CI; local `just conformance` runs it
# only with CONFORMANCE_BROWSER=1.
conformance-jco-browser: _conformance-jco-transpiles _conformance-jco-browser-run

# The jco-browser target's run (the guests are already transpiled).
_conformance-jco-browser-run:
    cd conformance/adapters/jco && \
        timeout {{conformance-timeout}} npm run run:browser

# --- timing lab ---------------------------------------------------------------

# Compose the timing lab with the in-guest provider: the lab's lann:webcrypto
# imports are satisfied by the provider under measurement, yielding one
# self-contained component in target/timing-lab-composed.wasm.
compose-timing-lab: build-guest-provider
    cargo build --release -p timing-lab --target wasm32-wasip2
    wac plug target/wasm32-wasip2/release/timing_lab.wasm \
        --plug target/wasm32-wasip2/release/lann_webcrypto_guest_provider.wasm \
        -o target/timing-lab-composed.wasm

# Run the dudect-style timing lab against the composed in-guest provider.
# Statistical and environment-sensitive by nature, so deliberately NOT part
# of `just ci` — run it on a quiet machine. Set TIMING_LAB_SAMPLES to trade
# runtime for sensitivity.
timing-lab: compose-timing-lab
    wasmtime run -W component-model-async=y -S cli \
        --env TIMING_LAB_SAMPLES \
        target/timing-lab-composed.wasm

# Run the timing lab as the scheduled job does: a run whose verdicts diverge
# is retried once at 4x samples, and only a second divergence is a failure.
# A dudect verdict is a statistical test, and the lab's own advice on a
# surprising one is to rerun with more samples before drawing conclusions —
# shared runners make that advice mandatory rather than optional. Under
# GitHub Actions the report also lands in the job summary.
timing-lab-scheduled:
    #!/usr/bin/env bash
    set -uo pipefail
    samples="${TIMING_LAB_SAMPLES:-2000}"
    run() { TIMING_LAB_SAMPLES="$1" just timing-lab 2>&1; }

    report=$(run "$samples"); status=$?
    printf '%s\n' "$report"
    if [ $status -ne 0 ]; then
        samples=$(( samples * 4 ))
        echo
        echo "timing lab: verdicts diverged; retrying at ${samples} samples/class before reporting failure."
        report=$(run "$samples"); status=$?
        printf '%s\n' "$report"
    fi

    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
        {
            echo "### timing lab — ${samples} samples/class"
            echo
            # The lab prints its report as a markdown table; lift it verbatim.
            printf '%s\n' "$report" | sed -n '/^| surface/,/^$/p'
            if [ $status -eq 0 ]; then
                echo "All surfaces matched expectations."
            else
                echo "**Surfaces diverged from expectation, and again on a retry at ${samples} samples/class.**"
                echo "A quiet positive control means the harness cannot detect leaks at this"
                echo "measurement distance; a LEAK on a real surface warrants investigation."
            fi
        } >> "$GITHUB_STEP_SUMMARY"
    fi
    exit $status

# --- mutation testing -----------------------------------------------------------

# Run cargo-mutants over the shared crypto core and the Wasmtime host, with
# the unit tests plus both conformance suites (via the wasmtime adapter's
# env-gated oracle test) as the oracle: a mutant survives only if neither
# distinguishes it. This is what polices assertion *strength* — the
# lockfiles pin the case inventory, not what the cases check. Expensive and
# deliberately NOT part of `just ci`; a weekly job runs it (the timing-lab
# workflow). Needs cargo-mutants (`cargo install cargo-mutants --locked`).
# Guests are prebuilt from unmutated sources: the subject is the host stack
# the wasm calls into. Results land in mutants.out/.
#
# Two mutants run at a time, each in its own copy of the tree (the oracle
# suites run single-threaded, so the test phases parallelize cleanly, and
# cargo-mutants' shared jobserver keeps the build phases from
# oversubscribing the runner). The guest paths are absolute for the same
# reason: the copies must reach the one prebuilt pair.
#
# The verdict is the missed set, not cargo-mutants' exit code: exit 3
# ("some mutants timed out") is a pass when mutants.out/missed.txt is
# empty, because on this host a hang IS a distinction — the WIT drain
# contract makes an operation that returns without draining its input
# stream deadlock the guest's feeder. Every other nonzero status (missed
# mutants, usage error, failing baseline) stays fatal.
mutants shard="": build-conformance-guest build-signing-guest
    #!/usr/bin/env bash
    set -uo pipefail
    CONFORMANCE_ORACLE_SHARED_GUEST="$(pwd)/conformance/guest/build/conformance-guest.component.wasm" \
    CONFORMANCE_ORACLE_SIGNING_GUEST="$(pwd)/conformance/signing-guest/build/conformance-signing-guest.component.wasm" \
        cargo mutants --jobs 2 --profile mutants \
        -p lann-webcrypto-core -p lann-webcrypto-wasmtime \
        {{ if shard != "" { "--shard " + shard } else { "" } }}
    status=$?
    if [ "$status" -eq 3 ] && [ -f mutants.out/missed.txt ] && ! [ -s mutants.out/missed.txt ]; then
        echo "mutants: timeouts only (caught-by-hang under the drain contract); pass"
        status=0
    fi
    exit $status
