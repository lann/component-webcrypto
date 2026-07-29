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

# Everything the jco CI job runs.
jco-checks:
    @just _step typecheck-jco
    @just _step test-node

# Everything the componentize CI job runs: the WPT WebCryptoAPI suites
# against the componentize-sdk JS guest library.
componentize-checks:
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
    cargo clippy --workspace --exclude crypto-demo --exclude guest-webcrypto --exclude crypto-demo-driver --exclude conformance-guest --exclude conformance-signing-guest --exclude conformance-composed-driver --exclude timing-lab -- -D warnings
    cargo clippy -p crypto-demo --target wasm32-unknown-unknown -- -D warnings
    cargo clippy -p conformance-guest --target wasm32-unknown-unknown -- -D warnings
    cargo clippy -p conformance-signing-guest --target wasm32-unknown-unknown -- -D warnings
    cargo clippy -p guest-webcrypto --target wasm32-wasip2 -- -D warnings
    cargo clippy -p crypto-demo-driver --target wasm32-wasip2 -- -D warnings
    cargo clippy -p timing-lab --target wasm32-wasip2 -- -D warnings
    cargo clippy -p conformance-composed-driver --target wasm32-wasip2 -- -D warnings
    # guest-sdk's optional source adaptors are only compiled with their
    # features on, and one of them holds the only code path that can produce
    # `Error::Read` — the crate's subtlest behaviour. Nothing in the
    # workspace enables them, so without this they are never checked.
    cargo clippy -p lann-webcrypto-guest --all-features --target wasm32-wasip2 -- -D warnings

# Validate WIT packages.
validate-wit:
    wasm-tools component wit wit
    wasm-tools component wit wasmtime-impl/wit
    wasm-tools component wit jco-impl/wit
    wasm-tools component wit guest-impl/wit
    wasm-tools component wit examples/crypto-demo/wit
    wasm-tools component wit examples/componentize-demo/wit
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

# Type-check the jco host against the interface definitions jco derives from
# `wit/`. The definitions are generated on demand, so there is no checked-in
# copy to go stale.
typecheck-jco:
    cd jco-impl && npm run typecheck

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

# --- componentize-js (JS guest) demo ------------------------------------------

# The componentize-js CLI (dicej's ComponentizeJS reboot) used to
# (re)generate the JS guest components. Building it compiles SpiderMonkey to
# wasm and needs WASI-SDK 30, so nobody here builds it: the
# componentize-js-toolchain workflow publishes one build per pinned revision
# and platform, and `component.sh toolchain` downloads it into
# target/toolchains on first use (set COMPONENTIZE_JS to use your own build
# instead). The pinned revision lives in componentize-sdk/componentize-js.rev.

# Componentize the JS WebCrypto-subset demo guest (componentize-sdk library +
# examples/componentize-demo app) into examples/componentize-demo/build/.
# The base directory is the repository root, so the app's module specifiers
# (./componentize-sdk/webcrypto.js) resolve against it.
build-componentize-demo:
    mkdir -p examples/componentize-demo/build
    "$(componentize-sdk/wpt/component.sh toolchain)" \
        -q -d examples/componentize-demo/wit -w componentize-demo \
        componentize examples/componentize-demo/app.js -p . \
        -o examples/componentize-demo/build/componentize-demo.component.wasm

# Compose the fully in-guest JS demo (the `compose-demo` recipe with the JS
# guest in place of the Rust one): the JS guest's lann:webcrypto imports are
# satisfied by the in-guest provider, then the CLI driver is plugged on top.
compose-componentize-demo: build-componentize-demo build-guest-provider
    cargo build --release -p crypto-demo-driver --target wasm32-wasip2
    wac plug examples/componentize-demo/build/componentize-demo.component.wasm \
        --plug target/wasm32-wasip2/release/guest_webcrypto.wasm \
        -o target/componentize-demo-with-crypto.wasm
    wac plug target/wasm32-wasip2/release/crypto_demo_driver.wasm \
        --plug target/componentize-demo-with-crypto.wasm \
        -o target/componentize-demo-composed.wasm

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
    componentize-sdk/wpt/update-toolchain-digest.sh {{platform}}

# Run the vendored web-platform-tests WebCryptoAPI suites against the
# componentize-sdk library: every in-subset test must pass; out-of-subset
# tests are reported by count (componentize-sdk/wpt/README.md has the
# vendoring and subset policy). The runner is componentized from the working
# tree with the pinned componentize-js (downloaded on first use), then
# composed with a freshly built in-guest provider and driver and run under
# `wasmtime` (v47+) and `wac`, like test-webcrypto-composed.
test-webcrypto-componentize-wpt: compose-wpt-runner
    timeout 600 wasmtime run -W component-model-async=y -S cli \
        target/wpt-runner-composed.wasm

# Componentize the WPT runner from the working tree and compose it with a
# freshly built in-guest provider and driver.
compose-wpt-runner: build-guest-provider
    componentize-sdk/wpt/component.sh build
    cargo build --release -p crypto-demo-driver --target wasm32-wasip2
    wac plug componentize-sdk/wpt/build/runner.component.wasm \
        --plug target/wasm32-wasip2/release/guest_webcrypto.wasm \
        -o target/wpt-runner-with-crypto.wasm
    wac plug target/wasm32-wasip2/release/crypto_demo_driver.wasm \
        --plug target/wpt-runner-with-crypto.wasm \
        -o target/wpt-runner-composed.wasm

# Re-record componentize-sdk/wpt/expected.js from an actual run: run this
# when a change legitimately moves a count, and review the diff — each moved
# number is a test that appeared, vanished, or crossed the in-subset
# boundary.
update-wpt-expectations: compose-wpt-runner
    componentize-sdk/wpt/update-expectations.sh target/wpt-runner-composed.wasm

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
conformance: _conformance-clean class-d-composition conformance-wasmtime conformance-composed conformance-jco-node _conformance-jco-browser-gate
    cargo run --release -p conformance-runner -- \
        --targets conformance/targets.toml \
        --results conformance/results \
        --lock shared=conformance/guest/tests.lock \
        --lock signing=conformance/signing-guest/tests.lock \
        --matrix-out conformance/matrix.md \
        --json-out conformance/results/matrix.json

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
        --plug target/wasm32-wasip2/release/guest_webcrypto.wasm \
        -o target/class-d-composition.wasm 2>&1)
    status=$?
    if [ $status -eq 0 ]; then
        echo "class-D gate: composing the signing guest with the in-guest provider SUCCEEDED." >&2
        echo "The provider must not export lann:webcrypto/ecdsa-sign (guest-impl/wit/world.wit)." >&2
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

