# The orchestration surface: repo-wide recipes plus one module per software
# component, each module's justfile colocated with its code (run
# `just --list <module>` for its recipes, or `cd` into its directory and
# use `just` there directly).

import 'justfile.shared.just'

# GitHub Actions plumbing: CI job entry points and workflow-only recipes.
mod gha '.github'

# The cross-implementation conformance tests (component-test stack).
mod conformance-ct "conformance/driver-ct/justfile"

# The demo guest + drivers (Wasmtime, composed in-guest, jco/Node).
mod demo 'examples'

# The jco host library (@lann/webcrypto-jco).
mod jco 'js/jco'

# The componentize-js guest library (@lann/webcrypto-componentize).
mod componentize 'js/componentize'

# The WPT harnesses: the composed WPT gate and the parity gates.
mod wpt 'js/componentize/wpt'

# The dudect-style timing lab (non-gating; see timing-lab/README.md).
mod timing-lab

# List the available recipes.
default:
    @just --list

# Run every CI check locally: each CI job runs exactly one gha:: job recipe.
ci: gha::rust-checks gha::jco-checks gha::componentize-checks

# Run the fast pre-commit checks (fmt, clippy, WIT, Rust tests).
check: fmt-check clippy validate-wit test

# Check formatting across all crates.
fmt-check:
    cargo fmt --all -- --check

# Run clippy across all crates (the wasm crates on their wasm targets).
clippy:
    cargo clippy --workspace --exclude crypto-demo --exclude lann-webcrypto-guest-provider --exclude crypto-demo-driver --exclude timing-lab -- -D warnings
    cargo clippy -p crypto-demo --target wasm32-unknown-unknown -- -D warnings
    cargo clippy -p lann-webcrypto-guest-provider --target wasm32-wasip2 -- -D warnings
    cargo clippy -p crypto-demo-driver --target wasm32-wasip2 -- -D warnings
    cargo clippy -p timing-lab --target wasm32-wasip2 -- -D warnings
    # The conformance suites build natively too (the census-parity tests),
    # which the workspace line covers; this checks their component builds
    # in the configuration the conformance run ships (rkyv corpus).
    cargo clippy -p conformance-guest-ct -p conformance-signing-guest-ct \
        --features conformance-guest-ct/rkyv-corpus --target wasm32-wasip2 -- -D warnings
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

# Run the Rust tests, including the wasmtime-demo integration test (which
# builds and runs the crypto-demo guest under the Wasmtime host).
test:
    cargo test --workspace --exclude crypto-demo --exclude crypto-demo-driver --exclude timing-lab

# Build the API docs for the public-facing crates: the Wasmtime host crate
# and the guest-side SDK. Both document on the host target (the SDK also
# lint-gates there), giving one rustdoc tree with a shared search index in
# target/doc.
rust-docs:
    cargo doc --no-deps -p lann-webcrypto-wasmtime -p lann-webcrypto-guest

# Run cargo-mutants over the shared crypto core and the Wasmtime host, with
# the unit tests plus both conformance suites (via the ct driver's
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
mutants shard="": conformance-ct::build
    #!/usr/bin/env bash
    set -uo pipefail
    CONFORMANCE_ORACLE_SHARED_GUEST="$(pwd)/target/wasm32-wasip2/release/conformance_guest_ct.wasm" \
    CONFORMANCE_ORACLE_SIGNING_GUEST="$(pwd)/target/wasm32-wasip2/release/conformance_signing_guest_ct.wasm" \
        cargo mutants --jobs 2 --profile mutants \
        -p lann-webcrypto-core -p lann-webcrypto-wasmtime \
        {{ if shard != "" { "--shard " + shard } else { "" } }}
    status=$?
    if [ "$status" -eq 3 ] && [ -f mutants.out/missed.txt ] && ! [ -s mutants.out/missed.txt ]; then
        echo "mutants: timeouts only (caught-by-hang under the drain contract); pass"
        status=0
    fi
    exit $status
