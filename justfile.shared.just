# Shared definitions imported by the root justfile and every module
# justfile. Import semantics place these in each importer's namespace, and
# imported recipe bodies run with the importer's working directory — so
# every recipe here anchors its paths on {{root}} and every variable is
# cwd-independent. Callers pass repository-root-relative paths.
#
# Everything here is [private]: these are building blocks, not entry
# points, so they stay out of every module's `just --list`.

root := `git rev-parse --show-toplevel`

# CI/opt-in predicates for the optional browser gates: non-empty when the
# gate should run — always under GitHub Actions, locally only when the
# opt-in variable is set to 1.
firefox-enabled := if env('GITHUB_ACTIONS', '') == 'true' { '1' } else if env('WPT_PARITY_FIREFOX', '') == '1' { '1' } else { '' }
chromium-enabled := if env('GITHUB_ACTIONS', '') == 'true' { '1' } else if env('WPT_PARITY_CHROMIUM', '') == '1' { '1' } else { '' }

# Build the crypto-demo guest component into examples/crypto-demo/build/.
# The output is renamed into place: `wasm-tools component new -o` truncates
# in place, so a direct write would expose an empty or partial component to
# a concurrent reader (the wasmtime-demo tests load this path).
[private]
build-component:
    #!/usr/bin/env bash
    set -euo pipefail
    cd '{{root}}'
    cargo build --release -p crypto-demo --target wasm32-unknown-unknown
    mkdir -p examples/crypto-demo/build
    wasm-tools component new \
        target/wasm32-unknown-unknown/release/crypto_demo.wasm \
        -o examples/crypto-demo/build/crypto-demo.component.wasm.tmp
    mv -f examples/crypto-demo/build/crypto-demo.component.wasm.tmp \
        examples/crypto-demo/build/crypto-demo.component.wasm

# Build the in-guest provider component (RustCrypto entirely in-guest; it
# exports the lann:webcrypto surface) into
# target/wasm32-wasip2/release/lann_webcrypto_guest_provider.wasm.
[private]
build-guest-provider:
    cargo build --release -p lann-webcrypto-guest-provider --target wasm32-wasip2 \
        --manifest-path '{{root}}/Cargo.toml'

# Compose `guest` with the in-guest provider and plug `driver` (a
# wasm32-wasip2 bin crate) on top, yielding one self-contained component at
# target/<stem>-composed.wasm (via target/<stem>-with-crypto.wasm). Every
# composition in the repository is this same two-step `wac plug`. `guest`
# is a repository-root-relative path.
[private]
_compose stem guest driver: build-guest-provider
    #!/usr/bin/env bash
    set -euo pipefail
    cd '{{root}}'
    cargo build --release -p {{driver}} --target wasm32-wasip2
    driver_wasm="target/wasm32-wasip2/release/$(echo '{{driver}}' | tr - _).wasm"
    wac plug {{guest}} \
        --plug target/wasm32-wasip2/release/lann_webcrypto_guest_provider.wasm \
        -o target/{{stem}}-with-crypto.wasm
    wac plug "$driver_wasm" \
        --plug target/{{stem}}-with-crypto.wasm \
        -o target/{{stem}}-composed.wasm

# Build a wasm32-unknown-unknown guest crate and wrap it into a component
# at `out` (a repository-root-relative path).
[private]
_build-guest crate out:
    #!/usr/bin/env bash
    set -euo pipefail
    cd '{{root}}'
    cargo build --release -p {{crate}} --target wasm32-unknown-unknown
    mkdir -p "$(dirname {{out}})"
    wasm-tools component new \
        "target/wasm32-unknown-unknown/release/$(echo '{{crate}}' | tr - _).wasm" \
        -o {{out}}
