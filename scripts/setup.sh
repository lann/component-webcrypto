#!/usr/bin/env bash
#
# Install the toolchain and dependencies needed to build, run, and test this
# repository. Safe to run repeatedly (idempotent).
#
# What it installs:
#   - the pinned Rust toolchain and the wasm32-unknown-unknown target the
#     guest component compiles to, as declared in rust-toolchain.toml
#   - wasm-tools, used to wrap guest modules into components and validate WIT
#   - just, the command runner used for development and CI recipes
#   - wac, the component linker used to compose the crypto-demo guest with the
#     in-guest provider (`just compose-demo`)
#   - wasmtime, the host runtime that runs the composed in-guest crypto
#     integration test (`just test-webcrypto-composed`)
#   - the jco demo driver's npm dependencies (jco)
#
# Prerequisites (not installed here): a Rust toolchain via rustup, and — for
# the jco host — Node 24+ with npm (jco's async ABI uses JSPI, which Node
# exposes behind --experimental-wasm-jspi from 24 on).
#
# Environment overrides:
#   WASM_TOOLS_VERSION   version of wasm-tools to install (default below)
#   JUST_VERSION         version of just to install (default below)
#   SKIP_NODE=1          skip installing the npm dependencies (jco demo
#                        driver and conformance jco adapter)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

WASM_TOOLS_VERSION="${WASM_TOOLS_VERSION:-1.247.0}"
JUST_VERSION="${JUST_VERSION:-1.40.0}"
WAC_VERSION="${WAC_VERSION:-0.10.1}"
WASMTIME_VERSION="${WASMTIME_VERSION:-47.0.1}"

log() { printf '\n==> %s\n' "$1"; }

log "Installing the pinned Rust toolchain and wasm targets (rust-toolchain.toml)"
(cd "$REPO_ROOT" && (rustup show active-toolchain || rustup toolchain install))

have() { command -v "$1" >/dev/null 2>&1; }

# Bootstrap cargo-binstall (prebuilt binaries; falls back to cargo install).
if ! have cargo-binstall; then
    log "Installing cargo-binstall"
    curl -L --proto '=https' --tlsv1.2 -sSf \
        https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash
fi

if ! have wasm-tools; then
    log "Installing wasm-tools ${WASM_TOOLS_VERSION}"
    # --force: a restored CI cache can contain cargo's install metadata without
    # the binary itself, which would otherwise make binstall a no-op.
    cargo binstall -y --force "wasm-tools@${WASM_TOOLS_VERSION}"
fi

if ! have just; then
    log "Installing just ${JUST_VERSION}"
    cargo binstall -y --force "just@${JUST_VERSION}"
fi

if ! have wac; then
    log "Installing wac ${WAC_VERSION}"
    cargo binstall -y --force "wac-cli@${WAC_VERSION}"
fi

if ! have wasmtime; then
    log "Installing wasmtime ${WASMTIME_VERSION}"
    cargo binstall -y --force "wasmtime-cli@${WASMTIME_VERSION}"
fi

if [ "${SKIP_NODE:-}" != "1" ]; then
    log "Installing the jco demo driver's npm dependencies (examples/jco-demo)"
    (cd "$REPO_ROOT/examples/jco-demo" && npm install)
    log "Installing the conformance jco adapter's npm dependencies (conformance/adapters/jco)"
    (cd "$REPO_ROOT/conformance/adapters/jco" && npm install)
fi

log "Done."
