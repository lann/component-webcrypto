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
#   - the Node host's npm dependencies (jco)
#
# Prerequisites (not installed here): a Rust toolchain via rustup, and — for
# the jco host — Node 24+ with npm (jco's async ABI uses JSPI, which Node
# exposes behind --experimental-wasm-jspi from 24 on).
#
# Environment overrides:
#   WASM_TOOLS_VERSION   version of wasm-tools to install (default below)
#   JUST_VERSION         version of just to install (default below)
#   SKIP_NODE=1          skip installing the Node host's npm dependencies

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

WASM_TOOLS_VERSION="${WASM_TOOLS_VERSION:-1.247.0}"
JUST_VERSION="${JUST_VERSION:-1.40.0}"

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

if [ "${SKIP_NODE:-}" != "1" ]; then
    log "Installing the Node host's npm dependencies (jco-impl)"
    (cd "$REPO_ROOT/jco-impl" && npm install)
fi

log "Done."
