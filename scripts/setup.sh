#!/usr/bin/env bash
#
# Install the toolchain and dependencies needed to build, run, and test this
# repository. Safe to run repeatedly (idempotent).
#
# What it installs:
#   - the pinned Rust toolchain and the wasm targets the guest crates
#     compile to, as declared in rust-toolchain.toml
#   - wasm-tools, used to wrap guest modules into components and validate WIT
#   - just, the command runner used for development and CI recipes
#   - wac, the component linker used to compose the crypto-demo guest with the
#     in-guest provider (`just demo::compose`)
#   - wasmtime, the host runtime that runs the composed in-guest crypto
#     integration test (`just demo::test-composed`)
#   - the npm dependencies of every JS tree in the repository (jco host,
#     demos, conformance jco runner, webcrypto-componentize and its parity harness)
#
# Prerequisites (not installed here): a Rust toolchain via rustup, and — for
# the jco host — Node 24+ with npm (jco's async ABI uses JSPI, which Node
# exposes behind --experimental-wasm-jspi from 24 on).
#
# Environment overrides:
#   WASM_TOOLS_VERSION   version of wasm-tools to install (default below)
#   JUST_VERSION         version of just to install (default below)
#   SKIP_NODE=1          skip installing the npm dependencies

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

WASM_TOOLS_VERSION="${WASM_TOOLS_VERSION:-1.247.0}"
JUST_VERSION="${JUST_VERSION:-1.54.0}"
WAC_VERSION="${WAC_VERSION:-0.10.1}"
WASMTIME_VERSION="${WASMTIME_VERSION:-47.0.1}"

log() { printf '\n==> %s\n' "$1"; }

log "Installing the pinned Rust toolchain and wasm targets (rust-toolchain.toml)"
(cd "$REPO_ROOT" && (rustup show active-toolchain || rustup toolchain install))

have() { command -v "$1" >/dev/null 2>&1; }

# Bootstrap cargo-binstall (prebuilt binaries; falls back to cargo install).
# It is itself pinned: the release asset for this platform is downloaded
# directly and verified against scripts/cargo-binstall.sha256 before it
# runs — never a floating bootstrap script. Bumping the version means
# re-recording those digests deliberately.
BINSTALL_VERSION="1.21.1"

sha256_of() {
    if have sha256sum; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

install_binstall() {
    local asset
    case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) asset="cargo-binstall-x86_64-unknown-linux-musl.tgz" ;;
    Linux-aarch64) asset="cargo-binstall-aarch64-unknown-linux-musl.tgz" ;;
    Darwin-*) asset="cargo-binstall-universal-apple-darwin.zip" ;;
    *) asset="" ;;
    esac
    if [ -z "$asset" ]; then
        echo "setup: no pinned cargo-binstall asset for $(uname -s)/$(uname -m); building from crates.io (registry checksums)" >&2
        cargo install cargo-binstall --locked --version "$BINSTALL_VERSION"
        return
    fi

    local want
    want="$(grep -v '^#' "$REPO_ROOT/scripts/cargo-binstall.sha256" | awk -v a="$asset" '$2 == a { print $1 }')"
    if [ -z "$want" ]; then
        echo "setup: scripts/cargo-binstall.sha256 pins no digest for ${asset}; record it deliberately" >&2
        exit 1
    fi

    local tmp
    tmp="$(mktemp -d)"
    curl -fsSL --proto '=https' --tlsv1.2 -o "${tmp}/${asset}" \
        "https://github.com/cargo-bins/cargo-binstall/releases/download/v${BINSTALL_VERSION}/${asset}"

    local got
    got="$(sha256_of "${tmp}/${asset}")"
    if [ "$got" != "$want" ]; then
        rm -rf "$tmp"
        cat >&2 <<EOF
setup: ${asset} does not match the digest pinned for cargo-binstall ${BINSTALL_VERSION}.
  expected ${want}
  actual   ${got}

The download has been removed. Either the published asset was replaced,
the pin is stale, or the download was tampered with. Re-record the
digests deliberately after establishing why they changed.
EOF
        exit 1
    fi

    mkdir -p "$HOME/.cargo/bin"
    case "$asset" in
    *.tgz) tar -xzf "${tmp}/${asset}" -C "$HOME/.cargo/bin" cargo-binstall ;;
    *.zip) unzip -q -o "${tmp}/${asset}" cargo-binstall -d "$HOME/.cargo/bin" ;;
    esac
    rm -rf "$tmp"
}

if ! have cargo-binstall; then
    log "Installing cargo-binstall ${BINSTALL_VERSION}"
    install_binstall
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
    log "Installing the webcrypto-componentize's npm dependencies (webcrypto-componentize)"
    (cd "$REPO_ROOT/js/componentize" && npm install)
    log "Installing the jco host's npm dependencies (webcrypto-jco)"
    (cd "$REPO_ROOT/js/jco" && npm install)
    log "Installing the jco demo driver's npm dependencies (examples/jco-demo)"
    (cd "$REPO_ROOT/examples/jco-demo" && npm install)
    log "Installing the conformance jco runner's npm dependencies (conformance/driver-ct/jco)"
    (cd "$REPO_ROOT/conformance/driver-ct/jco" && npm install)
    log "Installing the WPT parity gate's npm dependencies (js/componentize/wpt/parity)"
    (cd "$REPO_ROOT/js/componentize/wpt/parity" && npm install)
fi

log "Done."
