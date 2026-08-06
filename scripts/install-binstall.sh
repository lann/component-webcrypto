#!/usr/bin/env bash
# Install the pinned cargo-binstall from its GitHub release, verified
# against scripts/cargo-binstall.sha256 before it runs — never via a
# floating bootstrap script. Idempotent: an existing cargo-binstall on
# PATH is left alone. Bumping the version means re-recording those
# digests deliberately.
#
# Shared by scripts/setup.sh and the CI jobs that need one cargo tool
# without provisioning the Rust toolchain: the release asset is prebuilt,
# so nothing here needs cargo. Only the fallback for platforms without a
# pinned asset compiles from crates.io (registry checksums), and that
# path presumes a toolchain.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BINSTALL_VERSION="1.21.1"

log() { printf '\n==> %s\n' "$1"; }

have() { command -v "$1" >/dev/null 2>&1; }

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

if have cargo-binstall; then
    echo "cargo-binstall already present: $(cargo-binstall -V)"
else
    log "Installing cargo-binstall ${BINSTALL_VERSION}"
    install_binstall
fi
