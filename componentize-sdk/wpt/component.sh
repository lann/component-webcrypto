#!/usr/bin/env bash
#
# Make the pinned componentize-js toolchain available, and build the WPT
# runner component with it.
#
# The split here follows what the two artifacts actually cost. Building the
# runner component takes seconds, so it is built from the working tree on
# every run: there is no published component, and therefore no input lock to
# keep honest and no way to test a stale artifact. The *toolchain* is the
# expensive one — componentize-js embeds a SpiderMonkey build that takes
# ~20 minutes to compile — and it depends on nothing but the revision in
# componentize-sdk/componentize-js.rev, so it is built once per (revision,
# platform) by the componentize-js-toolchain workflow and published. Every
# other consumer, CI and contributor alike, downloads it.
#
# Subcommands:
#   toolchain  print the path to the pinned componentize-js, downloading it
#              if it is not already present
#   build      `toolchain`, then componentize build/runner.component.wasm
#
# Environment:
#   COMPONENTIZE_JS          use this binary instead of the pinned download
#                            (for testing a locally built toolchain)
#   COMPONENTIZE_JS_RELEASE  override the release URL downloads come from

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

V=componentize-sdk/wpt/vendor
B=componentize-sdk/wpt/build
REV="$(cat componentize-sdk/componentize-js.rev)"
TOOLCHAIN_DIR=target/toolchains
COMPONENTIZE_JS_RELEASE="${COMPONENTIZE_JS_RELEASE:-https://github.com/lann/component-webcrypto/releases/download/toolchains}"

# The platform an asset is built for, in the naming the workflow publishes.
platform() {
    local os arch
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    case "$(uname -m)" in
    aarch64 | arm64) arch=aarch64 ;;
    x86_64 | amd64) arch=x86_64 ;;
    *) arch="$(uname -m)" ;;
    esac
    echo "${os}-${arch}"
}

# Set TOOLCHAIN to the pinned componentize-js, downloading it on first use.
# Downloads land under target/, so a clean checkout fetches once and every
# later run is local.
ensure_toolchain() {
    if [ -n "${COMPONENTIZE_JS:-}" ]; then
        TOOLCHAIN="$COMPONENTIZE_JS"
        return
    fi
    TOOLCHAIN="$TOOLCHAIN_DIR/componentize-js-$REV"
    if [ -x "$TOOLCHAIN" ]; then
        return
    fi
    local asset="componentize-js-${REV}-$(platform).gz"
    echo "fetching ${asset} from ${COMPONENTIZE_JS_RELEASE}" >&2
    mkdir -p "$TOOLCHAIN_DIR"
    if curl -fsSL --retry 3 -o "$TOOLCHAIN.gz.tmp" "${COMPONENTIZE_JS_RELEASE}/${asset}"; then
        gzip -dc "$TOOLCHAIN.gz.tmp" > "$TOOLCHAIN.tmp"
        chmod +x "$TOOLCHAIN.tmp"
        mv "$TOOLCHAIN.tmp" "$TOOLCHAIN"
        rm -f "$TOOLCHAIN.gz.tmp"
        return
    fi
    rm -f "$TOOLCHAIN.gz.tmp" "$TOOLCHAIN.tmp"
    cat >&2 <<EOF
error: no componentize-js build is published for revision
${REV} on $(platform).

A toolchain is published per (revision, platform) by the
componentize-js-toolchain workflow, which runs when
componentize-sdk/componentize-js.rev changes. Either:
  - run that workflow for this revision (it takes ~20 minutes; pushing a
    change to the pin triggers it automatically), or
  - build componentize-js yourself and point COMPONENTIZE_JS at it — see
    componentize-sdk/README.md.
EOF
    exit 1
}

# Concatenate each vendored WPT suite into an importable module: the
# vendored files are classic scripts, and the appended `export` exposes
# each suite's entry point.
gen_suites() {
    mkdir -p "$B"
    cat "$V"/helpers.js "$V"/hmac_vectors.js "$V"/hmac.js > "$B"/group-hmac.js
    echo 'export { run_test };' >> "$B"/group-hmac.js
    cat "$V"/helpers.js "$V"/aes_gcm_96_iv_fixtures.js "$V"/aes_gcm_vectors.js "$V"/aes.js > "$B"/group-aes-gcm.js
    echo 'export { run_test };' >> "$B"/group-aes-gcm.js
    cat "$V"/helpers.js "$V"/symmetric_importKey.js > "$B"/group-import-key.js
    echo 'export { runTests };' >> "$B"/group-import-key.js
    cat "$V"/helpers.js "$V"/successes.js > "$B"/group-generate-key.js
    echo 'export { run_test };' >> "$B"/group-generate-key.js
}

case "${1:-}" in
toolchain)
    ensure_toolchain
    echo "$TOOLCHAIN"
    ;;
build)
    gen_suites
    ensure_toolchain
    "$TOOLCHAIN" -q -d examples/componentize-demo/wit -w componentize-demo \
        componentize componentize-sdk/wpt/runner.js -p . \
        -o "$B"/runner.component.wasm
    ;;
*)
    echo "usage: $0 {toolchain|build}" >&2
    exit 2
    ;;
esac
