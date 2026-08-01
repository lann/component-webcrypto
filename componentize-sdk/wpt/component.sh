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
#   toolchain     print the path to the pinned componentize-js, downloading
#                 it if it is not already present
#   suites        (re)generate the importable suite modules under build/
#                 (no toolchain needed — the parity baseline runs these
#                 directly on Node)
#   build         `toolchain` + `suites`, then componentize
#                 build/runner.component.wasm
#   build-parity  `toolchain` + `suites`, then componentize
#                 build/parity-runner.component.wasm (the ungated runner the
#                 parity gate transpiles with jco — see parity/)
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
#
# The binary is verified against the digests pinned in
# componentize-js.sha256 before it is ever executed — on download and again
# on every use of the cached copy. This toolchain compiles the component the
# WPT gate tests, so an unverified one could emit a backdoored component and
# a green run; the filename alone ties nothing to the pinned revision.
ensure_toolchain() {
    if [ -n "${COMPONENTIZE_JS:-}" ]; then
        # An explicitly supplied build: the caller owns its provenance.
        TOOLCHAIN="$COMPONENTIZE_JS"
        return
    fi
    TOOLCHAIN="$TOOLCHAIN_DIR/componentize-js-$REV"
    read_pinned_digests
    if [ -x "$TOOLCHAIN" ]; then
        verify_digest "$TOOLCHAIN" "$BINARY_SHA256" "cached toolchain"
        return
    fi
    local asset="componentize-js-${REV}-$(platform).gz"
    echo "fetching ${asset} from ${COMPONENTIZE_JS_RELEASE}" >&2
    mkdir -p "$TOOLCHAIN_DIR"
    if curl -fsSL --retry 3 -o "$TOOLCHAIN.gz.tmp" "${COMPONENTIZE_JS_RELEASE}/${asset}"; then
        verify_digest "$TOOLCHAIN.gz.tmp" "$ASSET_SHA256" "downloaded ${asset}"
        gzip -dc "$TOOLCHAIN.gz.tmp" > "$TOOLCHAIN.tmp"
        verify_digest "$TOOLCHAIN.tmp" "$BINARY_SHA256" "decompressed toolchain"
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

# Load this platform's pinned digests into ASSET_SHA256 / BINARY_SHA256.
read_pinned_digests() {
    local line
    line="$(grep -v '^#' componentize-sdk/componentize-js.sha256 | awk -v p="$(platform)" '$1 == p { print }')"
    if [ -z "$line" ]; then
        cat >&2 <<EOF
error: componentize-sdk/componentize-js.sha256 pins no digest for
$(platform) at revision ${REV}.

A toolchain is only trusted once its digests are recorded. Run
\`just update-toolchain-digest\` (it verifies the build-provenance
attestation before recording), or supply your own build on
COMPONENTIZE_JS.
EOF
        exit 1
    fi
    ASSET_SHA256="$(echo "$line" | awk '{ print $2 }')"
    BINARY_SHA256="$(echo "$line" | awk '{ print $3 }')"
}

# Fail unless `file` hashes to `want`. A mismatch deletes the file: a
# toolchain that fails verification must not survive to be picked up as a
# cache hit by the next run.
verify_digest() {
    local file="$1" want="$2" what="$3" got
    got="$(sha256sum "$file" | cut -d' ' -f1)"
    if [ "$got" != "$want" ]; then
        rm -f "$file"
        cat >&2 <<EOF
error: ${what} does not match the digest pinned for revision ${REV}.
  expected ${want}
  actual   ${got}

The file has been removed. Either the published asset was replaced, the
pin is stale, or the download was tampered with. Re-record deliberately
with \`just update-toolchain-digest\` after establishing why it changed.
EOF
        exit 1
    fi
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
    # The cfrg helpers assign their key tables as sloppy-mode implicit
    # globals; a concatenated module is strict, so declare them here (the
    # vendored sources stay pristine, like the appended exports).
    cat > "$B"/group-cfrg-bits.js <<'JS'
var publicKeys, privateKeys, noDeriveBitsKeys, noDeriveKeyKeys, ecdhKeys;
JS
    cat "$V"/helpers.js "$V"/cfrg_curves_bits_fixtures.js "$V"/cfrg_curves_bits.js >> "$B"/group-cfrg-bits.js
    echo 'export { define_tests_25519 };' >> "$B"/group-cfrg-bits.js
    cat > "$B"/group-cfrg-keys.js <<'JS'
var publicKeys, privateKeys, noDeriveBitsKeys, noDeriveKeyKeys, ecdhKeys;
JS
    cat "$V"/helpers.js "$V"/cfrg_curves_bits_fixtures.js "$V"/cfrg_curves_keys.js >> "$B"/group-cfrg-keys.js
    echo 'export { define_tests_25519 };' >> "$B"/group-cfrg-keys.js
    cat "$V"/helpers.js "$V"/okp_importKey_fixtures.js "$V"/okp_importKey.js > "$B"/group-okp-import-key.js
    echo 'export { runTests };' >> "$B"/group-okp-import-key.js
    cat "$V"/helpers.js "$V"/okp_importKey_failures_fixtures.js "$V"/importKey_failures.js > "$B"/group-okp-import-key-failures.js
    echo 'export { run_test };' >> "$B"/group-okp-import-key-failures.js
    # digest.https.any.js and ec_importKey.https.any.js register their
    # tests at top level (their bodies ship pre-indented for exactly this):
    # wrap each in a callable so the group starts on demand like the
    # others, helpers outside the wrapper.
    cat "$V"/helpers.js > "$B"/group-digest.js
    echo 'function run_digest_tests() {' >> "$B"/group-digest.js
    cat "$V"/digest.https.any.js >> "$B"/group-digest.js
    printf '}\nexport { run_digest_tests };\n' >> "$B"/group-digest.js
    cat "$V"/helpers.js > "$B"/group-ec-import-key.js
    echo 'function run_ec_import_tests() {' >> "$B"/group-ec-import-key.js
    cat "$V"/ec_importKey.https.any.js >> "$B"/group-ec-import-key.js
    printf '}\nexport { run_ec_import_tests };\n' >> "$B"/group-ec-import-key.js
    cat "$V"/helpers.js "$V"/eddsa_vectors.js "$V"/eddsa.js > "$B"/group-eddsa.js
    echo 'export { run_test };' >> "$B"/group-eddsa.js
    cat "$V"/helpers.js "$V"/eddsa_vectors.js "$V"/eddsa_small_order_points.js > "$B"/group-eddsa-small-order.js
    echo 'export { run_test };' >> "$B"/group-eddsa-small-order.js
    cat "$V"/helpers.js "$V"/ecdsa_vectors.js "$V"/ecdsa.js > "$B"/group-ecdsa.js
    echo 'export { run_test };' >> "$B"/group-ecdsa.js
    cat "$V"/helpers.js "$V"/ec_importKey_failures_fixtures.js "$V"/importKey_failures.js > "$B"/group-ec-import-key-failures.js
    echo 'export { run_test };' >> "$B"/group-ec-import-key-failures.js
    cat "$V"/helpers.js "$V"/hkdf_vectors.js "$V"/hkdf.js > "$B"/group-hkdf-derive.js
    echo 'export { define_tests };' >> "$B"/group-hkdf-derive.js
    cat "$V"/helpers.js "$V"/pbkdf2_vectors.js "$V"/pbkdf2.js > "$B"/group-pbkdf2-derive.js
    echo 'export { define_tests };' >> "$B"/group-pbkdf2-derive.js
}

case "${1:-}" in
toolchain)
    ensure_toolchain
    echo "$TOOLCHAIN"
    ;;
suites)
    gen_suites
    ;;
build)
    gen_suites
    ensure_toolchain
    "$TOOLCHAIN" -q -d examples/componentize-demo/wit -w componentize-demo \
        componentize componentize-sdk/wpt/runner.js -p . \
        -o "$B"/runner.component.wasm
    ;;
build-parity)
    gen_suites
    ensure_toolchain
    "$TOOLCHAIN" -q -d examples/componentize-demo/wit -w componentize-demo \
        componentize componentize-sdk/wpt/parity-runner.js -p . \
        -o "$B"/parity-runner.component.wasm
    ;;
*)
    echo "usage: $0 {toolchain|suites|build|build-parity}" >&2
    exit 2
    ;;
esac
