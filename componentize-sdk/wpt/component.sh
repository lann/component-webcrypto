#!/usr/bin/env bash
#
# Manage the componentized WPT runner. The runner component is a build
# artifact — never checked in: it is published as an asset on this
# repository's rolling `wpt-components` GitHub release, keyed by the hash of
# an input lock over everything it is generated from (the library, the
# harness and runner, the concatenated suites, the resolved WIT world, and
# the componentize-js revision pin). CI's builder job and the justfile
# recipes both drive this script, so the lock and build logic live in
# exactly one place.
#
# Subcommands:
#   lock     regenerate the suite modules under build/ and the input lock
#            (build/runner.lock.computed); print the lock hash
#   build    `lock`, then componentize the runner into
#            build/runner.component.wasm and record the lock it was built
#            from (build/runner.lock.built). Needs the componentize-js CLI
#            (override with $COMPONENTIZE_JS; see ../README.md).
#   ensure   `lock`, then make build/runner.component.wasm available: reuse
#            a local build whose recorded lock matches, else download the
#            published asset for this lock hash (override the release URL
#            with $WPT_COMPONENT_RELEASE), else fail with instructions.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

V=componentize-sdk/wpt/vendor
B=componentize-sdk/wpt/build
COMPONENTIZE_JS="${COMPONENTIZE_JS:-componentize-js}"
WPT_COMPONENT_RELEASE="${WPT_COMPONENT_RELEASE:-https://github.com/lann/component-webcrypto/releases/download/wpt-components}"

# Concatenate each vendored WPT suite into an importable module (the
# vendored files are classic scripts; the appended `export` exposes each
# suite's entry point), then write the input lock and compute its hash.
gen_lock() {
    mkdir -p "$B"
    cat "$V"/helpers.js "$V"/hmac_vectors.js "$V"/hmac.js > "$B"/group-hmac.js
    echo 'export { run_test };' >> "$B"/group-hmac.js
    cat "$V"/helpers.js "$V"/aes_gcm_96_iv_fixtures.js "$V"/aes_gcm_vectors.js "$V"/aes.js > "$B"/group-aes-gcm.js
    echo 'export { run_test };' >> "$B"/group-aes-gcm.js
    cat "$V"/helpers.js "$V"/symmetric_importKey.js > "$B"/group-import-key.js
    echo 'export { runTests };' >> "$B"/group-import-key.js
    cat "$V"/helpers.js "$V"/successes.js > "$B"/group-generate-key.js
    echo 'export { run_test };' >> "$B"/group-generate-key.js
    # The WIT input is the *resolved* `componentize-demo` world, not the
    # source files: the runner is componentized against that world's import
    # closure (mac, aead, digest, sha2, hmac-sha2, aes, aes-gcm), so an
    # interface outside it cannot change the component and must not
    # invalidate a published one. Source-file hashing could not express
    # this — `signature` shares webcrypto.wit with `mac` and `aead`. The
    # encoding also omits doc comments, which likewise cannot change the
    # component. wasm-tools is pinned (scripts/wasm-tools.version) so every
    # job encoding this world computes the same lock.
    wasm-tools component embed --dummy examples/componentize-demo/wit \
        --world componentize-demo -o "$B"/world.wasm
    {
        echo "componentize-js-rev $(cat componentize-sdk/componentize-js.rev)"
        sha256sum \
            componentize-sdk/webcrypto.js \
            componentize-sdk/wpt/harness.js \
            componentize-sdk/wpt/runner.js \
            "$B"/group-hmac.js \
            "$B"/group-aes-gcm.js \
            "$B"/group-import-key.js \
            "$B"/group-generate-key.js \
            "$B"/world.wasm
    } > "$B"/runner.lock.computed
    LOCK_HASH="$(sha256sum "$B"/runner.lock.computed | cut -c1-16)"
}

case "${1:-}" in
lock)
    gen_lock
    echo "$LOCK_HASH"
    ;;
build)
    gen_lock
    "$COMPONENTIZE_JS" -q -d examples/componentize-demo/wit -w componentize-demo \
        componentize componentize-sdk/wpt/runner.js -p . \
        -o "$B"/runner.component.wasm
    cp "$B"/runner.lock.computed "$B"/runner.lock.built
    echo "built $B/runner.component.wasm (lock $LOCK_HASH)"
    ;;
ensure)
    gen_lock
    if [ -f "$B"/runner.component.wasm ] && cmp -s "$B"/runner.lock.built "$B"/runner.lock.computed; then
        echo "using $B/runner.component.wasm (lock $LOCK_HASH)"
        exit 0
    fi
    asset="wpt-runner-${LOCK_HASH}.component.wasm"
    echo "fetching ${asset} from ${WPT_COMPONENT_RELEASE}"
    if curl -fsSL --retry 3 -o "$B"/runner.component.wasm.tmp "${WPT_COMPONENT_RELEASE}/${asset}"; then
        mv "$B"/runner.component.wasm.tmp "$B"/runner.component.wasm
        cp "$B"/runner.lock.computed "$B"/runner.lock.built
        exit 0
    fi
    rm -f "$B"/runner.component.wasm.tmp
    cat >&2 <<EOF
error: no WPT runner component is available for input lock ${LOCK_HASH}.

The runner's inputs (see $B/runner.lock.computed) do not match any published
component. Either:
  - push the change and let CI's wpt-component job build and publish it
    (it publishes on merge to main), or
  - build it locally: \`just update-wpt-component\` (needs the
    componentize-js CLI — see componentize-sdk/README.md).
EOF
    exit 1
    ;;
*)
    echo "usage: $0 {lock|build|ensure}" >&2
    exit 2
    ;;
esac
