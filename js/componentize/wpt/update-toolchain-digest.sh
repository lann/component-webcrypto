#!/usr/bin/env bash
#
# Record the digests of the published componentize-js build for the pinned
# revision, after verifying its build-provenance attestation.
#
# This is the one place a new toolchain binary is trusted. It is deliberately
# a separate, manual step: `component.sh` only ever *checks* digests, so
# adding a line to componentize-js.sha256 is a reviewable act rather than
# something a build does silently.
#
# Usage: update-toolchain-digest.sh [platform]   (default: this host's)

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."

REV="$(cat js/componentize/componentize-js.rev)"
PINS=js/componentize/componentize-js.sha256
RELEASE="${COMPONENTIZE_JS_RELEASE:-https://github.com/polymorph-components/polymorph-webcrypto/releases/download/toolchains}"
REPO="${COMPONENTIZE_JS_REPO:-polymorph-components/polymorph-webcrypto}"
WORKFLOW=".github/workflows/componentize-js-toolchain.yml"

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

PLATFORM="${1:-$(platform)}"
ASSET="componentize-js-${REV}-${PLATFORM}.gz"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "==> fetching ${ASSET}"
curl -fsSL --retry 3 -o "$TMP/asset.gz" "${RELEASE}/${ASSET}"
asset_sha="$(sha256sum "$TMP/asset.gz" | cut -d' ' -f1)"

# Verify the provenance of those exact bytes before trusting them. The
# attestation is queried by digest, so this cannot be satisfied by a
# differently-built artifact with the same name.
echo "==> verifying build provenance for sha256:${asset_sha}"
gh api "repos/${REPO}/attestations/sha256:${asset_sha}" > "$TMP/attestations.json"
python3 - "$TMP/attestations.json" "$ASSET" "$asset_sha" "$REPO" "$WORKFLOW" <<'PY'
import base64, json, sys

path, asset, digest, repo, workflow = sys.argv[1:6]
bundles = json.load(open(path)).get("attestations") or []
if not bundles:
    sys.exit(f"no build-provenance attestation for sha256:{digest}")

problems = []
for bundle in bundles:
    payload = json.loads(
        base64.b64decode(bundle["bundle"]["dsseEnvelope"]["payload"])
    )
    subjects = payload.get("subject", [])
    if not any(
        s.get("name") == asset and s.get("digest", {}).get("sha256") == digest
        for s in subjects
    ):
        problems.append("subject does not match the requested asset name and digest")
        continue
    external = (
        payload["predicate"]["buildDefinition"]["externalParameters"]["workflow"]
    )
    if external.get("repository") != f"https://github.com/{repo}":
        problems.append(f"built by another repository: {external.get('repository')}")
        continue
    if external.get("path") != workflow:
        problems.append(f"built by another workflow: {external.get('path')}")
        continue
    source = payload["predicate"]["buildDefinition"]["resolvedDependencies"][0]
    print(f"    attested: {external['path']}")
    print(f"    ref:      {external.get('ref')}")
    print(f"    commit:   {source['digest']['gitCommit']}")
    break
else:
    sys.exit("no acceptable attestation: " + "; ".join(problems))
PY

gzip -dc "$TMP/asset.gz" > "$TMP/binary"
binary_sha="$(sha256sum "$TMP/binary" | cut -d' ' -f1)"

# Rewrite this platform's line, leaving the comments and other platforms be.
tmp_pins="$TMP/pins"
awk -v p="$PLATFORM" '$1 != p || /^#/' "$PINS" > "$tmp_pins"
printf '%s  %s  %s\n' "$PLATFORM" "$asset_sha" "$binary_sha" >> "$tmp_pins"
mv "$tmp_pins" "$PINS"

echo "==> recorded in ${PINS}"
printf '%s  %s  %s\n' "$PLATFORM" "$asset_sha" "$binary_sha"
echo
echo "Commit this alongside componentize-js.rev: it is the record of which"
echo "binary this repository trusts for ${REV} on ${PLATFORM}."
