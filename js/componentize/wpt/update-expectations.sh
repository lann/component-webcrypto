#!/usr/bin/env bash
#
# Re-record js/componentize/wpt/expected.js from an actual run.
#
# The runner emits its observed census on every run, passing or failing, so
# this works whether the current expectations are stale, empty, or wrong —
# which is the point: the file exists to make a moved number a reviewable
# diff, not to be hand-maintained.
#
# Usage: update-expectations.sh <path to the composed runner component>

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."

COMPOSED="${1:?usage: update-expectations.sh <composed component>}"
EXPECTED=js/componentize/wpt/expected.js

output="$(timeout 600 wasmtime run -W component-model-async=y -S cli "$COMPOSED" 2>&1 || true)"
census="$(printf '%s\n' "$output" | sed -n 's/.*WPT-CENSUS //p' | tail -1)"
if [ -z "$census" ]; then
    echo "error: the runner emitted no WPT-CENSUS line; its output was:" >&2
    printf '%s\n' "$output" >&2
    exit 1
fi

python3 - "$EXPECTED" "$census" <<'PY'
import json, sys

path, census = sys.argv[1], sys.argv[2]
observed = json.loads(census)

# Keep everything above the export: the header explains why this file exists.
header = open(path).read().split("export const EXPECTED")[0]

body = ["export const EXPECTED = {"]
for group, counts in observed.items():
    fields = ", ".join(f"{k}: {v}" for k, v in counts.items())
    body.append(f"  {json.dumps(group)}: {{ {fields} }},")
body.append("};")

open(path, "w").write(header + "\n".join(body) + "\n")
print(f"recorded {len(observed)} groups in {path}")
PY

echo "Review the diff: every moved number is a test that appeared, vanished,"
echo "or crossed the in-subset boundary."
