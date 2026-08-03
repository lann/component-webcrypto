#!/usr/bin/env python3
"""Census-parity check for the guest-ct port (M1.5 acceptance).

Compares a component-test lockfile for conformance-guest-ct against the
incumbent census (conformance/guest/tests.lock). The inventories must be
equal except that (a) census entries under a generator prefix are covered
by that prefix's record with the same tags, and (b) the port adds exactly
the three `!feature` decline cases listed below (new in the port; the
incumbent asserted declines inside positively-tagged cases).

Usage: compare-census.py [guest-ct.lock]   (default: ../tests.lock)
"""
import collections
import os
import re
import sys

here = os.path.dirname(os.path.abspath(__file__))
root = os.path.normpath(os.path.join(here, "..", "..", ".."))
new_lock = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "..", "tests.lock")

census = {}
with open(os.path.join(root, "conformance", "guest", "tests.lock")) as f:
    for m in re.finditer(
        r'\{ name = "([^"]+)"(?:, features = \[([^\]]*)\])? \}', f.read()
    ):
        census[m.group(1)] = tuple(sorted(re.findall(r'"([^"]+)"', m.group(2) or "")))
assert len(census) == 11578, len(census)

exact, prefixes = {}, {}
for block in re.split(r"\n(?=\[\[)", open(new_lock).read()):
    name = re.search(r'^(?:name|prefix) = "([^"]+)"', block, re.M)
    if not name:
        continue
    tags_m = re.search(r"tags = \[([^\]]*)\]", block)
    tags = tuple(sorted(re.findall(r'"([^"]+)"', tags_m.group(1) if tags_m else "")))
    if block.startswith("[[case]]"):
        exact[name.group(1)] = tags
    elif block.startswith("[[generated]]"):
        prefixes[name.group(1)] = tags

DECLINES = {
    "chacha20-poly1305/decline/minting": ("!chacha20-poly1305",),
    "xchacha20-poly1305/decline/minting": ("!xchacha20-poly1305",),
    "sha1-checked/decline/minting": ("!sha1-checked",),
}

errors = []
for n, t in DECLINES.items():
    if exact.get(n) != t:
        errors.append(f"decline case missing/mistagged: {n} {exact.get(n)}")
for n, t in exact.items():
    if n in DECLINES:
        continue
    if n not in census:
        errors.append(f"exact case not in census: {n}")
    elif census[n] != t:
        errors.append(f"tags diverge on {n}: {t} vs census {census[n]}")

covered = collections.Counter()
for n, t in census.items():
    hits = [p for p in prefixes if n.startswith(p + "/")]
    if n in exact and n not in DECLINES:
        hits.append("<exact>")
    if len(hits) != 1:
        errors.append(f"{n}: covered by {hits}")
    elif hits[0] != "<exact>":
        covered[hits[0]] += 1
        if prefixes[hits[0]] != t:
            errors.append(f"{n}: prefix {hits[0]} tags {prefixes[hits[0]]} != {t}")

for p in prefixes:
    if covered[p] == 0:
        errors.append(f"prefix record covers no census case: {p}")

print(
    f"exact records: {len(exact)} (declines: {len(DECLINES)}), "
    f"prefix records: {len(prefixes)}; census prefix-covered: "
    f"{sum(covered.values())}, exact-covered: {len(census) - sum(covered.values())}"
)
if errors:
    print("FAIL")
    for e in errors[:20]:
        print(" ", e)
    sys.exit(1)
print("PASS: inventory = census + exactly the documented decline cases")
