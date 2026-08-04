# Conformance tests

Two test **suites** — the shared suite ([`guest-ct/`](guest-ct)) and the
host-only signing suite ([`signing-guest-ct/`](signing-guest-ct)), each a
guest component carrying its cases — run against every implementation of
`lann:webcrypto` on the [`lann:component-test`] stack: the suites are built
on its guest SDK and export its frozen `tests` contract, and the drivers,
lockfiles, and aggregation are its tooling. Run everything with
`just conformance-ct::all` (see [`driver-ct/justfile`](driver-ct/justfile)
for the individual recipes and the currently enabled targets).

[`lann:component-test`]: https://github.com/lann/component-test

## Layout

```
vectors/           # vendored Wycheproof JSON + the translation policy
                   #   (vectors/README.md) mapping vector expectations into
                   #   this package's stricter contract
harness/           # world-independent suite infrastructure: probe table
                   #   machinery, feature names, error rendering, assertion
                   #   helpers, stream delivery schedules
                   #   (crate: conformance-harness)
guest-ct/          # the shared suite: vectors compiled in (translate.rs),
                   #   per-kind contract batteries (contract.rs), API
                   #   probes (probes.rs); tests.lock pins its inventory
signing-guest-ct/  # the signing suite: cases for the private-key minting
                   #   surface the in-guest provider deliberately does not
                   #   export (ecdsa-sign, the gated rsa-sign interfaces,
                   #   the gated rsa-oaep-decrypt interface) — probes plus
                   #   the RSASSA-PKCS1-v1_5 sig-gen known-answer vectors
                   #   (deterministic signing byte-compares) and the
                   #   RSA-OAEP decryption vectors (deterministic
                   #   decryption of published ciphertexts); its own
                   #   tests.lock
class-d/           # the class-D gate's dedicated probe worlds (no Rust:
                   #   `wasm-tools component embed --dummy` builds them):
                   #   one world per withheld minting interface, each
                   #   importing only its own, proving the provider's
                   #   generic-kind exports keep those mints uncomposable
driver-ct/         # the host driver (ct-driver: wasmtime + RustCrypto as
                   #   the SUT, component-test-runner as the harness), the
                   #   jco/Node runner (jco/), targets.toml (target
                   #   capability manifests), the justfile module, and the
                   #   committed matrix.md / matrix-signing.md
```

## Cases, feature tags, and the lockfiles

Expectation policy lives in the cases, not the harness. Each case carries a
stable name (`<algorithm>/<source>/<case>/<schedule>` for vector cases,
`probe/<name>` for API-contract probes) and the feature **tags** it
exercises beyond the baseline surface. A target declares only the features
it is **missing** ([`driver-ct/targets.toml`](driver-ct/targets.toml)):
scheduling against that manifest is the runner's business — cases never
inspect feature state — and each feature's decline assertion is its own
`!feature` case, scheduled exactly on targets missing it. Growing the
suites therefore never silently sheds coverage: new cases run everywhere
until a target consciously opts out.

Each suite's case inventory is pinned by a component-test lockfile
(`guest-ct/tests.lock`, `signing-guest-ct/tests.lock`); the inventory is
the binding — the recorded sha256 is build provenance only, since wasm
builds are not reproducible across checkouts (lann/component-test#44).
`just conformance-ct::lock-check` gates drift and
`just conformance-ct::lock-update` regenerates after intentional case
changes, landing them as a reviewable diff. The aggregates bind against
these same committed lockfiles. The census-parity tests
(`census_test.rs` in each suite crate) additionally anchor the inventory to
the retired incumbent harness's final census, byte-frozen at the M1.6
cutover (and re-frozen as the incumbent's suites grew before its
retirement landed) as `src/census-fixture.lock` in each suite crate. The
port diverges from the incumbent ids in exactly one documented way, which
the parity tests account for: the additive `!feature` decline cases
(above). All other ids — including the RSA algorithm segments' modulus
words (`rsassa-pkcs1-v15-sha256-2048` etc.) — match the incumbent's
verbatim under the amended component-model label grammar (number-only
kebab words after the first).

The lockfiles pin the **inventory**, not the assertions. A case that keeps
its name while weakening what it checks produces no lockfile diff; that is
caught by review, and measured empirically by the weekly mutation run
(`just mutants`) — a mutant of the crypto core or the Wasmtime host that
neither the unit tests nor these suites distinguish fails that job.

Every executed vector runs under multiple **chunking schedules** (`whole`,
1-byte `bytes`, block-boundary `straddle`; empty stream inputs collapse to
`whole`). The streams-only WIT makes delivery schedule observable to
implementations, so chunking invariance is part of the conformance claim —
a class of test a buffer-based API could not even express.

## Targets and aggregation

`just conformance-ct::all` builds the suites and the driver, drift-checks
the lockfiles, runs the targets, and aggregates:

- **wasmtime-rustcrypto** (`run-wasmtime`): ct-driver embeds
  `lann-webcrypto-wasmtime` with every gated interface enabled — the
  full-support target.
- **composed** (`run-composed`): the suite plugged with the in-guest
  RustCrypto provider (`wac plug`), run under the generic component-test
  host runner; missing only the structural `ecdsa-sign` (class D).
- **jco-node** (`run-jco`): the suite transpiled with jco (JSPI) and driven
  from Node 24+ against `webcrypto-jco`; missing `sha1-checked` (platform
  SHA-1 carries no sha1dc collision detection).
- **jco-browser** (`run-browser`): the same transpiles and host module with
  the case loop running in headless Chromium (`driver-ct/jco/harness.mjs`
  in-page, driven by `run-browser.mjs` over
  `scripts/browser-page-driver.mjs`); missing `sha1-checked` and, for
  the signing suite, the fail-closed RSA private-key mints
  (`rsa-sign`, `rsa-oaep-decrypt`). Optional: it gates in CI (the runner
  image ships Chrome) and runs locally only with `CONFORMANCE_BROWSER=1`;
  the aggregates warn, not error, when its results are absent.
- The **signing suite** runs under the host-backed targets
  (wasmtime-rustcrypto, jco-node, jco-browser) only: its world imports
  `ecdsa-sign` structurally, which class D keeps out of the
  in-guest provider (see `rust/guest-provider/README.md`). The
  negative-composition gate (`just conformance-ct::class-d`, part of
  `all`) holds that declaration to the truth: it asserts the signing suite
  does not compose with the in-guest provider, so the provider cannot
  start exporting `ecdsa-sign` while the manifest still says it does not.
  The same gate asserts every other withheld minting interface with a
  dedicated minimal probe world (`class-d/*/wit`, one per interface): the
  signing suite's composition already fails on `ecdsa-sign`, so only a
  component importing *nothing withheld but* interface X can prove X
  stays unserved.

Each target writes JSONL results (`driver-ct/results/`); the aggregation
step (`component-test aggregate`) validates every results file against the
lockfile and the target manifest and renders
[`driver-ct/matrix.md`](driver-ct/matrix.md) /
[`matrix-signing.md`](driver-ct/matrix-signing.md), exiting nonzero on any
failure or transport problem.

## Vector provenance

What review cannot establish on its own is whether a vendored vector is
what upstream published. [`vectors/README.md`](vectors/README.md) records
the upstream revision of every file for that purpose, so a copy can be
re-fetched and diffed against its source.

## Growing the suites

Adding an algorithm interface to the package is not done until its vector
cases are here: vendor the vectors, extend the translation policy in
`vectors/README.md` + `guest-ct/src/translate.rs` (they must agree), add
the algorithm's `#[case_row]` registration in `guest-ct/src/lib.rs`, tag
the new cases with a feature name if any target legitimately cannot serve
them (declaring it missing in `driver-ct/targets.toml` for those targets,
and adding the feature's `!feature` decline case), and run
`just conformance-ct::lock-update` so the change lands as a reviewable
lockfile diff. An algorithm of a kind with a contract battery
(`guest-ct/src/contract.rs`) also adds its table row there, inheriting the
kind's standard cases as `<interface>/contract/…` lockfile entries; only
behavior specific to the algorithm needs a hand-written probe. An algorithm
the in-guest provider deliberately does not export lives in the signing
suite — that is absence, not failure.

## Results-schema tolerance

The component-test *schema* tolerates unknown result statuses on the
wire (its additive-evolution policy: a future component-test status
arrives without a format break) and the aggregate reports them as
warnings. This looked like a tolerance change against the incumbent
runner, which treated unknown outcomes as hard failures, and was
originally flagged here for sign-off. It is not one in effect: the
fold diverts an unknown-status row out of the parsed results, so the
case is then *missing* from coverage, and the aggregate's coverage
check — which this harness always runs with a full-census lockfile —
fails the run. An unknown status therefore surfaces as a warning
naming the case and status plus a coverage error, and cannot pass
silently. Gating parity with the incumbent holds; ratified on that
basis (upstream's fold/aggregate tests pin the diversion-plus-coverage
behavior).
