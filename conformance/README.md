# Conformance suite

One shared guest component carries the whole corpus as self-describing test
cases and runs it against every implementation of `lann:webcrypto`; the
runner aggregates per-target results — validating them against the target
facts in [`targets.toml`](targets.toml) and the checked-in corpus lockfiles —
and renders `matrix.md`. Run it with `just conformance` (see that recipe for
the currently enabled targets).

## Self-describing cases, target facts, and the lockfiles

Expectation policy lives in the corpus, not the harness. The guest exports
`all(missing) -> list<test-case>`; each case carries its stable `name`, the
`features` it exercises beyond the baseline surface (feature tags are inert
by default), and an async `run` returning `pass | fail(detail) |
skipped(detail)`. A target declares only the features it is **missing**
(`targets.toml`, cross-checked against what each adapter passed to `all`):
cases tagged with a missing feature report `skipped`, and the feature-tagged
*probes* assert the correct decline in both directions — a target that
serves a feature it declares missing, or declines one it doesn't, fails.
Growing the corpus therefore never silently sheds coverage: a new suite runs
everywhere until a target consciously opts out.

Corpora work the same way one level up: a corpus may `require` features
**structurally** (its world imports them — the signing corpus requires
`ecdsa-sign`, which class D keeps out of the in-guest provider), and which
corpora a target must produce results for is *derived*: every corpus except
those requiring a feature the target is missing. There is no per-target
corpus list to maintain.

The corpus inventory is pinned by lockfiles (`guest/tests.lock`,
`signing-guest/tests.lock`; TOML, one case per line with its feature tags,
Cargo.lock-style): the runner rejects any results file whose case names or
tags diverge, so corpus changes land intentionally via
`just update-conformance-lock` with a reviewable diff.

## Architecture

```
vectors/           # vendored Wycheproof JSON + the translation policy
                   #   (vectors/README.md) mapping vector expectations into
                   #   this package's stricter contract
guest/             # the conformance guest: vectors compiled in (no I/O
                   #   imports, so the composed target runs under a plain
                   #   `wasmtime run`); exports all(missing) ->
                   #   list<test-case>; tests.lock pins its corpus
signing-guest/     # host-only guest: probes for interfaces the in-guest
                   #   provider deliberately does not export (ecdsa-sign);
                   #   runs under the wasmtime and jco targets only, with
                   #   its own tests.lock
adapters/
  wasmtime/        # native adapter over wasmtime-webcrypto's add_to_linker
  composed-driver/   # CLI driver for the composed in-guest target (guest +
                   #   in-guest provider via `wac plug`); prints results JSON
  jco/             # Node + headless-Chromium adapters over jco-impl's
                   #   webcrypto.js (jco-node gates everywhere; jco-browser
                   #   gates in CI, locally opt-in via CONFORMANCE_BROWSER=1
                   #   with Chrome/Chromium 137+ installed)
runner/            # aggregation: transport invariants + matrix.md rendering
                   #   + the results-viewer data (--json-out)
web/               # the results viewer: a dependency-free static page
                   #   rendering the cross-target matrix as a collapsing
                   #   tree, with a live "test this browser" run
targets.toml       # corpus facts (structurally required features) and
                   #   target facts (missing features and why, optionality)
```

Result files are `results/<target>.json` (or `<target>-<corpus>.json`):
`{ "target", "corpus", "missing-features", "results": [{ "name",
"features", "outcome", "detail" }] }`. Adapters exit nonzero only on harness
errors — failing *cases* are the runner's business. The runner errors (exit
nonzero) when a derived-required (target, corpus) pair has no results file
or an excluded pair has one, a file's cases diverge from its corpus
lockfile, a file's `missing-features` diverges from targets.toml, any
(target, corpus) pair appears twice, or any case fails; `just conformance`
clears `results/` first, so stale files never classify as current.

## Test identity

`<suite>/<source>/<case>/<schedule>` for vector tests (e.g.
`aes-gcm/wycheproof/tc42/bytes`) and `probe/<name>` for API-contract probes.
One vector test runs both directions (seal and open) where applicable;
failures name the direction in `detail`. Matrix rows aggregate by suite
group, so ids must stay stable as the corpus grows.

Every executed vector runs under multiple **chunking schedules** (`whole`,
1-byte `bytes`, and block-boundary `straddle`; empty stream inputs collapse
to `whole`). The
streams-only WIT makes delivery schedule observable to implementations, so
chunking invariance is part of the conformance claim — a class of test a
buffer-based API could not even express.

## Results viewer

`just conformance-web` serves [`web/`](web) after a full conformance run: a
dependency-free static page rendering every case as a collapsing tree (rows
grouped by the `/` segments of case names, with per-subtree rollups) against
one column per target. Its data is the runner's `--json-out` aggregate
(`results/matrix.json` — lockfile case order, per-target outcome columns,
target facts), written alongside `matrix.md` and cleared with the rest of
`results/` each run.

The page is also itself a live target: **Test this browser** runs both
transpiled corpora (the same bundles the jco adapters use) against
`jco-impl/webcrypto.js` in the visiting browser — in a Web Worker, falling
back to the main thread — streaming results into a "this browser" column
and cross-checking the run against the static corpus. It needs
[WebAssembly JSPI](https://caniuse.com/wf-wasm-jspi); without it the page
still renders the static matrix. A finished run can be downloaded in the
results-file shape (the `this-browser` target is deliberately not declared
in targets.toml, so the runner would reject it — it is for inspection, not
gating).

The viewer is published at
<https://lann.github.io/component-webcrypto/> by the `pages` workflow: every
push to main reruns the conformance suite (including the jco-browser target)
and deploys the site assembled by `just conformance-web-site` — a pruned
mirror of the repository layout, which the page's relative URLs and the
transpiled guests' relative imports of `jco-impl/webcrypto.js` both rely on.

## Why this suite is shaped unlike its WebRTC sibling

This suite deliberately diverges from the
[`lann:webrtc-datachannels`](https://github.com/lann/webrtc-datachannels)
conformance machinery it is otherwise modeled on, because the thing under
test is different in kind: WebRTC conformance tests *sessions between peers*;
crypto conformance tests *functions against mathematics*.

- **The oracle is published vectors, not peer convergence** — so the corpus
  is data-driven (Wycheproof + a translation policy) rather than hand-written
  behavioral probes; probes exist only for the API contract itself (drain
  rule, extractability, error variants, algorithm names).
- **There are no interop pairs, signaling server, or live pairing.** The
  algorithms are deterministic: two implementations that both match the
  known-answer bytes match each other, transitively. The N×N live matrix the
  sibling needs is redundant here.
- **The "environment" axis is input adversity × delivery schedule**, not
  network topology: Wycheproof's negative vectors replace hostile networks,
  chunking schedules replace routing scenarios.
- **Divergence is declared as missing features, not expected failures**: the
  jco targets are missing `chacha20-poly1305` (browser WebCrypto implements
  none of it; minting declines `unsupported` — a platform gap a caller
  routes around with another provider) and `deterministic-ecdsa`
  (WebCrypto's randomized `k` makes RFC 6979's known-answer bytes
  unobservable, though the signatures still verify — the decline assertion
  checks exactly that). The anticipated future declarations are profile
  divergence (e.g. a FIPS-profile target missing a permissive-key-policy
  feature). Bugs get fixed, not declared.

## Deliberately deferred

- **Golden-artifact hand-off** (one target seals to a checked-in file,
  others open it): still deferred even now that a randomized seal exists
  (`aead-internal-nonce`), because its cross-target claims are already
  covered deterministically — every target must `open` the same
  vector-derived `iv ‖ ct ‖ tag` sealed messages, which pins the wire
  format, and each target's own `seal` is verified by reopening. A checked-in
  artifact would add only "target A's randomness works on target B", which
  the format pin already implies. Revisit if a wire format ever gains
  target-varying degrees of freedom.
- **The timing lab** (dudect-style statistical tests of the composed in-guest
  provider, targeting the class B/C surfaces in
  `guest-impl/README.md`): when built, it reports (a matrix column and
  artifacts) but does **not** gate — statistical p-values flapping in CI
  train people to ignore red.

## Growing the corpus

Adding an algorithm interface to the package is not done until its vector
suite is here: vendor the vectors, extend the translation policy in
`vectors/README.md` + `guest/src/translate.rs` (they must agree), tag the
new cases with a feature name if any target legitimately cannot serve them
(declaring it missing in `targets.toml` for those targets), and run
`just update-conformance-lock` so the corpus change lands as a reviewable
lockfile diff. An algorithm the in-guest provider deliberately does not
export lives in the host-only signing guest, whose corpus the composed
target never runs — that is absence, not failure.
