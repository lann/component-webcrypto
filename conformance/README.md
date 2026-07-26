# Conformance suite

One shared guest component runs the whole corpus against every
implementation of `lann:webcrypto`; the runner classifies per-target results
against [`manifests.toml`](manifests.toml) and renders `matrix.md`. Run it
with `just conformance` (see that recipe for the currently enabled targets).

## Architecture

```
vectors/           # vendored Wycheproof JSON + the translation policy
                   #   (vectors/README.md) mapping vector expectations into
                   #   this package's stricter contract
guest/             # the conformance guest: vectors compiled in (no I/O
                   #   imports, so the composed target runs under a
                   #   plain `wasmtime run`); exports count/run-all/run-slice
signing-guest/     # host-only guest: probes for interfaces the in-guest
                   #   provider deliberately does not export (ecdsa-sign);
                   #   runs under the wasmtime and jco targets only, results
                   #   merged into the same per-target files
adapters/
  wasmtime/        # native adapter over wasmtime-webcrypto's add_to_linker
  composed-driver/   # CLI driver for the composed in-guest target (guest +
                   #   in-guest provider via `wac plug`); prints results JSON
  jco/             # Node + headless-Chromium adapters over jco-impl's
                   #   webcrypto.js (jco-node gates everywhere; jco-browser
                   #   gates in CI, locally opt-in via CONFORMANCE_BROWSER=1
                   #   with Chrome/Chromium 137+ installed)
runner/            # classification + matrix.md rendering
```

Result files are `results/<target>.json`:
`{ "target": ..., "results": [{ "id", "passed", "detail" }] }`. Adapters exit
nonzero only on harness errors — failing *tests* are the runner's business.

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
- **Expectations in `manifests.toml` encode policy, not capability**: the
  jco targets expected-fail the ChaCha20-Poly1305 corpus (browser WebCrypto
  implements no ChaCha20-Poly1305, so the jco host declines those keys as
  `unsupported` — a missing platform feature a caller routes around with
  another provider) and the deterministic-ECDSA signing probe (WebCrypto's
  randomized `k` makes RFC 6979's known-answer bytes unobservable, though the
  signatures still verify). The anticipated future entries are profile
  divergence (e.g. a FIPS-profile target expected-failing the short-key HMAC
  vectors). Bugs get fixed, not manifested.

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
`vectors/README.md` + `guest/src/translate.rs` (they must agree), and update
the per-target manifests/profiles if the algorithm's policy differs by
implementation (e.g. an algorithm the in-guest provider deliberately does not
export appears in no composed results — that is absence, not failure).
