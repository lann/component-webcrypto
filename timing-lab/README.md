# timing-lab

A dudect-style statistical timing lab for the composed `lann:webcrypto`
in-guest provider: the same component the demos and conformance tests exercise,
measured entirely in-guest under `wasmtime`.

```
just timing-lab                          # compose + run
TIMING_LAB_SAMPLES=20000 just timing-lab # trade runtime for sensitivity
```

## Methodology

Per surface, the lab interleaves measurements of **two input classes chosen
so that only secret-dependent control flow could separate them**, then
compares the two timing distributions with Welch's t-test — over the full
data and over upper-percentile-cropped subsets (timing tails are heavy;
cropping the slowest samples exposes differences the tail would drown). A
surface leaks if max |t| over all crops exceeds 10, the reference dudect's
threshold for exactly this max-over-crops statistic (the single-test 4.5
would over-report).

Class design is the load-bearing choice. For verification surfaces the
classes are *tag corrupted at the first byte* vs *at the last byte*: both
calls fail authentication and recompute the same MAC, so any timing
difference isolates the tag **comparison** — the classic early-exit-compare
leak. For seal surfaces the classes are fixed vs varying plaintext, probing
data-dependent cipher timing (e.g. table-based AES).

## Controls

Two in-guest controls bracket every run:

- **`control/leaky-equal`** — a deliberate early-exit byte compare that MUST
  read as a leak. If it doesn't, the harness cannot see anything at this
  measurement distance and every other verdict is meaningless; the run fails.
- **`control/subtle-ct-eq`** — `subtle::ConstantTimeEq` on the same inputs,
  expected quiet.

## Detection limits (read before trusting a "quiet")

- **Sensitivity is proportional to the secret-dependent work.** The positive
  control leaks over a 4096-byte compare; a 16-byte tag compare's early-exit
  difference is ~two orders of magnitude smaller and may sit under the noise
  floor of the async stream plumbing each call crosses. A quiet verdict
  bounds the leak's size at this measurement distance; it does not prove
  constant time.
- **The clock is the guest's `wasi:clocks` monotonic clock** as wasmtime
  surfaces it. Its resolution and the component-boundary overhead set the
  noise floor; the positive control's |t| is the run's own report of how much
  headroom exists above it.
- **Statistical tests flake.** A LEAK verdict on a real surface warrants
  investigation, starting with a rerun at higher `TIMING_LAB_SAMPLES` — not
  an immediate conclusion. This is why `just timing-lab` is deliberately not
  part of `just ci`: shared CI runners add scheduling noise that produces
  both false quiets (noise floor) and false leaks (correlated drift).

## Relation to the timing-channel classes

`guest-impl/README.md` classifies each algorithm's timing behavior (classes
A–D) by *construction* — argument from the code's shape. The lab is the
*empirical* companion: it can confirm the positive claims are not obviously
wrong (ChaCha20-Poly1305's class A + B should be the boring, quiet row) and
catch regressions in the countermeasures (the fixsliced AES backend, the
masked-multiply GHASH, `subtle` comparisons). It cannot prove a negative.
