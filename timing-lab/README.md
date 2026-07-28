# timing-lab

A dudect-style statistical timing lab for the composed `lann:webcrypto`
in-guest provider: the same component the demos and conformance tests exercise,
measured entirely in-guest under `wasmtime`.

```
just timing-lab                          # compose + run
TIMING_LAB_SAMPLES=20000 just timing-lab # trade runtime for sensitivity
just timing-lab-scheduled                # as the scheduled job runs it
```

## Automation

`just timing-lab` is deliberately absent from `just ci`: a statistical
experiment on a shared runner cannot gate pull requests without flaking
them. But an unautomated lab rots — its runtime behavior (the positive
controls' sensitivity to clock granularity, say) decays invisibly while only
its *compilation* is checked.

So it runs on its own cadence instead, weekly, from
`.github/workflows/timing-lab.yml`, and there a failure **fails the job**
rather than being swallowed by `continue-on-error`: a scheduled failure
notifies, and a job nobody is told about is the state this replaces. To
absorb the flakes that motivated keeping it out of CI, `just
timing-lab-scheduled` retries a diverging run once at 4× samples and reports
failure only if the divergence survives — the lab's own advice on a
surprising verdict, applied automatically. The report lands in the run's job
summary either way.

`workflow_dispatch` takes a `samples` input for an on-demand run at a
different sensitivity.

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
leak. For seal surfaces the classes are *fixed* vs *freshly random*
plaintext, probing data-dependent cipher timing (e.g. table-based AES).

Three properties of the sampling loop keep class from correlating with
anything but the input:

- **A balanced, shuffled schedule.** Class order is a shuffled permutation of
  equal counts, not a per-trial coin flip: a coin flip's random walk exhausts
  one class ~√n trials before the other, leaving the run's final samples all
  one class — precisely where end-of-run drift lives.
- **Symmetric per-trial work.** Every trial draws a fresh random buffer and
  performs one clone regardless of which class it feeds to the operation.
  Generating random input only for the random class would put that work, and
  its cache pressure, in front of one class's measurements — a difference
  manufactured by the harness rather than found in the code.
- **Discarded warm-up.** Trials per class run before sampling begins, so
  one-off costs (code paths, caches, lazy allocations) land outside the data.

Probe lengths follow the signal, and the two kinds pull in opposite
directions. A tag comparison's early-exit signal is a fixed ~15-byte
difference no matter how long the message is, while the noise it competes
with — the stream transfer and the full MAC/GHASH recomputation, all inside
the timed window — grows with the message; the tag-compare surfaces
therefore use a short (64-byte) message. Data-dependent cipher effects
accumulate per block, so the seal surfaces use a long (16 KiB) plaintext.
Shortening the tag probes lowered their measured σ by 4–21× at identical
signal.

## Controls

Every run is bracketed by in-guest controls, one per class shape — a
positive control validates only the shape it uses, so each shape needs its
own:

- **`control/leaky-equal`** — a deliberate early-exit byte compare, the
  *corrupted-first-vs-last* shape. MUST read as a leak; if it doesn't, the
  harness cannot see anything at this measurement distance and every other
  verdict is meaningless, so the run fails.
- **`control/data-dependent-work`** — a per-byte loop whose trip count is the
  byte's low nibble, the *fixed-vs-random* shape. Also MUST read as a leak.
  Without it, a quiet seal verdict cannot distinguish "the cipher has no data
  dependence" from "the harness cannot see data dependence here".
- **`control/subtle-ct-eq`** — `subtle::ConstantTimeEq`, expected quiet.

The positive controls establish *detectability*, not a sensitivity
threshold: both leak by orders of magnitude, so they show the harness works,
not how small a leak it would catch.

## Detection limits (read before trusting a "quiet")

- **Sensitivity is proportional to the secret-dependent work.** The positive
  control leaks over a 4096-byte compare; a 16-byte tag compare's early-exit
  difference is ~two orders of magnitude smaller and may sit under the noise
  floor of the async stream plumbing each call crosses. A quiet verdict
  bounds the leak's size at this measurement distance; it does not prove
  constant time.
- **The reported `mean ns` and `sigma ns` are that measurement distance.**
  `mean` is how much unrelated work each sample carries alongside the
  operation under test; `sigma` is the run's own noise floor. A per-class
  difference well below `sigma / √samples` is invisible to that row, which is
  what its quiet verdict does and does not bound.
- **The clock is the guest's `wasi:clocks` monotonic clock** as wasmtime
  surfaces it. Its resolution and the component-boundary overhead set the
  noise floor; the positive control's |t| is the run's own report of how much
  headroom exists above it.
- **Statistical tests flake.** A LEAK verdict on a real surface warrants
  investigation, starting with a rerun at higher `TIMING_LAB_SAMPLES` — not
  an immediate conclusion. This is why `just timing-lab` is deliberately not
  part of `just ci`: shared CI runners add scheduling noise that produces
  both false quiets (noise floor) and false leaks (correlated drift). The
  scheduled job automates exactly that rerun (see Automation).

## Relation to the timing-channel classes

`guest-impl/README.md` classifies each algorithm's timing behavior (classes
A–D) by *construction* — argument from the code's shape. The lab is the
*empirical* companion: it can confirm the positive claims are not obviously
wrong (ChaCha20-Poly1305's class A + B should be the boring, quiet row) and
catch regressions in the countermeasures (the fixsliced AES backend, the
masked-multiply GHASH, `subtle` comparisons). It cannot prove a negative.
