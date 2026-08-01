# Experiments

Nothing under `experiments/` carries the guarantees the rest of this
repository makes. Specifically:

- **No CI coverage.** No recipe here is part of `just ci`, the conformance
  suites, or the WPT gates. Code in this directory can be broken by a change
  elsewhere in the tree without anything turning red.
- **No stability.** An experiment may be rewritten, broken, or deleted
  tomorrow. Do not depend on anything in this directory.
- **No review bar.** The code here is exploratory: it exists to exercise the
  `lann:webcrypto` interfaces from the position of a real consumer and to
  surface findings about the package surface, not to ship.

Each experiment is its own Cargo workspace (deliberately not a member of the
root workspace), so the root `cargo`/`just` gates never touch it. Each
directory's README says what the experiment is, how to run it, and what it
found. An experiment that turns out to be worth shipping graduates to its own
repository; it does not harden in place here.

## Contents

- [`hpke/`](hpke/) — RFC 9180 HPKE as a wasm component whose cryptography is
  entirely `lann:webcrypto` imports (via the `hpke-rs` pluggable-provider
  engine).
