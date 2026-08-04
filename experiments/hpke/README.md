# `experiments/hpke` — RFC 9180 HPKE over `lann:webcrypto`

An experimental consumer of the `lann:webcrypto` package: a wasm component
exporting RFC 9180 HPKE (base mode, single-shot) whose cryptography is
entirely `lann:webcrypto` imports. Read
[`experiments/README.md`](../README.md) first: nothing here carries the
repository's guarantees — no CI, no stability, delete-at-will.

The point is not to ship HPKE. It is to exercise the package's derive,
agreement, MAC, and AEAD surfaces from the position of a real protocol
consumer, and to record what that consumer runs into. If this were ever to
become a real deliverable it would graduate to its own repository.

## What it is

- **Suites**: DHKEM(X25519, HKDF-SHA-256) + HKDF-SHA-256 (fixed), with
  AES-128-GCM or AES-256-GCM per call. (A ChaCha20-Poly1305 arm existed
  until the package cut its ChaCha interfaces with the WebCrypto-scope
  narrowing — see issue #272; it would return with them.)
- **Engine**: [`hpke-rs`](https://crates.io/crates/hpke-rs), which is
  generic over a pluggable crypto provider (`hpke_rs_crypto::HpkeCrypto`
  — a flat, synchronous, byte-oriented trait). `guest/src/provider.rs`
  implements that trait over the `lann:webcrypto` imports; hpke-rs
  contributes the KEM/key-schedule state machine and none of the crypto.
- **Exports** (`guest/wit/world.wit`): single-shot base-mode
  `seal`/`open`, `generate-key-pair`, `derive-key-pair`, and a
  test-vector-only `seal-deterministic`. Keys travel as raw bytes — this
  is a byte-oriented protocol surface, deliberately *not* a capability
  surface (see findings).

## Layout

```
guest/       the wasm component (wit-bindgen; wasm32-unknown-unknown +
             `wasm-tools component new`, the crypto-demo pattern)
host-test/   Wasmtime-host smoke tests: lann-webcrypto-wasmtime serves the
             imports natively; round trips + RFC 9180 A.1/A.2 known answers
driver/      wasi:cli/run driver for the composed run (the demo-driver
             pattern)
justfile     build/test recipes; `just` lists them
```

This directory is its own Cargo workspace, not a member of the root
workspace, so the root gates never touch it. It reaches the repository's
crates by path (`rust/guest`, `rust/wasmtime`, `rust/guest-provider`).

## Running

Both smoke runs execute the component under a real wasm host; there are no
native unit tests of the HPKE logic.

```
just test           # Wasmtime host: lann-webcrypto-wasmtime (RustCrypto) serves
                    # the lann:webcrypto imports. Round trips, tamper and
                    # wrong-key/AAD failures, RFC 9180 A.1 + A.2 base-mode
                    # known answers (DeriveKeyPair, deterministic seal, open).
just test-composed  # Fully in-guest: the component's imports are satisfied
                    # by rust/guest-provider's provider via `wac plug`, a CLI driver
                    # is plugged on top, and the result runs under
                    # `wasmtime run`. Needs `wac` and `wasmtime` (v47+).
```

Both pass as of this writing, and the known answers are bit-exact against
RFC 9180 appendix A — the whole pipeline (hpke-rs → provider → async
imports → host crypto) reproduces the vectors' `enc` and ciphertexts.

## Findings

What building a real consumer surfaced, in decreasing order of interest.

1. **A synchronous crypto-provider trait can be bridged onto the async
   imports — but only behind async-lifted exports.** `HpkeCrypto` is sync;
   each provider method drives its import calls with
   `wit_bindgen::block_on`, which blocks on `waitable-set.wait`. The first
   attempt exported plain `func`s and trapped under Wasmtime with *"cannot
   block a synchronous task before returning"*: a task may block only if
   its export was lifted `async` (or after it has returned). Declaring the
   exports `async func` — even though they compute strictly synchronously
   and complete on first poll — makes the identical guest code legal. This
   works both against the Wasmtime host and cross-component against the
   in-guest provider's async-lifted exports.

   The async lifting is forced, not an artifact of choosing `block_on`.
   The component model permits sync-*lowering* the imports (asyncness of
   lift and lower are independent), and wit-bindgen generates it
   (`async: ["-all", …]` in `generate!`), turning e.g. `agree` into a
   plain blocking `fn agree(&self, peer: &PublicKey) -> Result<DeriveInput,
   Error>` — verified to run correctly against the Wasmtime host. But two
   limits keep it from changing the design:
   - Wasmtime classifies a sync-lowered call to an async callee as
     blocking and gates it behind the same may-block check, so it still
     traps inside a sync-lifted export (verified). Sync-lowered imports do
     not buy the exports back; they only replace *how* an async-lifted
     task blocks on the scalar calls.
   - The stream-carrying operations are unreachable this way. wit-bindgen
     happily generates the blocking signature (`fn sign(&self, data:
     StreamReader<u8>) -> Result<Vec<u8>, Error>`), but the caller is
     suspended for the call's whole duration and component instances are
     not reentrant, so nothing can feed the input stream the operation
     drains before resolving — a structural deadlock unless the stream's
     writer lives in another component. The package's streaming surface
     commits same-component consumers to the async ABI in practice.

   A hybrid — sync-lowered bindings for the scalar cluster (`x25519`,
   `key-agreement`, `derivation`), `block_on` for the stream ops — is
   feasible: only bytes cross between the two binding universes, so the
   duplicate-resource-type hazard of binding the same interfaces twice
   does not bite. This experiment deliberately does not use it. The guest SDK
   compiles its bindings async-lowered, so the sync cluster means
   bypassing the SDK with a parallel `generate!` universe (own resource
   and error types) — a real cost, paid to bypass machinery that all
   stays in place anyway for the exports and the stream ops.

2. **HPKE's labeled KDF cannot be expressed through the `hkdf-*`
   interfaces; it maps onto `hmac-sha2` instead.** Two independent
   mismatches, both inherent to RFC 9180's KDF discipline rather than to
   hpke-rs:
   - `LabeledExtract` prepends `"HPKE-v1" ‖ suite_id ‖ label` to the
     *secret* IKM. A handle-held secret (an `agree` output chained via
     `prepare-from`) cannot be prefix-concatenated, so the labeled forms
     are only computable over caller-held bytes.
   - The key schedule consumes raw PRKs: `psk_id_hash` and `info_hash`
     are Extract *outputs* embedded into `key_schedule_context`, and every
     Expand is keyed by a caller-held PRK with per-output `info`. The
     `hkdf` interfaces never expose a PRK (deliberately — WebCrypto's
     forced non-extractability, made structural).

   Since HKDF is just HMAC composition, the provider implements Extract as
   one `mac-key.sign` and Expand as the RFC 5869 `T(i)` loop. The package's
   handle-chaining path (`agree` → `prepare-from` → `derive-key`) fits its
   own worked example (plain X25519 → HKDF → AES-GCM) but not HPKE's exact
   shape. That is not an indictment of the WIT: plugging a byte-oriented
   library forfeits the no-secret-transits property from the start (the
   trait traffics in key bytes), so this consumer was never going to keep
   secrets behind handles. A *handle-native* HPKE — one designed against
   the WIT rather than behind `HpkeCrypto` — would need either labeled
   variants of extract or prefix-feeding of chained IKM to keep the DH
   shared secret off the caller's heap.

3. **The absent secret→public derivation costs X25519 consumers nothing.**
   The package deliberately provides no way to get a `public-key` from a
   `secret-key`. DHKEM decap needs `pkRm` (it is part of `kem_context`),
   and hpke-rs computes it as `secret_to_public(skR)`. For X25519 that is
   just DH with the base point: `X25519(sk, 9)` — `import-public-key-raw`
   of the base point plus `agree` recovers the derivation exactly. (This
   only works because the consumer holds raw scalars anyway; a NIST-curve
   DHKEM would need the same trick via a fixed generator point import.)

4. **Raw secret scalars enter as PKCS#8.** The WIT admits X25519 secret
   keys only as JWK or PKCS#8 (the format-admission rule: only formats a
   platform passes through verbatim). RFC 8410's PKCS#8 for X25519 is a
   fixed 16-byte DER prefix plus the scalar, so wrapping is trivial;
   `kem_key_gen` goes the other way (`generate-key` →
   `export-key-pkcs8` → strip). Cheap, but every byte-oriented consumer
   will re-implement these 16 bytes.

5. **The package has no random-bytes interface, and a consumer feels it.**
   hpke-rs needs a CSPRNG (encapsulation randomness). The provider
   harvests entropy by generating an extractable X25519 key, exporting it
   as PKCS#8, and hashing it host-side (SHA-256) to strip the clamping
   bias — one generated key per 32-byte block. It works and the output is
   uniform, but it is a workaround with real cost per draw. The roadmap's
   `getRandomValues` item (AGENTS.md, "Direction") is what this actually
   wants.

6. **HKDF's zero salts vs the non-empty HMAC key rule.** hpke-rs passes
   `[]` and `[0]` as Extract salts; `hmac-sha2.import-key-raw` rejects
   empty keys. HMAC zero-pads keys to the block size, so every all-zero
   salt is equivalent to 32 zero bytes — the provider normalizes through
   that equivalence. A pure RFC 5869 consumer should expect to need the
   same one-liner.

## Caveats (all deliberate, none fixable in place)

- Secrets — scalars, shared secrets, PRKs, AEAD keys — live in guest
  memory as plain bytes. This consumer demonstrates interface fit, not the
  package's capability discipline.
- `seal-deterministic` reuses ephemeral keys and nonces by construction;
  it exists for the RFC vectors and must never carry real traffic.
- Every AEAD/MAC operation imports its key fresh; nothing is cached.
- Smoke coverage only: two RFC vectors plus round trips. No Wycheproof,
  no negative-vector sweeps, no timing consideration. The conformance
  machinery in `conformance/` is the model for what "real" coverage looks
  like; building it here would mean this stopped being an experiment.
