# `guest-webcrypto`

The in-guest implementation of `lann:webcrypto`: a wasm component (built for
`wasm32-wasip2`) that runs RustCrypto entirely inside the guest and **exports**
the package surface. Compose it under any consumer with `wac plug` and the
result is a single self-contained component whose cryptography needs no crypto
capability from the host — `just test-webcrypto-composed` runs the shared
`crypto-demo` guest this way under a plain `wasmtime run`.

## Security notice: timing channels in wasm

Read this before choosing this provider.

The WebAssembly specification makes **no constant-time guarantee for any
instruction**. Worse, wasm crypto has a *two-compiler problem*: source-level
constant-time discipline (e.g. RustCrypto's `subtle` barriers) defeats the
first compiler (LLVM), but the bytecode that reaches the runtime is plain
arithmetic, and the JIT is a second optimizer that is free to reintroduce
exactly the transformations the source fought off — a `select` over secret
data can legally become a branch. No portable guarantee exists; empirical
verification is per-runtime, per-hardware, and fragile across runtime
upgrades. The repository's `timing-lab/` provides a first empirical check of
this provider's surfaces (see its README for methodology and, crucially, its
detection limits).

Two facts frame the residual risk:

- **The host is already trusted.** Anyone running crypto in a wasm guest has
  conceded that the host can read all key material. The marginal timing-channel
  adversaries are co-tenants and remote observers — so do **not** use this
  provider where hostile co-tenancy is part of the threat model.
- **The realistic baseline is worse.** The alternative in practice is linking
  crypto directly into application components. This provider strictly improves
  on that: the component model's share-nothing isolation keeps key material in
  *this* component's linear memory, unreachable from consumers — a
  memory-safety bug or malicious dependency in the application cannot
  exfiltrate a key, and `extractable: false` is genuinely enforced. Timing is
  the remaining channel; memory is closed.

When a host-side implementation is available, prefer it. The side-channel
ordering of this repository's implementations is: `jco-impl` (platform Web
Crypto — native, hardware-accelerated, best studied), then `wasmtime-impl`
(native RustCrypto), then this provider.

## Timing-channel classification

Whether an algorithm is safe to run in wasm is a property of how much its best
software implementation must **trust the machine below it** (including the
JIT), weighted by how **forgiving of failure** the construction is
(exploitability ≈ probability of a leak × blast radius of a small leak).

| Class | Trust required | Examples | In-guest policy |
| --- | --- | --- | --- |
| **A — structurally constant-time** | None beyond a correct compiler: no secret-dependent branches or memory indices, only add/xor/rotate. Nothing for a JIT to miscompile into a leak. | SHA-2, SHA-3, BLAKE2/3, HMAC, ChaCha20, HKDF | Export freely. |
| **B — CT given a constant-time multiplier and benign lowering** | Constant-latency hardware multiply; JIT lowers select/cmov without branches. This is where the two-compiler problem lives. | Poly1305, GHASH, X25519/Ed25519 | Export with the CT-variant implementation; document. |
| **C — CT only via costly variants** | The *fast* implementation leaks (secret-indexed tables); a bitsliced/fixsliced variant is CT at a several-fold cost. | AES | Export **only** the CT variant. |
| **D — not realistically CT in portable wasm** | Heroic implementation effort with near-zero leak tolerance: bignum branches, secret-dependent allocation, catastrophic small leaks (nonce bits → key recovery; remote-exploitable history). | RSA private-key ops, ECDSA signing, classic DH | **Never exported by this provider.** |

Class D is enforced structurally, not by documentation: this provider simply
does not export those algorithm interfaces, so a composition that needs them
**fails at `wac plug` time** rather than running quietly degraded — and one
level deeper, the shared `webcrypto-impl-core` compiles no ECDSA signing
code for wasm targets at all (`#[cfg(not(target_family = "wasm"))]`), so the
class-D code is absent from this component's binary, not merely unexported.
Choose a host-side provider for them.

`just class-d-composition` is that enforcement's gate: it asserts that the
conformance signing guest, whose world imports `ecdsa-sign`, does not
compose with this provider.

### What the failure looks like

`wac plug` reports a resource-type mismatch, not an unsatisfied import:

```
error: encoding produced a component that failed validation
Caused by:
    type mismatch for import `lann:webcrypto/ecdsa-sign@0.1.0`
    type mismatch in instance export `signing-key`
    resource types are not the same (...)
```

`wac plug` leaves imports it cannot satisfy in place — that is how the
composed demo keeps its `wasi:cli` imports — so an unexported interface is
not by itself a composition error. What makes it one here is that
`ecdsa-sign` does `use signature.{signing-key}` and this provider *does*
export `signature`: plugging rebinds `signing-key` to the provider's own
resource and orphans the `ecdsa-sign` import, which still names the
imported one.

The enforcement therefore rests on the provider exporting the generic
interface whose key resource the withheld minting interface mints. Every
minting interface in the package `use`s a generic key resource, and this
provider exports every generic kind, so the property holds across the
surface — but a future class-D interface minting a resource from a kind
this provider does not export would compose silently. The gate is what
catches that.

The classes describe **keyed operations**. Operations without secrets —
hashing public data, and notably **signature verification** (e.g. validating
JWTs) — are exempt regardless of the signing algorithm's class: the
`signature` primitive kind's `verify` over public keys is fine in-guest even
where the corresponding `sign` is class D — which is why this provider
exports `ecdsa-verify` but not `ecdsa-sign`. The key-resource layering is
what marks where secrets flow.

### What this provider exports today

| Algorithm | Class | Implementation | Residual assumptions |
| --- | --- | --- | --- |
| HMAC-SHA-2 (256/384/512) | A | `hmac` + `sha2` (pure ARX-style arithmetic; constant-time `verify_slice`) | None beyond compiler correctness. |
| AES-GCM (128/256) | C + B | `aes-gcm` with the soft **fixsliced** AES backend (bitsliced, table-free) + masked-multiply GHASH | Constant-latency integer multiply; JIT does not pathologically rewrite straight-line arithmetic. |
| ChaCha20-Poly1305 / XChaCha20-Poly1305 | A + B | `chacha20poly1305` (portable software backend: ChaCha20 is pure ARX by construction; Poly1305 is limb-based multiply-accumulate) | Constant-latency integer multiply (Poly1305 only). |
| AES-GCM / XChaCha20-Poly1305 internal-nonce (`aead-internal-nonce`) | as the underlying AEAD | The same ciphers under implementation-generated nonces (WASI random; SP 800-38D §8.2.2 RBG-based construction), with the 2^32 nonce budget enforced for 12-byte-nonce algorithms | As the underlying AEAD; the nonce is public, so its generation adds no timing surface. |
| X25519 key agreement | B | `x25519-dalek` (curve25519-dalek's constant-time Montgomery ladder: limb-based multiply-accumulate, no secret-dependent branches or indices; the all-zero contributory check compares in constant time) | Constant-latency integer multiply. |
| SHA-2 digests (256/384/512) | exempt (secret-free) | `sha2` | The `digest` primitive is unkeyed — hashing public data carries no secret to leak. `bytes.constant-time-equal` (via `subtle`) is exported for callers comparing digests against untrusted values. |
| Ed25519 (sign + verify) | B | `ed25519-dalek` (complete addition laws, no per-signature secret nonce, constant-time scalar arithmetic) | Constant-latency integer multiply; JIT does not pathologically rewrite straight-line arithmetic. |
| ECDSA P-256/P-384 (**verify only**) | exempt (secret-free) | `p256`/`p384` verification — public keys and public signatures | Signing is class D (per-signature secret nonce; small leaks are key-recovering) and its interface (`ecdsa-sign`) is **not exported**; compositions requiring it fail at `wac plug` time. |

ChaCha20-Poly1305 (class A + B) is the *recommended* AEAD for in-guest use —
constant time by construction rather than by countermeasure, it is the
cipher designed for exactly this situation. AES-GCM's class C is a heroic
implementation working against the algorithm's nature.
