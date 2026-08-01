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
| HMAC-SHA-2 (256/384/512) and HMAC-SHA-1 | A | `hmac` + `sha2`/`sha1` (pure ARX-style arithmetic; constant-time `verify_slice`) | None beyond compiler correctness. SHA-1 appears only inside the HMAC-family constructions (`hmac-sha1`, `hkdf-sha1`, `pbkdf2-sha1`), where collision resistance is not load-bearing. |
| AES-GCM (128/256) | C + B | `aes-gcm` with the soft **fixsliced** AES backend (bitsliced, table-free) + masked-multiply GHASH | Constant-latency integer multiply; JIT does not pathologically rewrite straight-line arithmetic. |
| AES-CBC / AES-CTR (128/256, the `cipher` kind) | C | The same fixsliced `aes` block cipher; CBC chaining, arbitrary-width wrapping CTR, and the branch-free PKCS#7 unpad are assembled here | As AES-GCM's AES half. The CBC padding *verdict* is API-visible by design (WebCrypto parity; one uniform error) — the unpad accumulates it without early exits, so timing adds nothing beyond the verdict itself. |
| ChaCha20-Poly1305 / XChaCha20-Poly1305 | A + B | `chacha20poly1305` (portable software backend: ChaCha20 is pure ARX by construction; Poly1305 is limb-based multiply-accumulate) | Constant-latency integer multiply (Poly1305 only). |
| AES-GCM / XChaCha20-Poly1305 internal-nonce (`aead-internal-nonce`) | as the underlying AEAD | The same ciphers under implementation-generated nonces (WASI random; SP 800-38D §8.2.2 RBG-based construction), with the 2^32 nonce budget enforced for 12-byte-nonce algorithms | As the underlying AEAD; the nonce is public, so its generation adds no timing surface. |
| X25519 key agreement | B | `x25519-dalek` (curve25519-dalek's constant-time Montgomery ladder: limb-based multiply-accumulate, no secret-dependent branches or indices; the all-zero contributory check compares in constant time) | Constant-latency integer multiply. |
| SHA-2 digests (256/384/512) | exempt (secret-free) | `sha2` | The `digest` primitive is unkeyed — hashing public data carries no secret to leak. `bytes.constant-time-equal` (via `subtle`) is exported for callers comparing digests against untrusted values. |
| Checked SHA-1 digests (`sha1-checked`) | exempt (secret-free) | `sha1-checked` (sha1dc counter-cryptanalysis; both postures) | Unkeyed, like SHA-2; the collision detection branches only on the input, which the digest kind treats as public. |
| Ed25519 (sign + verify) | B | `ed25519-dalek` (complete addition laws, no per-signature secret nonce, constant-time scalar arithmetic) | Constant-latency integer multiply; JIT does not pathologically rewrite straight-line arithmetic. |
| ECDSA P-256/P-384 (**verify only**) | exempt (secret-free) | `p256`/`p384` verification — public keys and public signatures | Signing is class D (per-signature secret nonce; small leaks are key-recovering) and its interface (`ecdsa-sign`) is **not exported**; compositions requiring it fail at `wac plug` time. |

ChaCha20-Poly1305 (class A + B) is the *recommended* AEAD for in-guest use —
constant time by construction rather than by countermeasure, it is the
cipher designed for exactly this situation. AES-GCM's class C is a heroic
implementation working against the algorithm's nature.

### Sources

The classes are this provider's names for distinctions documented in the
constant-time-implementation literature; the letters, the four-way cut,
and the export-policy column are this repository's contract. The criteria
anchor as follows.

- The primary text is [Pornin, *Constant-Time Crypto*
  (BearSSL)](https://bearssl.org/constanttime.html), which covers all four
  rows: hashes, HMAC, and ChaCha20 as "naturally" constant-time (class A);
  Poly1305 and GHASH as constant-time "only as long as the underlying
  multiplication opcodes are constant-time" (class B's trust assumption —
  its [companion page](https://bearssl.org/ctmul.html) catalogues CPUs
  where they are not); AES as fast-but-leaky tables versus bitsliced
  constant-time variants at a several-fold cost, with benchmarks
  (class C); and the RSA/EC bignum hazards (class D).
- Class A's criterion — no secret-dependent branches or memory indices —
  is the "avoid branchings controlled by secret data" and "avoid table
  look-ups indexed by secret data" rules of the [Cryptography Coding
  Standard](https://github.com/veorq/cryptocoding).
- Class B's wasm-specific axis, the two-compiler problem: [Watt et al.,
  *CT-Wasm: Type-Driven Secure Cryptography for the Web Ecosystem* (POPL
  2019)](https://arxiv.org/abs/1808.01348) on wasm's missing
  constant-time guarantee and JIT lowering of secret-dependent `select`;
  [Simon, Chisnall, and Anderson, *What You Get is What You C* (EuroS&P
  2018)](https://www.cl.cam.ac.uk/~rja14/Papers/whatyouc.pdf) on
  compilers breaking source-level constant-time discipline.
- Class C's empirical basis — table-based AES leaks in practice:
  [Bernstein, *Cache-timing attacks on AES*
  (2005)](https://cr.yp.to/antiforgery/cachetiming-20050414.pdf); [Osvik,
  Shamir, and Tromer, *Cache Attacks and Countermeasures: the Case of
  AES* (CT-RSA 2006)](https://eprint.iacr.org/2005/271). The constant-time
  variant this provider ships is the fixsliced construction: [Adomnicai
  and Peyrin, *Fixslicing AES-like Ciphers* (TCHES
  2021)](https://eprint.iacr.org/2020/1123).
- Class D's blast radius — small leaks are key-recovering, with a
  remote-exploitation history: [Kocher (CRYPTO
  '96)](https://paulkocher.com/doc/TimingAttacks.pdf) opened the field on
  RSA/DH/DSS; [Brumley and Boneh, *Remote Timing Attacks are Practical*
  (USENIX Security
  2003)](https://crypto.stanford.edu/~dabo/papers/ssl-timing.pdf)
  extracted RSA keys over a network; [Brumley and Tuveri (ESORICS
  2011)](https://eprint.iacr.org/2011/232) did the same to ECDSA. For the
  nonce-bits-to-key-recovery lattice step specifically: Howgrave-Graham
  and Smart, *Lattice Attacks on Digital Signature Schemes* (Designs,
  Codes and Cryptography, 2001); [Minerva (TCHES
  2020)](https://minerva.crocs.fi.muni.cz/); [TPM-FAIL (USENIX Security
  2020)](https://tpm.fail/).
