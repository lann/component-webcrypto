# The `lann:webcrypto` package

This document holds the package-wide contracts and the terminology that the
WIT doc comments reference. A doc comment states what is specific to its
item; everything shared lives here.

## How the package is organized

- The `types` interface holds the shared structural types (the `error`
  variant). Structural types carry no host-side identity, so one composition
  can share them across components.
- **Primitive-kind interfaces** (`mac`, `aead`, `aead-internal-nonce`,
  `digest`, `signature`, `derivation`, `key-agreement`) own the
  algorithm-agnostic resources.
  Operations hang off key resources. Adding an algorithm does not change
  these interfaces.
- **Algorithm interfaces** (`hmac-sha2`, `aes-gcm`, `chacha20-poly1305`,
  `sha2`, `hkdf`, `ed25519-*`, `ecdsa-*`, `x25519`) only mint keys, bound
  to their algorithm at creation. A key can therefore never be used with
  the wrong algorithm.

A component whose world imports only a primitive-kind interface can *use*
any key handle it is granted, but cannot mint or import keys. Key handles
are [capabilities](#terminology).

Operations are one-shot calls on immutable key resources. There are no
stateful computation objects, so misuse of in-progress state (concurrent
update, use after finalization) cannot be expressed, and the `error`
variant carries no misuse cases.

## Streaming contract

Every stream-taking operation in the package follows these rules.

**Drain rule.** An input stream is fully drained before the operation's
result resolves, even when the result is an error. A caller that feeds the
stream concurrently never observes its writer failing instead of the error.

**Truncating producers (security-critical).** Dropping the writer is a
stream's only end-of-input signal, and it carries no verdict. A producer
that fails midway is indistinguishable from one that finished: the
operation correctly computes over the delivered prefix. When the write path
can fail independently of the party that consumes the result (for example,
a writable end forwarded to another component), convey completeness in-band
(for example, length framing), or discard the result on producer failure.

**Making progress.** An implementation holds each in-flight operation's
bytes, so it bounds how many operations it services at once (by leaving a
call waiting to start). A caller with several operations in flight must
make progress on all of them concurrently:

- feed each operation's input stream without waiting on any other
  operation, and
- drain each returned stream as it becomes available.

A caller that withholds one in-flight operation's input or output while it
awaits another can deadlock against that bound, and no implementation can
rescue it: the bytes the implementation waits to reclaim are the bytes the
caller holds. The natural shape is safe: await an operation and drain its
stream in the same task, and run those tasks concurrently. Deferring every
read until the last call has returned is the shape that is not safe.

**Returned streams.** Read a returned stream to completion, or drop it; an
implementation may hold resources until one of the two happens. Dropping is
always sufficient to release the implementation.

## Key-options contract

Every `*-options` resource follows this contract:

- The constructor grants nothing. Every usage, and extractability, is
  opt-in, so a mint names exactly what the key is for.
- At least one usage must be enabled at mint. An untouched options resource
  cannot mint; the mint fails with `error.not-permitted`.
- The options are single-use: the mint takes ownership, so mutation after a
  mint is unrepresentable.
- An options resource cannot cross providers (resource types are
  per-instance). Construct it from the same import the mint comes from.

The usage vocabulary covers the algorithm family's WebCrypto usages even
where this package has no operation yet: usages are write-once enforcement
bits on platform-backed keys, so a grant absent at mint is unrecoverable
for a non-extractable key. Deny-by-default also covers evolution: future
usages arrive ungranted for every existing caller.

## Extractability

`extractable` is an API property, not a physical one. The implementation
necessarily holds the key material; the guarantee is that a component
holding only the key handle cannot obtain the material through this API.

Every key resource with an extractability gate also exposes it as a getter,
so a holder can ask the question without receiving the material. The getter
matters because a key resource need not have been minted by the component
that holds it.

A platform-resident key can be usable but unreadable. Export operations are
therefore fallible even where no extractability gate applies (see
`signature.verifying-key.export-key-raw`).

## Getter conventions

- `algorithm-*` getters project the
  [W3C Web Cryptography API](https://www.w3.org/TR/WebCryptoAPI/) registry's
  algorithm properties, spelled and denominated (bits) as the registry
  defines them.
- `*-size` getters report operation-contract quantities in bytes.
- `can-*` getters report the usage recorded at mint (or carried by a
  platform keystore key). An operation the key refuses fails with
  `error.not-permitted`.

## Format naming convention

Key-material functions are suffixed with the encoding they carry —
`-raw`, `-jwk`, and future formats alike — whenever a key's format family
has more than one admissible member. No format is privileged by an
unsuffixed name: this mirrors the Web Cryptography API, where the format
is spelled at every call site, and stays coherent for algorithm families
that have no raw form at all. Single-format-by-platform secrets
(`hkdf.import-ikm`, `pbkdf2.import-password` — WebCrypto accepts only raw
material for both) stay unsuffixed: theirs is not a format choice.

## JWK contract

Every `*-jwk` function follows this contract. The minting interfaces'
`import-key-jwk` docs name their algorithm-specific `alg` values.

- A JWK travels as JSON text. The implementation owns the parse. Duplicate
  members resolve last-wins (ECMA-404 engines' `JSON.parse` semantics,
  pinned so implementations cannot diverge on adversarial input). `k` is
  strict unpadded base64url (RFC 7515): padding, non-alphabet bytes, and
  non-zero trailing bits all fail with `error.invalid-key`.
- Import validates the material-bearing fields: `kty`, the key members
  (`k`, or `crv`/`x`/`y`/`d` for the OKP and EC forms), `alg` where the
  importing interface names accepted values (X25519 ignores `alg`
  entirely, WebCrypto's rule for the ECDH family), and `ext` against the
  requested extractability; failures are `error.invalid-key`. `use` and
  `key_ops` are ignored: this package has no JWK usage model, so they are
  the consumer's policy to check.
- A *public-key* import has no extractability request — minted public
  keys are unconditionally exportable — so a public JWK carrying
  `"ext": false` is rejected with `error.invalid-key`.
- Export returns exactly the material-bearing members — `kty`, `k`, and
  `alg` for the `oct` form; `kty`, `crv`, `x` (and `y`, and `d` on
  private exports) for the OKP and EC forms, which carry no `alg` — and
  nothing else. Metadata this package does not model (`key_ops`, `ext`,
  `use`) is the consumer's to stamp. Member order is not contract.
- `oct` algorithms without a registered JWK `alg` fail with
  `error.unsupported`.

## Error contract

No error case reports API misuse: the package aims to make misuse
inexpressible instead (see "Design notes"). The cases that need more than
their doc comment:

**`authentication-failed` is one-sided.** Failed verification MUST report
this case and nothing else; security telemetry may rely on it never being
misfiled. In the other direction, an implementation whose backend collapses
verification failure with other failures (WebCrypto's `decrypt` throws one
`OperationError` for both) MAY report this case for failures it cannot
distinguish from it. Rare operational false positives are therefore
possible on `open`; `verify` is exact on every current implementation,
because boolean-returning backends preserve the distinction. Either way the
case means *unauthenticated input*: at the cryptographic layer, a forgery
and accidental corruption are indistinguishable in principle.

**`other(string)`** carries operational conditions (a keystore that cannot
complete the operation now, an implementation's buffering limit). It never
carries semantic conditions a caller must branch on — and callers must
never branch on its string. A condition that turns out to need branching
or asserting does not stay in `other`: it migrates to a named `extension`
pair, which is a behavioral change for the producing implementation but
never a type change.

**`extension(extension-error)` carries named conditions outside the closed
set.** The closed cases are the conditions the *generic kinds'* contracts
name — universal across operation families; `extension` carries algorithm-
and feature-specific conditions, identified by the (`origin`, `name`) pair
and defined by the interface that produces them (the first is
`sha1-checked`'s `("lann:webcrypto", "collision-detected")`). The record's
fields have two fixed roles:

- the (`origin`, `name`) **pair** is the condition's only branchable
  identity;
- **`message`** is human-readable prose for logs and diagnostics — never
  contract, never branched on.

Conditions are *nominal*: the pair identifies, the message elaborates for
humans, and no field carries machine-readable data. Errors in this package
are verdicts — a condition that would need machine-readable parameters
indicates data that belongs on the resource surface (getters, results),
and admitting one would be a deliberate, semver-major redesign of the
error contract.

A consumer MUST handle a pair it does not recognize exactly as it handles
`other`: an operational failure. This rule is what makes migration from
`other` safe — a consumer that predates the named pair observes no change
in kind — and it means the closed set never has to grow again. `origin` is
an opaque namespace owned by the defining party (by convention its package
name; this package defines all of its conditions under
`"lann:webcrypto"`). Third-party providers mint conditions under their own
`origin`. SDKs expose constants for known pairs, and the conformance
suites pin exact pairs cross-implementation.

**Verification returns `result<_, error>`, not `bool`.** An ignored boolean
fails open; a dropped `result` does not.

## Timing-channel policy

Some algorithms leak key material through execution timing when the
implementation shares a timing domain with an observer. In particular,
ECDSA signing handles a per-signature secret nonce whose timing leakage is
key-recovering. Providers that execute inside an attacker-observable timing
domain should not export such interfaces; a composition that requires one
then fails at composition (`wac plug`) time rather than at run time. This
repository's in-guest provider documents its classification and policy in
`guest-impl/README.md`.

## Design notes

Decisions that shape the surface, recorded so the doc comments can stay
short:

- **Misuse should be unrepresentable — a design goal, not a guarantee.**
  Where possible, the interfaces make mistakes impossible to express
  rather than reporting them: operations are one-shot calls on immutable
  key resources (no in-progress state to misuse), keys bind their
  algorithm at mint, options are consumed by the mint, and the `error`
  variant carries no misuse cases. The goal informs every surface change;
  it is not a claim that no misuse of the package is possible (nonce
  reuse under the caller-nonce `aead` kind is the standing example).
  Where an operation combines *two* key capabilities, misuse is checked
  rather than unrepresentable: `key-agreement.secret-key.agree` fails
  `error.invalid-key` on an algorithm-mismatched peer, the W3C Web
  Cryptography API's own derive-time check.

- **No derive from a secret key to its public half.** A provider may hold
  a private key whose public half it cannot recompute (browser WebCrypto
  has no derive operation, and keystore-resident non-extractable keys sign
  but yield nothing else). `generate-key` returns the pair; importers use
  the public-key import. This holds for `signature` (no `signing-key` →
  `verifying-key`) and for `key-agreement` (no `secret-key` →
  `public-key`) alike; an agreement secret imported as an OKP JWK carries
  its public coordinate in the JWK itself, where RFC 8037 makes it
  mandatory.
- **Format admission: every key format is one a platform-backed host
  passes to the platform verbatim.** An import format the platform cannot
  ingest directly would force such a host to parse or transform key
  material itself — exactly the code a thin host should not carry — so
  formats without a platform door (bare X25519 secret scalars, for
  example) are not formats here. The admitted set per algorithm lives on
  its minting interface.
- **ECDSA binds curve and hash at mint** (unlike WebCrypto's per-operation
  hash). A granted key cannot be used with a weaker digest than its minter
  chose.
- **Private keys import and export only through platform formats.**
  Signing and agreement secret keys import as PKCS#8 or a private JWK and
  export (extractability-gated, fallibly) the same way — never as bare
  seeds or scalars, per the format-admission rule above. No import derives
  the public half (see the no-derive rule above); importers supply it
  separately through the public-key import.
- **Empty PBKDF2 passwords are accepted; empty HKDF IKM is not.** RFC 8018
  admits an empty `P`, the platform serves it, and the upstream test
  vectors exercise it as valid, so rejecting it would break platform
  fidelity without a safety win. A zero-entropy HKDF IKM, by contrast, is
  never what a caller meant.
- **Per-algorithm interfaces instead of variant enums** where platform
  support splits along the algorithm boundary (IETF ChaCha20-Poly1305
  versus XChaCha20-Poly1305): a composition that needs the missing one
  fails at composition time rather than at minting.
- **Unauthenticated modes are in, for compatibility.** AES-CBC and
  AES-CTR are WebCrypto-committed formats real systems must read and
  write, so the package carries them — quarantined in the `cipher` kind,
  which exists so their contract (confidentiality only, uniform `decrypt`
  failure) is stated once and cannot bleed into `aead`: the authenticated
  kind is unchanged, remains the default, and nothing ever falls back
  from one kind to the other. The uniform-failure rule is load-bearing —
  a CBC decryption error names no cause, because a distinguishable
  padding verdict is a padding-oracle amplifier. AES-KW is not part of
  this ruling: it belongs to the wrap direction (`wrap-key`/`unwrap-key`
  operations), not to a cipher kind.
- **FIPS 140-3 stays possible, not implemented.** The internal-nonce kind
  carries the approved-mode seal; interfaces deliberately permit
  policy-based rejection (short HMAC keys, imported internal-nonce
  material) so a FIPS profile is just a provider that exports only approved
  interfaces.

## Terminology

Brief definitions; follow the links for depth.

- **mint** — create a key resource (import, generate, or derive). The word
  marks the only points at which keys come into existence.
- **capability** — an unforgeable handle whose possession is the
  authority to use it.
  [Capability-based security](https://en.wikipedia.org/wiki/Capability-based_security).
- **unrepresentable (by construction)** — the API's shape makes the mistake
  impossible to express, rather than checking for it at run time.
- **extractable** — whether a key's material may be exported through this
  API. See [Extractability](#extractability).
- **MAC** — message authentication code; a keyed tag over data.
  [Wikipedia](https://en.wikipedia.org/wiki/Message_authentication_code).
- **AEAD** — authenticated encryption with associated data.
  [Wikipedia](https://en.wikipedia.org/wiki/Authenticated_encryption).
- **nonce** — a number used once; AEAD's per-message input. Reuse with the
  same key is catastrophic for GCM- and ChaCha-family algorithms.
  [Wikipedia](https://en.wikipedia.org/wiki/Cryptographic_nonce).
- **nonce budget** — the number of `seal` invocations an internal-nonce key
  can serve before the implementation can no longer guarantee that a fresh
  nonce is unique for that key (for random nonces, a bound on the
  collision probability, e.g. [SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final)
  §8.2.2's 2^32 bound for AES-GCM). Reaching it fails `error.key-exhausted`.
- **AAD** — associated data: authenticated but not encrypted AEAD input.
- **tag** — the authentication value a MAC or AEAD produces.
- **digest** — the output of a cryptographic hash function.
  [Wikipedia](https://en.wikipedia.org/wiki/Cryptographic_hash_function).
- **KDF** — key derivation function.
  [Wikipedia](https://en.wikipedia.org/wiki/Key_derivation_function).
- **key agreement** — a protocol in which two parties each combine their
  own secret key with the other's public key and arrive at the same shared
  secret (Diffie–Hellman).
  [Wikipedia](https://en.wikipedia.org/wiki/Key-agreement_protocol).
- **contributory check** — the rejection of an agreement whose shared
  secret one party forced regardless of the other's key. For X25519 the
  degenerate case is the all-zero shared secret, produced exactly by
  small-order peer points ([RFC 7748 §7](https://www.rfc-editor.org/rfc/rfc7748#section-7)).
- **IKM** — input keying material: the secret a KDF starts from
  ([RFC 5869](https://www.rfc-editor.org/rfc/rfc5869)).
- **JWK** — JSON Web Key ([RFC 7517](https://www.rfc-editor.org/rfc/rfc7517)).
- **constant time** — execution time independent of secret values, closing
  the timing side channel.
  [Timing attack](https://en.wikipedia.org/wiki/Timing_attack).
- **usage** — a per-key grant recorded at mint that permits an operation
  (WebCrypto's
  [`KeyUsage`](https://www.w3.org/TR/WebCryptoAPI/#dfn-KeyUsage)).
