# Conformance test vectors

The suite's authority rests on these files being what upstream published,
so the provenance below records the exact upstream revision each was taken
from. Checking a copy against its source is a matter of re-fetching that
revision and diffing; the digests are deliberately not mirrored into this
repository, since a checksum stored beside the file it checksums carries no
more authority than the file does.

Vendored from [C2SP/wycheproof](https://github.com/C2SP/wycheproof)
(`testvectors_v1`, schema v1; Apache-2.0 — see [LICENSE](LICENSE)), at
commit
[`b61843a9a5115bb758134b6a1f5d5e502d445342`](https://github.com/C2SP/wycheproof/tree/b61843a9a5115bb758134b6a1f5d5e502d445342/testvectors_v1)
(2026-07-21; the vendored files themselves last changed upstream in
`e0df04e0c033f2d25c5051dd06230336c7822358`, 2025-10-07):

- `hmac_sha256_test.json`, `hmac_sha384_test.json`, `hmac_sha512_test.json`
  — HMAC MAC vectors for every served SHA-2 parameterization.
- `pbkdf2_hmacsha256_test.json`, `pbkdf2_hmacsha384_test.json`,
  `pbkdf2_hmacsha512_test.json` — PBKDF2 derivation vectors for every
  served SHA-2 parameterization. Every vector runs and every one is
  `valid` upstream, including the empty-password cases — which is why
  `pbkdf2.import-password` accepts empty material where `hkdf.import-ikm`
  does not.
- `hkdf_sha256_test.json`, `hkdf_sha384_test.json`, `hkdf_sha512_test.json`
  — HKDF derivation vectors for every served SHA-2 parameterization. Every
  vector runs: the WIT surface carries the full (ikm, salt, info, size)
  parameter space, and the invalid vectors (`SizeTooLarge`) map onto the
  RFC 5869 output bound, reported as `error.other`.
- `aes_gcm_test.json` — AES-GCM AEAD vectors.
- `chacha20_poly1305_test.json`, `xchacha20_poly1305_test.json` —
  ChaCha20-Poly1305 and XChaCha20-Poly1305 AEAD vectors.
- `ed25519_test.json` — Ed25519 signature-verification vectors.
- `ecdsa_secp256r1_sha256_p1363_test.json`,
  `ecdsa_secp384r1_sha384_p1363_test.json` — ECDSA verification vectors
  with fixed-width `r ‖ s` (IEEE P1363) signatures, this package's wire
  format (the ASN.1-DER variants of these files are deliberately not
  vendored: DER signatures are unrepresentable in the WIT contract).
- `x25519_test.json` — X25519 key-agreement vectors, including the twist,
  non-canonical, and small-order public keys that discriminate agreement
  policies. The vectors carry each private key as a raw scalar, but the
  package's only secret-key import is the RFC 8037 OKP private JWK, whose
  public coordinate `x` is mandatory — so the derived companion
  `x25519_test_public_keys.json` maps each `tcId` to its private key's
  public coordinate. It is generated, not vendored: regenerate it with
  `derive_x25519_public_keys.py` (a plain RFC 7748 ladder, self-checked
  against the §6.1 key pairs) after refreshing the vector file.

Vendored from
[novifinancial/ed25519-speccheck](https://github.com/novifinancial/ed25519-speccheck)
(Apache-2.0), the test set from "Taming the many EdDSAs" (Chalkias,
Garillot, Nikolaenko), at commit
[`65519336fda78a3d016e947df6d82848aca0c9da`](https://github.com/novifinancial/ed25519-speccheck/blob/65519336fda78a3d016e947df6d82848aca0c9da/cases.json)
(the upstream file is `cases.json`; renamed here for clarity):

- `ed25519_speccheck.json` — adversarial Ed25519 vectors (small-order
  and non-canonical `A`/`R`, out-of-range `S`, mixed-order torsion
  components) that discriminate between the EdDSA verification policies
  real implementations ship. They pin the `ed25519-verify` WIT criterion
  (`verify_strict` semantics, cofactorless) across targets.

Vendored from the [NIST CAVP Secure Hashing byte-oriented test
vectors](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing)
(`shabytetestvectors.zip`; NIST publications are US-government works, not
subject to copyright):

- `SHA256ShortMsg.rsp`, `SHA384ShortMsg.rsp`, `SHA512ShortMsg.rsp` —
  SHA-2 digest vectors (message lengths 0 bits to two block lengths, in
  byte steps).

NIST distributes these in a zip rather than from a revision-controlled
source, so there is no commit to record; the files carry their own
generation stamps in their headers.

## Schedule policy

Vectors whose expected outcome is *acceptance* run under every chunking
schedule (`whole`, 1-byte `bytes`, block-straddling `straddle`):
assembled-input correctness is the claim chunking can affect.
Rejection-expectation vectors run `whole`, plus `straddle` for a
deterministic 1-in-20 sample (selected by vector id in
`guest/src/translate.rs`) — their verdict is computed after assembly, and
mis-assembly is already a detected failure of the accepted cases, so
chunking every rejection would add runs without adding that claim; the
sample instead pins the drain-on-error rule under chunked delivery on
every rejecting path family.

## Translation policy

Wycheproof describes the *algorithms*; the `lann:webcrypto` WIT is
deliberately stricter in places, so vector expectations are translated into
the package's contract before execution. This mapping is versioned
conformance policy; change it deliberately and in review. The authoritative
encoding is `conformance/guest/src/translate.rs`; in summary:

| Vector property | Our expectation |
| --- | --- |
| GCM, keySize 192 | **Skipped** — no implementation serves AES-192 (`import-key` declines it `unsupported`; probed). keySize 128 and 256 both run, in the caller-nonce *and* internal-nonce cases. |
| GCM, ivSize 0 | `seal`/`open` fail `invalid-nonce` (SP 800-38D requires a non-empty IV; the vectors' `ZeroLengthIv` groups are all marked invalid). |
| GCM, any other ivSize, `valid` | `seal` produces exactly `ct ‖ tag`; `open` recovers `msg`. The non-96-bit sizes — including every `CounterWrap` vector — exercise the §7.1 `J0` GHASH derivation. |
| GCM, any other ivSize, `invalid` | `open` fails `authentication-failed` (open direction only — an invalid vector has nothing to seal). |
| ChaCha20-Poly1305 (either variant), ivSize ≠ the variant's (96, or 192 for XChaCha) | `seal`/`open` fail `invalid-nonce` — the declared `chacha-variant` selects the accepted nonce length. Nothing is skipped: both files are all-keySize-256. |
| ChaCha20-Poly1305, variant ivSize, `valid` | `seal` produces exactly `ct ‖ tag`; `open` recovers `msg`. |
| ChaCha20-Poly1305, variant ivSize, `invalid` | `open` fails `authentication-failed` (open direction only). |
| Internal-nonce AEAD (same AEAD files, `aes-gcm-internal-nonce`/`*-internal-nonce` cases), keySize 256, variant ivSize, `valid` | `open(iv ‖ ct ‖ tag)` recovers `msg` — the only deterministic direction; a fresh `seal` is additionally round-tripped for self-consistency (its nonce is random, so only shape and reopening are checkable). |
| Internal-nonce AEAD, anything else (`invalid` result, or ivSize ≠ the algorithm's) | `open(iv ‖ ct ‖ tag)` fails `authentication-failed` — the nonce is carried in-band, so there is no invalid-nonce case: a wrong-length IV just misparses as a malformed sealed message. |
| HMAC, truncated tagSize | **Skipped** — the WIT's `sign`/`verify` operate on full-length tags; truncated-tag policy is an application concern. |
| HMAC, full-length tagSize, `valid` | `sign` equals `tag`; `verify(tag)` succeeds. |
| HMAC, full-length tagSize, `invalid` | `verify(tag)` fails with `authentication-failed`. |
| SHA-2 ShortMsg case | `compute` equals `MD`, and `bytes.constant-time-equal` agrees (a digest corpus has no invalid cases — wrong-digest behavior is the caller's comparison, probed separately). |
| Ed25519 / ECDSA-P1363, `valid` | `verify(sig)` succeeds. |
| ed25519-speccheck case 3 (mixed-order `A`/`R`, cofactorless-valid) | import and `verify(sig)` both succeed — the pinned criterion does not reject torsion components it cannot cheaply detect. |
| ed25519-speccheck, every other case | rejected at import (`invalid-key`) or verification (`authentication-failed`), per the `ed25519-verify` criterion; where the rejection lands is implementation-defined. |
| Ed25519 / ECDSA-P1363, `invalid` | `verify(sig)` fails `authentication-failed` — including malformed and wrong-length signatures; rejection deliberately carries no detail. Signing is covered by probes: Ed25519 round trips in the shared guest, ECDSA in the host-only signing guest (`conformance/signing-guest` — the shared guest cannot import `ecdsa-sign` because the in-guest provider it composes with does not export it). |
| X25519, any vector whose `shared` is non-zero (`valid`, and the `acceptable` twist/non-canonical cases — RFC 7748's masking accepts both) | `import-public-key` and `import-secret-key-jwk` (built with the derived `x` companion) succeed; `agree` succeeds; `derive-bits(none)` equals `shared`, and a truncated request equals its prefix. No chunking schedules: agreement carries no streams. |
| X25519, `ZeroSharedSecret` flag (small-order public keys) | import succeeds (deliberately permissive, like the platform's); `agree` fails `invalid-key` — the contributory all-zero check, pinned at the operation that computes the secret. |

Every executed vector runs under multiple *chunking schedules* (whole,
1-byte writes, and block-boundary-straddling writes): the streams-only WIT
makes delivery schedule observable to implementations, so chunking invariance
is part of the conformance claim.
