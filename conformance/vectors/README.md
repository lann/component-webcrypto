# Conformance test vectors

Vendored from [C2SP/wycheproof](https://github.com/C2SP/wycheproof)
(`testvectors_v1`, schema v1; Apache-2.0 — see [LICENSE](LICENSE)):

- `hmac_sha256_test.json` — HMAC-SHA-256 MAC vectors.
- `aes_gcm_test.json` — AES-GCM AEAD vectors.
- `chacha20_poly1305_test.json`, `xchacha20_poly1305_test.json` —
  ChaCha20-Poly1305 and XChaCha20-Poly1305 AEAD vectors.
- `ed25519_test.json` — Ed25519 signature-verification vectors.
- `ecdsa_secp256r1_sha256_p1363_test.json`,
  `ecdsa_secp384r1_sha384_p1363_test.json` — ECDSA verification vectors
  with fixed-width `r ‖ s` (IEEE P1363) signatures, this package's wire
  format (the ASN.1-DER variants of these files are deliberately not
  vendored: DER signatures are unrepresentable in the WIT contract).

Vendored from
[novifinancial/ed25519-speccheck](https://github.com/novifinancial/ed25519-speccheck)
(Apache-2.0), the test set from "Taming the many EdDSAs" (Chalkias,
Garillot, Nikolaenko):

- `ed25519_speccheck.json` — 12 adversarial Ed25519 vectors (small-order
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

## Translation policy

Wycheproof describes the *algorithms*; the `lann:webcrypto` WIT is
deliberately stricter in places, so vector expectations are translated into
the package's contract before execution. This mapping is versioned
conformance policy; change it deliberately and in review. The authoritative
encoding is `conformance/guest/src/translate.rs`; in summary:

| Vector property | Our expectation |
| --- | --- |
| GCM, keySize ≠ 256 | **Skipped** — `aes-gcm.import-key` rejects the key before any vector semantics apply; import rejection is covered by dedicated probes. |
| GCM, keySize 256, ivSize ≠ 96 | `seal`/`open` fail `invalid-nonce` regardless of the vector's own result (the WIT mandates 12-byte nonces; Wycheproof merely *discourages* other sizes). |
| GCM, keySize 256, ivSize 96, `valid` | `seal` produces exactly `ct ‖ tag`; `open` recovers `msg`. |
| GCM, keySize 256, ivSize 96, `invalid` | `open` fails `authentication-failed` (open direction only — an invalid vector has nothing to seal). |
| ChaCha20-Poly1305 (either variant), ivSize ≠ the variant's (96, or 192 for XChaCha) | `seal`/`open` fail `invalid-nonce` — the declared `chacha-variant` selects the accepted nonce length. Nothing is skipped: both files are all-keySize-256. |
| ChaCha20-Poly1305, variant ivSize, `valid` | `seal` produces exactly `ct ‖ tag`; `open` recovers `msg`. |
| ChaCha20-Poly1305, variant ivSize, `invalid` | `open` fails `authentication-failed` (open direction only). |
| Internal-nonce AEAD (same AEAD files, `aes-gcm-internal-nonce`/`*-internal-nonce` suites), keySize 256, variant ivSize, `valid` | `open(iv ‖ ct ‖ tag)` recovers `msg` — the only deterministic direction; a fresh `seal` is additionally round-tripped for self-consistency (its nonce is random, so only shape and reopening are checkable). |
| Internal-nonce AEAD, anything else (`invalid` result, or ivSize ≠ the algorithm's) | `open(iv ‖ ct ‖ tag)` fails `authentication-failed` — the nonce is carried in-band, so there is no invalid-nonce case: a wrong-length IV just misparses as a malformed sealed message. |
| HMAC, tagSize ≠ 256 | **Skipped** — the WIT's `sign`/`verify` operate on full-length tags; truncated-tag policy is an application concern. |
| HMAC, tagSize 256, `valid` | `sign` equals `tag`; `verify(tag)` succeeds. |
| HMAC, tagSize 256, `invalid` | `verify(tag)` fails with `authentication-failed`. |
| SHA-2 ShortMsg case | `compute` equals `MD`, and `bytes.constant-time-equal` agrees (a digest corpus has no invalid cases — wrong-digest behavior is the caller's comparison, probed separately). |
| Ed25519 / ECDSA-P1363, `valid` | `verify(sig)` succeeds. |
| ed25519-speccheck case 3 (mixed-order `A`/`R`, cofactorless-valid) | import and `verify(sig)` both succeed — the pinned criterion does not reject torsion components it cannot cheaply detect. |
| ed25519-speccheck, every other case | rejected at import (`invalid-key`) or verification (`authentication-failed`), per the `ed25519-verify` criterion; where the rejection lands is implementation-defined. |
| Ed25519 / ECDSA-P1363, `invalid` | `verify(sig)` fails `authentication-failed` — including malformed and wrong-length signatures; rejection deliberately carries no detail. Signing is covered by probes: Ed25519 round trips in the shared guest, ECDSA in the host-only signing guest (`conformance/signing-guest` — the shared guest cannot import `ecdsa-sign` because the in-guest provider it composes with does not export it). |

Every executed vector runs under multiple *chunking schedules* (whole,
1-byte writes, and block-boundary-straddling writes): the streams-only WIT
makes delivery schedule observable to implementations, so chunking invariance
is part of the conformance claim.
