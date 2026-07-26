# Conformance test vectors

Vendored from [C2SP/wycheproof](https://github.com/C2SP/wycheproof)
(`testvectors_v1`, schema v1; Apache-2.0 — see [LICENSE](LICENSE)):

- `hmac_sha256_test.json` — HMAC-SHA-256 MAC vectors.
- `aes_gcm_test.json` — AES-GCM AEAD vectors.

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
| HMAC, tagSize ≠ 256 | **Skipped** — the WIT's `sign`/`verify` operate on full-length tags; truncated-tag policy is an application concern. |
| HMAC, tagSize 256, `valid` | `sign` equals `tag`; `verify(tag)` succeeds. |
| HMAC, tagSize 256, `invalid` | `verify(tag)` fails with `authentication-failed`. |
| SHA-2 ShortMsg case | `compute` equals `MD`, and `bytes.constant-time-equal` agrees (a digest corpus has no invalid cases — wrong-digest behavior is the caller's comparison, probed separately). |

Every executed vector runs under multiple *chunking schedules* (whole,
1-byte writes, and block-boundary-straddling writes): the streams-only WIT
makes delivery schedule observable to implementations, so chunking invariance
is part of the conformance claim.
