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
  `valid` upstream, including the empty-password cases (empty KDF secrets
  are accepted package-wide — see `wit/README.md`, "Empty KDF secrets are
  accepted").
- `hkdf_sha256_test.json`, `hkdf_sha384_test.json`, `hkdf_sha512_test.json`
  — HKDF derivation vectors for every served SHA-2 parameterization. Every
  vector runs: the WIT surface carries the full (ikm, salt, info, size)
  parameter space, and the invalid vectors (`SizeTooLarge`) map onto the
  RFC 5869 output bound, reported as `error.other`.
- `aes_gcm_test.json` — AES-GCM AEAD vectors.
- `aes_wrap_test.json` — AES-KW (RFC 3394) key-wrapping vectors for the
  `key-wrap` kind. Valid vectors pin the wrapped wire format in both
  directions; invalid and `acceptable` ones map onto the WIT's domains
  (see the translation policy below).
- `aes_cbc_pkcs5_test.json` — AES-CBC vectors for the unauthenticated
  `cipher` kind (PKCS5 and PKCS7 padding coincide for AES's 16-byte
  blocks). Valid vectors round-trip both ways; invalid ones (bad or
  absent padding) must fail `decrypt` with the kind's one uniform error.
  There is no upstream CTR file; AES-CTR is pinned by probes (NIST SP
  800-38A F.5 known answers plus the wrapping-counter contract).
- `ed25519_test.json` — Ed25519 signature-verification vectors.
- `ecdsa_secp256r1_sha256_p1363_test.json`,
  `ecdsa_secp384r1_sha384_p1363_test.json` — ECDSA verification vectors
  with fixed-width `r ‖ s` (IEEE P1363) signatures, this package's wire
  format (the ASN.1-DER variants of these files are deliberately not
  vendored: DER signatures are unrepresentable in the WIT contract).
- `rsa_signature_{2048,3072,4096}_{sha256,sha384,sha512}_test.json`,
  `rsa_signature_8192_sha256_test.json` — RSASSA-PKCS1-v1_5 verification
  vectors for every served digest, with heavy invalid coverage (padding
  and DigestInfo malleation). The 2048/SHA-256 file's e = 3 groups pin
  the guaranteed-import exponent floor; the 8192-bit file pins
  large-modulus admission inside the family's 1024–16384-bit window.
- `rsa_pkcs1_{2048,3072,4096}_sig_gen_test.json` — RSASSA-PKCS1-v1_5
  signature-*generation* vectors: EMSA-PKCS1-v1_5 is deterministic, so
  signing under the group's private key (`privateKeyPkcs8`, and its
  full-CRT `privateKeyJwk` on the JWK path) byte-compares against the
  published signatures. These run in the host-only signing suite
  (`conformance/signing-guest`), tagged `rsa-sign` — the gated signing
  interfaces are class D, so the shared guest cannot import them. There
  are no RSA-PSS generation files: PSS salts are random, so PSS signing
  is covered by round-trip probes instead. The 1024-bit sibling file is
  deliberately not vendored — its keys sit below the signing interfaces'
  2048-bit floor — but its SHA-256 group's `privateKeyPkcs8` is embedded
  in the signing guest's admission probe as the must-reject constant.
- `rsa_pss_2048_sha256_mgf1_0_test.json`,
  `rsa_pss_2048_sha256_mgf1_32_test.json`,
  `rsa_pss_2048_sha384_mgf1_48_test.json`,
  `rsa_pss_3072_sha256_mgf1_32_test.json`,
  `rsa_pss_4096_{sha256_mgf1_32,sha384_mgf1_48,sha512_mgf1_32,sha512_mgf1_64}_test.json`
  — RSA-PSS verification vectors, restricted to the WebCrypto-expressible
  parameterizations (the MGF1 digest equals the message digest, as the
  WIT fixes it); each group carries the salt length the WIT binds at
  mint. The `sha512_mgf1_32` file pins a salt length differing from the
  digest length (JOSE's `PS*` fix them equal; the WIT does not). Two
  files (`mgf1_0` and `4096_sha512_mgf1_32`) carry no `publicKeyJwk`, so
  their JWK-path cases use a minimal `{kty, n, e}` JWK built from the
  group's published modulus and exponent.
- `rsa_pss_2048_sha256_mgf1_32_params_test.json` — RSA-PSS keys carrying
  the id-RSASSA-PSS AlgorithmIdentifier (RFC 8017 Appendix A parameters),
  which the RSA family contract rejects at import: the file exists as
  coverage for that rule, and every case translates to an SPKI
  import-must-fail (see the translation policy below).
- `rsa_oaep_2048_{sha256_mgf1sha256,sha384_mgf1sha384,sha512_mgf1sha512}_test.json`,
  `rsa_oaep_3072_{sha256_mgf1sha256,sha512_mgf1sha512}_test.json`,
  `rsa_oaep_4096_{sha256_mgf1sha256,sha512_mgf1sha512}_test.json` —
  RSA-OAEP decryption vectors, restricted to the WebCrypto-expressible
  parameterizations (the MGF1 digest equals the message digest, as the
  WIT fixes it — these are the only such dedicated files upstream
  publishes; the SHA-384 pairings beyond 2048 bits come from the misc
  file below). Decrypting a published ciphertext is deterministic, so
  the vectors pin `decryption-key.decrypt` in the host-only signing
  suite (`conformance/signing-guest`), tagged `rsa-oaep-decrypt` — the
  decryption interface is gated and class D, so the shared guest cannot
  import it. Only the SHA-256 files carry a `privateKeyJwk`; the other
  groups' JWK-path cases use a full-CRT private JWK built from the
  group's published `privateKey` components. There are no encryption
  vectors: OAEP encryption is randomized, so the encrypt side is covered
  by round-trip and contract probes instead.
- `rsa_oaep_misc_test.json` — RSA-OAEP decryption vectors at
  miscellaneous parameterizations. Most of the file is untranslatable
  (MGF1 digests differing from the message digest, which WebCrypto
  cannot express, and sub-window 1024/1536-bit keys); the expressible
  groups add the SHA-384 pairings at 3072/4096/8192 bits, the 8192-bit
  OAEP window top, and non-power-of-two modulus lengths
  (2688/3104/4032). Its 1024-bit SHA-256 group also feeds the
  encrypt-side window probe as the below-window must-reject key.
- `x25519_test.json` — X25519 key-agreement vectors, including the twist,
  non-canonical, and small-order public keys that discriminate agreement
  policies. The vectors carry each private key as a raw scalar, but the
  package's only secret-key import is the RFC 8037 OKP private JWK, whose
  public coordinate `x` is mandatory — so the derived companion
  `x25519_test_public_keys.json` maps each `tcId` to its private key's
  public coordinate. It is generated, not vendored: regenerate it with
  `derive_x25519_public_keys.py` (a plain RFC 7748 ladder, self-checked
  against the §6.1 key pairs) after refreshing the vector file.
- `ecdh_secp256r1_test.json`, `ecdh_secp384r1_test.json` — ECDH
  key-agreement vectors with SPKI-encoded peer public keys (upstream's
  `asn` encoding) and raw private scalars, including the off-curve,
  invalid-curve-attack, wrong-curve, and modified-ASN-parameter public
  keys that discriminate admission policies.
- `ecdh_secp256r1_ecpoint_test.json`, `ecdh_secp384r1_ecpoint_test.json` —
  the same agreements with raw uncompressed SEC1 peer points (upstream's
  `ecpoint` encoding), this package's `import-public-key-raw` format.
- `ecdh_secp256r1_webcrypto_test.json`,
  `ecdh_secp384r1_webcrypto_test.json` — the same agreements with both
  keys as JWK objects (serialized to JSON text for the JWK imports; the
  extra `kid` member is harmless, since unrecognized JWK members are
  ignored).
- `ecdh_secp256r1_test_public_keys.json`,
  `ecdh_secp256r1_ecpoint_test_public_keys.json`,
  `ecdh_secp384r1_test_public_keys.json`,
  `ecdh_secp384r1_ecpoint_test_public_keys.json` — derived companions for
  the scalar-carrying ECDH files: the package's EC private JWK import
  makes the public coordinates `x`/`y` mandatory (RFC 7518), so each
  companion maps its file's `tcId`s to the private scalar's coordinates.
  Generated, not vendored: regenerate with `derive_ecdh_public_keys.py`
  (plain affine curve arithmetic, self-checked against every valid
  vector's published shared secret) after refreshing the vector files.
  The webcrypto files need no companion: their keys are already JWKs.

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
encoding is `conformance/guest/src/translate.rs` (and
`conformance/signing-guest/src/rsa_sign.rs` for the sig-gen files, plus
`conformance/signing-guest/src/rsa_oaep.rs` for the RSA-OAEP files, which
only the host-only signing suite can run); in summary:

| Vector property | Our expectation |
| --- | --- |
| GCM, keySize 192 | **Skipped** — no implementation serves AES-192 (`import-key` declines it `unsupported`; probed). keySize 128 and 256 both run. |
| GCM, ivSize outside 96–1024 bits (12–128 bytes) | `seal`/`open` fail `invalid-nonce` — the `aes-gcm` contract's uniform nonce window, so the vectors' expected ciphertexts (and the `ZeroLengthIv` groups' invalid verdicts) are deliberately unreachable; the tc identities stay. |
| GCM, in-window ivSize, `valid` | `seal` produces exactly `ct ‖ tag`; `open` recovers `msg`. The non-96-bit sizes — including every `CounterWrap` vector — exercise the §7.1 `J0` GHASH derivation. |
| GCM, in-window ivSize, `invalid` | `open` fails `authentication-failed` (open direction only — an invalid vector has nothing to seal). |
| HMAC, truncated tagSize | **Skipped** — the WIT's `sign`/`verify` operate on full-length tags; truncated-tag policy is an application concern. |
| AES-KW, keySize 192 | **Skipped** — as GCM's keySize-192 rule (declined at minting; probed). |
| AES-KW, `valid` | `kw-key.wrap` (over a `to-wrap-input-raw` of the key data) produces exactly `ct`; `unwrap` + `hmac-sha2.unwrap-key-raw` recovers `msg`. No chunking schedules: wrapping trades in `list<u8>`. |
| AES-KW, `acceptable` (8-byte key data, RFC 3394's n = 1) | Outside the WIT's domains: `wrap` fails `invalid-key`, and the 16-byte wrapped form fails `unwrap` with `authentication-failed` (under the 24-byte minimum). |
| AES-KW, `invalid` | A `msg` outside the wrap domain fails `wrap` with `invalid-key` (an in-domain `msg` on a modified-`ct` vector wraps successfully and must not reproduce the tampered bytes); a present `ct` fails `unwrap` with `authentication-failed` — bad ICVs and malformed lengths are deliberately indistinguishable. |
| HMAC, full-length tagSize, `valid` | `sign` equals `tag`; `verify(tag)` succeeds. |
| HMAC, full-length tagSize, `invalid` | `verify(tag)` fails with `authentication-failed`. |
| SHA-2 ShortMsg case | `compute` equals `MD` (a digest corpus has no invalid cases — wrong-digest behavior is the caller's comparison). |
| Ed25519 / ECDSA-P1363, `valid` | `verify(sig)` succeeds. |
| ed25519-speccheck case 3 (mixed-order `A`/`R`, cofactorless-valid) | import and `verify(sig)` both succeed — the pinned criterion does not reject torsion components it cannot cheaply detect. |
| ed25519-speccheck, every other case | rejected at import (`invalid-key`) or verification (`authentication-failed`), per the `ed25519-verify` criterion; where the rejection lands is implementation-defined. |
| Ed25519 / ECDSA-P1363, `invalid` | `verify(sig)` fails `authentication-failed` — including malformed and wrong-length signatures; rejection deliberately carries no detail. Signing is covered by probes: Ed25519 round trips in the shared guest, ECDSA in the host-only signing guest (`conformance/signing-guest` — the shared guest cannot import `ecdsa-sign` because the in-guest provider it composes with does not export it). |
| RSASSA-PKCS1-v1_5 / RSA-PSS, `valid` | import succeeds and `verify(sig)` succeeds. Each valid vector translates **twice** — once importing the group key via SPKI (`tc<id>-spki`), once via the RSA public JWK (`tc<id>-jwk`: the group's own JWK where the file carries one, else a minimal `{kty, n, e}` built from the group's modulus and exponent) — so both import paths carry vector coverage. |
| RSASSA-PKCS1-v1_5 / RSA-PSS, `invalid` | import succeeds (the same group key, via SPKI only — the rejection under test is the verifier's, not the import path's); `verify(sig)` fails `authentication-failed`. |
| RSASSA-PKCS1-v1_5, `acceptable` (the `MissingNull` BER-laxity vectors) | `verify(sig)` fails `authentication-failed`: the WIT pins strict verification — the EMSA-PKCS1-v1_5 encoding is compared byte-exact — so upstream's lax-verifier allowances are uniform rejections here. Any target accepting one is a portability finding, not a case to exclude. |
| `rsa_pss_2048_sha256_mgf1_32_params_test.json` (id-RSASSA-PSS keys), every case | the SPKI import fails `invalid-key` — the RSA family contract admits only `rsaEncryption` SubjectPublicKeyInfos. Coverage is SPKI-only: the file carries no JWKs, and a plain RSA public JWK has no member that could carry the PSS AlgorithmIdentifier, so no JWK-side counterpart exists. No chunking schedules: import carries no streams. |
| RSASSA-PKCS1-v1_5 sig-gen, SHA-1 or SHA-224 group | **Skipped** — the `rsa-variant` set has no SHA-1 or SHA-224 case (SHA-1's collision resistance is broken, and no platform WebCrypto serves SHA-224), so the keys cannot mint. |
| RSASSA-PKCS1-v1_5 sig-gen, SHA-256/384/512 group, `valid` or `acceptable` | signing `msg` under the group's private key produces exactly `sig` (deterministic EMSA-PKCS1-v1_5). Each vector translates **twice** — once importing the key via PKCS#8 (`tc<id>-pkcs8`, message delivered whole), once via the group's own full-CRT private JWK (`tc<id>-jwk`, one-byte writes) — so both signing-import paths and two chunking schedules carry vector coverage. `acceptable` translates identically to `valid`: every such vector is flagged `SmallPublicKey` (e = 3), inside the family's guaranteed-import exponent floor, and generation is deterministic regardless of the exponent. Tagged `rsa-sign` (the gated feature), so targets declaring it missing skip these and prove the decline through the signing suite's probes. |
| RSA-OAEP, group with MGF1 digest ≠ message digest, a digest outside SHA-256/384/512, or a modulus outside 2048–8192 bits | **Skipped** — WebCrypto fixes the MGF1 digest to the message digest and the `rsa-variant` set has no SHA-1 or SHA-224 case, so the parameterization cannot mint; out-of-window keys fail the OAEP admission window (probed, with the misc file's 1024-bit group as the must-reject key). |
| RSA-OAEP, expressible group, `valid` | importing the group's private key and `decrypt(label, ct)` recovers exactly `msg` (upstream's empty label is the WIT's no-label call). Each vector translates **twice** — once importing via PKCS#8 (`tc<id>-pkcs8`), once via the group's full-CRT private JWK (`tc<id>-jwk`: the group's own JWK where the file carries one, else one built from the group's published `privateKey` components) — so both decryption-import paths carry vector coverage. Tagged `rsa-oaep-decrypt` (the gated feature), so targets declaring it missing skip these and prove the decline through the signing suite's probes. No chunking schedules: the `public-encryption` kind trades in whole byte lists. |
| RSA-OAEP, expressible group, `invalid` | `decrypt(label, ct)` fails `authentication-failed` — wrong lengths, damaged padding, and mismatched labels are deliberately indistinguishable (the RFC 8017 anti-padding-oracle rule the WIT pins; rejection carries no detail). |
| RSA-OAEP, `acceptable` (the `SmallIntegerCiphertext` vectors: a ciphertext that is a numerically small integer) | **Excluded** — acceptance is legitimately policy-divergent across implementations: platform WebCrypto decrypts them, while aws-lc-rs rejects them as RNG-failure/attack artifacts, and RFC 8017 tolerates either, so no single expectation holds across targets (the ECDH `acceptable` exclusions' reasoning). |
| X25519, any vector whose `shared` is non-zero (`valid`, and the `acceptable` twist/non-canonical cases — RFC 7748's masking accepts both) | `import-public-key` and `import-secret-key-jwk` (built with the derived `x` companion) succeed; `agree` succeeds; `derive-bits(none)` equals `shared`, and a truncated request equals its prefix. No chunking schedules: agreement carries no streams. |
| X25519, `ZeroSharedSecret` flag (small-order public keys) | import succeeds (deliberately permissive, like the platform's); `agree` fails `invalid-key` — the contributory all-zero check, pinned at the operation that computes the secret. |
| ECDH (any file), `valid` | the public import (per the file's encoding: raw / SPKI / JWK) and `import-secret-key-jwk` (the webcrypto files' own private JWK, or one built from the normalized scalar plus the derived `x`/`y` companion) succeed; `agree` succeeds; `derive-bits(none)` equals `shared`, and a truncated request equals its prefix. Scalars are normalized to the curve's field size (the files' big-endian hex may carry a leading zero byte or be short). No chunking schedules: agreement carries no streams. |
| ECDH, `invalid` | the public import fails `invalid-key`. Every invalid case in these files is a public-key admission failure — off-curve points and invalid-curve attacks, wrong curves, malformed encodings — and the WIT pins strict public admission at import, so they all land there (unlike X25519, where degenerate peers surface at `agree`). |
| ECDH ecpoint, `acceptable` (a compressed encoding of a valid point) | the raw import fails `invalid-key`: upstream marks compressed admission policy-divergent, but the WIT pins the raw format to uncompressed-only. |
| ECDH asn, flagged `UnnamedCurve` (either verdict) | the SPKI import fails `invalid-key`: the WIT pins named-OID-only curve admission, so explicit-parameter encodings reject on every implementation — including those whose parameters describe the declared curve, where upstream's invalid/acceptable split encodes its own notion of parameter validation rather than a boundary engines share. |
| ECDH asn, `acceptable` without `UnnamedCurve` (the `InvalidAsn` BER-laxity family and the compressed-point encoding) | **Excluded** — encodings whose acceptance is legitimately policy-divergent across implementations. The WIT deliberately leaves compressed-SPKI admission implementation-defined, and ASN.1/BER strictness beyond the documented shape differs across the platform engines the jco host delegates to, so no single expectation holds across targets (the same reasoning that keeps the DER-signature ECDSA files unvendored). The invalid-curve attacks, off-curve points, and wrong-curve rejections stay pinned through the named-curve SPKI cases and the ecpoint/webcrypto files. |

Every executed vector runs under multiple *chunking schedules* (whole,
1-byte writes, and block-boundary-straddling writes): the streams-only WIT
makes delivery schedule observable to implementations, so chunking invariance
is part of the conformance claim.
