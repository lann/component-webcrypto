//! The RSA-OAEP coverage: the Wycheproof decryption vectors (OAEP
//! decryption is deterministic — a published ciphertext either recovers
//! its message or fails — so the vectors pin `decryption-key.decrypt`
//! byte-for-byte) and the hand-written probes for the
//! `rsa-oaep-encrypt`/`rsa-oaep-decrypt` contract, including the decline
//! assertion a target declaring `rsa-oaep-decrypt` missing must satisfy.
//!
//! This module lives in the host-only signing guest because the in-guest
//! provider exports neither OAEP minting interface (decryption is class
//! D, and in-guest encryption runs secret plaintext through
//! non-constant-time bignum arithmetic — see rust/guest-provider/README.md), so
//! the shared guest could not compose with the provider if it imported
//! them. Encryption (`rsa-oaep-encrypt`) is ungated baseline surface for
//! the host-backed targets this suite runs under, so the encrypt-side
//! probe carries no feature tag; the decryption cases are tagged
//! `rsa-oaep-decrypt` (the gated feature).
//!
//! Translation policy (`conformance/vectors/README.md` is the summary;
//! this file is the authoritative encoding): only groups whose MGF1
//! digest equals the message digest translate (WebCrypto fixes them
//! equal), for the served digests SHA-256/384/512 and moduli inside the
//! OAEP window (2048–8192 bits) — which excludes most of
//! `rsa_oaep_misc_test.json` (mismatched-MGF and sub-window groups).
//! Upstream's `acceptable` results (all flagged `SmallIntegerCiphertext`:
//! a ciphertext that is a numerically small integer) are **excluded** —
//! acceptance is legitimately policy-divergent across implementations
//! (platform WebCrypto decrypts them; aws-lc-rs rejects them as
//! RNG-failure/attack artifacts), and RFC 8017 tolerates either, so no
//! single expectation holds across targets. Each vector runs twice —
//! once importing the group key via PKCS#8, once via its full-CRT
//! private JWK (the group's own `privateKeyJwk` where the file carries
//! one, else one built from the group's published CRT components) — so
//! both decryption-import paths carry vector coverage. No chunking
//! schedules: the `public-encryption` kind trades in whole byte lists.

use conformance_harness::stream::{open_ok, seal_ok, Schedule};
use conformance_harness::{
    b64url, describe, expect, expect_bytes, expect_err, ErrKind, FEATURE_RSA_OAEP_DECRYPT,
};
use lann_webcrypto_guest::bindings::public_encryption::DecryptionKeyOptions;
use lann_webcrypto_guest::bindings::rsa_oaep_decrypt::RsaModulus;
use lann_webcrypto_guest::bindings::rsa_oaep_encrypt::RsaVariant;
use lann_webcrypto_guest::bindings::types::Error;
use lann_webcrypto_guest::bindings::{rsa_oaep_decrypt, rsa_oaep_encrypt};
use serde::Deserialize;

/// The dedicated RSA-OAEP vector files (one modulus length + digest pair
/// each; every group's MGF1 digest equals its message digest).
const RSA_OAEP_VECTORS: [&str; 7] = [
    include_str!("../../vectors/rsa_oaep_2048_sha256_mgf1sha256_test.json"),
    include_str!("../../vectors/rsa_oaep_2048_sha384_mgf1sha384_test.json"),
    include_str!("../../vectors/rsa_oaep_2048_sha512_mgf1sha512_test.json"),
    include_str!("../../vectors/rsa_oaep_3072_sha256_mgf1sha256_test.json"),
    include_str!("../../vectors/rsa_oaep_3072_sha512_mgf1sha512_test.json"),
    include_str!("../../vectors/rsa_oaep_4096_sha256_mgf1sha256_test.json"),
    include_str!("../../vectors/rsa_oaep_4096_sha512_mgf1sha512_test.json"),
];

/// The miscellaneous-parameterization file: its WebCrypto-expressible
/// groups add the SHA-384 pairings at 3072/4096/8192 bits (no dedicated
/// upstream files exist for those), the 8192-bit window top, and
/// non-power-of-two modulus lengths with numerically small encoded
/// messages; the rest of the file (mismatched MGF digests, sub-window
/// keys) is untranslatable and skipped.
const RSA_OAEP_MISC_VECTORS: &str = include_str!("../../vectors/rsa_oaep_misc_test.json");

#[derive(Deserialize)]
struct VectorFile {
    #[serde(rename = "testGroups")]
    test_groups: Vec<OaepGroup>,
}

#[derive(Deserialize)]
struct OaepGroup {
    #[serde(rename = "keySize")]
    key_size: u32,
    sha: String,
    #[serde(rename = "mgfSha")]
    mgf_sha: String,
    #[serde(rename = "privateKeyPkcs8")]
    private_key_pkcs8: String,
    /// Upstream's own full-CRT private JWK; only the SHA-256 groups carry
    /// one. Groups without it get a JWK built from `private_key`.
    #[serde(rename = "privateKeyJwk")]
    private_key_jwk: Option<serde_json::Value>,
    /// The key's published components (big-endian hex), the JWK source
    /// for the groups upstream ships no `privateKeyJwk` for.
    #[serde(rename = "privateKey")]
    private_key: OaepPrivateKey,
    tests: Vec<OaepTest>,
}

/// A group key's RFC 8017 components, as upstream publishes them.
#[derive(Deserialize)]
struct OaepPrivateKey {
    modulus: String,
    #[serde(rename = "publicExponent")]
    public_exponent: String,
    #[serde(rename = "privateExponent")]
    private_exponent: String,
    prime1: String,
    prime2: String,
    exponent1: String,
    exponent2: String,
    coefficient: String,
}

impl OaepPrivateKey {
    /// The full-CRT RSA private JWK of these components (RFC 7518 §6.3:
    /// members are minimal big-endian base64url, so leading zero octets
    /// of the hex encodings are stripped).
    fn to_private_jwk(&self) -> String {
        let member = |hex: &str| b64url(strip_leading_zeros(&unhex("privateKey member", hex)));
        format!(
            r#"{{"kty":"RSA","n":"{}","e":"{}","d":"{}","p":"{}","q":"{}","dp":"{}","dq":"{}","qi":"{}"}}"#,
            member(&self.modulus),
            member(&self.public_exponent),
            member(&self.private_exponent),
            member(&self.prime1),
            member(&self.prime2),
            member(&self.exponent1),
            member(&self.exponent2),
            member(&self.coefficient),
        )
    }

    /// The public members alone, as an RSA public JWK.
    fn to_public_jwk(&self) -> String {
        format!(
            r#"{{"kty":"RSA","n":"{}","e":"{}"}}"#,
            b64url(strip_leading_zeros(&unhex(
                "privateKey modulus",
                &self.modulus
            ))),
            b64url(strip_leading_zeros(&unhex(
                "privateKey publicExponent",
                &self.public_exponent
            ))),
        )
    }
}

#[derive(Deserialize)]
struct OaepTest {
    #[serde(rename = "tcId")]
    tc_id: u64,
    msg: String,
    ct: String,
    label: String,
    result: String,
    #[serde(default)]
    flags: Vec<String>,
}

/// Decode a hex vector member, naming the vector on failure.
fn unhex(field: &str, hex: &str) -> Vec<u8> {
    data_encoding::HEXLOWER
        .decode(hex.as_bytes())
        .unwrap_or_else(|err| panic!("vector {field} has invalid hex: {err}"))
}

/// The minimal big-endian form of an unsigned integer's bytes (JWK
/// base64urlUInt members carry no leading zero octets).
fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[start..]
}

/// The OAEP window, in bits (the `rsa-oaep-encrypt` admission contract;
/// groups outside it cannot mint).
const OAEP_WINDOW_BITS: std::ops::RangeInclusive<u32> = 2048..=8192;

/// The mint-bound digest a translated group's `sha` member declares, or
/// `None` for digests outside the `rsa-variant` set (the misc file's
/// SHA-1 and SHA-224 groups).
fn translated_sha(field: &str, sha: &str) -> Option<(RsaVariant, &'static str)> {
    match sha {
        "SHA-256" => Some((RsaVariant::Sha256, "sha256")),
        "SHA-384" => Some((RsaVariant::Sha384, "sha384")),
        "SHA-512" => Some((RsaVariant::Sha512, "sha512")),
        "SHA-1" | "SHA-224" => None,
        other => panic!("vector group {field} has unknown sha {other:?}"),
    }
}

/// A group key's private material in one of the two decryption-import
/// encodings.
pub enum DecryptImport {
    /// `import-decryption-key-pkcs8` (the group's `privateKeyPkcs8`).
    Pkcs8(Vec<u8>),
    /// `import-decryption-key-jwk` (the group's full-CRT private JWK;
    /// JSON text).
    Jwk(String),
}

impl DecryptImport {
    /// The import segment of the case id.
    fn name(&self) -> &'static str {
        match self {
            DecryptImport::Pkcs8(_) => "pkcs8",
            DecryptImport::Jwk(_) => "jwk",
        }
    }
}

/// The translated expectation of one decryption vector.
enum Expected {
    /// `decrypt` recovers exactly the vector's `msg`.
    Decrypts(Vec<u8>),
    /// `decrypt` fails with the one detail-free
    /// `error.authentication-failed` — wrong lengths, damaged padding,
    /// and mismatched labels are deliberately indistinguishable (the RFC
    /// 8017 anti-padding-oracle rule the WIT pins).
    AuthenticationFailed,
}

/// One executed RSA-OAEP decryption vector: importing the group's private
/// key per `import` and decrypting `ct` under the vector's label.
pub struct RsaOaepCase {
    variant: RsaVariant,
    /// The digest segment of the case id (`sha256`, …).
    sha_name: &'static str,
    key_bits: u32,
    /// The source segment of the case id (`wycheproof`, or
    /// `wycheproof-misc` for the miscellaneous-parameterization file).
    source: &'static str,
    tc_id: u64,
    import: DecryptImport,
    /// `None` for upstream's empty label (the WIT's no-label call).
    label: Option<Vec<u8>>,
    ct: Vec<u8>,
    expected: Expected,
}

impl RsaOaepCase {
    /// The case's stable id
    /// (`rsa-oaep-<sha>-<bits>/<source>/tc<id>-<import>`; no schedule
    /// segment — nothing here streams).
    pub fn case_id(&self) -> String {
        format!(
            "rsa-oaep-{}-{}/{}/tc{}-{}",
            self.sha_name,
            self.key_bits,
            self.source,
            self.tc_id,
            self.import.name(),
        )
    }

    /// The features this case exercises beyond the baseline surface.
    pub fn features(&self) -> &'static [&'static str] {
        &[FEATURE_RSA_OAEP_DECRYPT]
    }
}

/// Translate one file's groups into cases (see the module doc for the
/// policy).
fn translate_file(text: &str, source: &'static str, cases: &mut Vec<RsaOaepCase>) {
    let file: VectorFile =
        serde_json::from_str(text).unwrap_or_else(|err| panic!("parsing rsa-oaep vectors: {err}"));
    for group in &file.test_groups {
        let field = format!("rsa-oaep {}-bit {} group", group.key_size, group.sha);
        // WebCrypto fixes the MGF1 digest to the message digest; a group
        // pairing them differently is unmintable.
        if group.mgf_sha != group.sha {
            continue;
        }
        let Some((variant, sha_name)) = translated_sha(&field, &group.sha) else {
            continue;
        };
        if !OAEP_WINDOW_BITS.contains(&group.key_size) {
            continue;
        }
        let pkcs8 = unhex(&field, &group.private_key_pkcs8);
        let jwk = group
            .private_key_jwk
            .as_ref()
            .map(|jwk| jwk.to_string())
            .unwrap_or_else(|| group.private_key.to_private_jwk());
        for test in &group.tests {
            let field = format!("{field} tc{}", test.tc_id);
            let expected = match test.result.as_str() {
                "valid" => Expected::Decrypts(unhex(&field, &test.msg)),
                // `acceptable` here always flags `SmallIntegerCiphertext`
                // (a ciphertext that is a numerically small integer):
                // acceptance is legitimately policy-divergent across
                // implementations, so the vector is excluded (see the
                // module doc).
                "acceptable" => {
                    assert!(
                        test.flags.iter().any(|f| f == "SmallIntegerCiphertext"),
                        "vector {field} is acceptable without SmallIntegerCiphertext"
                    );
                    continue;
                }
                "invalid" => Expected::AuthenticationFailed,
                other => panic!("vector {field} has unknown result {other:?}"),
            };
            let label = match test.label.as_str() {
                "" => None,
                hex => Some(unhex(&field, hex)),
            };
            let ct = unhex(&field, &test.ct);
            for import in [
                DecryptImport::Pkcs8(pkcs8.clone()),
                DecryptImport::Jwk(jwk.clone()),
            ] {
                cases.push(RsaOaepCase {
                    variant,
                    sha_name,
                    key_bits: group.key_size,
                    source,
                    tc_id: test.tc_id,
                    import,
                    label: label.clone(),
                    ct: ct.clone(),
                    expected: match &expected {
                        Expected::Decrypts(msg) => Expected::Decrypts(msg.clone()),
                        Expected::AuthenticationFailed => Expected::AuthenticationFailed,
                    },
                });
            }
        }
    }
}

/// The normalized decryption cases: every dedicated file, then the misc
/// file's expressible groups. Each vector runs twice, once per
/// decryption-import path.
pub fn cases() -> Vec<RsaOaepCase> {
    let mut cases = Vec::new();
    for text in RSA_OAEP_VECTORS {
        translate_file(text, "wycheproof", &mut cases);
    }
    translate_file(RSA_OAEP_MISC_VECTORS, "wycheproof-misc", &mut cases);
    cases
}

/// A decryption-key options resource with `decrypt` granted, carrying
/// only the `extractable` choice.
fn decrypt_options(extractable: bool) -> DecryptionKeyOptions {
    let options = DecryptionKeyOptions::new();
    options.can_decrypt(true);
    options.extractable(extractable);
    options
}

/// Run one decryption vector: import, decrypt, compare.
pub async fn run_case(case: &RsaOaepCase) -> Result<(), String> {
    let key = match &case.import {
        DecryptImport::Pkcs8(pkcs8) => rsa_oaep_decrypt::import_decryption_key_pkcs8(
            case.variant,
            pkcs8.clone(),
            decrypt_options(false),
        )
        .await
        .map_err(|e| describe("import-decryption-key-pkcs8", &e))?,
        DecryptImport::Jwk(jwk) => rsa_oaep_decrypt::import_decryption_key_jwk(
            case.variant,
            jwk.clone(),
            decrypt_options(false),
        )
        .await
        .map_err(|e| describe("import-decryption-key-jwk", &e))?,
    };
    let got = key.decrypt(case.label.clone(), case.ct.clone()).await;
    match &case.expected {
        Expected::Decrypts(msg) => {
            let got = got.map_err(|e| describe("decrypt", &e))?;
            expect_bytes(&got, msg, "decrypted message")
        }
        Expected::AuthenticationFailed => expect_err(
            "decrypt",
            ErrKind::AuthenticationFailed,
            got,
            "an invalid ciphertext decrypted",
        ),
    }
}

// --- probe material -------------------------------------------------------------

/// The vendored 2048-bit SHA-256 group's key, as (PKCS#8, full-CRT
/// private JWK, public-members-only JWK): known-good import material for
/// the probes, pulled from the compiled-in vectors rather than duplicated
/// as constants.
fn sample_key() -> (Vec<u8>, String, String) {
    let file: VectorFile = serde_json::from_str(RSA_OAEP_VECTORS[0])
        .unwrap_or_else(|err| panic!("parsing rsa-oaep vectors: {err}"));
    let group = &file.test_groups[0];
    assert_eq!(group.key_size, 2048, "the first file is the 2048-bit one");
    (
        unhex("2048-bit SHA-256 group", &group.private_key_pkcs8),
        group
            .private_key_jwk
            .as_ref()
            .expect("the SHA-256 groups carry a privateKeyJwk")
            .to_string(),
        group.private_key.to_public_jwk(),
    )
}

/// The 1024-bit modulus below the OAEP window, as an RSA public JWK:
/// built from the vendored misc file's 1024-bit SHA-256 group (a real
/// upstream key — inside the family's verification window, so the
/// rejection under test is the OAEP window alone).
fn public_jwk_1024() -> String {
    let file: VectorFile = serde_json::from_str(RSA_OAEP_MISC_VECTORS)
        .unwrap_or_else(|err| panic!("parsing rsa-oaep misc vectors: {err}"));
    file.test_groups
        .iter()
        .find(|group| group.key_size == 1024 && group.sha == "SHA-256")
        .expect("the misc file carries a 1024-bit SHA-256 group")
        .private_key
        .to_public_jwk()
}

/// A synthetic 9216-bit RSA public JWK — above the OAEP window, inside
/// the family's 16384-bit ceiling — for the window rejection alone: every
/// implementation checks the modulus length without factoring, so top bit
/// set and odd is all admission looks at (the value has no factorization
/// anyone knows).
fn public_jwk_9216() -> String {
    let mut n = vec![0xa5u8; 9216 / 8];
    n[0] = 0x80;
    *n.last_mut().expect("nonempty") |= 1;
    format!(r#"{{"kty":"RSA","n":"{}","e":"AQAB"}}"#, b64url(&n),)
}

/// The sample group's public key as an X.509 SubjectPublicKeyInfo,
/// derived from the group's `privateKeyPkcs8` with
/// `openssl pkey -pubout` (the vector files carry no public encodings).
const OAEP_2048_SPKI: &str = "30820122300d06092a864886f70d01010105000382010f003082010a02820101\
     00a2b451a07d0aa5f96e455671513550514a8a5b462ebef717094fa1fee82224\
     e637f9746d3f7cafd31878d80325b6ef5a1700f65903b469429e89d6eac88450\
     97b5ab393189db92512ed8a7711a1253facd20f79c15e8247f3d3e42e46e48c9\
     8e254a2fe9765313a03eff8f17e1a029397a1fa26a8dce26f490ed81299615d9\
     814c22da610428e09c7d9658594266f5c021d0fceca08d945a12be82de4d1ece\
     6b4c03145b5d3495d4ed5411eb878daf05fd7afc3e09ada0f1126422f590975a\
     1969816f48698bcbba1b4d9cae79d460d8f9f85e7975005d9bc22c4e5ac0f7c1\
     a45d12569a62807d3b9a02e5a530e773066f453d1f5b4c2e9cf7820283f742b9\
     d50203010001";

/// Assert an operation failed with the `("lann:webcrypto",
/// "message-too-long")` extension condition (the exact pair the WIT
/// names for a plaintext above the key's bound).
fn expect_too_long<T>(what: &str, result: Result<T, Error>) -> Result<(), String> {
    match result {
        Err(Error::Extension(ext))
            if ext.origin == "lann:webcrypto" && ext.name == "message-too-long" =>
        {
            Ok(())
        }
        Err(other) => Err(describe(
            &format!("{what}: expected extension(lann:webcrypto, message-too-long), got"),
            &other,
        )),
        Ok(_) => Err(format!("{what}: an over-bound payload was accepted")),
    }
}

// --- probes ---------------------------------------------------------------------

/// The encrypt side of the OAEP contract, observable without any private
/// key (untagged: `rsa-oaep-encrypt` is ungated baseline surface for the
/// host-backed targets this suite runs under). Both public imports mint
/// keys whose getters report the parameterization; the public exports
/// round-trip (`spki` byte-exact, `jwk` carrying the material members,
/// `raw` declining `unsupported` — the RSA family has no raw public
/// form); encryption is randomized, fills exactly the modulus, accepts a
/// label, and rejects an over-bound payload with the named extension
/// condition on both `encrypt` and `wrap`; and the OAEP window rejects
/// 1024- and 9216-bit moduli on the public half.
pub async fn rsa_oaep_encrypt_contract() -> Result<(), String> {
    let (_, _, public_jwk) = sample_key();
    let spki = conformance_harness::unhex(OAEP_2048_SPKI);

    let key = rsa_oaep_encrypt::import_encryption_key_spki(RsaVariant::Sha256, spki.clone())
        .await
        .map_err(|e| describe("import-encryption-key-spki", &e))?;
    expect(
        key.algorithm_name(),
        "RSA-OAEP".to_string(),
        "encryption-key algorithm-name",
    )?;
    expect(
        key.algorithm_hash(),
        Some("SHA-256".to_string()),
        "encryption-key algorithm-hash",
    )?;
    expect(
        key.algorithm_length(),
        Some(2048),
        "encryption-key algorithm-length",
    )?;
    expect(
        key.algorithm_public_exponent(),
        Some(vec![1, 0, 1]),
        "encryption-key algorithm-public-exponent",
    )?;

    // The public exports: SPKI round-trips byte-exact (rsaEncryption
    // SubjectPublicKeyInfo DER is canonical), the JWK carries the
    // material members, and raw declines.
    let exported = key
        .export_key_spki()
        .await
        .map_err(|e| describe("export-key-spki", &e))?;
    expect_bytes(&exported, &spki, "exported SPKI")?;
    let jwk = key
        .export_key_jwk()
        .await
        .map_err(|e| describe("export-key-jwk", &e))?;
    for member in ["\"kty\"", "\"n\"", "\"e\""] {
        if !jwk.contains(member) {
            return Err(format!("exported public JWK lacks {member}: {jwk}"));
        }
    }
    expect_err(
        "export-key-raw",
        ErrKind::Unsupported,
        key.export_key_raw().await,
        "an RSA public key exported a raw form",
    )?;

    // The JWK import path mints the same parameterization.
    let from_jwk = rsa_oaep_encrypt::import_encryption_key_jwk(RsaVariant::Sha256, public_jwk)
        .await
        .map_err(|e| describe("import-encryption-key-jwk", &e))?;
    expect(
        from_jwk.algorithm_length(),
        Some(2048),
        "jwk-imported encryption-key algorithm-length",
    )?;
    expect(
        from_jwk.algorithm_public_exponent(),
        Some(vec![1, 0, 1]),
        "jwk-imported encryption-key algorithm-public-exponent",
    )?;

    // The plaintext bound: modulus bytes (256) minus twice the digest
    // length (2 × 32) minus 2 = 190. At the bound the ciphertext fills
    // the modulus and encryption is randomized; one byte over fails the
    // named extension condition.
    let at_bound = vec![0x42u8; 190];
    let ct1 = key
        .encrypt(None, at_bound.clone())
        .await
        .map_err(|e| describe("encrypt (at the bound)", &e))?;
    expect(ct1.len(), 256, "ciphertext length")?;
    let ct2 = key
        .encrypt(None, at_bound.clone())
        .await
        .map_err(|e| describe("encrypt (again)", &e))?;
    if ct1 == ct2 {
        return Err("two encryptions of one plaintext produced identical ciphertexts".into());
    }
    expect_too_long(
        "encrypt (one over the bound)",
        key.encrypt(None, vec![0x42u8; 191]).await,
    )?;

    // A label is accepted (its binding is the round-trip probe's
    // business — verifying it needs a decryption key).
    let labeled = key
        .encrypt(Some(b"probe label".to_vec()), b"labeled payload".to_vec())
        .await
        .map_err(|e| describe("encrypt (with a label)", &e))?;
    expect(labeled.len(), 256, "labeled ciphertext length")?;

    // `wrap` rides the same bound: an in-bound serialization fills the
    // modulus, an over-bound one fails the same extension condition.
    expect(
        key.wrap(None, wrap_input_of(vec![0x51u8; 32]).await?)
            .await
            .map_err(|e| describe("wrap (in bound)", &e))?
            .len(),
        256,
        "wrapped-key ciphertext length",
    )?;
    expect_too_long(
        "wrap (over the bound)",
        key.wrap(None, wrap_input_of(vec![0x51u8; 191]).await?)
            .await,
    )?;

    // The OAEP window on the public half: a real 1024-bit key (below)
    // and a synthetic 9216-bit modulus (above; admission reads only the
    // length) both fail `invalid-key`.
    expect_err(
        "import-encryption-key-jwk (1024-bit)",
        ErrKind::InvalidKey,
        rsa_oaep_encrypt::import_encryption_key_jwk(RsaVariant::Sha256, public_jwk_1024()).await,
        "imported a modulus below the OAEP window",
    )?;
    expect_err(
        "import-encryption-key-jwk (9216-bit)",
        ErrKind::InvalidKey,
        rsa_oaep_encrypt::import_encryption_key_jwk(RsaVariant::Sha256, public_jwk_9216()).await,
        "imported a modulus above the OAEP window",
    )
}

/// The full transport round trip at every variant: a generated pair
/// encrypts → decrypts under both no-label and labeled calls, the label
/// binds (a wrong or absent label fails), a corrupted ciphertext fails,
/// and both failures are the *same* detail-free
/// `error.authentication-failed` (the anti-padding-oracle rule); a
/// wrapped AES-256-GCM key travels `wrap` → `unwrap` → typed mint and
/// opens what the original sealed; and the `decrypt`/`unwrap` grants are
/// enforced separately.
pub async fn rsa_oaep_round_trip() -> Result<(), String> {
    let payload = b"rsa-oaep round-trip payload";
    let label = b"rsa-oaep probe label".to_vec();
    for variant in [RsaVariant::Sha256, RsaVariant::Sha384, RsaVariant::Sha512] {
        let options = DecryptionKeyOptions::new();
        options.can_decrypt(true);
        options.can_unwrap(true);
        let (private, public) = rsa_oaep_decrypt::generate_key(variant, RsaModulus::M2048, options)
            .await
            .map_err(|e| describe("generate-key", &e))?;
        expect(
            private.algorithm_name(),
            "RSA-OAEP".to_string(),
            "generated decryption-key algorithm-name",
        )?;
        expect(
            private.algorithm_hash(),
            public.algorithm_hash(),
            "the pair's algorithm-hash getters",
        )?;
        expect(
            private.algorithm_length(),
            Some(2048),
            "generated decryption-key algorithm-length",
        )?;
        expect(
            private.algorithm_public_exponent(),
            Some(vec![1, 0, 1]),
            "generated decryption-key algorithm-public-exponent",
        )?;
        expect(
            private.algorithm_public_exponent(),
            public.algorithm_public_exponent(),
            "the pair's algorithm-public-exponent getters",
        )?;
        expect(private.can_decrypt(), true, "can-decrypt getter")?;
        expect(private.can_unwrap(), true, "can-unwrap getter")?;
        expect(private.extractable(), false, "extractable getter")?;

        // No-label and labeled round trips.
        let ct = public
            .encrypt(None, payload.to_vec())
            .await
            .map_err(|e| describe("encrypt", &e))?;
        let pt = private
            .decrypt(None, ct.clone())
            .await
            .map_err(|e| describe("decrypt", &e))?;
        expect_bytes(&pt, payload, "no-label round trip")?;
        let labeled_ct = public
            .encrypt(Some(label.clone()), payload.to_vec())
            .await
            .map_err(|e| describe("encrypt (labeled)", &e))?;
        let pt = private
            .decrypt(Some(label.clone()), labeled_ct.clone())
            .await
            .map_err(|e| describe("decrypt (labeled)", &e))?;
        expect_bytes(&pt, payload, "labeled round trip")?;

        // The label binds, corruption fails, and the two failures are
        // indistinguishable: both the exact detail-free
        // `authentication-failed` case.
        expect_err(
            "decrypt (label dropped)",
            ErrKind::AuthenticationFailed,
            private.decrypt(None, labeled_ct.clone()).await,
            "a labeled ciphertext decrypted without its label",
        )?;
        expect_err(
            "decrypt (wrong label)",
            ErrKind::AuthenticationFailed,
            private
                .decrypt(Some(b"a different label".to_vec()), labeled_ct.clone())
                .await,
            "a labeled ciphertext decrypted under a different label",
        )?;
        let mut corrupted = ct.clone();
        corrupted[0] ^= 0x01;
        expect_err(
            "decrypt (corrupted ciphertext)",
            ErrKind::AuthenticationFailed,
            private.decrypt(None, corrupted).await,
            "a corrupted ciphertext decrypted",
        )?;
    }

    // Key transport: an AES-256-GCM key seals a message, travels
    // `wrap` → `unwrap` → `aes-gcm.unwrap-key-raw`, and the minted key
    // opens the sealed message.
    use lann_webcrypto_guest::bindings::aead::AeadKeyOptions;
    use lann_webcrypto_guest::bindings::aes_gcm;

    let options = DecryptionKeyOptions::new();
    options.can_unwrap(true);
    let (private, public) =
        rsa_oaep_decrypt::generate_key(RsaVariant::Sha256, RsaModulus::M2048, options)
            .await
            .map_err(|e| describe("generate-key (transport)", &e))?;
    let content_options = AeadKeyOptions::new();
    content_options.can_seal(true);
    content_options.extractable(true);
    let content_key = aes_gcm::generate_key(aes_gcm::AesVariant::Aes256, content_options)
        .await
        .map_err(|e| describe("content-key generate-key", &e))?;
    let nonce = vec![0x51u8; 12];
    let aad = b"rsa-oaep transport probe".to_vec();
    let sealed = seal_ok(
        &content_key,
        &nonce,
        &aad,
        None,
        payload,
        Schedule::Whole,
        "content-key seal",
    )
    .await?;
    let wrapped = public
        .wrap(
            Some(label.clone()),
            content_key
                .to_wrap_input_raw()
                .await
                .map_err(|e| describe("to-wrap-input-raw", &e))?,
        )
        .await
        .map_err(|e| describe("encryption-key.wrap", &e))?;
    let unwrapped = private
        .unwrap(Some(label.clone()), wrapped)
        .await
        .map_err(|e| describe("decryption-key.unwrap", &e))?;
    let minted_options = AeadKeyOptions::new();
    minted_options.can_open(true);
    let minted = aes_gcm::unwrap_key_raw(aes_gcm::AesVariant::Aes256, unwrapped, minted_options)
        .await
        .map_err(|e| describe("aes-gcm.unwrap-key-raw", &e))?;
    let opened = open_ok(
        &minted,
        &nonce,
        &aad,
        None,
        &sealed,
        Schedule::Whole,
        "transported key's open",
    )
    .await?;
    expect_bytes(&opened, payload, "transported key's open")?;

    // The grants split disclosure from minting: the transport key above
    // was minted without `can-decrypt`, so the same ciphertext that
    // unwraps refuses to disclose.
    let ct = public
        .encrypt(None, payload.to_vec())
        .await
        .map_err(|e| describe("encrypt (grants)", &e))?;
    expect_err(
        "decrypt without the grant",
        ErrKind::NotPermitted,
        private.decrypt(None, ct.clone()).await,
        "an unwrap-only key disclosed plaintext",
    )?;
    let options = DecryptionKeyOptions::new();
    options.can_decrypt(true);
    let (decrypt_only, _) =
        rsa_oaep_decrypt::generate_key(RsaVariant::Sha256, RsaModulus::M2048, options)
            .await
            .map_err(|e| describe("generate-key (decrypt-only)", &e))?;
    expect_err(
        "unwrap without the grant",
        ErrKind::NotPermitted,
        decrypt_only.unwrap(None, ct).await,
        "a decrypt-only key minted from wrapped material",
    )?;
    expect_err(
        "generate-key without grants",
        ErrKind::NotPermitted,
        rsa_oaep_decrypt::generate_key(
            RsaVariant::Sha256,
            RsaModulus::M2048,
            DecryptionKeyOptions::new(),
        )
        .await,
        "minted a decryption key with no usage granted",
    )
}

/// The decryption-import admission edges: a valid 1024-bit PKCS#8 —
/// inside the family's verification window but below the OAEP window —
/// fails `invalid-key`, as do a partial-CRT private JWK (the platforms
/// require the full two-prime CRT form) and a public-only (`d`-less)
/// JWK.
pub async fn rsa_oaep_admission() -> Result<(), String> {
    let pkcs8_1024 = conformance_harness::unhex(crate::rsa_sign::RSA_1024_SIG_GEN_PKCS8);
    let (_, sample_jwk, _) = sample_key();
    let parsed: serde_json::Value =
        serde_json::from_str(&sample_jwk).expect("vector JWKs are valid JSON");
    let strip = |members: &[&str]| {
        let mut jwk = parsed.clone();
        let object = jwk.as_object_mut().expect("vector JWKs are objects");
        for member in members {
            object.remove(*member);
        }
        jwk.to_string()
    };
    expect_err(
        "1024-bit pkcs8",
        ErrKind::InvalidKey,
        rsa_oaep_decrypt::import_decryption_key_pkcs8(
            RsaVariant::Sha256,
            pkcs8_1024,
            decrypt_options(false),
        )
        .await,
        "imported a modulus below the OAEP window",
    )?;
    expect_err(
        "partial-CRT JWK",
        ErrKind::InvalidKey,
        rsa_oaep_decrypt::import_decryption_key_jwk(
            RsaVariant::Sha256,
            strip(&["qi"]),
            decrypt_options(false),
        )
        .await,
        "imported a private JWK missing a CRT member",
    )?;
    expect_err(
        "d-less JWK",
        ErrKind::InvalidKey,
        rsa_oaep_decrypt::import_decryption_key_jwk(
            RsaVariant::Sha256,
            strip(&["d", "p", "q", "dp", "dq", "qi"]),
            decrypt_options(false),
        )
        .await,
        "imported a public JWK as a decryption key",
    )
}

/// The two-way feature guarantee, serving side: a target that does not
/// declare `rsa-oaep-decrypt` missing serves its minting paths (here the
/// cheap imports; generation and the unwrap mints are covered by the
/// round-trip probe). The declining side is [`minting_declined`], which
/// `run_declined` runs for every tagged probe on a target declaring the
/// feature missing.
pub async fn rsa_oaep_declined() -> Result<(), String> {
    let (pkcs8, jwk, _) = sample_key();
    rsa_oaep_decrypt::import_decryption_key_pkcs8(
        RsaVariant::Sha256,
        pkcs8,
        decrypt_options(false),
    )
    .await
    .map_err(|e| describe("import-decryption-key-pkcs8", &e))?;
    rsa_oaep_decrypt::import_decryption_key_jwk(RsaVariant::Sha256, jwk, decrypt_options(false))
        .await
        .map_err(|e| describe("import-decryption-key-jwk", &e))?;
    Ok(())
}

/// Mint a wrap-input carrying `payload` (see `rsa_sign::unwrap_input_of`
/// for the HMAC-carrier mechanics; this one stops before the wrap, since
/// the OAEP `wrap` operation is itself the subject).
async fn wrap_input_of(
    payload: Vec<u8>,
) -> Result<lann_webcrypto_guest::bindings::wrapping::WrapInput, String> {
    use lann_webcrypto_guest::bindings::hmac_sha2;
    use lann_webcrypto_guest::bindings::mac::MacKeyOptions;
    use lann_webcrypto_guest::bindings::sha2::Sha2Variant;

    let carrier_options = MacKeyOptions::new();
    carrier_options.can_sign(true);
    carrier_options.extractable(true);
    let carrier = hmac_sha2::import_key_raw(Sha2Variant::Sha256, payload, carrier_options)
        .await
        .map_err(|e| describe("carrier import", &e))?;
    carrier
        .to_wrap_input_raw()
        .await
        .map_err(|e| describe("to-wrap-input-raw", &e))
}

/// Assert that every RSA-OAEP decryption minting path declines
/// `unsupported` on a target declaring `rsa-oaep-decrypt` missing:
/// generation, both imports, and both unwrap mints — five paths. The
/// unwrap payloads are known-good material, so the only condition in
/// play is service (a declining target must not answer `invalid-key`
/// from format validation instead).
pub async fn minting_declined() -> Result<String, String> {
    let (pkcs8, jwk, _) = sample_key();
    let accepted = "minted a key: the target serves a feature it declares missing";
    expect_err(
        "generate-key",
        ErrKind::Unsupported,
        rsa_oaep_decrypt::generate_key(
            RsaVariant::Sha256,
            RsaModulus::M2048,
            decrypt_options(false),
        )
        .await,
        accepted,
    )?;
    expect_err(
        "import-decryption-key-pkcs8",
        ErrKind::Unsupported,
        rsa_oaep_decrypt::import_decryption_key_pkcs8(
            RsaVariant::Sha256,
            pkcs8.clone(),
            decrypt_options(false),
        )
        .await,
        accepted,
    )?;
    expect_err(
        "import-decryption-key-jwk",
        ErrKind::Unsupported,
        rsa_oaep_decrypt::import_decryption_key_jwk(
            RsaVariant::Sha256,
            jwk.clone(),
            decrypt_options(false),
        )
        .await,
        accepted,
    )?;
    expect_err(
        "unwrap-decryption-key-pkcs8",
        ErrKind::Unsupported,
        rsa_oaep_decrypt::unwrap_decryption_key_pkcs8(
            RsaVariant::Sha256,
            crate::rsa_sign::unwrap_input_of(pkcs8).await?,
            decrypt_options(false),
        )
        .await,
        accepted,
    )?;
    expect_err(
        "unwrap-decryption-key-jwk",
        ErrKind::Unsupported,
        rsa_oaep_decrypt::unwrap_decryption_key_jwk(
            RsaVariant::Sha256,
            crate::rsa_sign::unwrap_input_of(jwk.into_bytes()).await?,
            decrypt_options(false),
        )
        .await,
        accepted,
    )?;
    Ok("every RSA-OAEP decryption minting path declined unsupported".into())
}
