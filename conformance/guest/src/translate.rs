//! Translation of the vendored test vectors into the `lann:webcrypto`
//! contract.
//!
//! This module is the authoritative encoding of the translation policy;
//! `conformance/vectors/README.md`, "Translation policy" carries the
//! current summary table, and the two must agree. Change the policy
//! deliberately and in review.
//!
//! Every executed vector is emitted once per chunking schedule; a vector whose
//! stream inputs are all empty runs only `whole` (the other schedules are
//! degenerate duplicates).

use conformance_harness::stream::Schedule;
use data_encoding::HEXLOWER_PERMISSIVE;
use serde::Deserialize;

/// The deterministic 1-in-N sample of rejection vectors that also run
/// `straddle` (selected by id, so the sample is stable and lands in the
/// lockfile).
const REJECTION_STRADDLE_SAMPLE: u64 = 20;

/// The schedule set for a vector whose longest stream input is
/// `max_input_len` bytes, whose expected outcome is acceptance (`valid`)
/// or rejection, and whose stable id within its file is `id`.
///
/// Rejection-expectation vectors run `whole`, plus `straddle` for a
/// deterministic 1-in-20 sample. Assembly-under-chunking correctness is
/// pinned by the valid cases (a mis-assembled valid input produces wrong
/// bytes — a distinct, detected failure), so chunking *every* rejection
/// would add hundreds of runs without adding that claim — but the
/// drain-on-error rule is its own contract, and the sample pins it under
/// chunked delivery on every rejecting path family rather than only
/// where a probe thought to ask (mirrored in
/// conformance/vectors/README.md's schedule policy).
fn schedules(max_input_len: usize, valid: bool, id: u64) -> Vec<Schedule> {
    if max_input_len == 0 {
        return vec![Schedule::Whole];
    }
    if valid {
        return vec![Schedule::Whole, Schedule::Bytes, Schedule::Straddle];
    }
    if id.is_multiple_of(REJECTION_STRADDLE_SAMPLE) {
        return vec![Schedule::Whole, Schedule::Straddle];
    }
    vec![Schedule::Whole]
}

/// The surface `lib.rs` materializes for every translated vector case.
pub trait VectorCase {
    /// The case's stable id (see conformance/README.md: ids must not
    /// change once locked).
    fn case_id(&self) -> String;

    /// The features this case exercises beyond the baseline surface.
    fn features(&self) -> &'static [&'static str] {
        &[]
    }
}

/// The id shape shared by the vector-derived cases:
/// `<alg>/<source>/tc<id>`, plus `/<schedule>` for cases that carry
/// stream inputs.
fn vector_case_id(alg: &str, source: &str, tc_id: u64, schedule: Option<Schedule>) -> String {
    match schedule {
        Some(schedule) => format!("{alg}/{source}/tc{tc_id}/{}", schedule.name()),
        None => format!("{alg}/{source}/tc{tc_id}"),
    }
}

/// A served HMAC digest parameterization, as named in test ids.
#[derive(Clone, Copy)]
pub enum HmacAlg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl HmacAlg {
    /// The algorithm name used in test ids.
    pub fn name(self) -> &'static str {
        match self {
            HmacAlg::Sha1 => "hmac-sha1",
            HmacAlg::Sha256 => "hmac-sha256",
            HmacAlg::Sha384 => "hmac-sha384",
            HmacAlg::Sha512 => "hmac-sha512",
        }
    }

    /// The full-length tag size in bits (truncated-tag groups are skipped
    /// per the translation policy).
    fn tag_bits(self) -> u32 {
        match self {
            HmacAlg::Sha1 => 160,
            HmacAlg::Sha256 => 256,
            HmacAlg::Sha384 => 384,
            HmacAlg::Sha512 => 512,
        }
    }
}

/// One executed HMAC vector under one schedule.
pub struct HmacCase {
    pub alg: HmacAlg,
    pub tc_id: u64,
    pub schedule: Schedule,
    pub key: Vec<u8>,
    pub msg: Vec<u8>,
    pub tag: Vec<u8>,
    /// `true`: `sign` must equal `tag` and `verify(tag)` must succeed.
    /// `false`: `verify(tag)` must fail with `authentication-failed`.
    pub valid: bool,
}

impl VectorCase for HmacCase {
    fn case_id(&self) -> String {
        vector_case_id(
            self.alg.name(),
            "wycheproof",
            self.tc_id,
            Some(self.schedule),
        )
    }
}

/// What the `lann:webcrypto` contract requires of an AEAD vector.
#[derive(Clone, Copy)]
pub enum AeadExpectation {
    /// Both `seal` and `open` must fail `invalid-nonce`.
    InvalidNonce,
    /// `seal` must produce exactly `ct ‖ tag`; `open` must recover `msg`.
    Valid,
    /// `open` must fail `authentication-failed` (open direction only).
    AuthenticationFailed,
}

/// A caller-nonce AEAD algorithm, as named in test ids (aligned with the
/// minting interfaces).
#[derive(Clone, Copy)]
pub enum AeadAlg {
    AesGcm,
}

impl AeadAlg {
    /// The algorithm's name as used in test ids.
    pub fn name(self) -> &'static str {
        match self {
            AeadAlg::AesGcm => "aes-gcm",
        }
    }
}

/// One executed caller-nonce AEAD vector under one schedule.
pub struct AeadCase {
    pub alg: AeadAlg,
    /// The key size in bits (128 or 256).
    pub key_bits: u32,
    pub tc_id: u64,
    pub schedule: Schedule,
    pub key: Vec<u8>,
    pub iv: Vec<u8>,
    pub aad: Vec<u8>,
    pub msg: Vec<u8>,
    /// The vector's ciphertext followed by its tag (the seal wire format).
    pub ct_tag: Vec<u8>,
    pub expectation: AeadExpectation,
}

impl VectorCase for AeadCase {
    fn case_id(&self) -> String {
        vector_case_id(
            self.alg.name(),
            "wycheproof",
            self.tc_id,
            Some(self.schedule),
        )
    }
}

const HMAC_VECTORS: [(HmacAlg, &str); 4] = [
    (
        HmacAlg::Sha1,
        include_str!("../../vectors/hmac_sha1_test.json"),
    ),
    (
        HmacAlg::Sha256,
        include_str!("../../vectors/hmac_sha256_test.json"),
    ),
    (
        HmacAlg::Sha384,
        include_str!("../../vectors/hmac_sha384_test.json"),
    ),
    (
        HmacAlg::Sha512,
        include_str!("../../vectors/hmac_sha512_test.json"),
    ),
];
const AEAD_VECTORS: [(AeadAlg, &str); 1] = [(
    AeadAlg::AesGcm,
    include_str!("../../vectors/aes_gcm_test.json"),
)];
const HKDF_VECTORS: [(HkdfAlg, &str); 4] = [
    (
        HkdfAlg::Sha1,
        include_str!("../../vectors/hkdf_sha1_test.json"),
    ),
    (
        HkdfAlg::Sha256,
        include_str!("../../vectors/hkdf_sha256_test.json"),
    ),
    (
        HkdfAlg::Sha384,
        include_str!("../../vectors/hkdf_sha384_test.json"),
    ),
    (
        HkdfAlg::Sha512,
        include_str!("../../vectors/hkdf_sha512_test.json"),
    ),
];
const PBKDF2_VECTORS: [(Pbkdf2Alg, &str); 4] = [
    (
        Pbkdf2Alg::Sha1,
        include_str!("../../vectors/pbkdf2_hmacsha1_test.json"),
    ),
    (
        Pbkdf2Alg::Sha256,
        include_str!("../../vectors/pbkdf2_hmacsha256_test.json"),
    ),
    (
        Pbkdf2Alg::Sha384,
        include_str!("../../vectors/pbkdf2_hmacsha384_test.json"),
    ),
    (
        Pbkdf2Alg::Sha512,
        include_str!("../../vectors/pbkdf2_hmacsha512_test.json"),
    ),
];
const SHA2_VECTORS: [(Sha2Alg, &str); 3] = [
    (
        Sha2Alg::Sha256,
        include_str!("../../vectors/SHA256ShortMsg.rsp"),
    ),
    (
        Sha2Alg::Sha384,
        include_str!("../../vectors/SHA384ShortMsg.rsp"),
    ),
    (
        Sha2Alg::Sha512,
        include_str!("../../vectors/SHA512ShortMsg.rsp"),
    ),
];

const SIG_VECTORS: [(SigAlg, &str); 3] = [
    (
        SigAlg::Ed25519,
        include_str!("../../vectors/ed25519_test.json"),
    ),
    (
        SigAlg::EcdsaP256Sha256,
        include_str!("../../vectors/ecdsa_secp256r1_sha256_p1363_test.json"),
    ),
    (
        SigAlg::EcdsaP384Sha384,
        include_str!("../../vectors/ecdsa_secp384r1_sha384_p1363_test.json"),
    ),
];

const X25519_VECTORS: &str = include_str!("../../vectors/x25519_test.json");
/// The derived companion mapping each XDH vector's `tcId` to its private
/// key's public coordinate (see `conformance/vectors/README.md`): the
/// vectors carry raw scalars, but the package's only secret-key import is
/// the OKP JWK, whose `x` is mandatory.
const X25519_PUBLIC_KEYS: &str = include_str!("../../vectors/x25519_test_public_keys.json");

/// The ECDH vector files, each with the derived companion mapping its
/// `tcId`s to the private scalar's public coordinates (see
/// `conformance/vectors/README.md`): the asn and ecpoint files carry raw
/// scalars, but the package's EC private JWK import makes `x`/`y`
/// mandatory (RFC 7518). The webcrypto files need no companion: their
/// keys are already JWKs.
const ECDH_VECTORS: [(EcdhCurve, EcdhFileEncoding, &str, Option<&str>); 6] = [
    (
        EcdhCurve::P256,
        EcdhFileEncoding::Spki,
        include_str!("../../vectors/ecdh_secp256r1_test.json"),
        Some(include_str!(
            "../../vectors/ecdh_secp256r1_test_public_keys.json"
        )),
    ),
    (
        EcdhCurve::P256,
        EcdhFileEncoding::Ecpoint,
        include_str!("../../vectors/ecdh_secp256r1_ecpoint_test.json"),
        Some(include_str!(
            "../../vectors/ecdh_secp256r1_ecpoint_test_public_keys.json"
        )),
    ),
    (
        EcdhCurve::P256,
        EcdhFileEncoding::Webcrypto,
        include_str!("../../vectors/ecdh_secp256r1_webcrypto_test.json"),
        None,
    ),
    (
        EcdhCurve::P384,
        EcdhFileEncoding::Spki,
        include_str!("../../vectors/ecdh_secp384r1_test.json"),
        Some(include_str!(
            "../../vectors/ecdh_secp384r1_test_public_keys.json"
        )),
    ),
    (
        EcdhCurve::P384,
        EcdhFileEncoding::Ecpoint,
        include_str!("../../vectors/ecdh_secp384r1_ecpoint_test.json"),
        Some(include_str!(
            "../../vectors/ecdh_secp384r1_ecpoint_test_public_keys.json"
        )),
    ),
    (
        EcdhCurve::P384,
        EcdhFileEncoding::Webcrypto,
        include_str!("../../vectors/ecdh_secp384r1_webcrypto_test.json"),
        None,
    ),
];

/// A served HKDF parameterization, as named in derivation vector ids.
#[derive(Clone, Copy)]
pub enum HkdfAlg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl HkdfAlg {
    /// The algorithm name used in test ids.
    pub fn name(self) -> &'static str {
        match self {
            HkdfAlg::Sha1 => "hkdf-sha1",
            HkdfAlg::Sha256 => "hkdf-sha256",
            HkdfAlg::Sha384 => "hkdf-sha384",
            HkdfAlg::Sha512 => "hkdf-sha512",
        }
    }
}

/// One Wycheproof HKDF vector: derive `size` bytes of output keying
/// material from (`ikm`, `salt`, `info`) and compare with `okm` — or, for
/// the `SizeTooLarge` vectors, expect the RFC 5869 output bound to fail
/// the derivation.
pub struct HkdfCase {
    pub alg: HkdfAlg,
    pub tc_id: u64,
    pub ikm: Vec<u8>,
    pub salt: Vec<u8>,
    pub info: Vec<u8>,
    /// Output size in bytes.
    pub size: u32,
    pub okm: Vec<u8>,
    pub valid: bool,
}

impl VectorCase for HkdfCase {
    fn case_id(&self) -> String {
        vector_case_id(self.alg.name(), "wycheproof", self.tc_id, None)
    }
}

#[derive(Deserialize)]
struct HkdfGroup {
    tests: Vec<HkdfTest>,
}

#[derive(Deserialize)]
struct HkdfTest {
    #[serde(rename = "tcId")]
    tc_id: u64,
    ikm: String,
    salt: String,
    info: String,
    size: u32,
    okm: String,
    result: String,
}

/// Translate the HKDF vector files. Every vector runs: the WIT surface
/// carries the full (ikm, salt, info, size) parameter space, and the
/// invalid vectors (`SizeTooLarge`) map onto the RFC 5869 output bound the
/// `derive-bits` contract reports as `error.other`.
pub fn hkdf_cases() -> Vec<HkdfCase> {
    let mut cases = Vec::new();
    for (alg, text) in HKDF_VECTORS {
        let file: VectorFile<HkdfGroup> = serde_json::from_str(text)
            .unwrap_or_else(|err| panic!("parsing {} vectors: {err}", alg.name()));
        for group in &file.test_groups {
            for test in &group.tests {
                let field = format!("{} tc{}", alg.name(), test.tc_id);
                cases.push(HkdfCase {
                    alg,
                    tc_id: test.tc_id,
                    ikm: unhex(&field, &test.ikm),
                    salt: unhex(&field, &test.salt),
                    info: unhex(&field, &test.info),
                    size: test.size,
                    okm: unhex(&field, &test.okm),
                    valid: is_valid(&field, &test.result),
                });
            }
        }
    }
    cases
}

/// A served PBKDF2 parameterization, as named in derivation vector ids.
#[derive(Clone, Copy)]
pub enum Pbkdf2Alg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Pbkdf2Alg {
    /// The algorithm name used in test ids.
    pub fn name(self) -> &'static str {
        match self {
            Pbkdf2Alg::Sha1 => "pbkdf2-sha1",
            Pbkdf2Alg::Sha256 => "pbkdf2-sha256",
            Pbkdf2Alg::Sha384 => "pbkdf2-sha384",
            Pbkdf2Alg::Sha512 => "pbkdf2-sha512",
        }
    }
}

/// One Wycheproof PBKDF2 vector: derive `dk_len` bytes from
/// (`password`, `salt`, `iterations`) and compare with `dk`. Every
/// upstream vector is `valid` (the file has no invalid cases), including
/// the empty-password ones (empty KDF secrets are accepted package-wide).
pub struct Pbkdf2Case {
    pub alg: Pbkdf2Alg,
    pub tc_id: u64,
    pub password: Vec<u8>,
    pub salt: Vec<u8>,
    pub iterations: u32,
    /// Output size in bytes.
    pub dk_len: u32,
    pub dk: Vec<u8>,
    pub valid: bool,
}

impl VectorCase for Pbkdf2Case {
    fn case_id(&self) -> String {
        vector_case_id(self.alg.name(), "wycheproof", self.tc_id, None)
    }
}

#[derive(Deserialize)]
struct Pbkdf2Group {
    tests: Vec<Pbkdf2Test>,
}

#[derive(Deserialize)]
struct Pbkdf2Test {
    #[serde(rename = "tcId")]
    tc_id: u64,
    password: String,
    salt: String,
    #[serde(rename = "iterationCount")]
    iterations: u32,
    #[serde(rename = "dkLen")]
    dk_len: u32,
    dk: String,
    result: String,
}

/// Translate the PBKDF2 vector files. Every vector runs: the WIT surface
/// carries the full (password, salt, iterations, dkLen) parameter space.
pub fn pbkdf2_cases() -> Vec<Pbkdf2Case> {
    let mut cases = Vec::new();
    for (alg, text) in PBKDF2_VECTORS {
        let file: VectorFile<Pbkdf2Group> = serde_json::from_str(text)
            .unwrap_or_else(|err| panic!("parsing {} vectors: {err}", alg.name()));
        for group in &file.test_groups {
            for test in &group.tests {
                let field = format!("{} tc{}", alg.name(), test.tc_id);
                cases.push(Pbkdf2Case {
                    alg,
                    tc_id: test.tc_id,
                    password: unhex(&field, &test.password),
                    salt: unhex(&field, &test.salt),
                    iterations: test.iterations,
                    dk_len: test.dk_len,
                    dk: unhex(&field, &test.dk),
                    valid: is_valid(&field, &test.result),
                });
            }
        }
    }
    cases
}

/// A served SHA-2 algorithm, as named in test ids (the digest vector
/// cases, and the RSA signature cases' digest parameterization).
#[derive(Clone, Copy)]
pub enum Sha2Alg {
    Sha256,
    Sha384,
    Sha512,
}

impl Sha2Alg {
    /// The algorithm's name as used in test ids.
    pub fn name(self) -> &'static str {
        match self {
            Sha2Alg::Sha256 => "sha256",
            Sha2Alg::Sha384 => "sha384",
            Sha2Alg::Sha512 => "sha512",
        }
    }
}

/// One executed SHA-2 digest vector under one schedule: `compute(msg)` must
/// equal `md`.
pub struct Sha2Case {
    pub alg: Sha2Alg,
    /// The vector's `Len` field (the message length in bits), which
    /// identifies the case within its file.
    pub len_bits: u64,
    pub schedule: Schedule,
    pub msg: Vec<u8>,
    pub md: Vec<u8>,
}

impl VectorCase for Sha2Case {
    fn case_id(&self) -> String {
        format!(
            "sha2/nist-cavp/{}-len{}/{}",
            self.alg.name(),
            self.len_bits,
            self.schedule.name()
        )
    }
}

#[derive(Deserialize)]
struct VectorFile<G> {
    #[serde(rename = "testGroups")]
    test_groups: Vec<G>,
}

#[derive(Deserialize)]
struct HmacGroup {
    #[serde(rename = "tagSize")]
    tag_size: u32,
    tests: Vec<HmacTest>,
}

#[derive(Deserialize)]
struct HmacTest {
    #[serde(rename = "tcId")]
    tc_id: u64,
    key: String,
    msg: String,
    tag: String,
    result: String,
}

#[derive(Deserialize)]
struct CbcGroup {
    #[serde(rename = "keySize")]
    key_size: u32,
    tests: Vec<CbcTest>,
}

#[derive(Deserialize)]
struct CbcTest {
    #[serde(rename = "tcId")]
    tc_id: u64,
    key: String,
    iv: String,
    msg: String,
    ct: String,
    result: String,
}

#[derive(Deserialize)]
struct KwGroup {
    #[serde(rename = "keySize")]
    key_size: u32,
    tests: Vec<KwTest>,
}

#[derive(Deserialize)]
struct KwTest {
    #[serde(rename = "tcId")]
    tc_id: u64,
    key: String,
    msg: String,
    ct: String,
    result: String,
}

#[derive(Deserialize)]
struct AeadGroup {
    #[serde(rename = "keySize")]
    key_size: u32,
    #[serde(rename = "ivSize")]
    iv_size: u32,
    tests: Vec<AeadTest>,
}

#[derive(Deserialize)]
struct AeadTest {
    #[serde(rename = "tcId")]
    tc_id: u64,
    key: String,
    iv: String,
    aad: String,
    msg: String,
    ct: String,
    tag: String,
    result: String,
}

fn unhex(field: &str, hex: &str) -> Vec<u8> {
    HEXLOWER_PERMISSIVE
        .decode(hex.as_bytes())
        .unwrap_or_else(|err| panic!("vector field {field} is not hex: {err}"))
}

fn is_valid(field: &str, result: &str) -> bool {
    match result {
        "valid" => true,
        "invalid" => false,
        other => panic!("vector {field} has unknown result {other:?}"),
    }
}

/// One Wycheproof X25519 vector: agree the imported secret key (built as
/// an OKP JWK from the raw scalar plus the derived companion's public
/// coordinate) with the imported peer, then check the shared secret — or,
/// for the `ZeroSharedSecret` (small-order peer) vectors, expect `agree`
/// to fail `invalid-key`. No chunking schedules: agreement carries no
/// streams.
pub struct X25519Case {
    pub tc_id: u64,
    /// The peer's raw u-coordinate.
    pub public: Vec<u8>,
    /// The secret key's raw scalar (the JWK `d`).
    pub private: Vec<u8>,
    /// The secret key's public coordinate (the JWK `x`, from the derived
    /// companion).
    pub private_public: Vec<u8>,
    /// The expected shared secret (`zero_shared` cases never reach it).
    pub shared: Vec<u8>,
    /// `true`: `agree` must fail `invalid-key` (the contributory check).
    /// `false`: `agree` must succeed and derive `shared` — Wycheproof's
    /// `acceptable` twist and non-canonical cases included, since RFC
    /// 7748's masking accepts both.
    pub zero_shared: bool,
}

impl VectorCase for X25519Case {
    fn case_id(&self) -> String {
        vector_case_id("x25519", "wycheproof", self.tc_id, None)
    }
}

#[derive(Deserialize)]
struct XdhGroup {
    tests: Vec<XdhTest>,
}

#[derive(Deserialize)]
struct XdhTest {
    #[serde(rename = "tcId")]
    tc_id: u64,
    flags: Vec<String>,
    public: String,
    private: String,
    shared: String,
    result: String,
}

/// Translate the X25519 vector file. Every vector runs: `acceptable` is
/// upstream's marker for policy-divergent cases (twist points,
/// non-canonical encodings, small-order peers), and the WIT pins one
/// policy — RFC 7748 masking with the contributory all-zero check at
/// `agree` — so each maps to a definite expectation by its
/// `ZeroSharedSecret` flag.
pub fn x25519_cases() -> Vec<X25519Case> {
    let file: VectorFile<XdhGroup> = serde_json::from_str(X25519_VECTORS)
        .unwrap_or_else(|err| panic!("parsing x25519 vectors: {err}"));
    let public_keys: std::collections::BTreeMap<String, String> =
        serde_json::from_str(X25519_PUBLIC_KEYS)
            .unwrap_or_else(|err| panic!("parsing the x25519 public-key companion: {err}"));
    let mut cases = Vec::new();
    for group in &file.test_groups {
        for test in &group.tests {
            let field = format!("x25519 tc{}", test.tc_id);
            match test.result.as_str() {
                "valid" | "acceptable" => {}
                other => panic!("vector {field} has unknown result {other:?}"),
            }
            let zero_shared = test.flags.iter().any(|flag| flag == "ZeroSharedSecret");
            let shared = unhex(&field, &test.shared);
            assert_eq!(
                zero_shared,
                shared.iter().all(|&b| b == 0),
                "vector {field}: ZeroSharedSecret flag disagrees with its shared value"
            );
            let private_public = public_keys
                .get(&test.tc_id.to_string())
                .unwrap_or_else(|| panic!("vector {field} missing from the public-key companion"));
            cases.push(X25519Case {
                tc_id: test.tc_id,
                public: unhex(&field, &test.public),
                private: unhex(&field, &test.private),
                private_public: unhex(&field, private_public),
                shared,
                zero_shared,
            });
        }
    }
    cases
}

/// A served ECDH curve, as named in test ids.
#[derive(Clone, Copy)]
pub enum EcdhCurve {
    P256,
    P384,
}

impl EcdhCurve {
    /// The algorithm name used in test ids.
    pub fn name(self) -> &'static str {
        match self {
            EcdhCurve::P256 => "ecdh-p256",
            EcdhCurve::P384 => "ecdh-p384",
        }
    }

    /// The curve's name as a JWK `crv` member.
    fn crv(self) -> &'static str {
        match self {
            EcdhCurve::P256 => "P-256",
            EcdhCurve::P384 => "P-384",
        }
    }

    /// The curve's field size in bytes: the width of a scalar and of each
    /// point coordinate.
    fn field_size(self) -> usize {
        match self {
            EcdhCurve::P256 => 32,
            EcdhCurve::P384 => 48,
        }
    }
}

/// How an ECDH vector file encodes its keys (Wycheproof's `encoding`
/// group member), which selects the public import under test.
#[derive(Clone, Copy)]
enum EcdhFileEncoding {
    /// `asn`: SPKI public keys, raw private scalars.
    Spki,
    /// `ecpoint`: raw uncompressed SEC1 public points, raw private
    /// scalars.
    Ecpoint,
    /// `webcrypto`: both keys as JWK objects.
    Webcrypto,
}

/// A vector's peer public key in its file's encoding, carrying the
/// dispatch to the matching import function.
pub enum EcdhPublic {
    /// `import-public-key-raw` (the ecpoint files).
    Raw(Vec<u8>),
    /// `import-public-key-spki` (the asn files).
    Spki(Vec<u8>),
    /// `import-public-key-jwk` (the webcrypto files; the JWK as JSON
    /// text).
    Jwk(String),
}

impl EcdhPublic {
    /// The source segment in test ids, naming the vector file family.
    fn source(&self) -> &'static str {
        match self {
            EcdhPublic::Raw(_) => "wycheproof-ecpoint",
            EcdhPublic::Spki(_) => "wycheproof-spki",
            EcdhPublic::Jwk(_) => "wycheproof-webcrypto",
        }
    }
}

/// One Wycheproof ECDH vector: agree the imported secret key (an EC
/// private JWK — the webcrypto files' own, or one built from the raw
/// scalar plus the derived companion's public coordinates) with the
/// imported peer, then check the shared secret — or, for the rejection
/// cases, expect the peer's import to fail `invalid-key`. No chunking
/// schedules: agreement carries no streams.
pub struct EcdhCase {
    pub curve: EcdhCurve,
    pub tc_id: u64,
    /// The peer's public key, in the file's encoding.
    pub public: EcdhPublic,
    /// The secret key as an EC private JWK (JSON text).
    pub secret_jwk: String,
    /// The expected shared secret (`reject_public` cases never reach it).
    pub shared: Vec<u8>,
    /// `true`: the public import must fail `invalid-key`. `false`:
    /// `agree` must succeed, `derive-bits(none)` must equal `shared`, and
    /// a 128-bit truncation must equal its prefix.
    pub reject_public: bool,
}

impl VectorCase for EcdhCase {
    fn case_id(&self) -> String {
        vector_case_id(self.curve.name(), self.public.source(), self.tc_id, None)
    }
}

#[derive(Deserialize)]
struct EcdhGroup {
    tests: Vec<EcdhTest>,
}

#[derive(Deserialize)]
struct EcdhTest {
    #[serde(rename = "tcId")]
    tc_id: u64,
    flags: Vec<String>,
    public: String,
    private: String,
    shared: String,
    result: String,
}

#[derive(Deserialize)]
struct EcdhWebcryptoGroup {
    tests: Vec<EcdhWebcryptoTest>,
}

#[derive(Deserialize)]
struct EcdhWebcryptoTest {
    #[serde(rename = "tcId")]
    tc_id: u64,
    public: serde_json::Value,
    private: serde_json::Value,
    shared: String,
    result: String,
}

/// The `x`/`y` coordinate pair one derived-companion entry carries.
#[derive(Deserialize)]
struct EcdhPublicCoordinates {
    x: String,
    y: String,
}

/// Normalize a Wycheproof big-endian integer scalar to exactly the
/// curve's field size: strip leading zero bytes, then left-pad (the
/// files' hex may carry a leading zero byte or be short). Panics if the
/// value is wider than the field.
fn normalize_scalar(field: &str, scalar: &[u8], size: usize) -> Vec<u8> {
    let significant: &[u8] = match scalar.iter().position(|&b| b != 0) {
        Some(first) => &scalar[first..],
        None => &[],
    };
    assert!(
        significant.len() <= size,
        "vector {field}: {}-byte scalar is wider than the {size}-byte field",
        significant.len()
    );
    let mut out = vec![0u8; size - significant.len()];
    out.extend_from_slice(significant);
    out
}

/// Translate the ECDH vector files (per curve: the SPKI-encoded `asn`
/// file, the raw-point `ecpoint` file, and the JWK `webcrypto` file):
///
/// - `valid` vectors run: import both keys, `agree`, and check the
///   shared secret at its natural length and a 128-bit truncation.
/// - `invalid` vectors expect the peer's import to fail `invalid-key`.
///   Every one is a public-key admission failure — off-curve points and
///   invalid-curve attacks, wrong curves, malformed encodings — and the
///   WIT pins strict public admission at import, so they all land there
///   (unlike X25519, where degenerate peers surface at `agree`).
/// - `acceptable` in the ecpoint files (a compressed encoding of a valid
///   point) also expects `invalid-key`: upstream marks compressed
///   admission policy-divergent, but the WIT pins the raw format to
///   uncompressed-only.
/// - In the asn files, every vector flagged `UnnamedCurve` (an
///   explicit-parameter encoding, whatever upstream's verdict) expects
///   `invalid-key`: the WIT pins named-OID-only curve admission, so the
///   whole family rejects on every implementation — including the
///   encodings whose parameters describe the declared curve, where
///   upstream's verdict splits on its own notion of parameter
///   validation.
/// - The asn files' remaining `acceptable` vectors (the `InvalidAsn`
///   BER-laxity family and the compressed-point encoding) are
///   **excluded**: their acceptance is legitimately policy-divergent
///   across implementations. The WIT deliberately leaves compressed-SPKI
///   admission implementation-defined, and ASN.1/BER strictness beyond
///   the documented shape differs across the platform engines the jco
///   host delegates to, so no single expectation holds across targets.
///   The invalid-curve attacks, off-curve points, and wrong-curve
///   rejections stay pinned through the named-curve SPKI cases and the
///   ecpoint/webcrypto files.
pub fn ecdh_cases() -> Vec<EcdhCase> {
    let mut cases = Vec::new();
    for (curve, encoding, text, companion) in ECDH_VECTORS {
        match encoding {
            EcdhFileEncoding::Webcrypto => {
                let file: VectorFile<EcdhWebcryptoGroup> = serde_json::from_str(text)
                    .unwrap_or_else(|err| {
                        panic!("parsing {} webcrypto vectors: {err}", curve.name())
                    });
                for group in &file.test_groups {
                    for test in &group.tests {
                        let field = format!("{} webcrypto tc{}", curve.name(), test.tc_id);
                        let reject_public = match test.result.as_str() {
                            "valid" => false,
                            "invalid" => true,
                            other => panic!("vector {field} has unknown result {other:?}"),
                        };
                        cases.push(EcdhCase {
                            curve,
                            tc_id: test.tc_id,
                            public: EcdhPublic::Jwk(test.public.to_string()),
                            secret_jwk: test.private.to_string(),
                            shared: unhex(&field, &test.shared),
                            reject_public,
                        });
                    }
                }
            }
            EcdhFileEncoding::Spki | EcdhFileEncoding::Ecpoint => {
                let file: VectorFile<EcdhGroup> = serde_json::from_str(text)
                    .unwrap_or_else(|err| panic!("parsing {} vectors: {err}", curve.name()));
                let public_keys: std::collections::BTreeMap<String, EcdhPublicCoordinates> =
                    serde_json::from_str(companion.expect("scalar-carrying files have companions"))
                        .unwrap_or_else(|err| {
                            panic!("parsing a {} public-key companion: {err}", curve.name())
                        });
                for group in &file.test_groups {
                    for test in &group.tests {
                        let field = format!("{} tc{}", curve.name(), test.tc_id);
                        let unnamed_curve = test.flags.iter().any(|flag| flag == "UnnamedCurve");
                        let reject_public = match (test.result.as_str(), encoding) {
                            _ if unnamed_curve => true,
                            ("valid", _) => false,
                            ("invalid", _) => true,
                            ("acceptable", EcdhFileEncoding::Ecpoint) => true,
                            ("acceptable", _) => continue,
                            (other, _) => panic!("vector {field} has unknown result {other:?}"),
                        };
                        let d = normalize_scalar(
                            &field,
                            &unhex(&field, &test.private),
                            curve.field_size(),
                        );
                        let coordinates =
                            public_keys.get(&test.tc_id.to_string()).unwrap_or_else(|| {
                                panic!("vector {field} missing from the public-key companion")
                            });
                        let public = unhex(&field, &test.public);
                        cases.push(EcdhCase {
                            curve,
                            tc_id: test.tc_id,
                            public: match encoding {
                                EcdhFileEncoding::Ecpoint => EcdhPublic::Raw(public),
                                _ => EcdhPublic::Spki(public),
                            },
                            secret_jwk: crate::mint::ecdh_secret_jwk(
                                curve.crv(),
                                &unhex(&field, &coordinates.x),
                                &unhex(&field, &coordinates.y),
                                &d,
                            ),
                            shared: unhex(&field, &test.shared),
                            reject_public,
                        });
                    }
                }
            }
        }
    }
    cases
}

/// The normalized HMAC cases: every full-length-tag vector of every
/// served digest parameterization, expanded over its schedule set.
pub fn hmac_cases() -> Vec<HmacCase> {
    let mut cases = Vec::new();
    for (alg, text) in HMAC_VECTORS {
        let file: VectorFile<HmacGroup> = serde_json::from_str(text)
            .unwrap_or_else(|err| panic!("parsing {} vectors: {err}", alg.name()));
        for group in &file.test_groups {
            if group.tag_size != alg.tag_bits() {
                continue;
            }
            for test in &group.tests {
                let field = format!("{} tc{}", alg.name(), test.tc_id);
                let key = unhex(&field, &test.key);
                let msg = unhex(&field, &test.msg);
                let tag = unhex(&field, &test.tag);
                let valid = is_valid(&field, &test.result);
                for schedule in schedules(msg.len(), valid, test.tc_id) {
                    cases.push(HmacCase {
                        alg,
                        tc_id: test.tc_id,
                        schedule,
                        key: key.clone(),
                        msg: msg.clone(),
                        tag: tag.clone(),
                        valid,
                    });
                }
            }
        }
    }
    cases
}

/// The normalized caller-nonce AEAD cases: every AES-GCM keySize-128 and
/// -256 vector (AES-192 is declined at minting, covered by probes),
/// expanded over their schedule sets.
pub fn aead_cases() -> Vec<AeadCase> {
    let mut cases = Vec::new();
    for (alg, text) in AEAD_VECTORS {
        let file: VectorFile<AeadGroup> = serde_json::from_str(text)
            .unwrap_or_else(|err| panic!("parsing {} vectors: {err}", alg.name()));
        for group in &file.test_groups {
            if group.key_size == 192 {
                continue;
            }
            for test in &group.tests {
                let field = format!("{} tc{}", alg.name(), test.tc_id);
                let (fields, expectation, max_input_len) = translate_aead(&field, alg, group, test);
                let valid = matches!(expectation, AeadExpectation::Valid);
                for schedule in schedules(max_input_len, valid, test.tc_id) {
                    let (key, iv, aad, msg, ct_tag) = fields.clone();
                    cases.push(AeadCase {
                        alg,
                        key_bits: group.key_size,
                        tc_id: test.tc_id,
                        schedule,
                        key,
                        iv,
                        aad,
                        msg,
                        ct_tag,
                        expectation,
                    });
                }
            }
        }
    }
    cases
}

/// Decode one Wycheproof AEAD test and derive its expectation. Nonce-length
/// policy is the algorithm's: GCM accepts 12–128-byte nonces (the
/// `aes-gcm` contract's uniform window, so every outside-window `ivSize`
/// group — including `ZeroLengthIv` — fails `invalid-nonce` on seal and
/// open alike, and its vector's ciphertext is deliberately unreachable;
/// in-window non-96-bit sizes run the vector's own verdict, exercising the
/// `J0` derivation).
#[allow(clippy::type_complexity)]
fn translate_aead(
    field: &str,
    alg: AeadAlg,
    group: &AeadGroup,
    test: &AeadTest,
) -> (
    (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>),
    AeadExpectation,
    usize,
) {
    let key = unhex(field, &test.key);
    let iv = unhex(field, &test.iv);
    let aad = unhex(field, &test.aad);
    let msg = unhex(field, &test.msg);
    let mut ct_tag = unhex(field, &test.ct);
    ct_tag.extend(unhex(field, &test.tag));
    let valid = is_valid(field, &test.result);
    let nonce_accepted = match alg {
        AeadAlg::AesGcm => (96..=1024).contains(&group.iv_size),
    };
    let (expectation, max_input_len) = if !nonce_accepted {
        (AeadExpectation::InvalidNonce, msg.len().max(ct_tag.len()))
    } else if valid {
        (AeadExpectation::Valid, msg.len().max(ct_tag.len()))
    } else {
        (AeadExpectation::AuthenticationFailed, ct_tag.len())
    };
    ((key, iv, aad, msg, ct_tag), expectation, max_input_len)
}

/// One executed AES-CBC vector under one schedule (Wycheproof
/// `aes_cbc_pkcs5_test.json`; PKCS5 and PKCS7 padding coincide for AES's
/// 16-byte blocks).
/// One AES-KW vector (RFC 3394; `aes_wrap_test.json`). Wrapping trades in
/// `list<u8>`, so there are no chunking schedules.
///
/// Upstream's verdicts translate onto the WIT contract:
/// - `valid`: `wrap` reproduces the vector's wrapped bytes exactly, and
///   `unwrap` + a raw unwrap mint recovers the key data.
/// - `acceptable` (8-byte key data, RFC 3394's n = 1): outside the WIT's
///   wrap domain — `wrap` fails `invalid-key`, and the 16-byte wrapped
///   form fails `unwrap` with `authentication-failed` (under the 24-byte
///   minimum).
/// - `invalid`: a present `msg` outside the wrap domain fails `wrap` with
///   `invalid-key`; a present `ct` fails `unwrap` with
///   `authentication-failed` (bad ICV and malformed lengths are
///   deliberately indistinguishable).
pub struct KwCase {
    /// The key size in bits (128 or 256; AES-192 is declined at minting,
    /// covered by probes).
    pub key_bits: u32,
    pub tc_id: u64,
    pub key: Vec<u8>,
    pub msg: Vec<u8>,
    pub ct: Vec<u8>,
    /// Upstream's verdict, translated: `true` round-trips both ways.
    pub valid: bool,
}

impl VectorCase for KwCase {
    fn case_id(&self) -> String {
        vector_case_id("aes-kw", "wycheproof", self.tc_id, None)
    }
}

/// The normalized AES-KW cases: every keySize-128 and -256 vector.
pub fn kw_cases() -> Vec<KwCase> {
    let file: VectorFile<KwGroup> =
        serde_json::from_str(include_str!("../../vectors/aes_wrap_test.json"))
            .unwrap_or_else(|err| panic!("parsing aes-kw vectors: {err}"));
    let mut cases = Vec::new();
    for group in &file.test_groups {
        if group.key_size == 192 {
            continue;
        }
        for test in &group.tests {
            let field = format!("aes-kw tc{}", test.tc_id);
            cases.push(KwCase {
                key_bits: group.key_size,
                tc_id: test.tc_id,
                key: unhex(&field, &test.key),
                msg: unhex(&field, &test.msg),
                ct: unhex(&field, &test.ct),
                // `acceptable` (the 8-byte ShortKey pair) is outside the
                // WIT's wrap domain, so it lands with `invalid`.
                valid: test.result == "valid",
            });
        }
    }
    cases
}

pub struct CbcCase {
    /// The key size in bits (128 or 256; AES-192 is declined at minting,
    /// covered by probes).
    pub key_bits: u32,
    pub tc_id: u64,
    pub schedule: Schedule,
    pub key: Vec<u8>,
    pub iv: Vec<u8>,
    pub msg: Vec<u8>,
    pub ct: Vec<u8>,
    /// Upstream's verdict: a valid vector round-trips both ways; an
    /// invalid one (bad or absent padding) must fail `decrypt` with the
    /// kind's uniform error.
    pub valid: bool,
}

impl VectorCase for CbcCase {
    fn case_id(&self) -> String {
        vector_case_id("aes-cbc", "wycheproof", self.tc_id, Some(self.schedule))
    }
}

/// The normalized AES-CBC cases: every keySize-128 and -256 vector,
/// expanded over its schedule set.
pub fn cbc_cases() -> Vec<CbcCase> {
    let file: VectorFile<CbcGroup> =
        serde_json::from_str(include_str!("../../vectors/aes_cbc_pkcs5_test.json"))
            .unwrap_or_else(|err| panic!("parsing aes-cbc vectors: {err}"));
    let mut cases = Vec::new();
    for group in &file.test_groups {
        if group.key_size == 192 {
            continue;
        }
        for test in &group.tests {
            let field = format!("aes-cbc tc{}", test.tc_id);
            let key = unhex(&field, &test.key);
            let iv = unhex(&field, &test.iv);
            let msg = unhex(&field, &test.msg);
            let ct = unhex(&field, &test.ct);
            let valid = is_valid(&field, &test.result);
            let max_input_len = msg.len().max(ct.len());
            for schedule in schedules(max_input_len, valid, test.tc_id) {
                cases.push(CbcCase {
                    key_bits: group.key_size,
                    tc_id: test.tc_id,
                    schedule,
                    key: key.clone(),
                    iv: iv.clone(),
                    msg: msg.clone(),
                    ct: ct.clone(),
                    valid,
                });
            }
        }
    }
    cases
}

/// The normalized SHA-2 digest cases: every NIST CAVP ShortMsg vector,
/// expanded over its schedule set. The `.rsp` format is line-oriented
/// `Field = value` triples (`Len` in bits, `Msg`, `MD`); a zero-length case
/// spells its message `00`, so `Msg` is truncated to `Len` bits.
pub fn sha2_cases() -> Vec<Sha2Case> {
    let mut cases = Vec::new();
    for (alg, text) in SHA2_VECTORS {
        let mut len_bits: Option<u64> = None;
        let mut msg: Option<Vec<u8>> = None;
        for line in text.lines() {
            let Some((field, value)) = line.split_once('=') else {
                continue;
            };
            let (field, value) = (field.trim(), value.trim());
            match field {
                "Len" => {
                    len_bits = Some(value.parse().unwrap_or_else(|err| {
                        panic!("{} vector Len {value:?} is not a number: {err}", alg.name())
                    }));
                }
                "Msg" => msg = Some(unhex(&format!("{} msg", alg.name()), value)),
                "MD" => {
                    let len_bits = len_bits.take().expect("MD before Len");
                    let mut msg = msg.take().expect("MD before Msg");
                    msg.truncate((len_bits / 8) as usize);
                    let md = unhex(&format!("{} len{len_bits} md", alg.name()), value);
                    for schedule in schedules(msg.len(), true, len_bits) {
                        cases.push(Sha2Case {
                            alg,
                            len_bits,
                            schedule,
                            msg: msg.clone(),
                            md: md.clone(),
                        });
                    }
                }
                _ => {}
            }
        }
    }
    cases
}

/// A served signature algorithm, as named in vector ids.
#[derive(Clone, Copy)]
pub enum SigAlg {
    Ed25519,
    EcdsaP256Sha256,
    EcdsaP384Sha384,
}

impl SigAlg {
    /// The algorithm's name as used in test ids.
    pub fn name(self) -> &'static str {
        match self {
            SigAlg::Ed25519 => "ed25519",
            SigAlg::EcdsaP256Sha256 => "ecdsa-p256-sha256",
            SigAlg::EcdsaP384Sha384 => "ecdsa-p384-sha384",
        }
    }
}

/// One executed signature-verification vector under one schedule: importing
/// the group's public key and verifying `sig` over `msg` must succeed
/// (`valid`) or fail `authentication-failed` (`invalid`).
pub struct SigCase {
    pub alg: SigAlg,
    pub tc_id: u64,
    pub schedule: Schedule,
    /// The public key in the minting interface's import format (raw 32
    /// bytes for Ed25519, an uncompressed SEC1 point for ECDSA).
    pub public: Vec<u8>,
    pub msg: Vec<u8>,
    pub sig: Vec<u8>,
    pub valid: bool,
}

impl VectorCase for SigCase {
    fn case_id(&self) -> String {
        vector_case_id(
            self.alg.name(),
            "wycheproof",
            self.tc_id,
            Some(self.schedule),
        )
    }
}

/// One executed ed25519-speccheck adversarial vector under one schedule:
/// degenerate keys and signatures (small-order and non-canonical `A`/`R`,
/// out-of-range `S`, mixed-order torsion components) that pin the
/// `ed25519-verify` verification criterion cross-target.
pub struct SpeccheckCase {
    /// The vector's index in the published set.
    pub tc_id: u64,
    pub schedule: Schedule,
    pub public: Vec<u8>,
    pub msg: Vec<u8>,
    pub sig: Vec<u8>,
    /// `true`: import and verification must both succeed (the one
    /// mixed-order case the cofactorless equation accepts). `false`: the
    /// input must be rejected — at import (`invalid-key`) or at
    /// verification (`authentication-failed`), per the WIT criterion.
    pub valid: bool,
}

impl VectorCase for SpeccheckCase {
    fn case_id(&self) -> String {
        vector_case_id("ed25519", "speccheck", self.tc_id, Some(self.schedule))
    }
}

#[derive(Deserialize)]
struct SpeccheckVector {
    message: String,
    pub_key: String,
    signature: String,
}

const SPECCHECK_VECTORS: &str = include_str!("../../vectors/ed25519_speccheck.json");

/// The index of the only speccheck vector the pinned criterion accepts:
/// case 3 (mixed-order `A` and `R` under a passing cofactorless equation) —
/// `verify_strict`'s published result set.
const SPECCHECK_VALID_CASE: u64 = 3;

/// The normalized speccheck cases, expanded over their schedule set.
pub fn speccheck_cases() -> Vec<SpeccheckCase> {
    let vectors: Vec<SpeccheckVector> =
        serde_json::from_str(SPECCHECK_VECTORS).expect("parsing ed25519_speccheck.json");
    let mut cases = Vec::new();
    for (index, vector) in vectors.iter().enumerate() {
        let field = format!("speccheck tc{index}");
        let msg = unhex(&field, &vector.message);
        let valid = index as u64 == SPECCHECK_VALID_CASE;
        for schedule in schedules(msg.len(), valid, index as u64) {
            cases.push(SpeccheckCase {
                tc_id: index as u64,
                schedule,
                public: unhex(&field, &vector.pub_key),
                msg: msg.clone(),
                sig: unhex(&field, &vector.signature),
                valid,
            });
        }
    }
    cases
}

#[derive(Deserialize)]
struct EddsaGroup {
    #[serde(rename = "publicKey")]
    public_key: EddsaPublicKey,
    tests: Vec<SigTest>,
}

#[derive(Deserialize)]
struct EddsaPublicKey {
    pk: String,
}

#[derive(Deserialize)]
struct EcdsaGroup {
    #[serde(rename = "publicKey")]
    public_key: EcdsaPublicKey,
    tests: Vec<SigTest>,
}

#[derive(Deserialize)]
struct EcdsaPublicKey {
    uncompressed: String,
}

#[derive(Deserialize)]
struct SigTest {
    #[serde(rename = "tcId")]
    tc_id: u64,
    msg: String,
    sig: String,
    result: String,
}

/// The normalized signature-verification cases (Wycheproof Ed25519 plus
/// the ECDSA P1363-signature files, whose fixed-width `r ‖ s` encoding is
/// exactly this package's wire format), expanded over its schedule set.
pub fn sig_cases() -> Vec<SigCase> {
    fn push_group(cases: &mut Vec<SigCase>, alg: SigAlg, public: &[u8], tests: &[SigTest]) {
        for test in tests {
            let field = format!("{} tc{}", alg.name(), test.tc_id);
            let msg = unhex(&field, &test.msg);
            let sig = unhex(&field, &test.sig);
            let valid = is_valid(&field, &test.result);
            for schedule in schedules(msg.len(), valid, test.tc_id) {
                cases.push(SigCase {
                    alg,
                    tc_id: test.tc_id,
                    schedule,
                    public: public.to_vec(),
                    msg: msg.clone(),
                    sig: sig.clone(),
                    valid,
                });
            }
        }
    }

    let mut cases = Vec::new();
    for (alg, text) in SIG_VECTORS {
        match alg {
            SigAlg::Ed25519 => {
                let file: VectorFile<EddsaGroup> = serde_json::from_str(text)
                    .unwrap_or_else(|err| panic!("parsing {} vectors: {err}", alg.name()));
                for group in &file.test_groups {
                    let public = unhex("ed25519 pk", &group.public_key.pk);
                    push_group(&mut cases, alg, &public, &group.tests);
                }
            }
            SigAlg::EcdsaP256Sha256 | SigAlg::EcdsaP384Sha384 => {
                let file: VectorFile<EcdsaGroup> = serde_json::from_str(text)
                    .unwrap_or_else(|err| panic!("parsing {} vectors: {err}", alg.name()));
                for group in &file.test_groups {
                    let public = unhex("ecdsa uncompressed", &group.public_key.uncompressed);
                    push_group(&mut cases, alg, &public, &group.tests);
                }
            }
        }
    }
    cases
}

/// The RSASSA-PKCS1-v1_5 verification vector files (one per digest ×
/// modulus-length parameterization, plus the 8192-bit file pinning
/// large-modulus admission inside the family's 1024–16384-bit window).
const RSA_PKCS1_VECTORS: [&str; 10] = [
    include_str!("../../vectors/rsa_signature_2048_sha256_test.json"),
    include_str!("../../vectors/rsa_signature_2048_sha384_test.json"),
    include_str!("../../vectors/rsa_signature_2048_sha512_test.json"),
    include_str!("../../vectors/rsa_signature_3072_sha256_test.json"),
    include_str!("../../vectors/rsa_signature_3072_sha384_test.json"),
    include_str!("../../vectors/rsa_signature_3072_sha512_test.json"),
    include_str!("../../vectors/rsa_signature_4096_sha256_test.json"),
    include_str!("../../vectors/rsa_signature_4096_sha384_test.json"),
    include_str!("../../vectors/rsa_signature_4096_sha512_test.json"),
    include_str!("../../vectors/rsa_signature_8192_sha256_test.json"),
];

/// The RSA-PSS verification vector files: the WebCrypto-expressible
/// parameterizations only (the MGF1 digest equals the message digest,
/// which the WIT fixes), each group carrying the salt length the WIT
/// binds at mint. The `sha512_mgf1_32` file pins a salt length that
/// differs from the digest length.
const RSA_PSS_VECTORS: [&str; 8] = [
    include_str!("../../vectors/rsa_pss_2048_sha256_mgf1_0_test.json"),
    include_str!("../../vectors/rsa_pss_2048_sha256_mgf1_32_test.json"),
    include_str!("../../vectors/rsa_pss_2048_sha384_mgf1_48_test.json"),
    include_str!("../../vectors/rsa_pss_3072_sha256_mgf1_32_test.json"),
    include_str!("../../vectors/rsa_pss_4096_sha256_mgf1_32_test.json"),
    include_str!("../../vectors/rsa_pss_4096_sha384_mgf1_48_test.json"),
    include_str!("../../vectors/rsa_pss_4096_sha512_mgf1_32_test.json"),
    include_str!("../../vectors/rsa_pss_4096_sha512_mgf1_64_test.json"),
];

/// The id-RSASSA-PSS-parameterized key file: every key carries the
/// AlgorithmIdentifier the RSA family contract rejects at import, so
/// every case translates to an SPKI import-must-fail (`invalid-key`).
const RSA_PSS_PARAMS_VECTORS: &str =
    include_str!("../../vectors/rsa_pss_2048_sha256_mgf1_32_params_test.json");

/// An RSA signature family, as named in test ids: the verification scheme
/// plus, for RSA-PSS, the salt length the WIT binds at mint.
#[derive(Clone, Copy)]
pub enum RsaFamily {
    Pkcs1V15,
    Pss { salt_len: u32 },
}

/// A translated RSA parameterization: the family, the mint-bound digest,
/// and the group key's modulus length (a property of the imported
/// material, but part of the test id — each vector file is one
/// parameterization).
#[derive(Clone, Copy)]
pub struct RsaAlg {
    pub family: RsaFamily,
    pub sha: Sha2Alg,
    pub key_bits: u32,
}

impl RsaAlg {
    /// The algorithm segment of this parameterization's test ids.
    pub fn name(self) -> String {
        match self.family {
            RsaFamily::Pkcs1V15 => {
                format!("rsassa-pkcs1-v15-{}-{}", self.sha.name(), self.key_bits)
            }
            RsaFamily::Pss { salt_len } => format!(
                "rsa-pss-{}-{}-salt{}",
                self.sha.name(),
                self.key_bits,
                salt_len
            ),
        }
    }
}

/// A vector's group public key in one of the family's two import
/// encodings, carrying the dispatch to the matching import function.
pub enum RsaImport {
    /// `import-verifying-key-spki` (the group's `publicKeyDer`).
    Spki(Vec<u8>),
    /// `import-verifying-key-jwk` (the group's own JWK where the file
    /// carries one, else a minimal `{kty, n, e}` built from the group's
    /// modulus and exponent; JSON text).
    Jwk(String),
}

/// What the `lann:webcrypto` contract requires of an RSA vector.
#[derive(Clone, Copy)]
pub enum RsaExpectation {
    /// Import succeeds and `verify(sig)` succeeds.
    Valid,
    /// Import succeeds and `verify(sig)` fails `authentication-failed`.
    AuthenticationFailed,
    /// The import itself fails `invalid-key` (the id-RSASSA-PSS file).
    RejectImport,
}

/// One executed RSA signature-verification vector: importing the group's
/// public key per `import` and verifying `sig` over `msg` per
/// `expectation`.
pub struct RsaCase {
    pub alg: RsaAlg,
    /// The source segment in test ids (`wycheproof`, or
    /// `wycheproof-params` for the id-RSASSA-PSS file).
    pub source: &'static str,
    pub tc_id: u64,
    pub import: RsaImport,
    /// `None` only for [`RsaExpectation::RejectImport`] cases, which
    /// carry no streams.
    pub schedule: Option<Schedule>,
    pub msg: Vec<u8>,
    pub sig: Vec<u8>,
    pub expectation: RsaExpectation,
}

impl VectorCase for RsaCase {
    fn case_id(&self) -> String {
        // Valid vectors translate once per import path, so those ids name
        // it; a rejection runs only via SPKI and its id stays plain.
        let import = match (&self.expectation, &self.import) {
            (RsaExpectation::Valid, RsaImport::Spki(_)) => "-spki",
            (RsaExpectation::Valid, RsaImport::Jwk(_)) => "-jwk",
            _ => "",
        };
        let base = format!(
            "{}/{}/tc{}{import}",
            self.alg.name(),
            self.source,
            self.tc_id
        );
        match self.schedule {
            Some(schedule) => format!("{base}/{}", schedule.name()),
            None => base,
        }
    }
}

/// The `modulus`/`publicExponent` members of a vector group's `publicKey`
/// object (big-endian hex, possibly with a leading zero byte).
#[derive(Deserialize)]
struct RsaPublicKeyMembers {
    modulus: String,
    #[serde(rename = "publicExponent")]
    public_exponent: String,
}

#[derive(Deserialize)]
struct RsaPkcs1Group {
    #[serde(rename = "keySize")]
    key_size: u32,
    sha: String,
    #[serde(rename = "publicKeyDer")]
    public_key_der: String,
    #[serde(rename = "keyJwk")]
    key_jwk: serde_json::Value,
    tests: Vec<SigTest>,
}

#[derive(Deserialize)]
struct RsaPssGroup {
    #[serde(rename = "keySize")]
    key_size: u32,
    sha: String,
    #[serde(rename = "mgfSha")]
    mgf_sha: String,
    #[serde(rename = "sLen")]
    salt_len: u32,
    #[serde(rename = "publicKeyDer")]
    public_key_der: String,
    /// Absent from two vendored files (`mgf1_0` and `4096_sha512_mgf1_32`)
    /// and from the params file.
    #[serde(rename = "publicKeyJwk")]
    public_key_jwk: Option<serde_json::Value>,
    #[serde(rename = "publicKey")]
    public_key: RsaPublicKeyMembers,
    tests: Vec<SigTest>,
}

/// The digest parameterization a vector group's `sha` member declares.
fn rsa_sha(field: &str, sha: &str) -> Sha2Alg {
    match sha {
        "SHA-256" => Sha2Alg::Sha256,
        "SHA-384" => Sha2Alg::Sha384,
        "SHA-512" => Sha2Alg::Sha512,
        other => panic!("vector group {field} has unserved sha {other:?}"),
    }
}

/// The minimal RSA public JWK (RFC 7518 §6.3.1: `kty`, `n`, `e`) for a
/// group's modulus and exponent, with the base64url members stripped of
/// leading zero bytes as the JWK integer encoding requires.
fn rsa_public_jwk(n: &[u8], e: &[u8]) -> String {
    fn strip(bytes: &[u8]) -> &[u8] {
        match bytes.iter().position(|&b| b != 0) {
            Some(first) => &bytes[first..],
            None => &[],
        }
    }
    format!(
        r#"{{"kty":"RSA","n":"{}","e":"{}"}}"#,
        conformance_harness::b64url(strip(n)),
        conformance_harness::b64url(strip(e)),
    )
}

/// Translate one file's group of RSA verification vectors:
///
/// - `valid` vectors run twice — once importing the group key via SPKI,
///   once via the RSA public JWK — so both import paths carry vector
///   coverage; each expands over the acceptance schedule set.
/// - `invalid` vectors run once, via SPKI (the rejection under test is
///   the verifier's, not the import path's): `verify(sig)` fails
///   `authentication-failed`.
/// - `acceptable` vectors (the `MissingNull` BER-laxity family) also fail
///   `authentication-failed`: the WIT pins strict verification — the
///   EMSA-PKCS1-v1_5 encoding is compared byte-exact — so upstream's
///   lax-verifier allowances are uniform rejections here.
fn push_rsa_group(
    cases: &mut Vec<RsaCase>,
    alg: RsaAlg,
    spki: &[u8],
    jwk: &str,
    tests: &[SigTest],
) {
    for test in tests {
        let field = format!("{} tc{}", alg.name(), test.tc_id);
        let msg = unhex(&field, &test.msg);
        let sig = unhex(&field, &test.sig);
        let valid = match test.result.as_str() {
            "valid" => true,
            "invalid" | "acceptable" => false,
            other => panic!("vector {field} has unknown result {other:?}"),
        };
        let imports: &[RsaImport] = if valid {
            &[
                RsaImport::Spki(spki.to_vec()),
                RsaImport::Jwk(jwk.to_string()),
            ]
        } else {
            &[RsaImport::Spki(spki.to_vec())]
        };
        for import in imports {
            for schedule in schedules(msg.len(), valid, test.tc_id) {
                cases.push(RsaCase {
                    alg,
                    source: "wycheproof",
                    tc_id: test.tc_id,
                    import: match import {
                        RsaImport::Spki(spki) => RsaImport::Spki(spki.clone()),
                        RsaImport::Jwk(jwk) => RsaImport::Jwk(jwk.clone()),
                    },
                    schedule: Some(schedule),
                    msg: msg.clone(),
                    sig: sig.clone(),
                    expectation: if valid {
                        RsaExpectation::Valid
                    } else {
                        RsaExpectation::AuthenticationFailed
                    },
                });
            }
        }
    }
}

/// The normalized RSA signature-verification cases: the RSASSA-PKCS1-v1_5
/// and RSA-PSS files translated per [`push_rsa_group`], plus the
/// id-RSASSA-PSS key file, whose every case expects the SPKI import to
/// fail `invalid-key` (the family contract admits only `rsaEncryption`
/// SubjectPublicKeyInfos). That file's coverage is SPKI-only: it carries
/// no JWKs, and a plain RSA public JWK has no member that could carry the
/// PSS AlgorithmIdentifier, so no JWK-side counterpart exists.
pub fn rsa_cases() -> Vec<RsaCase> {
    let mut cases = Vec::new();
    for text in RSA_PKCS1_VECTORS {
        let file: VectorFile<RsaPkcs1Group> = serde_json::from_str(text)
            .unwrap_or_else(|err| panic!("parsing rsassa-pkcs1-v15 vectors: {err}"));
        for group in &file.test_groups {
            let field = format!("rsassa-pkcs1-v15 {}-bit group", group.key_size);
            let alg = RsaAlg {
                family: RsaFamily::Pkcs1V15,
                sha: rsa_sha(&field, &group.sha),
                key_bits: group.key_size,
            };
            push_rsa_group(
                &mut cases,
                alg,
                &unhex(&field, &group.public_key_der),
                &group.key_jwk.to_string(),
                &group.tests,
            );
        }
    }
    for text in RSA_PSS_VECTORS {
        let file: VectorFile<RsaPssGroup> = serde_json::from_str(text)
            .unwrap_or_else(|err| panic!("parsing rsa-pss vectors: {err}"));
        for group in &file.test_groups {
            let field = format!("rsa-pss {}-bit group", group.key_size);
            // The WIT fixes the MGF1 digest to the message digest; only
            // files within that parameterization are vendored.
            assert_eq!(
                group.mgf_sha, group.sha,
                "{field}: mgfSha differs from sha, outside the WIT parameterization"
            );
            let alg = RsaAlg {
                family: RsaFamily::Pss {
                    salt_len: group.salt_len,
                },
                sha: rsa_sha(&field, &group.sha),
                key_bits: group.key_size,
            };
            let jwk = match &group.public_key_jwk {
                Some(jwk) => jwk.to_string(),
                None => rsa_public_jwk(
                    &unhex(&field, &group.public_key.modulus),
                    &unhex(&field, &group.public_key.public_exponent),
                ),
            };
            push_rsa_group(
                &mut cases,
                alg,
                &unhex(&field, &group.public_key_der),
                &jwk,
                &group.tests,
            );
        }
    }
    let file: VectorFile<RsaPssGroup> = serde_json::from_str(RSA_PSS_PARAMS_VECTORS)
        .unwrap_or_else(|err| panic!("parsing rsa-pss params vectors: {err}"));
    for group in &file.test_groups {
        let field = format!("rsa-pss-params {}-bit group", group.key_size);
        let alg = RsaAlg {
            family: RsaFamily::Pss {
                salt_len: group.salt_len,
            },
            sha: rsa_sha(&field, &group.sha),
            key_bits: group.key_size,
        };
        let spki = unhex(&field, &group.public_key_der);
        for test in &group.tests {
            cases.push(RsaCase {
                alg,
                source: "wycheproof-params",
                tc_id: test.tc_id,
                import: RsaImport::Spki(spki.clone()),
                schedule: None,
                msg: Vec::new(),
                sig: Vec::new(),
                expectation: RsaExpectation::RejectImport,
            });
        }
    }
    cases
}
