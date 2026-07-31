//! Translation of the vendored test vectors (Wycheproof JSON for HMAC, GCM,
//! and ChaCha20-Poly1305, NIST CAVP `.rsp` for SHA-2) into the
//! `lann:webcrypto` contract — the authoritative encoding of the policy
//! documented in `conformance/vectors/README.md`:
//!
//! | Vector property | Our expectation |
//! | --- | --- |
//! | GCM, keySize ≠ 256 | Skipped (import rejection is covered by probes). |
//! | GCM, keySize 256, ivSize 0 | `seal`/`open` both fail `invalid-nonce`. |
//! | GCM, keySize 256, any other ivSize, `valid` | `seal` = `ct ‖ tag`; `open` = `msg` (the non-96-bit sizes exercise the `J0` derivation). |
//! | GCM, keySize 256, any other ivSize, `invalid` | `open` fails `authentication-failed`. |
//! | ChaCha20-Poly1305, ivSize ≠ the variant's (96 / 192 for X) | `seal`/`open` both fail `invalid-nonce`. |
//! | ChaCha20-Poly1305, variant ivSize, `valid` | `seal` = `ct ‖ tag`; `open` = `msg`. |
//! | ChaCha20-Poly1305, variant ivSize, `invalid` | `open` fails `authentication-failed`. |
//! | HMAC, tagSize ≠ 256 | Skipped (truncated tags are an application concern). |
//! | HMAC, tagSize 256, `valid` | `sign` = `tag`; `verify(tag)` succeeds. |
//! | HMAC, tagSize 256, `invalid` | `verify(tag)` is `authentication-failed`. |
//! | SHA-2 ShortMsg case | `compute` = `MD` (every case; there are no invalid digest vectors). |
//! | Ed25519 / ECDSA-P1363, `valid` | `verify(sig)` succeeds. |
//! | Ed25519 / ECDSA-P1363, `invalid` | `verify(sig)` is `authentication-failed` (malformed signatures included — rejection carries no detail). |
//!
//! Every executed vector is emitted once per chunking schedule; a vector whose
//! stream inputs are all empty runs only `whole` (the other schedules are
//! degenerate duplicates).

use conformance_harness::stream::Schedule;
use conformance_harness::{FEATURE_CHACHA, FEATURE_GCM_ANY_IV};
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

/// A served HMAC digest parameterization, as named in test ids.
#[derive(Clone, Copy)]
pub enum HmacAlg {
    Sha256,
    Sha384,
    Sha512,
}

impl HmacAlg {
    /// The algorithm name used in test ids.
    pub fn name(self) -> &'static str {
        match self {
            HmacAlg::Sha256 => "hmac-sha256",
            HmacAlg::Sha384 => "hmac-sha384",
            HmacAlg::Sha512 => "hmac-sha512",
        }
    }

    /// The full-length tag size in bits (truncated-tag groups are skipped
    /// per the translation policy).
    fn tag_bits(self) -> u32 {
        match self {
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

impl HmacCase {
    /// The case's stable id (see conformance/README.md: ids must not
    /// change once locked).
    pub fn case_id(&self) -> String {
        format!(
            "{}/wycheproof/tc{}/{}",
            self.alg.name(),
            self.tc_id,
            self.schedule.name()
        )
    }

    /// The features this case exercises beyond the baseline surface.
    pub fn features(&self) -> &'static [&'static str] {
        &[]
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
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

impl AeadAlg {
    /// The algorithm's name as used in test ids.
    pub fn name(self) -> &'static str {
        match self {
            AeadAlg::AesGcm => "aes-gcm",
            AeadAlg::ChaCha20Poly1305 => "chacha20-poly1305",
            AeadAlg::XChaCha20Poly1305 => "xchacha20-poly1305",
        }
    }

    /// The algorithm's nonce length in bits (the vector files' `ivSize`).
    fn iv_bits(self) -> u32 {
        match self {
            AeadAlg::AesGcm | AeadAlg::ChaCha20Poly1305 => 96,
            AeadAlg::XChaCha20Poly1305 => 192,
        }
    }

    /// The features a case of this algorithm exercises.
    fn features(self) -> &'static [&'static str] {
        match self {
            AeadAlg::AesGcm => &[],
            AeadAlg::ChaCha20Poly1305 | AeadAlg::XChaCha20Poly1305 => &[FEATURE_CHACHA],
        }
    }
}

/// One executed caller-nonce AEAD vector under one schedule.
pub struct AeadCase {
    pub alg: AeadAlg,
    /// The key size in bits (128 or 256 for AES-GCM; the ChaCha vector
    /// files are all 256).
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

impl AeadCase {
    /// The case's stable id (see conformance/README.md: ids must not
    /// change once locked).
    pub fn case_id(&self) -> String {
        format!(
            "{}/wycheproof/tc{}/{}",
            self.alg.name(),
            self.tc_id,
            self.schedule.name()
        )
    }

    /// The features this case exercises beyond the baseline surface: the
    /// algorithm's, plus `aes-gcm-any-iv` for GCM nonces outside the
    /// 12–128-byte window every implementation serves (empty nonces are
    /// untagged — every target rejects them `invalid-nonce`).
    pub fn features(&self) -> &'static [&'static str] {
        if matches!(self.alg, AeadAlg::AesGcm)
            && !self.iv.is_empty()
            && !(12..=128).contains(&self.iv.len())
        {
            return &[FEATURE_GCM_ANY_IV];
        }
        self.alg.features()
    }
}

/// The algorithm behind an [`InternalNonceCase`], as named in test ids
/// (the minting interface's name).
#[derive(Clone, Copy)]
pub enum InternalNonceAlg {
    AesGcm,
    XChaCha20Poly1305,
}

impl InternalNonceAlg {
    /// The algorithm's name as used in test ids.
    pub fn name(self) -> &'static str {
        match self {
            InternalNonceAlg::AesGcm => "aes-gcm-internal-nonce",
            InternalNonceAlg::XChaCha20Poly1305 => "xchacha20-poly1305-internal-nonce",
        }
    }

    /// The features a case of this algorithm exercises.
    fn features(self) -> &'static [&'static str] {
        match self {
            InternalNonceAlg::AesGcm => &[],
            InternalNonceAlg::XChaCha20Poly1305 => &[FEATURE_CHACHA],
        }
    }
}

/// One executed internal-nonce AEAD vector under one schedule: the vector's
/// `iv || ct || tag` as a sealed message, driven through the `open`
/// direction (the only deterministic one; `seal` draws a random nonce).
pub struct InternalNonceCase {
    pub alg: InternalNonceAlg,
    /// The AES key size in bits for [`InternalNonceAlg::AesGcm`] (128 or
    /// 256); always 256 for XChaCha.
    pub key_bits: u32,
    pub tc_id: u64,
    pub schedule: Schedule,
    pub key: Vec<u8>,
    pub aad: Vec<u8>,
    pub msg: Vec<u8>,
    /// The vector's IV, ciphertext, and tag in the sealed wire format.
    pub sealed: Vec<u8>,
    /// `true`: `open` must recover `msg`. `false`: `open` must fail
    /// `authentication-failed` (an invalid vector, or one whose IV length
    /// is not the algorithm's — the sealed prefix misparses).
    pub valid: bool,
}

impl InternalNonceCase {
    /// The case's stable id (see conformance/README.md: ids must not
    /// change once locked).
    pub fn case_id(&self) -> String {
        format!(
            "{}/wycheproof/tc{}/{}",
            self.alg.name(),
            self.tc_id,
            self.schedule.name()
        )
    }

    /// The features this case exercises beyond the baseline surface.
    pub fn features(&self) -> &'static [&'static str] {
        self.alg.features()
    }
}

/// The normalized internal-nonce cases, derived from the same AEAD vector
/// files as the caller-nonce cases: `open(iv || ct || tag)` must recover
/// `msg` exactly when the vector is valid and its IV is the algorithm's
/// nonce length; every other case must fail `authentication-failed` (there
/// is no invalid-nonce case -- the nonce is carried in-band, so a
/// wrong-length IV is just a malformed sealed message).
pub fn internal_nonce_cases() -> Vec<InternalNonceCase> {
    let mut cases = Vec::new();
    for (aead_alg, text) in AEAD_VECTORS {
        // Only AES-GCM and XChaCha have internal-nonce minting interfaces
        // (see the WIT: nothing forces the 12-byte ChaCha construction into
        // a package-defined wire format).
        let alg = match aead_alg {
            AeadAlg::AesGcm => InternalNonceAlg::AesGcm,
            AeadAlg::ChaCha20Poly1305 => continue,
            AeadAlg::XChaCha20Poly1305 => InternalNonceAlg::XChaCha20Poly1305,
        };
        let file: VectorFile<AeadGroup> = serde_json::from_str(text)
            .unwrap_or_else(|err| panic!("parsing {} vectors: {err}", aead_alg.name()));
        for group in &file.test_groups {
            // AES-192 is declined at minting (probed); 128 and 256 run.
            if group.key_size == 192 {
                continue;
            }
            for test in &group.tests {
                let field = format!("{} tc{}", alg.name(), test.tc_id);
                let key = unhex(&field, &test.key);
                let aad = unhex(&field, &test.aad);
                let msg = unhex(&field, &test.msg);
                let mut sealed = unhex(&field, &test.iv);
                sealed.extend(unhex(&field, &test.ct));
                sealed.extend(unhex(&field, &test.tag));
                let valid = is_valid(&field, &test.result) && group.iv_size == aead_alg.iv_bits();
                for schedule in schedules(sealed.len(), valid, test.tc_id) {
                    cases.push(InternalNonceCase {
                        alg,
                        key_bits: group.key_size,
                        tc_id: test.tc_id,
                        schedule,
                        key: key.clone(),
                        aad: aad.clone(),
                        msg: msg.clone(),
                        sealed: sealed.clone(),
                        valid,
                    });
                }
            }
        }
    }
    cases
}

const HMAC_VECTORS: [(HmacAlg, &str); 3] = [
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
const AEAD_VECTORS: [(AeadAlg, &str); 3] = [
    (
        AeadAlg::AesGcm,
        include_str!("../../vectors/aes_gcm_test.json"),
    ),
    (
        AeadAlg::ChaCha20Poly1305,
        include_str!("../../vectors/chacha20_poly1305_test.json"),
    ),
    (
        AeadAlg::XChaCha20Poly1305,
        include_str!("../../vectors/xchacha20_poly1305_test.json"),
    ),
];
const HKDF_VECTORS: [(HkdfAlg, &str); 3] = [
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
const PBKDF2_VECTORS: [(Pbkdf2Alg, &str); 3] = [
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

/// A served HKDF parameterization, as named in derivation vector ids.
#[derive(Clone, Copy)]
pub enum HkdfAlg {
    Sha256,
    Sha384,
    Sha512,
}

impl HkdfAlg {
    /// The algorithm name used in test ids.
    pub fn name(self) -> &'static str {
        match self {
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

impl HkdfCase {
    /// The case's stable id (see conformance/README.md: ids must not
    /// change once locked).
    pub fn case_id(&self) -> String {
        format!("{}/wycheproof/tc{}", self.alg.name(), self.tc_id)
    }

    /// The features this case exercises beyond the baseline surface.
    pub fn features(&self) -> &'static [&'static str] {
        &[]
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
    Sha256,
    Sha384,
    Sha512,
}

impl Pbkdf2Alg {
    /// The algorithm name used in test ids.
    pub fn name(self) -> &'static str {
        match self {
            Pbkdf2Alg::Sha256 => "pbkdf2-sha256",
            Pbkdf2Alg::Sha384 => "pbkdf2-sha384",
            Pbkdf2Alg::Sha512 => "pbkdf2-sha512",
        }
    }
}

/// One Wycheproof PBKDF2 vector: derive `dk_len` bytes from
/// (`password`, `salt`, `iterations`) and compare with `dk`. Every
/// upstream vector is `valid` (the file has no invalid cases), including
/// the empty-password ones — which is why `import-password` accepts empty
/// material.
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

impl Pbkdf2Case {
    /// The case's stable id (see conformance/README.md: ids must not
    /// change once locked).
    pub fn case_id(&self) -> String {
        format!("{}/wycheproof/tc{}", self.alg.name(), self.tc_id)
    }

    /// The features this case exercises beyond the baseline surface.
    pub fn features(&self) -> &'static [&'static str] {
        &[]
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

/// A served SHA-2 algorithm, as named in digest vector ids.
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

impl Sha2Case {
    /// The case's stable id (see conformance/README.md: ids must not
    /// change once locked).
    pub fn case_id(&self) -> String {
        format!(
            "sha2/nist-cavp/{}-len{}/{}",
            self.alg.name(),
            self.len_bits,
            self.schedule.name()
        )
    }

    /// The features this case exercises beyond the baseline surface.
    pub fn features(&self) -> &'static [&'static str] {
        &[]
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
    hex::decode(hex).unwrap_or_else(|err| panic!("vector field {field} is not hex: {err}"))
}

fn is_valid(field: &str, result: &str) -> bool {
    match result {
        "valid" => true,
        "invalid" => false,
        other => panic!("vector {field} has unknown result {other:?}"),
    }
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
/// -256 vector (AES-192 is declined at minting, covered by probes) and
/// every ChaCha20-Poly1305 vector of both variants (those files are all
/// keySize-256, so nothing is skipped), expanded over their schedule sets.
pub fn aead_cases() -> Vec<AeadCase> {
    let mut cases = Vec::new();
    for (alg, text) in AEAD_VECTORS {
        let file: VectorFile<AeadGroup> = serde_json::from_str(text)
            .unwrap_or_else(|err| panic!("parsing {} vectors: {err}", alg.name()));
        for group in &file.test_groups {
            match alg {
                AeadAlg::AesGcm if group.key_size == 192 => continue,
                AeadAlg::AesGcm => {}
                _ => assert_eq!(
                    group.key_size,
                    256,
                    "{} vectors are all 256-bit",
                    alg.name()
                ),
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
/// policy is the algorithm's: GCM accepts any non-empty nonce (only the
/// `ZeroLengthIv` groups fail `invalid-nonce`; every other `ivSize` runs
/// the vector's own verdict, the non-96-bit sizes exercising the `J0`
/// derivation), while the ChaCha constructions fail `invalid-nonce` for any
/// `ivSize` but their own.
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
        AeadAlg::AesGcm => group.iv_size != 0,
        _ => group.iv_size == alg.iv_bits(),
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

impl SigCase {
    /// The case's stable id (see conformance/README.md: ids must not
    /// change once locked).
    pub fn case_id(&self) -> String {
        format!(
            "{}/wycheproof/tc{}/{}",
            self.alg.name(),
            self.tc_id,
            self.schedule.name()
        )
    }

    /// The features this case exercises beyond the baseline surface.
    pub fn features(&self) -> &'static [&'static str] {
        &[]
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

impl SpeccheckCase {
    /// The case's stable id (see conformance/README.md: ids must not
    /// change once locked).
    pub fn case_id(&self) -> String {
        format!(
            "ed25519/speccheck/tc{}/{}",
            self.tc_id,
            self.schedule.name()
        )
    }

    /// The features this case exercises beyond the baseline surface.
    pub fn features(&self) -> &'static [&'static str] {
        &[]
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
