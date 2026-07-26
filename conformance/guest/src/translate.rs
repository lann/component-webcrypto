//! Translation of the vendored test vectors (Wycheproof JSON for HMAC, GCM,
//! and ChaCha20-Poly1305, NIST CAVP `.rsp` for SHA-2) into the
//! `lann:webcrypto` contract — the authoritative encoding of the policy
//! documented in `conformance/vectors/README.md`:
//!
//! | Vector property | Our expectation |
//! | --- | --- |
//! | GCM, keySize ≠ 256 | Skipped (import rejection is covered by probes). |
//! | GCM, keySize 256, ivSize ≠ 96 | `seal`/`open` both fail `invalid-nonce`. |
//! | GCM, keySize 256, ivSize 96, `valid` | `seal` = `ct ‖ tag`; `open` = `msg`. |
//! | GCM, keySize 256, ivSize 96, `invalid` | `open` fails `authentication-failed`. |
//! | ChaCha20-Poly1305, ivSize ≠ the variant's (96 / 192 for X) | `seal`/`open` both fail `invalid-nonce`. |
//! | ChaCha20-Poly1305, variant ivSize, `valid` | `seal` = `ct ‖ tag`; `open` = `msg`. |
//! | ChaCha20-Poly1305, variant ivSize, `invalid` | `open` fails `authentication-failed`. |
//! | HMAC, tagSize ≠ 256 | Skipped (truncated tags are an application concern). |
//! | HMAC, tagSize 256, `valid` | `sign` = `tag`; `verify(tag)` succeeds. |
//! | HMAC, tagSize 256, `invalid` | `verify(tag)` is `authentication-failed`. |
//! | SHA-2 ShortMsg case | `compute` = `MD` (every case; there are no invalid digest vectors). |
//!
//! Every executed vector is emitted once per chunking schedule; a vector whose
//! stream inputs are all empty runs only `whole` (the other schedules are
//! degenerate duplicates).

use serde::Deserialize;

/// How a vector's byte inputs are delivered to the implementation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Schedule {
    /// One write of the whole input.
    Whole,
    /// One-byte writes.
    Bytes,
    /// Alternating 15/17-byte writes, straddling 16-byte block boundaries.
    Straddle,
}

impl Schedule {
    /// The schedule's name, as used in test ids.
    pub fn name(self) -> &'static str {
        match self {
            Schedule::Whole => "whole",
            Schedule::Bytes => "bytes",
            Schedule::Straddle => "straddle",
        }
    }

    /// Split `data` into the write-sized chunks this schedule delivers on a
    /// single stream.
    pub fn chunks(self, data: &[u8]) -> Vec<Vec<u8>> {
        match self {
            Schedule::Whole => {
                if data.is_empty() {
                    Vec::new()
                } else {
                    vec![data.to_vec()]
                }
            }
            Schedule::Bytes => data.iter().map(|byte| vec![*byte]).collect(),
            Schedule::Straddle => {
                let mut chunks = Vec::new();
                let mut offset = 0;
                let mut fifteen = true;
                while offset < data.len() {
                    let size = if fifteen { 15 } else { 17 };
                    let end = (offset + size).min(data.len());
                    chunks.push(data[offset..end].to_vec());
                    offset = end;
                    fifteen = !fifteen;
                }
                chunks
            }
        }
    }
}

/// The schedule set for a vector whose longest stream input is
/// `max_input_len` bytes.
fn schedules(max_input_len: usize) -> Vec<Schedule> {
    if max_input_len == 0 {
        return vec![Schedule::Whole];
    }
    vec![Schedule::Whole, Schedule::Bytes, Schedule::Straddle]
}

/// One executed HMAC-SHA-256 vector under one schedule.
pub struct HmacCase {
    pub tc_id: u64,
    pub schedule: Schedule,
    pub key: Vec<u8>,
    pub msg: Vec<u8>,
    pub tag: Vec<u8>,
    /// `true`: `sign` must equal `tag` and `verify(tag)` must succeed.
    /// `false`: `verify(tag)` must fail with `authentication-failed`.
    pub valid: bool,
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

/// One executed AES-256-GCM vector under one schedule.
pub struct GcmCase {
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

/// A `chacha-variant`, as named in ChaCha20-Poly1305 vector ids.
#[derive(Clone, Copy)]
pub enum ChaChaAlg {
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

impl ChaChaAlg {
    /// The variant's name as used in test ids (its WIT enum-case name).
    pub fn name(self) -> &'static str {
        match self {
            ChaChaAlg::ChaCha20Poly1305 => "chacha20-poly1305",
            ChaChaAlg::XChaCha20Poly1305 => "xchacha20-poly1305",
        }
    }

    /// The variant's nonce length in bits (the vector files' `ivSize`).
    fn iv_bits(self) -> u32 {
        match self {
            ChaChaAlg::ChaCha20Poly1305 => 96,
            ChaChaAlg::XChaCha20Poly1305 => 192,
        }
    }
}

/// One executed ChaCha20-Poly1305 vector under one schedule.
pub struct ChaChaCase {
    pub alg: ChaChaAlg,
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

const HMAC_VECTORS: &str = include_str!("../../vectors/hmac_sha256_test.json");
const GCM_VECTORS: &str = include_str!("../../vectors/aes_gcm_test.json");
const CHACHA_VECTORS: [(ChaChaAlg, &str); 2] = [
    (
        ChaChaAlg::ChaCha20Poly1305,
        include_str!("../../vectors/chacha20_poly1305_test.json"),
    ),
    (
        ChaChaAlg::XChaCha20Poly1305,
        include_str!("../../vectors/xchacha20_poly1305_test.json"),
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

/// The normalized HMAC-SHA-256 corpus: every tagSize-256 vector, expanded
/// over its schedule set.
pub fn hmac_cases() -> Vec<HmacCase> {
    let file: VectorFile<HmacGroup> =
        serde_json::from_str(HMAC_VECTORS).expect("parsing hmac_sha256_test.json");
    let mut cases = Vec::new();
    for group in &file.test_groups {
        if group.tag_size != 256 {
            continue;
        }
        for test in &group.tests {
            let field = format!("hmac tc{}", test.tc_id);
            let key = unhex(&field, &test.key);
            let msg = unhex(&field, &test.msg);
            let tag = unhex(&field, &test.tag);
            let valid = is_valid(&field, &test.result);
            for schedule in schedules(msg.len()) {
                cases.push(HmacCase {
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
    cases
}

/// The normalized AES-256-GCM corpus: every keySize-256 vector, expanded
/// over its schedule set.
pub fn gcm_cases() -> Vec<GcmCase> {
    let file: VectorFile<AeadGroup> =
        serde_json::from_str(GCM_VECTORS).expect("parsing aes_gcm_test.json");
    let mut cases = Vec::new();
    for group in &file.test_groups {
        if group.key_size != 256 {
            continue;
        }
        for test in &group.tests {
            let field = format!("gcm tc{}", test.tc_id);
            let (fields, expectation, max_input_len) = translate_aead(&field, group, test, 96);
            for schedule in schedules(max_input_len) {
                let (key, iv, aad, msg, ct_tag) = fields.clone();
                cases.push(GcmCase {
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
    cases
}

/// The normalized ChaCha20-Poly1305 corpus (both variants): every vector,
/// expanded over its schedule set. Both files are all-keySize-256, so unlike
/// GCM nothing is skipped.
pub fn chacha_cases() -> Vec<ChaChaCase> {
    let mut cases = Vec::new();
    for (alg, text) in CHACHA_VECTORS {
        let file: VectorFile<AeadGroup> = serde_json::from_str(text)
            .unwrap_or_else(|err| panic!("parsing {} vectors: {err}", alg.name()));
        for group in &file.test_groups {
            assert_eq!(
                group.key_size,
                256,
                "{} vectors are all 256-bit",
                alg.name()
            );
            for test in &group.tests {
                let field = format!("{} tc{}", alg.name(), test.tc_id);
                let (fields, expectation, max_input_len) =
                    translate_aead(&field, group, test, alg.iv_bits());
                for schedule in schedules(max_input_len) {
                    let (key, iv, aad, msg, ct_tag) = fields.clone();
                    cases.push(ChaChaCase {
                        alg,
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

/// Decode one Wycheproof AEAD test and derive its expectation: a group whose
/// `ivSize` is not the algorithm's nonce length must fail `invalid-nonce`;
/// otherwise the vector's own verdict applies.
#[allow(clippy::type_complexity)]
fn translate_aead(
    field: &str,
    group: &AeadGroup,
    test: &AeadTest,
    valid_iv_bits: u32,
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
    let (expectation, max_input_len) = if group.iv_size != valid_iv_bits {
        (AeadExpectation::InvalidNonce, msg.len().max(ct_tag.len()))
    } else if valid {
        (AeadExpectation::Valid, msg.len().max(ct_tag.len()))
    } else {
        (AeadExpectation::AuthenticationFailed, ct_tag.len())
    };
    ((key, iv, aad, msg, ct_tag), expectation, max_input_len)
}

/// The normalized SHA-2 digest corpus: every NIST CAVP ShortMsg vector,
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
                    for schedule in schedules(msg.len()) {
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
