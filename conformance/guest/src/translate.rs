//! Translation of the vendored Wycheproof vectors into the `lann:webcrypto`
//! contract — the authoritative encoding of the policy documented in
//! `conformance/vectors/README.md`:
//!
//! | Vector property | Our expectation |
//! | --- | --- |
//! | GCM, keySize ≠ 256 | Skipped (import rejection is covered by probes). |
//! | GCM, keySize 256, ivSize ≠ 96 | `seal`/`open` both fail `invalid-nonce`. |
//! | GCM, keySize 256, ivSize 96, `valid` | `seal` = `ct ‖ tag`; `open` = `msg`. |
//! | GCM, keySize 256, ivSize 96, `invalid` | `open` fails `authentication-failed`. |
//! | HMAC, tagSize ≠ 256 | Skipped (truncated tags are an application concern). |
//! | HMAC, tagSize 256, `valid` | `finalize` = `tag`; `verify(tag)` is true. |
//! | HMAC, tagSize 256, `invalid` | `verify(tag)` is false. |
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
    /// MAC only: the input split at its midpoint across two sequential
    /// `absorb` calls (each half written whole).
    SplitAbsorb,
}

impl Schedule {
    /// The schedule's name, as used in test ids.
    pub fn name(self) -> &'static str {
        match self {
            Schedule::Whole => "whole",
            Schedule::Bytes => "bytes",
            Schedule::Straddle => "straddle",
            Schedule::SplitAbsorb => "split-absorb",
        }
    }

    /// Split `data` into the write-sized chunks this schedule delivers on a
    /// single stream. (`split-absorb` splits across *absorb calls*, not
    /// within a stream, so each of its streams is written whole.)
    pub fn chunks(self, data: &[u8]) -> Vec<Vec<u8>> {
        match self {
            Schedule::Whole | Schedule::SplitAbsorb => {
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
fn schedules(max_input_len: usize, split_absorb: bool) -> Vec<Schedule> {
    if max_input_len == 0 {
        return vec![Schedule::Whole];
    }
    let mut set = vec![Schedule::Whole, Schedule::Bytes, Schedule::Straddle];
    if split_absorb {
        set.push(Schedule::SplitAbsorb);
    }
    set
}

/// One executed HMAC-SHA-256 vector under one schedule.
pub struct HmacCase {
    pub tc_id: u64,
    pub schedule: Schedule,
    pub key: Vec<u8>,
    pub msg: Vec<u8>,
    pub tag: Vec<u8>,
    /// `true`: `finalize` must equal `tag` and `verify(tag)` must be true.
    /// `false`: `verify(tag)` must be false.
    pub valid: bool,
}

/// What the `lann:webcrypto` contract requires of a GCM vector.
#[derive(Clone, Copy)]
pub enum GcmExpectation {
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
    pub expectation: GcmExpectation,
}

const HMAC_VECTORS: &str = include_str!("../../vectors/hmac_sha256_test.json");
const GCM_VECTORS: &str = include_str!("../../vectors/aes_gcm_test.json");

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
struct GcmGroup {
    #[serde(rename = "keySize")]
    key_size: u32,
    #[serde(rename = "ivSize")]
    iv_size: u32,
    tests: Vec<GcmTest>,
}

#[derive(Deserialize)]
struct GcmTest {
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
            for schedule in schedules(msg.len(), true) {
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
    let file: VectorFile<GcmGroup> =
        serde_json::from_str(GCM_VECTORS).expect("parsing aes_gcm_test.json");
    let mut cases = Vec::new();
    for group in &file.test_groups {
        if group.key_size != 256 {
            continue;
        }
        for test in &group.tests {
            let field = format!("gcm tc{}", test.tc_id);
            let key = unhex(&field, &test.key);
            let iv = unhex(&field, &test.iv);
            let aad = unhex(&field, &test.aad);
            let msg = unhex(&field, &test.msg);
            let mut ct_tag = unhex(&field, &test.ct);
            ct_tag.extend(unhex(&field, &test.tag));
            let valid = is_valid(&field, &test.result);
            let (expectation, max_input_len) = if group.iv_size != 96 {
                (GcmExpectation::InvalidNonce, msg.len().max(ct_tag.len()))
            } else if valid {
                (GcmExpectation::Valid, msg.len().max(ct_tag.len()))
            } else {
                (GcmExpectation::AuthenticationFailed, ct_tag.len())
            };
            for schedule in schedules(max_input_len, false) {
                cases.push(GcmCase {
                    tc_id: test.tc_id,
                    schedule,
                    key: key.clone(),
                    iv: iv.clone(),
                    aad: aad.clone(),
                    msg: msg.clone(),
                    ct_tag: ct_tag.clone(),
                    expectation,
                });
            }
        }
    }
    cases
}
