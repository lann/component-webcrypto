//! The case plan: the single, natively-testable source of truth mapping
//! the incumbent corpus (translate/contract/probes, reused wholesale from
//! `conformance-guest`) onto the `#[suite]` generator rows.
//!
//! Every `#[case_row]` in `lib.rs` delegates here ([`register`]), and the
//! native census-parity test (`census_test`) expands the same [`ROWS`]
//! table, so the inventory the suite registers and the inventory the test
//! asserts cannot drift from each other. Case *bodies* are the incumbent
//! runners, untouched; only naming/tagging/registration is new.

use std::rc::Rc;

#[cfg(not(feature = "rkyv-corpus"))]
use component_test_sdk::GeneratedCase;
use component_test_sdk::{ArcStr, Failure, Registry, Tags, Verdict};
use conformance_harness::FEATURE_SHA1_CHECKED;
use futures::future::LocalBoxFuture;

#[cfg(not(feature = "rkyv-corpus"))]
use crate::translate::VectorCase;
use crate::{contract, vectors};

/// One planned case: its full census id, the features it exercises (the
/// generator row's tags must equal them — asserted natively), and its
/// body (the incumbent runner over the translated data).
pub struct PlanCase {
    pub id: String,
    pub features: &'static [&'static str],
    pub run: Box<dyn Fn() -> LocalBoxFuture<'static, Result<(), String>>>,
}

/// One generator row: a static census prefix and the tags every case
/// under it carries (verified uniform against the incumbent census).
pub struct Row {
    pub prefix: &'static str,
    pub tags: &'static [&'static str],
}

const NO_TAGS: &[&str] = &[];

/// Every generator row, mirroring the census's two-segment groups.
pub const ROWS: &[Row] = &[
    // Wycheproof-derived vector suites.
    Row {
        prefix: "hkdf-sha1/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "hkdf-sha256/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "hkdf-sha384/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "hkdf-sha512/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "pbkdf2-sha1/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "pbkdf2-sha256/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "pbkdf2-sha384/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "pbkdf2-sha512/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "hmac-sha1/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "hmac-sha256/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "hmac-sha384/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "hmac-sha512/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "aes-gcm/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "aes-cbc/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "aes-kw/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "sha2/nist-cavp",
        tags: NO_TAGS,
    },
    Row {
        prefix: "ed25519/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "ed25519/speccheck",
        tags: NO_TAGS,
    },
    Row {
        prefix: "ecdsa-p256-sha256/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "ecdsa-p384-sha384/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "rsassa-pkcs1-v15-sha256-2048/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "rsassa-pkcs1-v15-sha384-2048/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "rsassa-pkcs1-v15-sha512-2048/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "rsassa-pkcs1-v15-sha256-3072/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "rsassa-pkcs1-v15-sha384-3072/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "rsassa-pkcs1-v15-sha512-3072/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "rsassa-pkcs1-v15-sha256-4096/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "rsassa-pkcs1-v15-sha384-4096/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "rsassa-pkcs1-v15-sha512-4096/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "rsassa-pkcs1-v15-sha256-8192/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "rsa-pss-sha256-2048-salt0/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "rsa-pss-sha256-2048-salt32/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "rsa-pss-sha384-2048-salt48/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "rsa-pss-sha256-3072-salt32/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "rsa-pss-sha256-4096-salt32/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "rsa-pss-sha384-4096-salt48/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "rsa-pss-sha512-4096-salt32/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "rsa-pss-sha512-4096-salt64/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "rsa-pss-sha256-2048-salt32/wycheproof-params",
        tags: NO_TAGS,
    },
    Row {
        prefix: "x25519/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "ecdh-p256/wycheproof-spki",
        tags: NO_TAGS,
    },
    Row {
        prefix: "ecdh-p256/wycheproof-ecpoint",
        tags: NO_TAGS,
    },
    Row {
        prefix: "ecdh-p256/wycheproof-webcrypto",
        tags: NO_TAGS,
    },
    Row {
        prefix: "ecdh-p384/wycheproof-spki",
        tags: NO_TAGS,
    },
    Row {
        prefix: "ecdh-p384/wycheproof-ecpoint",
        tags: NO_TAGS,
    },
    Row {
        prefix: "ecdh-p384/wycheproof-webcrypto",
        tags: NO_TAGS,
    },
    // Contract batteries.
    Row {
        prefix: "aes-gcm/contract",
        tags: NO_TAGS,
    },
    Row {
        prefix: "hmac-sha1/contract",
        tags: NO_TAGS,
    },
    Row {
        prefix: "hmac-sha2/contract",
        tags: NO_TAGS,
    },
    Row {
        prefix: "aes-cbc/contract",
        tags: NO_TAGS,
    },
    Row {
        prefix: "aes-ctr/contract",
        tags: NO_TAGS,
    },
    Row {
        prefix: "hkdf-sha2/contract",
        tags: NO_TAGS,
    },
    Row {
        prefix: "pbkdf2-sha2/contract",
        tags: NO_TAGS,
    },
    Row {
        prefix: "x25519/contract",
        tags: NO_TAGS,
    },
    Row {
        prefix: "ecdh/contract",
        tags: NO_TAGS,
    },
];

/// Generator rows added after the M1.6 cutover. `ROWS` is frozen with
/// the incumbent census fixture; every later row lands here instead,
/// pinned per-case by `census-postcutover.lock` (see `census_test`:
/// the fixture regenerates via the `#[ignore]`d regen test, and its
/// diff is the review surface, like a lockfile's). A new `#[case_row]`
/// prefix that lands in neither table fails the lockfile-partition
/// test.
pub const POST_CUTOVER_ROWS: &[Row] = &[
    Row {
        prefix: "ecdsa-p256-sha512/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "ecdsa-p384-sha512/wycheproof",
        tags: NO_TAGS,
    },
];

/// The planned cases under one row's prefix.
pub fn cases_under(prefix: &str) -> Vec<PlanCase> {
    let head = format!("{prefix}/");
    builder(prefix)
        .into_iter()
        .filter(|case| case.id.starts_with(&head))
        .collect()
}

/// Register one generator row: the `#[case_row]` entry point every row
/// in `lib.rs` delegates to. Under `rkyv-corpus`, vector rows take the
/// allocation-free fast path ([`register_row`]) over their per-row
/// archives; contract rows (table-driven, a dozen-odd cases each) keep
/// the [`PlanCase`] shape, whose costs are negligible at that count.
#[cfg(feature = "rkyv-corpus")]
pub fn register(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
    if rows::register_vector(registry, prefix, tags) {
        return;
    }
    for case in cases_under(prefix) {
        let name = component_test_sdk::CaseName::new(ArcStr::from(case.id))
            .unwrap_or_else(|e| panic!("invalid case id under `{prefix}`: {e}"));
        let run = case.run;
        registry.generated_named(
            prefix,
            tags,
            name,
            Box::new(move |_ctx| {
                let fut = run();
                Box::pin(async move { fut.await.map_err(Failure::Failed) })
            }),
        );
    }
}

/// Register one generator row (default/`preparsed` modes: the original
/// [`GeneratedCase`] path, costs unchanged — these modes exist for
/// measurement comparison).
#[cfg(not(feature = "rkyv-corpus"))]
pub fn register(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
    for case in generated(prefix) {
        registry.generated(prefix, tags, case);
    }
}

/// The generator-shaped view of a row: leaves (which may be
/// multi-segment: `tc375/whole`) plus verdict-shaped bodies.
#[cfg(not(feature = "rkyv-corpus"))]
pub fn generated(prefix: &str) -> Vec<GeneratedCase> {
    let head = format!("{prefix}/");
    cases_under(prefix)
        .into_iter()
        .map(|case| {
            let leaf = case
                .id
                .strip_prefix(&head)
                .expect("cases_under filtered by prefix")
                .to_string();
            let run = case.run;
            GeneratedCase::new(leaf, move |_ctx| {
                let fut = run();
                Box::pin(async move { fut.await.map_err(Failure::Failed) })
            })
        })
        .collect()
}

/// Run the incumbent probe named `ident` (its fn identifier in the
/// [`crate::probes`] table), as a `#[case]` body.
pub async fn probe(ident: &str) -> Verdict {
    let index = crate::probes::PROBES
        .iter()
        .position(|p| p.ident == ident)
        .unwrap_or_else(|| panic!("no probe named {ident}"));
    conformance_harness::run_probe(crate::probes::PROBES, index)
        .await
        .map_err(Failure::Failed)
}

/// Run the incumbent decline assertion for `feature`, as a `!feature`
/// decline case body: on a target declaring the feature missing, every
/// minting path must refuse it (`unsupported`).
pub async fn declined(feature: &'static str) -> Verdict {
    match crate::probes::run_declined(&[feature]).await {
        Ok(_detail) => Ok(()),
        Err(detail) => Err(Failure::Failed(detail)),
    }
}

// ------------------------------------------------------------- builders

/// The vector corpora the builders draw from. By default these are the
/// incumbent translate iterators (JSON parsed at registry-build time);
/// under the `preparsed` measurement feature, each is a postcard decode
/// of the same corpus serialized by build.rs — same values, same
/// call-per-row structure, no JSON parsing. (Under `rkyv-corpus` the
/// corpora are per-row archives instead — see [`rows`].)
#[cfg(not(feature = "rkyv-corpus"))]
mod corpus {
    #[cfg(not(feature = "preparsed"))]
    pub use crate::translate::{
        aead_cases, cbc_cases, ecdh_cases, hkdf_cases, hmac_cases, kw_cases, pbkdf2_cases,
        rsa_cases, sha2_cases, sig_cases, speccheck_cases, x25519_cases,
    };

    #[cfg(feature = "preparsed")]
    macro_rules! preparsed {
        ($(($fn_name:ident, $case:ty, $blob:literal),)*) => {
            $(pub fn $fn_name() -> Vec<$case> {
                postcard::from_bytes(include_bytes!(concat!(env!("OUT_DIR"), "/", $blob)))
                    .unwrap_or_else(|err| panic!("decoding {}: {err}", $blob))
            })*
        };
    }

    #[cfg(feature = "preparsed")]
    preparsed![
        (hkdf_cases, crate::translate::HkdfCase, "hkdf.bin"),
        (pbkdf2_cases, crate::translate::Pbkdf2Case, "pbkdf2.bin"),
        (hmac_cases, crate::translate::HmacCase, "hmac.bin"),
        (aead_cases, crate::translate::AeadCase, "aead.bin"),
        (cbc_cases, crate::translate::CbcCase, "cbc.bin"),
        (kw_cases, crate::translate::KwCase, "kw.bin"),
        (sha2_cases, crate::translate::Sha2Case, "sha2.bin"),
        (sig_cases, crate::translate::SigCase, "sig.bin"),
        (
            speccheck_cases,
            crate::translate::SpeccheckCase,
            "speccheck.bin"
        ),
        (rsa_cases, crate::translate::RsaCase, "rsa.bin"),
        (x25519_cases, crate::translate::X25519Case, "x25519.bin"),
        (ecdh_cases, crate::translate::EcdhCase, "ecdh.bin"),
    ];
}

/// The per-row archived corpora (`rkyv-corpus`): one `RowCorpus` blob
/// per vector generator row, written by build.rs with names pre-split
/// into shared prefix/leaf blobs (see `src/corpus.rs`). No runtime
/// prefix filtering, no shared-corpus multi-walk: each row includes
/// exactly its own cases.
#[cfg(feature = "rkyv-corpus")]
mod rows {
    use super::*;

    macro_rules! vector_rows {
        ($(($prefix:literal, $accessor:ident, $ty:ty, $blob:literal, $run:expr),)*) => {
            $(
                fn $accessor() -> &'static rkyv::Archived<crate::corpus::RowCorpus<$ty>> {
                    // include_bytes! only guarantees byte alignment; give
                    // the blob rkyv's 16-byte alignment via a wrapper
                    // static.
                    #[repr(C, align(16))]
                    struct Aligned<B: ?Sized>(B);
                    static BYTES: &Aligned<[u8]> =
                        &Aligned(*include_bytes!(concat!(env!("OUT_DIR"), "/", $blob)));
                    // SAFETY: unvalidated access is sound here because we
                    // control both ends — build.rs serialized these bytes
                    // with the same rkyv version and the very same
                    // `RowCorpus` type (shared source file) — and the
                    // consumer is a sandboxed test guest: a corrupted blob
                    // can at worst fail its own suite, not confuse a trust
                    // boundary.
                    unsafe {
                        rkyv::access_unchecked::<
                            rkyv::Archived<crate::corpus::RowCorpus<$ty>>,
                        >(&BYTES.0)
                    }
                }
            )*

            /// Register a vector row via the fast path; `false` if the
            /// prefix is not a vector row (i.e. a contract row).
            pub fn register_vector(
                registry: &mut Registry,
                prefix: &ArcStr,
                tags: &Tags,
            ) -> bool {
                match &**prefix {
                    $($prefix => {
                        super::register_row(registry, prefix, tags, $accessor(), $run);
                        true
                    })*
                    _ => false,
                }
            }

            /// The [`PlanCase`] view of a vector row (census-parity test
            /// and any non-fast-path consumer; old costs are fine here).
            pub fn plan_cases(prefix: &str) -> Option<Vec<PlanCase>> {
                match prefix {
                    $($prefix => Some(super::row_plan($accessor(), $run)),)*
                    _ => None,
                }
            }
        };
    }

    vector_rows![
        (
            "hkdf-sha1/wycheproof",
            hkdf_sha1_wycheproof,
            crate::translate::HkdfCase,
            "hkdf-sha1_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_hkdf_case(&c).await })
        ),
        (
            "hkdf-sha256/wycheproof",
            hkdf_sha256_wycheproof,
            crate::translate::HkdfCase,
            "hkdf-sha256_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_hkdf_case(&c).await })
        ),
        (
            "hkdf-sha384/wycheproof",
            hkdf_sha384_wycheproof,
            crate::translate::HkdfCase,
            "hkdf-sha384_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_hkdf_case(&c).await })
        ),
        (
            "hkdf-sha512/wycheproof",
            hkdf_sha512_wycheproof,
            crate::translate::HkdfCase,
            "hkdf-sha512_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_hkdf_case(&c).await })
        ),
        (
            "pbkdf2-sha1/wycheproof",
            pbkdf2_sha1_wycheproof,
            crate::translate::Pbkdf2Case,
            "pbkdf2-sha1_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_pbkdf2_case(&c).await })
        ),
        (
            "pbkdf2-sha256/wycheproof",
            pbkdf2_sha256_wycheproof,
            crate::translate::Pbkdf2Case,
            "pbkdf2-sha256_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_pbkdf2_case(&c).await })
        ),
        (
            "pbkdf2-sha384/wycheproof",
            pbkdf2_sha384_wycheproof,
            crate::translate::Pbkdf2Case,
            "pbkdf2-sha384_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_pbkdf2_case(&c).await })
        ),
        (
            "pbkdf2-sha512/wycheproof",
            pbkdf2_sha512_wycheproof,
            crate::translate::Pbkdf2Case,
            "pbkdf2-sha512_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_pbkdf2_case(&c).await })
        ),
        (
            "hmac-sha1/wycheproof",
            hmac_sha1_wycheproof,
            crate::translate::HmacCase,
            "hmac-sha1_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_hmac_case(&c).await })
        ),
        (
            "hmac-sha256/wycheproof",
            hmac_sha256_wycheproof,
            crate::translate::HmacCase,
            "hmac-sha256_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_hmac_case(&c).await })
        ),
        (
            "hmac-sha384/wycheproof",
            hmac_sha384_wycheproof,
            crate::translate::HmacCase,
            "hmac-sha384_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_hmac_case(&c).await })
        ),
        (
            "hmac-sha512/wycheproof",
            hmac_sha512_wycheproof,
            crate::translate::HmacCase,
            "hmac-sha512_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_hmac_case(&c).await })
        ),
        (
            "aes-gcm/wycheproof",
            aes_gcm_wycheproof,
            crate::translate::AeadCase,
            "aes-gcm_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_aead_case(&c).await })
        ),
        (
            "aes-cbc/wycheproof",
            aes_cbc_wycheproof,
            crate::translate::CbcCase,
            "aes-cbc_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_cbc_case(&c).await })
        ),
        (
            "aes-kw/wycheproof",
            aes_kw_wycheproof,
            crate::translate::KwCase,
            "aes-kw_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_kw_case(&c).await })
        ),
        (
            "sha2/nist-cavp",
            sha2_nist_cavp,
            crate::translate::Sha2Case,
            "sha2_nist-cavp.rkyv",
            |c| Box::pin(async move { vectors::run_sha2_case(&c).await })
        ),
        (
            "ed25519/wycheproof",
            ed25519_wycheproof,
            crate::translate::SigCase,
            "ed25519_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_sig_case(&c).await })
        ),
        (
            "ed25519/speccheck",
            ed25519_speccheck,
            crate::translate::SpeccheckCase,
            "ed25519_speccheck.rkyv",
            |c| Box::pin(async move { vectors::run_speccheck_case(&c).await })
        ),
        (
            "ecdsa-p256-sha256/wycheproof",
            ecdsa_p256_sha256_wycheproof,
            crate::translate::SigCase,
            "ecdsa-p256-sha256_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_sig_case(&c).await })
        ),
        (
            "ecdsa-p256-sha512/wycheproof",
            ecdsa_p256_sha512_wycheproof,
            crate::translate::SigCase,
            "ecdsa-p256-sha512_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_sig_case(&c).await })
        ),
        (
            "ecdsa-p384-sha384/wycheproof",
            ecdsa_p384_sha384_wycheproof,
            crate::translate::SigCase,
            "ecdsa-p384-sha384_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_sig_case(&c).await })
        ),
        (
            "ecdsa-p384-sha512/wycheproof",
            ecdsa_p384_sha512_wycheproof,
            crate::translate::SigCase,
            "ecdsa-p384-sha512_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_sig_case(&c).await })
        ),
        (
            "rsassa-pkcs1-v15-sha256-2048/wycheproof",
            rsassa_pkcs1_v15_sha256_2048_wycheproof,
            crate::translate::RsaCase,
            "rsassa-pkcs1-v15-sha256-2048_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_rsa_case(&c).await })
        ),
        (
            "rsassa-pkcs1-v15-sha384-2048/wycheproof",
            rsassa_pkcs1_v15_sha384_2048_wycheproof,
            crate::translate::RsaCase,
            "rsassa-pkcs1-v15-sha384-2048_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_rsa_case(&c).await })
        ),
        (
            "rsassa-pkcs1-v15-sha512-2048/wycheproof",
            rsassa_pkcs1_v15_sha512_2048_wycheproof,
            crate::translate::RsaCase,
            "rsassa-pkcs1-v15-sha512-2048_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_rsa_case(&c).await })
        ),
        (
            "rsassa-pkcs1-v15-sha256-3072/wycheproof",
            rsassa_pkcs1_v15_sha256_3072_wycheproof,
            crate::translate::RsaCase,
            "rsassa-pkcs1-v15-sha256-3072_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_rsa_case(&c).await })
        ),
        (
            "rsassa-pkcs1-v15-sha384-3072/wycheproof",
            rsassa_pkcs1_v15_sha384_3072_wycheproof,
            crate::translate::RsaCase,
            "rsassa-pkcs1-v15-sha384-3072_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_rsa_case(&c).await })
        ),
        (
            "rsassa-pkcs1-v15-sha512-3072/wycheproof",
            rsassa_pkcs1_v15_sha512_3072_wycheproof,
            crate::translate::RsaCase,
            "rsassa-pkcs1-v15-sha512-3072_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_rsa_case(&c).await })
        ),
        (
            "rsassa-pkcs1-v15-sha256-4096/wycheproof",
            rsassa_pkcs1_v15_sha256_4096_wycheproof,
            crate::translate::RsaCase,
            "rsassa-pkcs1-v15-sha256-4096_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_rsa_case(&c).await })
        ),
        (
            "rsassa-pkcs1-v15-sha384-4096/wycheproof",
            rsassa_pkcs1_v15_sha384_4096_wycheproof,
            crate::translate::RsaCase,
            "rsassa-pkcs1-v15-sha384-4096_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_rsa_case(&c).await })
        ),
        (
            "rsassa-pkcs1-v15-sha512-4096/wycheproof",
            rsassa_pkcs1_v15_sha512_4096_wycheproof,
            crate::translate::RsaCase,
            "rsassa-pkcs1-v15-sha512-4096_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_rsa_case(&c).await })
        ),
        (
            "rsassa-pkcs1-v15-sha256-8192/wycheproof",
            rsassa_pkcs1_v15_sha256_8192_wycheproof,
            crate::translate::RsaCase,
            "rsassa-pkcs1-v15-sha256-8192_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_rsa_case(&c).await })
        ),
        (
            "rsa-pss-sha256-2048-salt0/wycheproof",
            rsa_pss_sha256_2048_salt0_wycheproof,
            crate::translate::RsaCase,
            "rsa-pss-sha256-2048-salt0_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_rsa_case(&c).await })
        ),
        (
            "rsa-pss-sha256-2048-salt32/wycheproof",
            rsa_pss_sha256_2048_salt32_wycheproof,
            crate::translate::RsaCase,
            "rsa-pss-sha256-2048-salt32_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_rsa_case(&c).await })
        ),
        (
            "rsa-pss-sha384-2048-salt48/wycheproof",
            rsa_pss_sha384_2048_salt48_wycheproof,
            crate::translate::RsaCase,
            "rsa-pss-sha384-2048-salt48_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_rsa_case(&c).await })
        ),
        (
            "rsa-pss-sha256-3072-salt32/wycheproof",
            rsa_pss_sha256_3072_salt32_wycheproof,
            crate::translate::RsaCase,
            "rsa-pss-sha256-3072-salt32_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_rsa_case(&c).await })
        ),
        (
            "rsa-pss-sha256-4096-salt32/wycheproof",
            rsa_pss_sha256_4096_salt32_wycheproof,
            crate::translate::RsaCase,
            "rsa-pss-sha256-4096-salt32_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_rsa_case(&c).await })
        ),
        (
            "rsa-pss-sha384-4096-salt48/wycheproof",
            rsa_pss_sha384_4096_salt48_wycheproof,
            crate::translate::RsaCase,
            "rsa-pss-sha384-4096-salt48_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_rsa_case(&c).await })
        ),
        (
            "rsa-pss-sha512-4096-salt32/wycheproof",
            rsa_pss_sha512_4096_salt32_wycheproof,
            crate::translate::RsaCase,
            "rsa-pss-sha512-4096-salt32_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_rsa_case(&c).await })
        ),
        (
            "rsa-pss-sha512-4096-salt64/wycheproof",
            rsa_pss_sha512_4096_salt64_wycheproof,
            crate::translate::RsaCase,
            "rsa-pss-sha512-4096-salt64_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_rsa_case(&c).await })
        ),
        (
            "rsa-pss-sha256-2048-salt32/wycheproof-params",
            rsa_pss_sha256_2048_salt32_wycheproof_params,
            crate::translate::RsaCase,
            "rsa-pss-sha256-2048-salt32_wycheproof-params.rkyv",
            |c| Box::pin(async move { vectors::run_rsa_case(&c).await })
        ),
        (
            "x25519/wycheproof",
            x25519_wycheproof,
            crate::translate::X25519Case,
            "x25519_wycheproof.rkyv",
            |c| Box::pin(async move { vectors::run_x25519_case(&c).await })
        ),
        (
            "ecdh-p256/wycheproof-spki",
            ecdh_p256_wycheproof_spki,
            crate::translate::EcdhCase,
            "ecdh-p256_wycheproof-spki.rkyv",
            |c| Box::pin(async move { vectors::run_ecdh_case(&c).await })
        ),
        (
            "ecdh-p256/wycheproof-ecpoint",
            ecdh_p256_wycheproof_ecpoint,
            crate::translate::EcdhCase,
            "ecdh-p256_wycheproof-ecpoint.rkyv",
            |c| Box::pin(async move { vectors::run_ecdh_case(&c).await })
        ),
        (
            "ecdh-p256/wycheproof-webcrypto",
            ecdh_p256_wycheproof_webcrypto,
            crate::translate::EcdhCase,
            "ecdh-p256_wycheproof-webcrypto.rkyv",
            |c| Box::pin(async move { vectors::run_ecdh_case(&c).await })
        ),
        (
            "ecdh-p384/wycheproof-spki",
            ecdh_p384_wycheproof_spki,
            crate::translate::EcdhCase,
            "ecdh-p384_wycheproof-spki.rkyv",
            |c| Box::pin(async move { vectors::run_ecdh_case(&c).await })
        ),
        (
            "ecdh-p384/wycheproof-ecpoint",
            ecdh_p384_wycheproof_ecpoint,
            crate::translate::EcdhCase,
            "ecdh-p384_wycheproof-ecpoint.rkyv",
            |c| Box::pin(async move { vectors::run_ecdh_case(&c).await })
        ),
        (
            "ecdh-p384/wycheproof-webcrypto",
            ecdh_p384_wycheproof_webcrypto,
            crate::translate::EcdhCase,
            "ecdh-p384_wycheproof-webcrypto.rkyv",
            |c| Box::pin(async move { vectors::run_ecdh_case(&c).await })
        ),
    ];
}

/// The corpus slice a prefix draws from (the incumbent iterator + runner
/// pairing, exactly the incumbent `suites!` table's rows). Vector rows
/// come from [`vector_builder`] (mode-dependent); contract rows are
/// table-driven.
fn builder(prefix: &str) -> Vec<PlanCase> {
    if let Some(cases) = vector_builder(prefix) {
        return cases;
    }
    match prefix {
        "aes-gcm/contract" => contract_cases(
            contract::AEAD_FAMILIES,
            |f| f.areas().collect(),
            |f, a| f.case_id(a),
            |f| f.features,
            |f, a| Box::pin(contract::run(f, a)),
        ),
        "hmac-sha1/contract" | "hmac-sha2/contract" => contract_cases(
            contract::MAC_FAMILIES,
            |_| contract::MacArea::ALL.to_vec(),
            |f, a| f.case_id(a),
            |f| f.features,
            |f, a| Box::pin(contract::run_mac(f, a)),
        ),
        "aes-cbc/contract" | "aes-ctr/contract" => contract_cases(
            contract::CIPHER_FAMILIES,
            |_| contract::CipherArea::ALL.to_vec(),
            |f, a| f.case_id(a),
            |f| f.features,
            |f, a| Box::pin(contract::run_cipher(f, a)),
        ),
        "hkdf-sha2/contract" | "pbkdf2-sha2/contract" | "x25519/contract" | "ecdh/contract" => {
            contract_cases(
                contract::DERIVE_SOURCE_FAMILIES,
                |_| contract::DeriveArea::ALL.to_vec(),
                |f, a| f.case_id(a),
                |f| f.features,
                |f, a| Box::pin(contract::run_derive(f, a)),
            )
        }
        other => panic!("no builder for prefix {other}"),
    }
}

/// The vector rows, per corpus mode: `None` means "not a vector row".
/// Several prefixes share a corpus in the default/`preparsed` modes
/// (e.g. the four HMAC parameterizations live in one iterator);
/// `cases_under` filters by prefix. Under `rkyv-corpus` each row is its
/// own build-time archive, so no filtering happens at all.
#[cfg(not(feature = "rkyv-corpus"))]
fn vector_builder(prefix: &str) -> Option<Vec<PlanCase>> {
    Some(match prefix {
        p if p.starts_with("hkdf-") && p.ends_with("/wycheproof") => {
            vector_cases(corpus::hkdf_cases(), |c| {
                Box::pin(async move { vectors::run_hkdf_case(&c).await })
            })
        }
        p if p.starts_with("pbkdf2-") && p.ends_with("/wycheproof") => {
            vector_cases(corpus::pbkdf2_cases(), |c| {
                Box::pin(async move { vectors::run_pbkdf2_case(&c).await })
            })
        }
        p if p.starts_with("hmac-") && p.ends_with("/wycheproof") => {
            vector_cases(corpus::hmac_cases(), |c| {
                Box::pin(async move { vectors::run_hmac_case(&c).await })
            })
        }
        "aes-gcm/wycheproof" => vector_cases(corpus::aead_cases(), |c| {
            Box::pin(async move { vectors::run_aead_case(&c).await })
        }),
        "aes-cbc/wycheproof" => vector_cases(corpus::cbc_cases(), |c| {
            Box::pin(async move { vectors::run_cbc_case(&c).await })
        }),
        "aes-kw/wycheproof" => vector_cases(corpus::kw_cases(), |c| {
            Box::pin(async move { vectors::run_kw_case(&c).await })
        }),
        "sha2/nist-cavp" => vector_cases(corpus::sha2_cases(), |c| {
            Box::pin(async move { vectors::run_sha2_case(&c).await })
        }),
        "ed25519/wycheproof"
        | "ecdsa-p256-sha256/wycheproof"
        | "ecdsa-p256-sha512/wycheproof"
        | "ecdsa-p384-sha384/wycheproof"
        | "ecdsa-p384-sha512/wycheproof" => vector_cases(corpus::sig_cases(), |c| {
            Box::pin(async move { vectors::run_sig_case(&c).await })
        }),
        "ed25519/speccheck" => vector_cases(corpus::speccheck_cases(), |c| {
            Box::pin(async move { vectors::run_speccheck_case(&c).await })
        }),
        p if p.starts_with("rsassa-pkcs1-v15-") || p.starts_with("rsa-pss-") => {
            vector_cases(corpus::rsa_cases(), |c| {
                Box::pin(async move { vectors::run_rsa_case(&c).await })
            })
        }
        "x25519/wycheproof" => vector_cases(corpus::x25519_cases(), |c| {
            Box::pin(async move { vectors::run_x25519_case(&c).await })
        }),
        p if p.starts_with("ecdh-p") => vector_cases(corpus::ecdh_cases(), |c| {
            Box::pin(async move { vectors::run_ecdh_case(&c).await })
        }),
        _ => return None,
    })
}

#[cfg(feature = "rkyv-corpus")]
fn vector_builder(prefix: &str) -> Option<Vec<PlanCase>> {
    rows::plan_cases(prefix)
}

#[cfg(not(feature = "rkyv-corpus"))]
fn vector_cases<T: VectorCase + 'static>(
    cases: Vec<T>,
    run: fn(Rc<T>) -> LocalBoxFuture<'static, Result<(), String>>,
) -> Vec<PlanCase> {
    cases
        .into_iter()
        .map(|case| {
            let case = Rc::new(case);
            PlanCase {
                id: case.case_id(),
                features: case.features(),
                run: Box::new(move || run(case.clone())),
            }
        })
        .collect()
}

/// The zero-alloc registration fast path over one row's archive: one
/// `ArcStr` per shared name blob (two allocations per row), then per
/// case a `CaseName` of two refcounted substrings and a single boxed
/// closure. The per-case rkyv deserialize still happens when the case
/// *runs*, exactly as before.
#[cfg(feature = "rkyv-corpus")]
fn register_row<T>(
    registry: &mut Registry,
    row_prefix: &ArcStr,
    tags: &Tags,
    corpus: &'static rkyv::Archived<crate::corpus::RowCorpus<T>>,
    run: fn(Rc<T>) -> LocalBoxFuture<'static, Result<(), String>>,
) where
    T: rkyv::Archive + 'static,
    T::Archived: rkyv::Deserialize<T, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>>,
{
    let prefixes = ArcStr::from(corpus.prefixes_blob.as_str());
    let leaves = ArcStr::from(corpus.leaves_blob.as_str());
    for ((case, pr), lr) in corpus
        .cases
        .iter()
        .zip(corpus.prefix_ranges.iter())
        .zip(corpus.leaf_ranges.iter())
    {
        let name = component_test_sdk::CaseName::from_parts(
            prefixes.substr(pr.0.to_native() as usize..pr.1.to_native() as usize),
            leaves.substr(lr.0.to_native() as usize..lr.1.to_native() as usize),
        )
        .unwrap_or_else(|e| panic!("invalid archived name under `{row_prefix}`: {e}"));
        registry.generated_named(
            row_prefix,
            tags,
            name,
            Box::new(move |_ctx| {
                Box::pin(async move {
                    let case = rkyv::deserialize::<T, rkyv::rancor::Error>(case)
                        .expect("deserializing an archived case we serialized ourselves");
                    run(Rc::new(case)).await.map_err(Failure::Failed)
                })
            }),
        );
    }
}

/// The [`PlanCase`] view of one row's archive (census-parity test and
/// slow-path consumers; id assembly allocates — fine off the hot path).
#[cfg(feature = "rkyv-corpus")]
fn row_plan<T>(
    corpus: &'static rkyv::Archived<crate::corpus::RowCorpus<T>>,
    run: fn(Rc<T>) -> LocalBoxFuture<'static, Result<(), String>>,
) -> Vec<PlanCase>
where
    T: rkyv::Archive + 'static,
    T::Archived: rkyv::Deserialize<T, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>>,
{
    corpus
        .cases
        .iter()
        .zip(corpus.prefix_ranges.iter())
        .zip(corpus.leaf_ranges.iter())
        .map(|((case, pr), lr)| {
            let prefix =
                &corpus.prefixes_blob[pr.0.to_native() as usize..pr.1.to_native() as usize];
            let leaf = &corpus.leaves_blob[lr.0.to_native() as usize..lr.1.to_native() as usize];
            PlanCase {
                id: format!("{prefix}/{leaf}"),
                features: crate::corpus::FEATURE_SETS[corpus.features as usize],
                run: Box::new(move || {
                    let case = rkyv::deserialize::<T, rkyv::rancor::Error>(case)
                        .expect("deserializing an archived case we serialized ourselves");
                    run(Rc::new(case))
                }),
            }
        })
        .collect()
}

fn contract_cases<F: 'static, A: Copy + 'static>(
    families: &'static [F],
    areas: fn(&'static F) -> Vec<A>,
    id: fn(&'static F, A) -> String,
    features: fn(&'static F) -> &'static [&'static str],
    run: fn(&'static F, A) -> LocalBoxFuture<'static, Result<(), String>>,
) -> Vec<PlanCase> {
    let mut cases = Vec::new();
    for family in families {
        for area in areas(family) {
            cases.push(PlanCase {
                id: id(family, area),
                features: features(family),
                run: Box::new(move || run(family, area)),
            });
        }
    }
    cases
}

/// The features exercised by decline cases, re-exported for `lib.rs`.
pub mod features {
    pub use conformance_harness::FEATURE_SHA1_CHECKED;
}

// Referenced so the constant isn't unused in corpus modes where no row
// carries it (sha1-checked is probe+decline only).
const _: &str = FEATURE_SHA1_CHECKED;
