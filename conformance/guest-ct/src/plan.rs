//! The case plan: the single, natively-testable source of truth mapping
//! the incumbent corpus (translate/contract/probes, reused wholesale from
//! `conformance-guest`) onto the `#[suite]` generator rows.
//!
//! Every generator in `lib.rs` delegates here ([`generated`]), and the
//! native census-parity test (`census_test`) expands the same [`ROWS`]
//! table, so the inventory the suite registers and the inventory the test
//! asserts cannot drift from each other. Case *bodies* are the incumbent
//! runners, untouched; only naming/tagging/registration is new.

use std::rc::Rc;

use component_test_sdk::{Failure, GeneratedCase, Verdict};
use conformance_harness::{FEATURE_CHACHA, FEATURE_SHA1_CHECKED, FEATURE_XCHACHA};
use futures::future::LocalBoxFuture;

use crate::translate::VectorCase;
use crate::{contract, translate, vectors};

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
const CHACHA: &[&str] = &[FEATURE_CHACHA];
const XCHACHA: &[&str] = &[FEATURE_XCHACHA];

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
        prefix: "chacha20-poly1305/wycheproof",
        tags: CHACHA,
    },
    Row {
        prefix: "xchacha20-poly1305/wycheproof",
        tags: XCHACHA,
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
        prefix: "aes-gcm-internal-nonce/wycheproof",
        tags: NO_TAGS,
    },
    Row {
        prefix: "xchacha20-poly1305-internal-nonce/wycheproof",
        tags: XCHACHA,
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
        prefix: "chacha20-poly1305/contract",
        tags: CHACHA,
    },
    Row {
        prefix: "xchacha20-poly1305/contract",
        tags: XCHACHA,
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
        prefix: "aes-gcm-internal-nonce/contract",
        tags: NO_TAGS,
    },
    Row {
        prefix: "xchacha20-poly1305-internal-nonce/contract",
        tags: XCHACHA,
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

/// The planned cases under one row's prefix.
pub fn cases_under(prefix: &str) -> Vec<PlanCase> {
    let head = format!("{prefix}/");
    builder(prefix)
        .into_iter()
        .filter(|case| case.id.starts_with(&head))
        .collect()
}

/// The generator-shaped view of a row: leaves (which may be
/// multi-segment: `tc375/whole`) plus verdict-shaped bodies.
pub fn generated<Ctx>(prefix: &'static str) -> Vec<GeneratedCase<Ctx>> {
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
            GeneratedCase::new(leaf, move |_ctx: &Ctx| {
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

/// The corpus slice a prefix draws from (the incumbent iterator + runner
/// pairing, exactly the incumbent `suites!` table's rows). Several
/// prefixes share a builder (e.g. the four HMAC parameterizations live in
/// one iterator); `cases_under` filters by prefix.
fn builder(prefix: &str) -> Vec<PlanCase> {
    match prefix {
        p if p.starts_with("hkdf-") && p.ends_with("/wycheproof") => {
            vector_cases(translate::hkdf_cases(), |c| {
                Box::pin(async move { vectors::run_hkdf_case(&c).await })
            })
        }
        p if p.starts_with("pbkdf2-") && p.ends_with("/wycheproof") => {
            vector_cases(translate::pbkdf2_cases(), |c| {
                Box::pin(async move { vectors::run_pbkdf2_case(&c).await })
            })
        }
        p if p.starts_with("hmac-") && p.ends_with("/wycheproof") => {
            vector_cases(translate::hmac_cases(), |c| {
                Box::pin(async move { vectors::run_hmac_case(&c).await })
            })
        }
        "aes-gcm/wycheproof" | "chacha20-poly1305/wycheproof" | "xchacha20-poly1305/wycheproof" => {
            vector_cases(translate::aead_cases(), |c| {
                Box::pin(async move { vectors::run_aead_case(&c).await })
            })
        }
        "aes-cbc/wycheproof" => vector_cases(translate::cbc_cases(), |c| {
            Box::pin(async move { vectors::run_cbc_case(&c).await })
        }),
        "aes-kw/wycheproof" => vector_cases(translate::kw_cases(), |c| {
            Box::pin(async move { vectors::run_kw_case(&c).await })
        }),
        "aes-gcm-internal-nonce/wycheproof" | "xchacha20-poly1305-internal-nonce/wycheproof" => {
            vector_cases(translate::internal_nonce_cases(), |c| {
                Box::pin(async move { vectors::run_internal_nonce_case(&c).await })
            })
        }
        "sha2/nist-cavp" => vector_cases(translate::sha2_cases(), |c| {
            Box::pin(async move { vectors::run_sha2_case(&c).await })
        }),
        "ed25519/wycheproof" | "ecdsa-p256-sha256/wycheproof" | "ecdsa-p384-sha384/wycheproof" => {
            vector_cases(translate::sig_cases(), |c| {
                Box::pin(async move { vectors::run_sig_case(&c).await })
            })
        }
        "ed25519/speccheck" => vector_cases(translate::speccheck_cases(), |c| {
            Box::pin(async move { vectors::run_speccheck_case(&c).await })
        }),
        "x25519/wycheproof" => vector_cases(translate::x25519_cases(), |c| {
            Box::pin(async move { vectors::run_x25519_case(&c).await })
        }),
        p if p.starts_with("ecdh-p") => vector_cases(translate::ecdh_cases(), |c| {
            Box::pin(async move { vectors::run_ecdh_case(&c).await })
        }),
        "aes-gcm/contract" | "chacha20-poly1305/contract" | "xchacha20-poly1305/contract" => {
            contract_cases(
                contract::AEAD_FAMILIES,
                |f| f.areas().collect(),
                |f, a| f.case_id(a),
                |f| f.features,
                |f, a| Box::pin(contract::run(f, a)),
            )
        }
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
        "aes-gcm-internal-nonce/contract" | "xchacha20-poly1305-internal-nonce/contract" => {
            contract_cases(
                contract::INTERNAL_NONCE_FAMILIES,
                |f| f.areas().collect(),
                |f, a| f.case_id(a),
                |f| f.features,
                |f, a| Box::pin(contract::run_internal_nonce(f, a)),
            )
        }
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
    pub use conformance_harness::{FEATURE_CHACHA, FEATURE_SHA1_CHECKED, FEATURE_XCHACHA};
}

// Referenced so the constant isn't unused when only CHACHA/XCHACHA rows
// exist (sha1-checked is probe+decline only).
const _: &str = FEATURE_SHA1_CHECKED;
