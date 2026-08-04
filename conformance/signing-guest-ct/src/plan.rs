//! The case plan for the signing suite: the single, natively-testable
//! source of truth mapping the incumbent corpus (the RSA vector modules
//! plus the probe table, reused wholesale from
//! `conformance-signing-guest`) onto the `#[suite]` generator rows,
//! exactly as `conformance-guest-ct`'s `plan` does for the shared suite.
//!
//! Every `#[case_row]` in `lib.rs` delegates here ([`register`]), and the
//! native census-parity test (`census_test`) expands the same [`ROWS`]
//! table, so the inventory the suite registers and the inventory the test
//! asserts cannot drift from each other. Case *bodies* are the incumbent
//! runners, untouched; only naming/tagging/registration is new.

use std::cell::OnceCell;
use std::rc::Rc;

use component_test_sdk::{ArcStr, Failure, GeneratedCase, Registry, Tags, Verdict};
use conformance_harness::{FEATURE_RSA_OAEP_DECRYPT, FEATURE_RSA_SIGN};
use futures::future::LocalBoxFuture;

use crate::{rsa_oaep, rsa_sign};

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

const RSA_SIGN: &[&str] = &[FEATURE_RSA_SIGN];
const RSA_OAEP_DECRYPT: &[&str] = &[FEATURE_RSA_OAEP_DECRYPT];

/// Every generator row, mirroring the census's two-segment groups: the
/// RSASSA-PKCS1-v1_5 sig-gen parameterizations, then the RSA-OAEP
/// decryption parameterizations (the `wycheproof` per-parameter files,
/// then the `wycheproof-misc` groups of the collected misc file).
pub const ROWS: &[Row] = &[
    Row {
        prefix: "rsassa-pkcs1-v15-sha256-2048/wycheproof-sig-gen",
        tags: RSA_SIGN,
    },
    Row {
        prefix: "rsassa-pkcs1-v15-sha384-2048/wycheproof-sig-gen",
        tags: RSA_SIGN,
    },
    Row {
        prefix: "rsassa-pkcs1-v15-sha512-2048/wycheproof-sig-gen",
        tags: RSA_SIGN,
    },
    Row {
        prefix: "rsassa-pkcs1-v15-sha256-3072/wycheproof-sig-gen",
        tags: RSA_SIGN,
    },
    Row {
        prefix: "rsassa-pkcs1-v15-sha384-3072/wycheproof-sig-gen",
        tags: RSA_SIGN,
    },
    Row {
        prefix: "rsassa-pkcs1-v15-sha512-3072/wycheproof-sig-gen",
        tags: RSA_SIGN,
    },
    Row {
        prefix: "rsassa-pkcs1-v15-sha256-4096/wycheproof-sig-gen",
        tags: RSA_SIGN,
    },
    Row {
        prefix: "rsassa-pkcs1-v15-sha384-4096/wycheproof-sig-gen",
        tags: RSA_SIGN,
    },
    Row {
        prefix: "rsassa-pkcs1-v15-sha512-4096/wycheproof-sig-gen",
        tags: RSA_SIGN,
    },
    Row {
        prefix: "rsa-oaep-sha256-2048/wycheproof",
        tags: RSA_OAEP_DECRYPT,
    },
    Row {
        prefix: "rsa-oaep-sha384-2048/wycheproof",
        tags: RSA_OAEP_DECRYPT,
    },
    Row {
        prefix: "rsa-oaep-sha512-2048/wycheproof",
        tags: RSA_OAEP_DECRYPT,
    },
    Row {
        prefix: "rsa-oaep-sha256-3072/wycheproof",
        tags: RSA_OAEP_DECRYPT,
    },
    Row {
        prefix: "rsa-oaep-sha512-3072/wycheproof",
        tags: RSA_OAEP_DECRYPT,
    },
    Row {
        prefix: "rsa-oaep-sha256-4096/wycheproof",
        tags: RSA_OAEP_DECRYPT,
    },
    Row {
        prefix: "rsa-oaep-sha512-4096/wycheproof",
        tags: RSA_OAEP_DECRYPT,
    },
    Row {
        prefix: "rsa-oaep-sha256-2048/wycheproof-misc",
        tags: RSA_OAEP_DECRYPT,
    },
    Row {
        prefix: "rsa-oaep-sha384-2048/wycheproof-misc",
        tags: RSA_OAEP_DECRYPT,
    },
    Row {
        prefix: "rsa-oaep-sha512-2048/wycheproof-misc",
        tags: RSA_OAEP_DECRYPT,
    },
    Row {
        prefix: "rsa-oaep-sha256-3072/wycheproof-misc",
        tags: RSA_OAEP_DECRYPT,
    },
    Row {
        prefix: "rsa-oaep-sha384-3072/wycheproof-misc",
        tags: RSA_OAEP_DECRYPT,
    },
    Row {
        prefix: "rsa-oaep-sha512-3072/wycheproof-misc",
        tags: RSA_OAEP_DECRYPT,
    },
    Row {
        prefix: "rsa-oaep-sha256-4096/wycheproof-misc",
        tags: RSA_OAEP_DECRYPT,
    },
    Row {
        prefix: "rsa-oaep-sha384-4096/wycheproof-misc",
        tags: RSA_OAEP_DECRYPT,
    },
    Row {
        prefix: "rsa-oaep-sha512-4096/wycheproof-misc",
        tags: RSA_OAEP_DECRYPT,
    },
    Row {
        prefix: "rsa-oaep-sha256-8192/wycheproof-misc",
        tags: RSA_OAEP_DECRYPT,
    },
    Row {
        prefix: "rsa-oaep-sha384-8192/wycheproof-misc",
        tags: RSA_OAEP_DECRYPT,
    },
    Row {
        prefix: "rsa-oaep-sha512-8192/wycheproof-misc",
        tags: RSA_OAEP_DECRYPT,
    },
    Row {
        prefix: "rsa-oaep-sha256-2688/wycheproof-misc",
        tags: RSA_OAEP_DECRYPT,
    },
    Row {
        prefix: "rsa-oaep-sha256-4032/wycheproof-misc",
        tags: RSA_OAEP_DECRYPT,
    },
    Row {
        prefix: "rsa-oaep-sha384-3104/wycheproof-misc",
        tags: RSA_OAEP_DECRYPT,
    },
];

thread_local! {
    /// The translated corpora, parsed once per instance (31 generator
    /// rows share them; without the cache each row would re-parse the
    /// vector JSON).
    static SIGN_CASES: OnceCell<Rc<Vec<Rc<rsa_sign::RsaSignCase>>>> = const { OnceCell::new() };
    static OAEP_CASES: OnceCell<Rc<Vec<Rc<rsa_oaep::RsaOaepCase>>>> = const { OnceCell::new() };
}

fn sign_cases() -> Rc<Vec<Rc<rsa_sign::RsaSignCase>>> {
    SIGN_CASES.with(|c| {
        c.get_or_init(|| Rc::new(rsa_sign::cases().into_iter().map(Rc::new).collect()))
            .clone()
    })
}

fn oaep_cases() -> Rc<Vec<Rc<rsa_oaep::RsaOaepCase>>> {
    OAEP_CASES.with(|c| {
        c.get_or_init(|| Rc::new(rsa_oaep::cases().into_iter().map(Rc::new).collect()))
            .clone()
    })
}

/// The planned cases under one row's prefix.
pub fn cases_under(prefix: &str) -> Vec<PlanCase> {
    let head = format!("{prefix}/");
    let mut cases: Vec<PlanCase> = Vec::new();
    if prefix.starts_with("rsassa-pkcs1-v15-") {
        for case in sign_cases().iter() {
            let id = case.case_id();
            if id.starts_with(&head) {
                let case = case.clone();
                cases.push(PlanCase {
                    id,
                    features: case.features(),
                    run: Box::new(move || {
                        let case = case.clone();
                        Box::pin(async move { rsa_sign::run_case(&case).await })
                    }),
                });
            }
        }
    } else {
        for case in oaep_cases().iter() {
            let id = case.case_id();
            if id.starts_with(&head) {
                let case = case.clone();
                cases.push(PlanCase {
                    id,
                    features: case.features(),
                    run: Box::new(move || {
                        let case = case.clone();
                        Box::pin(async move { rsa_oaep::run_case(&case).await })
                    }),
                });
            }
        }
    }
    cases
}

/// Register one generator row: the `#[case_row]` entry point every row
/// in `lib.rs` delegates to.
pub fn register(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
    let head = format!("{prefix}/");
    for case in cases_under(prefix) {
        let leaf = case
            .id
            .strip_prefix(&head)
            .expect("cases_under filtered by prefix")
            .to_string();
        let run = case.run;
        registry.generated(
            prefix,
            tags,
            GeneratedCase::new(leaf, move |_ctx| {
                let fut = run();
                Box::pin(async move { fut.await.map_err(Failure::Failed) })
            }),
        );
    }
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
    let asserted = if feature == FEATURE_RSA_SIGN {
        rsa_sign::minting_declined().await
    } else if feature == FEATURE_RSA_OAEP_DECRYPT {
        rsa_oaep::minting_declined().await
    } else {
        Err(format!("no decline assertion for feature {feature}"))
    };
    match asserted {
        Ok(_detail) => Ok(()),
        Err(detail) => Err(Failure::Failed(detail)),
    }
}

/// The features exercised by decline cases, re-exported for `lib.rs`.
pub mod features {
    pub use conformance_harness::{FEATURE_RSA_OAEP_DECRYPT, FEATURE_RSA_SIGN};
}
