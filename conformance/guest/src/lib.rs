//! `conformance-guest`: the shared conformance component.
//!
//! One guest binary carries the whole suite — the Wycheproof-derived vector
//! cases (translated per `conformance/vectors/README.md` in [`translate`])
//! plus the hand-written API-contract [`probes`] — as self-describing
//! `test-case` resources. Each case declares the [`features`] it exercises;
//! `all(missing)` materializes the suite for a target missing those
//! features, and a case whose feature is missing asserts the correct
//! decline (reporting `skipped`) instead of exercising its subject.
//! Expectation mismatches are reported as `fail`, never traps, so a run
//! always yields an outcome per case.
//!
//! [`features`]: exports::conformance::webcrypto::tests::GuestTestCase::features

wit_bindgen::generate!({
    path: "wit",
    world: "conformance-guest",
    generate_all,
});

mod probes;
mod translate;
mod util;
mod vectors;

use std::collections::BTreeSet;

use exports::conformance::webcrypto::tests::{Guest, GuestTestCase, Outcome, TestCase};
use translate::{
    ChaChaCase, GcmCase, HmacCase, InternalNonceCase, Sha2Case, SigCase, SpeccheckCase,
};

/// The `chacha20-poly1305` feature: both ChaCha20-Poly1305 constructions
/// and the XChaCha internal-nonce minting interface. Browser WebCrypto
/// implements none of them, so the jco targets declare it missing.
pub const FEATURE_CHACHA: &str = "chacha20-poly1305";

/// The `deterministic-ecdsa` feature: RFC 6979 deterministic ECDSA
/// signatures (exercised only by the host-only signing suite;
/// declared here so every guest validates the same feature names).
pub const FEATURE_DETERMINISTIC_ECDSA: &str = "deterministic-ecdsa";

/// The `ecdsa-sign` feature: the `ecdsa-sign` minting interface itself.
/// Nothing in this suite is tagged with it — the signing suite's world
/// *imports* the interface, so a target missing the feature (the composed
/// target: class D) is excluded from that suite structurally rather than
/// case by case. Declared here so every guest validates the same names.
pub const FEATURE_ECDSA_SIGN: &str = "ecdsa-sign";

/// Every feature name a target may declare missing. `all` traps on names
/// outside this set, so a misspelled declaration is a harness bug rather
/// than a silently-inert one.
pub const KNOWN_FEATURES: &[&str] = &[
    FEATURE_CHACHA,
    FEATURE_DETERMINISTIC_ECDSA,
    FEATURE_ECDSA_SIGN,
];

/// Validate a `missing-features` declaration against [`KNOWN_FEATURES`],
/// returning the set. Panics (traps) on unknown names.
pub fn missing_set(missing: &[String]) -> BTreeSet<&str> {
    let mut set = BTreeSet::new();
    for feature in missing {
        assert!(
            KNOWN_FEATURES.contains(&feature.as_str()),
            "unknown feature {feature:?} in the missing declaration (known: {KNOWN_FEATURES:?})"
        );
        set.insert(feature.as_str());
    }
    set
}

struct Component;

/// One materialized conformance case: its stable name, the features it
/// exercises, whether the target provides them, and the data to run it.
pub struct Case {
    name: String,
    features: &'static [&'static str],
    /// Whether every feature this case exercises is provided by the target
    /// (i.e. none is declared missing). When false, `run` asserts the
    /// correct decline and reports `skipped`.
    provided: bool,
    kind: CaseKind,
}

enum CaseKind {
    Hmac(HmacCase),
    Gcm(GcmCase),
    ChaCha(ChaChaCase),
    InternalNonce(InternalNonceCase),
    Sha2(Sha2Case),
    Sig(SigCase),
    Speccheck(SpeccheckCase),
    Probe(usize),
}

/// Materialize one case as an exported `test-case` resource.
fn materialize(
    name: String,
    features: &'static [&'static str],
    missing: &BTreeSet<&str>,
    kind: CaseKind,
) -> TestCase {
    TestCase::new(Case {
        name,
        features,
        provided: features.iter().all(|feature| !missing.contains(feature)),
        kind,
    })
}

impl GuestTestCase for Case {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn features(&self) -> Vec<String> {
        self.features.iter().map(|s| s.to_string()).collect()
    }

    async fn run(&self) -> Outcome {
        if self.provided {
            let outcome = match &self.kind {
                CaseKind::Hmac(case) => vectors::run_hmac_case(case).await,
                CaseKind::Gcm(case) => vectors::run_gcm_case(case).await,
                CaseKind::ChaCha(case) => vectors::run_chacha_case(case).await,
                CaseKind::InternalNonce(case) => vectors::run_internal_nonce_case(case).await,
                CaseKind::Sha2(case) => vectors::run_sha2_case(case).await,
                CaseKind::Sig(case) => vectors::run_sig_case(case).await,
                CaseKind::Speccheck(case) => vectors::run_speccheck_case(case).await,
                CaseKind::Probe(index) => probes::run_one(*index).await,
            };
            match outcome {
                Ok(()) => Outcome::Pass,
                Err(detail) => Outcome::Fail(detail),
            }
        } else {
            // The target declares this case's feature missing. The
            // feature-tagged *probes* assert the correct decline on every
            // minting path (the two-way guarantee that a target cannot
            // serve a feature it declares missing); vector cases skip
            // without re-asserting it thousands of times.
            let asserted = match &self.kind {
                CaseKind::Probe(index) => probes::run_declined(*index).await,
                _ => Ok(format!(
                    "feature {} declared missing by the target",
                    self.features.join("+")
                )),
            };
            match asserted {
                Ok(detail) => Outcome::Skipped(detail),
                Err(detail) => Outcome::Fail(detail),
            }
        }
    }
}

impl Guest for Component {
    type TestCase = Case;

    fn all(missing_features: Vec<String>) -> Vec<TestCase> {
        let missing = missing_set(&missing_features);
        let mut cases = Vec::new();
        for case in translate::hmac_cases() {
            let name = format!(
                "{}/wycheproof/tc{}/{}",
                case.alg.name(),
                case.tc_id,
                case.schedule.name()
            );
            cases.push(materialize(name, &[], &missing, CaseKind::Hmac(case)));
        }
        for case in translate::gcm_cases() {
            let name = format!(
                "aes-gcm/wycheproof/tc{}/{}",
                case.tc_id,
                case.schedule.name()
            );
            cases.push(materialize(name, &[], &missing, CaseKind::Gcm(case)));
        }
        for case in translate::chacha_cases() {
            let name = format!(
                "{}/wycheproof/tc{}/{}",
                case.alg.name(),
                case.tc_id,
                case.schedule.name()
            );
            cases.push(materialize(
                name,
                &[FEATURE_CHACHA],
                &missing,
                CaseKind::ChaCha(case),
            ));
        }
        for case in translate::internal_nonce_cases() {
            let name = format!(
                "{}/wycheproof/tc{}/{}",
                case.alg.name(),
                case.tc_id,
                case.schedule.name()
            );
            let features: &'static [&'static str] = match case.alg {
                translate::InternalNonceAlg::AesGcm => &[],
                translate::InternalNonceAlg::XChaCha20Poly1305 => &[FEATURE_CHACHA],
            };
            cases.push(materialize(
                name,
                features,
                &missing,
                CaseKind::InternalNonce(case),
            ));
        }
        for case in translate::sha2_cases() {
            let name = format!(
                "sha2/nist-cavp/{}-len{}/{}",
                case.alg.name(),
                case.len_bits,
                case.schedule.name()
            );
            cases.push(materialize(name, &[], &missing, CaseKind::Sha2(case)));
        }
        for case in translate::sig_cases() {
            let name = format!(
                "{}/wycheproof/tc{}/{}",
                case.alg.name(),
                case.tc_id,
                case.schedule.name()
            );
            cases.push(materialize(name, &[], &missing, CaseKind::Sig(case)));
        }
        for case in translate::speccheck_cases() {
            let name = format!(
                "ed25519/speccheck/tc{}/{}",
                case.tc_id,
                case.schedule.name()
            );
            cases.push(materialize(name, &[], &missing, CaseKind::Speccheck(case)));
        }
        for (index, probe) in probes::PROBES.iter().enumerate() {
            cases.push(materialize(
                format!("probe/{}", probe.name),
                probe.features,
                &missing,
                CaseKind::Probe(index),
            ));
        }
        cases
    }
}

export!(Component);
