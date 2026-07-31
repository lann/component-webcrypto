//! `conformance-guest`: the shared conformance component.
//!
//! One guest binary carries the whole suite — the Wycheproof-derived vector
//! cases (translated per `conformance/vectors/README.md` in [`translate`]),
//! the per-kind [`contract`] batteries (the standard cases every minting
//! family inherits from one table row), and the hand-written API-contract
//! [`probes`] — as self-describing `test-case` resources. Each case declares the [`features`] it exercises;
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

mod contract;
mod mint;
mod probes;
mod translate;
mod vectors;

use std::collections::BTreeSet;

use conformance_harness::KNOWN_FEATURES;
use exports::conformance::webcrypto::tests::{Guest, GuestTestCase, Outcome, TestCase};
use translate::{AeadCase, HmacCase, InternalNonceCase, Sha2Case, SigCase, SpeccheckCase};

/// Validate a `missing-features` declaration against
/// [`KNOWN_FEATURES`], returning the set. Panics (traps) on unknown names.
pub fn missing_set(missing: &[String]) -> BTreeSet<&str> {
    conformance_harness::missing_features(missing, KNOWN_FEATURES)
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
    Aead(AeadCase),
    InternalNonce(InternalNonceCase),
    Sha2(Sha2Case),
    Sig(SigCase),
    Speccheck(SpeccheckCase),
    Contract(&'static contract::AeadFamily, contract::AeadArea),
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
        provided: conformance_harness::provided(features, missing),
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
                CaseKind::Aead(case) => vectors::run_aead_case(case).await,
                CaseKind::InternalNonce(case) => vectors::run_internal_nonce_case(case).await,
                CaseKind::Sha2(case) => vectors::run_sha2_case(case).await,
                CaseKind::Sig(case) => vectors::run_sig_case(case).await,
                CaseKind::Speccheck(case) => vectors::run_speccheck_case(case).await,
                CaseKind::Contract(family, area) => contract::run(family, *area).await,
                CaseKind::Probe(index) => {
                    conformance_harness::run_probe(probes::PROBES, *index).await
                }
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
                CaseKind::Contract(..) | CaseKind::Probe(_) => {
                    probes::run_declined(self.features).await
                }
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
            cases.push(materialize(
                case.case_id(),
                case.features(),
                &missing,
                CaseKind::Hmac(case),
            ));
        }
        for case in translate::aead_cases() {
            cases.push(materialize(
                case.case_id(),
                case.features(),
                &missing,
                CaseKind::Aead(case),
            ));
        }
        for case in translate::internal_nonce_cases() {
            cases.push(materialize(
                case.case_id(),
                case.features(),
                &missing,
                CaseKind::InternalNonce(case),
            ));
        }
        for case in translate::sha2_cases() {
            cases.push(materialize(
                case.case_id(),
                case.features(),
                &missing,
                CaseKind::Sha2(case),
            ));
        }
        for case in translate::sig_cases() {
            cases.push(materialize(
                case.case_id(),
                case.features(),
                &missing,
                CaseKind::Sig(case),
            ));
        }
        for case in translate::speccheck_cases() {
            cases.push(materialize(
                case.case_id(),
                case.features(),
                &missing,
                CaseKind::Speccheck(case),
            ));
        }
        for family in contract::AEAD_FAMILIES {
            for &area in contract::AeadArea::ALL {
                cases.push(materialize(
                    contract::case_id(family, area),
                    family.features,
                    &missing,
                    CaseKind::Contract(family, area),
                ));
            }
        }
        for (index, probe) in probes::PROBES.iter().enumerate() {
            cases.push(materialize(
                probe.case_id(),
                probe.features,
                &missing,
                CaseKind::Probe(index),
            ));
        }
        cases
    }
}

export!(Component);
