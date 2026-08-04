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
use translate::{
    AeadCase, EcdhCase, HkdfCase, HmacCase, KwCase, Pbkdf2Case, RsaCase, Sha2Case, SigCase,
    SpeccheckCase, VectorCase, X25519Case,
};

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

/// The suite registry: one row per suite, in census order.
///
/// Each row generates its `CaseKind` variant, its materialize loop in
/// `all_cases` (rows materialize in table order — the census order
/// `tests.lock` pins), its dispatch arm in `CaseKind::execute`, and its
/// skip posture in `CaseKind::asserts_decline`, so pairing a suite's
/// cases with the wrong runner is unrepresentable — the guarantee
/// [`conformance_harness::probes!`] gives the probe table.
///
/// Two row shapes:
///
/// - `vectors`: `Variant(CaseType): iterator => runner;` — one case per
///   translated vector, named by `case.case_id()` and tagged by
///   `case.features()` (the [`VectorCase`] trait).
/// - `contracts`: `Variant(FamilyType, AreaType): for <family> in FAMILIES,
///   <areas> => runner;` — one case per family × area. The `<areas>`
///   expression may name the `<family>` binder and must yield areas by
///   value.
///
/// The probe suite is part of the expansion rather than a row: its case
/// data is an index into [`probes::PROBES`], whose own table pairs each
/// probe with its runner.
macro_rules! suites {
    (
        vectors {
            $( $vvar:ident($vty:ty): $viter:path => $vrun:path ; )*
        }
        contracts {
            $( $cvar:ident($cfam:ty, $carea:ty):
                for $fam:ident in $cfams:expr, $careas:expr => $crun:path ; )*
        }
    ) => {
        enum CaseKind {
            $( $vvar($vty), )*
            $( $cvar(&'static $cfam, $carea), )*
            Probe(usize),
        }

        impl CaseKind {
            /// Run the case's subject, yielding the failure detail on
            /// expectation mismatch.
            async fn execute(&self) -> Result<(), String> {
                match self {
                    $( CaseKind::$vvar(case) => $vrun(case).await, )*
                    $( CaseKind::$cvar(family, area) => $crun(family, *area).await, )*
                    CaseKind::Probe(index) => {
                        conformance_harness::run_probe(probes::PROBES, *index).await
                    }
                }
            }

            /// Whether this case, when its features are declared missing,
            /// asserts the correct decline before reporting `skipped`. The
            /// contract batteries and feature-tagged probes assert the
            /// decline on every minting path (the two-way guarantee that a
            /// target cannot serve a feature it declares missing); vector
            /// cases skip without re-asserting it thousands of times.
            fn asserts_decline(&self) -> bool {
                matches!(self, $( CaseKind::$cvar(..) | )* CaseKind::Probe(_))
            }
        }

        /// Materialize every suite for a target missing `missing`, in
        /// census order.
        fn all_cases(missing: &BTreeSet<&str>) -> Vec<TestCase> {
            let mut cases = Vec::new();
            $(
                for case in $viter() {
                    cases.push(materialize(
                        case.case_id(),
                        case.features(),
                        missing,
                        CaseKind::$vvar(case),
                    ));
                }
            )*
            $(
                for $fam in $cfams {
                    for area in $careas {
                        cases.push(materialize(
                            $fam.case_id(area),
                            $fam.features,
                            missing,
                            CaseKind::$cvar($fam, area),
                        ));
                    }
                }
            )*
            for (index, probe) in probes::PROBES.iter().enumerate() {
                cases.push(materialize(
                    probe.case_id(),
                    probe.features,
                    missing,
                    CaseKind::Probe(index),
                ));
            }
            cases
        }
    };
}

suites! {
    vectors {
        Hkdf(HkdfCase): translate::hkdf_cases => vectors::run_hkdf_case;
        Pbkdf2(Pbkdf2Case): translate::pbkdf2_cases => vectors::run_pbkdf2_case;
        Hmac(HmacCase): translate::hmac_cases => vectors::run_hmac_case;
        Aead(AeadCase): translate::aead_cases => vectors::run_aead_case;
        Cbc(translate::CbcCase): translate::cbc_cases => vectors::run_cbc_case;
        Kw(KwCase): translate::kw_cases => vectors::run_kw_case;
        Sha2(Sha2Case): translate::sha2_cases => vectors::run_sha2_case;
        Sig(SigCase): translate::sig_cases => vectors::run_sig_case;
        Speccheck(SpeccheckCase): translate::speccheck_cases => vectors::run_speccheck_case;
        Rsa(RsaCase): translate::rsa_cases => vectors::run_rsa_case;
        X25519(X25519Case): translate::x25519_cases => vectors::run_x25519_case;
        Ecdh(EcdhCase): translate::ecdh_cases => vectors::run_ecdh_case;
    }
    contracts {
        AeadContract(contract::AeadFamily, contract::AeadArea):
            for family in contract::AEAD_FAMILIES, family.areas() => contract::run;
        MacContract(contract::MacFamily, contract::MacArea):
            for family in contract::MAC_FAMILIES,
            contract::MacArea::ALL.iter().copied() => contract::run_mac;
        CipherContract(contract::CipherFamily, contract::CipherArea):
            for family in contract::CIPHER_FAMILIES,
            contract::CipherArea::ALL.iter().copied() => contract::run_cipher;
        DeriveContract(contract::DeriveSourceFamily, contract::DeriveArea):
            for family in contract::DERIVE_SOURCE_FAMILIES,
            contract::DeriveArea::ALL.iter().copied() => contract::run_derive;
    }
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
            match self.kind.execute().await {
                Ok(()) => Outcome::Pass,
                Err(detail) => Outcome::Fail(detail),
            }
        } else {
            // The target declares this case's feature missing; see
            // `CaseKind::asserts_decline` for which cases assert the
            // correct decline before skipping.
            let asserted = if self.kind.asserts_decline() {
                probes::run_declined(self.features).await
            } else {
                Ok(format!(
                    "feature {} declared missing by the target",
                    self.features.join("+")
                ))
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
        all_cases(&missing)
    }
}

export!(Component);
