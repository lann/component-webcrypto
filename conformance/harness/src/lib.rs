//! The parts of the conformance guests that do not depend on which world a
//! guest is built against.
//!
//! There are two guests because there must be: the signing guest imports
//! `ecdsa-sign`, which the in-guest provider deliberately never exports, so
//! a single component could not run under every target. That split is a
//! property of their *worlds*, and everything below is unaffected by it —
//! the probe table, how a case is named, how a WIT error is rendered, and
//! how a target's missing-feature declaration is validated.
//!
//! Keeping those here means the two guests cannot answer the same question
//! differently. Error rendering is the one that would bite first: a failure
//! message is a suite's whole diagnostic output, and two renderers drifting
//! apart makes the same underlying failure look like two different ones
//! depending on which suite reported it.
//!
//! What deliberately stays in each guest is the harness that materializes
//! cases, because it is typed against `wit_bindgen`-generated types that
//! differ per world.

use std::collections::BTreeSet;

use lann_webcrypto_guest::bindings::types::Error;

/// A probe body. Boxed because each `async fn` has its own opaque type.
pub type ProbeFn = fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>>>>;

/// One probe: the function that runs it, the features it exercises beyond
/// the baseline surface, and that function's name.
///
/// The case id is *derived* from the function's own identifier rather than
/// written beside it, so a case cannot name one thing and run another. Held
/// as parallel lists — a name table and a `match index` dispatch — that was
/// a live hazard: inserting or reordering one alone re-points a name at a
/// different body, which then asserts the wrong thing and reports *pass*,
/// and a lockfile can show a reordering but not a mis-pairing.
pub struct Probe {
    /// The probe function's identifier, as `stringify!` sees it.
    pub ident: &'static str,
    pub features: &'static [&'static str],
    pub run: ProbeFn,
}

impl Probe {
    /// The case id: `probe/` plus the function's name in kebab case.
    pub fn case_id(&self) -> String {
        format!("probe/{}", self.ident.replace('_', "-"))
    }

    /// This probe's features, as the WIT `test-case.features` getter wants
    /// them.
    pub fn feature_names(&self) -> Vec<String> {
        self.features.iter().map(|s| s.to_string()).collect()
    }

    /// Whether a target missing `missing` provides what this probe needs.
    /// A probe whose feature is missing runs its decline assertion instead.
    pub fn provided_by(&self, missing: &BTreeSet<&str>) -> bool {
        self.features.iter().all(|f| !missing.contains(f))
    }
}

/// Declare a probe table: one function per line, in execution order, each
/// optionally followed by its feature in parentheses.
///
/// ```ignore
/// probes! {
///     hmac_import_empty_key,
///     chacha_key_metadata(chacha),
/// }
/// ```
///
/// The invoking module supplies `feature_tags!` to map a bare feature name
/// to the tags it stands for, since which features exist is a property of
/// the suite rather than of this macro.
#[macro_export]
macro_rules! probes {
    ($($name:ident $(($feature:ident))?),* $(,)?) => {
        pub const PROBES: &[$crate::Probe] = &[
            $($crate::Probe {
                ident: stringify!($name),
                features: feature_tags!($($feature)?),
                run: || Box::pin($name()),
            }),*
        ];
    };
}

/// Validate a target's missing-feature declaration against the features the
/// suite knows, returning it as a set.
///
/// An unknown name traps rather than being ignored: a misspelled
/// declaration would otherwise silently mean "missing nothing", quietly
/// re-enabling cases the target cannot serve — a harness bug reported as a
/// test outcome.
pub fn missing_features<'a>(declared: &'a [String], known: &[&str]) -> BTreeSet<&'a str> {
    let mut set = BTreeSet::new();
    for feature in declared {
        assert!(
            known.contains(&feature.as_str()),
            "unknown feature {feature:?} in the missing declaration (known: {known:?})"
        );
        set.insert(feature.as_str());
    }
    set
}

/// Render a WIT `error` with a context prefix.
///
/// Shared so that the same failure reads the same way whichever suite
/// reports it.
pub fn describe(context: &str, error: &Error) -> String {
    let rendered = match error {
        Error::InvalidKey(detail) => format!("invalid-key: {detail}"),
        Error::InvalidNonce(detail) => format!("invalid-nonce: {detail}"),
        Error::AuthenticationFailed => "authentication-failed".to_string(),
        Error::NotExtractable => "not-extractable".to_string(),
        Error::Unsupported(detail) => format!("unsupported: {detail}"),
        Error::KeyExhausted => "key-exhausted".to_string(),
        Error::Other(detail) => format!("other: {detail}"),
    };
    format!("{context}: {rendered}")
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn some_probe_body() -> Result<(), String> {
        Ok(())
    }

    /// The case id is the function's name, kebab-cased — the property that
    /// makes a name/body mismatch unrepresentable.
    #[test]
    fn case_id_derives_from_the_function_name() {
        let probe = Probe {
            ident: "hmac_import_empty_key",
            features: &[],
            run: || Box::pin(some_probe_body()),
        };
        assert_eq!(probe.case_id(), "probe/hmac-import-empty-key");
    }

    #[test]
    fn a_probe_is_provided_unless_one_of_its_features_is_missing() {
        let tagged = Probe {
            ident: "chacha_key_metadata",
            features: &["chacha20-poly1305"],
            run: || Box::pin(some_probe_body()),
        };
        assert!(tagged.provided_by(&BTreeSet::new()));
        assert!(!tagged.provided_by(&BTreeSet::from(["chacha20-poly1305"])));
    }

    #[test]
    fn declared_features_are_validated_against_the_known_set() {
        let known = ["chacha20-poly1305", "ecdsa-sign"];
        let declared = vec!["ecdsa-sign".to_string()];
        assert_eq!(
            missing_features(&declared, &known),
            BTreeSet::from(["ecdsa-sign"])
        );
    }

    #[test]
    #[should_panic(expected = "unknown feature")]
    fn a_misspelled_feature_traps_rather_than_meaning_nothing() {
        missing_features(&["chacha20-poly".to_string()], &["chacha20-poly1305"]);
    }
}
