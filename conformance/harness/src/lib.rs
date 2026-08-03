//! The parts of the conformance guests that do not depend on which world a
//! guest is built against.
//!
//! There are two guests because there must be: the signing guest imports
//! `ecdsa-sign`, which the in-guest provider deliberately never exports, so
//! a single component could not run under every target. That split is a
//! property of their *worlds*, and everything below is unaffected by it —
//! the probe table, how a case is named, which feature names exist, how a
//! WIT error is rendered, how an expected failure is asserted, how bytes
//! are delivered to an operation ([`stream`]), and how a target's
//! missing-feature declaration is validated.
//!
//! Keeping those here means the two guests cannot answer the same question
//! differently. Error rendering is the one that would bite first: a failure
//! message is a suite's whole diagnostic output, and two renderers drifting
//! apart makes the same underlying failure look like two different ones
//! depending on which suite reported it.
//!
//! What deliberately stays in each guest is the harness that materializes
//! cases, because it is typed against `wit_bindgen`-generated types that
//! differ per world (for a probes-only suite, [`export_probe_suite!`]
//! expands that glue in the invoking crate).

pub mod stream;

use std::collections::BTreeSet;

use data_encoding::{BASE64URL_NOPAD, HEXLOWER};

use lann_webcrypto_guest::bindings::types::Error;

/// The `chacha20-poly1305` feature: the IETF ChaCha20-Poly1305 (RFC 8439)
/// minting interface. Platform-backed hosts serve it where their platform
/// does (the Modern Algorithms proposal; Node's WebCrypto serves it,
/// browser WebCrypto does not yet).
pub const FEATURE_CHACHA: &str = "chacha20-poly1305";

/// The `xchacha20-poly1305` feature: the XChaCha construction — the
/// `xchacha20-poly1305` minting interface and the XChaCha internal-nonce
/// minting interface. No platform WebCrypto implements XChaCha (it is
/// absent from the Modern Algorithms proposal), so the jco targets declare
/// it missing.
pub const FEATURE_XCHACHA: &str = "xchacha20-poly1305";

/// The `ecdsa-sign` feature: the `ecdsa-sign` minting interface itself.
/// No case in the shared suite is tagged with it — the signing suite's
/// world *imports* the interface, so a target missing the feature (the
/// composed target: class D) is excluded from that suite structurally
/// rather than case by case. No case *can* be tagged with it: a guest
/// asking whether the interface declines must import it, and a target
/// missing it cannot instantiate that guest. The declaration is held to
/// the truth by `just conformance::class-d` instead.
pub const FEATURE_ECDSA_SIGN: &str = "ecdsa-sign";

/// The `sha1-checked` feature: the checked-SHA-1 minting interface (both
/// postures). Platform SHA-1 carries no sha1dc collision detection and
/// the jco host is constrained to `crypto.subtle`, so the jco targets
/// declare it missing — the first feature the in-guest provider serves
/// that the platform hosts do not.
pub const FEATURE_SHA1_CHECKED: &str = "sha1-checked";

/// Every feature name a target may declare missing — shared here so every
/// guest validates the same names. `all` traps on names outside this set,
/// so a misspelled declaration is a harness bug rather than a silently
/// inert one.
pub const KNOWN_FEATURES: &[&str] = &[
    FEATURE_CHACHA,
    FEATURE_XCHACHA,
    FEATURE_ECDSA_SIGN,
    FEATURE_SHA1_CHECKED,
];

/// A probe body. Boxed because each `async fn` has its own opaque type.
pub type ProbeFn = fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>>>>;

/// One probe: the function that runs it, the features it exercises beyond
/// the baseline surface, and that function's name.
///
/// The case id is *derived* from the function's own identifier rather than
/// written beside it, so a case cannot name one thing and run another (a
/// mis-pairing asserts the wrong thing and reports *pass*, and a lockfile
/// can show a reordering but not a mis-pairing).
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
        provided(self.features, missing)
    }
}

/// Whether a target missing `missing` provides every feature in
/// `features`.
pub fn provided(features: &[&str], missing: &BTreeSet<&str>) -> bool {
    features.iter().all(|feature| !missing.contains(feature))
}

/// Run the probe at `index` (into `probes`) on a target providing its
/// features.
pub async fn run_probe(probes: &[Probe], index: usize) -> Result<(), String> {
    match probes.get(index) {
        Some(probe) => (probe.run)().await,
        None => Err(format!("no probe at index {index}")),
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
/// The invoking module supplies `feature_tags!` to map a *tagged* name to
/// the features it stands for (an untagged probe exercises only the
/// baseline surface), since which tags exist is a property of the suite
/// rather than of this macro.
#[macro_export]
macro_rules! probes {
    ($($name:ident $(($feature:ident))?),* $(,)?) => {
        pub const PROBES: &[$crate::Probe] = &[
            $($crate::Probe {
                ident: stringify!($name),
                features: $crate::probes!(@features $(($feature))?),
                run: || Box::pin($name()),
            }),*
        ];
    };
    (@features) => {
        &[]
    };
    (@features ($feature:ident)) => {
        feature_tags!($feature)
    };
}

/// Export a probes-only conformance suite: the world-typed glue between a
/// [`probes!`] table and the generated `conformance:webcrypto/tests`
/// export, identical for every suite that carries no vector cases.
///
/// Invoke at the root of a crate whose world exports that interface, after
/// `wit_bindgen::generate!`: the expansion names the generated
/// `exports::…::tests` types and the generated `export!` macro, which is
/// why this is a macro rather than shared functions — those types differ
/// per world.
#[macro_export]
macro_rules! export_probe_suite {
    ($probes:expr) => {
        struct Component;

        /// One materialized probe case.
        struct Case {
            index: usize,
            provided: bool,
        }

        impl exports::conformance::webcrypto::tests::GuestTestCase for Case {
            fn name(&self) -> String {
                $probes[self.index].case_id()
            }

            fn features(&self) -> Vec<String> {
                $probes[self.index].feature_names()
            }

            async fn run(&self) -> exports::conformance::webcrypto::tests::Outcome {
                use exports::conformance::webcrypto::tests::Outcome;
                if self.provided {
                    match $crate::run_probe($probes, self.index).await {
                        Ok(()) => Outcome::Pass,
                        Err(detail) => Outcome::Fail(detail),
                    }
                } else {
                    // A suite exported through this macro carries no decline
                    // assertions; a feature-tagged probe fails loudly here
                    // until it brings one (hand-write the glue, as the
                    // shared guest does).
                    Outcome::Fail("probe has no decline assertion for its features".into())
                }
            }
        }

        impl exports::conformance::webcrypto::tests::Guest for Component {
            type TestCase = Case;

            fn all(
                missing_features: Vec<String>,
            ) -> Vec<exports::conformance::webcrypto::tests::TestCase> {
                let missing = $crate::missing_features(&missing_features, $crate::KNOWN_FEATURES);
                $probes
                    .iter()
                    .enumerate()
                    .map(|(index, probe)| {
                        exports::conformance::webcrypto::tests::TestCase::new(Case {
                            index,
                            provided: probe.provided_by(&missing),
                        })
                    })
                    .collect()
            }
        }

        export!(Component);
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
        Error::NotPermitted(detail) => format!("not-permitted: {detail}"),
        Error::KeyExhausted => "key-exhausted".to_string(),
        Error::Other(detail) => format!("other: {detail}"),
        Error::Extension(ext) => format!(
            "extension({origin}, {name}): {message}",
            origin = ext.origin,
            name = ext.name,
            message = ext.message,
        ),
    };
    format!("{context}: {rendered}")
}

/// A `types.error` case, by discriminant: what an assertion names when it
/// expects a specific failure. Mirrors the WIT variant case for case.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ErrKind {
    /// `invalid-key`.
    InvalidKey,
    /// `invalid-nonce`.
    InvalidNonce,
    /// `authentication-failed`.
    AuthenticationFailed,
    /// `not-extractable`.
    NotExtractable,
    /// `unsupported`.
    Unsupported,
    /// `not-permitted`.
    NotPermitted,
    /// `key-exhausted`.
    KeyExhausted,
    /// `other`.
    Other,
    /// `extension` (any condition; probes pinning a specific
    /// (`origin`, `name`) pair match on the payload directly).
    Extension,
}

impl ErrKind {
    /// The case's WIT name, as failure messages render it.
    pub fn name(self) -> &'static str {
        match self {
            ErrKind::InvalidKey => "invalid-key",
            ErrKind::InvalidNonce => "invalid-nonce",
            ErrKind::AuthenticationFailed => "authentication-failed",
            ErrKind::NotExtractable => "not-extractable",
            ErrKind::Unsupported => "unsupported",
            ErrKind::NotPermitted => "not-permitted",
            ErrKind::KeyExhausted => "key-exhausted",
            ErrKind::Other => "other",
            ErrKind::Extension => "extension",
        }
    }

    /// Whether `error` is this case.
    pub fn matches(self, error: &Error) -> bool {
        matches!(
            (self, error),
            (ErrKind::InvalidKey, Error::InvalidKey(_))
                | (ErrKind::InvalidNonce, Error::InvalidNonce(_))
                | (ErrKind::AuthenticationFailed, Error::AuthenticationFailed)
                | (ErrKind::NotExtractable, Error::NotExtractable)
                | (ErrKind::Unsupported, Error::Unsupported(_))
                | (ErrKind::NotPermitted, Error::NotPermitted(_))
                | (ErrKind::KeyExhausted, Error::KeyExhausted)
                | (ErrKind::Other, Error::Other(_))
                | (ErrKind::Extension, Error::Extension(_))
        )
    }
}

/// Assert that an operation failed with the expected error case: `what`
/// names the operation, `accepted` says what its wrongly succeeding would
/// mean.
///
/// Stands in for the three-arm match at every call site, so the failure
/// reads the same whichever suite reports it.
pub fn expect_err<T>(
    what: &str,
    want: ErrKind,
    result: Result<T, Error>,
    accepted: &str,
) -> Result<(), String> {
    match result {
        Err(error) if want.matches(&error) => Ok(()),
        Err(other) => Err(describe(
            &format!("{what}: expected {}, got", want.name()),
            &other,
        )),
        Ok(_) => Err(format!("{what}: {accepted}")),
    }
}

/// Assert getter equality, rendering both sides on mismatch.
pub fn expect<T: PartialEq + std::fmt::Debug>(got: T, want: T, what: &str) -> Result<(), String> {
    if got == want {
        Ok(())
    } else {
        Err(format!("{what}: got {got:?}, want {want:?}"))
    }
}

/// Compare byte strings, reporting lengths and the first differing offset
/// rather than the full contents.
pub fn expect_bytes(got: &[u8], want: &[u8], what: &str) -> Result<(), String> {
    if got == want {
        return Ok(());
    }
    if got.len() != want.len() {
        return Err(format!(
            "{what}: got {} bytes, want {} bytes",
            got.len(),
            want.len()
        ));
    }
    let index = got
        .iter()
        .zip(want)
        .position(|(g, w)| g != w)
        .unwrap_or_default();
    Err(format!(
        "{what}: first difference at byte {index} of {}: got {:#04x}, want {:#04x}",
        got.len(),
        got[index],
        want[index]
    ))
}

/// Decode a hex constant (probe-internal known-answer material).
pub fn unhex(hex: &str) -> Vec<u8> {
    HEXLOWER
        .decode(hex.as_bytes())
        .expect("probe hex constants are valid")
}

/// Unpadded base64url, for building the members of the JWKs the imports
/// take.
pub fn b64url(bytes: &[u8]) -> String {
    BASE64URL_NOPAD.encode(bytes)
}

/// RFC 6979 A.2.5: the P-256 example key's public x-coordinate
/// (known-answer material both suites import verifying keys from).
pub const P256_A25_X: &str = "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6";

/// RFC 6979 A.2.5: the P-256 example key's public y-coordinate.
pub const P256_A25_Y: &str = "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";

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

    /// The three arms of the assertion `expect_err` stands for: the wanted
    /// case passes, another case renders through `describe`, and wrongful
    /// success reports what it means.
    #[test]
    fn expect_err_distinguishes_all_three_arms() {
        assert_eq!(
            expect_err(
                "import-key-raw",
                ErrKind::InvalidKey,
                Err::<(), _>(Error::InvalidKey("too short".into())),
                "empty key imported",
            ),
            Ok(())
        );
        assert_eq!(
            expect_err(
                "import-key-raw",
                ErrKind::InvalidKey,
                Err::<(), _>(Error::Unsupported("no such variant".into())),
                "empty key imported",
            ),
            Err("import-key-raw: expected invalid-key, got: unsupported: no such variant".into())
        );
        assert_eq!(
            expect_err(
                "import-key-raw",
                ErrKind::InvalidKey,
                Ok(()),
                "empty key imported"
            ),
            Err("import-key-raw: empty key imported".into())
        );
    }

    /// Every `ErrKind` matches exactly its own WIT case.
    #[test]
    fn err_kind_matches_only_its_own_case() {
        let errors = [
            Error::InvalidKey(String::new()),
            Error::InvalidNonce(String::new()),
            Error::AuthenticationFailed,
            Error::NotExtractable,
            Error::Unsupported(String::new()),
            Error::KeyExhausted,
            Error::Other(String::new()),
        ];
        let kinds = [
            ErrKind::InvalidKey,
            ErrKind::InvalidNonce,
            ErrKind::AuthenticationFailed,
            ErrKind::NotExtractable,
            ErrKind::Unsupported,
            ErrKind::KeyExhausted,
            ErrKind::Other,
        ];
        for (i, kind) in kinds.iter().enumerate() {
            for (j, error) in errors.iter().enumerate() {
                assert_eq!(kind.matches(error), i == j, "{kind:?} vs case {j}");
            }
        }
    }

    #[test]
    fn expect_renders_both_sides_on_mismatch() {
        assert_eq!(expect(12, 12, "nonce-size"), Ok(()));
        assert_eq!(
            expect(8, 12, "nonce-size"),
            Err("nonce-size: got 8, want 12".into())
        );
    }

    #[test]
    fn expect_bytes_reports_the_first_differing_offset() {
        assert_eq!(expect_bytes(&[1, 2], &[1, 2], "tag"), Ok(()));
        assert_eq!(
            expect_bytes(&[1], &[1, 2], "tag"),
            Err("tag: got 1 bytes, want 2 bytes".into())
        );
        assert_eq!(
            expect_bytes(&[1, 3], &[1, 2], "tag"),
            Err("tag: first difference at byte 1 of 2: got 0x03, want 0x02".into())
        );
    }
}
