//! `conformance-signing-guest`: the host-only conformance component.
//!
//! Covers the signature-minting surface the in-guest provider deliberately
//! does not export — `ecdsa-sign` and the gated RSA signing interfaces are
//! class D (see rust/guest-provider/README.md) — which the shared
//! `conformance-guest` therefore cannot import, since it must compose with
//! that provider. This guest runs only under the host-backed targets
//! (wasmtime, jco).
//!
//! Two case families. The ECDSA coverage is probes only: private-key
//! imports are exercised as sign-then-verify round trips against
//! separately imported public points, never as known signature bytes —
//! the WIT deliberately leaves ECDSA signatures nondeterministic across
//! implementations, and no import ever derives a public half (the
//! w3c/webcrypto#356 gap). The Rust-side private-import known answers
//! (the RFC 6979 A.2.5 deterministic signature, out-of-range scalar
//! rejection) are pinned by `lann-webcrypto-core`'s unit tests. The RSA
//! signing coverage ([`rsa_sign`]) additionally carries vector cases:
//! RSASSA-PKCS1-v1_5 generation is deterministic, so the Wycheproof
//! `sig_gen` vectors byte-compare here the way verification vectors do in
//! the shared suite. `rsa-sign` is a *gated* feature (unlike the
//! structural `ecdsa-sign`), so its cases carry the feature tag and its
//! probes assert the decline on targets declaring it missing.

wit_bindgen::generate!({
    path: "../guest/wit",
    world: "signing-guest",
    generate_all,
});

mod rsa_sign;

use std::collections::BTreeSet;

use conformance_harness::stream::{sig_sign_ok, sig_verify_ok, sig_verify_op, Schedule};
use conformance_harness::{
    b64url, describe, expect, expect_err, probes, ErrKind, FEATURE_RSA_SIGN, KNOWN_FEATURES,
    P256_A25_X, P256_A25_Y,
};
use exports::conformance::webcrypto::tests::{Guest, GuestTestCase, Outcome, TestCase};
use lann_webcrypto_guest::bindings::ecdsa_sign::generate_key as raw_generate_key;
use lann_webcrypto_guest::bindings::ecdsa_verify::{import_verifying_key_raw, EcdsaVariant};
use lann_webcrypto_guest::bindings::signature::{SigningKey, SigningKeyOptions, VerifyingKey};
use lann_webcrypto_guest::bindings::types::Error;
use rsa_sign::{
    rsa_pss_sign_round_trip, rsa_sign_admission, rsa_sign_declined, rsa_sign_key_contract,
};

/// Generate a signing key with `sign` granted, carrying only the
/// `extractable` choice (the probes' subject is ECDSA, not usage policy).
async fn generate_key(
    variant: EcdsaVariant,
    extractable: bool,
) -> Result<(SigningKey, VerifyingKey), Error> {
    let options = SigningKeyOptions::new();
    options.can_sign(true);
    options.extractable(extractable);
    raw_generate_key(variant, options).await
}

/// The features a bare tag in the `probes!` table stands for. Which
/// features exist is this suite's business, not the harness's.
macro_rules! feature_tags {
    (rsa_sign) => {
        &[FEATURE_RSA_SIGN]
    };
}

probes! {
    ecdsa_p256_sign_roundtrip,
    ecdsa_p384_generate_roundtrip,
    ecdsa_sign_extractable_getter,
    ecdsa_p521_unsupported,
    ecdsa_private_format_imports,
    ecdsa_signing_key_exports,
    ecdsa_cross_hash_sign_roundtrip,
    ecdsa_unwrap_signing_key,
    rsa_sign_key_contract(rsa_sign),
    rsa_pss_sign_round_trip(rsa_sign),
    rsa_sign_admission(rsa_sign),
    rsa_sign_declined(rsa_sign),
}

/// Run the probe case whose `features` a target declares missing: assert
/// the correct decline (the shared guest's `run_declined`, ported for the
/// features this suite tags). This is the two-way guarantee behind the
/// plain `skipped` the vector cases report: a target cannot silently
/// serve a feature it declares missing.
async fn run_declined(features: &[&str]) -> Result<String, String> {
    if features == [FEATURE_RSA_SIGN] {
        rsa_sign::minting_declined().await
    } else {
        Err("probe has no decline assertion for its features".into())
    }
}

struct Component;

/// The data to run one materialized case.
enum CaseKind {
    /// One RSASSA-PKCS1-v1_5 signature-generation vector.
    RsaSign(rsa_sign::RsaSignCase),
    /// An index into [`PROBES`].
    Probe(usize),
}

impl CaseKind {
    /// Run the case's subject, yielding the failure detail on expectation
    /// mismatch.
    async fn execute(&self) -> Result<(), String> {
        match self {
            CaseKind::RsaSign(case) => rsa_sign::run_case(case).await,
            CaseKind::Probe(index) => conformance_harness::run_probe(PROBES, *index).await,
        }
    }

    /// Whether this case, when its features are declared missing, asserts
    /// the correct decline before reporting `skipped` (the shared guest's
    /// posture: probes assert it on every minting path, vector cases skip
    /// without re-asserting it hundreds of times).
    fn asserts_decline(&self) -> bool {
        matches!(self, CaseKind::Probe(_))
    }
}

/// One materialized conformance case: its stable name, the features it
/// exercises, whether the target provides them, and the data to run it.
pub struct Case {
    name: String,
    features: &'static [&'static str],
    provided: bool,
    kind: CaseKind,
}

/// Materialize the suite for a target missing `missing`, in census order:
/// the vector cases, then the probes.
fn all_cases(missing: &BTreeSet<&str>) -> Vec<TestCase> {
    let mut cases = Vec::new();
    for case in rsa_sign::cases() {
        cases.push(TestCase::new(Case {
            name: case.case_id(),
            features: case.features(),
            provided: conformance_harness::provided(case.features(), missing),
            kind: CaseKind::RsaSign(case),
        }));
    }
    for (index, probe) in PROBES.iter().enumerate() {
        cases.push(TestCase::new(Case {
            name: probe.case_id(),
            features: probe.features,
            provided: probe.provided_by(missing),
            kind: CaseKind::Probe(index),
        }));
    }
    cases
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
                run_declined(self.features).await
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
        let missing = conformance_harness::missing_features(&missing_features, KNOWN_FEATURES);
        all_cases(&missing)
    }
}

export!(Component);

// --- probes --------------------------------------------------------------------

/// A generated P-256 key reports its variant through the getters, its
/// signatures verify — both under the public half returned with it and
/// under the same point exported and re-imported through `ecdsa-verify` —
/// and a corrupted signature fails `authentication-failed`.
async fn ecdsa_p256_sign_roundtrip() -> Result<(), String> {
    let (key, public) = generate_key(EcdsaVariant::P256Sha256, false)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    expect(
        key.algorithm_name(),
        "ECDSA".to_string(),
        "signing-key algorithm-name",
    )?;
    expect(
        key.algorithm_curve(),
        Some("P-256".to_string()),
        "signing-key algorithm-curve",
    )?;
    expect(
        key.algorithm_hash(),
        Some("SHA-256".to_string()),
        "signing-key algorithm-hash",
    )?;

    let payload = b"host-only signing payload";
    let sig = sig_sign_ok(&key, payload, Schedule::Whole).await?;
    expect(sig.len(), 64, "P-256 signature length")?;
    sig_verify_ok(
        &public,
        payload,
        &sig,
        Schedule::Whole,
        "generated public half did not verify",
    )
    .await?;

    // The generated point survives an export → ecdsa-verify import round
    // trip (65-byte uncompressed SEC1), and the re-imported key verifies.
    let point = public
        .export_key_raw()
        .await
        .map_err(|e| describe("export-key-raw (public)", &e))?;
    if point.len() != 65 || point[0] != 0x04 {
        return Err(format!(
            "exported public key is not a 65-byte uncompressed SEC1 point ({} bytes)",
            point.len()
        ));
    }
    let imported = import_verifying_key_raw(EcdsaVariant::P256Sha256, point)
        .await
        .map_err(|e| describe("import-verifying-key-raw of the exported point", &e))?;
    sig_verify_ok(
        &imported,
        payload,
        &sig,
        Schedule::Whole,
        "re-imported key did not verify",
    )
    .await?;

    let mut corrupted = sig;
    corrupted[0] ^= 0x01;
    let verified = sig_verify_op(&imported, payload, &corrupted, Schedule::Whole).await?;
    expect_err(
        "verify",
        ErrKind::AuthenticationFailed,
        verified,
        "corrupted signature verified",
    )
}

/// A generated P-384 key round-trips sign→verify, and a *different* key's
/// public half rejects the signature.
async fn ecdsa_p384_generate_roundtrip() -> Result<(), String> {
    let (key, public) = generate_key(EcdsaVariant::P384Sha384, false)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    expect(
        key.algorithm_curve(),
        Some("P-384".to_string()),
        "generated signing-key algorithm-curve",
    )?;
    expect(
        key.algorithm_hash(),
        Some("SHA-384".to_string()),
        "generated signing-key algorithm-hash",
    )?;

    let payload = b"host-only signing payload";
    let sig = sig_sign_ok(&key, payload, Schedule::Whole).await?;
    expect(sig.len(), 96, "P-384 signature length")?;
    sig_verify_ok(
        &public,
        payload,
        &sig,
        Schedule::Whole,
        "round-trip signature did not verify",
    )
    .await?;

    let (_other, other_public) = generate_key(EcdsaVariant::P384Sha384, false)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    let verified = sig_verify_op(&other_public, payload, &sig, Schedule::Whole).await?;
    expect_err(
        "verify",
        ErrKind::AuthenticationFailed,
        verified,
        "signature verified under a different key",
    )
}

/// The `extractable` getter reads correctly in both directions on
/// generated signing keys (a hardcoded `true` must not pass). There is no
/// export operation to cross-check against — extractability is mint-time
/// recorded policy for future format-specific exports and platform key
/// storage.
async fn ecdsa_sign_extractable_getter() -> Result<(), String> {
    let (key, _public) = generate_key(EcdsaVariant::P256Sha256, true)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    expect(
        key.extractable(),
        true,
        "extractable generated key's extractable getter",
    )?;
    let (key, _public) = generate_key(EcdsaVariant::P256Sha256, false)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    expect(
        key.extractable(),
        false,
        "non-extractable generated key's extractable getter",
    )
}

/// The declared-but-unserved P-521 variant declines `unsupported` on both
/// minting paths (the `ecdsa-variant` contract; the `aes192` pattern).
async fn ecdsa_p521_unsupported() -> Result<(), String> {
    expect_err(
        "generate-key",
        ErrKind::Unsupported,
        generate_key(EcdsaVariant::P521Sha512, false).await,
        "P-521 key generated",
    )?;
    expect_err(
        "import-verifying-key-raw",
        ErrKind::Unsupported,
        import_verifying_key_raw(EcdsaVariant::P521Sha512, vec![0x04; 133]).await,
        "P-521 public key imported",
    )
}

// The RFC 6979 A.2.5 P-256 key's private half: the scalar and its PKCS#8
// encoding (the public coordinates are the harness's
// `P256_A25_X`/`P256_A25_Y`).
const P256_A25_D: &str = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
const P256_A25_PKCS8: &str = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721a1440342000460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";

/// The RFC 6979 A.2.5 public key as an uncompressed SEC1 point.
fn a25_point() -> Vec<u8> {
    let mut point = vec![0x04];
    point.extend(conformance_harness::unhex(P256_A25_X));
    point.extend(conformance_harness::unhex(P256_A25_Y));
    point
}

/// A signing key imported from either private format signs, and the
/// signature verifies under the same key's known public point imported
/// through `ecdsa-verify`; a wrong-curve PKCS#8 and a d-less EC JWK fail
/// `invalid-key`.
async fn ecdsa_private_format_imports() -> Result<(), String> {
    use lann_webcrypto_guest::bindings::ecdsa_sign;

    let options = || {
        let options = SigningKeyOptions::new();
        options.can_sign(true);
        options.extractable(false);
        options
    };
    let pkcs8 = conformance_harness::unhex(P256_A25_PKCS8);
    let jwk = format!(
        r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}","d":"{}"}}"#,
        b64url(&conformance_harness::unhex(P256_A25_X)),
        b64url(&conformance_harness::unhex(P256_A25_Y)),
        b64url(&conformance_harness::unhex(P256_A25_D)),
    );
    let public = import_verifying_key_raw(EcdsaVariant::P256Sha256, a25_point())
        .await
        .map_err(|e| describe("import-verifying-key-raw", &e))?;

    let payload = b"private-format signing payload";
    for (what, key) in [
        (
            "pkcs8",
            ecdsa_sign::import_signing_key_pkcs8(
                EcdsaVariant::P256Sha256,
                pkcs8.clone(),
                options(),
            )
            .await
            .map_err(|e| describe("import-signing-key-pkcs8", &e))?,
        ),
        (
            "jwk",
            ecdsa_sign::import_signing_key_jwk(EcdsaVariant::P256Sha256, jwk.clone(), options())
                .await
                .map_err(|e| describe("import-signing-key-jwk", &e))?,
        ),
    ] {
        expect(
            key.algorithm_curve(),
            Some("P-256".to_string()),
            "imported signing-key algorithm-curve",
        )?;
        let sig = sig_sign_ok(&key, payload, Schedule::Whole).await?;
        expect(sig.len(), 64, "P-256 signature length")?;
        sig_verify_ok(
            &public,
            payload,
            &sig,
            Schedule::Whole,
            &format!("{what}-imported key did not verify"),
        )
        .await?;
    }

    expect_err(
        "P-256 pkcs8 as p384-sha384",
        ErrKind::InvalidKey,
        ecdsa_sign::import_signing_key_pkcs8(EcdsaVariant::P384Sha384, pkcs8, options()).await,
        "imported a P-256 PKCS#8 under a P-384 variant",
    )?;
    expect_err(
        "d-less EC JWK",
        ErrKind::InvalidKey,
        ecdsa_sign::import_signing_key_jwk(
            EcdsaVariant::P256Sha256,
            format!(
                r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}"}}"#,
                b64url(&conformance_harness::unhex(P256_A25_X)),
                b64url(&conformance_harness::unhex(P256_A25_Y)),
            ),
            options(),
        )
        .await,
        "imported a d-less JWK as a signing key",
    )
}

/// The gated signing-key exports: a generated extractable key round-trips
/// through both formats to a key that still signs under the original
/// public half, and the gate holds on non-extractable keys.
async fn ecdsa_signing_key_exports() -> Result<(), String> {
    use lann_webcrypto_guest::bindings::ecdsa_sign;

    let (signing, public) = generate_key(EcdsaVariant::P256Sha256, true)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    let payload = b"signing-key export payload";
    let pkcs8 = signing
        .export_key_pkcs8()
        .await
        .map_err(|e| describe("export-key-pkcs8", &e))?;
    let jwk = signing
        .export_key_jwk()
        .await
        .map_err(|e| describe("export-key-jwk", &e))?;
    if !jwk.contains("\"d\"") || !jwk.contains("\"P-256\"") {
        return Err(format!(
            "exported private JWK missing material members: {jwk}"
        ));
    }

    let options = || {
        let options = SigningKeyOptions::new();
        options.can_sign(true);
        options.extractable(false);
        options
    };
    for (what, key) in [
        (
            "pkcs8",
            ecdsa_sign::import_signing_key_pkcs8(EcdsaVariant::P256Sha256, pkcs8, options())
                .await
                .map_err(|e| describe("re-import of exported PKCS#8", &e))?,
        ),
        (
            "jwk",
            ecdsa_sign::import_signing_key_jwk(EcdsaVariant::P256Sha256, jwk, options())
                .await
                .map_err(|e| describe("re-import of exported JWK", &e))?,
        ),
    ] {
        let sig = sig_sign_ok(&key, payload, Schedule::Whole).await?;
        sig_verify_ok(
            &public,
            payload,
            &sig,
            Schedule::Whole,
            &format!("{what} re-import did not verify"),
        )
        .await?;
    }

    let (non_extractable, _) = generate_key(EcdsaVariant::P256Sha256, false)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    expect_err(
        "export-key-pkcs8",
        ErrKind::NotExtractable,
        non_extractable.export_key_pkcs8().await,
        "exported a non-extractable signing key",
    )?;
    expect_err(
        "export-key-jwk",
        ErrKind::NotExtractable,
        non_extractable.export_key_jwk().await,
        "exported a non-extractable signing key",
    )
}

/// The cross pairings of curve and hash sign and verify as their own
/// variants: signature width follows the curve, the getters report the
/// minted hash, and a signature does not verify under the same point
/// minted with a different hash.
async fn ecdsa_cross_hash_sign_roundtrip() -> Result<(), String> {
    let payload = b"cross-hash signing payload";
    for (variant, curve, hash, sig_len) in [
        (EcdsaVariant::P256Sha384, "P-256", "SHA-384", 64),
        (EcdsaVariant::P256Sha512, "P-256", "SHA-512", 64),
        (EcdsaVariant::P384Sha256, "P-384", "SHA-256", 96),
        (EcdsaVariant::P384Sha512, "P-384", "SHA-512", 96),
    ] {
        let (key, public) = generate_key(variant, false)
            .await
            .map_err(|e| describe(&format!("generate-key ({curve}/{hash})"), &e))?;
        expect(
            key.algorithm_curve(),
            Some(curve.to_string()),
            "cross-variant signing-key algorithm-curve",
        )?;
        expect(
            key.algorithm_hash(),
            Some(hash.to_string()),
            "cross-variant signing-key algorithm-hash",
        )?;
        let sig = sig_sign_ok(&key, payload, Schedule::Whole).await?;
        expect(sig.len(), sig_len, "cross-variant signature length")?;
        sig_verify_ok(
            &public,
            payload,
            &sig,
            Schedule::Whole,
            &format!("{curve}/{hash} round trip"),
        )
        .await?;
    }

    // The hash is part of the key's identity: the same point under a
    // different hash rejects the signature.
    let (key, public) = generate_key(EcdsaVariant::P256Sha512, false)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    let sig = sig_sign_ok(&key, payload, Schedule::Whole).await?;
    let point = public
        .export_key_raw()
        .await
        .map_err(|e| describe("export-key-raw (public)", &e))?;
    let rebound = import_verifying_key_raw(EcdsaVariant::P256Sha256, point)
        .await
        .map_err(|e| describe("import-verifying-key-raw (rebound hash)", &e))?;
    let verified = sig_verify_op(&rebound, payload, &sig, Schedule::Whole).await?;
    expect_err(
        "verify under the wrong hash binding",
        ErrKind::AuthenticationFailed,
        verified,
        "a SHA-512-minted signature verified under a SHA-256 binding",
    )
}

/// The private-signature unwrap mints: a generated extractable P-256 key
/// travels wrapped under an AES-GCM KEK in both formats, mints back out
/// through `unwrap-signing-key-*`, and each minted key's signatures
/// verify under the original public half; the minted key carries the
/// mint's options, not the wrapped material's.
async fn ecdsa_unwrap_signing_key() -> Result<(), String> {
    use lann_webcrypto_guest::bindings::aead::AeadKeyOptions;
    use lann_webcrypto_guest::bindings::{aes_gcm, ecdsa_sign};

    let (signing, public) = generate_key(EcdsaVariant::P256Sha256, true)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    let kek_options = AeadKeyOptions::new();
    kek_options.can_wrap(true);
    kek_options.can_unwrap(true);
    let kek = aes_gcm::generate_key(aes_gcm::AesVariant::Aes256, kek_options)
        .await
        .map_err(|e| describe("kek generate-key", &e))?;
    let nonce = [0x51u8; 12].to_vec();
    let aad = b"ecdsa unwrap-mint probe".to_vec();

    let payload = b"unwrap-minted signing payload";
    for (what, input) in [
        (
            "pkcs8",
            signing
                .to_wrap_input_pkcs8()
                .await
                .map_err(|e| describe("to-wrap-input-pkcs8", &e))?,
        ),
        (
            "jwk",
            signing
                .to_wrap_input_jwk()
                .await
                .map_err(|e| describe("to-wrap-input-jwk", &e))?,
        ),
    ] {
        let wrapped = kek
            .wrap(nonce.clone(), aad.clone(), None, input)
            .await
            .map_err(|e| describe("aead-key.wrap", &e))?;
        let unwrapped = kek
            .unwrap(nonce.clone(), aad.clone(), None, wrapped)
            .await
            .map_err(|e| describe("aead-key.unwrap", &e))?;
        let options = SigningKeyOptions::new();
        options.can_sign(true);
        options.extractable(false);
        let minted = match what {
            "pkcs8" => {
                ecdsa_sign::unwrap_signing_key_pkcs8(EcdsaVariant::P256Sha256, unwrapped, options)
                    .await
                    .map_err(|e| describe("unwrap-signing-key-pkcs8", &e))?
            }
            _ => ecdsa_sign::unwrap_signing_key_jwk(EcdsaVariant::P256Sha256, unwrapped, options)
                .await
                .map_err(|e| describe("unwrap-signing-key-jwk", &e))?,
        };
        expect(
            minted.extractable(),
            false,
            &format!("{what}-minted key's extractable getter"),
        )?;
        expect(
            minted.algorithm_curve(),
            Some("P-256".to_string()),
            &format!("{what}-minted key's algorithm-curve"),
        )?;
        let sig = sig_sign_ok(&minted, payload, Schedule::Whole).await?;
        sig_verify_ok(
            &public,
            payload,
            &sig,
            Schedule::Whole,
            &format!("{what}-minted key did not verify under the original public half"),
        )
        .await?;
    }
    Ok(())
}
