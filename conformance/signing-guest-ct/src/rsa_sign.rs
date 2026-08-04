//! The gated RSA signing coverage: the Wycheproof `sig_gen` known-answer
//! cases (RSASSA-PKCS1-v1_5 is deterministic, so signing byte-compares
//! against the published vectors) and the hand-written probes for the
//! `rsassa-pkcs1-v15-sign` / `rsa-pss-sign` contract, including the
//! decline assertion a target declaring `rsa-sign` missing must satisfy.
//!
//! Translation policy (`conformance/vectors/README.md` is the summary;
//! this file is the authoritative encoding): only the SHA-256/384/512
//! groups translate — the `rsa-variant` set has no SHA-1 or SHA-224 case.
//! Upstream's `valid` and `acceptable` results translate identically:
//! every `acceptable` sig-gen vector is flagged `SmallPublicKey` (e = 3),
//! which the WIT family contract guarantees to import, and v1.5
//! generation is deterministic regardless of the exponent. Each vector
//! runs twice — once importing the group key via PKCS#8, once via the
//! group's own full-CRT private JWK — so both import paths carry vector
//! coverage. RSA-PSS has no sig-gen vectors (its salts are random);
//! [`rsa_pss_sign_round_trip`] covers signing instead.

use conformance_harness::stream::{sig_sign_ok, sig_verify_ok, sig_verify_op, Schedule};
use conformance_harness::{describe, expect, expect_bytes, expect_err, ErrKind, FEATURE_RSA_SIGN};
use lann_webcrypto_guest::bindings::rsa::RsaVariant;
use lann_webcrypto_guest::bindings::rsa_pss_verify;
use lann_webcrypto_guest::bindings::rsassa_pkcs1_v15_sign::RsaModulus;
use lann_webcrypto_guest::bindings::signature::{SigningKey, SigningKeyOptions, VerifyingKey};
use lann_webcrypto_guest::bindings::types::Error;
use lann_webcrypto_guest::bindings::wrapping::UnwrapInput;
use lann_webcrypto_guest::bindings::{rsa_pss_sign, rsassa_pkcs1_v15_sign};
use serde::Deserialize;

/// The RSASSA-PKCS1-v1_5 signature-generation vector files (one per
/// modulus length; each carries one group per digest, plus the e = 3
/// `SmallPublicKey` groups pinning the guaranteed-import exponent floor
/// on the signing paths).
const RSA_SIG_GEN_VECTORS: [&str; 3] = [
    include_str!("../../vectors/rsa_pkcs1_2048_sig_gen_test.json"),
    include_str!("../../vectors/rsa_pkcs1_3072_sig_gen_test.json"),
    include_str!("../../vectors/rsa_pkcs1_4096_sig_gen_test.json"),
];

#[derive(Deserialize)]
struct VectorFile {
    #[serde(rename = "testGroups")]
    test_groups: Vec<SigGenGroup>,
}

#[derive(Deserialize)]
struct SigGenGroup {
    #[serde(rename = "keySize")]
    key_size: u32,
    sha: String,
    #[serde(rename = "privateKeyPkcs8")]
    private_key_pkcs8: String,
    /// Upstream's own full-CRT private JWK. Absent only from the SHA-1
    /// and SHA-224 groups, which the translation excludes.
    #[serde(rename = "privateKeyJwk")]
    private_key_jwk: Option<serde_json::Value>,
    tests: Vec<SigGenTest>,
}

#[derive(Deserialize)]
struct SigGenTest {
    #[serde(rename = "tcId")]
    tc_id: u64,
    msg: String,
    sig: String,
    result: String,
}

/// Decode a hex vector member, naming the vector on failure.
fn unhex(field: &str, hex: &str) -> Vec<u8> {
    data_encoding::HEXLOWER
        .decode(hex.as_bytes())
        .unwrap_or_else(|err| panic!("vector {field} has invalid hex: {err}"))
}

/// The mint-bound digest a translated group's `sha` member declares, or
/// `None` for the excluded digests (SHA-1 and SHA-224 have no
/// `rsa-variant` case).
fn translated_sha(field: &str, sha: &str) -> Option<(RsaVariant, &'static str)> {
    match sha {
        "SHA-256" => Some((RsaVariant::Sha256, "sha256")),
        "SHA-384" => Some((RsaVariant::Sha384, "sha384")),
        "SHA-512" => Some((RsaVariant::Sha512, "sha512")),
        "SHA-1" | "SHA-224" => None,
        other => panic!("vector group {field} has unknown sha {other:?}"),
    }
}

/// A group key's private material in one of the two signing-import
/// encodings, carrying the dispatch to the matching import function.
pub enum SignImport {
    /// `import-signing-key-pkcs8` (the group's `privateKeyPkcs8`).
    Pkcs8(Vec<u8>),
    /// `import-signing-key-jwk` (the group's `privateKeyJwk`; JSON text).
    Jwk(String),
}

impl SignImport {
    /// The import segment of the case id.
    fn name(&self) -> &'static str {
        match self {
            SignImport::Pkcs8(_) => "pkcs8",
            SignImport::Jwk(_) => "jwk",
        }
    }
}

/// One executed RSASSA-PKCS1-v1_5 signature-generation vector: importing
/// the group's private key per `import`, signing `msg` under `schedule`,
/// and byte-comparing against the vector's deterministic `sig`.
pub struct RsaSignCase {
    variant: RsaVariant,
    /// The digest segment of the case id (`sha256`, …).
    sha_name: &'static str,
    key_bits: u32,
    tc_id: u64,
    import: SignImport,
    schedule: Schedule,
    msg: Vec<u8>,
    sig: Vec<u8>,
}

impl RsaSignCase {
    /// The case's stable id
    /// (`rsassa-pkcs1-v15-<sha>-<bits>/wycheproof-sig-gen/tc<id>-<import>/<schedule>`).
    pub fn case_id(&self) -> String {
        format!(
            // `b<bits>`: see the shared suite's `RsaAlg::name` — a bare
            // `2048` word would violate the component-test case-name
            // grammar (the documented divergence from the incumbent ids).
            "rsassa-pkcs1-v15-{}-b{}/wycheproof-sig-gen/tc{}-{}/{}",
            self.sha_name,
            self.key_bits,
            self.tc_id,
            self.import.name(),
            self.schedule.name(),
        )
    }

    /// The features this case exercises beyond the baseline surface.
    pub fn features(&self) -> &'static [&'static str] {
        &[FEATURE_RSA_SIGN]
    }
}

/// The normalized signature-generation cases. Each vector runs twice —
/// the PKCS#8 import delivers its message whole, the JWK import in
/// one-byte writes, so both import paths and two chunking schedules carry
/// vector coverage without multiplying every vector over the full
/// schedule set (empty messages collapse to one whole write either way).
pub fn cases() -> Vec<RsaSignCase> {
    let mut cases = Vec::new();
    for text in RSA_SIG_GEN_VECTORS {
        let file: VectorFile = serde_json::from_str(text)
            .unwrap_or_else(|err| panic!("parsing rsassa-pkcs1-v15 sig-gen vectors: {err}"));
        for group in &file.test_groups {
            let field = format!("rsassa-pkcs1-v15 sig-gen {}-bit group", group.key_size);
            let Some((variant, sha_name)) = translated_sha(&field, &group.sha) else {
                continue;
            };
            let pkcs8 = unhex(&field, &group.private_key_pkcs8);
            let jwk = group
                .private_key_jwk
                .as_ref()
                .unwrap_or_else(|| panic!("{field} carries no privateKeyJwk"))
                .to_string();
            for test in &group.tests {
                let field = format!("{field} tc{}", test.tc_id);
                match test.result.as_str() {
                    // `acceptable` here always flags `SmallPublicKey`
                    // (e = 3), inside the family's guaranteed-import
                    // exponent floor; generation is deterministic either
                    // way, so both results are known-answer cases.
                    "valid" | "acceptable" => {}
                    other => panic!("vector {field} has unknown result {other:?}"),
                }
                let msg = unhex(&field, &test.msg);
                let sig = unhex(&field, &test.sig);
                for (import, schedule) in [
                    (SignImport::Pkcs8(pkcs8.clone()), Schedule::Whole),
                    (SignImport::Jwk(jwk.clone()), Schedule::Bytes),
                ] {
                    cases.push(RsaSignCase {
                        variant,
                        sha_name,
                        key_bits: group.key_size,
                        tc_id: test.tc_id,
                        import,
                        schedule,
                        msg: msg.clone(),
                        sig: sig.clone(),
                    });
                }
            }
        }
    }
    cases
}

/// A signing-key options resource with `sign` granted, carrying only the
/// `extractable` choice.
fn signing_options(extractable: bool) -> SigningKeyOptions {
    let options = SigningKeyOptions::new();
    options.can_sign(true);
    options.extractable(extractable);
    options
}

/// Run one signature-generation vector: import, sign, byte-compare.
pub async fn run_case(case: &RsaSignCase) -> Result<(), String> {
    let key = match &case.import {
        SignImport::Pkcs8(pkcs8) => rsassa_pkcs1_v15_sign::import_signing_key_pkcs8(
            case.variant,
            pkcs8.clone(),
            signing_options(false),
        )
        .await
        .map_err(|e| describe("import-signing-key-pkcs8", &e))?,
        SignImport::Jwk(jwk) => rsassa_pkcs1_v15_sign::import_signing_key_jwk(
            case.variant,
            jwk.clone(),
            signing_options(false),
        )
        .await
        .map_err(|e| describe("import-signing-key-jwk", &e))?,
    };
    let got = sig_sign_ok(&key, &case.msg, case.schedule).await?;
    expect_bytes(&got, &case.sig, "deterministic EMSA-PKCS1-v1_5 signature")
}

// --- the interface table the probes dispatch over ------------------------------

/// A boxed minting future (each generated binding's `async fn` has its own
/// opaque type, so the table stores wrappers).
type Minted<T> = std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, Error>>>>;

/// One RSA signing interface's minting entry points, so each probe runs
/// identically over both interfaces (the key and options resources are the
/// shared `signature` types; only the minting functions differ).
struct SignIface {
    /// The interface name, as case failures render it.
    label: &'static str,
    /// The `algorithm-name` keys minted here report.
    algorithm: &'static str,
    generate: fn(RsaVariant, RsaModulus, SigningKeyOptions) -> Minted<(SigningKey, VerifyingKey)>,
    import_pkcs8: fn(RsaVariant, Vec<u8>, SigningKeyOptions) -> Minted<SigningKey>,
    import_jwk: fn(RsaVariant, String, SigningKeyOptions) -> Minted<SigningKey>,
    unwrap_pkcs8: fn(RsaVariant, UnwrapInput, SigningKeyOptions) -> Minted<SigningKey>,
    unwrap_jwk: fn(RsaVariant, UnwrapInput, SigningKeyOptions) -> Minted<SigningKey>,
}

/// Both gated RSA signing interfaces, in package order.
const SIGN_IFACES: [SignIface; 2] = [
    SignIface {
        label: "rsassa-pkcs1-v15-sign",
        algorithm: "RSASSA-PKCS1-v1_5",
        generate: |v, m, o| Box::pin(rsassa_pkcs1_v15_sign::generate_key(v, m, o)),
        import_pkcs8: |v, p, o| Box::pin(rsassa_pkcs1_v15_sign::import_signing_key_pkcs8(v, p, o)),
        import_jwk: |v, j, o| Box::pin(rsassa_pkcs1_v15_sign::import_signing_key_jwk(v, j, o)),
        unwrap_pkcs8: |v, i, o| Box::pin(rsassa_pkcs1_v15_sign::unwrap_signing_key_pkcs8(v, i, o)),
        unwrap_jwk: |v, i, o| Box::pin(rsassa_pkcs1_v15_sign::unwrap_signing_key_jwk(v, i, o)),
    },
    SignIface {
        label: "rsa-pss-sign",
        algorithm: "RSA-PSS",
        generate: |v, m, o| Box::pin(rsa_pss_sign::generate_key(v, m, o)),
        import_pkcs8: |v, p, o| Box::pin(rsa_pss_sign::import_signing_key_pkcs8(v, p, o)),
        import_jwk: |v, j, o| Box::pin(rsa_pss_sign::import_signing_key_jwk(v, j, o)),
        unwrap_pkcs8: |v, i, o| Box::pin(rsa_pss_sign::unwrap_signing_key_pkcs8(v, i, o)),
        unwrap_jwk: |v, i, o| Box::pin(rsa_pss_sign::unwrap_signing_key_jwk(v, i, o)),
    },
];

/// The vendored 2048-bit SHA-256 sig-gen group's private key, as (PKCS#8,
/// full-CRT private JWK): known-good import material for the probes,
/// pulled from the compiled-in vectors rather than duplicated as
/// constants.
fn sample_key() -> (Vec<u8>, String) {
    let file: VectorFile = serde_json::from_str(RSA_SIG_GEN_VECTORS[0])
        .unwrap_or_else(|err| panic!("parsing rsassa-pkcs1-v15 sig-gen vectors: {err}"));
    let group = file
        .test_groups
        .iter()
        .find(|group| group.sha == "SHA-256" && group.private_key_jwk.is_some())
        .expect("the 2048-bit file carries a SHA-256 group with a private JWK");
    (
        unhex("2048-bit SHA-256 sig-gen group", &group.private_key_pkcs8),
        group
            .private_key_jwk
            .as_ref()
            .expect("filtered on presence")
            .to_string(),
    )
}

/// Wycheproof `rsa_pkcs1_1024_sig_gen_test.json` (upstream C2SP/wycheproof
/// `testvectors_v1` at commit `b61843a9`, the same revision the vendored
/// vectors came from; the file itself is not vendored — its keys sit below
/// this package's signing window), SHA-256 group `privateKeyPkcs8`: a
/// valid 1024-bit key — inside the family's verification window — that
/// every signing import must reject. The OAEP admission probe
/// (`rsa_oaep`) shares it: the OAEP window has the same 2048-bit floor.
pub(crate) const RSA_1024_SIG_GEN_PKCS8: &str =
    "30820276020100300d06092a864886f70d0101010500048202603082025c0201\
     0002818100ac9048a7a4f560af91b4fcaf62a14595cb9ca9ec12000fc845e485\
     72113cab2890adb011a919575a40760d1f23fe92509c8a5810b6d05990b909dd\
     0f4c6014f2b31b6abd805bace99816e2eda41fd7b95405db7c5c8f4cf6babb14\
     f550d5d0dd5179b54951fff6aa9686f30f478db649b7c7044cc202dccad00343\
     468eaacfbf0203010001028181008505d47c271560aaf6cf65da6d5594a69c86\
     f01622ea194071606fde369b65f5a751bce06052409c3a04c6a8b2be935bc0d0\
     84829dea8ea0998398fd2a0b0719ac1a1ae2d133fcc72d9df27b377b9a0109ef\
     1a564e92b66963356b8da48f88fcdbc20658f74b542582925ec5cd03fb5e9a52\
     7c670465f792a69c1f6c7c5e1841024100d397dcfab4919db23bb6b88c451151\
     6f6135e1118277e496130f0cab3a75661010cc98ec8f40cdb0c1ab612c03bbe3\
     b023d891f46185788fb114437c8a9ae71d024100d0c7805159509ddad70f35b9\
     a76c7c2bd95a844d36b76d96138cfc7a2a55f88072e8b10ac37463caf9bf8d10\
     14c93a001214d7ce230c8332fb58dadb05d52f8b0240762d3c4b7dac5292284d\
     be3701a051864e99e4117e77ede06fd698f1cd5da25a58b79cb58ab0dbf0dbca\
     17249915486ea9269d260b8d9b2f4dec8e60b19d2075024062a4f06eff4944dc\
     6262905ae0cd343a2f9f42058d85cb646e665de086e249e0beea4cc42e276f03\
     374f9721f30044c445c6cd545b610d186883ca1c543c2f1302403cfcf044035c\
     1854475e1dba480ac50d2a059f32d18e819c96a3199b1e3855a653ec0e5577e4\
     d7677d6e0b7a55fc418b13202ee19430228c4bf9d28af8851c9b";

// --- probes ---------------------------------------------------------------------

/// Generated keys carry the mint's contract on both interfaces: the pair
/// is coherent (the returned public half verifies the private half's
/// signatures), the getters report the minted parameterization, the
/// private exports round-trip through both formats to keys that still
/// sign under the original public half, the extractability gate holds,
/// and a grantless mint is refused.
pub async fn rsa_sign_key_contract() -> Result<(), String> {
    let payload = b"rsa signing-key contract payload";
    let (sample_pkcs8, _) = sample_key();
    for iface in &SIGN_IFACES {
        let (key, public) =
            (iface.generate)(RsaVariant::Sha256, RsaModulus::M2048, signing_options(true))
                .await
                .map_err(|e| describe(&format!("{} generate-key", iface.label), &e))?;
        expect(
            key.algorithm_name(),
            iface.algorithm.to_string(),
            "generated signing-key algorithm-name",
        )?;
        expect(
            key.algorithm_hash(),
            Some("SHA-256".to_string()),
            "generated signing-key algorithm-hash",
        )?;
        expect(
            key.algorithm_length(),
            Some(2048),
            "generated signing-key algorithm-length",
        )?;
        expect(
            key.algorithm_curve(),
            None,
            "generated signing-key algorithm-curve",
        )?;
        expect(
            key.extractable(),
            true,
            "generated key's extractable getter",
        )?;
        expect(key.can_sign(), true, "generated key's can-sign getter")?;
        expect(
            public.algorithm_name(),
            iface.algorithm.to_string(),
            "generated verifying-key algorithm-name",
        )?;
        expect(
            public.algorithm_length(),
            Some(2048),
            "generated verifying-key algorithm-length",
        )?;

        let sig = sig_sign_ok(&key, payload, Schedule::Whole).await?;
        expect(sig.len(), 256, "2048-bit signature length")?;
        sig_verify_ok(
            &public,
            payload,
            &sig,
            Schedule::Whole,
            &format!("{}: generated public half did not verify", iface.label),
        )
        .await?;

        // The private exports round-trip: each format re-imports (as
        // non-extractable, proving the mint's options govern the minted
        // key) to a key whose signatures verify under the original
        // public half.
        let pkcs8 = key
            .export_key_pkcs8()
            .await
            .map_err(|e| describe(&format!("{} export-key-pkcs8", iface.label), &e))?;
        let jwk = key
            .export_key_jwk()
            .await
            .map_err(|e| describe(&format!("{} export-key-jwk", iface.label), &e))?;
        for member in [
            "\"kty\"", "\"n\"", "\"d\"", "\"p\"", "\"q\"", "\"dp\"", "\"dq\"", "\"qi\"",
        ] {
            if !jwk.contains(member) {
                return Err(format!(
                    "{}: exported private JWK lacks {member}: {jwk}",
                    iface.label
                ));
            }
        }
        for (what, minted) in [
            (
                "pkcs8",
                (iface.import_pkcs8)(RsaVariant::Sha256, pkcs8, signing_options(false))
                    .await
                    .map_err(|e| describe("re-import of exported PKCS#8", &e))?,
            ),
            (
                "jwk",
                (iface.import_jwk)(RsaVariant::Sha256, jwk, signing_options(false))
                    .await
                    .map_err(|e| describe("re-import of exported JWK", &e))?,
            ),
        ] {
            expect(
                minted.extractable(),
                false,
                &format!("{what} re-import's extractable getter"),
            )?;
            let sig = sig_sign_ok(&minted, payload, Schedule::Whole).await?;
            sig_verify_ok(
                &public,
                payload,
                &sig,
                Schedule::Whole,
                &format!("{}: {what} re-import did not verify", iface.label),
            )
            .await?;
        }

        // The extractability gate, on an imported non-extractable key
        // (no second generation needed).
        let sealed = (iface.import_pkcs8)(
            RsaVariant::Sha256,
            sample_pkcs8.clone(),
            signing_options(false),
        )
        .await
        .map_err(|e| describe(&format!("{} import-signing-key-pkcs8", iface.label), &e))?;
        expect_err(
            &format!("{} export-key-pkcs8", iface.label),
            ErrKind::NotExtractable,
            sealed.export_key_pkcs8().await,
            "exported a non-extractable signing key",
        )?;
        expect_err(
            &format!("{} export-key-jwk", iface.label),
            ErrKind::NotExtractable,
            sealed.export_key_jwk().await,
            "exported a non-extractable signing key",
        )?;

        // `can-sign` is the sole usage, so an untouched options resource
        // fails the mint `not-permitted`.
        expect_err(
            &format!("{} generate-key without grants", iface.label),
            ErrKind::NotPermitted,
            (iface.generate)(
                RsaVariant::Sha256,
                RsaModulus::M2048,
                SigningKeyOptions::new(),
            )
            .await,
            "minted a signing key with no usage granted",
        )?;
        expect_err(
            &format!("{} import without grants", iface.label),
            ErrKind::NotPermitted,
            (iface.import_pkcs8)(
                RsaVariant::Sha256,
                sample_pkcs8.clone(),
                SigningKeyOptions::new(),
            )
            .await,
            "minted a signing key with no usage granted",
        )?;
    }
    Ok(())
}

/// RSA-PSS signing round-trips at every variant: keys minted by
/// `rsa-pss-sign` sign with salt = digest length (the fixed contract —
/// `rsa-pss-verify` mints bound to that salt length verify them), and a
/// salt-0 mint of the same public key rejects the signature
/// `authentication-failed`.
pub async fn rsa_pss_sign_round_trip() -> Result<(), String> {
    let payload = b"rsa-pss round-trip payload";
    for (variant, digest_len) in [
        (RsaVariant::Sha256, 32u32),
        (RsaVariant::Sha384, 48),
        (RsaVariant::Sha512, 64),
    ] {
        let (key, public) =
            rsa_pss_sign::generate_key(variant, RsaModulus::M2048, signing_options(false))
                .await
                .map_err(|e| describe("rsa-pss-sign generate-key", &e))?;
        let sig = sig_sign_ok(&key, payload, Schedule::Whole).await?;
        sig_verify_ok(
            &public,
            payload,
            &sig,
            Schedule::Whole,
            "generated public half did not verify",
        )
        .await?;

        // The public half through `rsa-pss-verify`: the salt = digest
        // length mint verifies, a salt-0 mint of the same key does not.
        let spki = public
            .export_key_spki()
            .await
            .map_err(|e| describe("export-key-spki (public)", &e))?;
        let bound = rsa_pss_verify::import_verifying_key_spki(variant, digest_len, spki.clone())
            .await
            .map_err(|e| describe("rsa-pss-verify import (salt = digest length)", &e))?;
        sig_verify_ok(
            &bound,
            payload,
            &sig,
            Schedule::Whole,
            "signature did not verify under the salt = digest-length mint",
        )
        .await?;
        let salt0 = rsa_pss_verify::import_verifying_key_spki(variant, 0, spki)
            .await
            .map_err(|e| describe("rsa-pss-verify import (salt 0)", &e))?;
        let verified = sig_verify_op(&salt0, payload, &sig, Schedule::Whole).await?;
        expect_err(
            "verify under a salt-0 mint",
            ErrKind::AuthenticationFailed,
            verified,
            "a fixed-salt signature verified under a salt-0 binding",
        )?;
    }
    Ok(())
}

/// The signing-import admission edges: a valid 1024-bit key — inside the
/// family's verification window but below the signing interfaces'
/// 2048-bit floor — fails `invalid-key` on both interfaces, as do a
/// partial-CRT private JWK (the platforms require the full two-prime CRT
/// form) and a public-only (`d`-less) JWK.
pub async fn rsa_sign_admission() -> Result<(), String> {
    let pkcs8_1024 = data_encoding::HEXLOWER
        .decode(RSA_1024_SIG_GEN_PKCS8.as_bytes())
        .expect("probe hex constants are valid");
    let (_, sample_jwk) = sample_key();
    let parsed: serde_json::Value =
        serde_json::from_str(&sample_jwk).expect("vector JWKs are valid JSON");
    // Strip the JOSE alg (RS256), so the same material imports under both
    // interfaces and the rejection under test is the member's absence.
    let strip = |members: &[&str]| {
        let mut jwk = parsed.clone();
        let object = jwk.as_object_mut().expect("vector JWKs are objects");
        for member in members {
            object.remove(*member);
        }
        jwk.to_string()
    };
    for iface in &SIGN_IFACES {
        expect_err(
            &format!("{} 1024-bit pkcs8", iface.label),
            ErrKind::InvalidKey,
            (iface.import_pkcs8)(
                RsaVariant::Sha256,
                pkcs8_1024.clone(),
                signing_options(false),
            )
            .await,
            "imported a modulus below the signing interfaces' 2048-bit floor",
        )?;
        expect_err(
            &format!("{} partial-CRT JWK", iface.label),
            ErrKind::InvalidKey,
            (iface.import_jwk)(
                RsaVariant::Sha256,
                strip(&["alg", "qi"]),
                signing_options(false),
            )
            .await,
            "imported a private JWK missing a CRT member",
        )?;
        expect_err(
            &format!("{} d-less JWK", iface.label),
            ErrKind::InvalidKey,
            (iface.import_jwk)(
                RsaVariant::Sha256,
                strip(&["alg", "d", "p", "q", "dp", "dq", "qi"]),
                signing_options(false),
            )
            .await,
            "imported a public JWK as a signing key",
        )?;
    }
    Ok(())
}

/// The two-way feature guarantee, serving side: a target that does not
/// declare `rsa-sign` missing serves its minting paths (here the cheap
/// imports; generation and the unwrap mints are covered by the other
/// probes). The declining side is [`minting_declined`], which
/// `run_declined` runs for every `rsa-sign`-tagged case on a target
/// declaring the feature missing.
pub async fn rsa_sign_declined() -> Result<(), String> {
    let (pkcs8, jwk) = sample_key();
    for iface in &SIGN_IFACES {
        (iface.import_pkcs8)(RsaVariant::Sha256, pkcs8.clone(), signing_options(false))
            .await
            .map_err(|e| describe(&format!("{} import-signing-key-pkcs8", iface.label), &e))?;
        // The sample JWK carries upstream's `alg: "RS256"`, which only the
        // v1.5 interface accepts; strip it for the PSS import.
        let jwk = if iface.algorithm == "RSA-PSS" {
            let mut parsed: serde_json::Value =
                serde_json::from_str(&jwk).expect("vector JWKs are valid JSON");
            parsed
                .as_object_mut()
                .expect("vector JWKs are objects")
                .remove("alg");
            parsed.to_string()
        } else {
            jwk.clone()
        };
        (iface.import_jwk)(RsaVariant::Sha256, jwk, signing_options(false))
            .await
            .map_err(|e| describe(&format!("{} import-signing-key-jwk", iface.label), &e))?;
    }
    Ok(())
}

/// Mint an unwrap-input carrying `payload`: imported as an extractable
/// HMAC key (the raw wrap form of a MAC key is its bytes — there is no
/// direct bytes path to a `wrap-input`), wrapped under a fresh AES-GCM
/// KEK, then unwrapped. Everything here is feature-independent baseline
/// surface, so the decline probes (this module's and `rsa_oaep`'s) share
/// it.
pub(crate) async fn unwrap_input_of(payload: Vec<u8>) -> Result<UnwrapInput, String> {
    use lann_webcrypto_guest::bindings::aead::AeadKeyOptions;
    use lann_webcrypto_guest::bindings::hmac_sha2;
    use lann_webcrypto_guest::bindings::mac::MacKeyOptions;
    use lann_webcrypto_guest::bindings::sha2::Sha2Variant;
    use lann_webcrypto_guest::bindings::{aes_gcm, wrapping};

    let carrier_options = MacKeyOptions::new();
    carrier_options.can_sign(true);
    carrier_options.extractable(true);
    let carrier = hmac_sha2::import_key_raw(Sha2Variant::Sha256, payload, carrier_options)
        .await
        .map_err(|e| describe("carrier import", &e))?;
    let input: wrapping::WrapInput = carrier
        .to_wrap_input_raw()
        .await
        .map_err(|e| describe("to-wrap-input-raw", &e))?;

    let kek_options = AeadKeyOptions::new();
    kek_options.can_wrap(true);
    kek_options.can_unwrap(true);
    let kek = aes_gcm::generate_key(aes_gcm::AesVariant::Aes256, kek_options)
        .await
        .map_err(|e| describe("kek generate-key", &e))?;
    let nonce = vec![0x51u8; 12];
    let aad = b"rsa-sign decline probe".to_vec();
    let wrapped = kek
        .wrap(nonce.clone(), aad.clone(), None, input)
        .await
        .map_err(|e| describe("aead-key.wrap", &e))?;
    kek.unwrap(nonce, aad, None, wrapped)
        .await
        .map_err(|e| describe("aead-key.unwrap", &e))
}

/// Assert that every RSA signing minting path declines `unsupported` on a
/// target declaring `rsa-sign` missing: generation, both imports, and
/// both unwrap mints, on both interfaces — ten paths. The unwrap payloads
/// are known-good material, so the only condition in play is service (a
/// declining target must not answer `invalid-key` from format validation
/// instead).
pub async fn minting_declined() -> Result<String, String> {
    let (pkcs8, jwk) = sample_key();
    let accepted = "minted a key: the target serves a feature it declares missing";
    for iface in &SIGN_IFACES {
        expect_err(
            &format!("{} generate-key", iface.label),
            ErrKind::Unsupported,
            (iface.generate)(
                RsaVariant::Sha256,
                RsaModulus::M2048,
                signing_options(false),
            )
            .await,
            accepted,
        )?;
        expect_err(
            &format!("{} import-signing-key-pkcs8", iface.label),
            ErrKind::Unsupported,
            (iface.import_pkcs8)(RsaVariant::Sha256, pkcs8.clone(), signing_options(false)).await,
            accepted,
        )?;
        expect_err(
            &format!("{} import-signing-key-jwk", iface.label),
            ErrKind::Unsupported,
            (iface.import_jwk)(RsaVariant::Sha256, jwk.clone(), signing_options(false)).await,
            accepted,
        )?;
        expect_err(
            &format!("{} unwrap-signing-key-pkcs8", iface.label),
            ErrKind::Unsupported,
            (iface.unwrap_pkcs8)(
                RsaVariant::Sha256,
                unwrap_input_of(pkcs8.clone()).await?,
                signing_options(false),
            )
            .await,
            accepted,
        )?;
        expect_err(
            &format!("{} unwrap-signing-key-jwk", iface.label),
            ErrKind::Unsupported,
            (iface.unwrap_jwk)(
                RsaVariant::Sha256,
                unwrap_input_of(jwk.clone().into_bytes()).await?,
                signing_options(false),
            )
            .await,
            accepted,
        )?;
    }
    Ok("every RSA signing minting path declined unsupported".into())
}
