//! `conformance-signing-guest`: the host-only conformance component.
//!
//! Probes the signature-minting surface the in-guest provider deliberately
//! does not export — `ecdsa-sign` is class D (see guest-impl/README.md) —
//! which the shared `conformance-guest` therefore cannot import, since it
//! must compose with that provider. This guest runs only under the
//! host-backed targets (wasmtime, jco).
//!
//! This suite is probes only, and deliberately exercises **generated
//! keys, never imported private ones**: browser hosts can only realize
//! `import-signing-key` by importing private-only PKCS#8, whose platform
//! behavior is unspecified and inconsistent across engines
//! (w3c/webcrypto#356) — a portability hazard, not a conformance subject.
//! The private-import known answers this suite therefore cannot carry
//! (the RFC 6979 A.2.5 deterministic signature, scalar export identity,
//! known-point public derivation, out-of-range scalar rejection) are
//! pinned by `webcrypto-impl-core`'s unit tests, which cover both Rust
//! implementations portably.

wit_bindgen::generate!({
    path: "../guest/wit",
    world: "signing-guest",
    generate_all,
});

use std::collections::BTreeSet;

use exports::conformance::webcrypto::tests::{Guest, GuestTestCase, Outcome, TestCase};
use lann_webcrypto_guest::bindings::ecdsa_sign::generate_key;
use lann_webcrypto_guest::bindings::ecdsa_verify::{import_verifying_key, EcdsaVariant};
use lann_webcrypto_guest::bindings::signature::{SigningKey, VerifyingKey};
use lann_webcrypto_guest::bindings::types::Error;

/// The feature names shared with the conformance guest (`all` traps on
/// anything else), so a target passes one `missing` declaration to every
/// guest it runs. `chacha20-poly1305` tags nothing in this suite.
const FEATURE_CHACHA: &str = "chacha20-poly1305";
const FEATURE_ECDSA_SIGN: &str = "ecdsa-sign";
const KNOWN_FEATURES: &[&str] = &[FEATURE_CHACHA, FEATURE_ECDSA_SIGN];

struct Component;

/// One probe: its name (`probe/<name>` case ids) and the features it
/// exercises beyond the baseline surface.
struct Probe {
    name: &'static str,
    features: &'static [&'static str],
    run: ProbeFn,
}

/// A probe body. Boxed because each `async fn` has its own opaque type.
type ProbeFn = fn() -> core::pin::Pin<Box<dyn core::future::Future<Output = Result<(), String>>>>;

/// The probes, in suite order. Name, features and body are one row: kept as
/// parallel lists, inserting or reordering one alone re-points a name at
/// another probe's body, which then asserts the wrong thing and passes.
const PROBES: &[Probe] = &[
    Probe {
        name: "ecdsa-p256-sign-roundtrip",
        features: &[],
        run: || Box::pin(p256_sign_roundtrip()),
    },
    Probe {
        name: "ecdsa-p384-generate-roundtrip",
        features: &[],
        run: || Box::pin(p384_generate_roundtrip()),
    },
    Probe {
        name: "ecdsa-sign-key-export",
        features: &[],
        run: || Box::pin(sign_key_export()),
    },
    Probe {
        name: "ecdsa-sign-invalid-scalar",
        features: &[],
        run: || Box::pin(sign_invalid_scalar()),
    },
];

/// Run the probe at `index` on a target providing its features.
async fn run_one(index: usize) -> Result<(), String> {
    match PROBES.get(index) {
        Some(probe) => (probe.run)().await,
        None => Err(format!("no probe at index {index}")),
    }
}

/// One materialized signing probe.
struct Case {
    index: usize,
    provided: bool,
}

impl GuestTestCase for Case {
    fn name(&self) -> String {
        format!("probe/{}", PROBES[self.index].name)
    }

    fn features(&self) -> Vec<String> {
        PROBES[self.index]
            .features
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    async fn run(&self) -> Outcome {
        if self.provided {
            match run_one(self.index).await {
                Ok(()) => Outcome::Pass,
                Err(detail) => Outcome::Fail(detail),
            }
        } else {
            // No probe in this suite is feature-tagged today; `provided`
            // is computed generically so a future tagged probe fails
            // loudly here until it brings a decline assertion.
            Outcome::Fail("probe has no decline assertion for its features".into())
        }
    }
}

impl Guest for Component {
    type TestCase = Case;

    fn all(missing_features: Vec<String>) -> Vec<TestCase> {
        let mut set = BTreeSet::new();
        for feature in &missing_features {
            assert!(
                KNOWN_FEATURES.contains(&feature.as_str()),
                "unknown feature {feature:?} in the missing declaration (known: {KNOWN_FEATURES:?})"
            );
            set.insert(feature.as_str());
        }
        PROBES
            .iter()
            .enumerate()
            .map(|(index, probe)| {
                TestCase::new(Case {
                    index,
                    provided: probe.features.iter().all(|f| !set.contains(f)),
                })
            })
            .collect()
    }
}

// --- helpers -------------------------------------------------------------------

fn describe(context: &str, error: &Error) -> String {
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

/// Sign an entire byte stream (whole-write).
async fn sign(key: &SigningKey, data: &[u8]) -> Result<Vec<u8>, String> {
    let (mut tx, rx) = lann_webcrypto_guest::wit_stream::new();
    let (sig, ()) = futures::join!(key.sign(rx), async {
        let leftover = tx.write_all(data.to_vec()).await;
        assert!(leftover.is_empty(), "stream writer closed early");
        drop(tx);
    });
    sig.map_err(|e| describe("signing-key.sign", &e))
}

/// Verify `sig` over an entire byte stream (whole-write).
async fn verify(key: &VerifyingKey, data: &[u8], sig: &[u8]) -> Result<(), Error> {
    let (mut tx, rx) = lann_webcrypto_guest::wit_stream::new();
    let (verified, ()) = futures::join!(key.verify(rx, sig.to_vec()), async {
        let leftover = tx.write_all(data.to_vec()).await;
        assert!(leftover.is_empty(), "stream writer closed early");
        drop(tx);
    });
    verified
}

// --- probes --------------------------------------------------------------------

/// A generated P-256 key reports its variant through the getters, its
/// signatures verify — both under the public half returned with it and
/// under the same point exported and re-imported through `ecdsa-verify` —
/// and a corrupted signature fails `authentication-failed`.
async fn p256_sign_roundtrip() -> Result<(), String> {
    let (key, public) = generate_key(EcdsaVariant::P256Sha256, false)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    if key.algorithm_name() != "ECDSA"
        || key.algorithm_curve().as_deref() != Some("P-256")
        || key.algorithm_hash().as_deref() != Some("SHA-256")
    {
        return Err(format!(
            "signing-key metadata: name={} curve={:?} hash={:?}",
            key.algorithm_name(),
            key.algorithm_curve(),
            key.algorithm_hash()
        ));
    }

    let payload = b"host-only signing payload";
    let sig = sign(&key, payload).await?;
    if sig.len() != 64 {
        return Err(format!("P-256 signatures are 64 bytes, got {}", sig.len()));
    }
    verify(&public, payload, &sig)
        .await
        .map_err(|e| describe("generated public half did not verify", &e))?;

    // The generated point survives an export → ecdsa-verify import round
    // trip (65-byte uncompressed SEC1), and the re-imported key verifies.
    let point = public.export_key().await;
    if point.len() != 65 || point[0] != 0x04 {
        return Err(format!(
            "exported public key is not a 65-byte uncompressed SEC1 point ({} bytes)",
            point.len()
        ));
    }
    let imported = import_verifying_key(EcdsaVariant::P256Sha256, point)
        .await
        .map_err(|e| describe("import-verifying-key of the exported point", &e))?;
    verify(&imported, payload, &sig)
        .await
        .map_err(|e| describe("re-imported key did not verify", &e))?;

    let mut corrupted = sig;
    corrupted[0] ^= 0x01;
    match verify(&imported, payload, &corrupted).await {
        Err(Error::AuthenticationFailed) => Ok(()),
        Err(other) => Err(describe("expected authentication-failed, got", &other)),
        Ok(()) => Err("corrupted signature verified".into()),
    }
}

/// A generated P-384 key round-trips sign→verify, and a *different* key's
/// public half rejects the signature.
async fn p384_generate_roundtrip() -> Result<(), String> {
    let (key, public) = generate_key(EcdsaVariant::P384Sha384, false)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    if key.algorithm_curve().as_deref() != Some("P-384")
        || key.algorithm_hash().as_deref() != Some("SHA-384")
    {
        return Err(format!(
            "generated signing-key metadata: curve={:?} hash={:?}",
            key.algorithm_curve(),
            key.algorithm_hash()
        ));
    }

    let payload = b"host-only signing payload";
    let sig = sign(&key, payload).await?;
    if sig.len() != 96 {
        return Err(format!("P-384 signatures are 96 bytes, got {}", sig.len()));
    }
    verify(&public, payload, &sig)
        .await
        .map_err(|e| describe("round-trip signature did not verify", &e))?;

    let (_other, other_public) = generate_key(EcdsaVariant::P384Sha384, false)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    match verify(&other_public, payload, &sig).await {
        Err(Error::AuthenticationFailed) => Ok(()),
        Err(other) => Err(describe("expected authentication-failed, got", &other)),
        Ok(()) => Err("signature verified under a different key".into()),
    }
}

/// An extractable generated key exports a 32-byte scalar, stably; a
/// non-extractable one fails `not-extractable`. (Export *identity* against
/// a known scalar needs private-key import, which is deliberately out of
/// this suite — impl-core's unit tests pin it for the Rust
/// implementations.)
async fn sign_key_export() -> Result<(), String> {
    let (key, _public) = generate_key(EcdsaVariant::P256Sha256, true)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    if !key.extractable() {
        return Err("extractable key reports non-extractable".into());
    }
    let exported = key.export_key().await.map_err(|e| describe("export", &e))?;
    if exported.len() != 32 {
        return Err(format!(
            "exported P-256 scalar: got {} bytes, want 32",
            exported.len()
        ));
    }
    let again = key
        .export_key()
        .await
        .map_err(|e| describe("second export", &e))?;
    if again != exported {
        return Err("two exports of the same key differ".into());
    }

    let (key, _public) = generate_key(EcdsaVariant::P256Sha256, false)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    // Read the getter in its `false` direction: asserting only `true`
    // elsewhere leaves a hardcoded `true` passing the suite.
    if key.extractable() {
        return Err("non-extractable generated key reports extractable".into());
    }
    match key.export_key().await {
        Err(Error::NotExtractable) => Ok(()),
        Err(other) => Err(describe("expected not-extractable, got", &other)),
        Ok(_) => Err("non-extractable key exported".into()),
    }
}

/// Wrong-length scalars fail `invalid-key` at import. Only the length
/// cases run here — every implementation validates length before touching
/// a platform — while *range* validation (zero, ≥ the group order) rides
/// the unspecified private-only PKCS#8 import path on browser hosts
/// (w3c/webcrypto#356) and is pinned by impl-core's unit tests instead.
async fn sign_invalid_scalar() -> Result<(), String> {
    use lann_webcrypto_guest::bindings::ecdsa_sign::import_signing_key;

    async fn expect_invalid(what: &str, variant: EcdsaVariant, raw: Vec<u8>) -> Result<(), String> {
        match import_signing_key(variant, raw, false).await {
            Err(Error::InvalidKey(_)) => Ok(()),
            Err(other) => Err(format!(
                "{what}: expected invalid-key, got {}",
                describe("", &other)
            )),
            Ok(_) => Err(format!("{what}: malformed scalar was accepted")),
        }
    }

    expect_invalid("short scalar", EcdsaVariant::P256Sha256, vec![0x01; 16]).await?;
    expect_invalid(
        "p384 scalar for p256",
        EcdsaVariant::P256Sha256,
        vec![0x01; 48],
    )
    .await
}

export!(Component);
