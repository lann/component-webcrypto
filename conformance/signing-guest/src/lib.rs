//! `conformance-signing-guest`: the host-only conformance component.
//!
//! Probes the signature-minting surface the in-guest provider deliberately
//! does not export — `ecdsa-sign` is class D (see guest-impl/README.md) —
//! which the shared `conformance-guest` therefore cannot import, since it
//! must compose with that provider. This guest runs only under the
//! host-backed targets (wasmtime, jco).
//!
//! The corpus here is probes only: ECDSA signing has no cross-implementation
//! known answers (WebCrypto signs with a randomized `k`, RustCrypto with
//! RFC 6979's deterministic one), so behavior is pinned by round trips plus
//! one deterministic known-answer probe tagged with the
//! `deterministic-ecdsa` feature — a target declaring that feature missing
//! gets the two-way decline assertion (its signatures must actually be
//! randomized) instead.

wit_bindgen::generate!({
    path: "../guest/wit",
    world: "signing-guest",
    generate_all,
});

use std::collections::BTreeSet;

use exports::conformance::webcrypto::tests::{Guest, GuestTestCase, Outcome, TestCase};
use lann::webcrypto::ecdsa_sign::{generate_key, import_signing_key};
use lann::webcrypto::ecdsa_verify::{import_verifying_key, EcdsaVariant};
use lann::webcrypto::signature::{SigningKey, VerifyingKey};
use lann::webcrypto::types::Error;

/// The feature names shared with the conformance guest (`all` traps on
/// anything else), so a target passes one `missing` declaration to every
/// guest it runs. `chacha20-poly1305` tags nothing in this corpus.
const FEATURE_CHACHA: &str = "chacha20-poly1305";
const FEATURE_DETERMINISTIC_ECDSA: &str = "deterministic-ecdsa";
const FEATURE_ECDSA_SIGN: &str = "ecdsa-sign";
const KNOWN_FEATURES: &[&str] = &[
    FEATURE_CHACHA,
    FEATURE_DETERMINISTIC_ECDSA,
    FEATURE_ECDSA_SIGN,
];

// --- RFC 6979 A.2.5 (ECDSA P-256 + SHA-256, message "sample") ----------------

const P256_PRIVATE: &str = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
const P256_PUBLIC_X: &str = "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6";
const P256_PUBLIC_Y: &str = "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";
const P256_MESSAGE: &[u8] = b"sample";
const P256_SIG_R: &str = "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716";
const P256_SIG_S: &str = "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8";

struct Component;

/// One probe: its name (`probe/<name>` case ids) and the features it
/// exercises beyond the baseline surface.
struct Probe {
    name: &'static str,
    features: &'static [&'static str],
}

/// The probes, in corpus order. `run_one(i)` runs `PROBES[i]`.
const PROBES: &[Probe] = &[
    Probe {
        name: "ecdsa-p256-sign-roundtrip",
        features: &[],
    },
    Probe {
        name: "ecdsa-p384-generate-roundtrip",
        features: &[],
    },
    Probe {
        name: "ecdsa-sign-key-export",
        features: &[],
    },
    Probe {
        name: "ecdsa-sign-invalid-scalar",
        features: &[],
    },
    Probe {
        name: "ecdsa-sign-deterministic-rfc6979",
        features: &[FEATURE_DETERMINISTIC_ECDSA],
    },
];

/// Run the probe at `index` on a target providing its features.
async fn run_one(index: usize) -> Result<(), String> {
    match index {
        0 => p256_sign_roundtrip().await,
        1 => p384_generate_roundtrip().await,
        2 => sign_key_export().await,
        3 => sign_invalid_scalar().await,
        4 => sign_deterministic_rfc6979().await,
        _ => Err(format!("no probe at index {index}")),
    }
}

/// Run the probe at `index` on a target declaring its features missing:
/// assert the correct alternative behavior. The only tagged probe is the
/// RFC 6979 known answer, whose decline assertion is that signing is
/// actually randomized (and still verifies) — a target signing
/// deterministically while declaring `deterministic-ecdsa` missing fails.
async fn run_declined(index: usize) -> Result<String, String> {
    match PROBES.get(index).map(|probe| probe.features) {
        Some(features) if features == [FEATURE_DETERMINISTIC_ECDSA] => {
            sign_randomized_declined().await
        }
        Some(_) => Err("probe has no decline assertion for its features".into()),
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
            match run_declined(self.index).await {
                Ok(detail) => Outcome::Skipped(detail),
                Err(detail) => Outcome::Fail(detail),
            }
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

fn unhex(hex: &str) -> Vec<u8> {
    hex::decode(hex).expect("probe hex constants are valid")
}

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
    let (mut tx, rx) = wit_stream::new();
    let (sig, ()) = futures::join!(key.sign(rx), async {
        let leftover = tx.write_all(data.to_vec()).await;
        assert!(leftover.is_empty(), "stream writer closed early");
        drop(tx);
    });
    sig.map_err(|e| describe("signing-key.sign", &e))
}

/// Verify `sig` over an entire byte stream (whole-write).
async fn verify(key: &VerifyingKey, data: &[u8], sig: &[u8]) -> Result<(), Error> {
    let (mut tx, rx) = wit_stream::new();
    let (verified, ()) = futures::join!(key.verify(rx, sig.to_vec()), async {
        let leftover = tx.write_all(data.to_vec()).await;
        assert!(leftover.is_empty(), "stream writer closed early");
        drop(tx);
    });
    verified
}

/// The RFC 6979 A.2.5 public key as an uncompressed SEC1 point.
fn p256_public_point() -> Vec<u8> {
    let mut point = vec![0x04];
    point.extend(unhex(P256_PUBLIC_X));
    point.extend(unhex(P256_PUBLIC_Y));
    point
}

// --- probes --------------------------------------------------------------------

/// An imported P-256 scalar reports its variant through the getters, its
/// derived public key matches the known point, its signatures verify (under
/// both the derived key and an independently imported one), and a corrupted
/// signature fails `authentication-failed`.
async fn p256_sign_roundtrip() -> Result<(), String> {
    let key = import_signing_key(EcdsaVariant::P256Sha256, unhex(P256_PRIVATE), false)
        .await
        .map_err(|e| describe("import-signing-key", &e))?;
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

    let derived = key.verifying_key();
    let exported = derived.export_key().await;
    if exported != p256_public_point() {
        return Err("derived public key does not match the RFC 6979 point".into());
    }

    let sig = sign(&key, P256_MESSAGE).await?;
    if sig.len() != 64 {
        return Err(format!("P-256 signatures are 64 bytes, got {}", sig.len()));
    }
    verify(&derived, P256_MESSAGE, &sig)
        .await
        .map_err(|e| describe("derived key did not verify", &e))?;

    let imported = import_verifying_key(EcdsaVariant::P256Sha256, p256_public_point())
        .await
        .map_err(|e| describe("import-verifying-key", &e))?;
    verify(&imported, P256_MESSAGE, &sig)
        .await
        .map_err(|e| describe("imported key did not verify", &e))?;

    let mut corrupted = sig;
    corrupted[0] ^= 0x01;
    match verify(&imported, P256_MESSAGE, &corrupted).await {
        Err(Error::AuthenticationFailed) => Ok(()),
        Err(other) => Err(describe("expected authentication-failed, got", &other)),
        Ok(()) => Err("corrupted signature verified".into()),
    }
}

/// A generated P-384 key round-trips sign→verify, and a *different* key's
/// public half rejects the signature.
async fn p384_generate_roundtrip() -> Result<(), String> {
    let key = generate_key(EcdsaVariant::P384Sha384, false)
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
    verify(&key.verifying_key(), payload, &sig)
        .await
        .map_err(|e| describe("round-trip signature did not verify", &e))?;

    let other = generate_key(EcdsaVariant::P384Sha384, false)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    match verify(&other.verifying_key(), payload, &sig).await {
        Err(Error::AuthenticationFailed) => Ok(()),
        Err(other) => Err(describe("expected authentication-failed, got", &other)),
        Ok(()) => Err("signature verified under a different key".into()),
    }
}

/// An extractable imported key exports the scalar it was imported from; a
/// non-extractable one fails `not-extractable`.
async fn sign_key_export() -> Result<(), String> {
    let key = import_signing_key(EcdsaVariant::P256Sha256, unhex(P256_PRIVATE), true)
        .await
        .map_err(|e| describe("import-signing-key", &e))?;
    if !key.extractable() {
        return Err("extractable key reports non-extractable".into());
    }
    let exported = key.export_key().await.map_err(|e| describe("export", &e))?;
    if exported != unhex(P256_PRIVATE) {
        return Err("exported scalar does not round-trip".into());
    }

    let key = import_signing_key(EcdsaVariant::P256Sha256, unhex(P256_PRIVATE), false)
        .await
        .map_err(|e| describe("import-signing-key", &e))?;
    match key.export_key().await {
        Err(Error::NotExtractable) => Ok(()),
        Err(other) => Err(describe("expected not-extractable, got", &other)),
        Ok(_) => Err("non-extractable key exported".into()),
    }
}

/// Malformed scalars fail `invalid-key`: wrong lengths, zero (out of range),
/// and all-ones (≥ the group order).
async fn sign_invalid_scalar() -> Result<(), String> {
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
    .await?;
    expect_invalid("zero scalar", EcdsaVariant::P256Sha256, vec![0x00; 32]).await?;
    expect_invalid(
        "scalar above the group order",
        EcdsaVariant::P256Sha256,
        vec![0xff; 32],
    )
    .await
}

/// The RFC 6979 deterministic known answer: signing "sample" with the A.2.5
/// key reproduces the vector's `r ‖ s` exactly. Runs only on targets
/// providing the `deterministic-ecdsa` feature (RustCrypto); randomized-`k`
/// targets (WebCrypto) declare it missing and get
/// [`sign_randomized_declined`] instead.
async fn sign_deterministic_rfc6979() -> Result<(), String> {
    let key = import_signing_key(EcdsaVariant::P256Sha256, unhex(P256_PRIVATE), false)
        .await
        .map_err(|e| describe("import-signing-key", &e))?;
    let sig = sign(&key, P256_MESSAGE).await?;
    let mut expected = unhex(P256_SIG_R);
    expected.extend(unhex(P256_SIG_S));
    if sig != expected {
        return Err(format!(
            "signature is not the RFC 6979 deterministic one (randomized k? declare the \
             deterministic-ecdsa feature missing): got {}",
            hex::encode(&sig)
        ));
    }
    Ok(())
}

/// The decline assertion for a target declaring `deterministic-ecdsa`
/// missing: two signatures over the same message must differ (randomized
/// `k`) while still verifying. A target that signs deterministically while
/// declaring the feature missing fails.
async fn sign_randomized_declined() -> Result<String, String> {
    let key = import_signing_key(EcdsaVariant::P256Sha256, unhex(P256_PRIVATE), false)
        .await
        .map_err(|e| describe("import-signing-key", &e))?;
    let first = sign(&key, P256_MESSAGE).await?;
    let second = sign(&key, P256_MESSAGE).await?;
    if first == second {
        return Err(
            "two signatures over the same message are identical: the target signs \
             deterministically but declares the deterministic-ecdsa feature missing"
                .into(),
        );
    }
    verify(&key.verifying_key(), P256_MESSAGE, &first)
        .await
        .map_err(|e| describe("randomized signature did not verify", &e))?;
    Ok("signatures are randomized (and verify); deterministic-ecdsa declared missing".into())
}

export!(Component);
