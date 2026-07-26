//! `conformance-signing-guest`: the host-only conformance component.
//!
//! Probes the signature-minting surface the in-guest provider deliberately
//! does not export — `ecdsa-sign` is class D (see guest-impl/README.md) —
//! which the shared `conformance-guest` therefore cannot import, since it
//! must compose with that provider. This guest runs only under the
//! host-backed targets (wasmtime, jco); its results merge into the same
//! per-target files the runner consumes.
//!
//! The corpus here is probes only: ECDSA signing has no cross-implementation
//! known answers (WebCrypto signs with a randomized `k`, RustCrypto with
//! RFC 6979's deterministic one), so behavior is pinned by round trips plus
//! one deterministic known-answer probe that per-target manifests expect to
//! fail on randomized implementations.

wit_bindgen::generate!({
    path: "../guest/wit",
    world: "signing-guest",
    generate_all,
});

use exports::conformance::webcrypto::tests::{Guest, TestResult};
use lann::webcrypto::ecdsa_sign::{generate_key, import_signing_key};
use lann::webcrypto::ecdsa_verify::{import_verifying_key, EcdsaVariant};
use lann::webcrypto::signature::{SigningKey, VerifyingKey};
use lann::webcrypto::types::Error;

// --- RFC 6979 A.2.5 (ECDSA P-256 + SHA-256, message "sample") ----------------

const P256_PRIVATE: &str = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
const P256_PUBLIC_X: &str = "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6";
const P256_PUBLIC_Y: &str = "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";
const P256_MESSAGE: &[u8] = b"sample";
const P256_SIG_R: &str = "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716";
const P256_SIG_S: &str = "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8";

struct Component;

/// The probe names, in corpus order (`probe/<name>` ids).
const NAMES: &[&str] = &[
    "ecdsa-p256-sign-roundtrip",
    "ecdsa-p384-generate-roundtrip",
    "ecdsa-sign-key-export",
    "ecdsa-sign-invalid-scalar",
    "ecdsa-sign-deterministic-rfc6979",
];

/// Run the probe at `index` (into [`NAMES`]).
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

impl Guest for Component {
    fn count() -> u32 {
        NAMES.len() as u32
    }

    fn list_tests() -> Vec<String> {
        NAMES.iter().map(|name| format!("probe/{name}")).collect()
    }

    async fn run_all() -> Vec<TestResult> {
        run_slice_impl(0, u32::MAX).await
    }

    async fn run_slice(skip: u32, take: u32) -> Vec<TestResult> {
        run_slice_impl(skip, take).await
    }

    async fn run_many(tests: Vec<String>) -> Vec<TestResult> {
        let mut results = Vec::with_capacity(tests.len());
        for id in tests {
            let index = NAMES.iter().position(|name| format!("probe/{name}") == id);
            results.push(match index {
                Some(index) => to_result(id, run_one(index).await),
                None => TestResult {
                    id,
                    passed: false,
                    detail: "no test with this id in the corpus".into(),
                },
            });
        }
        results
    }
}

/// Run the probes with indices in `[skip, skip + take)`.
async fn run_slice_impl(skip: u32, take: u32) -> Vec<TestResult> {
    let skip = (skip as usize).min(NAMES.len());
    let end = skip.saturating_add(take as usize).min(NAMES.len());
    let mut results = Vec::with_capacity(end - skip);
    for (index, name) in NAMES.iter().enumerate().take(end).skip(skip) {
        results.push(to_result(format!("probe/{name}"), run_one(index).await));
    }
    results
}

fn to_result(id: String, outcome: Result<(), String>) -> TestResult {
    match outcome {
        Ok(()) => TestResult {
            id,
            passed: true,
            detail: String::new(),
        },
        Err(detail) => TestResult {
            id,
            passed: false,
            detail,
        },
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
/// key reproduces the vector's `r ‖ s` exactly. Deterministic-`k`
/// implementations (RustCrypto) pass; randomized-`k` ones (WebCrypto) fail
/// by design — the per-target manifests encode which is expected.
async fn sign_deterministic_rfc6979() -> Result<(), String> {
    let key = import_signing_key(EcdsaVariant::P256Sha256, unhex(P256_PRIVATE), false)
        .await
        .map_err(|e| describe("import-signing-key", &e))?;
    let sig = sign(&key, P256_MESSAGE).await?;
    let mut expected = unhex(P256_SIG_R);
    expected.extend(unhex(P256_SIG_S));
    if sig != expected {
        return Err(format!(
            "signature is not the RFC 6979 deterministic one (randomized k?): got {}",
            hex::encode(&sig)
        ));
    }
    Ok(())
}

export!(Component);
