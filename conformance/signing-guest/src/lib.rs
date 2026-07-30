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

use conformance_harness::stream::{sig_sign, sig_verify, Schedule};
use conformance_harness::{describe, expect, expect_err, export_probe_suite, probes, ErrKind};
use lann_webcrypto_guest::bindings::ecdsa_sign::generate_key;
use lann_webcrypto_guest::bindings::ecdsa_verify::{import_verifying_key, EcdsaVariant};

probes! {
    ecdsa_p256_sign_roundtrip,
    ecdsa_p384_generate_roundtrip,
    ecdsa_sign_key_export,
    ecdsa_sign_invalid_scalar,
}

export_probe_suite!(PROBES);

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
    let (sig, fed) = sig_sign(&key, payload, Schedule::Whole).await;
    fed?;
    expect(sig.len(), 64, "P-256 signature length")?;
    let (verified, fed) = sig_verify(&public, payload, &sig, Schedule::Whole).await;
    fed?;
    verified.map_err(|e| describe("generated public half did not verify", &e))?;

    // The generated point survives an export → ecdsa-verify import round
    // trip (65-byte uncompressed SEC1), and the re-imported key verifies.
    let point = public
        .export_key()
        .await
        .map_err(|e| describe("export-key (public)", &e))?;
    if point.len() != 65 || point[0] != 0x04 {
        return Err(format!(
            "exported public key is not a 65-byte uncompressed SEC1 point ({} bytes)",
            point.len()
        ));
    }
    let imported = import_verifying_key(EcdsaVariant::P256Sha256, point)
        .await
        .map_err(|e| describe("import-verifying-key of the exported point", &e))?;
    let (verified, fed) = sig_verify(&imported, payload, &sig, Schedule::Whole).await;
    fed?;
    verified.map_err(|e| describe("re-imported key did not verify", &e))?;

    let mut corrupted = sig;
    corrupted[0] ^= 0x01;
    let (verified, fed) = sig_verify(&imported, payload, &corrupted, Schedule::Whole).await;
    fed?;
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
    let (sig, fed) = sig_sign(&key, payload, Schedule::Whole).await;
    fed?;
    expect(sig.len(), 96, "P-384 signature length")?;
    let (verified, fed) = sig_verify(&public, payload, &sig, Schedule::Whole).await;
    fed?;
    verified.map_err(|e| describe("round-trip signature did not verify", &e))?;

    let (_other, other_public) = generate_key(EcdsaVariant::P384Sha384, false)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    let (verified, fed) = sig_verify(&other_public, payload, &sig, Schedule::Whole).await;
    fed?;
    expect_err(
        "verify",
        ErrKind::AuthenticationFailed,
        verified,
        "signature verified under a different key",
    )
}

/// An extractable generated key exports a 32-byte scalar, stably; a
/// non-extractable one fails `not-extractable`. (Export *identity* against
/// a known scalar needs private-key import, which is deliberately out of
/// this suite — impl-core's unit tests pin it for the Rust
/// implementations.)
async fn ecdsa_sign_key_export() -> Result<(), String> {
    let (key, _public) = generate_key(EcdsaVariant::P256Sha256, true)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    expect(
        key.extractable(),
        true,
        "extractable generated key's extractable getter",
    )?;
    let exported = key.export_key().await.map_err(|e| describe("export", &e))?;
    expect(exported.len(), 32, "exported P-256 scalar length")?;
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
    expect(
        key.extractable(),
        false,
        "non-extractable generated key's extractable getter",
    )?;
    expect_err(
        "export-key",
        ErrKind::NotExtractable,
        key.export_key().await,
        "non-extractable key exported",
    )
}

/// Wrong-length scalars fail `invalid-key` at import. Only the length
/// cases run here — every implementation validates length before touching
/// a platform — while *range* validation (zero, ≥ the group order) rides
/// the unspecified private-only PKCS#8 import path on browser hosts
/// (w3c/webcrypto#356) and is pinned by impl-core's unit tests instead.
async fn ecdsa_sign_invalid_scalar() -> Result<(), String> {
    use lann_webcrypto_guest::bindings::ecdsa_sign::import_signing_key;

    expect_err(
        "short scalar",
        ErrKind::InvalidKey,
        import_signing_key(EcdsaVariant::P256Sha256, vec![0x01; 16], false).await,
        "malformed scalar was accepted",
    )?;
    expect_err(
        "p384 scalar for p256",
        ErrKind::InvalidKey,
        import_signing_key(EcdsaVariant::P256Sha256, vec![0x01; 48], false).await,
        "malformed scalar was accepted",
    )
}
