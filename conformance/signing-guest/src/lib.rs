//! `conformance-signing-guest`: the host-only conformance component.
//!
//! Probes the signature-minting surface the in-guest provider deliberately
//! does not export — `ecdsa-sign` is class D (see rust/guest-provider/README.md) —
//! which the shared `conformance-guest` therefore cannot import, since it
//! must compose with that provider. This guest runs only under the
//! host-backed targets (wasmtime, jco).
//!
//! This suite is probes only. Private-key imports are exercised as
//! sign-then-verify round trips against separately imported public
//! points, never as known signature bytes: the WIT deliberately leaves
//! ECDSA signatures nondeterministic across implementations, and no
//! import ever derives a public half (the w3c/webcrypto#356 gap). The
//! Rust-side private-import known answers (the RFC 6979 A.2.5
//! deterministic signature, out-of-range scalar rejection) are pinned by
//! `lann-webcrypto-core`'s unit tests.

wit_bindgen::generate!({
    path: "../guest/wit",
    world: "signing-guest",
    generate_all,
});

use conformance_harness::stream::{sig_sign, sig_verify, Schedule};
use conformance_harness::{describe, expect, expect_err, export_probe_suite, probes, ErrKind};
use lann_webcrypto_guest::bindings::ecdsa_sign::generate_key as raw_generate_key;
use lann_webcrypto_guest::bindings::ecdsa_verify::{import_verifying_key_raw, EcdsaVariant};
use lann_webcrypto_guest::bindings::signature::{SigningKey, SigningKeyOptions, VerifyingKey};
use lann_webcrypto_guest::bindings::types::Error;

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

probes! {
    ecdsa_p256_sign_roundtrip,
    ecdsa_p384_generate_roundtrip,
    ecdsa_sign_extractable_getter,
    ecdsa_p521_unsupported,
    ecdsa_private_format_imports,
    ecdsa_signing_key_exports,
    ecdsa_cross_hash_sign_roundtrip,
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

/// Unpadded base64url, for building the EC private JWK the import takes.
fn b64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from_be_bytes([0, b[0], b[1], b[2]]);
        for i in 0..=chunk.len() {
            out.push(ALPHABET[((n >> (18 - 6 * i)) & 0x3f) as usize] as char);
        }
    }
    out
}

// The RFC 6979 A.2.5 P-256 key: private scalar, public coordinates, and
// the PKCS#8 encoding of the private key.
const P256_A25_D: &str = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
const P256_A25_X: &str = "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6";
const P256_A25_Y: &str = "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";
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
        let (sig, fed) = sig_sign(&key, payload, Schedule::Whole).await;
        fed?;
        expect(sig.len(), 64, "P-256 signature length")?;
        let (verified, fed) = sig_verify(&public, payload, &sig, Schedule::Whole).await;
        fed?;
        verified.map_err(|e| describe(&format!("{what}-imported key did not verify"), &e))?;
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
        let (sig, fed) = sig_sign(&key, payload, Schedule::Whole).await;
        fed?;
        let (verified, fed) = sig_verify(&public, payload, &sig, Schedule::Whole).await;
        fed?;
        verified.map_err(|e| describe(&format!("{what} re-import did not verify"), &e))?;
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
        let (sig, fed) = sig_sign(&key, payload, Schedule::Whole).await;
        fed?;
        expect(sig.len(), sig_len, "cross-variant signature length")?;
        let (verified, fed) = sig_verify(&public, payload, &sig, Schedule::Whole).await;
        fed?;
        verified.map_err(|e| describe(&format!("{curve}/{hash} round trip"), &e))?;
    }

    // The hash is part of the key's identity: the same point under a
    // different hash rejects the signature.
    let (key, public) = generate_key(EcdsaVariant::P256Sha512, false)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    let (sig, fed) = sig_sign(&key, payload, Schedule::Whole).await;
    fed?;
    let point = public
        .export_key_raw()
        .await
        .map_err(|e| describe("export-key-raw (public)", &e))?;
    let rebound = import_verifying_key_raw(EcdsaVariant::P256Sha256, point)
        .await
        .map_err(|e| describe("import-verifying-key-raw (rebound hash)", &e))?;
    let (verified, fed) = sig_verify(&rebound, payload, &sig, Schedule::Whole).await;
    fed?;
    expect_err(
        "verify under the wrong hash binding",
        ErrKind::AuthenticationFailed,
        verified,
        "a SHA-512-minted signature verified under a SHA-256 binding",
    )
}
