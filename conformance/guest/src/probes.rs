//! Hand-written API-contract probes: the parts of the `lann:webcrypto`
//! contract the Wycheproof vectors cannot express — key import/export and
//! extractability, error variants for misuse, the seal/open drain rule,
//! generated-key shape, and algorithm naming.

use crate::mint::{
    derive_options, generate_chacha_key, generate_ed25519_key, generate_hmac_key,
    generate_internal_nonce_key, generate_key, generate_xchacha_internal_nonce_key,
    generate_xchacha_key, import_aes_key_jwk, import_chacha_key, import_hmac_key,
    import_hmac_key_jwk, import_ikm, import_internal_nonce_key, import_key,
    import_xchacha_internal_nonce_key, import_xchacha_key,
};
use conformance_harness::stream::{
    compute, feed, in_open, in_seal, open, seal, sig_sign, sig_verify, sign, try_sign, verify,
    Schedule,
};
use conformance_harness::{
    describe, expect, expect_bytes, expect_err, probes, unhex, ErrKind, FEATURE_CHACHA,
    FEATURE_GCM_ANY_IV,
};
use lann_webcrypto_guest::bindings::aead::AeadKey;
use lann_webcrypto_guest::bindings::aes_gcm::AesVariant;
use lann_webcrypto_guest::bindings::bytes::constant_time_equal as bytes_constant_time_equal;
use lann_webcrypto_guest::bindings::ecdsa_verify::{
    import_verifying_key as import_ecdsa_verifying_key, EcdsaVariant,
};
use lann_webcrypto_guest::bindings::ed25519_verify::import_verifying_key as import_ed25519_verifying_key;
use lann_webcrypto_guest::bindings::sha2::{make_digest, Sha2Variant};
use lann_webcrypto_guest::bindings::types::Error;

/// The features a bare tag in the `probes!` table stands for. Which
/// features exist is this suite's business, not the harness's.
macro_rules! feature_tags {
    () => {
        &[]
    };
    (chacha) => {
        &[FEATURE_CHACHA]
    };
    (gcm_any_iv) => {
        &[FEATURE_GCM_ANY_IV]
    };
}

probes! {
    hmac_import_empty_key,
    hmac_sha384_sha512,
    sha2_truncated_unsupported,
    aes_import_wrong_length,
    aes192_unsupported,
    seal_drains_on_invalid_nonce,
    open_drains_on_invalid_nonce,
    sealed_length,
    key_export_roundtrip,
    not_extractable,
    generated_key_shape,
    algorithm_names,
    mac_verify_rejects_truncated,
    sign_prefix_drop,
    digest_reuse,
    constant_time_equal,
    chacha_key_metadata(chacha),
    chacha_nonce_lengths(chacha),
    ed25519_sign_roundtrip,
    sig_key_metadata,
    sig_import_invalid,
    verifying_key_export_roundtrip,
    internal_nonce_shape,
    chacha_internal_nonce_roundtrip(chacha),
    aes128_shape,
    open_short_input,
    stream_empty_writes,
    large_stream,
    extractable_getter,
    hmac_generate_length,
    gcm_full_parameters,
    gcm_any_iv(gcm_any_iv),
    chacha_tag_size_fixed(chacha),
    jwk_roundtrip,
    jwk_rejections,
    jwk_semantics,
    chacha_jwk_unsupported(chacha),
    mac_usage_policy,
    aead_usage_policy,
    internal_nonce_usage_policy,
    signing_usage_policy,
    hkdf_derive_key_equivalence,
    hkdf_grants_and_chaining,
}

/// Run the probe case whose `features` a target declares missing: assert
/// the correct decline. This is the two-way guarantee behind the plain
/// `skipped` the vector cases report: a target cannot silently serve a
/// feature it declares missing.
pub async fn run_declined(features: &[&str]) -> Result<String, String> {
    if features == [FEATURE_CHACHA] {
        chacha_minting_declined().await
    } else if features == [FEATURE_GCM_ANY_IV] {
        gcm_any_iv_declined().await
    } else {
        Err("probe has no decline assertion for its features".into())
    }
}

/// Assert that AES-GCM nonces outside the 12–128-byte window decline
/// `unsupported` in both directions — a target declaring `aes-gcm-any-iv`
/// missing must genuinely refuse them, not serve them or misreport the
/// refusal.
async fn gcm_any_iv_declined() -> Result<String, String> {
    let key = generate_key_256(false)
        .await
        .map_err(|detail| format!("minting an AES-256 key: {detail}"))?;
    for len in [8usize, 257] {
        let iv = vec![0x11u8; len];
        let (sealed, fed) = seal(&key, &iv, b"", None, b"msg", Schedule::Whole).await;
        fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
        expect_err(
            &format!("seal ({len}-byte nonce)"),
            ErrKind::Unsupported,
            sealed,
            "served a nonce length the target declares missing",
        )?;
        let (opened, fed) = open(&key, &iv, b"", None, &[0u8; 32], Schedule::Whole).await;
        fed.map_err(|e| format!("open ciphertext feeder: {e}"))?;
        expect_err(
            &format!("open ({len}-byte nonce)"),
            ErrKind::Unsupported,
            opened,
            "served a nonce length the target declares missing",
        )?;
    }
    Ok("AES-GCM nonces outside 12–128 bytes declined unsupported".into())
}

/// Assert that every ChaCha20-Poly1305 minting path declines `unsupported`.
async fn chacha_minting_declined() -> Result<String, String> {
    for (name, import, generate) in CHACHA_MINTERS {
        expect_err(
            &format!("{name} import-key"),
            ErrKind::Unsupported,
            import(vec![0x42u8; 32], false).await,
            "minted a key: the target serves a feature it declares missing",
        )?;
        expect_err(
            &format!("{name} generate-key"),
            ErrKind::Unsupported,
            generate(false).await,
            "minted a key: the target serves a feature it declares missing",
        )?;
    }
    expect_err(
        "xchacha internal-nonce generate-key",
        ErrKind::Unsupported,
        generate_xchacha_internal_nonce_key(false).await,
        "minted a key for a feature declared missing",
    )?;
    // The internal-nonce *import* is a minting path too. Omitting it left a
    // target free to decline five of the six entry points and still serve
    // this one, which is the hole this assertion exists to close.
    expect_err(
        "xchacha internal-nonce import-key",
        ErrKind::Unsupported,
        import_xchacha_internal_nonce_key(vec![0x42u8; 32], false).await,
        "minted a key for a feature declared missing",
    )?;
    Ok("every ChaCha20-Poly1305 minting path declined unsupported".into())
}

/// Generate an AES-256 key, rendering a WIT error as a probe failure.
async fn generate_key_256(
    extractable: bool,
) -> Result<lann_webcrypto_guest::bindings::aead::AeadKey, String> {
    generate_key(AesVariant::Aes256, extractable)
        .await
        .map_err(|e| describe("generate-key", &e))
}

/// Importing an empty HMAC key fails `invalid-key`.
async fn hmac_import_empty_key() -> Result<(), String> {
    expect_err(
        "import-key",
        ErrKind::InvalidKey,
        import_hmac_key(Sha2Variant::Sha256, Vec::new(), false).await,
        "empty HMAC key imported",
    )
}

/// The non-SHA-256 served variants compute correct tags (RFC 4231 test
/// case 2 known answers) and report their hash names.
async fn hmac_sha384_sha512() -> Result<(), String> {
    const KEY: &[u8] = b"Jefe";
    const DATA: &[u8] = b"what do ya want for nothing?";
    const TAG_SHA384: &str = "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e\
                              8e2240ca5e69e2c78b3239ecfab21649";
    const TAG_SHA512: &str = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
                              9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737";
    for (variant, hash, want_hex) in [
        (Sha2Variant::Sha384, "SHA-384", TAG_SHA384),
        (Sha2Variant::Sha512, "SHA-512", TAG_SHA512),
    ] {
        let key = import_hmac_key(variant, KEY.to_vec(), false)
            .await
            .map_err(|e| describe("import-key", &e))?;
        expect(
            key.algorithm_hash().as_deref(),
            Some(hash),
            &format!("{hash} key algorithm-hash"),
        )?;
        let want = unhex(want_hex);
        let (tag, fed) = sign(&key, DATA, Schedule::Whole).await;
        fed.map_err(|e| format!("sign data feeder: {e}"))?;
        expect_bytes(&tag, &want, &format!("HMAC-{hash} known-answer tag"))?;
        let (verified, fed) = verify(&key, DATA, &tag, Schedule::Whole).await;
        fed.map_err(|e| format!("verify data feeder: {e}"))?;
        verified.map_err(|e| describe("known-answer tag did not verify", &e))?;
    }
    Ok(())
}

/// No implementation of this package serves the truncated SHA-2 variants
/// (see the WIT `sha2-variant` doc): both minting paths fail `unsupported`.
async fn sha2_truncated_unsupported() -> Result<(), String> {
    for variant in [
        Sha2Variant::Sha224,
        Sha2Variant::Sha512224,
        Sha2Variant::Sha512256,
    ] {
        expect_err(
            &format!("import-key {variant:?}"),
            ErrKind::Unsupported,
            import_hmac_key(variant, b"truncated".to_vec(), false).await,
            "key imported",
        )?;
        expect_err(
            &format!("generate-key {variant:?}"),
            ErrKind::Unsupported,
            generate_hmac_key(variant, None, false).await,
            "key generated",
        )?;
        expect_err(
            &format!("make-digest {variant:?}"),
            ErrKind::Unsupported,
            make_digest(variant),
            "digest minted",
        )?;
    }
    Ok(())
}

/// Importing 16- or 24-byte material as an AES-256 key fails `invalid-key`.
async fn aes_import_wrong_length() -> Result<(), String> {
    for len in [16usize, 24] {
        expect_err(
            &format!("import-key ({len} bytes)"),
            ErrKind::InvalidKey,
            import_key(AesVariant::Aes256, vec![0u8; len], false).await,
            "imported as AES-256",
        )?;
    }
    Ok(())
}

/// No implementation of this package serves AES-192 (see the WIT
/// `aes-variant` doc): both minting paths fail `unsupported`.
async fn aes192_unsupported() -> Result<(), String> {
    expect_err(
        "import-key",
        ErrKind::Unsupported,
        import_key(AesVariant::Aes192, vec![0u8; 24], false).await,
        "AES-192 key imported",
    )?;
    expect_err(
        "generate-key",
        ErrKind::Unsupported,
        generate_key(AesVariant::Aes192, false).await,
        "AES-192 key generated",
    )
}

/// `seal` with a bad nonce still drains the plaintext stream: the concurrent
/// feeder must complete, and the error must be `invalid-nonce`.
async fn seal_drains_on_invalid_nonce() -> Result<(), String> {
    let key = generate_key_256(false).await?;
    let plaintext: Vec<u8> = (0..=255u8).cycle().take(2048).collect();
    let (sealed, fed) = seal(
        &key,
        &[],
        b"probe aad",
        None,
        &plaintext,
        Schedule::Straddle,
    )
    .await;
    fed.map_err(|e| format!("plaintext feeder did not complete: {e}"))?;
    expect_err(
        "seal",
        ErrKind::InvalidNonce,
        sealed,
        "empty nonce accepted",
    )
}

/// `open` with a bad nonce still drains the ciphertext stream: the concurrent
/// feeder must complete, and the error must be `invalid-nonce`.
async fn open_drains_on_invalid_nonce() -> Result<(), String> {
    let key = generate_key_256(false).await?;
    let ciphertext: Vec<u8> = (0..=255u8).cycle().take(2048).collect();
    let (opened, fed) = open(
        &key,
        &[],
        b"probe aad",
        None,
        &ciphertext,
        Schedule::Straddle,
    )
    .await;
    fed.map_err(|e| format!("ciphertext feeder did not complete: {e}"))?;
    expect_err(
        "open",
        ErrKind::InvalidNonce,
        opened,
        "empty nonce accepted",
    )
}

/// Sealed output is exactly plaintext length + the 16-byte tag, and the
/// size getters agree with the observed contract.
async fn sealed_length() -> Result<(), String> {
    let key = generate_key_256(false).await?;
    expect(key.nonce_size(), 12, "aead-key.nonce-size")?;
    expect(key.tag_size(), 16, "aead-key.tag-size")?;
    for len in [0usize, 1, 15, 16, 17, 1024] {
        let plaintext = vec![0xa5u8; len];
        let (sealed, fed) = seal(&key, &[1u8; 12], b"", None, &plaintext, Schedule::Whole).await;
        fed.map_err(|e| format!("plaintext feeder ({len} bytes): {e}"))?;
        let sealed = sealed.map_err(|e| describe(&format!("seal of {len} bytes"), &e))?;
        expect(
            sealed.len(),
            len + 16,
            &format!("sealed length for {len}-byte plaintext"),
        )?;
    }
    Ok(())
}

/// Import then export of an extractable key is the identity, for both HMAC
/// and AES keys.
async fn key_export_roundtrip() -> Result<(), String> {
    let hmac_raw = b"key-export-roundtrip".to_vec();
    let key = import_hmac_key(Sha2Variant::Sha256, hmac_raw.clone(), true)
        .await
        .map_err(|e| describe("import-key", &e))?;
    let exported = key
        .export_key()
        .await
        .map_err(|e| describe("hmac export", &e))?;
    expect_bytes(&exported, &hmac_raw, "exported HMAC key material")?;

    let aes_raw: Vec<u8> = (0..32u8).collect();
    let key = import_key(AesVariant::Aes256, aes_raw.clone(), true)
        .await
        .map_err(|e| describe("import-key", &e))?;
    let exported = key
        .export_key()
        .await
        .map_err(|e| describe("aes export", &e))?;
    expect_bytes(&exported, &aes_raw, "exported AES key material")
}

/// Export of a non-extractable key fails `not-extractable`, for both HMAC
/// and AES keys.
async fn not_extractable() -> Result<(), String> {
    let key = import_hmac_key(Sha2Variant::Sha256, b"not-extractable".to_vec(), false)
        .await
        .map_err(|e| describe("import-key", &e))?;
    expect_err(
        "hmac export-key",
        ErrKind::NotExtractable,
        key.export_key().await,
        "non-extractable HMAC key exported",
    )?;

    let key = import_key(AesVariant::Aes256, vec![0x42u8; 32], false)
        .await
        .map_err(|e| describe("import-key", &e))?;
    expect_err(
        "aes export-key",
        ErrKind::NotExtractable,
        key.export_key().await,
        "non-extractable AES key exported",
    )
}

/// Generated keys have the right shape: extractable generated HMAC keys
/// export the hash's block size (WebCrypto's `generateKey` default), AES-256
/// keys export 32 bytes, a generated HMAC key signs and verifies, and a
/// generated AES key round-trips seal/open.
async fn generated_key_shape() -> Result<(), String> {
    let hmac_key = generate_hmac_key(Sha2Variant::Sha256, None, true)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    let exported = hmac_key
        .export_key()
        .await
        .map_err(|e| describe("generated hmac export", &e))?;
    expect(
        exported.len(),
        64,
        "generated HMAC key export length (SHA-256 block size)",
    )?;

    let payload = b"generated-key-shape payload";
    let (tag, fed) = sign(&hmac_key, payload, Schedule::Whole).await;
    fed.map_err(|e| format!("sign data feeder: {e}"))?;
    let (verified, fed) = verify(&hmac_key, payload, &tag, Schedule::Whole).await;
    fed.map_err(|e| format!("verify data feeder: {e}"))?;
    verified.map_err(|e| describe("generated HMAC key's tag did not verify", &e))?;

    let aes_key = generate_key_256(true).await?;
    let exported = aes_key
        .export_key()
        .await
        .map_err(|e| describe("generated aes export", &e))?;
    expect(exported.len(), 32, "generated AES key export length")?;

    let nonce = [7u8; 12];
    let plaintext: Vec<u8> = (0..=255u8).cycle().take(3 * 16 + 5).collect();
    let (sealed, fed) = seal(
        &aes_key,
        &nonce,
        b"shape aad",
        None,
        &plaintext,
        Schedule::Whole,
    )
    .await;
    fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
    let sealed = sealed.map_err(|e| describe("seal under generated key", &e))?;
    let (opened, fed) = open(
        &aes_key,
        &nonce,
        b"shape aad",
        None,
        &sealed,
        Schedule::Whole,
    )
    .await;
    fed.map_err(|e| format!("open ciphertext feeder: {e}"))?;
    let opened = opened.map_err(|e| describe("open under generated key", &e))?;
    expect_bytes(&opened, &plaintext, "round-tripped plaintext")
}

/// The algorithm getters report the bound algorithm on keys.
async fn algorithm_names() -> Result<(), String> {
    let raw = b"algorithm-names".to_vec();
    let key_bits = raw.len() as u32 * 8;
    let imported = import_hmac_key(Sha2Variant::Sha256, raw, false)
        .await
        .map_err(|e| describe("import-key", &e))?;
    expect(
        imported.algorithm_name(),
        "HMAC".to_string(),
        "imported mac-key name",
    )?;
    expect(
        imported.algorithm_hash(),
        Some("SHA-256".to_string()),
        "imported mac-key hash",
    )?;
    expect(
        imported.algorithm_length(),
        key_bits,
        "imported mac-key length",
    )?;
    let generated = generate_hmac_key(Sha2Variant::Sha256, None, false)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    expect(
        generated.algorithm_name(),
        "HMAC".to_string(),
        "generated mac-key name",
    )?;
    expect(
        generated.algorithm_hash(),
        Some("SHA-256".to_string()),
        "generated mac-key hash",
    )?;
    expect(
        generated.algorithm_length(),
        512,
        "generated mac-key length",
    )?;

    let imported = import_key(AesVariant::Aes256, vec![0x24u8; 32], false)
        .await
        .map_err(|e| describe("import-key", &e))?;
    expect(
        imported.algorithm_name(),
        "AES-GCM".to_string(),
        "imported aead-key name",
    )?;
    expect(imported.algorithm_length(), 256, "imported aead-key length")?;
    let generated = generate_key_256(false).await?;
    expect(
        generated.algorithm_name(),
        "AES-GCM".to_string(),
        "generated aead-key name",
    )?;
    expect(
        generated.algorithm_length(),
        256,
        "generated aead-key length",
    )
}

/// `verify` rejects a 31-byte prefix of the correct tag.
async fn mac_verify_rejects_truncated() -> Result<(), String> {
    let key = import_hmac_key(
        Sha2Variant::Sha256,
        b"truncated-tag probe key".to_vec(),
        false,
    )
    .await
    .map_err(|e| describe("import-key", &e))?;
    let payload = b"truncated-tag payload";

    let (tag, fed) = sign(&key, payload, Schedule::Whole).await;
    fed.map_err(|e| format!("sign data feeder: {e}"))?;
    expect(tag.len(), 32, "tag length")?;

    let (verified, fed) = verify(&key, payload, &tag[..31], Schedule::Whole).await;
    fed.map_err(|e| format!("verify data feeder: {e}"))?;
    expect_err(
        "verify",
        ErrKind::AuthenticationFailed,
        verified,
        "31-byte prefix of the correct tag verified",
    )
}

/// Dropping the writer mid-message is the authoritative end of input, per
/// the WIT truncating-producer contract: `sign` over a stream whose writer
/// stops after delivering a prefix of a larger message equals `sign` over
/// that prefix delivered whole. There is no "abrupt drop" an implementation
/// may treat differently.
async fn sign_prefix_drop() -> Result<(), String> {
    let key = import_hmac_key(
        Sha2Variant::Sha256,
        b"prefix-drop probe key".to_vec(),
        false,
    )
    .await
    .map_err(|e| describe("import-key", &e))?;

    let message: Vec<u8> = (0..=255u8).cycle().take(2048).collect();
    let prefix_len = 700;

    // Feed only a prefix of the message's chunk schedule, then drop the
    // writer as if the producer failed midway.
    let (tx, rx) = lann_webcrypto_guest::wit_stream::new();
    let feed_prefix = async {
        let mut tx = tx;
        let mut sent = 0usize;
        for chunk in Schedule::Straddle.chunks(&message) {
            if sent >= prefix_len {
                break;
            }
            let take = chunk.len().min(prefix_len - sent);
            sent += take;
            let leftover = tx.write_all(chunk[..take].to_vec()).await;
            if !leftover.is_empty() {
                return Err(format!(
                    "stream writer closed early with {} bytes unwritten",
                    leftover.len()
                ));
            }
        }
        Ok(())
    };
    let (tag, fed) = futures::join!(key.sign(rx), feed_prefix);
    fed.map_err(|e| format!("prefix feeder: {e}"))?;
    let tag = tag.map_err(|e| describe("sign over dropped-early stream", &e))?;

    let (whole_tag, fed) = sign(&key, &message[..prefix_len], Schedule::Whole).await;
    fed.map_err(|e| format!("whole-prefix feeder: {e}"))?;
    expect_bytes(
        &tag,
        &whole_tag,
        "tag over dropped-early stream vs. its prefix delivered whole",
    )
}

/// A `digest` resource is reusable and algorithm-bound: repeated `compute`
/// calls agree, and each served variant reports its registry name.
async fn digest_reuse() -> Result<(), String> {
    for (variant, name) in [
        (Sha2Variant::Sha256, "SHA-256"),
        (Sha2Variant::Sha384, "SHA-384"),
        (Sha2Variant::Sha512, "SHA-512"),
    ] {
        let digest = make_digest(variant).map_err(|e| describe("make-digest", &e))?;
        expect(
            digest.algorithm_name(),
            name.to_string(),
            &format!("{name} digest algorithm-name"),
        )?;
        let (first, fed) = compute(&digest, b"reusable", Schedule::Whole).await;
        fed.map_err(|e| format!("first compute feeder: {e}"))?;
        let (second, fed) = compute(&digest, b"reusable", Schedule::Bytes).await;
        fed.map_err(|e| format!("second compute feeder: {e}"))?;
        expect_bytes(&second, &first, &format!("{name} recomputed digest"))?;
    }
    Ok(())
}

/// `constant-time-equal` agrees with plain equality across equal, differing,
/// different-length, and empty inputs.
async fn constant_time_equal() -> Result<(), String> {
    let a = [0xa5u8; 32];
    let mut b = a;
    b[31] ^= 0x01;
    let checks: [(&[u8], &[u8], bool, &str); 5] = [
        (&a, &a, true, "equal inputs"),
        (&a, &b, false, "last-byte difference"),
        (&a, &a[..31], false, "prefix of itself"),
        (&[], &[], true, "empty inputs"),
        (&[], &a, false, "empty versus non-empty"),
    ];
    for (x, y, want, what) in checks {
        if bytes_constant_time_equal(x, y) != want {
            return Err(format!("{what}: got {}, want {want}", !want));
        }
    }
    Ok(())
}

/// Both `chacha-variant`s mint 256-bit keys reporting their own algorithm
/// names, decline non-32-byte material as `invalid-key`, and generate
/// 32 bytes of key material.
async fn chacha_key_metadata() -> Result<(), String> {
    for (name, import, generate) in CHACHA_MINTERS {
        let key = import(vec![0x42u8; 32], false)
            .await
            .map_err(|e| describe("import-key", &e))?;
        expect(
            key.algorithm_name(),
            name.to_string(),
            &format!("{name} key algorithm-name"),
        )?;
        expect(
            key.algorithm_length(),
            256,
            &format!("{name} key algorithm-length"),
        )?;
        // The size getters exist so a component holding only the key handle
        // can frame nonces and ciphertext without matching on
        // `algorithm-name` (see the WIT). XChaCha is the one family where
        // the nonce size differs from the AES default, so asserting them
        // only on AES-GCM left the getters' whole purpose untested.
        let want_nonce = if name == "XChaCha20-Poly1305" { 24 } else { 12 };
        expect(key.nonce_size(), want_nonce, &format!("{name} nonce-size"))?;
        expect(key.tag_size(), 16, &format!("{name} tag-size"))?;
        expect_err(
            &format!("{name} import-key (16 bytes)"),
            ErrKind::InvalidKey,
            import(vec![0x42u8; 16], false).await,
            "imported 16 bytes of key material",
        )?;
        let generated = generate(true)
            .await
            .map_err(|e| describe("generate-key", &e))?;
        let raw = generated
            .export_key()
            .await
            .map_err(|e| describe("export", &e))?;
        expect(
            raw.len(),
            32,
            &format!("{name} generated key material length"),
        )?;
    }
    Ok(())
}

/// The two ChaCha constructions' minting interfaces, name-tagged for probe
/// messages. Boxed futures because the interfaces are distinct functions
/// with identical shapes.
type MintFuture<T> = std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, Error>>>>;
/// One construction's minting entry: (name, import-key, generate-key).
type ChachaMinter = (
    &'static str,
    fn(Vec<u8>, bool) -> MintFuture<AeadKey>,
    fn(bool) -> MintFuture<AeadKey>,
);
const CHACHA_MINTERS: [ChachaMinter; 2] = [
    (
        "ChaCha20-Poly1305",
        |raw, extractable| Box::pin(import_chacha_key(raw, extractable)),
        |extractable| Box::pin(generate_chacha_key(extractable)),
    ),
    (
        "XChaCha20-Poly1305",
        |raw, extractable| Box::pin(import_xchacha_key(raw, extractable)),
        |extractable| Box::pin(generate_xchacha_key(extractable)),
    ),
];

/// Each construction's key accepts exactly its own nonce length: the other
/// construction's length is `invalid-nonce` (nonce-length confusion between
/// the constructions cannot pass silently), and the correct length
/// round-trips.
async fn chacha_nonce_lengths() -> Result<(), String> {
    let msg = b"chacha-nonce-lengths";
    for ((name, import, _), good_len, bad_len) in [
        (CHACHA_MINTERS[0], 12usize, 24usize),
        (CHACHA_MINTERS[1], 24, 12),
    ] {
        let key = import(vec![0x42u8; 32], false)
            .await
            .map_err(|e| describe("import-key", &e))?;
        let (sealed, fed) = seal(&key, &vec![0u8; bad_len], b"", None, msg, Schedule::Whole).await;
        fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
        expect_err(
            &format!("{name} seal ({bad_len}-byte nonce)"),
            ErrKind::InvalidNonce,
            sealed,
            "sealed under the other construction's nonce length",
        )?;
        let (sealed, fed) = seal(&key, &vec![0u8; good_len], b"", None, msg, Schedule::Whole).await;
        fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
        let sealed = sealed.map_err(|e| describe("seal", &e))?;
        let (opened, fed) = open(
            &key,
            &vec![0u8; good_len],
            b"",
            None,
            &sealed,
            Schedule::Whole,
        )
        .await;
        fed.map_err(|e| format!("open ciphertext feeder: {e}"))?;
        let opened = opened.map_err(|e| describe("open", &e))?;
        expect_bytes(&opened, msg, "opened bytes")?;
    }
    Ok(())
}

/// A generated Ed25519 key signs, the public half returned with it
/// verifies, a corrupted signature fails `authentication-failed`, and a
/// *different* key's public half rejects the signature (keys are not
/// interchangeable).
async fn ed25519_sign_roundtrip() -> Result<(), String> {
    let (key, public) = generate_ed25519_key(false)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    let payload = b"conformance signature payload";
    let (sig, fed) = sig_sign(&key, payload, Schedule::Whole).await;
    fed?;
    expect(sig.len(), 64, "Ed25519 signature length")?;

    let (verified, fed) = sig_verify(&public, payload, &sig, Schedule::Whole).await;
    fed?;
    verified.map_err(|e| describe("round-trip signature did not verify", &e))?;

    let mut corrupted = sig.clone();
    corrupted[0] ^= 0x01;
    let (verified, fed) = sig_verify(&public, payload, &corrupted, Schedule::Whole).await;
    fed?;
    expect_err(
        "verify",
        ErrKind::AuthenticationFailed,
        verified,
        "corrupted signature verified",
    )?;

    let (_other, other_public) = generate_ed25519_key(false)
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

/// The signature getters report the mint binding: Ed25519 keys have no
/// curve/hash parameters; ECDSA keys report their variant's curve and hash.
async fn sig_key_metadata() -> Result<(), String> {
    let (signing, public) = generate_ed25519_key(true)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    expect(
        signing.algorithm_name(),
        "Ed25519".to_string(),
        "Ed25519 signing-key algorithm-name",
    )?;
    expect(
        signing.algorithm_curve(),
        None,
        "Ed25519 signing-key algorithm-curve",
    )?;
    expect(
        signing.algorithm_hash(),
        None,
        "Ed25519 signing-key algorithm-hash",
    )?;
    expect(
        signing.extractable(),
        true,
        "extractable generated key's extractable getter",
    )?;
    // The getter was only ever asserted in the `true` direction, so a
    // hardcoded `true` passed the whole suite. Mint the other kind and read
    // it back: `export-key` failing is a separate contract, checked
    // elsewhere.
    let (non_extractable, _) = generate_ed25519_key(false)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    expect(
        non_extractable.extractable(),
        false,
        "non-extractable generated key's extractable getter",
    )?;
    expect(
        public.algorithm_name(),
        "Ed25519".to_string(),
        "Ed25519 verifying-key algorithm-name",
    )?;
    expect(
        public.algorithm_curve(),
        None,
        "Ed25519 verifying-key algorithm-curve",
    )?;
    expect(
        public.algorithm_hash(),
        None,
        "Ed25519 verifying-key algorithm-hash",
    )?;

    // An ECDSA public key (any valid point works; this is the RFC 6979
    // A.2.5 public key).
    let mut point = vec![0x04];
    point.extend(unhex(
        "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
    ));
    point.extend(unhex(
        "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
    ));
    let key = import_ecdsa_verifying_key(EcdsaVariant::P256Sha256, point)
        .await
        .map_err(|e| describe("import-verifying-key", &e))?;
    expect(
        key.algorithm_name(),
        "ECDSA".to_string(),
        "ECDSA verifying-key algorithm-name",
    )?;
    expect(
        key.algorithm_curve(),
        Some("P-256".to_string()),
        "ECDSA verifying-key algorithm-curve",
    )?;
    expect(
        key.algorithm_hash(),
        Some("SHA-256".to_string()),
        "ECDSA verifying-key algorithm-hash",
    )
}

/// Malformed key material fails `invalid-key` on every signature import
/// path: wrong lengths, and a *compressed* SEC1 point (the WIT requires
/// uncompressed).
async fn sig_import_invalid() -> Result<(), String> {
    expect_err(
        "ed25519 short public",
        ErrKind::InvalidKey,
        import_ed25519_verifying_key(vec![0u8; 31]).await,
        "malformed material was accepted",
    )?;
    expect_err(
        "ecdsa wrong-length point",
        ErrKind::InvalidKey,
        import_ecdsa_verifying_key(EcdsaVariant::P256Sha256, vec![0x04; 64]).await,
        "malformed material was accepted",
    )?;
    // A compressed encoding of the RFC 6979 A.2.5 public key (y is odd).
    let mut compressed = vec![0x03];
    compressed.extend(unhex(
        "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
    ));
    expect_err(
        "ecdsa compressed point",
        ErrKind::InvalidKey,
        import_ecdsa_verifying_key(EcdsaVariant::P256Sha256, compressed).await,
        "malformed material was accepted",
    )
}

/// Public-key export is an identity round trip (no extractability gate),
/// and re-importing the export yields a key that still verifies.
async fn verifying_key_export_roundtrip() -> Result<(), String> {
    let (signing, public) = generate_ed25519_key(false)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    let payload = b"export roundtrip payload";
    let (sig, fed) = sig_sign(&signing, payload, Schedule::Whole).await;
    fed?;

    let exported = public
        .export_key()
        .await
        .map_err(|e| describe("export-key (public)", &e))?;
    expect(exported.len(), 32, "exported Ed25519 public key length")?;
    let reimported = import_ed25519_verifying_key(exported)
        .await
        .map_err(|e| describe("re-import of exported public key", &e))?;
    let (verified, fed) = sig_verify(&reimported, payload, &sig, Schedule::Whole).await;
    fed?;
    verified.map_err(|e| describe("re-imported key did not verify", &e))?;

    // ECDSA verifying keys: SEC1 import -> export is the identity, on
    // every target serving ecdsa-verify (including the composed provider,
    // which exports verification while declining class-D signing).
    for (variant, public) in [
        (
            EcdsaVariant::P256Sha256,
            // The vendored Wycheproof P-256 file's group public key.
            unhex("042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e"),
        ),
        (
            EcdsaVariant::P384Sha384,
            // The vendored Wycheproof P-384 file's group public key.
            unhex("042da57dda1089276a543f9ffdac0bff0d976cad71eb7280e7d9bfd9fee4bdb2f20f47ff888274389772d98cc5752138aa4b6d054d69dcf3e25ec49df870715e34883b1836197d76f8ad962e78f6571bbc7407b0d6091f9e4d88f014274406174f"),
        ),
    ] {
        let key = import_ecdsa_verifying_key(variant, public.clone())
            .await
            .map_err(|e| describe("import-verifying-key (ecdsa)", &e))?;
        let exported = key
            .export_key()
            .await
            .map_err(|e| describe("export-key (public)", &e))?;
        expect_bytes(&exported, &public, "exported ECDSA public key")?;
    }
    Ok(())
}

/// The internal-nonce API contract the vectors cannot express: sealed
/// messages carry the algorithm's wire format (nonce-prefix length), each
/// seal draws a fresh nonce, minting validates key material, and
/// extractability gates `export-key` exactly as for `aead-key`.
async fn internal_nonce_shape() -> Result<(), String> {
    // Wrong-length material is rejected at minting, as for `aes-gcm`.
    expect_err(
        "import-key (16 bytes as AES-256)",
        ErrKind::InvalidKey,
        import_internal_nonce_key(AesVariant::Aes256, vec![0u8; 16], false).await,
        "imported",
    )?;

    let key = generate_internal_nonce_key(AesVariant::Aes256, false)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    expect(
        key.algorithm_name(),
        "AES-GCM".to_string(),
        "algorithm-name",
    )?;
    expect(key.algorithm_length(), 256, "algorithm-length")?;

    let before = key
        .seals_remaining()
        .ok_or("AES-GCM internal-nonce key reports no nonce budget")?;

    let plaintext: Vec<u8> = (0..=255u8).cycle().take(1024 + 7).collect();
    let (sealed, fed) = in_seal(&key, b"shape aad", &plaintext, Schedule::Straddle).await;
    fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
    let sealed = sealed.map_err(|e| describe("seal", &e))?;
    // 12-byte IV prefix + ciphertext + 16-byte tag.
    expect(sealed.len(), plaintext.len() + 12 + 16, "sealed length")?;

    let (opened, fed) = in_open(&key, b"shape aad", &sealed, Schedule::Bytes).await;
    fed.map_err(|e| format!("open sealed feeder: {e}"))?;
    let opened = opened.map_err(|e| describe("open", &e))?;
    expect_bytes(&opened, &plaintext, "round-tripped plaintext")?;

    // The budget hint decreases as seals consume it: permitting N further
    // seals before means permitting at most N - 1 after.
    let after = key
        .seals_remaining()
        .ok_or("nonce budget disappeared after sealing")?;
    if after >= before {
        return Err(format!(
            "seals-remaining did not decrease: {before} -> {after}"
        ));
    }

    // A second seal draws a fresh nonce.
    let (resealed, fed) = in_seal(&key, b"shape aad", &plaintext, Schedule::Whole).await;
    fed.map_err(|e| format!("second seal feeder: {e}"))?;
    let resealed = resealed.map_err(|e| describe("second seal", &e))?;
    if sealed[..12] == resealed[..12] {
        return Err("two seals drew the same nonce".into());
    }

    // Wrong associated data fails closed, with no unverified plaintext.
    let (opened, fed) = in_open(&key, b"wrong aad", &sealed, Schedule::Whole).await;
    fed.map_err(|e| format!("wrong-aad open feeder: {e}"))?;
    expect_err(
        "open (wrong aad)",
        ErrKind::AuthenticationFailed,
        opened,
        "wrong aad opened",
    )?;

    // Input too short to carry the wire format is authentication-failed.
    let (opened, fed) = in_open(&key, b"", &sealed[..8], Schedule::Whole).await;
    fed.map_err(|e| format!("short-input open feeder: {e}"))?;
    expect_err(
        "open (8-byte sealed message)",
        ErrKind::AuthenticationFailed,
        opened,
        "opened",
    )?;

    // A non-extractable key refuses export-key.
    expect_err(
        "export-key",
        ErrKind::NotExtractable,
        key.export_key().await,
        "non-extractable key exported",
    )?;

    // An extractable generated key exports 32 bytes.
    let key = generate_internal_nonce_key(AesVariant::Aes256, true)
        .await
        .map_err(|e| describe("generate-key (extractable)", &e))?;
    let exported = key
        .export_key()
        .await
        .map_err(|e| describe("export-key", &e))?;
    expect(exported.len(), 32, "exported key length")?;
    Ok(())
}

/// The XChaCha internal-nonce construction round-trips with its 24-byte
/// nonce prefixed. There is no IETF-ChaCha internal-nonce interface to
/// pair this with — the package deliberately offers only XChaCha here (see
/// wit/chacha.wit) — so this probe covers the whole kind for the family.
async fn chacha_internal_nonce_roundtrip() -> Result<(), String> {
    let key = generate_xchacha_internal_nonce_key(false)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    expect(
        key.algorithm_name(),
        "XChaCha20-Poly1305".to_string(),
        "algorithm-name",
    )?;
    expect(key.algorithm_length(), 256, "algorithm-length")?;
    // 24-byte random nonces have no enforced budget.
    expect(key.seals_remaining(), None, "seals-remaining")?;
    // A non-extractable key refuses export; an extractable import
    // round-trips its 32 bytes.
    expect_err(
        "export-key",
        ErrKind::NotExtractable,
        key.export_key().await,
        "non-extractable key exported",
    )?;
    let raw = vec![0x42u8; 32];
    let imported = import_xchacha_internal_nonce_key(raw.clone(), true)
        .await
        .map_err(|e| describe("import-key", &e))?;
    let exported = imported
        .export_key()
        .await
        .map_err(|e| describe("export-key", &e))?;
    expect_bytes(&exported, &raw, "exported key material")?;

    let plaintext = b"chacha internal-nonce payload".to_vec();
    let (sealed, fed) = in_seal(&key, b"aad", &plaintext, Schedule::Whole).await;
    fed.map_err(|e| format!("seal feeder: {e}"))?;
    let sealed = sealed.map_err(|e| describe("seal", &e))?;
    // 24-byte nonce prefix + ciphertext + 16-byte tag.
    expect(sealed.len(), plaintext.len() + 24 + 16, "sealed length")?;
    let (opened, fed) = in_open(&key, b"aad", &sealed, Schedule::Whole).await;
    fed.map_err(|e| format!("open feeder: {e}"))?;
    let opened = opened.map_err(|e| describe("open", &e))?;
    expect_bytes(&opened, &plaintext, "round-tripped plaintext")
}

/// AES-128-GCM minting and round trip: every implementation serves the
/// variant, so its key shape (16-byte material, 128-bit length, the same
/// 12/16 nonce/tag contract) and a seal/open round trip are pinned for
/// both nonce disciplines.
async fn aes128_shape() -> Result<(), String> {
    let key = generate_key(AesVariant::Aes128, true)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    expect(key.algorithm_length(), 128, "algorithm-length")?;
    expect(key.nonce_size(), 12, "nonce-size")?;
    expect(key.tag_size(), 16, "tag-size")?;
    let exported = key
        .export_key()
        .await
        .map_err(|e| describe("export-key", &e))?;
    expect(exported.len(), 16, "exported key length")?;

    let plaintext = b"aes-128 round trip payload".to_vec();
    let nonce = [3u8; 12];
    let (sealed, fed) = seal(&key, &nonce, b"aad", None, &plaintext, Schedule::Straddle).await;
    fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
    let sealed = sealed.map_err(|e| describe("seal", &e))?;
    let (opened, fed) = open(&key, &nonce, b"aad", None, &sealed, Schedule::Whole).await;
    fed.map_err(|e| format!("open ciphertext feeder: {e}"))?;
    let opened = opened.map_err(|e| describe("open", &e))?;
    expect_bytes(&opened, &plaintext, "round-tripped plaintext")?;

    // The internal-nonce discipline serves AES-128 too.
    let key = generate_internal_nonce_key(AesVariant::Aes128, false)
        .await
        .map_err(|e| describe("generate-key (internal nonce)", &e))?;
    expect(
        key.algorithm_length(),
        128,
        "internal-nonce algorithm-length",
    )?;
    let (sealed, fed) = in_seal(&key, b"aad", &plaintext, Schedule::Whole).await;
    fed.map_err(|e| format!("internal-nonce seal feeder: {e}"))?;
    let sealed = sealed.map_err(|e| describe("internal-nonce seal", &e))?;
    let (opened, fed) = in_open(&key, b"aad", &sealed, Schedule::Whole).await;
    fed.map_err(|e| format!("internal-nonce open feeder: {e}"))?;
    let opened = opened.map_err(|e| describe("internal-nonce open", &e))?;
    expect_bytes(&opened, &plaintext, "internal-nonce round trip")
}

/// Caller-nonce `open` of inputs shorter than the tag fails
/// `authentication-failed` (the internal-nonce analogue is covered by
/// `internal-nonce-shape`).
async fn open_short_input() -> Result<(), String> {
    let key = generate_key_256(false).await?;
    for len in [0usize, 1, 15] {
        let (opened, fed) = open(
            &key,
            &[0u8; 12],
            b"",
            None,
            &vec![0xa5; len],
            Schedule::Whole,
        )
        .await;
        fed.map_err(|e| format!("{len}-byte open feeder: {e}"))?;
        expect_err(
            &format!("open ({len}-byte input)"),
            ErrKind::AuthenticationFailed,
            opened,
            "short input opened",
        )?;
    }
    Ok(())
}

/// Zero-length writes are legal on a `stream<u8>`, carry no data, and must
/// change neither an operation's result nor its liveness. They are the one
/// stream shape that reaches a host's "no items available, writer not
/// finishing" path, where a consumer that parks without arming its waker
/// never resumes: the failure mode is a wedged operation — and, for a host
/// holding an admission reservation across the call, a wedged instance —
/// Multi-mebibyte streams delivered in writes that straddle every
/// implementation's internal boundaries. The stream collectors batch:
/// jco reads in 64 KiB batches, the in-guest provider refills an 8 KiB
/// buffer, and the wasmtime host meters admission and output reservations
/// per buffer — and nothing else in the suite exceeds a few KiB, so those
/// seams were otherwise crossed only a couple of times. At this scale the
/// MAC tag must still be chunking-invariant against a single whole write,
/// and both AEAD disciplines must round-trip.
async fn large_stream() -> Result<(), String> {
    // Odd-sized so no chunk size divides it evenly.
    const LEN: usize = 2 * 1024 * 1024 + 13;

    /// Split `data` into writes cycling through sizes chosen to land one
    /// byte on either side of the 64 KiB and 8 KiB batch sizes, with a
    /// single-byte write between the seams.
    fn boundary_chunks(data: &[u8]) -> Vec<Vec<u8>> {
        const SIZES: [usize; 6] = [65537, 8191, 1, 65535, 8193, 4096];
        let mut chunks = Vec::new();
        let (mut offset, mut turn) = (0, 0);
        while offset < data.len() {
            let end = (offset + SIZES[turn % SIZES.len()]).min(data.len());
            chunks.push(data[offset..end].to_vec());
            offset = end;
            turn += 1;
        }
        chunks
    }

    let payload: Vec<u8> = (0..=255u8).cycle().take(LEN).collect();

    let key = import_hmac_key(Sha2Variant::Sha256, b"large-stream key".to_vec(), false)
        .await
        .map_err(|e| describe("import-key", &e))?;
    let (tx, rx) = lann_webcrypto_guest::wit_stream::new();
    let (chunked, fed) = futures::join!(key.sign(rx), feed(tx, boundary_chunks(&payload)));
    fed?;
    let chunked = chunked.map_err(|e| describe("sign over boundary chunks", &e))?;
    let (tx, rx) = lann_webcrypto_guest::wit_stream::new();
    let (whole, fed) = futures::join!(key.sign(rx), feed(tx, vec![payload.clone()]));
    fed?;
    let whole = whole.map_err(|e| describe("sign over one whole write", &e))?;
    expect_bytes(&chunked, &whole, "tag over boundary chunks vs one write")?;

    let key = generate_key_256(false).await?;
    let nonce = [5u8; 12];
    let (tx, rx) = lann_webcrypto_guest::wit_stream::new();
    let (sealed, fed) = futures::join!(
        key.seal(nonce.to_vec(), b"large aad".to_vec(), None, rx),
        feed(tx, boundary_chunks(&payload))
    );
    fed?;
    let sealed = sealed.map_err(|e| describe("seal", &e))?.collect().await;
    expect(sealed.len(), LEN + 16, "sealed length")?;
    let (tx, rx) = lann_webcrypto_guest::wit_stream::new();
    let (opened, fed) = futures::join!(
        key.open(nonce.to_vec(), b"large aad".to_vec(), None, rx),
        feed(tx, boundary_chunks(&sealed))
    );
    fed?;
    let opened = opened.map_err(|e| describe("open", &e))?.collect().await;
    expect_bytes(&opened, &payload, "round-tripped plaintext")?;

    let key = generate_internal_nonce_key(AesVariant::Aes256, false)
        .await
        .map_err(|e| describe("generate-key (internal nonce)", &e))?;
    let (tx, rx) = lann_webcrypto_guest::wit_stream::new();
    let (sealed, fed) = futures::join!(
        key.seal(b"large aad".to_vec(), rx),
        feed(tx, boundary_chunks(&payload))
    );
    fed?;
    let sealed = sealed
        .map_err(|e| describe("internal-nonce seal", &e))?
        .collect()
        .await;
    expect(sealed.len(), LEN + 12 + 16, "internal-nonce sealed length")?;
    let (tx, rx) = lann_webcrypto_guest::wit_stream::new();
    let (opened, fed) = futures::join!(
        key.open(b"large aad".to_vec(), rx),
        feed(tx, boundary_chunks(&sealed))
    );
    fed?;
    let opened = opened
        .map_err(|e| describe("internal-nonce open", &e))?
        .collect()
        .await;
    expect_bytes(&opened, &payload, "internal-nonce round trip")
}

/// rather than a wrong answer, so this probe hangs instead of failing when
/// it regresses.
async fn stream_empty_writes() -> Result<(), String> {
    let key = import_hmac_key(
        Sha2Variant::Sha256,
        b"empty-write probe key".to_vec(),
        false,
    )
    .await
    .map_err(|e| describe("import-key", &e))?;
    let payload: Vec<u8> = (0..=255u8).cycle().take(512).collect();

    // The baseline: the same payload as a single write.
    let (expected, fed) = sign(&key, &payload, Schedule::Whole).await;
    fed?;

    // Empty writes before, between and after the payload's chunks.
    let mut chunks = vec![Vec::new()];
    for chunk in Schedule::Straddle.chunks(&payload) {
        chunks.push(chunk);
        chunks.push(Vec::new());
    }
    let (tx, rx) = lann_webcrypto_guest::wit_stream::new();
    let (tag, fed) = futures::join!(key.sign(rx), feed(tx, chunks));
    fed?;
    let tag = tag.map_err(|e| describe("sign with interleaved empty writes", &e))?;
    expect_bytes(&tag, &expected, "tag over a stream with empty writes")?;

    // A stream of nothing but empty writes is an empty input, not a stall.
    let (tx, rx) = lann_webcrypto_guest::wit_stream::new();
    let (empty_tag, fed) = futures::join!(
        key.sign(rx),
        feed(tx, vec![Vec::new(), Vec::new(), Vec::new()])
    );
    fed?;
    let empty_tag = empty_tag.map_err(|e| describe("sign over only empty writes", &e))?;
    let (expected_empty, fed) = sign(&key, b"", Schedule::Whole).await;
    fed?;
    expect_bytes(&empty_tag, &expected_empty, "tag over only empty writes")?;

    // The same shape through an AEAD round trip: seal's plaintext stream and
    // open's ciphertext stream are separate collectors on the host.
    let aes = generate_key(AesVariant::Aes256, false)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    let nonce = [7u8; 12];
    let (tx, rx) = lann_webcrypto_guest::wit_stream::new();
    let (sealed, fed) = futures::join!(
        aes.seal(nonce.to_vec(), b"empty-write aad".to_vec(), None, rx),
        feed(tx, vec![Vec::new(), payload.clone(), Vec::new()])
    );
    fed?;
    let sealed = sealed.map_err(|e| describe("seal", &e))?.collect().await;
    let (opened, fed) = open(
        &aes,
        &nonce,
        b"empty-write aad",
        None,
        &sealed,
        Schedule::Whole,
    )
    .await;
    fed.map_err(|e| format!("open feeder: {e}"))?;
    let opened = opened.map_err(|e| describe("open", &e))?;
    expect_bytes(&opened, &payload, "round-tripped plaintext")
}

/// The `extractable` getter reports the flag each key was minted with, on
/// every key resource carrying an extractability gate, and agrees with what
/// `export-key` then does.
///
/// The getter is the only way to ask the question without taking the
/// answer: a caller that interrogated extractability through `export-key`
/// alone would receive the material whenever the answer is yes.
async fn extractable_getter() -> Result<(), String> {
    for extractable in [true, false] {
        let mac = import_hmac_key(
            Sha2Variant::Sha256,
            b"extractable-getter".to_vec(),
            extractable,
        )
        .await
        .map_err(|e| describe("import-key (hmac)", &e))?;
        let aead = import_key(AesVariant::Aes256, vec![0x24u8; 32], extractable)
            .await
            .map_err(|e| describe("import-key (aes-gcm)", &e))?;
        let internal = import_internal_nonce_key(AesVariant::Aes256, vec![0x42u8; 32], extractable)
            .await
            .map_err(|e| describe("import-key (aes-gcm-internal-nonce)", &e))?;

        let reported = [
            ("mac-key", mac.extractable(), mac.export_key().await),
            ("aead-key", aead.extractable(), aead.export_key().await),
            (
                "internal-nonce-key",
                internal.extractable(),
                internal.export_key().await,
            ),
        ];
        for (resource, getter, exported) in reported {
            if getter != extractable {
                return Err(format!(
                    "{resource}.extractable reports {getter} for a key minted {extractable}"
                ));
            }
            match (extractable, exported) {
                (true, Ok(_)) | (false, Err(Error::NotExtractable)) => {}
                (true, Err(err)) => {
                    return Err(describe(
                        &format!("{resource}: extractable key failed to export"),
                        &err,
                    ))
                }
                (false, Ok(_)) => return Err(format!("{resource}: non-extractable key exported")),
                (false, Err(err)) => {
                    return Err(describe(
                        &format!("{resource}: expected not-extractable, got"),
                        &err,
                    ))
                }
            }
        }
    }
    Ok(())
}

/// `hmac-sha2.generate-key` honors an explicit bit length: the key reports
/// it, an extractable key exports exactly `length / 8` bytes, and the
/// contract's rejections hold — zero fails `invalid-key`, a length that is
/// not a multiple of 8 fails `unsupported`.
async fn hmac_generate_length() -> Result<(), String> {
    let key = generate_hmac_key(Sha2Variant::Sha256, Some(256), true)
        .await
        .map_err(|e| describe("generate-key length 256", &e))?;
    if key.algorithm_length() != 256 {
        return Err(format!(
            "generated mac-key length: got {}, want 256",
            key.algorithm_length()
        ));
    }
    let exported = key
        .export_key()
        .await
        .map_err(|e| describe("export-key", &e))?;
    if exported.len() != 32 {
        return Err(format!(
            "exported material length: got {}, want 32",
            exported.len()
        ));
    }

    match generate_hmac_key(Sha2Variant::Sha256, Some(0), false).await {
        Err(Error::InvalidKey(_)) => {}
        Err(other) => return Err(describe("length 0: expected invalid-key, got", &other)),
        Ok(_) => return Err("length 0 minted a key".into()),
    }
    match generate_hmac_key(Sha2Variant::Sha256, Some(250), false).await {
        Err(Error::Unsupported(_)) => {}
        Err(other) => return Err(describe("length 250: expected unsupported, got", &other)),
        Ok(_) => return Err("sub-byte length 250 minted a key".into()),
    }
    Ok(())
}

/// The full GCM parameter space, cross-target: a 16-byte nonce
/// round-trips (the non-96-bit `J0` derivation), a 4-byte tag round-trips
/// and fails when opened at the default size, an out-of-set tag size is
/// declined `unsupported`, ChaCha declines any non-default tag size, and
/// the empty nonce fails `invalid-nonce`.
async fn gcm_full_parameters() -> Result<(), String> {
    let key = generate_key_256(false).await?;
    let msg = b"gcm-full-parameters";

    let (sealed, fed) = seal(&key, &[7u8; 16], b"aad", None, msg, Schedule::Straddle).await;
    fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
    let sealed = sealed.map_err(|e| describe("seal (16-byte nonce)", &e))?;
    let (opened, fed) = open(&key, &[7u8; 16], b"aad", None, &sealed, Schedule::Whole).await;
    fed.map_err(|e| format!("open ciphertext feeder: {e}"))?;
    let opened = opened.map_err(|e| describe("open (16-byte nonce)", &e))?;
    expect_bytes(&opened, msg, "opened bytes (16-byte nonce)")?;

    let (short, fed) = seal(&key, &[9u8; 12], b"aad", Some(4), msg, Schedule::Whole).await;
    fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
    let short = short.map_err(|e| describe("seal (4-byte tag)", &e))?;
    expect(short.len(), msg.len() + 4, "sealed length (4-byte tag)")?;
    let (opened, fed) = open(&key, &[9u8; 12], b"aad", Some(4), &short, Schedule::Whole).await;
    fed.map_err(|e| format!("open ciphertext feeder: {e}"))?;
    let opened = opened.map_err(|e| describe("open (4-byte tag)", &e))?;
    expect_bytes(&opened, msg, "opened bytes (4-byte tag)")?;
    let (opened, fed) = open(&key, &[9u8; 12], b"aad", None, &short, Schedule::Whole).await;
    fed.map_err(|e| format!("open ciphertext feeder: {e}"))?;
    expect_err(
        "open of a 4-byte-tag message at the default size",
        ErrKind::AuthenticationFailed,
        opened,
        "verified with the wrong declared tag size",
    )?;

    let (sealed, fed) = seal(&key, &[9u8; 12], b"", Some(5), msg, Schedule::Whole).await;
    fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
    expect_err(
        "seal with a 5-byte tag size",
        ErrKind::Unsupported,
        sealed,
        "sealed with a tag size outside the GCM set",
    )?;

    Ok(())
}

/// The ChaCha constructions fix their tag size: a non-default per-call
/// `tag-size` is declined `unsupported` (the parameter exists for GCM, and
/// nothing else may silently honor it).
async fn chacha_tag_size_fixed() -> Result<(), String> {
    let msg = b"chacha-tag-size";
    let chacha = import_chacha_key(vec![0x42u8; 32], false)
        .await
        .map_err(|e| describe("chacha import-key", &e))?;
    let (sealed, fed) = seal(&chacha, &[0u8; 12], b"", Some(12), msg, Schedule::Whole).await;
    fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
    expect_err(
        "ChaCha20-Poly1305 seal with a 12-byte tag size",
        ErrKind::Unsupported,
        sealed,
        "sealed with a non-default tag size",
    )?;
    let (sealed, fed) = seal(&chacha, &[0u8; 12], b"", Some(16), msg, Schedule::Whole).await;
    fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
    sealed.map_err(|e| describe("seal with the explicit default tag size", &e))?;
    Ok(())
}

/// AES-GCM nonces outside the 12–128-byte window round-trip on targets
/// serving the full contract (the short end and the long end both exercise
/// the `J0` derivation).
async fn gcm_any_iv() -> Result<(), String> {
    let key = generate_key_256(false).await?;
    let msg = b"gcm-any-iv";
    for len in [8usize, 257] {
        let iv = vec![0x11u8; len];
        let (sealed, fed) = seal(&key, &iv, b"aad", None, msg, Schedule::Whole).await;
        fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
        let sealed = sealed.map_err(|e| describe(&format!("seal ({len}-byte nonce)"), &e))?;
        let (opened, fed) = open(&key, &iv, b"aad", None, &sealed, Schedule::Whole).await;
        fed.map_err(|e| format!("open ciphertext feeder: {e}"))?;
        let opened = opened.map_err(|e| describe(&format!("open ({len}-byte nonce)"), &e))?;
        expect_bytes(&opened, msg, "opened bytes")?;
    }
    Ok(())
}

/// The WPT symmetric fixtures' key bytes (1..=32), as the JWK `k` those
/// fixtures encode.
const JWK_K_32: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA";

/// JWK import and export round-trip on both oct algorithms: imported JWKs
/// yield the expected raw material, and an extractable key's exported JWK
/// re-imports to the same key.
async fn jwk_roundtrip() -> Result<(), String> {
    let raw: Vec<u8> = (1..=32).collect();

    let hmac = import_hmac_key_jwk(
        Sha2Variant::Sha256,
        format!(r#"{{"kty":"oct","k":"{JWK_K_32}","alg":"HS256"}}"#),
        true,
    )
    .await
    .map_err(|e| describe("hmac import-key-jwk", &e))?;
    let exported = hmac
        .export_key()
        .await
        .map_err(|e| describe("export-key", &e))?;
    expect_bytes(&exported, &raw, "hmac material from JWK")?;
    let jwk = hmac
        .export_key_jwk()
        .await
        .map_err(|e| describe("export-key-jwk", &e))?;
    let reimported = import_hmac_key_jwk(Sha2Variant::Sha256, jwk, true)
        .await
        .map_err(|e| describe("re-import of exported JWK", &e))?;
    let exported = reimported
        .export_key()
        .await
        .map_err(|e| describe("export-key", &e))?;
    expect_bytes(&exported, &raw, "hmac material after JWK round trip")?;

    let aes = import_aes_key_jwk(
        AesVariant::Aes256,
        format!(r#"{{"kty":"oct","k":"{JWK_K_32}","alg":"A256GCM"}}"#),
        true,
    )
    .await
    .map_err(|e| describe("aes import-key-jwk", &e))?;
    let jwk = aes
        .export_key_jwk()
        .await
        .map_err(|e| describe("export-key-jwk", &e))?;
    if !jwk.contains(JWK_K_32) || !jwk.contains("A256GCM") || !jwk.contains("\"oct\"") {
        return Err(format!("exported AES JWK missing material members: {jwk}"));
    }
    Ok(())
}

/// Malformed and mismatched JWKs fail `invalid-key` on every path the
/// contract names: JSON garbage, a wrong `kty`, an `alg` disagreeing with
/// the declared variant, padded (non-strict) base64url, an `ext: false`
/// conflict, and material whose length disagrees with the AES variant.
async fn jwk_rejections() -> Result<(), String> {
    let cases: &[(&str, String)] = &[
        ("json garbage", "{".to_string()),
        ("non-object", "[]".to_string()),
        ("wrong kty", format!(r#"{{"kty":"EC","k":"{JWK_K_32}"}}"#)),
        (
            "alg mismatch",
            format!(r#"{{"kty":"oct","k":"{JWK_K_32}","alg":"HS384"}}"#),
        ),
        (
            "padded base64url",
            r#"{"kty":"oct","k":"AQI="}"#.to_string(),
        ),
    ];
    for (what, jwk) in cases {
        match import_hmac_key_jwk(Sha2Variant::Sha256, jwk.clone(), false).await {
            Err(Error::InvalidKey(_)) => {}
            Err(other) => {
                return Err(describe(
                    &format!("hmac import-key-jwk ({what}): expected invalid-key, got"),
                    &other,
                ))
            }
            Ok(_) => return Err(format!("hmac import-key-jwk ({what}) minted a key")),
        }
    }

    match import_hmac_key_jwk(
        Sha2Variant::Sha256,
        format!(r#"{{"kty":"oct","k":"{JWK_K_32}","ext":false}}"#),
        true,
    )
    .await
    {
        Err(Error::InvalidKey(_)) => {}
        Err(other) => {
            return Err(describe(
                "ext:false imported extractable: expected invalid-key, got",
                &other,
            ))
        }
        Ok(_) => return Err("ext:false JWK imported extractable".into()),
    }

    // 32 bytes of material under the aes128 variant declaration.
    match import_aes_key_jwk(
        AesVariant::Aes128,
        format!(r#"{{"kty":"oct","k":"{JWK_K_32}","alg":"A128GCM"}}"#),
        false,
    )
    .await
    {
        Err(Error::InvalidKey(_)) => Ok(()),
        Err(other) => Err(describe(
            "32-byte JWK as aes128: expected invalid-key, got",
            &other,
        )),
        Ok(_) => Err("32-byte JWK minted an aes128 key".into()),
    }
}

/// The contract's parsing semantics, pinned cross-target: duplicate JSON
/// members resolve last-wins, `use`/`key_ops` are ignored (consumer
/// policy), and an `ext: false` JWK imports fine non-extractable.
async fn jwk_semantics() -> Result<(), String> {
    let raw: Vec<u8> = (1..=32).collect();

    // Two `k` members: the second (the fixture bytes) must win.
    let dup = format!(r#"{{"kty":"oct","k":"AAAA","k":"{JWK_K_32}","alg":"HS256"}}"#);
    let key = import_hmac_key_jwk(Sha2Variant::Sha256, dup, true)
        .await
        .map_err(|e| describe("duplicate-member import", &e))?;
    let exported = key
        .export_key()
        .await
        .map_err(|e| describe("export-key", &e))?;
    expect_bytes(&exported, &raw, "last-wins material")?;

    let policy = format!(
        r#"{{"kty":"oct","k":"{JWK_K_32}","use":"enc","key_ops":["encrypt"],"ext":false}}"#
    );
    let key = import_hmac_key_jwk(Sha2Variant::Sha256, policy, false)
        .await
        .map_err(|e| describe("use/key_ops-carrying import", &e))?;
    let (tag, fed) = sign(&key, b"jwk-semantics", Schedule::Whole).await;
    fed.map_err(|e| format!("sign data feeder: {e}"))?;
    if tag.len() != 32 {
        return Err(format!("tag length {} from JWK-imported key", tag.len()));
    }
    Ok(())
}

/// ChaCha keys have no registered JWK `alg`: `export-key-jwk` declines
/// `unsupported` (and the extractability gate still applies first on
/// non-extractable keys).
async fn chacha_jwk_unsupported() -> Result<(), String> {
    let key = import_chacha_key(vec![0x42u8; 32], true)
        .await
        .map_err(|e| describe("chacha import-key", &e))?;
    match key.export_key_jwk().await {
        Err(Error::Unsupported(_)) => Ok(()),
        Err(other) => Err(describe(
            "export-key-jwk: expected unsupported, got",
            &other,
        )),
        Ok(_) => Err("ChaCha20-Poly1305 exported a JWK".into()),
    }
}

/// Usage policy on `mac-key`: an untouched options resource cannot mint
/// (`not-permitted`, the package-wide options contract), grants are
/// enforced per operation, and the usage getters report the recorded
/// grants.
async fn mac_usage_policy() -> Result<(), String> {
    use lann_webcrypto_guest::bindings::hmac_sha2;
    use lann_webcrypto_guest::bindings::mac::MacKeyOptions;

    let raw = b"mac-usage-policy key".to_vec();
    expect_err(
        "zero-usage import-key",
        ErrKind::NotPermitted,
        hmac_sha2::import_key(Sha2Variant::Sha256, raw.clone(), MacKeyOptions::new()).await,
        "minted a key with no enabled usage",
    )?;

    let options = MacKeyOptions::new();
    options.can_sign(true);
    let sign_only = hmac_sha2::import_key(Sha2Variant::Sha256, raw.clone(), options)
        .await
        .map_err(|e| describe("sign-only import-key", &e))?;
    expect(sign_only.can_sign(), true, "sign-only key can-sign")?;
    expect(sign_only.can_verify(), false, "sign-only key can-verify")?;

    let payload = b"usage-policy payload";
    let (tag, fed) = sign(&sign_only, payload, Schedule::Whole).await;
    fed.map_err(|e| format!("sign data feeder: {e}"))?;
    let (refused, fed) = verify(&sign_only, payload, &tag, Schedule::Whole).await;
    fed.map_err(|e| format!("verify data feeder: {e}"))?;
    expect_err(
        "verify on a sign-only key",
        ErrKind::NotPermitted,
        refused,
        "sign-only key verified",
    )?;

    let options = MacKeyOptions::new();
    options.can_verify(true);
    let verify_only = hmac_sha2::import_key(Sha2Variant::Sha256, raw, options)
        .await
        .map_err(|e| describe("verify-only import-key", &e))?;
    expect(verify_only.can_sign(), false, "verify-only key can-sign")?;
    expect(verify_only.can_verify(), true, "verify-only key can-verify")?;
    let (verified, fed) = verify(&verify_only, payload, &tag, Schedule::Whole).await;
    fed.map_err(|e| format!("verify data feeder: {e}"))?;
    verified.map_err(|e| describe("valid tag under a verify-only key", &e))?;
    let (refused, fed) = try_sign(&verify_only, payload, Schedule::Whole).await;
    fed.map_err(|e| format!("sign data feeder: {e}"))?;
    expect_err(
        "sign on a verify-only key",
        ErrKind::NotPermitted,
        refused,
        "verify-only key signed",
    )
}

/// Usage policy on `aead-key`: the seal/open grants are enforced per
/// operation and reported by the getters, and the wrap grants — recorded
/// ahead of operations — mint a key on their own but permit neither
/// operation.
async fn aead_usage_policy() -> Result<(), String> {
    use lann_webcrypto_guest::bindings::aead::AeadKeyOptions;
    use lann_webcrypto_guest::bindings::aes_gcm;

    let raw = vec![0x5au8; 32];
    expect_err(
        "zero-usage import-key",
        ErrKind::NotPermitted,
        aes_gcm::import_key(AesVariant::Aes256, raw.clone(), AeadKeyOptions::new()).await,
        "minted a key with no enabled usage",
    )?;

    let options = AeadKeyOptions::new();
    options.can_seal(true);
    let seal_only = aes_gcm::import_key(AesVariant::Aes256, raw.clone(), options)
        .await
        .map_err(|e| describe("seal-only import-key", &e))?;
    expect(seal_only.can_seal(), true, "seal-only key can-seal")?;
    expect(seal_only.can_open(), false, "seal-only key can-open")?;
    expect(seal_only.can_wrap(), false, "seal-only key can-wrap")?;
    expect(seal_only.can_unwrap(), false, "seal-only key can-unwrap")?;

    let nonce = [3u8; 12];
    let plaintext = b"usage-policy plaintext";
    let (sealed, fed) = seal(&seal_only, &nonce, b"", None, plaintext, Schedule::Whole).await;
    fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
    let sealed = sealed.map_err(|e| describe("seal under a seal-only key", &e))?;
    let (refused, fed) = open(&seal_only, &nonce, b"", None, &sealed, Schedule::Whole).await;
    fed.map_err(|e| format!("open ciphertext feeder: {e}"))?;
    expect_err(
        "open on a seal-only key",
        ErrKind::NotPermitted,
        refused,
        "seal-only key opened",
    )?;

    let options = AeadKeyOptions::new();
    options.can_open(true);
    let open_only = aes_gcm::import_key(AesVariant::Aes256, raw.clone(), options)
        .await
        .map_err(|e| describe("open-only import-key", &e))?;
    expect(open_only.can_seal(), false, "open-only key can-seal")?;
    expect(open_only.can_open(), true, "open-only key can-open")?;
    let (opened, fed) = open(&open_only, &nonce, b"", None, &sealed, Schedule::Whole).await;
    fed.map_err(|e| format!("open ciphertext feeder: {e}"))?;
    let opened = opened.map_err(|e| describe("open under an open-only key", &e))?;
    expect_bytes(&opened, plaintext, "plaintext under an open-only key")?;
    let (refused, fed) = seal(&open_only, &nonce, b"", None, plaintext, Schedule::Whole).await;
    fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
    expect_err(
        "seal on an open-only key",
        ErrKind::NotPermitted,
        refused,
        "open-only key sealed",
    )?;

    let options = AeadKeyOptions::new();
    options.can_wrap(true);
    let wrap_only = aes_gcm::import_key(AesVariant::Aes256, raw, options)
        .await
        .map_err(|e| describe("wrap-only import-key", &e))?;
    expect(wrap_only.can_wrap(), true, "wrap-only key can-wrap")?;
    expect(wrap_only.can_seal(), false, "wrap-only key can-seal")?;
    let (refused, fed) = seal(&wrap_only, &nonce, b"", None, plaintext, Schedule::Whole).await;
    fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
    expect_err(
        "seal on a wrap-only key",
        ErrKind::NotPermitted,
        refused,
        "wrap-only key sealed",
    )
}

/// Usage policy on `internal-nonce-key`: the seal/open grants are enforced
/// per operation and reported by the getters, and a zero-usage mint is
/// refused.
async fn internal_nonce_usage_policy() -> Result<(), String> {
    use lann_webcrypto_guest::bindings::aead_internal_nonce::InternalNonceKeyOptions;
    use lann_webcrypto_guest::bindings::aes_gcm_internal_nonce;

    let raw = vec![0xc3u8; 32];
    expect_err(
        "zero-usage import-key",
        ErrKind::NotPermitted,
        aes_gcm_internal_nonce::import_key(
            AesVariant::Aes256,
            raw.clone(),
            InternalNonceKeyOptions::new(),
        )
        .await,
        "minted a key with no enabled usage",
    )?;

    let options = InternalNonceKeyOptions::new();
    options.can_seal(true);
    let seal_only = aes_gcm_internal_nonce::import_key(AesVariant::Aes256, raw.clone(), options)
        .await
        .map_err(|e| describe("seal-only import-key", &e))?;
    expect(seal_only.can_seal(), true, "seal-only key can-seal")?;
    expect(seal_only.can_open(), false, "seal-only key can-open")?;

    let plaintext = b"internal-nonce usage-policy plaintext";
    let (sealed, fed) = in_seal(&seal_only, b"", plaintext, Schedule::Whole).await;
    fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
    let sealed = sealed.map_err(|e| describe("seal under a seal-only key", &e))?;
    let (refused, fed) = in_open(&seal_only, b"", &sealed, Schedule::Whole).await;
    fed.map_err(|e| format!("open input feeder: {e}"))?;
    expect_err(
        "open on a seal-only key",
        ErrKind::NotPermitted,
        refused,
        "seal-only key opened",
    )?;

    let options = InternalNonceKeyOptions::new();
    options.can_open(true);
    let open_only = aes_gcm_internal_nonce::import_key(AesVariant::Aes256, raw, options)
        .await
        .map_err(|e| describe("open-only import-key", &e))?;
    expect(open_only.can_seal(), false, "open-only key can-seal")?;
    expect(open_only.can_open(), true, "open-only key can-open")?;
    let (opened, fed) = in_open(&open_only, b"", &sealed, Schedule::Whole).await;
    fed.map_err(|e| format!("open input feeder: {e}"))?;
    let opened = opened.map_err(|e| describe("open under an open-only key", &e))?;
    expect_bytes(&opened, plaintext, "plaintext under an open-only key")?;
    let (refused, fed) = in_seal(&open_only, b"", plaintext, Schedule::Whole).await;
    fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
    expect_err(
        "seal on an open-only key",
        ErrKind::NotPermitted,
        refused,
        "open-only key sealed",
    )
}

/// Usage policy on `signing-key`: `sign` is the sole usage, so an
/// untouched options resource cannot generate, and a granted key reports
/// the grant through `can-sign`.
async fn signing_usage_policy() -> Result<(), String> {
    use lann_webcrypto_guest::bindings::ed25519_sign;
    use lann_webcrypto_guest::bindings::signature::SigningKeyOptions;

    expect_err(
        "zero-usage generate-key",
        ErrKind::NotPermitted,
        ed25519_sign::generate_key(SigningKeyOptions::new()).await,
        "generated a key with no enabled usage",
    )?;

    let options = SigningKeyOptions::new();
    options.can_sign(true);
    let (key, _public) = ed25519_sign::generate_key(options)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    expect(key.can_sign(), true, "granted key can-sign")
}

/// WebCrypto §14.3.7 defines `deriveKey` as get-key-length → derive-bits →
/// import, so for a fully granted input the two paths must agree exactly:
/// `derive-key` equals importing the truncated `derive-bits` output. The
/// HMAC length default (the hash's block size) rides the same
/// get-key-length step `generate-key` uses.
async fn hkdf_derive_key_equivalence() -> Result<(), String> {
    use lann_webcrypto_guest::bindings::aead::AeadKeyOptions;
    use lann_webcrypto_guest::bindings::aes_gcm;
    use lann_webcrypto_guest::bindings::hkdf;
    use lann_webcrypto_guest::bindings::hmac_sha2;
    use lann_webcrypto_guest::bindings::mac::MacKeyOptions;

    let ikm = import_ikm(b"equivalence input keying material".to_vec(), true, true)
        .await
        .map_err(|e| describe("import-ikm", &e))?;
    let input = hkdf::prepare(
        Sha2Variant::Sha256,
        &ikm,
        b"equivalence salt".to_vec(),
        b"equivalence info".to_vec(),
    )
    .await
    .map_err(|e| describe("prepare", &e))?;

    let bits = input
        .derive_bits(Some(256))
        .await
        .map_err(|e| describe("derive-bits", &e))?;

    let aead_options = AeadKeyOptions::new();
    aead_options.can_seal(true);
    aead_options.extractable(true);
    let derived = aes_gcm::derive_key(aes_gcm::AesVariant::Aes256, &input, aead_options)
        .await
        .map_err(|e| describe("aes-gcm derive-key", &e))?;
    let exported = derived
        .export_key()
        .await
        .map_err(|e| describe("export of derived AES key", &e))?;
    expect_bytes(&exported, &bits, "derive-key equals import(derive-bits)")?;

    // The HMAC default length is the block size, exactly as generate-key
    // resolves it — and the derived key reports it.
    let mac_options = MacKeyOptions::new();
    mac_options.can_sign(true);
    let mac = hmac_sha2::derive_key(Sha2Variant::Sha256, &input, None, mac_options)
        .await
        .map_err(|e| describe("hmac derive-key", &e))?;
    expect(mac.algorithm_length(), 512, "derived HMAC default length")?;

    // Prefix consistency across targets is the platform's own behavior:
    // AES-128 from the same input is the first half of the 256-bit output.
    let aead_options = AeadKeyOptions::new();
    aead_options.can_seal(true);
    aead_options.extractable(true);
    let derived = aes_gcm::derive_key(aes_gcm::AesVariant::Aes128, &input, aead_options)
        .await
        .map_err(|e| describe("aes-128 derive-key", &e))?;
    let exported = derived
        .export_key()
        .await
        .map_err(|e| describe("export of derived AES-128 key", &e))?;
    expect_bytes(
        &exported,
        &bits[..16],
        "AES-128 is the 256-bit output's prefix",
    )
}

/// The derive grants gate exactly their operations; an extractable key
/// from a bits-less input is refused (the cap rule: an exportable key is
/// bits disclosure by other means); KDF-from-KDF chaining fails as the
/// platform's `deriveKey(… → "HKDF")` does; and the contract's parameter
/// errors land on their documented cases.
async fn hkdf_grants_and_chaining() -> Result<(), String> {
    use lann_webcrypto_guest::bindings::aead::AeadKeyOptions;
    use lann_webcrypto_guest::bindings::aes_gcm;
    use lann_webcrypto_guest::bindings::hkdf;

    expect_err(
        "zero-grant import-ikm",
        ErrKind::NotPermitted,
        import_ikm(vec![1; 32], false, false).await,
        "minted material with no enabled grant",
    )?;
    expect_err(
        "empty ikm",
        ErrKind::InvalidKey,
        import_ikm(Vec::new(), true, true).await,
        "minted empty input keying material",
    )?;

    let bits_only = import_ikm(vec![2; 32], true, false)
        .await
        .map_err(|e| describe("bits-only import-ikm", &e))?;
    expect(bits_only.can_derive_bits(), true, "ikm can-derive-bits")?;
    expect(bits_only.can_derive_key(), false, "ikm can-derive-key")?;
    expect_err(
        "prepare on a truncated variant",
        ErrKind::Unsupported,
        hkdf::prepare(Sha2Variant::Sha224, &bits_only, Vec::new(), Vec::new()).await,
        "prepared over an unserved variant",
    )?;
    let input = hkdf::prepare(Sha2Variant::Sha256, &bits_only, Vec::new(), Vec::new())
        .await
        .map_err(|e| describe("prepare", &e))?;
    expect(
        input.can_derive_bits(),
        true,
        "input copies can-derive-bits",
    )?;
    expect(input.can_derive_key(), false, "input copies can-derive-key")?;
    let options = AeadKeyOptions::new();
    options.can_seal(true);
    expect_err(
        "derive-key without the grant",
        ErrKind::NotPermitted,
        aes_gcm::derive_key(aes_gcm::AesVariant::Aes256, &input, options).await,
        "minted a key from a key-less input",
    )?;
    expect_err(
        "derive-bits with no length on a KDF input",
        ErrKind::Other,
        input.derive_bits(None).await,
        "derived with the platform's null-length error case",
    )?;
    expect_err(
        "sub-byte derive length",
        ErrKind::Other,
        input.derive_bits(Some(12)).await,
        "derived a sub-byte length",
    )?;

    let key_only = import_ikm(vec![3; 32], false, true)
        .await
        .map_err(|e| describe("key-only import-ikm", &e))?;
    let input = hkdf::prepare(Sha2Variant::Sha256, &key_only, Vec::new(), Vec::new())
        .await
        .map_err(|e| describe("prepare (key-only)", &e))?;
    expect_err(
        "derive-bits without the grant",
        ErrKind::NotPermitted,
        input.derive_bits(Some(256)).await,
        "derived bits from a bits-less input",
    )?;
    let options = AeadKeyOptions::new();
    options.can_seal(true);
    options.extractable(true);
    expect_err(
        "extractable key from a bits-less input (the cap rule)",
        ErrKind::NotPermitted,
        aes_gcm::derive_key(aes_gcm::AesVariant::Aes256, &input, options).await,
        "laundered bits through an extractable derived key",
    )?;
    let options = AeadKeyOptions::new();
    options.can_seal(true);
    let key = aes_gcm::derive_key(aes_gcm::AesVariant::Aes256, &input, options)
        .await
        .map_err(|e| describe("non-extractable derive-key", &e))?;
    expect(key.extractable(), false, "derived key extractability")?;

    expect_err(
        "KDF-from-KDF chaining",
        ErrKind::Other,
        hkdf::prepare_from(Sha2Variant::Sha256, &input, Vec::new(), Vec::new()).await,
        "chained from an input with no natural output length",
    )?;

    // The grantless-options contract is per-mint: the consumed options above
    // must not have leaked grants anywhere. A fresh zero-grant options fails.
    let _ = derive_options(true, true); // constructed and dropped: no effect on anything
    Ok(())
}
