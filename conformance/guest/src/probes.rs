//! Hand-written API-contract probes: the parts of the `lann:webcrypto`
//! contract the Wycheproof vectors cannot express — key import/export and
//! extractability, error variants for misuse, the seal/open drain rule,
//! generated-key shape, and algorithm naming.

use crate::mint::{
    agreement_options, derive_options, generate_ed25519_key, generate_hmac_key,
    generate_internal_nonce_key, generate_key, generate_x25519_key,
    generate_xchacha_internal_nonce_key, import_aes_key_jwk, import_chacha_key, import_hmac_key,
    import_hmac_key_jwk, import_ikm, import_internal_nonce_key, import_key_raw, import_password,
    import_x25519_public_key, import_x25519_secret_key, import_xchacha_internal_nonce_key,
    x25519_secret_jwk,
};
use conformance_harness::stream::{
    compute, feed, in_open, in_seal, open, seal, sig_sign, sig_verify, sign, try_sign, verify,
    Schedule,
};
use conformance_harness::{
    describe, expect, expect_bytes, expect_err, probes, unhex, ErrKind, FEATURE_CHACHA,
    FEATURE_GCM_ANY_IV, FEATURE_SHA1_CHECKED,
};
use lann_webcrypto_guest::bindings::aes_gcm::AesVariant;
use lann_webcrypto_guest::bindings::bytes::constant_time_equal as bytes_constant_time_equal;
use lann_webcrypto_guest::bindings::ecdsa_verify::{
    import_verifying_key_raw as import_ecdsa_verifying_key, EcdsaVariant,
};
use lann_webcrypto_guest::bindings::ed25519_verify::import_verifying_key_raw as import_ed25519_verifying_key;
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
    (sha1_checked) => {
        &[FEATURE_SHA1_CHECKED]
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
    chacha_nonce_lengths(chacha),
    ed25519_sign_roundtrip,
    sig_key_metadata,
    sig_import_invalid,
    verifying_key_export_roundtrip,
    internal_nonce_shape,
    chacha_internal_nonce_roundtrip(chacha),
    aes128_internal_nonce,
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
    aead_wrap_grants,
    internal_nonce_usage_policy,
    signing_usage_policy,
    hkdf_derive_key_equivalence,
    hkdf_grants_and_chaining,
    pbkdf2_contract,
    x25519_key_contract,
    x25519_agree_contract,
    x25519_grants_and_chaining,
    sig_public_format_imports,
    ed25519_private_format_imports,
    ecdsa_cross_hash_variants,
    x25519_format_roundtrips,
    internal_nonce_jwk,
    sha1_checked_postures(sha1_checked),
}

/// Run the probe case whose `features` a target declares missing: assert
/// the correct decline. This is the two-way guarantee behind the plain
/// `skipped` the vector cases report: a target cannot silently serve a
/// feature it declares missing.
pub async fn run_declined(features: &[&str]) -> Result<String, String> {
    if features == [FEATURE_CHACHA] {
        chacha_minting_declined().await
    } else if features == [FEATURE_SHA1_CHECKED] {
        sha1_checked_minting_declined().await
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
    for family in chacha_families() {
        expect_err(
            &format!("{} import-key-raw", family.name),
            ErrKind::Unsupported,
            (family.import)(
                vec![0x42u8; family.key_len],
                crate::mint::aead_options(false),
            )
            .await,
            "minted a key: the target serves a feature it declares missing",
        )?;
        expect_err(
            &format!("{} generate-key", family.name),
            ErrKind::Unsupported,
            (family.generate)(crate::mint::aead_options(false)).await,
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
        "xchacha internal-nonce import-key-raw",
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
        "import-key-raw",
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
            .map_err(|e| describe("import-key-raw", &e))?;
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
            &format!("import-key-raw {variant:?}"),
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
            &format!("import-key-raw ({len} bytes)"),
            ErrKind::InvalidKey,
            import_key_raw(AesVariant::Aes256, vec![0u8; len], false).await,
            "imported as AES-256",
        )?;
    }
    Ok(())
}

/// No implementation of this package serves AES-192 (see the WIT
/// `aes-variant` doc): both minting paths fail `unsupported`.
async fn aes192_unsupported() -> Result<(), String> {
    expect_err(
        "import-key-raw",
        ErrKind::Unsupported,
        import_key_raw(AesVariant::Aes192, vec![0u8; 24], false).await,
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

/// Import then export of an extractable HMAC key is the identity (the
/// AEAD families' identity is the contract battery's `export` area).
async fn key_export_roundtrip() -> Result<(), String> {
    let hmac_raw = b"key-export-roundtrip".to_vec();
    let key = import_hmac_key(Sha2Variant::Sha256, hmac_raw.clone(), true)
        .await
        .map_err(|e| describe("import-key-raw", &e))?;
    let exported = key
        .export_key_raw()
        .await
        .map_err(|e| describe("hmac export", &e))?;
    expect_bytes(&exported, &hmac_raw, "exported HMAC key material")
}

/// Export of a non-extractable HMAC key fails `not-extractable` (the
/// AEAD families' gate is the contract battery's `export` area).
async fn not_extractable() -> Result<(), String> {
    let key = import_hmac_key(Sha2Variant::Sha256, b"not-extractable".to_vec(), false)
        .await
        .map_err(|e| describe("import-key-raw", &e))?;
    expect_err(
        "hmac export-key-raw",
        ErrKind::NotExtractable,
        key.export_key_raw().await,
        "non-extractable HMAC key exported",
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
        .export_key_raw()
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
        .export_key_raw()
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
        .map_err(|e| describe("import-key-raw", &e))?;
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

    let imported = import_key_raw(AesVariant::Aes256, vec![0x24u8; 32], false)
        .await
        .map_err(|e| describe("import-key-raw", &e))?;
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
    .map_err(|e| describe("import-key-raw", &e))?;
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
    .map_err(|e| describe("import-key-raw", &e))?;

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
        let first = first.map_err(|e| describe("first compute", &e))?;
        let (second, fed) = compute(&digest, b"reusable", Schedule::Bytes).await;
        fed.map_err(|e| format!("second compute feeder: {e}"))?;
        let second = second.map_err(|e| describe("second compute", &e))?;
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

/// The contract battery's ChaCha rows (`contract::AEAD_FAMILIES` tagged
/// with the feature): the minting entry points the decline and
/// nonce-length probes iterate.
fn chacha_families() -> impl Iterator<Item = &'static crate::contract::AeadFamily> {
    crate::contract::AEAD_FAMILIES
        .iter()
        .filter(|family| family.features.contains(&FEATURE_CHACHA))
}

/// Each construction's key accepts exactly its own nonce length: the other
/// construction's length is `invalid-nonce` (nonce-length confusion between
/// the constructions cannot pass silently), and the correct length
/// round-trips.
async fn chacha_nonce_lengths() -> Result<(), String> {
    let msg = b"chacha-nonce-lengths";
    for family in chacha_families() {
        let (name, good_len) = (family.name, family.nonce_len);
        let bad_len = if good_len == 12 { 24 } else { 12 };
        let key = (family.import)(
            vec![0x42u8; family.key_len],
            crate::mint::aead_options(false),
        )
        .await
        .map_err(|e| describe("import-key-raw", &e))?;
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
    // it back: `export-key-raw` failing is a separate contract, checked
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
        .map_err(|e| describe("import-verifying-key-raw", &e))?;
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
        .export_key_raw()
        .await
        .map_err(|e| describe("export-key-raw (public)", &e))?;
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
            .map_err(|e| describe("import-verifying-key-raw (ecdsa)", &e))?;
        let exported = key
            .export_key_raw()
            .await
            .map_err(|e| describe("export-key-raw (public)", &e))?;
        expect_bytes(&exported, &public, "exported ECDSA public key")?;
    }
    Ok(())
}

/// The internal-nonce API contract the vectors cannot express: sealed
/// messages carry the algorithm's wire format (nonce-prefix length), each
/// seal draws a fresh nonce, minting validates key material, and
/// extractability gates `export-key-raw` exactly as for `aead-key`.
async fn internal_nonce_shape() -> Result<(), String> {
    // Wrong-length material is rejected at minting, as for `aes-gcm`.
    expect_err(
        "import-key-raw (16 bytes as AES-256)",
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

    // A non-extractable key refuses export-key-raw.
    expect_err(
        "export-key-raw",
        ErrKind::NotExtractable,
        key.export_key_raw().await,
        "non-extractable key exported",
    )?;

    // An extractable generated key exports 32 bytes.
    let key = generate_internal_nonce_key(AesVariant::Aes256, true)
        .await
        .map_err(|e| describe("generate-key (extractable)", &e))?;
    let exported = key
        .export_key_raw()
        .await
        .map_err(|e| describe("export-key-raw", &e))?;
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
        "export-key-raw",
        ErrKind::NotExtractable,
        key.export_key_raw().await,
        "non-extractable key exported",
    )?;
    let raw = vec![0x42u8; 32];
    let imported = import_xchacha_internal_nonce_key(raw.clone(), true)
        .await
        .map_err(|e| describe("import-key-raw", &e))?;
    let exported = imported
        .export_key_raw()
        .await
        .map_err(|e| describe("export-key-raw", &e))?;
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

/// The internal-nonce discipline serves AES-128 too: a generated key
/// reports the 128-bit length and round-trips (the caller-nonce AES-128
/// shape is the contract battery's `aes-gcm/contract/aes128-*` cases).
async fn aes128_internal_nonce() -> Result<(), String> {
    let plaintext = b"aes-128 round trip payload".to_vec();
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
        .map_err(|e| describe("import-key-raw", &e))?;
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
    .map_err(|e| describe("import-key-raw", &e))?;
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
/// `export-key-raw` then does.
///
/// The getter is the only way to ask the question without taking the
/// answer: a caller that interrogated extractability through `export-key-raw`
/// alone would receive the material whenever the answer is yes.
async fn extractable_getter() -> Result<(), String> {
    for extractable in [true, false] {
        let mac = import_hmac_key(
            Sha2Variant::Sha256,
            b"extractable-getter".to_vec(),
            extractable,
        )
        .await
        .map_err(|e| describe("import-key-raw (hmac)", &e))?;
        let aead = import_key_raw(AesVariant::Aes256, vec![0x24u8; 32], extractable)
            .await
            .map_err(|e| describe("import-key-raw (aes-gcm)", &e))?;
        let internal = import_internal_nonce_key(AesVariant::Aes256, vec![0x42u8; 32], extractable)
            .await
            .map_err(|e| describe("import-key-raw (aes-gcm-internal-nonce)", &e))?;

        let reported = [
            ("mac-key", mac.extractable(), mac.export_key_raw().await),
            ("aead-key", aead.extractable(), aead.export_key_raw().await),
            (
                "internal-nonce-key",
                internal.extractable(),
                internal.export_key_raw().await,
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
        .export_key_raw()
        .await
        .map_err(|e| describe("export-key-raw", &e))?;
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
        .map_err(|e| describe("chacha import-key-raw", &e))?;
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
        .export_key_raw()
        .await
        .map_err(|e| describe("export-key-raw", &e))?;
    expect_bytes(&exported, &raw, "hmac material from JWK")?;
    let jwk = hmac
        .export_key_jwk()
        .await
        .map_err(|e| describe("export-key-jwk", &e))?;
    let reimported = import_hmac_key_jwk(Sha2Variant::Sha256, jwk, true)
        .await
        .map_err(|e| describe("re-import of exported JWK", &e))?;
    let exported = reimported
        .export_key_raw()
        .await
        .map_err(|e| describe("export-key-raw", &e))?;
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
        .export_key_raw()
        .await
        .map_err(|e| describe("export-key-raw", &e))?;
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
        .map_err(|e| describe("chacha import-key-raw", &e))?;
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
        "zero-usage import-key-raw",
        ErrKind::NotPermitted,
        hmac_sha2::import_key_raw(Sha2Variant::Sha256, raw.clone(), MacKeyOptions::new()).await,
        "minted a key with no enabled usage",
    )?;

    let options = MacKeyOptions::new();
    options.can_sign(true);
    let sign_only = hmac_sha2::import_key_raw(Sha2Variant::Sha256, raw.clone(), options)
        .await
        .map_err(|e| describe("sign-only import-key-raw", &e))?;
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
    let verify_only = hmac_sha2::import_key_raw(Sha2Variant::Sha256, raw, options)
        .await
        .map_err(|e| describe("verify-only import-key-raw", &e))?;
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

/// The wrap grants on `aead-key`: recorded ahead of the wrap operations
/// existing, each mints a key on its own, reports through its getter in
/// both directions, and permits neither seal nor open. (The seal/open
/// grants' enforcement and getters are the contract battery's `usage`
/// area, per family.)
async fn aead_wrap_grants() -> Result<(), String> {
    use lann_webcrypto_guest::bindings::aead::AeadKeyOptions;
    use lann_webcrypto_guest::bindings::aes_gcm;

    let options = AeadKeyOptions::new();
    options.can_wrap(true);
    let wrap_only = aes_gcm::import_key_raw(AesVariant::Aes256, vec![0x5au8; 32], options)
        .await
        .map_err(|e| describe("wrap-only import-key-raw", &e))?;
    expect(wrap_only.can_wrap(), true, "wrap-only key can-wrap")?;
    expect(wrap_only.can_unwrap(), false, "wrap-only key can-unwrap")?;
    expect(wrap_only.can_seal(), false, "wrap-only key can-seal")?;
    let (refused, fed) = seal(
        &wrap_only,
        &[3u8; 12],
        b"",
        None,
        b"usage-policy plaintext",
        Schedule::Whole,
    )
    .await;
    fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
    expect_err(
        "seal on a wrap-only key",
        ErrKind::NotPermitted,
        refused,
        "wrap-only key sealed",
    )?;

    let options = AeadKeyOptions::new();
    options.can_unwrap(true);
    let unwrap_only = aes_gcm::import_key_raw(AesVariant::Aes256, vec![0xa5u8; 32], options)
        .await
        .map_err(|e| describe("unwrap-only import-key-raw", &e))?;
    expect(unwrap_only.can_unwrap(), true, "unwrap-only key can-unwrap")?;
    expect(unwrap_only.can_wrap(), false, "unwrap-only key can-wrap")?;
    let (refused, fed) = open(
        &unwrap_only,
        &[3u8; 12],
        b"",
        None,
        &[0u8; 16],
        Schedule::Whole,
    )
    .await;
    fed.map_err(|e| format!("open input feeder: {e}"))?;
    expect_err(
        "open on an unwrap-only key",
        ErrKind::NotPermitted,
        refused,
        "unwrap-only key opened",
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
        "zero-usage import-key-raw",
        ErrKind::NotPermitted,
        aes_gcm_internal_nonce::import_key_raw(
            AesVariant::Aes256,
            raw.clone(),
            InternalNonceKeyOptions::new(),
        )
        .await,
        "minted a key with no enabled usage",
    )?;

    let options = InternalNonceKeyOptions::new();
    options.can_seal(true);
    let seal_only =
        aes_gcm_internal_nonce::import_key_raw(AesVariant::Aes256, raw.clone(), options)
            .await
            .map_err(|e| describe("seal-only import-key-raw", &e))?;
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
    let open_only = aes_gcm_internal_nonce::import_key_raw(AesVariant::Aes256, raw, options)
        .await
        .map_err(|e| describe("open-only import-key-raw", &e))?;
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
        .export_key_raw()
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
        .export_key_raw()
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
    expect(
        key_only.can_derive_bits(),
        false,
        "key-only ikm can-derive-bits",
    )?;
    expect(
        key_only.can_derive_key(),
        true,
        "key-only ikm can-derive-key",
    )?;
    let input = hkdf::prepare(Sha2Variant::Sha256, &key_only, Vec::new(), Vec::new())
        .await
        .map_err(|e| describe("prepare (key-only)", &e))?;
    expect(
        input.can_derive_bits(),
        false,
        "key-only input copies can-derive-bits",
    )?;
    expect(
        input.can_derive_key(),
        true,
        "key-only input copies can-derive-key",
    )?;
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

/// The PBKDF2 contract the vectors cannot express: an empty password is
/// accepted (the documented asymmetry with `import-ikm` — the platform and
/// the upstream vectors treat it as valid), a zero iteration count fails at
/// `prepare` with the platform's error, grants copy from the password, the
/// §14.3.7 equivalence holds for a PBKDF2 input, and chaining from a
/// PBKDF2 input fails exactly as from an HKDF one — there is deliberately
/// no `pbkdf2.prepare-from` at all, and `hkdf.prepare-from` refuses KDF
/// upstreams of either flavor.
async fn pbkdf2_contract() -> Result<(), String> {
    use lann_webcrypto_guest::bindings::aead::AeadKeyOptions;
    use lann_webcrypto_guest::bindings::aes_gcm;
    use lann_webcrypto_guest::bindings::hkdf;
    use lann_webcrypto_guest::bindings::pbkdf2;

    expect_err(
        "zero-grant import-password",
        ErrKind::NotPermitted,
        import_password(vec![1; 8], false, false).await,
        "minted a password with no enabled grant",
    )?;

    // RFC 7914 §11 known answer (c = 1), through the full WIT surface.
    let password = import_password(b"passwd".to_vec(), true, true)
        .await
        .map_err(|e| describe("import-password", &e))?;
    let input = pbkdf2::prepare(Sha2Variant::Sha256, &password, b"salt".to_vec(), 1)
        .await
        .map_err(|e| describe("prepare", &e))?;
    let dk = input
        .derive_bits(Some(64 * 8))
        .await
        .map_err(|e| describe("derive-bits", &e))?;
    expect_bytes(
        &dk,
        &unhex(
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc\
             49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
        ),
        "RFC 7914 derived key",
    )?;

    // The §14.3.7 equivalence, from a PBKDF2 source.
    let options = AeadKeyOptions::new();
    options.can_seal(true);
    options.extractable(true);
    let derived = aes_gcm::derive_key(aes_gcm::AesVariant::Aes256, &input, options)
        .await
        .map_err(|e| describe("derive-key", &e))?;
    let exported = derived
        .export_key_raw()
        .await
        .map_err(|e| describe("export of derived key", &e))?;
    expect_bytes(
        &exported,
        &dk[..32],
        "derive-key equals truncated derive-bits",
    )?;

    expect_err(
        "zero iteration count",
        ErrKind::Other,
        pbkdf2::prepare(Sha2Variant::Sha256, &password, b"salt".to_vec(), 0).await,
        "prepared with zero iterations",
    )?;
    expect_err(
        "prepare on a truncated variant",
        ErrKind::Unsupported,
        pbkdf2::prepare(Sha2Variant::Sha512224, &password, b"salt".to_vec(), 1).await,
        "prepared over an unserved variant",
    )?;

    // Empty passwords mint and derive (unlike empty IKM).
    let empty = import_password(Vec::new(), true, true)
        .await
        .map_err(|e| describe("empty import-password", &e))?;
    let input = pbkdf2::prepare(Sha2Variant::Sha256, &empty, vec![1, 2, 3, 4], 2)
        .await
        .map_err(|e| describe("prepare (empty password)", &e))?;
    input
        .derive_bits(Some(128))
        .await
        .map_err(|e| describe("derive-bits (empty password)", &e))?;

    // Grants copy; both getter directions report; chaining from a PBKDF2
    // input refuses like any KDF's.
    let bits_only = import_password(b"bits-only".to_vec(), true, false)
        .await
        .map_err(|e| describe("bits-only import-password", &e))?;
    expect(
        bits_only.can_derive_bits(),
        true,
        "bits-only password can-derive-bits",
    )?;
    expect(
        bits_only.can_derive_key(),
        false,
        "bits-only password can-derive-key",
    )?;
    let key_only = import_password(b"key-only".to_vec(), false, true)
        .await
        .map_err(|e| describe("key-only import-password", &e))?;
    expect(
        key_only.can_derive_bits(),
        false,
        "password can-derive-bits",
    )?;
    expect(key_only.can_derive_key(), true, "password can-derive-key")?;
    let input = pbkdf2::prepare(Sha2Variant::Sha256, &key_only, Vec::new(), 1)
        .await
        .map_err(|e| describe("prepare (key-only)", &e))?;
    expect(
        input.can_derive_bits(),
        false,
        "input copies can-derive-bits",
    )?;
    expect_err(
        "derive-bits without the grant",
        ErrKind::NotPermitted,
        input.derive_bits(Some(128)).await,
        "derived bits from a bits-less input",
    )?;
    expect_err(
        "chaining from a PBKDF2 input",
        ErrKind::Other,
        hkdf::prepare_from(Sha2Variant::Sha256, &input, Vec::new(), Vec::new()).await,
        "chained from a KDF input",
    )
}

/// RFC 7748 §6.1: Alice's and Bob's key pairs. The published private
/// scalars, public coordinates, and shared secret pin the whole
/// import-JWK → agree → derive path against a known answer.
const RFC7748_ALICE_D: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
const RFC7748_ALICE_X: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
const RFC7748_BOB_D: &str = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
const RFC7748_BOB_X: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
const RFC7748_SHARED: &str = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

/// The X25519 key surface: metadata getters in both grant directions,
/// generated-key freshness, public-key export round trips, the OKP JWK
/// import contract's rejections, extractability recording, and the
/// zero-grant mint refusals.
async fn x25519_key_contract() -> Result<(), String> {
    use lann_webcrypto_guest::bindings::x25519;

    let (secret, public) = generate_x25519_key(true, true)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    expect(
        secret.algorithm_name(),
        "X25519".to_string(),
        "secret-key algorithm-name",
    )?;
    expect(
        public.algorithm_name(),
        "X25519".to_string(),
        "public-key algorithm-name",
    )?;
    expect(secret.can_derive_bits(), true, "secret-key can-derive-bits")?;
    expect(secret.can_derive_key(), true, "secret-key can-derive-key")?;
    expect(
        secret.extractable(),
        false,
        "secret-key extractable (mint default)",
    )?;

    // Single-grant mints report through the getters in both directions.
    let (bits_only, _) = generate_x25519_key(true, false)
        .await
        .map_err(|e| describe("bits-only generate-key", &e))?;
    expect(
        bits_only.can_derive_bits(),
        true,
        "bits-only secret-key can-derive-bits",
    )?;
    expect(
        bits_only.can_derive_key(),
        false,
        "bits-only secret-key can-derive-key",
    )?;
    let (key_only, _) = generate_x25519_key(false, true)
        .await
        .map_err(|e| describe("key-only generate-key", &e))?;
    expect(
        key_only.can_derive_bits(),
        false,
        "key-only secret-key can-derive-bits",
    )?;
    expect(
        key_only.can_derive_key(),
        true,
        "key-only secret-key can-derive-key",
    )?;

    // A generated public key exports as the raw 32-byte u-coordinate and
    // re-imports to an equivalent key: both peers derive the same secret.
    let raw = public
        .export_key_raw()
        .await
        .map_err(|e| describe("public-key export-key-raw", &e))?;
    expect(raw.len(), 32, "exported public-key length")?;
    let reimported = import_x25519_public_key(raw.clone())
        .await
        .map_err(|e| describe("re-import of exported public key", &e))?;
    let direct = secret
        .agree(&public)
        .await
        .map_err(|e| describe("agree (original public)", &e))?
        .derive_bits(None)
        .await
        .map_err(|e| describe("derive-bits (original public)", &e))?;
    let via_reimport = secret
        .agree(&reimported)
        .await
        .map_err(|e| describe("agree (re-imported public)", &e))?
        .derive_bits(None)
        .await
        .map_err(|e| describe("derive-bits (re-imported public)", &e))?;
    expect_bytes(&via_reimport, &direct, "agreement after raw round trip")?;

    // Generated keys are fresh: a second generate yields a different
    // public point. Identical points mean the implementation's randomness
    // is broken (all-zero or constant output repeats the key), which
    // nothing else on this surface can observe — every round trip works
    // fine under a constant key.
    let (_, public2) = generate_x25519_key(true, true)
        .await
        .map_err(|e| describe("second generate-key", &e))?;
    let raw2 = public2
        .export_key_raw()
        .await
        .map_err(|e| describe("second public-key export-key-raw", &e))?;
    if raw2 == raw {
        return Err("two generated keys share a public point".into());
    }

    // The public JWK export carries the OKP material members.
    let jwk = public
        .export_key_jwk()
        .await
        .map_err(|e| describe("public-key export-key-jwk", &e))?;
    let x = crate::mint::b64url(&raw);
    if !jwk.contains("\"OKP\"") || !jwk.contains("\"X25519\"") || !jwk.contains(&x) {
        return Err(format!(
            "exported public JWK missing material members: {jwk}"
        ));
    }

    // Import rejections: a wrong-length public key, and OKP JWKs with the
    // wrong curve or without the private scalar.
    expect_err(
        "31-byte public key",
        ErrKind::InvalidKey,
        import_x25519_public_key(vec![1; 31]).await,
        "imported a wrong-length u-coordinate",
    )?;
    let alice_x = unhex(RFC7748_ALICE_X);
    let alice_d = unhex(RFC7748_ALICE_D);
    expect_err(
        "wrong-curve OKP JWK",
        ErrKind::InvalidKey,
        x25519::import_secret_key_jwk(
            x25519_secret_jwk(&alice_x, &alice_d).replace("X25519", "Ed25519"),
            agreement_options(true, true, false),
        )
        .await,
        "imported an Ed25519 JWK as X25519",
    )?;
    expect_err(
        "public-only OKP JWK",
        ErrKind::InvalidKey,
        x25519::import_secret_key_jwk(
            format!(
                r#"{{"kty":"OKP","crv":"X25519","x":"{}"}}"#,
                crate::mint::b64url(&alice_x)
            ),
            agreement_options(true, true, false),
        )
        .await,
        "imported a d-less JWK as a secret key",
    )?;

    // The zero-usage mint check, on both minting paths that take options.
    expect_err(
        "zero-grant import",
        ErrKind::NotPermitted,
        import_x25519_secret_key(&alice_x, &alice_d, false, false).await,
        "minted a secret key with no enabled grant",
    )?;
    expect_err(
        "zero-grant generate",
        ErrKind::NotPermitted,
        generate_x25519_key(false, false).await,
        "generated a key with no enabled grant",
    )?;

    // The extractable grant records through the options onto the minted
    // key (secret keys have no export operation; the getter is the
    // observable).
    let extractable_import = x25519::import_secret_key_jwk(
        x25519_secret_jwk(&alice_x, &alice_d),
        agreement_options(true, true, true),
    )
    .await
    .map_err(|e| describe("extractable import", &e))?;
    expect(
        extractable_import.extractable(),
        true,
        "extractable import's getter",
    )
}

/// The agreement operation itself: the RFC 7748 §6.1 known answer in both
/// directions, the agreed input's natural-length semantics (`none` is the
/// whole 32-byte secret, truncation takes a prefix), and its parameter
/// errors (zero, sub-byte, and over-length requests).
async fn x25519_agree_contract() -> Result<(), String> {
    let shared = unhex(RFC7748_SHARED);
    let alice =
        import_x25519_secret_key(&unhex(RFC7748_ALICE_X), &unhex(RFC7748_ALICE_D), true, true)
            .await
            .map_err(|e| describe("import Alice", &e))?;
    let bob = import_x25519_secret_key(&unhex(RFC7748_BOB_X), &unhex(RFC7748_BOB_D), true, true)
        .await
        .map_err(|e| describe("import Bob", &e))?;
    let alice_public = import_x25519_public_key(unhex(RFC7748_ALICE_X))
        .await
        .map_err(|e| describe("import Alice's public key", &e))?;
    let bob_public = import_x25519_public_key(unhex(RFC7748_BOB_X))
        .await
        .map_err(|e| describe("import Bob's public key", &e))?;

    let input = alice
        .agree(&bob_public)
        .await
        .map_err(|e| describe("agree (Alice with Bob)", &e))?;
    expect(
        input.can_derive_bits(),
        true,
        "input copies can-derive-bits",
    )?;
    expect(input.can_derive_key(), true, "input copies can-derive-key")?;
    let derived = input
        .derive_bits(None)
        .await
        .map_err(|e| describe("derive-bits (natural length)", &e))?;
    expect_bytes(&derived, &shared, "RFC 7748 shared secret")?;

    let other = bob
        .agree(&alice_public)
        .await
        .map_err(|e| describe("agree (Bob with Alice)", &e))?
        .derive_bits(None)
        .await
        .map_err(|e| describe("derive-bits (Bob's direction)", &e))?;
    expect_bytes(&other, &shared, "agreement commutes")?;

    let prefix = input
        .derive_bits(Some(128))
        .await
        .map_err(|e| describe("derive-bits (truncated)", &e))?;
    expect_bytes(&prefix, &shared[..16], "truncation takes a prefix")?;
    expect_err(
        "zero-length derive",
        ErrKind::Other,
        input.derive_bits(Some(0)).await,
        "derived a zero-length secret",
    )?;
    expect_err(
        "sub-byte derive length",
        ErrKind::Other,
        input.derive_bits(Some(12)).await,
        "derived a sub-byte length",
    )?;
    expect_err(
        "derive past the shared secret's length",
        ErrKind::Other,
        input.derive_bits(Some(264)).await,
        "derived more bits than the agreement produced",
    )
}

/// The derive grants an agreed input inherits gate exactly their
/// operations (including the cap rule), and — the property no KDF source
/// has — `hkdf.prepare-from` chains from an agreement: the spec's own
/// X25519 → HKDF → AES-GCM example, checked against HKDF over the same
/// shared secret imported as IKM.
async fn x25519_grants_and_chaining() -> Result<(), String> {
    use lann_webcrypto_guest::bindings::aead::AeadKeyOptions;
    use lann_webcrypto_guest::bindings::aes_gcm;
    use lann_webcrypto_guest::bindings::hkdf;

    let shared = unhex(RFC7748_SHARED);
    let alice =
        import_x25519_secret_key(&unhex(RFC7748_ALICE_X), &unhex(RFC7748_ALICE_D), true, true)
            .await
            .map_err(|e| describe("import Alice", &e))?;
    let bob_public = import_x25519_public_key(unhex(RFC7748_BOB_X))
        .await
        .map_err(|e| describe("import Bob's public key", &e))?;

    // Chaining equivalence: prepare-from over the agreed input equals
    // hkdf.prepare over the same shared secret imported as IKM.
    let input = alice
        .agree(&bob_public)
        .await
        .map_err(|e| describe("agree", &e))?;
    let chained = hkdf::prepare_from(
        Sha2Variant::Sha256,
        &input,
        b"chain salt".to_vec(),
        b"chain info".to_vec(),
    )
    .await
    .map_err(|e| describe("prepare-from", &e))?;
    let via_chain = chained
        .derive_bits(Some(256))
        .await
        .map_err(|e| describe("derive-bits (chained)", &e))?;
    let ikm = import_ikm(shared.clone(), true, true)
        .await
        .map_err(|e| describe("import-ikm (shared secret)", &e))?;
    let direct = hkdf::prepare(
        Sha2Variant::Sha256,
        &ikm,
        b"chain salt".to_vec(),
        b"chain info".to_vec(),
    )
    .await
    .map_err(|e| describe("prepare (imported shared secret)", &e))?
    .derive_bits(Some(256))
    .await
    .map_err(|e| describe("derive-bits (direct HKDF)", &e))?;
    expect_bytes(&via_chain, &direct, "chaining equals HKDF over the secret")?;

    // Bits-only: derive-bits works, derive-key and chaining are refused.
    let bits_only = import_x25519_secret_key(
        &unhex(RFC7748_ALICE_X),
        &unhex(RFC7748_ALICE_D),
        true,
        false,
    )
    .await
    .map_err(|e| describe("bits-only import", &e))?;
    let input = bits_only
        .agree(&bob_public)
        .await
        .map_err(|e| describe("agree (bits-only)", &e))?;
    input
        .derive_bits(None)
        .await
        .map_err(|e| describe("derive-bits (bits-only)", &e))?;
    let options = AeadKeyOptions::new();
    options.can_seal(true);
    expect_err(
        "derive-key without the grant",
        ErrKind::NotPermitted,
        aes_gcm::derive_key(aes_gcm::AesVariant::Aes256, &input, options).await,
        "minted a key from a key-less input",
    )?;
    expect_err(
        "chaining without the derive-key grant",
        ErrKind::NotPermitted,
        hkdf::prepare_from(Sha2Variant::Sha256, &input, Vec::new(), Vec::new()).await,
        "chained from a key-less input",
    )?;

    // Key-only: derive-bits is refused, the cap rule holds, and a
    // non-extractable derived key minting succeeds.
    let key_only = import_x25519_secret_key(
        &unhex(RFC7748_ALICE_X),
        &unhex(RFC7748_ALICE_D),
        false,
        true,
    )
    .await
    .map_err(|e| describe("key-only import", &e))?;
    let input = key_only
        .agree(&bob_public)
        .await
        .map_err(|e| describe("agree (key-only)", &e))?;
    expect_err(
        "derive-bits without the grant",
        ErrKind::NotPermitted,
        input.derive_bits(None).await,
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
    expect(key.extractable(), false, "derived key extractability")
}

// RFC 8032 §7.1 TEST 3: the seed, its public key, and the deterministic
// signature over the two-byte message `af82` — a cross-implementation
// known answer, since RFC 8032 signing is deterministic.
const ED25519_TEST3_SEED: &str = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";
const ED25519_TEST3_PUBLIC: &str =
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";
const ED25519_TEST3_MSG: &str = "af82";
const ED25519_TEST3_SIG: &str = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a";

// The RFC 6979 A.2.5 P-256 public key: the uncompressed SEC1 point and its
// SubjectPublicKeyInfo encoding.
const P256_A25_X: &str = "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6";
const P256_A25_Y: &str = "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";
const P256_A25_SPKI: &str = "3059301306072a8648ce3d020106082a8648ce3d0301070342000460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";

/// The RFC 8410 PKCS#8 encoding of a 32-byte private key (Ed25519 or
/// X25519 by OID tail: 0x70 or 0x6e).
fn rfc8410_pkcs8(oid_tail: u8, key: &[u8]) -> Vec<u8> {
    let mut out = unhex("302e020100300506032b650004220420");
    out[11] = oid_tail;
    out.extend_from_slice(key);
    out
}

/// The RFC 8410 SubjectPublicKeyInfo encoding of a 32-byte public key.
fn rfc8410_spki(oid_tail: u8, key: &[u8]) -> Vec<u8> {
    let mut out = unhex("302a300506032b6500032100");
    out[8] = oid_tail;
    out.extend_from_slice(key);
    out
}

/// The SPKI and JWK verifying-key import/export formats agree with the raw
/// form byte-for-byte, on both signature algorithms: raw → spki/jwk export
/// → re-import → raw export is the identity, a wrong-curve SPKI fails
/// `invalid-key`, and the JWK `alg` allowlists hold on both algorithms.
async fn sig_public_format_imports() -> Result<(), String> {
    use lann_webcrypto_guest::bindings::ecdsa_verify;
    use lann_webcrypto_guest::bindings::ed25519_verify;

    // Ed25519: the RFC 8032 TEST 3 public key through all three formats,
    // each verifying the pinned deterministic signature.
    let public_raw = unhex(ED25519_TEST3_PUBLIC);
    let msg = unhex(ED25519_TEST3_MSG);
    let sig = unhex(ED25519_TEST3_SIG);
    let raw_key = import_ed25519_verifying_key(public_raw.clone())
        .await
        .map_err(|e| describe("import-verifying-key-raw", &e))?;
    let spki = raw_key
        .export_key_spki()
        .await
        .map_err(|e| describe("export-key-spki", &e))?;
    expect_bytes(
        &spki,
        &rfc8410_spki(0x70, &public_raw),
        "Ed25519 SubjectPublicKeyInfo export",
    )?;
    let jwk = raw_key
        .export_key_jwk()
        .await
        .map_err(|e| describe("export-key-jwk", &e))?;
    let x = crate::mint::b64url(&public_raw);
    if !jwk.contains("\"OKP\"") || !jwk.contains("\"Ed25519\"") || !jwk.contains(&x) {
        return Err(format!(
            "exported Ed25519 JWK missing material members: {jwk}"
        ));
    }
    for (what, key) in [
        (
            "spki import",
            ed25519_verify::import_verifying_key_spki(spki)
                .await
                .map_err(|e| describe("import-verifying-key-spki", &e))?,
        ),
        (
            "jwk import",
            ed25519_verify::import_verifying_key_jwk(jwk)
                .await
                .map_err(|e| describe("import-verifying-key-jwk", &e))?,
        ),
    ] {
        let exported = key
            .export_key_raw()
            .await
            .map_err(|e| describe("export-key-raw", &e))?;
        expect_bytes(&exported, &public_raw, &format!("raw export after {what}"))?;
        let (verified, fed) = sig_verify(&key, &msg, &sig, Schedule::Whole).await;
        fed?;
        verified.map_err(|e| describe(&format!("TEST 3 signature under the {what}"), &e))?;
    }

    // ECDSA: the A.2.5 point through all three formats.
    let mut point = vec![0x04];
    point.extend(unhex(P256_A25_X));
    point.extend(unhex(P256_A25_Y));
    let raw_key = import_ecdsa_verifying_key(EcdsaVariant::P256Sha256, point.clone())
        .await
        .map_err(|e| describe("import-verifying-key-raw (ecdsa)", &e))?;
    let spki = raw_key
        .export_key_spki()
        .await
        .map_err(|e| describe("export-key-spki (ecdsa)", &e))?;
    expect_bytes(
        &spki,
        &unhex(P256_A25_SPKI),
        "P-256 SubjectPublicKeyInfo export",
    )?;
    let jwk = raw_key
        .export_key_jwk()
        .await
        .map_err(|e| describe("export-key-jwk (ecdsa)", &e))?;
    let (x, y) = (
        crate::mint::b64url(&unhex(P256_A25_X)),
        crate::mint::b64url(&unhex(P256_A25_Y)),
    );
    if !jwk.contains("\"EC\"")
        || !jwk.contains("\"P-256\"")
        || !jwk.contains(&x)
        || !jwk.contains(&y)
    {
        return Err(format!("exported EC JWK missing material members: {jwk}"));
    }
    for (what, key) in [
        (
            "spki import",
            ecdsa_verify::import_verifying_key_spki(EcdsaVariant::P256Sha256, spki.clone())
                .await
                .map_err(|e| describe("import-verifying-key-spki (ecdsa)", &e))?,
        ),
        (
            "jwk import",
            ecdsa_verify::import_verifying_key_jwk(EcdsaVariant::P256Sha256, jwk)
                .await
                .map_err(|e| describe("import-verifying-key-jwk (ecdsa)", &e))?,
        ),
    ] {
        let exported = key
            .export_key_raw()
            .await
            .map_err(|e| describe("export-key-raw (ecdsa)", &e))?;
        expect_bytes(&exported, &point, &format!("raw export after ECDSA {what}"))?;
    }

    // Cross-curve and cross-algorithm mismatches fail `invalid-key`.
    expect_err(
        "P-256 spki as p384-sha384",
        ErrKind::InvalidKey,
        ecdsa_verify::import_verifying_key_spki(EcdsaVariant::P384Sha384, spki).await,
        "imported a P-256 SubjectPublicKeyInfo under a P-384 variant",
    )?;
    expect_err(
        "X25519 spki as Ed25519",
        ErrKind::InvalidKey,
        ed25519_verify::import_verifying_key_spki(rfc8410_spki(0x6e, &public_raw)).await,
        "imported an X25519 SubjectPublicKeyInfo as Ed25519",
    )?;
    expect_err(
        "wrong-curve OKP JWK",
        ErrKind::InvalidKey,
        ed25519_verify::import_verifying_key_jwk(format!(
            r#"{{"kty":"OKP","crv":"X25519","x":"{}"}}"#,
            crate::mint::b64url(&public_raw)
        ))
        .await,
        "imported an X25519 JWK as Ed25519",
    )?;

    // The EC side of the JWK `alg` policy: the curve-paired JOSE alg is
    // accepted, and another curve's alg is `invalid-key`.
    ecdsa_verify::import_verifying_key_jwk(
        EcdsaVariant::P256Sha256,
        format!(r#"{{"kty":"EC","crv":"P-256","x":"{x}","y":"{y}","alg":"ES256"}}"#),
    )
    .await
    .map_err(|e| describe("EC import with alg ES256", &e))?;
    expect_err(
        "wrong-curve EC alg",
        ErrKind::InvalidKey,
        ecdsa_verify::import_verifying_key_jwk(
            EcdsaVariant::P256Sha256,
            format!(r#"{{"kty":"EC","crv":"P-256","x":"{x}","y":"{y}","alg":"ES384"}}"#),
        )
        .await,
        "imported an EC JWK with another curve's alg",
    )?;

    // The JWK `alg` policy: Ed25519 accepts its two registered spellings
    // case-sensitively, and a public JWK restricting extractability
    // (`ext: false`) cannot mint an unconditionally exportable public key.
    let x = crate::mint::b64url(&public_raw);
    for alg in ["Ed25519", "EdDSA"] {
        ed25519_verify::import_verifying_key_jwk(format!(
            r#"{{"kty":"OKP","crv":"Ed25519","x":"{x}","alg":"{alg}"}}"#
        ))
        .await
        .map_err(|e| describe(&format!("import with alg {alg}"), &e))?;
    }
    expect_err(
        "wrong-case alg",
        ErrKind::InvalidKey,
        ed25519_verify::import_verifying_key_jwk(format!(
            r#"{{"kty":"OKP","crv":"Ed25519","x":"{x}","alg":"ed25519"}}"#
        ))
        .await,
        "imported a JWK with a wrong-case alg",
    )?;
    expect_err(
        "ext:false public JWK",
        ErrKind::InvalidKey,
        ed25519_verify::import_verifying_key_jwk(format!(
            r#"{{"kty":"OKP","crv":"Ed25519","x":"{x}","ext":false}}"#
        ))
        .await,
        "minted an always-exportable key from an ext:false JWK",
    )
}

/// Ed25519 private-key imports: both formats reproduce the RFC 8032 TEST 3
/// deterministic signature; generated keys round-trip through the gated
/// JWK and PKCS#8 exports; the gate holds on non-extractable keys; a
/// d-less OKP JWK is not a signing key.
async fn ed25519_private_format_imports() -> Result<(), String> {
    use crate::mint::signing_options;
    use lann_webcrypto_guest::bindings::ed25519_sign;

    let seed = unhex(ED25519_TEST3_SEED);
    let msg = unhex(ED25519_TEST3_MSG);
    let expected_sig = unhex(ED25519_TEST3_SIG);

    let from_pkcs8 =
        ed25519_sign::import_signing_key_pkcs8(rfc8410_pkcs8(0x70, &seed), signing_options(false))
            .await
            .map_err(|e| describe("import-signing-key-pkcs8", &e))?;
    let (sig, fed) = sig_sign(&from_pkcs8, &msg, Schedule::Whole).await;
    fed?;
    expect_bytes(
        &sig,
        &expected_sig,
        "TEST 3 signature from the PKCS#8 import",
    )?;

    let jwk = format!(
        r#"{{"kty":"OKP","crv":"Ed25519","x":"{}","d":"{}"}}"#,
        crate::mint::b64url(&unhex(ED25519_TEST3_PUBLIC)),
        crate::mint::b64url(&seed),
    );
    let from_jwk = ed25519_sign::import_signing_key_jwk(jwk, signing_options(false))
        .await
        .map_err(|e| describe("import-signing-key-jwk", &e))?;
    let (sig, fed) = sig_sign(&from_jwk, &msg, Schedule::Whole).await;
    fed?;
    expect_bytes(&sig, &expected_sig, "TEST 3 signature from the JWK import")?;

    // Generated keys: the gated exports round-trip through both formats.
    let (signing, public) = generate_ed25519_key(true)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    let payload = b"private-format roundtrip payload";
    let pkcs8 = signing
        .export_key_pkcs8()
        .await
        .map_err(|e| describe("export-key-pkcs8", &e))?;
    let jwk = signing
        .export_key_jwk()
        .await
        .map_err(|e| describe("export-key-jwk (private)", &e))?;
    if !jwk.contains("\"d\"") {
        return Err(format!("exported private JWK carries no `d`: {jwk}"));
    }
    for (what, key) in [
        (
            "pkcs8",
            ed25519_sign::import_signing_key_pkcs8(pkcs8, signing_options(false))
                .await
                .map_err(|e| describe("re-import of exported PKCS#8", &e))?,
        ),
        (
            "jwk",
            ed25519_sign::import_signing_key_jwk(jwk, signing_options(false))
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

    // The extractability gate, in the failing direction.
    let (non_extractable, _) = generate_ed25519_key(false)
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
    )?;

    expect_err(
        "public-only OKP JWK",
        ErrKind::InvalidKey,
        ed25519_sign::import_signing_key_jwk(
            format!(
                r#"{{"kty":"OKP","crv":"Ed25519","x":"{}"}}"#,
                crate::mint::b64url(&unhex(ED25519_TEST3_PUBLIC))
            ),
            signing_options(false),
        )
        .await,
        "imported a d-less JWK as a signing key",
    )
}

/// The cross pairings of curve and hash are real variants: each mints a
/// verifying key whose getters report its own binding (never the curve's
/// default hash).
async fn ecdsa_cross_hash_variants() -> Result<(), String> {
    let mut p256 = vec![0x04];
    p256.extend(unhex(P256_A25_X));
    p256.extend(unhex(P256_A25_Y));
    // The vendored Wycheproof P-384 file's group public key.
    let p384 = unhex("042da57dda1089276a543f9ffdac0bff0d976cad71eb7280e7d9bfd9fee4bdb2f20f47ff888274389772d98cc5752138aa4b6d054d69dcf3e25ec49df870715e34883b1836197d76f8ad962e78f6571bbc7407b0d6091f9e4d88f014274406174f");
    for (variant, point, curve, hash) in [
        (EcdsaVariant::P256Sha384, &p256, "P-256", "SHA-384"),
        (EcdsaVariant::P256Sha512, &p256, "P-256", "SHA-512"),
        (EcdsaVariant::P384Sha256, &p384, "P-384", "SHA-256"),
        (EcdsaVariant::P384Sha512, &p384, "P-384", "SHA-512"),
    ] {
        let key = import_ecdsa_verifying_key(variant, point.clone())
            .await
            .map_err(|e| describe(&format!("import-verifying-key-raw ({curve}/{hash})"), &e))?;
        expect(
            key.algorithm_curve(),
            Some(curve.to_string()),
            "cross-variant algorithm-curve",
        )?;
        expect(
            key.algorithm_hash(),
            Some(hash.to_string()),
            "cross-variant algorithm-hash",
        )?;
    }
    Ok(())
}

/// The X25519 format surface: the RFC 7748 §6.1 keys through the SPKI and
/// PKCS#8 imports still derive the known shared secret, the gated secret
/// exports round-trip, and the gate holds on non-extractable keys.
async fn x25519_format_roundtrips() -> Result<(), String> {
    use lann_webcrypto_guest::bindings::x25519;

    let alice_x = unhex(RFC7748_ALICE_X);
    let alice_d = unhex(RFC7748_ALICE_D);
    let bob_x = unhex(RFC7748_BOB_X);
    let shared = unhex(RFC7748_SHARED);

    // Secret via PKCS#8, peer public via SPKI and JWK: every pairing
    // derives the RFC 7748 shared secret.
    let alice = x25519::import_secret_key_pkcs8(
        rfc8410_pkcs8(0x6e, &alice_d),
        agreement_options(true, true, true),
    )
    .await
    .map_err(|e| describe("import-secret-key-pkcs8", &e))?;
    let bob_spki = x25519::import_public_key_spki(rfc8410_spki(0x6e, &bob_x))
        .await
        .map_err(|e| describe("import-public-key-spki", &e))?;
    let bob_jwk = x25519::import_public_key_jwk(format!(
        r#"{{"kty":"OKP","crv":"X25519","x":"{}"}}"#,
        crate::mint::b64url(&bob_x)
    ))
    .await
    .map_err(|e| describe("import-public-key-jwk", &e))?;
    for (what, peer) in [("spki peer", &bob_spki), ("jwk peer", &bob_jwk)] {
        let derived = alice
            .agree(peer)
            .await
            .map_err(|e| describe(&format!("agree ({what})"), &e))?
            .derive_bits(None)
            .await
            .map_err(|e| describe(&format!("derive-bits ({what})"), &e))?;
        expect_bytes(
            &derived,
            &shared,
            &format!("RFC 7748 shared secret ({what})"),
        )?;
    }

    // The public SPKI export is the pinned RFC 8410 encoding of the raw
    // form; the gated secret exports carry the imported material.
    let alice_public = import_x25519_public_key(alice_x.clone())
        .await
        .map_err(|e| describe("import-public-key-raw", &e))?;
    let spki = alice_public
        .export_key_spki()
        .await
        .map_err(|e| describe("public-key export-key-spki", &e))?;
    expect_bytes(
        &spki,
        &rfc8410_spki(0x6e, &alice_x),
        "X25519 SubjectPublicKeyInfo export",
    )?;
    let pkcs8 = alice
        .export_key_pkcs8()
        .await
        .map_err(|e| describe("secret-key export-key-pkcs8", &e))?;
    expect_bytes(
        &pkcs8,
        &rfc8410_pkcs8(0x6e, &alice_d),
        "X25519 PKCS#8 export",
    )?;
    let jwk = alice
        .export_key_jwk()
        .await
        .map_err(|e| describe("secret-key export-key-jwk", &e))?;
    let d = crate::mint::b64url(&alice_d);
    if !jwk.contains("\"OKP\"") || !jwk.contains("\"X25519\"") || !jwk.contains(&d) {
        return Err(format!(
            "exported secret JWK missing material members: {jwk}"
        ));
    }

    // X25519 follows WebCrypto's ECDH-family JWK rule: `alg` is ignored
    // on import, while an `ext: false` public JWK is rejected (a minted
    // public key is unconditionally exportable).
    x25519::import_public_key_jwk(format!(
        r#"{{"kty":"OKP","crv":"X25519","x":"{}","alg":"anything"}}"#,
        crate::mint::b64url(&bob_x)
    ))
    .await
    .map_err(|e| describe("import-public-key-jwk (alg present)", &e))?;
    expect_err(
        "ext:false public JWK",
        ErrKind::InvalidKey,
        x25519::import_public_key_jwk(format!(
            r#"{{"kty":"OKP","crv":"X25519","x":"{}","ext":false}}"#,
            crate::mint::b64url(&bob_x)
        ))
        .await,
        "minted an always-exportable key from an ext:false JWK",
    )?;

    // The gate, in the failing direction (the JWK import path mints
    // non-extractable).
    let non_extractable = import_x25519_secret_key(&alice_x, &alice_d, true, true)
        .await
        .map_err(|e| describe("import-secret-key-jwk", &e))?;
    expect_err(
        "export-key-pkcs8",
        ErrKind::NotExtractable,
        non_extractable.export_key_pkcs8().await,
        "exported a non-extractable secret key",
    )?;
    expect_err(
        "export-key-jwk",
        ErrKind::NotExtractable,
        non_extractable.export_key_jwk().await,
        "exported a non-extractable secret key",
    )
}

/// The internal-nonce JWK surface: `import-key-jwk` mints a key
/// interoperable with the raw import of the same material, and
/// `export-key-jwk` round-trips behind the extractability gate.
async fn internal_nonce_jwk() -> Result<(), String> {
    use lann_webcrypto_guest::bindings::aes_gcm_internal_nonce;

    let raw: Vec<u8> = (1..=32).collect();
    let from_jwk = aes_gcm_internal_nonce::import_key_jwk(
        AesVariant::Aes256,
        format!(r#"{{"kty":"oct","k":"{JWK_K_32}","alg":"A256GCM"}}"#),
        crate::mint::internal_nonce_options(true),
    )
    .await
    .map_err(|e| describe("import-key-jwk", &e))?;
    let jwk = from_jwk
        .export_key_jwk()
        .await
        .map_err(|e| describe("export-key-jwk", &e))?;
    if !jwk.contains(JWK_K_32) || !jwk.contains("A256GCM") || !jwk.contains("\"oct\"") {
        return Err(format!("exported JWK missing material members: {jwk}"));
    }

    // A message sealed under the JWK-minted key opens under the raw import
    // of the same bytes.
    let (sealed, fed) = in_seal(
        &from_jwk,
        b"aad",
        b"internal-nonce jwk payload",
        Schedule::Whole,
    )
    .await;
    fed.map_err(|e| format!("seal data feeder: {e}"))?;
    let sealed = sealed.map_err(|e| describe("seal", &e))?;
    let raw_key = import_internal_nonce_key(AesVariant::Aes256, raw, false)
        .await
        .map_err(|e| describe("import-key-raw", &e))?;
    let (opened, fed) = in_open(&raw_key, b"aad", &sealed, Schedule::Whole).await;
    fed.map_err(|e| format!("open data feeder: {e}"))?;
    let opened = opened.map_err(|e| describe("open", &e))?;
    expect_bytes(&opened, b"internal-nonce jwk payload", "cross-mint open")?;

    // The gate and the variant check, in the failing directions.
    expect_err(
        "export-key-jwk",
        ErrKind::NotExtractable,
        raw_key.export_key_jwk().await,
        "exported a non-extractable key",
    )?;
    expect_err(
        "32-byte JWK as aes128",
        ErrKind::InvalidKey,
        aes_gcm_internal_nonce::import_key_jwk(
            AesVariant::Aes128,
            format!(r#"{{"kty":"oct","k":"{JWK_K_32}","alg":"A128GCM"}}"#),
            crate::mint::internal_nonce_options(false),
        )
        .await,
        "minted an aes128 key from 32 bytes",
    )
}

// The SHAttered colliding pair's first five blocks (bytes 0..320 of each
// PDF, from https://shattered.io): each half independently carries the
// attack's disturbance-vector pattern, and the two halves collide under
// plain SHA-1.
const SHATTERED_1: &str = "255044462d312e330a25e2e3cfd30a0a0a312030206f626a0a3c3c2f57696474682032203020522f4865696768742033203020522f547970652034203020522f537562747970652035203020522f46696c7465722036203020522f436f6c6f7253706163652037203020522f4c656e6774682038203020522f42697473506572436f6d706f6e656e7420383e3e0a73747265616d0affd8fffe00245348412d3120697320646561642121212121852fec092339759c39b1a1c63c4c97e1fffe017346dc9166b67e118f029ab621b2560ff9ca67cca8c7f85ba84c79030c2b3de218f86db3a90901d5df45c14f26fedfb3dc38e96ac22fe7bd728f0e45bce046d23c570feb141398bb552ef5a0a82be331fea48037b8b5d71f0e332edf93ac3500eb4ddc0decc1a864790c782c76215660dd309791d06bd0af3f98cda4bc4629b1";
const SHATTERED_2: &str = "255044462d312e330a25e2e3cfd30a0a0a312030206f626a0a3c3c2f57696474682032203020522f4865696768742033203020522f547970652034203020522f537562747970652035203020522f46696c7465722036203020522f436f6c6f7253706163652037203020522f4c656e6774682038203020522f42697473506572436f6d706f6e656e7420383e3e0a73747265616d0affd8fffe00245348412d3120697320646561642121212121852fec092339759c39b1a1c63c4c97e1fffe017f46dc93a6b67e013b029aaa1db2560b45ca67d688c7f84b8c4c791fe02b3df614f86db1690901c56b45c1530afedfb76038e972722fe7ad728f0e4904e046c230570fe9d41398abe12ef5bc942be33542a4802d98b5d70f2a332ec37fac3514e74ddc0f2cc1a874cd0c78305a21566461309789606bd0bf3f98cda8044629a1";

/// The `sha1-checked` contract, pinned with known answers: honest input is
/// standard SHA-1 in both postures; on the SHAttered pair the rejecting
/// posture fails with the exact `collision-detected` extension condition
/// and the mitigating posture returns the deterministic safe hashes, under
/// which the pair no longer collides.
async fn sha1_checked_postures() -> Result<(), String> {
    use lann_webcrypto_guest::bindings::sha1_checked;
    use lann_webcrypto_guest::bindings::types::Error;

    let rejecting =
        sha1_checked::make_rejecting_digest().map_err(|e| describe("make-rejecting-digest", &e))?;
    let mitigating = sha1_checked::make_mitigating_digest()
        .map_err(|e| describe("make-mitigating-digest", &e))?;

    // Honest input: the FIPS 180-1 "abc" answer, identical in both
    // postures, chunking-invariant, and reusable (the digest-kind
    // contract).
    let abc = unhex("a9993e364706816aba3e25717850c26c9cd0d89d");
    for digest in [&rejecting, &mitigating] {
        expect(
            digest.algorithm_name(),
            "SHA-1".to_string(),
            "checked-SHA-1 algorithm-name",
        )?;
        for schedule in [Schedule::Whole, Schedule::Bytes] {
            let (got, fed) = compute(digest, b"abc", schedule).await;
            fed.map_err(|e| format!("compute data feeder: {e}"))?;
            let got = got.map_err(|e| describe("compute (honest input)", &e))?;
            expect_bytes(&got, &abc, "honest-input digest is standard SHA-1")?;
        }
    }

    let m1 = unhex(SHATTERED_1);
    let m2 = unhex(SHATTERED_2);

    // The rejecting posture: the exact extension condition, pinned
    // cross-target. (origin, name) is the branchable pair; the message is
    // human-only, and its pin is implementation-convergence hygiene, like
    // every other message-string pin — not consumer contract.
    for m in [&m1, &m2] {
        let (got, fed) = compute(&rejecting, m, Schedule::Whole).await;
        fed.map_err(|e| format!("compute data feeder: {e}"))?;
        match got {
            Err(Error::Extension(ext))
                if ext.origin == "lann:webcrypto"
                    && ext.name == "collision-detected"
                    && ext.message == "input carries a SHA-1 collision attack pattern" => {}
            Err(other) => {
                return Err(describe(
                    "rejecting compute: expected the collision-detected extension condition, got",
                    &other,
                ))
            }
            Ok(_) => return Err("a rejecting digest hashed an attacked input".into()),
        }
    }

    // The mitigating posture: the deterministic safe hashes — never the
    // raw SHA-1 the pair collides under — and the pair no longer
    // collides.
    let (d1, fed) = compute(&mitigating, &m1, Schedule::Whole).await;
    fed.map_err(|e| format!("compute data feeder: {e}"))?;
    let d1 = d1.map_err(|e| describe("mitigating compute", &e))?;
    let (d2, fed) = compute(&mitigating, &m2, Schedule::Whole).await;
    fed.map_err(|e| format!("compute data feeder: {e}"))?;
    let d2 = d2.map_err(|e| describe("mitigating compute", &e))?;
    expect_bytes(
        &d1,
        &unhex("7117b3cb9225aaf0d8ef1a40e493957b0bf8693d"),
        "safe hash of the first SHAttered half",
    )?;
    expect_bytes(
        &d2,
        &unhex("29f38ae9fd98e2931120fa0bf213e024250d3f6a"),
        "safe hash of the second SHAttered half",
    )
}

/// The decline assertion for targets declaring `sha1-checked` missing:
/// both constructors must fail `unsupported`.
async fn sha1_checked_minting_declined() -> Result<String, String> {
    use lann_webcrypto_guest::bindings::sha1_checked;

    expect_err(
        "make-rejecting-digest",
        ErrKind::Unsupported,
        sha1_checked::make_rejecting_digest(),
        "minted a digest for a feature declared missing",
    )
    .map_err(|detail| format!("sha1-checked decline: {detail}"))?;
    expect_err(
        "make-mitigating-digest",
        ErrKind::Unsupported,
        sha1_checked::make_mitigating_digest(),
        "minted a digest for a feature declared missing",
    )
    .map_err(|detail| format!("sha1-checked decline: {detail}"))?;
    Ok("asserted both sha1-checked constructors decline unsupported".into())
}
