//! Hand-written API-contract probes: the parts of the `polymorph:webcrypto`
//! contract neither the Wycheproof vectors nor the per-kind [`contract`]
//! batteries express — error variants for misuse, the seal/open
//! stream-closure rule, parameter-space contracts, chaining semantics,
//! nonce budgets, and the feature-decline assertions.
//!
//! [`contract`]: crate::contract

use crate::mint::{
    agreement_options, cipher_options, derive_options, ecdh_secret_jwk, generate_ecdh_key,
    generate_ed25519_key, generate_hmac_key, generate_key, generate_kw_key, generate_x25519_key,
    import_aes_key_jwk, import_cbc_key, import_ctr_key, import_ecdh_public_key_raw,
    import_ecdh_secret_key, import_hmac_key, import_hmac_key_jwk, import_hmac_sha1_key, import_ikm,
    import_key_raw, import_kw_key, import_password, import_x25519_public_key,
    import_x25519_secret_key, kw_options, mac_options, signing_options, x25519_secret_jwk,
    ECDH_P256_D, ECDH_P256_PEER, ECDH_P256_SHARED, ECDH_P256_X, ECDH_P256_Y, RFC7748_ALICE_D,
    RFC7748_ALICE_X, RFC7748_BOB_D, RFC7748_BOB_X, RFC7748_SHARED,
};
use conformance_harness::stream::{
    ci_decrypt_ok, ci_decrypt_op, ci_encrypt, ci_encrypt_ok, ci_encrypt_op, compute, compute_ok,
    compute_op, feed, open, open_ok, open_op, seal, seal_ok, seal_op, sig_sign_ok, sig_verify_ok,
    sig_verify_op, sign, sign_ok, verify_ok, verify_op, Schedule,
};
use conformance_harness::{
    b64url, describe, expect, expect_bytes, expect_err, probes, unhex, ErrKind,
    FEATURE_SHA1_CHECKED, P256_A25_X, P256_A25_Y,
};
use polymorph_webcrypto_guest::bindings::aes_gcm::AesVariant;
use polymorph_webcrypto_guest::bindings::ecdsa_verify::{
    import_verifying_key_raw as import_ecdsa_verifying_key, EcdsaVariant,
};
use polymorph_webcrypto_guest::bindings::ed25519_verify::import_verifying_key_raw as import_ed25519_verifying_key;
use polymorph_webcrypto_guest::bindings::sha2::{make_digest, Sha2Variant};
use polymorph_webcrypto_guest::bindings::types::Error;

/// The features a bare tag in the `probes!` table stands for. Which
/// features exist is this suite's business, not the harness's.
macro_rules! feature_tags {
    () => {
        &[]
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
    seal_input_ends_on_invalid_nonce,
    open_input_ends_on_invalid_nonce,
    sealed_length,
    mac_verify_rejects_truncated,
    sign_prefix_drop,
    digest_reuse,
    ed25519_sign_roundtrip,
    sig_key_metadata,
    sig_import_invalid,
    verifying_key_export_roundtrip,
    open_short_input,
    stream_empty_writes,
    large_stream,
    hmac_generate_length,
    gcm_full_parameters,
    gcm_nonce_window,
    jwk_rejections,
    jwk_semantics,
    aead_wrap_grants,
    aead_wrap_operations,
    wrap_input_gates,
    kw_key_contract,
    kw_jwk_padding,
    cipher_wrap_uniform_failure,
    unwrap_jwk_usage_members,
    kdf_secret_unwrap,
    signing_key_unwrap,
    agreement_key_unwrap,
    cipher_key_unwrap,
    signing_usage_policy,
    hkdf_derive_key_equivalence,
    hkdf_params_and_chaining,
    pbkdf2_contract,
    x25519_key_contract,
    x25519_agree_contract,
    x25519_chaining,
    ecdh_key_contract,
    ecdh_agree_contract,
    ecdh_chaining,
    sig_public_format_imports,
    ed25519_private_format_imports,
    ecdsa_cross_hash_variants,
    rsa_key_contract,
    rsa_admission_contract,
    rsa_pss_salt_binding,
    x25519_format_roundtrips,
    ecdh_format_roundtrips,
    sha1_checked_postures(sha1_checked),
    ctr_known_answers,
    cipher_params_contract,
    cbc_uniform_failure,
    cipher_derive_key,
    sha1_derive_surface,
}

/// Run the probe case whose `features` a target declares missing: assert
/// the correct decline. This is the two-way guarantee behind the plain
/// `skipped` the vector cases report: a target cannot silently serve a
/// feature it declares missing.
pub async fn run_declined(features: &[&str]) -> Result<String, String> {
    if features == [FEATURE_SHA1_CHECKED] {
        sha1_checked_minting_declined().await
    } else {
        Err("probe has no decline assertion for its features".into())
    }
}

/// Generate an AES-256 key, rendering a WIT error as a probe failure.
async fn generate_key_256(
    extractable: bool,
) -> Result<polymorph_webcrypto_guest::bindings::aead::AeadKey, String> {
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
        let tag = sign_ok(&key, DATA, Schedule::Whole).await?;
        expect_bytes(&tag, &want, &format!("HMAC-{hash} known-answer tag"))?;
        verify_ok(
            &key,
            DATA,
            &tag,
            Schedule::Whole,
            "known-answer tag did not verify",
        )
        .await?;
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

/// `seal` with a bad nonce fails `invalid-nonce`, and the concurrent
/// feeder settles: the closure rule lets the implementation drain in full
/// (the feeder completes) or drop the reader early on the error (the
/// feeder reports leftover) — either way the call must not leave the
/// feeder wedged, which reaching the assertions at all demonstrates.
async fn seal_input_ends_on_invalid_nonce() -> Result<(), String> {
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
    // Either feed outcome conforms on an error result; only the verdict
    // is contract.
    drop(fed);
    expect_err(
        "seal",
        ErrKind::InvalidNonce,
        sealed,
        "empty nonce accepted",
    )
}

/// `open` with a bad nonce fails `invalid-nonce`, and the concurrent
/// feeder settles; see `seal_input_ends_on_invalid_nonce`.
async fn open_input_ends_on_invalid_nonce() -> Result<(), String> {
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
    // Either feed outcome conforms on an error result; only the verdict
    // is contract.
    drop(fed);
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

    let tag = sign_ok(&key, payload, Schedule::Whole).await?;
    expect(tag.len(), 32, "tag length")?;

    let verified = verify_op(&key, payload, &tag[..31], Schedule::Whole).await?;
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
    let (tx, rx) = polymorph_webcrypto_guest::wit_stream::new();
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

/// A generated Ed25519 key signs, the public half returned with it
/// verifies, a corrupted signature fails `authentication-failed`, and a
/// *different* key's public half rejects the signature (keys are not
/// interchangeable).
async fn ed25519_sign_roundtrip() -> Result<(), String> {
    let (key, public) = generate_ed25519_key(false)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    let payload = b"conformance signature payload";
    let sig = sig_sign_ok(&key, payload, Schedule::Whole).await?;
    expect(sig.len(), 64, "Ed25519 signature length")?;

    sig_verify_ok(
        &public,
        payload,
        &sig,
        Schedule::Whole,
        "round-trip signature did not verify",
    )
    .await?;

    let mut corrupted = sig.clone();
    corrupted[0] ^= 0x01;
    let verified = sig_verify_op(&public, payload, &corrupted, Schedule::Whole).await?;
    expect_err(
        "verify",
        ErrKind::AuthenticationFailed,
        verified,
        "corrupted signature verified",
    )?;

    let (_other, other_public) = generate_ed25519_key(false)
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
    let sig = sig_sign_ok(&signing, payload, Schedule::Whole).await?;

    let exported = public
        .export_key_raw()
        .await
        .map_err(|e| describe("export-key-raw (public)", &e))?;
    expect(exported.len(), 32, "exported Ed25519 public key length")?;
    let reimported = import_ed25519_verifying_key(exported)
        .await
        .map_err(|e| describe("re-import of exported public key", &e))?;
    sig_verify_ok(
        &reimported,
        payload,
        &sig,
        Schedule::Whole,
        "re-imported key did not verify",
    )
    .await?;

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

/// Caller-nonce `open` of inputs shorter than the tag fails
/// `authentication-failed`.
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
/// and the AEAD discipline must round-trip.
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
    let (tx, rx) = polymorph_webcrypto_guest::wit_stream::new();
    let (chunked, fed) = futures::join!(key.sign(rx), feed(tx, boundary_chunks(&payload)));
    fed?;
    let chunked = chunked.map_err(|e| describe("sign over boundary chunks", &e))?;
    let (tx, rx) = polymorph_webcrypto_guest::wit_stream::new();
    let (whole, fed) = futures::join!(key.sign(rx), feed(tx, vec![payload.clone()]));
    fed?;
    let whole = whole.map_err(|e| describe("sign over one whole write", &e))?;
    expect_bytes(&chunked, &whole, "tag over boundary chunks vs one write")?;

    let key = generate_key_256(false).await?;
    let nonce = [5u8; 12];
    let (tx, rx) = polymorph_webcrypto_guest::wit_stream::new();
    let (sealed, fed) = futures::join!(
        key.seal(nonce.to_vec(), b"large aad".to_vec(), None, rx),
        feed(tx, boundary_chunks(&payload))
    );
    fed?;
    let sealed = sealed.map_err(|e| describe("seal", &e))?.collect().await;
    expect(sealed.len(), LEN + 16, "sealed length")?;
    let (tx, rx) = polymorph_webcrypto_guest::wit_stream::new();
    let (opened, fed) = futures::join!(
        key.open(nonce.to_vec(), b"large aad".to_vec(), None, rx),
        feed(tx, boundary_chunks(&sealed))
    );
    fed?;
    let opened = opened.map_err(|e| describe("open", &e))?.collect().await;
    expect_bytes(&opened, &payload, "round-tripped plaintext")
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
    let (tx, rx) = polymorph_webcrypto_guest::wit_stream::new();
    let (tag, fed) = futures::join!(key.sign(rx), feed(tx, chunks));
    fed?;
    let tag = tag.map_err(|e| describe("sign with interleaved empty writes", &e))?;
    expect_bytes(&tag, &expected, "tag over a stream with empty writes")?;

    // A stream of nothing but empty writes is an empty input, not a stall.
    let (tx, rx) = polymorph_webcrypto_guest::wit_stream::new();
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
    let (tx, rx) = polymorph_webcrypto_guest::wit_stream::new();
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
/// declined `unsupported`, and the empty nonce fails `invalid-nonce`.
async fn gcm_full_parameters() -> Result<(), String> {
    let key = generate_key_256(false).await?;
    let msg = b"gcm-full-parameters";

    let sealed = seal_ok(
        &key,
        &[7u8; 16],
        b"aad",
        None,
        msg,
        Schedule::Straddle,
        "seal (16-byte nonce)",
    )
    .await?;
    let opened = open_ok(
        &key,
        &[7u8; 16],
        b"aad",
        None,
        &sealed,
        Schedule::Whole,
        "open (16-byte nonce)",
    )
    .await?;
    expect_bytes(&opened, msg, "opened bytes (16-byte nonce)")?;

    let short = seal_ok(
        &key,
        &[9u8; 12],
        b"aad",
        Some(4),
        msg,
        Schedule::Whole,
        "seal (4-byte tag)",
    )
    .await?;
    expect(short.len(), msg.len() + 4, "sealed length (4-byte tag)")?;
    let opened = open_ok(
        &key,
        &[9u8; 12],
        b"aad",
        Some(4),
        &short,
        Schedule::Whole,
        "open (4-byte tag)",
    )
    .await?;
    expect_bytes(&opened, msg, "opened bytes (4-byte tag)")?;
    let opened = open_op(&key, &[9u8; 12], b"aad", None, &short, Schedule::Whole).await?;
    expect_err(
        "open of a 4-byte-tag message at the default size",
        ErrKind::AuthenticationFailed,
        opened,
        "verified with the wrong declared tag size",
    )?;

    let sealed = seal_op(&key, &[9u8; 12], b"", Some(5), msg, Schedule::Whole).await?;
    expect_err(
        "seal with a 5-byte tag size",
        ErrKind::Unsupported,
        sealed,
        "sealed with a tag size outside the GCM set",
    )?;

    Ok(())
}

/// The AES-GCM nonce window is 12–128 bytes inclusive on every
/// implementation: both edges round-trip (128 bytes exercises the `J0`
/// derivation), and one byte outside either edge fails `invalid-nonce` on
/// seal and open alike.
async fn gcm_nonce_window() -> Result<(), String> {
    let key = generate_key_256(false).await?;
    let msg = b"gcm-nonce-window";
    for len in [12usize, 128] {
        let iv = vec![0x11u8; len];
        let sealed = seal_ok(
            &key,
            &iv,
            b"aad",
            None,
            msg,
            Schedule::Whole,
            &format!("seal ({len}-byte nonce)"),
        )
        .await?;
        let opened = open_ok(
            &key,
            &iv,
            b"aad",
            None,
            &sealed,
            Schedule::Whole,
            &format!("open ({len}-byte nonce)"),
        )
        .await?;
        expect_bytes(&opened, msg, "opened bytes")?;
    }
    for len in [11usize, 129] {
        let iv = vec![0x11u8; len];
        let sealed = seal_op(&key, &iv, b"", None, msg, Schedule::Whole).await?;
        expect_err(
            &format!("seal ({len}-byte nonce)"),
            ErrKind::InvalidNonce,
            sealed,
            "served a nonce outside the 12–128-byte window",
        )?;
        let opened = open_op(&key, &iv, b"", None, &[0u8; 32], Schedule::Whole).await?;
        expect_err(
            &format!("open ({len}-byte nonce)"),
            ErrKind::InvalidNonce,
            opened,
            "served a nonce outside the 12–128-byte window",
        )?;
    }
    Ok(())
}

/// The WPT symmetric fixtures' key bytes (1..=32), as the JWK `k` those
/// fixtures encode.
const JWK_K_32: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA";

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
    let tag = sign_ok(&key, b"jwk-semantics", Schedule::Whole).await?;
    if tag.len() != 32 {
        return Err(format!("tag length {} from JWK-imported key", tag.len()));
    }
    Ok(())
}

/// The wrap grants on `aead-key`: each mints a key on its own, reports
/// through its getter in both directions, and permits neither seal nor
/// open (the operations themselves are `aead_wrap_operations`'s subject). (The seal/open
/// grants' enforcement and getters are the contract battery's `usage`
/// area, per family.)
async fn aead_wrap_grants() -> Result<(), String> {
    use polymorph_webcrypto_guest::bindings::aead::AeadKeyOptions;
    use polymorph_webcrypto_guest::bindings::aes_gcm;

    let options = AeadKeyOptions::new();
    options.can_wrap(true);
    let wrap_only = aes_gcm::import_key_raw(AesVariant::Aes256, vec![0x5au8; 32], options)
        .await
        .map_err(|e| describe("wrap-only import-key-raw", &e))?;
    expect(wrap_only.can_wrap(), true, "wrap-only key can-wrap")?;
    expect(wrap_only.can_unwrap(), false, "wrap-only key can-unwrap")?;
    expect(wrap_only.can_seal(), false, "wrap-only key can-seal")?;
    let refused = seal_op(
        &wrap_only,
        &[3u8; 12],
        b"",
        None,
        b"usage-policy plaintext",
        Schedule::Whole,
    )
    .await?;
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

/// Usage policy on `signing-key`: `sign` is the sole usage, so an
/// untouched options resource cannot generate, and a granted key reports
/// the grant through `can-sign`.
async fn signing_usage_policy() -> Result<(), String> {
    use polymorph_webcrypto_guest::bindings::ed25519_sign;
    use polymorph_webcrypto_guest::bindings::signature::SigningKeyOptions;

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
    use polymorph_webcrypto_guest::bindings::aead::AeadKeyOptions;
    use polymorph_webcrypto_guest::bindings::aes_gcm;
    use polymorph_webcrypto_guest::bindings::hkdf_sha2;
    use polymorph_webcrypto_guest::bindings::hmac_sha2;
    use polymorph_webcrypto_guest::bindings::mac::MacKeyOptions;

    let ikm = import_ikm(b"equivalence input keying material".to_vec(), true, true)
        .await
        .map_err(|e| describe("import-ikm", &e))?;
    let input = hkdf_sha2::prepare(
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

/// The HKDF contract the battery's grant matrix does not carry: empty IKM
/// mints and derives (RFC 5869 admits it and the platform serves it — see
/// `wit/README.md`, "Empty KDF secrets are accepted"), `prepare` declines
/// unserved variants, the parameter errors land on their documented
/// cases, and KDF-from-KDF chaining fails as the platform's
/// `deriveKey(… → "HKDF")` does.
async fn hkdf_params_and_chaining() -> Result<(), String> {
    use polymorph_webcrypto_guest::bindings::hkdf_sha2;

    let empty = import_ikm(Vec::new(), true, true)
        .await
        .map_err(|e| describe("empty import-ikm", &e))?;
    let empty_input = hkdf_sha2::prepare(Sha2Variant::Sha256, &empty, b"salt".to_vec(), Vec::new())
        .await
        .map_err(|e| describe("prepare (empty ikm)", &e))?;
    empty_input
        .derive_bits(Some(128))
        .await
        .map_err(|e| describe("derive-bits (empty ikm)", &e))?;

    let ikm = import_ikm(vec![2; 32], true, true)
        .await
        .map_err(|e| describe("import-ikm", &e))?;
    expect_err(
        "prepare on a truncated variant",
        ErrKind::Unsupported,
        hkdf_sha2::prepare(Sha2Variant::Sha224, &ikm, Vec::new(), Vec::new()).await,
        "prepared over an unserved variant",
    )?;
    let input = hkdf_sha2::prepare(Sha2Variant::Sha256, &ikm, Vec::new(), Vec::new())
        .await
        .map_err(|e| describe("prepare", &e))?;
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

    expect_err(
        "KDF-from-KDF chaining",
        ErrKind::Other,
        hkdf_sha2::prepare_from(Sha2Variant::Sha256, &input, Vec::new(), Vec::new()).await,
        "chained from an input with no natural output length",
    )
}

/// The PBKDF2 contract the vectors and the battery cannot express: an
/// empty password is accepted (the documented asymmetry with `import-ikm`
/// — the platform and the upstream vectors treat it as valid), a zero
/// iteration count fails at `prepare` with the platform's error, the
/// §14.3.7 equivalence holds for a PBKDF2 input, and chaining from a
/// PBKDF2 input fails exactly as from an HKDF one — there is deliberately
/// no `pbkdf2-sha2.prepare-from` at all, and `hkdf-sha2.prepare-from` refuses KDF
/// upstreams of either flavor.
async fn pbkdf2_contract() -> Result<(), String> {
    use polymorph_webcrypto_guest::bindings::aead::AeadKeyOptions;
    use polymorph_webcrypto_guest::bindings::aes_gcm;
    use polymorph_webcrypto_guest::bindings::hkdf_sha2;
    use polymorph_webcrypto_guest::bindings::pbkdf2_sha2;

    // RFC 7914 §11 known answer (c = 1), through the full WIT surface.
    let password = import_password(b"passwd".to_vec(), true, true)
        .await
        .map_err(|e| describe("import-password", &e))?;
    let input = pbkdf2_sha2::prepare(Sha2Variant::Sha256, &password, b"salt".to_vec(), 1)
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

    // Chaining from a PBKDF2 input refuses like any KDF's.
    expect_err(
        "chaining from a PBKDF2 input",
        ErrKind::Other,
        hkdf_sha2::prepare_from(Sha2Variant::Sha256, &input, Vec::new(), Vec::new()).await,
        "chained from a KDF input",
    )?;

    expect_err(
        "zero iteration count",
        ErrKind::Other,
        pbkdf2_sha2::prepare(Sha2Variant::Sha256, &password, b"salt".to_vec(), 0).await,
        "prepared with zero iterations",
    )?;
    expect_err(
        "prepare on a truncated variant",
        ErrKind::Unsupported,
        pbkdf2_sha2::prepare(Sha2Variant::Sha512224, &password, b"salt".to_vec(), 1).await,
        "prepared over an unserved variant",
    )?;

    // Empty passwords mint and derive, like empty IKM.
    let empty = import_password(Vec::new(), true, true)
        .await
        .map_err(|e| describe("empty import-password", &e))?;
    let input = pbkdf2_sha2::prepare(Sha2Variant::Sha256, &empty, vec![1, 2, 3, 4], 2)
        .await
        .map_err(|e| describe("prepare (empty password)", &e))?;
    input
        .derive_bits(Some(128))
        .await
        .map_err(|e| describe("derive-bits (empty password)", &e))?;
    Ok(())
}

/// The X25519 key surface: metadata getters in both grant directions,
/// generated-key freshness, public-key export round trips, the OKP JWK
/// import contract's rejections, extractability recording, and the
/// zero-grant mint refusals.
async fn x25519_key_contract() -> Result<(), String> {
    use polymorph_webcrypto_guest::bindings::x25519;

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
    let x = b64url(&raw);
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
                b64url(&alice_x)
            ),
            agreement_options(true, true, false),
        )
        .await,
        "imported a d-less JWK as a secret key",
    )?;

    // The zero-usage mint check on the generation path (the import path's
    // is the derive battery's `x25519/contract/grants` case).
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

/// The chaining property no KDF source has: `hkdf-sha2.prepare-from`
/// chains from an agreement — the spec's own X25519 → HKDF → AES-GCM
/// example, checked against HKDF over the same shared secret imported as
/// IKM — and chaining is gated by the `derive-key` grant, refusing
/// `not-permitted` from a key-less input.
async fn x25519_chaining() -> Result<(), String> {
    use polymorph_webcrypto_guest::bindings::hkdf_sha2;

    let shared = unhex(RFC7748_SHARED);
    let alice =
        import_x25519_secret_key(&unhex(RFC7748_ALICE_X), &unhex(RFC7748_ALICE_D), true, true)
            .await
            .map_err(|e| describe("import Alice", &e))?;
    let bob_public = import_x25519_public_key(unhex(RFC7748_BOB_X))
        .await
        .map_err(|e| describe("import Bob's public key", &e))?;

    // Chaining equivalence: prepare-from over the agreed input equals
    // hkdf-sha2.prepare over the same shared secret imported as IKM.
    let input = alice
        .agree(&bob_public)
        .await
        .map_err(|e| describe("agree", &e))?;
    let chained = hkdf_sha2::prepare_from(
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
    let direct = hkdf_sha2::prepare(
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

    // Chaining rides the derive-key grant: a bits-only input refuses it.
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
    expect_err(
        "chaining without the derive-key grant",
        ErrKind::NotPermitted,
        hkdf_sha2::prepare_from(Sha2Variant::Sha256, &input, Vec::new(), Vec::new()).await,
        "chained from a key-less input",
    )
}

/// The ECDH key surface, on P-256: metadata getters in both grant
/// directions, generated-key freshness, the public raw-export round trip,
/// the wrong-length and crv-mismatch import rejections, extractability
/// recording, and the zero-grant mint refusal.
async fn ecdh_key_contract() -> Result<(), String> {
    use polymorph_webcrypto_guest::bindings::ecdh::{self, EcdhVariant};

    let (secret, public) = generate_ecdh_key(EcdhVariant::P256, true, true)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    expect(
        secret.algorithm_name(),
        "ECDH".to_string(),
        "secret-key algorithm-name",
    )?;
    expect(
        public.algorithm_name(),
        "ECDH".to_string(),
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
    let (bits_only, _) = generate_ecdh_key(EcdhVariant::P256, true, false)
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
    let (key_only, _) = generate_ecdh_key(EcdhVariant::P256, false, true)
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

    // A generated public key exports as the 65-byte uncompressed SEC1
    // point and re-imports to an equivalent key: both peers derive the
    // same secret.
    let raw = public
        .export_key_raw()
        .await
        .map_err(|e| describe("public-key export-key-raw", &e))?;
    expect(raw.len(), 65, "exported public-point length")?;
    let reimported = import_ecdh_public_key_raw(EcdhVariant::P256, raw.clone())
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
    // public point (the same randomness observable the X25519 probe
    // pins).
    let (_, public2) = generate_ecdh_key(EcdhVariant::P256, true, true)
        .await
        .map_err(|e| describe("second generate-key", &e))?;
    let raw2 = public2
        .export_key_raw()
        .await
        .map_err(|e| describe("second public-key export-key-raw", &e))?;
    if raw2 == raw {
        return Err("two generated keys share a public point".into());
    }

    // The public JWK export carries the EC material members.
    let jwk = public
        .export_key_jwk()
        .await
        .map_err(|e| describe("public-key export-key-jwk", &e))?;
    let x = b64url(&raw[1..33]);
    let y = b64url(&raw[33..]);
    if !jwk.contains("\"EC\"")
        || !jwk.contains("\"P-256\"")
        || !jwk.contains(&x)
        || !jwk.contains(&y)
    {
        return Err(format!(
            "exported public JWK missing material members: {jwk}"
        ));
    }

    // Import rejections: a wrong-length public point, and EC JWKs whose
    // crv disagrees with the declared variant, on both key halves.
    expect_err(
        "64-byte public point",
        ErrKind::InvalidKey,
        import_ecdh_public_key_raw(EcdhVariant::P256, raw[..64].to_vec()).await,
        "imported a truncated public point",
    )?;
    let d = unhex(ECDH_P256_D);
    let secret_x = unhex(ECDH_P256_X);
    let secret_y = unhex(ECDH_P256_Y);
    expect_err(
        "wrong-crv EC private JWK",
        ErrKind::InvalidKey,
        ecdh::import_secret_key_jwk(
            EcdhVariant::P256,
            ecdh_secret_jwk("P-384", &secret_x, &secret_y, &d),
            agreement_options(true, true, false),
        )
        .await,
        "imported a P-384-labeled JWK as P-256",
    )?;
    let peer = unhex(ECDH_P256_PEER);
    expect_err(
        "wrong-crv EC public JWK",
        ErrKind::InvalidKey,
        ecdh::import_public_key_jwk(
            EcdhVariant::P256,
            format!(
                r#"{{"kty":"EC","crv":"P-384","x":"{}","y":"{}"}}"#,
                b64url(&peer[1..33]),
                b64url(&peer[33..]),
            ),
        )
        .await,
        "imported a P-384-labeled JWK as P-256",
    )?;

    // The zero-usage mint check on the generation path (the import path's
    // is the derive battery's `ecdh/contract/grants` case).
    expect_err(
        "zero-grant generate",
        ErrKind::NotPermitted,
        generate_ecdh_key(EcdhVariant::P256, false, false).await,
        "generated a key with no enabled grant",
    )?;

    // The extractable grant records through the options onto the minted
    // key (secret keys have no ungated export; the getter is the
    // observable).
    let extractable_import = ecdh::import_secret_key_jwk(
        EcdhVariant::P256,
        ecdh_secret_jwk("P-256", &secret_x, &secret_y, &d),
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

/// The agreement operation on generated ECDH pairs: agreement commutes
/// and the shared secret's natural length is the curve's field size (32
/// bytes on P-256, 48 on P-384); a curve- or algorithm-mismatched peer
/// fails `agree` with `invalid-key` in both directions. The ECDH × X25519
/// pairings exercise the `key-agreement` kind's cross-algorithm check,
/// unobservable while X25519 was the only algorithm minting the kind's
/// resources.
async fn ecdh_agree_contract() -> Result<(), String> {
    use polymorph_webcrypto_guest::bindings::ecdh::EcdhVariant;

    for (variant, size, what) in [
        (EcdhVariant::P256, 32usize, "P-256"),
        (EcdhVariant::P384, 48, "P-384"),
    ] {
        let (a_secret, a_public) = generate_ecdh_key(variant, true, true)
            .await
            .map_err(|e| describe(&format!("generate-key ({what} pair A)"), &e))?;
        let (b_secret, b_public) = generate_ecdh_key(variant, true, true)
            .await
            .map_err(|e| describe(&format!("generate-key ({what} pair B)"), &e))?;
        let ab = a_secret
            .agree(&b_public)
            .await
            .map_err(|e| describe(&format!("agree ({what}, A with B)"), &e))?
            .derive_bits(None)
            .await
            .map_err(|e| describe(&format!("derive-bits ({what}, A's direction)"), &e))?;
        expect(
            ab.len(),
            size,
            &format!("natural shared-secret length ({what})"),
        )?;
        let ba = b_secret
            .agree(&a_public)
            .await
            .map_err(|e| describe(&format!("agree ({what}, B with A)"), &e))?
            .derive_bits(None)
            .await
            .map_err(|e| describe(&format!("derive-bits ({what}, B's direction)"), &e))?;
        expect_bytes(&ba, &ab, &format!("agreement commutes ({what})"))?;
    }

    let (p256_secret, p256_public) = generate_ecdh_key(EcdhVariant::P256, true, true)
        .await
        .map_err(|e| describe("generate-key (P-256)", &e))?;
    let (p384_secret, p384_public) = generate_ecdh_key(EcdhVariant::P384, true, true)
        .await
        .map_err(|e| describe("generate-key (P-384)", &e))?;
    let (x_secret, x_public) = generate_x25519_key(true, true)
        .await
        .map_err(|e| describe("generate-key (X25519)", &e))?;
    expect_err(
        "agree (P-256 secret, P-384 peer)",
        ErrKind::InvalidKey,
        p256_secret.agree(&p384_public).await,
        "agreed across curves",
    )?;
    expect_err(
        "agree (P-384 secret, P-256 peer)",
        ErrKind::InvalidKey,
        p384_secret.agree(&p256_public).await,
        "agreed across curves",
    )?;
    expect_err(
        "agree (X25519 secret, ECDH peer)",
        ErrKind::InvalidKey,
        x_secret.agree(&p256_public).await,
        "agreed across algorithms",
    )?;
    expect_err(
        "agree (ECDH secret, X25519 peer)",
        ErrKind::InvalidKey,
        p256_secret.agree(&x_public).await,
        "agreed across algorithms",
    )
}

/// `hkdf-sha2.prepare-from` chains from an ECDH agreement exactly as from
/// an X25519 one: the chained derivation equals HKDF over the same shared
/// secret imported as IKM, and chaining rides the `derive-key` grant,
/// refusing `not-permitted` from a key-less input.
async fn ecdh_chaining() -> Result<(), String> {
    use polymorph_webcrypto_guest::bindings::ecdh::EcdhVariant;
    use polymorph_webcrypto_guest::bindings::hkdf_sha2;

    let shared = unhex(ECDH_P256_SHARED);
    let secret_jwk = ecdh_secret_jwk(
        "P-256",
        &unhex(ECDH_P256_X),
        &unhex(ECDH_P256_Y),
        &unhex(ECDH_P256_D),
    );
    let secret = import_ecdh_secret_key(EcdhVariant::P256, secret_jwk.clone(), true, true)
        .await
        .map_err(|e| describe("import-secret-key-jwk", &e))?;
    let peer = import_ecdh_public_key_raw(EcdhVariant::P256, unhex(ECDH_P256_PEER))
        .await
        .map_err(|e| describe("import-public-key-raw", &e))?;

    // Chaining equivalence: prepare-from over the agreed input equals
    // hkdf-sha2.prepare over the same shared secret imported as IKM.
    let input = secret
        .agree(&peer)
        .await
        .map_err(|e| describe("agree", &e))?;
    let chained = hkdf_sha2::prepare_from(
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
    let direct = hkdf_sha2::prepare(
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

    // Chaining rides the derive-key grant: a bits-only input refuses it.
    let bits_only = import_ecdh_secret_key(EcdhVariant::P256, secret_jwk, true, false)
        .await
        .map_err(|e| describe("bits-only import", &e))?;
    let input = bits_only
        .agree(&peer)
        .await
        .map_err(|e| describe("agree (bits-only)", &e))?;
    expect_err(
        "chaining without the derive-key grant",
        ErrKind::NotPermitted,
        hkdf_sha2::prepare_from(Sha2Variant::Sha256, &input, Vec::new(), Vec::new()).await,
        "chained from a key-less input",
    )
}

// RFC 8032 §7.1 TEST 3: the seed, its public key, and the deterministic
// signature over the two-byte message `af82` — a cross-implementation
// known answer, since RFC 8032 signing is deterministic.
const ED25519_TEST3_SEED: &str = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";
const ED25519_TEST3_PUBLIC: &str =
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";
const ED25519_TEST3_MSG: &str = "af82";
const ED25519_TEST3_SIG: &str = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a";

// The RFC 6979 A.2.5 P-256 public key's SubjectPublicKeyInfo encoding
// (its coordinates are the harness's `P256_A25_X`/`P256_A25_Y`).
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
    use polymorph_webcrypto_guest::bindings::ecdsa_verify;
    use polymorph_webcrypto_guest::bindings::ed25519_verify;

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
    let x = b64url(&public_raw);
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
        sig_verify_ok(
            &key,
            &msg,
            &sig,
            Schedule::Whole,
            &format!("TEST 3 signature under the {what}"),
        )
        .await?;
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
    let (x, y) = (b64url(&unhex(P256_A25_X)), b64url(&unhex(P256_A25_Y)));
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
            b64url(&public_raw)
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
    let x = b64url(&public_raw);
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
    use polymorph_webcrypto_guest::bindings::ed25519_sign;

    let seed = unhex(ED25519_TEST3_SEED);
    let msg = unhex(ED25519_TEST3_MSG);
    let expected_sig = unhex(ED25519_TEST3_SIG);

    let from_pkcs8 =
        ed25519_sign::import_signing_key_pkcs8(rfc8410_pkcs8(0x70, &seed), signing_options(false))
            .await
            .map_err(|e| describe("import-signing-key-pkcs8", &e))?;
    let sig = sig_sign_ok(&from_pkcs8, &msg, Schedule::Whole).await?;
    expect_bytes(
        &sig,
        &expected_sig,
        "TEST 3 signature from the PKCS#8 import",
    )?;

    let jwk = format!(
        r#"{{"kty":"OKP","crv":"Ed25519","x":"{}","d":"{}"}}"#,
        b64url(&unhex(ED25519_TEST3_PUBLIC)),
        b64url(&seed),
    );
    let from_jwk = ed25519_sign::import_signing_key_jwk(jwk, signing_options(false))
        .await
        .map_err(|e| describe("import-signing-key-jwk", &e))?;
    let sig = sig_sign_ok(&from_jwk, &msg, Schedule::Whole).await?;
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
                b64url(&unhex(ED25519_TEST3_PUBLIC))
            ),
            signing_options(false),
        )
        .await,
        "imported a d-less JWK as a signing key",
    )
}

/// The cross pairings of curve and hash are real variants: each mints a
/// verifying key whose getters report its own binding (never the curve's
/// default hash), and each executes verification under that binding — a
/// well-formed wrong signature (in-range `r ‖ s`) fails
/// `authentication-failed` through the pairing's own digest. Upstream
/// publishes no vector file for P-256/SHA-384 or P-384/SHA-256, so those
/// two additionally verify an OpenSSL-generated known answer (the valid
/// signature passes; the same signature over a tampered message fails
/// through the pairing's digest) — their only positive verify execution
/// on any target, and their only verify execution at all on targets the
/// signing suite does not reach.
async fn ecdsa_cross_hash_variants() -> Result<(), String> {
    let mut p256 = vec![0x04];
    p256.extend(unhex(P256_A25_X));
    p256.extend(unhex(P256_A25_Y));
    // The vendored Wycheproof P-384 file's group public key.
    let p384 = unhex("042da57dda1089276a543f9ffdac0bff0d976cad71eb7280e7d9bfd9fee4bdb2f20f47ff888274389772d98cc5752138aa4b6d054d69dcf3e25ec49df870715e34883b1836197d76f8ad962e78f6571bbc7407b0d6091f9e4d88f014274406174f");
    // Known answers for the pairings without an upstream vector file,
    // generated with OpenSSL 3.5.3 (`openssl ecparam -genkey`, `openssl
    // dgst -sha384/-sha256 -sign`, DER decoded to fixed-width P1363)
    // over KAT_MESSAGE, and verified with `openssl dgst -verify` at
    // generation.
    let p256_sha384_key = unhex(
        "04c3ed370a58c67158ae8c9c83bc3060b3ee0d55492210d45a41deae1acf033d\
         8397234b01c5c72f2b7809b46e0802f3679eacc4ab9e3899e0a84d06b852afc9\
         70",
    );
    let p256_sha384_sig = unhex(
        "7b1c25e1ce70d578ba23d98a19e363c2781d5ddb95edc89bc5819c805c2b1204\
         9d863291e914f29eb064706a2a17cb6fc5aa1762b0ffacc9ac2a596198723d60",
    );
    let p384_sha256_key = unhex(
        "04d75237faa5db4f14f9e634b3c3b3718e338a4e12be06877d48f956f8c3b330\
         340153b104d0eae15a8b0effd6ff170e8b84b09622d6d75ed43d52fcc5329db7\
         c722b385556394e87f8c0dfb9713e47c7e5ee600a1c2461185ee9430d21cb694\
         99",
    );
    let p384_sha256_sig = unhex(
        "6b3ce4a6e26e864464e5aa1ae72439d0b5791a902a4a9ab576929592348a4d4d\
         99e0b2e2565b226bd0db0696a6479eae577c37d4fb188b651b36565fe9a86ba5\
         a3bf27b866c9683eb4b7f226fcf5e59cd2a98ee788a3ea7c55c4b124623db6bf",
    );
    const KAT_MESSAGE: &[u8] = b"cross-hash digest binding";
    for (variant, point, curve, hash, kat) in [
        (
            EcdsaVariant::P256Sha384,
            &p256,
            "P-256",
            "SHA-384",
            Some((&p256_sha384_key, &p256_sha384_sig)),
        ),
        (EcdsaVariant::P256Sha512, &p256, "P-256", "SHA-512", None),
        (
            EcdsaVariant::P384Sha256,
            &p384,
            "P-384",
            "SHA-256",
            Some((&p384_sha256_key, &p384_sha256_sig)),
        ),
        (EcdsaVariant::P384Sha512, &p384, "P-384", "SHA-512", None),
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
        expect(
            key.algorithm_public_exponent(),
            None,
            "cross-variant algorithm-public-exponent (ECDSA has none)",
        )?;
        // 0x0101…01 is in range (below both curve orders) and nonzero for
        // both halves, so rejection can only come from verification.
        let sig = vec![0x01u8; if curve == "P-256" { 64 } else { 96 }];
        let verified = sig_verify_op(&key, KAT_MESSAGE, &sig, Schedule::Whole).await?;
        expect_err(
            &format!("verify ({curve}/{hash})"),
            ErrKind::AuthenticationFailed,
            verified,
            "a fabricated signature verified",
        )?;
        let Some((kat_point, kat_sig)) = kat else {
            continue;
        };
        let kat_key = import_ecdsa_verifying_key(variant, kat_point.to_vec())
            .await
            .map_err(|e| {
                describe(
                    &format!("import-verifying-key-raw (KAT {curve}/{hash})"),
                    &e,
                )
            })?;
        sig_verify_ok(
            &kat_key,
            KAT_MESSAGE,
            kat_sig,
            Schedule::Whole,
            &format!("verify (KAT {curve}/{hash})"),
        )
        .await?;
        let mut tampered = KAT_MESSAGE.to_vec();
        tampered[0] ^= 0x01;
        let verified = sig_verify_op(&kat_key, &tampered, kat_sig, Schedule::Whole).await?;
        expect_err(
            &format!("verify (KAT {curve}/{hash}, tampered message)"),
            ErrKind::AuthenticationFailed,
            verified,
            "a known-answer signature verified a tampered message",
        )?;
    }
    Ok(())
}

/// The 2048-bit rsaEncryption SubjectPublicKeyInfo (e = 65537) shared by
/// Wycheproof `rsa_signature_2048_sha256_test.json` (group 1) and the
/// `rsa_pss_2048_sha256_mgf1_{0,32}` files.
const RSA_2048_SPKI: &str = "30820122300d06092a864886f70d01010105000382010f003082010a02820101\
     00a2b451a07d0aa5f96e455671513550514a8a5b462ebef717094fa1fee82224\
     e637f9746d3f7cafd31878d80325b6ef5a1700f65903b469429e89d6eac88450\
     97b5ab393189db92512ed8a7711a1253facd20f79c15e8247f3d3e42e46e48c9\
     8e254a2fe9765313a03eff8f17e1a029397a1fa26a8dce26f490ed81299615d9\
     814c22da610428e09c7d9658594266f5c021d0fceca08d945a12be82de4d1ece\
     6b4c03145b5d3495d4ed5411eb878daf05fd7afc3e09ada0f1126422f590975a\
     1969816f48698bcbba1b4d9cae79d460d8f9f85e7975005d9bc22c4e5ac0f7c1\
     a45d12569a62807d3b9a02e5a530e773066f453d1f5b4c2e9cf7820283f742b9\
     d50203010001";

/// [`RSA_2048_SPKI`]'s modulus as a JWK `n` member (Wycheproof
/// `rsa_signature_2048_sha256_test.json` group 1 `keyJwk`).
const RSA_2048_N: &str = "orRRoH0KpfluRVZxUTVQUUqKW0YuvvcXCU-h_ugiJOY3-XRtP3yv0xh42AMltu9aFwD2WQO0aUKeidbqyIRQl7WrOTGJ25JRLtincRoSU_rNIPecFegkfz0-QuRuSMmOJUov6XZTE6A-_48X4aApOXofomqNzib0kO2BKZYV2YFMItphBCjgnH2WWFlCZvXAIdD87KCNlFoSvoLeTR7Oa0wDFFtdNJXU7VQR64eNrwX9evw-Ca2g8RJkIvWQl1oZaYFvSGmLy7obTZyuedRg2Pn4Xnl1AF2bwixOWsD3waRdElaaYoB9O5oC5aUw53MGb0U9H1tMLpz3ggKD90K51Q";

/// The 2048-bit e = 3 rsaEncryption SubjectPublicKeyInfo of Wycheproof
/// `rsa_signature_2048_sha256_test.json` group 2.
const RSA_2048_E3_SPKI: &str = "30820120300d06092a864886f70d01010105000382010d003082010802820101\
     0090a5d7aba2c8dc828e616fc1fc45c7c52130c8589dcbe2913da187572f6c23\
     217b89a5186b6f90cbe053abfb0885a91f141dbe106ce6ad303904a5941df26c\
     ed10478cb56a7bd6cf1313c4966d9cf7c4509d9dc63566aa323e110af219f339\
     8c04e79bb486de8703793473136f5c9051af24bd2c0208ea1bf9321a3e8f24af\
     00aaca1216842eab248d58cf46ac786c49fd3ca8557e9b53993a4b9718cdc5c4\
     74bf1cfe58c07ad97b2c5acb7d86accc0fc7bed147adb2e77b8697d801509481\
     17714b806ff76f9d88147d84e93987b724bf4870429e85a7a7b51486a78d8a88\
     f1688f60e215d43d06221e2b993b5c12a607b80e9e0122472b29945f76b55737\
     c1020103";

/// The id-RSASSA-PSS SubjectPublicKeyInfo (algorithm 1.2.840.113549.1.1.10
/// with PSS parameters) carried by every group of Wycheproof
/// `rsa_pss_2048_sha256_mgf1_32_params_test.json`; its key material is
/// [`RSA_2048_SPKI`]'s.
const RSA_PSS_PARAMS_SPKI: &str =
    "30820156304106092a864886f70d01010a3034a00f300d060960864801650304\
     02010500a11c301a06092a864886f70d010108300d0609608648016503040201\
     0500a2030201200382010f003082010a0282010100a2b451a07d0aa5f96e4556\
     71513550514a8a5b462ebef717094fa1fee82224e637f9746d3f7cafd31878d8\
     0325b6ef5a1700f65903b469429e89d6eac8845097b5ab393189db92512ed8a7\
     711a1253facd20f79c15e8247f3d3e42e46e48c98e254a2fe9765313a03eff8f\
     17e1a029397a1fa26a8dce26f490ed81299615d9814c22da610428e09c7d9658\
     594266f5c021d0fceca08d945a12be82de4d1ece6b4c03145b5d3495d4ed5411\
     eb878daf05fd7afc3e09ada0f1126422f590975a1969816f48698bcbba1b4d9c\
     ae79d460d8f9f85e7975005d9bc22c4e5ac0f7c1a45d12569a62807d3b9a02e5\
     a530e773066f453d1f5b4c2e9cf7820283f742b9d50203010001";

/// A 768-bit rsaEncryption SubjectPublicKeyInfo (e = 65537), below the
/// RSA family's 1024-bit modulus floor. Generated for this probe with
/// `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:768`; only
/// its well-formedness and modulus length matter.
const RSA_768_SPKI: &str = "307c300d06092a864886f70d0101010500036b003068026100e5106a432f4deb\
     715d592e2ea049ed8a9d20f6cab20847ff350d40e3e4bf24e43fd841d80e2948\
     73794fac6ea95292c3e2a8894d82241133f475da49680efb5fdb4eded935680c\
     fb9a84deb995c52896248f2f23949cfcb512cc1e0cdb4c42210203010001";

/// Wycheproof `rsa_pss_2048_sha256_mgf1_32_test.json` tcId 1 (sLen 32): a
/// valid RSA-PSS SHA-256 signature over the empty message under
/// [`RSA_2048_SPKI`].
const RSA_PSS_SALT32_SIG: &str = "4f01e0c12b08625ecac89a69231906edf826380f37c959a96690d046316d68ff\
     ce9d5c471694fcebfc6b45534864689256e4fc81c78e583f675d0c94b4496474\
     51e81beff01a11a516d5e5ce3f1a910437cb8a3a5096b19fb15f4524a35b23d8\
     9cdba12cf5b71aac1047b28c562df7c5542c34ce23a182cf7e0e231934b17294\
     799d44877a1d68ef1b8f073619b7618e6b7c22db20030d98cf591ffc3d4da5f5\
     8613ecd5ecfc3b40a1d02f40891ca43695cd4c088b05a8054c89c595a47e2748\
     16f35384226f74459ee63e25a1bfc03c360490552ec38343f8ace502f065303b\
     00bc0ec320711b211fde92e57feb9013c3609342495ec0d7cabdec21e54acc38";

/// Wycheproof `rsa_pss_2048_sha256_mgf1_0_test.json` tcId 1 (sLen 0): a
/// valid RSA-PSS SHA-256 signature over the empty message under the same
/// key.
const RSA_PSS_SALT0_SIG: &str = "20081f8894a1330c4d503f642880e3c30e398fc6235c24f1be752e2d49cd9493\
     ac0cf999e275c4f89ff08f0d9ba4e264a332525a616d336bd9e822f41ab3f4fa\
     e2f48ec66c2e52642ed93b7cb944396fbaa727cbfdfc1f20aace99a6f2a74475\
     c338f8d9f22a38cb5bc51752076503b3aef1e65e5a8f8583d9ae7378ded038cf\
     516898ad06beb90a42b85764526fcea44f74258fa4efb1da253d337f65619181\
     ceb832dfe285ce78ae6b15f204e23bab274e87445d9f5df97f41dc8e3a97736b\
     62591d075744b2552f90bcf1b1393e1e7627ef1f985f2bbabd52e43a35d0ddf4\
     c67126e391f922ef7b1bb1911cd6e1b303cb2910dd70672bbfb62ea4eaad725c";

/// The RSA verifying-key contract on both minting families: the getters
/// report the mint binding (name, mint-bound hash, modulus length, the
/// public exponent's big-endian bytes, no curve), raw export fails
/// `unsupported` (RSA public keys have no raw
/// form), the SPKI export round-trips the imported DER, the JWK export
/// re-imports to the same key, a JWK `alg` disagreeing with the variant —
/// or with the other RSA family — fails `invalid-key`, and a public JWK
/// carrying `d` is not a verifying key.
async fn rsa_key_contract() -> Result<(), String> {
    use crate::mint::{
        import_rsa_pss_verifying_key_jwk, import_rsa_pss_verifying_key_spki,
        import_rsassa_verifying_key_jwk, import_rsassa_verifying_key_spki,
    };
    use polymorph_webcrypto_guest::bindings::rsa::RsaVariant;

    let spki = unhex(RSA_2048_SPKI);
    let v15 = import_rsassa_verifying_key_spki(RsaVariant::Sha256, spki.clone())
        .await
        .map_err(|e| describe("rsassa import-verifying-key-spki", &e))?;
    expect(
        v15.algorithm_name(),
        "RSASSA-PKCS1-v1_5".to_string(),
        "RSASSA verifying-key algorithm-name",
    )?;
    expect(
        v15.algorithm_hash(),
        Some("SHA-256".to_string()),
        "RSASSA verifying-key algorithm-hash",
    )?;
    expect(
        v15.algorithm_length(),
        Some(2048),
        "RSASSA verifying-key algorithm-length",
    )?;
    expect(
        v15.algorithm_public_exponent(),
        Some(vec![1, 0, 1]),
        "RSASSA verifying-key algorithm-public-exponent",
    )?;
    expect(
        v15.algorithm_curve(),
        None,
        "RSASSA verifying-key algorithm-curve",
    )?;

    let pss = import_rsa_pss_verifying_key_spki(RsaVariant::Sha384, 48, spki.clone())
        .await
        .map_err(|e| describe("pss import-verifying-key-spki", &e))?;
    expect(
        pss.algorithm_name(),
        "RSA-PSS".to_string(),
        "RSA-PSS verifying-key algorithm-name",
    )?;
    expect(
        pss.algorithm_hash(),
        Some("SHA-384".to_string()),
        "RSA-PSS verifying-key algorithm-hash",
    )?;
    expect(
        pss.algorithm_length(),
        Some(2048),
        "RSA-PSS verifying-key algorithm-length",
    )?;
    expect(
        pss.algorithm_curve(),
        None,
        "RSA-PSS verifying-key algorithm-curve",
    )?;

    for (what, key) in [("rsassa", &v15), ("pss", &pss)] {
        expect_err(
            &format!("{what} export-key-raw"),
            ErrKind::Unsupported,
            key.export_key_raw().await,
            "exported a raw form for an RSA public key",
        )?;
        let exported = key
            .export_key_spki()
            .await
            .map_err(|e| describe(&format!("{what} export-key-spki"), &e))?;
        expect_bytes(&exported, &spki, &format!("{what} SPKI export"))?;
    }

    // The JWK round trip: export carries the material members, and
    // re-importing yields a key whose SPKI equals the original.
    let jwk = v15
        .export_key_jwk()
        .await
        .map_err(|e| describe("rsassa export-key-jwk", &e))?;
    if !jwk.contains("\"RSA\"") || !jwk.contains(RSA_2048_N) {
        return Err(format!("exported RSA JWK missing material members: {jwk}"));
    }
    let reimported = import_rsassa_verifying_key_jwk(RsaVariant::Sha256, jwk)
        .await
        .map_err(|e| describe("re-import of exported JWK", &e))?;
    let exported = reimported
        .export_key_spki()
        .await
        .map_err(|e| describe("export-key-spki after the JWK round trip", &e))?;
    expect_bytes(&exported, &spki, "SPKI after the JWK round trip")?;

    // The JWK `alg` policy: the variant's own JOSE alg is accepted, an
    // alg of another digest — or of the other RSA family — is
    // `invalid-key`.
    let jwk_with =
        |alg: &str| format!(r#"{{"kty":"RSA","n":"{RSA_2048_N}","e":"AQAB","alg":"{alg}"}}"#);
    import_rsassa_verifying_key_jwk(RsaVariant::Sha256, jwk_with("RS256"))
        .await
        .map_err(|e| describe("rsassa import with alg RS256", &e))?;
    import_rsa_pss_verifying_key_jwk(RsaVariant::Sha256, 32, jwk_with("PS256"))
        .await
        .map_err(|e| describe("pss import with alg PS256", &e))?;
    expect_err(
        "RS256 JWK under the sha384 variant",
        ErrKind::InvalidKey,
        import_rsassa_verifying_key_jwk(RsaVariant::Sha384, jwk_with("RS256")).await,
        "imported a JWK with another variant's alg",
    )?;
    expect_err(
        "RS256 JWK under RSA-PSS",
        ErrKind::InvalidKey,
        import_rsa_pss_verifying_key_jwk(RsaVariant::Sha256, 32, jwk_with("RS256")).await,
        "imported a JWK with the other RSA family's alg",
    )?;
    expect_err(
        "PS256 JWK under RSASSA-PKCS1-v1_5",
        ErrKind::InvalidKey,
        import_rsassa_verifying_key_jwk(RsaVariant::Sha256, jwk_with("PS256")).await,
        "imported a JWK with the other RSA family's alg",
    )?;

    // Private material on a public import path.
    expect_err(
        "d-carrying RSA JWK",
        ErrKind::InvalidKey,
        import_rsassa_verifying_key_jwk(
            RsaVariant::Sha256,
            format!(r#"{{"kty":"RSA","n":"{RSA_2048_N}","e":"AQAB","d":"AQID"}}"#),
        )
        .await,
        "imported a d-carrying JWK as a verifying key",
    )
}

/// The RSA family admission contract at its edges: a 768-bit modulus
/// (below the 1024-bit floor) and a 16392-bit JWK `n` (above the
/// 16384-bit ceiling) fail `invalid-key`; e = 1 (odd but below the floor)
/// and e = 4 (even) fail `invalid-key`; e = 3 is guaranteed to import
/// (the vector cases verify under it); and an SPKI carrying the
/// id-RSASSA-PSS AlgorithmIdentifier fails `invalid-key` on both
/// families' SPKI imports.
async fn rsa_admission_contract() -> Result<(), String> {
    use crate::mint::{
        import_rsa_pss_verifying_key_spki, import_rsassa_verifying_key_jwk,
        import_rsassa_verifying_key_spki,
    };
    use polymorph_webcrypto_guest::bindings::rsa::RsaVariant;

    let spki_768 = unhex(RSA_768_SPKI);
    expect_err(
        "768-bit SPKI (rsassa)",
        ErrKind::InvalidKey,
        import_rsassa_verifying_key_spki(RsaVariant::Sha256, spki_768.clone()).await,
        "imported a modulus below the 1024-bit floor",
    )?;
    expect_err(
        "768-bit SPKI (pss)",
        ErrKind::InvalidKey,
        import_rsa_pss_verifying_key_spki(RsaVariant::Sha256, 32, spki_768).await,
        "imported a modulus below the 1024-bit floor",
    )?;

    // 2049 bytes with the top bit set: a 16392-bit modulus (odd, so only
    // the ceiling is in play).
    let oversized = format!(
        r#"{{"kty":"RSA","n":"{}","e":"AQAB"}}"#,
        b64url(&vec![0xffu8; 2049])
    );
    expect_err(
        "16392-bit JWK n",
        ErrKind::InvalidKey,
        import_rsassa_verifying_key_jwk(RsaVariant::Sha256, oversized).await,
        "imported a modulus above the 16384-bit ceiling",
    )?;

    for (what, e) in [("e = 1", "AQ"), ("e = 4", "BA")] {
        expect_err(
            &format!("JWK with {what}"),
            ErrKind::InvalidKey,
            import_rsassa_verifying_key_jwk(
                RsaVariant::Sha256,
                format!(r#"{{"kty":"RSA","n":"{RSA_2048_N}","e":"{e}"}}"#),
            )
            .await,
            "imported a public exponent the family floor rejects",
        )?;
    }

    let e3 = import_rsassa_verifying_key_spki(RsaVariant::Sha256, unhex(RSA_2048_E3_SPKI))
        .await
        .map_err(|e| describe("import of the e = 3 SPKI", &e))?;
    expect(
        e3.algorithm_length(),
        Some(2048),
        "e = 3 key algorithm-length",
    )?;

    let params_spki = unhex(RSA_PSS_PARAMS_SPKI);
    expect_err(
        "id-RSASSA-PSS SPKI (rsassa)",
        ErrKind::InvalidKey,
        import_rsassa_verifying_key_spki(RsaVariant::Sha256, params_spki.clone()).await,
        "imported a key carrying the id-RSASSA-PSS AlgorithmIdentifier",
    )?;
    expect_err(
        "id-RSASSA-PSS SPKI (pss)",
        ErrKind::InvalidKey,
        import_rsa_pss_verifying_key_spki(RsaVariant::Sha256, 32, params_spki).await,
        "imported a key carrying the id-RSASSA-PSS AlgorithmIdentifier",
    )
}

/// The mint-bound PSS salt length is part of the verification criterion:
/// each of the two vendored sLen-0/sLen-32 tcId-1 signatures (same key,
/// same digest, empty message) verifies under its own salt length's mint
/// and fails `authentication-failed` under the other's.
async fn rsa_pss_salt_binding() -> Result<(), String> {
    use crate::mint::import_rsa_pss_verifying_key_spki;
    use polymorph_webcrypto_guest::bindings::rsa::RsaVariant;

    let spki = unhex(RSA_2048_SPKI);
    let sig_salt32 = unhex(RSA_PSS_SALT32_SIG);
    let sig_salt0 = unhex(RSA_PSS_SALT0_SIG);
    let salt32 = import_rsa_pss_verifying_key_spki(RsaVariant::Sha256, 32, spki.clone())
        .await
        .map_err(|e| describe("import (salt 32)", &e))?;
    let salt0 = import_rsa_pss_verifying_key_spki(RsaVariant::Sha256, 0, spki)
        .await
        .map_err(|e| describe("import (salt 0)", &e))?;

    sig_verify_ok(
        &salt32,
        b"",
        &sig_salt32,
        Schedule::Whole,
        "the sLen-32 signature did not verify under its own salt length",
    )
    .await?;
    sig_verify_ok(
        &salt0,
        b"",
        &sig_salt0,
        Schedule::Whole,
        "the sLen-0 signature did not verify under its own salt length",
    )
    .await?;

    let verified = sig_verify_op(&salt0, b"", &sig_salt32, Schedule::Whole).await?;
    expect_err(
        "salt-0 mint verifying the sLen-32 signature",
        ErrKind::AuthenticationFailed,
        verified,
        "a signature verified under the wrong mint-bound salt length",
    )?;
    let verified = sig_verify_op(&salt32, b"", &sig_salt0, Schedule::Whole).await?;
    expect_err(
        "salt-32 mint verifying the sLen-0 signature",
        ErrKind::AuthenticationFailed,
        verified,
        "a signature verified under the wrong mint-bound salt length",
    )
}

/// The X25519 format surface: the RFC 7748 §6.1 keys through the SPKI and
/// PKCS#8 imports still derive the known shared secret, the gated secret
/// exports round-trip, and the gate holds on non-extractable keys.
async fn x25519_format_roundtrips() -> Result<(), String> {
    use polymorph_webcrypto_guest::bindings::x25519;

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
        b64url(&bob_x)
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
    let d = b64url(&alice_d);
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
        b64url(&bob_x)
    ))
    .await
    .map_err(|e| describe("import-public-key-jwk (alg present)", &e))?;
    expect_err(
        "ext:false public JWK",
        ErrKind::InvalidKey,
        x25519::import_public_key_jwk(format!(
            r#"{{"kty":"OKP","crv":"X25519","x":"{}","ext":false}}"#,
            b64url(&bob_x)
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

/// The X.509 SubjectPublicKeyInfo encoding of an uncompressed P-256
/// public point (the id-ecPublicKey AlgorithmIdentifier with the
/// prime256v1 named-curve parameter).
fn p256_ec_spki(point: &[u8]) -> Vec<u8> {
    let mut out = unhex("3059301306072a8648ce3d020106082a8648ce3d030107034200");
    out.extend_from_slice(point);
    out
}

/// The ECDH format surface: the Wycheproof P-256 known-answer keys
/// through the SPKI and JWK public imports and the PKCS#8 secret round
/// trip all derive the published shared secret, the public exports are
/// the pinned encodings, the extractability gate holds on the secret
/// exports, cross-curve material is rejected on every import format, and
/// the declared-but-unserved P-521 declines `unsupported`.
async fn ecdh_format_roundtrips() -> Result<(), String> {
    use polymorph_webcrypto_guest::bindings::ecdh::{self, EcdhVariant};

    let d = unhex(ECDH_P256_D);
    let x = unhex(ECDH_P256_X);
    let y = unhex(ECDH_P256_Y);
    let peer_point = unhex(ECDH_P256_PEER);
    let shared = unhex(ECDH_P256_SHARED);
    let peer_jwk_text = format!(
        r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}"}}"#,
        b64url(&peer_point[1..33]),
        b64url(&peer_point[33..]),
    );

    // Peer public via SPKI and JWK: every pairing derives the published
    // shared secret.
    let secret = ecdh::import_secret_key_jwk(
        EcdhVariant::P256,
        ecdh_secret_jwk("P-256", &x, &y, &d),
        agreement_options(true, true, true),
    )
    .await
    .map_err(|e| describe("import-secret-key-jwk", &e))?;
    let peer_spki = ecdh::import_public_key_spki(EcdhVariant::P256, p256_ec_spki(&peer_point))
        .await
        .map_err(|e| describe("import-public-key-spki", &e))?;
    let peer_jwk = ecdh::import_public_key_jwk(EcdhVariant::P256, peer_jwk_text.clone())
        .await
        .map_err(|e| describe("import-public-key-jwk", &e))?;
    for (what, peer) in [("spki peer", &peer_spki), ("jwk peer", &peer_jwk)] {
        let derived = secret
            .agree(peer)
            .await
            .map_err(|e| describe(&format!("agree ({what})"), &e))?
            .derive_bits(None)
            .await
            .map_err(|e| describe(&format!("derive-bits ({what})"), &e))?;
        expect_bytes(&derived, &shared, &format!("known shared secret ({what})"))?;
    }

    // The public exports are the pinned encodings of the raw point.
    let peer = import_ecdh_public_key_raw(EcdhVariant::P256, peer_point.clone())
        .await
        .map_err(|e| describe("import-public-key-raw", &e))?;
    let raw = peer
        .export_key_raw()
        .await
        .map_err(|e| describe("public-key export-key-raw", &e))?;
    expect_bytes(&raw, &peer_point, "raw public-point export")?;
    let spki = peer
        .export_key_spki()
        .await
        .map_err(|e| describe("public-key export-key-spki", &e))?;
    expect_bytes(
        &spki,
        &p256_ec_spki(&peer_point),
        "P-256 SubjectPublicKeyInfo export",
    )?;

    // The gated secret exports carry the imported material. The PKCS#8
    // export round-trips through its own import rather than pinning
    // bytes: encoders legitimately differ on the ECPrivateKey optional
    // members (the embedded public key and parameters).
    let jwk = secret
        .export_key_jwk()
        .await
        .map_err(|e| describe("secret-key export-key-jwk", &e))?;
    let d_b64 = b64url(&d);
    if !jwk.contains("\"EC\"") || !jwk.contains("\"P-256\"") || !jwk.contains(&d_b64) {
        return Err(format!(
            "exported secret JWK missing material members: {jwk}"
        ));
    }
    let pkcs8 = secret
        .export_key_pkcs8()
        .await
        .map_err(|e| describe("secret-key export-key-pkcs8", &e))?;
    let reimported = ecdh::import_secret_key_pkcs8(
        EcdhVariant::P256,
        pkcs8.clone(),
        agreement_options(true, true, false),
    )
    .await
    .map_err(|e| describe("import-secret-key-pkcs8", &e))?;
    let derived = reimported
        .agree(&peer)
        .await
        .map_err(|e| describe("agree (pkcs8 round trip)", &e))?
        .derive_bits(None)
        .await
        .map_err(|e| describe("derive-bits (pkcs8 round trip)", &e))?;
    expect_bytes(&derived, &shared, "known shared secret (pkcs8 round trip)")?;

    // The extractability gate, in the failing direction.
    let non_extractable = import_ecdh_secret_key(
        EcdhVariant::P256,
        ecdh_secret_jwk("P-256", &x, &y, &d),
        true,
        true,
    )
    .await
    .map_err(|e| describe("non-extractable import", &e))?;
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
    )?;

    // Cross-curve material is rejected on every import format, in both
    // directions.
    let (p384_secret, p384_public) =
        ecdh::generate_key(EcdhVariant::P384, agreement_options(true, true, true))
            .await
            .map_err(|e| describe("generate-key (P-384)", &e))?;
    let p384_spki = p384_public
        .export_key_spki()
        .await
        .map_err(|e| describe("P-384 public export-key-spki", &e))?;
    let p384_jwk = p384_secret
        .export_key_jwk()
        .await
        .map_err(|e| describe("P-384 secret export-key-jwk", &e))?;
    let p384_pkcs8 = p384_secret
        .export_key_pkcs8()
        .await
        .map_err(|e| describe("P-384 secret export-key-pkcs8", &e))?;
    expect_err(
        "P-256 SPKI under p384",
        ErrKind::InvalidKey,
        ecdh::import_public_key_spki(EcdhVariant::P384, p256_ec_spki(&peer_point)).await,
        "imported cross-curve material",
    )?;
    expect_err(
        "P-256 public JWK under p384",
        ErrKind::InvalidKey,
        ecdh::import_public_key_jwk(EcdhVariant::P384, peer_jwk_text).await,
        "imported cross-curve material",
    )?;
    expect_err(
        "P-256 private JWK under p384",
        ErrKind::InvalidKey,
        ecdh::import_secret_key_jwk(
            EcdhVariant::P384,
            ecdh_secret_jwk("P-256", &x, &y, &d),
            agreement_options(true, true, false),
        )
        .await,
        "imported cross-curve material",
    )?;
    expect_err(
        "P-256 PKCS#8 under p384",
        ErrKind::InvalidKey,
        ecdh::import_secret_key_pkcs8(
            EcdhVariant::P384,
            pkcs8,
            agreement_options(true, true, false),
        )
        .await,
        "imported cross-curve material",
    )?;
    expect_err(
        "P-384 SPKI under p256",
        ErrKind::InvalidKey,
        ecdh::import_public_key_spki(EcdhVariant::P256, p384_spki).await,
        "imported cross-curve material",
    )?;
    expect_err(
        "P-384 private JWK under p256",
        ErrKind::InvalidKey,
        ecdh::import_secret_key_jwk(
            EcdhVariant::P256,
            p384_jwk,
            agreement_options(true, true, false),
        )
        .await,
        "imported cross-curve material",
    )?;
    expect_err(
        "P-384 PKCS#8 under p256",
        ErrKind::InvalidKey,
        ecdh::import_secret_key_pkcs8(
            EcdhVariant::P256,
            p384_pkcs8,
            agreement_options(true, true, false),
        )
        .await,
        "imported cross-curve material",
    )?;

    // P-521 is declared but unserved: minting declines `unsupported`.
    expect_err(
        "import-public-key-raw (p521)",
        ErrKind::Unsupported,
        ecdh::import_public_key_raw(EcdhVariant::P521, vec![0x04; 133]).await,
        "served the unserved curve",
    )?;
    expect_err(
        "generate-key (p521)",
        ErrKind::Unsupported,
        ecdh::generate_key(EcdhVariant::P521, agreement_options(true, true, false)).await,
        "served the unserved curve",
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
    use polymorph_webcrypto_guest::bindings::sha1_checked;
    use polymorph_webcrypto_guest::bindings::types::Error;

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
            let got = compute_ok(digest, b"abc", schedule, "compute (honest input)").await?;
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
        let got = compute_op(&rejecting, m, Schedule::Whole).await?;
        match got {
            Err(Error::Extension(ext))
                if ext.origin == "polymorph:webcrypto"
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
    let d1 = compute_ok(&mitigating, &m1, Schedule::Whole, "mitigating compute").await?;
    let d2 = compute_ok(&mitigating, &m2, Schedule::Whole, "mitigating compute").await?;
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
    use polymorph_webcrypto_guest::bindings::sha1_checked;

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

// NIST SP 800-38A F.5: the CTR known-answer inputs (the same plaintext
// and initial counter block at both served key sizes).
const SP800_38A_CTR_IV: &str = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
const SP800_38A_PLAINTEXT: &str = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";

/// AES-CTR known answers (NIST SP 800-38A F.5.1/F.5.5) plus the wrapping
/// counter contract, self-consistently: a message enciphered under a
/// narrow counter must equal its blocks enciphered one at a time at the
/// wrapped counter values, so the two implementations cannot disagree on
/// the wrap without disagreeing here.
async fn ctr_known_answers() -> Result<(), String> {
    let iv = unhex(SP800_38A_CTR_IV);
    let plaintext = unhex(SP800_38A_PLAINTEXT);
    for (variant, key, expected) in [
        (
            AesVariant::Aes128,
            unhex("2b7e151628aed2a6abf7158809cf4f3c"),
            unhex("874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee"),
        ),
        (
            AesVariant::Aes256,
            unhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
            unhex("601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6"),
        ),
    ] {
        let key = import_ctr_key(variant, key, false)
            .await
            .map_err(|e| describe("import-key-raw", &e))?;
        for schedule in [Schedule::Whole, Schedule::Straddle] {
            let sealed = ci_encrypt_ok(&key, &iv, Some(128), &plaintext, schedule, "encrypt").await?;
            expect_bytes(&sealed, &expected, "SP 800-38A ciphertext")?;
        }
        let opened =
            ci_decrypt_ok(&key, &iv, Some(128), &expected, Schedule::Whole, "decrypt").await?;
        expect_bytes(&opened, &plaintext, "SP 800-38A round trip")?;
    }

    // The wrap: a 2-bit counter starting at 3 covers counters 3, 0, 1, 2
    // without carrying into the fixed portion.
    let key = import_ctr_key(AesVariant::Aes256, vec![3; 32], false)
        .await
        .map_err(|e| describe("import-key-raw", &e))?;
    let mut iv = [0xabu8; 16];
    iv[15] = 0xff;
    let sealed = ci_encrypt_ok(
        &key,
        &iv,
        Some(2),
        &[0; 64],
        Schedule::Whole,
        "encrypt (2-bit counter)",
    )
    .await?;
    for (i, low) in [0xffu8, 0xfc, 0xfd, 0xfe].into_iter().enumerate() {
        let mut counter = [0xabu8; 16];
        counter[15] = low;
        let (block, fed) = ci_encrypt(&key, &counter, Some(128), &[0; 16], Schedule::Whole).await;
        fed.map_err(|e| format!("encrypt block feeder: {e}"))?;
        let block = block.map_err(|e| describe("encrypt (single block)", &e))?;
        expect_bytes(
            &sealed[i * 16..(i + 1) * 16],
            &block,
            &format!("wrapped counter block {i}"),
        )?;
    }

    // And a message needing more blocks than the counter space holds
    // fails rather than reuse counter values.
    let sealed = ci_encrypt_op(&key, &iv, Some(2), &[0; 80], Schedule::Whole).await?;
    expect_err(
        "encrypt past the counter space",
        ErrKind::Other,
        sealed,
        "enciphered more blocks than the counter width holds",
    )
}

/// The per-call parameter contract on both modes: IV length, and the
/// counter-length presence, absence, and range rules — all
/// `invalid-nonce`.
async fn cipher_params_contract() -> Result<(), String> {
    let cbc = import_cbc_key(AesVariant::Aes256, vec![1; 32], false)
        .await
        .map_err(|e| describe("import-key-raw (cbc)", &e))?;
    let ctr = import_ctr_key(AesVariant::Aes256, vec![1; 32], false)
        .await
        .map_err(|e| describe("import-key-raw (ctr)", &e))?;

    for (what, key, iv_len, counter) in [
        ("15-byte cbc iv", &cbc, 15usize, None),
        ("17-byte cbc iv", &cbc, 17, None),
        ("cbc with a counter length", &cbc, 16, Some(64u8)),
        ("ctr without a counter length", &ctr, 16, None),
        ("ctr counter length 0", &ctr, 16, Some(0)),
        ("ctr counter length 129", &ctr, 16, Some(129)),
        ("15-byte ctr counter block", &ctr, 15, Some(64)),
    ] {
        let sealed = ci_encrypt_op(key, &vec![0; iv_len], counter, b"x", Schedule::Whole).await?;
        expect_err(
            what,
            ErrKind::InvalidNonce,
            sealed,
            "accepted bad parameters",
        )?;
        let opened =
            ci_decrypt_op(key, &vec![0; iv_len], counter, &[0; 16], Schedule::Whole).await?;
        expect_err(
            what,
            ErrKind::InvalidNonce,
            opened,
            "accepted bad parameters",
        )?;
    }
    Ok(())
}

/// The cipher kind's uniform-failure rule, pinned to the byte: an empty
/// ciphertext, a misaligned one, and one whose padding is corrupt render
/// the *identical* error — kind and message — because any second
/// rendering would be a distinguishable padding verdict.
async fn cbc_uniform_failure() -> Result<(), String> {
    let key = import_cbc_key(AesVariant::Aes256, vec![7; 32], false)
        .await
        .map_err(|e| describe("import-key-raw", &e))?;
    let iv = [0u8; 16];

    // A ciphertext with valid shape but corrupt padding: encrypt, then
    // flip a bit in the final block.
    let mut corrupted = ci_encrypt_ok(
        &key,
        &iv,
        None,
        b"uniform failure payload",
        Schedule::Whole,
        "encrypt",
    )
    .await?;
    let last = corrupted.len() - 1;
    corrupted[last] ^= 0x01;

    for (what, ciphertext) in [
        ("empty ciphertext", vec![]),
        ("misaligned ciphertext", vec![1; 15]),
        ("corrupt padding", corrupted),
    ] {
        let opened = ci_decrypt_op(&key, &iv, None, &ciphertext, Schedule::Whole).await?;
        match opened {
            Err(Error::Other(detail)) if detail == "AES-CBC decryption failed" => {}
            Err(other) => {
                return Err(describe(
                    &format!("{what}: expected the uniform failure, got"),
                    &other,
                ))
            }
            Ok(_) => return Err(format!("{what} decrypted")),
        }
    }
    Ok(())
}

/// `derive-key` on both cipher minting interfaces agrees with
/// `derive-bits` + `import-key-raw` over the same HKDF derivation (the
/// `hkdf_derive_key_equivalence` pattern).
async fn cipher_derive_key() -> Result<(), String> {
    use polymorph_webcrypto_guest::bindings::{aes_cbc, aes_ctr, hkdf_sha2};

    let ikm = import_ikm(vec![0x0b; 22], true, true)
        .await
        .map_err(|e| describe("import-ikm", &e))?;
    let input = hkdf_sha2::prepare(
        polymorph_webcrypto_guest::bindings::sha2::Sha2Variant::Sha256,
        &ikm,
        b"salt".to_vec(),
        b"info".to_vec(),
    )
    .await
    .map_err(|e| describe("hkdf-sha2.prepare", &e))?;
    let bits = input
        .derive_bits(Some(256))
        .await
        .map_err(|e| describe("derive-bits", &e))?;

    let iv = [5u8; 16];
    let payload = b"derive-key equivalence payload";
    for mode in ["cbc", "ctr"] {
        let derived = match mode {
            "cbc" => {
                aes_cbc::derive_key(
                    AesVariant::Aes256,
                    &input,
                    crate::mint::cipher_options(false),
                )
                .await
            }
            _ => {
                aes_ctr::derive_key(
                    AesVariant::Aes256,
                    &input,
                    crate::mint::cipher_options(false),
                )
                .await
            }
        }
        .map_err(|e| describe(&format!("{mode} derive-key"), &e))?;
        let imported = match mode {
            "cbc" => import_cbc_key(AesVariant::Aes256, bits.clone(), false).await,
            _ => import_ctr_key(AesVariant::Aes256, bits.clone(), false).await,
        }
        .map_err(|e| describe("import-key-raw of the derived bits", &e))?;

        let counter = if mode == "ctr" { Some(64) } else { None };
        let sealed = ci_encrypt_ok(
            &derived,
            &iv,
            counter,
            payload,
            Schedule::Whole,
            "encrypt (derived key)",
        )
        .await?;
        let opened = ci_decrypt_ok(
            &imported,
            &iv,
            counter,
            &sealed,
            Schedule::Whole,
            "decrypt (imported bits)",
        )
        .await?;
        expect_bytes(&opened, payload, &format!("{mode} derive-key equivalence"))?;
    }
    Ok(())
}

/// The SHA-1 derive surface the vectors cannot express: HMAC-SHA-1
/// `derive-key` agrees with `derive-bits` + import, the SHA-1 KDF prepare
/// steps ride the shared `ikm`/`password` resources (one source
/// parameterizes either hash family), and the SHA-1 KDFs enforce the
/// shared chaining and iteration rules.
async fn sha1_derive_surface() -> Result<(), String> {
    use crate::mint::mac_options;
    use polymorph_webcrypto_guest::bindings::{
        hkdf_sha1, hkdf_sha2, hmac_sha1, pbkdf2_sha1, pbkdf2_sha2,
    };

    // The SHA-1 KDF prepare steps ride the shared resources, and
    // `derive-key` agrees with `derive-bits` + import.
    let payload = b"sha1 family payload";
    let ikm = import_ikm(vec![0x0b; 22], true, true)
        .await
        .map_err(|e| describe("import-ikm", &e))?;
    let input = hkdf_sha1::prepare(&ikm, b"salt".to_vec(), b"info".to_vec())
        .await
        .map_err(|e| describe("hkdf-sha1.prepare", &e))?;
    let bits = input
        .derive_bits(Some(160))
        .await
        .map_err(|e| describe("derive-bits", &e))?;
    let derived = hmac_sha1::derive_key(&input, Some(160), mac_options(false))
        .await
        .map_err(|e| describe("hmac-sha1.derive-key", &e))?;
    let imported = import_hmac_sha1_key(bits.clone(), false)
        .await
        .map_err(|e| describe("import of the derived bits", &e))?;
    let tag = sign_ok(&derived, payload, Schedule::Whole).await?;
    verify_ok(
        &imported,
        payload,
        &tag,
        Schedule::Whole,
        "derive-key disagreed with derive-bits + import",
    )
    .await?;

    // Chaining: `hkdf-sha1.prepare-from` rejects a KDF source exactly as
    // `hkdf-sha2.prepare-from` does (only agreements have a natural length).
    expect_err(
        "hkdf-sha1.prepare-from a KDF source",
        ErrKind::Other,
        hkdf_sha1::prepare_from(&input, b"s".to_vec(), b"i".to_vec()).await,
        "chained from a source with no natural length",
    )?;
    // And the SHA-2 chain from the same resources still works: one ikm
    // parameterizes either hash family.
    hkdf_sha2::prepare(
        polymorph_webcrypto_guest::bindings::sha2::Sha2Variant::Sha256,
        &ikm,
        b"salt".to_vec(),
        b"info".to_vec(),
    )
    .await
    .map_err(|e| describe("hkdf-sha2.prepare over the same ikm", &e))?;

    // PBKDF2-SHA-1: the zero-iteration refusal, on the shared password.
    let password = import_password(b"password".to_vec(), true, true)
        .await
        .map_err(|e| describe("import-password", &e))?;
    expect_err(
        "pbkdf2-sha1.prepare with zero iterations",
        ErrKind::Other,
        pbkdf2_sha1::prepare(&password, b"salt".to_vec(), 0).await,
        "prepared a zero-iteration derivation",
    )?;
    pbkdf2_sha2::prepare(
        polymorph_webcrypto_guest::bindings::sha2::Sha2Variant::Sha256,
        &password,
        b"salt".to_vec(),
        1,
    )
    .await
    .map_err(|e| describe("pbkdf2-sha2.prepare over the same password", &e))?;
    Ok(())
}

/// The wrap operations on `aead-key`: `wrap` is byte-identical to sealing
/// the exported bytes, `unwrap` verifies (a tampered wrap fails
/// `authentication-failed`), and the raw unwrap mint recovers the material.
async fn aead_wrap_operations() -> Result<(), String> {
    use polymorph_webcrypto_guest::bindings::hmac_sha2;

    let kek = generate_key(AesVariant::Aes256, false)
        .await
        .map_err(|e| describe("kek generate", &e))?;
    let payload = import_hmac_key(Sha2Variant::Sha256, vec![0x42u8; 20], true)
        .await
        .map_err(|e| describe("payload import", &e))?;
    let nonce = [7u8; 12];

    let input = payload
        .to_wrap_input_raw()
        .await
        .map_err(|e| describe("to-wrap-input-raw", &e))?;
    let wrapped = kek
        .wrap(nonce.to_vec(), b"aad".to_vec(), None, input)
        .await
        .map_err(|e| describe("aead-key.wrap", &e))?;
    let exported = payload
        .export_key_raw()
        .await
        .map_err(|e| describe("payload export", &e))?;
    let (sealed, fed) = seal(&kek, &nonce, b"aad", None, &exported, Schedule::Whole).await;
    fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
    let sealed = sealed.map_err(|e| describe("seal comparison", &e))?;
    expect_bytes(&wrapped, &sealed, "wrap vs seal over the export")?;

    let mut tampered = wrapped.clone();
    tampered[0] ^= 1;
    expect_err(
        "unwrap of a tampered wrap",
        ErrKind::AuthenticationFailed,
        kek.unwrap(nonce.to_vec(), b"aad".to_vec(), None, tampered)
            .await,
        "tampered wrap unwrapped",
    )?;

    let unwrapped = kek
        .unwrap(nonce.to_vec(), b"aad".to_vec(), None, wrapped)
        .await
        .map_err(|e| describe("aead-key.unwrap", &e))?;
    let minted = hmac_sha2::unwrap_key_raw(Sha2Variant::Sha256, unwrapped, mac_options(true))
        .await
        .map_err(|e| describe("hmac-sha2.unwrap-key-raw", &e))?;
    let recovered = minted
        .export_key_raw()
        .await
        .map_err(|e| describe("minted export", &e))?;
    expect_bytes(&recovered, &[0x42u8; 20], "recovered material")
}

/// The wrap-input gates: `to-wrap-input-*` sits behind the source key's
/// extractability gate, exactly like the exports.
async fn wrap_input_gates() -> Result<(), String> {
    let sealed_key = import_hmac_key(Sha2Variant::Sha256, vec![9u8; 32], false)
        .await
        .map_err(|e| describe("import", &e))?;
    expect_err(
        "to-wrap-input-raw on a non-extractable key",
        ErrKind::NotExtractable,
        sealed_key.to_wrap_input_raw().await,
        "non-extractable material entered the wrap path",
    )?;
    expect_err(
        "to-wrap-input-jwk on a non-extractable key",
        ErrKind::NotExtractable,
        sealed_key.to_wrap_input_jwk().await,
        "non-extractable material entered the wrap path",
    )
}

/// The `kw-key` capability surface: getters, grants (a wrap-only key
/// refuses `unwrap`), the AES-192 decline on every minting path, exports,
/// and the unwrap domain (out-of-domain input is `authentication-failed`,
/// indistinguishable from a bad ICV).
async fn kw_key_contract() -> Result<(), String> {
    use polymorph_webcrypto_guest::bindings::aes_kw;
    use polymorph_webcrypto_guest::bindings::key_wrap::KwKeyOptions;

    let key = import_kw_key(AesVariant::Aes256, vec![1u8; 32], true)
        .await
        .map_err(|e| describe("import-key-raw", &e))?;
    expect(key.algorithm_name(), "AES-KW".to_string(), "algorithm-name")?;
    expect(key.algorithm_length(), 256, "algorithm-length")?;
    expect(key.extractable(), true, "extractable getter")?;
    let jwk = key
        .export_key_jwk()
        .await
        .map_err(|e| describe("export-key-jwk", &e))?;
    if !jwk.contains("\"A256KW\"") {
        return Err(format!("exported JWK lacks the A256KW alg: {jwk}"));
    }
    let back = aes_kw::import_key_jwk(AesVariant::Aes256, jwk.clone(), kw_options(true))
        .await
        .map_err(|e| describe("import-key-jwk", &e))?;
    expect_bytes(
        &back
            .export_key_raw()
            .await
            .map_err(|e| describe("export", &e))?,
        &[1u8; 32],
        "JWK round trip",
    )?;

    // Grants.
    let options = KwKeyOptions::new();
    options.can_wrap(true);
    let wrap_only = aes_kw::generate_key(AesVariant::Aes128, options)
        .await
        .map_err(|e| describe("wrap-only generate", &e))?;
    expect(wrap_only.can_wrap(), true, "wrap-only can-wrap")?;
    expect(wrap_only.can_unwrap(), false, "wrap-only can-unwrap")?;
    expect_err(
        "unwrap on a wrap-only key",
        ErrKind::NotPermitted,
        wrap_only.unwrap(vec![0u8; 24]).await,
        "wrap-only key unwrapped",
    )?;
    expect_err(
        "zero-usage kw mint",
        ErrKind::NotPermitted,
        aes_kw::generate_key(AesVariant::Aes128, KwKeyOptions::new()).await,
        "zero-usage options minted",
    )?;

    // AES-192 declines on every minting path.
    expect_err(
        "aes-kw import-key-raw AES-192",
        ErrKind::Unsupported,
        import_kw_key(AesVariant::Aes192, vec![0u8; 24], false).await,
        "AES-192 kw key minted",
    )?;
    expect_err(
        "aes-kw generate-key AES-192",
        ErrKind::Unsupported,
        generate_kw_key(AesVariant::Aes192, false).await,
        "AES-192 kw key generated",
    )?;

    // Unwrap domain: under 24 bytes, or off the 8-byte grid.
    let key = import_kw_key(AesVariant::Aes256, vec![1u8; 32], false)
        .await
        .map_err(|e| describe("import", &e))?;
    for bad in [vec![0u8; 16], vec![0u8; 20], Vec::new()] {
        expect_err(
            "unwrap outside the wrapped-form domain",
            ErrKind::AuthenticationFailed,
            key.unwrap(bad).await,
            "out-of-domain wrapped form unwrapped",
        )?;
    }
    // Wrap domain: off-grid or under 16 bytes fails invalid-key.
    let short = import_hmac_key(Sha2Variant::Sha256, vec![2u8; 9], true)
        .await
        .map_err(|e| describe("short payload import", &e))?;
    expect_err(
        "wrap outside the input domain",
        ErrKind::InvalidKey,
        key.wrap(
            short
                .to_wrap_input_raw()
                .await
                .map_err(|e| describe("to-wrap-input", &e))?,
        )
        .await,
        "out-of-domain material wrapped",
    )
}

/// The AES-KW JWK padding rule: a JWK-format wrap-input is space-padded to
/// a multiple of 8 (observable in the wrapped length), and the JWK unwrap
/// mint's parse tolerates the trailing padding.
async fn kw_jwk_padding() -> Result<(), String> {
    use polymorph_webcrypto_guest::bindings::hmac_sha2;

    let kek = generate_kw_key(AesVariant::Aes128, false)
        .await
        .map_err(|e| describe("kek generate", &e))?;
    let payload = import_hmac_key(Sha2Variant::Sha256, vec![5u8; 20], true)
        .await
        .map_err(|e| describe("payload import", &e))?;
    let jwk_len = payload
        .export_key_jwk()
        .await
        .map_err(|e| describe("payload export-key-jwk", &e))?
        .len();
    let input = payload
        .to_wrap_input_jwk()
        .await
        .map_err(|e| describe("to-wrap-input-jwk", &e))?;
    let wrapped = kek.wrap(input).await.map_err(|e| describe("wrap", &e))?;
    expect(
        wrapped.len(),
        jwk_len.div_ceil(8) * 8 + 8,
        "wrapped length carries the space padding",
    )?;
    let minted = hmac_sha2::unwrap_key_jwk(
        Sha2Variant::Sha256,
        kek.unwrap(wrapped.clone())
            .await
            .map_err(|e| describe("unwrap", &e))?,
        mac_options(true),
    )
    .await
    .map_err(|e| describe("hmac-sha2.unwrap-key-jwk", &e))?;
    expect_bytes(
        &minted
            .export_key_raw()
            .await
            .map_err(|e| describe("export", &e))?,
        &[5u8; 20],
        "JWK-wrapped material",
    )
}

/// The cipher kind's wrap surface keeps the uniform-failure rule: a
/// malformed CBC unwrap fails with the mode's one fixed `other` message,
/// never `authentication-failed`.
async fn cipher_wrap_uniform_failure() -> Result<(), String> {
    use polymorph_webcrypto_guest::bindings::aes_cbc;

    // Full grants: the comparison below runs both `wrap` and `encrypt` on
    // one key (grant enforcement is `cipher_usage_policy`'s subject).
    let kek = aes_cbc::generate_key(AesVariant::Aes256, crate::mint::cipher_options(false))
        .await
        .map_err(|e| describe("kek generate", &e))?;
    match kek.unwrap(vec![0u8; 16], None, vec![1u8; 15]).await {
        Err(Error::Other(detail)) if detail == "AES-CBC decryption failed" => {}
        Err(other) => {
            return Err(describe(
                "cipher unwrap: expected the uniform failure, got",
                &other,
            ))
        }
        Ok(_) => return Err("unwrapped a malformed CBC wrap".into()),
    }
    // The wrap path is encrypt over the serialized material.
    let payload = import_hmac_key(Sha2Variant::Sha256, vec![3u8; 16], true)
        .await
        .map_err(|e| describe("payload import", &e))?;
    let wrapped = kek
        .wrap(
            vec![9u8; 16],
            None,
            payload
                .to_wrap_input_raw()
                .await
                .map_err(|e| describe("to-wrap-input", &e))?,
        )
        .await
        .map_err(|e| describe("cipher-key.wrap", &e))?;
    let (sealed, fed) = ci_encrypt(&kek, &[9u8; 16], None, &[3u8; 16], Schedule::Whole).await;
    fed.map_err(|e| format!("encrypt feeder: {e}"))?;
    let sealed = sealed.map_err(|e| describe("encrypt comparison", &e))?;
    expect_bytes(&wrapped, &sealed, "cipher wrap vs encrypt over the export")
}

/// The unwrap-path JWK `use`/`key_ops` checks: the mints validate the two
/// members in the caller's stead, with fixed `invalid-key` messages.
async fn unwrap_jwk_usage_members() -> Result<(), String> {
    use polymorph_webcrypto_guest::bindings::hmac_sha2;
    use polymorph_webcrypto_guest::bindings::mac::MacKeyOptions;

    let kek = generate_key(AesVariant::Aes256, false)
        .await
        .map_err(|e| describe("kek generate", &e))?;
    let nonce = [8u8; 12];

    // The export path strips use/key_ops, so a member-carrying JWK enters
    // the wrap path as an HMAC key's raw bytes: what unwraps is exactly
    // the hand-built text.
    let carrying = format!(
        "{{\"kty\":\"oct\",\"k\":\"{}\",\"use\":\"sig\",\"key_ops\":[\"sign\"]}}",
        conformance_harness::b64url(&[6u8; 32]),
    );
    let as_material = import_hmac_key(Sha2Variant::Sha256, carrying.into_bytes(), true)
        .await
        .map_err(|e| describe("carrier import", &e))?;
    let wrapped = kek
        .wrap(
            nonce.to_vec(),
            b"".to_vec(),
            None,
            as_material
                .to_wrap_input_raw()
                .await
                .map_err(|e| describe("to-wrap-input", &e))?,
        )
        .await
        .map_err(|e| describe("wrap", &e))?;

    // A mint whose grants exceed the JWK's key_ops fails invalid-key…
    let options = MacKeyOptions::new();
    options.can_sign(true);
    options.can_verify(true);
    match hmac_sha2::unwrap_key_jwk(
        Sha2Variant::Sha256,
        kek.unwrap(nonce.to_vec(), b"".to_vec(), None, wrapped.clone())
            .await
            .map_err(|e| describe("unwrap", &e))?,
        options,
    )
    .await
    {
        Err(Error::InvalidKey(msg)) => {
            if msg.contains("sig") || msg.contains("sign") || msg.contains("{") {
                return Err(format!("unwrap-mint message echoes the JWK: {msg}"));
            }
        }
        Err(other) => {
            return Err(describe(
                "key_ops mismatch: expected invalid-key, got",
                &other,
            ))
        }
        Ok(_) => return Err("minted past a key_ops member missing a granted usage".into()),
    }

    // …and a sign-only mint (within key_ops, matching use) succeeds.
    let options = MacKeyOptions::new();
    options.can_sign(true);
    hmac_sha2::unwrap_key_jwk(
        Sha2Variant::Sha256,
        kek.unwrap(nonce.to_vec(), b"".to_vec(), None, wrapped)
            .await
            .map_err(|e| describe("second unwrap", &e))?,
        options,
    )
    .await
    .map_err(|e| describe("conforming unwrap-key-jwk", &e))?;
    Ok(())
}

/// The KDF unwrap doors: a secret can arrive wrapped and parameterize
/// derivations without its bytes ever surfacing, agreeing with the same
/// secret imported directly.
async fn kdf_secret_unwrap() -> Result<(), String> {
    use polymorph_webcrypto_guest::bindings::{hkdf, hkdf_sha2, pbkdf2, pbkdf2_sha2};

    let kek = generate_key(AesVariant::Aes256, false)
        .await
        .map_err(|e| describe("kek generate", &e))?;
    let secret = vec![0x11u8; 22];
    let carrier = import_hmac_key(Sha2Variant::Sha256, secret.clone(), true)
        .await
        .map_err(|e| describe("carrier import", &e))?;
    let nonce = [4u8; 12];
    let wrapped = kek
        .wrap(
            nonce.to_vec(),
            b"".to_vec(),
            None,
            carrier
                .to_wrap_input_raw()
                .await
                .map_err(|e| describe("to-wrap-input", &e))?,
        )
        .await
        .map_err(|e| describe("wrap", &e))?;

    // HKDF: unwrapped IKM derives the same bits as directly imported IKM.
    let unwrapped_ikm = hkdf::unwrap_ikm(
        kek.unwrap(nonce.to_vec(), b"".to_vec(), None, wrapped)
            .await
            .map_err(|e| describe("unwrap", &e))?,
        derive_options(true, true),
    )
    .await
    .map_err(|e| describe("hkdf.unwrap-ikm", &e))?;
    let direct_ikm = import_ikm(secret.clone(), true, true)
        .await
        .map_err(|e| describe("direct import-ikm", &e))?;
    let via_unwrap = hkdf_sha2::prepare(
        Sha2Variant::Sha256,
        &unwrapped_ikm,
        b"salt".to_vec(),
        b"info".to_vec(),
    )
    .await
    .map_err(|e| describe("prepare", &e))?
    .derive_bits(Some(256))
    .await
    .map_err(|e| describe("derive-bits", &e))?;
    let via_import = hkdf_sha2::prepare(
        Sha2Variant::Sha256,
        &direct_ikm,
        b"salt".to_vec(),
        b"info".to_vec(),
    )
    .await
    .map_err(|e| describe("prepare (direct)", &e))?
    .derive_bits(Some(256))
    .await
    .map_err(|e| describe("derive-bits (direct)", &e))?;
    expect_bytes(&via_unwrap, &via_import, "HKDF bits via unwrap-ikm")?;

    // PBKDF2: the same, through unwrap-password.
    let wrapped = kek
        .wrap(
            nonce.to_vec(),
            b"pw".to_vec(),
            None,
            carrier
                .to_wrap_input_raw()
                .await
                .map_err(|e| describe("to-wrap-input", &e))?,
        )
        .await
        .map_err(|e| describe("wrap (password)", &e))?;
    let unwrapped_pw = pbkdf2::unwrap_password(
        kek.unwrap(nonce.to_vec(), b"pw".to_vec(), None, wrapped)
            .await
            .map_err(|e| describe("unwrap (password)", &e))?,
        derive_options(true, true),
    )
    .await
    .map_err(|e| describe("pbkdf2.unwrap-password", &e))?;
    let direct_pw = import_password(secret, true, true)
        .await
        .map_err(|e| describe("direct import-password", &e))?;
    let via_unwrap =
        pbkdf2_sha2::prepare(Sha2Variant::Sha256, &unwrapped_pw, b"salt".to_vec(), 1000)
            .await
            .map_err(|e| describe("pbkdf2 prepare", &e))?
            .derive_bits(Some(256))
            .await
            .map_err(|e| describe("pbkdf2 derive-bits", &e))?;
    let via_import = pbkdf2_sha2::prepare(Sha2Variant::Sha256, &direct_pw, b"salt".to_vec(), 1000)
        .await
        .map_err(|e| describe("pbkdf2 prepare (direct)", &e))?
        .derive_bits(Some(256))
        .await
        .map_err(|e| describe("pbkdf2 derive-bits (direct)", &e))?;
    expect_bytes(&via_unwrap, &via_import, "PBKDF2 bits via unwrap-password")
}

/// Wrap `input` under the AEAD `kek` and unwrap it back: the transport
/// leg every unwrap-mint probe shares.
async fn wrap_then_unwrap(
    kek: &polymorph_webcrypto_guest::bindings::aead::AeadKey,
    input: polymorph_webcrypto_guest::bindings::wrapping::WrapInput,
) -> Result<polymorph_webcrypto_guest::bindings::wrapping::UnwrapInput, String> {
    let nonce = [0x51u8; 12];
    let wrapped = kek
        .wrap(nonce.to_vec(), b"unwrap-mint probe".to_vec(), None, input)
        .await
        .map_err(|e| describe("aead-key.wrap", &e))?;
    kek.unwrap(nonce.to_vec(), b"unwrap-mint probe".to_vec(), None, wrapped)
        .await
        .map_err(|e| describe("aead-key.unwrap", &e))
}

/// The private-signature unwrap mints: an Ed25519 signing key wrapped as
/// PKCS#8 and as a JWK mints back out through `unwrap-signing-key-*`,
/// signs, and verifies under the original public half; the minted key
/// carries the mint's options.
async fn signing_key_unwrap() -> Result<(), String> {
    use polymorph_webcrypto_guest::bindings::ed25519_sign;

    let (key, public) = generate_ed25519_key(true)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    let kek = generate_key(AesVariant::Aes256, false)
        .await
        .map_err(|e| describe("kek generate", &e))?;
    let payload = b"unwrap-minted signature";

    let input = key
        .to_wrap_input_pkcs8()
        .await
        .map_err(|e| describe("to-wrap-input-pkcs8", &e))?;
    let minted = ed25519_sign::unwrap_signing_key_pkcs8(
        wrap_then_unwrap(&kek, input).await?,
        signing_options(false),
    )
    .await
    .map_err(|e| describe("unwrap-signing-key-pkcs8", &e))?;
    expect(
        minted.extractable(),
        false,
        "pkcs8-minted extractable getter",
    )?;
    expect(minted.can_sign(), true, "pkcs8-minted can-sign getter")?;
    let sig = sig_sign_ok(&minted, payload, Schedule::Whole).await?;
    sig_verify_ok(
        &public,
        payload,
        &sig,
        Schedule::Whole,
        "pkcs8-minted signature did not verify",
    )
    .await?;

    let input = key
        .to_wrap_input_jwk()
        .await
        .map_err(|e| describe("to-wrap-input-jwk", &e))?;
    let minted = ed25519_sign::unwrap_signing_key_jwk(
        wrap_then_unwrap(&kek, input).await?,
        signing_options(false),
    )
    .await
    .map_err(|e| describe("unwrap-signing-key-jwk", &e))?;
    let sig = sig_sign_ok(&minted, payload, Schedule::Whole).await?;
    sig_verify_ok(
        &public,
        payload,
        &sig,
        Schedule::Whole,
        "jwk-minted signature did not verify",
    )
    .await
}

/// The agreement unwrap mints: RFC 7748 §6.1's Alice secret, wrapped as a
/// JWK and as PKCS#8, mints back out through `unwrap-secret-key-*` and
/// agrees with Bob's public to the vector's shared secret.
async fn agreement_key_unwrap() -> Result<(), String> {
    use polymorph_webcrypto_guest::bindings::x25519;

    let secret = x25519::import_secret_key_jwk(
        x25519_secret_jwk(&unhex(RFC7748_ALICE_X), &unhex(RFC7748_ALICE_D)),
        agreement_options(true, true, true),
    )
    .await
    .map_err(|e| describe("import-secret-key-jwk", &e))?;
    let peer = import_x25519_public_key(unhex(RFC7748_BOB_X))
        .await
        .map_err(|e| describe("import-public-key-raw", &e))?;
    let kek = generate_key(AesVariant::Aes256, false)
        .await
        .map_err(|e| describe("kek generate", &e))?;

    let input = secret
        .to_wrap_input_jwk()
        .await
        .map_err(|e| describe("to-wrap-input-jwk", &e))?;
    let minted = x25519::unwrap_secret_key_jwk(
        wrap_then_unwrap(&kek, input).await?,
        agreement_options(true, true, false),
    )
    .await
    .map_err(|e| describe("unwrap-secret-key-jwk", &e))?;
    let shared = minted
        .agree(&peer)
        .await
        .map_err(|e| describe("agree (jwk-minted)", &e))?
        .derive_bits(None)
        .await
        .map_err(|e| describe("derive-bits (jwk-minted)", &e))?;
    expect_bytes(&shared, &unhex(RFC7748_SHARED), "jwk-minted shared secret")?;

    let input = secret
        .to_wrap_input_pkcs8()
        .await
        .map_err(|e| describe("to-wrap-input-pkcs8", &e))?;
    let minted = x25519::unwrap_secret_key_pkcs8(
        wrap_then_unwrap(&kek, input).await?,
        agreement_options(true, true, false),
    )
    .await
    .map_err(|e| describe("unwrap-secret-key-pkcs8", &e))?;
    let shared = minted
        .agree(&peer)
        .await
        .map_err(|e| describe("agree (pkcs8-minted)", &e))?
        .derive_bits(None)
        .await
        .map_err(|e| describe("derive-bits (pkcs8-minted)", &e))?;
    expect_bytes(
        &shared,
        &unhex(RFC7748_SHARED),
        "pkcs8-minted shared secret",
    )
}

/// The unauthenticated modes' unwrap mints: an AES-CBC key travels raw
/// under an AES-KW KEK, an AES-CTR key travels as a JWK under an AEAD
/// KEK, and each minted key agrees with its original across an
/// encrypt/decrypt round trip.
async fn cipher_key_unwrap() -> Result<(), String> {
    use polymorph_webcrypto_guest::bindings::{aes_cbc, aes_ctr};

    let plaintext = b"cipher unwrap-mint probe";

    let original = import_cbc_key(AesVariant::Aes256, vec![0x2au8; 32], true)
        .await
        .map_err(|e| describe("cbc import", &e))?;
    let kw_kek = generate_kw_key(AesVariant::Aes128, false)
        .await
        .map_err(|e| describe("kw kek generate", &e))?;
    let input = original
        .to_wrap_input_raw()
        .await
        .map_err(|e| describe("to-wrap-input-raw", &e))?;
    let wrapped = kw_kek
        .wrap(input)
        .await
        .map_err(|e| describe("kw-key.wrap", &e))?;
    let minted = aes_cbc::unwrap_key_raw(
        AesVariant::Aes256,
        kw_kek
            .unwrap(wrapped)
            .await
            .map_err(|e| describe("kw-key.unwrap", &e))?,
        cipher_options(false),
    )
    .await
    .map_err(|e| describe("aes-cbc.unwrap-key-raw", &e))?;
    let iv = [7u8; 16];
    let sealed = ci_encrypt_ok(
        &minted,
        &iv,
        None,
        plaintext,
        Schedule::Whole,
        "encrypt under the raw-minted key",
    )
    .await?;
    let opened = ci_decrypt_ok(
        &original,
        &iv,
        None,
        &sealed,
        Schedule::Whole,
        "decrypt under the original",
    )
    .await?;
    expect_bytes(&opened, plaintext, "CBC unwrap-mint round trip")?;

    let original = import_ctr_key(AesVariant::Aes128, vec![0x3cu8; 16], true)
        .await
        .map_err(|e| describe("ctr import", &e))?;
    let kek = generate_key(AesVariant::Aes256, false)
        .await
        .map_err(|e| describe("kek generate", &e))?;
    let input = original
        .to_wrap_input_jwk()
        .await
        .map_err(|e| describe("to-wrap-input-jwk", &e))?;
    let minted = aes_ctr::unwrap_key_jwk(
        AesVariant::Aes128,
        wrap_then_unwrap(&kek, input).await?,
        cipher_options(false),
    )
    .await
    .map_err(|e| describe("aes-ctr.unwrap-key-jwk", &e))?;
    let sealed = ci_encrypt_ok(
        &original,
        &iv,
        Some(64),
        plaintext,
        Schedule::Whole,
        "encrypt under the original",
    )
    .await?;
    let opened = ci_decrypt_ok(
        &minted,
        &iv,
        Some(64),
        &sealed,
        Schedule::Whole,
        "decrypt under the jwk-minted key",
    )
    .await?;
    expect_bytes(&opened, plaintext, "CTR unwrap-mint round trip")
}
