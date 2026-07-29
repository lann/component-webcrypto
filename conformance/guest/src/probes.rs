//! Hand-written API-contract probes: the parts of the `lann:webcrypto`
//! contract the Wycheproof vectors cannot express — key import/export and
//! extractability, error variants for misuse, the seal/open drain rule,
//! generated-key shape, and algorithm naming.

use conformance_harness::probes;

use crate::translate::Schedule;
use crate::util::{
    compute, describe, expect_bytes, in_open, in_seal, open, seal, sig_verify, sign, unhex, verify,
};
use crate::FEATURE_CHACHA;
use lann_webcrypto_guest::bindings::aead::AeadKey;
use lann_webcrypto_guest::bindings::aes_gcm::{generate_key, import_key, AesVariant};
use lann_webcrypto_guest::bindings::aes_gcm_internal_nonce::{
    generate_key as generate_internal_nonce_key, import_key as import_internal_nonce_key,
};
use lann_webcrypto_guest::bindings::bytes::constant_time_equal as bytes_constant_time_equal;
use lann_webcrypto_guest::bindings::chacha20_poly1305::{
    generate_key as generate_chacha_key, import_key as import_chacha_key,
};
use lann_webcrypto_guest::bindings::ecdsa_verify::{
    import_verifying_key as import_ecdsa_verifying_key, EcdsaVariant,
};
use lann_webcrypto_guest::bindings::ed25519_sign::{
    generate_key as generate_ed25519_key, import_signing_key as import_ed25519_signing_key,
};
use lann_webcrypto_guest::bindings::ed25519_verify::import_verifying_key as import_ed25519_verifying_key;
use lann_webcrypto_guest::bindings::hmac_sha2::{
    generate_key as generate_hmac_key, import_key as import_hmac_key,
};
use lann_webcrypto_guest::bindings::sha2::{make_digest, Sha2Variant};
use lann_webcrypto_guest::bindings::types::Error;
use lann_webcrypto_guest::bindings::xchacha20_poly1305::{
    generate_key as generate_xchacha_key, import_key as import_xchacha_key,
};
use lann_webcrypto_guest::bindings::xchacha20_poly1305_internal_nonce::{
    generate_key as generate_xchacha_internal_nonce_key,
    import_key as import_xchacha_internal_nonce_key,
};

/// The features a bare tag in the `probes!` table stands for. Which
/// features exist is this suite's business, not the harness's.
macro_rules! feature_tags {
    () => {
        &[]
    };
    (chacha) => {
        &[FEATURE_CHACHA]
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
    ed25519_sign_known_answer,
    open_short_input,
    stream_empty_writes,
    extractable_getter,
    hmac_generate_length,
}

/// Run the probe at `index` (into [`PROBES`]) on a target providing its
/// features.
pub async fn run_one(index: usize) -> Result<(), String> {
    match PROBES.get(index) {
        Some(probe) => (probe.run)().await,
        None => Err(format!("no probe at index {index}")),
    }
}

/// Run the probe at `index` on a target that declares its features missing:
/// assert the correct decline. Every feature-tagged probe here exercises
/// ChaCha20-Poly1305, so the assertion is shared — each ChaCha minting path
/// must fail `unsupported`. This is the two-way guarantee behind the plain
/// `skipped` the vector cases report: a target cannot silently serve a
/// feature it declares missing.
pub async fn run_declined(index: usize) -> Result<String, String> {
    match PROBES.get(index).map(|probe| probe.features) {
        Some(features) if features == [FEATURE_CHACHA] => chacha_minting_declined().await,
        Some(_) => Err("probe has no decline assertion for its features".into()),
        None => Err(format!("no probe at index {index}")),
    }
}

/// Assert that every ChaCha20-Poly1305 minting path declines `unsupported`.
async fn chacha_minting_declined() -> Result<String, String> {
    for (name, import, generate) in CHACHA_MINTERS {
        match import(vec![0x42u8; 32], false).await {
            Err(Error::Unsupported(_)) => {}
            Err(other) => {
                return Err(describe(
                    &format!("{name} import-key: expected unsupported from a missing feature, got"),
                    &other,
                ))
            }
            Ok(_) => {
                return Err(format!(
                "{name} import-key minted a key: the target serves a feature it declares missing"
            ))
            }
        }
        match generate(false).await {
            Err(Error::Unsupported(_)) => {}
            Err(other) => {
                return Err(describe(
                    &format!(
                        "{name} generate-key: expected unsupported from a missing feature, got"
                    ),
                    &other,
                ))
            }
            Ok(_) => {
                return Err(format!(
                "{name} generate-key minted a key: the target serves a feature it declares missing"
            ))
            }
        }
    }
    match generate_xchacha_internal_nonce_key(false).await {
        Err(Error::Unsupported(_)) => {}
        Err(other) => return Err(describe(
            "xchacha internal-nonce generate-key: expected unsupported from a missing feature, got",
            &other,
        )),
        Ok(_) => {
            return Err(
                "xchacha internal-nonce generate-key minted a key for a feature \
                 declared missing"
                    .into(),
            )
        }
    }
    // The internal-nonce *import* is a minting path too. Omitting it left a
    // target free to decline five of the six entry points and still serve
    // this one, which is the hole this assertion exists to close.
    match import_xchacha_internal_nonce_key(vec![0x42u8; 32], false).await {
        Err(Error::Unsupported(_)) => {}
        Err(other) => return Err(describe(
            "xchacha internal-nonce import-key: expected unsupported from a missing feature, got",
            &other,
        )),
        Ok(_) => {
            return Err(
                "xchacha internal-nonce import-key minted a key for a feature declared missing"
                    .into(),
            )
        }
    }
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
    match import_hmac_key(Sha2Variant::Sha256, Vec::new(), false).await {
        Err(Error::InvalidKey(_)) => Ok(()),
        Err(other) => Err(describe("expected invalid-key, got", &other)),
        Ok(_) => Err("empty HMAC key imported".into()),
    }
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
        if key.algorithm_hash().as_deref() != Some(hash) {
            return Err(format!(
                "{hash} key reports algorithm-hash {:?}",
                key.algorithm_hash()
            ));
        }
        let want: Vec<u8> = want_hex
            .replace(' ', "")
            .as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
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
        match import_hmac_key(variant, b"truncated".to_vec(), false).await {
            Err(Error::Unsupported(_)) => {}
            Err(other) => {
                return Err(describe(
                    &format!("import-key {variant:?}: expected unsupported, got"),
                    &other,
                ))
            }
            Ok(_) => return Err(format!("{variant:?} key imported")),
        }
        match generate_hmac_key(variant, None, false).await {
            Err(Error::Unsupported(_)) => {}
            Err(other) => {
                return Err(describe(
                    &format!("generate-key {variant:?}: expected unsupported, got"),
                    &other,
                ))
            }
            Ok(_) => return Err(format!("{variant:?} key generated")),
        }
        match make_digest(variant) {
            Err(Error::Unsupported(_)) => {}
            Err(other) => {
                return Err(describe(
                    &format!("make-digest {variant:?}: expected unsupported, got"),
                    &other,
                ))
            }
            Ok(_) => return Err(format!("{variant:?} digest minted")),
        }
    }
    Ok(())
}

/// Importing 16- or 24-byte material as an AES-256 key fails `invalid-key`.
async fn aes_import_wrong_length() -> Result<(), String> {
    for len in [16usize, 24] {
        match import_key(AesVariant::Aes256, vec![0u8; len], false).await {
            Err(Error::InvalidKey(_)) => {}
            Err(other) => {
                return Err(describe(
                    &format!("{len}-byte key: expected invalid-key, got"),
                    &other,
                ))
            }
            Ok(_) => return Err(format!("{len}-byte key imported as AES-256")),
        }
    }
    Ok(())
}

/// No implementation of this package serves AES-192 (see the WIT
/// `aes-variant` doc): both minting paths fail `unsupported`.
async fn aes192_unsupported() -> Result<(), String> {
    match import_key(AesVariant::Aes192, vec![0u8; 24], false).await {
        Err(Error::Unsupported(_)) => {}
        Err(other) => return Err(describe("import-key: expected unsupported, got", &other)),
        Ok(_) => return Err("AES-192 key imported".into()),
    }
    match generate_key(AesVariant::Aes192, false).await {
        Err(Error::Unsupported(_)) => Ok(()),
        Err(other) => Err(describe("generate-key: expected unsupported, got", &other)),
        Ok(_) => Err("AES-192 key generated".into()),
    }
}

/// `seal` with a bad nonce still drains the plaintext stream: the concurrent
/// feeder must complete, and the error must be `invalid-nonce`.
async fn seal_drains_on_invalid_nonce() -> Result<(), String> {
    let key = generate_key_256(false).await?;
    let plaintext: Vec<u8> = (0..=255u8).cycle().take(2048).collect();
    let (sealed, fed) = seal(
        &key,
        &[0u8; 8],
        b"probe aad",
        &plaintext,
        Schedule::Straddle,
    )
    .await;
    fed.map_err(|e| format!("plaintext feeder did not complete: {e}"))?;
    match sealed {
        Err(Error::InvalidNonce(_)) => Ok(()),
        Err(other) => Err(describe("expected invalid-nonce, got", &other)),
        Ok(_) => Err("8-byte nonce accepted".into()),
    }
}

/// `open` with a bad nonce still drains the ciphertext stream: the concurrent
/// feeder must complete, and the error must be `invalid-nonce`.
async fn open_drains_on_invalid_nonce() -> Result<(), String> {
    let key = generate_key_256(false).await?;
    let ciphertext: Vec<u8> = (0..=255u8).cycle().take(2048).collect();
    let (opened, fed) = open(
        &key,
        &[0u8; 8],
        b"probe aad",
        &ciphertext,
        Schedule::Straddle,
    )
    .await;
    fed.map_err(|e| format!("ciphertext feeder did not complete: {e}"))?;
    match opened {
        Err(Error::InvalidNonce(_)) => Ok(()),
        Err(other) => Err(describe("expected invalid-nonce, got", &other)),
        Ok(_) => Err("8-byte nonce accepted".into()),
    }
}

/// Sealed output is exactly plaintext length + the 16-byte tag, and the
/// size getters agree with the observed contract.
async fn sealed_length() -> Result<(), String> {
    let key = generate_key_256(false).await?;
    if key.nonce_size() != 12 {
        return Err(format!(
            "aead-key.nonce-size: got {}, want 12",
            key.nonce_size()
        ));
    }
    if key.tag_size() != 16 {
        return Err(format!(
            "aead-key.tag-size: got {}, want 16",
            key.tag_size()
        ));
    }
    for len in [0usize, 1, 15, 16, 17, 1024] {
        let plaintext = vec![0xa5u8; len];
        let (sealed, fed) = seal(&key, &[1u8; 12], b"", &plaintext, Schedule::Whole).await;
        fed.map_err(|e| format!("plaintext feeder ({len} bytes): {e}"))?;
        let sealed = sealed.map_err(|e| describe(&format!("seal of {len} bytes"), &e))?;
        if sealed.len() != len + 16 {
            return Err(format!(
                "sealed length for {len}-byte plaintext: got {}, want {}",
                sealed.len(),
                len + 16
            ));
        }
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
    match key.export_key().await {
        Err(Error::NotExtractable) => {}
        Err(other) => return Err(describe("hmac: expected not-extractable, got", &other)),
        Ok(_) => return Err("non-extractable HMAC key exported".into()),
    }

    let key = import_key(AesVariant::Aes256, vec![0x42u8; 32], false)
        .await
        .map_err(|e| describe("import-key", &e))?;
    match key.export_key().await {
        Err(Error::NotExtractable) => Ok(()),
        Err(other) => Err(describe("aes: expected not-extractable, got", &other)),
        Ok(_) => Err("non-extractable AES key exported".into()),
    }
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
    if exported.len() != 64 {
        return Err(format!(
            "generated HMAC key exports {} bytes, want 64 (SHA-256 block size)",
            exported.len()
        ));
    }

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
    if exported.len() != 32 {
        return Err(format!(
            "generated AES key exports {} bytes, want 32",
            exported.len()
        ));
    }

    let nonce = [7u8; 12];
    let plaintext: Vec<u8> = (0..=255u8).cycle().take(3 * 16 + 5).collect();
    let (sealed, fed) = seal(&aes_key, &nonce, b"shape aad", &plaintext, Schedule::Whole).await;
    fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
    let sealed = sealed.map_err(|e| describe("seal under generated key", &e))?;
    let (opened, fed) = open(&aes_key, &nonce, b"shape aad", &sealed, Schedule::Whole).await;
    fed.map_err(|e| format!("open ciphertext feeder: {e}"))?;
    let opened = opened.map_err(|e| describe("open under generated key", &e))?;
    expect_bytes(&opened, &plaintext, "round-tripped plaintext")
}

/// The algorithm getters report the bound algorithm on keys.
async fn algorithm_names() -> Result<(), String> {
    fn expect<T: PartialEq + std::fmt::Debug>(got: T, want: T, what: &str) -> Result<(), String> {
        if got == want {
            Ok(())
        } else {
            Err(format!("{what}: got {got:?}, want {want:?}"))
        }
    }

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
    if tag.len() != 32 {
        return Err(format!("tag length: got {}, want 32", tag.len()));
    }

    let (verified, fed) = verify(&key, payload, &tag[..31], Schedule::Whole).await;
    fed.map_err(|e| format!("verify data feeder: {e}"))?;
    match verified {
        Err(Error::AuthenticationFailed) => Ok(()),
        Err(other) => Err(describe("expected authentication-failed, got", &other)),
        Ok(()) => Err("31-byte prefix of the correct tag verified".into()),
    }
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
        if digest.algorithm_name() != name {
            return Err(format!(
                "{name} digest reports algorithm-name {:?}",
                digest.algorithm_name()
            ));
        }
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
        if key.algorithm_name() != name {
            return Err(format!(
                "{name} key name: got {:?}, want {name:?}",
                key.algorithm_name()
            ));
        }
        if key.algorithm_length() != 256 {
            return Err(format!(
                "{name} key length: got {}, want 256",
                key.algorithm_length()
            ));
        }
        // The size getters exist so a component holding only the key handle
        // can frame nonces and ciphertext without matching on
        // `algorithm-name` (see the WIT). XChaCha is the one family where
        // the nonce size differs from the AES default, so asserting them
        // only on AES-GCM left the getters' whole purpose untested.
        let want_nonce = if name == "XChaCha20-Poly1305" { 24 } else { 12 };
        if key.nonce_size() != want_nonce {
            return Err(format!(
                "{name} nonce-size: got {}, want {want_nonce}",
                key.nonce_size()
            ));
        }
        if key.tag_size() != 16 {
            return Err(format!("{name} tag-size: got {}, want 16", key.tag_size()));
        }
        match import(vec![0x42u8; 16], false).await {
            Err(Error::InvalidKey(_)) => {}
            Err(other) => {
                return Err(describe(
                    "import-key(16 bytes): expected invalid-key, got",
                    &other,
                ))
            }
            Ok(_) => return Err(format!("{name} imported 16 bytes of key material")),
        }
        let generated = generate(true)
            .await
            .map_err(|e| describe("generate-key", &e))?;
        let raw = generated
            .export_key()
            .await
            .map_err(|e| describe("export", &e))?;
        if raw.len() != 32 {
            return Err(format!(
                "{name} generated {} bytes of key material, want 32",
                raw.len()
            ));
        }
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
        let (sealed, fed) = seal(&key, &vec![0u8; bad_len], b"", msg, Schedule::Whole).await;
        fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
        match sealed {
            Err(Error::InvalidNonce(_)) => {}
            Err(other) => return Err(describe("seal: expected invalid-nonce, got", &other)),
            Ok(_) => {
                return Err(format!("{name} sealed under a {bad_len}-byte nonce"));
            }
        }
        let (sealed, fed) = seal(&key, &vec![0u8; good_len], b"", msg, Schedule::Whole).await;
        fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
        let sealed = sealed.map_err(|e| describe("seal", &e))?;
        let (opened, fed) = open(&key, &vec![0u8; good_len], b"", &sealed, Schedule::Whole).await;
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
    let (tx, rx) = lann_webcrypto_guest::wit_stream::new();
    let (sig, fed) = futures::join!(key.sign(rx), crate::util::feed_whole(tx, payload));
    fed?;
    let sig = sig.map_err(|e| describe("sign", &e))?;
    if sig.len() != 64 {
        return Err(format!(
            "Ed25519 signatures are 64 bytes, got {}",
            sig.len()
        ));
    }

    let (verified, fed) = sig_verify(&public, payload, &sig, Schedule::Whole).await;
    fed?;
    verified.map_err(|e| describe("round-trip signature did not verify", &e))?;

    let mut corrupted = sig.clone();
    corrupted[0] ^= 0x01;
    let (verified, fed) = sig_verify(&public, payload, &corrupted, Schedule::Whole).await;
    fed?;
    match verified {
        Err(Error::AuthenticationFailed) => {}
        Err(other) => return Err(describe("expected authentication-failed, got", &other)),
        Ok(()) => return Err("corrupted signature verified".into()),
    }

    let (_other, other_public) = generate_ed25519_key(false)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    let (verified, fed) = sig_verify(&other_public, payload, &sig, Schedule::Whole).await;
    fed?;
    match verified {
        Err(Error::AuthenticationFailed) => Ok(()),
        Err(other) => Err(describe("expected authentication-failed, got", &other)),
        Ok(()) => Err("signature verified under a different key".into()),
    }
}

/// The signature getters report the mint binding: Ed25519 keys have no
/// curve/hash parameters; ECDSA keys report their variant's curve and hash.
async fn sig_key_metadata() -> Result<(), String> {
    let (signing, public) = generate_ed25519_key(true)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    if signing.algorithm_name() != "Ed25519" {
        return Err(format!(
            "Ed25519 signing-key.algorithm-name: {}",
            signing.algorithm_name()
        ));
    }
    if signing.algorithm_curve().is_some() || signing.algorithm_hash().is_some() {
        return Err("Ed25519 keys report no curve/hash parameters".into());
    }
    if !signing.extractable() {
        return Err("extractable generated key reports non-extractable".into());
    }
    // The getter was only ever asserted in the `true` direction, so a
    // hardcoded `true` passed the whole suite. Mint the other kind and read
    // it back: `export-key` failing is a separate contract, checked
    // elsewhere.
    let (non_extractable, _) = generate_ed25519_key(false)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    if non_extractable.extractable() {
        return Err("non-extractable generated key reports extractable".into());
    }
    if public.algorithm_name() != "Ed25519"
        || public.algorithm_curve().is_some()
        || public.algorithm_hash().is_some()
    {
        return Err("generated Ed25519 verifying-key metadata mismatch".into());
    }

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
    if key.algorithm_name() != "ECDSA"
        || key.algorithm_curve().as_deref() != Some("P-256")
        || key.algorithm_hash().as_deref() != Some("SHA-256")
    {
        return Err(format!(
            "ECDSA verifying-key metadata: name={} curve={:?} hash={:?}",
            key.algorithm_name(),
            key.algorithm_curve(),
            key.algorithm_hash()
        ));
    }
    Ok(())
}

/// Malformed key material fails `invalid-key` on every signature import
/// path: wrong lengths, and a *compressed* SEC1 point (the WIT requires
/// uncompressed).
async fn sig_import_invalid() -> Result<(), String> {
    fn expect_invalid(what: &str, result: Result<(), Error>) -> Result<(), String> {
        match result {
            Err(Error::InvalidKey(_)) => Ok(()),
            Err(other) => Err(format!(
                "{what}: expected invalid-key, got {}",
                describe("", &other)
            )),
            Ok(()) => Err(format!("{what}: malformed material was accepted")),
        }
    }

    expect_invalid(
        "ed25519 short public",
        import_ed25519_verifying_key(vec![0u8; 31]).await.map(drop),
    )?;
    expect_invalid(
        "ed25519 short seed",
        import_ed25519_signing_key(vec![0u8; 16], false)
            .await
            .map(drop),
    )?;
    expect_invalid(
        "ecdsa wrong-length point",
        import_ecdsa_verifying_key(EcdsaVariant::P256Sha256, vec![0x04; 64])
            .await
            .map(drop),
    )?;
    // A compressed encoding of the RFC 6979 A.2.5 public key (y is odd).
    let mut compressed = vec![0x03];
    compressed.extend(unhex(
        "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
    ));
    expect_invalid(
        "ecdsa compressed point",
        import_ecdsa_verifying_key(EcdsaVariant::P256Sha256, compressed)
            .await
            .map(drop),
    )
}

/// Public-key export is an identity round trip (no extractability gate),
/// and re-importing the export yields a key that still verifies.
async fn verifying_key_export_roundtrip() -> Result<(), String> {
    let (signing, public) = generate_ed25519_key(false)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    let payload = b"export roundtrip payload";
    let (tx, rx) = lann_webcrypto_guest::wit_stream::new();
    let (sig, fed) = futures::join!(signing.sign(rx), crate::util::feed_whole(tx, payload));
    fed?;
    let sig = sig.map_err(|e| describe("sign", &e))?;

    let exported = public
        .export_key()
        .await
        .map_err(|e| describe("export-key (public)", &e))?;
    if exported.len() != 32 {
        return Err(format!(
            "Ed25519 public keys export as 32 bytes, got {}",
            exported.len()
        ));
    }
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
    match import_internal_nonce_key(AesVariant::Aes256, vec![0u8; 16], false).await {
        Err(Error::InvalidKey(_)) => {}
        Err(other) => return Err(describe("expected invalid-key, got", &other)),
        Ok(_) => return Err("16-byte key imported as AES-256 (internal nonce)".into()),
    }

    let key = generate_internal_nonce_key(AesVariant::Aes256, false)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    if key.algorithm_name() != "AES-GCM" {
        return Err(format!(
            "algorithm-name: got {:?}, want \"AES-GCM\"",
            key.algorithm_name()
        ));
    }
    if key.algorithm_length() != 256 {
        return Err(format!(
            "algorithm-length: got {}, want 256",
            key.algorithm_length()
        ));
    }

    let before = key
        .seals_remaining()
        .ok_or("AES-GCM internal-nonce key reports no nonce budget")?;

    let plaintext: Vec<u8> = (0..=255u8).cycle().take(1024 + 7).collect();
    let (sealed, fed) = in_seal(&key, b"shape aad", &plaintext, Schedule::Straddle).await;
    fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
    let sealed = sealed.map_err(|e| describe("seal", &e))?;
    // 12-byte IV prefix + ciphertext + 16-byte tag.
    if sealed.len() != plaintext.len() + 12 + 16 {
        return Err(format!(
            "sealed length: got {}, want {}",
            sealed.len(),
            plaintext.len() + 12 + 16
        ));
    }

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
    match opened {
        Err(Error::AuthenticationFailed) => {}
        Err(other) => return Err(describe("expected authentication-failed, got", &other)),
        Ok(_) => return Err("wrong aad opened".into()),
    }

    // Input too short to carry the wire format is authentication-failed.
    let (opened, fed) = in_open(&key, b"", &sealed[..8], Schedule::Whole).await;
    fed.map_err(|e| format!("short-input open feeder: {e}"))?;
    match opened {
        Err(Error::AuthenticationFailed) => {}
        Err(other) => {
            return Err(describe(
                "short input: expected authentication-failed, got",
                &other,
            ))
        }
        Ok(_) => return Err("8-byte sealed message opened".into()),
    }

    // A non-extractable key refuses export-key.
    match key.export_key().await {
        Err(Error::NotExtractable) => {}
        Err(other) => return Err(describe("expected not-extractable, got", &other)),
        Ok(_) => return Err("non-extractable key exported".into()),
    }

    // An extractable generated key exports 32 bytes.
    let key = generate_internal_nonce_key(AesVariant::Aes256, true)
        .await
        .map_err(|e| describe("generate-key (extractable)", &e))?;
    let exported = key
        .export_key()
        .await
        .map_err(|e| describe("export-key", &e))?;
    if exported.len() != 32 {
        return Err(format!(
            "exported key length: got {}, want 32",
            exported.len()
        ));
    }
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
    if key.algorithm_name() != "XChaCha20-Poly1305" {
        return Err(format!(
            "algorithm-name: got {:?}, want \"XChaCha20-Poly1305\"",
            key.algorithm_name()
        ));
    }
    if key.algorithm_length() != 256 {
        return Err(format!(
            "algorithm-length: got {}, want 256",
            key.algorithm_length()
        ));
    }
    // 24-byte random nonces have no enforced budget.
    if let Some(budget) = key.seals_remaining() {
        return Err(format!(
            "seals-remaining: got {budget}, want none (no enforced budget)"
        ));
    }
    // A non-extractable key refuses export; an extractable import
    // round-trips its 32 bytes.
    match key.export_key().await {
        Err(Error::NotExtractable) => {}
        Err(other) => return Err(describe("expected not-extractable, got", &other)),
        Ok(_) => return Err("non-extractable key exported".into()),
    }
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
    if sealed.len() != plaintext.len() + 24 + 16 {
        return Err(format!(
            "sealed length: got {}, want {}",
            sealed.len(),
            plaintext.len() + 24 + 16
        ));
    }
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
    if key.algorithm_length() != 128 {
        return Err(format!(
            "algorithm-length: got {}, want 128",
            key.algorithm_length()
        ));
    }
    if key.nonce_size() != 12 || key.tag_size() != 16 {
        return Err(format!(
            "nonce/tag size: got {}/{}, want 12/16",
            key.nonce_size(),
            key.tag_size()
        ));
    }
    let exported = key
        .export_key()
        .await
        .map_err(|e| describe("export-key", &e))?;
    if exported.len() != 16 {
        return Err(format!(
            "exported key length: got {}, want 16",
            exported.len()
        ));
    }

    let plaintext = b"aes-128 round trip payload".to_vec();
    let nonce = [3u8; 12];
    let (sealed, fed) = seal(&key, &nonce, b"aad", &plaintext, Schedule::Straddle).await;
    fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
    let sealed = sealed.map_err(|e| describe("seal", &e))?;
    let (opened, fed) = open(&key, &nonce, b"aad", &sealed, Schedule::Whole).await;
    fed.map_err(|e| format!("open ciphertext feeder: {e}"))?;
    let opened = opened.map_err(|e| describe("open", &e))?;
    expect_bytes(&opened, &plaintext, "round-tripped plaintext")?;

    // The internal-nonce discipline serves AES-128 too.
    let key = generate_internal_nonce_key(AesVariant::Aes128, false)
        .await
        .map_err(|e| describe("generate-key (internal nonce)", &e))?;
    if key.algorithm_length() != 128 {
        return Err(format!(
            "internal-nonce algorithm-length: got {}, want 128",
            key.algorithm_length()
        ));
    }
    let (sealed, fed) = in_seal(&key, b"aad", &plaintext, Schedule::Whole).await;
    fed.map_err(|e| format!("internal-nonce seal feeder: {e}"))?;
    let sealed = sealed.map_err(|e| describe("internal-nonce seal", &e))?;
    let (opened, fed) = in_open(&key, b"aad", &sealed, Schedule::Whole).await;
    fed.map_err(|e| format!("internal-nonce open feeder: {e}"))?;
    let opened = opened.map_err(|e| describe("internal-nonce open", &e))?;
    expect_bytes(&opened, &plaintext, "internal-nonce round trip")
}

/// The RFC 8032 §7.1 TEST 2 known answer, in the suite rather than only
/// the demo guest: `import-signing-key` succeeds, signing is deterministic
/// and byte-exact, the seed round-trips through `export-key`, and the
/// vector's public key verifies the signature.
async fn ed25519_sign_known_answer() -> Result<(), String> {
    let seed = unhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    let public = unhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
    let message = [0x72u8];
    let sig = unhex(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
         085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    );

    let key = import_ed25519_signing_key(seed.clone(), true)
        .await
        .map_err(|e| describe("import-signing-key", &e))?;
    let exported = key
        .export_key()
        .await
        .map_err(|e| describe("export-key", &e))?;
    expect_bytes(&exported, &seed, "exported seed")?;

    let (tx, rx) = lann_webcrypto_guest::wit_stream::new();
    let (got, fed) = futures::join!(key.sign(rx), crate::util::feed_whole(tx, &message));
    fed?;
    let got = got.map_err(|e| describe("sign", &e))?;
    expect_bytes(&got, &sig, "RFC 8032 test-2 signature")?;

    // The signature verifies under the vector's public key: the seed and
    // that key are the same key pair.
    let verifying = import_ed25519_verifying_key(public)
        .await
        .map_err(|e| describe("import-verifying-key", &e))?;
    let (verified, fed) = sig_verify(&verifying, &message, &got, Schedule::Whole).await;
    fed?;
    verified.map_err(|e| describe("vector public key did not verify the signature", &e))
}

/// Caller-nonce `open` of inputs shorter than the tag fails
/// `authentication-failed` (the internal-nonce analogue is covered by
/// `internal-nonce-shape`).
async fn open_short_input() -> Result<(), String> {
    let key = generate_key_256(false).await?;
    for len in [0usize, 1, 15] {
        let (opened, fed) = open(&key, &[0u8; 12], b"", &vec![0xa5; len], Schedule::Whole).await;
        fed.map_err(|e| format!("{len}-byte open feeder: {e}"))?;
        match opened {
            Err(Error::AuthenticationFailed) => {}
            Err(other) => {
                return Err(describe(
                    &format!("{len}-byte input: expected authentication-failed, got"),
                    &other,
                ))
            }
            Ok(_) => return Err(format!("{len}-byte input opened")),
        }
    }
    Ok(())
}

/// Zero-length writes are legal on a `stream<u8>`, carry no data, and must
/// change neither an operation's result nor its liveness. They are the one
/// stream shape that reaches a host's "no items available, writer not
/// finishing" path, where a consumer that parks without arming its waker
/// never resumes: the failure mode is a wedged operation — and, for a host
/// holding an admission reservation across the call, a wedged instance —
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
    let (tag, fed) = futures::join!(key.sign(rx), crate::util::feed(tx, chunks));
    fed?;
    let tag = tag.map_err(|e| describe("sign with interleaved empty writes", &e))?;
    expect_bytes(&tag, &expected, "tag over a stream with empty writes")?;

    // A stream of nothing but empty writes is an empty input, not a stall.
    let (tx, rx) = lann_webcrypto_guest::wit_stream::new();
    let (empty_tag, fed) = futures::join!(
        key.sign(rx),
        crate::util::feed(tx, vec![Vec::new(), Vec::new(), Vec::new()])
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
        aes.seal(nonce.to_vec(), b"empty-write aad".to_vec(), rx),
        crate::util::feed(tx, vec![Vec::new(), payload.clone(), Vec::new()])
    );
    fed?;
    let sealed = sealed.map_err(|e| describe("seal", &e))?.collect().await;
    let (opened, fed) = open(&aes, &nonce, b"empty-write aad", &sealed, Schedule::Whole).await;
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
