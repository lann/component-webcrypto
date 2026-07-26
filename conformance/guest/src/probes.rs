//! Hand-written API-contract probes: the parts of the `lann:webcrypto`
//! contract the Wycheproof vectors cannot express — key import/export and
//! extractability, error variants for misuse, the seal/open drain rule,
//! generated-key shape, and algorithm naming.

use crate::lann::webcrypto::aes_gcm::{generate_key, import_key, AesVariant};
use crate::lann::webcrypto::bytes::constant_time_equal;
use crate::lann::webcrypto::chacha20_poly1305::{
    generate_key as generate_chacha_key, import_key as import_chacha_key, ChachaVariant,
};
use crate::lann::webcrypto::ecdsa_verify::{
    import_verifying_key as import_ecdsa_verifying_key, EcdsaVariant,
};
use crate::lann::webcrypto::ed25519_sign::{
    generate_key as generate_ed25519_key, import_signing_key as import_ed25519_signing_key,
};
use crate::lann::webcrypto::ed25519_verify::import_verifying_key as import_ed25519_verifying_key;
use crate::lann::webcrypto::hmac_sha2::{
    generate_key as generate_hmac_key, import_key as import_hmac_key,
};
use crate::lann::webcrypto::sha2::{make_digest, Sha2Variant};
use crate::lann::webcrypto::types::Error;
use crate::translate::Schedule;
use crate::util::{compute, describe, expect_bytes, open, seal, sig_verify, sign, verify};

/// The probe names, in execution order. `run_one(i)` runs `NAMES[i]`.
pub const NAMES: &[&str] = &[
    "hmac-import-empty-key",
    "hmac-sha384-sha512",
    "sha2-truncated-unsupported",
    "aes-import-wrong-length",
    "aes192-unsupported",
    "seal-drains-on-invalid-nonce",
    "open-drains-on-invalid-nonce",
    "sealed-length",
    "key-export-roundtrip",
    "not-extractable",
    "generated-key-shape",
    "algorithm-names",
    "mac-verify-rejects-truncated",
    "sign-prefix-drop",
    "digest-reuse",
    "constant-time-equal",
    "chacha-key-metadata",
    "chacha-nonce-lengths",
    "ed25519-sign-roundtrip",
    "sig-key-metadata",
    "sig-import-invalid",
    "verifying-key-export-roundtrip",
];

/// Run the probe at `index` (into [`NAMES`]).
pub async fn run_one(index: usize) -> Result<(), String> {
    match index {
        0 => hmac_import_empty_key().await,
        1 => hmac_sha384_sha512().await,
        2 => sha2_truncated_unsupported().await,
        3 => aes_import_wrong_length().await,
        4 => aes192_unsupported().await,
        5 => seal_drains_on_invalid_nonce().await,
        6 => open_drains_on_invalid_nonce().await,
        7 => sealed_length().await,
        8 => key_export_roundtrip().await,
        9 => not_extractable().await,
        10 => generated_key_shape().await,
        11 => algorithm_names().await,
        12 => mac_verify_rejects_truncated().await,
        13 => sign_prefix_drop().await,
        14 => digest_reuse().await,
        15 => constant_time_equal_probe().await,
        16 => chacha_key_metadata().await,
        17 => chacha_nonce_lengths().await,
        18 => ed25519_sign_roundtrip().await,
        19 => sig_key_metadata().await,
        20 => sig_import_invalid().await,
        21 => verifying_key_export_roundtrip().await,
        _ => Err(format!("no probe at index {index}")),
    }
}

/// Generate an AES-256 key, rendering a WIT error as a probe failure.
async fn generate_key_256(
    extractable: bool,
) -> Result<crate::lann::webcrypto::aead::AeadKey, String> {
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
        match generate_hmac_key(variant, false).await {
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

/// Sealed output is exactly plaintext length + the 16-byte tag.
async fn sealed_length() -> Result<(), String> {
    let key = generate_key_256(false).await?;
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
        .export()
        .await
        .map_err(|e| describe("hmac export", &e))?;
    expect_bytes(&exported, &hmac_raw, "exported HMAC key material")?;

    let aes_raw: Vec<u8> = (0..32u8).collect();
    let key = import_key(AesVariant::Aes256, aes_raw.clone(), true)
        .await
        .map_err(|e| describe("import-key", &e))?;
    let exported = key.export().await.map_err(|e| describe("aes export", &e))?;
    expect_bytes(&exported, &aes_raw, "exported AES key material")
}

/// Export of a non-extractable key fails `not-extractable`, for both HMAC
/// and AES keys.
async fn not_extractable() -> Result<(), String> {
    let key = import_hmac_key(Sha2Variant::Sha256, b"not-extractable".to_vec(), false)
        .await
        .map_err(|e| describe("import-key", &e))?;
    match key.export().await {
        Err(Error::NotExtractable) => {}
        Err(other) => return Err(describe("hmac: expected not-extractable, got", &other)),
        Ok(_) => return Err("non-extractable HMAC key exported".into()),
    }

    let key = import_key(AesVariant::Aes256, vec![0x42u8; 32], false)
        .await
        .map_err(|e| describe("import-key", &e))?;
    match key.export().await {
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
    let hmac_key = generate_hmac_key(Sha2Variant::Sha256, true)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    let exported = hmac_key
        .export()
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
        .export()
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
    let generated = generate_hmac_key(Sha2Variant::Sha256, false)
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
    let (tx, rx) = crate::wit_stream::new();
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
async fn constant_time_equal_probe() -> Result<(), String> {
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
        if constant_time_equal(x, y) != want {
            return Err(format!("{what}: got {}, want {want}", !want));
        }
    }
    Ok(())
}

/// Both `chacha-variant`s mint 256-bit keys reporting their own algorithm
/// names, decline non-32-byte material as `invalid-key`, and generate
/// 32 bytes of key material.
async fn chacha_key_metadata() -> Result<(), String> {
    for (variant, name) in [
        (ChachaVariant::Chacha20Poly1305, "ChaCha20-Poly1305"),
        (ChachaVariant::Xchacha20Poly1305, "XChaCha20-Poly1305"),
    ] {
        let key = import_chacha_key(variant, vec![0x42u8; 32], false)
            .await
            .map_err(|e| describe("import-key", &e))?;
        if key.algorithm_name() != name {
            return Err(format!(
                "{variant:?} key name: got {:?}, want {name:?}",
                key.algorithm_name()
            ));
        }
        if key.algorithm_length() != 256 {
            return Err(format!(
                "{variant:?} key length: got {}, want 256",
                key.algorithm_length()
            ));
        }
        match import_chacha_key(variant, vec![0x42u8; 16], false).await {
            Err(Error::InvalidKey(_)) => {}
            Err(other) => {
                return Err(describe(
                    "import-key(16 bytes): expected invalid-key, got",
                    &other,
                ))
            }
            Ok(_) => return Err(format!("{variant:?} imported 16 bytes of key material")),
        }
        let generated = generate_chacha_key(variant, true)
            .await
            .map_err(|e| describe("generate-key", &e))?;
        let raw = generated
            .export()
            .await
            .map_err(|e| describe("export", &e))?;
        if raw.len() != 32 {
            return Err(format!(
                "{variant:?} generated {} bytes of key material, want 32",
                raw.len()
            ));
        }
    }
    Ok(())
}

/// Each `chacha-variant`'s key accepts exactly its own nonce length: the
/// other variant's length is `invalid-nonce` (nonce-length confusion between
/// the constructions cannot pass silently), and the correct length
/// round-trips.
async fn chacha_nonce_lengths() -> Result<(), String> {
    let msg = b"chacha-nonce-lengths";
    for (variant, good_len, bad_len) in [
        (ChachaVariant::Chacha20Poly1305, 12usize, 24usize),
        (ChachaVariant::Xchacha20Poly1305, 24, 12),
    ] {
        let key = import_chacha_key(variant, vec![0x42u8; 32], false)
            .await
            .map_err(|e| describe("import-key", &e))?;
        let (sealed, fed) = seal(&key, &vec![0u8; bad_len], b"", msg, Schedule::Whole).await;
        fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
        match sealed {
            Err(Error::InvalidNonce(_)) => {}
            Err(other) => return Err(describe("seal: expected invalid-nonce, got", &other)),
            Ok(_) => {
                return Err(format!("{variant:?} sealed under a {bad_len}-byte nonce"));
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

/// A generated Ed25519 key signs, its derived public key verifies, a
/// corrupted signature fails `authentication-failed`, and a *different*
/// key's public half rejects the signature (keys are not interchangeable).
async fn ed25519_sign_roundtrip() -> Result<(), String> {
    let key = generate_ed25519_key(false)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    let payload = b"conformance signature payload";
    let (tx, rx) = crate::wit_stream::new();
    let (sig, fed) = futures::join!(key.sign(rx), crate::util::feed_whole(tx, payload));
    fed?;
    let sig = sig.map_err(|e| describe("sign", &e))?;
    if sig.len() != 64 {
        return Err(format!(
            "Ed25519 signatures are 64 bytes, got {}",
            sig.len()
        ));
    }

    let public = key.verifying_key();
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

    let other = generate_ed25519_key(false)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    let (verified, fed) = sig_verify(&other.verifying_key(), payload, &sig, Schedule::Whole).await;
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
    let signing = generate_ed25519_key(true)
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
    let public = signing.verifying_key();
    if public.algorithm_name() != "Ed25519"
        || public.algorithm_curve().is_some()
        || public.algorithm_hash().is_some()
    {
        return Err("derived Ed25519 verifying-key metadata mismatch".into());
    }

    // An ECDSA public key (any valid point works; this is the RFC 6979
    // A.2.5 public key).
    let mut point = vec![0x04];
    point.extend(crate::util::unhex(
        "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
    ));
    point.extend(crate::util::unhex(
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
    compressed.extend(crate::util::unhex(
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
    let signing = generate_ed25519_key(false)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    let payload = b"export roundtrip payload";
    let (tx, rx) = crate::wit_stream::new();
    let (sig, fed) = futures::join!(signing.sign(rx), crate::util::feed_whole(tx, payload));
    fed?;
    let sig = sig.map_err(|e| describe("sign", &e))?;

    let exported = signing.verifying_key().export().await;
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
    verified.map_err(|e| describe("re-imported key did not verify", &e))
}
