//! Hand-written API-contract probes: the parts of the `lann:webcrypto`
//! contract the Wycheproof vectors cannot express — key import/export and
//! extractability, error variants for misuse, the seal/open drain rule,
//! generated-key shape, and algorithm naming.

use crate::lann::webcrypto::aes_gcm::{generate_key, import_key, AesVariant};
use crate::lann::webcrypto::hmac_sha2::{
    generate_key as generate_hmac_key, import_key as import_hmac_key, Sha2Variant,
};
use crate::lann::webcrypto::types::Error;
use crate::translate::Schedule;
use crate::util::{describe, expect_bytes, open, seal, sign, verify};

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
