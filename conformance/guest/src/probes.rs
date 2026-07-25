//! Hand-written API-contract probes: the parts of the `lann:webcrypto`
//! contract the Wycheproof vectors cannot express — key import/export and
//! extractability, error variants for misuse, the seal/open drain rule,
//! generated-key shape, and algorithm naming.

use crate::lann::webcrypto::aes_gcm::{generate_aes256_gcm_key, import_aes256_gcm_key};
use crate::lann::webcrypto::hmac::{generate_hmac_sha256_key, import_hmac_sha256_key};
use crate::lann::webcrypto::mac::Mac;
use crate::lann::webcrypto::types::Error;
use crate::translate::Schedule;
use crate::util::{absorb, describe, expect_bytes, open, seal};

/// The probe names, in execution order. `run_one(i)` runs `NAMES[i]`.
pub const NAMES: &[&str] = &[
    "hmac-import-empty-key",
    "aes-import-wrong-length",
    "seal-drains-on-invalid-nonce",
    "open-drains-on-invalid-nonce",
    "sealed-length",
    "absorb-concatenation",
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
        1 => aes_import_wrong_length().await,
        2 => seal_drains_on_invalid_nonce().await,
        3 => open_drains_on_invalid_nonce().await,
        4 => sealed_length().await,
        5 => absorb_concatenation().await,
        6 => key_export_roundtrip().await,
        7 => not_extractable().await,
        8 => generated_key_shape().await,
        9 => algorithm_names().await,
        10 => mac_verify_rejects_truncated().await,
        _ => Err(format!("no probe at index {index}")),
    }
}

/// Importing an empty HMAC key fails `invalid-key`.
async fn hmac_import_empty_key() -> Result<(), String> {
    match import_hmac_sha256_key(Vec::new(), false).await {
        Err(Error::InvalidKey(_)) => Ok(()),
        Err(other) => Err(describe("expected invalid-key, got", &other)),
        Ok(_) => Err("empty HMAC key imported".into()),
    }
}

/// Importing 16- or 24-byte material as an AES-256 key fails `invalid-key`.
async fn aes_import_wrong_length() -> Result<(), String> {
    for len in [16usize, 24] {
        match import_aes256_gcm_key(vec![0u8; len], false).await {
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

/// `seal` with a bad nonce still drains the plaintext stream: the concurrent
/// feeder must complete, and the error must be `invalid-nonce`.
async fn seal_drains_on_invalid_nonce() -> Result<(), String> {
    let key = generate_aes256_gcm_key(false).await;
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
    let key = generate_aes256_gcm_key(false).await;
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
    let key = generate_aes256_gcm_key(false).await;
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

/// Three sequential absorbs produce the same tag as one absorb of the
/// concatenation.
async fn absorb_concatenation() -> Result<(), String> {
    let key = import_hmac_sha256_key(b"absorb-concatenation probe key".to_vec(), false)
        .await
        .map_err(|e| describe("import-hmac-sha256-key", &e))?;
    let parts: [&[u8]; 3] = [b"first part / ", b"", b"second and third"];
    let whole: Vec<u8> = parts.concat();

    let mac = key.start();
    for part in parts {
        absorb(&mac, part, Schedule::Whole).await?;
    }
    let split_tag = Mac::finalize(mac).await;

    let mac = key.start();
    absorb(&mac, &whole, Schedule::Whole).await?;
    let whole_tag = Mac::finalize(mac).await;

    expect_bytes(&split_tag, &whole_tag, "3-absorb tag vs 1-absorb tag")
}

/// Import then export of an extractable key is the identity, for both HMAC
/// and AES keys.
async fn key_export_roundtrip() -> Result<(), String> {
    let hmac_raw = b"key-export-roundtrip".to_vec();
    let key = import_hmac_sha256_key(hmac_raw.clone(), true)
        .await
        .map_err(|e| describe("import-hmac-sha256-key", &e))?;
    let exported = key
        .export()
        .await
        .map_err(|e| describe("hmac export", &e))?;
    expect_bytes(&exported, &hmac_raw, "exported HMAC key material")?;

    let aes_raw: Vec<u8> = (0..32u8).collect();
    let key = import_aes256_gcm_key(aes_raw.clone(), true)
        .await
        .map_err(|e| describe("import-aes256-gcm-key", &e))?;
    let exported = key.export().await.map_err(|e| describe("aes export", &e))?;
    expect_bytes(&exported, &aes_raw, "exported AES key material")
}

/// Export of a non-extractable key fails `not-extractable`, for both HMAC
/// and AES keys.
async fn not_extractable() -> Result<(), String> {
    let key = import_hmac_sha256_key(b"not-extractable".to_vec(), false)
        .await
        .map_err(|e| describe("import-hmac-sha256-key", &e))?;
    match key.export().await {
        Err(Error::NotExtractable) => {}
        Err(other) => return Err(describe("hmac: expected not-extractable, got", &other)),
        Ok(_) => return Err("non-extractable HMAC key exported".into()),
    }

    let key = import_aes256_gcm_key(vec![0x42u8; 32], false)
        .await
        .map_err(|e| describe("import-aes256-gcm-key", &e))?;
    match key.export().await {
        Err(Error::NotExtractable) => Ok(()),
        Err(other) => Err(describe("aes: expected not-extractable, got", &other)),
        Ok(_) => Err("non-extractable AES key exported".into()),
    }
}

/// Generated keys have the right shape: extractable generated keys export 32
/// bytes, a generated HMAC key signs and verifies, and a generated AES key
/// round-trips seal/open.
async fn generated_key_shape() -> Result<(), String> {
    let hmac_key = generate_hmac_sha256_key(true).await;
    let exported = hmac_key
        .export()
        .await
        .map_err(|e| describe("generated hmac export", &e))?;
    if exported.len() != 32 {
        return Err(format!(
            "generated HMAC key exports {} bytes, want 32",
            exported.len()
        ));
    }

    let payload = b"generated-key-shape payload";
    let mac = hmac_key.start();
    absorb(&mac, payload, Schedule::Whole).await?;
    let tag = Mac::finalize(mac).await;
    let mac = hmac_key.start();
    absorb(&mac, payload, Schedule::Whole).await?;
    if !Mac::verify(mac, tag).await {
        return Err("generated HMAC key's tag did not verify".into());
    }

    let aes_key = generate_aes256_gcm_key(true).await;
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

/// `algorithm()` reports the bound algorithm name on keys and computations.
async fn algorithm_names() -> Result<(), String> {
    let expect = |got: String, want: &str, what: &str| -> Result<(), String> {
        if got == want {
            Ok(())
        } else {
            Err(format!("{what}: got {got:?}, want {want:?}"))
        }
    };

    let imported = import_hmac_sha256_key(b"algorithm-names".to_vec(), false)
        .await
        .map_err(|e| describe("import-hmac-sha256-key", &e))?;
    expect(imported.algorithm(), "HMAC-SHA-256", "imported mac-key")?;
    let mac = imported.start();
    expect(mac.algorithm(), "HMAC-SHA-256", "mac computation")?;
    drop(mac);
    let generated = generate_hmac_sha256_key(false).await;
    expect(generated.algorithm(), "HMAC-SHA-256", "generated mac-key")?;

    let imported = import_aes256_gcm_key(vec![0x24u8; 32], false)
        .await
        .map_err(|e| describe("import-aes256-gcm-key", &e))?;
    expect(imported.algorithm(), "AES-256-GCM", "imported aead-key")?;
    let generated = generate_aes256_gcm_key(false).await;
    expect(generated.algorithm(), "AES-256-GCM", "generated aead-key")
}

/// `verify` rejects a 31-byte prefix of the correct tag.
async fn mac_verify_rejects_truncated() -> Result<(), String> {
    let key = import_hmac_sha256_key(b"truncated-tag probe key".to_vec(), false)
        .await
        .map_err(|e| describe("import-hmac-sha256-key", &e))?;
    let payload = b"truncated-tag payload";

    let mac = key.start();
    absorb(&mac, payload, Schedule::Whole).await?;
    let tag = Mac::finalize(mac).await;
    if tag.len() != 32 {
        return Err(format!("tag length: got {}, want 32", tag.len()));
    }

    let mac = key.start();
    absorb(&mac, payload, Schedule::Whole).await?;
    if Mac::verify(mac, tag[..31].to_vec()).await {
        return Err("31-byte prefix of the correct tag verified".into());
    }
    Ok(())
}
