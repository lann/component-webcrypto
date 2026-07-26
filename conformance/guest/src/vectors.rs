//! Execution of the normalized vector cases against the imported
//! `lann:webcrypto` interfaces.

use crate::lann::webcrypto::aes_gcm::{import_key, AesVariant};
use crate::lann::webcrypto::bytes::constant_time_equal;
use crate::lann::webcrypto::hmac_sha2::import_key as import_hmac_key;
use crate::lann::webcrypto::sha2::{make_digest, Sha2Variant};
use crate::lann::webcrypto::types::Error;
use crate::translate::{GcmCase, GcmExpectation, HmacCase, Sha2Alg, Sha2Case};
use crate::util::{compute, describe, expect_bytes, open, seal, sign, verify};

/// Run one SHA-2 digest vector under its schedule.
pub async fn run_sha2_case(case: &Sha2Case) -> Result<(), String> {
    let variant = match case.alg {
        Sha2Alg::Sha256 => Sha2Variant::Sha256,
        Sha2Alg::Sha384 => Sha2Variant::Sha384,
        Sha2Alg::Sha512 => Sha2Variant::Sha512,
    };
    let digest = make_digest(variant).map_err(|e| describe("make-digest", &e))?;
    let (got, fed) = compute(&digest, &case.msg, case.schedule).await;
    fed.map_err(|e| format!("compute data feeder: {e}"))?;
    expect_bytes(&got, &case.md, "computed digest")?;
    // The comparison every caller of a digest vector makes; pins
    // `constant-time-equal`'s agreement with plain equality on real data.
    if !constant_time_equal(&got, &case.md) {
        return Err("constant-time-equal disagreed with byte equality".into());
    }
    Ok(())
}

/// Run one HMAC-SHA-256 vector under its schedule.
pub async fn run_hmac_case(case: &HmacCase) -> Result<(), String> {
    let key = import_hmac_key(Sha2Variant::Sha256, case.key.clone(), false)
        .await
        .map_err(|e| describe("import-key", &e))?;
    if case.valid {
        let (tag, fed) = sign(&key, &case.msg, case.schedule).await;
        fed.map_err(|e| format!("sign data feeder: {e}"))?;
        expect_bytes(&tag, &case.tag, "sign tag")?;

        let (verified, fed) = verify(&key, &case.msg, &case.tag, case.schedule).await;
        fed.map_err(|e| format!("verify data feeder: {e}"))?;
        verified.map_err(|e| describe("verify(tag) failed for a valid vector", &e))?;
    } else {
        let (verified, fed) = verify(&key, &case.msg, &case.tag, case.schedule).await;
        fed.map_err(|e| format!("verify data feeder: {e}"))?;
        match verified {
            Err(Error::AuthenticationFailed) => {}
            Err(other) => {
                return Err(describe(
                    "verify of an invalid vector: expected authentication-failed, got",
                    &other,
                ));
            }
            Ok(()) => return Err("verify(tag) succeeded for an invalid vector".into()),
        }
    }
    Ok(())
}

/// Run one AES-256-GCM vector under its schedule.
pub async fn run_gcm_case(case: &GcmCase) -> Result<(), String> {
    let key = import_key(AesVariant::Aes256, case.key.clone(), false)
        .await
        .map_err(|e| describe("import-key", &e))?;
    match case.expectation {
        GcmExpectation::InvalidNonce => {
            let (sealed, fed) = seal(&key, &case.iv, &case.aad, &case.msg, case.schedule).await;
            fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
            match sealed {
                Err(Error::InvalidNonce(_)) => {}
                Err(other) => return Err(describe("seal: expected invalid-nonce, got", &other)),
                Ok(_) => {
                    return Err(format!("seal accepted a {}-byte nonce", case.iv.len()));
                }
            }
            let (opened, fed) = open(&key, &case.iv, &case.aad, &case.ct_tag, case.schedule).await;
            fed.map_err(|e| format!("open ciphertext feeder: {e}"))?;
            match opened {
                Err(Error::InvalidNonce(_)) => Ok(()),
                Err(other) => Err(describe("open: expected invalid-nonce, got", &other)),
                Ok(_) => Err(format!("open accepted a {}-byte nonce", case.iv.len())),
            }
        }
        GcmExpectation::Valid => {
            let (sealed, fed) = seal(&key, &case.iv, &case.aad, &case.msg, case.schedule).await;
            fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
            let sealed = sealed.map_err(|e| describe("seal", &e))?;
            expect_bytes(&sealed, &case.ct_tag, "sealed bytes")?;

            let (opened, fed) = open(&key, &case.iv, &case.aad, &case.ct_tag, case.schedule).await;
            fed.map_err(|e| format!("open ciphertext feeder: {e}"))?;
            let opened = opened.map_err(|e| describe("open", &e))?;
            expect_bytes(&opened, &case.msg, "opened bytes")
        }
        GcmExpectation::AuthenticationFailed => {
            let (opened, fed) = open(&key, &case.iv, &case.aad, &case.ct_tag, case.schedule).await;
            fed.map_err(|e| format!("open ciphertext feeder: {e}"))?;
            match opened {
                Err(Error::AuthenticationFailed) => Ok(()),
                Err(other) => Err(describe(
                    "open: expected authentication-failed, got",
                    &other,
                )),
                Ok(_) => Err("open accepted an invalid vector".into()),
            }
        }
    }
}
