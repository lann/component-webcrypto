//! Execution of the normalized Wycheproof cases against the imported
//! `lann:webcrypto` interfaces.

use crate::lann::webcrypto::aes_gcm::import_aes256_gcm_key;
use crate::lann::webcrypto::hmac::import_hmac_sha256_key;
use crate::lann::webcrypto::mac::Mac;
use crate::lann::webcrypto::types::Error;
use crate::translate::{GcmCase, GcmExpectation, HmacCase};
use crate::util::{absorb, describe, expect_bytes, open, seal};

/// Run one HMAC-SHA-256 vector under its schedule.
pub async fn run_hmac_case(case: &HmacCase) -> Result<(), String> {
    let key = import_hmac_sha256_key(case.key.clone(), false)
        .await
        .map_err(|e| describe("import-hmac-sha256-key", &e))?;
    if case.valid {
        let mac = key.start();
        absorb(&mac, &case.msg, case.schedule).await?;
        let tag = Mac::finalize(mac).await;
        expect_bytes(&tag, &case.tag, "finalize tag")?;

        let mac = key.start();
        absorb(&mac, &case.msg, case.schedule).await?;
        if !Mac::verify(mac, case.tag.clone()).await {
            return Err("verify(tag) returned false for a valid vector".into());
        }
    } else {
        let mac = key.start();
        absorb(&mac, &case.msg, case.schedule).await?;
        if Mac::verify(mac, case.tag.clone()).await {
            return Err("verify(tag) returned true for an invalid vector".into());
        }
    }
    Ok(())
}

/// Run one AES-256-GCM vector under its schedule.
pub async fn run_gcm_case(case: &GcmCase) -> Result<(), String> {
    let key = import_aes256_gcm_key(case.key.clone(), false)
        .await
        .map_err(|e| describe("import-aes256-gcm-key", &e))?;
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
