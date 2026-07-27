//! Execution of the normalized vector cases against the imported
//! `lann:webcrypto` interfaces.

use crate::translate::{
    AeadExpectation, ChaChaAlg, ChaChaCase, GcmCase, HmacCase, InternalNonceAlg, InternalNonceCase,
    Schedule, Sha2Alg, Sha2Case, SigAlg, SigCase, SpeccheckCase,
};
use crate::util::{
    compute, describe, expect_bytes, in_open, in_seal, open, seal, sig_verify, sign, verify,
};
use lann_webcrypto_guest::raw::aead::AeadKey;
use lann_webcrypto_guest::raw::aes_gcm::{import_key, AesVariant};
use lann_webcrypto_guest::raw::aes_gcm_internal_nonce::import_key as import_gcm_internal_key;
use lann_webcrypto_guest::raw::bytes::constant_time_equal;
use lann_webcrypto_guest::raw::chacha20_poly1305::import_key as import_chacha_key;
use lann_webcrypto_guest::raw::ecdsa_verify::{
    import_verifying_key as import_ecdsa_verifying_key, EcdsaVariant,
};
use lann_webcrypto_guest::raw::ed25519_verify::import_verifying_key as import_ed25519_verifying_key;
use lann_webcrypto_guest::raw::hmac_sha2::import_key as import_hmac_key;
use lann_webcrypto_guest::raw::sha2::{make_digest, Sha2Variant};
use lann_webcrypto_guest::raw::types::Error;
use lann_webcrypto_guest::raw::xchacha20_poly1305::import_key as import_xchacha_key;
use lann_webcrypto_guest::raw::xchacha20_poly1305_internal_nonce::import_key as import_xchacha_internal_key;

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
    run_aead_expectation(
        &key,
        case.expectation,
        &case.iv,
        &case.aad,
        &case.msg,
        &case.ct_tag,
        case.schedule,
    )
    .await
}

/// Run one ChaCha20-Poly1305 vector (either variant) under its schedule.
pub async fn run_chacha_case(case: &ChaChaCase) -> Result<(), String> {
    let key = match case.alg {
        ChaChaAlg::ChaCha20Poly1305 => import_chacha_key(case.key.clone(), false)
            .await
            .map_err(|e| describe("import-key", &e))?,
        ChaChaAlg::XChaCha20Poly1305 => import_xchacha_key(case.key.clone(), false)
            .await
            .map_err(|e| describe("import-key", &e))?,
    };
    run_aead_expectation(
        &key,
        case.expectation,
        &case.iv,
        &case.aad,
        &case.msg,
        &case.ct_tag,
        case.schedule,
    )
    .await
}

/// Drive one imported AEAD key through a vector's expectation; shared by
/// every AEAD algorithm's vector suite.
async fn run_aead_expectation(
    key: &AeadKey,
    expectation: AeadExpectation,
    iv: &[u8],
    aad: &[u8],
    msg: &[u8],
    ct_tag: &[u8],
    schedule: Schedule,
) -> Result<(), String> {
    match expectation {
        AeadExpectation::InvalidNonce => {
            let (sealed, fed) = seal(key, iv, aad, msg, schedule).await;
            fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
            match sealed {
                Err(Error::InvalidNonce(_)) => {}
                Err(other) => return Err(describe("seal: expected invalid-nonce, got", &other)),
                Ok(_) => {
                    return Err(format!("seal accepted a {}-byte nonce", iv.len()));
                }
            }
            let (opened, fed) = open(key, iv, aad, ct_tag, schedule).await;
            fed.map_err(|e| format!("open ciphertext feeder: {e}"))?;
            match opened {
                Err(Error::InvalidNonce(_)) => Ok(()),
                Err(other) => Err(describe("open: expected invalid-nonce, got", &other)),
                Ok(_) => Err(format!("open accepted a {}-byte nonce", iv.len())),
            }
        }
        AeadExpectation::Valid => {
            let (sealed, fed) = seal(key, iv, aad, msg, schedule).await;
            fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
            let sealed = sealed.map_err(|e| describe("seal", &e))?;
            expect_bytes(&sealed, ct_tag, "sealed bytes")?;

            let (opened, fed) = open(key, iv, aad, ct_tag, schedule).await;
            fed.map_err(|e| format!("open ciphertext feeder: {e}"))?;
            let opened = opened.map_err(|e| describe("open", &e))?;
            expect_bytes(&opened, msg, "opened bytes")
        }
        AeadExpectation::AuthenticationFailed => {
            let (opened, fed) = open(key, iv, aad, ct_tag, schedule).await;
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

/// Run one internal-nonce AEAD vector under its schedule: `open` the
/// vector's `iv || ct || tag` (the deterministic direction), and, for valid
/// vectors, additionally round-trip a fresh `seal` (randomized, so only
/// self-consistency is checkable).
pub async fn run_internal_nonce_case(case: &InternalNonceCase) -> Result<(), String> {
    let key = match case.alg {
        InternalNonceAlg::AesGcm => {
            import_gcm_internal_key(AesVariant::Aes256, case.key.clone(), false)
                .await
                .map_err(|e| describe("import-key", &e))?
        }
        InternalNonceAlg::XChaCha20Poly1305 => import_xchacha_internal_key(case.key.clone(), false)
            .await
            .map_err(|e| describe("import-key", &e))?,
    };
    let (opened, fed) = in_open(&key, &case.aad, &case.sealed, case.schedule).await;
    fed.map_err(|e| format!("open sealed feeder: {e}"))?;
    if case.valid {
        let opened = opened.map_err(|e| describe("open", &e))?;
        expect_bytes(&opened, &case.msg, "opened bytes")?;

        let (resealed, fed) = in_seal(&key, &case.aad, &case.msg, case.schedule).await;
        fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
        let resealed = resealed.map_err(|e| describe("seal", &e))?;
        if resealed.len() != case.sealed.len() {
            return Err(format!(
                "resealed length: got {}, want {}",
                resealed.len(),
                case.sealed.len()
            ));
        }
        let (reopened, fed) = in_open(&key, &case.aad, &resealed, Schedule::Whole).await;
        fed.map_err(|e| format!("re-open sealed feeder: {e}"))?;
        let reopened = reopened.map_err(|e| describe("open of fresh seal", &e))?;
        expect_bytes(&reopened, &case.msg, "round-tripped bytes")
    } else {
        match opened {
            Err(Error::AuthenticationFailed) => Ok(()),
            Err(other) => Err(describe(
                "open: expected authentication-failed, got",
                &other,
            )),
            Ok(_) => Err("open accepted an invalid sealed message".into()),
        }
    }
}

/// Run one ed25519-speccheck adversarial vector under its schedule. The
/// WIT criterion permits rejecting a degenerate public key at import or at
/// verification, so both count as rejection; anything else — acceptance,
/// or a different error — fails the case.
pub async fn run_speccheck_case(case: &SpeccheckCase) -> Result<(), String> {
    let key = match import_ed25519_verifying_key(case.public.clone()).await {
        Ok(key) => key,
        Err(Error::InvalidKey(_)) if !case.valid => return Ok(()),
        Err(err) => return Err(describe("import-verifying-key", &err)),
    };
    let (verified, fed) = sig_verify(&key, &case.msg, &case.sig, case.schedule).await;
    fed.map_err(|e| format!("verify data feeder: {e}"))?;
    if case.valid {
        verified.map_err(|e| describe("verify failed for the valid case", &e))
    } else {
        match verified {
            Err(Error::AuthenticationFailed) => Ok(()),
            Err(other) => Err(describe(
                "verify: expected authentication-failed, got",
                &other,
            )),
            Ok(()) => Err("a degenerate signature verified".into()),
        }
    }
}

/// Run one signature-verification vector under its schedule.
pub async fn run_sig_case(case: &SigCase) -> Result<(), String> {
    let key = match case.alg {
        SigAlg::Ed25519 => import_ed25519_verifying_key(case.public.clone())
            .await
            .map_err(|e| describe("import-verifying-key", &e))?,
        SigAlg::EcdsaP256Sha256 => {
            import_ecdsa_verifying_key(EcdsaVariant::P256Sha256, case.public.clone())
                .await
                .map_err(|e| describe("import-verifying-key", &e))?
        }
        SigAlg::EcdsaP384Sha384 => {
            import_ecdsa_verifying_key(EcdsaVariant::P384Sha384, case.public.clone())
                .await
                .map_err(|e| describe("import-verifying-key", &e))?
        }
    };
    let (verified, fed) = sig_verify(&key, &case.msg, &case.sig, case.schedule).await;
    fed.map_err(|e| format!("verify data feeder: {e}"))?;
    if case.valid {
        verified.map_err(|e| describe("verify(sig) failed for a valid vector", &e))
    } else {
        match verified {
            Err(Error::AuthenticationFailed) => Ok(()),
            Err(other) => Err(describe(
                "verify of an invalid vector: expected authentication-failed, got",
                &other,
            )),
            Ok(()) => Err("verify(sig) succeeded for an invalid vector".into()),
        }
    }
}
