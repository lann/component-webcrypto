//! Execution of the normalized vector cases against the imported
//! `lann:webcrypto` interfaces.

use crate::mint::{
    import_cbc_key, import_chacha_key, import_hmac_key, import_hmac_sha1_key, import_ikm,
    import_internal_nonce_key as import_gcm_internal_key, import_key_raw, import_kw_key,
    import_password, import_x25519_public_key, import_x25519_secret_key,
    import_xchacha_internal_nonce_key as import_xchacha_internal_key, import_xchacha_key,
    mac_options,
};
use crate::translate::{
    AeadAlg, AeadCase, AeadExpectation, CbcCase, HkdfAlg, HkdfCase, HmacAlg, HmacCase,
    InternalNonceAlg, InternalNonceCase, KwCase, Pbkdf2Alg, Pbkdf2Case, Sha2Alg, Sha2Case, SigAlg,
    SigCase, SpeccheckCase, X25519Case,
};
use conformance_harness::stream::{
    ci_decrypt, ci_encrypt, compute, in_open, in_seal, open, seal, sig_verify, sign, verify,
    Schedule,
};
use conformance_harness::{describe, expect, expect_bytes, expect_err, ErrKind};
use lann_webcrypto_guest::bindings::aead::AeadKey;
use lann_webcrypto_guest::bindings::aes_gcm::AesVariant;
use lann_webcrypto_guest::bindings::bytes::constant_time_equal;
use lann_webcrypto_guest::bindings::ecdsa_verify::{
    import_verifying_key_raw as import_ecdsa_verifying_key, EcdsaVariant,
};
use lann_webcrypto_guest::bindings::ed25519_verify::import_verifying_key_raw as import_ed25519_verifying_key;
use lann_webcrypto_guest::bindings::hkdf_sha2;
use lann_webcrypto_guest::bindings::pbkdf2_sha2;
use lann_webcrypto_guest::bindings::sha2::{make_digest, Sha2Variant};
use lann_webcrypto_guest::bindings::types::Error;

/// The `aes-variant` for a vector's key size (the sizes the translation
/// emits; AES-192 never reaches execution).
fn aes_variant(key_bits: u32) -> Result<AesVariant, String> {
    match key_bits {
        128 => Ok(AesVariant::Aes128),
        256 => Ok(AesVariant::Aes256),
        bits => Err(format!("untranslatable AES key size: {bits}")),
    }
}

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
    let got = got.map_err(|e| describe("compute", &e))?;
    expect_bytes(&got, &case.md, "computed digest")?;
    // The comparison every caller of a digest vector makes; pins
    // `constant-time-equal`'s agreement with plain equality on real data.
    if !constant_time_equal(&got, &case.md) {
        return Err("constant-time-equal disagreed with byte equality".into());
    }
    Ok(())
}

/// Run one HMAC vector under its schedule.
pub async fn run_hmac_case(case: &HmacCase) -> Result<(), String> {
    let key = match case.alg {
        HmacAlg::Sha1 => import_hmac_sha1_key(case.key.clone(), false).await,
        HmacAlg::Sha256 => import_hmac_key(Sha2Variant::Sha256, case.key.clone(), false).await,
        HmacAlg::Sha384 => import_hmac_key(Sha2Variant::Sha384, case.key.clone(), false).await,
        HmacAlg::Sha512 => import_hmac_key(Sha2Variant::Sha512, case.key.clone(), false).await,
    }
    .map_err(|e| describe("import-key-raw", &e))?;
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
        expect_err(
            "verify of an invalid vector",
            ErrKind::AuthenticationFailed,
            verified,
            "verify(tag) succeeded",
        )?;
    }
    Ok(())
}

/// Run one HKDF vector: derive the declared size and compare, or — for the
/// invalid (`SizeTooLarge`) vectors — expect the RFC 5869 output bound to
/// fail with `error.other`.
pub async fn run_hkdf_case(case: &HkdfCase) -> Result<(), String> {
    // The SHA-1 arm never reads this (its prepare has no variant); any
    // served variant placates the initializer.
    let variant = match case.alg {
        HkdfAlg::Sha1 | HkdfAlg::Sha256 => Sha2Variant::Sha256,
        HkdfAlg::Sha384 => Sha2Variant::Sha384,
        HkdfAlg::Sha512 => Sha2Variant::Sha512,
    };
    let ikm = import_ikm(case.ikm.clone(), true, true)
        .await
        .map_err(|e| describe("import-ikm", &e))?;
    let input = match case.alg {
        HkdfAlg::Sha1 => {
            lann_webcrypto_guest::bindings::hkdf_sha1::prepare(
                &ikm,
                case.salt.clone(),
                case.info.clone(),
            )
            .await
        }
        _ => hkdf_sha2::prepare(variant, &ikm, case.salt.clone(), case.info.clone()).await,
    }
    .map_err(|e| describe("prepare", &e))?;
    let derived = input.derive_bits(Some(case.size * 8)).await;
    if case.valid {
        let okm = derived.map_err(|e| describe("derive-bits", &e))?;
        expect_bytes(&okm, &case.okm, "output keying material")?;
    } else {
        expect_err(
            "derive-bits past the RFC 5869 output bound",
            ErrKind::Other,
            derived,
            "derivation succeeded",
        )?;
    }
    Ok(())
}

/// Run one X25519 vector: import the peer's raw public key and the OKP
/// JWK secret key, `agree`, and check the derived shared secret at its
/// natural length (and a truncated prefix) — or, for the small-order
/// (`ZeroSharedSecret`) vectors, expect `agree` to fail `invalid-key`.
pub async fn run_x25519_case(case: &X25519Case) -> Result<(), String> {
    let peer = import_x25519_public_key(case.public.clone())
        .await
        .map_err(|e| describe("import-public-key-raw", &e))?;
    let secret = import_x25519_secret_key(&case.private_public, &case.private, true, true)
        .await
        .map_err(|e| describe("import-secret-key-jwk", &e))?;
    let agreed = secret.agree(&peer).await;
    if case.zero_shared {
        return expect_err(
            "agree with a small-order peer",
            ErrKind::InvalidKey,
            agreed,
            "agreement produced the all-zero shared secret",
        );
    }
    let input = agreed.map_err(|e| describe("agree", &e))?;
    let shared = input
        .derive_bits(None)
        .await
        .map_err(|e| describe("derive-bits (natural length)", &e))?;
    expect_bytes(&shared, &case.shared, "shared secret")?;
    let prefix = input
        .derive_bits(Some(128))
        .await
        .map_err(|e| describe("derive-bits (truncated)", &e))?;
    expect_bytes(&prefix, &case.shared[..16], "truncated shared secret")?;
    Ok(())
}

/// Run one PBKDF2 vector: derive the declared size and compare.
pub async fn run_pbkdf2_case(case: &Pbkdf2Case) -> Result<(), String> {
    let variant = match case.alg {
        Pbkdf2Alg::Sha1 | Pbkdf2Alg::Sha256 => Sha2Variant::Sha256,
        Pbkdf2Alg::Sha384 => Sha2Variant::Sha384,
        Pbkdf2Alg::Sha512 => Sha2Variant::Sha512,
    };
    let password = import_password(case.password.clone(), true, true)
        .await
        .map_err(|e| describe("import-password", &e))?;
    let input = match case.alg {
        Pbkdf2Alg::Sha1 => {
            lann_webcrypto_guest::bindings::pbkdf2_sha1::prepare(
                &password,
                case.salt.clone(),
                case.iterations,
            )
            .await
        }
        _ => pbkdf2_sha2::prepare(variant, &password, case.salt.clone(), case.iterations).await,
    }
    .map_err(|e| describe("prepare", &e))?;
    let derived = input.derive_bits(Some(case.dk_len * 8)).await;
    if case.valid {
        let dk = derived.map_err(|e| describe("derive-bits", &e))?;
        expect_bytes(&dk, &case.dk, "derived key")?;
    } else {
        expect_err(
            "derive-bits of an invalid vector",
            ErrKind::Other,
            derived,
            "derivation succeeded",
        )?;
    }
    Ok(())
}

/// Run one AES-CBC vector under its schedule: a valid vector round-trips
/// byte-exactly both ways; an invalid one (bad or absent padding) fails
/// `decrypt` with the cipher kind's one uniform error — kind *and*
/// message pinned, since any second rendering would be a distinguishable
/// verdict.
pub async fn run_cbc_case(case: &CbcCase) -> Result<(), String> {
    let key = import_cbc_key(aes_variant(case.key_bits)?, case.key.clone(), false)
        .await
        .map_err(|e| describe("import-key-raw", &e))?;
    if case.valid {
        let (sealed, fed) = ci_encrypt(&key, &case.iv, None, &case.msg, case.schedule).await;
        fed.map_err(|e| format!("encrypt plaintext feeder: {e}"))?;
        let sealed = sealed.map_err(|e| describe("encrypt", &e))?;
        expect_bytes(&sealed, &case.ct, "computed ciphertext")?;
        let (opened, fed) = ci_decrypt(&key, &case.iv, None, &case.ct, case.schedule).await;
        fed.map_err(|e| format!("decrypt ciphertext feeder: {e}"))?;
        let opened = opened.map_err(|e| describe("decrypt", &e))?;
        expect_bytes(&opened, &case.msg, "decrypted plaintext")
    } else {
        let (opened, fed) = ci_decrypt(&key, &case.iv, None, &case.ct, case.schedule).await;
        fed.map_err(|e| format!("decrypt ciphertext feeder: {e}"))?;
        match opened {
            Err(Error::Other(detail)) if detail == "AES-CBC decryption failed" => Ok(()),
            Err(other) => Err(describe(
                "decrypt: expected the uniform failure, got",
                &other,
            )),
            Ok(_) => Err("decrypted a ciphertext upstream marks invalid".into()),
        }
    }
}

/// Run one caller-nonce AEAD vector (any algorithm) under its schedule.
pub async fn run_aead_case(case: &AeadCase) -> Result<(), String> {
    let key = match case.alg {
        AeadAlg::AesGcm => {
            import_key_raw(aes_variant(case.key_bits)?, case.key.clone(), false).await
        }
        AeadAlg::ChaCha20Poly1305 => import_chacha_key(case.key.clone(), false).await,
        AeadAlg::XChaCha20Poly1305 => import_xchacha_key(case.key.clone(), false).await,
    }
    .map_err(|e| describe("import-key-raw", &e))?;
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
/// every AEAD algorithm's vector cases.
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
            let (sealed, fed) = seal(key, iv, aad, None, msg, schedule).await;
            fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
            expect_err(
                "seal",
                ErrKind::InvalidNonce,
                sealed,
                &format!("accepted a {}-byte nonce", iv.len()),
            )?;
            let (opened, fed) = open(key, iv, aad, None, ct_tag, schedule).await;
            fed.map_err(|e| format!("open ciphertext feeder: {e}"))?;
            expect_err(
                "open",
                ErrKind::InvalidNonce,
                opened,
                &format!("accepted a {}-byte nonce", iv.len()),
            )
        }
        AeadExpectation::Valid => {
            let (sealed, fed) = seal(key, iv, aad, None, msg, schedule).await;
            fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
            let sealed = sealed.map_err(|e| describe("seal", &e))?;
            expect_bytes(&sealed, ct_tag, "sealed bytes")?;

            let (opened, fed) = open(key, iv, aad, None, ct_tag, schedule).await;
            fed.map_err(|e| format!("open ciphertext feeder: {e}"))?;
            let opened = opened.map_err(|e| describe("open", &e))?;
            expect_bytes(&opened, msg, "opened bytes")
        }
        AeadExpectation::AuthenticationFailed => {
            let (opened, fed) = open(key, iv, aad, None, ct_tag, schedule).await;
            fed.map_err(|e| format!("open ciphertext feeder: {e}"))?;
            expect_err(
                "open",
                ErrKind::AuthenticationFailed,
                opened,
                "accepted an invalid vector",
            )
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
            import_gcm_internal_key(aes_variant(case.key_bits)?, case.key.clone(), false)
                .await
                .map_err(|e| describe("import-key-raw", &e))?
        }
        InternalNonceAlg::XChaCha20Poly1305 => import_xchacha_internal_key(case.key.clone(), false)
            .await
            .map_err(|e| describe("import-key-raw", &e))?,
    };
    let (opened, fed) = in_open(&key, &case.aad, &case.sealed, case.schedule).await;
    fed.map_err(|e| format!("open sealed feeder: {e}"))?;
    if case.valid {
        let opened = opened.map_err(|e| describe("open", &e))?;
        expect_bytes(&opened, &case.msg, "opened bytes")?;

        let (resealed, fed) = in_seal(&key, &case.aad, &case.msg, case.schedule).await;
        fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
        let resealed = resealed.map_err(|e| describe("seal", &e))?;
        expect(resealed.len(), case.sealed.len(), "resealed length")?;
        let (reopened, fed) = in_open(&key, &case.aad, &resealed, Schedule::Whole).await;
        fed.map_err(|e| format!("re-open sealed feeder: {e}"))?;
        let reopened = reopened.map_err(|e| describe("open of fresh seal", &e))?;
        expect_bytes(&reopened, &case.msg, "round-tripped bytes")
    } else {
        expect_err(
            "open",
            ErrKind::AuthenticationFailed,
            opened,
            "accepted an invalid sealed message",
        )
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
        Err(err) => return Err(describe("import-verifying-key-raw", &err)),
    };
    let (verified, fed) = sig_verify(&key, &case.msg, &case.sig, case.schedule).await;
    fed.map_err(|e| format!("verify data feeder: {e}"))?;
    if case.valid {
        verified.map_err(|e| describe("verify failed for the valid case", &e))
    } else {
        expect_err(
            "verify",
            ErrKind::AuthenticationFailed,
            verified,
            "a degenerate signature verified",
        )
    }
}

/// Run one signature-verification vector under its schedule.
pub async fn run_sig_case(case: &SigCase) -> Result<(), String> {
    let key = match case.alg {
        SigAlg::Ed25519 => import_ed25519_verifying_key(case.public.clone())
            .await
            .map_err(|e| describe("import-verifying-key-raw", &e))?,
        SigAlg::EcdsaP256Sha256 => {
            import_ecdsa_verifying_key(EcdsaVariant::P256Sha256, case.public.clone())
                .await
                .map_err(|e| describe("import-verifying-key-raw", &e))?
        }
        SigAlg::EcdsaP384Sha384 => {
            import_ecdsa_verifying_key(EcdsaVariant::P384Sha384, case.public.clone())
                .await
                .map_err(|e| describe("import-verifying-key-raw", &e))?
        }
    };
    let (verified, fed) = sig_verify(&key, &case.msg, &case.sig, case.schedule).await;
    fed.map_err(|e| format!("verify data feeder: {e}"))?;
    if case.valid {
        verified.map_err(|e| describe("verify(sig) failed for a valid vector", &e))
    } else {
        expect_err(
            "verify of an invalid vector",
            ErrKind::AuthenticationFailed,
            verified,
            "verify(sig) succeeded",
        )
    }
}

/// Run one AES-KW vector: both directions, list-based (no schedules).
///
/// The wrap direction routes the vector's key data through an extractable
/// HMAC import and `to-wrap-input-raw` — the only door into the wrap path,
/// by design. The unwrap direction mints the recovered data back out
/// through `hmac-sha2.unwrap-key-raw` and compares the export.
pub async fn run_kw_case(case: &KwCase) -> Result<(), String> {
    use lann_webcrypto_guest::bindings::hmac_sha2;

    let kek = import_kw_key(aes_variant(case.key_bits)?, case.key.clone(), false)
        .await
        .map_err(|e| describe("aes-kw import-key-raw", &e))?;

    // Wrap direction: possible only for a non-empty msg (the wrap-input
    // enters as an extractable key's material, and empty material has no
    // importable form).
    if !case.msg.is_empty() {
        let payload = import_hmac_key(Sha2Variant::Sha256, case.msg.clone(), true)
            .await
            .map_err(|e| describe("payload import", &e))?;
        let input = payload
            .to_wrap_input_raw()
            .await
            .map_err(|e| describe("to-wrap-input-raw", &e))?;
        let wrapped = kek.wrap(input).await;
        let in_domain = case.msg.len() >= 16 && case.msg.len().is_multiple_of(8);
        if case.valid {
            let wrapped = wrapped.map_err(|e| describe("kw-key.wrap", &e))?;
            expect_bytes(&wrapped, &case.ct, "wrapped bytes")?;
        } else if !in_domain {
            expect_err(
                "wrap outside the input domain",
                ErrKind::InvalidKey,
                wrapped,
                "wrapped material outside the RFC 3394 domain",
            )?;
        } else {
            // An in-domain msg on a rejection vector (a modified-ct case):
            // wrapping it succeeds and must NOT reproduce the vector's
            // tampered bytes.
            let wrapped = wrapped.map_err(|e| describe("kw-key.wrap", &e))?;
            if wrapped == case.ct {
                return Err("wrap reproduced a wrapped form upstream marks invalid".into());
            }
        }
    }

    // Unwrap direction: possible only for a non-empty ct.
    if !case.ct.is_empty() {
        let unwrapped = kek.unwrap(case.ct.clone()).await;
        if case.valid {
            let input = unwrapped.map_err(|e| describe("kw-key.unwrap", &e))?;
            let minted = hmac_sha2::unwrap_key_raw(Sha2Variant::Sha256, input, mac_options(true))
                .await
                .map_err(|e| describe("hmac-sha2.unwrap-key-raw", &e))?;
            let recovered = minted
                .export_key_raw()
                .await
                .map_err(|e| describe("recovered-material export", &e))?;
            expect_bytes(&recovered, &case.msg, "unwrapped key data")?;
        } else {
            expect_err(
                "unwrap of an invalid wrapped form",
                ErrKind::AuthenticationFailed,
                unwrapped,
                "unwrapped a wrapped form upstream marks invalid",
            )?;
        }
    }
    Ok(())
}
