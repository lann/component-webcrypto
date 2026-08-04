//! Execution of the normalized vector cases against the imported
//! `lann:webcrypto` interfaces.

use crate::mint::{
    import_cbc_key, import_ecdh_public_key_jwk, import_ecdh_public_key_raw,
    import_ecdh_public_key_spki, import_ecdh_secret_key, import_hmac_key, import_hmac_sha1_key,
    import_ikm, import_key_raw, import_kw_key, import_password, import_rsa_pss_verifying_key_jwk,
    import_rsa_pss_verifying_key_spki, import_rsassa_verifying_key_jwk,
    import_rsassa_verifying_key_spki, import_x25519_public_key, import_x25519_secret_key,
    mac_options,
};
use crate::translate::{
    AeadAlg, AeadCase, AeadExpectation, CbcCase, EcdhCase, EcdhCurve, EcdhPublic, HkdfAlg,
    HkdfCase, HmacAlg, HmacCase, KwCase, Pbkdf2Alg, Pbkdf2Case, RsaCase, RsaExpectation, RsaFamily,
    RsaImport, Sha2Alg, Sha2Case, SigAlg, SigCase, SpeccheckCase, X25519Case,
};
use conformance_harness::stream::{
    ci_decrypt_ok, ci_decrypt_op, ci_encrypt_ok, compute_ok, open_ok, open_op, seal_ok, seal_op,
    sig_verify, sign_ok, verify_ok, verify_op, Schedule,
};
use conformance_harness::{describe, expect_bytes, expect_err, ErrKind};
use lann_webcrypto_guest::bindings::aead::AeadKey;
use lann_webcrypto_guest::bindings::aes_gcm::AesVariant;
use lann_webcrypto_guest::bindings::ecdh::EcdhVariant;
use lann_webcrypto_guest::bindings::ecdsa_verify::{
    import_verifying_key_raw as import_ecdsa_verifying_key, EcdsaVariant,
};
use lann_webcrypto_guest::bindings::ed25519_verify::import_verifying_key_raw as import_ed25519_verifying_key;
use lann_webcrypto_guest::bindings::hkdf_sha2;
use lann_webcrypto_guest::bindings::pbkdf2_sha2;
use lann_webcrypto_guest::bindings::rsa::RsaVariant;
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
    let got = compute_ok(&digest, &case.msg, case.schedule, "compute").await?;
    expect_bytes(&got, &case.md, "computed digest")?;
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
        let tag = sign_ok(&key, &case.msg, case.schedule).await?;
        expect_bytes(&tag, &case.tag, "sign tag")?;

        verify_ok(
            &key,
            &case.msg,
            &case.tag,
            case.schedule,
            "verify(tag) failed for a valid vector",
        )
        .await?;
    } else {
        let verified = verify_op(&key, &case.msg, &case.tag, case.schedule).await?;
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

/// The `ecdh-variant` for a translated case's curve (P-521 never reaches
/// translation; its decline is probed).
fn ecdh_variant(curve: EcdhCurve) -> EcdhVariant {
    match curve {
        EcdhCurve::P256 => EcdhVariant::P256,
        EcdhCurve::P384 => EcdhVariant::P384,
    }
}

/// Run one ECDH vector: import the peer's public key per the file's
/// encoding and the secret key as an EC private JWK, `agree`, and check
/// the derived shared secret at its natural length (and a truncated
/// prefix) — or, for the rejection cases, expect the public import to
/// fail `invalid-key` (every rejection in these files is a public-key
/// admission failure; the WIT pins strict admission at import).
pub async fn run_ecdh_case(case: &EcdhCase) -> Result<(), String> {
    let variant = ecdh_variant(case.curve);
    let (what, peer) = match &case.public {
        EcdhPublic::Raw(raw) => (
            "import-public-key-raw",
            import_ecdh_public_key_raw(variant, raw.clone()).await,
        ),
        EcdhPublic::Spki(spki) => (
            "import-public-key-spki",
            import_ecdh_public_key_spki(variant, spki.clone()).await,
        ),
        EcdhPublic::Jwk(jwk) => (
            "import-public-key-jwk",
            import_ecdh_public_key_jwk(variant, jwk.clone()).await,
        ),
    };
    if case.reject_public {
        return expect_err(
            what,
            ErrKind::InvalidKey,
            peer,
            "imported a public key upstream marks for rejection",
        );
    }
    let peer = peer.map_err(|e| describe(what, &e))?;
    let secret = import_ecdh_secret_key(variant, case.secret_jwk.clone(), true, true)
        .await
        .map_err(|e| describe("import-secret-key-jwk", &e))?;
    let input = secret
        .agree(&peer)
        .await
        .map_err(|e| describe("agree", &e))?;
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
        let sealed =
            ci_encrypt_ok(&key, &case.iv, None, &case.msg, case.schedule, "encrypt").await?;
        expect_bytes(&sealed, &case.ct, "computed ciphertext")?;
        let opened =
            ci_decrypt_ok(&key, &case.iv, None, &case.ct, case.schedule, "decrypt").await?;
        expect_bytes(&opened, &case.msg, "decrypted plaintext")
    } else {
        let opened = ci_decrypt_op(&key, &case.iv, None, &case.ct, case.schedule).await?;
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

/// Run one caller-nonce AEAD vector under its schedule.
pub async fn run_aead_case(case: &AeadCase) -> Result<(), String> {
    let key = match case.alg {
        AeadAlg::AesGcm => {
            import_key_raw(aes_variant(case.key_bits)?, case.key.clone(), false).await
        }
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
            let sealed = seal_op(key, iv, aad, None, msg, schedule).await?;
            expect_err(
                "seal",
                ErrKind::InvalidNonce,
                sealed,
                &format!("accepted a {}-byte nonce", iv.len()),
            )?;
            let opened = open_op(key, iv, aad, None, ct_tag, schedule).await?;
            expect_err(
                "open",
                ErrKind::InvalidNonce,
                opened,
                &format!("accepted a {}-byte nonce", iv.len()),
            )
        }
        AeadExpectation::Valid => {
            let sealed = seal_ok(key, iv, aad, None, msg, schedule, "seal").await?;
            expect_bytes(&sealed, ct_tag, "sealed bytes")?;

            let opened = open_ok(key, iv, aad, None, ct_tag, schedule, "open").await?;
            expect_bytes(&opened, msg, "opened bytes")
        }
        AeadExpectation::AuthenticationFailed => {
            let opened = open_op(key, iv, aad, None, ct_tag, schedule).await?;
            expect_err(
                "open",
                ErrKind::AuthenticationFailed,
                opened,
                "accepted an invalid vector",
            )
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
        SigAlg::EcdsaP256Sha512 => {
            import_ecdsa_verifying_key(EcdsaVariant::P256Sha512, case.public.clone())
                .await
                .map_err(|e| describe("import-verifying-key-raw", &e))?
        }
        SigAlg::EcdsaP384Sha384 => {
            import_ecdsa_verifying_key(EcdsaVariant::P384Sha384, case.public.clone())
                .await
                .map_err(|e| describe("import-verifying-key-raw", &e))?
        }
        SigAlg::EcdsaP384Sha512 => {
            import_ecdsa_verifying_key(EcdsaVariant::P384Sha512, case.public.clone())
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

/// The `rsa-variant` for a translated case's digest parameterization.
fn rsa_variant(sha: Sha2Alg) -> RsaVariant {
    match sha {
        Sha2Alg::Sha256 => RsaVariant::Sha256,
        Sha2Alg::Sha384 => RsaVariant::Sha384,
        Sha2Alg::Sha512 => RsaVariant::Sha512,
    }
}

/// Run one RSA signature-verification vector: import the group's public
/// key per the case's import path and expectation — the id-RSASSA-PSS
/// file's cases must fail the import `invalid-key`; everything else
/// imports and verifies `sig` over `msg` under the case's schedule,
/// succeeding (`valid`) or failing `authentication-failed` (`invalid`,
/// and the `acceptable` BER-laxity vectors the strict verification
/// contract rejects uniformly).
pub async fn run_rsa_case(case: &RsaCase) -> Result<(), String> {
    let variant = rsa_variant(case.alg.sha);
    let (what, key) = match (case.alg.family, &case.import) {
        (RsaFamily::Pkcs1V15, RsaImport::Spki(spki)) => (
            "import-verifying-key-spki",
            import_rsassa_verifying_key_spki(variant, spki.clone()).await,
        ),
        (RsaFamily::Pkcs1V15, RsaImport::Jwk(jwk)) => (
            "import-verifying-key-jwk",
            import_rsassa_verifying_key_jwk(variant, jwk.clone()).await,
        ),
        (RsaFamily::Pss { salt_len }, RsaImport::Spki(spki)) => (
            "import-verifying-key-spki",
            import_rsa_pss_verifying_key_spki(variant, salt_len, spki.clone()).await,
        ),
        (RsaFamily::Pss { salt_len }, RsaImport::Jwk(jwk)) => (
            "import-verifying-key-jwk",
            import_rsa_pss_verifying_key_jwk(variant, salt_len, jwk.clone()).await,
        ),
    };
    if matches!(case.expectation, RsaExpectation::RejectImport) {
        return expect_err(
            what,
            ErrKind::InvalidKey,
            key,
            "imported a key carrying the id-RSASSA-PSS AlgorithmIdentifier",
        );
    }
    let key = key.map_err(|e| describe(what, &e))?;
    let schedule = case
        .schedule
        .ok_or("verification case carries no schedule")?;
    let (verified, fed) = sig_verify(&key, &case.msg, &case.sig, schedule).await;
    fed.map_err(|e| format!("verify data feeder: {e}"))?;
    match case.expectation {
        RsaExpectation::Valid => {
            verified.map_err(|e| describe("verify(sig) failed for a valid vector", &e))
        }
        _ => expect_err(
            "verify of an invalid vector",
            ErrKind::AuthenticationFailed,
            verified,
            "verify(sig) succeeded",
        ),
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
