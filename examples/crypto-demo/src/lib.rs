//! `crypto-demo`: an example WebAssembly component that exercises the
//! `lann:webcrypto` `mac`, `aead`, `digest`, and `signature` primitive kinds
//! end to end.
//!
//! The component is host-agnostic: the same binary runs unchanged under the
//! Wasmtime (RustCrypto) host and the jco (browser WebCrypto) host, which is
//! what demonstrates cross-implementation compatibility. It drives:
//!
//!   - HMAC-SHA-256 against an RFC 4231 known-answer vector, with the payload
//!     signed both as one stream write and as several small chunked writes
//!     (the result must be chunking-invariant),
//!   - tag verification, positive and negative,
//!   - SHA-256 against the FIPS 180-2 "abc" example (whole and chunked) and
//!     `bytes.constant-time-equal`,
//!   - AES-256-GCM against a NIST GCM known-answer vector (seal and open),
//!   - seal/open round trips with a generated key, including tampered
//!     ciphertext and wrong associated data failing with
//!     `authentication-failed`,
//!   - Ed25519 against an RFC 8032 known-answer vector (deterministic
//!     signing, public-key derivation, verification) and ECDSA P-256
//!     verification against an RFC 6979 known-answer vector,
//!   - the key-capability surface: import/generate, `export` on extractable
//!     keys (an import→export identity round trip), `not-extractable`
//!     failures, and `invalid-key`/`invalid-nonce` rejections.

wit_bindgen::generate!({
    path: "wit",
    world: "crypto-demo",
    generate_all,
});

use exports::demo::webcrypto_demo::demo::Guest;
use lann_webcrypto_guest::bindings::aead::AeadKey;
use lann_webcrypto_guest::bindings::aead_internal_nonce::InternalNonceKey;
use lann_webcrypto_guest::bindings::aes_gcm::{generate_key, import_key, AesVariant};
use lann_webcrypto_guest::bindings::aes_gcm_internal_nonce::generate_key as generate_internal_nonce_key;
use lann_webcrypto_guest::bindings::bytes::constant_time_equal;
use lann_webcrypto_guest::bindings::digest::Digest;
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
use lann_webcrypto_guest::bindings::mac::MacKey;
use lann_webcrypto_guest::bindings::sha2::{make_digest, Sha2Variant};
use lann_webcrypto_guest::bindings::signature::{SigningKey, VerifyingKey};
use lann_webcrypto_guest::bindings::types::Error;
use lann_webcrypto_guest::wit_stream;

// --- RFC 4231 test case 2 (HMAC-SHA-256) ------------------------------------

const HMAC_KEY: &[u8] = b"Jefe";
const HMAC_DATA: &[u8] = b"what do ya want for nothing?";
const HMAC_TAG: &str = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

// --- NIST GCM revised spec, test case 16 (AES-256-GCM) ----------------------

const GCM_KEY: &str = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
const GCM_IV: &str = "cafebabefacedbaddecaf888";
const GCM_PLAINTEXT: &str = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
const GCM_AAD: &str = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
const GCM_CIPHERTEXT: &str = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
                              8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662";
const GCM_TAG: &str = "76fc6ece0f4e1768cddf8853bb2d551b";

// --- RFC 8032 §7.1 test 2 (Ed25519) ------------------------------------------

const ED25519_SEED: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
const ED25519_PUBLIC: &str = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
const ED25519_MESSAGE: &[u8] = &[0x72];
const ED25519_SIG: &str = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
                           085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";

// --- RFC 6979 A.2.5 (ECDSA P-256 + SHA-256, message "sample") ----------------

const ECDSA_PUBLIC_X: &str = "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6";
const ECDSA_PUBLIC_Y: &str = "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";
const ECDSA_MESSAGE: &[u8] = b"sample";
const ECDSA_SIG_R: &str = "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716";
const ECDSA_SIG_S: &str = "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8";

struct Component;

impl Guest for Component {
    async fn run() -> Result<String, String> {
        let mut passed: Vec<&'static str> = Vec::new();
        let mut check = async |name: &'static str, result: Result<(), String>| match result {
            Ok(()) => {
                passed.push(name);
                Ok(())
            }
            Err(detail) => Err(format!("check '{name}' failed: {detail}")),
        };

        check("hmac-known-answer", hmac_known_answer(usize::MAX).await).await?;
        check("hmac-chunked-sign", hmac_known_answer(5).await).await?;
        check("hmac-verify", hmac_verify().await).await?;
        check("hmac-generated-key", hmac_generated_key().await).await?;
        check("hmac-key-export", hmac_key_export().await).await?;
        check("sha256-digest", sha256_digest(usize::MAX).await).await?;
        check("sha256-digest-chunked", sha256_digest(5).await).await?;
        check("constant-time-equal", bytes_equal().await).await?;
        check("gcm-known-answer-seal", gcm_known_answer_seal().await).await?;
        check("gcm-known-answer-open", gcm_known_answer_open().await).await?;
        check("gcm-round-trip", gcm_round_trip().await).await?;
        check("gcm-tampered", gcm_tampered().await).await?;
        check("gcm-wrong-aad", gcm_wrong_aad().await).await?;
        check("gcm-invalid-key", gcm_invalid_key().await).await?;
        check("gcm-invalid-nonce", gcm_invalid_nonce().await).await?;
        check("gcm-key-export", gcm_key_export().await).await?;
        check("gcm-internal-nonce", gcm_internal_nonce().await).await?;
        check("ed25519-known-answer", ed25519_known_answer().await).await?;
        check("ed25519-verify", ed25519_verify_check().await).await?;
        check("ed25519-generated-key", ed25519_generated_key().await).await?;
        check("ed25519-key-export", ed25519_key_export().await).await?;
        check(
            "ecdsa-verify-known-answer",
            ecdsa_verify_known_answer().await,
        )
        .await?;

        Ok(format!(
            "{} checks passed: {}",
            passed.len(),
            passed.join(", ")
        ))
    }
}

// --- mac checks --------------------------------------------------------------

/// HMAC the RFC 4231 payload, feeding it in `chunk`-byte writes, and compare
/// against the vector's tag. `usize::MAX` feeds the payload as one write.
async fn hmac_known_answer(chunk: usize) -> Result<(), String> {
    let key = import_hmac_key(Sha2Variant::Sha256, HMAC_KEY.to_vec(), true)
        .await
        .map_err(|e| describe("import-key", &e))?;
    expect_eq(
        key.algorithm_name(),
        "HMAC".to_string(),
        "mac-key.algorithm-name",
    )?;
    expect_eq(
        key.algorithm_hash(),
        Some("SHA-256".to_string()),
        "mac-key.algorithm-hash",
    )?;
    expect_eq(
        key.algorithm_length(),
        HMAC_KEY.len() as u32 * 8,
        "mac-key.algorithm-length",
    )?;

    let tag = sign_chunked(&key, HMAC_DATA, chunk).await?;
    expect_eq(hex(&tag), HMAC_TAG.to_string(), "sign tag")
}

/// `verify` accepts the correct tag and rejects a corrupted one.
async fn hmac_verify() -> Result<(), String> {
    let key = import_hmac_key(Sha2Variant::Sha256, HMAC_KEY.to_vec(), false)
        .await
        .map_err(|e| describe("import-key", &e))?;

    let mut tag = unhex(HMAC_TAG);
    verify_chunked(&key, HMAC_DATA, tag.clone(), usize::MAX)
        .await?
        .map_err(|e| describe("correct tag did not verify", &e))?;

    tag[0] ^= 0x01;
    match verify_chunked(&key, HMAC_DATA, tag, usize::MAX).await? {
        Err(Error::AuthenticationFailed) => Ok(()),
        Err(other) => Err(describe("expected authentication-failed, got", &other)),
        Ok(()) => Err("corrupted tag verified".into()),
    }
}

/// A generated key signs and verifies, and two calls on the same key agree.
async fn hmac_generated_key() -> Result<(), String> {
    let key = generate_hmac_key(Sha2Variant::Sha256, None, false)
        .await
        .map_err(|e| describe("generate-key", &e))?;

    let tag = sign_chunked(&key, b"payload", usize::MAX).await?;
    expect_eq(tag.len(), 32, "tag length")?;

    if verify_chunked(&key, b"payload", tag, 3).await?.is_err() {
        return Err("generated key's tag did not verify".into());
    }

    // A non-extractable key must not export.
    match key.export_key().await {
        Err(Error::NotExtractable) => Ok(()),
        Err(other) => Err(describe("expected not-extractable, got", &other)),
        Ok(_) => Err("non-extractable key exported".into()),
    }
}

/// `import` → `export` on an extractable key is the identity; a generated
/// extractable key exports the hash's block size of material (WebCrypto's
/// `generateKey` default: 64 bytes for SHA-256).
async fn hmac_key_export() -> Result<(), String> {
    // Exercises the library's newtype layer (`hmac_sha2` + `Mac`) rather
    // than the raw bindings the rest of the demo drives.
    use lann_webcrypto_guest::hmac_sha2;
    let key = hmac_sha2::import_key(Sha2Variant::Sha256, HMAC_KEY.to_vec(), true)
        .await
        .map_err(|e| format!("import-key: {e}"))?;
    let exported = key
        .export_key()
        .await
        .map_err(|e| format!("export of extractable key: {e}"))?;
    expect_eq(exported, HMAC_KEY.to_vec(), "exported key material")?;
    let tag = key
        .sign(HMAC_DATA)
        .await
        .map_err(|e| format!("sign: {e}"))?;
    expect_eq(hex(&tag), HMAC_TAG.to_string(), "wrapper sign tag")?;
    key.verify(HMAC_DATA, &tag)
        .await
        .map_err(|e| format!("wrapper verify: {e}"))?;

    // A borrowed payload spanning several of the wrapper's feed chunks
    // round-trips sign→verify (the wrapper feeds borrowed sources
    // incrementally; the result must be chunking-invariant).
    let big: Vec<u8> = (0..=255u8).cycle().take(3 * 8192 + 11).collect();
    let tag = key
        .sign(&big[..])
        .await
        .map_err(|e| format!("wrapper sign (multi-chunk): {e}"))?;
    key.verify(&big[..], tag)
        .await
        .map_err(|e| format!("wrapper verify (multi-chunk): {e}"))?;

    let generated = hmac_sha2::generate_key(Sha2Variant::Sha256, None, true)
        .await
        .map_err(|e| format!("generate-key: {e}"))?;
    let exported = generated
        .export_key()
        .await
        .map_err(|e| format!("export of generated key: {e}"))?;
    expect_eq(exported.len(), 64, "generated key length")
}

// --- digest & bytes checks -----------------------------------------------------

/// The FIPS 180-2 "abc" SHA-256 example digest.
const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

/// SHA-256 the FIPS example message, feeding it in `chunk`-byte writes, and
/// compare against the known digest. `usize::MAX` feeds it as one write.
async fn sha256_digest(chunk: usize) -> Result<(), String> {
    let digest = make_digest(Sha2Variant::Sha256).map_err(|e| describe("make-digest", &e))?;
    expect_eq(
        digest.algorithm_name(),
        "SHA-256".to_string(),
        "digest.algorithm-name",
    )?;
    let got = compute_chunked(&digest, b"abc", chunk).await?;
    expect_eq(hex(&got), SHA256_ABC.to_string(), "computed digest")?;
    // The resource is reusable: a second compute agrees.
    let again = compute_chunked(&digest, b"abc", chunk).await?;
    expect_eq(hex(&again), SHA256_ABC.to_string(), "recomputed digest")
}

/// `constant-time-equal` agrees with plain equality.
async fn bytes_equal() -> Result<(), String> {
    let digest = unhex(SHA256_ABC);
    let mut tampered = digest.clone();
    tampered[0] ^= 0x01;
    expect_eq(constant_time_equal(&digest, &digest), true, "equal inputs")?;
    expect_eq(
        constant_time_equal(&digest, &tampered),
        false,
        "differing inputs",
    )?;
    expect_eq(
        constant_time_equal(&digest, &digest[..31]),
        false,
        "different lengths",
    )?;
    expect_eq(constant_time_equal(&[], &[]), true, "empty inputs")
}

// --- aead checks -------------------------------------------------------------

/// Seal the NIST vector's plaintext and compare against its ciphertext‖tag.
async fn gcm_known_answer_seal() -> Result<(), String> {
    let key = import_key(AesVariant::Aes256, unhex(GCM_KEY), false)
        .await
        .map_err(|e| describe("import-key", &e))?;
    expect_eq(
        key.algorithm_name(),
        "AES-GCM".to_string(),
        "aead-key.algorithm-name",
    )?;
    expect_eq(key.algorithm_length(), 256, "aead-key.algorithm-length")?;
    expect_eq(key.nonce_size(), 12, "aead-key.nonce-size")?;
    expect_eq(key.tag_size(), 16, "aead-key.tag-size")?;

    let sealed = seal_chunked(
        &key,
        &unhex(GCM_IV),
        &unhex(GCM_AAD),
        &unhex(GCM_PLAINTEXT),
        7,
    )
    .await
    .map_err(|e| describe("seal", &e))?;
    let mut expected = unhex(GCM_CIPHERTEXT);
    expected.extend(unhex(GCM_TAG));
    expect_eq(hex(&sealed), hex(&expected), "sealed bytes")
}

/// Open the NIST vector's ciphertext‖tag (fed one byte at a time) and compare
/// against its plaintext.
async fn gcm_known_answer_open() -> Result<(), String> {
    let key = import_key(AesVariant::Aes256, unhex(GCM_KEY), false)
        .await
        .map_err(|e| describe("import-key", &e))?;

    let mut ciphertext = unhex(GCM_CIPHERTEXT);
    ciphertext.extend(unhex(GCM_TAG));
    let opened = open_chunked(&key, &unhex(GCM_IV), &unhex(GCM_AAD), &ciphertext, 1)
        .await
        .map_err(|e| describe("open", &e))?;
    expect_eq(hex(&opened), GCM_PLAINTEXT.replace(' ', ""), "opened bytes")
}

/// Seal then open under a generated key round-trips the plaintext.
async fn gcm_round_trip() -> Result<(), String> {
    let key = generate_key(AesVariant::Aes256, false)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    let nonce = [7u8; 12];
    let aad = b"round-trip aad";
    let plaintext: Vec<u8> = (0..=255u8).cycle().take(3 * 1024 + 17).collect();

    let sealed = seal_chunked(&key, &nonce, aad, &plaintext, 512)
        .await
        .map_err(|e| describe("seal", &e))?;
    expect_eq(sealed.len(), plaintext.len() + 16, "sealed length")?;

    let opened = open_chunked(&key, &nonce, aad, &sealed, 512)
        .await
        .map_err(|e| describe("open", &e))?;
    expect_eq(opened == plaintext, true, "round-tripped plaintext")
}

/// A flipped ciphertext bit fails with `authentication-failed`.
async fn gcm_tampered() -> Result<(), String> {
    let key = generate_key(AesVariant::Aes256, false)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    let nonce = [9u8; 12];
    let mut sealed = seal_chunked(&key, &nonce, b"", b"attack at dawn", usize::MAX)
        .await
        .map_err(|e| describe("seal", &e))?;
    sealed[0] ^= 0x80;
    match open_chunked(&key, &nonce, b"", &sealed, usize::MAX).await {
        Err(Error::AuthenticationFailed) => Ok(()),
        Err(other) => Err(describe("expected authentication-failed, got", &other)),
        Ok(_) => Err("tampered ciphertext opened".into()),
    }
}

/// The wrong associated data fails with `authentication-failed`.
async fn gcm_wrong_aad() -> Result<(), String> {
    let key = generate_key(AesVariant::Aes256, false)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    let nonce = [11u8; 12];
    let sealed = seal_chunked(&key, &nonce, b"right aad", b"payload", usize::MAX)
        .await
        .map_err(|e| describe("seal", &e))?;
    match open_chunked(&key, &nonce, b"wrong aad", &sealed, usize::MAX).await {
        Err(Error::AuthenticationFailed) => Ok(()),
        Err(other) => Err(describe("expected authentication-failed, got", &other)),
        Ok(_) => Err("wrong aad opened".into()),
    }
}

/// Importing wrong-length key material fails with `invalid-key`.
async fn gcm_invalid_key() -> Result<(), String> {
    match import_key(AesVariant::Aes256, vec![0u8; 16], false).await {
        Err(Error::InvalidKey(_)) => Ok(()),
        Err(other) => Err(describe("expected invalid-key, got", &other)),
        Ok(_) => Err("16-byte key imported as AES-256".into()),
    }
}

/// Sealing with a wrong-length nonce fails with `invalid-nonce`.
async fn gcm_invalid_nonce() -> Result<(), String> {
    let key = generate_key(AesVariant::Aes256, false)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    match seal_chunked(&key, &[0u8; 8], b"", b"payload", usize::MAX).await {
        Err(Error::InvalidNonce(_)) => Ok(()),
        Err(other) => Err(describe("expected invalid-nonce, got", &other)),
        Ok(_) => Err("8-byte nonce accepted".into()),
    }
}

/// Extractability behaves for AEAD keys exactly as for MAC keys.
async fn gcm_key_export() -> Result<(), String> {
    let raw = unhex(GCM_KEY);
    let key = import_key(AesVariant::Aes256, raw.clone(), true)
        .await
        .map_err(|e| describe("import-key", &e))?;
    let exported = key
        .export_key()
        .await
        .map_err(|e| describe("export of extractable key", &e))?;
    expect_eq(exported, raw, "exported key material")?;

    let sealed_key = generate_key(AesVariant::Aes256, false)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    match sealed_key.export_key().await {
        Err(Error::NotExtractable) => Ok(()),
        Err(other) => Err(describe("expected not-extractable, got", &other)),
        Ok(_) => Err("non-extractable key exported".into()),
    }
}

/// The internal-nonce discipline end to end: sealed messages are
/// self-contained (`iv ‖ ciphertext ‖ tag`), round-trip under the same key,
/// draw a fresh nonce per seal, and fail closed on wrong associated data.
async fn gcm_internal_nonce() -> Result<(), String> {
    let key = generate_internal_nonce_key(AesVariant::Aes256, false)
        .await
        .map_err(|e| describe("generate-key (internal nonce)", &e))?;
    expect_eq(
        key.algorithm_name(),
        "AES-GCM".to_string(),
        "internal-nonce-key.algorithm-name",
    )?;
    expect_eq(
        key.algorithm_length(),
        256,
        "internal-nonce-key.algorithm-length",
    )?;

    let before = key
        .seals_remaining()
        .ok_or("AES-GCM internal-nonce key reports no nonce budget")?;

    let aad = b"internal-nonce aad";
    let plaintext: Vec<u8> = (0..=255u8).cycle().take(2 * 1024 + 9).collect();

    let sealed = in_seal_chunked(&key, aad, &plaintext, 512)
        .await
        .map_err(|e| describe("seal", &e))?;
    // 12-byte IV prefix + ciphertext + 16-byte tag.
    expect_eq(sealed.len(), plaintext.len() + 12 + 16, "sealed length")?;

    let opened = in_open_chunked(&key, aad, &sealed, 512)
        .await
        .map_err(|e| describe("open", &e))?;
    expect_eq(opened == plaintext, true, "round-tripped plaintext")?;

    // The budget hint decreases as seals consume it: if the key permits N
    // further seals, after one it permits at most N - 1.
    let after = key
        .seals_remaining()
        .ok_or("nonce budget disappeared after sealing")?;
    expect_eq(after < before, true, "seals-remaining decreased")?;

    // A second seal of the same plaintext must draw a fresh nonce.
    let resealed = in_seal_chunked(&key, aad, &plaintext, usize::MAX)
        .await
        .map_err(|e| describe("second seal", &e))?;
    expect_eq(
        sealed[..12] != resealed[..12],
        true,
        "distinct nonces across seals",
    )?;

    match in_open_chunked(&key, b"wrong aad", &sealed, usize::MAX).await {
        Err(Error::AuthenticationFailed) => Ok(()),
        Err(other) => Err(describe("expected authentication-failed, got", &other)),
        Ok(_) => Err("wrong aad opened".into()),
    }
}

// --- stream helpers ----------------------------------------------------------

/// `sign`, feeding `data` in `chunk`-byte pieces (one stream; `usize::MAX`
/// writes it whole).
async fn sign_chunked(key: &MacKey, data: &[u8], chunk: usize) -> Result<Vec<u8>, String> {
    let (tx, rx) = wit_stream::new();
    let (tag, fed) = futures::join!(key.sign(rx), feed(tx, data, chunk));
    fed?;
    tag.map_err(|e| describe("mac-key.sign", &e))
}

/// `compute`, feeding `data` in `chunk`-byte pieces (one stream;
/// `usize::MAX` writes it whole).
async fn compute_chunked(digest: &Digest, data: &[u8], chunk: usize) -> Result<Vec<u8>, String> {
    let (tx, rx) = wit_stream::new();
    let (got, fed) = futures::join!(digest.compute(rx), feed(tx, data, chunk));
    fed?;
    got.map_err(|e| describe("digest.compute", &e))
}

/// `verify`, feeding `data` in `chunk`-byte pieces (one stream; `usize::MAX`
/// writes it whole).
async fn verify_chunked(
    key: &MacKey,
    data: &[u8],
    tag: Vec<u8>,
    chunk: usize,
) -> Result<Result<(), Error>, String> {
    let (tx, rx) = wit_stream::new();
    let (verified, fed) = futures::join!(key.verify(rx, tag), feed(tx, data, chunk));
    fed?;
    Ok(verified)
}

/// `seal`, feeding the plaintext in `chunk`-byte pieces and collecting the
/// returned ciphertext stream.
async fn seal_chunked(
    key: &AeadKey,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    chunk: usize,
) -> Result<Vec<u8>, Error> {
    let (tx, rx) = wit_stream::new();
    let (sealed, fed) = futures::join!(
        key.seal(nonce.to_vec(), aad.to_vec(), rx),
        feed(tx, plaintext, chunk)
    );
    fed.map_err(Error::Other)?;
    Ok(sealed?.collect().await)
}

/// `open`, feeding the ciphertext in `chunk`-byte pieces and collecting the
/// returned plaintext stream.
async fn open_chunked(
    key: &AeadKey,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    chunk: usize,
) -> Result<Vec<u8>, Error> {
    let (tx, rx) = wit_stream::new();
    let (opened, fed) = futures::join!(
        key.open(nonce.to_vec(), aad.to_vec(), rx),
        feed(tx, ciphertext, chunk)
    );
    fed.map_err(Error::Other)?;
    Ok(opened?.collect().await)
}

/// `internal-nonce-key.seal`, feeding the plaintext in `chunk`-byte pieces
/// and collecting the returned sealed-message stream.
async fn in_seal_chunked(
    key: &InternalNonceKey,
    aad: &[u8],
    plaintext: &[u8],
    chunk: usize,
) -> Result<Vec<u8>, Error> {
    let (tx, rx) = wit_stream::new();
    let (sealed, fed) = futures::join!(key.seal(aad.to_vec(), rx), feed(tx, plaintext, chunk));
    fed.map_err(Error::Other)?;
    Ok(sealed?.collect().await)
}

/// `internal-nonce-key.open`, feeding the sealed message in `chunk`-byte
/// pieces and collecting the returned plaintext stream.
async fn in_open_chunked(
    key: &InternalNonceKey,
    aad: &[u8],
    sealed: &[u8],
    chunk: usize,
) -> Result<Vec<u8>, Error> {
    let (tx, rx) = wit_stream::new();
    let (opened, fed) = futures::join!(key.open(aad.to_vec(), rx), feed(tx, sealed, chunk));
    fed.map_err(Error::Other)?;
    Ok(opened?.collect().await)
}

/// Write `data` to `tx` in `chunk`-byte pieces, then drop the writer to end
/// the stream.
async fn feed(
    mut tx: wit_bindgen::StreamWriter<u8>,
    data: &[u8],
    chunk: usize,
) -> Result<(), String> {
    for piece in data.chunks(chunk.max(1)) {
        let leftover = tx.write_all(piece.to_vec()).await;
        if !leftover.is_empty() {
            return Err("stream writer closed early".into());
        }
    }
    Ok(())
}

// --- small utilities ---------------------------------------------------------

/// Render a WIT `error` with a context prefix.
fn describe(context: &str, error: &Error) -> String {
    let rendered = match error {
        Error::InvalidKey(detail) => format!("invalid-key: {detail}"),
        Error::InvalidNonce(detail) => format!("invalid-nonce: {detail}"),
        Error::AuthenticationFailed => "authentication-failed".to_string(),
        Error::NotExtractable => "not-extractable".to_string(),
        Error::Unsupported(detail) => format!("unsupported: {detail}"),
        Error::KeyExhausted => "key-exhausted".to_string(),
        Error::Other(detail) => format!("other: {detail}"),
    };
    format!("{context}: {rendered}")
}

fn expect_eq<T: PartialEq + std::fmt::Debug>(got: T, want: T, what: &str) -> Result<(), String> {
    if got == want {
        Ok(())
    } else {
        Err(format!("{what}: got {got:?}, want {want:?}"))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(hex: &str) -> Vec<u8> {
    let hex: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    hex.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

export!(Component);

// --- signature checks ----------------------------------------------------------

/// Sign an entire byte stream (whole-write) with a `signing-key`.
async fn sig_sign(key: &SigningKey, data: &[u8]) -> Result<Vec<u8>, String> {
    let (tx, rx) = wit_stream::new();
    let (sig, fed) = futures::join!(key.sign(rx), feed(tx, data, usize::MAX));
    fed?;
    sig.map_err(|e| describe("signing-key.sign", &e))
}

/// Verify `sig` over an entire byte stream (whole-write) with a
/// `verifying-key`.
async fn sig_verify(
    key: &VerifyingKey,
    data: &[u8],
    sig: Vec<u8>,
) -> Result<Result<(), Error>, String> {
    let (tx, rx) = wit_stream::new();
    let (verified, fed) = futures::join!(key.verify(rx, sig), feed(tx, data, usize::MAX));
    fed?;
    Ok(verified)
}

/// The RFC 8032 known answer: importing the seed reproduces the vector's
/// signature (Ed25519 is deterministic), the getters report the algorithm,
/// and the vector's public key verifies the result.
async fn ed25519_known_answer() -> Result<(), String> {
    let key = import_ed25519_signing_key(unhex(ED25519_SEED), false)
        .await
        .map_err(|e| describe("import-signing-key", &e))?;
    expect_eq(
        key.algorithm_name(),
        "Ed25519".to_string(),
        "signing-key.algorithm-name",
    )?;
    expect_eq(key.algorithm_curve(), None, "signing-key.algorithm-curve")?;
    expect_eq(key.algorithm_hash(), None, "signing-key.algorithm-hash")?;

    let sig = sig_sign(&key, ED25519_MESSAGE).await?;
    expect_eq(
        hex(&sig),
        ED25519_SIG.replace(char::is_whitespace, ""),
        "signature",
    )?;

    let public = import_ed25519_verifying_key(unhex(ED25519_PUBLIC))
        .await
        .map_err(|e| describe("import-verifying-key", &e))?;
    sig_verify(&public, ED25519_MESSAGE, sig)
        .await?
        .map_err(|e| describe("known-answer signature did not verify", &e))
}

/// An imported public key verifies the vector's signature and rejects a
/// corrupted one with `authentication-failed`.
async fn ed25519_verify_check() -> Result<(), String> {
    let key = import_ed25519_verifying_key(unhex(ED25519_PUBLIC))
        .await
        .map_err(|e| describe("import-verifying-key", &e))?;
    expect_eq(
        key.algorithm_name(),
        "Ed25519".to_string(),
        "verifying-key.algorithm-name",
    )?;

    let mut sig = unhex(&ED25519_SIG.replace(char::is_whitespace, ""));
    sig_verify(&key, ED25519_MESSAGE, sig.clone())
        .await?
        .map_err(|e| describe("correct signature did not verify", &e))?;

    sig[0] ^= 0x01;
    match sig_verify(&key, ED25519_MESSAGE, sig).await? {
        Err(Error::AuthenticationFailed) => Ok(()),
        Err(other) => Err(describe("expected authentication-failed, got", &other)),
        Ok(()) => Err("corrupted signature verified".into()),
    }
}

/// A generated key pair round-trips sign→verify, and the private half's
/// non-extractable material stays that way.
async fn ed25519_generated_key() -> Result<(), String> {
    let (key, public) = generate_ed25519_key(false)
        .await
        .map_err(|e| describe("generate-key", &e))?;
    expect_eq(key.extractable(), false, "signing-key.extractable")?;

    let sig = sig_sign(&key, b"payload").await?;
    expect_eq(sig.len(), 64, "signature length")?;
    sig_verify(&public, b"payload", sig)
        .await?
        .map_err(|e| describe("round-trip signature did not verify", &e))?;

    match key.export_key().await {
        Err(Error::NotExtractable) => Ok(()),
        Err(other) => Err(describe("expected not-extractable, got", &other)),
        Ok(_) => Err("non-extractable key exported".into()),
    }
}

/// An extractable imported key exports the seed it was imported from.
async fn ed25519_key_export() -> Result<(), String> {
    let key = import_ed25519_signing_key(unhex(ED25519_SEED), true)
        .await
        .map_err(|e| describe("import-signing-key", &e))?;
    expect_eq(key.extractable(), true, "signing-key.extractable")?;
    let exported = key.export_key().await.map_err(|e| describe("export", &e))?;
    expect_eq(hex(&exported), ED25519_SEED.to_string(), "exported seed")
}

/// The RFC 6979 known answer: an imported P-256 public key reports its
/// variant through the getters, verifies the deterministic signature over
/// "sample", and rejects a corrupted one.
async fn ecdsa_verify_known_answer() -> Result<(), String> {
    let mut point = vec![0x04];
    point.extend(unhex(ECDSA_PUBLIC_X));
    point.extend(unhex(ECDSA_PUBLIC_Y));
    let key = import_ecdsa_verifying_key(EcdsaVariant::P256Sha256, point)
        .await
        .map_err(|e| describe("import-verifying-key", &e))?;
    expect_eq(
        key.algorithm_name(),
        "ECDSA".to_string(),
        "verifying-key.algorithm-name",
    )?;
    expect_eq(
        key.algorithm_curve(),
        Some("P-256".to_string()),
        "verifying-key.algorithm-curve",
    )?;
    expect_eq(
        key.algorithm_hash(),
        Some("SHA-256".to_string()),
        "verifying-key.algorithm-hash",
    )?;

    let mut sig = unhex(ECDSA_SIG_R);
    sig.extend(unhex(ECDSA_SIG_S));
    sig_verify(&key, ECDSA_MESSAGE, sig.clone())
        .await?
        .map_err(|e| describe("known-answer signature did not verify", &e))?;

    sig[0] ^= 0x01;
    match sig_verify(&key, ECDSA_MESSAGE, sig).await? {
        Err(Error::AuthenticationFailed) => Ok(()),
        Err(other) => Err(describe("expected authentication-failed, got", &other)),
        Ok(()) => Err("corrupted signature verified".into()),
    }
}
