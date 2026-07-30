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

use anyhow::{ensure, Context, Result};
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

/// Assert that `result` failed with an error matching `pattern` (e.g.
/// `Error::InvalidKey(_)`). `accepted` says what its wrongly succeeding
/// would mean.
macro_rules! expect_error {
    ($result:expr, $pattern:pat, $accepted:expr $(,)?) => {
        match $result {
            Err(err) if matches!(err, $pattern) => Ok(()),
            Err(other) => Err(anyhow::Error::new(other).context(concat!(
                "expected ",
                stringify!($pattern),
                ", got"
            ))),
            Ok(_) => anyhow::bail!($accepted),
        }
    };
}

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
        let mut check = async |name: &'static str, result: Result<()>| match result {
            Ok(()) => {
                passed.push(name);
                Ok(())
            }
            Err(err) => Err(format!("check '{name}' failed: {err:#}")),
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
        check("aead-wrapper-seal", aead_wrapper_seal().await).await?;
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
async fn hmac_known_answer(chunk: usize) -> Result<()> {
    let key = import_hmac_key(Sha2Variant::Sha256, HMAC_KEY.to_vec(), true)
        .await
        .context("import-key")?;
    ensure!(
        key.algorithm_name() == "HMAC",
        "mac-key.algorithm-name: got {}",
        key.algorithm_name()
    );
    ensure!(
        key.algorithm_hash().as_deref() == Some("SHA-256"),
        "mac-key.algorithm-hash: got {:?}",
        key.algorithm_hash()
    );
    ensure!(
        key.algorithm_length() == HMAC_KEY.len() as u32 * 8,
        "mac-key.algorithm-length: got {}",
        key.algorithm_length()
    );

    let tag = hex(&sign_chunked(&key, HMAC_DATA, chunk).await?);
    ensure!(tag == HMAC_TAG, "sign tag: got {tag}, want {HMAC_TAG}");
    Ok(())
}

/// `verify` accepts the correct tag and rejects a corrupted one.
async fn hmac_verify() -> Result<()> {
    let key = import_hmac_key(Sha2Variant::Sha256, HMAC_KEY.to_vec(), false)
        .await
        .context("import-key")?;

    let mut tag = unhex(HMAC_TAG);
    verify_chunked(&key, HMAC_DATA, tag.clone(), usize::MAX)
        .await?
        .context("correct tag did not verify")?;

    tag[0] ^= 0x01;
    expect_error!(
        verify_chunked(&key, HMAC_DATA, tag, usize::MAX).await?,
        Error::AuthenticationFailed,
        "corrupted tag verified",
    )
}

/// A generated key signs and verifies, and two calls on the same key agree.
async fn hmac_generated_key() -> Result<()> {
    let key = generate_hmac_key(Sha2Variant::Sha256, None, false)
        .await
        .context("generate-key")?;

    let tag = sign_chunked(&key, b"payload", usize::MAX).await?;
    ensure!(tag.len() == 32, "tag length: got {}, want 32", tag.len());

    verify_chunked(&key, b"payload", tag, 3)
        .await?
        .context("generated key's tag did not verify")?;

    // A non-extractable key must not export.
    expect_error!(
        key.export_key().await,
        Error::NotExtractable,
        "non-extractable key exported",
    )
}

/// `import` → `export` on an extractable key is the identity; a generated
/// extractable key exports the hash's block size of material (WebCrypto's
/// `generateKey` default: 64 bytes for SHA-256).
async fn hmac_key_export() -> Result<()> {
    // Exercises the library's newtype layer (`hmac_sha2` + `Mac`) rather
    // than the raw bindings the rest of the demo drives.
    use lann_webcrypto_guest::hmac_sha2;
    let key = hmac_sha2::import_key(Sha2Variant::Sha256, HMAC_KEY.to_vec(), true)
        .await
        .context("import-key")?;
    let exported = key
        .export_key()
        .await
        .context("export of extractable key")?;
    ensure!(
        exported == HMAC_KEY,
        "exported key material: got {}",
        hex(&exported)
    );
    let tag = key.sign(HMAC_DATA).await.context("sign")?;
    ensure!(
        hex(&tag) == HMAC_TAG,
        "wrapper sign tag: got {}, want {HMAC_TAG}",
        hex(&tag)
    );
    key.verify(HMAC_DATA, &tag)
        .await
        .context("wrapper verify")?;

    // A borrowed payload spanning several of the wrapper's feed chunks
    // round-trips sign→verify (the wrapper feeds borrowed sources
    // incrementally; the result must be chunking-invariant).
    let big: Vec<u8> = (0..=255u8).cycle().take(3 * 8192 + 11).collect();
    let tag = key
        .sign(&big[..])
        .await
        .context("wrapper sign (multi-chunk)")?;
    key.verify(&big[..], tag)
        .await
        .context("wrapper verify (multi-chunk)")?;

    let generated = hmac_sha2::generate_key(Sha2Variant::Sha256, None, true)
        .await
        .context("generate-key")?;
    let exported = generated
        .export_key()
        .await
        .context("export of generated key")?;
    ensure!(
        exported.len() == 64,
        "generated key length: got {}, want 64",
        exported.len()
    );
    Ok(())
}

/// The library's `Aead`/`AeadInternalNonce` wrappers: `seal` is the one
/// operation whose result may arrive before its input is consumed, so its
/// `Seal` collects concurrently with feeding rather than awaiting the
/// operation and reading afterwards.
///
/// Two `Seal`s under one `join!` is the shape the package's making-progress
/// rule asks for, and the reason `Seal` is a `Future` rather than an
/// `async fn`'s anonymous one.
async fn aead_wrapper_seal() -> Result<()> {
    use lann_webcrypto_guest::{aes_gcm, aes_gcm_internal_nonce};

    let key = aes_gcm::import_key(AesVariant::Aes256, unhex(GCM_KEY), false)
        .await
        .context("import-key")?;
    let nonce = unhex(GCM_IV);
    let plaintext = unhex(GCM_PLAINTEXT);
    let aad = unhex(GCM_AAD);

    let sealed = key
        .seal(&nonce[..], &aad[..], &plaintext[..])
        .await
        .context("wrapper seal")?;
    ensure!(
        hex(&sealed) == format!("{GCM_CIPHERTEXT}{GCM_TAG}"),
        "wrapper sealed message: got {}",
        hex(&sealed)
    );

    // A payload spanning several of the wrapper's feed chunks: the collect
    // runs alongside the feed, so this must not depend on the whole input
    // being taken before any output is produced.
    let big: Vec<u8> = (0..=255u8).cycle().take(3 * 8192 + 11).collect();
    let (first, second) = futures::join!(
        key.seal(&nonce[..], &aad[..], &big[..]),
        key.seal(&nonce[..], &aad[..], &big[..]),
    );
    let first = first.context("wrapper seal (multi-chunk)")?;
    let second = second.context("wrapper seal (concurrent)")?;
    ensure!(first == second, "concurrent seals of one payload differ");
    ensure!(
        first.len() == big.len() + 16,
        "sealed length is plaintext plus tag: got {}, want {}",
        first.len(),
        big.len() + 16
    );

    // The internal-nonce wrapper seals over the same shape; its wire format
    // carries the nonce, so the sealed message is longer still.
    let internal = aes_gcm_internal_nonce::generate_key(AesVariant::Aes256, false)
        .await
        .context("generate-key (internal nonce)")?;
    let sealed = internal
        .seal(&aad[..], &plaintext[..])
        .await
        .context("internal-nonce wrapper seal")?;
    ensure!(
        sealed.len() == plaintext.len() + 12 + 16,
        "internal-nonce sealed length: got {}, want {}",
        sealed.len(),
        plaintext.len() + 12 + 16
    );
    Ok(())
}

// --- digest & bytes checks -----------------------------------------------------

/// The FIPS 180-2 "abc" SHA-256 example digest.
const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

/// SHA-256 the FIPS example message, feeding it in `chunk`-byte writes, and
/// compare against the known digest. `usize::MAX` feeds it as one write.
async fn sha256_digest(chunk: usize) -> Result<()> {
    let digest = make_digest(Sha2Variant::Sha256).context("make-digest")?;
    ensure!(
        digest.algorithm_name() == "SHA-256",
        "digest.algorithm-name: got {}",
        digest.algorithm_name()
    );
    let got = hex(&compute_chunked(&digest, b"abc", chunk).await?);
    ensure!(got == SHA256_ABC, "computed digest: got {got}");
    // The resource is reusable: a second compute agrees.
    let again = hex(&compute_chunked(&digest, b"abc", chunk).await?);
    ensure!(again == SHA256_ABC, "recomputed digest: got {again}");
    Ok(())
}

/// `constant-time-equal` agrees with plain equality.
async fn bytes_equal() -> Result<()> {
    let digest = unhex(SHA256_ABC);
    let mut tampered = digest.clone();
    tampered[0] ^= 0x01;
    ensure!(
        constant_time_equal(&digest, &digest),
        "equal inputs compared unequal"
    );
    ensure!(
        !constant_time_equal(&digest, &tampered),
        "differing inputs compared equal"
    );
    ensure!(
        !constant_time_equal(&digest, &digest[..31]),
        "different lengths compared equal"
    );
    ensure!(
        constant_time_equal(&[], &[]),
        "empty inputs compared unequal"
    );
    Ok(())
}

// --- aead checks -------------------------------------------------------------

/// Seal the NIST vector's plaintext and compare against its ciphertext‖tag.
async fn gcm_known_answer_seal() -> Result<()> {
    let key = import_key(AesVariant::Aes256, unhex(GCM_KEY), false)
        .await
        .context("import-key")?;
    ensure!(
        key.algorithm_name() == "AES-GCM",
        "aead-key.algorithm-name: got {}",
        key.algorithm_name()
    );
    ensure!(
        key.algorithm_length() == 256,
        "aead-key.algorithm-length: got {}",
        key.algorithm_length()
    );
    ensure!(
        key.nonce_size() == 12,
        "aead-key.nonce-size: got {}",
        key.nonce_size()
    );
    ensure!(
        key.tag_size() == 16,
        "aead-key.tag-size: got {}",
        key.tag_size()
    );

    let sealed = seal_chunked(
        &key,
        &unhex(GCM_IV),
        &unhex(GCM_AAD),
        &unhex(GCM_PLAINTEXT),
        7,
    )
    .await?
    .context("seal")?;
    let mut expected = unhex(GCM_CIPHERTEXT);
    expected.extend(unhex(GCM_TAG));
    ensure!(sealed == expected, "sealed bytes: got {}", hex(&sealed));
    Ok(())
}

/// Open the NIST vector's ciphertext‖tag (fed one byte at a time) and compare
/// against its plaintext.
async fn gcm_known_answer_open() -> Result<()> {
    let key = import_key(AesVariant::Aes256, unhex(GCM_KEY), false)
        .await
        .context("import-key")?;

    let mut ciphertext = unhex(GCM_CIPHERTEXT);
    ciphertext.extend(unhex(GCM_TAG));
    let opened = open_chunked(&key, &unhex(GCM_IV), &unhex(GCM_AAD), &ciphertext, 1)
        .await?
        .context("open")?;
    ensure!(
        hex(&opened) == GCM_PLAINTEXT.replace(' ', ""),
        "opened bytes: got {}",
        hex(&opened)
    );
    Ok(())
}

/// Seal then open under a generated key round-trips the plaintext.
async fn gcm_round_trip() -> Result<()> {
    let key = generate_key(AesVariant::Aes256, false)
        .await
        .context("generate-key")?;
    let nonce = [7u8; 12];
    let aad = b"round-trip aad";
    let plaintext: Vec<u8> = (0..=255u8).cycle().take(3 * 1024 + 17).collect();

    let sealed = seal_chunked(&key, &nonce, aad, &plaintext, 512)
        .await?
        .context("seal")?;
    ensure!(
        sealed.len() == plaintext.len() + 16,
        "sealed length: got {}, want {}",
        sealed.len(),
        plaintext.len() + 16
    );

    let opened = open_chunked(&key, &nonce, aad, &sealed, 512)
        .await?
        .context("open")?;
    ensure!(opened == plaintext, "round-tripped plaintext differs");
    Ok(())
}

/// A flipped ciphertext bit fails with `authentication-failed`.
async fn gcm_tampered() -> Result<()> {
    let key = generate_key(AesVariant::Aes256, false)
        .await
        .context("generate-key")?;
    let nonce = [9u8; 12];
    let mut sealed = seal_chunked(&key, &nonce, b"", b"attack at dawn", usize::MAX)
        .await?
        .context("seal")?;
    sealed[0] ^= 0x80;
    expect_error!(
        open_chunked(&key, &nonce, b"", &sealed, usize::MAX).await?,
        Error::AuthenticationFailed,
        "tampered ciphertext opened",
    )
}

/// The wrong associated data fails with `authentication-failed`.
async fn gcm_wrong_aad() -> Result<()> {
    let key = generate_key(AesVariant::Aes256, false)
        .await
        .context("generate-key")?;
    let nonce = [11u8; 12];
    let sealed = seal_chunked(&key, &nonce, b"right aad", b"payload", usize::MAX)
        .await?
        .context("seal")?;
    expect_error!(
        open_chunked(&key, &nonce, b"wrong aad", &sealed, usize::MAX).await?,
        Error::AuthenticationFailed,
        "wrong aad opened",
    )
}

/// Importing wrong-length key material fails with `invalid-key`.
async fn gcm_invalid_key() -> Result<()> {
    expect_error!(
        import_key(AesVariant::Aes256, vec![0u8; 16], false).await,
        Error::InvalidKey(_),
        "16-byte key imported as AES-256",
    )
}

/// Sealing with a wrong-length nonce fails with `invalid-nonce`.
async fn gcm_invalid_nonce() -> Result<()> {
    let key = generate_key(AesVariant::Aes256, false)
        .await
        .context("generate-key")?;
    expect_error!(
        seal_chunked(&key, &[0u8; 8], b"", b"payload", usize::MAX).await?,
        Error::InvalidNonce(_),
        "8-byte nonce accepted",
    )
}

/// Extractability behaves for AEAD keys exactly as for MAC keys.
async fn gcm_key_export() -> Result<()> {
    let raw = unhex(GCM_KEY);
    let key = import_key(AesVariant::Aes256, raw.clone(), true)
        .await
        .context("import-key")?;
    let exported = key
        .export_key()
        .await
        .context("export of extractable key")?;
    ensure!(
        exported == raw,
        "exported key material: got {}",
        hex(&exported)
    );

    let sealed_key = generate_key(AesVariant::Aes256, false)
        .await
        .context("generate-key")?;
    expect_error!(
        sealed_key.export_key().await,
        Error::NotExtractable,
        "non-extractable key exported",
    )
}

/// The internal-nonce discipline end to end: sealed messages are
/// self-contained (`iv ‖ ciphertext ‖ tag`), round-trip under the same key,
/// draw a fresh nonce per seal, and fail closed on wrong associated data.
async fn gcm_internal_nonce() -> Result<()> {
    let key = generate_internal_nonce_key(AesVariant::Aes256, false)
        .await
        .context("generate-key (internal nonce)")?;
    ensure!(
        key.algorithm_name() == "AES-GCM",
        "internal-nonce-key.algorithm-name: got {}",
        key.algorithm_name()
    );
    ensure!(
        key.algorithm_length() == 256,
        "internal-nonce-key.algorithm-length: got {}",
        key.algorithm_length()
    );

    let before = key
        .seals_remaining()
        .context("AES-GCM internal-nonce key reports no nonce budget")?;

    let aad = b"internal-nonce aad";
    let plaintext: Vec<u8> = (0..=255u8).cycle().take(2 * 1024 + 9).collect();

    let sealed = in_seal_chunked(&key, aad, &plaintext, 512)
        .await?
        .context("seal")?;
    // 12-byte IV prefix + ciphertext + 16-byte tag.
    ensure!(
        sealed.len() == plaintext.len() + 12 + 16,
        "sealed length: got {}, want {}",
        sealed.len(),
        plaintext.len() + 12 + 16
    );

    let opened = in_open_chunked(&key, aad, &sealed, 512)
        .await?
        .context("open")?;
    ensure!(opened == plaintext, "round-tripped plaintext differs");

    // The budget hint decreases as seals consume it: if the key permits N
    // further seals, after one it permits at most N - 1.
    let after = key
        .seals_remaining()
        .context("nonce budget disappeared after sealing")?;
    ensure!(
        after < before,
        "seals-remaining did not decrease: {before} then {after}"
    );

    // A second seal of the same plaintext must draw a fresh nonce.
    let resealed = in_seal_chunked(&key, aad, &plaintext, usize::MAX)
        .await?
        .context("second seal")?;
    ensure!(
        sealed[..12] != resealed[..12],
        "two seals drew the same nonce"
    );

    expect_error!(
        in_open_chunked(&key, b"wrong aad", &sealed, usize::MAX).await?,
        Error::AuthenticationFailed,
        "wrong aad opened",
    )
}

// --- stream helpers ----------------------------------------------------------

/// Run the operation built by `op` over a fresh stream, feeding it `data`
/// in `chunk`-byte writes concurrently with the call (`usize::MAX` writes
/// it whole). The outer error is the feeder's; the inner result is the
/// operation's own.
async fn run_chunked<T, F>(
    data: &[u8],
    chunk: usize,
    op: impl FnOnce(lann_webcrypto_guest::StreamReader<u8>) -> F,
) -> Result<Result<T, Error>>
where
    F: std::future::Future<Output = Result<T, Error>>,
{
    let (tx, rx) = wit_stream::new();
    let (result, fed) = futures::join!(op(rx), feed(tx, data, chunk));
    fed?;
    Ok(result)
}

/// `sign`, feeding `data` in `chunk`-byte pieces.
async fn sign_chunked(key: &MacKey, data: &[u8], chunk: usize) -> Result<Vec<u8>> {
    run_chunked(data, chunk, |rx| key.sign(rx))
        .await?
        .context("mac-key.sign")
}

/// `compute`, feeding `data` in `chunk`-byte pieces.
async fn compute_chunked(digest: &Digest, data: &[u8], chunk: usize) -> Result<Vec<u8>> {
    run_chunked(data, chunk, |rx| digest.compute(rx))
        .await?
        .context("digest.compute")
}

/// `verify`, feeding `data` in `chunk`-byte pieces.
async fn verify_chunked(
    key: &MacKey,
    data: &[u8],
    tag: Vec<u8>,
    chunk: usize,
) -> Result<Result<(), Error>> {
    run_chunked(data, chunk, |rx| key.verify(rx, tag)).await
}

/// `seal`, feeding the plaintext in `chunk`-byte pieces and collecting the
/// returned ciphertext stream.
async fn seal_chunked(
    key: &AeadKey,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    chunk: usize,
) -> Result<Result<Vec<u8>, Error>> {
    match run_chunked(plaintext, chunk, |rx| {
        key.seal(nonce.to_vec(), aad.to_vec(), rx)
    })
    .await?
    {
        Ok(sealed) => Ok(Ok(sealed.collect().await)),
        Err(err) => Ok(Err(err)),
    }
}

/// `open`, feeding the ciphertext in `chunk`-byte pieces and collecting the
/// returned plaintext stream.
async fn open_chunked(
    key: &AeadKey,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    chunk: usize,
) -> Result<Result<Vec<u8>, Error>> {
    match run_chunked(ciphertext, chunk, |rx| {
        key.open(nonce.to_vec(), aad.to_vec(), rx)
    })
    .await?
    {
        Ok(opened) => Ok(Ok(opened.collect().await)),
        Err(err) => Ok(Err(err)),
    }
}

/// `internal-nonce-key.seal`, feeding the plaintext in `chunk`-byte pieces
/// and collecting the returned sealed-message stream.
async fn in_seal_chunked(
    key: &InternalNonceKey,
    aad: &[u8],
    plaintext: &[u8],
    chunk: usize,
) -> Result<Result<Vec<u8>, Error>> {
    match run_chunked(plaintext, chunk, |rx| key.seal(aad.to_vec(), rx)).await? {
        Ok(sealed) => Ok(Ok(sealed.collect().await)),
        Err(err) => Ok(Err(err)),
    }
}

/// `internal-nonce-key.open`, feeding the sealed message in `chunk`-byte
/// pieces and collecting the returned plaintext stream.
async fn in_open_chunked(
    key: &InternalNonceKey,
    aad: &[u8],
    sealed: &[u8],
    chunk: usize,
) -> Result<Result<Vec<u8>, Error>> {
    match run_chunked(sealed, chunk, |rx| key.open(aad.to_vec(), rx)).await? {
        Ok(opened) => Ok(Ok(opened.collect().await)),
        Err(err) => Ok(Err(err)),
    }
}

/// Write `data` to `tx` in `chunk`-byte pieces, then drop the writer to end
/// the stream.
async fn feed(mut tx: wit_bindgen::StreamWriter<u8>, data: &[u8], chunk: usize) -> Result<()> {
    for piece in data.chunks(chunk.max(1)) {
        let leftover = tx.write_all(piece.to_vec()).await;
        ensure!(leftover.is_empty(), "stream writer closed early");
    }
    Ok(())
}

// --- small utilities ---------------------------------------------------------

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
async fn sig_sign(key: &SigningKey, data: &[u8]) -> Result<Vec<u8>> {
    run_chunked(data, usize::MAX, |rx| key.sign(rx))
        .await?
        .context("signing-key.sign")
}

/// Verify `sig` over an entire byte stream (whole-write) with a
/// `verifying-key`.
async fn sig_verify(key: &VerifyingKey, data: &[u8], sig: Vec<u8>) -> Result<Result<(), Error>> {
    run_chunked(data, usize::MAX, |rx| key.verify(rx, sig)).await
}

/// The RFC 8032 known answer: importing the seed reproduces the vector's
/// signature (Ed25519 is deterministic), the getters report the algorithm,
/// and the vector's public key verifies the result.
async fn ed25519_known_answer() -> Result<()> {
    let key = import_ed25519_signing_key(unhex(ED25519_SEED), false)
        .await
        .context("import-signing-key")?;
    ensure!(
        key.algorithm_name() == "Ed25519",
        "signing-key.algorithm-name: got {}",
        key.algorithm_name()
    );
    ensure!(
        key.algorithm_curve().is_none(),
        "signing-key.algorithm-curve: got {:?}",
        key.algorithm_curve()
    );
    ensure!(
        key.algorithm_hash().is_none(),
        "signing-key.algorithm-hash: got {:?}",
        key.algorithm_hash()
    );

    let sig = sig_sign(&key, ED25519_MESSAGE).await?;
    ensure!(
        hex(&sig) == ED25519_SIG.replace(char::is_whitespace, ""),
        "signature: got {}",
        hex(&sig)
    );

    let public = import_ed25519_verifying_key(unhex(ED25519_PUBLIC))
        .await
        .context("import-verifying-key")?;
    sig_verify(&public, ED25519_MESSAGE, sig)
        .await?
        .context("known-answer signature did not verify")?;
    Ok(())
}

/// An imported public key verifies the vector's signature and rejects a
/// corrupted one with `authentication-failed`.
async fn ed25519_verify_check() -> Result<()> {
    let key = import_ed25519_verifying_key(unhex(ED25519_PUBLIC))
        .await
        .context("import-verifying-key")?;
    ensure!(
        key.algorithm_name() == "Ed25519",
        "verifying-key.algorithm-name: got {}",
        key.algorithm_name()
    );

    let mut sig = unhex(&ED25519_SIG.replace(char::is_whitespace, ""));
    sig_verify(&key, ED25519_MESSAGE, sig.clone())
        .await?
        .context("correct signature did not verify")?;

    sig[0] ^= 0x01;
    expect_error!(
        sig_verify(&key, ED25519_MESSAGE, sig).await?,
        Error::AuthenticationFailed,
        "corrupted signature verified",
    )
}

/// A generated key pair round-trips sign→verify, and the private half's
/// non-extractable material stays that way.
async fn ed25519_generated_key() -> Result<()> {
    let (key, public) = generate_ed25519_key(false).await.context("generate-key")?;
    ensure!(
        !key.extractable(),
        "non-extractable signing key reports extractable"
    );

    let sig = sig_sign(&key, b"payload").await?;
    ensure!(
        sig.len() == 64,
        "signature length: got {}, want 64",
        sig.len()
    );
    sig_verify(&public, b"payload", sig)
        .await?
        .context("round-trip signature did not verify")?;

    expect_error!(
        key.export_key().await,
        Error::NotExtractable,
        "non-extractable key exported",
    )
}

/// An extractable imported key exports the seed it was imported from.
async fn ed25519_key_export() -> Result<()> {
    let key = import_ed25519_signing_key(unhex(ED25519_SEED), true)
        .await
        .context("import-signing-key")?;
    ensure!(
        key.extractable(),
        "extractable signing key reports non-extractable"
    );
    let exported = key.export_key().await.context("export")?;
    ensure!(
        hex(&exported) == ED25519_SEED,
        "exported seed: got {}",
        hex(&exported)
    );
    Ok(())
}

/// The RFC 6979 known answer: an imported P-256 public key reports its
/// variant through the getters, verifies the deterministic signature over
/// "sample", and rejects a corrupted one.
async fn ecdsa_verify_known_answer() -> Result<()> {
    let mut point = vec![0x04];
    point.extend(unhex(ECDSA_PUBLIC_X));
    point.extend(unhex(ECDSA_PUBLIC_Y));
    let key = import_ecdsa_verifying_key(EcdsaVariant::P256Sha256, point)
        .await
        .context("import-verifying-key")?;
    ensure!(
        key.algorithm_name() == "ECDSA",
        "verifying-key.algorithm-name: got {}",
        key.algorithm_name()
    );
    ensure!(
        key.algorithm_curve().as_deref() == Some("P-256"),
        "verifying-key.algorithm-curve: got {:?}",
        key.algorithm_curve()
    );
    ensure!(
        key.algorithm_hash().as_deref() == Some("SHA-256"),
        "verifying-key.algorithm-hash: got {:?}",
        key.algorithm_hash()
    );

    let mut sig = unhex(ECDSA_SIG_R);
    sig.extend(unhex(ECDSA_SIG_S));
    sig_verify(&key, ECDSA_MESSAGE, sig.clone())
        .await?
        .context("known-answer signature did not verify")?;

    sig[0] ^= 0x01;
    expect_error!(
        sig_verify(&key, ECDSA_MESSAGE, sig).await?,
        Error::AuthenticationFailed,
        "corrupted signature verified",
    )
}
