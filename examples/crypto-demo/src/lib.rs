//! `crypto-demo`: an example WebAssembly component that exercises the
//! `lann:webcrypto` primitive kinds end to end.
//!
//! The component is host-agnostic: the same binary runs unchanged under the
//! Wasmtime (RustCrypto) host and the jco (browser WebCrypto) host, which is
//! what demonstrates cross-implementation compatibility. It drives
//! known-answer vectors (whole and chunked — results must be
//! chunking-invariant), seal/open round trips with tampering and
//! wrong-AAD failures, signature known answers, and the key-capability
//! surface (import/generate/export, `not-extractable`, and
//! `invalid-key`/`invalid-nonce` rejections) — one check per behavior;
//! the `check(...)` names below are the inventory, and the integration
//! tests assert the expected summary.

wit_bindgen::generate!({
    path: "wit",
    world: "crypto-demo",
    generate_all,
});

use anyhow::{ensure, Context, Result};
use exports::demo::webcrypto_demo::demo::Guest;
use lann_webcrypto_guest::bindings::aead::AeadKey;
use lann_webcrypto_guest::bindings::aead_internal_nonce::InternalNonceKey;
use lann_webcrypto_guest::bindings::aes_gcm::AesVariant;
use lann_webcrypto_guest::bindings::bytes::constant_time_equal;
use lann_webcrypto_guest::bindings::digest::Digest;
use lann_webcrypto_guest::bindings::ecdsa_verify::{
    import_verifying_key_raw as import_ecdsa_verifying_key, EcdsaVariant,
};
use lann_webcrypto_guest::bindings::ed25519_verify::import_verifying_key_raw as import_ed25519_verifying_key;
use lann_webcrypto_guest::bindings::mac::MacKey;
use lann_webcrypto_guest::bindings::sha2::{make_digest, Sha2Variant};
use lann_webcrypto_guest::bindings::signature::{SigningKey, VerifyingKey};
use lann_webcrypto_guest::bindings::types::Error;
use lann_webcrypto_guest::wit_stream;

// Full-grant minting wrappers over the raw bindings: the demo's checks
// exercise algorithms and the key-capability surface, not usage policy, so
// every usage is granted and only `extractable` varies per check.

fn mac_options(extractable: bool) -> lann_webcrypto_guest::bindings::mac::MacKeyOptions {
    let options = lann_webcrypto_guest::bindings::mac::MacKeyOptions::new();
    options.can_sign(true);
    options.can_verify(true);
    options.extractable(extractable);
    options
}

fn aead_options(extractable: bool) -> lann_webcrypto_guest::bindings::aead::AeadKeyOptions {
    let options = lann_webcrypto_guest::bindings::aead::AeadKeyOptions::new();
    options.can_seal(true);
    options.can_open(true);
    options.can_wrap(true);
    options.can_unwrap(true);
    options.extractable(extractable);
    options
}

fn kw_options(extractable: bool) -> lann_webcrypto_guest::bindings::key_wrap::KwKeyOptions {
    let options = lann_webcrypto_guest::bindings::key_wrap::KwKeyOptions::new();
    options.can_wrap(true);
    options.can_unwrap(true);
    options.extractable(extractable);
    options
}

fn internal_nonce_options(
    extractable: bool,
) -> lann_webcrypto_guest::bindings::aead_internal_nonce::InternalNonceKeyOptions {
    let options =
        lann_webcrypto_guest::bindings::aead_internal_nonce::InternalNonceKeyOptions::new();
    options.can_seal(true);
    options.can_open(true);
    options.extractable(extractable);
    options
}

async fn import_hmac_key(
    variant: Sha2Variant,
    raw: Vec<u8>,
    extractable: bool,
) -> Result<MacKey, Error> {
    lann_webcrypto_guest::bindings::hmac_sha2::import_key_raw(
        variant,
        raw,
        mac_options(extractable),
    )
    .await
}

async fn generate_hmac_key(
    variant: Sha2Variant,
    length: Option<u32>,
    extractable: bool,
) -> Result<MacKey, Error> {
    lann_webcrypto_guest::bindings::hmac_sha2::generate_key(
        variant,
        length,
        mac_options(extractable),
    )
    .await
}

async fn import_key_raw(
    variant: AesVariant,
    raw: Vec<u8>,
    extractable: bool,
) -> Result<AeadKey, Error> {
    lann_webcrypto_guest::bindings::aes_gcm::import_key_raw(variant, raw, aead_options(extractable))
        .await
}

async fn generate_key(variant: AesVariant, extractable: bool) -> Result<AeadKey, Error> {
    lann_webcrypto_guest::bindings::aes_gcm::generate_key(variant, aead_options(extractable)).await
}

async fn generate_internal_nonce_key(
    variant: AesVariant,
    extractable: bool,
) -> Result<InternalNonceKey, Error> {
    lann_webcrypto_guest::bindings::aes_gcm_internal_nonce::generate_key(
        variant,
        internal_nonce_options(extractable),
    )
    .await
}

async fn generate_ed25519_key(extractable: bool) -> Result<(SigningKey, VerifyingKey), Error> {
    let options = lann_webcrypto_guest::bindings::signature::SigningKeyOptions::new();
    options.can_sign(true);
    options.extractable(extractable);
    lann_webcrypto_guest::bindings::ed25519_sign::generate_key(options).await
}

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
        check("concurrent-seal-open", concurrent_seal_open().await).await?;
        check("ed25519-verify", ed25519_verify_check().await).await?;
        check("ed25519-generated-key", ed25519_generated_key().await).await?;
        check(
            "ecdsa-verify-known-answer",
            ecdsa_verify_known_answer().await,
        )
        .await?;
        check("aes-kw-known-answer", aes_kw_known_answer().await).await?;
        check("aead-wrap-unwrap", aead_wrap_unwrap().await).await?;
        check("wrap-gates", wrap_gates().await).await?;
        check("hkdf-rfc5869-derive", hkdf_derive().await).await?;
        check("pbkdf2-rfc7914-derive", pbkdf2_derive().await).await?;
        check("x25519-agreement", x25519_agreement().await).await?;

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
        .context("import-key-raw")?;
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
        .context("import-key-raw")?;

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
        key.export_key_raw().await,
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
    let full_grant = lann_webcrypto_guest::MacKeyOptions {
        sign: true,
        verify: true,
        extractable: true,
    };
    let key = hmac_sha2::import_key_raw(Sha2Variant::Sha256, HMAC_KEY, full_grant)
        .await
        .context("import-key-raw")?;
    let exported = key
        .export_key_raw()
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

    let generated = hmac_sha2::generate_key(Sha2Variant::Sha256, None, full_grant)
        .await
        .context("generate-key")?;
    let exported = generated
        .export_key_raw()
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

    let seal_open = lann_webcrypto_guest::AeadKeyOptions {
        seal: true,
        open: true,
        ..Default::default()
    };
    let key = aes_gcm::import_key_raw(AesVariant::Aes256, unhex(GCM_KEY), seal_open)
        .await
        .context("import-key-raw")?;
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
    let internal = aes_gcm_internal_nonce::generate_key(
        AesVariant::Aes256,
        lann_webcrypto_guest::InternalNonceKeyOptions {
            seal: true,
            open: true,
            extractable: false,
        },
    )
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

/// Eight seal→open round trips in flight at once, each draining its own
/// streams — the making-progress shape the package asks callers for.
///
/// Correctness is asserted here; the *contended* case is the Wasmtime
/// integration test that reruns this demo with a pool smaller than the
/// concurrency (examples/wasmtime-demo/tests/demo.rs), where this check
/// hangs if an implementation stops releasing an operation's capacity when
/// its output is drained. On other hosts the pool is ample and this is a
/// plain concurrency check.
async fn concurrent_seal_open() -> Result<()> {
    use lann_webcrypto_guest::aes_gcm;

    let key = aes_gcm::generate_key(
        AesVariant::Aes256,
        lann_webcrypto_guest::AeadKeyOptions {
            seal: true,
            open: true,
            ..Default::default()
        },
    )
    .await
    .context("generate-key")?;

    async fn round_trip(key: &lann_webcrypto_guest::Aead, lane: u8) -> Result<()> {
        let mut nonce = [0u8; 12];
        nonce[0] = lane;
        let payload: Vec<u8> = (0..2048u32).map(|i| (i as u8).wrapping_add(lane)).collect();
        let sealed = key
            .seal(&nonce[..], &b"concurrent"[..], &payload[..])
            .await
            .with_context(|| format!("seal (lane {lane})"))?;
        let opened = key
            .open(&nonce[..], &b"concurrent"[..], &sealed[..])
            .await
            .with_context(|| format!("open (lane {lane})"))?
            .collect()
            .await;
        ensure!(opened == payload, "lane {lane} round trip differs");
        Ok(())
    }

    let lanes = futures::join!(
        round_trip(&key, 0),
        round_trip(&key, 1),
        round_trip(&key, 2),
        round_trip(&key, 3),
        round_trip(&key, 4),
        round_trip(&key, 5),
        round_trip(&key, 6),
        round_trip(&key, 7),
    );
    let (a, b, c, d, e, f, g, h) = lanes;
    a.and(b).and(c).and(d).and(e).and(f).and(g).and(h)
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
    let key = import_key_raw(AesVariant::Aes256, unhex(GCM_KEY), false)
        .await
        .context("import-key-raw")?;
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
    let key = import_key_raw(AesVariant::Aes256, unhex(GCM_KEY), false)
        .await
        .context("import-key-raw")?;

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
        import_key_raw(AesVariant::Aes256, vec![0u8; 16], false).await,
        Error::InvalidKey(_),
        "16-byte key imported as AES-256",
    )
}

/// Sealing with an empty nonce fails with `invalid-nonce` (GCM accepts any
/// non-empty length).
async fn gcm_invalid_nonce() -> Result<()> {
    let key = generate_key(AesVariant::Aes256, false)
        .await
        .context("generate-key")?;
    expect_error!(
        seal_chunked(&key, &[], b"", b"payload", usize::MAX).await?,
        Error::InvalidNonce(_),
        "empty nonce accepted",
    )
}

/// Extractability behaves for AEAD keys exactly as for MAC keys.
async fn gcm_key_export() -> Result<()> {
    let raw = unhex(GCM_KEY);
    let key = import_key_raw(AesVariant::Aes256, raw.clone(), true)
        .await
        .context("import-key-raw")?;
    let exported = key
        .export_key_raw()
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
        sealed_key.export_key_raw().await,
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

// --- key-wrapping checks ---------------------------------------------------------

/// RFC 3394 §4.1: wrap 128 bits of key data under a 128-bit KEK and match
/// the wire format, then unwrap and mint the payload back and prove the
/// minted key is the same material.
async fn aes_kw_known_answer() -> Result<()> {
    use lann_webcrypto_guest::bindings::{aes_gcm, aes_kw, hmac_sha2};
    let kek_raw = unhex("000102030405060708090a0b0c0d0e0f");
    let data_raw = unhex("00112233445566778899aabbccddeeff");
    let expected = "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5";

    let kek = aes_kw::import_key_raw(AesVariant::Aes128, kek_raw, kw_options(false))
        .await
        .context("aes-kw.import-key-raw")?;
    ensure!(
        kek.algorithm_name() == "AES-KW",
        "kw-key.algorithm-name: got {}",
        kek.algorithm_name()
    );
    ensure!(kek.algorithm_length() == 128);
    ensure!(kek.can_wrap() && kek.can_unwrap());

    // The payload enters the wrap path as an extractable key's material.
    let payload = aes_gcm::import_key_raw(AesVariant::Aes128, data_raw.clone(), aead_options(true))
        .await
        .context("payload import")?;
    let wrapped = kek
        .wrap(
            payload
                .to_wrap_input_raw()
                .await
                .context("to-wrap-input-raw")?,
        )
        .await
        .context("kw-key.wrap")?;
    ensure!(
        hex(&wrapped) == expected,
        "RFC 3394 wire format: got {}",
        hex(&wrapped)
    );

    // Tampering fails closed, indistinguishably from a malformed length.
    let mut tampered = wrapped.clone();
    tampered[0] ^= 1;
    ensure!(
        matches!(kek.unwrap(tampered).await, Err(Error::AuthenticationFailed)),
        "tampered unwrap must fail authentication-failed"
    );
    ensure!(
        matches!(
            kek.unwrap(vec![0u8; 20]).await,
            Err(Error::AuthenticationFailed)
        ),
        "out-of-domain unwrap must fail authentication-failed"
    );

    // Unwrap and mint as an HMAC key; its tag must match one minted from
    // the same bytes directly.
    let unwrapped = kek.unwrap(wrapped).await.context("kw-key.unwrap")?;
    let minted = hmac_sha2::unwrap_key_raw(Sha2Variant::Sha256, unwrapped, mac_options(false))
        .await
        .context("hmac-sha2.unwrap-key-raw")?;
    let direct = import_hmac_key(Sha2Variant::Sha256, data_raw, false)
        .await
        .context("direct import")?;
    let msg = b"wrapped and direct keys must agree";
    ensure!(
        sign_chunked(&minted, msg, usize::MAX).await?
            == sign_chunked(&direct, msg, usize::MAX).await?,
        "minted key disagrees with the directly imported material"
    );
    Ok(())
}

/// AEAD wrapping: `wrap` is byte-identical to sealing the exported bytes,
/// and a JWK-format wrap round-trips through `unwrap-key-jwk`.
async fn aead_wrap_unwrap() -> Result<()> {
    use lann_webcrypto_guest::bindings::{aes_gcm, hmac_sha2};
    let kek = aes_gcm::generate_key(AesVariant::Aes256, aead_options(false))
        .await
        .context("kek generate")?;
    let payload = import_hmac_key(Sha2Variant::Sha256, vec![0x42; 20], true)
        .await
        .context("payload import")?;
    let nonce = vec![7u8; 12];

    // Byte identity with seal over the exported bytes (raw format).
    let wrapped = kek
        .wrap(
            nonce.clone(),
            b"aad".to_vec(),
            None,
            payload.to_wrap_input_raw().await?,
        )
        .await
        .context("aead-key.wrap")?;
    let sealed = seal_chunked(
        &kek,
        &nonce,
        b"aad",
        &payload.export_key_raw().await?,
        usize::MAX,
    )
    .await?
    .context("seal comparison")?;
    ensure!(wrapped == sealed, "wrap must equal seal over the export");

    // JWK-format wrap round-trips through the unwrap mint.
    let jwk_wrapped = kek
        .wrap(
            nonce.clone(),
            Vec::new(),
            None,
            payload.to_wrap_input_jwk().await?,
        )
        .await?;
    let input = kek
        .unwrap(nonce.clone(), Vec::new(), None, jwk_wrapped)
        .await
        .context("aead-key.unwrap")?;
    let minted = hmac_sha2::unwrap_key_jwk(Sha2Variant::Sha256, input, mac_options(false))
        .await
        .context("hmac-sha2.unwrap-key-jwk")?;
    let msg = b"jwk round trip";
    ensure!(
        sign_chunked(&minted, msg, usize::MAX).await?
            == sign_chunked(&payload, msg, usize::MAX).await?,
        "JWK-wrapped key disagrees with the original"
    );

    // A tampered wrap fails closed.
    let mut tampered = wrapped;
    tampered[0] ^= 1;
    ensure!(
        matches!(
            kek.unwrap(nonce, b"aad".to_vec(), None, tampered).await,
            Err(Error::AuthenticationFailed)
        ),
        "tampered aead unwrap must fail authentication-failed"
    );
    Ok(())
}

/// The wrap gates: `to-wrap-input-*` sits behind the extractability gate,
/// and the wrap grants refuse ungranted operations.
async fn wrap_gates() -> Result<()> {
    use lann_webcrypto_guest::bindings::aes_kw;
    let sealed_key = import_hmac_key(Sha2Variant::Sha256, vec![9; 32], false).await?;
    ensure!(
        matches!(
            sealed_key.to_wrap_input_raw().await,
            Err(Error::NotExtractable)
        ),
        "to-wrap-input-raw on a non-extractable key must fail not-extractable"
    );

    let wrap_only_options = lann_webcrypto_guest::bindings::key_wrap::KwKeyOptions::new();
    wrap_only_options.can_wrap(true);
    let wrap_only = aes_kw::generate_key(AesVariant::Aes256, wrap_only_options)
        .await
        .context("wrap-only generate")?;
    ensure!(wrap_only.can_wrap() && !wrap_only.can_unwrap());
    ensure!(
        matches!(
            wrap_only.unwrap(vec![0u8; 24]).await,
            Err(Error::NotPermitted(_))
        ),
        "unwrap on a wrap-only key must fail not-permitted"
    );
    Ok(())
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
        key.seal(nonce.to_vec(), aad.to_vec(), None, rx)
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
        key.open(nonce.to_vec(), aad.to_vec(), None, rx)
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

/// An imported public key verifies the vector's signature and rejects a
/// corrupted one with `authentication-failed`.
async fn ed25519_verify_check() -> Result<()> {
    let key = import_ed25519_verifying_key(unhex(ED25519_PUBLIC))
        .await
        .context("import-verifying-key-raw")?;
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
        .context("round-trip signature did not verify")
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
        .context("import-verifying-key-raw")?;
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

// --- derivation checks -----------------------------------------------------------

/// HKDF-SHA-256 against RFC 5869 test case 1, through the SDK wrappers:
/// import the IKM, prepare with the vector's salt and info, and derive its
/// 42-byte OKM; a null-length derive must fail (a KDF has no natural
/// output length); the same input then mints an HMAC key that round-trips
/// sign/verify.
async fn hkdf_derive() -> Result<()> {
    use lann_webcrypto_guest::{hkdf, hkdf_sha2, DeriveOptions, MacKeyOptions};
    let options = DeriveOptions {
        derive_bits: true,
        derive_key: true,
    };
    let ikm = hkdf::import_ikm(vec![0x0b; 22], options).await?;
    let input = hkdf_sha2::prepare(
        Sha2Variant::Sha256,
        &ikm,
        unhex("000102030405060708090a0b0c"),
        unhex("f0f1f2f3f4f5f6f7f8f9"),
    )
    .await?;
    let okm = input.derive_bits(Some(42 * 8)).await?;
    ensure!(
        okm == unhex(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        ),
        "OKM mismatch: got {}",
        hex(&okm)
    );
    ensure!(
        input.derive_bits(None).await.is_err(),
        "null-length derive on a KDF source succeeded"
    );

    let mac = lann_webcrypto_guest::hmac_sha2::derive_key(
        Sha2Variant::Sha256,
        &input,
        None,
        MacKeyOptions {
            sign: true,
            verify: true,
            extractable: false,
        },
    )
    .await?;
    let payload = &b"derived-key payload"[..];
    let tag = mac.sign(payload).await?;
    mac.verify(payload, tag)
        .await
        .context("derived HMAC key did not round-trip")
}

/// PBKDF2-HMAC-SHA-256 against RFC 7914 §11's first PBKDF2 vector
/// (P="passwd", S="salt", c=1, dkLen=64), through the SDK wrappers.
async fn pbkdf2_derive() -> Result<()> {
    use lann_webcrypto_guest::{pbkdf2, pbkdf2_sha2, DeriveOptions};
    let options = DeriveOptions {
        derive_bits: true,
        derive_key: false,
    };
    let password = pbkdf2::import_password(b"passwd", options).await?;
    let input = pbkdf2_sha2::prepare(Sha2Variant::Sha256, &password, b"salt", 1).await?;
    let dk = input.derive_bits(Some(64 * 8)).await?;
    ensure!(
        dk == unhex(
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc\
             49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
        ),
        "derived key mismatch: got {}",
        hex(&dk)
    );
    Ok(())
}

/// X25519 agreement through the SDK wrappers: two generated keypairs
/// agree in both directions on the same 32-byte secret, and both agreed
/// inputs chain into HKDF (WebCrypto's `deriveKey(ECDH -> HKDF)` shape)
/// to the same bits.
async fn x25519_agreement() -> Result<()> {
    use lann_webcrypto_guest::{hkdf_sha2, x25519, AgreementKeyOptions};
    let options = AgreementKeyOptions {
        derive_bits: true,
        derive_key: true,
        extractable: false,
    };
    let (a_secret, a_public) = x25519::generate_key(options).await?;
    let (b_secret, b_public) = x25519::generate_key(options).await?;
    let ab = a_secret.agree(&b_public).await?;
    let ba = b_secret.agree(&a_public).await?;
    let ab_bits = ab.derive_bits(None).await?;
    let ba_bits = ba.derive_bits(None).await?;
    ensure!(
        ab_bits.len() == 32,
        "shared secret is {} bytes",
        ab_bits.len()
    );
    ensure!(ab_bits == ba_bits, "shared secrets disagree by direction");

    let a_input = hkdf_sha2::prepare_from(Sha2Variant::Sha256, &ab, b"salt", b"info").await?;
    let b_input = hkdf_sha2::prepare_from(Sha2Variant::Sha256, &ba, b"salt", b"info").await?;
    ensure!(
        a_input.derive_bits(Some(256)).await? == b_input.derive_bits(Some(256)).await?,
        "chained derivations disagree by direction"
    );
    Ok(())
}
