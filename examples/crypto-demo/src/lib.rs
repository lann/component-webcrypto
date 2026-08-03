//! `crypto-demo`: an example WebAssembly component that exercises the
//! `lann:webcrypto` primitive kinds end to end through the
//! `lann-webcrypto-guest` library.
//!
//! The component is host-agnostic: the same binary runs unchanged under the
//! Wasmtime (RustCrypto) host and the jco (browser WebCrypto) host, which is
//! what demonstrates cross-implementation compatibility. Each kind gets one
//! happy-path tour (against a known-answer vector where the algorithm has a
//! deterministic one); the remaining checks assert the library's wrapper
//! plumbing — the lazy `Seal` future, every `DataSource` variant, the
//! `Error::Read` precedence rule — which executes nowhere else in the
//! repository. Algorithm correctness and the rejection surface are the
//! conformance suites' job (`conformance/`), which gate the same targets.
//! The `check(...)` names below are the inventory, and the integration
//! tests assert the expected summary.

wit_bindgen::generate!({
    path: "wit",
    world: "crypto-demo",
    generate_all,
});

use anyhow::{ensure, Context, Result};
use data_encoding_macro::hexlower;
use exports::demo::webcrypto_demo::demo::Guest;
use lann_webcrypto_guest::aes_gcm::AesVariant;
use lann_webcrypto_guest::sha2::Sha2Variant;
use lann_webcrypto_guest::{constant_time_equal, wit_stream, Error};

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
const HMAC_TAG: [u8; 32] =
    hexlower!("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

// --- NIST GCM revised spec, test case 16 (AES-256-GCM) ----------------------

const GCM_KEY: [u8; 32] =
    hexlower!("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
const GCM_IV: [u8; 12] = hexlower!("cafebabefacedbaddecaf888");
const GCM_PLAINTEXT: [u8; 60] = hexlower!(
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
     1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
);
const GCM_AAD: [u8; 20] = hexlower!("feedfacedeadbeeffeedfacedeadbeefabaddad2");
const GCM_CIPHERTEXT: [u8; 60] = hexlower!(
    "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
     8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
);
const GCM_TAG: [u8; 16] = hexlower!("76fc6ece0f4e1768cddf8853bb2d551b");

// --- RFC 3394 §4.1 (AES-KW: a 128-bit KEK wrapping 128 bits of key data) -----

const KW_KEK: [u8; 16] = hexlower!("000102030405060708090a0b0c0d0e0f");
const KW_DATA: [u8; 16] = hexlower!("00112233445566778899aabbccddeeff");
const KW_WRAPPED: [u8; 24] = hexlower!("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5");

// --- RFC 8032 §7.1 test 2 (Ed25519) ------------------------------------------

const ED25519_PUBLIC: [u8; 32] =
    hexlower!("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
const ED25519_MESSAGE: &[u8] = &[0x72];
const ED25519_SIG: [u8; 64] = hexlower!(
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
     085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
);

// --- RFC 6979 A.2.5 (ECDSA P-256 + SHA-256, message "sample") ----------------

const ECDSA_PUBLIC_X: [u8; 32] =
    hexlower!("60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6");
const ECDSA_PUBLIC_Y: [u8; 32] =
    hexlower!("7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299");
const ECDSA_MESSAGE: &[u8] = b"sample";
const ECDSA_SIG_R: [u8; 32] =
    hexlower!("efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716");
const ECDSA_SIG_S: [u8; 32] =
    hexlower!("f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8");

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

        check("hmac-key-export", hmac_key_export().await).await?;
        check("digest-wrapper", digest_wrapper().await).await?;
        check("constant-time-equal", bytes_equal().await).await?;
        check("aead-wrapper-seal", aead_wrapper_seal().await).await?;
        check("concurrent-seal-open", concurrent_seal_open().await).await?;
        check("internal-nonce-wrapper", internal_nonce_wrapper().await).await?;
        check("key-wrap-tour", key_wrap_tour().await).await?;
        check(
            "aes-ctr-wrapper-roundtrip",
            aes_ctr_wrapper_roundtrip().await,
        )
        .await?;
        check("ed25519-verify", ed25519_verify_check().await).await?;
        check(
            "ed25519-wrapper-roundtrip",
            ed25519_wrapper_roundtrip().await,
        )
        .await?;
        check(
            "ecdsa-verify-known-answer",
            ecdsa_verify_known_answer().await,
        )
        .await?;
        check("hkdf-rfc5869-derive", hkdf_derive().await).await?;
        check("pbkdf2-rfc7914-derive", pbkdf2_derive().await).await?;
        check("x25519-agreement", x25519_agreement().await).await?;
        check("ecdh-agreement", ecdh_agreement().await).await?;
        check(
            "mac-datasource-equivalence",
            mac_datasource_equivalence().await,
        )
        .await?;
        check("read-error-precedence", read_error_precedence().await).await?;

        Ok(format!(
            "{} checks passed: {}",
            passed.len(),
            passed.join(", ")
        ))
    }
}

// --- mac -----------------------------------------------------------------

/// The MAC tour: `import` → `export` on an extractable key is the identity,
/// the imported key produces the RFC 4231 tag and verifies it, a payload
/// spanning several feed chunks round-trips (results must be
/// chunking-invariant), and a generated extractable key exports the hash's
/// block size of material (WebCrypto's `generateKey` default: 64 bytes for
/// SHA-256).
async fn hmac_key_export() -> Result<()> {
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
        tag == HMAC_TAG,
        "wrapper sign tag: got {}, want {}",
        hex(&tag),
        hex(&HMAC_TAG)
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

// --- digest & bytes -------------------------------------------------------

/// The FIPS 180-2 "abc" SHA-256 example digest.
const SHA256_ABC: [u8; 32] =
    hexlower!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

/// The digest tour: the `Digest` wrapper computes the FIPS 180-2 "abc"
/// example digest, and the resource is reusable — a second compute agrees.
async fn digest_wrapper() -> Result<()> {
    let digest = lann_webcrypto_guest::sha2::make_digest(Sha2Variant::Sha256)?;
    ensure!(
        digest.algorithm_name() == "SHA-256",
        "algorithm-name: got {}",
        digest.algorithm_name()
    );
    let got = digest.compute(b"abc").await?;
    ensure!(got == SHA256_ABC, "computed digest: got {}", hex(&got));
    let again = digest.compute(b"abc").await?;
    ensure!(
        again == SHA256_ABC,
        "recomputed digest: got {}",
        hex(&again)
    );
    Ok(())
}

/// `constant-time-equal` agrees with plain equality.
async fn bytes_equal() -> Result<()> {
    let digest = SHA256_ABC;
    let mut tampered = digest;
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

// --- aead -----------------------------------------------------------------

/// The AEAD tour, and the library's `Aead`/`AeadInternalNonce` wrappers:
/// `seal` is the one operation whose result may arrive before its input is
/// consumed, so its `Seal` collects concurrently with feeding rather than
/// awaiting the operation and reading afterwards. The single-shot seal is
/// checked against the NIST GCM vector's ciphertext‖tag.
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
    let key = aes_gcm::import_key_raw(AesVariant::Aes256, GCM_KEY, seal_open)
        .await
        .context("import-key-raw")?;
    let nonce = GCM_IV;
    let plaintext = GCM_PLAINTEXT;
    let aad = GCM_AAD;

    let sealed = key
        .seal(&nonce[..], &aad[..], &plaintext[..])
        .await
        .context("wrapper seal")?;
    ensure!(
        sealed == [GCM_CIPHERTEXT.as_slice(), GCM_TAG.as_slice()].concat(),
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

/// The `AeadInternalNonce` wrapper end to end: generate, seal (a lazy
/// [`Seal`](lann_webcrypto_guest::Seal)), open, and the budget getter.
async fn internal_nonce_wrapper() -> Result<()> {
    use lann_webcrypto_guest::{aes_gcm_internal_nonce, InternalNonceKeyOptions};
    let key = aes_gcm_internal_nonce::generate_key(
        aes_gcm_internal_nonce::AesVariant::Aes256,
        InternalNonceKeyOptions {
            seal: true,
            open: true,
            extractable: false,
        },
    )
    .await?;
    let plaintext = &b"internal-nonce wrapper payload"[..];
    let sealed = key.seal(&b"aad"[..], plaintext).await?;
    let opened = key.open(&b"aad"[..], sealed).await?.collect().await;
    ensure!(opened == plaintext, "round trip disagreed");
    ensure!(
        key.seals_remaining().is_none_or(|left| left > 0),
        "budget exhausted after one seal"
    );
    Ok(())
}

// --- cipher ----------------------------------------------------------------

/// The cipher tour: the `CipherKey` wrapper end to end — generate through
/// `aes_ctr`, encrypt (a lazy [`Seal`](lann_webcrypto_guest::Seal)),
/// decrypt, and compare.
async fn aes_ctr_wrapper_roundtrip() -> Result<()> {
    use lann_webcrypto_guest::{aes_ctr, CipherKeyOptions};
    let key = aes_ctr::generate_key(
        aes_ctr::AesVariant::Aes256,
        CipherKeyOptions {
            encrypt: true,
            decrypt: true,
            wrap: false,
            unwrap: false,
            extractable: false,
        },
    )
    .await?;
    let plaintext = &b"counter-mode wrapper payload"[..];
    let iv = [0u8; 16];
    let ciphertext = key.encrypt(&iv[..], Some(64), plaintext).await?;
    ensure!(ciphertext != plaintext, "ciphertext equals plaintext");
    let decrypted = key
        .decrypt(&iv[..], Some(64), ciphertext)
        .await?
        .collect()
        .await;
    ensure!(decrypted == plaintext, "round trip disagreed");
    Ok(())
}

// --- signature ---------------------------------------------------------------

/// An imported public key reports its algorithm through the getters,
/// verifies the RFC 8032 signature, and rejects a corrupted one with
/// `authentication-failed`.
async fn ed25519_verify_check() -> Result<()> {
    use lann_webcrypto_guest::ed25519;
    let key = ed25519::import_verifying_key_raw(ED25519_PUBLIC)
        .await
        .context("import-verifying-key-raw")?;
    ensure!(
        key.algorithm_name() == "Ed25519",
        "verifying-key.algorithm-name: got {}",
        key.algorithm_name()
    );

    let mut sig = ED25519_SIG.to_vec();
    key.verify(ED25519_MESSAGE, sig.clone())
        .await
        .context("correct signature did not verify")?;

    sig[0] ^= 0x01;
    expect_error!(
        key.verify(ED25519_MESSAGE, sig).await,
        Error::AuthenticationFailed,
        "corrupted signature verified",
    )
}

/// The signature wrappers end to end: generate through `ed25519`, sign
/// through `SigningKey`, verify through `VerifyingKey`, and fail closed on
/// a tampered signature.
async fn ed25519_wrapper_roundtrip() -> Result<()> {
    use lann_webcrypto_guest::{ed25519, SigningKeyOptions};
    let (signing, verifying) = ed25519::generate_key(SigningKeyOptions {
        sign: true,
        extractable: false,
    })
    .await?;
    ensure!(
        !signing.extractable(),
        "non-extractable signing key reports extractable"
    );
    let payload = &b"wrapper-signed payload"[..];
    let mut sig = signing.sign(payload).await?;
    ensure!(
        sig.len() == 64,
        "signature length: got {}, want 64",
        sig.len()
    );
    verifying
        .verify(payload, sig.clone())
        .await
        .context("fresh signature did not verify")?;
    sig[0] ^= 0x01;
    expect_error!(
        verifying.verify(payload, sig).await,
        Error::AuthenticationFailed,
        "tampered signature verified",
    )
}

/// The RFC 6979 known answer: an imported P-256 public key reports its
/// variant through the getters, verifies the deterministic signature over
/// "sample", and rejects a corrupted one.
async fn ecdsa_verify_known_answer() -> Result<()> {
    use lann_webcrypto_guest::ecdsa::{self, EcdsaVariant};
    let mut point = vec![0x04];
    point.extend(ECDSA_PUBLIC_X);
    point.extend(ECDSA_PUBLIC_Y);
    let key = ecdsa::import_verifying_key_raw(EcdsaVariant::P256Sha256, point)
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

    let mut sig = ECDSA_SIG_R.to_vec();
    sig.extend(ECDSA_SIG_S);
    key.verify(ECDSA_MESSAGE, sig.clone())
        .await
        .context("known-answer signature did not verify")?;

    sig[0] ^= 0x01;
    expect_error!(
        key.verify(ECDSA_MESSAGE, sig).await,
        Error::AuthenticationFailed,
        "corrupted signature verified",
    )
}

// --- derivation --------------------------------------------------------------

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
        hexlower!("000102030405060708090a0b0c"),
        hexlower!("f0f1f2f3f4f5f6f7f8f9"),
    )
    .await?;
    let okm = input.derive_bits(Some(42 * 8)).await?;
    ensure!(
        okm == hexlower!(
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
        dk == hexlower!(
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

/// ECDH agreement through the SDK wrappers, the same shape as
/// `x25519-agreement` per curve: two generated keypairs agree in both
/// directions on the same field-size secret (32 bytes for P-256, 48 for
/// P-384), and on P-256 both agreed inputs chain into HKDF to the same
/// bits.
async fn ecdh_agreement() -> Result<()> {
    use lann_webcrypto_guest::ecdh::{self, EcdhVariant};
    use lann_webcrypto_guest::{hkdf_sha2, AgreementKeyOptions};
    let options = AgreementKeyOptions {
        derive_bits: true,
        derive_key: true,
        extractable: false,
    };

    for (variant, field_size) in [(EcdhVariant::P256, 32), (EcdhVariant::P384, 48)] {
        let (a_secret, a_public) = ecdh::generate_key(variant, options).await?;
        let (b_secret, b_public) = ecdh::generate_key(variant, options).await?;
        let ab = a_secret.agree(&b_public).await?;
        let ba = b_secret.agree(&a_public).await?;
        let ab_bits = ab.derive_bits(None).await?;
        let ba_bits = ba.derive_bits(None).await?;
        ensure!(
            ab_bits.len() == field_size,
            "{variant:?} shared secret is {} bytes, want {field_size}",
            ab_bits.len()
        );
        ensure!(
            ab_bits == ba_bits,
            "{variant:?} shared secrets disagree by direction"
        );

        if variant == EcdhVariant::P256 {
            let a_input =
                hkdf_sha2::prepare_from(Sha2Variant::Sha256, &ab, b"salt", b"info").await?;
            let b_input =
                hkdf_sha2::prepare_from(Sha2Variant::Sha256, &ba, b"salt", b"info").await?;
            ensure!(
                a_input.derive_bits(Some(256)).await? == b_input.derive_bits(Some(256)).await?,
                "chained derivations disagree by direction"
            );
        }
    }
    Ok(())
}

// --- byte-source plumbing ------------------------------------------------------

/// Every `DataSource` variant produces the RFC 4231 tag: borrowed and
/// owned buffers, a multi-chunk `Buf` (feature `bytes`), an incremental
/// reader (feature `futures-io`), and a passed-through stream. The
/// feature-gated feed loops execute only here.
async fn mac_datasource_equivalence() -> Result<()> {
    use lann_webcrypto_guest::{hmac_sha2, DataSource, MacKeyOptions};
    let key = hmac_sha2::import_key_raw(
        Sha2Variant::Sha256,
        HMAC_KEY,
        MacKeyOptions {
            sign: true,
            verify: true,
            extractable: false,
        },
    )
    .await?;
    let expected = HMAC_TAG;

    let borrowed = key.sign(HMAC_DATA).await?;
    ensure!(
        borrowed == expected,
        "borrowed source: got {}",
        hex(&borrowed)
    );

    let owned = key.sign(HMAC_DATA.to_vec()).await?;
    ensure!(owned == expected, "owned source: got {}", hex(&owned));

    let (head, tail) = HMAC_DATA.split_at(9);
    let buf = bytes::Buf::chain(head, tail);
    let bufed = key.sign(DataSource::from_buf(buf)).await?;
    ensure!(bufed == expected, "buf source: got {}", hex(&bufed));

    let read = key
        .sign(DataSource::from_reader(ChunkReader::new(HMAC_DATA, 7)))
        .await?;
    ensure!(read == expected, "reader source: got {}", hex(&read));

    let (tx, rx) = wit_stream::new();
    let feed = async move {
        let mut tx = tx;
        // Dropping the writer ends the stream; the sign resolves only then.
        tx.write_all(HMAC_DATA.to_vec()).await
    };
    let (streamed, leftover) = futures::join!(key.sign(rx), feed);
    ensure!(leftover.is_empty(), "the operation left input unread");
    let streamed = streamed?;
    ensure!(
        streamed == expected,
        "stream source: got {}",
        hex(&streamed)
    );
    Ok(())
}

/// A failing `from_reader` source surfaces as `Error::Read`, taking
/// precedence over the operation's own outcome: the operation only saw a
/// truncated input.
async fn read_error_precedence() -> Result<()> {
    use lann_webcrypto_guest::{hmac_sha2, DataSource, MacKeyOptions};
    let key = hmac_sha2::import_key_raw(
        Sha2Variant::Sha256,
        HMAC_KEY,
        MacKeyOptions {
            sign: true,
            verify: true,
            extractable: false,
        },
    )
    .await?;
    let result = key
        .sign(DataSource::from_reader(FailingReader { fed: false }))
        .await;
    ensure!(
        matches!(result, Err(Error::Read(_))),
        "expected Error::Read, got {result:?}"
    );
    Ok(())
}

/// Yields `data` in `chunk`-byte reads — a well-behaved incremental
/// reader.
struct ChunkReader {
    data: &'static [u8],
    chunk: usize,
}

impl ChunkReader {
    fn new(data: &'static [u8], chunk: usize) -> Self {
        Self { data, chunk }
    }
}

impl futures_io::AsyncRead for ChunkReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let n = self.chunk.min(self.data.len()).min(buf.len());
        buf[..n].copy_from_slice(&self.data[..n]);
        self.data = &self.data[n..];
        std::task::Poll::Ready(Ok(n))
    }
}

/// Yields one chunk, then fails — the truncating producer whose failure
/// `Error::Read` must report over the operation's outcome.
struct FailingReader {
    fed: bool,
}

impl futures_io::AsyncRead for FailingReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.fed {
            return std::task::Poll::Ready(Err(std::io::Error::other("reader failed midway")));
        }
        self.fed = true;
        let n = buf.len().min(4);
        buf[..n].copy_from_slice(&[0xAB; 4][..n]);
        std::task::Poll::Ready(Ok(n))
    }
}

// --- small utilities ---------------------------------------------------------

/// One key-wrap tour: the RFC 3394 known answer through `kw-key.wrap`, the
/// unwrap half minting the key data back out through the raw unwrap mint,
/// and the AEAD wrap identity (`wrap` equals `seal` over the exported
/// bytes). The rejection surface and domains are the conformance suites'
/// job.
async fn key_wrap_tour() -> Result<()> {
    use lann_webcrypto_guest::{aes_gcm, aes_kw, hmac_sha2, KwKeyOptions, MacKeyOptions};

    let kek = aes_kw::import_key_raw(
        AesVariant::Aes128,
        KW_KEK,
        KwKeyOptions {
            wrap: true,
            unwrap: true,
            extractable: false,
        },
    )
    .await
    .context("aes-kw import-key-raw")?;
    ensure!(
        kek.algorithm_name() == "AES-KW",
        "kw-key.algorithm-name: got {}",
        kek.algorithm_name()
    );

    // The key data enters the wrap path as an extractable key's material.
    let payload = hmac_sha2::import_key_raw(
        Sha2Variant::Sha256,
        KW_DATA,
        MacKeyOptions {
            sign: true,
            verify: false,
            extractable: true,
        },
    )
    .await
    .context("payload import")?;
    let wrapped = kek
        .wrap(payload.to_wrap_input_raw().await.context("to-wrap-input")?)
        .await
        .context("kw-key.wrap")?;
    ensure!(
        wrapped == KW_WRAPPED,
        "RFC 3394 wire format: got {}",
        hex(&wrapped)
    );

    // Unwrap and mint the key data back out: the minted key must agree
    // with the original on a tag.
    let minted = hmac_sha2::unwrap_key_raw(
        Sha2Variant::Sha256,
        kek.unwrap(wrapped).await.context("kw-key.unwrap")?,
        MacKeyOptions {
            sign: true,
            verify: false,
            extractable: false,
        },
    )
    .await
    .context("hmac-sha2.unwrap-key-raw")?;
    let via_wrap = minted.sign(HMAC_DATA).await.context("minted sign")?;
    let direct = payload.sign(HMAC_DATA).await.context("payload sign")?;
    ensure!(
        via_wrap == direct,
        "the unwrapped key disagrees with the original"
    );

    // The AEAD wrap identity: `wrap` is byte-identical to sealing the
    // exported bytes.
    let aead_kek = aes_gcm::import_key_raw(
        AesVariant::Aes256,
        GCM_KEY,
        lann_webcrypto_guest::AeadKeyOptions {
            seal: true,
            wrap: true,
            ..Default::default()
        },
    )
    .await
    .context("aead kek import")?;
    let nonce = GCM_IV;
    let wrapped = aead_kek
        .wrap(
            nonce,
            Vec::new(),
            None,
            payload.to_wrap_input_raw().await.context("to-wrap-input")?,
        )
        .await
        .context("aead-key.wrap")?;
    let sealed = aead_kek
        .seal(&nonce[..], &[][..], &payload.export_key_raw().await?[..])
        .await
        .context("seal comparison")?;
    ensure!(
        wrapped == sealed,
        "aead wrap must equal seal over the export"
    );
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(bytes)
}

export!(Component);
