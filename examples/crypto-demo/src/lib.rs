//! `crypto-demo`: an example WebAssembly component that exercises the
//! `lann:webcrypto` `mac` and `aead` primitive kinds end to end.
//!
//! The component is host-agnostic: the same binary runs unchanged under the
//! Wasmtime (RustCrypto) host and the jco (browser WebCrypto) host, which is
//! what demonstrates cross-implementation compatibility. It drives:
//!
//!   - HMAC-SHA-256 against an RFC 4231 known-answer vector, with the payload
//!     signed both as one stream write and as several small chunked writes
//!     (the result must be chunking-invariant),
//!   - tag verification, positive and negative,
//!   - AES-256-GCM against a NIST GCM known-answer vector (seal and open),
//!   - seal/open round trips with a generated key, including tampered
//!     ciphertext and wrong associated data failing with
//!     `authentication-failed`,
//!   - the key-capability surface: import/generate, `export` on extractable
//!     keys (an import→export identity round trip), `not-extractable`
//!     failures, and `invalid-key`/`invalid-nonce` rejections.

wit_bindgen::generate!({
    path: "wit",
    world: "crypto-demo",
    generate_all,
});

use exports::demo::webcrypto_demo::demo::Guest;
use lann::webcrypto::aead::AeadKey;
use lann::webcrypto::aes_gcm::{generate_aes256_gcm_key, import_aes256_gcm_key};
use lann::webcrypto::hmac::{generate_hmac_sha256_key, import_hmac_sha256_key};
use lann::webcrypto::mac::MacKey;
use lann::webcrypto::types::Error;

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
        check("gcm-known-answer-seal", gcm_known_answer_seal().await).await?;
        check("gcm-known-answer-open", gcm_known_answer_open().await).await?;
        check("gcm-round-trip", gcm_round_trip().await).await?;
        check("gcm-tampered", gcm_tampered().await).await?;
        check("gcm-wrong-aad", gcm_wrong_aad().await).await?;
        check("gcm-invalid-key", gcm_invalid_key().await).await?;
        check("gcm-invalid-nonce", gcm_invalid_nonce().await).await?;
        check("gcm-key-export", gcm_key_export().await).await?;

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
    let key = import_hmac_sha256_key(HMAC_KEY.to_vec(), true)
        .await
        .map_err(|e| describe("import-hmac-sha256-key", &e))?;
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
    let key = import_hmac_sha256_key(HMAC_KEY.to_vec(), false)
        .await
        .map_err(|e| describe("import-hmac-sha256-key", &e))?;

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
    let key = generate_hmac_sha256_key(false).await;

    let tag = sign_chunked(&key, b"payload", usize::MAX).await?;
    expect_eq(tag.len(), 32, "tag length")?;

    if verify_chunked(&key, b"payload", tag, 3).await?.is_err() {
        return Err("generated key's tag did not verify".into());
    }

    // A non-extractable key must not export.
    match key.export().await {
        Err(Error::NotExtractable) => Ok(()),
        Err(other) => Err(describe("expected not-extractable, got", &other)),
        Ok(_) => Err("non-extractable key exported".into()),
    }
}

/// `import` → `export` on an extractable key is the identity; a generated
/// extractable key exports 32 bytes.
async fn hmac_key_export() -> Result<(), String> {
    let key = import_hmac_sha256_key(HMAC_KEY.to_vec(), true)
        .await
        .map_err(|e| describe("import-hmac-sha256-key", &e))?;
    let exported = key
        .export()
        .await
        .map_err(|e| describe("export of extractable key", &e))?;
    expect_eq(exported, HMAC_KEY.to_vec(), "exported key material")?;

    let generated = generate_hmac_sha256_key(true).await;
    let exported = generated
        .export()
        .await
        .map_err(|e| describe("export of generated key", &e))?;
    expect_eq(exported.len(), 32, "generated key length")
}

// --- aead checks -------------------------------------------------------------

/// Seal the NIST vector's plaintext and compare against its ciphertext‖tag.
async fn gcm_known_answer_seal() -> Result<(), String> {
    let key = import_aes256_gcm_key(unhex(GCM_KEY), false)
        .await
        .map_err(|e| describe("import-aes256-gcm-key", &e))?;
    expect_eq(
        key.algorithm_name(),
        "AES-GCM".to_string(),
        "aead-key.algorithm-name",
    )?;
    expect_eq(key.algorithm_length(), 256, "aead-key.algorithm-length")?;

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
    let key = import_aes256_gcm_key(unhex(GCM_KEY), false)
        .await
        .map_err(|e| describe("import-aes256-gcm-key", &e))?;

    let mut ciphertext = unhex(GCM_CIPHERTEXT);
    ciphertext.extend(unhex(GCM_TAG));
    let opened = open_chunked(&key, &unhex(GCM_IV), &unhex(GCM_AAD), &ciphertext, 1)
        .await
        .map_err(|e| describe("open", &e))?;
    expect_eq(hex(&opened), GCM_PLAINTEXT.replace(' ', ""), "opened bytes")
}

/// Seal then open under a generated key round-trips the plaintext.
async fn gcm_round_trip() -> Result<(), String> {
    let key = generate_aes256_gcm_key(false).await;
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
    let key = generate_aes256_gcm_key(false).await;
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
    let key = generate_aes256_gcm_key(false).await;
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
    match import_aes256_gcm_key(vec![0u8; 16], false).await {
        Err(Error::InvalidKey(_)) => Ok(()),
        Err(other) => Err(describe("expected invalid-key, got", &other)),
        Ok(_) => Err("16-byte key imported as AES-256".into()),
    }
}

/// Sealing with a wrong-length nonce fails with `invalid-nonce`.
async fn gcm_invalid_nonce() -> Result<(), String> {
    let key = generate_aes256_gcm_key(false).await;
    match seal_chunked(&key, &[0u8; 8], b"", b"payload", usize::MAX).await {
        Err(Error::InvalidNonce(_)) => Ok(()),
        Err(other) => Err(describe("expected invalid-nonce, got", &other)),
        Ok(_) => Err("8-byte nonce accepted".into()),
    }
}

/// Extractability behaves for AEAD keys exactly as for MAC keys.
async fn gcm_key_export() -> Result<(), String> {
    let raw = unhex(GCM_KEY);
    let key = import_aes256_gcm_key(raw.clone(), true)
        .await
        .map_err(|e| describe("import-aes256-gcm-key", &e))?;
    let exported = key
        .export()
        .await
        .map_err(|e| describe("export of extractable key", &e))?;
    expect_eq(exported, raw, "exported key material")?;

    let sealed_key = generate_aes256_gcm_key(false).await;
    match sealed_key.export().await {
        Err(Error::NotExtractable) => Ok(()),
        Err(other) => Err(describe("expected not-extractable, got", &other)),
        Ok(_) => Err("non-extractable key exported".into()),
    }
}

// --- stream helpers ----------------------------------------------------------

/// `sign`, feeding `data` in `chunk`-byte pieces (one stream; `usize::MAX`
/// writes it whole).
async fn sign_chunked(key: &MacKey, data: &[u8], chunk: usize) -> Result<Vec<u8>, String> {
    let (tx, rx) = wit_stream::new();
    let (tag, fed) = futures::join!(key.sign(rx), feed(tx, data, chunk));
    fed?;
    Ok(tag)
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
    Ok(read_all(sealed?).await)
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
    Ok(read_all(opened?).await)
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

/// Drain a byte stream to its end.
async fn read_all(mut rx: wit_bindgen::StreamReader<u8>) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let (status, batch) = rx.read(Vec::with_capacity(8 * 1024)).await;
        out.extend(batch);
        if matches!(
            status,
            wit_bindgen::StreamResult::Dropped | wit_bindgen::StreamResult::Cancelled
        ) {
            break;
        }
    }
    out
}

// --- small utilities ---------------------------------------------------------

/// Render a WIT `error` with a context prefix.
fn describe(context: &str, error: &Error) -> String {
    let rendered = match error {
        Error::InvalidKey(detail) => format!("invalid-key: {detail}"),
        Error::InvalidNonce(detail) => format!("invalid-nonce: {detail}"),
        Error::AuthenticationFailed => "authentication-failed".to_string(),
        Error::NotExtractable => "not-extractable".to_string(),
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
