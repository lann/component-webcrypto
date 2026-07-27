//! Stream, error-rendering, and comparison helpers shared by the vector
//! cases and the API-contract probes.

use crate::translate::Schedule;
use lann_webcrypto_guest::raw::aead::AeadKey;
use lann_webcrypto_guest::raw::aead_internal_nonce::InternalNonceKey;
use lann_webcrypto_guest::raw::digest::Digest;
use lann_webcrypto_guest::raw::mac::MacKey;
use lann_webcrypto_guest::raw::types::Error;

/// Render a WIT `error` with a context prefix.
pub fn describe(context: &str, error: &Error) -> String {
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

/// Compare byte strings, reporting lengths and the first differing offset
/// rather than the full contents.
pub fn expect_bytes(got: &[u8], want: &[u8], what: &str) -> Result<(), String> {
    if got == want {
        return Ok(());
    }
    if got.len() != want.len() {
        return Err(format!(
            "{what}: got {} bytes, want {} bytes",
            got.len(),
            want.len()
        ));
    }
    let index = got
        .iter()
        .zip(want)
        .position(|(g, w)| g != w)
        .unwrap_or_default();
    Err(format!(
        "{what}: first difference at byte {index} of {}: got {:#04x}, want {:#04x}",
        got.len(),
        got[index],
        want[index]
    ))
}

/// Write `chunks` to `tx` in order (one write per chunk — the schedule's
/// delivery pattern), then drop the writer to end the stream.
pub async fn feed(
    mut tx: wit_bindgen::StreamWriter<u8>,
    chunks: Vec<Vec<u8>>,
) -> Result<(), String> {
    for chunk in chunks {
        let leftover = tx.write_all(chunk).await;
        if !leftover.is_empty() {
            return Err(format!(
                "stream writer closed early with {} bytes unwritten",
                leftover.len()
            ));
        }
    }
    Ok(())
}

/// Write `data` to `tx` as one write, then drop the writer to end the
/// stream.
pub async fn feed_whole(tx: wit_bindgen::StreamWriter<u8>, data: &[u8]) -> Result<(), String> {
    feed(tx, vec![data.to_vec()]).await
}

/// `sign`, feeding `data` per `schedule` concurrently with the call. Returns
/// the tag and the feeder's outcome separately, so feeder failures are
/// distinguishable from the call's own result.
pub async fn sign(key: &MacKey, data: &[u8], schedule: Schedule) -> (Vec<u8>, Result<(), String>) {
    let (tx, rx) = lann_webcrypto_guest::wit_stream::new();
    let (tag, fed) = futures::join!(key.sign(rx), feed(tx, schedule.chunks(data)));
    match tag {
        Ok(tag) => (tag, fed),
        Err(err) => {
            let failed: Result<(), String> = Err(format!("mac-key.sign failed: {err:?}"));
            (Vec::new(), failed.and(fed))
        }
    }
}

/// `verify`, feeding `data` per `schedule` concurrently with the call; same
/// outcome split as [`sign`].
pub async fn verify(
    key: &MacKey,
    data: &[u8],
    tag: &[u8],
    schedule: Schedule,
) -> (Result<(), Error>, Result<(), String>) {
    let (tx, rx) = lann_webcrypto_guest::wit_stream::new();
    futures::join!(
        key.verify(rx, tag.to_vec()),
        feed(tx, schedule.chunks(data))
    )
}

/// `compute`, feeding `data` per `schedule` concurrently with the call; same
/// outcome split as [`sign`].
pub async fn compute(
    digest: &Digest,
    data: &[u8],
    schedule: Schedule,
) -> (Vec<u8>, Result<(), String>) {
    let (tx, rx) = lann_webcrypto_guest::wit_stream::new();
    let (got, fed) = futures::join!(digest.compute(rx), feed(tx, schedule.chunks(data)));
    match got {
        Ok(got) => (got, fed),
        Err(err) => {
            let failed: Result<(), String> = Err(format!("digest.compute failed: {err:?}"));
            (Vec::new(), failed.and(fed))
        }
    }
}

/// `internal-nonce-key.seal`, feeding the plaintext per `schedule`
/// concurrently with the call; same outcome split as [`seal`].
pub async fn in_seal(
    key: &InternalNonceKey,
    aad: &[u8],
    plaintext: &[u8],
    schedule: Schedule,
) -> (Result<Vec<u8>, Error>, Result<(), String>) {
    let (tx, rx) = lann_webcrypto_guest::wit_stream::new();
    let (sealed, fed) = futures::join!(
        key.seal(aad.to_vec(), rx),
        feed(tx, schedule.chunks(plaintext))
    );
    let sealed = match sealed {
        Ok(stream) => Ok(stream.collect().await),
        Err(err) => Err(err),
    };
    (sealed, fed)
}

/// `internal-nonce-key.open`, feeding the sealed message per `schedule`
/// concurrently with the call; same outcome split as [`seal`].
pub async fn in_open(
    key: &InternalNonceKey,
    aad: &[u8],
    sealed: &[u8],
    schedule: Schedule,
) -> (Result<Vec<u8>, Error>, Result<(), String>) {
    let (tx, rx) = lann_webcrypto_guest::wit_stream::new();
    let (opened, fed) = futures::join!(
        key.open(aad.to_vec(), rx),
        feed(tx, schedule.chunks(sealed))
    );
    let opened = match opened {
        Ok(stream) => Ok(stream.collect().await),
        Err(err) => Err(err),
    };
    (opened, fed)
}

/// `seal`, feeding the plaintext per `schedule` concurrently with the call.
/// Returns the call's outcome (the collected ciphertext stream on success)
/// and the feeder's outcome separately, so drain-rule violations are
/// distinguishable from the call's own error.
pub async fn seal(
    key: &AeadKey,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    schedule: Schedule,
) -> (Result<Vec<u8>, Error>, Result<(), String>) {
    let (tx, rx) = lann_webcrypto_guest::wit_stream::new();
    let (sealed, fed) = futures::join!(
        key.seal(nonce.to_vec(), aad.to_vec(), rx),
        feed(tx, schedule.chunks(plaintext))
    );
    let sealed = match sealed {
        Ok(stream) => Ok(stream.collect().await),
        Err(err) => Err(err),
    };
    (sealed, fed)
}

/// `open`, feeding the ciphertext per `schedule` concurrently with the call;
/// same outcome split as [`seal`].
pub async fn open(
    key: &AeadKey,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    schedule: Schedule,
) -> (Result<Vec<u8>, Error>, Result<(), String>) {
    let (tx, rx) = lann_webcrypto_guest::wit_stream::new();
    let (opened, fed) = futures::join!(
        key.open(nonce.to_vec(), aad.to_vec(), rx),
        feed(tx, schedule.chunks(ciphertext))
    );
    let opened = match opened {
        Ok(stream) => Ok(stream.collect().await),
        Err(err) => Err(err),
    };
    (opened, fed)
}

/// `verifying-key.verify`, feeding `data` per `schedule` concurrently with
/// the call; same outcome split as [`verify`].
pub async fn sig_verify(
    key: &lann_webcrypto_guest::raw::signature::VerifyingKey,
    data: &[u8],
    sig: &[u8],
    schedule: Schedule,
) -> (Result<(), Error>, Result<(), String>) {
    let (tx, rx) = lann_webcrypto_guest::wit_stream::new();
    futures::join!(
        key.verify(rx, sig.to_vec()),
        feed(tx, schedule.chunks(data))
    )
}

/// Decode a hex constant (probe-internal known-answer material).
pub fn unhex(hex: &str) -> Vec<u8> {
    hex::decode(hex).expect("probe hex constants are valid")
}
