//! Stream delivery shared by the conformance guests: the chunking
//! [`Schedule`]s and helpers that run one operation while feeding its input
//! concurrently.
//!
//! Every base helper returns the operation's outcome and the feeder's
//! outcome *separately*, so the feeder's fate (fully written, or rejected
//! by an early close the closure rule permits on error) is distinguishable
//! from the call's own error. The lann-webcrypto-guest wrappers
//! deliberately merge the two; the stream-closure probes are why these
//! helpers do not.
//!
//! Two folding layers serve the callers that treat both outcomes as one
//! error path. The `*_op` helpers fold the feeder's failure (under the
//! operation's fixed feeder context) and surface the operation's own
//! result, for sites that assert on the operation's error. The `*_ok`
//! helpers additionally fold the operation's error through [`describe`]
//! under the caller's context, for the plain ok path.

use lann_webcrypto_guest::bindings::aead::AeadKey;
use lann_webcrypto_guest::bindings::aead_internal_nonce::InternalNonceKey;
use lann_webcrypto_guest::bindings::cipher::CipherKey;
use lann_webcrypto_guest::bindings::digest::Digest;
use lann_webcrypto_guest::bindings::mac::MacKey;
use lann_webcrypto_guest::bindings::signature::{SigningKey, VerifyingKey};
use lann_webcrypto_guest::bindings::types::Error;
use lann_webcrypto_guest::wit_bindgen::StreamWriter;
use lann_webcrypto_guest::{wit_stream, StreamReader};

use crate::describe;

/// How a case's byte inputs are delivered to the implementation.
#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub enum Schedule {
    /// One write of the whole input.
    Whole,
    /// One-byte writes.
    Bytes,
    /// Alternating 15/17-byte writes, straddling 16-byte block boundaries.
    Straddle,
}

impl Schedule {
    /// The schedule's name, as used in test ids.
    pub fn name(self) -> &'static str {
        match self {
            Schedule::Whole => "whole",
            Schedule::Bytes => "bytes",
            Schedule::Straddle => "straddle",
        }
    }

    /// Split `data` into the write-sized chunks this schedule delivers on a
    /// single stream.
    pub fn chunks(self, data: &[u8]) -> Vec<Vec<u8>> {
        match self {
            Schedule::Whole => {
                if data.is_empty() {
                    Vec::new()
                } else {
                    vec![data.to_vec()]
                }
            }
            Schedule::Bytes => data.iter().map(|byte| vec![*byte]).collect(),
            Schedule::Straddle => {
                let mut chunks = Vec::new();
                let mut offset = 0;
                let mut fifteen = true;
                while offset < data.len() {
                    let size = if fifteen { 15 } else { 17 };
                    let end = (offset + size).min(data.len());
                    chunks.push(data[offset..end].to_vec());
                    offset = end;
                    fifteen = !fifteen;
                }
                chunks
            }
        }
    }
}

/// Write `chunks` to `tx` in order (one write per chunk — the schedule's
/// delivery pattern), then drop the writer to end the stream.
pub async fn feed(mut tx: StreamWriter<u8>, chunks: Vec<Vec<u8>>) -> Result<(), String> {
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

/// Run the operation built by `op` over a fresh stream while feeding it
/// `chunks`, returning both outcomes.
async fn run_split<T, F>(
    chunks: Vec<Vec<u8>>,
    op: impl FnOnce(StreamReader<u8>) -> F,
) -> (T, Result<(), String>)
where
    F: std::future::Future<Output = T>,
{
    let (tx, rx) = wit_stream::new();
    futures::join!(op(rx), feed(tx, chunks))
}

/// Fold a WIT error from an operation the contract lets callers treat as
/// infallible on a fully granted key (`sign`) into the feeder slot, so
/// those callers keep a single error path.
fn merge<T: Default>(
    what: &str,
    result: Result<T, Error>,
    fed: Result<(), String>,
) -> (T, Result<(), String>) {
    match result {
        Ok(value) => (value, fed),
        Err(err) => {
            let failed: Result<(), String> = Err(describe(&format!("{what} failed"), &err));
            (T::default(), failed.and(fed))
        }
    }
}

/// Await the output stream a successful `seal`/`open` hands back.
async fn collect(result: Result<StreamReader<u8>, Error>) -> Result<Vec<u8>, Error> {
    match result {
        Ok(stream) => Ok(stream.collect().await),
        Err(err) => Err(err),
    }
}

/// `mac-key.sign`, feeding `data` per `schedule` concurrently with the
/// call. Returns the tag and the feeder's outcome separately, so feeder
/// failures are distinguishable from the call's own result.
pub async fn sign(key: &MacKey, data: &[u8], schedule: Schedule) -> (Vec<u8>, Result<(), String>) {
    let (tag, fed) = run_split(schedule.chunks(data), |rx| key.sign(rx)).await;
    merge("mac-key.sign", tag, fed)
}

/// `mac-key.sign`, like [`sign`] but surfacing the operation's own result:
/// for probing keys whose usage policy refuses the operation, where
/// [`sign`]'s treat-as-infallible shape does not apply.
pub async fn try_sign(
    key: &MacKey,
    data: &[u8],
    schedule: Schedule,
) -> (Result<Vec<u8>, Error>, Result<(), String>) {
    run_split(schedule.chunks(data), |rx| key.sign(rx)).await
}

/// `mac-key.verify`, feeding `data` per `schedule` concurrently with the
/// call; same outcome split as [`sign`].
pub async fn verify(
    key: &MacKey,
    data: &[u8],
    tag: &[u8],
    schedule: Schedule,
) -> (Result<(), Error>, Result<(), String>) {
    run_split(schedule.chunks(data), |rx| key.verify(rx, tag.to_vec())).await
}

/// `cipher-key.encrypt`, feeding the plaintext per `schedule` concurrently
/// with the call; same outcome split as [`seal`].
pub async fn ci_encrypt(
    key: &CipherKey,
    iv: &[u8],
    counter_length: Option<u8>,
    plaintext: &[u8],
    schedule: Schedule,
) -> (Result<Vec<u8>, Error>, Result<(), String>) {
    let (sealed, fed) = run_split(schedule.chunks(plaintext), |rx| {
        key.encrypt(iv.to_vec(), counter_length, rx)
    })
    .await;
    (collect(sealed).await, fed)
}

/// `cipher-key.decrypt`; same outcome split as [`seal`].
pub async fn ci_decrypt(
    key: &CipherKey,
    iv: &[u8],
    counter_length: Option<u8>,
    ciphertext: &[u8],
    schedule: Schedule,
) -> (Result<Vec<u8>, Error>, Result<(), String>) {
    let (opened, fed) = run_split(schedule.chunks(ciphertext), |rx| {
        key.decrypt(iv.to_vec(), counter_length, rx)
    })
    .await;
    (collect(opened).await, fed)
}

/// `digest.compute`, feeding `data` per `schedule` concurrently with the
/// call. Returns the call's outcome and the feeder's separately: unlike
/// `sign`, `compute` is fallible by contract on some digest kinds
/// (checked SHA-1's rejecting posture), so its error is a probe subject,
/// not foldable operational noise.
pub async fn compute(
    digest: &Digest,
    data: &[u8],
    schedule: Schedule,
) -> (Result<Vec<u8>, Error>, Result<(), String>) {
    run_split(schedule.chunks(data), |rx| digest.compute(rx)).await
}

/// `aead-key.seal`, feeding the plaintext per `schedule` concurrently with
/// the call. Returns the call's outcome (the collected ciphertext stream on
/// success) and the feeder's outcome separately, so drain-rule violations
/// are distinguishable from the call's own error.
pub async fn seal(
    key: &AeadKey,
    nonce: &[u8],
    aad: &[u8],
    tag_size: Option<u8>,
    plaintext: &[u8],
    schedule: Schedule,
) -> (Result<Vec<u8>, Error>, Result<(), String>) {
    let (sealed, fed) = run_split(schedule.chunks(plaintext), |rx| {
        key.seal(nonce.to_vec(), aad.to_vec(), tag_size, rx)
    })
    .await;
    (collect(sealed).await, fed)
}

/// `aead-key.open`, feeding the ciphertext per `schedule` concurrently with
/// the call; same outcome split as [`seal`].
pub async fn open(
    key: &AeadKey,
    nonce: &[u8],
    aad: &[u8],
    tag_size: Option<u8>,
    ciphertext: &[u8],
    schedule: Schedule,
) -> (Result<Vec<u8>, Error>, Result<(), String>) {
    let (opened, fed) = run_split(schedule.chunks(ciphertext), |rx| {
        key.open(nonce.to_vec(), aad.to_vec(), tag_size, rx)
    })
    .await;
    (collect(opened).await, fed)
}

/// `internal-nonce-key.seal`, feeding the plaintext per `schedule`
/// concurrently with the call; same outcome split as [`seal`].
pub async fn in_seal(
    key: &InternalNonceKey,
    aad: &[u8],
    plaintext: &[u8],
    schedule: Schedule,
) -> (Result<Vec<u8>, Error>, Result<(), String>) {
    let (sealed, fed) =
        run_split(schedule.chunks(plaintext), |rx| key.seal(aad.to_vec(), rx)).await;
    (collect(sealed).await, fed)
}

/// `internal-nonce-key.open`, feeding the sealed message per `schedule`
/// concurrently with the call; same outcome split as [`seal`].
pub async fn in_open(
    key: &InternalNonceKey,
    aad: &[u8],
    sealed: &[u8],
    schedule: Schedule,
) -> (Result<Vec<u8>, Error>, Result<(), String>) {
    let (opened, fed) = run_split(schedule.chunks(sealed), |rx| key.open(aad.to_vec(), rx)).await;
    (collect(opened).await, fed)
}

/// `signing-key.sign`, feeding `data` per `schedule` concurrently with the
/// call; same outcome split as [`sign`].
pub async fn sig_sign(
    key: &SigningKey,
    data: &[u8],
    schedule: Schedule,
) -> (Vec<u8>, Result<(), String>) {
    let (sig, fed) = run_split(schedule.chunks(data), |rx| key.sign(rx)).await;
    merge("signing-key.sign", sig, fed)
}

/// `verifying-key.verify`, feeding `data` per `schedule` concurrently with
/// the call; same outcome split as [`verify`].
pub async fn sig_verify(
    key: &VerifyingKey,
    data: &[u8],
    sig: &[u8],
    schedule: Schedule,
) -> (Result<(), Error>, Result<(), String>) {
    run_split(schedule.chunks(data), |rx| key.verify(rx, sig.to_vec())).await
}

/// Fold a feeder failure under `feeder`, surfacing the operation's outcome.
fn folded<T>((result, fed): (T, Result<(), String>), feeder: &str) -> Result<T, String> {
    fed.map_err(|e| format!("{feeder}: {e}"))?;
    Ok(result)
}

/// [`sign`], with the feeder's outcome folded into the error path.
pub async fn sign_ok(key: &MacKey, data: &[u8], schedule: Schedule) -> Result<Vec<u8>, String> {
    folded(sign(key, data, schedule).await, "sign data feeder")
}

/// [`verify`], with the feeder's outcome folded into the error path.
pub async fn verify_op(
    key: &MacKey,
    data: &[u8],
    tag: &[u8],
    schedule: Schedule,
) -> Result<Result<(), Error>, String> {
    folded(verify(key, data, tag, schedule).await, "verify data feeder")
}

/// [`verify_op`], additionally folding the operation's error under `what`.
pub async fn verify_ok(
    key: &MacKey,
    data: &[u8],
    tag: &[u8],
    schedule: Schedule,
    what: &str,
) -> Result<(), String> {
    verify_op(key, data, tag, schedule)
        .await?
        .map_err(|e| describe(what, &e))
}

/// [`compute`], with the feeder's outcome folded into the error path.
pub async fn compute_op(
    digest: &Digest,
    data: &[u8],
    schedule: Schedule,
) -> Result<Result<Vec<u8>, Error>, String> {
    folded(compute(digest, data, schedule).await, "compute data feeder")
}

/// [`compute_op`], additionally folding the operation's error under `what`.
pub async fn compute_ok(
    digest: &Digest,
    data: &[u8],
    schedule: Schedule,
    what: &str,
) -> Result<Vec<u8>, String> {
    compute_op(digest, data, schedule)
        .await?
        .map_err(|e| describe(what, &e))
}

/// [`ci_encrypt`], with the feeder's outcome folded into the error path.
pub async fn ci_encrypt_op(
    key: &CipherKey,
    iv: &[u8],
    counter_length: Option<u8>,
    plaintext: &[u8],
    schedule: Schedule,
) -> Result<Result<Vec<u8>, Error>, String> {
    folded(
        ci_encrypt(key, iv, counter_length, plaintext, schedule).await,
        "encrypt plaintext feeder",
    )
}

/// [`ci_encrypt_op`], additionally folding the operation's error under
/// `what`.
pub async fn ci_encrypt_ok(
    key: &CipherKey,
    iv: &[u8],
    counter_length: Option<u8>,
    plaintext: &[u8],
    schedule: Schedule,
    what: &str,
) -> Result<Vec<u8>, String> {
    ci_encrypt_op(key, iv, counter_length, plaintext, schedule)
        .await?
        .map_err(|e| describe(what, &e))
}

/// [`ci_decrypt`], with the feeder's outcome folded into the error path.
pub async fn ci_decrypt_op(
    key: &CipherKey,
    iv: &[u8],
    counter_length: Option<u8>,
    ciphertext: &[u8],
    schedule: Schedule,
) -> Result<Result<Vec<u8>, Error>, String> {
    folded(
        ci_decrypt(key, iv, counter_length, ciphertext, schedule).await,
        "decrypt ciphertext feeder",
    )
}

/// [`ci_decrypt_op`], additionally folding the operation's error under
/// `what`.
pub async fn ci_decrypt_ok(
    key: &CipherKey,
    iv: &[u8],
    counter_length: Option<u8>,
    ciphertext: &[u8],
    schedule: Schedule,
    what: &str,
) -> Result<Vec<u8>, String> {
    ci_decrypt_op(key, iv, counter_length, ciphertext, schedule)
        .await?
        .map_err(|e| describe(what, &e))
}

/// [`seal`], with the feeder's outcome folded into the error path.
pub async fn seal_op(
    key: &AeadKey,
    nonce: &[u8],
    aad: &[u8],
    tag_size: Option<u8>,
    plaintext: &[u8],
    schedule: Schedule,
) -> Result<Result<Vec<u8>, Error>, String> {
    folded(
        seal(key, nonce, aad, tag_size, plaintext, schedule).await,
        "seal plaintext feeder",
    )
}

/// [`seal_op`], additionally folding the operation's error under `what`.
pub async fn seal_ok(
    key: &AeadKey,
    nonce: &[u8],
    aad: &[u8],
    tag_size: Option<u8>,
    plaintext: &[u8],
    schedule: Schedule,
    what: &str,
) -> Result<Vec<u8>, String> {
    seal_op(key, nonce, aad, tag_size, plaintext, schedule)
        .await?
        .map_err(|e| describe(what, &e))
}

/// [`open`], with the feeder's outcome folded into the error path.
pub async fn open_op(
    key: &AeadKey,
    nonce: &[u8],
    aad: &[u8],
    tag_size: Option<u8>,
    ciphertext: &[u8],
    schedule: Schedule,
) -> Result<Result<Vec<u8>, Error>, String> {
    folded(
        open(key, nonce, aad, tag_size, ciphertext, schedule).await,
        "open ciphertext feeder",
    )
}

/// [`open_op`], additionally folding the operation's error under `what`.
pub async fn open_ok(
    key: &AeadKey,
    nonce: &[u8],
    aad: &[u8],
    tag_size: Option<u8>,
    ciphertext: &[u8],
    schedule: Schedule,
    what: &str,
) -> Result<Vec<u8>, String> {
    open_op(key, nonce, aad, tag_size, ciphertext, schedule)
        .await?
        .map_err(|e| describe(what, &e))
}

/// [`in_seal`], with the feeder's outcome folded into the error path.
pub async fn in_seal_op(
    key: &InternalNonceKey,
    aad: &[u8],
    plaintext: &[u8],
    schedule: Schedule,
) -> Result<Result<Vec<u8>, Error>, String> {
    folded(
        in_seal(key, aad, plaintext, schedule).await,
        "seal plaintext feeder",
    )
}

/// [`in_seal_op`], additionally folding the operation's error under `what`.
pub async fn in_seal_ok(
    key: &InternalNonceKey,
    aad: &[u8],
    plaintext: &[u8],
    schedule: Schedule,
    what: &str,
) -> Result<Vec<u8>, String> {
    in_seal_op(key, aad, plaintext, schedule)
        .await?
        .map_err(|e| describe(what, &e))
}

/// [`in_open`], with the feeder's outcome folded into the error path.
pub async fn in_open_op(
    key: &InternalNonceKey,
    aad: &[u8],
    sealed: &[u8],
    schedule: Schedule,
) -> Result<Result<Vec<u8>, Error>, String> {
    folded(
        in_open(key, aad, sealed, schedule).await,
        "open sealed feeder",
    )
}

/// [`in_open_op`], additionally folding the operation's error under `what`.
pub async fn in_open_ok(
    key: &InternalNonceKey,
    aad: &[u8],
    sealed: &[u8],
    schedule: Schedule,
    what: &str,
) -> Result<Vec<u8>, String> {
    in_open_op(key, aad, sealed, schedule)
        .await?
        .map_err(|e| describe(what, &e))
}

/// [`sig_sign`], with the feeder's outcome folded into the error path
/// as-is (the feeder slot already carries [`sig_sign`]'s merged context).
pub async fn sig_sign_ok(
    key: &SigningKey,
    data: &[u8],
    schedule: Schedule,
) -> Result<Vec<u8>, String> {
    let (sig, fed) = sig_sign(key, data, schedule).await;
    fed?;
    Ok(sig)
}

/// [`sig_verify`], with the feeder's outcome folded into the error path
/// as-is.
pub async fn sig_verify_op(
    key: &VerifyingKey,
    data: &[u8],
    sig: &[u8],
    schedule: Schedule,
) -> Result<Result<(), Error>, String> {
    let (verified, fed) = sig_verify(key, data, sig, schedule).await;
    fed?;
    Ok(verified)
}

/// [`sig_verify_op`], additionally folding the operation's error under
/// `what`.
pub async fn sig_verify_ok(
    key: &VerifyingKey,
    data: &[u8],
    sig: &[u8],
    schedule: Schedule,
    what: &str,
) -> Result<(), String> {
    sig_verify_op(key, data, sig, schedule)
        .await?
        .map_err(|e| describe(what, &e))
}
