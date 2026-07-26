//! The timing lab: dudect-style statistical timing tests of the composed
//! `lann:webcrypto` in-guest provider, run entirely in-guest.
//!
//! Methodology ("dude, is my code constant time?" — Reparaz, Balasch,
//! Verbauwhede, DATE 2017): for each surface, interleave measurements of two
//! input classes chosen so that only secret-dependent control flow could
//! separate them (e.g. a tag corrupted at the FIRST byte vs the LAST byte —
//! both calls fail, so any timing difference isolates the tag comparison),
//! then compare the two timing distributions with Welch's t-test over the
//! full data and upper-percentile-cropped subsets, flagging max |t| > 10
//! (the reference dudect's moderate threshold; the crops make max |t| an
//! inflated statistic, so the single-test 4.5 would over-report).
//!
//! Two in-guest controls bracket the harness's sensitivity: a deliberately
//! leaky early-exit compare that MUST read as a leak (otherwise the harness
//! cannot see anything and every other verdict is meaningless — the run
//! fails), and `subtle::ConstantTimeEq`, expected quiet.
//!
//! See timing-lab/README.md for the design, the detection limits, and why
//! this is a non-gating lab rather than a CI check.

mod stats;

mod bindings {
    wit_bindgen::generate!({
        path: "wit",
        world: "lab",
        generate_all,
    });
}

use bindings::lann::webcrypto::aead::AeadKey;
use bindings::lann::webcrypto::aes_gcm;
use bindings::lann::webcrypto::bytes;
use bindings::lann::webcrypto::chacha20_poly1305 as chacha;
use bindings::lann::webcrypto::hmac_sha2;
use bindings::lann::webcrypto::mac::MacKey;
use bindings::wit_stream;

use std::time::Instant;

use stats::{max_cropped_t, Verdict, THRESHOLD};

/// Samples per class per surface (override with TIMING_LAB_SAMPLES).
const DEFAULT_SAMPLES: usize = 2000;

/// Buffer length for the byte-comparison surfaces. Large enough that an
/// early-exit compare's first-vs-last-byte difference clears the clock and
/// call-overhead noise floor.
const COMPARE_LEN: usize = 4096;

/// Plaintext length for the fixed-vs-random seal surfaces.
const SEAL_LEN: usize = 16 * 1024;

/// xorshift64* — deterministic, seedable, good enough for class selection
/// and random-class inputs. Not a CSPRNG and doesn't need to be.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed.max(1))
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }

    fn bit(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }
}

/// The deliberately leaky positive-control compare: byte-by-byte with an
/// early exit, the exact shape dudect exists to catch.
#[inline(never)]
fn leaky_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for (x, y) in a.iter().zip(b) {
        if x != y {
            return false;
        }
    }
    true
}

/// One measured surface: `sample(class)` runs the operation once for the
/// given class and returns its duration in nanoseconds.
struct Report {
    name: &'static str,
    expect_leak: bool,
    samples_per_class: usize,
    max_t: f64,
    verdict: Verdict,
}

/// Interleaved two-class sampling loop: class order is drawn per trial from
/// the deterministic PRNG so environmental drift decorrelates from class.
async fn measure<F, Fut>(
    name: &'static str,
    expect_leak: bool,
    samples: usize,
    rng: &mut Rng,
    mut sample: F,
) -> Result<Report, String>
where
    F: FnMut(bool) -> Fut,
    Fut: std::future::Future<Output = Result<u64, String>>,
{
    let mut class0 = Vec::with_capacity(samples);
    let mut class1 = Vec::with_capacity(samples);
    // Warm-up: populate code paths, caches, and lazy allocations untimed.
    for class in [false, true] {
        sample(class).await.map_err(|e| format!("{name}: {e}"))?;
    }
    while class0.len() < samples || class1.len() < samples {
        let class = if class0.len() >= samples {
            true
        } else if class1.len() >= samples {
            false
        } else {
            rng.bit()
        };
        let ns = sample(class).await.map_err(|e| format!("{name}: {e}"))?;
        if class {
            class1.push(ns as f64);
        } else {
            class0.push(ns as f64);
        }
    }
    let max_t = max_cropped_t(&class0, &class1);
    let verdict = if !max_t.is_finite() {
        Verdict::Inconclusive
    } else if max_t.abs() > THRESHOLD {
        Verdict::Leak
    } else {
        Verdict::Quiet
    };
    Ok(Report {
        name,
        expect_leak,
        samples_per_class: samples,
        max_t,
        verdict,
    })
}

/// Time one closure with the in-guest monotonic clock.
fn timed<R>(op: impl FnOnce() -> R) -> (u64, R) {
    let start = Instant::now();
    let out = op();
    (start.elapsed().as_nanos() as u64, out)
}

/// Build the two comparison classes: `expected` plus a copy corrupted at the
/// first byte (class 0) or the last byte (class 1). Both compares FAIL;
/// only an early exit distinguishes them.
fn corrupted(expected: &[u8], class: bool) -> Vec<u8> {
    let mut probe = expected.to_vec();
    let index = if class { probe.len() - 1 } else { 0 };
    probe[index] ^= 0x01;
    probe
}

/// Drain a byte stream to its end, discarding the contents.
async fn drain(mut rx: wit_bindgen::StreamReader<u8>) {
    loop {
        let (status, _) = rx.read(Vec::with_capacity(8 * 1024)).await;
        if matches!(
            status,
            wit_bindgen::StreamResult::Dropped | wit_bindgen::StreamResult::Cancelled
        ) {
            break;
        }
    }
}

/// `mac-key.verify` with the whole message fed as one chunk, timed from
/// stream creation to the call's completion.
async fn timed_verify(key: &MacKey, message: &[u8], tag: Vec<u8>) -> Result<u64, String> {
    let start = Instant::now();
    let (mut tx, rx) = wit_stream::new();
    let (result, _) = futures::join!(key.verify(rx, tag), async move {
        let _ = tx.write_all(message.to_vec()).await;
        drop(tx);
    });
    let ns = start.elapsed().as_nanos() as u64;
    match result {
        Err(bindings::lann::webcrypto::types::Error::AuthenticationFailed) => Ok(ns),
        Ok(()) => Err("corrupted tag unexpectedly verified".into()),
        Err(err) => Err(format!("unexpected verify error: {err:?}")),
    }
}

/// `aead-key.open` of a corrupted sealed message, timed from stream creation
/// until the failure surfaces.
async fn timed_open_fail(key: &AeadKey, nonce: &[u8], sealed: &[u8]) -> Result<u64, String> {
    let start = Instant::now();
    let (mut tx, rx) = wit_stream::new();
    let (result, _) = futures::join!(key.open(nonce.to_vec(), Vec::new(), rx), async move {
        let _ = tx.write_all(sealed.to_vec()).await;
        drop(tx);
    });
    let ns = start.elapsed().as_nanos() as u64;
    match result {
        Err(bindings::lann::webcrypto::types::Error::AuthenticationFailed) => Ok(ns),
        Ok(rx) => {
            drain(rx).await;
            Err("corrupted ciphertext unexpectedly opened".into())
        }
        Err(err) => Err(format!("unexpected open error: {err:?}")),
    }
}

/// `aead-key.seal` of a full plaintext buffer, timed from stream creation
/// until the ciphertext is fully drained.
async fn timed_seal(key: &AeadKey, nonce: &[u8], plaintext: &[u8]) -> Result<u64, String> {
    let start = Instant::now();
    let (mut tx, rx) = wit_stream::new();
    let (result, _) = futures::join!(key.seal(nonce.to_vec(), Vec::new(), rx), async move {
        let _ = tx.write_all(plaintext.to_vec()).await;
        drop(tx);
    });
    match result {
        Ok(rx) => {
            drain(rx).await;
            Ok(start.elapsed().as_nanos() as u64)
        }
        Err(err) => Err(format!("seal failed: {err:?}")),
    }
}

/// Read a byte stream to its end, collecting the contents.
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

/// `mac-key.sign` over one chunk (untimed; produces the valid tag the
/// corrupted classes are derived from).
async fn sign(key: &MacKey, message: &[u8]) -> Vec<u8> {
    let (mut tx, rx) = wit_stream::new();
    let (tag, _) = futures::join!(key.sign(rx), async move {
        let _ = tx.write_all(message.to_vec()).await;
        drop(tx);
    });
    tag
}

/// `aead-key.seal` to a collected byte vector (untimed; produces the valid
/// sealed message the corrupted classes are derived from).
async fn seal_bytes(key: &AeadKey, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let (mut tx, rx) = wit_stream::new();
    let (result, _) = futures::join!(key.seal(nonce.to_vec(), Vec::new(), rx), async move {
        let _ = tx.write_all(plaintext.to_vec()).await;
        drop(tx);
    });
    match result {
        Ok(rx) => Ok(read_all(rx).await),
        Err(err) => Err(format!("seal failed: {err:?}")),
    }
}

/// Tag-comparison surface over an AEAD algorithm: `open` with the tag byte
/// corrupted at the start (class 0) vs the end (class 1) of the ciphertext's
/// final 16 bytes. Both fail authentication; GHASH/Poly1305 recomputation is
/// identical, so the classes isolate the tag *comparison*.
async fn measure_open(
    name: &'static str,
    key: &AeadKey,
    nonce: &[u8],
    samples: usize,
    rng: &mut Rng,
) -> Result<Report, String> {
    let mut plaintext = vec![0u8; SEAL_LEN];
    rng.fill(&mut plaintext);
    let sealed = seal_bytes(key, nonce, &plaintext)
        .await
        .map_err(|e| format!("{name}: {e}"))?;
    let tag_at = sealed.len() - 16;
    let mut first = sealed.clone();
    first[tag_at] ^= 0x01;
    let mut last = sealed;
    last[tag_at + 15] ^= 0x01;
    measure(name, false, samples, rng, |class| {
        let sealed = if class { last.clone() } else { first.clone() };
        async move { timed_open_fail(key, nonce, &sealed).await }
    })
    .await
}

/// Fixed-vs-random plaintext surface over an AEAD algorithm's `seal`: a
/// secret-independent cipher shows no class difference; a data-dependent
/// one (e.g. a table-based AES) can.
async fn measure_seal(
    name: &'static str,
    key: &AeadKey,
    nonce: &[u8],
    samples: usize,
    rng: &mut Rng,
) -> Result<Report, String> {
    let fixed = vec![0u8; SEAL_LEN];
    let mut random = vec![0u8; SEAL_LEN];
    measure(name, false, samples, rng, |class| {
        let plaintext = if class {
            // Fresh random plaintext per trial, from a per-call cheap fill.
            random.rotate_left(1);
            random[0] ^= 0x5a;
            random.clone()
        } else {
            fixed.clone()
        };
        async move { timed_seal(key, nonce, &plaintext).await }
    })
    .await
}

async fn run_lab() -> Result<(), String> {
    let samples = std::env::var("TIMING_LAB_SAMPLES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_SAMPLES);
    let mut rng = Rng::new(0x74696d696e675f6c);

    let mut expected = vec![0u8; COMPARE_LEN];
    rng.fill(&mut expected);

    let mut reports = Vec::new();

    // Positive control: the harness MUST see this leak.
    {
        let expected = expected.clone();
        reports.push(
            measure(
                "control/leaky-equal (in-guest)",
                true,
                samples,
                &mut rng,
                |class| {
                    let probe = corrupted(&expected, class);
                    let expected = expected.clone();
                    async move {
                        let (ns, ok) = timed(|| leaky_equal(&expected, &probe));
                        if ok {
                            return Err("corrupted buffer compared equal".into());
                        }
                        Ok(ns)
                    }
                },
            )
            .await?,
        );
    }

    // Negative control: subtle::ConstantTimeEq in-guest, expected quiet.
    {
        use subtle::ConstantTimeEq;
        let expected = expected.clone();
        reports.push(
            measure(
                "control/subtle-ct-eq (in-guest)",
                false,
                samples,
                &mut rng,
                |class| {
                    let probe = corrupted(&expected, class);
                    let expected = expected.clone();
                    async move {
                        let (ns, eq) = timed(|| bool::from(expected.ct_eq(&probe)));
                        if eq {
                            return Err("corrupted buffer compared equal".into());
                        }
                        Ok(ns)
                    }
                },
            )
            .await?,
        );
    }

    // bytes.constant-time-equal across the component boundary.
    {
        let expected = expected.clone();
        reports.push(
            measure(
                "bytes/constant-time-equal",
                false,
                samples,
                &mut rng,
                |class| {
                    let probe = corrupted(&expected, class);
                    let expected = expected.clone();
                    async move {
                        let (ns, eq) = timed(|| bytes::constant_time_equal(&expected, &probe));
                        if eq {
                            return Err("corrupted buffer compared equal".into());
                        }
                        Ok(ns)
                    }
                },
            )
            .await?,
        );
    }

    // mac-key.verify: corrupted tag, first vs last byte.
    {
        let key = hmac_sha2::generate_key(hmac_sha2::Sha2Variant::Sha256, false)
            .await
            .map_err(|e| format!("hmac generate-key: {e:?}"))?;
        let mut message = vec![0u8; SEAL_LEN];
        rng.fill(&mut message);
        let tag = sign(&key, &message).await;
        reports.push(
            measure(
                "hmac-sha256/verify tag compare",
                false,
                samples,
                &mut rng,
                |class| {
                    let probe = corrupted(&tag, class);
                    let key = &key;
                    let message = &message;
                    async move { timed_verify(key, message, probe).await }
                },
            )
            .await?,
        );
    }

    // AEAD tag rejection + seal data-dependence, per algorithm.
    let gcm_key = aes_gcm::generate_key(aes_gcm::AesVariant::Aes256, false)
        .await
        .map_err(|e| format!("aes-gcm generate-key: {e:?}"))?;
    let chacha_key = chacha::generate_key(chacha::ChachaVariant::Chacha20Poly1305, false)
        .await
        .map_err(|e| format!("chacha generate-key: {e:?}"))?;
    let gcm_nonce = [0x24u8; 12];
    reports.push(
        measure_open(
            "aes-256-gcm/open tag compare",
            &gcm_key,
            &gcm_nonce,
            samples,
            &mut rng,
        )
        .await?,
    );
    reports.push(
        measure_open(
            "chacha20-poly1305/open tag compare",
            &chacha_key,
            &gcm_nonce,
            samples,
            &mut rng,
        )
        .await?,
    );
    reports.push(
        measure_seal(
            "aes-256-gcm/seal fixed-vs-random",
            &gcm_key,
            &gcm_nonce,
            samples,
            &mut rng,
        )
        .await?,
    );
    reports.push(
        measure_seal(
            "chacha20-poly1305/seal fixed-vs-random",
            &chacha_key,
            &gcm_nonce,
            samples,
            &mut rng,
        )
        .await?,
    );

    // Render and evaluate.
    let mut failures = 0;
    println!("timing lab: {samples} samples/class, threshold max |t| > {THRESHOLD}");
    println!();
    println!("| surface | samples/class | max \\|t\\| | verdict | expected |");
    println!("| --- | --- | --- | --- | --- |");
    for r in &reports {
        let verdict = match r.verdict {
            Verdict::Quiet => "quiet",
            Verdict::Leak => "LEAK",
            Verdict::Inconclusive => "inconclusive",
        };
        let expected = if r.expect_leak { "leak" } else { "quiet" };
        let ok = matches!(
            (&r.verdict, r.expect_leak),
            (Verdict::Leak, true) | (Verdict::Quiet, false)
        );
        if !ok {
            failures += 1;
        }
        println!(
            "| {} | {} | {:.1} | {}{} | {} |",
            r.name,
            r.samples_per_class,
            r.max_t,
            verdict,
            if ok { "" } else { " ***" },
            expected,
        );
    }
    println!();
    if failures > 0 {
        return Err(format!(
            "{failures} surface(s) diverged from expectation (see ***). \
             A quiet positive control means the harness cannot detect leaks \
             at this measurement distance; a LEAK on a real surface warrants \
             investigation (statistical flakes happen — rerun with more \
             samples via TIMING_LAB_SAMPLES before drawing conclusions)."
        ));
    }
    println!("OK: all surfaces matched expectations.");
    Ok(())
}

struct Component;

impl wasip3::exports::cli::run::Guest for Component {
    async fn run() -> Result<(), ()> {
        match run_lab().await {
            Ok(()) => Ok(()),
            Err(err) => {
                eprintln!("timing lab failed: {err}");
                Err(())
            }
        }
    }
}

wasip3::cli::command::export!(Component);
