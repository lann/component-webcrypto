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
//! Class order is a balanced shuffled schedule and every trial performs the
//! same preparation work regardless of class, so neither the run's own drift
//! nor the harness's input generation can masquerade as a class difference.
//!
//! In-guest controls bracket the harness's detectability, one per class
//! shape — a positive control validates only the shape it uses. A
//! deliberately leaky early-exit compare covers the corrupted-first-vs-last
//! shape and a data-dependent loop covers fixed-vs-random; both MUST read as
//! leaks (otherwise the harness cannot see anything and every other verdict
//! is meaningless — the run fails). `subtle::ConstantTimeEq` is the negative
//! control, expected quiet.
//!
//! See timing-lab/README.md for the design, the detection limits, and why
//! this is a non-gating lab rather than a CI check.

mod stats;

mod bindings {
    wit_bindgen::generate!({
        path: "wit",
        world: "lab",
        features: ["chacha20-poly1305"],
        generate_all,
    });
}

use bindings::lann::webcrypto::aead::AeadKey;
use bindings::lann::webcrypto::aes_gcm;
use bindings::lann::webcrypto::bytes;
use bindings::lann::webcrypto::chacha20_poly1305 as chacha;
use bindings::lann::webcrypto::ecdh;
use bindings::lann::webcrypto::hmac_sha2;
use bindings::lann::webcrypto::key_agreement::{
    AgreementKeyOptions, PublicKey as AgreementPublicKey, SecretKey as AgreementSecretKey,
};
use bindings::lann::webcrypto::mac::MacKey;
use bindings::lann::webcrypto::x25519;
use bindings::wit_stream;

use data_encoding_macro::hexlower;

use std::time::Instant;

use stats::{max_cropped_t, Accumulator, Verdict, THRESHOLD};

/// Samples per class per surface (override with TIMING_LAB_SAMPLES).
const DEFAULT_SAMPLES: usize = 2000;

/// Trials per class run and discarded before sampling begins: populate code
/// paths, caches, and lazy allocations so their one-off costs land outside
/// the measured data.
const WARMUP: usize = 32;

/// Buffer length for the byte-comparison surfaces. Large enough that an
/// early-exit compare's first-vs-last-byte difference clears the clock and
/// call-overhead noise floor.
const COMPARE_LEN: usize = 4096;

/// Message length for the tag-comparison surfaces (`verify`, `open`).
///
/// Deliberately short. An early-exit tag compare's signal is a fixed
/// ~15-byte difference no matter how long the message is, while the noise
/// it competes with — the stream transfer plus the full MAC/GHASH
/// recomputation, all inside the timed window — grows with the message. A
/// short message therefore maximizes the signal-to-noise ratio of exactly
/// the difference these surfaces exist to detect.
const TAG_PROBE_LEN: usize = 64;

/// Plaintext length for the fixed-vs-random seal surfaces. Long, for the
/// opposite reason: data-dependent cipher effects accumulate per block, so
/// the signal grows with the plaintext.
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

    /// Fisher-Yates shuffle. The modulo's bias is irrelevant here: this
    /// orders a class schedule, it does not generate secrets.
    fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = (self.next_u64() % (i as u64 + 1)) as usize;
            items.swap(i, j);
        }
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

/// The deliberately data-dependent positive control, for the *fixed-vs-random*
/// class shape the seal surfaces use.
///
/// Each byte drives a loop whose trip count is its low nibble: the all-zero
/// fixed class does no inner work, a random one averages 7.5 iterations per
/// byte. A variable trip count cannot be flattened into branchless code, so
/// this leaks by construction — which is the point. Without it, a quiet
/// verdict on the seal surfaces cannot distinguish "the cipher has no data
/// dependence" from "the harness cannot see data dependence here".
#[inline(never)]
fn data_dependent_work(data: &[u8]) -> u32 {
    let mut acc = 1u32;
    for &b in data {
        for _ in 0..(b & 0x0f) {
            acc = acc.wrapping_mul(31).wrapping_add(b as u32);
        }
    }
    acc
}

/// One measured surface: `sample(class)` runs the operation once for the
/// given class and returns its duration in nanoseconds.
struct Report {
    name: &'static str,
    expect_leak: bool,
    samples_per_class: usize,
    max_t: f64,
    verdict: Verdict,
    /// Pooled mean sample time, ns — the measurement distance: how much
    /// unrelated work each sample carries alongside the operation under
    /// test.
    mean_ns: f64,
    /// Pooled standard deviation, ns. Together with the sample count this
    /// is what a quiet verdict actually bounds: a per-class difference much
    /// below `sigma_ns / sqrt(samples)` is invisible here.
    sigma_ns: f64,
}

/// Interleaved two-class sampling loop over a balanced, shuffled schedule,
/// so environmental drift decorrelates from class.
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
    for i in 0..WARMUP * 2 {
        sample(i % 2 == 1)
            .await
            .map_err(|e| format!("{name}: {e}"))?;
    }
    // A balanced shuffled schedule, not a per-trial coin flip: a coin
    // flip's random walk exhausts one class ~sqrt(n) trials before the
    // other, so the run's final samples are all one class — recorrelating
    // class with time exactly where end-of-run drift lives.
    let mut schedule = vec![false; samples];
    schedule.resize(samples * 2, true);
    rng.shuffle(&mut schedule);
    for class in schedule {
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
    let mut pooled = Accumulator::default();
    for &x in class0.iter().chain(&class1) {
        pooled.push(x);
    }
    Ok(Report {
        name,
        expect_leak,
        samples_per_class: samples,
        max_t,
        verdict,
        mean_ns: pooled.mean(),
        sigma_ns: pooled.variance().sqrt(),
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
    let (result, _) = futures::join!(key.open(nonce.to_vec(), Vec::new(), None, rx), async move {
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
    let (result, _) = futures::join!(key.seal(nonce.to_vec(), Vec::new(), None, rx), async move {
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
///
/// Deliberately not the `lann-webcrypto-guest` wrappers: this crate shares
/// wit-bindgen runtime types with `wasip3` (pinned to an older wit-bindgen;
/// see Cargo.toml), and mixing two runtime versions in one component does
/// not work — and a measurement harness wants its stream plumbing inline
/// anyway, where it can be seen not to perturb the timed window.
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
async fn sign(key: &MacKey, message: &[u8]) -> Result<Vec<u8>, String> {
    let (mut tx, rx) = wit_stream::new();
    let (tag, _) = futures::join!(key.sign(rx), async move {
        let _ = tx.write_all(message.to_vec()).await;
        drop(tx);
    });
    tag.map_err(|e| format!("mac-key.sign failed: {e:?}"))
}

/// `aead-key.seal` to a collected byte vector (untimed; produces the valid
/// sealed message the corrupted classes are derived from).
async fn seal_bytes(key: &AeadKey, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let (mut tx, rx) = wit_stream::new();
    let (result, _) = futures::join!(key.seal(nonce.to_vec(), Vec::new(), None, rx), async move {
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
    let mut plaintext = vec![0u8; TAG_PROBE_LEN];
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
///
/// `control/data-dependent-work` brackets this class shape's detectability;
/// read a quiet verdict here only against that control's verdict.
async fn measure_seal(
    name: &'static str,
    key: &AeadKey,
    nonce: &[u8],
    samples: usize,
    rng: &mut Rng,
) -> Result<Report, String> {
    let fixed = vec![0u8; SEAL_LEN];
    let mut random = vec![0u8; SEAL_LEN];
    // A second generator: `measure` holds `rng` mutably for the whole run,
    // and the class schedule and the input material are independent draws.
    let mut inputs = Rng::new(rng.next_u64());
    measure(name, false, samples, rng, |class| {
        // Both classes draw a fresh fill and one clone, so the work
        // preceding the timed window is identical whichever class is
        // selected. Filling only for the random class would put 16 KiB of
        // extra work and cache pressure in front of one class's
        // measurements — a class-correlated difference manufactured by the
        // harness itself.
        inputs.fill(&mut random);
        let plaintext = if class { random.clone() } else { fixed.clone() };
        async move { timed_seal(key, nonce, &plaintext).await }
    })
    .await
}

/// The agreement surfaces' known-answer constants: a published secret
/// scalar, its peer's public key, and the published shared secret. Each
/// surface's setup agrees the known-answer key with the peer and checks
/// the published value, so a wrong PKCS#8 template or import path fails
/// loudly before sampling. X25519 is RFC 7748 §6.1 (Alice's scalar, Bob's
/// public key); the ECDH pairs are Wycheproof
/// `ecdh_secp{256,384}r1_ecpoint_test.json` tcId 1.
const X25519_KAT_D: [u8; 32] =
    hexlower!("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
const X25519_PEER: [u8; 32] =
    hexlower!("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
const X25519_SHARED: [u8; 32] =
    hexlower!("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
const ECDH_P256_KAT_D: [u8; 32] =
    hexlower!("0612465c89a023ab17855b0a6bcebfd3febb53aef84138647b5352e02c10c346");
const ECDH_P256_PEER: [u8; 65] = hexlower!(
    "0462d5bd3372af75fe85a040715d0f502428e07046868b0bfdfa61d731afe44f\
     26ac333a93a9e70a81cd5a95b5bf8d13990eb741c8c38872b4a07d275a014e30\
     cf"
);
const ECDH_P256_SHARED: [u8; 32] =
    hexlower!("53020d908b0219328b658b525f26780e3ae12bcd952bb25a93bc0895e1714285");
const ECDH_P384_KAT_D: [u8; 48] = hexlower!(
    "766e61425b2da9f846c09fc3564b93a6f8603b7392c785165bf20da948c49fd1\
     fb1dee4edd64356b9f21c588b75dfd81"
);
const ECDH_P384_PEER: [u8; 97] = hexlower!(
    "04790a6e059ef9a5940163183d4a7809135d29791643fc43a2f17ee8bf677ab8\
     4f791b64a6be15969ffa012dd9185d8796d9b954baa8a75e82df711b3b56eadf\
     f6b0f668c3b26b4b1aeb308a1fcc1c680d329a6705025f1c98a0b5e5bfcb163c\
     aa"
);
const ECDH_P384_SHARED: [u8; 48] = hexlower!(
    "6461defb95d996b24296f5a1832b34db05ed031114fbe7d98d098f93859866e4\
     de1e229da71fef0c77fe49b249190135"
);

/// A scalar with one bit set, at `bit` counted from `LE` little-endian or
/// big-endian byte order.
const fn single_bit_scalar<const N: usize, const LE: bool>(bit: usize) -> [u8; N] {
    let mut scalar = [0u8; N];
    let byte = bit / 8;
    scalar[if LE { byte } else { N - 1 - byte }] = 1 << (bit % 8);
    scalar
}

/// The measured fixed class's scalars: a single mid-position bit, the
/// extreme low end of the Hamming-weight distribution the random class
/// draws from (mean n/2 ± ~√n/2). The canonical leak the fixed-vs-random
/// scalar shape targets — weight-proportional scalar-mult timing, a
/// double-and-add regression — separates the class *means* by the weight
/// difference times the per-bit cost, so the fixed scalar's distance from
/// the random mean is a direct multiplier on the surface's sensitivity; a
/// near-mean fixed scalar (a typical published test vector) would leave
/// almost none. Deliberately distinct from the known-answer scalars above,
/// which validate the template and import path against published vectors.
///
/// A mid-position bit keeps the value an unremarkable in-range scalar
/// (complete-formula P-curve code and the Montgomery ladder have no
/// small-scalar special cases, but nothing is gained by sitting near one).
/// X25519 clamping sets bit 254, so its fixed scalar measures at weight 2;
/// the P-curve scalars measure at weight 1.
const X25519_FIXED_D: [u8; 32] = single_bit_scalar::<32, true>(128);
const ECDH_P256_FIXED_D: [u8; 32] = single_bit_scalar::<32, false>(128);
const ECDH_P384_FIXED_D: [u8; 48] = single_bit_scalar::<48, false>(192);

/// PKCS#8 PrivateKeyInfo prefixes for a bare scalar of the algorithm's
/// fixed field size: version, algorithm identifier, and the nested
/// octet-string (and, for EC, ECPrivateKey) headers — every length is
/// scalar-size-determined, so the encoding is this constant followed by
/// the scalar bytes. The setup known-answer check validates each template.
const X25519_PKCS8_PREFIX: [u8; 16] = hexlower!("302e020100300506032b656e04220420");
const P256_PKCS8_PREFIX: [u8; 35] = hexlower!(
    "3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201\
     010420"
);
const P384_PKCS8_PREFIX: [u8; 32] =
    hexlower!("304e020100301006072a8648ce3d020106052b81040022043730350201010430");

/// The curve group orders, big-endian: a fresh ECDH scalar draw is valid
/// iff it is nonzero and below the order, so the sampling loop can
/// rejection-sample locally instead of routing rejections through import.
const N_P256: [u8; 32] =
    hexlower!("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
const N_P384: [u8; 48] = hexlower!(
    "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf\
     581a0db248b0a77aecec196accc52973"
);

/// Whether a big-endian scalar draw is in `[1, n-1]`. Byte-lexicographic
/// comparison is numeric comparison for equal-length big-endian strings.
fn scalar_in_range(scalar: &[u8], order: &[u8]) -> bool {
    scalar.iter().any(|&b| b != 0) && scalar < order
}

/// `secret-key.agree` with a fixed peer, timed from the call until its
/// completion; the returned derive-input is dropped outside the window.
async fn timed_agree(key: &AgreementSecretKey, peer: &AgreementPublicKey) -> Result<u64, String> {
    let start = Instant::now();
    let result = key.agree(peer);
    let result = result.await;
    let ns = start.elapsed().as_nanos() as u64;
    match result {
        Ok(_input) => Ok(ns),
        Err(err) => Err(format!("agree failed: {err:?}")),
    }
}

/// One agreement algorithm's fixed inputs: the known-answer scalar and
/// shared secret, the low-weight fixed-class scalar, the PKCS#8 template,
/// and the curve order for local rejection-sampling of random draws
/// (`None` for X25519, where every 32-byte string is a valid clamped
/// scalar).
struct AgreeSurface {
    name: &'static str,
    kat_scalar: &'static [u8],
    fixed_scalar: &'static [u8],
    prefix: &'static [u8],
    order: Option<&'static [u8]>,
    expected_shared: &'static [u8],
}

/// Fixed-vs-random secret *scalar* against a fixed peer, over a
/// key-agreement algorithm's `agree`: the peer — and with it every
/// point-dependent operand — is identical across classes, each trial
/// assembles and imports a fresh PKCS#8 key whichever class it feeds, and
/// the timed window is `agree` alone, so only scalar-dependent control
/// flow or memory access in the scalar multiplication separates the
/// classes. The fixed class's scalar has minimal Hamming weight (see the
/// `*_FIXED_D` constants), maximizing the class-mean separation a
/// weight-shaped leak would produce.
///
/// `control/data-dependent-work` brackets this class shape's
/// detectability, as for the seal surfaces.
async fn measure_agree<F, Fut>(
    surface: AgreeSurface,
    peer: &AgreementPublicKey,
    samples: usize,
    rng: &mut Rng,
    import: F,
) -> Result<Report, String>
where
    F: Fn(Vec<u8>) -> Fut,
    Fut: std::future::Future<
        Output = Result<AgreementSecretKey, bindings::lann::webcrypto::types::Error>,
    >,
{
    let AgreeSurface {
        name,
        kat_scalar,
        fixed_scalar,
        prefix,
        order,
        expected_shared,
    } = surface;
    // Known-answer check: the published scalar's key must agree with the
    // peer on the published shared secret, or the template/import path is
    // wrong and every measurement below would be of something else.
    let kat_key = import([prefix, kat_scalar].concat())
        .await
        .map_err(|e| format!("{name}: known-answer import failed: {e:?}"))?;
    let input = kat_key
        .agree(peer)
        .await
        .map_err(|e| format!("{name}: known-answer agree failed: {e:?}"))?;
    let shared = input
        .derive_bits(None)
        .await
        .map_err(|e| format!("{name}: known-answer derive failed: {e:?}"))?;
    if shared != expected_shared {
        return Err(format!(
            "{name}: known-answer shared secret mismatch — bad PKCS#8 template or import path"
        ));
    }

    let mut random = vec![0u8; fixed_scalar.len()];
    let mut inputs = Rng::new(rng.next_u64());
    measure(name, false, samples, rng, |class| {
        // Both classes draw a fresh in-range scalar and assemble one
        // PKCS#8 buffer, so the work preceding the timed window is
        // identical whichever class is selected (the seal surfaces'
        // symmetric-preparation rule).
        loop {
            inputs.fill(&mut random);
            match order {
                Some(order) if !scalar_in_range(&random, order) => continue,
                _ => break,
            }
        }
        let scalar: &[u8] = if class { &random } else { fixed_scalar };
        let pkcs8 = [prefix, scalar].concat();
        let import = &import;
        async move {
            let key = import(pkcs8)
                .await
                .map_err(|e| format!("import failed: {e:?}"))?;
            timed_agree(&key, peer).await
        }
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

    // Positive control for the fixed-vs-random class shape, bracketing the
    // seal surfaces the way leaky-equal brackets the compare surfaces.
    {
        let fixed = vec![0u8; SEAL_LEN];
        let mut random = vec![0u8; SEAL_LEN];
        let mut inputs = Rng::new(rng.next_u64());
        reports.push(
            measure(
                "control/data-dependent-work (in-guest)",
                true,
                samples,
                &mut rng,
                |class| {
                    // Symmetric per-trial work, as in `measure_seal`.
                    inputs.fill(&mut random);
                    let data = if class { random.clone() } else { fixed.clone() };
                    async move {
                        let (ns, acc) = timed(|| data_dependent_work(&data));
                        // The accumulator is dead otherwise, and the
                        // optimizer is entitled to delete the whole loop.
                        std::hint::black_box(acc);
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
        let options = bindings::lann::webcrypto::mac::MacKeyOptions::new();
        options.can_sign(true);
        options.can_verify(true);
        let key = hmac_sha2::generate_key(hmac_sha2::Sha2Variant::Sha256, None, options)
            .await
            .map_err(|e| format!("hmac generate-key: {e:?}"))?;
        let mut message = vec![0u8; TAG_PROBE_LEN];
        rng.fill(&mut message);
        let tag = sign(&key, &message).await?;
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

    // AEAD tag rejection + seal data-dependence, per algorithm. The lab
    // measures seal/open, so grant exactly those usages.
    fn seal_open_options() -> bindings::lann::webcrypto::aead::AeadKeyOptions {
        let options = bindings::lann::webcrypto::aead::AeadKeyOptions::new();
        options.can_seal(true);
        options.can_open(true);
        options
    }
    let gcm_key = aes_gcm::generate_key(aes_gcm::AesVariant::Aes256, seal_open_options())
        .await
        .map_err(|e| format!("aes-gcm generate-key: {e:?}"))?;
    let chacha_key = chacha::generate_key(seal_open_options())
        .await
        .map_err(|e| format!("chacha generate-key: {e:?}"))?;
    // AES-GCM and the IETF ChaCha20-Poly1305 construction both take a
    // 12-byte nonce, so one value serves both surfaces.
    let nonce12 = [0x24u8; 12];
    reports.push(
        measure_open(
            "aes-256-gcm/open tag compare",
            &gcm_key,
            &nonce12,
            samples,
            &mut rng,
        )
        .await?,
    );
    reports.push(
        measure_open(
            "chacha20-poly1305/open tag compare",
            &chacha_key,
            &nonce12,
            samples,
            &mut rng,
        )
        .await?,
    );
    reports.push(
        measure_seal(
            "aes-256-gcm/seal fixed-vs-random",
            &gcm_key,
            &nonce12,
            samples,
            &mut rng,
        )
        .await?,
    );
    reports.push(
        measure_seal(
            "chacha20-poly1305/seal fixed-vs-random",
            &chacha_key,
            &nonce12,
            samples,
            &mut rng,
        )
        .await?,
    );

    // Key agreement: fixed-vs-random secret scalar, per algorithm. The lab
    // measures `agree` (whose output feeds derivation), so grant
    // derive-bits — also what the setup known-answer check reads.
    fn agree_options() -> AgreementKeyOptions {
        let options = AgreementKeyOptions::new();
        options.can_derive_bits(true);
        options
    }
    {
        let peer = x25519::import_public_key_raw(X25519_PEER.to_vec())
            .await
            .map_err(|e| format!("x25519 import-public-key: {e:?}"))?;
        reports.push(
            measure_agree(
                AgreeSurface {
                    name: "x25519/agree fixed-vs-random scalar",
                    kat_scalar: &X25519_KAT_D,
                    fixed_scalar: &X25519_FIXED_D,
                    prefix: &X25519_PKCS8_PREFIX,
                    order: None,
                    expected_shared: &X25519_SHARED,
                },
                &peer,
                samples,
                &mut rng,
                |pkcs8| x25519::import_secret_key_pkcs8(pkcs8, agree_options()),
            )
            .await?,
        );
    }
    {
        let peer = ecdh::import_public_key_raw(ecdh::EcdhVariant::P256, ECDH_P256_PEER.to_vec())
            .await
            .map_err(|e| format!("ecdh p256 import-public-key: {e:?}"))?;
        reports.push(
            measure_agree(
                AgreeSurface {
                    name: "ecdh-p256/agree fixed-vs-random scalar",
                    kat_scalar: &ECDH_P256_KAT_D,
                    fixed_scalar: &ECDH_P256_FIXED_D,
                    prefix: &P256_PKCS8_PREFIX,
                    order: Some(&N_P256),
                    expected_shared: &ECDH_P256_SHARED,
                },
                &peer,
                samples,
                &mut rng,
                |pkcs8| {
                    ecdh::import_secret_key_pkcs8(ecdh::EcdhVariant::P256, pkcs8, agree_options())
                },
            )
            .await?,
        );
    }
    {
        let peer = ecdh::import_public_key_raw(ecdh::EcdhVariant::P384, ECDH_P384_PEER.to_vec())
            .await
            .map_err(|e| format!("ecdh p384 import-public-key: {e:?}"))?;
        reports.push(
            measure_agree(
                AgreeSurface {
                    name: "ecdh-p384/agree fixed-vs-random scalar",
                    kat_scalar: &ECDH_P384_KAT_D,
                    fixed_scalar: &ECDH_P384_FIXED_D,
                    prefix: &P384_PKCS8_PREFIX,
                    order: Some(&N_P384),
                    expected_shared: &ECDH_P384_SHARED,
                },
                &peer,
                samples,
                &mut rng,
                |pkcs8| {
                    ecdh::import_secret_key_pkcs8(ecdh::EcdhVariant::P384, pkcs8, agree_options())
                },
            )
            .await?,
        );
    }

    // Render and evaluate.
    let mut failures = 0;
    println!("timing lab: {samples} samples/class, threshold max |t| > {THRESHOLD}");
    println!();
    println!("| surface | samples/class | mean ns | sigma ns | max \\|t\\| | verdict | expected |");
    println!("| --- | --- | --- | --- | --- | --- | --- |");
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
            "| {} | {} | {:.0} | {:.0} | {:.1} | {}{} | {} |",
            r.name,
            r.samples_per_class,
            r.mean_ns,
            r.sigma_ns,
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
