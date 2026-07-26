//! `conformance-guest`: the shared conformance component.
//!
//! One guest binary runs the whole corpus — the Wycheproof-derived vector
//! cases (translated per `conformance/vectors/README.md` in [`translate`])
//! plus the hand-written API-contract [`probes`] — against whichever
//! `lann:webcrypto` implementation the target under test provides, and
//! reports one `test-result` per executed test. Expectation mismatches are
//! reported as failures, never traps, so a single run always yields the full
//! result list.
//!
//! The corpus is indexable (`count`/`list-tests` + `run-slice`/`run-many`) so
//! a harness can split one run across several fresh component instances or
//! select an arbitrary subset; `run-all` is `run-slice(0, count())`.

wit_bindgen::generate!({
    path: "wit",
    world: "conformance-guest",
    generate_all,
});

mod probes;
mod translate;
mod util;
mod vectors;

use exports::conformance::webcrypto::tests::{Guest, TestResult};
use translate::{
    ChaChaCase, GcmCase, HmacCase, InternalNonceCase, Sha2Case, SigCase, SpeccheckCase,
};

struct Component;

/// The materialized corpus, in corpus order.
struct Corpus {
    hmac: Vec<HmacCase>,
    gcm: Vec<GcmCase>,
    chacha: Vec<ChaChaCase>,
    internal_nonce: Vec<InternalNonceCase>,
    sha2: Vec<Sha2Case>,
    sig: Vec<SigCase>,
    speccheck: Vec<SpeccheckCase>,
}

/// One corpus entry: a vector case or a probe index.
enum Test<'a> {
    Hmac(&'a HmacCase),
    Gcm(&'a GcmCase),
    ChaCha(&'a ChaChaCase),
    InternalNonce(&'a InternalNonceCase),
    Sha2(&'a Sha2Case),
    Sig(&'a SigCase),
    Speccheck(&'a SpeccheckCase),
    Probe(usize),
}

impl Corpus {
    fn load() -> Self {
        Corpus {
            hmac: translate::hmac_cases(),
            gcm: translate::gcm_cases(),
            chacha: translate::chacha_cases(),
            internal_nonce: translate::internal_nonce_cases(),
            sha2: translate::sha2_cases(),
            sig: translate::sig_cases(),
            speccheck: translate::speccheck_cases(),
        }
    }

    fn len(&self) -> usize {
        self.hmac.len()
            + self.gcm.len()
            + self.chacha.len()
            + self.internal_nonce.len()
            + self.sha2.len()
            + self.sig.len()
            + self.speccheck.len()
            + probes::NAMES.len()
    }

    /// The test at corpus index `index`.
    fn test(&self, index: usize) -> Option<Test<'_>> {
        let mut index = index;
        if index < self.hmac.len() {
            return Some(Test::Hmac(&self.hmac[index]));
        }
        index -= self.hmac.len();
        if index < self.gcm.len() {
            return Some(Test::Gcm(&self.gcm[index]));
        }
        index -= self.gcm.len();
        if index < self.chacha.len() {
            return Some(Test::ChaCha(&self.chacha[index]));
        }
        index -= self.chacha.len();
        if index < self.internal_nonce.len() {
            return Some(Test::InternalNonce(&self.internal_nonce[index]));
        }
        index -= self.internal_nonce.len();
        if index < self.sha2.len() {
            return Some(Test::Sha2(&self.sha2[index]));
        }
        index -= self.sha2.len();
        if index < self.sig.len() {
            return Some(Test::Sig(&self.sig[index]));
        }
        index -= self.sig.len();
        if index < self.speccheck.len() {
            return Some(Test::Speccheck(&self.speccheck[index]));
        }
        index -= self.speccheck.len();
        (index < probes::NAMES.len()).then_some(Test::Probe(index))
    }
}

impl Test<'_> {
    fn id(&self) -> String {
        match self {
            Test::Hmac(case) => format!(
                "hmac-sha256/wycheproof/tc{}/{}",
                case.tc_id,
                case.schedule.name()
            ),
            Test::Gcm(case) => format!(
                "aes-gcm/wycheproof/tc{}/{}",
                case.tc_id,
                case.schedule.name()
            ),
            Test::ChaCha(case) => format!(
                "{}/wycheproof/tc{}/{}",
                case.alg.name(),
                case.tc_id,
                case.schedule.name()
            ),
            Test::InternalNonce(case) => format!(
                "{}/wycheproof/tc{}/{}",
                case.alg.name(),
                case.tc_id,
                case.schedule.name()
            ),
            Test::Sha2(case) => format!(
                "sha2/nist-cavp/{}-len{}/{}",
                case.alg.name(),
                case.len_bits,
                case.schedule.name()
            ),
            Test::Sig(case) => format!(
                "{}/wycheproof/tc{}/{}",
                case.alg.name(),
                case.tc_id,
                case.schedule.name()
            ),
            Test::Speccheck(case) => format!(
                "ed25519/speccheck/tc{}/{}",
                case.tc_id,
                case.schedule.name()
            ),
            Test::Probe(index) => format!("probe/{}", probes::NAMES[*index]),
        }
    }

    async fn run(&self) -> TestResult {
        let outcome = match self {
            Test::Hmac(case) => vectors::run_hmac_case(case).await,
            Test::Gcm(case) => vectors::run_gcm_case(case).await,
            Test::ChaCha(case) => vectors::run_chacha_case(case).await,
            Test::InternalNonce(case) => vectors::run_internal_nonce_case(case).await,
            Test::Sha2(case) => vectors::run_sha2_case(case).await,
            Test::Sig(case) => vectors::run_sig_case(case).await,
            Test::Speccheck(case) => vectors::run_speccheck_case(case).await,
            Test::Probe(index) => probes::run_one(*index).await,
        };
        to_result(self.id(), outcome)
    }
}

impl Guest for Component {
    fn count() -> u32 {
        Corpus::load().len() as u32
    }

    fn list_tests() -> Vec<String> {
        let corpus = Corpus::load();
        (0..corpus.len())
            .map(|index| corpus.test(index).unwrap().id())
            .collect()
    }

    async fn run_all() -> Vec<TestResult> {
        run_slice_impl(0, u32::MAX).await
    }

    async fn run_slice(skip: u32, take: u32) -> Vec<TestResult> {
        run_slice_impl(skip, take).await
    }

    async fn run_many(tests: Vec<String>) -> Vec<TestResult> {
        let corpus = Corpus::load();
        let by_id: std::collections::HashMap<String, usize> = (0..corpus.len())
            .map(|index| (corpus.test(index).unwrap().id(), index))
            .collect();
        let mut results = Vec::with_capacity(tests.len());
        for id in tests {
            results.push(match by_id.get(&id) {
                Some(&index) => corpus.test(index).unwrap().run().await,
                None => TestResult {
                    id,
                    passed: false,
                    detail: "no test with this id in the corpus".into(),
                },
            });
        }
        results
    }
}

/// Run the corpus tests with global indices in `[skip, skip + take)`.
async fn run_slice_impl(skip: u32, take: u32) -> Vec<TestResult> {
    let corpus = Corpus::load();
    let skip = (skip as usize).min(corpus.len());
    let end = skip.saturating_add(take as usize).min(corpus.len());
    let mut results = Vec::with_capacity(end - skip);
    for index in skip..end {
        results.push(corpus.test(index).unwrap().run().await);
    }
    results
}

fn to_result(id: String, outcome: Result<(), String>) -> TestResult {
    match outcome {
        Ok(()) => TestResult {
            id,
            passed: true,
            detail: String::new(),
        },
        Err(detail) => TestResult {
            id,
            passed: false,
            detail,
        },
    }
}

export!(Component);
