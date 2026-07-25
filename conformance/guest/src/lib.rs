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
//! The corpus is indexable (`count` + `run-slice`) so a harness can split one
//! run across several fresh component instances; `run-all` is
//! `run-slice(0, count())`.

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

struct Component;

impl Guest for Component {
    fn count() -> u32 {
        (translate::hmac_cases().len() + translate::gcm_cases().len() + probes::NAMES.len()) as u32
    }

    async fn run_all() -> Vec<TestResult> {
        run_slice_impl(0, u32::MAX).await
    }

    async fn run_slice(skip: u32, take: u32) -> Vec<TestResult> {
        run_slice_impl(skip, take).await
    }
}

/// Run the corpus tests with global indices in `[skip, skip + take)`.
async fn run_slice_impl(skip: u32, take: u32) -> Vec<TestResult> {
    let skip = skip as usize;
    let end = skip.saturating_add(take as usize);
    let hmac_cases = translate::hmac_cases();
    let gcm_cases = translate::gcm_cases();

    let mut results = Vec::new();
    let mut index = 0usize;
    let selected = |index: usize| index >= skip && index < end;

    for case in &hmac_cases {
        if selected(index) {
            let id = format!(
                "hmac-sha256/wycheproof/tc{}/{}",
                case.tc_id,
                case.schedule.name()
            );
            results.push(to_result(id, vectors::run_hmac_case(case).await));
        }
        index += 1;
    }

    for case in &gcm_cases {
        if selected(index) {
            let id = format!(
                "aes-gcm/wycheproof/tc{}/{}",
                case.tc_id,
                case.schedule.name()
            );
            results.push(to_result(id, vectors::run_gcm_case(case).await));
        }
        index += 1;
    }

    for (probe, name) in probes::NAMES.iter().enumerate() {
        if selected(index) {
            results.push(to_result(
                format!("probe/{name}"),
                probes::run_one(probe).await,
            ));
        }
        index += 1;
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
