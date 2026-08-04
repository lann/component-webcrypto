//! `conformance-signing-guest-ct`: the host-only signing conformance
//! suite ported onto the `lann:component-test` guest SDK, exactly as
//! `conformance-guest-ct` ports `conformance-guest`.
//!
//! The corpus is the incumbent's (`conformance-signing-guest`), copied
//! into `probes.rs` (its crate root cannot be `#[path]`-included — see
//! that module's header). What is new is the registration layer: one
//! literal `#[case]` fn per incumbent `probes!` row, named by the same
//! ident-derivation the incumbent used (`probe/<ident with _ -> ->`).
//! The incumbent census carries no feature tags, so there are no
//! `!feature` decline cases to add.
//!
//! The static inventory (names + tags) is pinned to the incumbent census
//! (`conformance/signing-guest/tests.lock`) by a native test
//! (`census_test`).

pub mod probes;

#[cfg(test)]
mod census_test;

use component_test_sdk::{Failure, Verdict};

/// Run the incumbent probe named `ident` (its fn identifier in the
/// [`crate::probes`] table), as a `#[case]` body.
pub async fn probe(ident: &str) -> Verdict {
    let index = crate::probes::PROBES
        .iter()
        .position(|p| p.ident == ident)
        .unwrap_or_else(|| panic!("no probe named {ident}"));
    conformance_harness::run_probe(crate::probes::PROBES, index)
        .await
        .map_err(Failure::Failed)
}

// The suite proper. cfg-gated to wasm32: the SDK glue exports the
// component contract, which only exists for the component target; the
// native build carries the probe table for the census-parity test.
#[cfg(target_arch = "wasm32")]
#[component_test_sdk::suite(name = "")]
mod signing {
    /// The hand-written probes: one literal case per incumbent `probes!`
    /// row.
    mod probe {

        #[case]
        async fn ecdsa_p256_sign_roundtrip() -> Verdict {
            crate::probe("ecdsa_p256_sign_roundtrip").await
        }

        #[case]
        async fn ecdsa_p384_generate_roundtrip() -> Verdict {
            crate::probe("ecdsa_p384_generate_roundtrip").await
        }

        #[case]
        async fn ecdsa_sign_extractable_getter() -> Verdict {
            crate::probe("ecdsa_sign_extractable_getter").await
        }

        #[case]
        async fn ecdsa_p521_unsupported() -> Verdict {
            crate::probe("ecdsa_p521_unsupported").await
        }

        #[case]
        async fn ecdsa_private_format_imports() -> Verdict {
            crate::probe("ecdsa_private_format_imports").await
        }

        #[case]
        async fn ecdsa_signing_key_exports() -> Verdict {
            crate::probe("ecdsa_signing_key_exports").await
        }

        #[case]
        async fn ecdsa_cross_hash_sign_roundtrip() -> Verdict {
            crate::probe("ecdsa_cross_hash_sign_roundtrip").await
        }

        #[case]
        async fn ecdsa_unwrap_signing_key() -> Verdict {
            crate::probe("ecdsa_unwrap_signing_key").await
        }
    }
}
