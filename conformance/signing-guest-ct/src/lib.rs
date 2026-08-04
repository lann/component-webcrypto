//! `conformance-signing-guest-ct`: the host-only signing conformance
//! suite ported onto the `lann:component-test` guest SDK, exactly as
//! `conformance-guest-ct` ports `conformance-guest`.
//!
//! The corpus is the incumbent's (`conformance-signing-guest`), inherited
//! at the M1.6 cutover: the probe table (`probes.rs`), the
//! RSASSA-PKCS1-v1_5 sig-gen vector cases (`rsa_sign.rs`), and the
//! RSA-OAEP decryption vector cases (`rsa_oaep.rs`). What is new is the
//! registration layer: `#[case_row]` rows for the RSA vector suites (one
//! per census two-segment prefix, tags at the row, registration delegated
//! to `plan::register`), literal `#[case]` fns for the probes (named by
//! the same ident-derivation the incumbent used: `probe/<ident with _ ->
//! ->`), and — replacing the incumbent's in-case `provided`/`run_declined`
//! branch — explicit `!feature` decline cases for the two gated features
//! this suite tags (`rsa-sign`, `rsa-oaep-decrypt`). Cases never inspect
//! feature state: scheduling against a target's capability manifest is
//! the runner's job.
//!
//! The static inventory (names + tags) is pinned to the incumbent census
//! (`src/census-fixture.lock`) by a native test (`census_test`).

pub mod plan;
pub mod probes;
pub mod rsa_oaep;
pub mod rsa_sign;

#[cfg(test)]
mod census_test;

// The suite proper. cfg-gated to wasm32: the SDK glue exports the
// component contract, which only exists for the component target; the
// native build carries the plan/probe table for the census-parity test.
#[cfg(target_arch = "wasm32")]
#[component_test_sdk::suite(name = "")]
mod signing {
    use component_test_sdk::{ArcStr, Registry, Tags};

    #[case_row(
        prefix = "rsassa-pkcs1-v15-sha256-b2048/wycheproof-sig-gen",
        tags("rsa-sign")
    )]
    fn row_rsassa_pkcs1_v15_sha256_b2048_wycheproof_sig_gen(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(
        prefix = "rsassa-pkcs1-v15-sha384-b2048/wycheproof-sig-gen",
        tags("rsa-sign")
    )]
    fn row_rsassa_pkcs1_v15_sha384_b2048_wycheproof_sig_gen(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(
        prefix = "rsassa-pkcs1-v15-sha512-b2048/wycheproof-sig-gen",
        tags("rsa-sign")
    )]
    fn row_rsassa_pkcs1_v15_sha512_b2048_wycheproof_sig_gen(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(
        prefix = "rsassa-pkcs1-v15-sha256-b3072/wycheproof-sig-gen",
        tags("rsa-sign")
    )]
    fn row_rsassa_pkcs1_v15_sha256_b3072_wycheproof_sig_gen(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(
        prefix = "rsassa-pkcs1-v15-sha384-b3072/wycheproof-sig-gen",
        tags("rsa-sign")
    )]
    fn row_rsassa_pkcs1_v15_sha384_b3072_wycheproof_sig_gen(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(
        prefix = "rsassa-pkcs1-v15-sha512-b3072/wycheproof-sig-gen",
        tags("rsa-sign")
    )]
    fn row_rsassa_pkcs1_v15_sha512_b3072_wycheproof_sig_gen(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(
        prefix = "rsassa-pkcs1-v15-sha256-b4096/wycheproof-sig-gen",
        tags("rsa-sign")
    )]
    fn row_rsassa_pkcs1_v15_sha256_b4096_wycheproof_sig_gen(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(
        prefix = "rsassa-pkcs1-v15-sha384-b4096/wycheproof-sig-gen",
        tags("rsa-sign")
    )]
    fn row_rsassa_pkcs1_v15_sha384_b4096_wycheproof_sig_gen(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(
        prefix = "rsassa-pkcs1-v15-sha512-b4096/wycheproof-sig-gen",
        tags("rsa-sign")
    )]
    fn row_rsassa_pkcs1_v15_sha512_b4096_wycheproof_sig_gen(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "rsa-oaep-sha256-b2048/wycheproof", tags("rsa-oaep-decrypt"))]
    fn row_rsa_oaep_sha256_b2048_wycheproof(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "rsa-oaep-sha384-b2048/wycheproof", tags("rsa-oaep-decrypt"))]
    fn row_rsa_oaep_sha384_b2048_wycheproof(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "rsa-oaep-sha512-b2048/wycheproof", tags("rsa-oaep-decrypt"))]
    fn row_rsa_oaep_sha512_b2048_wycheproof(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "rsa-oaep-sha256-b3072/wycheproof", tags("rsa-oaep-decrypt"))]
    fn row_rsa_oaep_sha256_b3072_wycheproof(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "rsa-oaep-sha512-b3072/wycheproof", tags("rsa-oaep-decrypt"))]
    fn row_rsa_oaep_sha512_b3072_wycheproof(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "rsa-oaep-sha256-b4096/wycheproof", tags("rsa-oaep-decrypt"))]
    fn row_rsa_oaep_sha256_b4096_wycheproof(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "rsa-oaep-sha512-b4096/wycheproof", tags("rsa-oaep-decrypt"))]
    fn row_rsa_oaep_sha512_b4096_wycheproof(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(
        prefix = "rsa-oaep-sha256-b2048/wycheproof-misc",
        tags("rsa-oaep-decrypt")
    )]
    fn row_rsa_oaep_sha256_b2048_wycheproof_misc(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(
        prefix = "rsa-oaep-sha384-b2048/wycheproof-misc",
        tags("rsa-oaep-decrypt")
    )]
    fn row_rsa_oaep_sha384_b2048_wycheproof_misc(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(
        prefix = "rsa-oaep-sha512-b2048/wycheproof-misc",
        tags("rsa-oaep-decrypt")
    )]
    fn row_rsa_oaep_sha512_b2048_wycheproof_misc(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(
        prefix = "rsa-oaep-sha256-b3072/wycheproof-misc",
        tags("rsa-oaep-decrypt")
    )]
    fn row_rsa_oaep_sha256_b3072_wycheproof_misc(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(
        prefix = "rsa-oaep-sha384-b3072/wycheproof-misc",
        tags("rsa-oaep-decrypt")
    )]
    fn row_rsa_oaep_sha384_b3072_wycheproof_misc(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(
        prefix = "rsa-oaep-sha512-b3072/wycheproof-misc",
        tags("rsa-oaep-decrypt")
    )]
    fn row_rsa_oaep_sha512_b3072_wycheproof_misc(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(
        prefix = "rsa-oaep-sha256-b4096/wycheproof-misc",
        tags("rsa-oaep-decrypt")
    )]
    fn row_rsa_oaep_sha256_b4096_wycheproof_misc(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(
        prefix = "rsa-oaep-sha384-b4096/wycheproof-misc",
        tags("rsa-oaep-decrypt")
    )]
    fn row_rsa_oaep_sha384_b4096_wycheproof_misc(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(
        prefix = "rsa-oaep-sha512-b4096/wycheproof-misc",
        tags("rsa-oaep-decrypt")
    )]
    fn row_rsa_oaep_sha512_b4096_wycheproof_misc(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(
        prefix = "rsa-oaep-sha256-b8192/wycheproof-misc",
        tags("rsa-oaep-decrypt")
    )]
    fn row_rsa_oaep_sha256_b8192_wycheproof_misc(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(
        prefix = "rsa-oaep-sha384-b8192/wycheproof-misc",
        tags("rsa-oaep-decrypt")
    )]
    fn row_rsa_oaep_sha384_b8192_wycheproof_misc(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(
        prefix = "rsa-oaep-sha512-b8192/wycheproof-misc",
        tags("rsa-oaep-decrypt")
    )]
    fn row_rsa_oaep_sha512_b8192_wycheproof_misc(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(
        prefix = "rsa-oaep-sha256-b2688/wycheproof-misc",
        tags("rsa-oaep-decrypt")
    )]
    fn row_rsa_oaep_sha256_b2688_wycheproof_misc(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(
        prefix = "rsa-oaep-sha256-b4032/wycheproof-misc",
        tags("rsa-oaep-decrypt")
    )]
    fn row_rsa_oaep_sha256_b4032_wycheproof_misc(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(
        prefix = "rsa-oaep-sha384-b3104/wycheproof-misc",
        tags("rsa-oaep-decrypt")
    )]
    fn row_rsa_oaep_sha384_b3104_wycheproof_misc(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    /// The hand-written probes: one literal case per incumbent `probes!`
    /// row.
    mod probe {

        #[case]
        async fn ecdsa_p256_sign_roundtrip() -> Verdict {
            crate::plan::probe("ecdsa_p256_sign_roundtrip").await
        }

        #[case]
        async fn ecdsa_p384_generate_roundtrip() -> Verdict {
            crate::plan::probe("ecdsa_p384_generate_roundtrip").await
        }

        #[case]
        async fn ecdsa_sign_extractable_getter() -> Verdict {
            crate::plan::probe("ecdsa_sign_extractable_getter").await
        }

        #[case]
        async fn ecdsa_p521_unsupported() -> Verdict {
            crate::plan::probe("ecdsa_p521_unsupported").await
        }

        #[case]
        async fn ecdsa_private_format_imports() -> Verdict {
            crate::plan::probe("ecdsa_private_format_imports").await
        }

        #[case]
        async fn ecdsa_signing_key_exports() -> Verdict {
            crate::plan::probe("ecdsa_signing_key_exports").await
        }

        #[case]
        async fn ecdsa_cross_hash_sign_roundtrip() -> Verdict {
            crate::plan::probe("ecdsa_cross_hash_sign_roundtrip").await
        }

        #[case]
        async fn ecdsa_unwrap_signing_key() -> Verdict {
            crate::plan::probe("ecdsa_unwrap_signing_key").await
        }

        #[case(tags("rsa-sign"))]
        async fn rsa_sign_key_contract() -> Verdict {
            crate::plan::probe("rsa_sign_key_contract").await
        }

        #[case(tags("rsa-sign"))]
        async fn rsa_pss_sign_round_trip() -> Verdict {
            crate::plan::probe("rsa_pss_sign_round_trip").await
        }

        #[case(tags("rsa-sign"))]
        async fn rsa_sign_admission() -> Verdict {
            crate::plan::probe("rsa_sign_admission").await
        }

        #[case(tags("rsa-sign"))]
        async fn rsa_sign_declined() -> Verdict {
            crate::plan::probe("rsa_sign_declined").await
        }

        #[case]
        async fn rsa_oaep_encrypt_contract() -> Verdict {
            crate::plan::probe("rsa_oaep_encrypt_contract").await
        }

        #[case(tags("rsa-oaep-decrypt"))]
        async fn rsa_oaep_round_trip() -> Verdict {
            crate::plan::probe("rsa_oaep_round_trip").await
        }

        #[case(tags("rsa-oaep-decrypt"))]
        async fn rsa_oaep_admission() -> Verdict {
            crate::plan::probe("rsa_oaep_admission").await
        }

        #[case(tags("rsa-oaep-decrypt"))]
        async fn rsa_oaep_declined() -> Verdict {
            crate::plan::probe("rsa_oaep_declined").await
        }
    }

    /// Decline cases (new in this port; not in the incumbent census):
    /// the incumbent asserted declines inside positively-tagged cases
    /// when a feature was missing. Here, positively-tagged cases only
    /// exercise; each gated feature's decline assertion is its own
    /// `!feature` case, scheduled by the runner exactly on targets
    /// missing it.
    mod rsa_sign {
        mod decline {
            #[case(tags("!rsa-sign"))]
            async fn minting() -> Verdict {
                crate::plan::declined(crate::plan::features::FEATURE_RSA_SIGN).await
            }
        }
    }

    mod rsa_oaep_decrypt {
        mod decline {
            #[case(tags("!rsa-oaep-decrypt"))]
            async fn minting() -> Verdict {
                crate::plan::declined(crate::plan::features::FEATURE_RSA_OAEP_DECRYPT).await
            }
        }
    }
}
