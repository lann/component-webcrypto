//! `conformance-guest-ct`: the webcrypto conformance suite ported onto
//! the `lann:component-test` guest SDK (M1.5 skeleton).
//!
//! The corpus is the incumbent's (`conformance-guest`), inherited
//! wholesale at the M1.6 cutover: translation, minting, runners,
//! contract batteries, probes — the modules below, moved here
//! unmodified when the incumbent was deleted. What
//! is new is the registration layer: `#[case_row]` rows for the
//! vector and contract suites (one per census two-segment prefix, tags at
//! the row, registration delegated to `plan::register` — under the
//! `rkyv-corpus` feature that is the allocation-free per-row-archive
//! fast path), literal `#[case]` fns for the probes, and — replacing the
//! incumbent's in-case `provided`/`run_declined` branch — explicit
//! `!feature` decline cases. Cases never inspect feature state:
//! scheduling against a target's capability manifest is the runner's job.
//!
//! The static inventory (names + tags) is pinned to the incumbent census
//! by a native test (`census_test`); execution against a SUT is out of
//! scope for this stage.

// The corpus, inherited wholesale from the incumbent `conformance-guest`
// at the M1.6 cutover (these files moved here verbatim; the incumbent is
// deleted). translation, minting, runners, contract batteries, probes.
pub mod contract;
pub mod mint;
pub mod probes;
pub mod translate;
pub mod vectors;

pub mod plan;

#[cfg(feature = "rkyv-corpus")]
pub mod corpus;

#[cfg(all(feature = "preparsed", feature = "rkyv-corpus"))]
compile_error!("`preparsed` and `rkyv-corpus` are mutually exclusive corpus modes");

#[cfg(test)]
mod census_test;

// The suite proper. cfg-gated to wasm32: the SDK glue exports the
// component contract, which only exists for the component target; the
// native build carries the plan/corpus for the census-parity test.
#[cfg(target_arch = "wasm32")]
#[component_test_sdk::suite(name = "")]
mod webcrypto {
    use component_test_sdk::{ArcStr, Registry, Tags};

    #[case_row(prefix = "hkdf-sha1/wycheproof")]
    fn row_hkdf_sha1_wycheproof(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "hkdf-sha256/wycheproof")]
    fn row_hkdf_sha256_wycheproof(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "hkdf-sha384/wycheproof")]
    fn row_hkdf_sha384_wycheproof(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "hkdf-sha512/wycheproof")]
    fn row_hkdf_sha512_wycheproof(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "pbkdf2-sha1/wycheproof")]
    fn row_pbkdf2_sha1_wycheproof(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "pbkdf2-sha256/wycheproof")]
    fn row_pbkdf2_sha256_wycheproof(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "pbkdf2-sha384/wycheproof")]
    fn row_pbkdf2_sha384_wycheproof(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "pbkdf2-sha512/wycheproof")]
    fn row_pbkdf2_sha512_wycheproof(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "hmac-sha1/wycheproof")]
    fn row_hmac_sha1_wycheproof(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "hmac-sha256/wycheproof")]
    fn row_hmac_sha256_wycheproof(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "hmac-sha384/wycheproof")]
    fn row_hmac_sha384_wycheproof(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "hmac-sha512/wycheproof")]
    fn row_hmac_sha512_wycheproof(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "aes-gcm/wycheproof")]
    fn row_aes_gcm_wycheproof(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "chacha20-poly1305/wycheproof", tags("chacha20-poly1305"))]
    fn row_chacha20_poly1305_wycheproof(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "xchacha20-poly1305/wycheproof", tags("xchacha20-poly1305"))]
    fn row_xchacha20_poly1305_wycheproof(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "aes-cbc/wycheproof")]
    fn row_aes_cbc_wycheproof(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "aes-kw/wycheproof")]
    fn row_aes_kw_wycheproof(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "aes-gcm-internal-nonce/wycheproof")]
    fn row_aes_gcm_internal_nonce_wycheproof(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(
        prefix = "xchacha20-poly1305-internal-nonce/wycheproof",
        tags("xchacha20-poly1305")
    )]
    fn row_xchacha20_poly1305_internal_nonce_wycheproof(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "sha2/nist-cavp")]
    fn row_sha2_nist_cavp(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "ed25519/wycheproof")]
    fn row_ed25519_wycheproof(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "ed25519/speccheck")]
    fn row_ed25519_speccheck(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "ecdsa-p256-sha256/wycheproof")]
    fn row_ecdsa_p256_sha256_wycheproof(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "ecdsa-p384-sha384/wycheproof")]
    fn row_ecdsa_p384_sha384_wycheproof(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "rsassa-pkcs1-v15-sha256-b2048/wycheproof")]
    fn row_rsassa_pkcs1_v15_sha256_b2048_wycheproof(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "rsassa-pkcs1-v15-sha384-b2048/wycheproof")]
    fn row_rsassa_pkcs1_v15_sha384_b2048_wycheproof(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "rsassa-pkcs1-v15-sha512-b2048/wycheproof")]
    fn row_rsassa_pkcs1_v15_sha512_b2048_wycheproof(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "rsassa-pkcs1-v15-sha256-b3072/wycheproof")]
    fn row_rsassa_pkcs1_v15_sha256_b3072_wycheproof(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "rsassa-pkcs1-v15-sha384-b3072/wycheproof")]
    fn row_rsassa_pkcs1_v15_sha384_b3072_wycheproof(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "rsassa-pkcs1-v15-sha512-b3072/wycheproof")]
    fn row_rsassa_pkcs1_v15_sha512_b3072_wycheproof(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "rsassa-pkcs1-v15-sha256-b4096/wycheproof")]
    fn row_rsassa_pkcs1_v15_sha256_b4096_wycheproof(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "rsassa-pkcs1-v15-sha384-b4096/wycheproof")]
    fn row_rsassa_pkcs1_v15_sha384_b4096_wycheproof(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "rsassa-pkcs1-v15-sha512-b4096/wycheproof")]
    fn row_rsassa_pkcs1_v15_sha512_b4096_wycheproof(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "rsassa-pkcs1-v15-sha256-b8192/wycheproof")]
    fn row_rsassa_pkcs1_v15_sha256_b8192_wycheproof(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "rsa-pss-sha256-b2048-salt0/wycheproof")]
    fn row_rsa_pss_sha256_b2048_salt0_wycheproof(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "rsa-pss-sha256-b2048-salt32/wycheproof")]
    fn row_rsa_pss_sha256_b2048_salt32_wycheproof(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "rsa-pss-sha384-b2048-salt48/wycheproof")]
    fn row_rsa_pss_sha384_b2048_salt48_wycheproof(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "rsa-pss-sha256-b3072-salt32/wycheproof")]
    fn row_rsa_pss_sha256_b3072_salt32_wycheproof(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "rsa-pss-sha256-b4096-salt32/wycheproof")]
    fn row_rsa_pss_sha256_b4096_salt32_wycheproof(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "rsa-pss-sha384-b4096-salt48/wycheproof")]
    fn row_rsa_pss_sha384_b4096_salt48_wycheproof(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "rsa-pss-sha512-b4096-salt32/wycheproof")]
    fn row_rsa_pss_sha512_b4096_salt32_wycheproof(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "rsa-pss-sha512-b4096-salt64/wycheproof")]
    fn row_rsa_pss_sha512_b4096_salt64_wycheproof(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "rsa-pss-sha256-b2048-salt32/wycheproof-params")]
    fn row_rsa_pss_sha256_b2048_salt32_wycheproof_params(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "x25519/wycheproof")]
    fn row_x25519_wycheproof(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "ecdh-p256/wycheproof-spki")]
    fn row_ecdh_p256_wycheproof_spki(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "ecdh-p256/wycheproof-ecpoint")]
    fn row_ecdh_p256_wycheproof_ecpoint(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "ecdh-p256/wycheproof-webcrypto")]
    fn row_ecdh_p256_wycheproof_webcrypto(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "ecdh-p384/wycheproof-spki")]
    fn row_ecdh_p384_wycheproof_spki(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "ecdh-p384/wycheproof-ecpoint")]
    fn row_ecdh_p384_wycheproof_ecpoint(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "ecdh-p384/wycheproof-webcrypto")]
    fn row_ecdh_p384_wycheproof_webcrypto(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "aes-gcm/contract")]
    fn row_aes_gcm_contract(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "chacha20-poly1305/contract", tags("chacha20-poly1305"))]
    fn row_chacha20_poly1305_contract(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "xchacha20-poly1305/contract", tags("xchacha20-poly1305"))]
    fn row_xchacha20_poly1305_contract(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "hmac-sha1/contract")]
    fn row_hmac_sha1_contract(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "hmac-sha2/contract")]
    fn row_hmac_sha2_contract(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "aes-cbc/contract")]
    fn row_aes_cbc_contract(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "aes-ctr/contract")]
    fn row_aes_ctr_contract(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "aes-gcm-internal-nonce/contract")]
    fn row_aes_gcm_internal_nonce_contract(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(
        prefix = "xchacha20-poly1305-internal-nonce/contract",
        tags("xchacha20-poly1305")
    )]
    fn row_xchacha20_poly1305_internal_nonce_contract(
        registry: &mut Registry,
        prefix: &ArcStr,
        tags: &Tags,
    ) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "hkdf-sha2/contract")]
    fn row_hkdf_sha2_contract(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "pbkdf2-sha2/contract")]
    fn row_pbkdf2_sha2_contract(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "x25519/contract")]
    fn row_x25519_contract(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    #[case_row(prefix = "ecdh/contract")]
    fn row_ecdh_contract(registry: &mut Registry, prefix: &ArcStr, tags: &Tags) {
        crate::plan::register(registry, prefix, tags)
    }

    /// The hand-written API-contract probes: one literal case per
    /// incumbent `probes!` row, named by the same ident-derivation the
    /// incumbent used (`probe/<ident with _ -> ->`).
    mod probe {

        #[case]
        async fn hmac_import_empty_key() -> Verdict {
            crate::plan::probe("hmac_import_empty_key").await
        }

        #[case]
        async fn hmac_sha384_sha512() -> Verdict {
            crate::plan::probe("hmac_sha384_sha512").await
        }

        #[case]
        async fn sha2_truncated_unsupported() -> Verdict {
            crate::plan::probe("sha2_truncated_unsupported").await
        }

        #[case]
        async fn aes_import_wrong_length() -> Verdict {
            crate::plan::probe("aes_import_wrong_length").await
        }

        #[case]
        async fn aes192_unsupported() -> Verdict {
            crate::plan::probe("aes192_unsupported").await
        }

        #[case]
        async fn seal_input_ends_on_invalid_nonce() -> Verdict {
            crate::plan::probe("seal_input_ends_on_invalid_nonce").await
        }

        #[case]
        async fn open_input_ends_on_invalid_nonce() -> Verdict {
            crate::plan::probe("open_input_ends_on_invalid_nonce").await
        }

        #[case]
        async fn sealed_length() -> Verdict {
            crate::plan::probe("sealed_length").await
        }

        #[case]
        async fn mac_verify_rejects_truncated() -> Verdict {
            crate::plan::probe("mac_verify_rejects_truncated").await
        }

        #[case]
        async fn sign_prefix_drop() -> Verdict {
            crate::plan::probe("sign_prefix_drop").await
        }

        #[case]
        async fn digest_reuse() -> Verdict {
            crate::plan::probe("digest_reuse").await
        }

        #[case]
        async fn constant_time_equal() -> Verdict {
            crate::plan::probe("constant_time_equal").await
        }

        #[case(tags("chacha20-poly1305"))]
        async fn chacha_nonce_lengths() -> Verdict {
            crate::plan::probe("chacha_nonce_lengths").await
        }

        #[case(tags("xchacha20-poly1305"))]
        async fn xchacha_nonce_lengths() -> Verdict {
            crate::plan::probe("xchacha_nonce_lengths").await
        }

        #[case]
        async fn ed25519_sign_roundtrip() -> Verdict {
            crate::plan::probe("ed25519_sign_roundtrip").await
        }

        #[case]
        async fn sig_key_metadata() -> Verdict {
            crate::plan::probe("sig_key_metadata").await
        }

        #[case]
        async fn sig_import_invalid() -> Verdict {
            crate::plan::probe("sig_import_invalid").await
        }

        #[case]
        async fn verifying_key_export_roundtrip() -> Verdict {
            crate::plan::probe("verifying_key_export_roundtrip").await
        }

        #[case]
        async fn internal_nonce_shape() -> Verdict {
            crate::plan::probe("internal_nonce_shape").await
        }

        #[case]
        async fn open_short_input() -> Verdict {
            crate::plan::probe("open_short_input").await
        }

        #[case]
        async fn stream_empty_writes() -> Verdict {
            crate::plan::probe("stream_empty_writes").await
        }

        #[case]
        async fn large_stream() -> Verdict {
            crate::plan::probe("large_stream").await
        }

        #[case]
        async fn hmac_generate_length() -> Verdict {
            crate::plan::probe("hmac_generate_length").await
        }

        #[case]
        async fn gcm_full_parameters() -> Verdict {
            crate::plan::probe("gcm_full_parameters").await
        }

        #[case]
        async fn gcm_nonce_window() -> Verdict {
            crate::plan::probe("gcm_nonce_window").await
        }

        #[case(tags("chacha20-poly1305"))]
        async fn chacha_tag_size_fixed() -> Verdict {
            crate::plan::probe("chacha_tag_size_fixed").await
        }

        #[case]
        async fn jwk_rejections() -> Verdict {
            crate::plan::probe("jwk_rejections").await
        }

        #[case]
        async fn jwk_semantics() -> Verdict {
            crate::plan::probe("jwk_semantics").await
        }

        #[case(tags("xchacha20-poly1305"))]
        async fn xchacha_jwk_unsupported() -> Verdict {
            crate::plan::probe("xchacha_jwk_unsupported").await
        }

        #[case]
        async fn aead_wrap_grants() -> Verdict {
            crate::plan::probe("aead_wrap_grants").await
        }

        #[case]
        async fn aead_wrap_operations() -> Verdict {
            crate::plan::probe("aead_wrap_operations").await
        }

        #[case]
        async fn wrap_input_gates() -> Verdict {
            crate::plan::probe("wrap_input_gates").await
        }

        #[case]
        async fn kw_key_contract() -> Verdict {
            crate::plan::probe("kw_key_contract").await
        }

        #[case]
        async fn kw_jwk_padding() -> Verdict {
            crate::plan::probe("kw_jwk_padding").await
        }

        #[case]
        async fn cipher_wrap_uniform_failure() -> Verdict {
            crate::plan::probe("cipher_wrap_uniform_failure").await
        }

        #[case]
        async fn unwrap_jwk_usage_members() -> Verdict {
            crate::plan::probe("unwrap_jwk_usage_members").await
        }

        #[case]
        async fn kdf_secret_unwrap() -> Verdict {
            crate::plan::probe("kdf_secret_unwrap").await
        }

        #[case]
        async fn signing_key_unwrap() -> Verdict {
            crate::plan::probe("signing_key_unwrap").await
        }

        #[case]
        async fn agreement_key_unwrap() -> Verdict {
            crate::plan::probe("agreement_key_unwrap").await
        }

        #[case]
        async fn cipher_key_unwrap() -> Verdict {
            crate::plan::probe("cipher_key_unwrap").await
        }

        #[case]
        async fn internal_nonce_key_unwrap() -> Verdict {
            crate::plan::probe("internal_nonce_key_unwrap").await
        }

        #[case(tags("chacha20-poly1305"))]
        async fn chacha_key_unwrap() -> Verdict {
            crate::plan::probe("chacha_key_unwrap").await
        }

        #[case(tags("xchacha20-poly1305"))]
        async fn xchacha_key_unwrap() -> Verdict {
            crate::plan::probe("xchacha_key_unwrap").await
        }

        #[case]
        async fn signing_usage_policy() -> Verdict {
            crate::plan::probe("signing_usage_policy").await
        }

        #[case]
        async fn hkdf_derive_key_equivalence() -> Verdict {
            crate::plan::probe("hkdf_derive_key_equivalence").await
        }

        #[case]
        async fn hkdf_params_and_chaining() -> Verdict {
            crate::plan::probe("hkdf_params_and_chaining").await
        }

        #[case]
        async fn pbkdf2_contract() -> Verdict {
            crate::plan::probe("pbkdf2_contract").await
        }

        #[case]
        async fn x25519_key_contract() -> Verdict {
            crate::plan::probe("x25519_key_contract").await
        }

        #[case]
        async fn x25519_agree_contract() -> Verdict {
            crate::plan::probe("x25519_agree_contract").await
        }

        #[case]
        async fn x25519_chaining() -> Verdict {
            crate::plan::probe("x25519_chaining").await
        }

        #[case]
        async fn ecdh_key_contract() -> Verdict {
            crate::plan::probe("ecdh_key_contract").await
        }

        #[case]
        async fn ecdh_agree_contract() -> Verdict {
            crate::plan::probe("ecdh_agree_contract").await
        }

        #[case]
        async fn ecdh_chaining() -> Verdict {
            crate::plan::probe("ecdh_chaining").await
        }

        #[case]
        async fn sig_public_format_imports() -> Verdict {
            crate::plan::probe("sig_public_format_imports").await
        }

        #[case]
        async fn ed25519_private_format_imports() -> Verdict {
            crate::plan::probe("ed25519_private_format_imports").await
        }

        #[case]
        async fn ecdsa_cross_hash_variants() -> Verdict {
            crate::plan::probe("ecdsa_cross_hash_variants").await
        }

        #[case]
        async fn rsa_key_contract() -> Verdict {
            crate::plan::probe("rsa_key_contract").await
        }

        #[case]
        async fn rsa_admission_contract() -> Verdict {
            crate::plan::probe("rsa_admission_contract").await
        }

        #[case]
        async fn rsa_pss_salt_binding() -> Verdict {
            crate::plan::probe("rsa_pss_salt_binding").await
        }

        #[case]
        async fn x25519_format_roundtrips() -> Verdict {
            crate::plan::probe("x25519_format_roundtrips").await
        }

        #[case]
        async fn ecdh_format_roundtrips() -> Verdict {
            crate::plan::probe("ecdh_format_roundtrips").await
        }

        #[case]
        async fn internal_nonce_jwk() -> Verdict {
            crate::plan::probe("internal_nonce_jwk").await
        }

        #[case(tags("sha1-checked"))]
        async fn sha1_checked_postures() -> Verdict {
            crate::plan::probe("sha1_checked_postures").await
        }

        #[case]
        async fn ctr_known_answers() -> Verdict {
            crate::plan::probe("ctr_known_answers").await
        }

        #[case]
        async fn cipher_params_contract() -> Verdict {
            crate::plan::probe("cipher_params_contract").await
        }

        #[case]
        async fn cbc_uniform_failure() -> Verdict {
            crate::plan::probe("cbc_uniform_failure").await
        }

        #[case]
        async fn cipher_derive_key() -> Verdict {
            crate::plan::probe("cipher_derive_key").await
        }

        #[case]
        async fn sha1_derive_surface() -> Verdict {
            crate::plan::probe("sha1_derive_surface").await
        }
    }

    /// Decline cases (new in this port; not in the incumbent census):
    /// the incumbent asserted declines inside positively-tagged cases
    /// when a feature was missing. Here, positively-tagged cases only
    /// exercise; each feature's decline assertion is its own `!feature`
    /// case, scheduled by the runner exactly on targets missing it.
    mod chacha20_poly1305 {
        mod decline {
            #[case(tags("!chacha20-poly1305"))]
            async fn minting() -> Verdict {
                crate::plan::declined(crate::plan::features::FEATURE_CHACHA).await
            }
        }
    }

    mod xchacha20_poly1305 {
        mod decline {
            #[case(tags("!xchacha20-poly1305"))]
            async fn minting() -> Verdict {
                crate::plan::declined(crate::plan::features::FEATURE_XCHACHA).await
            }
        }
    }

    mod sha1_checked {
        mod decline {
            #[case(tags("!sha1-checked"))]
            async fn minting() -> Verdict {
                crate::plan::declined(crate::plan::features::FEATURE_SHA1_CHECKED).await
            }
        }
    }
}
