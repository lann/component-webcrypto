//! Under the `preparsed` feature, run the incumbent translate iterators
//! at build time and serialize each corpus with postcard into OUT_DIR;
//! plan.rs then decodes the blobs instead of re-parsing the vector JSON
//! at registry-build time. A measurement experiment: the corpus is
//! byte-identical either way (same code produces it, just earlier).

// The same #[path] inclusion lib.rs uses. translate.rs only reaches into
// the rest of the incumbent for `crate::mint::ecdh_secret_jwk`, which is
// a pure string builder; a stub module satisfies it without dragging the
// bindings-heavy mint.rs into the build script.
#[path = "../guest/src/translate.rs"]
#[allow(dead_code)]
mod translate;

mod mint {
    /// Build-time copy of `conformance-guest`'s `mint::ecdh_secret_jwk`
    /// (kept in sync by the census-parity test: a drift changes case
    /// payloads and fails vectors).
    pub fn ecdh_secret_jwk(crv: &str, x: &[u8], y: &[u8], d: &[u8]) -> String {
        format!(
            r#"{{"kty":"EC","crv":"{crv}","x":"{}","y":"{}","d":"{}"}}"#,
            conformance_harness::b64url(x),
            conformance_harness::b64url(y),
            conformance_harness::b64url(d),
        )
    }
}

fn main() {
    println!("cargo::rerun-if-changed=../guest/src/translate.rs");
    println!("cargo::rerun-if-changed=../vectors");
    if std::env::var_os("CARGO_FEATURE_PREPARSED").is_none() {
        return;
    }
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    fn write(out: &std::path::Path, name: &str, cases: &[impl serde::Serialize]) {
        let bytes = postcard::to_allocvec(cases)
            .unwrap_or_else(|err| panic!("postcard-encoding {name}: {err}"));
        std::fs::write(out.join(format!("{name}.bin")), bytes)
            .unwrap_or_else(|err| panic!("writing {name}.bin: {err}"));
    }
    write(&out, "hkdf", &translate::hkdf_cases());
    write(&out, "pbkdf2", &translate::pbkdf2_cases());
    write(&out, "hmac", &translate::hmac_cases());
    write(&out, "aead", &translate::aead_cases());
    write(&out, "cbc", &translate::cbc_cases());
    write(&out, "kw", &translate::kw_cases());
    write(&out, "internal_nonce", &translate::internal_nonce_cases());
    write(&out, "sha2", &translate::sha2_cases());
    write(&out, "sig", &translate::sig_cases());
    write(&out, "speccheck", &translate::speccheck_cases());
    write(&out, "x25519", &translate::x25519_cases());
    write(&out, "ecdh", &translate::ecdh_cases());
}
