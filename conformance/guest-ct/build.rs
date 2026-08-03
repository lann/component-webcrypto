//! Under the `preparsed` feature, run the incumbent translate iterators
//! at build time and serialize each corpus with postcard into OUT_DIR;
//! plan.rs then decodes the blobs instead of re-parsing the vector JSON
//! at registry-build time. Under `rkyv-corpus`, archive each corpus with
//! rkyv instead — ids and feature indices precomputed natively — so the
//! registry build does no corpus deserialization at all. Measurement
//! experiments: the corpus is byte-identical either way (same code
//! produces it, just earlier).

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

// The archived-corpus container, shared with the crate (`src/corpus.rs`)
// so the serialized and accessed types cannot drift.
#[path = "src/corpus.rs"]
#[allow(dead_code)]
mod corpus;

/// Which measurement encoding this build produces (from the feature
/// flags; `None` in the default JSON-at-runtime mode).
#[derive(Clone, Copy)]
enum Mode {
    Postcard,
    Rkyv,
}

/// rkyv's high-level serializer, spelled out for the `write` bound.
type RkyvSerializer<'a> = rkyv::api::high::HighSerializer<
    rkyv::util::AlignedVec,
    rkyv::ser::allocator::ArenaHandle<'a>,
    rkyv::rancor::Error,
>;

fn main() {
    println!("cargo::rerun-if-changed=../guest/src/translate.rs");
    println!("cargo::rerun-if-changed=../vectors");
    let mode = if std::env::var_os("CARGO_FEATURE_PREPARSED").is_some() {
        Mode::Postcard
    } else if std::env::var_os("CARGO_FEATURE_RKYV_CORPUS").is_some() {
        Mode::Rkyv
    } else {
        return;
    };
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    fn write<T>(out: &std::path::Path, mode: Mode, name: &str, cases: Vec<T>)
    where
        T: serde::Serialize + translate::VectorCase,
        corpus::Corpus<T>: for<'a> rkyv::Serialize<RkyvSerializer<'a>>,
    {
        let (bytes, file) = match mode {
            Mode::Postcard => (
                postcard::to_allocvec(&cases)
                    .unwrap_or_else(|err| panic!("postcard-encoding {name}: {err}")),
                format!("{name}.bin"),
            ),
            Mode::Rkyv => {
                let corpus = corpus::Corpus {
                    ids: cases.iter().map(|c| c.case_id()).collect(),
                    features: cases.iter().map(|c| corpus::feature_index(c.features())).collect(),
                    cases,
                };
                (
                    rkyv::to_bytes::<rkyv::rancor::Error>(&corpus)
                        .unwrap_or_else(|err| panic!("rkyv-archiving {name}: {err}"))
                        .to_vec(),
                    format!("{name}.rkyv"),
                )
            }
        };
        std::fs::write(out.join(&file), bytes)
            .unwrap_or_else(|err| panic!("writing {file}: {err}"));
    }
    write(&out, mode, "hkdf", translate::hkdf_cases());
    write(&out, mode, "pbkdf2", translate::pbkdf2_cases());
    write(&out, mode, "hmac", translate::hmac_cases());
    write(&out, mode, "aead", translate::aead_cases());
    write(&out, mode, "cbc", translate::cbc_cases());
    write(&out, mode, "kw", translate::kw_cases());
    write(&out, mode, "internal_nonce", translate::internal_nonce_cases());
    write(&out, mode, "sha2", translate::sha2_cases());
    write(&out, mode, "sig", translate::sig_cases());
    write(&out, mode, "speccheck", translate::speccheck_cases());
    write(&out, mode, "x25519", translate::x25519_cases());
    write(&out, mode, "ecdh", translate::ecdh_cases());
}
