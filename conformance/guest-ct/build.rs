//! Under the `preparsed` feature, run the incumbent translate iterators
//! at build time and serialize each corpus with postcard into OUT_DIR;
//! plan.rs then decodes the blobs instead of re-parsing the vector JSON
//! at registry-build time. Under `rkyv-corpus`, split each corpus into
//! per-generator-row `RowCorpus` archives (names pre-split into
//! canonical prefix/leaf blobs, feature index precomputed and asserted
//! row-uniform — see `src/corpus.rs` for the layout) so the registry
//! build does no corpus deserialization, filtering, or per-case string
//! work at all. Measurement experiments: the corpus is value-identical
//! either way (same code produces it, just earlier).

// The same module the crate compiles (src/translate.rs). translate.rs
// only reaches into the rest of the suite for
// `crate::mint::ecdh_secret_jwk`, which is
// a pure string builder; a stub module satisfies it without dragging the
// bindings-heavy mint.rs into the build script.
#[path = "src/translate.rs"]
#[allow(dead_code)]
mod translate;

mod mint {
    /// Build-time copy of `src/mint.rs`'s `ecdh_secret_jwk`, kept in
    /// sync by vector execution: a drift changes the ECDH cases'
    /// payloads and fails them in rkyv-corpus conformance runs (the
    /// census-parity test compares ids and tags only and cannot see
    /// payloads).
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

use translate::VectorCase;

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
    println!("cargo::rerun-if-changed=src/translate.rs");
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
        T: serde::Serialize + VectorCase,
        corpus::RowCorpus<T>: for<'a> rkyv::Serialize<RkyvSerializer<'a>>,
    {
        match mode {
            Mode::Postcard => {
                let bytes = postcard::to_allocvec(&cases)
                    .unwrap_or_else(|err| panic!("postcard-encoding {name}: {err}"));
                let file = format!("{name}.bin");
                std::fs::write(out.join(&file), bytes)
                    .unwrap_or_else(|err| panic!("writing {file}: {err}"));
            }
            Mode::Rkyv => write_rows(out, cases),
        }
    }
    write(&out, mode, "hkdf", translate::hkdf_cases());
    write(&out, mode, "pbkdf2", translate::pbkdf2_cases());
    write(&out, mode, "hmac", translate::hmac_cases());
    write(&out, mode, "aead", translate::aead_cases());
    write(&out, mode, "cbc", translate::cbc_cases());
    write(&out, mode, "kw", translate::kw_cases());
    write(&out, mode, "sha2", translate::sha2_cases());
    write(&out, mode, "sig", translate::sig_cases());
    write(&out, mode, "speccheck", translate::speccheck_cases());
    write(&out, mode, "rsa", translate::rsa_cases());
    write(&out, mode, "x25519", translate::x25519_cases());
    write(
        &out,
        mode,
        "x25519-encoded",
        translate::x25519_encoded_cases(),
    );
    write(&out, mode, "ecdh", translate::ecdh_cases());
}

/// Split one translate corpus into per-generator-row `RowCorpus`
/// archives: the row is a case id's first two segments (exactly the
/// census's two-segment groups / the `#[case_row]` prefixes), the file
/// `<row with / -> _>.rkyv`. Names are validated and split into the
/// canonical (prefix, leaf) form here, natively; corpus order is
/// preserved within each row.
fn write_rows<T>(out: &std::path::Path, cases: Vec<T>)
where
    T: VectorCase,
    corpus::RowCorpus<T>: for<'a> rkyv::Serialize<RkyvSerializer<'a>>,
{
    // Insertion-ordered row map (a handful of rows per corpus).
    let mut rows: Vec<(String, corpus::RowCorpus<T>)> = Vec::new();
    for case in cases {
        let id = case.case_id();
        let feature = corpus::feature_index(case.features());
        let (prefix, leaf) = id
            .rsplit_once('/')
            .unwrap_or_else(|| panic!("vector case id `{id}` has a single segment"));
        assert!(
            !leaf.is_empty() && prefix.split('/').all(is_label),
            "case id `{id}` violates the case-name grammar (prefix labels / leaf)"
        );
        let row_key = {
            let mut segs = id.splitn(3, '/');
            let (a, b) = (segs.next().unwrap(), segs.next().unwrap_or_default());
            assert!(
                !b.is_empty(),
                "case id `{id}` has no row (two-segment) prefix"
            );
            format!("{a}/{b}")
        };
        let row = match rows.iter_mut().find(|(key, _)| *key == row_key) {
            Some((_, row)) => {
                assert_eq!(
                    row.features, feature,
                    "row `{row_key}` mixes feature sets (case `{id}`)"
                );
                row
            }
            None => {
                rows.push((
                    row_key,
                    corpus::RowCorpus {
                        prefixes_blob: String::new(),
                        prefix_ranges: Vec::new(),
                        leaves_blob: String::new(),
                        leaf_ranges: Vec::new(),
                        cases: Vec::new(),
                        features: feature,
                    },
                ));
                &mut rows.last_mut().unwrap().1
            }
        };
        let ps = row.prefixes_blob.len() as u32;
        row.prefixes_blob.push_str(prefix);
        row.prefix_ranges.push((ps, row.prefixes_blob.len() as u32));
        let ls = row.leaves_blob.len() as u32;
        row.leaves_blob.push_str(leaf);
        row.leaf_ranges.push((ls, row.leaves_blob.len() as u32));
        row.cases.push(case);
    }
    for (row_key, row) in rows {
        let file = format!("{}.rkyv", row_key.replace('/', "_"));
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&row)
            .unwrap_or_else(|err| panic!("rkyv-archiving {row_key}: {err}"));
        std::fs::write(out.join(&file), &*bytes)
            .unwrap_or_else(|err| panic!("writing {file}: {err}"));
    }
}

/// A WIT label (kebab-case; first word `[a-z][a-z0-9]*`, later words may
/// also be number-only, per the amended component-model grammar) — the
/// constraint on non-leaf case-name segments, checked natively so the
/// guest's `CaseName::from_parts` never trips at registry build.
fn is_label(seg: &str) -> bool {
    !seg.is_empty()
        && seg
            .split('-')
            .enumerate()
            .all(|(i, word)| match word.chars().next() {
                Some(c) if c.is_ascii_lowercase() => word
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
                Some(c) if c.is_ascii_digit() && i > 0 => word.chars().all(|c| c.is_ascii_digit()),
                _ => false,
            })
}
