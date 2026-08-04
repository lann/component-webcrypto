//! The archived-corpus containers the `rkyv-corpus` measurement feature
//! embeds, written by build.rs and accessed zero-copy by `plan`. Shared
//! between the build script (which `#[path]`-includes this file) and the
//! crate, so the serialized and accessed types cannot drift.

/// One generator row's corpus, with everything registration needs
/// precomputed natively by build.rs:
///
/// - Names come pre-split per the `CaseName` canonical rule (prefix =
///   everything before the last slash, leaf = final segment) and
///   pre-concatenated: `prefixes_blob`/`leaves_blob` are the row's case
///   prefixes/leaves back to back, `prefix_ranges`/`leaf_ranges` the
///   per-case `(start, end)` byte ranges into them. At registry build
///   the guest turns each blob into one shared `ArcStr` and every
///   case's `CaseName` is two refcounted substrings — no per-case
///   string allocation, no runtime prefix filtering or stripping.
/// - `cases[i]` is the archived case body input, deserialized only when
///   the case runs.
/// - `features` is the row's uniform feature set as an index into
///   [`FEATURE_SETS`] (rows are uniformly tagged — asserted by build.rs
///   here and by the census-parity test natively).
///
/// One blob per row (44 census rows → 31 vector-row blobs; contract
/// rows are table-driven, not corpus-backed) means shared corpora
/// (aead, hmac, ...) are split natively at build time instead of being
/// rebuilt and filtered once per row at registry build.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct RowCorpus<T> {
    pub prefixes_blob: String,
    pub prefix_ranges: Vec<(u32, u32)>,
    pub leaves_blob: String,
    pub leaf_ranges: Vec<(u32, u32)>,
    pub cases: Vec<T>,
    pub features: u8,
}

/// Every feature set a translated vector case can carry, indexed by
/// [`RowCorpus::features`] (build.rs panics on an unlisted set, so
/// growth is loud).
pub const FEATURE_SETS: &[&[&str]] = &[
    &[],
    &[conformance_harness::FEATURE_CHACHA],
    &[conformance_harness::FEATURE_XCHACHA],
];

/// The [`FEATURE_SETS`] index of a case's feature slice.
pub fn feature_index(features: &[&str]) -> u8 {
    FEATURE_SETS
        .iter()
        .position(|set| *set == features)
        .unwrap_or_else(|| panic!("feature set {features:?} is not in FEATURE_SETS")) as u8
}
