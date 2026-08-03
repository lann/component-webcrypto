//! The archived-corpus container the `rkyv-corpus` measurement feature
//! embeds: one blob per vector corpus, written by build.rs and accessed
//! zero-copy by `plan::corpus`. Shared between the build script (which
//! `#[path]`-includes this file) and the crate, so the serialized and
//! accessed types cannot drift.

/// One corpus, with everything the registry build needs precomputed
/// natively: the full case ids (the runtime never re-derives them via
/// `VectorCase::case_id`) and each case's feature set as an index into
/// [`FEATURE_SETS`] (feature slices aren't archivable as `&'static`s).
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Corpus<T> {
    pub ids: Vec<String>,
    pub features: Vec<u8>,
    pub cases: Vec<T>,
}

/// Every feature set a translated vector case can carry, indexed by
/// `Corpus::features` (build.rs panics on an unlisted set, so growth is
/// loud).
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
        .unwrap_or_else(|| panic!("feature set {features:?} is not in FEATURE_SETS"))
        as u8
}
