//! The per-kind contract batteries: the standard cases every minting
//! family of a primitive kind must pass, derived from one table row per
//! minted algorithm.
//!
//! The row carries the family's entry points and the facts the WIT binds
//! at mint; the battery instantiates each [`AeadArea`] contract rule
//! against every row. That makes the rule × family matrix structural: a
//! new family is one row here (landing as a reviewable `tests.lock` diff
//! of `<interface>/contract/…` cases), and a new package-wide rule is one
//! area, covering every family at once — the class of gap where a rule is
//! asserted on N−1 of N families cannot recur within battery scope.
//!
//! Only rules that are kind-uniform by WIT contract belong here.
//! Algorithm-specific behavior — nonce windows, tag-size parameters,
//! nonce budgets, wire formats, known answers — stays in the hand-written
//! probes and the vector cases; a rule that would need a per-family
//! branch in an area body belongs there too.

use crate::mint;
use conformance_harness::stream::{open, seal, Schedule};
use conformance_harness::{describe, expect, expect_bytes, expect_err, ErrKind, FEATURE_CHACHA};
use lann_webcrypto_guest::bindings::aead::{AeadKey, AeadKeyOptions};
use lann_webcrypto_guest::bindings::aes_gcm::AesVariant;
use lann_webcrypto_guest::bindings::types::Error;
use lann_webcrypto_guest::bindings::{aes_gcm, chacha20_poly1305, xchacha20_poly1305};

/// A boxed minting future: the families' entry points are distinct
/// functions with identical shapes, so the table stores them behind one
/// signature.
type MintFuture<T> = std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, Error>>>>;

/// One caller-nonce AEAD minting family: its entry points and the facts
/// the WIT binds at mint. Everything a battery case asserts is a field
/// here, so the row doubles as the family's contract summary.
pub struct AeadFamily {
    /// The minting interface's name (the case id's group segment).
    pub interface: &'static str,
    /// The variant within the interface, if it mints more than one
    /// algorithm; distinguishes the case ids.
    pub variant: Option<&'static str>,
    /// The `algorithm-name` getter's value (the registry spelling).
    pub name: &'static str,
    /// The features a target may declare missing for this family.
    pub features: &'static [&'static str],
    /// The raw key length in bytes; `algorithm-length` reports it in bits.
    pub key_len: usize,
    /// A length every implementation must reject `invalid-key`.
    pub bad_key_len: usize,
    /// The `nonce-size` getter's value: the nonce length `seal`/`open`
    /// always accept.
    pub nonce_len: usize,
    /// The `tag-size` getter's value: the default tag length.
    pub tag_len: usize,
    /// Mint by import with the given options.
    pub import: fn(Vec<u8>, AeadKeyOptions) -> MintFuture<AeadKey>,
    /// Mint by generation with the given options.
    pub generate: fn(AeadKeyOptions) -> MintFuture<AeadKey>,
}

pub const AEAD_FAMILIES: &[AeadFamily] = &[
    AeadFamily {
        interface: "aes-gcm",
        variant: Some("aes128"),
        name: "AES-GCM",
        features: &[],
        key_len: 16,
        bad_key_len: 32,
        nonce_len: 12,
        tag_len: 16,
        import: |raw, options| Box::pin(aes_gcm::import_key(AesVariant::Aes128, raw, options)),
        generate: |options| Box::pin(aes_gcm::generate_key(AesVariant::Aes128, options)),
    },
    AeadFamily {
        interface: "aes-gcm",
        variant: Some("aes256"),
        name: "AES-GCM",
        features: &[],
        key_len: 32,
        bad_key_len: 16,
        nonce_len: 12,
        tag_len: 16,
        import: |raw, options| Box::pin(aes_gcm::import_key(AesVariant::Aes256, raw, options)),
        generate: |options| Box::pin(aes_gcm::generate_key(AesVariant::Aes256, options)),
    },
    AeadFamily {
        interface: "chacha20-poly1305",
        variant: None,
        name: "ChaCha20-Poly1305",
        features: &[FEATURE_CHACHA],
        key_len: 32,
        bad_key_len: 16,
        nonce_len: 12,
        tag_len: 16,
        import: |raw, options| Box::pin(chacha20_poly1305::import_key(raw, options)),
        generate: |options| Box::pin(chacha20_poly1305::generate_key(options)),
    },
    AeadFamily {
        interface: "xchacha20-poly1305",
        variant: None,
        name: "XChaCha20-Poly1305",
        features: &[FEATURE_CHACHA],
        key_len: 32,
        bad_key_len: 16,
        nonce_len: 24,
        tag_len: 16,
        import: |raw, options| Box::pin(xchacha20_poly1305::import_key(raw, options)),
        generate: |options| Box::pin(xchacha20_poly1305::generate_key(options)),
    },
];

/// The kind-uniform contract rules. Adding a case here adds one
/// conformance case per family in [`AEAD_FAMILIES`].
#[derive(Clone, Copy)]
pub enum AeadArea {
    /// The mint-bound facts, read back from a key minted by each entry
    /// point.
    Getters,
    /// Extractability in both directions on both minting paths, and the
    /// import → export identity.
    Export,
    /// Wrong-length key material is `invalid-key` at import.
    RejectKey,
    /// Usage policy: deny-by-default at mint, per-operation enforcement,
    /// and the usage getters reporting the recorded grants.
    Usage,
    /// Seal → open self-consistency at the family's nonce and tag facts.
    Roundtrip,
}

impl AeadArea {
    pub const ALL: &[AeadArea] = &[
        AeadArea::Getters,
        AeadArea::Export,
        AeadArea::RejectKey,
        AeadArea::Usage,
        AeadArea::Roundtrip,
    ];

    /// The area's name, as used in case ids.
    pub fn id(self) -> &'static str {
        match self {
            AeadArea::Getters => "getters",
            AeadArea::Export => "export",
            AeadArea::RejectKey => "reject-key",
            AeadArea::Usage => "usage",
            AeadArea::Roundtrip => "roundtrip",
        }
    }
}

/// The case's stable id: `<interface>/contract/[<variant>-]<area>`, so the
/// battery groups as `<interface>/contract` beside the family's vector
/// groups.
pub fn case_id(family: &AeadFamily, area: AeadArea) -> String {
    match family.variant {
        Some(variant) => format!("{}/contract/{}-{}", family.interface, variant, area.id()),
        None => format!("{}/contract/{}", family.interface, area.id()),
    }
}

/// Run one battery case.
pub async fn run(family: &AeadFamily, area: AeadArea) -> Result<(), String> {
    match area {
        AeadArea::Getters => getters(family).await,
        AeadArea::Export => export(family).await,
        AeadArea::RejectKey => reject_key(family).await,
        AeadArea::Usage => usage(family).await,
        AeadArea::Roundtrip => roundtrip(family).await,
    }
}

/// Key material for a family's import entry point.
fn raw_key(family: &AeadFamily) -> Vec<u8> {
    vec![0x42u8; family.key_len]
}

/// A key minted by each entry point reports the row's mint-bound facts.
/// Asserted per family because a getter checked on one family leaves
/// precisely the family where the value differs untested.
async fn getters(family: &AeadFamily) -> Result<(), String> {
    let imported = (family.import)(raw_key(family), mint::aead_options(false)).await;
    let generated = (family.generate)(mint::aead_options(false)).await;
    for (how, key) in [("imported", imported), ("generated", generated)] {
        let key = key.map_err(|e| describe(&format!("{how} mint"), &e))?;
        expect(
            key.algorithm_name(),
            family.name.to_string(),
            &format!("{how} key algorithm-name"),
        )?;
        expect(
            key.algorithm_length(),
            family.key_len as u32 * 8,
            &format!("{how} key algorithm-length"),
        )?;
        expect(
            key.nonce_size(),
            family.nonce_len as u32,
            &format!("{how} key nonce-size"),
        )?;
        expect(
            key.tag_size(),
            family.tag_len as u32,
            &format!("{how} key tag-size"),
        )?;
    }
    Ok(())
}

/// The `extractable` getter reports the minted flag in both directions on
/// both minting paths, `export-key` is gated by it, and import → export
/// is the identity.
async fn export(family: &AeadFamily) -> Result<(), String> {
    let raw = raw_key(family);
    let key = (family.import)(raw.clone(), mint::aead_options(true))
        .await
        .map_err(|e| describe("extractable import", &e))?;
    expect(key.extractable(), true, "extractable imported key's getter")?;
    let exported = key
        .export_key()
        .await
        .map_err(|e| describe("export of an extractable import", &e))?;
    expect_bytes(&exported, &raw, "exported key material")?;

    let key = (family.generate)(mint::aead_options(true))
        .await
        .map_err(|e| describe("extractable generate", &e))?;
    let exported = key
        .export_key()
        .await
        .map_err(|e| describe("export of an extractable generated key", &e))?;
    expect(
        exported.len(),
        family.key_len,
        "generated key material length",
    )?;

    for (how, key) in [
        (
            "imported",
            (family.import)(raw, mint::aead_options(false)).await,
        ),
        (
            "generated",
            (family.generate)(mint::aead_options(false)).await,
        ),
    ] {
        let key = key.map_err(|e| describe(&format!("non-extractable {how} mint"), &e))?;
        expect(
            key.extractable(),
            false,
            &format!("non-extractable {how} key's getter"),
        )?;
        expect_err(
            &format!("export-key on a non-extractable {how} key"),
            ErrKind::NotExtractable,
            key.export_key().await,
            "non-extractable key exported",
        )?;
    }
    Ok(())
}

/// Wrong-length key material — empty, and the row's `bad_key_len` — fails
/// `invalid-key` at import.
async fn reject_key(family: &AeadFamily) -> Result<(), String> {
    for len in [0, family.bad_key_len] {
        expect_err(
            &format!("import-key ({len} bytes)"),
            ErrKind::InvalidKey,
            (family.import)(vec![0u8; len], mint::aead_options(false)).await,
            "wrong-length key material imported",
        )?;
    }
    Ok(())
}

/// The package-wide usage contract, per family: an untouched options
/// resource cannot mint (`not-permitted`), a granted operation is served,
/// an ungranted one is refused `not-permitted`, and the usage getters
/// report the recorded grants. (The wrap-grant facet — grants recorded
/// ahead of the operations existing — is one probe, `aead_usage_policy`,
/// not a per-family fact.)
async fn usage(family: &AeadFamily) -> Result<(), String> {
    let raw = raw_key(family);
    expect_err(
        "zero-usage import-key",
        ErrKind::NotPermitted,
        (family.import)(raw.clone(), AeadKeyOptions::new()).await,
        "minted a key with no enabled usage",
    )?;

    let options = AeadKeyOptions::new();
    options.can_seal(true);
    let seal_only = (family.import)(raw.clone(), options)
        .await
        .map_err(|e| describe("seal-only import-key", &e))?;
    expect(seal_only.can_seal(), true, "seal-only key can-seal")?;
    expect(seal_only.can_open(), false, "seal-only key can-open")?;
    expect(seal_only.can_wrap(), false, "seal-only key can-wrap")?;
    expect(seal_only.can_unwrap(), false, "seal-only key can-unwrap")?;

    let nonce = vec![3u8; family.nonce_len];
    let plaintext = b"battery usage plaintext";
    let (sealed, fed) = seal(&seal_only, &nonce, b"", None, plaintext, Schedule::Whole).await;
    fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
    let sealed = sealed.map_err(|e| describe("seal under a seal-only key", &e))?;
    let (refused, fed) = open(&seal_only, &nonce, b"", None, &sealed, Schedule::Whole).await;
    fed.map_err(|e| format!("open ciphertext feeder: {e}"))?;
    expect_err(
        "open on a seal-only key",
        ErrKind::NotPermitted,
        refused,
        "seal-only key opened",
    )?;

    let options = AeadKeyOptions::new();
    options.can_open(true);
    let open_only = (family.import)(raw, options)
        .await
        .map_err(|e| describe("open-only import-key", &e))?;
    expect(open_only.can_seal(), false, "open-only key can-seal")?;
    expect(open_only.can_open(), true, "open-only key can-open")?;
    let (opened, fed) = open(&open_only, &nonce, b"", None, &sealed, Schedule::Whole).await;
    fed.map_err(|e| format!("open ciphertext feeder: {e}"))?;
    let opened = opened.map_err(|e| describe("open under an open-only key", &e))?;
    expect_bytes(&opened, plaintext, "plaintext under an open-only key")?;
    let (refused, fed) = seal(&open_only, &nonce, b"", None, plaintext, Schedule::Whole).await;
    fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
    expect_err(
        "seal on an open-only key",
        ErrKind::NotPermitted,
        refused,
        "open-only key sealed",
    )
}

/// Seal → open self-consistency at the row's facts: the sealed message is
/// plaintext plus the default tag, and opens back to the plaintext under
/// the same key, nonce, and associated data.
async fn roundtrip(family: &AeadFamily) -> Result<(), String> {
    let key = (family.generate)(mint::aead_options(false))
        .await
        .map_err(|e| describe("generate-key", &e))?;
    let nonce = vec![7u8; family.nonce_len];
    let aad = b"battery roundtrip aad";
    let plaintext: Vec<u8> = (0..=255u8).cycle().take(3 * 16 + 5).collect();

    let (sealed, fed) = seal(&key, &nonce, aad, None, &plaintext, Schedule::Straddle).await;
    fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
    let sealed = sealed.map_err(|e| describe("seal", &e))?;
    expect(
        sealed.len(),
        plaintext.len() + family.tag_len,
        "sealed length",
    )?;

    let (opened, fed) = open(&key, &nonce, aad, None, &sealed, Schedule::Whole).await;
    fed.map_err(|e| format!("open ciphertext feeder: {e}"))?;
    let opened = opened.map_err(|e| describe("open", &e))?;
    expect_bytes(&opened, &plaintext, "round-tripped plaintext")
}
