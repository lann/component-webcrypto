//! The per-kind contract batteries: the standard cases every minting
//! family of a primitive kind must pass, derived from one table row per
//! minted algorithm.
//!
//! Each kind's row type carries the family's entry points and the facts
//! the WIT binds at mint; the battery instantiates each of the kind's
//! contract areas against every row. That makes the rule × family matrix
//! structural: a new family is one row here (landing as a reviewable
//! `tests.lock` diff of `<interface>/contract/…` cases), and a new
//! package-wide rule is one area, covering every family at once — the
//! class of gap where a rule is asserted on N−1 of N families cannot
//! recur within battery scope.
//!
//! Only rules that are kind-uniform by WIT contract belong here.
//! Algorithm-specific behavior — nonce windows, tag-size parameters,
//! nonce budgets, wire formats, known answers, chaining semantics —
//! stays in the hand-written probes and the vector cases; a rule that
//! would need a per-family branch in an area body belongs there too.

use crate::mint;
use conformance_harness::stream::{
    ci_decrypt, ci_encrypt, in_open, in_seal, open, seal, sign, try_sign, verify, Schedule,
};
use conformance_harness::{
    describe, expect, expect_bytes, expect_err, unhex, ErrKind, FEATURE_CHACHA, FEATURE_XCHACHA,
};
use lann_webcrypto_guest::bindings::aead::{AeadKey, AeadKeyOptions};
use lann_webcrypto_guest::bindings::aead_internal_nonce::{
    InternalNonceKey, InternalNonceKeyOptions,
};
use lann_webcrypto_guest::bindings::aes_gcm::AesVariant;
use lann_webcrypto_guest::bindings::cipher::{CipherKey, CipherKeyOptions};
use lann_webcrypto_guest::bindings::derivation::DeriveInput;
use lann_webcrypto_guest::bindings::mac::{MacKey, MacKeyOptions};
use lann_webcrypto_guest::bindings::sha2::Sha2Variant;
use lann_webcrypto_guest::bindings::types::Error;
use lann_webcrypto_guest::bindings::{
    aes_cbc, aes_ctr, aes_gcm, aes_gcm_internal_nonce, chacha20_poly1305, hkdf, hkdf_sha2,
    hmac_sha1, hmac_sha2, pbkdf2, pbkdf2_sha2, x25519, xchacha20_poly1305,
    xchacha20_poly1305_internal_nonce,
};

/// A boxed minting future: the families' entry points are distinct
/// functions with identical shapes, so the tables store them behind one
/// signature.
type MintFuture<T> = std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, Error>>>>;

/// A case's stable id: `<interface>/contract/[<variant>-]<area>`, so a
/// battery groups as `<interface>/contract` beside the family's vector
/// groups.
fn contract_case_id(interface: &str, variant: Option<&str>, area: &str) -> String {
    match variant {
        Some(variant) => format!("{interface}/contract/{variant}-{area}"),
        None => format!("{interface}/contract/{area}"),
    }
}

/// Key material for an import entry point: `len` distinct bytes, so an
/// export identity cannot pass on length alone.
fn oct_key(len: usize) -> Vec<u8> {
    (1..=len as u8).collect()
}

/// The oct-JWK facts a family binds: its registered JOSE `alg`, and
/// another oct algorithm's `alg` its import must reject `invalid-key`.
pub struct OctJwk {
    pub alg: &'static str,
    pub wrong_alg: &'static str,
}

// ---------------------------------------------------------------------------
// Caller-nonce AEAD
// ---------------------------------------------------------------------------

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
    /// The family's oct-JWK binding, or `None` for a family with no
    /// registered JWK form (its decline is a hand-written probe).
    pub jwk: Option<AeadJwk>,
    /// Mint by import with the given options.
    pub import: fn(Vec<u8>, AeadKeyOptions) -> MintFuture<AeadKey>,
    /// Mint by generation with the given options.
    pub generate: fn(AeadKeyOptions) -> MintFuture<AeadKey>,
}

/// A caller-nonce family's JWK entry point and `alg` facts.
pub struct AeadJwk {
    pub algs: OctJwk,
    pub import: fn(String, AeadKeyOptions) -> MintFuture<AeadKey>,
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
        jwk: Some(AeadJwk {
            algs: OctJwk {
                alg: "A128GCM",
                wrong_alg: "A256GCM",
            },
            import: |jwk, options| {
                Box::pin(aes_gcm::import_key_jwk(AesVariant::Aes128, jwk, options))
            },
        }),
        import: |raw, options| Box::pin(aes_gcm::import_key_raw(AesVariant::Aes128, raw, options)),
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
        jwk: Some(AeadJwk {
            algs: OctJwk {
                alg: "A256GCM",
                wrong_alg: "A128GCM",
            },
            import: |jwk, options| {
                Box::pin(aes_gcm::import_key_jwk(AesVariant::Aes256, jwk, options))
            },
        }),
        import: |raw, options| Box::pin(aes_gcm::import_key_raw(AesVariant::Aes256, raw, options)),
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
        // The W3C Modern Algorithms proposal's registered `alg`; the
        // alg-less form (the WPT fixtures' shape) rides the shared
        // accepts-absent rule the area asserts on every family.
        jwk: Some(AeadJwk {
            algs: OctJwk {
                alg: "C20P",
                wrong_alg: "A256GCM",
            },
            import: |jwk, options| Box::pin(chacha20_poly1305::import_key_jwk(jwk, options)),
        }),
        import: |raw, options| Box::pin(chacha20_poly1305::import_key_raw(raw, options)),
        generate: |options| Box::pin(chacha20_poly1305::generate_key(options)),
    },
    AeadFamily {
        interface: "xchacha20-poly1305",
        variant: None,
        name: "XChaCha20-Poly1305",
        features: &[FEATURE_XCHACHA],
        key_len: 32,
        bad_key_len: 16,
        nonce_len: 24,
        tag_len: 16,
        // No specification registers a JWK form for XChaCha; the
        // preserved decline is the `xchacha_jwk_unsupported` probe.
        jwk: None,
        import: |raw, options| Box::pin(xchacha20_poly1305::import_key_raw(raw, options)),
        generate: |options| Box::pin(xchacha20_poly1305::generate_key(options)),
    },
];

/// The kind-uniform contract rules. Adding a case here adds one
/// conformance case per family in [`AEAD_FAMILIES`].
#[derive(Clone, Copy, PartialEq)]
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
    /// The oct-JWK contract: `alg` binding, the material round trip, and
    /// the extractability gate on the JWK export.
    Jwk,
}

impl AeadArea {
    pub const ALL: &[AeadArea] = &[
        AeadArea::Getters,
        AeadArea::Export,
        AeadArea::RejectKey,
        AeadArea::Usage,
        AeadArea::Roundtrip,
        AeadArea::Jwk,
    ];

    /// The area's name, as used in case ids.
    pub fn id(self) -> &'static str {
        match self {
            AeadArea::Getters => "getters",
            AeadArea::Export => "export",
            AeadArea::RejectKey => "reject-key",
            AeadArea::Usage => "usage",
            AeadArea::Roundtrip => "roundtrip",
            AeadArea::Jwk => "jwk",
        }
    }
}

impl AeadFamily {
    pub fn case_id(&self, area: AeadArea) -> String {
        contract_case_id(self.interface, self.variant, area.id())
    }

    /// The areas this row serves: every row runs the whole battery except
    /// `jwk` on a family with no JWK form.
    pub fn areas(&self) -> impl Iterator<Item = AeadArea> + '_ {
        AeadArea::ALL
            .iter()
            .copied()
            .filter(|area| *area != AeadArea::Jwk || self.jwk.is_some())
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
        AeadArea::Jwk => jwk(family).await,
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
/// both minting paths, `export-key-raw` is gated by it, and import → export
/// is the identity.
async fn export(family: &AeadFamily) -> Result<(), String> {
    let raw = raw_key(family);
    let key = (family.import)(raw.clone(), mint::aead_options(true))
        .await
        .map_err(|e| describe("extractable import", &e))?;
    expect(key.extractable(), true, "extractable imported key's getter")?;
    let exported = key
        .export_key_raw()
        .await
        .map_err(|e| describe("export of an extractable import", &e))?;
    expect_bytes(&exported, &raw, "exported key material")?;

    let key = (family.generate)(mint::aead_options(true))
        .await
        .map_err(|e| describe("extractable generate", &e))?;
    let exported = key
        .export_key_raw()
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
            &format!("export-key-raw on a non-extractable {how} key"),
            ErrKind::NotExtractable,
            key.export_key_raw().await,
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
            &format!("import-key-raw ({len} bytes)"),
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
/// ahead of the operations existing — is one probe, `aead_wrap_grants`,
/// not a per-family fact.)
async fn usage(family: &AeadFamily) -> Result<(), String> {
    let raw = raw_key(family);
    expect_err(
        "zero-usage import-key-raw",
        ErrKind::NotPermitted,
        (family.import)(raw.clone(), AeadKeyOptions::new()).await,
        "minted a key with no enabled usage",
    )?;

    let options = AeadKeyOptions::new();
    options.can_seal(true);
    let seal_only = (family.import)(raw.clone(), options)
        .await
        .map_err(|e| describe("seal-only import-key-raw", &e))?;
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
        .map_err(|e| describe("open-only import-key-raw", &e))?;
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

/// The oct-JWK contract, per family: the registered `alg` imports and the
/// material round-trips, the export carries the JWK members, the alg-less
/// form is accepted, another algorithm's `alg` is `invalid-key`, and the
/// extractability gate holds on the JWK export.
async fn jwk(family: &AeadFamily) -> Result<(), String> {
    let jwk_row = family.jwk.as_ref().expect("jwk area on a JWK-less family");
    let (alg, wrong_alg) = (jwk_row.algs.alg, jwk_row.algs.wrong_alg);
    let raw = oct_key(family.key_len);
    let k = mint::b64url(&raw);

    let key = (jwk_row.import)(
        format!(r#"{{"kty":"oct","k":"{k}","alg":"{alg}"}}"#),
        mint::aead_options(true),
    )
    .await
    .map_err(|e| describe("import-key-jwk", &e))?;
    let exported = key
        .export_key_raw()
        .await
        .map_err(|e| describe("export-key-raw", &e))?;
    expect_bytes(&exported, &raw, "material from the JWK")?;
    let exported_jwk = key
        .export_key_jwk()
        .await
        .map_err(|e| describe("export-key-jwk", &e))?;
    if !exported_jwk.contains(&k)
        || !exported_jwk.contains("\"oct\"")
        || !exported_jwk.contains(alg)
    {
        return Err(format!(
            "exported JWK missing material members: {exported_jwk}"
        ));
    }
    let reimported = (jwk_row.import)(exported_jwk, mint::aead_options(true))
        .await
        .map_err(|e| describe("re-import of exported JWK", &e))?;
    let exported = reimported
        .export_key_raw()
        .await
        .map_err(|e| describe("export-key-raw after JWK re-import", &e))?;
    expect_bytes(&exported, &raw, "material after the JWK round trip")?;

    (jwk_row.import)(
        format!(r#"{{"kty":"oct","k":"{k}"}}"#),
        mint::aead_options(false),
    )
    .await
    .map_err(|e| describe("import-key-jwk (alg-less)", &e))?;
    expect_err(
        "import-key-jwk with another algorithm's alg",
        ErrKind::InvalidKey,
        (jwk_row.import)(
            format!(r#"{{"kty":"oct","k":"{k}","alg":"{wrong_alg}"}}"#),
            mint::aead_options(false),
        )
        .await,
        "imported a JWK bound to another algorithm",
    )?;

    let key = (family.import)(raw, mint::aead_options(false))
        .await
        .map_err(|e| describe("non-extractable import-key-raw", &e))?;
    expect_err(
        "export-key-jwk on a non-extractable key",
        ErrKind::NotExtractable,
        key.export_key_jwk().await,
        "non-extractable key exported",
    )
}

// ---------------------------------------------------------------------------
// MAC
// ---------------------------------------------------------------------------

/// One MAC minting family: its entry points and the facts the WIT binds
/// at mint.
pub struct MacFamily {
    pub interface: &'static str,
    pub variant: Option<&'static str>,
    /// The `algorithm-name` getter's value.
    pub name: &'static str,
    /// The `algorithm-hash` getter's value.
    pub hash: &'static str,
    pub features: &'static [&'static str],
    /// The tag length in bytes (the hash's output size).
    pub tag_len: usize,
    /// `generate-key`'s default key length in bytes (the hash's block
    /// size, WebCrypto's `generateKey` default).
    pub generate_default_len: usize,
    pub jwk: OctJwk,
    pub import: fn(Vec<u8>, MacKeyOptions) -> MintFuture<MacKey>,
    pub import_jwk: fn(String, MacKeyOptions) -> MintFuture<MacKey>,
    /// Mint by generation at the default length.
    pub generate: fn(MacKeyOptions) -> MintFuture<MacKey>,
}

pub const MAC_FAMILIES: &[MacFamily] = &[
    MacFamily {
        interface: "hmac-sha2",
        variant: Some("sha256"),
        name: "HMAC",
        hash: "SHA-256",
        features: &[],
        tag_len: 32,
        generate_default_len: 64,
        jwk: OctJwk {
            alg: "HS256",
            wrong_alg: "HS384",
        },
        import: |raw, options| {
            Box::pin(hmac_sha2::import_key_raw(Sha2Variant::Sha256, raw, options))
        },
        import_jwk: |jwk, options| {
            Box::pin(hmac_sha2::import_key_jwk(Sha2Variant::Sha256, jwk, options))
        },
        generate: |options| Box::pin(hmac_sha2::generate_key(Sha2Variant::Sha256, None, options)),
    },
    MacFamily {
        interface: "hmac-sha2",
        variant: Some("sha384"),
        name: "HMAC",
        hash: "SHA-384",
        features: &[],
        tag_len: 48,
        generate_default_len: 128,
        jwk: OctJwk {
            alg: "HS384",
            wrong_alg: "HS256",
        },
        import: |raw, options| {
            Box::pin(hmac_sha2::import_key_raw(Sha2Variant::Sha384, raw, options))
        },
        import_jwk: |jwk, options| {
            Box::pin(hmac_sha2::import_key_jwk(Sha2Variant::Sha384, jwk, options))
        },
        generate: |options| Box::pin(hmac_sha2::generate_key(Sha2Variant::Sha384, None, options)),
    },
    MacFamily {
        interface: "hmac-sha2",
        variant: Some("sha512"),
        name: "HMAC",
        hash: "SHA-512",
        features: &[],
        tag_len: 64,
        generate_default_len: 128,
        jwk: OctJwk {
            alg: "HS512",
            wrong_alg: "HS384",
        },
        import: |raw, options| {
            Box::pin(hmac_sha2::import_key_raw(Sha2Variant::Sha512, raw, options))
        },
        import_jwk: |jwk, options| {
            Box::pin(hmac_sha2::import_key_jwk(Sha2Variant::Sha512, jwk, options))
        },
        generate: |options| Box::pin(hmac_sha2::generate_key(Sha2Variant::Sha512, None, options)),
    },
    MacFamily {
        interface: "hmac-sha1",
        variant: None,
        name: "HMAC",
        hash: "SHA-1",
        features: &[],
        tag_len: 20,
        generate_default_len: 64,
        jwk: OctJwk {
            alg: "HS1",
            wrong_alg: "HS256",
        },
        import: |raw, options| Box::pin(hmac_sha1::import_key_raw(raw, options)),
        import_jwk: |jwk, options| Box::pin(hmac_sha1::import_key_jwk(jwk, options)),
        generate: |options| Box::pin(hmac_sha1::generate_key(None, options)),
    },
];

/// The kind-uniform contract rules for MAC families.
#[derive(Clone, Copy)]
pub enum MacArea {
    Getters,
    Export,
    Usage,
    /// A generated key's sign → verify self-consistency at the row's tag
    /// length.
    Roundtrip,
    Jwk,
}

impl MacArea {
    pub const ALL: &[MacArea] = &[
        MacArea::Getters,
        MacArea::Export,
        MacArea::Usage,
        MacArea::Roundtrip,
        MacArea::Jwk,
    ];

    pub fn id(self) -> &'static str {
        match self {
            MacArea::Getters => "getters",
            MacArea::Export => "export",
            MacArea::Usage => "usage",
            MacArea::Roundtrip => "roundtrip",
            MacArea::Jwk => "jwk",
        }
    }
}

impl MacFamily {
    pub fn case_id(&self, area: MacArea) -> String {
        contract_case_id(self.interface, self.variant, area.id())
    }
}

pub async fn run_mac(family: &MacFamily, area: MacArea) -> Result<(), String> {
    match area {
        MacArea::Getters => mac_getters(family).await,
        MacArea::Export => mac_export(family).await,
        MacArea::Usage => mac_usage(family).await,
        MacArea::Roundtrip => mac_roundtrip(family).await,
        MacArea::Jwk => mac_jwk(family).await,
    }
}

/// A key minted by each entry point reports the row's mint-bound facts;
/// the generated key's length is the row's default.
async fn mac_getters(family: &MacFamily) -> Result<(), String> {
    let raw = oct_key(32);
    let imported = (family.import)(raw, mint::mac_options(false)).await;
    let generated = (family.generate)(mint::mac_options(false)).await;
    for (how, key, want_bits) in [
        ("imported", imported, 256u32),
        (
            "generated",
            generated,
            family.generate_default_len as u32 * 8,
        ),
    ] {
        let key = key.map_err(|e| describe(&format!("{how} mint"), &e))?;
        expect(
            key.algorithm_name(),
            family.name.to_string(),
            &format!("{how} key algorithm-name"),
        )?;
        expect(
            key.algorithm_hash(),
            Some(family.hash.to_string()),
            &format!("{how} key algorithm-hash"),
        )?;
        expect(
            key.algorithm_length(),
            want_bits,
            &format!("{how} key algorithm-length"),
        )?;
    }
    Ok(())
}

/// The `extractable` getter reports the minted flag in both directions on
/// both minting paths, `export-key-raw` is gated by it, and import →
/// export is the identity.
async fn mac_export(family: &MacFamily) -> Result<(), String> {
    let raw = oct_key(32);
    let key = (family.import)(raw.clone(), mint::mac_options(true))
        .await
        .map_err(|e| describe("extractable import", &e))?;
    expect(key.extractable(), true, "extractable imported key's getter")?;
    let exported = key
        .export_key_raw()
        .await
        .map_err(|e| describe("export of an extractable import", &e))?;
    expect_bytes(&exported, &raw, "exported key material")?;

    let key = (family.generate)(mint::mac_options(true))
        .await
        .map_err(|e| describe("extractable generate", &e))?;
    let exported = key
        .export_key_raw()
        .await
        .map_err(|e| describe("export of an extractable generated key", &e))?;
    expect(
        exported.len(),
        family.generate_default_len,
        "generated key material length",
    )?;

    for (how, key) in [
        (
            "imported",
            (family.import)(raw, mint::mac_options(false)).await,
        ),
        (
            "generated",
            (family.generate)(mint::mac_options(false)).await,
        ),
    ] {
        let key = key.map_err(|e| describe(&format!("non-extractable {how} mint"), &e))?;
        expect(
            key.extractable(),
            false,
            &format!("non-extractable {how} key's getter"),
        )?;
        expect_err(
            &format!("export-key-raw on a non-extractable {how} key"),
            ErrKind::NotExtractable,
            key.export_key_raw().await,
            "non-extractable key exported",
        )?;
    }
    Ok(())
}

/// The package-wide usage contract, per family: the zero-usage mint
/// refusal, per-operation enforcement in both grant directions, and the
/// usage getters reporting the recorded grants.
async fn mac_usage(family: &MacFamily) -> Result<(), String> {
    let raw = oct_key(32);
    expect_err(
        "zero-usage import-key-raw",
        ErrKind::NotPermitted,
        (family.import)(raw.clone(), MacKeyOptions::new()).await,
        "minted a key with no enabled usage",
    )?;

    let options = MacKeyOptions::new();
    options.can_sign(true);
    let sign_only = (family.import)(raw.clone(), options)
        .await
        .map_err(|e| describe("sign-only import-key-raw", &e))?;
    expect(sign_only.can_sign(), true, "sign-only key can-sign")?;
    expect(sign_only.can_verify(), false, "sign-only key can-verify")?;

    let payload = b"battery usage payload";
    let (tag, fed) = sign(&sign_only, payload, Schedule::Whole).await;
    fed.map_err(|e| format!("sign data feeder: {e}"))?;
    let (refused, fed) = verify(&sign_only, payload, &tag, Schedule::Whole).await;
    fed.map_err(|e| format!("verify data feeder: {e}"))?;
    expect_err(
        "verify on a sign-only key",
        ErrKind::NotPermitted,
        refused,
        "sign-only key verified",
    )?;

    let options = MacKeyOptions::new();
    options.can_verify(true);
    let verify_only = (family.import)(raw, options)
        .await
        .map_err(|e| describe("verify-only import-key-raw", &e))?;
    expect(verify_only.can_sign(), false, "verify-only key can-sign")?;
    expect(verify_only.can_verify(), true, "verify-only key can-verify")?;
    let (verified, fed) = verify(&verify_only, payload, &tag, Schedule::Whole).await;
    fed.map_err(|e| format!("verify data feeder: {e}"))?;
    verified.map_err(|e| describe("valid tag under a verify-only key", &e))?;
    let (refused, fed) = try_sign(&verify_only, payload, Schedule::Whole).await;
    fed.map_err(|e| format!("sign data feeder: {e}"))?;
    expect_err(
        "sign on a verify-only key",
        ErrKind::NotPermitted,
        refused,
        "verify-only key signed",
    )
}

/// A generated key signs and verifies its own tag at the row's tag length.
async fn mac_roundtrip(family: &MacFamily) -> Result<(), String> {
    let key = (family.generate)(mint::mac_options(false))
        .await
        .map_err(|e| describe("generate-key", &e))?;
    let payload: Vec<u8> = (0..=255u8).cycle().take(3 * 16 + 5).collect();
    let (tag, fed) = sign(&key, &payload, Schedule::Straddle).await;
    fed.map_err(|e| format!("sign data feeder: {e}"))?;
    expect(tag.len(), family.tag_len, "tag length")?;
    let (verified, fed) = verify(&key, &payload, &tag, Schedule::Whole).await;
    fed.map_err(|e| format!("verify data feeder: {e}"))?;
    verified.map_err(|e| describe("round-trip tag did not verify", &e))
}

/// The oct-JWK contract, per family (the [`jwk`] script over MAC entry
/// points).
async fn mac_jwk(family: &MacFamily) -> Result<(), String> {
    let (alg, wrong_alg) = (family.jwk.alg, family.jwk.wrong_alg);
    let raw = oct_key(32);
    let k = mint::b64url(&raw);

    let key = (family.import_jwk)(
        format!(r#"{{"kty":"oct","k":"{k}","alg":"{alg}"}}"#),
        mint::mac_options(true),
    )
    .await
    .map_err(|e| describe("import-key-jwk", &e))?;
    let exported = key
        .export_key_raw()
        .await
        .map_err(|e| describe("export-key-raw", &e))?;
    expect_bytes(&exported, &raw, "material from the JWK")?;
    let exported_jwk = key
        .export_key_jwk()
        .await
        .map_err(|e| describe("export-key-jwk", &e))?;
    if !exported_jwk.contains(&k)
        || !exported_jwk.contains("\"oct\"")
        || !exported_jwk.contains(alg)
    {
        return Err(format!(
            "exported JWK missing material members: {exported_jwk}"
        ));
    }
    let reimported = (family.import_jwk)(exported_jwk, mint::mac_options(true))
        .await
        .map_err(|e| describe("re-import of exported JWK", &e))?;
    let exported = reimported
        .export_key_raw()
        .await
        .map_err(|e| describe("export-key-raw after JWK re-import", &e))?;
    expect_bytes(&exported, &raw, "material after the JWK round trip")?;

    (family.import_jwk)(
        format!(r#"{{"kty":"oct","k":"{k}"}}"#),
        mint::mac_options(false),
    )
    .await
    .map_err(|e| describe("import-key-jwk (alg-less)", &e))?;
    expect_err(
        "import-key-jwk with another algorithm's alg",
        ErrKind::InvalidKey,
        (family.import_jwk)(
            format!(r#"{{"kty":"oct","k":"{k}","alg":"{wrong_alg}"}}"#),
            mint::mac_options(false),
        )
        .await,
        "imported a JWK bound to another algorithm",
    )?;

    let key = (family.import)(raw, mint::mac_options(false))
        .await
        .map_err(|e| describe("non-extractable import-key-raw", &e))?;
    expect_err(
        "export-key-jwk on a non-extractable key",
        ErrKind::NotExtractable,
        key.export_key_jwk().await,
        "non-extractable key exported",
    )
}

// ---------------------------------------------------------------------------
// Unauthenticated cipher
// ---------------------------------------------------------------------------

/// One cipher minting family: its entry points and the facts the WIT
/// binds at mint.
pub struct CipherFamily {
    pub interface: &'static str,
    pub variant: Option<&'static str>,
    /// The `algorithm-name` getter's value.
    pub name: &'static str,
    pub features: &'static [&'static str],
    /// The raw key length in bytes; `algorithm-length` reports it in bits.
    pub key_len: usize,
    /// A length every implementation must reject `invalid-key`.
    pub bad_key_len: usize,
    /// The `iv-size` getter's value.
    pub iv_len: usize,
    /// The per-call `counter-length` the mode requires (`None` for CBC,
    /// which refuses one).
    pub counter_length: Option<u8>,
    pub jwk: OctJwk,
    pub import: fn(Vec<u8>, CipherKeyOptions) -> MintFuture<CipherKey>,
    pub import_jwk: fn(String, CipherKeyOptions) -> MintFuture<CipherKey>,
    pub generate: fn(CipherKeyOptions) -> MintFuture<CipherKey>,
}

pub const CIPHER_FAMILIES: &[CipherFamily] = &[
    CipherFamily {
        interface: "aes-cbc",
        variant: Some("aes128"),
        name: "AES-CBC",
        features: &[],
        key_len: 16,
        bad_key_len: 32,
        iv_len: 16,
        counter_length: None,
        jwk: OctJwk {
            alg: "A128CBC",
            wrong_alg: "A128CTR",
        },
        import: |raw, options| Box::pin(aes_cbc::import_key_raw(AesVariant::Aes128, raw, options)),
        import_jwk: |jwk, options| {
            Box::pin(aes_cbc::import_key_jwk(AesVariant::Aes128, jwk, options))
        },
        generate: |options| Box::pin(aes_cbc::generate_key(AesVariant::Aes128, options)),
    },
    CipherFamily {
        interface: "aes-cbc",
        variant: Some("aes256"),
        name: "AES-CBC",
        features: &[],
        key_len: 32,
        bad_key_len: 16,
        iv_len: 16,
        counter_length: None,
        jwk: OctJwk {
            alg: "A256CBC",
            wrong_alg: "A256CTR",
        },
        import: |raw, options| Box::pin(aes_cbc::import_key_raw(AesVariant::Aes256, raw, options)),
        import_jwk: |jwk, options| {
            Box::pin(aes_cbc::import_key_jwk(AesVariant::Aes256, jwk, options))
        },
        generate: |options| Box::pin(aes_cbc::generate_key(AesVariant::Aes256, options)),
    },
    CipherFamily {
        interface: "aes-ctr",
        variant: Some("aes128"),
        name: "AES-CTR",
        features: &[],
        key_len: 16,
        bad_key_len: 32,
        iv_len: 16,
        counter_length: Some(64),
        jwk: OctJwk {
            alg: "A128CTR",
            wrong_alg: "A128CBC",
        },
        import: |raw, options| Box::pin(aes_ctr::import_key_raw(AesVariant::Aes128, raw, options)),
        import_jwk: |jwk, options| {
            Box::pin(aes_ctr::import_key_jwk(AesVariant::Aes128, jwk, options))
        },
        generate: |options| Box::pin(aes_ctr::generate_key(AesVariant::Aes128, options)),
    },
    CipherFamily {
        interface: "aes-ctr",
        variant: Some("aes256"),
        name: "AES-CTR",
        features: &[],
        key_len: 32,
        bad_key_len: 16,
        iv_len: 16,
        counter_length: Some(64),
        jwk: OctJwk {
            alg: "A256CTR",
            wrong_alg: "A256CBC",
        },
        import: |raw, options| Box::pin(aes_ctr::import_key_raw(AesVariant::Aes256, raw, options)),
        import_jwk: |jwk, options| {
            Box::pin(aes_ctr::import_key_jwk(AesVariant::Aes256, jwk, options))
        },
        generate: |options| Box::pin(aes_ctr::generate_key(AesVariant::Aes256, options)),
    },
];

/// The kind-uniform contract rules for cipher families.
#[derive(Clone, Copy)]
pub enum CipherArea {
    Getters,
    Export,
    RejectKey,
    Usage,
    Jwk,
}

impl CipherArea {
    pub const ALL: &[CipherArea] = &[
        CipherArea::Getters,
        CipherArea::Export,
        CipherArea::RejectKey,
        CipherArea::Usage,
        CipherArea::Jwk,
    ];

    pub fn id(self) -> &'static str {
        match self {
            CipherArea::Getters => "getters",
            CipherArea::Export => "export",
            CipherArea::RejectKey => "reject-key",
            CipherArea::Usage => "usage",
            CipherArea::Jwk => "jwk",
        }
    }
}

impl CipherFamily {
    pub fn case_id(&self, area: CipherArea) -> String {
        contract_case_id(self.interface, self.variant, area.id())
    }
}

pub async fn run_cipher(family: &CipherFamily, area: CipherArea) -> Result<(), String> {
    match area {
        CipherArea::Getters => cipher_getters(family).await,
        CipherArea::Export => cipher_export(family).await,
        CipherArea::RejectKey => cipher_reject_key(family).await,
        CipherArea::Usage => cipher_usage(family).await,
        CipherArea::Jwk => cipher_jwk(family).await,
    }
}

/// A key minted by each entry point reports the row's mint-bound facts.
async fn cipher_getters(family: &CipherFamily) -> Result<(), String> {
    let imported = (family.import)(oct_key(family.key_len), mint::cipher_options(false)).await;
    let generated = (family.generate)(mint::cipher_options(false)).await;
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
            key.iv_size(),
            family.iv_len as u32,
            &format!("{how} key iv-size"),
        )?;
    }
    Ok(())
}

/// The `extractable` getter reports the minted flag in both directions on
/// both minting paths, `export-key-raw` is gated by it, and import →
/// export is the identity.
async fn cipher_export(family: &CipherFamily) -> Result<(), String> {
    let raw = oct_key(family.key_len);
    let key = (family.import)(raw.clone(), mint::cipher_options(true))
        .await
        .map_err(|e| describe("extractable import", &e))?;
    expect(key.extractable(), true, "extractable imported key's getter")?;
    let exported = key
        .export_key_raw()
        .await
        .map_err(|e| describe("export of an extractable import", &e))?;
    expect_bytes(&exported, &raw, "exported key material")?;

    let key = (family.generate)(mint::cipher_options(true))
        .await
        .map_err(|e| describe("extractable generate", &e))?;
    let exported = key
        .export_key_raw()
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
            (family.import)(raw, mint::cipher_options(false)).await,
        ),
        (
            "generated",
            (family.generate)(mint::cipher_options(false)).await,
        ),
    ] {
        let key = key.map_err(|e| describe(&format!("non-extractable {how} mint"), &e))?;
        expect(
            key.extractable(),
            false,
            &format!("non-extractable {how} key's getter"),
        )?;
        expect_err(
            &format!("export-key-raw on a non-extractable {how} key"),
            ErrKind::NotExtractable,
            key.export_key_raw().await,
            "non-extractable key exported",
        )?;
    }
    Ok(())
}

/// Wrong-length key material — empty, and the row's `bad_key_len` — fails
/// `invalid-key` at import.
async fn cipher_reject_key(family: &CipherFamily) -> Result<(), String> {
    for len in [0, family.bad_key_len] {
        expect_err(
            &format!("import-key-raw ({len} bytes)"),
            ErrKind::InvalidKey,
            (family.import)(vec![0u8; len], mint::cipher_options(false)).await,
            "wrong-length key material imported",
        )?;
    }
    Ok(())
}

/// The package-wide usage contract, per family: the zero-usage mint
/// refusal, per-operation enforcement in both grant directions, and the
/// usage getters — including the recorded wrap/unwrap vocabulary.
async fn cipher_usage(family: &CipherFamily) -> Result<(), String> {
    let raw = oct_key(family.key_len);
    expect_err(
        "zero-usage import-key-raw",
        ErrKind::NotPermitted,
        (family.import)(raw.clone(), CipherKeyOptions::new()).await,
        "minted a key with no enabled usage",
    )?;

    let options = CipherKeyOptions::new();
    options.can_encrypt(true);
    options.can_wrap(true);
    let encrypt_only = (family.import)(raw.clone(), options)
        .await
        .map_err(|e| describe("encrypt-only import-key-raw", &e))?;
    expect(encrypt_only.can_encrypt(), true, "encrypt-only can-encrypt")?;
    expect(
        encrypt_only.can_decrypt(),
        false,
        "encrypt-only can-decrypt",
    )?;
    expect(encrypt_only.can_wrap(), true, "encrypt-only can-wrap")?;
    expect(encrypt_only.can_unwrap(), false, "encrypt-only can-unwrap")?;

    let iv = vec![0u8; family.iv_len];
    let payload = b"battery usage payload";
    let (sealed, fed) = ci_encrypt(
        &encrypt_only,
        &iv,
        family.counter_length,
        payload,
        Schedule::Whole,
    )
    .await;
    fed.map_err(|e| format!("encrypt plaintext feeder: {e}"))?;
    let sealed = sealed.map_err(|e| describe("encrypt under an encrypt-only key", &e))?;
    let (refused, fed) = ci_decrypt(
        &encrypt_only,
        &iv,
        family.counter_length,
        &sealed,
        Schedule::Whole,
    )
    .await;
    fed.map_err(|e| format!("decrypt ciphertext feeder: {e}"))?;
    expect_err(
        "decrypt on an encrypt-only key",
        ErrKind::NotPermitted,
        refused,
        "encrypt-only key decrypted",
    )?;

    let options = CipherKeyOptions::new();
    options.can_decrypt(true);
    let decrypt_only = (family.import)(raw, options)
        .await
        .map_err(|e| describe("decrypt-only import-key-raw", &e))?;
    expect(
        decrypt_only.can_encrypt(),
        false,
        "decrypt-only can-encrypt",
    )?;
    expect(decrypt_only.can_decrypt(), true, "decrypt-only can-decrypt")?;
    let (opened, fed) = ci_decrypt(
        &decrypt_only,
        &iv,
        family.counter_length,
        &sealed,
        Schedule::Whole,
    )
    .await;
    fed.map_err(|e| format!("decrypt ciphertext feeder: {e}"))?;
    let opened = opened.map_err(|e| describe("decrypt under a decrypt-only key", &e))?;
    expect_bytes(&opened, payload, "plaintext under a decrypt-only key")?;
    let (refused, fed) = ci_encrypt(
        &decrypt_only,
        &iv,
        family.counter_length,
        payload,
        Schedule::Whole,
    )
    .await;
    fed.map_err(|e| format!("encrypt plaintext feeder: {e}"))?;
    expect_err(
        "encrypt on a decrypt-only key",
        ErrKind::NotPermitted,
        refused,
        "decrypt-only key encrypted",
    )
}

/// The oct-JWK contract, per family (the [`jwk`] script over cipher entry
/// points; the `alg` values are mode-specific, so the wrong-`alg` case is
/// the other mode's).
async fn cipher_jwk(family: &CipherFamily) -> Result<(), String> {
    let (alg, wrong_alg) = (family.jwk.alg, family.jwk.wrong_alg);
    let raw = oct_key(family.key_len);
    let k = mint::b64url(&raw);

    let key = (family.import_jwk)(
        format!(r#"{{"kty":"oct","k":"{k}","alg":"{alg}"}}"#),
        mint::cipher_options(true),
    )
    .await
    .map_err(|e| describe("import-key-jwk", &e))?;
    let exported = key
        .export_key_raw()
        .await
        .map_err(|e| describe("export-key-raw", &e))?;
    expect_bytes(&exported, &raw, "material from the JWK")?;
    let exported_jwk = key
        .export_key_jwk()
        .await
        .map_err(|e| describe("export-key-jwk", &e))?;
    if !exported_jwk.contains(&k)
        || !exported_jwk.contains("\"oct\"")
        || !exported_jwk.contains(alg)
    {
        return Err(format!(
            "exported JWK missing material members: {exported_jwk}"
        ));
    }
    let reimported = (family.import_jwk)(exported_jwk, mint::cipher_options(true))
        .await
        .map_err(|e| describe("re-import of exported JWK", &e))?;
    let exported = reimported
        .export_key_raw()
        .await
        .map_err(|e| describe("export-key-raw after JWK re-import", &e))?;
    expect_bytes(&exported, &raw, "material after the JWK round trip")?;

    (family.import_jwk)(
        format!(r#"{{"kty":"oct","k":"{k}"}}"#),
        mint::cipher_options(false),
    )
    .await
    .map_err(|e| describe("import-key-jwk (alg-less)", &e))?;
    expect_err(
        "import-key-jwk with the other mode's alg",
        ErrKind::InvalidKey,
        (family.import_jwk)(
            format!(r#"{{"kty":"oct","k":"{k}","alg":"{wrong_alg}"}}"#),
            mint::cipher_options(false),
        )
        .await,
        "imported a JWK bound to the other mode",
    )?;

    let key = (family.import)(raw, mint::cipher_options(false))
        .await
        .map_err(|e| describe("non-extractable import-key-raw", &e))?;
    expect_err(
        "export-key-jwk on a non-extractable key",
        ErrKind::NotExtractable,
        key.export_key_jwk().await,
        "non-extractable key exported",
    )
}

// ---------------------------------------------------------------------------
// Internal-nonce AEAD
// ---------------------------------------------------------------------------

/// One internal-nonce AEAD minting family: its entry points and the facts
/// the WIT binds at mint.
pub struct InternalNonceFamily {
    pub interface: &'static str,
    pub variant: Option<&'static str>,
    /// The `algorithm-name` getter's value.
    pub name: &'static str,
    pub features: &'static [&'static str],
    /// The raw key length in bytes; `algorithm-length` reports it in bits.
    pub key_len: usize,
    /// A length every implementation must reject `invalid-key`.
    pub bad_key_len: usize,
    /// The wire format's nonce-prefix length in bytes.
    pub nonce_len: usize,
    /// The wire format's tag length in bytes.
    pub tag_len: usize,
    /// Whether `seals-remaining` reports a budget (`some`) for this
    /// algorithm.
    pub budget: bool,
    /// The family's oct-JWK binding, or `None` for an interface with no
    /// JWK minting path.
    pub jwk: Option<InternalNonceJwk>,
    pub import: fn(Vec<u8>, InternalNonceKeyOptions) -> MintFuture<InternalNonceKey>,
    pub generate: fn(InternalNonceKeyOptions) -> MintFuture<InternalNonceKey>,
}

/// An internal-nonce family's JWK entry point and `alg` facts.
pub struct InternalNonceJwk {
    pub algs: OctJwk,
    pub import: fn(String, InternalNonceKeyOptions) -> MintFuture<InternalNonceKey>,
}

pub const INTERNAL_NONCE_FAMILIES: &[InternalNonceFamily] = &[
    InternalNonceFamily {
        interface: "aes-gcm-internal-nonce",
        variant: Some("aes128"),
        name: "AES-GCM",
        features: &[],
        key_len: 16,
        bad_key_len: 32,
        nonce_len: 12,
        tag_len: 16,
        budget: true,
        jwk: Some(InternalNonceJwk {
            algs: OctJwk {
                alg: "A128GCM",
                wrong_alg: "A256GCM",
            },
            import: |jwk, options| {
                Box::pin(aes_gcm_internal_nonce::import_key_jwk(
                    AesVariant::Aes128,
                    jwk,
                    options,
                ))
            },
        }),
        import: |raw, options| {
            Box::pin(aes_gcm_internal_nonce::import_key_raw(
                AesVariant::Aes128,
                raw,
                options,
            ))
        },
        generate: |options| {
            Box::pin(aes_gcm_internal_nonce::generate_key(
                AesVariant::Aes128,
                options,
            ))
        },
    },
    InternalNonceFamily {
        interface: "aes-gcm-internal-nonce",
        variant: Some("aes256"),
        name: "AES-GCM",
        features: &[],
        key_len: 32,
        bad_key_len: 16,
        nonce_len: 12,
        tag_len: 16,
        budget: true,
        jwk: Some(InternalNonceJwk {
            algs: OctJwk {
                alg: "A256GCM",
                wrong_alg: "A128GCM",
            },
            import: |jwk, options| {
                Box::pin(aes_gcm_internal_nonce::import_key_jwk(
                    AesVariant::Aes256,
                    jwk,
                    options,
                ))
            },
        }),
        import: |raw, options| {
            Box::pin(aes_gcm_internal_nonce::import_key_raw(
                AesVariant::Aes256,
                raw,
                options,
            ))
        },
        generate: |options| {
            Box::pin(aes_gcm_internal_nonce::generate_key(
                AesVariant::Aes256,
                options,
            ))
        },
    },
    InternalNonceFamily {
        interface: "xchacha20-poly1305-internal-nonce",
        variant: None,
        name: "XChaCha20-Poly1305",
        features: &[FEATURE_XCHACHA],
        key_len: 32,
        bad_key_len: 16,
        nonce_len: 24,
        // 24-byte random nonces have no enforced budget.
        budget: false,
        tag_len: 16,
        // The interface mints from raw material and generation only.
        jwk: None,
        import: |raw, options| {
            Box::pin(xchacha20_poly1305_internal_nonce::import_key_raw(
                raw, options,
            ))
        },
        generate: |options| Box::pin(xchacha20_poly1305_internal_nonce::generate_key(options)),
    },
];

/// The kind-uniform contract rules for internal-nonce families.
#[derive(Clone, Copy, PartialEq)]
pub enum InternalNonceArea {
    Getters,
    Export,
    RejectKey,
    Usage,
    /// Seal → open self-consistency, including the wire format's
    /// `nonce ‖ ciphertext ‖ tag` length at the row's facts.
    Roundtrip,
    Jwk,
}

impl InternalNonceArea {
    pub const ALL: &[InternalNonceArea] = &[
        InternalNonceArea::Getters,
        InternalNonceArea::Export,
        InternalNonceArea::RejectKey,
        InternalNonceArea::Usage,
        InternalNonceArea::Roundtrip,
        InternalNonceArea::Jwk,
    ];

    pub fn id(self) -> &'static str {
        match self {
            InternalNonceArea::Getters => "getters",
            InternalNonceArea::Export => "export",
            InternalNonceArea::RejectKey => "reject-key",
            InternalNonceArea::Usage => "usage",
            InternalNonceArea::Roundtrip => "roundtrip",
            InternalNonceArea::Jwk => "jwk",
        }
    }
}

impl InternalNonceFamily {
    pub fn case_id(&self, area: InternalNonceArea) -> String {
        contract_case_id(self.interface, self.variant, area.id())
    }

    /// The areas this row serves: every row runs the whole battery except
    /// `jwk` on an interface with no JWK minting path.
    pub fn areas(&self) -> impl Iterator<Item = InternalNonceArea> + '_ {
        InternalNonceArea::ALL
            .iter()
            .copied()
            .filter(|area| *area != InternalNonceArea::Jwk || self.jwk.is_some())
    }
}

pub async fn run_internal_nonce(
    family: &InternalNonceFamily,
    area: InternalNonceArea,
) -> Result<(), String> {
    match area {
        InternalNonceArea::Getters => internal_nonce_getters(family).await,
        InternalNonceArea::Export => internal_nonce_export(family).await,
        InternalNonceArea::RejectKey => internal_nonce_reject_key(family).await,
        InternalNonceArea::Usage => internal_nonce_usage(family).await,
        InternalNonceArea::Roundtrip => internal_nonce_roundtrip(family).await,
        InternalNonceArea::Jwk => internal_nonce_jwk_area(family).await,
    }
}

/// A key minted by each entry point reports the row's mint-bound facts,
/// including whether a nonce budget exists at all (its consumption is the
/// `internal_nonce_shape` probe's subject).
async fn internal_nonce_getters(family: &InternalNonceFamily) -> Result<(), String> {
    let imported =
        (family.import)(oct_key(family.key_len), mint::internal_nonce_options(false)).await;
    let generated = (family.generate)(mint::internal_nonce_options(false)).await;
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
            key.seals_remaining().is_some(),
            family.budget,
            &format!("{how} key seals-remaining presence"),
        )?;
    }
    Ok(())
}

/// The `extractable` getter reports the minted flag in both directions on
/// both minting paths, `export-key-raw` is gated by it, and import →
/// export is the identity.
async fn internal_nonce_export(family: &InternalNonceFamily) -> Result<(), String> {
    let raw = oct_key(family.key_len);
    let key = (family.import)(raw.clone(), mint::internal_nonce_options(true))
        .await
        .map_err(|e| describe("extractable import", &e))?;
    expect(key.extractable(), true, "extractable imported key's getter")?;
    let exported = key
        .export_key_raw()
        .await
        .map_err(|e| describe("export of an extractable import", &e))?;
    expect_bytes(&exported, &raw, "exported key material")?;

    let key = (family.generate)(mint::internal_nonce_options(true))
        .await
        .map_err(|e| describe("extractable generate", &e))?;
    let exported = key
        .export_key_raw()
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
            (family.import)(raw, mint::internal_nonce_options(false)).await,
        ),
        (
            "generated",
            (family.generate)(mint::internal_nonce_options(false)).await,
        ),
    ] {
        let key = key.map_err(|e| describe(&format!("non-extractable {how} mint"), &e))?;
        expect(
            key.extractable(),
            false,
            &format!("non-extractable {how} key's getter"),
        )?;
        expect_err(
            &format!("export-key-raw on a non-extractable {how} key"),
            ErrKind::NotExtractable,
            key.export_key_raw().await,
            "non-extractable key exported",
        )?;
    }
    Ok(())
}

/// Wrong-length key material — empty, and the row's `bad_key_len` — fails
/// `invalid-key` at import.
async fn internal_nonce_reject_key(family: &InternalNonceFamily) -> Result<(), String> {
    for len in [0, family.bad_key_len] {
        expect_err(
            &format!("import-key-raw ({len} bytes)"),
            ErrKind::InvalidKey,
            (family.import)(vec![0u8; len], mint::internal_nonce_options(false)).await,
            "wrong-length key material imported",
        )?;
    }
    Ok(())
}

/// The package-wide usage contract, per family: the zero-usage mint
/// refusal, per-operation enforcement in both grant directions, and the
/// usage getters reporting the recorded grants.
async fn internal_nonce_usage(family: &InternalNonceFamily) -> Result<(), String> {
    let raw = oct_key(family.key_len);
    expect_err(
        "zero-usage import-key-raw",
        ErrKind::NotPermitted,
        (family.import)(raw.clone(), InternalNonceKeyOptions::new()).await,
        "minted a key with no enabled usage",
    )?;

    let options = InternalNonceKeyOptions::new();
    options.can_seal(true);
    let seal_only = (family.import)(raw.clone(), options)
        .await
        .map_err(|e| describe("seal-only import-key-raw", &e))?;
    expect(seal_only.can_seal(), true, "seal-only key can-seal")?;
    expect(seal_only.can_open(), false, "seal-only key can-open")?;

    let plaintext = b"battery usage plaintext";
    let (sealed, fed) = in_seal(&seal_only, b"", plaintext, Schedule::Whole).await;
    fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
    let sealed = sealed.map_err(|e| describe("seal under a seal-only key", &e))?;
    let (refused, fed) = in_open(&seal_only, b"", &sealed, Schedule::Whole).await;
    fed.map_err(|e| format!("open input feeder: {e}"))?;
    expect_err(
        "open on a seal-only key",
        ErrKind::NotPermitted,
        refused,
        "seal-only key opened",
    )?;

    let options = InternalNonceKeyOptions::new();
    options.can_open(true);
    let open_only = (family.import)(raw, options)
        .await
        .map_err(|e| describe("open-only import-key-raw", &e))?;
    expect(open_only.can_seal(), false, "open-only key can-seal")?;
    expect(open_only.can_open(), true, "open-only key can-open")?;
    let (opened, fed) = in_open(&open_only, b"", &sealed, Schedule::Whole).await;
    fed.map_err(|e| format!("open input feeder: {e}"))?;
    let opened = opened.map_err(|e| describe("open under an open-only key", &e))?;
    expect_bytes(&opened, plaintext, "plaintext under an open-only key")?;
    let (refused, fed) = in_seal(&open_only, b"", plaintext, Schedule::Whole).await;
    fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
    expect_err(
        "seal on an open-only key",
        ErrKind::NotPermitted,
        refused,
        "open-only key sealed",
    )
}

/// Seal → open self-consistency at the row's facts: the sealed message
/// carries the wire format (`nonce ‖ ciphertext ‖ tag`) and opens back to
/// the plaintext under the same key and associated data.
async fn internal_nonce_roundtrip(family: &InternalNonceFamily) -> Result<(), String> {
    let key = (family.generate)(mint::internal_nonce_options(false))
        .await
        .map_err(|e| describe("generate-key", &e))?;
    let aad = b"battery roundtrip aad";
    let plaintext: Vec<u8> = (0..=255u8).cycle().take(3 * 16 + 5).collect();

    let (sealed, fed) = in_seal(&key, aad, &plaintext, Schedule::Straddle).await;
    fed.map_err(|e| format!("seal plaintext feeder: {e}"))?;
    let sealed = sealed.map_err(|e| describe("seal", &e))?;
    expect(
        sealed.len(),
        plaintext.len() + family.nonce_len + family.tag_len,
        "sealed length",
    )?;

    let (opened, fed) = in_open(&key, aad, &sealed, Schedule::Whole).await;
    fed.map_err(|e| format!("open sealed feeder: {e}"))?;
    let opened = opened.map_err(|e| describe("open", &e))?;
    expect_bytes(&opened, &plaintext, "round-tripped plaintext")
}

/// The oct-JWK contract, per family (the [`jwk`] script over
/// internal-nonce entry points).
async fn internal_nonce_jwk_area(family: &InternalNonceFamily) -> Result<(), String> {
    let jwk_row = family.jwk.as_ref().expect("jwk area on a JWK-less family");
    let (alg, wrong_alg) = (jwk_row.algs.alg, jwk_row.algs.wrong_alg);
    let raw = oct_key(family.key_len);
    let k = mint::b64url(&raw);

    let key = (jwk_row.import)(
        format!(r#"{{"kty":"oct","k":"{k}","alg":"{alg}"}}"#),
        mint::internal_nonce_options(true),
    )
    .await
    .map_err(|e| describe("import-key-jwk", &e))?;
    let exported = key
        .export_key_raw()
        .await
        .map_err(|e| describe("export-key-raw", &e))?;
    expect_bytes(&exported, &raw, "material from the JWK")?;
    let exported_jwk = key
        .export_key_jwk()
        .await
        .map_err(|e| describe("export-key-jwk", &e))?;
    if !exported_jwk.contains(&k)
        || !exported_jwk.contains("\"oct\"")
        || !exported_jwk.contains(alg)
    {
        return Err(format!(
            "exported JWK missing material members: {exported_jwk}"
        ));
    }
    let reimported = (jwk_row.import)(exported_jwk, mint::internal_nonce_options(true))
        .await
        .map_err(|e| describe("re-import of exported JWK", &e))?;
    let exported = reimported
        .export_key_raw()
        .await
        .map_err(|e| describe("export-key-raw after JWK re-import", &e))?;
    expect_bytes(&exported, &raw, "material after the JWK round trip")?;

    (jwk_row.import)(
        format!(r#"{{"kty":"oct","k":"{k}"}}"#),
        mint::internal_nonce_options(false),
    )
    .await
    .map_err(|e| describe("import-key-jwk (alg-less)", &e))?;
    expect_err(
        "import-key-jwk with another algorithm's alg",
        ErrKind::InvalidKey,
        (jwk_row.import)(
            format!(r#"{{"kty":"oct","k":"{k}","alg":"{wrong_alg}"}}"#),
            mint::internal_nonce_options(false),
        )
        .await,
        "imported a JWK bound to another algorithm",
    )?;

    let key = (family.import)(raw, mint::internal_nonce_options(false))
        .await
        .map_err(|e| describe("non-extractable import-key-raw", &e))?;
    expect_err(
        "export-key-jwk on a non-extractable key",
        ErrKind::NotExtractable,
        key.export_key_jwk().await,
        "non-extractable key exported",
    )
}

// ---------------------------------------------------------------------------
// Derive sources
// ---------------------------------------------------------------------------

/// One derive-source family: a minting interface whose secret feeds the
/// shared `derivation.derive-input` resource (an HKDF `ikm`, a PBKDF2
/// `password`, an X25519 agreement). The row's closure carries the whole
/// source-specific path — mint the source with the given grants and
/// produce an input from it — so the battery's grant matrix is
/// source-agnostic.
pub struct DeriveSourceFamily {
    pub interface: &'static str,
    pub features: &'static [&'static str],
    /// Mint the source with `(derive-bits, derive-key)` grants and
    /// produce a `derive-input` from it, reporting the source's own grant
    /// getters. A zero-grant call must fail at the mint (`not-permitted`).
    pub prepare: fn(bool, bool) -> MintFuture<PreparedSource>,
}

/// A minted source's grant getters and the input prepared from it.
pub struct PreparedSource {
    pub can_derive_bits: bool,
    pub can_derive_key: bool,
    pub input: DeriveInput,
}

pub const DERIVE_SOURCE_FAMILIES: &[DeriveSourceFamily] = &[
    DeriveSourceFamily {
        interface: "hkdf-sha2",
        features: &[],
        prepare: |bits, key| {
            Box::pin(async move {
                let ikm =
                    hkdf::import_ikm(vec![0x42u8; 32], mint::derive_options(bits, key)).await?;
                let (can_bits, can_key) = (ikm.can_derive_bits(), ikm.can_derive_key());
                let input = hkdf_sha2::prepare(
                    Sha2Variant::Sha256,
                    &ikm,
                    b"battery salt".to_vec(),
                    b"battery info".to_vec(),
                )
                .await?;
                Ok(PreparedSource {
                    can_derive_bits: can_bits,
                    can_derive_key: can_key,
                    input,
                })
            })
        },
    },
    DeriveSourceFamily {
        interface: "pbkdf2-sha2",
        features: &[],
        prepare: |bits, key| {
            Box::pin(async move {
                let password = pbkdf2::import_password(
                    b"battery password".to_vec(),
                    mint::derive_options(bits, key),
                )
                .await?;
                let (can_bits, can_key) = (password.can_derive_bits(), password.can_derive_key());
                let input = pbkdf2_sha2::prepare(
                    Sha2Variant::Sha256,
                    &password,
                    b"battery salt".to_vec(),
                    2,
                )
                .await?;
                Ok(PreparedSource {
                    can_derive_bits: can_bits,
                    can_derive_key: can_key,
                    input,
                })
            })
        },
    },
    DeriveSourceFamily {
        interface: "x25519",
        features: &[],
        prepare: |bits, key| {
            Box::pin(async move {
                let secret = x25519::import_secret_key_jwk(
                    mint::x25519_secret_jwk(
                        &unhex(mint::RFC7748_ALICE_X),
                        &unhex(mint::RFC7748_ALICE_D),
                    ),
                    mint::agreement_options(bits, key, false),
                )
                .await?;
                let (can_bits, can_key) = (secret.can_derive_bits(), secret.can_derive_key());
                let peer = x25519::import_public_key_raw(unhex(mint::RFC7748_BOB_X)).await?;
                let input = secret.agree(&peer).await?;
                Ok(PreparedSource {
                    can_derive_bits: can_bits,
                    can_derive_key: can_key,
                    input,
                })
            })
        },
    },
];

/// The kind-uniform contract rules for derive sources.
#[derive(Clone, Copy)]
pub enum DeriveArea {
    /// The grant matrix: the zero-grant mint refusal; the grants copying
    /// from source to input and gating exactly their operations; and the
    /// cap rule — an extractable key from a bits-less input is refused,
    /// because an exportable key is bits disclosure by other means.
    Grants,
}

impl DeriveArea {
    pub const ALL: &[DeriveArea] = &[DeriveArea::Grants];

    pub fn id(self) -> &'static str {
        match self {
            DeriveArea::Grants => "grants",
        }
    }
}

impl DeriveSourceFamily {
    pub fn case_id(&self, area: DeriveArea) -> String {
        contract_case_id(self.interface, None, area.id())
    }
}

pub async fn run_derive(family: &DeriveSourceFamily, area: DeriveArea) -> Result<(), String> {
    match area {
        DeriveArea::Grants => derive_grants(family).await,
    }
}

/// The derive grant matrix, per source (see [`DeriveArea::Grants`]).
async fn derive_grants(family: &DeriveSourceFamily) -> Result<(), String> {
    expect_err(
        "zero-grant mint",
        ErrKind::NotPermitted,
        (family.prepare)(false, false).await,
        "minted a source with no enabled grant",
    )?;

    let prepared = (family.prepare)(true, false)
        .await
        .map_err(|e| describe("bits-only mint", &e))?;
    expect(
        prepared.can_derive_bits,
        true,
        "bits-only source can-derive-bits",
    )?;
    expect(
        prepared.can_derive_key,
        false,
        "bits-only source can-derive-key",
    )?;
    expect(
        prepared.input.can_derive_bits(),
        true,
        "input copies can-derive-bits",
    )?;
    expect(
        prepared.input.can_derive_key(),
        false,
        "input copies can-derive-key",
    )?;
    prepared
        .input
        .derive_bits(Some(256))
        .await
        .map_err(|e| describe("derive-bits under the grant", &e))?;
    let options = AeadKeyOptions::new();
    options.can_seal(true);
    expect_err(
        "derive-key without the grant",
        ErrKind::NotPermitted,
        aes_gcm::derive_key(AesVariant::Aes256, &prepared.input, options).await,
        "minted a key from a key-less input",
    )?;

    let prepared = (family.prepare)(false, true)
        .await
        .map_err(|e| describe("key-only mint", &e))?;
    expect(
        prepared.can_derive_bits,
        false,
        "key-only source can-derive-bits",
    )?;
    expect(
        prepared.can_derive_key,
        true,
        "key-only source can-derive-key",
    )?;
    expect(
        prepared.input.can_derive_bits(),
        false,
        "input copies can-derive-bits",
    )?;
    expect(
        prepared.input.can_derive_key(),
        true,
        "input copies can-derive-key",
    )?;
    expect_err(
        "derive-bits without the grant",
        ErrKind::NotPermitted,
        prepared.input.derive_bits(Some(256)).await,
        "derived bits from a bits-less input",
    )?;
    let options = AeadKeyOptions::new();
    options.can_seal(true);
    options.extractable(true);
    expect_err(
        "extractable key from a bits-less input (the cap rule)",
        ErrKind::NotPermitted,
        aes_gcm::derive_key(AesVariant::Aes256, &prepared.input, options).await,
        "laundered bits through an extractable derived key",
    )?;
    let options = AeadKeyOptions::new();
    options.can_seal(true);
    let key = aes_gcm::derive_key(AesVariant::Aes256, &prepared.input, options)
        .await
        .map_err(|e| describe("non-extractable derive-key", &e))?;
    expect(key.extractable(), false, "derived key extractability")
}
