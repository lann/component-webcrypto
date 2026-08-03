//! The exported `lann:webcrypto` resources and key-minting functions.
//!
//! The cryptography itself lives in `lann-webcrypto-core`, shared verbatim
//! with the Wasmtime host; this module contributes only what is
//! guest-specific — stream plumbing, the exported resource types, and the
//! bindings glue converting the generated types to the core's.
//!
//! Byte `stream`s are the only bulk data path: incoming streams are drained
//! to completion (even when the operation resolves with an error, per the WIT
//! contract for `seal`/`open`), and outgoing streams are fed from a detached
//! task (`wit_bindgen::spawn`) after the export returns.

use std::cell::Cell;

use lann_webcrypto_core::{
    served_sha2, AeadKeyMaterial, AeadPolicy, AgreementPolicy, CipherKeyMaterial, CipherMode,
    CipherPolicy, InternalNoncePolicy, KwKeyMaterial, KwPolicy, MacKeyMaterial, MacPolicy,
    SigPublic, SigningKeyMaterial, SigningPolicy, UnwrapInputMaterial, WrapFormat,
    WrapInputMaterial, HMAC_NAME,
};

use crate::exports::lann::webcrypto::aead::{
    AeadKey as ExportedAeadKey, AeadKeyOptions as ExportedAeadKeyOptions, Guest as AeadGuest,
    GuestAeadKey, GuestAeadKeyOptions,
};
use crate::exports::lann::webcrypto::aead_internal_nonce::{
    Guest as AeadInternalNonceGuest, GuestInternalNonceKey, GuestInternalNonceKeyOptions,
    InternalNonceKey as ExportedInternalNonceKey,
    InternalNonceKeyOptions as ExportedInternalNonceKeyOptions,
};
use crate::exports::lann::webcrypto::aes_cbc::Guest as AesCbcGuest;
use crate::exports::lann::webcrypto::aes_ctr::Guest as AesCtrGuest;
use crate::exports::lann::webcrypto::aes_gcm::{AesVariant, Guest as AesGcmGuest};
use crate::exports::lann::webcrypto::aes_gcm_internal_nonce::Guest as AesGcmInternalNonceGuest;
use crate::exports::lann::webcrypto::aes_kw::Guest as AesKwGuest;
use crate::exports::lann::webcrypto::bytes::Guest as BytesGuest;
use crate::exports::lann::webcrypto::chacha20_poly1305::Guest as ChaChaPoly1305Guest;
use crate::exports::lann::webcrypto::cipher::{
    CipherKey as ExportedCipherKey, CipherKeyOptions as ExportedCipherKeyOptions,
    Guest as CipherGuest, GuestCipherKey, GuestCipherKeyOptions,
};
use crate::exports::lann::webcrypto::derivation::{
    self, Guest as DerivationGuest, GuestDeriveInput, GuestDeriveOptions,
};
use crate::exports::lann::webcrypto::digest::{self as digest, Guest as DigestGuest, GuestDigest};
use crate::exports::lann::webcrypto::ecdh::{EcdhVariant, Guest as EcdhGuest};
use crate::exports::lann::webcrypto::ecdsa_verify::{EcdsaVariant, Guest as EcdsaVerifyGuest};
use crate::exports::lann::webcrypto::ed25519_sign::Guest as Ed25519SignGuest;
use crate::exports::lann::webcrypto::ed25519_verify::Guest as Ed25519VerifyGuest;
use crate::exports::lann::webcrypto::hkdf::{self as hkdf_iface, Guest as HkdfGuest, GuestIkm};
use crate::exports::lann::webcrypto::hkdf_sha1::Guest as HkdfSha1Guest;
use crate::exports::lann::webcrypto::hkdf_sha2::Guest as HkdfSha2Guest;
use crate::exports::lann::webcrypto::hmac_sha1::Guest as HmacSha1Guest;
use crate::exports::lann::webcrypto::hmac_sha2::Guest as HmacSha2Guest;
use crate::exports::lann::webcrypto::key_agreement::{
    self as key_agreement_iface, Guest as KeyAgreementGuest, GuestAgreementKeyOptions,
    GuestPublicKey, GuestSecretKey,
};
use crate::exports::lann::webcrypto::key_wrap::{
    self as key_wrap_iface, Guest as KeyWrapGuest, GuestKwKey, GuestKwKeyOptions,
};
use crate::exports::lann::webcrypto::mac::{
    self, Guest as MacGuest, GuestMacKey, GuestMacKeyOptions,
};
use crate::exports::lann::webcrypto::pbkdf2::{
    self as pbkdf2_iface, Guest as Pbkdf2Guest, GuestPassword,
};
use crate::exports::lann::webcrypto::pbkdf2_sha1::Guest as Pbkdf2Sha1Guest;
use crate::exports::lann::webcrypto::pbkdf2_sha2::Guest as Pbkdf2Sha2Guest;
use crate::exports::lann::webcrypto::rsa_pss_verify::Guest as RsaPssVerifyGuest;
use crate::exports::lann::webcrypto::rsassa_pkcs1_v15_verify::{
    Guest as RsassaVerifyGuest, RsaVariant,
};
use crate::exports::lann::webcrypto::sha1_checked::Guest as Sha1CheckedGuest;
use crate::exports::lann::webcrypto::sha2::{Guest as Sha2Guest, Sha2Variant};
use crate::exports::lann::webcrypto::signature::{
    self as signature_iface, Guest as SignatureGuest, GuestSigningKey, GuestSigningKeyOptions,
    GuestVerifyingKey,
};
use crate::exports::lann::webcrypto::wrapping::{
    self as wrapping_iface, Guest as WrappingGuest, GuestUnwrapInput, GuestWrapInput,
};
use crate::exports::lann::webcrypto::x25519::Guest as X25519Guest;
use crate::exports::lann::webcrypto::xchacha20_poly1305::Guest as XChaChaPoly1305Guest;
use crate::exports::lann::webcrypto::xchacha20_poly1305_internal_nonce::Guest as XChachaInternalNonceGuest;
use crate::lann::webcrypto::types::Error;

pub struct Component;

// --- bindings glue -------------------------------------------------------------

lann_webcrypto_core::impl_conversions! {
    error: Error,
    extension: crate::lann::webcrypto::types::ExtensionError,
    sha2: Sha2Variant,
    aes: AesVariant,
    ecdsa: EcdsaVariant,
    ecdh: EcdhVariant,
    rsa: RsaVariant,
}

/// Unwrap an entropy result: the WASI random source backing the guest's
/// `getrandom` is always available, so a failure is unreachable.
fn rng_infallible<T>(result: Result<T, lann_webcrypto_core::RngError>) -> T {
    result.expect("WASI random source is always available")
}

// --- stream plumbing ---------------------------------------------------------

/// Drain an entire `stream<u8>` into a buffer, resolving once the stream ends
/// (its writer dropped).
///
/// If the buffer's allocation fails, the remainder of the stream is still
/// drained — and discarded — before the error is returned: the WIT contract
/// promises the input stream is fully consumed even when the call resolves
/// with an error, so the caller's writer always completes.
async fn drain_stream(
    mut data: wit_bindgen::StreamReader<u8>,
) -> Result<crate::buffer::Buffered, Error> {
    let mut out = Ok(crate::buffer::Buffered::new());
    loop {
        let (status, batch) = data.read(Vec::with_capacity(8 * 1024)).await;
        if let Ok(buffered) = &mut out {
            if buffered.extend(&batch).is_err() {
                out = Err(Error::Other(
                    "allocation failed buffering stream input".to_string(),
                ));
            }
        }
        if matches!(
            status,
            wit_bindgen::StreamResult::Dropped | wit_bindgen::StreamResult::Cancelled
        ) {
            break;
        }
    }
    out
}

/// Return `bytes` as a `stream<u8>`, fed by a detached task after the caller
/// returns the reader.
fn stream_of(bytes: Vec<u8>) -> wit_bindgen::StreamReader<u8> {
    let (mut tx, rx) = crate::wit_stream::new();
    wit_bindgen::spawn_local(async move {
        let _ = tx.write_all(bytes).await;
        drop(tx);
    });
    rx
}

// --- wrapping (the provider-held intermediates) ----------------------------------

impl WrappingGuest for Component {
    type WrapInput = WrapInput;
    type UnwrapInput = UnwrapInput;
}

/// An exported `wrapping.wrap-input`. The material sits in a `Cell` so the
/// consuming operation can move it out through its owned handle (wasm is
/// single-threaded); the handle itself is destroyed with the call, on
/// failure as on success.
pub struct WrapInput {
    material: Cell<Option<WrapInputMaterial>>,
}

impl WrapInput {
    fn handle(
        material: Result<WrapInputMaterial, lann_webcrypto_core::Error>,
    ) -> Result<wrapping_iface::WrapInput, Error> {
        Ok(wrapping_iface::WrapInput::new(Self {
            material: Cell::new(Some(material?)),
        }))
    }

    /// Move the material out of an owned handle: each intermediate is
    /// consumed by exactly one operation, so the cell is always full.
    fn take(handle: wrapping_iface::WrapInput) -> WrapInputMaterial {
        handle
            .get::<Self>()
            .material
            .take()
            .expect("an owned wrap-input handle is consumed exactly once")
    }
}

impl GuestWrapInput for WrapInput {}

/// An exported `wrapping.unwrap-input`. See [`WrapInput`] for the cell.
pub struct UnwrapInput {
    material: Cell<Option<UnwrapInputMaterial>>,
}

impl UnwrapInput {
    fn handle(
        material: Result<UnwrapInputMaterial, lann_webcrypto_core::Error>,
    ) -> Result<wrapping_iface::UnwrapInput, Error> {
        Ok(wrapping_iface::UnwrapInput::new(Self {
            material: Cell::new(Some(material?)),
        }))
    }

    /// Move the material out of an owned handle. See [`WrapInput::take`].
    fn take(handle: wrapping_iface::UnwrapInput) -> UnwrapInputMaterial {
        handle
            .get::<Self>()
            .material
            .take()
            .expect("an owned unwrap-input handle is consumed exactly once")
    }
}

impl GuestUnwrapInput for UnwrapInput {}

// --- key-wrap ----------------------------------------------------------------

impl KeyWrapGuest for Component {
    type KwKey = KwKey;
    type KwKeyOptions = KwKeyOptions;
}

/// An exported `kw-key-options`. See [`MacKeyOptions`].
pub struct KwKeyOptions {
    policy: Cell<KwPolicy>,
}

impl GuestKwKeyOptions for KwKeyOptions {
    fn new() -> Self {
        Self {
            policy: Cell::new(KwPolicy::default()),
        }
    }

    fn can_wrap(&self, allowed: bool) {
        self.policy.set(KwPolicy {
            wrap: allowed,
            ..self.policy.get()
        });
    }

    fn can_unwrap(&self, allowed: bool) {
        self.policy.set(KwPolicy {
            unwrap: allowed,
            ..self.policy.get()
        });
    }

    fn extractable(&self, allowed: bool) {
        self.policy.set(KwPolicy {
            extractable: allowed,
            ..self.policy.get()
        });
    }
}

/// An exported `key-wrap.kw-key`: the AES-KW key-encryption key.
pub struct KwKey {
    material: KwKeyMaterial,
}

impl GuestKwKey for KwKey {
    async fn wrap(&self, input: wrapping_iface::WrapInput) -> Result<Vec<u8>, Error> {
        Ok(self.material.wrap(WrapInput::take(input))?)
    }

    async fn unwrap(&self, wrapped: Vec<u8>) -> Result<wrapping_iface::UnwrapInput, Error> {
        UnwrapInput::handle(self.material.unwrap(&wrapped))
    }

    fn algorithm_name(&self) -> String {
        self.material.name().to_string()
    }

    fn algorithm_length(&self) -> u32 {
        self.material.length_bits()
    }

    fn extractable(&self) -> bool {
        self.material.extractable()
    }

    fn can_wrap(&self) -> bool {
        self.material.can_wrap()
    }

    fn can_unwrap(&self) -> bool {
        self.material.can_unwrap()
    }

    async fn to_wrap_input_raw(&self) -> Result<wrapping_iface::WrapInput, Error> {
        WrapInput::handle(
            self.material
                .export()
                .map(|raw| WrapInputMaterial::new(WrapFormat::Raw, raw)),
        )
    }

    async fn to_wrap_input_jwk(&self) -> Result<wrapping_iface::WrapInput, Error> {
        WrapInput::handle(
            self.material
                .export_jwk()
                .map(|jwk| WrapInputMaterial::new(WrapFormat::Jwk, jwk.into_bytes())),
        )
    }

    async fn export_key_raw(&self) -> Result<Vec<u8>, Error> {
        Ok(self.material.export()?)
    }

    async fn export_key_jwk(&self) -> Result<String, Error> {
        Ok(self.material.export_jwk()?)
    }
}

// --- aes-kw (key minting) --------------------------------------------------------

impl AesKwGuest for Component {
    async fn import_key_raw(
        variant: AesVariant,
        raw: Vec<u8>,
        options: key_wrap_iface::KwKeyOptions,
    ) -> Result<key_wrap_iface::KwKey, Error> {
        let policy = options.get::<KwKeyOptions>().policy.get();
        let material = KwKeyMaterial::import(variant.into(), raw, policy)?;
        Ok(key_wrap_iface::KwKey::new(KwKey { material }))
    }

    async fn import_key_jwk(
        variant: AesVariant,
        jwk: String,
        options: key_wrap_iface::KwKeyOptions,
    ) -> Result<key_wrap_iface::KwKey, Error> {
        let policy = options.get::<KwKeyOptions>().policy.get();
        let material = KwKeyMaterial::import_jwk(variant.into(), &jwk, policy)?;
        Ok(key_wrap_iface::KwKey::new(KwKey { material }))
    }

    async fn generate_key(
        variant: AesVariant,
        options: key_wrap_iface::KwKeyOptions,
    ) -> Result<key_wrap_iface::KwKey, Error> {
        let policy = options.get::<KwKeyOptions>().policy.get();
        let material = rng_infallible(KwKeyMaterial::generate(variant.into(), policy))?;
        Ok(key_wrap_iface::KwKey::new(KwKey { material }))
    }

    async fn derive_key(
        variant: AesVariant,
        input: derivation::DeriveInputBorrow<'_>,
        options: key_wrap_iface::KwKeyOptions,
    ) -> Result<key_wrap_iface::KwKey, Error> {
        let policy = options.get::<KwKeyOptions>().policy.get();
        let material = lann_webcrypto_core::derive_kw_key(
            variant.into(),
            &input.get::<DeriveInput>().material,
            policy,
        )?;
        Ok(key_wrap_iface::KwKey::new(KwKey { material }))
    }

    async fn unwrap_key_raw(
        variant: AesVariant,
        input: wrapping_iface::UnwrapInput,
        options: key_wrap_iface::KwKeyOptions,
    ) -> Result<key_wrap_iface::KwKey, Error> {
        let policy = options.get::<KwKeyOptions>().policy.get();
        let material =
            lann_webcrypto_core::unwrap_kw_key(variant.into(), UnwrapInput::take(input), policy)?;
        Ok(key_wrap_iface::KwKey::new(KwKey { material }))
    }

    async fn unwrap_key_jwk(
        variant: AesVariant,
        input: wrapping_iface::UnwrapInput,
        options: key_wrap_iface::KwKeyOptions,
    ) -> Result<key_wrap_iface::KwKey, Error> {
        let policy = options.get::<KwKeyOptions>().policy.get();
        let material = lann_webcrypto_core::unwrap_kw_key_jwk(
            variant.into(),
            UnwrapInput::take(input),
            policy,
        )?;
        Ok(key_wrap_iface::KwKey::new(KwKey { material }))
    }
}

// --- mac ---------------------------------------------------------------------

impl MacGuest for Component {
    type MacKey = MacKey;
    type MacKeyOptions = MacKeyOptions;
}

/// The shared shape of every exported `*-options` resource: an all-deny
/// policy held in a `Cell` (the setters take `&self`; wasm is
/// single-threaded), with one setter per WIT method writing one boolean
/// policy field, listed as `method => policy field` rows.
macro_rules! options_resource {
    (
        $(#[$meta:meta])*
        pub struct $ty:ident($policy:path): $guest:ident {
            $($method:ident => $field:ident),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        pub struct $ty {
            policy: Cell<$policy>,
        }

        impl $guest for $ty {
            fn new() -> Self {
                Self {
                    policy: Cell::new(<$policy>::default()),
                }
            }

            $(
                fn $method(&self, allowed: bool) {
                    let mut policy = self.policy.get();
                    policy.$field = allowed;
                    self.policy.set(policy);
                }
            )+
        }
    };
}

options_resource! {
    /// An exported `mac-key-options`: mint-time policy under construction.
    pub struct MacKeyOptions(MacPolicy): GuestMacKeyOptions {
        can_sign => sign,
        can_verify => verify,
        extractable => extractable,
    }
}

/// An exported `mac-key`: the shared core's HMAC key material.
pub struct MacKey {
    material: MacKeyMaterial,
}

impl GuestMacKey for MacKey {
    async fn sign(&self, data: wit_bindgen::StreamReader<u8>) -> Result<Vec<u8>, Error> {
        // Buffer the whole stream, then fold it into the HMAC state; the
        // result is chunking-invariant either way.
        let bytes = drain_stream(data).await?;
        Ok(self.material.sign(&bytes)?)
    }

    async fn verify(&self, data: wit_bindgen::StreamReader<u8>, tag: Vec<u8>) -> Result<(), Error> {
        let bytes = drain_stream(data).await?;
        Ok(self.material.verify(&bytes, &tag)?)
    }

    fn algorithm_name(&self) -> String {
        HMAC_NAME.to_string()
    }

    fn algorithm_hash(&self) -> Option<String> {
        Some(self.material.hash_name().to_string())
    }

    fn algorithm_length(&self) -> u32 {
        self.material.length_bits()
    }

    fn extractable(&self) -> bool {
        self.material.extractable()
    }

    fn can_sign(&self) -> bool {
        self.material.can_sign()
    }

    fn can_verify(&self) -> bool {
        self.material.can_verify()
    }

    async fn export_key_raw(&self) -> Result<Vec<u8>, Error> {
        Ok(self.material.export()?)
    }

    async fn export_key_jwk(&self) -> Result<String, Error> {
        Ok(self.material.export_jwk()?)
    }

    async fn to_wrap_input_raw(&self) -> Result<wrapping_iface::WrapInput, Error> {
        WrapInput::handle(
            self.material
                .export()
                .map(|raw| WrapInputMaterial::new(WrapFormat::Raw, raw)),
        )
    }

    async fn to_wrap_input_jwk(&self) -> Result<wrapping_iface::WrapInput, Error> {
        WrapInput::handle(
            self.material
                .export_jwk()
                .map(|jwk| WrapInputMaterial::new(WrapFormat::Jwk, jwk.into_bytes())),
        )
    }
}

// --- aead --------------------------------------------------------------------

impl AeadGuest for Component {
    type AeadKey = AeadKey;
    type AeadKeyOptions = AeadKeyOptions;
}

options_resource! {
    /// An exported `aead-key-options`. See [`MacKeyOptions`].
    pub struct AeadKeyOptions(AeadPolicy): GuestAeadKeyOptions {
        can_seal => seal,
        can_open => open,
        can_wrap => wrap,
        can_unwrap => unwrap,
        extractable => extractable,
    }
}

/// An exported `aead-key`: the shared core's AEAD key material.
pub struct AeadKey {
    material: AeadKeyMaterial,
}

impl GuestAeadKey for AeadKey {
    fn nonce_size(&self) -> u32 {
        self.material.nonce_len() as u32
    }

    fn tag_size(&self) -> u32 {
        self.material.tag_len() as u32
    }

    async fn seal(
        &self,
        nonce: Vec<u8>,
        aad: Vec<u8>,
        tag_size: Option<u8>,
        plaintext: wit_bindgen::StreamReader<u8>,
    ) -> Result<wit_bindgen::StreamReader<u8>, Error> {
        let msg = drain_stream(plaintext).await?;
        Ok(stream_of(self.material.seal(&nonce, &aad, tag_size, &msg)?))
    }

    async fn open(
        &self,
        nonce: Vec<u8>,
        aad: Vec<u8>,
        tag_size: Option<u8>,
        ciphertext: wit_bindgen::StreamReader<u8>,
    ) -> Result<wit_bindgen::StreamReader<u8>, Error> {
        // Like `seal`: fully drain the input first. Buffering the whole
        // message is inherent to `open`: no unverified plaintext may be
        // observable.
        let msg = drain_stream(ciphertext).await?;
        Ok(stream_of(self.material.open(&nonce, &aad, tag_size, &msg)?))
    }

    fn algorithm_name(&self) -> String {
        self.material.name().to_string()
    }

    fn algorithm_length(&self) -> u32 {
        self.material.length_bits()
    }

    fn extractable(&self) -> bool {
        self.material.extractable()
    }

    fn can_seal(&self) -> bool {
        self.material.can_seal()
    }

    fn can_open(&self) -> bool {
        self.material.can_open()
    }

    fn can_wrap(&self) -> bool {
        self.material.can_wrap()
    }

    fn can_unwrap(&self) -> bool {
        self.material.can_unwrap()
    }

    async fn wrap(
        &self,
        nonce: Vec<u8>,
        aad: Vec<u8>,
        tag_size: Option<u8>,
        input: wrapping_iface::WrapInput,
    ) -> Result<Vec<u8>, Error> {
        Ok(self
            .material
            .wrap(&nonce, &aad, tag_size, WrapInput::take(input))?)
    }

    async fn unwrap(
        &self,
        nonce: Vec<u8>,
        aad: Vec<u8>,
        tag_size: Option<u8>,
        wrapped: Vec<u8>,
    ) -> Result<wrapping_iface::UnwrapInput, Error> {
        UnwrapInput::handle(
            self.material
                .unwrap_wrapped(&nonce, &aad, tag_size, &wrapped),
        )
    }

    async fn to_wrap_input_raw(&self) -> Result<wrapping_iface::WrapInput, Error> {
        WrapInput::handle(
            self.material
                .export()
                .map(|raw| WrapInputMaterial::new(WrapFormat::Raw, raw)),
        )
    }

    async fn to_wrap_input_jwk(&self) -> Result<wrapping_iface::WrapInput, Error> {
        WrapInput::handle(
            self.material
                .export_jwk()
                .map(|jwk| WrapInputMaterial::new(WrapFormat::Jwk, jwk.into_bytes())),
        )
    }

    async fn export_key_raw(&self) -> Result<Vec<u8>, Error> {
        Ok(self.material.export()?)
    }

    async fn export_key_jwk(&self) -> Result<String, Error> {
        Ok(self.material.export_jwk()?)
    }
}

// --- digest --------------------------------------------------------------------

impl DigestGuest for Component {
    type Digest = Digest;
}

/// An exported `digest`: no key material, just the algorithm it is bound
/// to (a SHA-2 variant, or checked SHA-1 in a collision posture).
/// `compute` is one-shot and stateless per call, so the resource is
/// reusable.
pub struct Digest {
    variant: lann_webcrypto_core::DigestKind,
}

impl GuestDigest for Digest {
    async fn compute(&self, data: wit_bindgen::StreamReader<u8>) -> Result<Vec<u8>, Error> {
        // Buffer the whole stream, then hash it; the result is
        // chunking-invariant either way. Besides the buffering itself,
        // the only failure is checked SHA-1's `collision-detected` in
        // the rejecting posture.
        let bytes = drain_stream(data).await?;
        Ok(self.variant.digest(&bytes)?)
    }

    fn algorithm_name(&self) -> String {
        self.variant.hash_name().to_string()
    }
}

// --- bytes ---------------------------------------------------------------------

impl BytesGuest for Component {
    fn constant_time_equal(a: Vec<u8>, b: Vec<u8>) -> bool {
        lann_webcrypto_core::constant_time_equal(&a, &b)
    }
}

// --- sha2 (digest minting) ---------------------------------------------------

impl Sha2Guest for Component {
    fn make_digest(variant: Sha2Variant) -> Result<digest::Digest, Error> {
        let variant = served_sha2(variant.into())?;
        Ok(digest::Digest::new(Digest {
            variant: lann_webcrypto_core::DigestKind::Sha2(variant),
        }))
    }
}

// --- sha1-checked (digest minting) ---------------------------------------------

impl Sha1CheckedGuest for Component {
    fn make_rejecting_digest() -> Result<digest::Digest, Error> {
        Ok(digest::Digest::new(Digest {
            variant: lann_webcrypto_core::DigestKind::Sha1Checked(
                lann_webcrypto_core::Sha1Posture::Reject,
            ),
        }))
    }

    fn make_mitigating_digest() -> Result<digest::Digest, Error> {
        Ok(digest::Digest::new(Digest {
            variant: lann_webcrypto_core::DigestKind::Sha1Checked(
                lann_webcrypto_core::Sha1Posture::Mitigate,
            ),
        }))
    }
}

// --- hmac-sha2 (key minting) -----------------------------------------------------

impl HmacSha2Guest for Component {
    async fn import_key_raw(
        variant: Sha2Variant,
        raw: Vec<u8>,
        options: mac::MacKeyOptions,
    ) -> Result<mac::MacKey, Error> {
        let policy = options.get::<MacKeyOptions>().policy.get();
        let material = MacKeyMaterial::import(variant.into(), raw, policy)?;
        Ok(mac::MacKey::new(MacKey { material }))
    }

    async fn import_key_jwk(
        variant: Sha2Variant,
        jwk: String,
        options: mac::MacKeyOptions,
    ) -> Result<mac::MacKey, Error> {
        let policy = options.get::<MacKeyOptions>().policy.get();
        let material = MacKeyMaterial::import_jwk(variant.into(), &jwk, policy)?;
        Ok(mac::MacKey::new(MacKey { material }))
    }

    async fn generate_key(
        variant: Sha2Variant,
        length: Option<u32>,
        options: mac::MacKeyOptions,
    ) -> Result<mac::MacKey, Error> {
        let policy = options.get::<MacKeyOptions>().policy.get();
        let material = rng_infallible(MacKeyMaterial::generate(variant.into(), length, policy))?;
        Ok(mac::MacKey::new(MacKey { material }))
    }

    async fn derive_key(
        variant: Sha2Variant,
        input: derivation::DeriveInputBorrow<'_>,
        length: Option<u32>,
        options: mac::MacKeyOptions,
    ) -> Result<mac::MacKey, Error> {
        let policy = options.get::<MacKeyOptions>().policy.get();
        let material = lann_webcrypto_core::derive_mac_key(
            &input.get::<DeriveInput>().material,
            variant.into(),
            length,
            policy,
        )?;
        Ok(mac::MacKey::new(MacKey { material }))
    }

    async fn unwrap_key_raw(
        variant: Sha2Variant,
        input: wrapping_iface::UnwrapInput,
        options: mac::MacKeyOptions,
    ) -> Result<mac::MacKey, Error> {
        let policy = options.get::<MacKeyOptions>().policy.get();
        let material =
            lann_webcrypto_core::unwrap_mac_key(variant.into(), UnwrapInput::take(input), policy)?;
        Ok(mac::MacKey::new(MacKey { material }))
    }

    async fn unwrap_key_jwk(
        variant: Sha2Variant,
        input: wrapping_iface::UnwrapInput,
        options: mac::MacKeyOptions,
    ) -> Result<mac::MacKey, Error> {
        let policy = options.get::<MacKeyOptions>().policy.get();
        let material = lann_webcrypto_core::unwrap_mac_key_jwk(
            variant.into(),
            UnwrapInput::take(input),
            policy,
        )?;
        Ok(mac::MacKey::new(MacKey { material }))
    }
}

impl HmacSha1Guest for Component {
    async fn import_key_raw(
        raw: Vec<u8>,
        options: mac::MacKeyOptions,
    ) -> Result<mac::MacKey, Error> {
        let policy = options.get::<MacKeyOptions>().policy.get();
        let material = MacKeyMaterial::import_sha1(raw, policy)?;
        Ok(mac::MacKey::new(MacKey { material }))
    }

    async fn import_key_jwk(
        jwk: String,
        options: mac::MacKeyOptions,
    ) -> Result<mac::MacKey, Error> {
        let policy = options.get::<MacKeyOptions>().policy.get();
        let material = MacKeyMaterial::import_jwk_sha1(&jwk, policy)?;
        Ok(mac::MacKey::new(MacKey { material }))
    }

    async fn generate_key(
        length: Option<u32>,
        options: mac::MacKeyOptions,
    ) -> Result<mac::MacKey, Error> {
        let policy = options.get::<MacKeyOptions>().policy.get();
        let material = rng_infallible(MacKeyMaterial::generate_sha1(length, policy))?;
        Ok(mac::MacKey::new(MacKey { material }))
    }

    async fn derive_key(
        input: derivation::DeriveInputBorrow<'_>,
        length: Option<u32>,
        options: mac::MacKeyOptions,
    ) -> Result<mac::MacKey, Error> {
        let policy = options.get::<MacKeyOptions>().policy.get();
        let material = lann_webcrypto_core::derive_mac_key_sha1(
            &input.get::<DeriveInput>().material,
            length,
            policy,
        )?;
        Ok(mac::MacKey::new(MacKey { material }))
    }

    async fn unwrap_key_raw(
        input: wrapping_iface::UnwrapInput,
        options: mac::MacKeyOptions,
    ) -> Result<mac::MacKey, Error> {
        let policy = options.get::<MacKeyOptions>().policy.get();
        let material = lann_webcrypto_core::unwrap_mac_key_sha1(UnwrapInput::take(input), policy)?;
        Ok(mac::MacKey::new(MacKey { material }))
    }

    async fn unwrap_key_jwk(
        input: wrapping_iface::UnwrapInput,
        options: mac::MacKeyOptions,
    ) -> Result<mac::MacKey, Error> {
        let policy = options.get::<MacKeyOptions>().policy.get();
        let material =
            lann_webcrypto_core::unwrap_mac_key_jwk_sha1(UnwrapInput::take(input), policy)?;
        Ok(mac::MacKey::new(MacKey { material }))
    }
}

impl HkdfSha1Guest for Component {
    async fn prepare(
        input: hkdf_iface::IkmBorrow<'_>,
        salt: Vec<u8>,
        info: Vec<u8>,
    ) -> Result<derivation::DeriveInput, Error> {
        let material = lann_webcrypto_core::DeriveInputMaterial::prepare_sha1(
            &input.get::<Ikm>().material,
            &salt,
            info,
        )?;
        Ok(derivation::DeriveInput::new(DeriveInput { material }))
    }

    async fn prepare_from(
        input: derivation::DeriveInputBorrow<'_>,
        salt: Vec<u8>,
        info: Vec<u8>,
    ) -> Result<derivation::DeriveInput, Error> {
        let material = lann_webcrypto_core::DeriveInputMaterial::prepare_from_sha1(
            &input.get::<DeriveInput>().material,
            &salt,
            info,
        )?;
        Ok(derivation::DeriveInput::new(DeriveInput { material }))
    }
}

impl Pbkdf2Sha1Guest for Component {
    async fn prepare(
        input: pbkdf2_iface::PasswordBorrow<'_>,
        salt: Vec<u8>,
        iterations: u32,
    ) -> Result<derivation::DeriveInput, Error> {
        let material = lann_webcrypto_core::DeriveInputMaterial::prepare_pbkdf2_sha1(
            &input.get::<Password>().material,
            salt,
            iterations,
        )?;
        Ok(derivation::DeriveInput::new(DeriveInput { material }))
    }
}

// --- derivation & hkdf ---------------------------------------------------------

impl DerivationGuest for Component {
    type DeriveOptions = DeriveOptions;
    type DeriveInput = DeriveInput;
}

options_resource! {
    /// An exported `derive-options`. See [`MacKeyOptions`].
    pub struct DeriveOptions(lann_webcrypto_core::DerivePolicy): GuestDeriveOptions {
        can_derive_bits => derive_bits,
        can_derive_key => derive_key,
    }
}

/// An exported `derive-input`: the shared core's parameterized derivation
/// (run eagerly at `prepare` — the PRK, not the base secret).
pub struct DeriveInput {
    material: lann_webcrypto_core::DeriveInputMaterial,
}

impl GuestDeriveInput for DeriveInput {
    fn can_derive_bits(&self) -> bool {
        self.material.policy().derive_bits
    }

    fn can_derive_key(&self) -> bool {
        self.material.policy().derive_key
    }

    async fn derive_bits(&self, length: Option<u32>) -> Result<Vec<u8>, Error> {
        Ok(self.material.derive_bits(length)?.to_vec())
    }
}

impl HkdfGuest for Component {
    type Ikm = Ikm;

    async fn import_ikm(
        raw: Vec<u8>,
        options: derivation::DeriveOptions,
    ) -> Result<hkdf_iface::Ikm, Error> {
        let policy = options.get::<DeriveOptions>().policy.get();
        let material = lann_webcrypto_core::IkmMaterial::import(raw, policy)?;
        Ok(hkdf_iface::Ikm::new(Ikm { material }))
    }

    async fn unwrap_ikm(
        input: wrapping_iface::UnwrapInput,
        options: derivation::DeriveOptions,
    ) -> Result<hkdf_iface::Ikm, Error> {
        let policy = options.get::<DeriveOptions>().policy.get();
        let material = lann_webcrypto_core::unwrap_ikm(UnwrapInput::take(input), policy)?;
        Ok(hkdf_iface::Ikm::new(Ikm { material }))
    }
}

impl HkdfSha2Guest for Component {
    async fn prepare(
        variant: Sha2Variant,
        input: hkdf_iface::IkmBorrow<'_>,
        salt: Vec<u8>,
        info: Vec<u8>,
    ) -> Result<derivation::DeriveInput, Error> {
        let material = lann_webcrypto_core::DeriveInputMaterial::prepare(
            variant.into(),
            &input.get::<Ikm>().material,
            &salt,
            info,
        )?;
        Ok(derivation::DeriveInput::new(DeriveInput { material }))
    }

    async fn prepare_from(
        variant: Sha2Variant,
        input: derivation::DeriveInputBorrow<'_>,
        salt: Vec<u8>,
        info: Vec<u8>,
    ) -> Result<derivation::DeriveInput, Error> {
        let material = lann_webcrypto_core::DeriveInputMaterial::prepare_from(
            variant.into(),
            &input.get::<DeriveInput>().material,
            &salt,
            info,
        )?;
        Ok(derivation::DeriveInput::new(DeriveInput { material }))
    }
}

/// An exported `hkdf.ikm`: the shared core's input keying material.
pub struct Ikm {
    material: lann_webcrypto_core::IkmMaterial,
}

impl GuestIkm for Ikm {
    fn can_derive_bits(&self) -> bool {
        self.material.policy().derive_bits
    }

    fn can_derive_key(&self) -> bool {
        self.material.policy().derive_key
    }
}

impl Pbkdf2Guest for Component {
    type Password = Password;

    async fn import_password(
        raw: Vec<u8>,
        options: derivation::DeriveOptions,
    ) -> Result<pbkdf2_iface::Password, Error> {
        let policy = options.get::<DeriveOptions>().policy.get();
        let material = lann_webcrypto_core::PasswordMaterial::import(raw, policy)?;
        Ok(pbkdf2_iface::Password::new(Password { material }))
    }

    async fn unwrap_password(
        input: wrapping_iface::UnwrapInput,
        options: derivation::DeriveOptions,
    ) -> Result<pbkdf2_iface::Password, Error> {
        let policy = options.get::<DeriveOptions>().policy.get();
        let material = lann_webcrypto_core::unwrap_password(UnwrapInput::take(input), policy)?;
        Ok(pbkdf2_iface::Password::new(Password { material }))
    }
}

impl Pbkdf2Sha2Guest for Component {
    async fn prepare(
        variant: Sha2Variant,
        input: pbkdf2_iface::PasswordBorrow<'_>,
        salt: Vec<u8>,
        iterations: u32,
    ) -> Result<derivation::DeriveInput, Error> {
        let material = lann_webcrypto_core::DeriveInputMaterial::prepare_pbkdf2(
            variant.into(),
            &input.get::<Password>().material,
            salt,
            iterations,
        )?;
        Ok(derivation::DeriveInput::new(DeriveInput { material }))
    }
}

/// An exported `pbkdf2.password`: the shared core's password material.
pub struct Password {
    material: lann_webcrypto_core::PasswordMaterial,
}

impl GuestPassword for Password {
    fn can_derive_bits(&self) -> bool {
        self.material.policy().derive_bits
    }

    fn can_derive_key(&self) -> bool {
        self.material.policy().derive_key
    }
}

// --- key-agreement, x25519 & ecdh -------------------------------------------------

impl KeyAgreementGuest for Component {
    type AgreementKeyOptions = AgreementKeyOptions;
    type PublicKey = AgreementPublicKey;
    type SecretKey = AgreementSecretKey;
}

options_resource! {
    /// An exported `agreement-key-options`. See [`MacKeyOptions`].
    pub struct AgreementKeyOptions(AgreementPolicy): GuestAgreementKeyOptions {
        can_derive_bits => derive_bits,
        can_derive_key => derive_key,
        extractable => extractable,
    }
}

/// An exported `key-agreement.public-key`: public material only.
pub struct AgreementPublicKey {
    material: lann_webcrypto_core::AgreementPublicMaterial,
}

impl GuestPublicKey for AgreementPublicKey {
    fn algorithm_name(&self) -> String {
        self.material.name().to_string()
    }

    async fn export_key_raw(&self) -> Result<Vec<u8>, Error> {
        Ok(self.material.export())
    }

    async fn export_key_jwk(&self) -> Result<String, Error> {
        Ok(self.material.export_jwk())
    }

    async fn export_key_spki(&self) -> Result<Vec<u8>, Error> {
        Ok(self.material.export_spki())
    }
}

/// An exported `key-agreement.secret-key`: the shared core's agreement
/// secret (X25519 or ECDH; both class B — see the README's classification
/// table).
pub struct AgreementSecretKey {
    material: lann_webcrypto_core::AgreementSecretMaterial,
}

impl GuestSecretKey for AgreementSecretKey {
    async fn agree(
        &self,
        peer: key_agreement_iface::PublicKeyBorrow<'_>,
    ) -> Result<derivation::DeriveInput, Error> {
        let material = self
            .material
            .agree(&peer.get::<AgreementPublicKey>().material)?;
        Ok(derivation::DeriveInput::new(DeriveInput { material }))
    }

    fn algorithm_name(&self) -> String {
        self.material.name().to_string()
    }

    fn can_derive_bits(&self) -> bool {
        self.material.policy().derive_bits
    }

    fn can_derive_key(&self) -> bool {
        self.material.policy().derive_key
    }

    fn extractable(&self) -> bool {
        self.material.policy().extractable
    }

    async fn export_key_jwk(&self) -> Result<String, Error> {
        Ok(self.material.export_jwk()?)
    }

    async fn export_key_pkcs8(&self) -> Result<Vec<u8>, Error> {
        Ok(self.material.export_pkcs8()?)
    }

    async fn to_wrap_input_jwk(&self) -> Result<wrapping_iface::WrapInput, Error> {
        WrapInput::handle(
            self.material
                .export_jwk()
                .map(|jwk| WrapInputMaterial::new(WrapFormat::Jwk, jwk.into_bytes())),
        )
    }

    async fn to_wrap_input_pkcs8(&self) -> Result<wrapping_iface::WrapInput, Error> {
        WrapInput::handle(
            self.material
                .export_pkcs8()
                .map(|der| WrapInputMaterial::new(WrapFormat::Pkcs8, der)),
        )
    }
}

impl X25519Guest for Component {
    async fn import_public_key_raw(raw: Vec<u8>) -> Result<key_agreement_iface::PublicKey, Error> {
        let material = lann_webcrypto_core::AgreementPublicMaterial::import_x25519(&raw)?;
        Ok(key_agreement_iface::PublicKey::new(AgreementPublicKey {
            material,
        }))
    }

    async fn import_public_key_spki(
        spki: Vec<u8>,
    ) -> Result<key_agreement_iface::PublicKey, Error> {
        let material = lann_webcrypto_core::AgreementPublicMaterial::import_x25519_spki(&spki)?;
        Ok(key_agreement_iface::PublicKey::new(AgreementPublicKey {
            material,
        }))
    }

    async fn import_public_key_jwk(jwk: String) -> Result<key_agreement_iface::PublicKey, Error> {
        let material = lann_webcrypto_core::AgreementPublicMaterial::import_x25519_jwk(&jwk)?;
        Ok(key_agreement_iface::PublicKey::new(AgreementPublicKey {
            material,
        }))
    }

    async fn import_secret_key_pkcs8(
        pkcs8: Vec<u8>,
        options: key_agreement_iface::AgreementKeyOptions,
    ) -> Result<key_agreement_iface::SecretKey, Error> {
        let policy = options.get::<AgreementKeyOptions>().policy.get();
        let material =
            lann_webcrypto_core::AgreementSecretMaterial::import_x25519_pkcs8(&pkcs8, policy)?;
        Ok(key_agreement_iface::SecretKey::new(AgreementSecretKey {
            material,
        }))
    }

    async fn import_secret_key_jwk(
        jwk: String,
        options: key_agreement_iface::AgreementKeyOptions,
    ) -> Result<key_agreement_iface::SecretKey, Error> {
        let policy = options.get::<AgreementKeyOptions>().policy.get();
        let material =
            lann_webcrypto_core::AgreementSecretMaterial::import_x25519_jwk(&jwk, policy)?;
        Ok(key_agreement_iface::SecretKey::new(AgreementSecretKey {
            material,
        }))
    }

    async fn generate_key(
        options: key_agreement_iface::AgreementKeyOptions,
    ) -> Result<
        (
            key_agreement_iface::SecretKey,
            key_agreement_iface::PublicKey,
        ),
        Error,
    > {
        let policy = options.get::<AgreementKeyOptions>().policy.get();
        let (secret, public) =
            rng_infallible(lann_webcrypto_core::AgreementSecretMaterial::generate_x25519(policy))?;
        Ok((
            key_agreement_iface::SecretKey::new(AgreementSecretKey { material: secret }),
            key_agreement_iface::PublicKey::new(AgreementPublicKey { material: public }),
        ))
    }

    async fn unwrap_secret_key_jwk(
        input: wrapping_iface::UnwrapInput,
        options: key_agreement_iface::AgreementKeyOptions,
    ) -> Result<key_agreement_iface::SecretKey, Error> {
        let policy = options.get::<AgreementKeyOptions>().policy.get();
        let material =
            lann_webcrypto_core::unwrap_x25519_secret_key_jwk(UnwrapInput::take(input), policy)?;
        Ok(key_agreement_iface::SecretKey::new(AgreementSecretKey {
            material,
        }))
    }

    async fn unwrap_secret_key_pkcs8(
        input: wrapping_iface::UnwrapInput,
        options: key_agreement_iface::AgreementKeyOptions,
    ) -> Result<key_agreement_iface::SecretKey, Error> {
        let policy = options.get::<AgreementKeyOptions>().policy.get();
        let material =
            lann_webcrypto_core::unwrap_x25519_secret_key_pkcs8(UnwrapInput::take(input), policy)?;
        Ok(key_agreement_iface::SecretKey::new(AgreementSecretKey {
            material,
        }))
    }
}

impl EcdhGuest for Component {
    async fn import_public_key_raw(
        variant: EcdhVariant,
        raw: Vec<u8>,
    ) -> Result<key_agreement_iface::PublicKey, Error> {
        let material =
            lann_webcrypto_core::AgreementPublicMaterial::import_ecdh(variant.into(), &raw)?;
        Ok(key_agreement_iface::PublicKey::new(AgreementPublicKey {
            material,
        }))
    }

    async fn import_public_key_spki(
        variant: EcdhVariant,
        spki: Vec<u8>,
    ) -> Result<key_agreement_iface::PublicKey, Error> {
        let material =
            lann_webcrypto_core::AgreementPublicMaterial::import_ecdh_spki(variant.into(), &spki)?;
        Ok(key_agreement_iface::PublicKey::new(AgreementPublicKey {
            material,
        }))
    }

    async fn import_public_key_jwk(
        variant: EcdhVariant,
        jwk: String,
    ) -> Result<key_agreement_iface::PublicKey, Error> {
        let material =
            lann_webcrypto_core::AgreementPublicMaterial::import_ecdh_jwk(variant.into(), &jwk)?;
        Ok(key_agreement_iface::PublicKey::new(AgreementPublicKey {
            material,
        }))
    }

    async fn import_secret_key_jwk(
        variant: EcdhVariant,
        jwk: String,
        options: key_agreement_iface::AgreementKeyOptions,
    ) -> Result<key_agreement_iface::SecretKey, Error> {
        let policy = options.get::<AgreementKeyOptions>().policy.get();
        let material = lann_webcrypto_core::AgreementSecretMaterial::import_ecdh_jwk(
            variant.into(),
            &jwk,
            policy,
        )?;
        Ok(key_agreement_iface::SecretKey::new(AgreementSecretKey {
            material,
        }))
    }

    async fn import_secret_key_pkcs8(
        variant: EcdhVariant,
        pkcs8: Vec<u8>,
        options: key_agreement_iface::AgreementKeyOptions,
    ) -> Result<key_agreement_iface::SecretKey, Error> {
        let policy = options.get::<AgreementKeyOptions>().policy.get();
        let material = lann_webcrypto_core::AgreementSecretMaterial::import_ecdh_pkcs8(
            variant.into(),
            &pkcs8,
            policy,
        )?;
        Ok(key_agreement_iface::SecretKey::new(AgreementSecretKey {
            material,
        }))
    }

    async fn generate_key(
        variant: EcdhVariant,
        options: key_agreement_iface::AgreementKeyOptions,
    ) -> Result<
        (
            key_agreement_iface::SecretKey,
            key_agreement_iface::PublicKey,
        ),
        Error,
    > {
        let policy = options.get::<AgreementKeyOptions>().policy.get();
        let (secret, public) = rng_infallible(
            lann_webcrypto_core::AgreementSecretMaterial::generate_ecdh(variant.into(), policy),
        )?;
        Ok((
            key_agreement_iface::SecretKey::new(AgreementSecretKey { material: secret }),
            key_agreement_iface::PublicKey::new(AgreementPublicKey { material: public }),
        ))
    }

    async fn unwrap_secret_key_jwk(
        variant: EcdhVariant,
        input: wrapping_iface::UnwrapInput,
        options: key_agreement_iface::AgreementKeyOptions,
    ) -> Result<key_agreement_iface::SecretKey, Error> {
        let policy = options.get::<AgreementKeyOptions>().policy.get();
        let material = lann_webcrypto_core::unwrap_ecdh_secret_key_jwk(
            variant.into(),
            UnwrapInput::take(input),
            policy,
        )?;
        Ok(key_agreement_iface::SecretKey::new(AgreementSecretKey {
            material,
        }))
    }

    async fn unwrap_secret_key_pkcs8(
        variant: EcdhVariant,
        input: wrapping_iface::UnwrapInput,
        options: key_agreement_iface::AgreementKeyOptions,
    ) -> Result<key_agreement_iface::SecretKey, Error> {
        let policy = options.get::<AgreementKeyOptions>().policy.get();
        let material = lann_webcrypto_core::unwrap_ecdh_secret_key_pkcs8(
            variant.into(),
            UnwrapInput::take(input),
            policy,
        )?;
        Ok(key_agreement_iface::SecretKey::new(AgreementSecretKey {
            material,
        }))
    }
}

// --- aes-gcm (key minting) -------------------------------------------------------

impl AesGcmGuest for Component {
    async fn import_key_raw(
        variant: AesVariant,
        raw: Vec<u8>,
        options: ExportedAeadKeyOptions,
    ) -> Result<ExportedAeadKey, Error> {
        let policy = options.get::<AeadKeyOptions>().policy.get();
        let material = AeadKeyMaterial::import_aes_gcm(variant.into(), raw, policy)?;
        Ok(ExportedAeadKey::new(AeadKey { material }))
    }

    async fn import_key_jwk(
        variant: AesVariant,
        jwk: String,
        options: ExportedAeadKeyOptions,
    ) -> Result<ExportedAeadKey, Error> {
        let policy = options.get::<AeadKeyOptions>().policy.get();
        let material = AeadKeyMaterial::import_aes_gcm_jwk(variant.into(), &jwk, policy)?;
        Ok(ExportedAeadKey::new(AeadKey { material }))
    }

    async fn generate_key(
        variant: AesVariant,
        options: ExportedAeadKeyOptions,
    ) -> Result<ExportedAeadKey, Error> {
        let policy = options.get::<AeadKeyOptions>().policy.get();
        let material = rng_infallible(AeadKeyMaterial::generate_aes_gcm(variant.into(), policy))?;
        Ok(ExportedAeadKey::new(AeadKey { material }))
    }

    async fn derive_key(
        variant: AesVariant,
        input: derivation::DeriveInputBorrow<'_>,
        options: ExportedAeadKeyOptions,
    ) -> Result<ExportedAeadKey, Error> {
        let policy = options.get::<AeadKeyOptions>().policy.get();
        let material = lann_webcrypto_core::derive_aes_gcm_key(
            &input.get::<DeriveInput>().material,
            variant.into(),
            policy,
        )?;
        Ok(ExportedAeadKey::new(AeadKey { material }))
    }

    async fn unwrap_key_raw(
        variant: AesVariant,
        input: wrapping_iface::UnwrapInput,
        options: ExportedAeadKeyOptions,
    ) -> Result<ExportedAeadKey, Error> {
        let policy = options.get::<AeadKeyOptions>().policy.get();
        let material = lann_webcrypto_core::unwrap_aes_gcm_key(
            variant.into(),
            UnwrapInput::take(input),
            policy,
        )?;
        Ok(ExportedAeadKey::new(AeadKey { material }))
    }

    async fn unwrap_key_jwk(
        variant: AesVariant,
        input: wrapping_iface::UnwrapInput,
        options: ExportedAeadKeyOptions,
    ) -> Result<ExportedAeadKey, Error> {
        let policy = options.get::<AeadKeyOptions>().policy.get();
        let material = lann_webcrypto_core::unwrap_aes_gcm_key_jwk(
            variant.into(),
            UnwrapInput::take(input),
            policy,
        )?;
        Ok(ExportedAeadKey::new(AeadKey { material }))
    }
}

// --- cipher (the unauthenticated-mode kind) --------------------------------------

impl CipherGuest for Component {
    type CipherKey = CipherKey;
    type CipherKeyOptions = CipherKeyOptions;
}

options_resource! {
    /// An exported `cipher-key-options`. See [`MacKeyOptions`].
    pub struct CipherKeyOptions(CipherPolicy): GuestCipherKeyOptions {
        can_encrypt => encrypt,
        can_decrypt => decrypt,
        can_wrap => wrap,
        can_unwrap => unwrap,
        extractable => extractable,
    }
}

/// An exported `cipher-key`: the shared core's unauthenticated-mode key
/// material.
pub struct CipherKey {
    material: CipherKeyMaterial,
}

impl GuestCipherKey for CipherKey {
    async fn encrypt(
        &self,
        iv: Vec<u8>,
        counter_length: Option<u8>,
        plaintext: wit_bindgen::StreamReader<u8>,
    ) -> Result<wit_bindgen::StreamReader<u8>, Error> {
        let msg = drain_stream(plaintext).await?;
        Ok(stream_of(self.material.encrypt(
            &iv,
            counter_length,
            &msg,
        )?))
    }

    async fn decrypt(
        &self,
        iv: Vec<u8>,
        counter_length: Option<u8>,
        ciphertext: wit_bindgen::StreamReader<u8>,
    ) -> Result<wit_bindgen::StreamReader<u8>, Error> {
        let msg = drain_stream(ciphertext).await?;
        Ok(stream_of(self.material.decrypt(
            &iv,
            counter_length,
            &msg,
        )?))
    }

    fn algorithm_name(&self) -> String {
        self.material.name().to_string()
    }

    fn algorithm_length(&self) -> u32 {
        self.material.length_bits()
    }

    fn iv_size(&self) -> u32 {
        16
    }

    fn extractable(&self) -> bool {
        self.material.policy().extractable
    }

    fn can_encrypt(&self) -> bool {
        self.material.policy().encrypt
    }

    fn can_decrypt(&self) -> bool {
        self.material.policy().decrypt
    }

    fn can_wrap(&self) -> bool {
        self.material.policy().wrap
    }

    fn can_unwrap(&self) -> bool {
        self.material.policy().unwrap
    }

    async fn wrap(
        &self,
        iv: Vec<u8>,
        counter_length: Option<u8>,
        input: wrapping_iface::WrapInput,
    ) -> Result<Vec<u8>, Error> {
        Ok(self
            .material
            .wrap(&iv, counter_length, WrapInput::take(input))?)
    }

    async fn unwrap(
        &self,
        iv: Vec<u8>,
        counter_length: Option<u8>,
        wrapped: Vec<u8>,
    ) -> Result<wrapping_iface::UnwrapInput, Error> {
        UnwrapInput::handle(self.material.unwrap_wrapped(&iv, counter_length, &wrapped))
    }

    async fn to_wrap_input_raw(&self) -> Result<wrapping_iface::WrapInput, Error> {
        WrapInput::handle(
            self.material
                .export()
                .map(|raw| WrapInputMaterial::new(WrapFormat::Raw, raw)),
        )
    }

    async fn to_wrap_input_jwk(&self) -> Result<wrapping_iface::WrapInput, Error> {
        WrapInput::handle(
            self.material
                .export_jwk()
                .map(|jwk| WrapInputMaterial::new(WrapFormat::Jwk, jwk.into_bytes())),
        )
    }

    async fn export_key_raw(&self) -> Result<Vec<u8>, Error> {
        Ok(self.material.export()?)
    }

    async fn export_key_jwk(&self) -> Result<String, Error> {
        Ok(self.material.export_jwk()?)
    }
}

// --- aes-cbc / aes-ctr (key minting) ----------------------------------------------

/// The shared minting body of the two unauthenticated-mode interfaces:
/// they differ only in the `CipherMode` they bind.
macro_rules! cipher_minting {
    ($guest:path, $mode:expr) => {
        impl $guest for Component {
            async fn import_key_raw(
                variant: AesVariant,
                raw: Vec<u8>,
                options: ExportedCipherKeyOptions,
            ) -> Result<ExportedCipherKey, Error> {
                let policy = options.get::<CipherKeyOptions>().policy.get();
                let material = CipherKeyMaterial::import($mode, variant.into(), raw, policy)?;
                Ok(ExportedCipherKey::new(CipherKey { material }))
            }

            async fn import_key_jwk(
                variant: AesVariant,
                jwk: String,
                options: ExportedCipherKeyOptions,
            ) -> Result<ExportedCipherKey, Error> {
                let policy = options.get::<CipherKeyOptions>().policy.get();
                let material = CipherKeyMaterial::import_jwk($mode, variant.into(), &jwk, policy)?;
                Ok(ExportedCipherKey::new(CipherKey { material }))
            }

            async fn generate_key(
                variant: AesVariant,
                options: ExportedCipherKeyOptions,
            ) -> Result<ExportedCipherKey, Error> {
                let policy = options.get::<CipherKeyOptions>().policy.get();
                let material =
                    rng_infallible(CipherKeyMaterial::generate($mode, variant.into(), policy))?;
                Ok(ExportedCipherKey::new(CipherKey { material }))
            }

            async fn derive_key(
                variant: AesVariant,
                input: derivation::DeriveInputBorrow<'_>,
                options: ExportedCipherKeyOptions,
            ) -> Result<ExportedCipherKey, Error> {
                let policy = options.get::<CipherKeyOptions>().policy.get();
                let material = lann_webcrypto_core::derive_cipher_key(
                    &input.get::<DeriveInput>().material,
                    $mode,
                    variant.into(),
                    policy,
                )?;
                Ok(ExportedCipherKey::new(CipherKey { material }))
            }

            async fn unwrap_key_raw(
                variant: AesVariant,
                input: wrapping_iface::UnwrapInput,
                options: ExportedCipherKeyOptions,
            ) -> Result<ExportedCipherKey, Error> {
                let policy = options.get::<CipherKeyOptions>().policy.get();
                let material = lann_webcrypto_core::unwrap_cipher_key(
                    $mode,
                    variant.into(),
                    UnwrapInput::take(input),
                    policy,
                )?;
                Ok(ExportedCipherKey::new(CipherKey { material }))
            }

            async fn unwrap_key_jwk(
                variant: AesVariant,
                input: wrapping_iface::UnwrapInput,
                options: ExportedCipherKeyOptions,
            ) -> Result<ExportedCipherKey, Error> {
                let policy = options.get::<CipherKeyOptions>().policy.get();
                let material = lann_webcrypto_core::unwrap_cipher_key_jwk(
                    $mode,
                    variant.into(),
                    UnwrapInput::take(input),
                    policy,
                )?;
                Ok(ExportedCipherKey::new(CipherKey { material }))
            }
        }
    };
}

cipher_minting!(AesCbcGuest, CipherMode::Cbc);
cipher_minting!(AesCtrGuest, CipherMode::Ctr);

// --- chacha20-poly1305 / xchacha20-poly1305 (key minting) ---------------------

impl ChaChaPoly1305Guest for Component {
    async fn import_key_raw(
        raw: Vec<u8>,
        options: ExportedAeadKeyOptions,
    ) -> Result<ExportedAeadKey, Error> {
        let policy = options.get::<AeadKeyOptions>().policy.get();
        let material = AeadKeyMaterial::import_chacha20_poly1305(raw, policy)?;
        Ok(ExportedAeadKey::new(AeadKey { material }))
    }

    async fn import_key_jwk(
        jwk: String,
        options: ExportedAeadKeyOptions,
    ) -> Result<ExportedAeadKey, Error> {
        let policy = options.get::<AeadKeyOptions>().policy.get();
        let material = AeadKeyMaterial::import_chacha20_poly1305_jwk(&jwk, policy)?;
        Ok(ExportedAeadKey::new(AeadKey { material }))
    }

    async fn generate_key(options: ExportedAeadKeyOptions) -> Result<ExportedAeadKey, Error> {
        let policy = options.get::<AeadKeyOptions>().policy.get();
        let material = rng_infallible(AeadKeyMaterial::generate_chacha20_poly1305(policy))?;
        Ok(ExportedAeadKey::new(AeadKey { material }))
    }

    async fn unwrap_key_raw(
        input: wrapping_iface::UnwrapInput,
        options: ExportedAeadKeyOptions,
    ) -> Result<ExportedAeadKey, Error> {
        let policy = options.get::<AeadKeyOptions>().policy.get();
        let material = lann_webcrypto_core::unwrap_chacha_key(UnwrapInput::take(input), policy)?;
        Ok(ExportedAeadKey::new(AeadKey { material }))
    }

    async fn unwrap_key_jwk(
        input: wrapping_iface::UnwrapInput,
        options: ExportedAeadKeyOptions,
    ) -> Result<ExportedAeadKey, Error> {
        let policy = options.get::<AeadKeyOptions>().policy.get();
        let material =
            lann_webcrypto_core::unwrap_chacha_key_jwk(UnwrapInput::take(input), policy)?;
        Ok(ExportedAeadKey::new(AeadKey { material }))
    }
}

impl XChaChaPoly1305Guest for Component {
    async fn import_key_raw(
        raw: Vec<u8>,
        options: ExportedAeadKeyOptions,
    ) -> Result<ExportedAeadKey, Error> {
        let policy = options.get::<AeadKeyOptions>().policy.get();
        let material = AeadKeyMaterial::import_xchacha20_poly1305(raw, policy)?;
        Ok(ExportedAeadKey::new(AeadKey { material }))
    }

    async fn generate_key(options: ExportedAeadKeyOptions) -> Result<ExportedAeadKey, Error> {
        let policy = options.get::<AeadKeyOptions>().policy.get();
        let material = rng_infallible(AeadKeyMaterial::generate_xchacha20_poly1305(policy))?;
        Ok(ExportedAeadKey::new(AeadKey { material }))
    }

    async fn unwrap_key_raw(
        input: wrapping_iface::UnwrapInput,
        options: ExportedAeadKeyOptions,
    ) -> Result<ExportedAeadKey, Error> {
        let policy = options.get::<AeadKeyOptions>().policy.get();
        let material = lann_webcrypto_core::unwrap_xchacha_key(UnwrapInput::take(input), policy)?;
        Ok(ExportedAeadKey::new(AeadKey { material }))
    }
}

// --- aead-internal-nonce -------------------------------------------------------

impl AeadInternalNonceGuest for Component {
    type InternalNonceKey = InternalNonceKey;
    type InternalNonceKeyOptions = InternalNonceKeyOptions;
}

options_resource! {
    /// An exported `internal-nonce-key-options`. See [`MacKeyOptions`].
    pub struct InternalNonceKeyOptions(InternalNoncePolicy): GuestInternalNonceKeyOptions {
        can_seal => seal,
        can_open => open,
        extractable => extractable,
    }
}

/// An exported `internal-nonce-key`: the shared core's AEAD key material
/// plus the seal count enforcing the WIT nonce budget
/// (`error.key-exhausted`) for 12-byte-nonce algorithms.
pub struct InternalNonceKey {
    material: AeadKeyMaterial,
    /// `seal` invocations so far, counted against the nonce budget.
    /// A `Cell` because exports take `&self` (wasm is single-threaded).
    sealed: std::cell::Cell<u64>,
}

impl InternalNonceKey {
    fn new(material: AeadKeyMaterial) -> Self {
        Self {
            material,
            sealed: std::cell::Cell::new(0),
        }
    }
}

impl GuestInternalNonceKey for InternalNonceKey {
    fn seals_remaining(&self) -> Option<u64> {
        self.material.seals_remaining(self.sealed.get())
    }

    async fn seal(
        &self,
        aad: Vec<u8>,
        plaintext: wit_bindgen::StreamReader<u8>,
    ) -> Result<wit_bindgen::StreamReader<u8>, Error> {
        let msg = drain_stream(plaintext).await?;
        // Count this invocation against the algorithm's nonce budget, per
        // the minting interfaces' SHOULD-enforce contract.
        self.material.check_budget(self.sealed.get())?;
        self.sealed.set(self.sealed.get() + 1);
        let sealed = rng_infallible(self.material.seal_internal(&aad, &msg))?;
        Ok(stream_of(sealed))
    }

    async fn open(
        &self,
        aad: Vec<u8>,
        sealed: wit_bindgen::StreamReader<u8>,
    ) -> Result<wit_bindgen::StreamReader<u8>, Error> {
        // Like `seal`: fully drain the input first; buffering the whole
        // message is inherent to `open` (no unverified plaintext may be
        // observable).
        let msg = drain_stream(sealed).await?;
        Ok(stream_of(self.material.open_internal(&aad, &msg)?))
    }

    fn algorithm_name(&self) -> String {
        self.material.name().to_string()
    }

    fn algorithm_length(&self) -> u32 {
        self.material.length_bits()
    }

    fn extractable(&self) -> bool {
        self.material.extractable()
    }

    fn can_seal(&self) -> bool {
        self.material.can_seal()
    }

    fn can_open(&self) -> bool {
        self.material.can_open()
    }

    async fn to_wrap_input_raw(&self) -> Result<wrapping_iface::WrapInput, Error> {
        WrapInput::handle(
            self.material
                .export()
                .map(|raw| WrapInputMaterial::new(WrapFormat::Raw, raw)),
        )
    }

    async fn to_wrap_input_jwk(&self) -> Result<wrapping_iface::WrapInput, Error> {
        WrapInput::handle(
            self.material
                .export_jwk()
                .map(|jwk| WrapInputMaterial::new(WrapFormat::Jwk, jwk.into_bytes())),
        )
    }

    async fn export_key_raw(&self) -> Result<Vec<u8>, Error> {
        Ok(self.material.export()?)
    }

    async fn export_key_jwk(&self) -> Result<String, Error> {
        Ok(self.material.export_jwk()?)
    }
}

// --- aes-gcm-internal-nonce (key minting) ----------------------------------------

impl AesGcmInternalNonceGuest for Component {
    async fn import_key_raw(
        variant: AesVariant,
        raw: Vec<u8>,
        options: ExportedInternalNonceKeyOptions,
    ) -> Result<ExportedInternalNonceKey, Error> {
        let policy = options.get::<InternalNonceKeyOptions>().policy.get();
        let material = AeadKeyMaterial::import_aes_gcm(variant.into(), raw, policy.into())?;
        Ok(ExportedInternalNonceKey::new(InternalNonceKey::new(
            material,
        )))
    }

    async fn import_key_jwk(
        variant: AesVariant,
        jwk: String,
        options: ExportedInternalNonceKeyOptions,
    ) -> Result<ExportedInternalNonceKey, Error> {
        let policy = options.get::<InternalNonceKeyOptions>().policy.get();
        let material = AeadKeyMaterial::import_aes_gcm_jwk(variant.into(), &jwk, policy.into())?;
        Ok(ExportedInternalNonceKey::new(InternalNonceKey::new(
            material,
        )))
    }

    async fn generate_key(
        variant: AesVariant,
        options: ExportedInternalNonceKeyOptions,
    ) -> Result<ExportedInternalNonceKey, Error> {
        let policy = options.get::<InternalNonceKeyOptions>().policy.get();
        let material = rng_infallible(AeadKeyMaterial::generate_aes_gcm(
            variant.into(),
            policy.into(),
        ))?;
        Ok(ExportedInternalNonceKey::new(InternalNonceKey::new(
            material,
        )))
    }

    async fn unwrap_key_raw(
        variant: AesVariant,
        input: wrapping_iface::UnwrapInput,
        options: ExportedInternalNonceKeyOptions,
    ) -> Result<ExportedInternalNonceKey, Error> {
        let policy = options.get::<InternalNonceKeyOptions>().policy.get();
        let material = lann_webcrypto_core::unwrap_aes_gcm_internal_key(
            variant.into(),
            UnwrapInput::take(input),
            policy,
        )?;
        Ok(ExportedInternalNonceKey::new(InternalNonceKey::new(
            material,
        )))
    }

    async fn unwrap_key_jwk(
        variant: AesVariant,
        input: wrapping_iface::UnwrapInput,
        options: ExportedInternalNonceKeyOptions,
    ) -> Result<ExportedInternalNonceKey, Error> {
        let policy = options.get::<InternalNonceKeyOptions>().policy.get();
        let material = lann_webcrypto_core::unwrap_aes_gcm_internal_key_jwk(
            variant.into(),
            UnwrapInput::take(input),
            policy,
        )?;
        Ok(ExportedInternalNonceKey::new(InternalNonceKey::new(
            material,
        )))
    }
}

// --- xchacha20-poly1305-internal-nonce (key minting) ------------------------------

impl XChachaInternalNonceGuest for Component {
    async fn import_key_raw(
        raw: Vec<u8>,
        options: ExportedInternalNonceKeyOptions,
    ) -> Result<ExportedInternalNonceKey, Error> {
        let policy = options.get::<InternalNonceKeyOptions>().policy.get();
        let material = AeadKeyMaterial::import_xchacha20_poly1305(raw, policy.into())?;
        Ok(ExportedInternalNonceKey::new(InternalNonceKey::new(
            material,
        )))
    }

    async fn generate_key(
        options: ExportedInternalNonceKeyOptions,
    ) -> Result<ExportedInternalNonceKey, Error> {
        let policy = options.get::<InternalNonceKeyOptions>().policy.get();
        let material = rng_infallible(AeadKeyMaterial::generate_xchacha20_poly1305(policy.into()))?;
        Ok(ExportedInternalNonceKey::new(InternalNonceKey::new(
            material,
        )))
    }

    async fn unwrap_key_raw(
        input: wrapping_iface::UnwrapInput,
        options: ExportedInternalNonceKeyOptions,
    ) -> Result<ExportedInternalNonceKey, Error> {
        let policy = options.get::<InternalNonceKeyOptions>().policy.get();
        let material =
            lann_webcrypto_core::unwrap_xchacha_internal_key(UnwrapInput::take(input), policy)?;
        Ok(ExportedInternalNonceKey::new(InternalNonceKey::new(
            material,
        )))
    }
}

// --- signature -----------------------------------------------------------------

impl SignatureGuest for Component {
    type VerifyingKey = VerifyingKey;
    type SigningKey = SigningKey;
    type SigningKeyOptions = SigningKeyOptions;
}

options_resource! {
    /// An exported `signing-key-options`. See [`MacKeyOptions`].
    pub struct SigningKeyOptions(SigningPolicy): GuestSigningKeyOptions {
        can_sign => sign,
        extractable => extractable,
    }
}

/// An exported `verifying-key`: public material bound to its algorithm
/// (and its curve, digest, or salt-length parameterization) at minting.
/// The ECDSA and RSA arms exist for *verification only* — secret-free, so
/// exempt from the timing-channel classes; ECDSA signing is class D, its
/// interface is not exported, and the shared core compiles no ECDSA
/// signing code for wasm targets. The package defines no RSA private-key
/// interface at all.
pub struct VerifyingKey {
    public: SigPublic,
}

impl GuestVerifyingKey for VerifyingKey {
    async fn verify(&self, data: wit_bindgen::StreamReader<u8>, sig: Vec<u8>) -> Result<(), Error> {
        let bytes = drain_stream(data).await?;
        Ok(self.public.verify(&bytes, &sig)?)
    }

    fn algorithm_name(&self) -> String {
        self.public.name().to_string()
    }

    fn algorithm_curve(&self) -> Option<String> {
        self.public.curve().map(str::to_string)
    }

    fn algorithm_hash(&self) -> Option<String> {
        self.public.hash().map(str::to_string)
    }

    fn algorithm_length(&self) -> Option<u32> {
        self.public.length()
    }

    async fn export_key_raw(&self) -> Result<Vec<u8>, Error> {
        Ok(self.public.export()?)
    }

    async fn export_key_spki(&self) -> Result<Vec<u8>, Error> {
        Ok(self.public.export_spki())
    }

    async fn export_key_jwk(&self) -> Result<String, Error> {
        Ok(self.public.export_jwk())
    }
}

/// An exported `signing-key`: the shared core's signing-key material. On
/// this wasm target the core mints only Ed25519 signing keys
/// (constant-time by construction); ECDSA signing is class D, its
/// interface is not exported, and the core compiles no ECDSA signing code
/// for wasm targets.
pub struct SigningKey {
    material: SigningKeyMaterial,
}

impl GuestSigningKey for SigningKey {
    async fn sign(&self, data: wit_bindgen::StreamReader<u8>) -> Result<Vec<u8>, Error> {
        let bytes = drain_stream(data).await?;
        Ok(self.material.sign(&bytes)?)
    }

    fn algorithm_name(&self) -> String {
        self.material.name().to_string()
    }

    fn algorithm_curve(&self) -> Option<String> {
        self.material.curve().map(str::to_string)
    }

    fn algorithm_hash(&self) -> Option<String> {
        self.material.hash().map(str::to_string)
    }

    fn algorithm_length(&self) -> Option<u32> {
        self.material.length()
    }

    fn extractable(&self) -> bool {
        self.material.extractable()
    }

    fn can_sign(&self) -> bool {
        self.material.can_sign()
    }

    async fn export_key_jwk(&self) -> Result<String, Error> {
        Ok(self.material.export_jwk()?)
    }

    async fn export_key_pkcs8(&self) -> Result<Vec<u8>, Error> {
        Ok(self.material.export_pkcs8()?)
    }

    async fn to_wrap_input_jwk(&self) -> Result<wrapping_iface::WrapInput, Error> {
        WrapInput::handle(
            self.material
                .export_jwk()
                .map(|jwk| WrapInputMaterial::new(WrapFormat::Jwk, jwk.into_bytes())),
        )
    }

    async fn to_wrap_input_pkcs8(&self) -> Result<wrapping_iface::WrapInput, Error> {
        WrapInput::handle(
            self.material
                .export_pkcs8()
                .map(|der| WrapInputMaterial::new(WrapFormat::Pkcs8, der)),
        )
    }
}

// --- ed25519 (key minting) -----------------------------------------------------

impl Ed25519VerifyGuest for Component {
    async fn import_verifying_key_raw(
        raw: Vec<u8>,
    ) -> Result<signature_iface::VerifyingKey, Error> {
        let public = SigPublic::import_ed25519(&raw)?;
        Ok(signature_iface::VerifyingKey::new(VerifyingKey { public }))
    }

    async fn import_verifying_key_spki(
        spki: Vec<u8>,
    ) -> Result<signature_iface::VerifyingKey, Error> {
        let public = SigPublic::import_ed25519_spki(&spki)?;
        Ok(signature_iface::VerifyingKey::new(VerifyingKey { public }))
    }

    async fn import_verifying_key_jwk(jwk: String) -> Result<signature_iface::VerifyingKey, Error> {
        let public = SigPublic::import_ed25519_jwk(&jwk)?;
        Ok(signature_iface::VerifyingKey::new(VerifyingKey { public }))
    }
}

impl Ed25519SignGuest for Component {
    async fn generate_key(
        options: signature_iface::SigningKeyOptions,
    ) -> Result<(signature_iface::SigningKey, signature_iface::VerifyingKey), Error> {
        let policy = options.get::<SigningKeyOptions>().policy.get();
        let material = rng_infallible(SigningKeyMaterial::generate_ed25519(policy))?;
        let public = material.public();
        Ok((
            signature_iface::SigningKey::new(SigningKey { material }),
            signature_iface::VerifyingKey::new(VerifyingKey { public }),
        ))
    }

    async fn import_signing_key_pkcs8(
        pkcs8: Vec<u8>,
        options: signature_iface::SigningKeyOptions,
    ) -> Result<signature_iface::SigningKey, Error> {
        let policy = options.get::<SigningKeyOptions>().policy.get();
        let material = SigningKeyMaterial::import_ed25519_pkcs8(&pkcs8, policy)?;
        Ok(signature_iface::SigningKey::new(SigningKey { material }))
    }

    async fn import_signing_key_jwk(
        jwk: String,
        options: signature_iface::SigningKeyOptions,
    ) -> Result<signature_iface::SigningKey, Error> {
        let policy = options.get::<SigningKeyOptions>().policy.get();
        let material = SigningKeyMaterial::import_ed25519_jwk(&jwk, policy)?;
        Ok(signature_iface::SigningKey::new(SigningKey { material }))
    }

    async fn unwrap_signing_key_pkcs8(
        input: wrapping_iface::UnwrapInput,
        options: signature_iface::SigningKeyOptions,
    ) -> Result<signature_iface::SigningKey, Error> {
        let policy = options.get::<SigningKeyOptions>().policy.get();
        let material = lann_webcrypto_core::unwrap_ed25519_signing_key_pkcs8(
            UnwrapInput::take(input),
            policy,
        )?;
        Ok(signature_iface::SigningKey::new(SigningKey { material }))
    }

    async fn unwrap_signing_key_jwk(
        input: wrapping_iface::UnwrapInput,
        options: signature_iface::SigningKeyOptions,
    ) -> Result<signature_iface::SigningKey, Error> {
        let policy = options.get::<SigningKeyOptions>().policy.get();
        let material =
            lann_webcrypto_core::unwrap_ed25519_signing_key_jwk(UnwrapInput::take(input), policy)?;
        Ok(signature_iface::SigningKey::new(SigningKey { material }))
    }
}

// --- ecdsa (verification-key minting only; signing is class D) ------------------

impl EcdsaVerifyGuest for Component {
    async fn import_verifying_key_raw(
        variant: EcdsaVariant,
        raw: Vec<u8>,
    ) -> Result<signature_iface::VerifyingKey, Error> {
        let public = SigPublic::import_ecdsa(variant.into(), &raw)?;
        Ok(signature_iface::VerifyingKey::new(VerifyingKey { public }))
    }

    async fn import_verifying_key_spki(
        variant: EcdsaVariant,
        spki: Vec<u8>,
    ) -> Result<signature_iface::VerifyingKey, Error> {
        let public = SigPublic::import_ecdsa_spki(variant.into(), &spki)?;
        Ok(signature_iface::VerifyingKey::new(VerifyingKey { public }))
    }

    async fn import_verifying_key_jwk(
        variant: EcdsaVariant,
        jwk: String,
    ) -> Result<signature_iface::VerifyingKey, Error> {
        let public = SigPublic::import_ecdsa_jwk(variant.into(), &jwk)?;
        Ok(signature_iface::VerifyingKey::new(VerifyingKey { public }))
    }
}

// --- rsa (verification-key minting only; no RSA private-key interface exists) ----

impl RsassaVerifyGuest for Component {
    async fn import_verifying_key_spki(
        variant: RsaVariant,
        spki: Vec<u8>,
    ) -> Result<signature_iface::VerifyingKey, Error> {
        let public = SigPublic::import_rsassa_spki(variant.into(), &spki)?;
        Ok(signature_iface::VerifyingKey::new(VerifyingKey { public }))
    }

    async fn import_verifying_key_jwk(
        variant: RsaVariant,
        jwk: String,
    ) -> Result<signature_iface::VerifyingKey, Error> {
        let public = SigPublic::import_rsassa_jwk(variant.into(), &jwk)?;
        Ok(signature_iface::VerifyingKey::new(VerifyingKey { public }))
    }
}

impl RsaPssVerifyGuest for Component {
    async fn import_verifying_key_spki(
        variant: RsaVariant,
        salt_length: u32,
        spki: Vec<u8>,
    ) -> Result<signature_iface::VerifyingKey, Error> {
        let public = SigPublic::import_pss_spki(variant.into(), salt_length, &spki)?;
        Ok(signature_iface::VerifyingKey::new(VerifyingKey { public }))
    }

    async fn import_verifying_key_jwk(
        variant: RsaVariant,
        salt_length: u32,
        jwk: String,
    ) -> Result<signature_iface::VerifyingKey, Error> {
        let public = SigPublic::import_pss_jwk(variant.into(), salt_length, &jwk)?;
        Ok(signature_iface::VerifyingKey::new(VerifyingKey { public }))
    }
}
