//! The exported `lann:webcrypto` resources and key-minting functions.
//!
//! The cryptography itself lives in `webcrypto-impl-core`, shared verbatim
//! with the Wasmtime host; this module contributes only what is
//! guest-specific — stream plumbing, the exported resource types, and the
//! bindings glue converting the generated types to the core's.
//!
//! Byte `stream`s are the only bulk data path: incoming streams are drained
//! to completion (even when the operation resolves with an error, per the WIT
//! contract for `seal`/`open`), and outgoing streams are fed from a detached
//! task (`wit_bindgen::spawn`) after the export returns.

use std::cell::Cell;

use webcrypto_impl_core::{
    served_sha2, AeadKeyMaterial, AeadPolicy, AgreementPolicy, InternalNoncePolicy, MacKeyMaterial,
    MacPolicy, SigPublic, SigningKeyMaterial, SigningPolicy, HMAC_NAME,
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
use crate::exports::lann::webcrypto::aes_gcm::{AesVariant, Guest as AesGcmGuest};
use crate::exports::lann::webcrypto::aes_gcm_internal_nonce::Guest as AesGcmInternalNonceGuest;
use crate::exports::lann::webcrypto::bytes::Guest as BytesGuest;
use crate::exports::lann::webcrypto::chacha20_poly1305::Guest as ChaChaPoly1305Guest;
use crate::exports::lann::webcrypto::derivation::{
    self, Guest as DerivationGuest, GuestDeriveInput, GuestDeriveOptions,
};
use crate::exports::lann::webcrypto::digest::{self as digest, Guest as DigestGuest, GuestDigest};
use crate::exports::lann::webcrypto::ecdsa_verify::{EcdsaVariant, Guest as EcdsaVerifyGuest};
use crate::exports::lann::webcrypto::ed25519_sign::Guest as Ed25519SignGuest;
use crate::exports::lann::webcrypto::ed25519_verify::Guest as Ed25519VerifyGuest;
use crate::exports::lann::webcrypto::hkdf::{self as hkdf_iface, Guest as HkdfGuest, GuestIkm};
use crate::exports::lann::webcrypto::hmac_sha2::Guest as HmacSha2Guest;
use crate::exports::lann::webcrypto::key_agreement::{
    self as key_agreement_iface, Guest as KeyAgreementGuest, GuestAgreementKeyOptions,
    GuestPublicKey, GuestSecretKey,
};
use crate::exports::lann::webcrypto::mac::{
    self, Guest as MacGuest, GuestMacKey, GuestMacKeyOptions,
};
use crate::exports::lann::webcrypto::pbkdf2::{
    self as pbkdf2_iface, Guest as Pbkdf2Guest, GuestPassword,
};
use crate::exports::lann::webcrypto::sha2::{Guest as Sha2Guest, Sha2Variant};
use crate::exports::lann::webcrypto::signature::{
    self as signature_iface, Guest as SignatureGuest, GuestSigningKey, GuestSigningKeyOptions,
    GuestVerifyingKey,
};
use crate::exports::lann::webcrypto::x25519::Guest as X25519Guest;
use crate::exports::lann::webcrypto::xchacha20_poly1305::Guest as XChaChaPoly1305Guest;
use crate::exports::lann::webcrypto::xchacha20_poly1305_internal_nonce::Guest as XChachaInternalNonceGuest;
use crate::lann::webcrypto::types::Error;

pub struct Component;

// --- bindings glue -------------------------------------------------------------

webcrypto_impl_core::impl_conversions! {
    error: Error,
    sha2: Sha2Variant,
    aes: AesVariant,
    ecdsa: EcdsaVariant,
}

/// Unwrap an entropy result: the WASI random source backing the guest's
/// `getrandom` is always available, so a failure is unreachable.
fn rng_infallible<T>(result: Result<T, webcrypto_impl_core::RngError>) -> T {
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

// --- mac ---------------------------------------------------------------------

impl MacGuest for Component {
    type MacKey = MacKey;
    type MacKeyOptions = MacKeyOptions;
}

/// An exported `mac-key-options`: mint-time policy under construction. The
/// policy sits in a `Cell` because the setters take `&self` (wasm is
/// single-threaded).
pub struct MacKeyOptions {
    policy: Cell<MacPolicy>,
}

impl GuestMacKeyOptions for MacKeyOptions {
    fn new() -> Self {
        Self {
            policy: Cell::new(MacPolicy::default()),
        }
    }

    fn can_sign(&self, allowed: bool) {
        self.policy.set(MacPolicy {
            sign: allowed,
            ..self.policy.get()
        });
    }

    fn can_verify(&self, allowed: bool) {
        self.policy.set(MacPolicy {
            verify: allowed,
            ..self.policy.get()
        });
    }

    fn extractable(&self, allowed: bool) {
        self.policy.set(MacPolicy {
            extractable: allowed,
            ..self.policy.get()
        });
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

    async fn export_key(&self) -> Result<Vec<u8>, Error> {
        Ok(self.material.export()?)
    }

    async fn export_key_jwk(&self) -> Result<String, Error> {
        Ok(self.material.export_jwk()?)
    }
}

// --- aead --------------------------------------------------------------------

impl AeadGuest for Component {
    type AeadKey = AeadKey;
    type AeadKeyOptions = AeadKeyOptions;
}

/// An exported `aead-key-options`. See [`MacKeyOptions`].
pub struct AeadKeyOptions {
    policy: Cell<AeadPolicy>,
}

impl GuestAeadKeyOptions for AeadKeyOptions {
    fn new() -> Self {
        Self {
            policy: Cell::new(AeadPolicy::default()),
        }
    }

    fn can_seal(&self, allowed: bool) {
        self.policy.set(AeadPolicy {
            seal: allowed,
            ..self.policy.get()
        });
    }

    fn can_open(&self, allowed: bool) {
        self.policy.set(AeadPolicy {
            open: allowed,
            ..self.policy.get()
        });
    }

    fn can_wrap(&self, allowed: bool) {
        self.policy.set(AeadPolicy {
            wrap: allowed,
            ..self.policy.get()
        });
    }

    fn can_unwrap(&self, allowed: bool) {
        self.policy.set(AeadPolicy {
            unwrap: allowed,
            ..self.policy.get()
        });
    }

    fn extractable(&self, allowed: bool) {
        self.policy.set(AeadPolicy {
            extractable: allowed,
            ..self.policy.get()
        });
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

    async fn export_key(&self) -> Result<Vec<u8>, Error> {
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

/// An exported `digest`: no key material, just the SHA-2 variant it is
/// bound to. `compute` is one-shot and stateless per call, so the resource
/// is reusable.
pub struct Digest {
    variant: webcrypto_impl_core::Sha2,
}

impl GuestDigest for Digest {
    async fn compute(&self, data: wit_bindgen::StreamReader<u8>) -> Result<Vec<u8>, Error> {
        // Buffer the whole stream, then hash it; the result is
        // chunking-invariant either way.
        //
        // Hashing computes in-process, so the only operational failure is
        // the buffering itself.
        let bytes = drain_stream(data).await?;
        Ok(self.variant.digest(&bytes))
    }

    fn algorithm_name(&self) -> String {
        self.variant.hash_name().to_string()
    }
}

// --- bytes ---------------------------------------------------------------------

impl BytesGuest for Component {
    fn constant_time_equal(a: Vec<u8>, b: Vec<u8>) -> bool {
        webcrypto_impl_core::constant_time_equal(&a, &b)
    }
}

// --- sha2 (digest minting) ---------------------------------------------------

impl Sha2Guest for Component {
    fn make_digest(variant: Sha2Variant) -> Result<digest::Digest, Error> {
        let variant = served_sha2(variant.into())?;
        Ok(digest::Digest::new(Digest { variant }))
    }
}

// --- hmac-sha2 (key minting) -----------------------------------------------------

impl HmacSha2Guest for Component {
    async fn import_key(
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
        let material = webcrypto_impl_core::derive_mac_key(
            &input.get::<DeriveInput>().material,
            variant.into(),
            length,
            policy,
        )?;
        Ok(mac::MacKey::new(MacKey { material }))
    }
}

// --- derivation & hkdf ---------------------------------------------------------

impl DerivationGuest for Component {
    type DeriveOptions = DeriveOptions;
    type DeriveInput = DeriveInput;
}

/// An exported `derive-options`. See [`MacKeyOptions`].
pub struct DeriveOptions {
    policy: Cell<webcrypto_impl_core::DerivePolicy>,
}

impl GuestDeriveOptions for DeriveOptions {
    fn new() -> Self {
        Self {
            policy: Cell::new(webcrypto_impl_core::DerivePolicy::default()),
        }
    }

    fn can_derive_bits(&self, allowed: bool) {
        self.policy.set(webcrypto_impl_core::DerivePolicy {
            derive_bits: allowed,
            ..self.policy.get()
        });
    }

    fn can_derive_key(&self, allowed: bool) {
        self.policy.set(webcrypto_impl_core::DerivePolicy {
            derive_key: allowed,
            ..self.policy.get()
        });
    }
}

/// An exported `derive-input`: the shared core's parameterized derivation
/// (run eagerly at `prepare` — the PRK, not the base secret).
pub struct DeriveInput {
    material: webcrypto_impl_core::DeriveInputMaterial,
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
        let material = webcrypto_impl_core::IkmMaterial::import(raw, policy)?;
        Ok(hkdf_iface::Ikm::new(Ikm { material }))
    }

    async fn prepare(
        variant: Sha2Variant,
        input: hkdf_iface::IkmBorrow<'_>,
        salt: Vec<u8>,
        info: Vec<u8>,
    ) -> Result<derivation::DeriveInput, Error> {
        let material = webcrypto_impl_core::DeriveInputMaterial::prepare(
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
        let material = webcrypto_impl_core::DeriveInputMaterial::prepare_from(
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
    material: webcrypto_impl_core::IkmMaterial,
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
        let material = webcrypto_impl_core::PasswordMaterial::import(raw, policy)?;
        Ok(pbkdf2_iface::Password::new(Password { material }))
    }

    async fn prepare(
        variant: Sha2Variant,
        input: pbkdf2_iface::PasswordBorrow<'_>,
        salt: Vec<u8>,
        iterations: u32,
    ) -> Result<derivation::DeriveInput, Error> {
        let material = webcrypto_impl_core::DeriveInputMaterial::prepare_pbkdf2(
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
    material: webcrypto_impl_core::PasswordMaterial,
}

impl GuestPassword for Password {
    fn can_derive_bits(&self) -> bool {
        self.material.policy().derive_bits
    }

    fn can_derive_key(&self) -> bool {
        self.material.policy().derive_key
    }
}

// --- key-agreement & x25519 ------------------------------------------------------

impl KeyAgreementGuest for Component {
    type AgreementKeyOptions = AgreementKeyOptions;
    type PublicKey = AgreementPublicKey;
    type SecretKey = AgreementSecretKey;
}

/// An exported `agreement-key-options`. See [`MacKeyOptions`].
pub struct AgreementKeyOptions {
    policy: Cell<AgreementPolicy>,
}

impl GuestAgreementKeyOptions for AgreementKeyOptions {
    fn new() -> Self {
        Self {
            policy: Cell::new(AgreementPolicy::default()),
        }
    }

    fn can_derive_bits(&self, allowed: bool) {
        self.policy.set(AgreementPolicy {
            derive_bits: allowed,
            ..self.policy.get()
        });
    }

    fn can_derive_key(&self, allowed: bool) {
        self.policy.set(AgreementPolicy {
            derive_key: allowed,
            ..self.policy.get()
        });
    }

    fn extractable(&self, allowed: bool) {
        self.policy.set(AgreementPolicy {
            extractable: allowed,
            ..self.policy.get()
        });
    }
}

/// An exported `key-agreement.public-key`: public material only.
pub struct AgreementPublicKey {
    material: webcrypto_impl_core::AgreementPublicMaterial,
}

impl GuestPublicKey for AgreementPublicKey {
    fn algorithm_name(&self) -> String {
        self.material.name().to_string()
    }

    async fn export_key(&self) -> Result<Vec<u8>, Error> {
        Ok(self.material.export())
    }

    async fn export_key_jwk(&self) -> Result<String, Error> {
        Ok(self.material.export_jwk())
    }
}

/// An exported `key-agreement.secret-key`: the shared core's X25519 secret
/// (dalek's constant-time Montgomery ladder — class B; see the README's
/// classification table).
pub struct AgreementSecretKey {
    material: webcrypto_impl_core::AgreementSecretMaterial,
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
}

impl X25519Guest for Component {
    async fn import_public_key(raw: Vec<u8>) -> Result<key_agreement_iface::PublicKey, Error> {
        let material = webcrypto_impl_core::AgreementPublicMaterial::import(&raw)?;
        Ok(key_agreement_iface::PublicKey::new(AgreementPublicKey {
            material,
        }))
    }

    async fn import_secret_key_jwk(
        jwk: String,
        options: key_agreement_iface::AgreementKeyOptions,
    ) -> Result<key_agreement_iface::SecretKey, Error> {
        let policy = options.get::<AgreementKeyOptions>().policy.get();
        let material = webcrypto_impl_core::AgreementSecretMaterial::import_jwk(&jwk, policy)?;
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
        let (secret, public) = rng_infallible(
            webcrypto_impl_core::AgreementSecretMaterial::generate(policy),
        )?;
        Ok((
            key_agreement_iface::SecretKey::new(AgreementSecretKey { material: secret }),
            key_agreement_iface::PublicKey::new(AgreementPublicKey { material: public }),
        ))
    }
}

// --- aes-gcm (key minting) -------------------------------------------------------

impl AesGcmGuest for Component {
    async fn import_key(
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
        let material = webcrypto_impl_core::derive_aes_gcm_key(
            &input.get::<DeriveInput>().material,
            variant.into(),
            policy,
        )?;
        Ok(ExportedAeadKey::new(AeadKey { material }))
    }
}

// --- chacha20-poly1305 / xchacha20-poly1305 (key minting) ---------------------

impl ChaChaPoly1305Guest for Component {
    async fn import_key(
        raw: Vec<u8>,
        options: ExportedAeadKeyOptions,
    ) -> Result<ExportedAeadKey, Error> {
        let policy = options.get::<AeadKeyOptions>().policy.get();
        let material = AeadKeyMaterial::import_chacha20_poly1305(raw, policy)?;
        Ok(ExportedAeadKey::new(AeadKey { material }))
    }

    async fn generate_key(options: ExportedAeadKeyOptions) -> Result<ExportedAeadKey, Error> {
        let policy = options.get::<AeadKeyOptions>().policy.get();
        let material = rng_infallible(AeadKeyMaterial::generate_chacha20_poly1305(policy))?;
        Ok(ExportedAeadKey::new(AeadKey { material }))
    }
}

impl XChaChaPoly1305Guest for Component {
    async fn import_key(
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
}

// --- aead-internal-nonce -------------------------------------------------------

impl AeadInternalNonceGuest for Component {
    type InternalNonceKey = InternalNonceKey;
    type InternalNonceKeyOptions = InternalNonceKeyOptions;
}

/// An exported `internal-nonce-key-options`. See [`MacKeyOptions`].
pub struct InternalNonceKeyOptions {
    policy: Cell<InternalNoncePolicy>,
}

impl GuestInternalNonceKeyOptions for InternalNonceKeyOptions {
    fn new() -> Self {
        Self {
            policy: Cell::new(InternalNoncePolicy::default()),
        }
    }

    fn can_seal(&self, allowed: bool) {
        self.policy.set(InternalNoncePolicy {
            seal: allowed,
            ..self.policy.get()
        });
    }

    fn can_open(&self, allowed: bool) {
        self.policy.set(InternalNoncePolicy {
            open: allowed,
            ..self.policy.get()
        });
    }

    fn extractable(&self, allowed: bool) {
        self.policy.set(InternalNoncePolicy {
            extractable: allowed,
            ..self.policy.get()
        });
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

    async fn export_key(&self) -> Result<Vec<u8>, Error> {
        Ok(self.material.export()?)
    }
}

// --- aes-gcm-internal-nonce (key minting) ----------------------------------------

impl AesGcmInternalNonceGuest for Component {
    async fn import_key(
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
}

// --- xchacha20-poly1305-internal-nonce (key minting) ------------------------------

impl XChachaInternalNonceGuest for Component {
    async fn import_key(
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
}

// --- signature -----------------------------------------------------------------

impl SignatureGuest for Component {
    type VerifyingKey = VerifyingKey;
    type SigningKey = SigningKey;
    type SigningKeyOptions = SigningKeyOptions;
}

/// An exported `signing-key-options`. See [`MacKeyOptions`].
pub struct SigningKeyOptions {
    policy: Cell<SigningPolicy>,
}

impl GuestSigningKeyOptions for SigningKeyOptions {
    fn new() -> Self {
        Self {
            policy: Cell::new(SigningPolicy::default()),
        }
    }

    fn can_sign(&self, allowed: bool) {
        self.policy.set(SigningPolicy {
            sign: allowed,
            ..self.policy.get()
        });
    }

    fn extractable(&self, allowed: bool) {
        self.policy.set(SigningPolicy {
            extractable: allowed,
            ..self.policy.get()
        });
    }
}

/// An exported `verifying-key`: public material bound to its algorithm
/// (and, for ECDSA, its curve/digest variant) at minting. The ECDSA arms
/// exist for *verification only* — secret-free, so exempt from the
/// timing-channel classes; ECDSA signing is class D, and the shared core
/// compiles no ECDSA signing code for wasm targets.
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

    async fn export_key(&self) -> Result<Vec<u8>, Error> {
        // The WIT `err` case exists for providers holding the key as an
        // unreadable handle; this implementation holds the encoding
        // in-process, so it never errs.
        Ok(self.public.export())
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

    fn extractable(&self) -> bool {
        self.material.extractable()
    }

    fn can_sign(&self) -> bool {
        self.material.can_sign()
    }
}

// --- ed25519 (key minting) -----------------------------------------------------

impl Ed25519VerifyGuest for Component {
    async fn import_verifying_key(raw: Vec<u8>) -> Result<signature_iface::VerifyingKey, Error> {
        let public = SigPublic::import_ed25519(&raw)?;
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
}

// --- ecdsa (verification-key minting only; signing is class D) ------------------

impl EcdsaVerifyGuest for Component {
    async fn import_verifying_key(
        variant: EcdsaVariant,
        raw: Vec<u8>,
    ) -> Result<signature_iface::VerifyingKey, Error> {
        let public = SigPublic::import_ecdsa(variant.into(), &raw)?;
        Ok(signature_iface::VerifyingKey::new(VerifyingKey { public }))
    }
}
