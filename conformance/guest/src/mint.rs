//! Full-grant minting helpers over the raw `lann:webcrypto` bindings.
//!
//! The vector cases and most probes mint keys to exercise *algorithms*,
//! not usage policy, so these wrappers grant every usage and expose only
//! the `extractable` choice. Usage policy itself (deny-by-default, the
//! zero-usage refusal, per-operation enforcement) is a probe subject in
//! its own right, exercised with explicitly constructed options.

use lann_webcrypto_guest::bindings::aead::{AeadKey, AeadKeyOptions};
use lann_webcrypto_guest::bindings::aead_internal_nonce::{
    InternalNonceKey, InternalNonceKeyOptions,
};
use lann_webcrypto_guest::bindings::aes_gcm::AesVariant;
use lann_webcrypto_guest::bindings::derivation::DeriveOptions;
use lann_webcrypto_guest::bindings::hkdf::{self, Ikm};
use lann_webcrypto_guest::bindings::mac::{MacKey, MacKeyOptions};
use lann_webcrypto_guest::bindings::sha2::Sha2Variant;
use lann_webcrypto_guest::bindings::signature::{SigningKey, SigningKeyOptions, VerifyingKey};
use lann_webcrypto_guest::bindings::types::Error;
use lann_webcrypto_guest::bindings::{
    aes_gcm, aes_gcm_internal_nonce, chacha20_poly1305, ed25519_sign, hmac_sha2,
    xchacha20_poly1305, xchacha20_poly1305_internal_nonce,
};

/// A `mac-key-options` granting both usages.
pub fn mac_options(extractable: bool) -> MacKeyOptions {
    let options = MacKeyOptions::new();
    options.can_sign(true);
    options.can_verify(true);
    options.extractable(extractable);
    options
}

/// An `aead-key-options` granting every usage.
pub fn aead_options(extractable: bool) -> AeadKeyOptions {
    let options = AeadKeyOptions::new();
    options.can_seal(true);
    options.can_open(true);
    options.can_wrap(true);
    options.can_unwrap(true);
    options.extractable(extractable);
    options
}

/// An `internal-nonce-key-options` granting both usages.
pub fn internal_nonce_options(extractable: bool) -> InternalNonceKeyOptions {
    let options = InternalNonceKeyOptions::new();
    options.can_seal(true);
    options.can_open(true);
    options.extractable(extractable);
    options
}

/// A `signing-key-options` granting `sign`.
pub fn signing_options(extractable: bool) -> SigningKeyOptions {
    let options = SigningKeyOptions::new();
    options.can_sign(true);
    options.extractable(extractable);
    options
}

/// A `derive-options` with the given grants.
pub fn derive_options(bits: bool, key: bool) -> DeriveOptions {
    let options = DeriveOptions::new();
    options.can_derive_bits(bits);
    options.can_derive_key(key);
    options
}

/// Import HKDF input keying material with the given grants.
pub async fn import_ikm(raw: Vec<u8>, bits: bool, key: bool) -> Result<Ikm, Error> {
    hkdf::import_ikm(raw, derive_options(bits, key)).await
}

pub async fn import_hmac_key(
    variant: Sha2Variant,
    raw: Vec<u8>,
    extractable: bool,
) -> Result<MacKey, Error> {
    hmac_sha2::import_key(variant, raw, mac_options(extractable)).await
}

pub async fn import_hmac_key_jwk(
    variant: Sha2Variant,
    jwk: String,
    extractable: bool,
) -> Result<MacKey, Error> {
    hmac_sha2::import_key_jwk(variant, jwk, mac_options(extractable)).await
}

pub async fn generate_hmac_key(
    variant: Sha2Variant,
    length: Option<u32>,
    extractable: bool,
) -> Result<MacKey, Error> {
    hmac_sha2::generate_key(variant, length, mac_options(extractable)).await
}

pub async fn import_key(
    variant: AesVariant,
    raw: Vec<u8>,
    extractable: bool,
) -> Result<AeadKey, Error> {
    aes_gcm::import_key(variant, raw, aead_options(extractable)).await
}

pub async fn import_aes_key_jwk(
    variant: AesVariant,
    jwk: String,
    extractable: bool,
) -> Result<AeadKey, Error> {
    aes_gcm::import_key_jwk(variant, jwk, aead_options(extractable)).await
}

pub async fn generate_key(variant: AesVariant, extractable: bool) -> Result<AeadKey, Error> {
    aes_gcm::generate_key(variant, aead_options(extractable)).await
}

pub async fn import_internal_nonce_key(
    variant: AesVariant,
    raw: Vec<u8>,
    extractable: bool,
) -> Result<InternalNonceKey, Error> {
    aes_gcm_internal_nonce::import_key(variant, raw, internal_nonce_options(extractable)).await
}

pub async fn generate_internal_nonce_key(
    variant: AesVariant,
    extractable: bool,
) -> Result<InternalNonceKey, Error> {
    aes_gcm_internal_nonce::generate_key(variant, internal_nonce_options(extractable)).await
}

pub async fn import_chacha_key(raw: Vec<u8>, extractable: bool) -> Result<AeadKey, Error> {
    chacha20_poly1305::import_key(raw, aead_options(extractable)).await
}

pub async fn generate_chacha_key(extractable: bool) -> Result<AeadKey, Error> {
    chacha20_poly1305::generate_key(aead_options(extractable)).await
}

pub async fn import_xchacha_key(raw: Vec<u8>, extractable: bool) -> Result<AeadKey, Error> {
    xchacha20_poly1305::import_key(raw, aead_options(extractable)).await
}

pub async fn generate_xchacha_key(extractable: bool) -> Result<AeadKey, Error> {
    xchacha20_poly1305::generate_key(aead_options(extractable)).await
}

pub async fn import_xchacha_internal_nonce_key(
    raw: Vec<u8>,
    extractable: bool,
) -> Result<InternalNonceKey, Error> {
    xchacha20_poly1305_internal_nonce::import_key(raw, internal_nonce_options(extractable)).await
}

pub async fn generate_xchacha_internal_nonce_key(
    extractable: bool,
) -> Result<InternalNonceKey, Error> {
    xchacha20_poly1305_internal_nonce::generate_key(internal_nonce_options(extractable)).await
}

pub async fn generate_ed25519_key(extractable: bool) -> Result<(SigningKey, VerifyingKey), Error> {
    ed25519_sign::generate_key(signing_options(extractable)).await
}
