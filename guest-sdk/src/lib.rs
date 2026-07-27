//! Guest-side bindings and ergonomic helpers for the `lann:webcrypto`
//! interfaces.
//!
//! This crate is the intended way for Rust guest components to *consume*
//! `lann:webcrypto`: it binds the whole import surface once (the [`raw`]
//! module) and wraps the key resources in newtypes with one-`await`
//! byte-buffer methods, so callers need none of the stream plumbing the
//! interfaces are defined in terms of.
//!
//! Most consumers need **no `lann:webcrypto` WIT at all**: link this crate
//! and call it, and the componentized binary imports exactly the interfaces
//! it uses (unused imports are stripped). Only list the imports in your own
//! world — remapping them onto this crate's [`raw`] modules with
//! wit-bindgen's `with:` option — if your own interfaces name these types or
//! external tooling validates your world's shape. Do **not** bind the same
//! interfaces with a second `generate!` without that remapping: the two
//! expansions would produce distinct, unconvertible resource types.
//!
//! # Contract notes carried over from the WIT
//!
//! - **Byte-buffer methods hide streams, not the drain rule.** The wrapped
//!   operations fully drain their input even when they fail; these helpers
//!   feed the buffer and await the result concurrently, so that contract is
//!   invisible here. Streaming callers use the [`raw`] resources directly
//!   with wit-bindgen's own stream primitives ([`wit_stream::new`],
//!   `StreamWriter::write_all`, `StreamReader::collect`) — this crate adds
//!   no stream API of its own.
//! - **Writer drop ends the message.** A stream's producer failing midway
//!   is indistinguishable from it finishing (the ABI carries no verdict at
//!   end-of-stream). The byte-buffer helpers own their whole input, so this
//!   only concerns streaming callers; see the WIT's truncating-producer
//!   warning.
//! - **Implementations may bound input sizes.** Hosts enforce buffering
//!   limits as recoverable `error.other` values (see the WIT `types.error`
//!   docs); nothing here retries or special-cases them.
//! - **Nonces are the caller's problem only on `aead`.** Prefer
//!   [`InternalNonceKey`] (minted by `aes-gcm-internal-nonce` /
//!   `xchacha20-poly1305-internal-nonce`), whose nonces are
//!   implementation-managed and carried in the sealed message.

#![deny(missing_docs)]

use wit_bindgen::{StreamReader, StreamWriter};

mod bindings {
    #![allow(missing_docs)]
    wit_bindgen::generate!({
        path: "wit",
        world: "imports",
        generate_all,
        pub_export_macro: false,
    });
}

/// The generated bindings for the full `lann:webcrypto` import surface.
///
/// The newtype wrappers cover the common byte-buffer cases; these are the
/// escape hatch for streaming callers and for passing resources through a
/// consumer's own interfaces (via [`MacKey::into_raw`] and friends).
pub mod raw {
    pub use super::bindings::lann::webcrypto::{
        aead, aead_internal_nonce, aes_gcm, aes_gcm_internal_nonce, bytes, chacha20_poly1305,
        digest, ecdsa_sign, ecdsa_verify, ed25519_sign, ed25519_verify, hmac_sha2, mac, sha2,
        signature, types, xchacha20_poly1305, xchacha20_poly1305_internal_nonce,
    };
}

pub use bindings::wit_stream;
pub use raw::types::Error;

// --- operation plumbing ---------------------------------------------------------

/// The error every byte-buffer helper reports when its stream writer was
/// closed before the whole buffer was written — a callee violating the
/// drain rule, which conforming implementations never do.
fn writer_closed<E: RawError>(leftover: usize) -> E {
    E::stream_failure(format!(
        "stream writer closed early with {leftover} bytes unwritten"
    ))
}

/// Run `op` while feeding `data` into `tx`, surfacing the operation's own
/// error over a feeder failure (per the drain rule, the feeder finishing is
/// part of the operation's contract even on error).
async fn call_fed<T, E: RawError>(
    op: impl std::future::Future<Output = Result<T, E>>,
    mut tx: StreamWriter<u8>,
    data: &[u8],
) -> Result<T, E> {
    let feeder = async {
        let leftover = tx.write_all(data.to_vec()).await;
        // The operation resolves only once the stream ends: drop the
        // writer as soon as the buffer is written.
        drop(tx);
        leftover
    };
    let (result, leftover) = futures::join!(op, feeder);
    match (result, leftover.len()) {
        (Err(err), _) => Err(err),
        (Ok(value), 0) => Ok(value),
        (Ok(_), leftover) => Err(writer_closed(leftover)),
    }
}

// --- raw traits ----------------------------------------------------------------

/// The error type of one bindings generation.
///
/// Implemented for this crate's generated [`Error`]; implement it (and the
/// per-resource raw traits) for your own generation's types to use the
/// newtype wrappers with them.
pub trait RawError {
    /// Construct the implementation-defined operational-failure case
    /// (`error.other`) carrying `detail`.
    fn stream_failure(detail: String) -> Self;
}

impl RawError for Error {
    fn stream_failure(detail: String) -> Self {
        Error::Other(detail)
    }
}

/// One bindings generation's `mac.mac-key` resource.
pub trait RawMacKey {
    /// The generation's `types.error`.
    type Error: RawError;
    /// `mac-key.sign`.
    fn sign(
        &self,
        data: StreamReader<u8>,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, Self::Error>>;
    /// `mac-key.verify`.
    fn verify(
        &self,
        data: StreamReader<u8>,
        tag: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>>;
    /// `mac-key.algorithm-name`.
    fn algorithm_name(&self) -> String;
    /// `mac-key.algorithm-hash`.
    fn algorithm_hash(&self) -> Option<String>;
    /// `mac-key.algorithm-length`.
    fn algorithm_length(&self) -> u32;
    /// `mac-key.export-key`.
    fn export_key(&self) -> impl std::future::Future<Output = Result<Vec<u8>, Self::Error>>;
}

impl RawMacKey for raw::mac::MacKey {
    type Error = Error;
    async fn sign(&self, data: StreamReader<u8>) -> Result<Vec<u8>, Error> {
        self.sign(data).await
    }
    async fn verify(&self, data: StreamReader<u8>, tag: Vec<u8>) -> Result<(), Error> {
        self.verify(data, tag).await
    }
    fn algorithm_name(&self) -> String {
        self.algorithm_name()
    }
    fn algorithm_hash(&self) -> Option<String> {
        self.algorithm_hash()
    }
    fn algorithm_length(&self) -> u32 {
        self.algorithm_length()
    }
    async fn export_key(&self) -> Result<Vec<u8>, Error> {
        self.export_key().await
    }
}

/// One bindings generation's `aead.aead-key` resource.
pub trait RawAeadKey {
    /// The generation's `types.error`.
    type Error: RawError;
    /// `aead-key.seal`.
    fn seal(
        &self,
        nonce: Vec<u8>,
        aad: Vec<u8>,
        plaintext: StreamReader<u8>,
    ) -> impl std::future::Future<Output = Result<StreamReader<u8>, Self::Error>>;
    /// `aead-key.open`.
    fn open(
        &self,
        nonce: Vec<u8>,
        aad: Vec<u8>,
        ciphertext: StreamReader<u8>,
    ) -> impl std::future::Future<Output = Result<StreamReader<u8>, Self::Error>>;
    /// `aead-key.algorithm-name`.
    fn algorithm_name(&self) -> String;
    /// `aead-key.algorithm-length`.
    fn algorithm_length(&self) -> u32;
    /// `aead-key.nonce-size`.
    fn nonce_size(&self) -> u32;
    /// `aead-key.tag-size`.
    fn tag_size(&self) -> u32;
    /// `aead-key.export-key`.
    fn export_key(&self) -> impl std::future::Future<Output = Result<Vec<u8>, Self::Error>>;
}

impl RawAeadKey for raw::aead::AeadKey {
    type Error = Error;
    async fn seal(
        &self,
        nonce: Vec<u8>,
        aad: Vec<u8>,
        plaintext: StreamReader<u8>,
    ) -> Result<StreamReader<u8>, Error> {
        self.seal(nonce, aad, plaintext).await
    }
    async fn open(
        &self,
        nonce: Vec<u8>,
        aad: Vec<u8>,
        ciphertext: StreamReader<u8>,
    ) -> Result<StreamReader<u8>, Error> {
        self.open(nonce, aad, ciphertext).await
    }
    fn algorithm_name(&self) -> String {
        self.algorithm_name()
    }
    fn algorithm_length(&self) -> u32 {
        self.algorithm_length()
    }
    fn nonce_size(&self) -> u32 {
        self.nonce_size()
    }
    fn tag_size(&self) -> u32 {
        self.tag_size()
    }
    async fn export_key(&self) -> Result<Vec<u8>, Error> {
        self.export_key().await
    }
}

/// One bindings generation's `aead-internal-nonce.internal-nonce-key`
/// resource.
pub trait RawInternalNonceKey {
    /// The generation's `types.error`.
    type Error: RawError;
    /// `internal-nonce-key.seal`.
    fn seal(
        &self,
        aad: Vec<u8>,
        plaintext: StreamReader<u8>,
    ) -> impl std::future::Future<Output = Result<StreamReader<u8>, Self::Error>>;
    /// `internal-nonce-key.open`.
    fn open(
        &self,
        aad: Vec<u8>,
        sealed: StreamReader<u8>,
    ) -> impl std::future::Future<Output = Result<StreamReader<u8>, Self::Error>>;
    /// `internal-nonce-key.algorithm-name`.
    fn algorithm_name(&self) -> String;
    /// `internal-nonce-key.algorithm-length`.
    fn algorithm_length(&self) -> u32;
    /// `internal-nonce-key.seals-remaining`.
    fn seals_remaining(&self) -> Option<u64>;
    /// `internal-nonce-key.export-key`.
    fn export_key(&self) -> impl std::future::Future<Output = Result<Vec<u8>, Self::Error>>;
}

impl RawInternalNonceKey for raw::aead_internal_nonce::InternalNonceKey {
    type Error = Error;
    async fn seal(
        &self,
        aad: Vec<u8>,
        plaintext: StreamReader<u8>,
    ) -> Result<StreamReader<u8>, Error> {
        self.seal(aad, plaintext).await
    }
    async fn open(
        &self,
        aad: Vec<u8>,
        sealed: StreamReader<u8>,
    ) -> Result<StreamReader<u8>, Error> {
        self.open(aad, sealed).await
    }
    fn algorithm_name(&self) -> String {
        self.algorithm_name()
    }
    fn algorithm_length(&self) -> u32 {
        self.algorithm_length()
    }
    fn seals_remaining(&self) -> Option<u64> {
        self.seals_remaining()
    }
    async fn export_key(&self) -> Result<Vec<u8>, Error> {
        self.export_key().await
    }
}

/// One bindings generation's `digest.digest` resource.
pub trait RawDigest {
    /// The generation's `types.error`.
    type Error: RawError;
    /// `digest.compute`.
    fn compute(
        &self,
        data: StreamReader<u8>,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, Self::Error>>;
    /// `digest.algorithm-name`.
    fn algorithm_name(&self) -> String;
}

impl RawDigest for raw::digest::Digest {
    type Error = Error;
    async fn compute(&self, data: StreamReader<u8>) -> Result<Vec<u8>, Error> {
        self.compute(data).await
    }
    fn algorithm_name(&self) -> String {
        self.algorithm_name()
    }
}

/// One bindings generation's `signature.verifying-key` resource.
pub trait RawVerifyingKey {
    /// The generation's `types.error`.
    type Error: RawError;
    /// `verifying-key.verify`.
    fn verify(
        &self,
        data: StreamReader<u8>,
        sig: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>>;
    /// `verifying-key.algorithm-name`.
    fn algorithm_name(&self) -> String;
    /// `verifying-key.algorithm-curve`.
    fn algorithm_curve(&self) -> Option<String>;
    /// `verifying-key.algorithm-hash`.
    fn algorithm_hash(&self) -> Option<String>;
    /// `verifying-key.export-key`.
    fn export_key(&self) -> impl std::future::Future<Output = Vec<u8>>;
}

impl RawVerifyingKey for raw::signature::VerifyingKey {
    type Error = Error;
    async fn verify(&self, data: StreamReader<u8>, sig: Vec<u8>) -> Result<(), Error> {
        self.verify(data, sig).await
    }
    fn algorithm_name(&self) -> String {
        self.algorithm_name()
    }
    fn algorithm_curve(&self) -> Option<String> {
        self.algorithm_curve()
    }
    fn algorithm_hash(&self) -> Option<String> {
        self.algorithm_hash()
    }
    async fn export_key(&self) -> Vec<u8> {
        self.export_key().await
    }
}

/// One bindings generation's `signature.signing-key` resource.
pub trait RawSigningKey {
    /// The generation's `types.error`.
    type Error: RawError;
    /// The generation's `verifying-key` resource.
    type VerifyingKey: RawVerifyingKey<Error = Self::Error>;
    /// `signing-key.sign`.
    fn sign(
        &self,
        data: StreamReader<u8>,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, Self::Error>>;
    /// `signing-key.verifying-key`.
    fn verifying_key(&self) -> Self::VerifyingKey;
    /// `signing-key.algorithm-name`.
    fn algorithm_name(&self) -> String;
    /// `signing-key.algorithm-curve`.
    fn algorithm_curve(&self) -> Option<String>;
    /// `signing-key.algorithm-hash`.
    fn algorithm_hash(&self) -> Option<String>;
    /// `signing-key.extractable`.
    fn extractable(&self) -> bool;
    /// `signing-key.export-key`.
    fn export_key(&self) -> impl std::future::Future<Output = Result<Vec<u8>, Self::Error>>;
}

impl RawSigningKey for raw::signature::SigningKey {
    type Error = Error;
    type VerifyingKey = raw::signature::VerifyingKey;
    async fn sign(&self, data: StreamReader<u8>) -> Result<Vec<u8>, Error> {
        self.sign(data).await
    }
    fn verifying_key(&self) -> raw::signature::VerifyingKey {
        self.verifying_key()
    }
    fn algorithm_name(&self) -> String {
        self.algorithm_name()
    }
    fn algorithm_curve(&self) -> Option<String> {
        self.algorithm_curve()
    }
    fn algorithm_hash(&self) -> Option<String> {
        self.algorithm_hash()
    }
    fn extractable(&self) -> bool {
        self.extractable()
    }
    async fn export_key(&self) -> Result<Vec<u8>, Error> {
        self.export_key().await
    }
}

// --- newtypes ------------------------------------------------------------------

/// Generate the shared newtype plumbing: constructors, raw accessors, and
/// `From` in both directions.
macro_rules! newtype_common {
    ($name:ident, $bound:ident, $default:ty, $doc_res:literal) => {
        impl<R: $bound> $name<R> {
            #[doc = concat!("Wrap a raw `", $doc_res, "` resource.")]
            pub fn from_raw(raw: R) -> Self {
                Self(raw)
            }

            #[doc = concat!("Borrow the raw `", $doc_res, "` resource.")]
            pub fn as_raw(&self) -> &R {
                &self.0
            }

            #[doc = concat!("Unwrap into the raw `", $doc_res, "` resource.")]
            pub fn into_raw(self) -> R {
                self.0
            }
        }

        impl<R: $bound> From<R> for $name<R> {
            fn from(raw: R) -> Self {
                Self(raw)
            }
        }
    };
}

/// A `mac.mac-key`: sign and verify byte buffers with one `await` each.
///
/// Generic over the bindings generation (see [`RawMacKey`]); the default is
/// this crate's own [`raw`] bindings.
pub struct MacKey<R: RawMacKey = raw::mac::MacKey>(R);
newtype_common!(MacKey, RawMacKey, raw::mac::MacKey, "mac-key");

impl<R: RawMacKey> MacKey<R> {
    /// Compute the authentication tag over `data`.
    pub async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, R::Error> {
        let (tx, rx) = wit_stream::new();
        call_fed(self.0.sign(rx), tx, data).await
    }

    /// Verify `tag` over `data`, failing closed with
    /// `error.authentication-failed`.
    pub async fn verify(&self, data: &[u8], tag: &[u8]) -> Result<(), R::Error> {
        let (tx, rx) = wit_stream::new();
        call_fed(self.0.verify(rx, tag.to_vec()), tx, data).await
    }

    /// The registry name of the key's algorithm family, e.g. `"HMAC"`.
    pub fn algorithm_name(&self) -> String {
        self.0.algorithm_name()
    }

    /// The registry name of the digest the algorithm is parameterized over,
    /// e.g. `"SHA-256"`.
    pub fn algorithm_hash(&self) -> Option<String> {
        self.0.algorithm_hash()
    }

    /// The key length in bits.
    pub fn algorithm_length(&self) -> u32 {
        self.0.algorithm_length()
    }

    /// The raw key material; fails with `error.not-extractable` unless the
    /// key was minted extractable.
    pub async fn export_key(&self) -> Result<Vec<u8>, R::Error> {
        self.0.export_key().await
    }
}

/// An `aead.aead-key`: caller-nonce seal and open over byte buffers.
///
/// Prefer [`InternalNonceKey`] unless interop requires an externally
/// specified nonce layout: nonce reuse under one key is catastrophic, and
/// this type's `seal` leaves nonce uniqueness entirely to you.
pub struct AeadKey<R: RawAeadKey = raw::aead::AeadKey>(R);
newtype_common!(AeadKey, RawAeadKey, raw::aead::AeadKey, "aead-key");

impl<R: RawAeadKey> AeadKey<R> {
    /// Encrypt and authenticate `plaintext` under `nonce` and `aad`,
    /// returning `ciphertext ‖ tag`. The caller is responsible for nonce
    /// uniqueness per key.
    pub async fn seal(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, R::Error> {
        let (tx, rx) = wit_stream::new();
        let out = call_fed(self.0.seal(nonce.to_vec(), aad.to_vec(), rx), tx, plaintext).await?;
        Ok(out.collect().await)
    }

    /// Decrypt and verify `ciphertext ‖ tag` under `nonce` and `aad`,
    /// failing closed with `error.authentication-failed`.
    pub async fn open(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, R::Error> {
        let (tx, rx) = wit_stream::new();
        let out = call_fed(
            self.0.open(nonce.to_vec(), aad.to_vec(), rx),
            tx,
            ciphertext,
        )
        .await?;
        Ok(out.collect().await)
    }

    /// The registry name of the key's algorithm family, e.g. `"AES-GCM"`.
    pub fn algorithm_name(&self) -> String {
        self.0.algorithm_name()
    }

    /// The key length in bits.
    pub fn algorithm_length(&self) -> u32 {
        self.0.algorithm_length()
    }

    /// The size in bytes of the nonce `seal`/`open` require.
    pub fn nonce_size(&self) -> u32 {
        self.0.nonce_size()
    }

    /// The size in bytes of the tag trailing the ciphertext.
    pub fn tag_size(&self) -> u32 {
        self.0.tag_size()
    }

    /// The raw key material; fails with `error.not-extractable` unless the
    /// key was minted extractable.
    pub async fn export_key(&self) -> Result<Vec<u8>, R::Error> {
        self.0.export_key().await
    }
}

/// An `aead-internal-nonce.internal-nonce-key`: misuse-resistant seal and
/// open — the nonce is implementation-managed and carried in the sealed
/// message (wire format per the minting interface).
pub struct InternalNonceKey<R: RawInternalNonceKey = raw::aead_internal_nonce::InternalNonceKey>(R);
newtype_common!(
    InternalNonceKey,
    RawInternalNonceKey,
    raw::aead_internal_nonce::InternalNonceKey,
    "internal-nonce-key"
);

impl<R: RawInternalNonceKey> InternalNonceKey<R> {
    /// Encrypt and authenticate `plaintext` under a fresh
    /// implementation-generated nonce with `aad`, returning the
    /// self-contained sealed message.
    pub async fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, R::Error> {
        let (tx, rx) = wit_stream::new();
        let out = call_fed(self.0.seal(aad.to_vec(), rx), tx, plaintext).await?;
        Ok(out.collect().await)
    }

    /// Decrypt and verify a sealed message under `aad`, failing closed with
    /// `error.authentication-failed`.
    pub async fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, R::Error> {
        let (tx, rx) = wit_stream::new();
        let out = call_fed(self.0.open(aad.to_vec(), rx), tx, sealed).await?;
        Ok(out.collect().await)
    }

    /// The registry name of the key's algorithm family.
    pub fn algorithm_name(&self) -> String {
        self.0.algorithm_name()
    }

    /// The key length in bits.
    pub fn algorithm_length(&self) -> u32 {
        self.0.algorithm_length()
    }

    /// The remaining nonce budget, as a key-rotation hint; `none` when no
    /// budget is enforced.
    pub fn seals_remaining(&self) -> Option<u64> {
        self.0.seals_remaining()
    }

    /// The raw key material; fails with `error.not-extractable` unless the
    /// key was minted extractable.
    pub async fn export_key(&self) -> Result<Vec<u8>, R::Error> {
        self.0.export_key().await
    }
}

/// A `digest.digest`: a reusable, algorithm-bound hash.
pub struct Digest<R: RawDigest = raw::digest::Digest>(R);
newtype_common!(Digest, RawDigest, raw::digest::Digest, "digest");

impl<R: RawDigest> Digest<R> {
    /// Digest `data`.
    pub async fn compute(&self, data: &[u8]) -> Result<Vec<u8>, R::Error> {
        let (tx, rx) = wit_stream::new();
        call_fed(self.0.compute(rx), tx, data).await
    }

    /// The registry name of the algorithm, e.g. `"SHA-256"`.
    pub fn algorithm_name(&self) -> String {
        self.0.algorithm_name()
    }
}

/// A `signature.verifying-key`: public-key signature verification.
pub struct VerifyingKey<R: RawVerifyingKey = raw::signature::VerifyingKey>(R);
newtype_common!(
    VerifyingKey,
    RawVerifyingKey,
    raw::signature::VerifyingKey,
    "verifying-key"
);

impl<R: RawVerifyingKey> VerifyingKey<R> {
    /// Verify `sig` over `data`, failing closed with
    /// `error.authentication-failed` (per the minting interface's
    /// verification criterion).
    pub async fn verify(&self, data: &[u8], sig: &[u8]) -> Result<(), R::Error> {
        let (tx, rx) = wit_stream::new();
        call_fed(self.0.verify(rx, sig.to_vec()), tx, data).await
    }

    /// The registry name of the key's algorithm family, e.g. `"Ed25519"`.
    pub fn algorithm_name(&self) -> String {
        self.0.algorithm_name()
    }

    /// The curve name for curve-parameterized algorithms, e.g. `"P-256"`.
    pub fn algorithm_curve(&self) -> Option<String> {
        self.0.algorithm_curve()
    }

    /// The mint-bound digest name, e.g. `"SHA-256"`.
    pub fn algorithm_hash(&self) -> Option<String> {
        self.0.algorithm_hash()
    }

    /// The public key material (always exportable).
    pub async fn export_key(&self) -> Vec<u8> {
        self.0.export_key().await
    }
}

/// A `signature.signing-key`: private-key signing.
pub struct SigningKey<R: RawSigningKey = raw::signature::SigningKey>(R);
newtype_common!(
    SigningKey,
    RawSigningKey,
    raw::signature::SigningKey,
    "signing-key"
);

impl<R: RawSigningKey> SigningKey<R> {
    /// Sign `data`, returning the signature in the minting interface's
    /// documented wire format.
    pub async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, R::Error> {
        let (tx, rx) = wit_stream::new();
        call_fed(self.0.sign(rx), tx, data).await
    }

    /// Derive the corresponding public key.
    pub fn verifying_key(&self) -> VerifyingKey<R::VerifyingKey> {
        VerifyingKey::from_raw(self.0.verifying_key())
    }

    /// The registry name of the key's algorithm family.
    pub fn algorithm_name(&self) -> String {
        self.0.algorithm_name()
    }

    /// The curve name for curve-parameterized algorithms.
    pub fn algorithm_curve(&self) -> Option<String> {
        self.0.algorithm_curve()
    }

    /// The mint-bound digest name.
    pub fn algorithm_hash(&self) -> Option<String> {
        self.0.algorithm_hash()
    }

    /// Whether `export-key` may return the private material.
    pub fn extractable(&self) -> bool {
        self.0.extractable()
    }

    /// The private key material; fails with `error.not-extractable` unless
    /// the key was minted extractable.
    pub async fn export_key(&self) -> Result<Vec<u8>, R::Error> {
        self.0.export_key().await
    }
}

// --- minting -------------------------------------------------------------------

/// Key and digest minting over this crate's own bindings, one module per
/// algorithm interface, returning the newtype wrappers.
pub mod mint {
    use super::*;

    /// `hmac-sha2` minting.
    pub mod hmac_sha2 {
        use super::*;
        pub use raw::sha2::Sha2Variant;

        /// Import raw key material as an HMAC key over `variant`.
        pub async fn import_key(
            variant: Sha2Variant,
            raw_material: Vec<u8>,
            extractable: bool,
        ) -> Result<MacKey, Error> {
            Ok(MacKey::from_raw(
                raw::hmac_sha2::import_key(variant, raw_material, extractable).await?,
            ))
        }

        /// Generate a fresh random HMAC key over `variant`.
        pub async fn generate_key(
            variant: Sha2Variant,
            extractable: bool,
        ) -> Result<MacKey, Error> {
            Ok(MacKey::from_raw(
                raw::hmac_sha2::generate_key(variant, extractable).await?,
            ))
        }
    }

    /// `aes-gcm` minting (caller-nonce).
    pub mod aes_gcm {
        use super::*;
        pub use raw::aes_gcm::AesVariant;

        /// Import raw key material as the declared AES variant.
        pub async fn import_key(
            variant: AesVariant,
            raw_material: Vec<u8>,
            extractable: bool,
        ) -> Result<AeadKey, Error> {
            Ok(AeadKey::from_raw(
                raw::aes_gcm::import_key(variant, raw_material, extractable).await?,
            ))
        }

        /// Generate a fresh random key of the declared AES variant.
        pub async fn generate_key(
            variant: AesVariant,
            extractable: bool,
        ) -> Result<AeadKey, Error> {
            Ok(AeadKey::from_raw(
                raw::aes_gcm::generate_key(variant, extractable).await?,
            ))
        }
    }

    /// `chacha20-poly1305` minting (IETF construction, caller-nonce).
    pub mod chacha20_poly1305 {
        use super::*;

        /// Import 32 bytes of raw key material.
        pub async fn import_key(
            raw_material: Vec<u8>,
            extractable: bool,
        ) -> Result<AeadKey, Error> {
            Ok(AeadKey::from_raw(
                raw::chacha20_poly1305::import_key(raw_material, extractable).await?,
            ))
        }

        /// Generate a fresh random 256-bit key.
        pub async fn generate_key(extractable: bool) -> Result<AeadKey, Error> {
            Ok(AeadKey::from_raw(
                raw::chacha20_poly1305::generate_key(extractable).await?,
            ))
        }
    }

    /// `xchacha20-poly1305` minting (extended-nonce construction,
    /// caller-nonce).
    pub mod xchacha20_poly1305 {
        use super::*;

        /// Import 32 bytes of raw key material.
        pub async fn import_key(
            raw_material: Vec<u8>,
            extractable: bool,
        ) -> Result<AeadKey, Error> {
            Ok(AeadKey::from_raw(
                raw::xchacha20_poly1305::import_key(raw_material, extractable).await?,
            ))
        }

        /// Generate a fresh random 256-bit key.
        pub async fn generate_key(extractable: bool) -> Result<AeadKey, Error> {
            Ok(AeadKey::from_raw(
                raw::xchacha20_poly1305::generate_key(extractable).await?,
            ))
        }
    }

    /// `aes-gcm-internal-nonce` minting.
    pub mod aes_gcm_internal_nonce {
        use super::*;
        pub use raw::aes_gcm::AesVariant;

        /// Import raw key material as an internal-nonce AES-GCM key.
        pub async fn import_key(
            variant: AesVariant,
            raw_material: Vec<u8>,
            extractable: bool,
        ) -> Result<InternalNonceKey, Error> {
            Ok(InternalNonceKey::from_raw(
                raw::aes_gcm_internal_nonce::import_key(variant, raw_material, extractable).await?,
            ))
        }

        /// Generate a fresh random internal-nonce AES-GCM key.
        pub async fn generate_key(
            variant: AesVariant,
            extractable: bool,
        ) -> Result<InternalNonceKey, Error> {
            Ok(InternalNonceKey::from_raw(
                raw::aes_gcm_internal_nonce::generate_key(variant, extractable).await?,
            ))
        }
    }

    /// `xchacha20-poly1305-internal-nonce` minting — the recommended
    /// internal-nonce algorithm.
    pub mod xchacha20_poly1305_internal_nonce {
        use super::*;

        /// Import 32 bytes of raw key material as an internal-nonce key.
        pub async fn import_key(
            raw_material: Vec<u8>,
            extractable: bool,
        ) -> Result<InternalNonceKey, Error> {
            Ok(InternalNonceKey::from_raw(
                raw::xchacha20_poly1305_internal_nonce::import_key(raw_material, extractable)
                    .await?,
            ))
        }

        /// Generate a fresh random internal-nonce key.
        pub async fn generate_key(extractable: bool) -> Result<InternalNonceKey, Error> {
            Ok(InternalNonceKey::from_raw(
                raw::xchacha20_poly1305_internal_nonce::generate_key(extractable).await?,
            ))
        }
    }

    /// `sha2` digest minting.
    pub mod sha2 {
        use super::*;
        pub use raw::sha2::Sha2Variant;

        /// Mint a digest bound to the declared SHA-2 variant.
        pub fn make_digest(variant: Sha2Variant) -> Result<Digest, Error> {
            Ok(Digest::from_raw(raw::sha2::make_digest(variant)?))
        }
    }

    /// `ed25519-verify` / `ed25519-sign` minting.
    pub mod ed25519 {
        use super::*;

        /// Import a 32-byte raw public key.
        pub async fn import_verifying_key(raw_material: Vec<u8>) -> Result<VerifyingKey, Error> {
            Ok(VerifyingKey::from_raw(
                raw::ed25519_verify::import_verifying_key(raw_material).await?,
            ))
        }

        /// Import a 32-byte raw private key (the RFC 8032 seed).
        pub async fn import_signing_key(
            raw_material: Vec<u8>,
            extractable: bool,
        ) -> Result<SigningKey, Error> {
            Ok(SigningKey::from_raw(
                raw::ed25519_sign::import_signing_key(raw_material, extractable).await?,
            ))
        }

        /// Generate a fresh random signing key.
        pub async fn generate_key(extractable: bool) -> Result<SigningKey, Error> {
            Ok(SigningKey::from_raw(
                raw::ed25519_sign::generate_key(extractable).await?,
            ))
        }
    }

    /// `ecdsa-verify` / `ecdsa-sign` minting.
    pub mod ecdsa {
        use super::*;
        pub use raw::ecdsa_verify::EcdsaVariant;

        /// Import a public key as an uncompressed SEC1 point.
        pub async fn import_verifying_key(
            variant: EcdsaVariant,
            raw_material: Vec<u8>,
        ) -> Result<VerifyingKey, Error> {
            Ok(VerifyingKey::from_raw(
                raw::ecdsa_verify::import_verifying_key(variant, raw_material).await?,
            ))
        }

        /// Import a raw scalar as a signing key of the declared variant.
        pub async fn import_signing_key(
            variant: EcdsaVariant,
            raw_material: Vec<u8>,
            extractable: bool,
        ) -> Result<SigningKey, Error> {
            Ok(SigningKey::from_raw(
                raw::ecdsa_sign::import_signing_key(variant, raw_material, extractable).await?,
            ))
        }

        /// Generate a fresh random signing key of the declared variant.
        pub async fn generate_key(
            variant: EcdsaVariant,
            extractable: bool,
        ) -> Result<SigningKey, Error> {
            Ok(SigningKey::from_raw(
                raw::ecdsa_sign::generate_key(variant, extractable).await?,
            ))
        }
    }
}

/// `bytes.constant-time-equal`: whether `a` and `b` are equal, in time
/// independent of their contents.
pub fn constant_time_equal(a: &[u8], b: &[u8]) -> bool {
    raw::bytes::constant_time_equal(a, b)
}
