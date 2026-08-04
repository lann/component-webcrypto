//! Host trait implementations for the `lann:webcrypto` imports.
//!
//! Following the split the generated bindings produce (and mirroring
//! `wasmtime_wasi_http::p3`), the store-free traits are implemented for the
//! [`WasiWebcryptoCtxView`] "data" type, while the traits whose methods need
//! the async `Accessor` are implemented for the [`WasiWebcrypto`] `HasData`
//! marker.
//!
//! The cryptography itself lives in `lann-webcrypto-core`, shared verbatim
//! with the in-guest provider; this module contributes only what is
//! host-specific — the resource table and the shapes every operation
//! shares (mint into the table, drain-then-compute, drain-then-stream-out),
//! over the stream plumbing in [`crate::streams`] and the admission in
//! [`crate::limits`].

use lann_webcrypto_core::{
    served_sha2, AeadKeyMaterial, DecryptionKeyMaterial, DigestKind, EncryptionKeyMaterial,
    KwKeyMaterial, MacKeyMaterial, Sha1Posture, SigPublic, SigningKeyMaterial, WrapFormat,
    WrapInputMaterial, HMAC_NAME,
};
use wasmtime::component::{Accessor, Resource, StreamReader};
use wasmtime::Result;

use crate::bindings::webcrypto::aead::{self, HostAeadKey, HostAeadKeyWithStore};
use crate::bindings::webcrypto::aead_internal_nonce::{
    self, HostInternalNonceKey, HostInternalNonceKeyWithStore,
};
use crate::bindings::webcrypto::cipher::{
    self as cipher_iface, HostCipherKey, HostCipherKeyWithStore,
};
use crate::bindings::webcrypto::derivation::{
    self as derivation_iface, HostDeriveInput, HostDeriveInputWithStore,
};
use crate::bindings::webcrypto::digest::{HostDigest, HostDigestWithStore};
use crate::bindings::webcrypto::hkdf::{self as hkdf_iface, HostIkm, HostIkmWithStore};
use crate::bindings::webcrypto::key_agreement::{
    self as key_agreement_iface, HostPublicKey, HostPublicKeyWithStore, HostSecretKey,
    HostSecretKeyWithStore,
};
use crate::bindings::webcrypto::key_wrap::{
    self as key_wrap_iface, HostKwKey, HostKwKeyOptionsWithStore, HostKwKeyWithStore,
};
use crate::bindings::webcrypto::mac::{self, HostMacKey, HostMacKeyWithStore};
use crate::bindings::webcrypto::pbkdf2::{
    self as pbkdf2_iface, HostPassword, HostPasswordWithStore,
};
use crate::bindings::webcrypto::public_encryption::{
    self as public_encryption_iface, HostDecryptionKey, HostDecryptionKeyWithStore,
    HostEncryptionKey, HostEncryptionKeyWithStore,
};
use crate::bindings::webcrypto::types::{self, Error};
use crate::bindings::webcrypto::wrapping::{
    self as wrapping_iface, HostUnwrapInput, HostUnwrapInputWithStore, HostWrapInput,
    HostWrapInputWithStore,
};
use crate::bindings::webcrypto::{
    aes_cbc as aes_cbc_iface, aes_ctr as aes_ctr_iface, aes_gcm as aes_gcm_iface,
    aes_gcm_internal_nonce as aes_gcm_in_iface, aes_kw as aes_kw_iface, bytes as bytes_iface,
    chacha20_poly1305 as chacha_iface, digest as digest_iface, ecdh as ecdh_iface,
    ecdsa_sign as ecdsa_sign_iface, ecdsa_verify as ecdsa_verify_iface,
    ed25519_sign as ed25519_sign_iface, ed25519_verify as ed25519_verify_iface,
    hkdf_sha1 as hkdf_sha1_iface, hkdf_sha2 as hkdf_sha2_iface, hmac_sha1 as hmac_sha1_iface,
    hmac_sha2 as hmac_sha2_iface, pbkdf2_sha1 as pbkdf2_sha1_iface,
    pbkdf2_sha2 as pbkdf2_sha2_iface, rsa as rsa_iface, rsa_oaep_decrypt as rsa_oaep_decrypt_iface,
    rsa_oaep_encrypt as rsa_oaep_encrypt_iface, rsa_pss_sign as rsa_pss_sign_iface,
    rsa_pss_verify as rsa_pss_verify_iface, rsassa_pkcs1_v15_sign as rsassa_sign_iface,
    rsassa_pkcs1_v15_verify as rsassa_verify_iface, sha1_checked as sha1_checked_iface,
    sha2 as sha2_iface, signature as signature_iface, x25519 as x25519_iface,
    xchacha20_poly1305 as xchacha_iface, xchacha20_poly1305_internal_nonce as xchacha_in_iface,
};
use crate::limits::{admit_input, Reservation};
use crate::streams::{drain_stream, GuardedOutput};
use crate::{
    AeadKey, AgreementPublicKey, AgreementSecretKey, CipherKey, DecryptionKey, DeriveInput, Digest,
    EncryptionKey, Ikm, InternalNonceKey, KwKey, MacKey, Minted, Password, SigningKey, UnwrapInput,
    VerifyingKey, WasiWebcrypto, WasiWebcryptoCtxView, WrapInput,
};

// --- bindings glue -------------------------------------------------------------

lann_webcrypto_core::impl_conversions! {
    error: Error,
    extension: types::ExtensionError,
    sha2: sha2_iface::Sha2Variant,
    aes: aes_gcm_iface::AesVariant,
    ecdsa: ecdsa_verify_iface::EcdsaVariant,
    ecdh: ecdh_iface::EcdhVariant,
    rsa: rsa_iface::RsaVariant,
}

/// Render an entropy failure as the trap-shaped host error for key or nonce
/// generation: the host treats a failing random source as an operational
/// host fault, never a guest-visible WIT error.
fn rng_trap(what: &str) -> impl Fn(lann_webcrypto_core::RngError) -> wasmtime::Error + '_ {
    move |err| wasmtime::Error::msg(format!("{what} failed: {err}"))
}

// --- shared operation shapes ---------------------------------------------------

/// The message for a mint the retention budget cannot admit.
fn retention_message(limit: u64) -> String {
    format!(
        "minted resources exceed the retention limit ({limit} bytes); see \
         WasiWebcryptoCtx::set_retention_limit"
    )
}

/// Render an exhausted retention budget as the WIT's recoverable
/// operational error.
fn retention_exhausted(limit: u64) -> Error {
    Error::Other(retention_message(limit))
}

/// Charge one resource's retention floor, trap-shaped: for the
/// `*-options.new` constructors, whose WIT signatures carry no error
/// channel.
fn charge_floor_or_trap(ctx: &crate::WasiWebcryptoCtx) -> Result<Reservation> {
    ctx.charge_retention(0)
        .ok_or_else(|| wasmtime::Error::msg(retention_message(ctx.retention_limit_bytes())))
}

/// Consume a `*-key-options` resource (the mint took ownership), yielding
/// its accumulated state.
async fn take_options<T: Send, O: Send + 'static>(
    accessor: &Accessor<T, WasiWebcrypto>,
    options: Resource<O>,
) -> Result<O> {
    accessor.with(|mut access| Ok(access.get().table.delete(options)?))
}

/// Charge a mint's retention (the per-resource floor plus the payload's
/// variable-length material bytes, fail-fast — see `lib.rs`,
/// "Minted-resource retention"), then push its outcome into the store's
/// table: a successful mint becomes a resource handle assembled by
/// [`Minted::minted`], carrying its reservation; a WIT error — the core's
/// verdict, or the exhausted budget — flows to the caller.
async fn mint<T: Send, R: Minted + Send + 'static>(
    accessor: &Accessor<T, WasiWebcrypto>,
    minted: std::result::Result<R::Payload, lann_webcrypto_core::Error>,
) -> Result<std::result::Result<Resource<R>, Error>> {
    let payload = match minted {
        Ok(payload) => payload,
        Err(err) => return Ok(Err(err.into())),
    };
    accessor.with(|mut access| {
        let view = access.get();
        match view.ctx.charge_retention(R::payload_bytes(&payload)) {
            Some(retention) => Ok(Ok(view.table.push(R::minted(payload, retention))?)),
            None => Ok(Err(retention_exhausted(view.ctx.retention_limit_bytes()))),
        }
    })
}

/// Charge the retention floor for each half of a generated key pair, then
/// push both into the store's table (both halves are floor-only resources).
/// An exhausted budget mints neither half.
async fn mint_key_pair<T: Send, A, B>(
    accessor: &Accessor<T, WasiWebcrypto>,
    first: A::Payload,
    second: B::Payload,
) -> Result<std::result::Result<(Resource<A>, Resource<B>), Error>>
where
    A: Minted + Send + 'static,
    B: Minted + Send + 'static,
{
    accessor.with(|mut access| {
        let view = access.get();
        let (Some(r1), Some(r2)) = (view.ctx.charge_retention(0), view.ctx.charge_retention(0))
        else {
            return Ok(Err(retention_exhausted(view.ctx.retention_limit_bytes())));
        };
        let a = view.table.push(A::minted(first, r1))?;
        let b = view.table.push(B::minted(second, r2))?;
        Ok(Ok((a, b)))
    })
}

/// Run `op` on the table-held resource behind `self_`.
async fn with_resource<T: Send, R: 'static, O>(
    accessor: &Accessor<T, WasiWebcrypto>,
    self_: Resource<R>,
    op: impl FnOnce(&R) -> O,
) -> Result<O> {
    accessor.with(|mut access| Ok(op(access.get().table.get(&self_)?)))
}

/// Mint a `wrap-input` from a key's gated serialization: the shape every
/// `to-wrap-input-*` shares.
async fn to_wrap_input<T: Send, R: 'static>(
    accessor: &Accessor<T, WasiWebcrypto>,
    self_: Resource<R>,
    format: WrapFormat,
    serialize: impl FnOnce(&R) -> std::result::Result<Vec<u8>, lann_webcrypto_core::Error>,
) -> Result<std::result::Result<Resource<WrapInput>, Error>> {
    let material = with_resource(accessor, self_, |key| {
        serialize(key).map(|bytes| WrapInputMaterial::new(format, bytes))
    })
    .await?;
    mint(accessor, material).await
}

/// Delete the table-held resource behind `rep` (the `drop` every key
/// resource shares).
async fn drop_resource<T: Send, R: 'static>(
    accessor: &Accessor<T, WasiWebcrypto>,
    rep: Resource<R>,
) -> Result<()> {
    accessor.with(|mut access| {
        access.get().table.delete(rep)?;
        Ok(())
    })
}

/// The shared shape of every `*-options` resource: `new` charges the
/// retention floor and mints an all-deny policy holder into the table, each
/// setter writes one boolean policy field, and `drop` deletes the table
/// entry. One invocation per options resource, listing its WIT setters as
/// `method => policy field` rows.
macro_rules! host_options {
    (
        $iface:ident::{$host:ident, $host_with_store:ident} for $ty:ty {
            $($method:ident => $field:ident),+ $(,)?
        }
    ) => {
        impl $iface::$host for WasiWebcryptoCtxView<'_> {
            fn new(&mut self) -> Result<Resource<$ty>> {
                let retention = charge_floor_or_trap(self.ctx)?;
                Ok(self
                    .table
                    .push(<$ty>::minted(Default::default(), retention))?)
            }

            $(
                fn $method(&mut self, self_: Resource<$ty>, allowed: bool) -> Result<()> {
                    self.table.get_mut(&self_)?.policy.$field = allowed;
                    Ok(())
                }
            )+
        }

        impl<T: Send> $iface::$host_with_store<T> for WasiWebcrypto {
            async fn drop(accessor: &Accessor<T, Self>, rep: Resource<$ty>) -> Result<()> {
                drop_resource(accessor, rep).await
            }
        }
    };
}

/// Admit one operation, drain its whole input under the admitted cap, then
/// run `op` on the table-held resource over the buffered bytes — the shape
/// of every buffer-then-compute operation. Per the WIT contract the input
/// stream is fully drained even when the call resolves with an error, so
/// the caller's writer always completes.
async fn drain_then<T: Send, R: 'static, O>(
    accessor: &Accessor<T, WasiWebcrypto>,
    self_: Resource<R>,
    data: StreamReader<u8>,
    op: impl FnOnce(&R, &[u8]) -> std::result::Result<O, Error>,
) -> Result<std::result::Result<O, Error>> {
    let (_reservation, cap) = admit_input(accessor).await?;
    let bytes = match drain_stream(accessor, data, cap).await? {
        Ok(bytes) => bytes,
        Err(err) => return Ok(Err(err)),
    };
    accessor.with(|mut access| Ok(op(access.get().table.get(&self_)?, &bytes)))
}

/// Like [`drain_then`], for the seal/open shape: `op`'s output bytes are
/// handed back as a stream whose producer carries the admission
/// reservation, so pool capacity frees only when the bytes have left.
/// (`op`'s outer `Result` is a trap-shaped host error — a failing nonce
/// source.) Buffering the whole message is inherent to this shape: for
/// `open`, no unverified plaintext may be observable.
async fn drain_then_stream<T: Send, R: 'static>(
    accessor: &Accessor<T, WasiWebcrypto>,
    self_: Resource<R>,
    input: StreamReader<u8>,
    op: impl FnOnce(&mut R, &[u8]) -> Result<std::result::Result<Vec<u8>, Error>>,
) -> Result<std::result::Result<StreamReader<u8>, Error>> {
    let (reservation, cap) = admit_input(accessor).await?;
    let msg = match drain_stream(accessor, input, cap).await? {
        Ok(msg) => msg,
        Err(err) => return Ok(Err(err)),
    };
    let out = accessor.with(|mut access| op(access.get().table.get_mut(&self_)?, &msg))?;
    let out = match out {
        Ok(out) => out,
        Err(err) => return Ok(Err(err)),
    };
    let reader =
        accessor.with(|access| StreamReader::new(access, GuardedOutput::new(out, reservation)))?;
    Ok(Ok(reader))
}

// --- types -------------------------------------------------------------------

impl types::Host for WasiWebcryptoCtxView<'_> {}

// --- bytes ---------------------------------------------------------------------

impl bytes_iface::Host for WasiWebcryptoCtxView<'_> {
    fn constant_time_equal(&mut self, a: Vec<u8>, b: Vec<u8>) -> Result<bool> {
        Ok(lann_webcrypto_core::constant_time_equal(&a, &b))
    }
}

// --- mac ---------------------------------------------------------------------

impl mac::Host for WasiWebcryptoCtxView<'_> {}

impl HostMacKey for WasiWebcryptoCtxView<'_> {
    fn algorithm_name(&mut self, self_: Resource<MacKey>) -> Result<String> {
        self.table.get(&self_)?;
        Ok(HMAC_NAME.to_string())
    }

    fn algorithm_hash(&mut self, self_: Resource<MacKey>) -> Result<Option<String>> {
        Ok(Some(
            self.table.get(&self_)?.material.hash_name().to_string(),
        ))
    }

    fn algorithm_length(&mut self, self_: Resource<MacKey>) -> Result<u32> {
        Ok(self.table.get(&self_)?.material.length_bits())
    }

    fn extractable(&mut self, self_: Resource<MacKey>) -> Result<bool> {
        Ok(self.table.get(&self_)?.material.extractable())
    }

    fn can_sign(&mut self, self_: Resource<MacKey>) -> Result<bool> {
        Ok(self.table.get(&self_)?.material.can_sign())
    }

    fn can_verify(&mut self, self_: Resource<MacKey>) -> Result<bool> {
        Ok(self.table.get(&self_)?.material.can_verify())
    }
}

host_options! {
    mac::{HostMacKeyOptions, HostMacKeyOptionsWithStore} for crate::MacKeyOptions {
        can_sign => sign,
        can_verify => verify,
        extractable => extractable,
    }
}

impl<T: Send> HostMacKeyWithStore<T> for WasiWebcrypto {
    async fn sign(
        accessor: &Accessor<T, Self>,
        self_: Resource<MacKey>,
        data: StreamReader<u8>,
    ) -> Result<std::result::Result<Vec<u8>, Error>> {
        // Buffer the whole stream, then fold it into the HMAC state; the
        // result is chunking-invariant either way.
        drain_then(accessor, self_, data, |key, bytes| {
            key.material.sign(bytes).map_err(Error::from)
        })
        .await
    }

    async fn verify(
        accessor: &Accessor<T, Self>,
        self_: Resource<MacKey>,
        data: StreamReader<u8>,
        tag: Vec<u8>,
    ) -> Result<std::result::Result<(), Error>> {
        drain_then(accessor, self_, data, |key, bytes| {
            key.material.verify(bytes, &tag).map_err(Error::from)
        })
        .await
    }

    async fn export_key_raw(
        accessor: &Accessor<T, Self>,
        self_: Resource<MacKey>,
    ) -> Result<std::result::Result<Vec<u8>, Error>> {
        with_resource(accessor, self_, |key| {
            key.material.export().map_err(Error::from)
        })
        .await
    }

    async fn export_key_jwk(
        accessor: &Accessor<T, Self>,
        self_: Resource<MacKey>,
    ) -> Result<std::result::Result<String, Error>> {
        with_resource(accessor, self_, |key| {
            key.material.export_jwk().map_err(Error::from)
        })
        .await
    }

    async fn to_wrap_input_raw(
        accessor: &Accessor<T, Self>,
        self_: Resource<MacKey>,
    ) -> Result<std::result::Result<Resource<WrapInput>, Error>> {
        to_wrap_input(accessor, self_, WrapFormat::Raw, |key| {
            key.material.export()
        })
        .await
    }

    async fn to_wrap_input_jwk(
        accessor: &Accessor<T, Self>,
        self_: Resource<MacKey>,
    ) -> Result<std::result::Result<Resource<WrapInput>, Error>> {
        to_wrap_input(accessor, self_, WrapFormat::Jwk, |key| {
            key.material.export_jwk().map(String::into_bytes)
        })
        .await
    }

    async fn drop(accessor: &Accessor<T, Self>, rep: Resource<MacKey>) -> Result<()> {
        drop_resource(accessor, rep).await
    }
}

// --- aead --------------------------------------------------------------------

impl aead::Host for WasiWebcryptoCtxView<'_> {}

impl HostAeadKey for WasiWebcryptoCtxView<'_> {
    fn algorithm_name(&mut self, self_: Resource<AeadKey>) -> Result<String> {
        Ok(self.table.get(&self_)?.material.name().to_string())
    }

    fn algorithm_length(&mut self, self_: Resource<AeadKey>) -> Result<u32> {
        Ok(self.table.get(&self_)?.material.length_bits())
    }

    fn nonce_size(&mut self, self_: Resource<AeadKey>) -> Result<u32> {
        Ok(self.table.get(&self_)?.material.nonce_len() as u32)
    }

    fn tag_size(&mut self, self_: Resource<AeadKey>) -> Result<u32> {
        Ok(self.table.get(&self_)?.material.tag_len() as u32)
    }

    fn extractable(&mut self, self_: Resource<AeadKey>) -> Result<bool> {
        Ok(self.table.get(&self_)?.material.extractable())
    }

    fn can_seal(&mut self, self_: Resource<AeadKey>) -> Result<bool> {
        Ok(self.table.get(&self_)?.material.can_seal())
    }

    fn can_open(&mut self, self_: Resource<AeadKey>) -> Result<bool> {
        Ok(self.table.get(&self_)?.material.can_open())
    }

    fn can_wrap(&mut self, self_: Resource<AeadKey>) -> Result<bool> {
        Ok(self.table.get(&self_)?.material.can_wrap())
    }

    fn can_unwrap(&mut self, self_: Resource<AeadKey>) -> Result<bool> {
        Ok(self.table.get(&self_)?.material.can_unwrap())
    }
}

host_options! {
    aead::{HostAeadKeyOptions, HostAeadKeyOptionsWithStore} for crate::AeadKeyOptions {
        can_seal => seal,
        can_open => open,
        can_wrap => wrap,
        can_unwrap => unwrap,
        extractable => extractable,
    }
}

impl<T: Send> HostAeadKeyWithStore<T> for WasiWebcrypto {
    async fn seal(
        accessor: &Accessor<T, Self>,
        self_: Resource<AeadKey>,
        nonce: Vec<u8>,
        aad: Vec<u8>,
        tag_size: Option<u8>,
        plaintext: StreamReader<u8>,
    ) -> Result<std::result::Result<StreamReader<u8>, Error>> {
        drain_then_stream(accessor, self_, plaintext, |key, msg| {
            Ok(key
                .material
                .seal(&nonce, &aad, tag_size, msg)
                .map_err(Error::from))
        })
        .await
    }

    async fn open(
        accessor: &Accessor<T, Self>,
        self_: Resource<AeadKey>,
        nonce: Vec<u8>,
        aad: Vec<u8>,
        tag_size: Option<u8>,
        ciphertext: StreamReader<u8>,
    ) -> Result<std::result::Result<StreamReader<u8>, Error>> {
        drain_then_stream(accessor, self_, ciphertext, |key, msg| {
            Ok(key
                .material
                .open(&nonce, &aad, tag_size, msg)
                .map_err(Error::from))
        })
        .await
    }

    async fn export_key_raw(
        accessor: &Accessor<T, Self>,
        self_: Resource<AeadKey>,
    ) -> Result<std::result::Result<Vec<u8>, Error>> {
        with_resource(accessor, self_, |key| {
            key.material.export().map_err(Error::from)
        })
        .await
    }

    async fn export_key_jwk(
        accessor: &Accessor<T, Self>,
        self_: Resource<AeadKey>,
    ) -> Result<std::result::Result<String, Error>> {
        with_resource(accessor, self_, |key| {
            key.material.export_jwk().map_err(Error::from)
        })
        .await
    }

    async fn wrap(
        accessor: &Accessor<T, Self>,
        self_: Resource<AeadKey>,
        nonce: Vec<u8>,
        aad: Vec<u8>,
        tag_size: Option<u8>,
        input: Resource<WrapInput>,
    ) -> Result<std::result::Result<Vec<u8>, Error>> {
        let input = take_options(accessor, input).await?.material;
        with_resource(accessor, self_, |key| {
            key.material
                .wrap(&nonce, &aad, tag_size, input)
                .map_err(Error::from)
        })
        .await
    }

    async fn unwrap(
        accessor: &Accessor<T, Self>,
        self_: Resource<AeadKey>,
        nonce: Vec<u8>,
        aad: Vec<u8>,
        tag_size: Option<u8>,
        wrapped: Vec<u8>,
    ) -> Result<std::result::Result<Resource<UnwrapInput>, Error>> {
        let material = with_resource(accessor, self_, |key| {
            key.material
                .unwrap_wrapped(&nonce, &aad, tag_size, &wrapped)
        })
        .await?;
        mint(accessor, material).await
    }

    async fn to_wrap_input_raw(
        accessor: &Accessor<T, Self>,
        self_: Resource<AeadKey>,
    ) -> Result<std::result::Result<Resource<WrapInput>, Error>> {
        to_wrap_input(accessor, self_, WrapFormat::Raw, |key| {
            key.material.export()
        })
        .await
    }

    async fn to_wrap_input_jwk(
        accessor: &Accessor<T, Self>,
        self_: Resource<AeadKey>,
    ) -> Result<std::result::Result<Resource<WrapInput>, Error>> {
        to_wrap_input(accessor, self_, WrapFormat::Jwk, |key| {
            key.material.export_jwk().map(String::into_bytes)
        })
        .await
    }

    async fn drop(accessor: &Accessor<T, Self>, rep: Resource<AeadKey>) -> Result<()> {
        drop_resource(accessor, rep).await
    }
}

// --- cipher (the unauthenticated-mode kind) --------------------------------------

impl cipher_iface::Host for WasiWebcryptoCtxView<'_> {}

impl HostCipherKey for WasiWebcryptoCtxView<'_> {
    fn algorithm_name(&mut self, self_: Resource<CipherKey>) -> Result<String> {
        Ok(self.table.get(&self_)?.material.name().to_string())
    }

    fn algorithm_length(&mut self, self_: Resource<CipherKey>) -> Result<u32> {
        Ok(self.table.get(&self_)?.material.length_bits())
    }

    fn iv_size(&mut self, self_: Resource<CipherKey>) -> Result<u32> {
        let _ = self.table.get(&self_)?;
        Ok(16)
    }

    fn extractable(&mut self, self_: Resource<CipherKey>) -> Result<bool> {
        Ok(self.table.get(&self_)?.material.policy().extractable)
    }

    fn can_encrypt(&mut self, self_: Resource<CipherKey>) -> Result<bool> {
        Ok(self.table.get(&self_)?.material.policy().encrypt)
    }

    fn can_decrypt(&mut self, self_: Resource<CipherKey>) -> Result<bool> {
        Ok(self.table.get(&self_)?.material.policy().decrypt)
    }

    fn can_wrap(&mut self, self_: Resource<CipherKey>) -> Result<bool> {
        Ok(self.table.get(&self_)?.material.policy().wrap)
    }

    fn can_unwrap(&mut self, self_: Resource<CipherKey>) -> Result<bool> {
        Ok(self.table.get(&self_)?.material.policy().unwrap)
    }
}

host_options! {
    cipher_iface::{HostCipherKeyOptions, HostCipherKeyOptionsWithStore}
    for crate::CipherKeyOptions {
        can_encrypt => encrypt,
        can_decrypt => decrypt,
        can_wrap => wrap,
        can_unwrap => unwrap,
        extractable => extractable,
    }
}

impl<T: Send> HostCipherKeyWithStore<T> for WasiWebcrypto {
    async fn encrypt(
        accessor: &Accessor<T, Self>,
        self_: Resource<CipherKey>,
        iv: Vec<u8>,
        counter_length: Option<u8>,
        plaintext: StreamReader<u8>,
    ) -> Result<std::result::Result<StreamReader<u8>, Error>> {
        drain_then_stream(accessor, self_, plaintext, |key, msg| {
            Ok(key
                .material
                .encrypt(&iv, counter_length, msg)
                .map_err(Error::from))
        })
        .await
    }

    async fn decrypt(
        accessor: &Accessor<T, Self>,
        self_: Resource<CipherKey>,
        iv: Vec<u8>,
        counter_length: Option<u8>,
        ciphertext: StreamReader<u8>,
    ) -> Result<std::result::Result<StreamReader<u8>, Error>> {
        drain_then_stream(accessor, self_, ciphertext, |key, msg| {
            Ok(key
                .material
                .decrypt(&iv, counter_length, msg)
                .map_err(Error::from))
        })
        .await
    }

    async fn export_key_raw(
        accessor: &Accessor<T, Self>,
        self_: Resource<CipherKey>,
    ) -> Result<std::result::Result<Vec<u8>, Error>> {
        with_resource(accessor, self_, |key| {
            key.material.export().map_err(Error::from)
        })
        .await
    }

    async fn export_key_jwk(
        accessor: &Accessor<T, Self>,
        self_: Resource<CipherKey>,
    ) -> Result<std::result::Result<String, Error>> {
        with_resource(accessor, self_, |key| {
            key.material.export_jwk().map_err(Error::from)
        })
        .await
    }

    async fn wrap(
        accessor: &Accessor<T, Self>,
        self_: Resource<CipherKey>,
        iv: Vec<u8>,
        counter_length: Option<u8>,
        input: Resource<WrapInput>,
    ) -> Result<std::result::Result<Vec<u8>, Error>> {
        let input = take_options(accessor, input).await?.material;
        with_resource(accessor, self_, |key| {
            key.material
                .wrap(&iv, counter_length, input)
                .map_err(Error::from)
        })
        .await
    }

    async fn unwrap(
        accessor: &Accessor<T, Self>,
        self_: Resource<CipherKey>,
        iv: Vec<u8>,
        counter_length: Option<u8>,
        wrapped: Vec<u8>,
    ) -> Result<std::result::Result<Resource<UnwrapInput>, Error>> {
        let material = with_resource(accessor, self_, |key| {
            key.material.unwrap_wrapped(&iv, counter_length, &wrapped)
        })
        .await?;
        mint(accessor, material).await
    }

    async fn to_wrap_input_raw(
        accessor: &Accessor<T, Self>,
        self_: Resource<CipherKey>,
    ) -> Result<std::result::Result<Resource<WrapInput>, Error>> {
        to_wrap_input(accessor, self_, WrapFormat::Raw, |key| {
            key.material.export()
        })
        .await
    }

    async fn to_wrap_input_jwk(
        accessor: &Accessor<T, Self>,
        self_: Resource<CipherKey>,
    ) -> Result<std::result::Result<Resource<WrapInput>, Error>> {
        to_wrap_input(accessor, self_, WrapFormat::Jwk, |key| {
            key.material.export_jwk().map(String::into_bytes)
        })
        .await
    }

    async fn drop(accessor: &Accessor<T, Self>, rep: Resource<CipherKey>) -> Result<()> {
        drop_resource(accessor, rep).await
    }
}

// --- aes-cbc / aes-ctr (key minting) ----------------------------------------------

/// The shared minting body of the two unauthenticated-mode interfaces:
/// they differ only in the `CipherMode` they bind.
macro_rules! cipher_minting {
    ($iface:path, $mode:expr) => {
        const _: () = {
            use $iface as iface;

            impl iface::Host for WasiWebcryptoCtxView<'_> {}

            impl<T: Send> iface::HostWithStore<T> for WasiWebcrypto {
                async fn import_key_raw(
                    accessor: &Accessor<T, Self>,
                    variant: iface::AesVariant,
                    raw: Vec<u8>,
                    options: Resource<crate::CipherKeyOptions>,
                ) -> Result<std::result::Result<Resource<CipherKey>, Error>> {
                    let policy = take_options(accessor, options).await?.policy;
                    let material = lann_webcrypto_core::CipherKeyMaterial::import(
                        $mode,
                        variant.into(),
                        raw,
                        policy,
                    );
                    mint(accessor, material).await
                }

                async fn import_key_jwk(
                    accessor: &Accessor<T, Self>,
                    variant: iface::AesVariant,
                    jwk: String,
                    options: Resource<crate::CipherKeyOptions>,
                ) -> Result<std::result::Result<Resource<CipherKey>, Error>> {
                    let policy = take_options(accessor, options).await?.policy;
                    let material = lann_webcrypto_core::CipherKeyMaterial::import_jwk(
                        $mode,
                        variant.into(),
                        &jwk,
                        policy,
                    );
                    mint(accessor, material).await
                }

                async fn generate_key(
                    accessor: &Accessor<T, Self>,
                    variant: iface::AesVariant,
                    options: Resource<crate::CipherKeyOptions>,
                ) -> Result<std::result::Result<Resource<CipherKey>, Error>> {
                    let policy = take_options(accessor, options).await?.policy;
                    let material = lann_webcrypto_core::CipherKeyMaterial::generate(
                        $mode,
                        variant.into(),
                        policy,
                    )
                    .map_err(rng_trap("random key generation"))?;
                    mint(accessor, material).await
                }

                async fn derive_key(
                    accessor: &Accessor<T, Self>,
                    variant: iface::AesVariant,
                    input: Resource<DeriveInput>,
                    options: Resource<crate::CipherKeyOptions>,
                ) -> Result<std::result::Result<Resource<CipherKey>, Error>> {
                    let policy = take_options(accessor, options).await?.policy;
                    let material = with_resource(accessor, input, |input| {
                        lann_webcrypto_core::derive_cipher_key(
                            &input.material,
                            $mode,
                            variant.into(),
                            policy,
                        )
                    })
                    .await?;
                    mint(accessor, material).await
                }

                async fn unwrap_key_raw(
                    accessor: &Accessor<T, Self>,
                    variant: iface::AesVariant,
                    input: Resource<UnwrapInput>,
                    options: Resource<crate::CipherKeyOptions>,
                ) -> Result<std::result::Result<Resource<CipherKey>, Error>> {
                    let policy = take_options(accessor, options).await?.policy;
                    let input = take_options(accessor, input).await?.material;
                    let material = lann_webcrypto_core::unwrap_cipher_key(
                        $mode,
                        variant.into(),
                        input,
                        policy,
                    );
                    mint(accessor, material).await
                }

                async fn unwrap_key_jwk(
                    accessor: &Accessor<T, Self>,
                    variant: iface::AesVariant,
                    input: Resource<UnwrapInput>,
                    options: Resource<crate::CipherKeyOptions>,
                ) -> Result<std::result::Result<Resource<CipherKey>, Error>> {
                    let policy = take_options(accessor, options).await?.policy;
                    let input = take_options(accessor, input).await?.material;
                    let material = lann_webcrypto_core::unwrap_cipher_key_jwk(
                        $mode,
                        variant.into(),
                        input,
                        policy,
                    );
                    mint(accessor, material).await
                }
            }
        };
    };
}

cipher_minting!(aes_cbc_iface, lann_webcrypto_core::CipherMode::Cbc);
cipher_minting!(aes_ctr_iface, lann_webcrypto_core::CipherMode::Ctr);

// --- wrapping (the provider-held intermediates) -----------------------------------

impl wrapping_iface::Host for WasiWebcryptoCtxView<'_> {}

impl HostWrapInput for WasiWebcryptoCtxView<'_> {}

impl HostUnwrapInput for WasiWebcryptoCtxView<'_> {}

impl<T: Send> HostWrapInputWithStore<T> for WasiWebcrypto {
    async fn drop(accessor: &Accessor<T, Self>, rep: Resource<WrapInput>) -> Result<()> {
        drop_resource(accessor, rep).await
    }
}

impl<T: Send> HostUnwrapInputWithStore<T> for WasiWebcrypto {
    async fn drop(accessor: &Accessor<T, Self>, rep: Resource<UnwrapInput>) -> Result<()> {
        drop_resource(accessor, rep).await
    }
}

// --- key-wrap ----------------------------------------------------------------

impl key_wrap_iface::Host for WasiWebcryptoCtxView<'_> {}

impl HostKwKey for WasiWebcryptoCtxView<'_> {
    fn algorithm_name(&mut self, self_: Resource<KwKey>) -> Result<String> {
        Ok(self.table.get(&self_)?.material.name().to_string())
    }

    fn algorithm_length(&mut self, self_: Resource<KwKey>) -> Result<u32> {
        Ok(self.table.get(&self_)?.material.length_bits())
    }

    fn extractable(&mut self, self_: Resource<KwKey>) -> Result<bool> {
        Ok(self.table.get(&self_)?.material.extractable())
    }

    fn can_wrap(&mut self, self_: Resource<KwKey>) -> Result<bool> {
        Ok(self.table.get(&self_)?.material.can_wrap())
    }

    fn can_unwrap(&mut self, self_: Resource<KwKey>) -> Result<bool> {
        Ok(self.table.get(&self_)?.material.can_unwrap())
    }
}

impl key_wrap_iface::HostKwKeyOptions for WasiWebcryptoCtxView<'_> {
    fn new(&mut self) -> Result<Resource<crate::KwKeyOptions>> {
        let retention = charge_floor_or_trap(self.ctx)?;
        Ok(self
            .table
            .push(crate::KwKeyOptions::minted(Default::default(), retention))?)
    }

    fn can_wrap(&mut self, self_: Resource<crate::KwKeyOptions>, allowed: bool) -> Result<()> {
        self.table.get_mut(&self_)?.policy.wrap = allowed;
        Ok(())
    }

    fn can_unwrap(&mut self, self_: Resource<crate::KwKeyOptions>, allowed: bool) -> Result<()> {
        self.table.get_mut(&self_)?.policy.unwrap = allowed;
        Ok(())
    }

    fn extractable(&mut self, self_: Resource<crate::KwKeyOptions>, allowed: bool) -> Result<()> {
        self.table.get_mut(&self_)?.policy.extractable = allowed;
        Ok(())
    }
}

impl<T: Send> HostKwKeyOptionsWithStore<T> for WasiWebcrypto {
    async fn drop(accessor: &Accessor<T, Self>, rep: Resource<crate::KwKeyOptions>) -> Result<()> {
        drop_resource(accessor, rep).await
    }
}

impl<T: Send> HostKwKeyWithStore<T> for WasiWebcrypto {
    async fn wrap(
        accessor: &Accessor<T, Self>,
        self_: Resource<KwKey>,
        input: Resource<WrapInput>,
    ) -> Result<std::result::Result<Vec<u8>, Error>> {
        let input = take_options(accessor, input).await?.material;
        with_resource(accessor, self_, |key| {
            key.material.wrap(input).map_err(Error::from)
        })
        .await
    }

    async fn unwrap(
        accessor: &Accessor<T, Self>,
        self_: Resource<KwKey>,
        wrapped: Vec<u8>,
    ) -> Result<std::result::Result<Resource<UnwrapInput>, Error>> {
        let material = with_resource(accessor, self_, |key| key.material.unwrap(&wrapped)).await?;
        mint(accessor, material).await
    }

    async fn to_wrap_input_raw(
        accessor: &Accessor<T, Self>,
        self_: Resource<KwKey>,
    ) -> Result<std::result::Result<Resource<WrapInput>, Error>> {
        to_wrap_input(accessor, self_, WrapFormat::Raw, |key| {
            key.material.export()
        })
        .await
    }

    async fn to_wrap_input_jwk(
        accessor: &Accessor<T, Self>,
        self_: Resource<KwKey>,
    ) -> Result<std::result::Result<Resource<WrapInput>, Error>> {
        to_wrap_input(accessor, self_, WrapFormat::Jwk, |key| {
            key.material.export_jwk().map(String::into_bytes)
        })
        .await
    }

    async fn export_key_raw(
        accessor: &Accessor<T, Self>,
        self_: Resource<KwKey>,
    ) -> Result<std::result::Result<Vec<u8>, Error>> {
        with_resource(accessor, self_, |key| {
            key.material.export().map_err(Error::from)
        })
        .await
    }

    async fn export_key_jwk(
        accessor: &Accessor<T, Self>,
        self_: Resource<KwKey>,
    ) -> Result<std::result::Result<String, Error>> {
        with_resource(accessor, self_, |key| {
            key.material.export_jwk().map_err(Error::from)
        })
        .await
    }

    async fn drop(accessor: &Accessor<T, Self>, rep: Resource<KwKey>) -> Result<()> {
        drop_resource(accessor, rep).await
    }
}

// --- aes-kw (key minting) --------------------------------------------------------

impl aes_kw_iface::Host for WasiWebcryptoCtxView<'_> {}

impl<T: Send> aes_kw_iface::HostWithStore<T> for WasiWebcrypto {
    async fn import_key_raw(
        accessor: &Accessor<T, Self>,
        variant: aes_kw_iface::AesVariant,
        raw: Vec<u8>,
        options: Resource<crate::KwKeyOptions>,
    ) -> Result<std::result::Result<Resource<KwKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = KwKeyMaterial::import(variant.into(), raw, policy);
        mint(accessor, material).await
    }

    async fn import_key_jwk(
        accessor: &Accessor<T, Self>,
        variant: aes_kw_iface::AesVariant,
        jwk: String,
        options: Resource<crate::KwKeyOptions>,
    ) -> Result<std::result::Result<Resource<KwKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = KwKeyMaterial::import_jwk(variant.into(), &jwk, policy);
        mint(accessor, material).await
    }

    async fn generate_key(
        accessor: &Accessor<T, Self>,
        variant: aes_kw_iface::AesVariant,
        options: Resource<crate::KwKeyOptions>,
    ) -> Result<std::result::Result<Resource<KwKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = KwKeyMaterial::generate(variant.into(), policy)
            .map_err(rng_trap("random key generation"))?;
        mint(accessor, material).await
    }

    async fn derive_key(
        accessor: &Accessor<T, Self>,
        variant: aes_kw_iface::AesVariant,
        input: Resource<DeriveInput>,
        options: Resource<crate::KwKeyOptions>,
    ) -> Result<std::result::Result<Resource<KwKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = with_resource(accessor, input, |input| {
            lann_webcrypto_core::derive_kw_key(variant.into(), &input.material, policy)
        })
        .await?;
        mint(accessor, material).await
    }

    async fn unwrap_key_raw(
        accessor: &Accessor<T, Self>,
        variant: aes_kw_iface::AesVariant,
        input: Resource<UnwrapInput>,
        options: Resource<crate::KwKeyOptions>,
    ) -> Result<std::result::Result<Resource<KwKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let input = take_options(accessor, input).await?.material;
        let material = lann_webcrypto_core::unwrap_kw_key(variant.into(), input, policy);
        mint(accessor, material).await
    }

    async fn unwrap_key_jwk(
        accessor: &Accessor<T, Self>,
        variant: aes_kw_iface::AesVariant,
        input: Resource<UnwrapInput>,
        options: Resource<crate::KwKeyOptions>,
    ) -> Result<std::result::Result<Resource<KwKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let input = take_options(accessor, input).await?.material;
        let material = lann_webcrypto_core::unwrap_kw_key_jwk(variant.into(), input, policy);
        mint(accessor, material).await
    }
}

// --- derivation -------------------------------------------------------------

impl derivation_iface::Host for WasiWebcryptoCtxView<'_> {}

host_options! {
    derivation_iface::{HostDeriveOptions, HostDeriveOptionsWithStore} for crate::DeriveOptions {
        can_derive_bits => derive_bits,
        can_derive_key => derive_key,
    }
}

impl HostDeriveInput for WasiWebcryptoCtxView<'_> {
    fn can_derive_bits(&mut self, self_: Resource<DeriveInput>) -> Result<bool> {
        Ok(self.table.get(&self_)?.material.policy().derive_bits)
    }

    fn can_derive_key(&mut self, self_: Resource<DeriveInput>) -> Result<bool> {
        Ok(self.table.get(&self_)?.material.policy().derive_key)
    }
}

impl<T: Send> HostDeriveInputWithStore<T> for WasiWebcrypto {
    async fn derive_bits(
        accessor: &Accessor<T, Self>,
        self_: Resource<DeriveInput>,
        length: Option<u32>,
    ) -> Result<std::result::Result<Vec<u8>, Error>> {
        with_resource(accessor, self_, |input| {
            input
                .material
                .derive_bits(length)
                .map(|okm| okm.to_vec())
                .map_err(Error::from)
        })
        .await
    }

    async fn drop(accessor: &Accessor<T, Self>, rep: Resource<DeriveInput>) -> Result<()> {
        drop_resource(accessor, rep).await
    }
}

// --- hkdf ----------------------------------------------------------------------

impl hkdf_iface::Host for WasiWebcryptoCtxView<'_> {}

impl HostIkm for WasiWebcryptoCtxView<'_> {
    fn can_derive_bits(&mut self, self_: Resource<Ikm>) -> Result<bool> {
        Ok(self.table.get(&self_)?.material.policy().derive_bits)
    }

    fn can_derive_key(&mut self, self_: Resource<Ikm>) -> Result<bool> {
        Ok(self.table.get(&self_)?.material.policy().derive_key)
    }
}

impl<T: Send> HostIkmWithStore<T> for WasiWebcrypto {
    async fn drop(accessor: &Accessor<T, Self>, rep: Resource<Ikm>) -> Result<()> {
        drop_resource(accessor, rep).await
    }
}

impl<T: Send> hkdf_iface::HostWithStore<T> for WasiWebcrypto {
    async fn import_ikm(
        accessor: &Accessor<T, Self>,
        raw: Vec<u8>,
        options: Resource<crate::DeriveOptions>,
    ) -> Result<std::result::Result<Resource<Ikm>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = lann_webcrypto_core::IkmMaterial::import(raw, policy);
        mint(accessor, material).await
    }

    async fn unwrap_ikm(
        accessor: &Accessor<T, Self>,
        input: Resource<UnwrapInput>,
        options: Resource<crate::DeriveOptions>,
    ) -> Result<std::result::Result<Resource<Ikm>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let input = take_options(accessor, input).await?.material;
        let material = lann_webcrypto_core::unwrap_ikm(input, policy);
        mint(accessor, material).await
    }
}

impl hkdf_sha2_iface::Host for WasiWebcryptoCtxView<'_> {}

impl<T: Send> hkdf_sha2_iface::HostWithStore<T> for WasiWebcrypto {
    async fn prepare(
        accessor: &Accessor<T, Self>,
        variant: hkdf_sha2_iface::Sha2Variant,
        input: Resource<Ikm>,
        salt: Vec<u8>,
        info: Vec<u8>,
    ) -> Result<std::result::Result<Resource<DeriveInput>, Error>> {
        let material = with_resource(accessor, input, |ikm| {
            lann_webcrypto_core::DeriveInputMaterial::prepare(
                variant.into(),
                &ikm.material,
                &salt,
                info,
            )
        })
        .await?;
        mint(accessor, material).await
    }

    async fn prepare_from(
        accessor: &Accessor<T, Self>,
        variant: hkdf_sha2_iface::Sha2Variant,
        input: Resource<DeriveInput>,
        salt: Vec<u8>,
        info: Vec<u8>,
    ) -> Result<std::result::Result<Resource<DeriveInput>, Error>> {
        let material = with_resource(accessor, input, |upstream| {
            lann_webcrypto_core::DeriveInputMaterial::prepare_from(
                variant.into(),
                &upstream.material,
                &salt,
                info,
            )
        })
        .await?;
        mint(accessor, material).await
    }
}

// --- the SHA-1 constructions (hmac-sha1 / hkdf-sha1 / pbkdf2-sha1) ---------------

impl hmac_sha1_iface::Host for WasiWebcryptoCtxView<'_> {}

impl<T: Send> hmac_sha1_iface::HostWithStore<T> for WasiWebcrypto {
    async fn import_key_raw(
        accessor: &Accessor<T, Self>,
        raw: Vec<u8>,
        options: Resource<crate::MacKeyOptions>,
    ) -> Result<std::result::Result<Resource<MacKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = MacKeyMaterial::import_sha1(raw, policy);
        mint(accessor, material).await
    }

    async fn import_key_jwk(
        accessor: &Accessor<T, Self>,
        jwk: String,
        options: Resource<crate::MacKeyOptions>,
    ) -> Result<std::result::Result<Resource<MacKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = MacKeyMaterial::import_jwk_sha1(&jwk, policy);
        mint(accessor, material).await
    }

    async fn generate_key(
        accessor: &Accessor<T, Self>,
        length: Option<u32>,
        options: Resource<crate::MacKeyOptions>,
    ) -> Result<std::result::Result<Resource<MacKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = MacKeyMaterial::generate_sha1(length, policy)
            .map_err(rng_trap("random key generation"))?;
        mint(accessor, material).await
    }

    async fn derive_key(
        accessor: &Accessor<T, Self>,
        input: Resource<DeriveInput>,
        length: Option<u32>,
        options: Resource<crate::MacKeyOptions>,
    ) -> Result<std::result::Result<Resource<MacKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = with_resource(accessor, input, |input| {
            lann_webcrypto_core::derive_mac_key_sha1(&input.material, length, policy)
        })
        .await?;
        mint(accessor, material).await
    }

    async fn unwrap_key_raw(
        accessor: &Accessor<T, Self>,
        input: Resource<UnwrapInput>,
        options: Resource<crate::MacKeyOptions>,
    ) -> Result<std::result::Result<Resource<MacKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let input = take_options(accessor, input).await?.material;
        let material = lann_webcrypto_core::unwrap_mac_key_sha1(input, policy);
        mint(accessor, material).await
    }

    async fn unwrap_key_jwk(
        accessor: &Accessor<T, Self>,
        input: Resource<UnwrapInput>,
        options: Resource<crate::MacKeyOptions>,
    ) -> Result<std::result::Result<Resource<MacKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let input = take_options(accessor, input).await?.material;
        let material = lann_webcrypto_core::unwrap_mac_key_jwk_sha1(input, policy);
        mint(accessor, material).await
    }
}

impl hkdf_sha1_iface::Host for WasiWebcryptoCtxView<'_> {}

impl<T: Send> hkdf_sha1_iface::HostWithStore<T> for WasiWebcrypto {
    async fn prepare(
        accessor: &Accessor<T, Self>,
        input: Resource<Ikm>,
        salt: Vec<u8>,
        info: Vec<u8>,
    ) -> Result<std::result::Result<Resource<DeriveInput>, Error>> {
        let material = with_resource(accessor, input, |ikm| {
            lann_webcrypto_core::DeriveInputMaterial::prepare_sha1(&ikm.material, &salt, info)
        })
        .await?;
        mint(accessor, material).await
    }

    async fn prepare_from(
        accessor: &Accessor<T, Self>,
        input: Resource<DeriveInput>,
        salt: Vec<u8>,
        info: Vec<u8>,
    ) -> Result<std::result::Result<Resource<DeriveInput>, Error>> {
        let material = with_resource(accessor, input, |upstream| {
            lann_webcrypto_core::DeriveInputMaterial::prepare_from_sha1(
                &upstream.material,
                &salt,
                info,
            )
        })
        .await?;
        mint(accessor, material).await
    }
}

impl pbkdf2_sha1_iface::Host for WasiWebcryptoCtxView<'_> {}

impl<T: Send> pbkdf2_sha1_iface::HostWithStore<T> for WasiWebcrypto {
    async fn prepare(
        accessor: &Accessor<T, Self>,
        input: Resource<Password>,
        salt: Vec<u8>,
        iterations: u32,
    ) -> Result<std::result::Result<Resource<DeriveInput>, Error>> {
        let material = with_resource(accessor, input, |password| {
            lann_webcrypto_core::DeriveInputMaterial::prepare_pbkdf2_sha1(
                &password.material,
                salt.clone(),
                iterations,
            )
        })
        .await?;
        mint(accessor, material).await
    }
}

// --- pbkdf2 --------------------------------------------------------------------

impl pbkdf2_iface::Host for WasiWebcryptoCtxView<'_> {}

impl HostPassword for WasiWebcryptoCtxView<'_> {
    fn can_derive_bits(&mut self, self_: Resource<Password>) -> Result<bool> {
        Ok(self.table.get(&self_)?.material.policy().derive_bits)
    }

    fn can_derive_key(&mut self, self_: Resource<Password>) -> Result<bool> {
        Ok(self.table.get(&self_)?.material.policy().derive_key)
    }
}

impl<T: Send> HostPasswordWithStore<T> for WasiWebcrypto {
    async fn drop(accessor: &Accessor<T, Self>, rep: Resource<Password>) -> Result<()> {
        drop_resource(accessor, rep).await
    }
}

impl<T: Send> pbkdf2_iface::HostWithStore<T> for WasiWebcrypto {
    async fn import_password(
        accessor: &Accessor<T, Self>,
        raw: Vec<u8>,
        options: Resource<crate::DeriveOptions>,
    ) -> Result<std::result::Result<Resource<Password>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = lann_webcrypto_core::PasswordMaterial::import(raw, policy);
        mint(accessor, material).await
    }

    async fn unwrap_password(
        accessor: &Accessor<T, Self>,
        input: Resource<UnwrapInput>,
        options: Resource<crate::DeriveOptions>,
    ) -> Result<std::result::Result<Resource<Password>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let input = take_options(accessor, input).await?.material;
        let material = lann_webcrypto_core::unwrap_password(input, policy);
        mint(accessor, material).await
    }
}

impl pbkdf2_sha2_iface::Host for WasiWebcryptoCtxView<'_> {}

impl<T: Send> pbkdf2_sha2_iface::HostWithStore<T> for WasiWebcrypto {
    async fn prepare(
        accessor: &Accessor<T, Self>,
        variant: pbkdf2_sha2_iface::Sha2Variant,
        input: Resource<Password>,
        salt: Vec<u8>,
        iterations: u32,
    ) -> Result<std::result::Result<Resource<DeriveInput>, Error>> {
        let material = with_resource(accessor, input, |password| {
            lann_webcrypto_core::DeriveInputMaterial::prepare_pbkdf2(
                variant.into(),
                &password.material,
                salt,
                iterations,
            )
        })
        .await?;
        mint(accessor, material).await
    }
}

// --- key-agreement -------------------------------------------------------------

impl key_agreement_iface::Host for WasiWebcryptoCtxView<'_> {}

host_options! {
    key_agreement_iface::{HostAgreementKeyOptions, HostAgreementKeyOptionsWithStore}
    for crate::AgreementKeyOptions {
        can_derive_bits => derive_bits,
        can_derive_key => derive_key,
        extractable => extractable,
    }
}

impl HostPublicKey for WasiWebcryptoCtxView<'_> {
    fn algorithm_name(&mut self, self_: Resource<AgreementPublicKey>) -> Result<String> {
        Ok(self.table.get(&self_)?.material.name().to_string())
    }
}

impl<T: Send> HostPublicKeyWithStore<T> for WasiWebcrypto {
    async fn export_key_raw(
        accessor: &Accessor<T, Self>,
        self_: Resource<AgreementPublicKey>,
    ) -> Result<std::result::Result<Vec<u8>, Error>> {
        with_resource(accessor, self_, |key| Ok(key.material.export())).await
    }

    async fn export_key_jwk(
        accessor: &Accessor<T, Self>,
        self_: Resource<AgreementPublicKey>,
    ) -> Result<std::result::Result<String, Error>> {
        with_resource(accessor, self_, |key| Ok(key.material.export_jwk())).await
    }

    async fn export_key_spki(
        accessor: &Accessor<T, Self>,
        self_: Resource<AgreementPublicKey>,
    ) -> Result<std::result::Result<Vec<u8>, Error>> {
        with_resource(accessor, self_, |key| Ok(key.material.export_spki())).await
    }

    async fn drop(accessor: &Accessor<T, Self>, rep: Resource<AgreementPublicKey>) -> Result<()> {
        drop_resource(accessor, rep).await
    }
}

impl HostSecretKey for WasiWebcryptoCtxView<'_> {
    fn algorithm_name(&mut self, self_: Resource<AgreementSecretKey>) -> Result<String> {
        Ok(self.table.get(&self_)?.material.name().to_string())
    }

    fn can_derive_bits(&mut self, self_: Resource<AgreementSecretKey>) -> Result<bool> {
        Ok(self.table.get(&self_)?.material.policy().derive_bits)
    }

    fn can_derive_key(&mut self, self_: Resource<AgreementSecretKey>) -> Result<bool> {
        Ok(self.table.get(&self_)?.material.policy().derive_key)
    }

    fn extractable(&mut self, self_: Resource<AgreementSecretKey>) -> Result<bool> {
        Ok(self.table.get(&self_)?.material.policy().extractable)
    }
}

impl<T: Send> HostSecretKeyWithStore<T> for WasiWebcrypto {
    async fn agree(
        accessor: &Accessor<T, Self>,
        self_: Resource<AgreementSecretKey>,
        peer: Resource<AgreementPublicKey>,
    ) -> Result<std::result::Result<Resource<DeriveInput>, Error>> {
        let material = accessor.with(|mut access| -> Result<_> {
            let view = access.get();
            let secret = view.table.get(&self_)?;
            let peer = view.table.get(&peer)?;
            Ok(secret.material.agree(&peer.material))
        })?;
        mint(accessor, material).await
    }

    async fn export_key_jwk(
        accessor: &Accessor<T, Self>,
        self_: Resource<AgreementSecretKey>,
    ) -> Result<std::result::Result<String, Error>> {
        with_resource(accessor, self_, |key| {
            key.material.export_jwk().map_err(Error::from)
        })
        .await
    }

    async fn export_key_pkcs8(
        accessor: &Accessor<T, Self>,
        self_: Resource<AgreementSecretKey>,
    ) -> Result<std::result::Result<Vec<u8>, Error>> {
        with_resource(accessor, self_, |key| {
            key.material.export_pkcs8().map_err(Error::from)
        })
        .await
    }

    async fn to_wrap_input_jwk(
        accessor: &Accessor<T, Self>,
        self_: Resource<AgreementSecretKey>,
    ) -> Result<std::result::Result<Resource<WrapInput>, Error>> {
        to_wrap_input(accessor, self_, WrapFormat::Jwk, |key| {
            key.material.export_jwk().map(String::into_bytes)
        })
        .await
    }

    async fn to_wrap_input_pkcs8(
        accessor: &Accessor<T, Self>,
        self_: Resource<AgreementSecretKey>,
    ) -> Result<std::result::Result<Resource<WrapInput>, Error>> {
        to_wrap_input(accessor, self_, WrapFormat::Pkcs8, |key| {
            key.material.export_pkcs8()
        })
        .await
    }

    async fn drop(accessor: &Accessor<T, Self>, rep: Resource<AgreementSecretKey>) -> Result<()> {
        drop_resource(accessor, rep).await
    }
}

// --- x25519 (key minting) --------------------------------------------------------

impl x25519_iface::Host for WasiWebcryptoCtxView<'_> {}

impl<T: Send> x25519_iface::HostWithStore<T> for WasiWebcrypto {
    async fn import_public_key_raw(
        accessor: &Accessor<T, Self>,
        raw: Vec<u8>,
    ) -> Result<std::result::Result<Resource<AgreementPublicKey>, Error>> {
        let material = lann_webcrypto_core::AgreementPublicMaterial::import_x25519(&raw);
        mint(accessor, material).await
    }

    async fn import_public_key_spki(
        accessor: &Accessor<T, Self>,
        spki: Vec<u8>,
    ) -> Result<std::result::Result<Resource<AgreementPublicKey>, Error>> {
        let material = lann_webcrypto_core::AgreementPublicMaterial::import_x25519_spki(&spki);
        mint(accessor, material).await
    }

    async fn import_public_key_jwk(
        accessor: &Accessor<T, Self>,
        jwk: String,
    ) -> Result<std::result::Result<Resource<AgreementPublicKey>, Error>> {
        let material = lann_webcrypto_core::AgreementPublicMaterial::import_x25519_jwk(&jwk);
        mint(accessor, material).await
    }

    async fn import_secret_key_pkcs8(
        accessor: &Accessor<T, Self>,
        pkcs8: Vec<u8>,
        options: Resource<crate::AgreementKeyOptions>,
    ) -> Result<std::result::Result<Resource<AgreementSecretKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material =
            lann_webcrypto_core::AgreementSecretMaterial::import_x25519_pkcs8(&pkcs8, policy);
        mint(accessor, material).await
    }

    async fn import_secret_key_jwk(
        accessor: &Accessor<T, Self>,
        jwk: String,
        options: Resource<crate::AgreementKeyOptions>,
    ) -> Result<std::result::Result<Resource<AgreementSecretKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material =
            lann_webcrypto_core::AgreementSecretMaterial::import_x25519_jwk(&jwk, policy);
        mint(accessor, material).await
    }

    async fn generate_key(
        accessor: &Accessor<T, Self>,
        options: Resource<crate::AgreementKeyOptions>,
    ) -> Result<
        std::result::Result<(Resource<AgreementSecretKey>, Resource<AgreementPublicKey>), Error>,
    > {
        let policy = take_options(accessor, options).await?.policy;
        let material = lann_webcrypto_core::AgreementSecretMaterial::generate_x25519(policy)
            .map_err(rng_trap("random key generation"))?;
        match material {
            Ok((secret, public)) => mint_key_pair(accessor, secret, public).await,
            Err(err) => Ok(Err(err.into())),
        }
    }

    async fn unwrap_secret_key_jwk(
        accessor: &Accessor<T, Self>,
        input: Resource<UnwrapInput>,
        options: Resource<crate::AgreementKeyOptions>,
    ) -> Result<std::result::Result<Resource<AgreementSecretKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let input = take_options(accessor, input).await?.material;
        let material = lann_webcrypto_core::unwrap_x25519_secret_key_jwk(input, policy);
        mint(accessor, material).await
    }

    async fn unwrap_secret_key_pkcs8(
        accessor: &Accessor<T, Self>,
        input: Resource<UnwrapInput>,
        options: Resource<crate::AgreementKeyOptions>,
    ) -> Result<std::result::Result<Resource<AgreementSecretKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let input = take_options(accessor, input).await?.material;
        let material = lann_webcrypto_core::unwrap_x25519_secret_key_pkcs8(input, policy);
        mint(accessor, material).await
    }
}

// --- ecdh (key minting) ----------------------------------------------------------

impl ecdh_iface::Host for WasiWebcryptoCtxView<'_> {}

impl<T: Send> ecdh_iface::HostWithStore<T> for WasiWebcrypto {
    async fn import_public_key_raw(
        accessor: &Accessor<T, Self>,
        variant: ecdh_iface::EcdhVariant,
        raw: Vec<u8>,
    ) -> Result<std::result::Result<Resource<AgreementPublicKey>, Error>> {
        let material =
            lann_webcrypto_core::AgreementPublicMaterial::import_ecdh(variant.into(), &raw);
        mint(accessor, material).await
    }

    async fn import_public_key_spki(
        accessor: &Accessor<T, Self>,
        variant: ecdh_iface::EcdhVariant,
        spki: Vec<u8>,
    ) -> Result<std::result::Result<Resource<AgreementPublicKey>, Error>> {
        let material =
            lann_webcrypto_core::AgreementPublicMaterial::import_ecdh_spki(variant.into(), &spki);
        mint(accessor, material).await
    }

    async fn import_public_key_jwk(
        accessor: &Accessor<T, Self>,
        variant: ecdh_iface::EcdhVariant,
        jwk: String,
    ) -> Result<std::result::Result<Resource<AgreementPublicKey>, Error>> {
        let material =
            lann_webcrypto_core::AgreementPublicMaterial::import_ecdh_jwk(variant.into(), &jwk);
        mint(accessor, material).await
    }

    async fn import_secret_key_jwk(
        accessor: &Accessor<T, Self>,
        variant: ecdh_iface::EcdhVariant,
        jwk: String,
        options: Resource<crate::AgreementKeyOptions>,
    ) -> Result<std::result::Result<Resource<AgreementSecretKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = lann_webcrypto_core::AgreementSecretMaterial::import_ecdh_jwk(
            variant.into(),
            &jwk,
            policy,
        );
        mint(accessor, material).await
    }

    async fn import_secret_key_pkcs8(
        accessor: &Accessor<T, Self>,
        variant: ecdh_iface::EcdhVariant,
        pkcs8: Vec<u8>,
        options: Resource<crate::AgreementKeyOptions>,
    ) -> Result<std::result::Result<Resource<AgreementSecretKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = lann_webcrypto_core::AgreementSecretMaterial::import_ecdh_pkcs8(
            variant.into(),
            &pkcs8,
            policy,
        );
        mint(accessor, material).await
    }

    async fn generate_key(
        accessor: &Accessor<T, Self>,
        variant: ecdh_iface::EcdhVariant,
        options: Resource<crate::AgreementKeyOptions>,
    ) -> Result<
        std::result::Result<(Resource<AgreementSecretKey>, Resource<AgreementPublicKey>), Error>,
    > {
        let policy = take_options(accessor, options).await?.policy;
        let material =
            lann_webcrypto_core::AgreementSecretMaterial::generate_ecdh(variant.into(), policy)
                .map_err(rng_trap("random key generation"))?;
        match material {
            Ok((secret, public)) => mint_key_pair(accessor, secret, public).await,
            Err(err) => Ok(Err(err.into())),
        }
    }

    async fn unwrap_secret_key_jwk(
        accessor: &Accessor<T, Self>,
        variant: ecdh_iface::EcdhVariant,
        input: Resource<UnwrapInput>,
        options: Resource<crate::AgreementKeyOptions>,
    ) -> Result<std::result::Result<Resource<AgreementSecretKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let input = take_options(accessor, input).await?.material;
        let material =
            lann_webcrypto_core::unwrap_ecdh_secret_key_jwk(variant.into(), input, policy);
        mint(accessor, material).await
    }

    async fn unwrap_secret_key_pkcs8(
        accessor: &Accessor<T, Self>,
        variant: ecdh_iface::EcdhVariant,
        input: Resource<UnwrapInput>,
        options: Resource<crate::AgreementKeyOptions>,
    ) -> Result<std::result::Result<Resource<AgreementSecretKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let input = take_options(accessor, input).await?.material;
        let material =
            lann_webcrypto_core::unwrap_ecdh_secret_key_pkcs8(variant.into(), input, policy);
        mint(accessor, material).await
    }
}

// --- digest --------------------------------------------------------------------

impl digest_iface::Host for WasiWebcryptoCtxView<'_> {}

impl HostDigest for WasiWebcryptoCtxView<'_> {
    fn algorithm_name(&mut self, self_: Resource<Digest>) -> Result<String> {
        Ok(self.table.get(&self_)?.variant.hash_name().to_string())
    }
}

impl<T: Send> HostDigestWithStore<T> for WasiWebcrypto {
    async fn compute(
        accessor: &Accessor<T, Self>,
        self_: Resource<Digest>,
        data: StreamReader<u8>,
    ) -> Result<std::result::Result<Vec<u8>, Error>> {
        // Buffer the whole stream, then hash it; the result is
        // chunking-invariant either way. The only error a compute can
        // report is checked SHA-1's `collision-detected` in the rejecting
        // posture.
        drain_then(accessor, self_, data, |digest, bytes| {
            digest.variant.digest(bytes).map_err(Into::into)
        })
        .await
    }

    async fn drop(accessor: &Accessor<T, Self>, rep: Resource<Digest>) -> Result<()> {
        drop_resource(accessor, rep).await
    }
}

// --- sha2 (digest minting) ---------------------------------------------------

impl sha2_iface::Host for WasiWebcryptoCtxView<'_> {
    fn make_digest(
        &mut self,
        variant: sha2_iface::Sha2Variant,
    ) -> Result<std::result::Result<Resource<Digest>, Error>> {
        let variant = match served_sha2(variant.into()) {
            Ok(variant) => variant,
            Err(err) => return Ok(Err(err.into())),
        };
        let Some(retention) = self.ctx.charge_retention(0) else {
            return Ok(Err(retention_exhausted(self.ctx.retention_limit_bytes())));
        };
        Ok(Ok(self.table.push(Digest::minted(
            DigestKind::Sha2(variant),
            retention,
        ))?))
    }
}

// --- sha1-checked (digest minting) ---------------------------------------------

impl sha1_checked_iface::Host for WasiWebcryptoCtxView<'_> {
    fn make_rejecting_digest(&mut self) -> Result<std::result::Result<Resource<Digest>, Error>> {
        let Some(retention) = self.ctx.charge_retention(0) else {
            return Ok(Err(retention_exhausted(self.ctx.retention_limit_bytes())));
        };
        Ok(Ok(self.table.push(Digest::minted(
            DigestKind::Sha1Checked(Sha1Posture::Reject),
            retention,
        ))?))
    }

    fn make_mitigating_digest(&mut self) -> Result<std::result::Result<Resource<Digest>, Error>> {
        let Some(retention) = self.ctx.charge_retention(0) else {
            return Ok(Err(retention_exhausted(self.ctx.retention_limit_bytes())));
        };
        Ok(Ok(self.table.push(Digest::minted(
            DigestKind::Sha1Checked(Sha1Posture::Mitigate),
            retention,
        ))?))
    }
}

// --- hmac-sha2 (key minting) -----------------------------------------------------

impl hmac_sha2_iface::Host for WasiWebcryptoCtxView<'_> {}

impl<T: Send> hmac_sha2_iface::HostWithStore<T> for WasiWebcrypto {
    async fn import_key_raw(
        accessor: &Accessor<T, Self>,
        variant: hmac_sha2_iface::Sha2Variant,
        raw: Vec<u8>,
        options: Resource<crate::MacKeyOptions>,
    ) -> Result<std::result::Result<Resource<MacKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = MacKeyMaterial::import(variant.into(), raw, policy);
        mint(accessor, material).await
    }

    async fn import_key_jwk(
        accessor: &Accessor<T, Self>,
        variant: hmac_sha2_iface::Sha2Variant,
        jwk: String,
        options: Resource<crate::MacKeyOptions>,
    ) -> Result<std::result::Result<Resource<MacKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = MacKeyMaterial::import_jwk(variant.into(), &jwk, policy);
        mint(accessor, material).await
    }

    async fn generate_key(
        accessor: &Accessor<T, Self>,
        variant: hmac_sha2_iface::Sha2Variant,
        length: Option<u32>,
        options: Resource<crate::MacKeyOptions>,
    ) -> Result<std::result::Result<Resource<MacKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = MacKeyMaterial::generate(variant.into(), length, policy)
            .map_err(rng_trap("random key generation"))?;
        mint(accessor, material).await
    }

    async fn derive_key(
        accessor: &Accessor<T, Self>,
        variant: hmac_sha2_iface::Sha2Variant,
        input: Resource<DeriveInput>,
        length: Option<u32>,
        options: Resource<crate::MacKeyOptions>,
    ) -> Result<std::result::Result<Resource<MacKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = with_resource(accessor, input, |input| {
            lann_webcrypto_core::derive_mac_key(&input.material, variant.into(), length, policy)
        })
        .await?;
        mint(accessor, material).await
    }

    async fn unwrap_key_raw(
        accessor: &Accessor<T, Self>,
        variant: hmac_sha2_iface::Sha2Variant,
        input: Resource<UnwrapInput>,
        options: Resource<crate::MacKeyOptions>,
    ) -> Result<std::result::Result<Resource<MacKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let input = take_options(accessor, input).await?.material;
        let material = lann_webcrypto_core::unwrap_mac_key(variant.into(), input, policy);
        mint(accessor, material).await
    }

    async fn unwrap_key_jwk(
        accessor: &Accessor<T, Self>,
        variant: hmac_sha2_iface::Sha2Variant,
        input: Resource<UnwrapInput>,
        options: Resource<crate::MacKeyOptions>,
    ) -> Result<std::result::Result<Resource<MacKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let input = take_options(accessor, input).await?.material;
        let material = lann_webcrypto_core::unwrap_mac_key_jwk(variant.into(), input, policy);
        mint(accessor, material).await
    }
}

// --- aes-gcm (key minting) -------------------------------------------------------

impl aes_gcm_iface::Host for WasiWebcryptoCtxView<'_> {}

impl<T: Send> aes_gcm_iface::HostWithStore<T> for WasiWebcrypto {
    async fn import_key_raw(
        accessor: &Accessor<T, Self>,
        variant: aes_gcm_iface::AesVariant,
        raw: Vec<u8>,
        options: Resource<crate::AeadKeyOptions>,
    ) -> Result<std::result::Result<Resource<AeadKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = AeadKeyMaterial::import_aes_gcm(variant.into(), raw, policy);
        mint(accessor, material).await
    }

    async fn import_key_jwk(
        accessor: &Accessor<T, Self>,
        variant: aes_gcm_iface::AesVariant,
        jwk: String,
        options: Resource<crate::AeadKeyOptions>,
    ) -> Result<std::result::Result<Resource<AeadKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = AeadKeyMaterial::import_aes_gcm_jwk(variant.into(), &jwk, policy);
        mint(accessor, material).await
    }

    async fn generate_key(
        accessor: &Accessor<T, Self>,
        variant: aes_gcm_iface::AesVariant,
        options: Resource<crate::AeadKeyOptions>,
    ) -> Result<std::result::Result<Resource<AeadKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = AeadKeyMaterial::generate_aes_gcm(variant.into(), policy)
            .map_err(rng_trap("random key generation"))?;
        mint(accessor, material).await
    }

    async fn derive_key(
        accessor: &Accessor<T, Self>,
        variant: aes_gcm_iface::AesVariant,
        input: Resource<DeriveInput>,
        options: Resource<crate::AeadKeyOptions>,
    ) -> Result<std::result::Result<Resource<AeadKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = with_resource(accessor, input, |input| {
            lann_webcrypto_core::derive_aes_gcm_key(&input.material, variant.into(), policy)
        })
        .await?;
        mint(accessor, material).await
    }

    async fn unwrap_key_raw(
        accessor: &Accessor<T, Self>,
        variant: aes_gcm_iface::AesVariant,
        input: Resource<UnwrapInput>,
        options: Resource<crate::AeadKeyOptions>,
    ) -> Result<std::result::Result<Resource<AeadKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let input = take_options(accessor, input).await?.material;
        let material = lann_webcrypto_core::unwrap_aes_gcm_key(variant.into(), input, policy);
        mint(accessor, material).await
    }

    async fn unwrap_key_jwk(
        accessor: &Accessor<T, Self>,
        variant: aes_gcm_iface::AesVariant,
        input: Resource<UnwrapInput>,
        options: Resource<crate::AeadKeyOptions>,
    ) -> Result<std::result::Result<Resource<AeadKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let input = take_options(accessor, input).await?.material;
        let material = lann_webcrypto_core::unwrap_aes_gcm_key_jwk(variant.into(), input, policy);
        mint(accessor, material).await
    }
}

// --- chacha20-poly1305 / xchacha20-poly1305 (key minting) ---------------------

impl chacha_iface::Host for WasiWebcryptoCtxView<'_> {}
impl xchacha_iface::Host for WasiWebcryptoCtxView<'_> {}

impl<T: Send> chacha_iface::HostWithStore<T> for WasiWebcrypto {
    async fn import_key_raw(
        accessor: &Accessor<T, Self>,
        raw: Vec<u8>,
        options: Resource<crate::AeadKeyOptions>,
    ) -> Result<std::result::Result<Resource<AeadKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = AeadKeyMaterial::import_chacha20_poly1305(raw, policy);
        mint(accessor, material).await
    }

    async fn import_key_jwk(
        accessor: &Accessor<T, Self>,
        jwk: String,
        options: Resource<crate::AeadKeyOptions>,
    ) -> Result<std::result::Result<Resource<AeadKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = AeadKeyMaterial::import_chacha20_poly1305_jwk(&jwk, policy);
        mint(accessor, material).await
    }

    async fn generate_key(
        accessor: &Accessor<T, Self>,
        options: Resource<crate::AeadKeyOptions>,
    ) -> Result<std::result::Result<Resource<AeadKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = AeadKeyMaterial::generate_chacha20_poly1305(policy)
            .map_err(rng_trap("random key generation"))?;
        mint(accessor, material).await
    }

    async fn unwrap_key_raw(
        accessor: &Accessor<T, Self>,
        input: Resource<UnwrapInput>,
        options: Resource<crate::AeadKeyOptions>,
    ) -> Result<std::result::Result<Resource<AeadKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let input = take_options(accessor, input).await?.material;
        let material = lann_webcrypto_core::unwrap_chacha_key(input, policy);
        mint(accessor, material).await
    }

    async fn unwrap_key_jwk(
        accessor: &Accessor<T, Self>,
        input: Resource<UnwrapInput>,
        options: Resource<crate::AeadKeyOptions>,
    ) -> Result<std::result::Result<Resource<AeadKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let input = take_options(accessor, input).await?.material;
        let material = lann_webcrypto_core::unwrap_chacha_key_jwk(input, policy);
        mint(accessor, material).await
    }
}

impl<T: Send> xchacha_iface::HostWithStore<T> for WasiWebcrypto {
    async fn import_key_raw(
        accessor: &Accessor<T, Self>,
        raw: Vec<u8>,
        options: Resource<crate::AeadKeyOptions>,
    ) -> Result<std::result::Result<Resource<AeadKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = AeadKeyMaterial::import_xchacha20_poly1305(raw, policy);
        mint(accessor, material).await
    }

    async fn generate_key(
        accessor: &Accessor<T, Self>,
        options: Resource<crate::AeadKeyOptions>,
    ) -> Result<std::result::Result<Resource<AeadKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = AeadKeyMaterial::generate_xchacha20_poly1305(policy)
            .map_err(rng_trap("random key generation"))?;
        mint(accessor, material).await
    }

    async fn unwrap_key_raw(
        accessor: &Accessor<T, Self>,
        input: Resource<UnwrapInput>,
        options: Resource<crate::AeadKeyOptions>,
    ) -> Result<std::result::Result<Resource<AeadKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let input = take_options(accessor, input).await?.material;
        let material = lann_webcrypto_core::unwrap_xchacha_key(input, policy);
        mint(accessor, material).await
    }
}

// --- aead-internal-nonce -------------------------------------------------------

impl aead_internal_nonce::Host for WasiWebcryptoCtxView<'_> {}

impl HostInternalNonceKey for WasiWebcryptoCtxView<'_> {
    fn algorithm_name(&mut self, self_: Resource<InternalNonceKey>) -> Result<String> {
        Ok(self.table.get(&self_)?.material.name().to_string())
    }

    fn algorithm_length(&mut self, self_: Resource<InternalNonceKey>) -> Result<u32> {
        Ok(self.table.get(&self_)?.material.length_bits())
    }

    fn seals_remaining(&mut self, self_: Resource<InternalNonceKey>) -> Result<Option<u64>> {
        let key = self.table.get(&self_)?;
        Ok(key.material.seals_remaining(key.sealed))
    }

    fn extractable(&mut self, self_: Resource<InternalNonceKey>) -> Result<bool> {
        Ok(self.table.get(&self_)?.material.extractable())
    }

    fn can_seal(&mut self, self_: Resource<InternalNonceKey>) -> Result<bool> {
        Ok(self.table.get(&self_)?.material.can_seal())
    }

    fn can_open(&mut self, self_: Resource<InternalNonceKey>) -> Result<bool> {
        Ok(self.table.get(&self_)?.material.can_open())
    }
}

host_options! {
    aead_internal_nonce::{HostInternalNonceKeyOptions, HostInternalNonceKeyOptionsWithStore}
    for crate::InternalNonceKeyOptions {
        can_seal => seal,
        can_open => open,
        extractable => extractable,
    }
}

impl<T: Send> HostInternalNonceKeyWithStore<T> for WasiWebcrypto {
    async fn seal(
        accessor: &Accessor<T, Self>,
        self_: Resource<InternalNonceKey>,
        aad: Vec<u8>,
        plaintext: StreamReader<u8>,
    ) -> Result<std::result::Result<StreamReader<u8>, Error>> {
        drain_then_stream(accessor, self_, plaintext, |key, msg| {
            // Count this invocation against the algorithm's nonce budget
            // before drawing the nonce, per the minting interfaces'
            // SHOULD-enforce contract.
            if let Err(err) = key.material.check_budget(key.sealed) {
                return Ok(Err(err.into()));
            }
            key.sealed += 1;
            key.material
                .seal_internal(&aad, msg)
                .map_err(rng_trap("nonce generation"))
                .map(|sealed| sealed.map_err(Error::from))
        })
        .await
    }

    async fn open(
        accessor: &Accessor<T, Self>,
        self_: Resource<InternalNonceKey>,
        aad: Vec<u8>,
        sealed: StreamReader<u8>,
    ) -> Result<std::result::Result<StreamReader<u8>, Error>> {
        drain_then_stream(accessor, self_, sealed, |key, msg| {
            Ok(key.material.open_internal(&aad, msg).map_err(Error::from))
        })
        .await
    }

    async fn export_key_raw(
        accessor: &Accessor<T, Self>,
        self_: Resource<InternalNonceKey>,
    ) -> Result<std::result::Result<Vec<u8>, Error>> {
        with_resource(accessor, self_, |key| {
            key.material.export().map_err(Error::from)
        })
        .await
    }

    async fn export_key_jwk(
        accessor: &Accessor<T, Self>,
        self_: Resource<InternalNonceKey>,
    ) -> Result<std::result::Result<String, Error>> {
        with_resource(accessor, self_, |key| {
            key.material.export_jwk().map_err(Error::from)
        })
        .await
    }

    async fn to_wrap_input_raw(
        accessor: &Accessor<T, Self>,
        self_: Resource<InternalNonceKey>,
    ) -> Result<std::result::Result<Resource<WrapInput>, Error>> {
        to_wrap_input(accessor, self_, WrapFormat::Raw, |key| {
            key.material.export()
        })
        .await
    }

    async fn to_wrap_input_jwk(
        accessor: &Accessor<T, Self>,
        self_: Resource<InternalNonceKey>,
    ) -> Result<std::result::Result<Resource<WrapInput>, Error>> {
        to_wrap_input(accessor, self_, WrapFormat::Jwk, |key| {
            key.material.export_jwk().map(String::into_bytes)
        })
        .await
    }

    async fn drop(accessor: &Accessor<T, Self>, rep: Resource<InternalNonceKey>) -> Result<()> {
        drop_resource(accessor, rep).await
    }
}

// --- aes-gcm-internal-nonce (key minting) ----------------------------------------

impl aes_gcm_in_iface::Host for WasiWebcryptoCtxView<'_> {}

impl<T: Send> aes_gcm_in_iface::HostWithStore<T> for WasiWebcrypto {
    async fn import_key_raw(
        accessor: &Accessor<T, Self>,
        variant: aes_gcm_iface::AesVariant,
        raw: Vec<u8>,
        options: Resource<crate::InternalNonceKeyOptions>,
    ) -> Result<std::result::Result<Resource<InternalNonceKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = AeadKeyMaterial::import_aes_gcm(variant.into(), raw, policy.into());
        mint(accessor, material).await
    }

    async fn import_key_jwk(
        accessor: &Accessor<T, Self>,
        variant: aes_gcm_iface::AesVariant,
        jwk: String,
        options: Resource<crate::InternalNonceKeyOptions>,
    ) -> Result<std::result::Result<Resource<InternalNonceKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = AeadKeyMaterial::import_aes_gcm_jwk(variant.into(), &jwk, policy.into());
        mint(accessor, material).await
    }

    async fn generate_key(
        accessor: &Accessor<T, Self>,
        variant: aes_gcm_iface::AesVariant,
        options: Resource<crate::InternalNonceKeyOptions>,
    ) -> Result<std::result::Result<Resource<InternalNonceKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = AeadKeyMaterial::generate_aes_gcm(variant.into(), policy.into())
            .map_err(rng_trap("random key generation"))?;
        mint(accessor, material).await
    }

    async fn unwrap_key_raw(
        accessor: &Accessor<T, Self>,
        variant: aes_gcm_iface::AesVariant,
        input: Resource<UnwrapInput>,
        options: Resource<crate::InternalNonceKeyOptions>,
    ) -> Result<std::result::Result<Resource<InternalNonceKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let input = take_options(accessor, input).await?.material;
        let material =
            lann_webcrypto_core::unwrap_aes_gcm_internal_key(variant.into(), input, policy);
        mint(accessor, material).await
    }

    async fn unwrap_key_jwk(
        accessor: &Accessor<T, Self>,
        variant: aes_gcm_iface::AesVariant,
        input: Resource<UnwrapInput>,
        options: Resource<crate::InternalNonceKeyOptions>,
    ) -> Result<std::result::Result<Resource<InternalNonceKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let input = take_options(accessor, input).await?.material;
        let material =
            lann_webcrypto_core::unwrap_aes_gcm_internal_key_jwk(variant.into(), input, policy);
        mint(accessor, material).await
    }
}

// --- xchacha20-poly1305-internal-nonce (key minting) ------------------------------

impl xchacha_in_iface::Host for WasiWebcryptoCtxView<'_> {}

impl<T: Send> xchacha_in_iface::HostWithStore<T> for WasiWebcrypto {
    async fn import_key_raw(
        accessor: &Accessor<T, Self>,
        raw: Vec<u8>,
        options: Resource<crate::InternalNonceKeyOptions>,
    ) -> Result<std::result::Result<Resource<InternalNonceKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = AeadKeyMaterial::import_xchacha20_poly1305(raw, policy.into());
        mint(accessor, material).await
    }

    async fn generate_key(
        accessor: &Accessor<T, Self>,
        options: Resource<crate::InternalNonceKeyOptions>,
    ) -> Result<std::result::Result<Resource<InternalNonceKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = AeadKeyMaterial::generate_xchacha20_poly1305(policy.into())
            .map_err(rng_trap("random key generation"))?;
        mint(accessor, material).await
    }

    async fn unwrap_key_raw(
        accessor: &Accessor<T, Self>,
        input: Resource<UnwrapInput>,
        options: Resource<crate::InternalNonceKeyOptions>,
    ) -> Result<std::result::Result<Resource<InternalNonceKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let input = take_options(accessor, input).await?.material;
        let material = lann_webcrypto_core::unwrap_xchacha_internal_key(input, policy);
        mint(accessor, material).await
    }
}

// --- signature -----------------------------------------------------------------

impl signature_iface::Host for WasiWebcryptoCtxView<'_> {}

impl signature_iface::HostVerifyingKey for WasiWebcryptoCtxView<'_> {
    fn algorithm_name(&mut self, self_: Resource<VerifyingKey>) -> Result<String> {
        Ok(self.table.get(&self_)?.public.name().to_string())
    }

    fn algorithm_curve(&mut self, self_: Resource<VerifyingKey>) -> Result<Option<String>> {
        Ok(self.table.get(&self_)?.public.curve().map(str::to_string))
    }

    fn algorithm_hash(&mut self, self_: Resource<VerifyingKey>) -> Result<Option<String>> {
        Ok(self.table.get(&self_)?.public.hash().map(str::to_string))
    }

    fn algorithm_length(&mut self, self_: Resource<VerifyingKey>) -> Result<Option<u32>> {
        Ok(self.table.get(&self_)?.public.length())
    }
}

impl<T: Send> signature_iface::HostVerifyingKeyWithStore<T> for WasiWebcrypto {
    async fn verify(
        accessor: &Accessor<T, Self>,
        self_: Resource<VerifyingKey>,
        data: StreamReader<u8>,
        sig: Vec<u8>,
    ) -> Result<std::result::Result<(), Error>> {
        drain_then(accessor, self_, data, |key, bytes| {
            key.public.verify(bytes, &sig).map_err(Error::from)
        })
        .await
    }

    async fn export_key_raw(
        accessor: &Accessor<T, Self>,
        self_: Resource<VerifyingKey>,
    ) -> Result<std::result::Result<Vec<u8>, Error>> {
        with_resource(accessor, self_, |key| {
            key.public.export().map_err(Error::from)
        })
        .await
    }

    async fn export_key_spki(
        accessor: &Accessor<T, Self>,
        self_: Resource<VerifyingKey>,
    ) -> Result<std::result::Result<Vec<u8>, Error>> {
        with_resource(accessor, self_, |key| Ok(key.public.export_spki())).await
    }

    async fn export_key_jwk(
        accessor: &Accessor<T, Self>,
        self_: Resource<VerifyingKey>,
    ) -> Result<std::result::Result<String, Error>> {
        with_resource(accessor, self_, |key| Ok(key.public.export_jwk())).await
    }

    async fn drop(accessor: &Accessor<T, Self>, rep: Resource<VerifyingKey>) -> Result<()> {
        drop_resource(accessor, rep).await
    }
}

impl signature_iface::HostSigningKey for WasiWebcryptoCtxView<'_> {
    fn algorithm_name(&mut self, self_: Resource<SigningKey>) -> Result<String> {
        Ok(self.table.get(&self_)?.material.name().to_string())
    }

    fn algorithm_curve(&mut self, self_: Resource<SigningKey>) -> Result<Option<String>> {
        Ok(self.table.get(&self_)?.material.curve().map(str::to_string))
    }

    fn algorithm_hash(&mut self, self_: Resource<SigningKey>) -> Result<Option<String>> {
        Ok(self.table.get(&self_)?.material.hash().map(str::to_string))
    }

    fn algorithm_length(&mut self, self_: Resource<SigningKey>) -> Result<Option<u32>> {
        Ok(self.table.get(&self_)?.material.length())
    }

    fn extractable(&mut self, self_: Resource<SigningKey>) -> Result<bool> {
        Ok(self.table.get(&self_)?.material.extractable())
    }

    fn can_sign(&mut self, self_: Resource<SigningKey>) -> Result<bool> {
        Ok(self.table.get(&self_)?.material.can_sign())
    }
}

host_options! {
    signature_iface::{HostSigningKeyOptions, HostSigningKeyOptionsWithStore}
    for crate::SigningKeyOptions {
        can_sign => sign,
        extractable => extractable,
    }
}

impl<T: Send> signature_iface::HostSigningKeyWithStore<T> for WasiWebcrypto {
    async fn sign(
        accessor: &Accessor<T, Self>,
        self_: Resource<SigningKey>,
        data: StreamReader<u8>,
    ) -> Result<std::result::Result<Vec<u8>, Error>> {
        drain_then(accessor, self_, data, |key, bytes| {
            key.material.sign(bytes).map_err(Error::from)
        })
        .await
    }

    async fn export_key_jwk(
        accessor: &Accessor<T, Self>,
        self_: Resource<SigningKey>,
    ) -> Result<std::result::Result<String, Error>> {
        with_resource(accessor, self_, |key| {
            key.material.export_jwk().map_err(Error::from)
        })
        .await
    }

    async fn export_key_pkcs8(
        accessor: &Accessor<T, Self>,
        self_: Resource<SigningKey>,
    ) -> Result<std::result::Result<Vec<u8>, Error>> {
        with_resource(accessor, self_, |key| {
            key.material.export_pkcs8().map_err(Error::from)
        })
        .await
    }

    async fn to_wrap_input_jwk(
        accessor: &Accessor<T, Self>,
        self_: Resource<SigningKey>,
    ) -> Result<std::result::Result<Resource<WrapInput>, Error>> {
        to_wrap_input(accessor, self_, WrapFormat::Jwk, |key| {
            key.material.export_jwk().map(String::into_bytes)
        })
        .await
    }

    async fn to_wrap_input_pkcs8(
        accessor: &Accessor<T, Self>,
        self_: Resource<SigningKey>,
    ) -> Result<std::result::Result<Resource<WrapInput>, Error>> {
        to_wrap_input(accessor, self_, WrapFormat::Pkcs8, |key| {
            key.material.export_pkcs8()
        })
        .await
    }

    async fn drop(accessor: &Accessor<T, Self>, rep: Resource<SigningKey>) -> Result<()> {
        drop_resource(accessor, rep).await
    }
}

// --- ed25519 (key minting) -----------------------------------------------------

impl ed25519_verify_iface::Host for WasiWebcryptoCtxView<'_> {}
impl ed25519_sign_iface::Host for WasiWebcryptoCtxView<'_> {}

impl<T: Send> ed25519_verify_iface::HostWithStore<T> for WasiWebcrypto {
    async fn import_verifying_key_raw(
        accessor: &Accessor<T, Self>,
        raw: Vec<u8>,
    ) -> Result<std::result::Result<Resource<VerifyingKey>, Error>> {
        let public = SigPublic::import_ed25519(&raw);
        mint(accessor, public).await
    }

    async fn import_verifying_key_spki(
        accessor: &Accessor<T, Self>,
        spki: Vec<u8>,
    ) -> Result<std::result::Result<Resource<VerifyingKey>, Error>> {
        let public = SigPublic::import_ed25519_spki(&spki);
        mint(accessor, public).await
    }

    async fn import_verifying_key_jwk(
        accessor: &Accessor<T, Self>,
        jwk: String,
    ) -> Result<std::result::Result<Resource<VerifyingKey>, Error>> {
        let public = SigPublic::import_ed25519_jwk(&jwk);
        mint(accessor, public).await
    }
}

impl<T: Send> ed25519_sign_iface::HostWithStore<T> for WasiWebcrypto {
    async fn generate_key(
        accessor: &Accessor<T, Self>,
        options: Resource<crate::SigningKeyOptions>,
    ) -> Result<std::result::Result<(Resource<SigningKey>, Resource<VerifyingKey>), Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = match SigningKeyMaterial::generate_ed25519(policy)
            .map_err(rng_trap("random key generation"))?
        {
            Ok(material) => material,
            Err(err) => return Ok(Err(err.into())),
        };
        mint_signing_pair(accessor, material).await
    }

    async fn import_signing_key_pkcs8(
        accessor: &Accessor<T, Self>,
        pkcs8: Vec<u8>,
        options: Resource<crate::SigningKeyOptions>,
    ) -> Result<std::result::Result<Resource<SigningKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = SigningKeyMaterial::import_ed25519_pkcs8(&pkcs8, policy);
        mint(accessor, material).await
    }

    async fn import_signing_key_jwk(
        accessor: &Accessor<T, Self>,
        jwk: String,
        options: Resource<crate::SigningKeyOptions>,
    ) -> Result<std::result::Result<Resource<SigningKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = SigningKeyMaterial::import_ed25519_jwk(&jwk, policy);
        mint(accessor, material).await
    }

    async fn unwrap_signing_key_pkcs8(
        accessor: &Accessor<T, Self>,
        input: Resource<UnwrapInput>,
        options: Resource<crate::SigningKeyOptions>,
    ) -> Result<std::result::Result<Resource<SigningKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let input = take_options(accessor, input).await?.material;
        let material = lann_webcrypto_core::unwrap_ed25519_signing_key_pkcs8(input, policy);
        mint(accessor, material).await
    }

    async fn unwrap_signing_key_jwk(
        accessor: &Accessor<T, Self>,
        input: Resource<UnwrapInput>,
        options: Resource<crate::SigningKeyOptions>,
    ) -> Result<std::result::Result<Resource<SigningKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let input = take_options(accessor, input).await?.material;
        let material = lann_webcrypto_core::unwrap_ed25519_signing_key_jwk(input, policy);
        mint(accessor, material).await
    }
}

/// Push a generated signing key and the public half returned with it.
async fn mint_signing_pair<T: Send>(
    accessor: &Accessor<T, WasiWebcrypto>,
    material: SigningKeyMaterial,
) -> Result<std::result::Result<(Resource<SigningKey>, Resource<VerifyingKey>), Error>> {
    let public = material.public();
    mint_key_pair(accessor, material, public).await
}

// --- ecdsa (key minting) ---------------------------------------------------------

impl ecdsa_verify_iface::Host for WasiWebcryptoCtxView<'_> {}
impl ecdsa_sign_iface::Host for WasiWebcryptoCtxView<'_> {}

impl<T: Send> ecdsa_verify_iface::HostWithStore<T> for WasiWebcrypto {
    async fn import_verifying_key_raw(
        accessor: &Accessor<T, Self>,
        variant: ecdsa_verify_iface::EcdsaVariant,
        raw: Vec<u8>,
    ) -> Result<std::result::Result<Resource<VerifyingKey>, Error>> {
        let public = SigPublic::import_ecdsa(variant.into(), &raw);
        mint(accessor, public).await
    }

    async fn import_verifying_key_spki(
        accessor: &Accessor<T, Self>,
        variant: ecdsa_verify_iface::EcdsaVariant,
        spki: Vec<u8>,
    ) -> Result<std::result::Result<Resource<VerifyingKey>, Error>> {
        let public = SigPublic::import_ecdsa_spki(variant.into(), &spki);
        mint(accessor, public).await
    }

    async fn import_verifying_key_jwk(
        accessor: &Accessor<T, Self>,
        variant: ecdsa_verify_iface::EcdsaVariant,
        jwk: String,
    ) -> Result<std::result::Result<Resource<VerifyingKey>, Error>> {
        let public = SigPublic::import_ecdsa_jwk(variant.into(), &jwk);
        mint(accessor, public).await
    }
}

impl<T: Send> ecdsa_sign_iface::HostWithStore<T> for WasiWebcrypto {
    async fn generate_key(
        accessor: &Accessor<T, Self>,
        variant: ecdsa_verify_iface::EcdsaVariant,
        options: Resource<crate::SigningKeyOptions>,
    ) -> Result<std::result::Result<(Resource<SigningKey>, Resource<VerifyingKey>), Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = match SigningKeyMaterial::generate_ecdsa(variant.into(), policy)
            .map_err(rng_trap("random key generation"))?
        {
            Ok(material) => material,
            Err(err) => return Ok(Err(err.into())),
        };
        mint_signing_pair(accessor, material).await
    }

    async fn import_signing_key_pkcs8(
        accessor: &Accessor<T, Self>,
        variant: ecdsa_verify_iface::EcdsaVariant,
        pkcs8: Vec<u8>,
        options: Resource<crate::SigningKeyOptions>,
    ) -> Result<std::result::Result<Resource<SigningKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = SigningKeyMaterial::import_ecdsa_pkcs8(variant.into(), &pkcs8, policy);
        mint(accessor, material).await
    }

    async fn import_signing_key_jwk(
        accessor: &Accessor<T, Self>,
        variant: ecdsa_verify_iface::EcdsaVariant,
        jwk: String,
        options: Resource<crate::SigningKeyOptions>,
    ) -> Result<std::result::Result<Resource<SigningKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = SigningKeyMaterial::import_ecdsa_jwk(variant.into(), &jwk, policy);
        mint(accessor, material).await
    }

    async fn unwrap_signing_key_pkcs8(
        accessor: &Accessor<T, Self>,
        variant: ecdsa_verify_iface::EcdsaVariant,
        input: Resource<UnwrapInput>,
        options: Resource<crate::SigningKeyOptions>,
    ) -> Result<std::result::Result<Resource<SigningKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let input = take_options(accessor, input).await?.material;
        let material =
            lann_webcrypto_core::unwrap_ecdsa_signing_key_pkcs8(variant.into(), input, policy);
        mint(accessor, material).await
    }

    async fn unwrap_signing_key_jwk(
        accessor: &Accessor<T, Self>,
        variant: ecdsa_verify_iface::EcdsaVariant,
        input: Resource<UnwrapInput>,
        options: Resource<crate::SigningKeyOptions>,
    ) -> Result<std::result::Result<Resource<SigningKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let input = take_options(accessor, input).await?.material;
        let material =
            lann_webcrypto_core::unwrap_ecdsa_signing_key_jwk(variant.into(), input, policy);
        mint(accessor, material).await
    }
}

// --- rsa (key minting) -----------------------------------------------------------

impl rsa_iface::Host for WasiWebcryptoCtxView<'_> {}
impl rsassa_verify_iface::Host for WasiWebcryptoCtxView<'_> {}
impl rsa_pss_verify_iface::Host for WasiWebcryptoCtxView<'_> {}
impl rsassa_sign_iface::Host for WasiWebcryptoCtxView<'_> {}
impl rsa_pss_sign_iface::Host for WasiWebcryptoCtxView<'_> {}

/// The WIT `rsa.rsa-modulus` cases, converted locally: the type is
/// deliberately outside the shared core's `impl_conversions!` (see its
/// doc in the core).
impl From<rsa_iface::RsaModulus> for lann_webcrypto_core::RsaModulus {
    fn from(modulus: rsa_iface::RsaModulus) -> Self {
        match modulus {
            rsa_iface::RsaModulus::M2048 => Self::M2048,
            rsa_iface::RsaModulus::M3072 => Self::M3072,
            rsa_iface::RsaModulus::M4096 => Self::M4096,
            rsa_iface::RsaModulus::M8192 => Self::M8192,
        }
    }
}

impl<T: Send> rsassa_verify_iface::HostWithStore<T> for WasiWebcrypto {
    async fn import_verifying_key_spki(
        accessor: &Accessor<T, Self>,
        variant: rsa_iface::RsaVariant,
        spki: Vec<u8>,
    ) -> Result<std::result::Result<Resource<VerifyingKey>, Error>> {
        let public = SigPublic::import_rsassa_spki(variant.into(), &spki);
        mint(accessor, public).await
    }

    async fn import_verifying_key_jwk(
        accessor: &Accessor<T, Self>,
        variant: rsa_iface::RsaVariant,
        jwk: String,
    ) -> Result<std::result::Result<Resource<VerifyingKey>, Error>> {
        let public = SigPublic::import_rsassa_jwk(variant.into(), &jwk);
        mint(accessor, public).await
    }
}

impl<T: Send> rsa_pss_verify_iface::HostWithStore<T> for WasiWebcrypto {
    async fn import_verifying_key_spki(
        accessor: &Accessor<T, Self>,
        variant: rsa_iface::RsaVariant,
        salt_length: u32,
        spki: Vec<u8>,
    ) -> Result<std::result::Result<Resource<VerifyingKey>, Error>> {
        let public = SigPublic::import_pss_spki(variant.into(), salt_length, &spki);
        mint(accessor, public).await
    }

    async fn import_verifying_key_jwk(
        accessor: &Accessor<T, Self>,
        variant: rsa_iface::RsaVariant,
        salt_length: u32,
        jwk: String,
    ) -> Result<std::result::Result<Resource<VerifyingKey>, Error>> {
        let public = SigPublic::import_pss_jwk(variant.into(), salt_length, &jwk);
        mint(accessor, public).await
    }
}

impl<T: Send> rsassa_sign_iface::HostWithStore<T> for WasiWebcrypto {
    async fn generate_key(
        accessor: &Accessor<T, Self>,
        variant: rsa_iface::RsaVariant,
        modulus: rsa_iface::RsaModulus,
        options: Resource<crate::SigningKeyOptions>,
    ) -> Result<std::result::Result<(Resource<SigningKey>, Resource<VerifyingKey>), Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material =
            match SigningKeyMaterial::generate_rsassa(variant.into(), modulus.into(), policy)
                .map_err(rng_trap("random key generation"))?
            {
                Ok(material) => material,
                Err(err) => return Ok(Err(err.into())),
            };
        mint_signing_pair(accessor, material).await
    }

    async fn import_signing_key_pkcs8(
        accessor: &Accessor<T, Self>,
        variant: rsa_iface::RsaVariant,
        pkcs8: Vec<u8>,
        options: Resource<crate::SigningKeyOptions>,
    ) -> Result<std::result::Result<Resource<SigningKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = SigningKeyMaterial::import_rsassa_pkcs8(variant.into(), &pkcs8, policy);
        mint(accessor, material).await
    }

    async fn import_signing_key_jwk(
        accessor: &Accessor<T, Self>,
        variant: rsa_iface::RsaVariant,
        jwk: String,
        options: Resource<crate::SigningKeyOptions>,
    ) -> Result<std::result::Result<Resource<SigningKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = SigningKeyMaterial::import_rsassa_jwk(variant.into(), &jwk, policy);
        mint(accessor, material).await
    }

    async fn unwrap_signing_key_pkcs8(
        accessor: &Accessor<T, Self>,
        variant: rsa_iface::RsaVariant,
        input: Resource<UnwrapInput>,
        options: Resource<crate::SigningKeyOptions>,
    ) -> Result<std::result::Result<Resource<SigningKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let input = take_options(accessor, input).await?.material;
        let material =
            lann_webcrypto_core::unwrap_rsassa_signing_key_pkcs8(variant.into(), input, policy);
        mint(accessor, material).await
    }

    async fn unwrap_signing_key_jwk(
        accessor: &Accessor<T, Self>,
        variant: rsa_iface::RsaVariant,
        input: Resource<UnwrapInput>,
        options: Resource<crate::SigningKeyOptions>,
    ) -> Result<std::result::Result<Resource<SigningKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let input = take_options(accessor, input).await?.material;
        let material =
            lann_webcrypto_core::unwrap_rsassa_signing_key_jwk(variant.into(), input, policy);
        mint(accessor, material).await
    }
}

impl<T: Send> rsa_pss_sign_iface::HostWithStore<T> for WasiWebcrypto {
    async fn generate_key(
        accessor: &Accessor<T, Self>,
        variant: rsa_iface::RsaVariant,
        modulus: rsa_iface::RsaModulus,
        options: Resource<crate::SigningKeyOptions>,
    ) -> Result<std::result::Result<(Resource<SigningKey>, Resource<VerifyingKey>), Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material =
            match SigningKeyMaterial::generate_pss(variant.into(), modulus.into(), policy)
                .map_err(rng_trap("random key generation"))?
            {
                Ok(material) => material,
                Err(err) => return Ok(Err(err.into())),
            };
        mint_signing_pair(accessor, material).await
    }

    async fn import_signing_key_pkcs8(
        accessor: &Accessor<T, Self>,
        variant: rsa_iface::RsaVariant,
        pkcs8: Vec<u8>,
        options: Resource<crate::SigningKeyOptions>,
    ) -> Result<std::result::Result<Resource<SigningKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = SigningKeyMaterial::import_pss_pkcs8(variant.into(), &pkcs8, policy);
        mint(accessor, material).await
    }

    async fn import_signing_key_jwk(
        accessor: &Accessor<T, Self>,
        variant: rsa_iface::RsaVariant,
        jwk: String,
        options: Resource<crate::SigningKeyOptions>,
    ) -> Result<std::result::Result<Resource<SigningKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = SigningKeyMaterial::import_pss_jwk(variant.into(), &jwk, policy);
        mint(accessor, material).await
    }

    async fn unwrap_signing_key_pkcs8(
        accessor: &Accessor<T, Self>,
        variant: rsa_iface::RsaVariant,
        input: Resource<UnwrapInput>,
        options: Resource<crate::SigningKeyOptions>,
    ) -> Result<std::result::Result<Resource<SigningKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let input = take_options(accessor, input).await?.material;
        let material =
            lann_webcrypto_core::unwrap_pss_signing_key_pkcs8(variant.into(), input, policy);
        mint(accessor, material).await
    }

    async fn unwrap_signing_key_jwk(
        accessor: &Accessor<T, Self>,
        variant: rsa_iface::RsaVariant,
        input: Resource<UnwrapInput>,
        options: Resource<crate::SigningKeyOptions>,
    ) -> Result<std::result::Result<Resource<SigningKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let input = take_options(accessor, input).await?.material;
        let material =
            lann_webcrypto_core::unwrap_pss_signing_key_jwk(variant.into(), input, policy);
        mint(accessor, material).await
    }
}

// --- public-encryption -----------------------------------------------------------

impl public_encryption_iface::Host for WasiWebcryptoCtxView<'_> {}

host_options! {
    public_encryption_iface::{HostDecryptionKeyOptions, HostDecryptionKeyOptionsWithStore}
    for crate::DecryptionKeyOptions {
        can_decrypt => decrypt,
        can_unwrap => unwrap,
        extractable => extractable,
    }
}

impl HostEncryptionKey for WasiWebcryptoCtxView<'_> {
    fn algorithm_name(&mut self, self_: Resource<EncryptionKey>) -> Result<String> {
        Ok(self.table.get(&self_)?.material.name().to_string())
    }

    fn algorithm_hash(&mut self, self_: Resource<EncryptionKey>) -> Result<Option<String>> {
        Ok(self.table.get(&self_)?.material.hash().map(str::to_string))
    }

    fn algorithm_length(&mut self, self_: Resource<EncryptionKey>) -> Result<Option<u32>> {
        Ok(self.table.get(&self_)?.material.length())
    }
}

impl<T: Send> HostEncryptionKeyWithStore<T> for WasiWebcrypto {
    async fn encrypt(
        accessor: &Accessor<T, Self>,
        self_: Resource<EncryptionKey>,
        label: Option<Vec<u8>>,
        plaintext: Vec<u8>,
    ) -> Result<std::result::Result<Vec<u8>, Error>> {
        with_resource(accessor, self_, |key| {
            key.material
                .encrypt(label.as_deref(), &plaintext)
                .map_err(Error::from)
        })
        .await
    }

    async fn wrap(
        accessor: &Accessor<T, Self>,
        self_: Resource<EncryptionKey>,
        label: Option<Vec<u8>>,
        input: Resource<WrapInput>,
    ) -> Result<std::result::Result<Vec<u8>, Error>> {
        let input = take_options(accessor, input).await?.material;
        with_resource(accessor, self_, |key| {
            key.material
                .wrap(label.as_deref(), input)
                .map_err(Error::from)
        })
        .await
    }

    async fn export_key_raw(
        accessor: &Accessor<T, Self>,
        self_: Resource<EncryptionKey>,
    ) -> Result<std::result::Result<Vec<u8>, Error>> {
        with_resource(accessor, self_, |key| {
            key.material.export().map_err(Error::from)
        })
        .await
    }

    async fn export_key_spki(
        accessor: &Accessor<T, Self>,
        self_: Resource<EncryptionKey>,
    ) -> Result<std::result::Result<Vec<u8>, Error>> {
        with_resource(accessor, self_, |key| Ok(key.material.export_spki())).await
    }

    async fn export_key_jwk(
        accessor: &Accessor<T, Self>,
        self_: Resource<EncryptionKey>,
    ) -> Result<std::result::Result<String, Error>> {
        with_resource(accessor, self_, |key| Ok(key.material.export_jwk())).await
    }

    async fn drop(accessor: &Accessor<T, Self>, rep: Resource<EncryptionKey>) -> Result<()> {
        drop_resource(accessor, rep).await
    }
}

impl HostDecryptionKey for WasiWebcryptoCtxView<'_> {
    fn algorithm_name(&mut self, self_: Resource<DecryptionKey>) -> Result<String> {
        Ok(self.table.get(&self_)?.material.name().to_string())
    }

    fn algorithm_hash(&mut self, self_: Resource<DecryptionKey>) -> Result<Option<String>> {
        Ok(self.table.get(&self_)?.material.hash().map(str::to_string))
    }

    fn algorithm_length(&mut self, self_: Resource<DecryptionKey>) -> Result<Option<u32>> {
        Ok(self.table.get(&self_)?.material.length())
    }

    fn can_decrypt(&mut self, self_: Resource<DecryptionKey>) -> Result<bool> {
        Ok(self.table.get(&self_)?.material.can_decrypt())
    }

    fn can_unwrap(&mut self, self_: Resource<DecryptionKey>) -> Result<bool> {
        Ok(self.table.get(&self_)?.material.can_unwrap())
    }

    fn extractable(&mut self, self_: Resource<DecryptionKey>) -> Result<bool> {
        Ok(self.table.get(&self_)?.material.extractable())
    }
}

impl<T: Send> HostDecryptionKeyWithStore<T> for WasiWebcrypto {
    async fn decrypt(
        accessor: &Accessor<T, Self>,
        self_: Resource<DecryptionKey>,
        label: Option<Vec<u8>>,
        ciphertext: Vec<u8>,
    ) -> Result<std::result::Result<Vec<u8>, Error>> {
        with_resource(accessor, self_, |key| {
            key.material
                .decrypt(label.as_deref(), &ciphertext)
                .map_err(Error::from)
        })
        .await
    }

    async fn unwrap(
        accessor: &Accessor<T, Self>,
        self_: Resource<DecryptionKey>,
        label: Option<Vec<u8>>,
        ciphertext: Vec<u8>,
    ) -> Result<std::result::Result<Resource<UnwrapInput>, Error>> {
        let material = with_resource(accessor, self_, |key| {
            key.material.unwrap(label.as_deref(), &ciphertext)
        })
        .await?;
        mint(accessor, material).await
    }

    async fn export_key_jwk(
        accessor: &Accessor<T, Self>,
        self_: Resource<DecryptionKey>,
    ) -> Result<std::result::Result<String, Error>> {
        with_resource(accessor, self_, |key| {
            key.material.export_jwk().map_err(Error::from)
        })
        .await
    }

    async fn export_key_pkcs8(
        accessor: &Accessor<T, Self>,
        self_: Resource<DecryptionKey>,
    ) -> Result<std::result::Result<Vec<u8>, Error>> {
        with_resource(accessor, self_, |key| {
            key.material.export_pkcs8().map_err(Error::from)
        })
        .await
    }

    async fn to_wrap_input_jwk(
        accessor: &Accessor<T, Self>,
        self_: Resource<DecryptionKey>,
    ) -> Result<std::result::Result<Resource<WrapInput>, Error>> {
        to_wrap_input(accessor, self_, WrapFormat::Jwk, |key| {
            key.material.export_jwk().map(String::into_bytes)
        })
        .await
    }

    async fn to_wrap_input_pkcs8(
        accessor: &Accessor<T, Self>,
        self_: Resource<DecryptionKey>,
    ) -> Result<std::result::Result<Resource<WrapInput>, Error>> {
        to_wrap_input(accessor, self_, WrapFormat::Pkcs8, |key| {
            key.material.export_pkcs8()
        })
        .await
    }

    async fn drop(accessor: &Accessor<T, Self>, rep: Resource<DecryptionKey>) -> Result<()> {
        drop_resource(accessor, rep).await
    }
}

// --- rsa-oaep (key minting) --------------------------------------------------------

impl rsa_oaep_encrypt_iface::Host for WasiWebcryptoCtxView<'_> {}
impl rsa_oaep_decrypt_iface::Host for WasiWebcryptoCtxView<'_> {}

impl<T: Send> rsa_oaep_encrypt_iface::HostWithStore<T> for WasiWebcrypto {
    async fn import_encryption_key_spki(
        accessor: &Accessor<T, Self>,
        variant: rsa_iface::RsaVariant,
        spki: Vec<u8>,
    ) -> Result<std::result::Result<Resource<EncryptionKey>, Error>> {
        let material = EncryptionKeyMaterial::import_oaep_spki(variant.into(), &spki);
        mint(accessor, material).await
    }

    async fn import_encryption_key_jwk(
        accessor: &Accessor<T, Self>,
        variant: rsa_iface::RsaVariant,
        jwk: String,
    ) -> Result<std::result::Result<Resource<EncryptionKey>, Error>> {
        let material = EncryptionKeyMaterial::import_oaep_jwk(variant.into(), &jwk);
        mint(accessor, material).await
    }
}

impl<T: Send> rsa_oaep_decrypt_iface::HostWithStore<T> for WasiWebcrypto {
    async fn generate_key(
        accessor: &Accessor<T, Self>,
        variant: rsa_iface::RsaVariant,
        modulus: rsa_iface::RsaModulus,
        options: Resource<crate::DecryptionKeyOptions>,
    ) -> Result<std::result::Result<(Resource<DecryptionKey>, Resource<EncryptionKey>), Error>>
    {
        let policy = take_options(accessor, options).await?.policy;
        let material =
            match DecryptionKeyMaterial::generate_oaep(variant.into(), modulus.into(), policy)
                .map_err(rng_trap("random key generation"))?
            {
                Ok(material) => material,
                Err(err) => return Ok(Err(err.into())),
            };
        let public = material.public();
        mint_key_pair(accessor, material, public).await
    }

    async fn import_decryption_key_pkcs8(
        accessor: &Accessor<T, Self>,
        variant: rsa_iface::RsaVariant,
        pkcs8: Vec<u8>,
        options: Resource<crate::DecryptionKeyOptions>,
    ) -> Result<std::result::Result<Resource<DecryptionKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = DecryptionKeyMaterial::import_oaep_pkcs8(variant.into(), &pkcs8, policy);
        mint(accessor, material).await
    }

    async fn import_decryption_key_jwk(
        accessor: &Accessor<T, Self>,
        variant: rsa_iface::RsaVariant,
        jwk: String,
        options: Resource<crate::DecryptionKeyOptions>,
    ) -> Result<std::result::Result<Resource<DecryptionKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = DecryptionKeyMaterial::import_oaep_jwk(variant.into(), &jwk, policy);
        mint(accessor, material).await
    }

    async fn unwrap_decryption_key_pkcs8(
        accessor: &Accessor<T, Self>,
        variant: rsa_iface::RsaVariant,
        input: Resource<UnwrapInput>,
        options: Resource<crate::DecryptionKeyOptions>,
    ) -> Result<std::result::Result<Resource<DecryptionKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let input = take_options(accessor, input).await?.material;
        let material =
            lann_webcrypto_core::unwrap_oaep_decryption_key_pkcs8(variant.into(), input, policy);
        mint(accessor, material).await
    }

    async fn unwrap_decryption_key_jwk(
        accessor: &Accessor<T, Self>,
        variant: rsa_iface::RsaVariant,
        input: Resource<UnwrapInput>,
        options: Resource<crate::DecryptionKeyOptions>,
    ) -> Result<std::result::Result<Resource<DecryptionKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let input = take_options(accessor, input).await?.material;
        let material =
            lann_webcrypto_core::unwrap_oaep_decryption_key_jwk(variant.into(), input, policy);
        mint(accessor, material).await
    }
}

#[cfg(test)]
mod tests {
    use crate::bindings::webcrypto::sha1_checked::Host as _;
    use crate::bindings::webcrypto::sha2::{self as sha2_iface, Host as _};
    use crate::bindings::webcrypto::types::Error;
    use crate::{MacKey, Minted as _};
    use lann_webcrypto_core::{MacKeyMaterial, MacPolicy, Sha2Variant};

    /// Minting charges the retention budget: a spent budget fails a
    /// fallible mint with the WIT's operational error and traps an options
    /// constructor (whose signature has no error channel), and dropping a
    /// held resource readmits the next mint.
    #[test]
    fn minting_charges_the_retention_budget() {
        let mut ctx = crate::WasiWebcryptoCtx::new();
        ctx.set_retention_limit(Some(crate::limits::RETENTION_FLOOR));
        let mut table = wasmtime::component::ResourceTable::new();
        let mut view = crate::WasiWebcryptoCtxView {
            ctx: &mut ctx,
            table: &mut table,
        };

        let digest = view
            .make_digest(sha2_iface::Sha2Variant::Sha256)
            .unwrap()
            .expect("one floor-sized mint fits the budget");

        match view.make_rejecting_digest().unwrap() {
            Err(Error::Other(msg)) => assert!(msg.contains("set_retention_limit"), "{msg}"),
            other => panic!("expected the retention error, got {other:?}"),
        }
        let trap = crate::bindings::webcrypto::mac::HostMacKeyOptions::new(&mut view)
            .expect_err("an options mint past the budget traps");
        assert!(trap.to_string().contains("set_retention_limit"), "{trap}");

        view.table.delete(digest).unwrap();
        view.make_rejecting_digest()
            .unwrap()
            .expect("the dropped resource's charge readmits the mint");
    }

    /// `Debug` on key-holding types never prints key material: the bytes
    /// are redacted (in the shared core's material types, which these
    /// resource types derive through), so a key reaching a log line cannot
    /// leak.
    #[test]
    fn debug_redacts_key_material() {
        let policy = MacPolicy {
            sign: true,
            verify: true,
            extractable: true,
        };
        let pool = crate::limits::pool(1024);
        let key = MacKey::minted(
            MacKeyMaterial::import(Sha2Variant::Sha256, vec![0xAB; 32], policy).unwrap(),
            crate::limits::charge(&pool, 32).unwrap(),
        );
        let rendered = format!("{key:?}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(!rendered.contains("171"), "{rendered}"); // 0xAB
        assert!(!rendered.to_lowercase().contains("ab, ab"), "{rendered}");
    }
}
