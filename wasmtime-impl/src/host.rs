//! Host trait implementations for the `lann:webcrypto` imports.
//!
//! Following the split the generated bindings produce (and mirroring
//! `wasmtime_wasi_http::p3`), the store-free traits are implemented for the
//! [`WasiWebcryptoCtxView`] "data" type, while the traits whose methods need
//! the async `Accessor` are implemented for the [`WasiWebcrypto`] `HasData`
//! marker.
//!
//! The cryptography itself lives in `webcrypto-impl-core`, shared verbatim
//! with the in-guest provider; this module contributes only what is
//! host-specific — the resource table and the shapes every operation
//! shares (mint into the table, drain-then-compute, drain-then-stream-out),
//! over the stream plumbing in [`crate::streams`] and the admission in
//! [`crate::limits`].

use wasmtime::component::{Accessor, Resource, StreamReader};
use wasmtime::Result;
use webcrypto_impl_core::{
    served_sha2, AeadKeyMaterial, DigestKind, MacKeyMaterial, Sha1Posture, SigPublic,
    SigningKeyMaterial, HMAC_NAME,
};

use crate::bindings::webcrypto::aead::{self, HostAeadKey, HostAeadKeyWithStore};
use crate::bindings::webcrypto::aead_internal_nonce::{
    self, HostInternalNonceKey, HostInternalNonceKeyWithStore,
};
use crate::bindings::webcrypto::derivation::{
    self as derivation_iface, HostDeriveInput, HostDeriveInputWithStore, HostDeriveOptions,
    HostDeriveOptionsWithStore,
};
use crate::bindings::webcrypto::digest::{HostDigest, HostDigestWithStore};
use crate::bindings::webcrypto::hkdf::{self as hkdf_iface, HostIkm, HostIkmWithStore};
use crate::bindings::webcrypto::key_agreement::{
    self as key_agreement_iface, HostAgreementKeyOptions, HostAgreementKeyOptionsWithStore,
    HostPublicKey, HostPublicKeyWithStore, HostSecretKey, HostSecretKeyWithStore,
};
use crate::bindings::webcrypto::mac::{self, HostMacKey, HostMacKeyWithStore};
use crate::bindings::webcrypto::pbkdf2::{
    self as pbkdf2_iface, HostPassword, HostPasswordWithStore,
};
use crate::bindings::webcrypto::types::{self, Error};
use crate::bindings::webcrypto::{
    aes_gcm as aes_gcm_iface, aes_gcm_internal_nonce as aes_gcm_in_iface, bytes as bytes_iface,
    chacha20_poly1305 as chacha_iface, digest as digest_iface, ecdsa_sign as ecdsa_sign_iface,
    ecdsa_verify as ecdsa_verify_iface, ed25519_sign as ed25519_sign_iface,
    ed25519_verify as ed25519_verify_iface, hmac_sha2 as hmac_sha2_iface,
    sha1_checked as sha1_checked_iface, sha2 as sha2_iface, signature as signature_iface,
    x25519 as x25519_iface, xchacha20_poly1305 as xchacha_iface,
    xchacha20_poly1305_internal_nonce as xchacha_in_iface,
};
use crate::limits::admit_input;
use crate::streams::{drain_stream, GuardedOutput};
use crate::{
    AeadKey, AgreementPublicKey, AgreementSecretKey, DeriveInput, Digest, Ikm, InternalNonceKey,
    MacKey, Password, SigningKey, VerifyingKey, WasiWebcrypto, WasiWebcryptoCtxView,
};

// --- bindings glue -------------------------------------------------------------

webcrypto_impl_core::impl_conversions! {
    error: Error,
    extension: types::ExtensionError,
    sha2: sha2_iface::Sha2Variant,
    aes: aes_gcm_iface::AesVariant,
    ecdsa: ecdsa_verify_iface::EcdsaVariant,
}

/// Render an entropy failure as the trap-shaped host error for key or nonce
/// generation: the host treats a failing random source as an operational
/// host fault, never a guest-visible WIT error.
fn rng_trap(what: &str) -> impl Fn(webcrypto_impl_core::RngError) -> wasmtime::Error + '_ {
    move |err| wasmtime::Error::msg(format!("{what} failed: {err}"))
}

// --- shared operation shapes ---------------------------------------------------

/// Consume a `*-key-options` resource (the mint took ownership), yielding
/// its accumulated state.
async fn take_options<T: Send, O: Send + 'static>(
    accessor: &Accessor<T, WasiWebcrypto>,
    options: Resource<O>,
) -> Result<O> {
    accessor.with(|mut access| Ok(access.get().table.delete(options)?))
}

/// Push a mint's outcome into the store's table: a successful mint becomes
/// a resource handle, a WIT error flows to the caller.
async fn mint<T: Send, R: Send + 'static>(
    accessor: &Accessor<T, WasiWebcrypto>,
    minted: std::result::Result<R, webcrypto_impl_core::Error>,
) -> Result<std::result::Result<Resource<R>, Error>> {
    match minted {
        Ok(resource) => accessor.with(|mut access| Ok(Ok(access.get().table.push(resource)?))),
        Err(err) => Ok(Err(err.into())),
    }
}

/// Run `op` on the table-held resource behind `self_`.
async fn with_resource<T: Send, R: 'static, O>(
    accessor: &Accessor<T, WasiWebcrypto>,
    self_: Resource<R>,
    op: impl FnOnce(&R) -> O,
) -> Result<O> {
    accessor.with(|mut access| Ok(op(access.get().table.get(&self_)?)))
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
        Ok(webcrypto_impl_core::constant_time_equal(&a, &b))
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

impl mac::HostMacKeyOptions for WasiWebcryptoCtxView<'_> {
    fn new(&mut self) -> Result<Resource<crate::MacKeyOptions>> {
        Ok(self.table.push(crate::MacKeyOptions::default())?)
    }

    fn can_sign(&mut self, self_: Resource<crate::MacKeyOptions>, allowed: bool) -> Result<()> {
        self.table.get_mut(&self_)?.policy.sign = allowed;
        Ok(())
    }

    fn can_verify(&mut self, self_: Resource<crate::MacKeyOptions>, allowed: bool) -> Result<()> {
        self.table.get_mut(&self_)?.policy.verify = allowed;
        Ok(())
    }

    fn extractable(&mut self, self_: Resource<crate::MacKeyOptions>, allowed: bool) -> Result<()> {
        self.table.get_mut(&self_)?.policy.extractable = allowed;
        Ok(())
    }
}

impl<T: Send> mac::HostMacKeyOptionsWithStore<T> for WasiWebcrypto {
    async fn drop(accessor: &Accessor<T, Self>, rep: Resource<crate::MacKeyOptions>) -> Result<()> {
        drop_resource(accessor, rep).await
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

impl aead::HostAeadKeyOptions for WasiWebcryptoCtxView<'_> {
    fn new(&mut self) -> Result<Resource<crate::AeadKeyOptions>> {
        Ok(self.table.push(crate::AeadKeyOptions::default())?)
    }

    fn can_seal(&mut self, self_: Resource<crate::AeadKeyOptions>, allowed: bool) -> Result<()> {
        self.table.get_mut(&self_)?.policy.seal = allowed;
        Ok(())
    }

    fn can_open(&mut self, self_: Resource<crate::AeadKeyOptions>, allowed: bool) -> Result<()> {
        self.table.get_mut(&self_)?.policy.open = allowed;
        Ok(())
    }

    fn can_wrap(&mut self, self_: Resource<crate::AeadKeyOptions>, allowed: bool) -> Result<()> {
        self.table.get_mut(&self_)?.policy.wrap = allowed;
        Ok(())
    }

    fn can_unwrap(&mut self, self_: Resource<crate::AeadKeyOptions>, allowed: bool) -> Result<()> {
        self.table.get_mut(&self_)?.policy.unwrap = allowed;
        Ok(())
    }

    fn extractable(&mut self, self_: Resource<crate::AeadKeyOptions>, allowed: bool) -> Result<()> {
        self.table.get_mut(&self_)?.policy.extractable = allowed;
        Ok(())
    }
}

impl<T: Send> aead::HostAeadKeyOptionsWithStore<T> for WasiWebcrypto {
    async fn drop(
        accessor: &Accessor<T, Self>,
        rep: Resource<crate::AeadKeyOptions>,
    ) -> Result<()> {
        drop_resource(accessor, rep).await
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

    async fn drop(accessor: &Accessor<T, Self>, rep: Resource<AeadKey>) -> Result<()> {
        drop_resource(accessor, rep).await
    }
}

// --- derivation -------------------------------------------------------------

impl derivation_iface::Host for WasiWebcryptoCtxView<'_> {}

impl HostDeriveOptions for WasiWebcryptoCtxView<'_> {
    fn new(&mut self) -> Result<Resource<crate::DeriveOptions>> {
        Ok(self.table.push(crate::DeriveOptions::default())?)
    }

    fn can_derive_bits(
        &mut self,
        self_: Resource<crate::DeriveOptions>,
        allowed: bool,
    ) -> Result<()> {
        self.table.get_mut(&self_)?.policy.derive_bits = allowed;
        Ok(())
    }

    fn can_derive_key(
        &mut self,
        self_: Resource<crate::DeriveOptions>,
        allowed: bool,
    ) -> Result<()> {
        self.table.get_mut(&self_)?.policy.derive_key = allowed;
        Ok(())
    }
}

impl<T: Send> HostDeriveOptionsWithStore<T> for WasiWebcrypto {
    async fn drop(accessor: &Accessor<T, Self>, rep: Resource<crate::DeriveOptions>) -> Result<()> {
        drop_resource(accessor, rep).await
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
        let material = webcrypto_impl_core::IkmMaterial::import(raw, policy);
        mint(accessor, material.map(|material| Ikm { material })).await
    }

    async fn prepare(
        accessor: &Accessor<T, Self>,
        variant: hkdf_iface::Sha2Variant,
        input: Resource<Ikm>,
        salt: Vec<u8>,
        info: Vec<u8>,
    ) -> Result<std::result::Result<Resource<DeriveInput>, Error>> {
        let material = with_resource(accessor, input, |ikm| {
            webcrypto_impl_core::DeriveInputMaterial::prepare(
                variant.into(),
                &ikm.material,
                &salt,
                info,
            )
        })
        .await?;
        mint(accessor, material.map(|material| DeriveInput { material })).await
    }

    async fn prepare_from(
        accessor: &Accessor<T, Self>,
        variant: hkdf_iface::Sha2Variant,
        input: Resource<DeriveInput>,
        salt: Vec<u8>,
        info: Vec<u8>,
    ) -> Result<std::result::Result<Resource<DeriveInput>, Error>> {
        let material = with_resource(accessor, input, |upstream| {
            webcrypto_impl_core::DeriveInputMaterial::prepare_from(
                variant.into(),
                &upstream.material,
                &salt,
                info,
            )
        })
        .await?;
        mint(accessor, material.map(|material| DeriveInput { material })).await
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
        let material = webcrypto_impl_core::PasswordMaterial::import(raw, policy);
        mint(accessor, material.map(|material| Password { material })).await
    }

    async fn prepare(
        accessor: &Accessor<T, Self>,
        variant: pbkdf2_iface::Sha2Variant,
        input: Resource<Password>,
        salt: Vec<u8>,
        iterations: u32,
    ) -> Result<std::result::Result<Resource<DeriveInput>, Error>> {
        let material = with_resource(accessor, input, |password| {
            webcrypto_impl_core::DeriveInputMaterial::prepare_pbkdf2(
                variant.into(),
                &password.material,
                salt,
                iterations,
            )
        })
        .await?;
        mint(accessor, material.map(|material| DeriveInput { material })).await
    }
}

// --- key-agreement -------------------------------------------------------------

impl key_agreement_iface::Host for WasiWebcryptoCtxView<'_> {}

impl HostAgreementKeyOptions for WasiWebcryptoCtxView<'_> {
    fn new(&mut self) -> Result<Resource<crate::AgreementKeyOptions>> {
        Ok(self.table.push(crate::AgreementKeyOptions::default())?)
    }

    fn can_derive_bits(
        &mut self,
        self_: Resource<crate::AgreementKeyOptions>,
        allowed: bool,
    ) -> Result<()> {
        self.table.get_mut(&self_)?.policy.derive_bits = allowed;
        Ok(())
    }

    fn can_derive_key(
        &mut self,
        self_: Resource<crate::AgreementKeyOptions>,
        allowed: bool,
    ) -> Result<()> {
        self.table.get_mut(&self_)?.policy.derive_key = allowed;
        Ok(())
    }

    fn extractable(
        &mut self,
        self_: Resource<crate::AgreementKeyOptions>,
        allowed: bool,
    ) -> Result<()> {
        self.table.get_mut(&self_)?.policy.extractable = allowed;
        Ok(())
    }
}

impl<T: Send> HostAgreementKeyOptionsWithStore<T> for WasiWebcrypto {
    async fn drop(
        accessor: &Accessor<T, Self>,
        rep: Resource<crate::AgreementKeyOptions>,
    ) -> Result<()> {
        drop_resource(accessor, rep).await
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
        mint(accessor, material.map(|material| DeriveInput { material })).await
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
        let material = webcrypto_impl_core::AgreementPublicMaterial::import(&raw);
        mint(
            accessor,
            material.map(|material| AgreementPublicKey { material }),
        )
        .await
    }

    async fn import_public_key_spki(
        accessor: &Accessor<T, Self>,
        spki: Vec<u8>,
    ) -> Result<std::result::Result<Resource<AgreementPublicKey>, Error>> {
        let material = webcrypto_impl_core::AgreementPublicMaterial::import_spki(&spki);
        mint(
            accessor,
            material.map(|material| AgreementPublicKey { material }),
        )
        .await
    }

    async fn import_public_key_jwk(
        accessor: &Accessor<T, Self>,
        jwk: String,
    ) -> Result<std::result::Result<Resource<AgreementPublicKey>, Error>> {
        let material = webcrypto_impl_core::AgreementPublicMaterial::import_jwk(&jwk);
        mint(
            accessor,
            material.map(|material| AgreementPublicKey { material }),
        )
        .await
    }

    async fn import_secret_key_pkcs8(
        accessor: &Accessor<T, Self>,
        pkcs8: Vec<u8>,
        options: Resource<crate::AgreementKeyOptions>,
    ) -> Result<std::result::Result<Resource<AgreementSecretKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = webcrypto_impl_core::AgreementSecretMaterial::import_pkcs8(&pkcs8, policy);
        mint(
            accessor,
            material.map(|material| AgreementSecretKey { material }),
        )
        .await
    }

    async fn import_secret_key_jwk(
        accessor: &Accessor<T, Self>,
        jwk: String,
        options: Resource<crate::AgreementKeyOptions>,
    ) -> Result<std::result::Result<Resource<AgreementSecretKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = webcrypto_impl_core::AgreementSecretMaterial::import_jwk(&jwk, policy);
        mint(
            accessor,
            material.map(|material| AgreementSecretKey { material }),
        )
        .await
    }

    async fn generate_key(
        accessor: &Accessor<T, Self>,
        options: Resource<crate::AgreementKeyOptions>,
    ) -> Result<
        std::result::Result<(Resource<AgreementSecretKey>, Resource<AgreementPublicKey>), Error>,
    > {
        let policy = take_options(accessor, options).await?.policy;
        let material = webcrypto_impl_core::AgreementSecretMaterial::generate(policy)
            .map_err(rng_trap("random key generation"))?;
        match material {
            Ok((secret, public)) => accessor.with(|mut access| {
                let view = access.get();
                let secret = view.table.push(AgreementSecretKey { material: secret })?;
                let public = view.table.push(AgreementPublicKey { material: public })?;
                Ok(Ok((secret, public)))
            }),
            Err(err) => Ok(Err(err.into())),
        }
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
        Ok(Ok(self.table.push(Digest {
            variant: DigestKind::Sha2(variant),
        })?))
    }
}

// --- sha1-checked (digest minting) ---------------------------------------------

impl sha1_checked_iface::Host for WasiWebcryptoCtxView<'_> {
    fn make_rejecting_digest(&mut self) -> Result<std::result::Result<Resource<Digest>, Error>> {
        Ok(Ok(self.table.push(Digest {
            variant: DigestKind::Sha1Checked(Sha1Posture::Reject),
        })?))
    }

    fn make_mitigating_digest(&mut self) -> Result<std::result::Result<Resource<Digest>, Error>> {
        Ok(Ok(self.table.push(Digest {
            variant: DigestKind::Sha1Checked(Sha1Posture::Mitigate),
        })?))
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
        mint(accessor, material.map(|material| MacKey { material })).await
    }

    async fn import_key_jwk(
        accessor: &Accessor<T, Self>,
        variant: hmac_sha2_iface::Sha2Variant,
        jwk: String,
        options: Resource<crate::MacKeyOptions>,
    ) -> Result<std::result::Result<Resource<MacKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = MacKeyMaterial::import_jwk(variant.into(), &jwk, policy);
        mint(accessor, material.map(|material| MacKey { material })).await
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
        mint(accessor, material.map(|material| MacKey { material })).await
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
            webcrypto_impl_core::derive_mac_key(&input.material, variant.into(), length, policy)
        })
        .await?;
        mint(accessor, material.map(|material| MacKey { material })).await
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
        mint(accessor, material.map(|material| AeadKey { material })).await
    }

    async fn import_key_jwk(
        accessor: &Accessor<T, Self>,
        variant: aes_gcm_iface::AesVariant,
        jwk: String,
        options: Resource<crate::AeadKeyOptions>,
    ) -> Result<std::result::Result<Resource<AeadKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = AeadKeyMaterial::import_aes_gcm_jwk(variant.into(), &jwk, policy);
        mint(accessor, material.map(|material| AeadKey { material })).await
    }

    async fn generate_key(
        accessor: &Accessor<T, Self>,
        variant: aes_gcm_iface::AesVariant,
        options: Resource<crate::AeadKeyOptions>,
    ) -> Result<std::result::Result<Resource<AeadKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = AeadKeyMaterial::generate_aes_gcm(variant.into(), policy)
            .map_err(rng_trap("random key generation"))?;
        mint(accessor, material.map(|material| AeadKey { material })).await
    }

    async fn derive_key(
        accessor: &Accessor<T, Self>,
        variant: aes_gcm_iface::AesVariant,
        input: Resource<DeriveInput>,
        options: Resource<crate::AeadKeyOptions>,
    ) -> Result<std::result::Result<Resource<AeadKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = with_resource(accessor, input, |input| {
            webcrypto_impl_core::derive_aes_gcm_key(&input.material, variant.into(), policy)
        })
        .await?;
        mint(accessor, material.map(|material| AeadKey { material })).await
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
        mint(accessor, material.map(|material| AeadKey { material })).await
    }

    async fn generate_key(
        accessor: &Accessor<T, Self>,
        options: Resource<crate::AeadKeyOptions>,
    ) -> Result<std::result::Result<Resource<AeadKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = AeadKeyMaterial::generate_chacha20_poly1305(policy)
            .map_err(rng_trap("random key generation"))?;
        mint(accessor, material.map(|material| AeadKey { material })).await
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
        mint(accessor, material.map(|material| AeadKey { material })).await
    }

    async fn generate_key(
        accessor: &Accessor<T, Self>,
        options: Resource<crate::AeadKeyOptions>,
    ) -> Result<std::result::Result<Resource<AeadKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = AeadKeyMaterial::generate_xchacha20_poly1305(policy)
            .map_err(rng_trap("random key generation"))?;
        mint(accessor, material.map(|material| AeadKey { material })).await
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

impl aead_internal_nonce::HostInternalNonceKeyOptions for WasiWebcryptoCtxView<'_> {
    fn new(&mut self) -> Result<Resource<crate::InternalNonceKeyOptions>> {
        Ok(self.table.push(crate::InternalNonceKeyOptions::default())?)
    }

    fn can_seal(
        &mut self,
        self_: Resource<crate::InternalNonceKeyOptions>,
        allowed: bool,
    ) -> Result<()> {
        self.table.get_mut(&self_)?.policy.seal = allowed;
        Ok(())
    }

    fn can_open(
        &mut self,
        self_: Resource<crate::InternalNonceKeyOptions>,
        allowed: bool,
    ) -> Result<()> {
        self.table.get_mut(&self_)?.policy.open = allowed;
        Ok(())
    }

    fn extractable(
        &mut self,
        self_: Resource<crate::InternalNonceKeyOptions>,
        allowed: bool,
    ) -> Result<()> {
        self.table.get_mut(&self_)?.policy.extractable = allowed;
        Ok(())
    }
}

impl<T: Send> aead_internal_nonce::HostInternalNonceKeyOptionsWithStore<T> for WasiWebcrypto {
    async fn drop(
        accessor: &Accessor<T, Self>,
        rep: Resource<crate::InternalNonceKeyOptions>,
    ) -> Result<()> {
        drop_resource(accessor, rep).await
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
        mint(
            accessor,
            material.map(|material| InternalNonceKey {
                material,
                sealed: 0,
            }),
        )
        .await
    }

    async fn import_key_jwk(
        accessor: &Accessor<T, Self>,
        variant: aes_gcm_iface::AesVariant,
        jwk: String,
        options: Resource<crate::InternalNonceKeyOptions>,
    ) -> Result<std::result::Result<Resource<InternalNonceKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = AeadKeyMaterial::import_aes_gcm_jwk(variant.into(), &jwk, policy.into());
        mint(
            accessor,
            material.map(|material| InternalNonceKey {
                material,
                sealed: 0,
            }),
        )
        .await
    }

    async fn generate_key(
        accessor: &Accessor<T, Self>,
        variant: aes_gcm_iface::AesVariant,
        options: Resource<crate::InternalNonceKeyOptions>,
    ) -> Result<std::result::Result<Resource<InternalNonceKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = AeadKeyMaterial::generate_aes_gcm(variant.into(), policy.into())
            .map_err(rng_trap("random key generation"))?;
        mint(
            accessor,
            material.map(|material| InternalNonceKey {
                material,
                sealed: 0,
            }),
        )
        .await
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
        mint(
            accessor,
            material.map(|material| InternalNonceKey {
                material,
                sealed: 0,
            }),
        )
        .await
    }

    async fn generate_key(
        accessor: &Accessor<T, Self>,
        options: Resource<crate::InternalNonceKeyOptions>,
    ) -> Result<std::result::Result<Resource<InternalNonceKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = AeadKeyMaterial::generate_xchacha20_poly1305(policy.into())
            .map_err(rng_trap("random key generation"))?;
        mint(
            accessor,
            material.map(|material| InternalNonceKey {
                material,
                sealed: 0,
            }),
        )
        .await
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
        // The WIT `err` case exists for providers holding the key as an
        // unreadable handle; this implementation holds the encoding
        // in-process, so it never errs.
        with_resource(accessor, self_, |key| Ok(key.public.export())).await
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

    fn extractable(&mut self, self_: Resource<SigningKey>) -> Result<bool> {
        Ok(self.table.get(&self_)?.material.extractable())
    }

    fn can_sign(&mut self, self_: Resource<SigningKey>) -> Result<bool> {
        Ok(self.table.get(&self_)?.material.can_sign())
    }
}

impl signature_iface::HostSigningKeyOptions for WasiWebcryptoCtxView<'_> {
    fn new(&mut self) -> Result<Resource<crate::SigningKeyOptions>> {
        Ok(self.table.push(crate::SigningKeyOptions::default())?)
    }

    fn can_sign(&mut self, self_: Resource<crate::SigningKeyOptions>, allowed: bool) -> Result<()> {
        self.table.get_mut(&self_)?.policy.sign = allowed;
        Ok(())
    }

    fn extractable(
        &mut self,
        self_: Resource<crate::SigningKeyOptions>,
        allowed: bool,
    ) -> Result<()> {
        self.table.get_mut(&self_)?.policy.extractable = allowed;
        Ok(())
    }
}

impl<T: Send> signature_iface::HostSigningKeyOptionsWithStore<T> for WasiWebcrypto {
    async fn drop(
        accessor: &Accessor<T, Self>,
        rep: Resource<crate::SigningKeyOptions>,
    ) -> Result<()> {
        drop_resource(accessor, rep).await
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
        mint(accessor, public.map(|public| VerifyingKey { public })).await
    }

    async fn import_verifying_key_spki(
        accessor: &Accessor<T, Self>,
        spki: Vec<u8>,
    ) -> Result<std::result::Result<Resource<VerifyingKey>, Error>> {
        let public = SigPublic::import_ed25519_spki(&spki);
        mint(accessor, public.map(|public| VerifyingKey { public })).await
    }

    async fn import_verifying_key_jwk(
        accessor: &Accessor<T, Self>,
        jwk: String,
    ) -> Result<std::result::Result<Resource<VerifyingKey>, Error>> {
        let public = SigPublic::import_ed25519_jwk(&jwk);
        mint(accessor, public.map(|public| VerifyingKey { public })).await
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
        mint_key_pair(accessor, material).await
    }

    async fn import_signing_key_pkcs8(
        accessor: &Accessor<T, Self>,
        pkcs8: Vec<u8>,
        options: Resource<crate::SigningKeyOptions>,
    ) -> Result<std::result::Result<Resource<SigningKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = SigningKeyMaterial::import_ed25519_pkcs8(&pkcs8, policy);
        mint(accessor, material.map(|material| SigningKey { material })).await
    }

    async fn import_signing_key_jwk(
        accessor: &Accessor<T, Self>,
        jwk: String,
        options: Resource<crate::SigningKeyOptions>,
    ) -> Result<std::result::Result<Resource<SigningKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = SigningKeyMaterial::import_ed25519_jwk(&jwk, policy);
        mint(accessor, material.map(|material| SigningKey { material })).await
    }
}

/// Push a generated signing key and the public half returned with it.
async fn mint_key_pair<T: Send>(
    accessor: &Accessor<T, WasiWebcrypto>,
    material: SigningKeyMaterial,
) -> Result<std::result::Result<(Resource<SigningKey>, Resource<VerifyingKey>), Error>> {
    let public = material.public();
    accessor.with(|mut access| {
        let table = access.get().table;
        let signing = table.push(SigningKey { material })?;
        let verifying = table.push(VerifyingKey { public })?;
        Ok(Ok((signing, verifying)))
    })
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
        mint(accessor, public.map(|public| VerifyingKey { public })).await
    }

    async fn import_verifying_key_spki(
        accessor: &Accessor<T, Self>,
        variant: ecdsa_verify_iface::EcdsaVariant,
        spki: Vec<u8>,
    ) -> Result<std::result::Result<Resource<VerifyingKey>, Error>> {
        let public = SigPublic::import_ecdsa_spki(variant.into(), &spki);
        mint(accessor, public.map(|public| VerifyingKey { public })).await
    }

    async fn import_verifying_key_jwk(
        accessor: &Accessor<T, Self>,
        variant: ecdsa_verify_iface::EcdsaVariant,
        jwk: String,
    ) -> Result<std::result::Result<Resource<VerifyingKey>, Error>> {
        let public = SigPublic::import_ecdsa_jwk(variant.into(), &jwk);
        mint(accessor, public.map(|public| VerifyingKey { public })).await
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
        mint_key_pair(accessor, material).await
    }

    async fn import_signing_key_pkcs8(
        accessor: &Accessor<T, Self>,
        variant: ecdsa_verify_iface::EcdsaVariant,
        pkcs8: Vec<u8>,
        options: Resource<crate::SigningKeyOptions>,
    ) -> Result<std::result::Result<Resource<SigningKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = SigningKeyMaterial::import_ecdsa_pkcs8(variant.into(), &pkcs8, policy);
        mint(accessor, material.map(|material| SigningKey { material })).await
    }

    async fn import_signing_key_jwk(
        accessor: &Accessor<T, Self>,
        variant: ecdsa_verify_iface::EcdsaVariant,
        jwk: String,
        options: Resource<crate::SigningKeyOptions>,
    ) -> Result<std::result::Result<Resource<SigningKey>, Error>> {
        let policy = take_options(accessor, options).await?.policy;
        let material = SigningKeyMaterial::import_ecdsa_jwk(variant.into(), &jwk, policy);
        mint(accessor, material.map(|material| SigningKey { material })).await
    }
}

#[cfg(test)]
mod tests {
    use crate::MacKey;
    use webcrypto_impl_core::{MacKeyMaterial, MacPolicy, Sha2Variant};

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
        let key = MacKey {
            material: MacKeyMaterial::import(Sha2Variant::Sha256, vec![0xAB; 32], policy).unwrap(),
        };
        let rendered = format!("{key:?}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(!rendered.contains("171"), "{rendered}"); // 0xAB
        assert!(!rendered.to_lowercase().contains("ab, ab"), "{rendered}");
    }
}
