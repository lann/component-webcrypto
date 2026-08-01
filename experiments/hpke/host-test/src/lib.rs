//! Wasmtime host harness for the experimental HPKE component, backed by
//! [`lann_webcrypto_wasmtime`]'s RustCrypto implementation of `lann:webcrypto`.
//!
//! The component's exports are async-lifted WIT functions and all of its
//! state travels as bytes, so each helper instantiates fresh and makes one
//! call under the store's concurrent scope — ample for smoke tests.

use std::path::Path;

use lann_webcrypto_wasmtime::standalone::{self, Ctx};
use lann_webcrypto_wasmtime::WasiWebcryptoCtx;
use wasmtime::component::Accessor;

mod bindings {
    wasmtime::component::bindgen!({
        path: "../guest/wit",
        world: "hpke-guest",
        imports: {
            default: async | store | trappable,
        },
        exports: {
            default: async,
        },
    });
}

pub use bindings::exports::experiments::hpke::hpke::{AeadId, KeyPair, Sealed};

async fn instantiate(
    component_path: &Path,
) -> anyhow::Result<(wasmtime::Store<Ctx>, bindings::HpkeGuest)> {
    let (component, linker, mut store) = standalone::load(component_path, WasiWebcryptoCtx::new())?;
    let guest = bindings::HpkeGuest::instantiate_async(&mut store, &component, &linker).await?;
    Ok((store, guest))
}

pub async fn generate_key_pair(component: &Path) -> anyhow::Result<Result<KeyPair, String>> {
    let (mut store, guest) = instantiate(component).await?;
    let result = store
        .run_concurrent(async move |accessor: &Accessor<Ctx>| {
            guest
                .experiments_hpke_hpke()
                .call_generate_key_pair(accessor)
                .await
        })
        .await??;
    Ok(result)
}

pub async fn derive_key_pair(
    component: &Path,
    ikm: &[u8],
) -> anyhow::Result<Result<KeyPair, String>> {
    let (mut store, guest) = instantiate(component).await?;
    let ikm = ikm.to_vec();
    let result = store
        .run_concurrent(async move |accessor: &Accessor<Ctx>| {
            guest
                .experiments_hpke_hpke()
                .call_derive_key_pair(accessor, ikm)
                .await
        })
        .await??;
    Ok(result)
}

pub async fn seal(
    component: &Path,
    aead: AeadId,
    recipient_public_key: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> anyhow::Result<Result<Sealed, String>> {
    let (mut store, guest) = instantiate(component).await?;
    let (pk, info, aad, pt) = (
        recipient_public_key.to_vec(),
        info.to_vec(),
        aad.to_vec(),
        plaintext.to_vec(),
    );
    let result = store
        .run_concurrent(async move |accessor: &Accessor<Ctx>| {
            guest
                .experiments_hpke_hpke()
                .call_seal(accessor, aead, pk, info, aad, pt)
                .await
        })
        .await??;
    Ok(result)
}

pub async fn seal_deterministic(
    component: &Path,
    aead: AeadId,
    recipient_public_key: &[u8],
    ikm_e: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> anyhow::Result<Result<Sealed, String>> {
    let (mut store, guest) = instantiate(component).await?;
    let (pk, ikm_e, info, aad, pt) = (
        recipient_public_key.to_vec(),
        ikm_e.to_vec(),
        info.to_vec(),
        aad.to_vec(),
        plaintext.to_vec(),
    );
    let result = store
        .run_concurrent(async move |accessor: &Accessor<Ctx>| {
            guest
                .experiments_hpke_hpke()
                .call_seal_deterministic(accessor, aead, pk, ikm_e, info, aad, pt)
                .await
        })
        .await??;
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
pub async fn open(
    component: &Path,
    aead: AeadId,
    recipient_secret_key: &[u8],
    enc: &[u8],
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> anyhow::Result<Result<Vec<u8>, String>> {
    let (mut store, guest) = instantiate(component).await?;
    let (sk, enc, info, aad, ct) = (
        recipient_secret_key.to_vec(),
        enc.to_vec(),
        info.to_vec(),
        aad.to_vec(),
        ciphertext.to_vec(),
    );
    let result = store
        .run_concurrent(async move |accessor: &Accessor<Ctx>| {
            guest
                .experiments_hpke_hpke()
                .call_open(accessor, aead, sk, enc, info, aad, ct)
                .await
        })
        .await??;
    Ok(result)
}
