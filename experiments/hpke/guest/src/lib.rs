//! `hpke-guest`: an experimental WebAssembly component exporting RFC 9180
//! HPKE (base mode, DHKEM(X25519, HKDF-SHA-256), HKDF-SHA-256) whose
//! cryptography is entirely `polymorph:webcrypto` imports.
//!
//! The HPKE state machine is [`hpke_rs`], driven through its pluggable
//! [`hpke_rs_crypto::HpkeCrypto`] provider trait; [`provider`] implements
//! that trait over the imports, bridging the synchronous trait onto the
//! async imports with `wit_bindgen::block_on`. The exports are `async
//! func`s even though they compute synchronously: the component model
//! permits a task to block on waitables only when its export was lifted
//! `async` (a sync-lifted task traps with "cannot block a synchronous
//! task"), so the async lifting is what makes the blocking bridge legal.

mod provider;

wit_bindgen::generate!({
    path: "wit",
    world: "hpke-guest",
});

use exports::experiments::hpke::hpke::{AeadId, Guest, KeyPair, Sealed};
use hpke_rs::{Hpke, HpkeError, HpkeKeyPair, HpkePrivateKey, HpkePublicKey, Mode};
use hpke_rs_crypto::types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use provider::WebcryptoProvider;

fn aead_algorithm(aead: AeadId) -> AeadAlgorithm {
    match aead {
        AeadId::Aes128Gcm => AeadAlgorithm::Aes128Gcm,
        AeadId::Aes256Gcm => AeadAlgorithm::Aes256Gcm,
    }
}

fn new_hpke(aead: AeadId) -> Hpke<WebcryptoProvider> {
    Hpke::new(
        Mode::Base,
        KemAlgorithm::DhKem25519,
        KdfAlgorithm::HkdfSha256,
        aead_algorithm(aead),
    )
}

fn err_string(err: HpkeError) -> String {
    format!("{err}")
}

fn key_pair(pair: HpkeKeyPair) -> KeyPair {
    KeyPair {
        // `as_slice` on the private key is behind hpke-rs's `hazmat`
        // feature: this export interface traffics in raw key bytes.
        secret_key: pair.private_key().as_slice().to_vec(),
        public_key: pair.public_key().as_slice().to_vec(),
    }
}

struct Component;

impl Guest for Component {
    async fn generate_key_pair() -> Result<KeyPair, String> {
        // The AEAD parameter is irrelevant to key generation; any suite
        // member selects the same X25519 KEM.
        let mut hpke = new_hpke(AeadId::Aes128Gcm);
        hpke.generate_key_pair().map(key_pair).map_err(err_string)
    }

    async fn derive_key_pair(ikm: Vec<u8>) -> Result<KeyPair, String> {
        let hpke = new_hpke(AeadId::Aes128Gcm);
        hpke.derive_key_pair(&ikm).map(key_pair).map_err(err_string)
    }

    async fn seal(
        aead: AeadId,
        recipient_public_key: Vec<u8>,
        info: Vec<u8>,
        aad: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> Result<Sealed, String> {
        let mut hpke = new_hpke(aead);
        let (enc, ciphertext) = hpke
            .seal(
                &HpkePublicKey::new(recipient_public_key),
                &info,
                &aad,
                &plaintext,
                None,
                None,
                None,
            )
            .map_err(err_string)?;
        Ok(Sealed { enc, ciphertext })
    }

    async fn seal_deterministic(
        aead: AeadId,
        recipient_public_key: Vec<u8>,
        ikm_e: Vec<u8>,
        info: Vec<u8>,
        aad: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> Result<Sealed, String> {
        let mut hpke = new_hpke(aead);
        // Seed the test PRNG: encapsulation's randomness becomes `ikm-e`,
        // so the ephemeral pair is DeriveKeyPair(ikm-e) per RFC 9180.
        hpke.seed(&ikm_e).map_err(err_string)?;
        let (enc, ciphertext) = hpke
            .seal(
                &HpkePublicKey::new(recipient_public_key),
                &info,
                &aad,
                &plaintext,
                None,
                None,
                None,
            )
            .map_err(err_string)?;
        Ok(Sealed { enc, ciphertext })
    }

    async fn open(
        aead: AeadId,
        recipient_secret_key: Vec<u8>,
        enc: Vec<u8>,
        info: Vec<u8>,
        aad: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        let hpke = new_hpke(aead);
        hpke.open(
            &enc,
            &HpkePrivateKey::new(recipient_secret_key),
            &info,
            &aad,
            &ciphertext,
            None,
            None,
            None,
        )
        .map_err(err_string)
    }
}

export!(Component);
