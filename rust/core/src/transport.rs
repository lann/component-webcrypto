//! The `public-encryption` key material: RSA-OAEP (RFC 8017 §7.1)
//! encryption and decryption keys over the aws-lc-rs backend, native
//! targets only — like RSA signing, RSA private-key operations are class
//! D (the timing-attack lineage `wit/rsa.wit` records), and *encryption*
//! processes the secret plaintext through the same big-integer arithmetic,
//! so neither half of this module is compiled for wasm (see the crate
//! doc). The in-guest provider's world never exports these interfaces;
//! this module's absence from wasm builds is the defence in depth.
//!
//! The load-bearing rules here:
//!
//! - Every decryption failure — wrong-length ciphertext, damaged padding,
//!   a mismatched label — collapses to the one detail-free
//!   [`Error::AuthenticationFailed`], as RFC 8017 §7.1.2 requires: a
//!   distinguishable verdict is a padding-oracle amplifier (Manger's
//!   attack recovers plaintext from exactly such a distinction).
//! - A plaintext above the key's bound (modulus bytes − 2·digest length
//!   − 2) fails `encrypt`/`wrap` with the named extension condition
//!   `("lann:webcrypto", "message-too-long")`.
//! - Admission tightens the RSA family window on both ends: 2048–8192
//!   bits (the WIT `rsa-oaep-encrypt` contract — encryption creates
//!   future artifacts, so there is no legacy tier below 2048).

use zeroize::Zeroizing;

use aws_lc_rs::rsa::{
    OaepAlgorithm, OaepPrivateDecryptingKey, OaepPublicEncryptingKey, PrivateDecryptingKey,
    PublicEncryptingKey, OAEP_SHA256_MGF1SHA256, OAEP_SHA384_MGF1SHA384, OAEP_SHA512_MGF1SHA512,
};

use crate::sig::{
    admit_rsa_2048_8192, decode_rsa_pkcs8, decode_rsa_spki, rsa_hash_name,
    rsa_pkcs8_to_private_jwk, rsa_private_jwk_to_pkcs8,
};
use crate::{
    not_permitted, Error, RngError, RsaModulus, RsaVariant, TransportPolicy, RSA_OAEP_NAME,
};

/// The window's owner in the admission diagnostic.
const OAEP_WINDOW_WHAT: &str = "RSA-OAEP keys";

/// The aws-lc-rs OAEP parameterization of a variant: the variant's digest
/// as both the OAEP hash and the MGF1 hash, as WebCrypto fixes it.
fn oaep_algorithm(variant: RsaVariant) -> &'static OaepAlgorithm {
    match variant {
        RsaVariant::Sha256 => &OAEP_SHA256_MGF1SHA256,
        RsaVariant::Sha384 => &OAEP_SHA384_MGF1SHA384,
        RsaVariant::Sha512 => &OAEP_SHA512_MGF1SHA512,
    }
}

/// The JWK `alg` value an RSA-OAEP import accepts: the variant's JOSE alg
/// (the WIT import rule). JOSE's suffix-less `"RSA-OAEP"` is OAEP under
/// SHA-1, which no variant serves, so it appears in no allowlist.
fn oaep_jwk_algs(variant: RsaVariant) -> &'static [&'static str] {
    match variant {
        RsaVariant::Sha256 => &["RSA-OAEP-256"],
        RsaVariant::Sha384 => &["RSA-OAEP-384"],
        RsaVariant::Sha512 => &["RSA-OAEP-512"],
    }
}

/// The material behind a `public-encryption.encryption-key` resource: the
/// RSA-OAEP public key bound to its digest at minting, alongside its OAEP
/// view (the backend types are disjoint, and the view exposes no way
/// back). Secret-free to hold, and grant-free (the WIT resource carries
/// no usage policy — public keys are unconditionally usable), but the
/// *plaintexts* it processes are secret, which is what keeps it off wasm
/// targets.
pub struct EncryptionKeyMaterial {
    public: PublicEncryptingKey,
    oaep: OaepPublicEncryptingKey,
    variant: RsaVariant,
}

impl EncryptionKeyMaterial {
    /// Import a public key as an `rsaEncryption` SubjectPublicKeyInfo
    /// (the `rsa-oaep-encrypt.import-encryption-key-spki` contract):
    /// admission follows the WIT `rsa` family contract plus the
    /// 2048–8192-bit OAEP window.
    pub fn import_oaep_spki(variant: RsaVariant, spki: &[u8]) -> Result<Self, Error> {
        let (n, e) = decode_rsa_spki(spki)?;
        admit_rsa_2048_8192(&n, &e, OAEP_WINDOW_WHAT)?;
        let key = PublicEncryptingKey::from_der(spki)
            .map_err(|err| Error::InvalidKey(format!("invalid RSA spki: {err}")))?;
        Ok(Self::from_public(key, variant))
    }

    /// Import a public key as an RSA public JWK (the
    /// `rsa-oaep-encrypt.import-encryption-key-jwk` contract): a present
    /// `alg` must be the variant's JOSE alg, and admission then follows
    /// the SPKI import's contract.
    pub fn import_oaep_jwk(variant: RsaVariant, jwk: &str) -> Result<Self, Error> {
        let parsed = crate::jwk::parse_rsa_public(jwk, Some(oaep_jwk_algs(variant)))?;
        let n = rsa::BigUint::from_bytes_be(&parsed.n);
        let e = rsa::BigUint::from_bytes_be(&parsed.e);
        admit_rsa_2048_8192(&n, &e, OAEP_WINDOW_WHAT)?;
        // Assemble the members into an SPKI for the backend, with the
        // window as the explicit ceiling (the `rsa` crate's default
        // construction paths enforce a 4096-bit maximum). Bounds the
        // crate still enforces — an exponent above its 2^33−1 ceiling —
        // also render `invalid-key`, the WIT's implementation-defined
        // latitude for large exponents.
        use spki::EncodePublicKey as _;
        let assembled = rsa::RsaPublicKey::new_with_max_size(n, e, 8192)
            .map_err(|err| Error::InvalidKey(format!("invalid RSA public key: {err}")))?;
        let spki = assembled
            .to_public_key_der()
            .expect("valid key encodes")
            .into_vec();
        let key = PublicEncryptingKey::from_der(&spki)
            .map_err(|err| Error::InvalidKey(format!("invalid RSA public key: {err}")))?;
        Ok(Self::from_public(key, variant))
    }

    /// Wrap an admitted public key with its OAEP view. The backend
    /// constructor's `Result` carries no failing path for a key its own
    /// validation admitted.
    fn from_public(public: PublicEncryptingKey, variant: RsaVariant) -> Self {
        let oaep = OaepPublicEncryptingKey::new(public.clone())
            .expect("a validated public key parameterizes OAEP");
        Self {
            public,
            oaep,
            variant,
        }
    }

    /// Encrypt a plaintext bounded by the key (the `encryption-key.encrypt`
    /// contract): OAEP under the mint-bound digest (which is also the
    /// MGF1 digest), with `label` bound into the padding — decryption
    /// succeeds only under the same label; `None` and an empty label are
    /// the same parameterization (RFC 8017's default label is the empty
    /// string). Encryption is randomized. A plaintext above the key's
    /// bound — modulus bytes − 2·digest length − 2 — fails with the
    /// extension condition `("lann:webcrypto", "message-too-long")`.
    pub fn encrypt(&self, label: Option<&[u8]>, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let bound = self.oaep.max_plaintext_size(oaep_algorithm(self.variant));
        if plaintext.len() > bound {
            return Err(Error::message_too_long(bound, plaintext.len()));
        }
        let mut ciphertext = vec![0u8; self.oaep.ciphertext_size()];
        let written = self
            .oaep
            .encrypt(
                oaep_algorithm(self.variant),
                plaintext,
                &mut ciphertext,
                label,
            )
            .map_err(|_| Error::Other("RSA-OAEP encryption failed".into()))?
            .len();
        ciphertext.truncate(written);
        Ok(ciphertext)
    }

    /// Encrypt serialized key material (the `encryption-key.wrap`
    /// contract): [`encrypt`](Self::encrypt) over the intermediate's
    /// bytes, consumed on failure as on success. No format-specific rule
    /// applies (unlike AES-KW's JWK padding), so the serialized form must
    /// fit the key's bound as any plaintext must.
    pub fn wrap(
        &self,
        label: Option<&[u8]>,
        input: crate::WrapInputMaterial,
    ) -> Result<Vec<u8>, Error> {
        self.encrypt(label, &input.into_bytes())
    }

    /// The registry `algorithm-name`, `"RSA-OAEP"`.
    pub fn name(&self) -> &'static str {
        RSA_OAEP_NAME
    }

    /// The mint-bound digest name (`encryption-key.algorithm-hash`).
    pub fn hash(&self) -> Option<&'static str> {
        Some(rsa_hash_name(self.variant))
    }

    /// The modulus length in bits (`encryption-key.algorithm-length`).
    pub fn length(&self) -> Option<u32> {
        Some(self.public.key_size_bits() as u32)
    }

    /// The public exponent's big-endian bytes
    /// (`encryption-key.algorithm-public-exponent`).
    pub fn public_exponent(&self) -> Option<Vec<u8>> {
        let (_, e) = decode_rsa_spki(&self.spki_der())
            .expect("the backend serializes a valid rsaEncryption SPKI");
        Some(e.to_bytes_be())
    }

    /// RSA public keys have no raw form (the platform serves `spki` and
    /// `jwk` only), so the `encryption-key.export-key-raw` contract
    /// renders `unsupported`.
    pub fn export(&self) -> Result<Vec<u8>, Error> {
        Err(Error::Unsupported(
            "RSA public keys have no raw form".into(),
        ))
    }

    /// The public key as a SubjectPublicKeyInfo
    /// (`encryption-key.export-key-spki`).
    pub fn export_spki(&self) -> Vec<u8> {
        self.spki_der()
    }

    /// The public key as an RSA public JWK
    /// (`encryption-key.export-key-jwk`).
    pub fn export_jwk(&self) -> String {
        let (n, e) = decode_rsa_spki(&self.spki_der())
            .expect("the backend serializes a valid rsaEncryption SPKI");
        crate::jwk::build_rsa_public(&n.to_bytes_be(), &e.to_bytes_be())
    }

    /// The backend's SPKI marshal (the export paths' component source:
    /// the key type exposes no component getters).
    fn spki_der(&self) -> Vec<u8> {
        use aws_lc_rs::encoding::AsDer as _;
        let der: aws_lc_rs::encoding::PublicKeyX509Der =
            self.public.as_der().expect("valid key encodes");
        der.as_ref().to_vec()
    }
}

// Public material is not secret, but printing it wholesale is rarely
// useful; identify the key by algorithm only.
impl std::fmt::Debug for EncryptionKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptionKeyMaterial")
            .field("algorithm", &self.name())
            .field("hash", &self.hash())
            .finish()
    }
}

/// The material behind a `public-encryption.decryption-key` resource: the
/// RSA-OAEP private key bound to its digest at minting, its OAEP view
/// (the backend types are disjoint), and the mint-time policy.
pub struct DecryptionKeyMaterial {
    private: PrivateDecryptingKey,
    oaep: OaepPrivateDecryptingKey,
    variant: RsaVariant,
    policy: TransportPolicy,
}

impl DecryptionKeyMaterial {
    /// Import a decryption key as an `rsaEncryption` PKCS#8
    /// PrivateKeyInfo with CRT parameters (the
    /// `rsa-oaep-decrypt.import-decryption-key-pkcs8` contract): explicit
    /// admission (the OAEP window and the family exponent floor) ahead of
    /// the backend, whose own parse then validates the key in full — DER
    /// form, n = p·q, and CRT coherence.
    pub fn import_oaep_pkcs8(
        variant: RsaVariant,
        pkcs8_der: &[u8],
        policy: TransportPolicy,
    ) -> Result<Self, Error> {
        policy.check_useful()?;
        let (n, e) = decode_rsa_pkcs8(pkcs8_der)?;
        admit_rsa_2048_8192(&n, &e, OAEP_WINDOW_WHAT)?;
        let private = PrivateDecryptingKey::from_pkcs8(pkcs8_der)
            .map_err(|err| Error::InvalidKey(format!("invalid RSA pkcs8: {err}")))?;
        Ok(Self::from_private(private, variant, policy))
    }

    /// Import a decryption key as a full-CRT RSA private JWK (the
    /// `rsa-oaep-decrypt.import-decryption-key-jwk` contract): a present
    /// `alg` must be the variant's JOSE alg, the RFC 8017 body is
    /// assembled into a PKCS#8 PrivateKeyInfo (zeroized on drop), and the
    /// PKCS#8 import path runs from there.
    pub fn import_oaep_jwk(
        variant: RsaVariant,
        jwk: &str,
        policy: TransportPolicy,
    ) -> Result<Self, Error> {
        policy.check_useful()?;
        let parsed =
            crate::jwk::parse_rsa_private(jwk, policy.extractable, Some(oaep_jwk_algs(variant)))?;
        let pkcs8_der = rsa_private_jwk_to_pkcs8(&parsed)?;
        Self::import_oaep_pkcs8(variant, &pkcs8_der, policy)
    }

    /// Generate a fresh random RSA-OAEP key pair of a standard modulus
    /// size (the `rsa-oaep-decrypt.generate-key` contract); the public
    /// exponent is 65537. Callers mint the public half with
    /// [`public`](Self::public).
    ///
    /// The outer channel is never `Err` here: aws-lc-rs generates from its
    /// own internal DRBG, so an entropy failure is indistinguishable from
    /// any other generation failure and surfaces as the inner `other`.
    pub fn generate_oaep(
        variant: RsaVariant,
        modulus: RsaModulus,
        policy: TransportPolicy,
    ) -> Result<Result<Self, Error>, RngError> {
        if let Err(err) = policy.check_useful() {
            return Ok(Err(err));
        }
        let size = match modulus {
            RsaModulus::M2048 => aws_lc_rs::rsa::KeySize::Rsa2048,
            RsaModulus::M3072 => aws_lc_rs::rsa::KeySize::Rsa3072,
            RsaModulus::M4096 => aws_lc_rs::rsa::KeySize::Rsa4096,
            RsaModulus::M8192 => aws_lc_rs::rsa::KeySize::Rsa8192,
        };
        Ok(match PrivateDecryptingKey::generate(size) {
            Ok(private) => Ok(Self::from_private(private, variant, policy)),
            Err(_) => Err(Error::Other("RSA key generation failed".into())),
        })
    }

    /// Wrap an admitted private key with its OAEP view.
    fn from_private(
        private: PrivateDecryptingKey,
        variant: RsaVariant,
        policy: TransportPolicy,
    ) -> Self {
        let oaep = OaepPrivateDecryptingKey::new(private.clone())
            .expect("a validated private key parameterizes OAEP");
        Self {
            private,
            oaep,
            variant,
            policy,
        }
    }

    /// Decrypt a ciphertext produced by the matching public key under the
    /// same label (the `decryption-key.decrypt` contract). Fails
    /// `not-permitted` without the `decrypt` grant.
    ///
    /// Every decryption failure is the one detail-free
    /// `authentication-failed`: a wrong-length ciphertext, damaged
    /// padding, a mismatched label, and every other backend verdict
    /// collapse into a single unit case, because any caller-visible
    /// distinction between "malformed ciphertext" and "padding did not
    /// verify" is the oracle RFC 8017 §7.1.2 instructs implementations
    /// not to expose (Manger's attack turns it into plaintext recovery).
    ///
    /// The copy returned is *not* protected: see the note on
    /// [`crate`](crate#exported-material) — the plaintext is bound for the
    /// caller either way.
    pub fn decrypt(&self, label: Option<&[u8]>, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        if !self.policy.decrypt {
            return Err(not_permitted("decrypt"));
        }
        Ok(self.decrypt_inner(label, ciphertext)?.to_vec())
    }

    /// Decrypt a wrapped key into an intermediate for a typed unwrap mint
    /// (the `decryption-key.unwrap` contract): the material never reaches
    /// the caller. Fails `not-permitted` without the `unwrap` grant;
    /// failures are otherwise as [`decrypt`](Self::decrypt), including the
    /// detail-free collapse.
    pub fn unwrap(
        &self,
        label: Option<&[u8]>,
        ciphertext: &[u8],
    ) -> Result<crate::UnwrapInputMaterial, Error> {
        if !self.policy.unwrap {
            return Err(not_permitted("unwrap"));
        }
        Ok(crate::UnwrapInputMaterial::from_zeroizing(
            self.decrypt_inner(label, ciphertext)?,
        ))
    }

    /// The shared OAEP decryption: one buffer, one collapsed verdict.
    fn decrypt_inner(
        &self,
        label: Option<&[u8]>,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let mut out = Zeroizing::new(vec![0u8; self.oaep.min_output_size()]);
        let written = self
            .oaep
            .decrypt(oaep_algorithm(self.variant), ciphertext, &mut out, label)
            .map_err(|_| Error::AuthenticationFailed)?
            .len();
        out.truncate(written);
        Ok(out)
    }

    /// The corresponding [`EncryptionKeyMaterial`]. There is no WIT derive
    /// contract — `generate-key` returns the pair instead — but this core
    /// holds the private material, so hosts use this to mint the public
    /// half at generation.
    pub fn public(&self) -> EncryptionKeyMaterial {
        EncryptionKeyMaterial::from_public(self.private.public_key(), self.variant)
    }

    /// The registry `algorithm-name`, `"RSA-OAEP"`.
    pub fn name(&self) -> &'static str {
        RSA_OAEP_NAME
    }

    /// The mint-bound digest name (`decryption-key.algorithm-hash`).
    pub fn hash(&self) -> Option<&'static str> {
        Some(rsa_hash_name(self.variant))
    }

    /// The modulus length in bits (`decryption-key.algorithm-length`).
    pub fn length(&self) -> Option<u32> {
        Some(self.private.key_size_bits() as u32)
    }

    /// The public exponent's big-endian bytes
    /// (`decryption-key.algorithm-public-exponent`), from the private
    /// key's public half — public data, so no extractability gate.
    pub fn public_exponent(&self) -> Option<Vec<u8>> {
        use aws_lc_rs::encoding::AsDer as _;
        let der: aws_lc_rs::encoding::PublicKeyX509Der = self
            .private
            .public_key()
            .as_der()
            .expect("valid key encodes");
        let (_, e) = decode_rsa_spki(der.as_ref())
            .expect("the backend serializes a valid rsaEncryption SPKI");
        Some(e.to_bytes_be())
    }

    /// Whether the key permits `decrypt` (`can-decrypt`).
    pub fn can_decrypt(&self) -> bool {
        self.policy.decrypt
    }

    /// Whether the key permits `unwrap` (`can-unwrap`).
    pub fn can_unwrap(&self) -> bool {
        self.policy.unwrap
    }

    /// Whether the private material may be exported (`extractable`).
    pub fn extractable(&self) -> bool {
        self.policy.extractable
    }

    /// The private key as a full two-prime CRT RSA private JWK (the
    /// `decryption-key.export-key-jwk` contract), behind the
    /// extractability gate, mirroring what the imports require.
    ///
    /// The copy returned is *not* protected: see the note on
    /// [`crate`](crate#exported-material).
    pub fn export_jwk(&self) -> Result<String, Error> {
        Ok(rsa_pkcs8_to_private_jwk(&self.pkcs8_marshal()?))
    }

    /// The private key as a PKCS#8 PrivateKeyInfo (the
    /// `decryption-key.export-key-pkcs8` contract), behind the same gate.
    ///
    /// The copy returned is *not* protected: see the note on
    /// [`crate`](crate#exported-material).
    pub fn export_pkcs8(&self) -> Result<Vec<u8>, Error> {
        Ok(self.pkcs8_marshal()?.to_vec())
    }

    /// The backend's PKCS#8 marshal behind the extractability gate — the
    /// component source of both private exports (the key type exposes no
    /// component getters).
    fn pkcs8_marshal(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        if !self.policy.extractable {
            return Err(Error::NotExtractable);
        }
        use aws_lc_rs::encoding::AsDer as _;
        let der: aws_lc_rs::encoding::Pkcs8V1Der =
            self.private.as_der().expect("valid key encodes");
        Ok(Zeroizing::new(der.as_ref().to_vec()))
    }
}

// Debug is implemented by hand so key material can never reach logs: only
// the algorithm binding and policy are printed, with the material
// redacted.
impl std::fmt::Debug for DecryptionKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptionKeyMaterial")
            .field("algorithm", &self.name())
            .field("hash", &self.hash())
            .field("policy", &self.policy)
            .field("private", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ExtensionError;
    use data_encoding_macro::hexlower;

    /// Every grant, non-extractable.
    fn dp() -> TransportPolicy {
        TransportPolicy {
            decrypt: true,
            unwrap: true,
            extractable: false,
        }
    }

    /// Every grant, extractable.
    fn xp() -> TransportPolicy {
        TransportPolicy {
            extractable: true,
            ..dp()
        }
    }

    /// Wycheproof `rsa_oaep_2048_sha256_mgf1sha256_test.json` (upstream
    /// C2SP/wycheproof `testvectors_v1` at commit
    /// `b61843a9a5115bb758134b6a1f5d5e502d445342`, the same revision the
    /// vendored vectors came from; the file itself is not yet vendored),
    /// group 1 `privateKeyPkcs8`: the 2048-bit key (e = 65537) every case
    /// in the file decrypts under.
    fn oaep_2048_pkcs8() -> Vec<u8> {
        hexlower!(
            "308204bd020100300d06092a864886f70d0101010500048204a7308204a30201\
             000282010100a2b451a07d0aa5f96e455671513550514a8a5b462ebef717094f\
             a1fee82224e637f9746d3f7cafd31878d80325b6ef5a1700f65903b469429e89\
             d6eac8845097b5ab393189db92512ed8a7711a1253facd20f79c15e8247f3d3e\
             42e46e48c98e254a2fe9765313a03eff8f17e1a029397a1fa26a8dce26f490ed\
             81299615d9814c22da610428e09c7d9658594266f5c021d0fceca08d945a12be\
             82de4d1ece6b4c03145b5d3495d4ed5411eb878daf05fd7afc3e09ada0f11264\
             22f590975a1969816f48698bcbba1b4d9cae79d460d8f9f85e7975005d9bc22c\
             4e5ac0f7c1a45d12569a62807d3b9a02e5a530e773066f453d1f5b4c2e9cf782\
             0283f742b9d502030100010282010024cdc62317f5d72a6f6ba6cc9632899b01\
             d1ff28867d72f61688995bc855a4e420a8405250089bdb13cf8e09543827b748\
             b9d27fbb2b4d9e20af8c5a6a862796d1a4cc18ad16ea678bc1bd4a83bbbe9c5e\
             57453b5ce7388e41a3ba4ce2b77b4438a229e954f720dae0353dc088ac8a76b2\
             6dc276f8e1b7851ddd6398ad16ff2e78195123b9b036e945c38c9d12434f6df7\
             6fe22359eb3e1ac9c011678fc926fad3ae475a4fffff55feb2d147e9c894f4c0\
             e29a599e762462482d968bf42780945fc0d2c31c573c4431b8f4fe8b8c67bec8\
             15abd44f7a86edca1c2308737358d2c2ae5e2e0e2dadf730980262377e58b13b\
             7d9992060a0bc870ccfdb4a9319ee102818100dc431050f782e894fb5248247d\
             98cb7d58b8d1e24f3b55d041c56e4de086b0d5bb028bda42eeb5d234d5681e58\
             09d415e6a289ad4cfbf78f978f6c35814f50eebff1c5b80a69f788e81e6bab5d\
             daa78369d659d143ec6f17e79813a575cfad9c569156b90113e2e9110ad9e7b4\
             8a1c9348a6e653321191290ea36cfb3a5b18f102818100bd1a81e7977f989812\
             2273ae3222b598ea5fb19eb4eabc38308a5e32196603b2e500ffb79f5b886816\
             611debc472fac45544070beb057c941378a6868af3b7a03d3f9880ec47d5e089\
             b94fbde542aba9ae8d72c57088d7abf5b131f39098f7bc160f90536abc9492fd\
             4e06f3ed7299d4b97bb03677207d95669f140cfbc20f2502818100a94b528b28\
             f291599121d91952ffd1c7f21d7c1479d99d478885fb161870ee1218bf084726\
             12dbe5497e8d9c650688e09c786961ae3e2c354dc48ae34514759c4c23c45884\
             88961dc06b414e61c0e1e7fbbd2923d31532fe289f96da220711e58c14019808\
             e00414276933bb07e4efb9b4a9b37656917205209f33f09515d7c10281803af0\
             e72a933aef09ff2503df78bafed531c02ff1a2bc437c540cdcbd4ad35435cf51\
             1763596543480629b114ca7f780ff7efa32ea0cb6e000d6d9ea1f2ef71fd9cf9\
             948422a165557e37e755edfe70d90b920502eb478bc98a63f788ce3a0f856d6e\
             de7251a383bfa8fa480a81a925af7b3cc538c4bab8c9f7597ffb68011d8d0281\
             802640fbfbcfefb163ee7a87b6483a66ee41f956d90fa8a7939bfc042ee0924b\
             1b7993d0445f758d51933e85179c0320b0c968b48a91c38b5be923e1097c0c56\
             2f88d42294b6a2759bafa5428a74f1270874e45f6fcc60f21602de5eccd143cf\
             31241f5921b5ad3983fb54ef17be3b285367e50c999c67247b552fe4bfce945f\
             7b"
        )
        .to_vec()
    }

    /// Wycheproof `rsa_oaep_2048_sha256_mgf1sha256_test.json` group 1
    /// `privateKeyJwk` (alg RSA-OAEP-256; the same key as the PKCS#8).
    const OAEP_2048_PRIVATE_JWK: &str = r#"{"kty":"RSA","alg":"RSA-OAEP-256","n":"orRRoH0KpfluRVZxUTVQUUqKW0YuvvcXCU-h_ugiJOY3-XRtP3yv0xh42AMltu9aFwD2WQO0aUKeidbqyIRQl7WrOTGJ25JRLtincRoSU_rNIPecFegkfz0-QuRuSMmOJUov6XZTE6A-_48X4aApOXofomqNzib0kO2BKZYV2YFMItphBCjgnH2WWFlCZvXAIdD87KCNlFoSvoLeTR7Oa0wDFFtdNJXU7VQR64eNrwX9evw-Ca2g8RJkIvWQl1oZaYFvSGmLy7obTZyuedRg2Pn4Xnl1AF2bwixOWsD3waRdElaaYoB9O5oC5aUw53MGb0U9H1tMLpz3ggKD90K51Q","e":"AQAB","kid":"none","d":"JM3GIxf11ypva6bMljKJmwHR_yiGfXL2FoiZW8hVpOQgqEBSUAib2xPPjglUOCe3SLnSf7srTZ4gr4xaaoYnltGkzBitFupni8G9SoO7vpxeV0U7XOc4jkGjukzit3tEOKIp6VT3INrgNT3AiKyKdrJtwnb44beFHd1jmK0W_y54GVEjubA26UXDjJ0SQ09t92_iI1nrPhrJwBFnj8km-tOuR1pP__9V_rLRR-nIlPTA4ppZnnYkYkgtlov0J4CUX8DSwxxXPEQxuPT-i4xnvsgVq9RPeobtyhwjCHNzWNLCrl4uDi2t9zCYAmI3flixO32ZkgYKC8hwzP20qTGe4Q","p":"3EMQUPeC6JT7UkgkfZjLfVi40eJPO1XQQcVuTeCGsNW7AovaQu610jTVaB5YCdQV5qKJrUz794-Xj2w1gU9Q7r_xxbgKafeI6B5rq13ap4Np1lnRQ-xvF-eYE6V1z62cVpFWuQET4ukRCtnntIock0im5lMyEZEpDqNs-zpbGPE","q":"vRqB55d_mJgSInOuMiK1mOpfsZ606rw4MIpeMhlmA7LlAP-3n1uIaBZhHevEcvrEVUQHC-sFfJQTeKaGivO3oD0_mIDsR9XgiblPveVCq6mujXLFcIjXq_WxMfOQmPe8Fg-QU2q8lJL9Tgbz7XKZ1Ll7sDZ3IH2VZp8UDPvCDyU","dp":"qUtSiyjykVmRIdkZUv_Rx_IdfBR52Z1HiIX7Fhhw7hIYvwhHJhLb5Ul-jZxlBojgnHhpYa4-LDVNxIrjRRR1nEwjxFiEiJYdwGtBTmHA4ef7vSkj0xUy_iifltoiBxHljBQBmAjgBBQnaTO7B-TvubSps3ZWkXIFIJ8z8JUV18E","dq":"OvDnKpM67wn_JQPfeLr-1THAL_GivEN8VAzcvUrTVDXPURdjWWVDSAYpsRTKf3gP9--jLqDLbgANbZ6h8u9x_Zz5lIQioWVVfjfnVe3-cNkLkgUC60eLyYpj94jOOg-FbW7eclGjg7-o-kgKgaklr3s8xTjEurjJ91l_-2gBHY0","qi":"JkD7-8_vsWPueoe2SDpm7kH5VtkPqKeTm_wELuCSSxt5k9BEX3WNUZM-hRecAyCwyWi0ipHDi1vpI-EJfAxWL4jUIpS2onWbr6VCinTxJwh05F9vzGDyFgLeXszRQ88xJB9ZIbWtOYP7VO8XvjsoU2flDJmcZyR7VS_kv86UX3s"}"#;

    /// The public members of the group key, tagged with the variant's
    /// JOSE alg.
    const OAEP_2048_PUBLIC_JWK: &str = r#"{"kty":"RSA","alg":"RSA-OAEP-256","n":"orRRoH0KpfluRVZxUTVQUUqKW0YuvvcXCU-h_ugiJOY3-XRtP3yv0xh42AMltu9aFwD2WQO0aUKeidbqyIRQl7WrOTGJ25JRLtincRoSU_rNIPecFegkfz0-QuRuSMmOJUov6XZTE6A-_48X4aApOXofomqNzib0kO2BKZYV2YFMItphBCjgnH2WWFlCZvXAIdD87KCNlFoSvoLeTR7Oa0wDFFtdNJXU7VQR64eNrwX9evw-Ca2g8RJkIvWQl1oZaYFvSGmLy7obTZyuedRg2Pn4Xnl1AF2bwixOWsD3waRdElaaYoB9O5oC5aUw53MGb0U9H1tMLpz3ggKD90K51Q","e":"AQAB"}"#;

    /// Wycheproof `rsa_oaep_2048_sha256_mgf1sha256_test.json` tcId 1: a
    /// valid ciphertext of the empty message under the empty label.
    fn oaep_tc1_ct() -> Vec<u8> {
        hexlower!(
            "6e62bf24d95aff6868afec2a92a445b6458f16f688c19fe1212f66a631378316\
             53cedd359d8cff4dd485d77dfd55812c181373201f54aafd65730d2a304e6234\
             55d51125d891e65d97fce52341cae45fb64c38a384a1c621e2713ee6794633f0\
             29a9fd4d774f56551eac2176162e162640f25eab873a3451c475570f19228bce\
             de4c67c370a75ed7fabccd538c9819eff182481b10d42f1a9f6a05373b8cf9b7\
             1818d467bd3b8ebacb619e8ad42916e600c043effceb3855bc48a629e60ae886\
             f51b2a7876b0e623fb2ce68af4b039242f963adb0e4240aed0ed07f65f1ee7c0\
             cc77d210d0c2d1dc10c81b881aa0c9c9e9499665cf2970d2ccfeeb3191531765"
        )
        .to_vec()
    }

    /// Wycheproof `rsa_oaep_2048_sha256_mgf1sha256_test.json` tcId 8: a
    /// valid ciphertext of the message `"313233343030"` under the 8-byte
    /// all-zero label.
    fn oaep_tc8_ct() -> Vec<u8> {
        hexlower!(
            "6583e2f176aa7e7f655d2c53497349c156c8851fb23325589e85fb83bfa85734\
             6caba222cdaa3234e71564154298c24dbb85e18822a1d5e7faa47863a64d7687\
             4a3cbc70f4d9f137426a344c473fac1dd7008a9973765e9f66c5b492535a647c\
             273c4f78ceb5aa7ba963a2142f2ce4a81f804c002b9b2eabb3c75e80a3c6ceaf\
             e5384a544c672a5d28d32bb87115f43eb79775fd9b3f4a2f6e6a89368bdd95ef\
             1d014877b60afdb1234acd57653a65459f01b2fbe381f22a739504b4897a7e6c\
             33b6349b276db6083abad9c169405859b800c812237634b503de6ada43013c1d\
             86697a135be78a9784576d796d62aa7819e2ea0e2d902ffdd9cfdd1ae66212ee"
        )
        .to_vec()
    }

    /// The tcId 8 message: `"123400"` as ASCII.
    const TC8_MSG: &[u8] = b"123400";

    /// The tcId 8 label: 8 zero bytes.
    const TC8_LABEL: &[u8] = &[0u8; 8];

    /// A synthetic RSA modulus of `bits` length for admission-only checks:
    /// top bit set, odd (an actual factorization is irrelevant — admission
    /// looks only at the value bounds).
    fn synthetic_public_jwk(bits: usize) -> String {
        assert_eq!(bits % 8, 0);
        let mut n = vec![0u8; bits / 8];
        n[0] = 0x80;
        *n.last_mut().unwrap() |= 1;
        crate::jwk::build_rsa_public(&n, &[1, 0, 1])
    }

    /// Wycheproof tcId 1 and tcId 8: the PKCS#8 and JWK imports agree on
    /// the known answers — the empty-label case and the labeled case —
    /// and the getters report the mint.
    #[test]
    fn oaep_2048_sha256_decrypt_known_answers() {
        for key in [
            DecryptionKeyMaterial::import_oaep_pkcs8(RsaVariant::Sha256, &oaep_2048_pkcs8(), dp())
                .unwrap(),
            DecryptionKeyMaterial::import_oaep_jwk(RsaVariant::Sha256, OAEP_2048_PRIVATE_JWK, dp())
                .unwrap(),
        ] {
            assert_eq!(key.decrypt(None, &oaep_tc1_ct()).unwrap(), b"");
            assert_eq!(
                key.decrypt(Some(TC8_LABEL), &oaep_tc8_ct()).unwrap(),
                TC8_MSG
            );
            assert_eq!(key.name(), "RSA-OAEP");
            assert_eq!(key.hash(), Some("SHA-256"));
            assert_eq!(key.length(), Some(2048));
        }
    }

    /// The label binds: tcId 8's ciphertext decrypts only under its own
    /// label — an absent, empty, or different label is the same
    /// detail-free failure. `None` and the empty label are one
    /// parameterization (tcId 1 decrypts under both).
    #[test]
    fn oaep_label_binds() {
        let key =
            DecryptionKeyMaterial::import_oaep_pkcs8(RsaVariant::Sha256, &oaep_2048_pkcs8(), dp())
                .unwrap();
        assert_eq!(
            key.decrypt(None, &oaep_tc8_ct()),
            Err(Error::AuthenticationFailed)
        );
        assert_eq!(
            key.decrypt(Some(b""), &oaep_tc8_ct()),
            Err(Error::AuthenticationFailed)
        );
        assert_eq!(
            key.decrypt(Some(&[0u8; 7]), &oaep_tc8_ct()),
            Err(Error::AuthenticationFailed)
        );
        assert_eq!(key.decrypt(Some(b""), &oaep_tc1_ct()).unwrap(), b"");
    }

    /// Encrypt→decrypt round trips for every variant over one key, with
    /// and without a label; encryption is randomized (two ciphertexts of
    /// one plaintext differ, both decrypt).
    #[test]
    fn oaep_round_trips_per_variant() {
        for variant in [RsaVariant::Sha256, RsaVariant::Sha384, RsaVariant::Sha512] {
            let key = DecryptionKeyMaterial::import_oaep_pkcs8(variant, &oaep_2048_pkcs8(), dp())
                .unwrap();
            let public = key.public();
            assert_eq!(public.hash(), key.hash());
            let a = public.encrypt(None, b"message").unwrap();
            let b = public.encrypt(None, b"message").unwrap();
            assert_eq!(a.len(), 256);
            assert_ne!(a, b, "OAEP encryption is randomized");
            assert_eq!(key.decrypt(None, &a).unwrap(), b"message");
            assert_eq!(key.decrypt(None, &b).unwrap(), b"message");
            let labeled = public.encrypt(Some(b"context"), b"message").unwrap();
            assert_eq!(key.decrypt(Some(b"context"), &labeled).unwrap(), b"message");
            assert_eq!(
                key.decrypt(None, &labeled),
                Err(Error::AuthenticationFailed)
            );
        }
    }

    /// The plaintext bound is k − 2·hLen − 2 exactly, per variant: the
    /// bound-length plaintext encrypts, one byte more fails with the
    /// named extension condition carrying the bound and the got-length.
    #[test]
    fn oaep_plaintext_bound() {
        for (variant, bound) in [
            (RsaVariant::Sha256, 256 - 2 * 32 - 2),
            (RsaVariant::Sha384, 256 - 2 * 48 - 2),
            (RsaVariant::Sha512, 256 - 2 * 64 - 2),
        ] {
            let key = DecryptionKeyMaterial::import_oaep_pkcs8(variant, &oaep_2048_pkcs8(), dp())
                .unwrap();
            let public = key.public();
            let at_bound = vec![7u8; bound];
            let ct = public.encrypt(None, &at_bound).unwrap();
            assert_eq!(key.decrypt(None, &ct).unwrap(), at_bound);
            let over = vec![7u8; bound + 1];
            assert_eq!(
                public.encrypt(None, &over),
                Err(Error::Extension(ExtensionError {
                    origin: "lann:webcrypto".into(),
                    name: "message-too-long".into(),
                    message: format!(
                        "this key bounds plaintexts to {bound} bytes, got {} bytes",
                        bound + 1
                    ),
                }))
            );
            // `wrap` renders the same condition for over-bound serialized
            // material.
            assert_eq!(
                public.wrap(
                    None,
                    crate::WrapInputMaterial::new(crate::WrapFormat::Pkcs8, over)
                ),
                public.encrypt(None, &vec![7u8; bound + 1])
            );
        }
    }

    /// The OAEP window on the public half: 2048 and 8192 bits import,
    /// 1024 (the family's legacy verification floor) and 16384 (the
    /// family's ceiling) reject with the message naming the window.
    #[test]
    fn oaep_public_window() {
        for bits in [2048usize, 8192] {
            let key = EncryptionKeyMaterial::import_oaep_jwk(
                RsaVariant::Sha256,
                &synthetic_public_jwk(bits),
            )
            .unwrap();
            assert_eq!(key.length(), Some(bits as u32));
        }
        for bits in [1024usize, 16384] {
            match EncryptionKeyMaterial::import_oaep_jwk(
                RsaVariant::Sha256,
                &synthetic_public_jwk(bits),
            ) {
                Err(Error::InvalidKey(msg)) => assert_eq!(
                    msg,
                    format!("RSA-OAEP keys are 2048-8192 bits, got {bits} bits")
                ),
                other => panic!("expected the window diagnostic, got {other:?}"),
            }
        }
    }

    /// The OAEP window on the private half: a valid 1024-bit key —
    /// inside the family's verification window — rejects on both import
    /// paths' shared admission. The material is Wycheproof
    /// `rsa_pkcs1_1024_sig_gen_test.json`'s (upstream `testvectors_v1`
    /// at commit `b61843a9…`, not vendored — its keys sit below this
    /// package's private-key windows), SHA-256 group `privateKeyPkcs8`.
    #[test]
    fn oaep_private_window() {
        let pkcs8 = hexlower!(
            "30820276020100300d06092a864886f70d0101010500048202603082025c0201\
             0002818100ac9048a7a4f560af91b4fcaf62a14595cb9ca9ec12000fc845e485\
             72113cab2890adb011a919575a40760d1f23fe92509c8a5810b6d05990b909dd\
             0f4c6014f2b31b6abd805bace99816e2eda41fd7b95405db7c5c8f4cf6babb14\
             f550d5d0dd5179b54951fff6aa9686f30f478db649b7c7044cc202dccad00343\
             468eaacfbf0203010001028181008505d47c271560aaf6cf65da6d5594a69c86\
             f01622ea194071606fde369b65f5a751bce06052409c3a04c6a8b2be935bc0d0\
             84829dea8ea0998398fd2a0b0719ac1a1ae2d133fcc72d9df27b377b9a0109ef\
             1a564e92b66963356b8da48f88fcdbc20658f74b542582925ec5cd03fb5e9a52\
             7c670465f792a69c1f6c7c5e1841024100d397dcfab4919db23bb6b88c451151\
             6f6135e1118277e496130f0cab3a75661010cc98ec8f40cdb0c1ab612c03bbe3\
             b023d891f46185788fb114437c8a9ae71d024100d0c7805159509ddad70f35b9\
             a76c7c2bd95a844d36b76d96138cfc7a2a55f88072e8b10ac37463caf9bf8d10\
             14c93a001214d7ce230c8332fb58dadb05d52f8b0240762d3c4b7dac5292284d\
             be3701a051864e99e4117e77ede06fd698f1cd5da25a58b79cb58ab0dbf0dbca\
             17249915486ea9269d260b8d9b2f4dec8e60b19d2075024062a4f06eff4944dc\
             6262905ae0cd343a2f9f42058d85cb646e665de086e249e0beea4cc42e276f03\
             374f9721f30044c445c6cd545b610d186883ca1c543c2f1302403cfcf044035c\
             1854475e1dba480ac50d2a059f32d18e819c96a3199b1e3855a653ec0e5577e4\
             d7677d6e0b7a55fc418b13202ee19430228c4bf9d28af8851c9b"
        )
        .to_vec();
        match DecryptionKeyMaterial::import_oaep_pkcs8(RsaVariant::Sha256, &pkcs8, dp()) {
            Err(Error::InvalidKey(msg)) => {
                assert_eq!(msg, "RSA-OAEP keys are 2048-8192 bits, got 1024 bits")
            }
            other => panic!("expected the window diagnostic, got {other:?}"),
        }
    }

    /// The mint gates and grants: zero-usage policies fail at mint, a
    /// decrypt-only key cannot `unwrap`, an unwrap-only key cannot
    /// `decrypt`, and the getters report the grants.
    #[test]
    fn oaep_grants() {
        assert!(matches!(
            DecryptionKeyMaterial::import_oaep_pkcs8(
                RsaVariant::Sha256,
                &oaep_2048_pkcs8(),
                TransportPolicy::default(),
            ),
            Err(Error::NotPermitted(_))
        ));
        let decrypt_only = DecryptionKeyMaterial::import_oaep_pkcs8(
            RsaVariant::Sha256,
            &oaep_2048_pkcs8(),
            TransportPolicy {
                decrypt: true,
                unwrap: false,
                extractable: false,
            },
        )
        .unwrap();
        assert!(decrypt_only.can_decrypt());
        assert!(!decrypt_only.can_unwrap());
        assert_eq!(
            decrypt_only.unwrap(None, &oaep_tc1_ct()).err(),
            Some(Error::NotPermitted(
                "this key does not permit unwrap".into()
            ))
        );
        let unwrap_only = DecryptionKeyMaterial::import_oaep_pkcs8(
            RsaVariant::Sha256,
            &oaep_2048_pkcs8(),
            TransportPolicy {
                decrypt: false,
                unwrap: true,
                extractable: false,
            },
        )
        .unwrap();
        assert_eq!(
            unwrap_only.decrypt(None, &oaep_tc1_ct()),
            Err(Error::NotPermitted(
                "this key does not permit decrypt".into()
            ))
        );
        assert!(unwrap_only.unwrap(None, &oaep_tc1_ct()).is_ok());
    }

    /// The extractability gate holds on both private exports, and the
    /// extractable exports round-trip: the JWK carries every CRT member
    /// and re-imports to a key that decrypts the known answer, as does
    /// the PKCS#8.
    #[test]
    fn oaep_exports_and_gates() {
        let sealed =
            DecryptionKeyMaterial::import_oaep_pkcs8(RsaVariant::Sha256, &oaep_2048_pkcs8(), dp())
                .unwrap();
        assert!(!sealed.extractable());
        assert_eq!(sealed.export_jwk(), Err(Error::NotExtractable));
        assert_eq!(sealed.export_pkcs8(), Err(Error::NotExtractable));

        let open =
            DecryptionKeyMaterial::import_oaep_pkcs8(RsaVariant::Sha256, &oaep_2048_pkcs8(), xp())
                .unwrap();
        assert!(open.extractable());
        let jwk = open.export_jwk().unwrap();
        for member in [
            "\"n\"", "\"e\"", "\"d\"", "\"p\"", "\"q\"", "\"dp\"", "\"dq\"", "\"qi\"",
        ] {
            assert!(jwk.contains(member), "JWK lacks {member}: {jwk}");
        }
        let back = DecryptionKeyMaterial::import_oaep_jwk(RsaVariant::Sha256, &jwk, dp()).unwrap();
        assert_eq!(back.decrypt(None, &oaep_tc1_ct()).unwrap(), b"");
        let pkcs8 = open.export_pkcs8().unwrap();
        let back =
            DecryptionKeyMaterial::import_oaep_pkcs8(RsaVariant::Sha256, &pkcs8, dp()).unwrap();
        assert_eq!(back.decrypt(None, &oaep_tc1_ct()).unwrap(), b"");
    }

    /// The public export surface: no raw form (`unsupported`), the SPKI
    /// round-trips byte-exactly (DER is canonical), the JWK export
    /// re-imports to the same key, and the SPKI matches the JWK-imported
    /// key's.
    #[test]
    fn oaep_public_exports() {
        let key =
            DecryptionKeyMaterial::import_oaep_pkcs8(RsaVariant::Sha256, &oaep_2048_pkcs8(), dp())
                .unwrap();
        let public = key.public();
        match public.export() {
            Err(Error::Unsupported(msg)) => {
                assert_eq!(msg, "RSA public keys have no raw form")
            }
            other => panic!("expected unsupported, got {other:?}"),
        }
        let spki = public.export_spki();
        let back = EncryptionKeyMaterial::import_oaep_spki(RsaVariant::Sha256, &spki).unwrap();
        assert_eq!(back.export_spki(), spki);
        let jwk = public.export_jwk();
        let back = EncryptionKeyMaterial::import_oaep_jwk(RsaVariant::Sha256, &jwk).unwrap();
        assert_eq!(back.export_spki(), spki);
        let from_jwk =
            EncryptionKeyMaterial::import_oaep_jwk(RsaVariant::Sha256, OAEP_2048_PUBLIC_JWK)
                .unwrap();
        assert_eq!(from_jwk.export_spki(), spki);
        // A ciphertext from the format-imported key decrypts.
        let ct = from_jwk.encrypt(Some(b"label"), b"payload").unwrap();
        assert_eq!(key.decrypt(Some(b"label"), &ct).unwrap(), b"payload");
    }

    /// The JWK `alg` policy: each import accepts only its variant's JOSE
    /// alg — the digests cross-reject, and JOSE's suffix-less
    /// `"RSA-OAEP"` (OAEP under SHA-1, which no variant serves) is
    /// refused everywhere.
    #[test]
    fn oaep_jwk_alg_policy() {
        match EncryptionKeyMaterial::import_oaep_jwk(RsaVariant::Sha384, OAEP_2048_PUBLIC_JWK) {
            Err(Error::InvalidKey(msg)) => assert_eq!(
                msg,
                r#"JWK alg is "RSA-OAEP-256", not one of ["RSA-OAEP-384"]"#
            ),
            other => panic!("expected the alg diagnostic, got {other:?}"),
        }
        let sha1_tagged = OAEP_2048_PUBLIC_JWK.replace("RSA-OAEP-256", "RSA-OAEP");
        for variant in [RsaVariant::Sha256, RsaVariant::Sha384, RsaVariant::Sha512] {
            assert!(matches!(
                EncryptionKeyMaterial::import_oaep_jwk(variant, &sha1_tagged),
                Err(Error::InvalidKey(_))
            ));
        }
        assert!(matches!(
            DecryptionKeyMaterial::import_oaep_jwk(RsaVariant::Sha384, OAEP_2048_PRIVATE_JWK, dp()),
            Err(Error::InvalidKey(_))
        ));
    }

    /// Generation mints a coherent pair: the reported length matches the
    /// requested modulus, the public half's ciphertexts decrypt, the
    /// getters agree across the halves, and the exported PKCS#8
    /// re-imports to a key that decrypts the pair's ciphertexts.
    #[test]
    fn oaep_generate_round_trip() {
        let key = DecryptionKeyMaterial::generate_oaep(RsaVariant::Sha256, RsaModulus::M2048, xp())
            .unwrap()
            .unwrap();
        assert_eq!(key.name(), "RSA-OAEP");
        assert_eq!(key.hash(), Some("SHA-256"));
        assert_eq!(key.length(), Some(2048));
        let public = key.public();
        assert_eq!(public.name(), "RSA-OAEP");
        assert_eq!(public.hash(), Some("SHA-256"));
        assert_eq!(public.length(), Some(2048));
        let ct = public.encrypt(Some(b"ctx"), b"transported").unwrap();
        assert_eq!(key.decrypt(Some(b"ctx"), &ct).unwrap(), b"transported");
        let back = DecryptionKeyMaterial::import_oaep_pkcs8(
            RsaVariant::Sha256,
            &key.export_pkcs8().unwrap(),
            dp(),
        )
        .unwrap();
        assert_eq!(back.decrypt(Some(b"ctx"), &ct).unwrap(), b"transported");
        // A zero-usage generation fails at mint.
        assert!(matches!(
            DecryptionKeyMaterial::generate_oaep(
                RsaVariant::Sha256,
                RsaModulus::M2048,
                TransportPolicy::default()
            ),
            Ok(Err(Error::NotPermitted(_)))
        ));
    }

    /// Every decryption failure is one detail-free verdict: an empty,
    /// truncated, extended, corrupted, or wrong-label ciphertext all
    /// yield the same `authentication-failed` value, indistinguishable
    /// from one another (RFC 8017 §7.1.2's requirement).
    #[test]
    fn oaep_failures_are_detail_free() {
        let key =
            DecryptionKeyMaterial::import_oaep_pkcs8(RsaVariant::Sha256, &oaep_2048_pkcs8(), dp())
                .unwrap();
        let valid = oaep_tc1_ct();
        let mut corrupted = valid.clone();
        corrupted[0] ^= 1;
        let mut extended = valid.clone();
        extended.push(0);
        let verdicts = [
            key.decrypt(None, &[]),
            key.decrypt(None, &valid[..255]),
            key.decrypt(None, &extended),
            key.decrypt(None, &corrupted),
            key.decrypt(Some(b"wrong"), &valid),
        ];
        for verdict in verdicts {
            assert_eq!(verdict, Err(Error::AuthenticationFailed));
        }
        // The unwrap path collapses identically.
        assert_eq!(
            key.unwrap(None, &corrupted).err(),
            Some(Error::AuthenticationFailed)
        );
    }

    /// The transport wrap/unwrap circle: serialized key material wrapped
    /// under the public key unwraps into an intermediate that the typed
    /// mints consume — an HMAC JWK mints back to the same material, and
    /// the decryption-key mints reuse the imports behind the unwrap-path
    /// redaction and `use`/`key_ops` checks.
    #[test]
    fn oaep_wrap_unwrap_mints() {
        let key =
            DecryptionKeyMaterial::import_oaep_pkcs8(RsaVariant::Sha256, &oaep_2048_pkcs8(), dp())
                .unwrap();
        let public = key.public();

        // A symmetric key rides the transport circle.
        let mac = crate::MacKeyMaterial::import(
            crate::Sha2Variant::Sha256,
            vec![5; 32],
            crate::MacPolicy {
                sign: true,
                verify: false,
                extractable: true,
            },
        )
        .unwrap();
        let wrapped = public
            .wrap(
                Some(b"kt"),
                crate::WrapInputMaterial::new(
                    crate::WrapFormat::Jwk,
                    mac.export_jwk().unwrap().into_bytes(),
                ),
            )
            .unwrap();
        let minted = crate::unwrap_mac_key_jwk(
            crate::Sha2Variant::Sha256,
            key.unwrap(Some(b"kt"), &wrapped).unwrap(),
            crate::MacPolicy {
                sign: true,
                verify: false,
                extractable: true,
            },
        )
        .unwrap();
        assert_eq!(minted.export().unwrap(), vec![5; 32]);

        // The decryption-key mints: PKCS#8, and JWK with its
        // `use`/`key_ops` checks.
        let minted = crate::unwrap_oaep_decryption_key_pkcs8(
            RsaVariant::Sha256,
            crate::UnwrapInputMaterial::new(oaep_2048_pkcs8()),
            dp(),
        )
        .unwrap();
        assert_eq!(minted.decrypt(None, &oaep_tc1_ct()).unwrap(), b"");
        let enc_use = format!(
            r#"{{{},"use":"enc","key_ops":["decrypt","unwrapKey"]}}"#,
            OAEP_2048_PRIVATE_JWK
                .strip_prefix('{')
                .unwrap()
                .strip_suffix('}')
                .unwrap()
        );
        let minted = crate::unwrap_oaep_decryption_key_jwk(
            RsaVariant::Sha256,
            crate::UnwrapInputMaterial::new(enc_use.into_bytes()),
            dp(),
        )
        .unwrap();
        assert_eq!(minted.decrypt(None, &oaep_tc1_ct()).unwrap(), b"");
        // A decryption key's family is "enc": a sig-tagged JWK is refused.
        let sig_use = format!(
            r#"{{{},"use":"sig"}}"#,
            OAEP_2048_PRIVATE_JWK
                .strip_prefix('{')
                .unwrap()
                .strip_suffix('}')
                .unwrap()
        );
        assert!(matches!(
            crate::unwrap_oaep_decryption_key_jwk(
                RsaVariant::Sha256,
                crate::UnwrapInputMaterial::new(sig_use.into_bytes()),
                dp(),
            ),
            Err(Error::InvalidKey(_))
        ));
        // key_ops missing a granted usage is refused.
        let narrow_ops = format!(
            r#"{{{},"key_ops":["decrypt"]}}"#,
            OAEP_2048_PRIVATE_JWK
                .strip_prefix('{')
                .unwrap()
                .strip_suffix('}')
                .unwrap()
        );
        assert!(matches!(
            crate::unwrap_oaep_decryption_key_jwk(
                RsaVariant::Sha256,
                crate::UnwrapInputMaterial::new(narrow_ops.into_bytes()),
                dp(),
            ),
            Err(Error::InvalidKey(_))
        ));
        // The redaction: an out-of-window key's message is fixed.
        match crate::unwrap_oaep_decryption_key_pkcs8(
            RsaVariant::Sha256,
            crate::UnwrapInputMaterial::new(vec![0xff; 64]),
            dp(),
        ) {
            Err(Error::InvalidKey(msg)) => {
                assert_eq!(msg, "unwrapped material is not a valid RSA PKCS#8 key")
            }
            other => panic!("expected the redacted diagnostic, got {other:?}"),
        }
    }

    /// The SPKI algorithm pre-check renders the family diagnostic on the
    /// OAEP import too.
    #[test]
    fn oaep_spki_algorithm_is_checked() {
        // An Ed25519 SPKI is well-formed DER under the wrong algorithm.
        let ed = crate::SigningKeyMaterial::import_ed25519_seed(
            &[7; 32],
            crate::SigningPolicy {
                sign: true,
                extractable: false,
            },
        )
        .unwrap();
        match EncryptionKeyMaterial::import_oaep_spki(
            RsaVariant::Sha256,
            &ed.public().export_spki(),
        ) {
            Err(Error::InvalidKey(msg)) => {
                assert_eq!(msg, "SPKI algorithm must be rsaEncryption, got 1.3.101.112")
            }
            other => panic!("expected the algorithm diagnostic, got {other:?}"),
        }
    }

    #[test]
    fn debug_redacts_private_material() {
        let key =
            DecryptionKeyMaterial::import_oaep_pkcs8(RsaVariant::Sha256, &oaep_2048_pkcs8(), xp())
                .unwrap();
        let rendered = format!("{key:?}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(rendered.contains("RSA-OAEP"), "{rendered}");
    }
}
