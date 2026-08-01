//! The `cipher.cipher-key` material: unauthenticated AES modes (CBC with
//! PKCS#7 padding, CTR with an arbitrary-width wrapping counter), served
//! for compatibility with WebCrypto-committed formats. See the WIT
//! `cipher` interface and `wit/README.md`, "Design notes",
//! "Unauthenticated modes are in, for compatibility".
//!
//! The load-bearing rule here is decrypt-failure uniformity: every
//! malformed-input condition on `decrypt` — a ciphertext of the wrong
//! shape, a bad final padding block — renders as one fixed
//! [`Error::Other`] message per algorithm, so nothing distinguishes a
//! padding verdict from any other malformation (a distinguishable verdict
//! is a padding-oracle amplifier).

use aes::cipher::{BlockDecrypt as _, BlockEncrypt as _, KeyInit as _};
use aes::{Aes128, Aes256};
use zeroize::Zeroizing;

use crate::{CipherPolicy, Error, RngError};

/// The AES block size in bytes: the CBC block/IV size and the CTR counter
/// block size.
const BLOCK: usize = 16;

/// The served AES modes a `cipher-key` can be bound to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherMode {
    /// AES-CBC with PKCS#7 padding (WebCrypto's `AES-CBC`).
    Cbc,
    /// AES-CTR with a per-call counter width (WebCrypto's `AES-CTR`).
    Ctr,
}

impl CipherMode {
    /// The registry `algorithm-name` for keys of this mode.
    pub fn name(self) -> &'static str {
        match self {
            Self::Cbc => "AES-CBC",
            Self::Ctr => "AES-CTR",
        }
    }

    /// The JWK `alg` for this mode at an AES key length in bits.
    fn jwk_alg(self, bits: u32) -> &'static str {
        match (self, bits) {
            (Self::Cbc, 128) => "A128CBC",
            (Self::Cbc, _) => "A256CBC",
            (Self::Ctr, 128) => "A128CTR",
            (Self::Ctr, _) => "A256CTR",
        }
    }

    /// The fixed uniform message every `decrypt` failure of this mode
    /// renders (see the module doc).
    fn decrypt_failed(self) -> Error {
        Error::Other(format!("{} decryption failed", self.name()))
    }
}

/// The AES block cipher backing a [`CipherKeyMaterial`], keyed at minting.
// The size skew between the AES-128 and AES-256 key schedules is inherent.
#[allow(clippy::large_enum_variant)]
enum Block {
    Aes128(Aes128),
    Aes256(Aes256),
}

impl Block {
    fn encrypt_block(&self, block: &mut [u8; BLOCK]) {
        match self {
            Self::Aes128(c) => c.encrypt_block(block.into()),
            Self::Aes256(c) => c.encrypt_block(block.into()),
        }
    }

    fn decrypt_block(&self, block: &mut [u8; BLOCK]) {
        match self {
            Self::Aes128(c) => c.decrypt_block(block.into()),
            Self::Aes256(c) => c.decrypt_block(block.into()),
        }
    }
}

/// The material behind a `cipher.cipher-key` resource: the keyed AES block
/// cipher, its mode, the raw key bytes (zeroized on drop), and the
/// mint-time policy.
pub struct CipherKeyMaterial {
    mode: CipherMode,
    block: Block,
    raw: Zeroizing<Vec<u8>>,
    policy: CipherPolicy,
}

impl CipherKeyMaterial {
    /// Import raw key material as the declared AES variant and mode (the
    /// `import-key-raw` contract shared by `aes-cbc` and `aes-ctr`):
    /// material whose length disagrees with the variant is `invalid-key`;
    /// AES-192 is `unsupported`.
    pub fn import(
        mode: CipherMode,
        variant: crate::AesVariant,
        raw: Vec<u8>,
        policy: CipherPolicy,
    ) -> Result<Self, Error> {
        policy.check_useful()?;
        type Make = fn(&[u8]) -> Block;
        let (expected, make): (usize, Make) = match variant {
            crate::AesVariant::Aes128 => (16, |raw| {
                Block::Aes128(Aes128::new_from_slice(raw).expect("length checked"))
            }),
            crate::AesVariant::Aes192 => {
                return Err(Error::Unsupported(
                    "AES-192 is not served by this implementation".into(),
                ))
            }
            crate::AesVariant::Aes256 => (32, |raw| {
                Block::Aes256(Aes256::new_from_slice(raw).expect("length checked"))
            }),
        };
        if raw.len() != expected {
            return Err(Error::InvalidKey(format!(
                "{variant:?} requires {expected} bytes of key material, got {} bytes",
                raw.len()
            )));
        }
        Ok(Self {
            mode,
            block: make(&raw),
            raw: Zeroizing::new(raw),
            policy,
        })
    }

    /// Import an RFC 7517 `oct` JWK (the `import-key-jwk` contract shared
    /// by `aes-cbc` and `aes-ctr`): `alg`, when present, must name the
    /// declared variant and mode; the decoded material is then subject to
    /// [`import`](Self::import)'s contract.
    pub fn import_jwk(
        mode: CipherMode,
        variant: crate::AesVariant,
        jwk: &str,
        policy: CipherPolicy,
    ) -> Result<Self, Error> {
        let alg = match variant {
            crate::AesVariant::Aes128 => mode.jwk_alg(128),
            crate::AesVariant::Aes192 => {
                return Err(Error::Unsupported(
                    "AES-192 is not served by this implementation".into(),
                ))
            }
            crate::AesVariant::Aes256 => mode.jwk_alg(256),
        };
        let raw = crate::jwk::parse_oct(jwk, Some(alg), policy.extractable)?;
        Self::import(mode, variant, raw, policy)
    }

    /// Generate a fresh random key of the declared variant and mode. The
    /// inner error is `unsupported` for AES-192; the outer channel is
    /// entropy failure.
    pub fn generate(
        mode: CipherMode,
        variant: crate::AesVariant,
        policy: CipherPolicy,
    ) -> Result<Result<Self, Error>, RngError> {
        if let Err(err) = policy.check_useful() {
            return Ok(Err(err));
        }
        let len = match variant {
            crate::AesVariant::Aes128 => 16,
            crate::AesVariant::Aes192 => {
                return Ok(Err(Error::Unsupported(
                    "AES-192 is not served by this implementation".into(),
                )))
            }
            crate::AesVariant::Aes256 => 32,
        };
        Ok(Ok(Self::import(
            mode,
            variant,
            crate::random_bytes(len)?,
            policy,
        )
        .expect("generated key material always matches the variant")))
    }

    /// The mode this key is bound to.
    pub fn mode(&self) -> CipherMode {
        self.mode
    }

    /// The registry `algorithm-name`.
    pub fn name(&self) -> &'static str {
        self.mode.name()
    }

    /// The key length in bits.
    pub fn length_bits(&self) -> u32 {
        (self.raw.len() * 8) as u32
    }

    /// The material's length in bytes.
    pub fn byte_len(&self) -> usize {
        self.raw.len()
    }

    /// The mint-time policy.
    pub fn policy(&self) -> CipherPolicy {
        self.policy
    }

    /// The raw key material, behind the extractability gate.
    pub fn export(&self) -> Result<Vec<u8>, Error> {
        if !self.policy.extractable {
            return Err(Error::NotExtractable);
        }
        Ok(self.raw.to_vec())
    }

    /// The key as an `oct` JWK, behind the same gate as
    /// [`export`](Self::export).
    pub fn export_jwk(&self) -> Result<String, Error> {
        let alg = self.mode.jwk_alg(self.length_bits());
        Ok(crate::jwk::build_oct(&self.export()?, Some(alg)))
    }

    /// Encrypt `plaintext` (the `cipher-key.encrypt` contract): PKCS#7-pad
    /// and CBC-chain, or CTR keystream. Usage is the caller's to check.
    pub fn encrypt(
        &self,
        iv: &[u8],
        counter_length: Option<u8>,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if !self.policy.encrypt {
            return Err(crate::not_permitted("encrypt"));
        }
        let iv = self.checked_iv(iv, counter_length)?;
        match self.mode {
            CipherMode::Cbc => Ok(self.cbc_encrypt(iv, plaintext)),
            CipherMode::Ctr => {
                let n = counter_length.expect("checked_iv requires it for CTR");
                self.ctr_apply(iv, n, plaintext)
            }
        }
    }

    /// Decrypt `ciphertext` (the `cipher-key.decrypt` contract). Every
    /// malformed-input failure is the mode's one uniform error (see the
    /// module doc).
    pub fn decrypt(
        &self,
        iv: &[u8],
        counter_length: Option<u8>,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if !self.policy.decrypt {
            return Err(crate::not_permitted("decrypt"));
        }
        let iv = self.checked_iv(iv, counter_length)?;
        match self.mode {
            CipherMode::Cbc => self.cbc_decrypt(iv, ciphertext),
            CipherMode::Ctr => {
                let n = counter_length.expect("checked_iv requires it for CTR");
                self.ctr_apply(iv, n, ciphertext)
            }
        }
    }

    /// Validate the per-call `iv` and `counter-length` against the mode's
    /// contract, returning the IV as a block.
    fn checked_iv(&self, iv: &[u8], counter_length: Option<u8>) -> Result<[u8; BLOCK], Error> {
        match (self.mode, counter_length) {
            (CipherMode::Cbc, Some(_)) => {
                return Err(Error::InvalidNonce(
                    "AES-CBC takes no counter length".into(),
                ))
            }
            (CipherMode::Ctr, None) => {
                return Err(Error::InvalidNonce(
                    "AES-CTR requires a counter length".into(),
                ))
            }
            (CipherMode::Ctr, Some(n)) if n == 0 || n > 128 => {
                return Err(Error::InvalidNonce(format!(
                    "the counter length must be 1 to 128 bits, got {n}"
                )))
            }
            _ => {}
        }
        iv.try_into().map_err(|_| {
            Error::InvalidNonce(format!(
                "{} requires a 16-byte IV, got {} bytes",
                self.name(),
                iv.len()
            ))
        })
    }

    /// CBC-encrypt with PKCS#7 padding: output is always a non-zero
    /// multiple of the block size.
    fn cbc_encrypt(&self, iv: [u8; BLOCK], plaintext: &[u8]) -> Vec<u8> {
        let pad = BLOCK - plaintext.len() % BLOCK; // 1..=BLOCK: full block when aligned
        let mut out = Vec::with_capacity(plaintext.len() + pad);
        out.extend_from_slice(plaintext);
        out.extend(std::iter::repeat_n(pad as u8, pad));
        let mut chain = iv;
        for block in out.chunks_exact_mut(BLOCK) {
            for (byte, prev) in block.iter_mut().zip(chain) {
                *byte ^= prev;
            }
            let block: &mut [u8; BLOCK] = block.try_into().expect("chunks_exact");
            self.block.encrypt_block(block);
            chain = *block;
        }
        out
    }

    /// CBC-decrypt and unpad. Uniform failure: wrong-shape ciphertext and
    /// bad padding are indistinguishable.
    fn cbc_decrypt(&self, iv: [u8; BLOCK], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(BLOCK) {
            return Err(self.mode.decrypt_failed());
        }
        let mut out = ciphertext.to_vec();
        let mut chain = iv;
        for block in out.chunks_exact_mut(BLOCK) {
            let cipher_block: [u8; BLOCK] = (&*block).try_into().expect("chunks_exact");
            let block: &mut [u8; BLOCK] = block.try_into().expect("chunks_exact");
            self.block.decrypt_block(block);
            for (byte, prev) in block.iter_mut().zip(chain) {
                *byte ^= prev;
            }
            chain = cipher_block;
        }
        // PKCS#7 unpad, branch-free over the final block: accumulate the
        // verdict without early exits, so the check's timing does not
        // depend on which byte disagrees.
        let pad = out[out.len() - 1];
        let mut bad = u8::from(pad == 0) | u8::from(pad as usize > BLOCK);
        let clamped = if pad as usize > BLOCK || pad == 0 {
            1
        } else {
            pad as usize
        };
        for &byte in &out[out.len() - clamped..] {
            bad |= byte ^ pad;
        }
        if bad != 0 {
            return Err(self.mode.decrypt_failed());
        }
        out.truncate(out.len() - clamped);
        Ok(out)
    }

    /// The CTR keystream XOR (encrypt and decrypt are the same
    /// operation): the rightmost `counter_bits` of the counter block
    /// increment per block, wrapping within that width without carrying
    /// into the fixed portion (SP 800-38A / WebCrypto `AesCtrParams`
    /// semantics). A message needing more blocks than the counter space
    /// holds fails rather than reuse counter values.
    fn ctr_apply(
        &self,
        initial: [u8; BLOCK],
        counter_bits: u8,
        data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let blocks = data.len().div_ceil(BLOCK);
        if counter_bits < 64 && blocks as u64 > 1u64 << counter_bits {
            return Err(Error::Other(format!(
                "the message needs {blocks} blocks, more than the {counter_bits}-bit counter space"
            )));
        }
        let mut out = Vec::with_capacity(data.len());
        let mut counter = initial;
        for chunk in data.chunks(BLOCK) {
            let mut keystream = counter;
            self.block.encrypt_block(&mut keystream);
            out.extend(chunk.iter().zip(keystream).map(|(byte, ks)| byte ^ ks));
            increment_wrapping(&mut counter, &initial, counter_bits);
        }
        Ok(out)
    }
}

/// Increment the rightmost `bits` of `counter` as a big-endian integer,
/// wrapping within that width: the whole block increments with carry, then
/// the fixed (leftmost `128 - bits`) portion is restored from `initial`,
/// which discards exactly the carry out of the counter width.
fn increment_wrapping(counter: &mut [u8; BLOCK], initial: &[u8; BLOCK], bits: u8) {
    for byte in counter.iter_mut().rev() {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
    let fixed_bits = 128 - u32::from(bits);
    let fixed_bytes = (fixed_bits / 8) as usize;
    counter[..fixed_bytes].copy_from_slice(&initial[..fixed_bytes]);
    let partial = fixed_bits % 8;
    if partial != 0 {
        let mask = 0xffu8 << (8 - partial);
        counter[fixed_bytes] = (initial[fixed_bytes] & mask) | (counter[fixed_bytes] & !mask);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    fn policy() -> CipherPolicy {
        CipherPolicy {
            encrypt: true,
            decrypt: true,
            wrap: false,
            unwrap: false,
            extractable: true,
        }
    }

    fn key(mode: CipherMode, raw: &[u8]) -> CipherKeyMaterial {
        let variant = if raw.len() == 16 {
            crate::AesVariant::Aes128
        } else {
            crate::AesVariant::Aes256
        };
        CipherKeyMaterial::import(mode, variant, raw.to_vec(), policy()).unwrap()
    }

    // NIST SP 800-38A F.2.1/F.2.2 (CBC-AES128), with the PKCS#7 tail the
    // WebCrypto wire format appends to the block-aligned plaintext.
    #[test]
    fn cbc_nist_known_answer() {
        let key = key(CipherMode::Cbc, &hex!("2b7e151628aed2a6abf7158809cf4f3c"));
        let iv = hex!("000102030405060708090a0b0c0d0e0f");
        let plaintext = hex!(
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef"
            "f69f2445df4f9b17ad2b417be66c3710"
        );
        let expected_body = hex!(
            "7649abac8119b246cee98e9b12e9197d"
            "5086cb9b507219ee95db113a917678b2"
            "73bed6b8e3c1743b7116e69e22229516"
            "3ff1caa1681fac09120eca307586e1a7"
        );
        let sealed = key.encrypt(&iv, None, &plaintext).unwrap();
        assert_eq!(sealed.len(), plaintext.len() + 16);
        assert_eq!(&sealed[..plaintext.len()], expected_body);
        assert_eq!(key.decrypt(&iv, None, &sealed).unwrap(), plaintext);
    }

    #[test]
    fn cbc_decrypt_failures_are_uniform() {
        let key = key(CipherMode::Cbc, &[7; 32]);
        let iv = [0; 16];
        let uniform = Err(Error::Other("AES-CBC decryption failed".into()));
        // Empty, misaligned, and bad-padding ciphertexts are
        // indistinguishable.
        assert_eq!(key.decrypt(&iv, None, &[]), uniform);
        assert_eq!(key.decrypt(&iv, None, &[1; 15]), uniform);
        assert_eq!(key.decrypt(&iv, None, &[1; 16]), uniform);
    }

    #[test]
    fn cbc_pads_a_full_block_when_aligned() {
        let key = key(CipherMode::Cbc, &[9; 16]);
        let sealed = key.encrypt(&[1; 16], None, b"").unwrap();
        assert_eq!(sealed.len(), 16);
        assert_eq!(key.decrypt(&[1; 16], None, &sealed).unwrap(), b"");
    }

    // NIST SP 800-38A F.5.1 (CTR-AES128): the full 128-bit counter.
    #[test]
    fn ctr_nist_known_answer() {
        let key = key(CipherMode::Ctr, &hex!("2b7e151628aed2a6abf7158809cf4f3c"));
        let iv = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let plaintext = hex!(
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef"
            "f69f2445df4f9b17ad2b417be66c3710"
        );
        let expected = hex!(
            "874d6191b620e3261bef6864990db6ce"
            "9806f66b7970fdff8617187bb9fffdff"
            "5ae4df3edbd5d35e5b4f09020db03eab"
            "1e031dda2fbe03d1792170a0f3009cee"
        );
        let sealed = key.encrypt(&iv, Some(128), &plaintext).unwrap();
        assert_eq!(sealed, expected);
        assert_eq!(key.decrypt(&iv, Some(128), &sealed).unwrap(), plaintext);
    }

    #[test]
    fn ctr_counter_wraps_within_its_width() {
        // A 2-bit counter starting at 3 wraps to 0 without touching the
        // fixed portion: blocks use counters 3, 0, 1, 2.
        let key = key(CipherMode::Ctr, &[3; 16]);
        let mut iv = [0xabu8; 16];
        iv[15] = 0xff; // low 2 bits = 3
        let sealed = key.encrypt(&iv, Some(2), &[0; 64]).unwrap();

        // Reconstruct from single-block encryptions at the wrapped
        // counters.
        for (i, low) in [0xff, 0xfc, 0xfd, 0xfe].into_iter().enumerate() {
            let mut counter = [0xabu8; 16];
            counter[15] = low;
            let block = key.encrypt(&counter, Some(128), &[0; 16]).unwrap();
            assert_eq!(&sealed[i * 16..(i + 1) * 16], &block[..], "block {i}");
        }

        // And a message longer than the counter space fails.
        assert!(matches!(
            key.encrypt(&iv, Some(2), &[0; 80]),
            Err(Error::Other(_))
        ));
    }

    #[test]
    fn parameter_contract() {
        let cbc = key(CipherMode::Cbc, &[1; 16]);
        let ctr = key(CipherMode::Ctr, &[1; 16]);
        assert!(matches!(
            cbc.encrypt(&[0; 15], None, b"x"),
            Err(Error::InvalidNonce(_))
        ));
        assert!(matches!(
            cbc.encrypt(&[0; 16], Some(64), b"x"),
            Err(Error::InvalidNonce(_))
        ));
        assert!(matches!(
            ctr.encrypt(&[0; 16], None, b"x"),
            Err(Error::InvalidNonce(_))
        ));
        assert!(matches!(
            ctr.encrypt(&[0; 16], Some(129), b"x"),
            Err(Error::InvalidNonce(_))
        ));
    }

    #[test]
    fn jwk_round_trip_carries_the_mode_alg() {
        let key = key(CipherMode::Ctr, &[5; 32]);
        let jwk = key.export_jwk().unwrap();
        assert!(jwk.contains("A256CTR"), "{jwk}");
        let back = CipherKeyMaterial::import_jwk(
            CipherMode::Ctr,
            crate::AesVariant::Aes256,
            &jwk,
            policy(),
        )
        .unwrap();
        assert_eq!(back.export().unwrap(), key.export().unwrap());
        // The wrong mode's alg is rejected.
        assert!(matches!(
            CipherKeyMaterial::import_jwk(
                CipherMode::Cbc,
                crate::AesVariant::Aes256,
                &jwk,
                policy()
            ),
            Err(Error::InvalidKey(_))
        ));
    }
}
