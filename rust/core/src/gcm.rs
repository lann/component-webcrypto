//! The general GCM path: AES-GCM over the contract's 12–128-byte nonce
//! window and any tag size in the algorithm's set — the parameter space
//! `aead-key.seal`/`open` accept and the `aes-gcm` minting interface
//! documents, which the `aes-gcm` crate's type-level parameterization
//! cannot express at runtime.
//!
//! GCM is assembled per NIST SP 800-38D from the same primitives the
//! `aes-gcm` crate composes: `ghash` (masked-multiply universal hash) and
//! `ctr` over the fixsliced `aes`, so the timing-channel classification is
//! unchanged (see lann-webcrypto-guest-provider's README). The standard-parameter path
//! (96-bit nonce, 16-byte tag) does not come through here: callers route
//! it to the `aes-gcm` crate, and the unit tests pin this module to the
//! crate's output on the shared parameter point.
//!
//! Every byte of the algorithm is SP 800-38D §7:
//!
//! - `H = CIPH_K(0^128)`, the GHASH key;
//! - `J0`: for 96-bit nonces, `nonce ‖ 0^31 ‖ 1`; otherwise
//!   `GHASH_H(nonce ‖ pad ‖ 0^64 ‖ [len(nonce)]_64)` (§7.1 step 2);
//! - ciphertext: CTR-32 keystream starting at `inc32(J0)`;
//! - tag: `GHASH_H(aad ‖ pad ‖ ct ‖ pad ‖ [len(aad)]_64 ‖ [len(ct)]_64)`
//!   encrypted with `CIPH_K(J0)`, truncated to the requested size.

use aes::cipher::consts::U16;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockCipher, BlockEncrypt, InnerIvInit, StreamCipher, StreamCipherSeek};
use ghash::universal_hash::{KeyInit as _, UniversalHash};
use ghash::GHash;
use subtle::ConstantTimeEq as _;

use crate::Error;

/// One 16-byte block in the block cipher's array type.
type Block = GenericArray<u8, U16>;

/// The GCM tag sizes in bytes (SP 800-38D §5.2.1.2 and the WebCrypto
/// registry's 32–128-bit set, which agree).
pub const GCM_TAG_SIZES: [u8; 7] = [4, 8, 12, 13, 14, 15, 16];

/// Validate a per-call tag size against [`GCM_TAG_SIZES`], resolving
/// `None` to the 16-byte default.
pub fn check_tag_size(tag_size: Option<u8>) -> Result<usize, Error> {
    let size = tag_size.unwrap_or(16);
    if GCM_TAG_SIZES.contains(&size) {
        Ok(usize::from(size))
    } else {
        Err(Error::Unsupported(format!(
            "AES-GCM does not define {size}-byte tags; the set is 4, 8, 12, 13, 14, 15, or 16",
        )))
    }
}

/// An AES cipher for the general path, keyed per call from the retained
/// material (the schedule is zeroized on drop — the `aes` crate's
/// `zeroize` feature).
// Each variant is an expanded key schedule; the size skew between the
// AES-128 and AES-256 schedules is inherent, and the value lives only for
// the duration of one call.
#[allow(clippy::large_enum_variant)]
pub enum GcmAes {
    Aes128(aes::Aes128),
    Aes256(aes::Aes256),
}

impl GcmAes {
    /// Key a cipher from raw material (16 or 32 bytes; minting fixed the
    /// length).
    pub fn new(raw: &[u8]) -> Option<Self> {
        use aes::cipher::KeyInit as _;
        match raw.len() {
            16 => Some(Self::Aes128(
                aes::Aes128::new_from_slice(raw).expect("length matched"),
            )),
            32 => Some(Self::Aes256(
                aes::Aes256::new_from_slice(raw).expect("length matched"),
            )),
            _ => None,
        }
    }

    /// [`seal`] over whichever variant this is.
    pub fn seal(&self, nonce: &[u8], aad: &[u8], tag_len: usize, msg: &[u8]) -> Vec<u8> {
        match self {
            Self::Aes128(c) => seal(c, nonce, aad, tag_len, msg),
            Self::Aes256(c) => seal(c, nonce, aad, tag_len, msg),
        }
    }

    /// [`open`] over whichever variant this is.
    pub fn open(
        &self,
        nonce: &[u8],
        aad: &[u8],
        tag_len: usize,
        msg: &[u8],
    ) -> Result<Vec<u8>, Error> {
        match self {
            Self::Aes128(c) => open(c, nonce, aad, tag_len, msg),
            Self::Aes256(c) => open(c, nonce, aad, tag_len, msg),
        }
    }
}

/// Encrypt and authenticate `msg`, returning `ciphertext ‖ tag` with a
/// `tag_len`-byte tag. Callers validate the nonce (the contract's
/// 12–128-byte window) and `tag_len` (in [`GCM_TAG_SIZES`]); the §7.1
/// assembly itself is length-generic.
pub fn seal<C: BlockEncrypt + BlockCipher<BlockSize = U16>>(
    cipher: &C,
    nonce: &[u8],
    aad: &[u8],
    tag_len: usize,
    msg: &[u8],
) -> Vec<u8> {
    let (ghash, j0) = init(cipher, nonce);
    let mut keystream = keystream(cipher, &j0);

    let mut out = msg.to_vec();
    keystream.seek(16u64); // the first block, CIPH_K(J0), is the tag mask
    keystream.apply_keystream(&mut out);

    let full_tag = tag(cipher, ghash, &j0, aad, &out);
    out.extend_from_slice(&full_tag[..tag_len]);
    out
}

/// Decrypt and verify `msg` (`ciphertext ‖ tag`, with a `tag_len`-byte
/// tag). Any failure — input shorter than the tag, tag mismatch — reports
/// `authentication-failed` with no detail, and no plaintext is produced
/// before the tag verifies.
pub fn open<C: BlockEncrypt + BlockCipher<BlockSize = U16>>(
    cipher: &C,
    nonce: &[u8],
    aad: &[u8],
    tag_len: usize,
    msg: &[u8],
) -> Result<Vec<u8>, Error> {
    if msg.len() < tag_len {
        return Err(Error::AuthenticationFailed);
    }
    let (ct, presented_tag) = msg.split_at(msg.len() - tag_len);

    let (ghash, j0) = init(cipher, nonce);
    let full_tag = tag(cipher, ghash, &j0, aad, ct);
    if !bool::from(full_tag[..tag_len].ct_eq(presented_tag)) {
        return Err(Error::AuthenticationFailed);
    }

    let mut out = ct.to_vec();
    let mut keystream = keystream(cipher, &j0);
    keystream.seek(16u64);
    keystream.apply_keystream(&mut out);
    Ok(out)
}

/// Derive the GHASH instance and `J0` for `nonce` (SP 800-38D §7.1 steps
/// 1–2).
fn init<C: BlockEncrypt + BlockCipher<BlockSize = U16>>(
    cipher: &C,
    nonce: &[u8],
) -> (GHash, Block) {
    let mut h = Block::default();
    cipher.encrypt_block(&mut h);
    let ghash = GHash::new(ghash::Key::from_slice(h.as_slice()));

    let mut j0 = Block::default();
    if nonce.len() == 12 {
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;
    } else {
        let mut deriver = ghash.clone();
        deriver.update_padded(nonce);
        let mut lens = [0u8; 16];
        lens[8..].copy_from_slice(&(nonce.len() as u64 * 8).to_be_bytes());
        deriver.update(&[*ghash::Block::from_slice(&lens)]);
        j0 = *Block::from_slice(deriver.finalize().as_slice());
    }
    (ghash, j0)
}

/// The CTR-32 keystream over the counter blocks starting at `J0` (block 0
/// is `CIPH_K(J0)`, the tag mask; data begins at block 1 = `inc32(J0)`).
fn keystream<'c, C: BlockEncrypt + BlockCipher<BlockSize = U16>>(
    cipher: &'c C,
    j0: &Block,
) -> ctr::Ctr32BE<&'c C> {
    ctr::Ctr32BE::from_core(ctr::CtrCore::inner_iv_init(cipher, j0))
}

/// The full 16-byte tag over `aad` and `ct` (SP 800-38D §7.1 steps 5–6).
fn tag<C: BlockEncrypt + BlockCipher<BlockSize = U16>>(
    cipher: &C,
    mut ghash: GHash,
    j0: &Block,
    aad: &[u8],
    ct: &[u8],
) -> [u8; 16] {
    ghash.update_padded(aad);
    ghash.update_padded(ct);
    let mut lens = [0u8; 16];
    lens[..8].copy_from_slice(&(aad.len() as u64 * 8).to_be_bytes());
    lens[8..].copy_from_slice(&(ct.len() as u64 * 8).to_be_bytes());
    ghash.update(&[*ghash::Block::from_slice(&lens)]);
    let mut tag: [u8; 16] = ghash.finalize().into();

    let mut mask = *j0;
    cipher.encrypt_block(&mut mask);
    for (t, m) in tag.iter_mut().zip(mask) {
        *t ^= m;
    }
    tag
}

#[cfg(test)]
mod tests {
    use aes::cipher::KeyInit as _;
    use aes::{Aes128, Aes256};

    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Wycheproof aes_gcm_test.json tcId 68 (64-bit IV): the non-96-bit
    /// `J0` derivation against an independent source.
    #[test]
    fn wycheproof_64_bit_iv() {
        let cipher = Aes128::new_from_slice(&hex("aa023d0478dcb2b2312498293d9a9129")).unwrap();
        let nonce = hex("0432bc49ac344120");
        let aad = hex("aac39231129872a2");
        let msg = hex("2035af313d1346ab00154fea78322105");
        let want_ct = hex("64c36bb3b732034e3a7d04efc5197785");
        let want_tag = hex("b7d0dd70b00d65b97cfd080ff4b819d1");

        let sealed = seal(&cipher, &nonce, &aad, 16, &msg);
        assert_eq!(sealed[..msg.len()], want_ct[..]);
        assert_eq!(sealed[msg.len()..], want_tag[..]);
        assert_eq!(open(&cipher, &nonce, &aad, 16, &sealed).unwrap(), msg);
    }

    /// Wycheproof aes_gcm_test.json tcId 71 (128-bit IV, empty-free
    /// aad/msg variant) — a second independent point on the derivation.
    #[test]
    fn wycheproof_128_bit_iv() {
        let cipher = Aes128::new_from_slice(&hex("2034a82547276c83dd3212a813572bce")).unwrap();
        let nonce = hex("3254202d854734812398127a3d134421");
        let aad = hex("1a0293d8f90219058902139013908190bc490890d3ff12a3");
        let msg = hex("02efd2e5782312827ed5d230189a2a342b277ce048462193");
        let want_ct = hex("64069c2d58690561f27ee199e6b479b6369eec688672bde9");
        let want_tag = hex("9b7abadd6e69c1d9ec925786534f5075");

        let sealed = seal(&cipher, &nonce, &aad, 16, &msg);
        assert_eq!(sealed[..msg.len()], want_ct[..]);
        assert_eq!(sealed[msg.len()..], want_tag[..]);
    }

    /// On the standard parameter point this module agrees with the
    /// `aes-gcm` crate, which serves that path in production: the two
    /// implementations pin each other.
    #[test]
    fn agrees_with_the_aes_gcm_crate_at_the_standard_point() {
        use aes_gcm::aead::{Aead as _, Payload};
        use aes_gcm::Aes256Gcm;

        let key = [7u8; 32];
        let nonce = [9u8; 12];
        let crate_sealed = Aes256Gcm::new_from_slice(&key)
            .unwrap()
            .encrypt(
                aes_gcm::Nonce::from_slice(&nonce),
                Payload {
                    msg: b"cross-check",
                    aad: b"aad",
                },
            )
            .unwrap();
        let cipher = Aes256::new_from_slice(&key).unwrap();
        assert_eq!(
            seal(&cipher, &nonce, b"aad", 16, b"cross-check"),
            crate_sealed
        );
    }

    /// A truncated GCM tag is the prefix of the full tag: seal at every
    /// size in the set, verify each opens, and that the same bytes fail at
    /// a different declared size or with a flipped bit.
    #[test]
    fn truncated_tags_round_trip_and_fail_closed() {
        let cipher = Aes256::new_from_slice(&[3u8; 32]).unwrap();
        let full = seal(&cipher, &[5u8; 12], b"aad", 16, b"msg");
        for &size in &GCM_TAG_SIZES {
            let tag_len = usize::from(size);
            let mut sealed = full[..b"msg".len()].to_vec();
            sealed.extend_from_slice(&full[b"msg".len()..b"msg".len() + tag_len]);
            assert_eq!(
                open(&cipher, &[5u8; 12], b"aad", tag_len, &sealed).unwrap(),
                b"msg"
            );
            if tag_len < 16 {
                assert_eq!(
                    open(&cipher, &[5u8; 12], b"aad", 16, &sealed),
                    Err(Error::AuthenticationFailed)
                );
            }
            let mut tampered = sealed.clone();
            *tampered.last_mut().unwrap() ^= 1;
            assert_eq!(
                open(&cipher, &[5u8; 12], b"aad", tag_len, &tampered),
                Err(Error::AuthenticationFailed)
            );
        }
    }

    #[test]
    fn tag_size_set_is_enforced() {
        assert_eq!(check_tag_size(None), Ok(16));
        assert_eq!(check_tag_size(Some(4)), Ok(4));
        assert_eq!(check_tag_size(Some(13)), Ok(13));
        assert!(matches!(
            check_tag_size(Some(0)),
            Err(Error::Unsupported(_))
        ));
        assert!(matches!(
            check_tag_size(Some(5)),
            Err(Error::Unsupported(_))
        ));
        assert!(matches!(
            check_tag_size(Some(17)),
            Err(Error::Unsupported(_))
        ));
    }

    /// Input shorter than the declared tag fails closed.
    #[test]
    fn short_input_fails_closed() {
        let cipher = Aes128::new_from_slice(&[1u8; 16]).unwrap();
        assert_eq!(
            open(&cipher, &[2u8; 12], b"", 16, b"short"),
            Err(Error::AuthenticationFailed)
        );
    }
}
