//! Digest dispatch: the served SHA-2 variants, the checked-SHA-1
//! postures, digesting, and the HMAC operations keyed over SHA-2.

use sha1_checked::{CollisionResult, Digest as _};

use crate::{Error, Sha2Variant};

/// The served SHA-2 variants a key or digest can be bound to. Only the WIT
/// `sha2-variant` cases the Rust implementations serve appear here: the
/// truncated variants are declined at minting (see the WIT `sha2-variant`
/// doc).
#[derive(Clone, Copy, Debug)]
pub enum Sha2 {
    Sha256,
    Sha384,
    Sha512,
}

/// The served [`Sha2`] for a WIT `sha2-variant`, or `unsupported` for one
/// the Rust implementations decline (the truncated variants; see the WIT
/// `sha2-variant` doc). Shared by the `sha2` and `hmac-sha2` minting paths.
pub fn served_sha2(variant: Sha2Variant) -> Result<Sha2, Error> {
    match variant {
        Sha2Variant::Sha256 => Ok(Sha2::Sha256),
        Sha2Variant::Sha384 => Ok(Sha2::Sha384),
        Sha2Variant::Sha512 => Ok(Sha2::Sha512),
        Sha2Variant::Sha224 | Sha2Variant::Sha512224 | Sha2Variant::Sha512256 => Err(
            Error::Unsupported(format!("{variant:?} is not served by this implementation")),
        ),
    }
}

/// The hash an HMAC-family construction (HMAC, HKDF, PBKDF2) is keyed
/// over: SHA-1 or a served SHA-2 variant. SHA-1 appears here and nowhere
/// else outside `sha1-checked` — the constructions run the hash
/// internally, where collision resistance is not load-bearing and no
/// digest is exposed (see the WIT `hmac-sha1` doc).
#[derive(Clone, Copy, Debug)]
pub enum HmacHash {
    Sha1,
    Sha2(Sha2),
}

/// One-shot HMAC over `data` with `key` material, for the concrete HMAC
/// type `M`. Infallible: HMAC accepts key material of any length
/// (longer-than-block keys are hashed first), so setup cannot fail for
/// material accepted at import/generation time.
fn hmac_tag<M: hmac::Mac + hmac::digest::KeyInit>(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut hmac = <M as hmac::Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    hmac.update(data);
    hmac.finalize().into_bytes().to_vec()
}

/// One-shot HMAC verification of `tag` over `data`, for the concrete HMAC
/// type `M`.
fn hmac_check<M: hmac::Mac + hmac::digest::KeyInit>(
    key: &[u8],
    data: &[u8],
    tag: &[u8],
) -> Result<(), Error> {
    let mut hmac = <M as hmac::Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    hmac.update(data);
    // `verify_slice` compares in constant time, per the WIT contract.
    hmac.verify_slice(tag)
        .map_err(|_| Error::AuthenticationFailed)
}

impl HmacHash {
    /// The hash name (`mac-key.algorithm-hash`, and the KDF inputs'
    /// diagnostics).
    pub fn hash_name(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA-1",
            Self::Sha2(variant) => variant.hash_name(),
        }
    }

    /// The underlying hash's block length in bytes (the length of a
    /// generated HMAC key, per WebCrypto's `generateKey` default).
    pub(crate) fn block_len(self) -> usize {
        match self {
            Self::Sha1 => 64,
            Self::Sha2(variant) => variant.block_len(),
        }
    }

    /// One-shot HMAC over `data` with `key` material. See
    /// [`Sha2::hmac_sign`].
    pub(crate) fn hmac_sign(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => hmac_tag::<hmac::Hmac<sha1::Sha1>>(key, data),
            Self::Sha2(variant) => variant.hmac_sign(key, data),
        }
    }

    /// One-shot constant-time HMAC verification. See [`Sha2::hmac_verify`].
    pub(crate) fn hmac_verify(self, key: &[u8], data: &[u8], tag: &[u8]) -> Result<(), Error> {
        match self {
            Self::Sha1 => hmac_check::<hmac::Hmac<sha1::Sha1>>(key, data, tag),
            Self::Sha2(variant) => variant.hmac_verify(key, data, tag),
        }
    }
}

/// The algorithm a `digest` resource is bound to: a served SHA-2 variant,
/// or checked SHA-1 in one of its collision postures (the `sha1-checked`
/// minting interface; plain SHA-1 is deliberately unrepresentable).
#[derive(Clone, Copy, Debug)]
pub enum DigestKind {
    Sha2(Sha2),
    Sha1Checked(Sha1Posture),
}

/// What a checked-SHA-1 digest does when collision detection fires: the
/// posture each `sha1-checked` constructor binds.
#[derive(Clone, Copy, Debug)]
pub enum Sha1Posture {
    /// `make-rejecting-digest`: fail with the `collision-detected`
    /// extension condition.
    Reject,
    /// `make-mitigating-digest`: return the deterministic sha1dc safe
    /// hash.
    Mitigate,
}

impl DigestKind {
    /// The digest's `algorithm-name` (the registry hash name).
    pub fn hash_name(self) -> &'static str {
        match self {
            Self::Sha2(variant) => variant.hash_name(),
            Self::Sha1Checked(_) => "SHA-1",
        }
    }

    /// One-shot digest of `data`, applying the bound posture's
    /// collision behavior for checked SHA-1.
    pub fn digest(self, data: &[u8]) -> Result<Vec<u8>, Error> {
        match self {
            Self::Sha2(variant) => Ok(variant.digest(data)),
            Self::Sha1Checked(posture) => sha1_checked_digest(posture, data),
        }
    }
}

/// Checked SHA-1 over `data`: standard SHA-1 for honest input; for input
/// carrying a collision attack pattern, the posture decides — the sha1dc
/// safe hash (deterministic, so parties agree on it) or the
/// `collision-detected` extension error.
fn sha1_checked_digest(posture: Sha1Posture, data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut hasher = sha1_checked::Sha1::new();
    hasher.update(data);
    match (posture, hasher.try_finalize()) {
        (_, CollisionResult::Ok(digest)) => Ok(digest.to_vec()),
        (Sha1Posture::Mitigate, CollisionResult::Mitigated(digest)) => Ok(digest.to_vec()),
        // `Collision` carries the unmitigated digest and is only produced
        // with the safe hash disabled, which this hasher never is; treat
        // it as detection all the same, never as output.
        (Sha1Posture::Mitigate, CollisionResult::Collision(_))
        | (Sha1Posture::Reject, CollisionResult::Mitigated(_) | CollisionResult::Collision(_)) => {
            Err(Error::collision_detected())
        }
    }
}

impl Sha2 {
    /// The hash name (WebCrypto's `HmacKeyAlgorithm.hash`, and a `digest`'s
    /// `algorithm-name`).
    pub fn hash_name(self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
        }
    }

    /// The underlying hash's block length in bytes (the length of a
    /// generated HMAC key, per WebCrypto's `generateKey` default).
    pub(crate) fn block_len(self) -> usize {
        match self {
            Self::Sha256 => 64,
            Self::Sha384 | Self::Sha512 => 128,
        }
    }

    /// One-shot digest of `data`.
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        fn hash<D: sha2::Digest>(data: &[u8]) -> Vec<u8> {
            D::digest(data).to_vec()
        }
        match self {
            Self::Sha256 => hash::<sha2::Sha256>(data),
            Self::Sha384 => hash::<sha2::Sha384>(data),
            Self::Sha512 => hash::<sha2::Sha512>(data),
        }
    }

    /// One-shot HMAC over `data` with `key` material. Infallible: see
    /// [`hmac_tag`].
    pub(crate) fn hmac_sign(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => hmac_tag::<hmac::Hmac<sha2::Sha256>>(key, data),
            Self::Sha384 => hmac_tag::<hmac::Hmac<sha2::Sha384>>(key, data),
            Self::Sha512 => hmac_tag::<hmac::Hmac<sha2::Sha512>>(key, data),
        }
    }

    /// One-shot constant-time HMAC verification of `tag` over `data`.
    pub(crate) fn hmac_verify(self, key: &[u8], data: &[u8], tag: &[u8]) -> Result<(), Error> {
        match self {
            Self::Sha256 => hmac_check::<hmac::Hmac<sha2::Sha256>>(key, data, tag),
            Self::Sha384 => hmac_check::<hmac::Hmac<sha2::Sha384>>(key, data, tag),
            Self::Sha512 => hmac_check::<hmac::Hmac<sha2::Sha512>>(key, data, tag),
        }
    }
}

#[cfg(test)]
mod tests {
    use data_encoding::HEXLOWER;
    use data_encoding_macro::hexlower;

    use super::*;

    #[test]
    fn truncated_variants_are_unsupported() {
        for variant in [
            Sha2Variant::Sha224,
            Sha2Variant::Sha512224,
            Sha2Variant::Sha512256,
        ] {
            match served_sha2(variant) {
                Err(Error::Unsupported(msg)) => {
                    assert_eq!(
                        msg,
                        format!("{variant:?} is not served by this implementation")
                    )
                }
                other => panic!("expected unsupported, got {other:?}"),
            }
        }
        assert!(served_sha2(Sha2Variant::Sha256).is_ok());
    }

    /// FIPS 180-4's "abc" known answer pins the digest dispatch.
    #[test]
    fn sha256_known_answer() {
        let md = Sha2::Sha256.digest(b"abc");
        assert_eq!(
            md,
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }

    // The SHAttered colliding pair's first five blocks (bytes 0..320 of
    // each PDF, from https://shattered.io): each half independently
    // carries the attack's disturbance-vector pattern, and the two halves
    // collide under plain SHA-1.
    const SHATTERED_1: &str = "255044462d312e330a25e2e3cfd30a0a0a312030206f626a0a3c3c2f57696474682032203020522f4865696768742033203020522f547970652034203020522f537562747970652035203020522f46696c7465722036203020522f436f6c6f7253706163652037203020522f4c656e6774682038203020522f42697473506572436f6d706f6e656e7420383e3e0a73747265616d0affd8fffe00245348412d3120697320646561642121212121852fec092339759c39b1a1c63c4c97e1fffe017346dc9166b67e118f029ab621b2560ff9ca67cca8c7f85ba84c79030c2b3de218f86db3a90901d5df45c14f26fedfb3dc38e96ac22fe7bd728f0e45bce046d23c570feb141398bb552ef5a0a82be331fea48037b8b5d71f0e332edf93ac3500eb4ddc0decc1a864790c782c76215660dd309791d06bd0af3f98cda4bc4629b1";
    const SHATTERED_2: &str = "255044462d312e330a25e2e3cfd30a0a0a312030206f626a0a3c3c2f57696474682032203020522f4865696768742033203020522f547970652034203020522f537562747970652035203020522f46696c7465722036203020522f436f6c6f7253706163652037203020522f4c656e6774682038203020522f42697473506572436f6d706f6e656e7420383e3e0a73747265616d0affd8fffe00245348412d3120697320646561642121212121852fec092339759c39b1a1c63c4c97e1fffe017f46dc93a6b67e013b029aaa1db2560b45ca67d688c7f84b8c4c791fe02b3df614f86db1690901c56b45c1530afedfb76038e972722fe7ad728f0e4904e046c230570fe9d41398abe12ef5bc942be33542a4802d98b5d70f2a332ec37fac3514e74ddc0f2cc1a874cd0c78305a21566461309789606bd0bf3f98cda8044629a1";

    #[test]
    fn sha1_checked_honest_input_is_standard_sha1() {
        // FIPS 180-1 "abc" known answer, identical in both postures.
        let expected = hexlower!("a9993e364706816aba3e25717850c26c9cd0d89d");
        for posture in [Sha1Posture::Reject, Sha1Posture::Mitigate] {
            let kind = DigestKind::Sha1Checked(posture);
            assert_eq!(kind.digest(b"abc").unwrap(), expected);
            assert_eq!(kind.hash_name(), "SHA-1");
        }
    }

    #[test]
    fn sha1_checked_postures_on_the_shattered_pair() {
        let m1 = unhex(SHATTERED_1);
        let m2 = unhex(SHATTERED_2);

        // The rejecting posture names the condition.
        for m in [&m1, &m2] {
            assert_eq!(
                DigestKind::Sha1Checked(Sha1Posture::Reject).digest(m),
                Err(Error::collision_detected())
            );
        }

        // The mitigating posture returns the deterministic safe hash —
        // and the colliding pair no longer collides under it.
        let mitigate = DigestKind::Sha1Checked(Sha1Posture::Mitigate);
        let d1 = mitigate.digest(&m1).unwrap();
        let d2 = mitigate.digest(&m2).unwrap();
        assert_eq!(d1, hexlower!("7117b3cb9225aaf0d8ef1a40e493957b0bf8693d"));
        assert_eq!(d2, hexlower!("29f38ae9fd98e2931120fa0bf213e024250d3f6a"));
        assert_ne!(d1, d2);
    }

    fn unhex(hex: &str) -> Vec<u8> {
        HEXLOWER.decode(hex.as_bytes()).unwrap()
    }

    #[test]
    fn hmac_sign_verify_round_trip() {
        let tag = Sha2::Sha256.hmac_sign(b"key", b"message");
        assert!(Sha2::Sha256.hmac_verify(b"key", b"message", &tag).is_ok());
        assert_eq!(
            Sha2::Sha256.hmac_verify(b"key", b"tampered", &tag),
            Err(Error::AuthenticationFailed)
        );
    }
}
