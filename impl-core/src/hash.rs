//! SHA-2 dispatch: the served variants, digesting, and the HMAC operations
//! keyed over them.

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

    /// One-shot HMAC over `data` with `key` material. Infallible: HMAC
    /// accepts key material of any length (longer-than-block keys are
    /// hashed first), so setup cannot fail for material accepted at
    /// import/generation time.
    pub(crate) fn hmac_sign(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        fn tag<M: hmac::Mac + hmac::digest::KeyInit>(key: &[u8], data: &[u8]) -> Vec<u8> {
            let mut hmac =
                <M as hmac::Mac>::new_from_slice(key).expect("HMAC accepts any key length");
            hmac.update(data);
            hmac.finalize().into_bytes().to_vec()
        }
        match self {
            Self::Sha256 => tag::<hmac::Hmac<sha2::Sha256>>(key, data),
            Self::Sha384 => tag::<hmac::Hmac<sha2::Sha384>>(key, data),
            Self::Sha512 => tag::<hmac::Hmac<sha2::Sha512>>(key, data),
        }
    }

    /// One-shot constant-time HMAC verification of `tag` over `data`.
    pub(crate) fn hmac_verify(self, key: &[u8], data: &[u8], tag: &[u8]) -> Result<(), Error> {
        fn check<M: hmac::Mac + hmac::digest::KeyInit>(
            key: &[u8],
            data: &[u8],
            tag: &[u8],
        ) -> Result<(), Error> {
            let mut hmac =
                <M as hmac::Mac>::new_from_slice(key).expect("HMAC accepts any key length");
            hmac.update(data);
            // `verify_slice` compares in constant time, per the WIT contract.
            hmac.verify_slice(tag)
                .map_err(|_| Error::AuthenticationFailed)
        }
        match self {
            Self::Sha256 => check::<hmac::Hmac<sha2::Sha256>>(key, data, tag),
            Self::Sha384 => check::<hmac::Hmac<sha2::Sha384>>(key, data, tag),
            Self::Sha512 => check::<hmac::Hmac<sha2::Sha512>>(key, data, tag),
        }
    }
}

#[cfg(test)]
mod tests {
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
