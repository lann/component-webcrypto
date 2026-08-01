//! The RFC 8410 DER forms (Ed25519, X25519): SubjectPublicKeyInfo and
//! version-0 PrivateKeyInfo over 32-byte keys.
//!
//! The EC algorithms ride their curve crates' own encoders; these two
//! families are assembled here because the interchange form every platform
//! imports is the *v1* PrivateKeyInfo (the seed alone, RFC 8410 §7), while
//! the crates' encoders write v2 keypairs.

use der::asn1::{BitStringRef, OctetStringRef};
use der::{Decode as _, Encode as _};
use pkcs8::{AlgorithmIdentifierRef, PrivateKeyInfo};
use spki::SubjectPublicKeyInfoRef;
use zeroize::Zeroizing;

use crate::Error;

/// RFC 8410 algorithm identifiers.
pub const OID_X25519: pkcs8::ObjectIdentifier = pkcs8::ObjectIdentifier::new_unwrap("1.3.101.110");
pub const OID_ED25519: pkcs8::ObjectIdentifier = pkcs8::ObjectIdentifier::new_unwrap("1.3.101.112");

/// Build the SubjectPublicKeyInfo for a 32-byte RFC 8410 public key.
pub fn rfc8410_spki(oid: pkcs8::ObjectIdentifier, key: &[u8; 32]) -> Vec<u8> {
    let spki = SubjectPublicKeyInfoRef {
        algorithm: AlgorithmIdentifierRef {
            oid,
            parameters: None,
        },
        subject_public_key: BitStringRef::from_bytes(key).expect("32 bytes fit a BIT STRING"),
    };
    spki.to_der().expect("fixed-shape DER cannot fail")
}

/// Parse a SubjectPublicKeyInfo, requiring the declared RFC 8410 algorithm
/// and a 32-byte key (every failure is `invalid-key`).
pub fn parse_rfc8410_spki(
    oid: pkcs8::ObjectIdentifier,
    what: &str,
    spki: &[u8],
) -> Result<[u8; 32], Error> {
    let info = SubjectPublicKeyInfoRef::from_der(spki).map_err(|err| {
        Error::InvalidKey(format!("{what}: malformed SubjectPublicKeyInfo: {err}"))
    })?;
    if info.algorithm.oid != oid {
        return Err(Error::InvalidKey(format!(
            "{what}: SubjectPublicKeyInfo algorithm is {}, not {oid}",
            info.algorithm.oid
        )));
    }
    let raw = info.subject_public_key.as_bytes().ok_or_else(|| {
        Error::InvalidKey(format!("{what}: public key bits are not byte-aligned"))
    })?;
    raw.try_into().map_err(|_| {
        Error::InvalidKey(format!(
            "{what}: public keys are 32 bytes, got {} bytes",
            raw.len()
        ))
    })
}

/// Build the version-0 PrivateKeyInfo (RFC 8410 §7: the 32-byte key inside
/// a CurvePrivateKey OCTET STRING) — the v1 form every platform imports.
pub fn rfc8410_pkcs8(oid: pkcs8::ObjectIdentifier, key: &[u8; 32]) -> Zeroizing<Vec<u8>> {
    let curve_private = OctetStringRef::new(key)
        .expect("32 bytes fit an OCTET STRING")
        .to_der()
        .expect("fixed-shape DER cannot fail");
    let info = PrivateKeyInfo {
        algorithm: AlgorithmIdentifierRef {
            oid,
            parameters: None,
        },
        private_key: &curve_private,
        public_key: None,
    };
    let out = Zeroizing::new(info.to_der().expect("fixed-shape DER cannot fail"));
    // `curve_private` holds the seed too; scrub it before it drops.
    drop(Zeroizing::new(curve_private));
    out
}

/// Parse a PrivateKeyInfo, requiring the declared RFC 8410 algorithm and a
/// 32-byte CurvePrivateKey (every failure is `invalid-key`). A v2 public
/// key, when present, is ignored: the imported key's identity is the
/// seed's, exactly as the JWK imports treat `x`.
pub fn parse_rfc8410_pkcs8(
    oid: pkcs8::ObjectIdentifier,
    what: &str,
    pkcs8_der: &[u8],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let info = PrivateKeyInfo::from_der(pkcs8_der)
        .map_err(|err| Error::InvalidKey(format!("{what}: malformed PrivateKeyInfo: {err}")))?;
    if info.algorithm.oid != oid {
        return Err(Error::InvalidKey(format!(
            "{what}: PrivateKeyInfo algorithm is {}, not {oid}",
            info.algorithm.oid
        )));
    }
    let curve_private = OctetStringRef::from_der(info.private_key)
        .map_err(|err| Error::InvalidKey(format!("{what}: malformed CurvePrivateKey: {err}")))?;
    let raw = curve_private.as_bytes();
    let mut out = Zeroizing::new([0u8; 32]);
    if raw.len() != 32 {
        return Err(Error::InvalidKey(format!(
            "{what}: private keys are 32 bytes, got {} bytes",
            raw.len()
        )));
    }
    out.copy_from_slice(raw);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc8410_round_trips() {
        let key = [7u8; 32];
        for oid in [OID_X25519, OID_ED25519] {
            let spki = rfc8410_spki(oid, &key);
            assert_eq!(parse_rfc8410_spki(oid, "test", &spki).unwrap(), key);
            let pkcs8_der = rfc8410_pkcs8(oid, &key);
            assert_eq!(*parse_rfc8410_pkcs8(oid, "test", &pkcs8_der).unwrap(), key);
        }
        // Wrong algorithm is rejected in both directions.
        let spki = rfc8410_spki(OID_X25519, &key);
        assert!(matches!(
            parse_rfc8410_spki(OID_ED25519, "test", &spki),
            Err(Error::InvalidKey(_))
        ));
        let p8 = rfc8410_pkcs8(OID_ED25519, &key);
        assert!(matches!(
            parse_rfc8410_pkcs8(OID_X25519, "test", &p8),
            Err(Error::InvalidKey(_))
        ));
        assert!(matches!(
            parse_rfc8410_pkcs8(OID_X25519, "test", b"garbage"),
            Err(Error::InvalidKey(_))
        ));
    }
}
