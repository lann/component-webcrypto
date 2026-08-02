//! The JWK carrier: RFC 7517 `oct`-key and RFC 8037 OKP-key parse and
//! build, shared by every `import-key-jwk`/`export-key-jwk` implementation
//! so the two Rust implementations cannot diverge on it.
//!
//! The package-wide contract lives on `mac.mac-key.export-key-jwk` in the
//! WIT. The load-bearing choices, restated where they are implemented:
//!
//! - JSON parses through [`serde_json::Value`], whose duplicate-member
//!   handling is last-wins — the `JSON.parse` semantics the contract pins,
//!   so adversarial JWKs behave identically here and on platform-backed
//!   hosts.
//! - `k` decodes as strict unpadded base64url: padding, non-alphabet
//!   bytes, and non-zero trailing bits are all `invalid-key` (OKP's `x`
//!   and `d` likewise).
//! - `use` and `key_ops` are ignored on the import path (the package has
//!   no usage model; the caller holds the JWK); the unwrap path validates
//!   them in the caller's stead ([`check_unwrap_members`]). `ext` is
//!   validated against the requested extractability everywhere.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::Value;

use crate::Error;

/// The `use`-member family an unwrap-path JWK must match when the member
/// is present (the WIT JWK contract's unwrap-path rule).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UseFamily {
    /// Encryption, wrapping, and agreement keys: `"enc"`.
    Enc,
    /// MAC and signature keys: `"sig"`.
    Sig,
}

impl UseFamily {
    fn member(self) -> &'static str {
        match self {
            Self::Enc => "enc",
            Self::Sig => "sig",
        }
    }
}

/// The unwrap-path `use`/`key_ops` checks (the WIT JWK contract): a
/// `key_ops` member, when present, must include every granted usage; a
/// `use` member, when present, must match the key's family. Every failure
/// is `invalid-key` with a fixed message — the JWK is decrypted material
/// the caller must never see, so nothing from it reaches the error string.
pub fn check_unwrap_members(
    jwk: &str,
    granted: &[&'static str],
    family: UseFamily,
) -> Result<(), Error> {
    // A malformed envelope falls to the reused import path's parse, whose
    // message the unwrap mints redact; only well-formed objects are
    // checked here.
    let Ok(Value::Object(jwk)) = serde_json::from_str::<Value>(jwk) else {
        return Ok(());
    };
    match jwk.get("use") {
        None => {}
        Some(Value::String(member)) if member == family.member() => {}
        Some(_) => {
            return Err(Error::InvalidKey(
                "the unwrapped JWK's `use` member does not match the key's family".into(),
            ))
        }
    }
    match jwk.get("key_ops") {
        None => Ok(()),
        Some(Value::Array(ops)) => {
            let listed = |name: &str| {
                ops.iter()
                    .any(|op| matches!(op, Value::String(s) if s == name))
            };
            if granted.iter().all(|name| listed(name)) {
                Ok(())
            } else {
                Err(Error::InvalidKey(
                    "the unwrapped JWK's `key_ops` member does not include every granted usage"
                        .into(),
                ))
            }
        }
        Some(_) => Err(Error::InvalidKey(
            "the unwrapped JWK's `key_ops` member is malformed".into(),
        )),
    }
}

/// Parse an `oct` JWK, validate it against the declared algorithm and the
/// requested extractability, and return the raw key material (the
/// `import-key-jwk` contract; every failure is `invalid-key`).
///
/// `expected_alg` is the algorithm's registered JOSE `alg`: a present
/// member must match it, and an absent member is accepted (JWK `alg` is
/// optional on import).
pub fn parse_oct(jwk: &str, expected_alg: &str, extractable: bool) -> Result<Vec<u8>, Error> {
    let jwk = parse_object(jwk)?;
    require_kty(&jwk, "oct")?;

    match jwk.get("alg") {
        None => {}
        Some(Value::String(alg)) if alg == expected_alg => {}
        Some(Value::String(alg)) => {
            return Err(Error::InvalidKey(format!(
                "JWK alg is {alg:?}, not {expected_alg:?}"
            )))
        }
        Some(_) => return Err(Error::InvalidKey("JWK `alg` must be a string".into())),
    }

    check_ext(&jwk, extractable)?;

    let Some(Value::String(k)) = jwk.get("k") else {
        return Err(Error::InvalidKey(
            "JWK must carry `k` (base64url key material)".into(),
        ));
    };
    decode_member("k", k)
}

/// The RFC 8037 OKP private key pair a `parse_okp_private` returns: the
/// public coordinate `x` (mandatory in RFC 8037) and the private scalar
/// `d`, both decoded.
#[derive(Debug)]
pub struct OkpPrivate {
    pub x: Vec<u8>,
    pub d: zeroize::Zeroizing<Vec<u8>>,
}

/// Parse an OKP private JWK (RFC 8037 §2), validate it against the
/// declared curve, `allowed_algs` (see `check_alg`), and the requested
/// extractability, and return the
/// decoded `x`/`d` pair (every failure is `invalid-key`). Curve-specific
/// validation — lengths, `x`-matches-`d` — stays with the caller, which
/// knows the curve.
pub fn parse_okp_private(
    jwk: &str,
    expected_crv: &str,
    extractable: bool,
    allowed_algs: Option<&[&str]>,
) -> Result<OkpPrivate, Error> {
    let jwk = parse_object(jwk)?;
    require_kty(&jwk, "OKP")?;
    check_alg(&jwk, allowed_algs)?;
    require_crv(&jwk, expected_crv)?;

    check_ext(&jwk, extractable)?;

    let Some(Value::String(x)) = jwk.get("x") else {
        return Err(Error::InvalidKey(
            "OKP JWK must carry `x` (base64url public key)".into(),
        ));
    };
    let Some(Value::String(d)) = jwk.get("d") else {
        return Err(Error::InvalidKey(
            "OKP private JWK must carry `d` (base64url private key)".into(),
        ));
    };
    Ok(OkpPrivate {
        x: decode_member("x", x)?,
        d: zeroize::Zeroizing::new(decode_member("d", d)?),
    })
}

/// Parse an OKP *public* JWK (RFC 8037 §2: `kty`, `crv`, `x`; a present
/// `d` is rejected — a caller holding private material meant the private
/// import), validated against the declared curve and `allowed_algs` (see
/// `check_alg`), returning the decoded public coordinate (every failure
/// is `invalid-key`). A public JWK carrying `"ext": false` is rejected:
/// the minted public-key resources are unconditionally exportable, so
/// admitting one would violate the JWK's own restriction.
pub fn parse_okp_public(
    jwk: &str,
    expected_crv: &str,
    allowed_algs: Option<&[&str]>,
) -> Result<Vec<u8>, Error> {
    let jwk = parse_object(jwk)?;
    require_kty(&jwk, "OKP")?;
    require_crv(&jwk, expected_crv)?;
    check_alg(&jwk, allowed_algs)?;
    check_ext(&jwk, true)?;
    if jwk.get("d").is_some() {
        return Err(Error::InvalidKey(
            "JWK carries `d`; import it as a private key".into(),
        ));
    }
    let Some(Value::String(x)) = jwk.get("x") else {
        return Err(Error::InvalidKey(
            "OKP JWK must carry `x` (base64url public key)".into(),
        ));
    };
    decode_member("x", x)
}

/// The decoded members of an EC JWK (RFC 7518 §6.2): the public
/// coordinates, and `d` for the private form.
#[derive(Debug)]
pub struct EcJwk {
    pub x: Vec<u8>,
    pub y: Vec<u8>,
    /// Unread on wasm targets: the sole consumer is ECDSA private import,
    /// whose code is compiled out there (class D — see the crate doc).
    #[cfg_attr(target_family = "wasm", allow(dead_code))]
    pub d: Option<zeroize::Zeroizing<Vec<u8>>>,
}

/// Parse an EC JWK, validated against the declared curve and — for the
/// private form — the requested extractability. `private` selects the
/// form: the public form rejects a present `d`, the private form requires
/// it. Coordinate lengths and curve membership stay with the caller,
/// which knows the curve.
pub fn parse_ec(
    jwk: &str,
    expected_crv: &str,
    private: bool,
    extractable: bool,
    allowed_algs: Option<&[&str]>,
) -> Result<EcJwk, Error> {
    let jwk = parse_object(jwk)?;
    require_kty(&jwk, "EC")?;
    require_crv(&jwk, expected_crv)?;
    check_alg(&jwk, allowed_algs)?;
    // The public form takes the same `"ext": false` rejection as
    // `parse_okp_public`, and for the same reason.
    check_ext(&jwk, if private { extractable } else { true })?;
    let Some(Value::String(x)) = jwk.get("x") else {
        return Err(Error::InvalidKey(
            "EC JWK must carry `x` (base64url coordinate)".into(),
        ));
    };
    let Some(Value::String(y)) = jwk.get("y") else {
        return Err(Error::InvalidKey(
            "EC JWK must carry `y` (base64url coordinate)".into(),
        ));
    };
    let d = match (private, jwk.get("d")) {
        (false, None) => None,
        (false, Some(_)) => {
            return Err(Error::InvalidKey(
                "JWK carries `d`; import it as a private key".into(),
            ))
        }
        (true, Some(Value::String(d))) => Some(zeroize::Zeroizing::new(decode_member("d", d)?)),
        (true, _) => {
            return Err(Error::InvalidKey(
                "EC private JWK must carry `d` (base64url private key)".into(),
            ))
        }
    };
    Ok(EcJwk {
        x: decode_member("x", x)?,
        y: decode_member("y", y)?,
        d,
    })
}

/// Build the EC public JWK (RFC 7518 §6.2.1): exactly the material-bearing
/// members.
pub fn build_ec_public(crv: &str, x: &[u8], y: &[u8]) -> String {
    serde_json::json!({
        "kty": "EC",
        "crv": crv,
        "x": URL_SAFE_NO_PAD.encode(x),
        "y": URL_SAFE_NO_PAD.encode(y),
    })
    .to_string()
}

/// Build the EC private JWK (RFC 7518 §6.2.2): the public members plus `d`.
/// Unused on wasm targets: the sole caller is ECDSA private export, whose
/// code is compiled out there (class D — see the crate doc).
#[cfg_attr(target_family = "wasm", allow(dead_code))]
pub fn build_ec_private(crv: &str, x: &[u8], y: &[u8], d: &[u8]) -> String {
    serde_json::json!({
        "kty": "EC",
        "crv": crv,
        "x": URL_SAFE_NO_PAD.encode(x),
        "y": URL_SAFE_NO_PAD.encode(y),
        "d": URL_SAFE_NO_PAD.encode(d),
    })
    .to_string()
}

/// Require the JWK's `crv` member to be exactly `expected`.
fn require_crv(jwk: &serde_json::Map<String, Value>, expected: &str) -> Result<(), Error> {
    match jwk.get("crv") {
        Some(Value::String(crv)) if crv == expected => Ok(()),
        Some(Value::String(crv)) => Err(Error::InvalidKey(format!(
            "JWK crv is {crv:?}, not {expected:?}"
        ))),
        _ => Err(Error::InvalidKey("JWK must carry a string `crv`".into())),
    }
}

/// Parse the JWK's JSON envelope: a JSON object, by `JSON.parse` semantics.
fn parse_object(jwk: &str) -> Result<serde_json::Map<String, Value>, Error> {
    let jwk: Value = serde_json::from_str(jwk)
        .map_err(|err| Error::InvalidKey(format!("JWK is not valid JSON: {err}")))?;
    let Value::Object(jwk) = jwk else {
        return Err(Error::InvalidKey("JWK must be a JSON object".into()));
    };
    Ok(jwk)
}

/// Require the JWK's `kty` member to be exactly `expected`.
fn require_kty(jwk: &serde_json::Map<String, Value>, expected: &str) -> Result<(), Error> {
    match jwk.get("kty") {
        Some(Value::String(kty)) if kty == expected => Ok(()),
        Some(Value::String(kty)) => Err(Error::InvalidKey(format!(
            "JWK kty must be {expected:?}, got {kty:?}"
        ))),
        _ => Err(Error::InvalidKey("JWK must carry a string `kty`".into())),
    }
}

/// Validate `ext` against the requested extractability (the import
/// contract: `ext: false` conflicts with an extractable import).
/// Validate a JWK `alg` member against the algorithm interface's accepted
/// values. `None` means the member is ignored entirely (the WebCrypto rule
/// for ECDH-family imports, which X25519 follows); `Some` accepts an
/// absent member or any listed value, case-sensitively.
fn check_alg(jwk: &serde_json::Map<String, Value>, allowed: Option<&[&str]>) -> Result<(), Error> {
    let Some(allowed) = allowed else {
        return Ok(());
    };
    match jwk.get("alg") {
        None => Ok(()),
        Some(Value::String(alg)) if allowed.contains(&alg.as_str()) => Ok(()),
        Some(Value::String(alg)) => Err(Error::InvalidKey(format!(
            "JWK alg is {alg:?}, not one of {allowed:?}"
        ))),
        Some(_) => Err(Error::InvalidKey("JWK `alg` must be a string".into())),
    }
}

fn check_ext(jwk: &serde_json::Map<String, Value>, extractable: bool) -> Result<(), Error> {
    match jwk.get("ext") {
        None => Ok(()),
        Some(Value::Bool(false)) if extractable => Err(Error::InvalidKey(
            "JWK ext is false; the key cannot be imported extractable".into(),
        )),
        Some(Value::Bool(_)) => Ok(()),
        Some(_) => Err(Error::InvalidKey("JWK `ext` must be a boolean".into())),
    }
}

/// Decode a material-bearing member as strict unpadded base64url.
fn decode_member(name: &str, value: &str) -> Result<Vec<u8>, Error> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|err| Error::InvalidKey(format!("JWK `{name}` is not unpadded base64url: {err}")))
}

/// Build the `oct` JWK for an export: exactly the material-bearing members
/// (`kty`, `k`, `alg`), per the `export-key-jwk` contract.
pub fn build_oct(raw: &[u8], alg: &str) -> String {
    serde_json::json!({
        "kty": "oct",
        "k": URL_SAFE_NO_PAD.encode(raw),
        "alg": alg,
    })
    .to_string()
}

/// Build the OKP public JWK for an export (RFC 8037 §2): exactly the
/// material-bearing members (`kty`, `crv`, `x`).
pub fn build_okp_public(crv: &str, x: &[u8]) -> String {
    serde_json::json!({
        "kty": "OKP",
        "crv": crv,
        "x": URL_SAFE_NO_PAD.encode(x),
    })
    .to_string()
}

/// Build the OKP private JWK (RFC 8037 §2): the public members plus `d`.
pub fn build_okp_private(crv: &str, x: &[u8], d: &[u8]) -> String {
    serde_json::json!({
        "kty": "OKP",
        "crv": crv,
        "x": URL_SAFE_NO_PAD.encode(x),
        "d": URL_SAFE_NO_PAD.encode(d),
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let jwk = build_oct(&[1, 2, 3, 4, 5], "HS256");
        assert_eq!(parse_oct(&jwk, "HS256", true).unwrap(), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn absent_alg_is_accepted_and_a_wrong_one_rejected() {
        // JWK `alg` is optional on import (the WPT fixtures for
        // ChaCha20-Poly1305 omit it)…
        let jwk = r#"{"kty":"oct","k":"AQID"}"#;
        assert_eq!(parse_oct(jwk, "C20P", false).unwrap(), vec![1, 2, 3]);
        // …a matching one is accepted…
        let jwk = build_oct(&[7; 32], "C20P");
        assert!(jwk.contains(r#""alg":"C20P""#));
        assert_eq!(parse_oct(&jwk, "C20P", true).unwrap(), vec![7; 32]);
        // …and another algorithm's is rejected.
        let tagged = r#"{"kty":"oct","k":"AQID","alg":"A256GCM"}"#;
        assert!(matches!(
            parse_oct(tagged, "C20P", false),
            Err(Error::InvalidKey(_))
        ));
    }

    #[test]
    fn wpt_fixture_k_decodes() {
        // The key data the WPT symmetric_importKey fixtures encode.
        let raw: Vec<u8> = (1..=32).collect();
        let jwk =
            r#"{"kty":"oct","k":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA","alg":"HS256"}"#;
        assert_eq!(parse_oct(jwk, "HS256", false).unwrap(), raw);
    }

    #[test]
    fn duplicate_members_resolve_last_wins() {
        // The JSON.parse semantics the contract pins: the second `k` wins.
        let jwk = r#"{"kty":"oct","k":"AAAA","k":"AQID"}"#;
        assert_eq!(parse_oct(jwk, "HS256", false).unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn alg_mismatch_and_wrong_kty_are_invalid() {
        let jwk = build_oct(&[1; 16], "A128GCM");
        assert!(matches!(
            parse_oct(&jwk, "A256GCM", false),
            Err(Error::InvalidKey(_))
        ));
        // A present-but-wrong kty names the expected value; only a missing
        // or non-string kty falls to the carry-a-string diagnostic.
        match parse_oct(r#"{"kty":"EC","k":"AQID"}"#, "HS256", false) {
            Err(Error::InvalidKey(msg)) => {
                assert_eq!(msg, r#"JWK kty must be "oct", got "EC""#)
            }
            _ => panic!("expected invalid-key"),
        }
        match parse_oct(r#"{"k":"AQID"}"#, "HS256", false) {
            Err(Error::InvalidKey(msg)) => {
                assert_eq!(msg, "JWK must carry a string `kty`")
            }
            _ => panic!("expected invalid-key"),
        }
    }

    #[test]
    fn base64url_is_strict() {
        // Padding, the standard alphabet's `+`, and non-zero trailing bits
        // are each rejected.
        for k in ["AQI=", "+w", "AQ7"] {
            let jwk = format!(r#"{{"kty":"oct","k":"{k}"}}"#);
            assert!(
                matches!(parse_oct(&jwk, "HS256", false), Err(Error::InvalidKey(_))),
                "{k} accepted"
            );
        }
    }

    #[test]
    fn ext_false_conflicts_with_extractable_import() {
        let jwk = r#"{"kty":"oct","k":"AQID","ext":false}"#;
        assert!(matches!(
            parse_oct(jwk, "HS256", true),
            Err(Error::InvalidKey(_))
        ));
        // Non-extractable import of the same JWK is fine.
        assert_eq!(parse_oct(jwk, "HS256", false).unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn use_and_key_ops_are_ignored() {
        let jwk = r#"{"kty":"oct","k":"AQID","use":"enc","key_ops":["encrypt"]}"#;
        assert_eq!(parse_oct(jwk, "HS256", false).unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn garbage_is_invalid_not_a_panic() {
        for jwk in ["", "[]", "42", "{", r#"{"kty":"oct","k":7}"#] {
            assert!(matches!(
                parse_oct(jwk, "HS256", false),
                Err(Error::InvalidKey(_))
            ));
            assert!(matches!(
                parse_okp_private(jwk, "X25519", false, None),
                Err(Error::InvalidKey(_))
            ));
        }
    }

    #[test]
    fn public_jwk_ext_false_is_rejected() {
        // Minted public keys are unconditionally exportable, so a public
        // JWK restricting extractability cannot be honored.
        let okp = r#"{"kty":"OKP","crv":"X25519","x":"AQID","ext":false}"#;
        assert!(matches!(
            parse_okp_public(okp, "X25519", None),
            Err(Error::InvalidKey(_))
        ));
        let ec = r#"{"kty":"EC","crv":"P-256","x":"AQID","y":"AQID","ext":false}"#;
        assert!(matches!(
            parse_ec(ec, "P-256", false, false, None),
            Err(Error::InvalidKey(_))
        ));
    }

    #[test]
    fn alg_validates_against_the_allowed_list() {
        for alg in ["Ed25519", "EdDSA"] {
            let jwk = format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"AQID","alg":"{alg}"}}"#);
            assert!(parse_okp_public(&jwk, "Ed25519", Some(&["Ed25519", "EdDSA"])).is_ok());
        }
        // Wrong case and wrong value are both rejected, case-sensitively.
        for alg in ["ed25519", "ED25519", "ES256"] {
            let jwk = format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"AQID","alg":"{alg}"}}"#);
            assert!(matches!(
                parse_okp_public(&jwk, "Ed25519", Some(&["Ed25519", "EdDSA"])),
                Err(Error::InvalidKey(_))
            ));
        }
        // `None` ignores the member entirely (the ECDH-family import rule).
        let jwk = r#"{"kty":"OKP","crv":"X25519","x":"AQID","alg":"anything"}"#;
        assert!(parse_okp_public(jwk, "X25519", None).is_ok());
    }

    #[test]
    fn okp_round_trip() {
        let jwk = build_okp_private("X25519", &[1; 32], &[2; 32]);
        let okp = parse_okp_private(&jwk, "X25519", true, None).unwrap();
        assert_eq!(okp.x, vec![1; 32]);
        assert_eq!(okp.d.as_slice(), &[2; 32]);
    }

    #[test]
    fn okp_contract_errors() {
        // Wrong curve, wrong kty, missing x, missing d, ext conflict.
        // A present-but-wrong crv names the expected value; only a missing
        // or non-string crv falls to the carry-a-string diagnostic.
        let jwk = build_okp_private("Ed25519", &[1; 32], &[2; 32]);
        match parse_okp_private(&jwk, "X25519", false, None) {
            Err(Error::InvalidKey(msg)) => {
                assert_eq!(msg, r#"JWK crv is "Ed25519", not "X25519""#)
            }
            _ => panic!("expected invalid-key"),
        }
        match parse_okp_private(
            r#"{"kty":"OKP","x":"AQID","d":"AQID"}"#,
            "X25519",
            false,
            None,
        ) {
            Err(Error::InvalidKey(msg)) => {
                assert_eq!(msg, "JWK must carry a string `crv`")
            }
            _ => panic!("expected invalid-key"),
        }
        assert!(matches!(
            parse_okp_private(
                r#"{"kty":"oct","crv":"X25519","x":"AQID","d":"AQID"}"#,
                "X25519",
                false,
                None
            ),
            Err(Error::InvalidKey(_))
        ));
        assert!(matches!(
            parse_okp_private(
                r#"{"kty":"OKP","crv":"X25519","d":"AQID"}"#,
                "X25519",
                false,
                None
            ),
            Err(Error::InvalidKey(_))
        ));
        assert!(matches!(
            parse_okp_private(
                r#"{"kty":"OKP","crv":"X25519","x":"AQID"}"#,
                "X25519",
                false,
                None
            ),
            Err(Error::InvalidKey(_))
        ));
        assert!(matches!(
            parse_okp_private(
                r#"{"kty":"OKP","crv":"X25519","x":"AQID","d":"AQID","ext":false}"#,
                "X25519",
                true,
                None
            ),
            Err(Error::InvalidKey(_))
        ));
        // Strict base64url applies to x and d.
        assert!(matches!(
            parse_okp_private(
                r#"{"kty":"OKP","crv":"X25519","x":"AQI=","d":"AQID"}"#,
                "X25519",
                false,
                None
            ),
            Err(Error::InvalidKey(_))
        ));
    }
}
