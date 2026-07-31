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
//! - `use` and `key_ops` are ignored (the package has no usage model);
//!   `ext` is validated against the requested extractability.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::Value;

use crate::Error;

/// Parse an `oct` JWK, validate it against the declared algorithm and the
/// requested extractability, and return the raw key material (the
/// `import-key-jwk` contract; every failure is `invalid-key`).
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
/// declared curve and the requested extractability, and return the
/// decoded `x`/`d` pair (every failure is `invalid-key`). Curve-specific
/// validation — lengths, `x`-matches-`d` — stays with the caller, which
/// knows the curve.
pub fn parse_okp_private(
    jwk: &str,
    expected_crv: &str,
    extractable: bool,
) -> Result<OkpPrivate, Error> {
    let jwk = parse_object(jwk)?;
    require_kty(&jwk, "OKP")?;

    match jwk.get("crv") {
        Some(Value::String(crv)) if crv == expected_crv => {}
        Some(Value::String(crv)) => {
            return Err(Error::InvalidKey(format!(
                "JWK crv is {crv:?}, not {expected_crv:?}"
            )))
        }
        _ => return Err(Error::InvalidKey("JWK must carry a string `crv`".into())),
    }

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
/// Test-only: the package defines no secret-key export, so production code
/// only ever parses this form.
#[cfg(test)]
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
        assert!(matches!(
            parse_oct(r#"{"kty":"EC","k":"AQID"}"#, "HS256", false),
            Err(Error::InvalidKey(_))
        ));
        assert!(matches!(
            parse_oct(r#"{"k":"AQID"}"#, "HS256", false),
            Err(Error::InvalidKey(_))
        ));
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
                parse_okp_private(jwk, "X25519", false),
                Err(Error::InvalidKey(_))
            ));
        }
    }

    #[test]
    fn okp_round_trip() {
        let jwk = build_okp_private("X25519", &[1; 32], &[2; 32]);
        let okp = parse_okp_private(&jwk, "X25519", true).unwrap();
        assert_eq!(okp.x, vec![1; 32]);
        assert_eq!(okp.d.as_slice(), &[2; 32]);
    }

    #[test]
    fn okp_contract_errors() {
        // Wrong curve, wrong kty, missing x, missing d, ext conflict.
        let jwk = build_okp_private("Ed25519", &[1; 32], &[2; 32]);
        assert!(matches!(
            parse_okp_private(&jwk, "X25519", false),
            Err(Error::InvalidKey(_))
        ));
        assert!(matches!(
            parse_okp_private(
                r#"{"kty":"oct","crv":"X25519","x":"AQID","d":"AQID"}"#,
                "X25519",
                false
            ),
            Err(Error::InvalidKey(_))
        ));
        assert!(matches!(
            parse_okp_private(
                r#"{"kty":"OKP","crv":"X25519","d":"AQID"}"#,
                "X25519",
                false
            ),
            Err(Error::InvalidKey(_))
        ));
        assert!(matches!(
            parse_okp_private(
                r#"{"kty":"OKP","crv":"X25519","x":"AQID"}"#,
                "X25519",
                false
            ),
            Err(Error::InvalidKey(_))
        ));
        assert!(matches!(
            parse_okp_private(
                r#"{"kty":"OKP","crv":"X25519","x":"AQID","d":"AQID","ext":false}"#,
                "X25519",
                true
            ),
            Err(Error::InvalidKey(_))
        ));
        // Strict base64url applies to x and d.
        assert!(matches!(
            parse_okp_private(
                r#"{"kty":"OKP","crv":"X25519","x":"AQI=","d":"AQID"}"#,
                "X25519",
                false
            ),
            Err(Error::InvalidKey(_))
        ));
    }
}
