//! The JWK carrier: RFC 7517 `oct`-key parse and build, shared by every
//! `import-key-jwk`/`export-key-jwk` implementation so the two Rust
//! implementations cannot diverge on it.
//!
//! The package-wide contract lives on `mac.mac-key.export-key-jwk` in the
//! WIT. The load-bearing choices, restated where they are implemented:
//!
//! - JSON parses through [`serde_json::Value`], whose duplicate-member
//!   handling is last-wins — the `JSON.parse` semantics the contract pins,
//!   so adversarial JWKs behave identically here and on platform-backed
//!   hosts.
//! - `k` decodes as strict unpadded base64url: padding, non-alphabet
//!   bytes, and non-zero trailing bits are all `invalid-key`.
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
    let jwk: Value = serde_json::from_str(jwk)
        .map_err(|err| Error::InvalidKey(format!("JWK is not valid JSON: {err}")))?;
    let Value::Object(jwk) = jwk else {
        return Err(Error::InvalidKey("JWK must be a JSON object".into()));
    };

    match jwk.get("kty") {
        Some(Value::String(kty)) if kty == "oct" => {}
        Some(Value::String(kty)) => {
            return Err(Error::InvalidKey(format!(
                "JWK kty must be \"oct\", got {kty:?}"
            )))
        }
        _ => return Err(Error::InvalidKey("JWK must carry a string `kty`".into())),
    }

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

    match jwk.get("ext") {
        None => {}
        Some(Value::Bool(false)) if extractable => {
            return Err(Error::InvalidKey(
                "JWK ext is false; the key cannot be imported extractable".into(),
            ))
        }
        Some(Value::Bool(_)) => {}
        Some(_) => return Err(Error::InvalidKey("JWK `ext` must be a boolean".into())),
    }

    let Some(Value::String(k)) = jwk.get("k") else {
        return Err(Error::InvalidKey(
            "JWK must carry `k` (base64url key material)".into(),
        ));
    };
    URL_SAFE_NO_PAD
        .decode(k)
        .map_err(|err| Error::InvalidKey(format!("JWK `k` is not unpadded base64url: {err}")))
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
        let jwk = format!(
            r#"{{"kty":"oct","k":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA","alg":"HS256"}}"#
        );
        assert_eq!(parse_oct(&jwk, "HS256", false).unwrap(), raw);
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
        }
    }
}
