//! Mint-time key policy: the state a `*-key-options` resource accumulates
//! and a mint consumes. One struct per kind, mirroring the per-kind usage
//! vocabularies in the WIT; the `Default` impls are the options
//! constructors' documented defaults — **nothing granted** — and
//! [`useful`] is the shared at-least-one-usage mint check, which an
//! untouched default therefore fails.

use crate::Error;

/// `mac.mac-key-options`.
#[derive(Clone, Copy, Debug, Default)]
pub struct MacPolicy {
    pub sign: bool,
    pub verify: bool,
    pub extractable: bool,
}

impl MacPolicy {
    /// The at-least-one-usage mint check (the options contract).
    pub fn check_useful(&self) -> Result<(), Error> {
        useful(self.sign || self.verify)
    }

    /// The granted usages under their W3C Web Cryptography API names.
    pub fn webcrypto_usages(&self) -> Vec<&'static str> {
        granted(&[(self.sign, "sign"), (self.verify, "verify")])
    }
}

/// `cipher.cipher-key-options`.
#[derive(Clone, Copy, Debug, Default)]
pub struct CipherPolicy {
    pub encrypt: bool,
    pub decrypt: bool,
    pub wrap: bool,
    pub unwrap: bool,
    pub extractable: bool,
}

impl CipherPolicy {
    /// The at-least-one-usage mint check (the options contract).
    pub fn check_useful(&self) -> Result<(), Error> {
        useful(self.encrypt || self.decrypt || self.wrap || self.unwrap)
    }

    /// The granted usages under their W3C Web Cryptography API names (the
    /// unwrap-path JWK `key_ops` check's reference set).
    pub fn webcrypto_usages(&self) -> Vec<&'static str> {
        granted(&[
            (self.encrypt, "encrypt"),
            (self.decrypt, "decrypt"),
            (self.wrap, "wrapKey"),
            (self.unwrap, "unwrapKey"),
        ])
    }
}

/// `aead.aead-key-options`.
#[derive(Clone, Copy, Debug, Default)]
pub struct AeadPolicy {
    pub seal: bool,
    pub open: bool,
    pub wrap: bool,
    pub unwrap: bool,
    pub extractable: bool,
}

impl AeadPolicy {
    /// The at-least-one-usage mint check (the options contract).
    pub fn check_useful(&self) -> Result<(), Error> {
        useful(self.seal || self.open || self.wrap || self.unwrap)
    }

    /// The granted usages under their W3C Web Cryptography API names
    /// (`seal` → `"encrypt"`, `open` → `"decrypt"`; the unwrap-path JWK
    /// `key_ops` check's reference set).
    pub fn webcrypto_usages(&self) -> Vec<&'static str> {
        granted(&[
            (self.seal, "encrypt"),
            (self.open, "decrypt"),
            (self.wrap, "wrapKey"),
            (self.unwrap, "unwrapKey"),
        ])
    }
}

/// `key-wrap.kw-key-options`.
#[derive(Clone, Copy, Debug, Default)]
pub struct KwPolicy {
    pub wrap: bool,
    pub unwrap: bool,
    pub extractable: bool,
}

impl KwPolicy {
    /// The at-least-one-usage mint check (the options contract).
    pub fn check_useful(&self) -> Result<(), Error> {
        useful(self.wrap || self.unwrap)
    }

    /// The granted usages under their W3C Web Cryptography API names.
    pub fn webcrypto_usages(&self) -> Vec<&'static str> {
        granted(&[(self.wrap, "wrapKey"), (self.unwrap, "unwrapKey")])
    }
}

/// `signature.signing-key-options` (degenerate: `sign` is the sole usage).
#[derive(Clone, Copy, Debug, Default)]
pub struct SigningPolicy {
    pub sign: bool,
    pub extractable: bool,
}

impl SigningPolicy {
    /// The at-least-one-usage mint check (the options contract).
    pub fn check_useful(&self) -> Result<(), Error> {
        useful(self.sign)
    }

    /// The granted usages under their W3C Web Cryptography API names.
    pub fn webcrypto_usages(&self) -> Vec<&'static str> {
        granted(&[(self.sign, "sign")])
    }
}

/// `public-encryption.decryption-key-options`: the disclosure/minting
/// grant pair (`decrypt` returns plaintext, `unwrap` mints keys the
/// caller never reads) plus mint-time recorded extractability.
#[derive(Clone, Copy, Debug, Default)]
pub struct TransportPolicy {
    pub decrypt: bool,
    pub unwrap: bool,
    pub extractable: bool,
}

impl TransportPolicy {
    /// The at-least-one-usage mint check (the options contract).
    pub fn check_useful(&self) -> Result<(), Error> {
        useful(self.decrypt || self.unwrap)
    }

    /// The granted usages under their W3C Web Cryptography API names (the
    /// unwrap-path JWK `key_ops` check's reference set).
    pub fn webcrypto_usages(&self) -> Vec<&'static str> {
        granted(&[(self.decrypt, "decrypt"), (self.unwrap, "unwrapKey")])
    }
}

/// `key-agreement.agreement-key-options`: the derive pair that flows to
/// every `derive-input` the key's `agree` mints, plus mint-time recorded
/// extractability.
#[derive(Clone, Copy, Debug, Default)]
pub struct AgreementPolicy {
    pub derive_bits: bool,
    pub derive_key: bool,
    pub extractable: bool,
}

impl AgreementPolicy {
    /// The at-least-one-usage mint check (the options contract).
    pub fn check_useful(&self) -> Result<(), Error> {
        useful(self.derive_bits || self.derive_key)
    }

    /// The granted usages under their W3C Web Cryptography API names.
    pub fn webcrypto_usages(&self) -> Vec<&'static str> {
        granted(&[
            (self.derive_bits, "deriveBits"),
            (self.derive_key, "deriveKey"),
        ])
    }
}

/// `derivation.derive-options`.
#[derive(Clone, Copy, Debug, Default)]
pub struct DerivePolicy {
    pub derive_bits: bool,
    pub derive_key: bool,
}

impl DerivePolicy {
    /// The at-least-one-usage mint check (the options contract).
    pub fn check_useful(&self) -> Result<(), Error> {
        useful(self.derive_bits || self.derive_key)
    }
}

/// Collect the granted usage names from `(granted, name)` pairs.
fn granted(pairs: &[(bool, &'static str)]) -> Vec<&'static str> {
    pairs
        .iter()
        .filter_map(|&(on, name)| on.then_some(name))
        .collect()
}

/// The at-least-one-usage mint check: a key with no enabled usage fails at
/// mint (platform backends cannot mint zero-usage keys, so the contract
/// declines uniformly).
fn useful(any: bool) -> Result<(), Error> {
    if any {
        Ok(())
    } else {
        Err(Error::NotPermitted(
            "a key with no enabled usage cannot be minted".into(),
        ))
    }
}

/// The refusal an operation renders on a usage-denied key.
pub fn not_permitted(operation: &str) -> Error {
    Error::NotPermitted(format!("this key does not permit {operation}"))
}
