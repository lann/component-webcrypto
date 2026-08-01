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
}

/// `aead.aead-key-options`. `wrap`/`unwrap` are vocabulary ahead of
/// operations: recorded and reported, nothing here consumes them yet.
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
}

/// `aead-internal-nonce.internal-nonce-key-options` (seal/open only: the
/// kind has no WebCrypto usage vocabulary beyond its own operations). The
/// at-least-one-usage mint check runs on the widened [`AeadPolicy`], which
/// the `From` impl below produces with the wrap grants disabled.
#[derive(Clone, Copy, Debug, Default)]
pub struct InternalNoncePolicy {
    pub seal: bool,
    pub open: bool,
    pub extractable: bool,
}

impl From<InternalNoncePolicy> for AeadPolicy {
    /// Widen for the shared AEAD material: the internal-nonce vocabulary
    /// has no wrap usages, so they arrive disabled.
    fn from(policy: InternalNoncePolicy) -> Self {
        Self {
            seal: policy.seal,
            open: policy.open,
            wrap: false,
            unwrap: false,
            extractable: policy.extractable,
        }
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
