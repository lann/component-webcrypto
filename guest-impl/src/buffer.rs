//! Fallible buffering of operation input, so allocation failure surfaces as
//! an error result instead of a trap.
//!
//! Every stream-taking operation buffers its whole input, and a stream's
//! length is unknowable up front, so the buffer is where an oversized message
//! meets this component's linear-memory limit. Growing the buffer with
//! `try_reserve` turns that encounter into `error.other` — the *operation's*
//! failure, recoverable by its caller — where an infallible `Vec` would abort
//! and trap the instance, taking the composition around it down too.
//!
//! The memory limit is the bound, deliberately. It is the one number the
//! deployment already controls — the embedder sets it on the composed
//! instance the way it sets the host providers' pools — and this provider has
//! essentially one caller: the composition it was plugged into. Admission
//! control exists to protect a shared resource from callers that cannot
//! coordinate; this provider's caller can coordinate with itself, knows its
//! own workload, and pays for its own concurrency. A provider-side scheduler
//! or watermark would be a second, uncoordinated number baked into a wasm
//! binary — untunable per deployment, and a behavioral divergence from the
//! host providers that makes the same guest perform differently composed than
//! hosted. (The Model's `backpressure.{inc,dec}` remains available to a
//! component callee should a genuinely shared deployment ever need it; it is
//! unused here because there is nothing to schedule *between*.)
//!
//! The fallibility is honest but partial: only the buffering paths are
//! fallible, while the crypto core's output allocation (input-sized) and the
//! drain loop's own batch buffers are not. Those can still abort at the very
//! edge of memory; what this module guarantees is that the dominant
//! allocation — the message itself — fails softly.
//!
//! What is *not* buffered here: key material held in resources. That
//! retention is long-lived rather than transient; bounding imported key
//! length is a separate question from surviving an oversized message.

/// Allocation failed while buffering; rendered as `error.other` at the
/// operation boundary.
#[derive(Debug)]
pub(crate) struct OutOfMemory;

/// An operation's buffered input, grown fallibly.
///
/// Derefs to the bytes, so call sites read as if they held the `Vec`.
#[derive(Debug, Default)]
pub(crate) struct Buffered {
    bytes: Vec<u8>,
}

impl Buffered {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Append a batch, failing — and releasing everything buffered, so
    /// nothing stays retained while the caller discards the rest of the
    /// stream — if the allocation cannot be satisfied.
    pub(crate) fn extend(&mut self, batch: &[u8]) -> Result<(), OutOfMemory> {
        self.try_grow(batch.len())?;
        self.bytes.extend_from_slice(batch);
        Ok(())
    }

    /// Reserve room for `additional` more bytes, releasing the buffer on
    /// failure.
    fn try_grow(&mut self, additional: usize) -> Result<(), OutOfMemory> {
        if self.bytes.try_reserve(additional).is_err() {
            self.bytes = Vec::new();
            return Err(OutOfMemory);
        }
        Ok(())
    }
}

impl std::ops::Deref for Buffered {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Buffered` accumulates batches in order.
    #[test]
    fn buffered_accumulates() {
        let mut buffered = Buffered::new();
        buffered.extend(&[1, 2, 3]).unwrap();
        buffered.extend(&[4, 5]).unwrap();
        assert_eq!(&*buffered, &[1, 2, 3, 4, 5]);
    }

    /// A reservation that cannot be satisfied fails instead of aborting, and
    /// releases what was buffered so the drain loop retains nothing while it
    /// discards the rest of the stream.
    #[test]
    fn failed_reservation_errs_and_releases() {
        let mut buffered = Buffered::new();
        buffered.extend(&[0u8; 64]).unwrap();
        // `usize::MAX` additional bytes always exceeds `Vec`'s capacity
        // limit, so the reservation fails without the test allocating.
        assert!(buffered.try_grow(usize::MAX).is_err());
        assert!(buffered.is_empty());
    }
}
