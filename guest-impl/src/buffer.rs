//! Fallible buffering of operation input, so allocation failure surfaces as
//! an error result instead of a trap.
//!
//! Every stream-taking operation buffers its whole input, and a stream's
//! length is unknowable up front, so the buffer is where an oversized message
//! meets this component's linear-memory limit. Growing the buffer with
//! `try_reserve` turns that encounter into `error.other` — an operational
//! condition, which is what `other` carries — and leaves the instance able to
//! serve the next call. An infallible `Vec` would abort instead, trapping the
//! instance and, under a shared store-level memory budget, potentially the
//! composition around it.
//!
//! Only the input buffers are fallible. Allocations inside the crypto core
//! and the bindings remain infallible, but they are proportional to input
//! that was already admitted here, so the buffering paths are where
//! exhaustion lands first.
//!
//! Bounding retention below the memory limit is deliberately not attempted:
//! the sandbox's memory limit is the bound, and this module's job is to make
//! hitting it a recoverable error on the operation that did.

/// Allocation failed while buffering; render as `error.other` at the
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

    /// Append a batch, failing (and dropping what was buffered) if the
    /// allocation cannot be satisfied.
    pub(crate) fn extend(&mut self, batch: &[u8]) -> Result<(), OutOfMemory> {
        self.try_grow(batch.len())?;
        self.bytes.extend_from_slice(batch);
        Ok(())
    }

    /// Reserve room for `additional` more bytes, releasing the buffer on
    /// failure so nothing stays retained while the drain loop discards the
    /// rest of the stream.
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
