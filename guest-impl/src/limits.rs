//! Transient retention accounting, and the component-model backpressure that
//! bounds it.
//!
//! Every stream-taking operation buffers its whole input, and every
//! stream-returning one holds its whole output until the caller reads it (the
//! single-message contract). Nothing in the package limits how many
//! operations a caller starts at once, so without a bound a caller could make
//! this provider retain `calls × message` bytes of its own linear memory.
//!
//! Being a component rather than a host, this implementation has the
//! mechanism the Component Model provides for exactly this: `backpressure.inc`
//! / `backpressure.dec` hold a *new* call in the "starting" state, before its
//! core wasm entry point runs and before its arguments are lowered into this
//! component's memory. A caller's queued call therefore costs this provider
//! nothing at all — the bytes stay in the caller's memory until the call
//! starts (see Concurrency.md, "Backpressure").
//!
//! Two consequences worth stating, because they are why this is not the
//! host-side admission pool in a different shape:
//!
//! - **Retention is counted, not reserved.** A host that must decide at the
//!   call boundary reserves a per-call bound pessimistically, since a
//!   stream's length is unknowable up front. Backpressure is a watermark on
//!   what is *already* held, so this counts bytes as they arrive and needs no
//!   per-call ceiling — and no separate accounting for the `list<u8>`
//!   parameters, which the caller still owns while a call waits.
//! - **The gate is component-instance-wide**, which is what the Model
//!   defines and what this provider wants: the resource being protected is
//!   this instance's memory, not any one interface's.
//!
//! What is *not* counted: key material held in resources. That retention is
//! long-lived rather than transient, so counting it against a watermark would
//! leave the provider backpressured for as long as the key lives. Bounding
//! imported key length is a separate question from bounding concurrency.

use std::cell::Cell;

/// The retained-bytes watermark above which new calls are held.
///
/// A fixed figure rather than a configured one: this provider is composed
/// into a component and has no configuration surface to read. It is chosen to
/// be large enough that ordinary single-message use never reaches it, and
/// small enough to bound a caller that starts operations without draining
/// them.
const HIGH_WATER_BYTES: usize = 8 * 1024 * 1024;

thread_local! {
    /// Bytes currently retained on behalf of in-flight operations.
    static RETAINED: Cell<usize> = const { Cell::new(0) };
    /// Whether this provider currently holds the backpressure counter up.
    /// Tracked so `inc` and `dec` stay balanced: the built-in is a counter,
    /// and an unmatched `inc` would wedge the instance permanently.
    static HELD: Cell<bool> = const { Cell::new(false) };
}

/// A charge against the retention watermark, released on drop.
///
/// The guard travels with the bytes it accounts for: held across an
/// operation's buffering, and moved into the task that writes the output
/// stream, so capacity frees when the bytes actually do.
#[derive(Debug, Default)]
pub(crate) struct Retention {
    bytes: usize,
}

impl Retention {
    /// Charge `bytes` more to this guard.
    pub(crate) fn charge(&mut self, bytes: usize) {
        self.bytes += bytes;
        RETAINED.with(|retained| retained.set(retained.get().saturating_add(bytes)));
        sync();
    }
}

impl Drop for Retention {
    fn drop(&mut self) {
        RETAINED.with(|retained| retained.set(retained.get().saturating_sub(self.bytes)));
        sync();
    }
}

/// Match the backpressure counter to the watermark.
///
/// The built-in is called only on a transition, so this provider contributes
/// at most one to the instance-wide counter however many operations are in
/// flight. An unmatched `inc` would hold every later call in the starting
/// state for the life of the instance, which is why `HELD` exists and why the
/// balance is what the tests below assert.
fn sync() {
    let over = RETAINED.with(Cell::get) > HIGH_WATER_BYTES;
    HELD.with(|held| {
        if over == held.get() {
            return;
        }
        set_backpressure(over);
        held.set(over);
    });
}

/// This provider's contribution to the instance-wide backpressure counter.
///
/// Off wasm the built-ins are unreachable stubs, so the transition is
/// recorded instead — which is what makes the balance testable at all, the
/// counter being the thing that wedges an instance when it is wrong.
fn set_backpressure(on: bool) {
    #[cfg(target_arch = "wasm32")]
    {
        if on {
            wit_bindgen::backpressure_inc();
        } else {
            wit_bindgen::backpressure_dec();
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        COUNTER.with(|counter| counter.set(counter.get() + if on { 1 } else { -1 }));
    }
}

#[cfg(not(target_arch = "wasm32"))]
thread_local! {
    /// The counter the built-ins would have moved. Test-only.
    static COUNTER: Cell<i32> = const { Cell::new(0) };
}

/// An operation's buffered input, and the retention it is charged against.
///
/// Derefs to the bytes, so call sites read as if they held the `Vec` — the
/// guard exists to be dropped with them.
#[derive(Debug, Default)]
pub(crate) struct Buffered {
    bytes: Vec<u8>,
    _charge: Retention,
}

impl Buffered {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Append a batch, charging it to the watermark.
    pub(crate) fn extend(&mut self, batch: Vec<u8>) {
        self._charge.charge(batch.len());
        self.bytes.extend(batch);
    }
}

impl std::ops::Deref for Buffered {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

/// Charge `bytes` to the watermark, returning the guard that releases it.
pub(crate) fn charge(bytes: usize) -> Retention {
    let mut retention = Retention::default();
    retention.charge(bytes);
    retention
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counter() -> i32 {
        COUNTER.with(Cell::get)
    }

    /// Charges accumulate and release exactly, so a sequence of operations
    /// leaves the watermark where it started. An imbalance here would leave
    /// the provider permanently backpressured.
    #[test]
    fn charges_release_exactly() {
        let start = RETAINED.with(Cell::get);
        {
            let mut first = Retention::default();
            first.charge(100);
            first.charge(50);
            let _second = charge(25);
            assert_eq!(RETAINED.with(Cell::get), start + 175);
        }
        assert_eq!(RETAINED.with(Cell::get), start);
    }

    /// `Buffered` charges what it holds and releases it when dropped.
    #[test]
    fn buffered_charges_its_bytes() {
        let start = RETAINED.with(Cell::get);
        {
            let mut buffered = Buffered::new();
            buffered.extend(vec![0u8; 64]);
            buffered.extend(vec![0u8; 32]);
            assert_eq!(buffered.len(), 96);
            assert_eq!(RETAINED.with(Cell::get), start + 96);
        }
        assert_eq!(RETAINED.with(Cell::get), start);
    }

    /// Crossing the watermark raises the counter, and falling back lowers it
    /// again — exactly once each way.
    #[test]
    fn crossing_the_watermark_is_balanced() {
        assert_eq!(counter(), 0);
        let under = charge(HIGH_WATER_BYTES);
        assert_eq!(counter(), 0, "at the watermark is not over it");
        {
            let _over = charge(1);
            assert_eq!(counter(), 1);
        }
        assert_eq!(counter(), 0, "falling back below releases the counter");
        drop(under);
        assert_eq!(counter(), 0);
    }

    /// Several concurrent charges above the watermark contribute one to the
    /// counter between them, not one apiece: an `inc` per operation would
    /// need an exactly matching `dec` per operation to ever release.
    #[test]
    fn overlapping_charges_hold_the_counter_once() {
        assert_eq!(counter(), 0);
        {
            let _first = charge(HIGH_WATER_BYTES + 1);
            let _second = charge(HIGH_WATER_BYTES + 1);
            let _third = charge(HIGH_WATER_BYTES + 1);
            assert_eq!(counter(), 1);
        }
        assert_eq!(counter(), 0);
    }
}
