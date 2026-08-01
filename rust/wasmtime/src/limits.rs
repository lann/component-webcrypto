//! Admission control for host-side input buffering.
//!
//! Every stream-taking operation buffers its whole input in host memory (the
//! single-message contract), so a guest with many concurrent calls could
//! otherwise make the host retain `calls × per-call-bound` bytes — unbounded.
//! A counting semaphore bounds *aggregate* retention: bytes are permits, each
//! operation acquires its per-call bound before draining, waits (fairly, in
//! request order) when the budget is spent, and releases when its buffers are
//! gone — including the returned output stream, whose producer carries the
//! [`Reservation`].
//!
//! Reservations are pessimistic (the full per-call bound, since a stream's
//! length is unknowable up front): an admitted operation never waits for more
//! capacity mid-flight, so admission cannot deadlock on partial allocations.
//! The caller clamps the per-call bound to the budget, so one operation is
//! always admittable and admission cannot livelock either.
//!
//! The permit is owned and `'static`, so it can be released without store
//! access — host futures may be dropped at any point, e.g. on task
//! cancellation.
//!
//! The primitive itself is [`mea::semaphore`] rather than a hand-written
//! queue: the hard-to-test parts — waking a parked waiter without holding
//! the lock the waker may re-enter, deciding after a release whether the
//! *front* waiter fits, unwinding a cancelled waiter out of the queue —
//! live in the vetted crate.

use std::sync::Arc;

use mea::semaphore::Semaphore;
use wasmtime::component::{Accessor, AsAccessor as _};

use crate::WasiWebcrypto;

/// The admission pool: a fixed aggregate budget in bytes, held as permits.
///
/// The budget belongs to the pool, not to each acquirer. Passing it per
/// acquisition would leave the pool enforcing nothing of its own: every
/// waiter would judge one shared counter against its own ceiling, so
/// acquirers configured differently could disagree about how full the pool
/// is, and a release could not tell whether the next waiter fits without
/// borrowing a ceiling from whoever happened to be releasing.
pub(crate) type BufferPool = Semaphore;

/// An admitted reservation of pool capacity; released on drop.
///
/// The guard travels with the operation's buffers: held across the input
/// drain and moved into the output stream's producer where one exists, so
/// capacity frees only when the retained bytes actually do.
pub(crate) type Reservation = mea::semaphore::OwnedSemaphorePermit;

/// A pool holding at most `total` bytes across all admitted operations.
pub(crate) fn pool(total: u64) -> Arc<BufferPool> {
    Arc::new(Semaphore::new(permits(total)))
}

/// Reserve `amount` bytes, waiting until the pool can fit them. `amount`
/// must be `<= total` (the caller clamps), so an empty pool always admits.
pub(crate) async fn admit(pool: &Arc<BufferPool>, amount: u64) -> Reservation {
    pool.clone().acquire_owned(permits(amount)).await
}

/// Admit one stream-draining operation against the context's buffer limits
/// (waiting FIFO for pool capacity), returning the reservation guard and
/// the operation's buffering cap.
pub(crate) async fn admit_input<T: Send>(
    accessor: &Accessor<T, WasiWebcrypto>,
) -> wasmtime::Result<(Reservation, usize)> {
    let (pool, per_call) = accessor.as_accessor().with(|mut access| {
        let fuel = wasmtime::AsContextMut::as_context_mut(&mut access).hostcall_fuel() as u64;
        let view = access.get();
        let (per_call, total) = view.ctx.buffer_limits(fuel);
        Ok::<_, wasmtime::Error>((view.ctx.pool(total).clone(), per_call))
    })?;
    let reservation = admit(&pool, per_call).await;
    Ok((reservation, usize::try_from(per_call).unwrap_or(usize::MAX)))
}

/// Bytes as permits, saturating rather than truncating: a budget beyond
/// `usize` is unreachable on any host that could allocate it, and wrapping a
/// large limit into a small one would silently tighten it.
fn permits(bytes: u64) -> usize {
    usize::try_from(bytes).unwrap_or(usize::MAX).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    fn poll_once<F: Future>(fut: std::pin::Pin<&mut F>) -> Poll<F::Output> {
        fut.poll(&mut Context::from_waker(Waker::noop()))
    }

    /// An empty pool admits immediately, even for a reservation equal to the
    /// whole budget — the case that makes `per_call == total` workable
    /// rather than a deadlock.
    #[test]
    fn admits_up_to_the_whole_budget() {
        let pool = pool(100);
        let mut a = pin!(admit(&pool, 100));
        let Poll::Ready(_guard) = poll_once(a.as_mut()) else {
            panic!("first admission should not wait");
        };
    }

    /// Admission is in request order: a later, smaller reservation cannot
    /// barge past an earlier waiting one. Without this a stream of small
    /// operations could starve a large one indefinitely.
    #[test]
    fn admission_is_fifo_and_release_admits_the_waiter() {
        let pool = pool(100);
        let mut first = pin!(admit(&pool, 60));
        let Poll::Ready(guard1) = poll_once(first.as_mut()) else {
            panic!("first admission should not wait");
        };
        let mut second = pin!(admit(&pool, 60));
        assert!(poll_once(second.as_mut()).is_pending(), "budget is spent");
        let mut third = pin!(admit(&pool, 10));
        assert!(
            poll_once(third.as_mut()).is_pending(),
            "a smaller later arrival must not barge past the front waiter"
        );
        drop(guard1);
        let Poll::Ready(_guard2) = poll_once(second.as_mut()) else {
            panic!("released capacity admits the front waiter");
        };
    }

    /// A reservation releases its bytes when dropped, whoever drops it and
    /// wherever — the guard travels into the output stream's producer, which
    /// is dropped without store access.
    #[test]
    fn dropping_a_reservation_returns_its_bytes() {
        let pool = pool(100);
        let mut first = pin!(admit(&pool, 100));
        let Poll::Ready(guard) = poll_once(first.as_mut()) else {
            panic!("first admission should not wait");
        };
        assert_eq!(pool.available_permits(), 0);
        drop(guard);
        assert_eq!(pool.available_permits(), 100);
    }

    /// A cancelled waiter leaves the queue rather than blocking it: dropping
    /// a pending admission (a host future cancelled mid-flight) must not
    /// wedge the operations behind it.
    #[test]
    fn a_cancelled_waiter_does_not_block_the_queue() {
        let pool = pool(100);
        let mut first = pin!(admit(&pool, 100));
        let Poll::Ready(guard1) = poll_once(first.as_mut()) else {
            panic!("first admission should not wait");
        };
        // Boxed so `drop` really drops the future (`pin!` locals live to end
        // of scope).
        let mut second = Box::pin(admit(&pool, 100));
        assert!(poll_once(second.as_mut()).is_pending());
        let mut third = pin!(admit(&pool, 100));
        assert!(poll_once(third.as_mut()).is_pending());
        drop(second);
        drop(guard1);
        let Poll::Ready(_guard3) = poll_once(third.as_mut()) else {
            panic!("the queue must advance past a cancelled waiter");
        };
    }

    /// Byte budgets convert to permits without wrapping.
    #[test]
    fn a_budget_beyond_usize_saturates() {
        assert_eq!(permits(0), 1, "a zero budget would admit nothing");
        assert_eq!(permits(100), 100);
        assert_eq!(permits(u64::MAX), usize::MAX);
    }
}
