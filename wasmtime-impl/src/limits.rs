//! Admission control for host-side input buffering.
//!
//! Every stream-taking operation buffers its whole input in host memory (the
//! single-message contract), so a guest with many concurrent calls could
//! otherwise make the host retain `calls × per-call-bound` bytes — unbounded.
//! The [`BufferPool`] bounds *aggregate* retention: each operation reserves
//! its per-call buffering bound from the pool before draining, waiting
//! (FIFO) for capacity when the pool is full, and releases the reservation
//! when its buffers are gone — including the returned output stream, whose
//! producer carries the [`Reservation`].
//!
//! Reservations are pessimistic (the full per-call bound, since a stream's
//! length is unknowable up front): an admitted operation never waits for
//! more capacity mid-flight, so admission cannot deadlock on partial
//! allocations. When the per-call bound exceeds the pool, one operation is
//! always admitted, capped to the pool size, so admission cannot livelock
//! either.
//!
//! The pool is shared behind an [`Arc`] so reservation guards can release
//! without store access (host futures may be dropped at any point, e.g. on
//! task cancellation).

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

/// Shared admission state: reserved bytes and the FIFO wait queue.
#[derive(Debug, Default)]
pub(crate) struct BufferPool {
    state: Mutex<PoolState>,
}

#[derive(Debug, Default)]
struct PoolState {
    /// Bytes currently reserved by admitted operations.
    reserved: u64,
    /// Waiting admissions, front first. Tickets keep FIFO order stable
    /// across spurious wakes and cancelled waiters.
    queue: VecDeque<Waiter>,
    /// The next ticket to hand out.
    next_ticket: u64,
}

/// A queued admission: its ticket, how much it asked for, and its waker
/// once it has parked. The amount is recorded so a releasing or admitting
/// operation can ask whether *this* waiter fits, rather than guessing from
/// its own size.
#[derive(Debug)]
struct Waiter {
    ticket: u64,
    amount: u64,
    waker: Option<Waker>,
}

impl PoolState {
    /// Take the front waiter's waker if the pool can now fit *that* waiter.
    ///
    /// Returns the waker instead of waking it: a `Waker` may poll inline on
    /// the waking thread, and `std::sync::Mutex` is not reentrant, so waking
    /// under the pool lock risks deadlock. Every caller drops the guard
    /// first.
    #[must_use]
    fn take_front_waker(&mut self, total: u64) -> Option<Waker> {
        let front = self.queue.front_mut()?;
        if self.reserved.saturating_add(front.amount) > total {
            return None;
        }
        front.waker.take()
    }
}

/// Lock the pool, recovering from poisoning rather than panicking.
///
/// A panic elsewhere must not turn every later admission — including ones
/// in `Drop` — into an abort. The invariant this guards is a byte counter
/// and a queue; a poisoned lock leaves both readable and consistent.
fn lock(state: &Mutex<PoolState>) -> std::sync::MutexGuard<'_, PoolState> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl BufferPool {
    /// Reserve `amount` bytes, waiting (FIFO) until the pool can fit it
    /// under `total`. `amount` must be `<= total` (the caller clamps), so
    /// an empty pool always admits.
    pub(crate) fn admit(self: &Arc<Self>, amount: u64, total: u64) -> Admit {
        Admit {
            pool: self.clone(),
            amount,
            total,
            ticket: None,
        }
    }
}

/// A pending admission; resolves to a [`Reservation`].
pub(crate) struct Admit {
    pool: Arc<BufferPool>,
    amount: u64,
    total: u64,
    ticket: Option<u64>,
}

impl Future for Admit {
    type Output = Reservation;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut state = lock(&this.pool.state);
        // Join the queue on first poll; admission is strictly in ticket
        // order, so later arrivals cannot barge past earlier ones.
        let amount = this.amount;
        let ticket = *this.ticket.get_or_insert_with(|| {
            let ticket = state.next_ticket;
            state.next_ticket += 1;
            state.queue.push_back(Waiter {
                ticket,
                amount,
                waker: None,
            });
            ticket
        });
        let is_front = state.queue.front().is_some_and(|w| w.ticket == ticket);
        if is_front && state.reserved.saturating_add(this.amount) <= this.total {
            state.queue.pop_front();
            state.reserved += this.amount;
            // Cascade: the new front may also fit (e.g. after a bulk
            // release, or when reservations shrink). Whether it fits is a
            // question about *its* size, not this one's.
            let waker = state.take_front_waker(this.total);
            drop(state);
            if let Some(waker) = waker {
                waker.wake();
            }
            this.ticket = None;
            Poll::Ready(Reservation {
                pool: this.pool.clone(),
                amount: this.amount,
                total: this.total,
            })
        } else {
            let entry = state
                .queue
                .iter_mut()
                .find(|w| w.ticket == ticket)
                .expect("queued ticket present until admitted or dropped");
            entry.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

impl Drop for Admit {
    fn drop(&mut self) {
        // A cancelled waiter leaves the queue; if it was the front, the
        // next waiter gets its turn.
        let Some(ticket) = self.ticket else { return };
        let mut state = lock(&self.pool.state);
        let Some(index) = state.queue.iter().position(|w| w.ticket == ticket) else {
            return;
        };
        state.queue.remove(index);
        let waker = if index == 0 {
            state.take_front_waker(self.total)
        } else {
            None
        };
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

/// An admitted reservation of pool capacity; released on drop.
///
/// The guard travels with the operation's buffers: held across the input
/// drain and moved into the output stream's producer where one exists, so
/// capacity frees only when the retained bytes actually do.
#[derive(Debug)]
pub(crate) struct Reservation {
    pool: Arc<BufferPool>,
    amount: u64,
    /// The ceiling this reservation was admitted against, so releasing it
    /// can tell whether the next waiter now fits.
    total: u64,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let mut state = lock(&self.pool.state);
        state.reserved = state.reserved.saturating_sub(self.amount);
        let waker = state.take_front_waker(self.total);
        // Wake outside the lock: see `take_front_waker`.
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    fn poll_once<F: Future>(fut: Pin<&mut F>) -> Poll<F::Output> {
        fut.poll(&mut Context::from_waker(Waker::noop()))
    }

    /// An empty pool admits immediately, even for a reservation equal to
    /// the whole pool.
    #[test]
    fn admits_up_to_total() {
        let pool = Arc::new(BufferPool::default());
        let mut a = pin!(pool.admit(100, 100));
        let Poll::Ready(_guard) = poll_once(a.as_mut()) else {
            panic!("first admission should not wait");
        };
    }

    /// Admissions are FIFO: a later small reservation cannot barge past an
    /// earlier waiting one, and capacity release admits the front waiter.
    #[test]
    fn fifo_admission_and_release() {
        let pool = Arc::new(BufferPool::default());
        let mut first = pin!(pool.admit(60, 100));
        let Poll::Ready(guard1) = poll_once(first.as_mut()) else {
            panic!("first admission should not wait");
        };
        let mut second = pin!(pool.admit(60, 100));
        assert!(poll_once(second.as_mut()).is_pending(), "pool is full");
        let mut third = pin!(pool.admit(10, 100));
        assert!(
            poll_once(third.as_mut()).is_pending(),
            "smaller later arrival must not barge past the front waiter"
        );
        drop(guard1);
        let Poll::Ready(_guard2) = poll_once(second.as_mut()) else {
            panic!("released capacity admits the front waiter");
        };
        let Poll::Ready(_guard3) = poll_once(third.as_mut()) else {
            panic!("cascade admits the next waiter that fits");
        };
    }

    /// Dropping a waiting admission leaves the queue usable (the next
    /// waiter becomes the front).
    #[test]
    fn cancelled_waiter_unblocks_queue() {
        let pool = Arc::new(BufferPool::default());
        let mut first = pin!(pool.admit(100, 100));
        let Poll::Ready(guard1) = poll_once(first.as_mut()) else {
            panic!("first admission should not wait");
        };
        // Box so `drop` really drops the future (`pin!` locals live to end
        // of scope).
        let mut second = Box::pin(pool.admit(100, 100));
        assert!(poll_once(second.as_mut()).is_pending());
        let mut third = pin!(pool.admit(100, 100));
        assert!(poll_once(third.as_mut()).is_pending());
        drop(second);
        drop(guard1);
        let Poll::Ready(_guard3) = poll_once(third.as_mut()) else {
            panic!("queue must advance past a cancelled waiter");
        };
    }

    /// A waker that records whether it fired, and re-enters the pool lock
    /// when it does — the shape of an executor that polls inline on the
    /// waking thread. Waking under the pool's non-reentrant `Mutex` would
    /// deadlock here rather than merely being impolite.
    fn reentrant_waker(
        pool: &Arc<BufferPool>,
        fired: &Arc<std::sync::atomic::AtomicBool>,
    ) -> Waker {
        struct Reentrant(Arc<BufferPool>, Arc<std::sync::atomic::AtomicBool>);
        impl std::task::Wake for Reentrant {
            fn wake(self: Arc<Self>) {
                self.1.store(true, std::sync::atomic::Ordering::SeqCst);
                // Would deadlock if the caller still held the lock.
                let _ = lock(&self.0.state).reserved;
            }
        }
        Waker::from(Arc::new(Reentrant(pool.clone(), fired.clone())))
    }

    /// Releasing a reservation must not wake with the pool lock held.
    #[test]
    fn release_wakes_outside_the_lock() {
        let pool = Arc::new(BufferPool::default());
        let mut first = pin!(pool.admit(100, 100));
        let Poll::Ready(guard1) = poll_once(first.as_mut()) else {
            panic!("first admission should not wait");
        };
        let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let waker = reentrant_waker(&pool, &fired);
        let mut second = pin!(pool.admit(100, 100));
        assert!(second
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending());
        drop(guard1);
        assert!(
            fired.load(std::sync::atomic::Ordering::SeqCst),
            "the front waiter should have been woken"
        );
    }

    /// The cascade after an admission must ask whether the *front waiter*
    /// fits, not whether another operation of the admitting one's size
    /// would. Here a 60-byte admission leaves 40 free: another 60 would not
    /// fit, but the 5-byte waiter behind it does. Consulting the wrong
    /// amount leaves that waiter parked with nothing scheduled to wake it.
    #[test]
    fn cascade_consults_the_front_waiters_amount() {
        let pool = Arc::new(BufferPool::default());
        let mut first = pin!(pool.admit(60, 100));
        let Poll::Ready(guard1) = poll_once(first.as_mut()) else {
            panic!("first admission should not wait");
        };

        // Queue a same-size waiter, then a small one behind it.
        let mut second = pin!(pool.admit(60, 100));
        assert!(poll_once(second.as_mut()).is_pending(), "pool is full");
        let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let waker = reentrant_waker(&pool, &fired);
        let mut third = pin!(pool.admit(5, 100));
        assert!(third
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending());

        // Releasing admits `second` (60 of 100). The cascade must then see
        // that `third` (5) fits in the remaining 40 and wake it.
        drop(guard1);
        let Poll::Ready(_guard2) = poll_once(second.as_mut()) else {
            panic!("released capacity admits the front waiter");
        };
        assert!(
            fired.load(std::sync::atomic::Ordering::SeqCst),
            "the waiter that fits must be woken by the cascade"
        );
    }
}
