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
    queue: VecDeque<(u64, Option<Waker>)>,
    /// The next ticket to hand out.
    next_ticket: u64,
}

impl PoolState {
    /// Wake the queue's front waiter, if any.
    fn wake_front(&mut self) {
        if let Some((_, waker)) = self.queue.front_mut() {
            if let Some(waker) = waker.take() {
                waker.wake();
            }
        }
    }
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
        let mut state = this.pool.state.lock().unwrap();
        // Join the queue on first poll; admission is strictly in ticket
        // order, so later arrivals cannot barge past earlier ones.
        let ticket = *this.ticket.get_or_insert_with(|| {
            let ticket = state.next_ticket;
            state.next_ticket += 1;
            state.queue.push_back((ticket, None));
            ticket
        });
        let is_front = state.queue.front().is_some_and(|(t, _)| *t == ticket);
        if is_front && state.reserved.saturating_add(this.amount) <= this.total {
            state.queue.pop_front();
            state.reserved += this.amount;
            // Cascade: the new front may also fit (e.g. after a bulk
            // release, or when reservations shrink).
            if state.reserved.saturating_add(this.amount) <= this.total {
                state.wake_front();
            }
            this.ticket = None;
            Poll::Ready(Reservation {
                pool: this.pool.clone(),
                amount: this.amount,
            })
        } else {
            let entry = state
                .queue
                .iter_mut()
                .find(|(t, _)| *t == ticket)
                .expect("queued ticket present until admitted or dropped");
            entry.1 = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

impl Drop for Admit {
    fn drop(&mut self) {
        // A cancelled waiter leaves the queue; if it was the front, the
        // next waiter gets its turn.
        if let Some(ticket) = self.ticket {
            let mut state = self.pool.state.lock().unwrap();
            if let Some(index) = state.queue.iter().position(|(t, _)| *t == ticket) {
                state.queue.remove(index);
                if index == 0 {
                    state.wake_front();
                }
            }
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
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let mut state = self.pool.state.lock().unwrap();
        state.reserved = state.reserved.saturating_sub(self.amount);
        state.wake_front();
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
}
