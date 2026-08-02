//! Stream plumbing for the host: draining input `stream<u8>`s into buffers
//! under the admission caps, and producing output streams that carry their
//! admission [`Reservation`].

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::channel::oneshot;
use wasmtime::component::{
    Accessor, Destination, Source, StreamConsumer, StreamProducer, StreamReader, StreamResult,
    VecBuffer,
};
use wasmtime::{Result, StoreContextMut};

use crate::bindings::webcrypto::types::Error;
use crate::limits::Reservation;
use crate::WasiWebcrypto;

/// A [`StreamConsumer`] that drains every byte of a `stream<u8>` into a
/// buffer, handing the completed buffer back through `done_tx` when the
/// stream ends.
///
/// Dropping the consumer is how Wasmtime signals end-of-stream (the writer
/// dropped its end), so `Drop` is the sole completion point. If a host-side
/// pipe error occurs, the buffer is never delivered — the channel closes
/// unsent and [`drain_stream`] surfaces an error — so a partial buffer can
/// never be mistaken for the complete input.
struct ByteCollector {
    buf: Vec<u8>,
    /// The per-call buffering cap: bytes beyond it are drained but
    /// discarded — this host drains to completion rather than exercising
    /// the streaming contract's early-close-on-error permission — and the
    /// operation reports the overflow instead of a result.
    cap: usize,
    overflowed: bool,
    failed: bool,
    done_tx: Option<oneshot::Sender<std::result::Result<Vec<u8>, InputOverflow>>>,
}

/// Marker for an input stream that exceeded the per-call buffering cap.
#[derive(Debug, PartialEq)]
struct InputOverflow;

impl ByteCollector {
    /// Retain `chunk` while the running total stays within the per-call
    /// cap. The first chunk that would push past the cap latches the
    /// collector into drain-and-discard: the held buffer is freed, this
    /// chunk and every later one are dropped, and `Drop` delivers the
    /// overflow marker instead of a buffer.
    fn accept(&mut self, chunk: &[u8]) {
        if !self.overflowed && self.buf.len().saturating_add(chunk.len()) > self.cap {
            self.overflowed = true;
            self.buf = Vec::new();
        }
        if !self.overflowed {
            self.buf.extend_from_slice(chunk);
        }
    }
}

impl<D: Send + 'static> StreamConsumer<D> for ByteCollector {
    type Item = u8;

    fn poll_consume(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        mut store: StoreContextMut<D>,
        mut source: Source<'_, u8>,
        finish: bool,
    ) -> Poll<Result<StreamResult>> {
        let this = self.get_mut(); // safe: ByteCollector is Unpin

        let available = source.remaining(&mut store);
        if available > 0 {
            let mut chunk = Vec::with_capacity(available);
            if let Err(err) = source.read(&mut store, &mut chunk) {
                // Never let `Drop` deliver a partial buffer as if it were
                // the complete input.
                this.failed = true;
                return Poll::Ready(Err(err));
            }
            this.accept(&chunk);
            return Poll::Ready(Ok(StreamResult::Completed));
        }

        // No bytes available. When `finish` is set the writer cancelled its
        // pending write; the stream itself remains open, so keep the buffer
        // and keep collecting — `Drop` is the completion point.
        if finish {
            return Poll::Ready(Ok(StreamResult::Cancelled));
        }

        // Otherwise this is a zero-length write, which is legal. Report it
        // consumed rather than parking: `StreamConsumer` permits
        // `Ready(Completed)` with nothing taken when nothing was available,
        // provided the next call can accept an item — unconditionally true
        // here, since this collector either buffers or, past the cap,
        // drains and discards.
        //
        // This consumer must never return `Pending`: it awaits no
        // external event, so it has nothing to arm `cx`'s waker from, and
        // a parked poll is never resumed — the writer would never receive
        // `COMPLETED`, `drain_stream`'s completion signal would never
        // fire, and the admission `Reservation` held across the call
        // would starve every other operation in the store.
        Poll::Ready(Ok(StreamResult::Completed))
    }
}

impl Drop for ByteCollector {
    fn drop(&mut self) {
        if !self.failed {
            if let Some(tx) = self.done_tx.take() {
                let _ = tx.send(if self.overflowed {
                    Err(InputOverflow)
                } else {
                    Ok(std::mem::take(&mut self.buf))
                });
            }
        }
    }
}

/// Drain an entire `stream<u8>` into a buffer, resolving once the stream ends
/// (its writer dropped). The outer `Result` is a host-side pipe error (the
/// consumer torn down without delivering the complete input); the inner one
/// reports an input that exceeded the admitted per-call buffering cap as
/// the WIT's recoverable operational error.
pub(crate) async fn drain_stream<T: Send>(
    accessor: &Accessor<T, WasiWebcrypto>,
    data: StreamReader<u8>,
    cap: usize,
) -> Result<std::result::Result<Vec<u8>, Error>> {
    let (done_tx, done_rx) = oneshot::channel();
    accessor.with(|access| {
        data.pipe(
            access,
            ByteCollector {
                buf: Vec::new(),
                cap,
                overflowed: false,
                failed: false,
                done_tx: Some(done_tx),
            },
        )
    })?;
    Ok(done_rx
        .await
        .map_err(|_| wasmtime::Error::msg("input stream ended without completing"))?
        .map_err(|InputOverflow| {
            Error::Other(format!(
                "input exceeds the per-call buffer limit ({cap} bytes); see \
                 WasiWebcryptoCtx::set_per_call_buffer_limit and \
                 Store::set_hostcall_fuel"
            ))
        }))
}

/// A host-produced output stream that carries the operation's buffer-pool
/// [`Reservation`]: the reservation releases only when the output bytes have
/// been handed off (or the stream is dropped), so pool capacity tracks the
/// bytes the host actually retains.
pub(crate) struct GuardedOutput {
    data: Option<Vec<u8>>,
    _reservation: Reservation,
}

impl GuardedOutput {
    pub(crate) fn new(data: Vec<u8>, reservation: Reservation) -> Self {
        Self {
            data: (!data.is_empty()).then_some(data),
            _reservation: reservation,
        }
    }
}

impl<D> StreamProducer<D> for GuardedOutput {
    type Item = u8;
    type Buffer = VecBuffer<u8>;

    fn poll_produce<'a>(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _store: StoreContextMut<'a, D>,
        mut dst: Destination<'a, Self::Item, Self::Buffer>,
        _finish: bool,
    ) -> Poll<Result<StreamResult>> {
        let this = self.get_mut();
        match this.data.take() {
            // Hand the whole buffer over but stay alive (`Completed`): we
            // are polled again once it has drained, and only then drop —
            // releasing the reservation after the bytes have left.
            Some(bytes) => {
                dst.set_buffer(bytes.into());
                Poll::Ready(Ok(StreamResult::Completed))
            }
            None => Poll::Ready(Ok(StreamResult::Dropped)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ByteCollector;
    use futures::channel::oneshot;

    /// A collector with the given cap and no completion channel (these
    /// tests observe the retention state directly).
    fn collector(cap: usize) -> ByteCollector {
        ByteCollector {
            buf: Vec::new(),
            cap,
            overflowed: false,
            failed: false,
            done_tx: None,
        }
    }

    /// An input summing to exactly the cap is retained in full: the latch
    /// fires strictly past the cap, not at it.
    #[test]
    fn accept_retains_up_to_the_cap() {
        let mut c = collector(8);
        c.accept(&[1; 5]);
        c.accept(&[2; 3]);
        assert!(!c.overflowed);
        assert_eq!(c.buf, [1, 1, 1, 1, 1, 2, 2, 2]);
    }

    /// The chunk that pushes one byte past the cap latches drain-and-discard
    /// and frees what was held.
    #[test]
    fn accept_latches_one_byte_past_the_cap() {
        let mut c = collector(8);
        c.accept(&[1; 8]);
        c.accept(&[2; 1]);
        assert!(c.overflowed);
        assert!(c.buf.is_empty());
    }

    /// A single chunk that jumps far past the cap latches too — the
    /// comparison is an ordering, not an exact-boundary hit.
    #[test]
    fn accept_latches_on_a_jump_past_the_cap() {
        let mut c = collector(8);
        c.accept(&[1; 19]);
        assert!(c.overflowed);
        assert!(c.buf.is_empty());
    }

    /// Once latched, later chunks stay discarded: the latch never resets
    /// within a collection.
    #[test]
    fn accept_stays_latched() {
        let mut c = collector(8);
        c.accept(&[1; 9]);
        c.accept(&[2; 1]);
        assert!(c.overflowed);
        assert!(c.buf.is_empty());
    }

    /// Dropping the collector (Wasmtime's end-of-stream notification)
    /// delivers the collected buffer.
    #[test]
    fn byte_collector_drop_delivers_buffer() {
        let (done_tx, mut done_rx) = oneshot::channel();
        drop(ByteCollector {
            buf: b"collected".to_vec(),
            cap: usize::MAX,
            overflowed: false,
            failed: false,
            done_tx: Some(done_tx),
        });
        assert_eq!(done_rx.try_recv(), Ok(Some(Ok(b"collected".to_vec()))));
    }

    /// An over-cap collector delivers the overflow marker, not the (already
    /// discarded) buffer.
    #[test]
    fn byte_collector_overflow_delivers_marker() {
        let (done_tx, mut done_rx) = oneshot::channel();
        drop(ByteCollector {
            buf: Vec::new(),
            cap: 4,
            overflowed: true,
            failed: false,
            done_tx: Some(done_tx),
        });
        assert_eq!(done_rx.try_recv(), Ok(Some(Err(super::InputOverflow))));
    }

    /// After a pipe error, dropping the collector must NOT deliver the
    /// partial buffer as if it were the complete input: the channel closes
    /// unsent, which `drain_stream` maps to an error.
    #[test]
    fn byte_collector_drop_after_failure_delivers_nothing() {
        let (done_tx, mut done_rx) =
            oneshot::channel::<std::result::Result<Vec<u8>, super::InputOverflow>>();
        drop(ByteCollector {
            buf: b"partial".to_vec(),
            cap: usize::MAX,
            overflowed: false,
            failed: true,
            done_tx: Some(done_tx),
        });
        assert!(done_rx.try_recv().is_err());
    }
}
