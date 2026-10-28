use crate::{
    ConnectionInfo, Error, Observer,
    buffer::{Buffer, ReadChunk, WriteBatch},
    client::{Inner, lock},
};
#[cfg(any(feature = "tokio", feature = "futures-io"))]
use std::pin::Pin;
use std::{
    io::{self, IoSlice},
    sync::{Arc, Mutex, Weak},
    task::{Context, Poll, Waker},
    time::Instant,
};

pub(crate) const MAX_IO: usize = 64 * 1024;
const MIN_BUFFER: usize = 4096;
#[derive(Default)]
pub(crate) struct State {
    pub connected: bool,
    pub handshake_waker: Option<Waker>,
    pub read_deadline: Option<Instant>,
    pub write_deadline: Option<Instant>,
    pub terminal: Option<Error>,
    pub eof: bool,
    pub read_pending: bool,
    pub owned_read_pending: bool,
    pub read_data: Option<ReadChunk>,
    pub write_pending: bool,
    pub owned_write_pending: bool,
    pub write_shutdown_pending: bool,
    pub write_shutdown: bool,
    pub write_shutdown_error: Option<Error>,
    pub write_queued: Option<WriteBatch>,
    pub write_spares: [Option<Buffer>; 2],
    pub write_wait_flush: bool,
    pub read_waker: Option<Waker>,
    pub write_waker: Option<Waker>,
}
impl State {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn take_spare(&mut self, capacity: usize) -> Option<Buffer> {
        let index = self
            .write_spares
            .iter()
            .enumerate()
            .filter_map(|(i, b)| {
                b.as_ref()
                    .filter(|b| b.capacity >= capacity)
                    .map(|b| (i, b.capacity))
            })
            .min_by_key(|(_, capacity)| *capacity)
            .map(|(i, _)| i)
            .or_else(|| self.write_spares.iter().position(Option::is_some));
        index.and_then(|i| self.write_spares[i].take())
    }

    pub fn recycle(&mut self, buffer: Option<Buffer>) {
        if let Some(slot) = self.write_spares.iter_mut().find(|slot| slot.is_none()) {
            *slot = buffer;
        }
    }
}
pub(crate) struct Shared {
    pub state: Mutex<State>,
    pub inner: Weak<Inner>,
    pub observer: Option<Arc<dyn Observer>>,
}
impl Shared {
    pub fn fail(&self, error: Error) {
        let mut state = lock(&self.state);
        if state.terminal.is_none() {
            state.terminal = Some(error.clone());
        }
        state.read_pending = false;
        state.write_pending = false;
        state.write_queued = None;
        state.write_spares = [None, None];
        let handshake = state.handshake_waker.take();
        let read = state.read_waker.take();
        let write = state.write_waker.take();
        drop(state);
        if let Some(waker) = handshake {
            waker.wake();
        }
        if let Some(waker) = read {
            waker.wake();
        }
        if let Some(waker) = write {
            waker.wake();
        }
    }
    pub fn dispatch(&self, id: u64, batch: WriteBatch) {
        let result = self
            .inner
            .upgrade()
            .ok_or_else(Error::closed)
            .and_then(|inner| inner.write(id, batch));
        if let Err(error) = result {
            self.fail(error);
        }
    }
}

/// A buffered CONNECT stream. Reads retain native-owned leases across canceled
/// futures. Writes use at most two 64 KiB buffers: one in flight and one queued.
/// Queued writes progress automatically, including without an explicit flush.
pub struct NaiveStream {
    pub(crate) inner: Arc<Inner>,
    pub(crate) shared: Arc<Shared>,
    pub(crate) id: u64,
    pub(crate) closed: bool,
    pub(crate) owns_close: bool,
}
impl NaiveStream {
    /// Splits the stream into one independent reader and writer for concurrent
    /// owned IO. Dropping the last half aborts the stream; dropping only one
    /// half does not synthesize an EOF or a FIN.
    pub fn into_split(self) -> (crate::owned::ReadHalf, crate::owned::WriteHalf) {
        crate::owned::split(self)
    }
    pub(crate) fn io_view(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            shared: self.shared.clone(),
            id: self.id,
            closed: false,
            owns_close: false,
        }
    }
    pub fn id(&self) -> u64 {
        self.id
    }
    /// Waits for CONNECT/padding negotiation. Canceling this future leaves the
    /// stream intact; dropping the stream cancels CONNECT. Application writes
    /// are never sent before this completes, including through the IO adapters.
    pub async fn handshake(&mut self) -> Result<(), Error> {
        std::future::poll_fn(|cx| self.poll_handshake(cx)).await
    }
    pub fn poll_handshake(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let mut state = lock(&self.shared.state);
        if let Some(error) = &state.terminal {
            return Poll::Ready(Err(error.clone()));
        }
        if state.connected {
            return Poll::Ready(Ok(()));
        }
        state.handshake_waker = Some(cx.waker().clone());
        Poll::Pending
    }
    /// Snapshot after a successful handshake. It fails for a pending/closed
    /// stream; client aggregate stats remain available after shutdown.
    pub async fn info(&self) -> Result<ConnectionInfo, Error> {
        self.inner.info(self.id).await
    }
    pub fn read_deadline(&self) -> Option<Instant> {
        lock(&self.shared.state).read_deadline
    }
    pub fn write_deadline(&self) -> Option<Instant> {
        lock(&self.shared.state).write_deadline
    }
    /// Sets a persistent deadline. Clearing/extending it resumes subsequent
    /// reads without discarding data received while the deadline was expired.
    pub fn set_read_deadline(&self, deadline: Option<Instant>) -> Result<(), Error> {
        self.deadline_handle().set_read_deadline(deadline)
    }
    /// Accepted buffered writes continue even after this expires. A timeout
    /// limits waiting/accepting new bytes; close the stream to abort queued IO.
    pub fn set_write_deadline(&self, deadline: Option<Instant>) -> Result<(), Error> {
        self.deadline_handle().set_write_deadline(deadline)
    }
    pub fn set_deadline(&self, deadline: Option<Instant>) -> Result<(), Error> {
        self.deadline_handle().set_deadline(deadline)
    }
    /// An independent controller for deadline changes while split IO is pending.
    /// It does not keep the stream, client or read buffers alive.
    pub fn deadline_handle(&self) -> DeadlineHandle {
        DeadlineHandle {
            inner: Arc::downgrade(&self.inner),
            shared: Arc::downgrade(&self.shared),
            id: self.id,
        }
    }
    /// Cancels both directions immediately; shutdown() flushes before closing.
    pub fn close(&mut self) {
        if !self.closed {
            self.closed = true;
            self.shared.fail(Error::closed());
            self.inner.cancel(self.id);
        }
    }
    /// Drains accepted writes and then closes both directions. Unlike
    /// `shutdown_write`, this is available for every supported transport.
    pub async fn close_after_flush(&mut self) -> Result<(), Error> {
        std::future::poll_fn(|cx| self.poll_close_stream(cx))
            .await
            .map_err(Into::into)
    }
    /// Poll a bounded write of owned copies. Usable with any executor.
    pub fn poll_write_slices(
        &mut self,
        cx: &mut Context<'_>,
        slices: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let mut state = lock(&self.shared.state);
        if let Some(error) = &state.terminal {
            return Poll::Ready(Err(error.io()));
        }
        if state.write_shutdown || state.write_shutdown_pending {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let size = slices
            .iter()
            .fold(0usize, |n, s| n.saturating_add(s.len()))
            .min(MAX_IO);
        if size == 0 {
            return Poll::Ready(Ok(0));
        }
        if expired(state.write_deadline) {
            return Poll::Ready(Err(Error::native(-7).io()));
        }
        if !state.connected {
            state.write_wait_flush = false;
            state.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        if state.owned_write_pending {
            state.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let capacity = size.clamp(MIN_BUFFER, MAX_IO).next_power_of_two();
        if state.write_pending {
            if state.write_queued.is_none() {
                let batch = WriteBatch::new(state.take_spare(capacity), capacity);
                state.write_queued = Some(batch);
            }
            let batch = state.write_queued.as_mut().unwrap();
            if batch.remaining() == 0 {
                state.write_wait_flush = false;
                state.write_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            let mut n = 0;
            for slice in slices {
                n += batch.append(slice);
                if batch.remaining() == 0 {
                    break;
                }
            }
            return Poll::Ready(Ok(n));
        }
        let mut batch = WriteBatch::new(state.take_spare(capacity), capacity);
        let mut n = 0;
        for slice in slices {
            n += batch.append(slice);
            if batch.remaining() == 0 {
                break;
            }
        }
        state.write_pending = true;
        drop(state);
        if let Err(error) = self.inner.write(self.id, batch) {
            self.shared.fail(error.clone());
            return Poll::Ready(Err(error.io()));
        }
        Poll::Ready(Ok(n))
    }
}
#[derive(Clone)]
pub struct DeadlineHandle {
    inner: Weak<Inner>,
    shared: Weak<Shared>,
    id: u64,
}
impl DeadlineHandle {
    pub fn set_read_deadline(&self, deadline: Option<Instant>) -> Result<(), Error> {
        self.set(1, deadline)
    }
    pub fn set_write_deadline(&self, deadline: Option<Instant>) -> Result<(), Error> {
        self.set(2, deadline)
    }
    pub fn set_deadline(&self, deadline: Option<Instant>) -> Result<(), Error> {
        self.set(3, deadline)
    }
    fn set(&self, mask: u32, deadline: Option<Instant>) -> Result<(), Error> {
        let inner = self.inner.upgrade().ok_or_else(Error::closed)?;
        let shared = self.shared.upgrade().ok_or_else(Error::closed)?;
        // Keep state changes and native posts in the same order across cloned
        // controllers. Native submission only posts a task; it never calls back
        // synchronously while this lock is held.
        let mut state = lock(&shared.state);
        if let Some(error) = &state.terminal {
            return Err(error.clone());
        }
        let micros = match deadline {
            None => -1,
            Some(deadline) => i64::try_from(
                deadline
                    .saturating_duration_since(Instant::now())
                    .as_nanos()
                    .div_ceil(1000),
            )
            .map_err(|_| Error::invalid("deadline is too far in the future"))?,
        };
        let read = if mask & 1 != 0 {
            state.read_deadline = deadline;
            state.read_waker.take()
        } else {
            None
        };
        let write = if mask & 2 != 0 {
            state.write_deadline = deadline;
            state.write_waker.take()
        } else {
            None
        };
        let mut result = 0;
        let submitted = inner.submit(|engine| {
            result = unsafe { naive_sys::naive_engine_set_deadline(engine, self.id, mask, micros) };
        });
        drop(state);
        if let Some(waker) = read {
            waker.wake();
        }
        if let Some(waker) = write {
            waker.wake();
        }
        submitted?;
        if result != 0 {
            return Err(Error::native(result));
        }
        Ok(())
    }
}

impl Drop for NaiveStream {
    fn drop(&mut self) {
        if self.owns_close {
            self.close();
        }
    }
}
impl std::fmt::Debug for NaiveStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NaiveStream")
            .field("id", &self.id)
            .field("closed", &self.closed)
            .finish()
    }
}
impl NaiveStream {
    /// Returns the next native-owned immutable chunk without copying payload.
    /// `None` is EOF. Canceling only this future preserves the pending read and
    /// any completed data for the next read. Hosts own retention/backpressure.
    pub async fn read_chunk(&mut self) -> Result<Option<ReadChunk>, Error> {
        std::future::poll_fn(|cx| self.poll_read_chunk(cx)).await
    }
    pub fn poll_read_chunk(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<ReadChunk>, Error>> {
        let mut state = lock(&self.shared.state);
        if expired(state.read_deadline) && state.terminal.is_none() && !state.eof {
            return Poll::Ready(Err(Error::native(-7)));
        }
        if let Some(chunk) = state.read_data.take() {
            return Poll::Ready(Ok(Some(chunk)));
        }
        if let Some(error) = &state.terminal {
            return Poll::Ready(Err(error.clone()));
        }
        if state.eof {
            return Poll::Ready(Ok(None));
        }
        state.read_waker = Some(cx.waker().clone());
        if !state.connected || state.owned_read_pending {
            return Poll::Pending;
        }
        if !state.read_pending {
            state.read_pending = true;
            if let Err(error) = self.inner.submit(|ptr| unsafe {
                naive_sys::naive_engine_read(ptr, self.id, MAX_IO);
            }) {
                state.read_pending = false;
                state.terminal = Some(error.clone());
                return Poll::Ready(Err(error));
            }
        }
        Poll::Pending
    }
    /// Poll a read into a slice without requiring an IO-trait adapter.
    pub fn poll_read_slice(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_read_with(cx, buffer.len(), |bytes| {
            buffer[..bytes.len()].copy_from_slice(bytes)
        })
    }
    pub(crate) fn poll_read_with(
        &mut self,
        cx: &mut Context<'_>,
        capacity: usize,
        put: impl FnOnce(&[u8]),
    ) -> Poll<io::Result<usize>> {
        if capacity == 0 {
            return Poll::Ready(Ok(0));
        }
        let mut state = lock(&self.shared.state);
        if expired(state.read_deadline) && state.terminal.is_none() && !state.eof {
            return Poll::Ready(Err(Error::native(-7).io()));
        }
        if let Some(chunk) = &mut state.read_data {
            let n = capacity.min(chunk.length - chunk.offset);
            put(chunk.buffer.bytes(chunk.offset, chunk.offset + n));
            chunk.offset += n;
            if chunk.offset == chunk.length {
                state.read_data = None;
            }
            return Poll::Ready(Ok(n));
        }
        if let Some(error) = &state.terminal {
            return Poll::Ready(Err(error.io()));
        }
        if state.eof {
            return Poll::Ready(Ok(0));
        }
        state.read_waker = Some(cx.waker().clone());
        if !state.connected {
            return Poll::Pending;
        }
        if state.owned_read_pending {
            return Poll::Pending;
        }
        if !state.read_pending {
            state.read_pending = true;
            let capacity = capacity.clamp(MIN_BUFFER, MAX_IO).next_power_of_two();
            // Only a capacity crosses FFI, never the caller's borrowed buffer.
            let result = self
                .inner
                .submit(|ptr| unsafe { naive_sys::naive_engine_read(ptr, self.id, capacity) });
            if let Err(error) = result {
                state.read_pending = false;
                state.terminal = Some(error.clone());
                return Poll::Ready(Err(error.io()));
            }
        }
        Poll::Pending
    }
}
impl NaiveStream {
    /// Ends only this stream's write direction after draining accepted writes.
    /// H2/H3 proxy streams support this; other negotiated transports may return
    /// Unsupported without closing the read direction. `close()` aborts both.
    pub async fn shutdown_write(&mut self) -> Result<(), Error> {
        std::future::poll_fn(|cx| self.poll_shutdown_write(cx))
            .await
            .map_err(Into::into)
    }
    pub fn poll_shutdown_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        {
            let mut state = lock(&self.shared.state);
            if let Some(error) = &state.terminal {
                return Poll::Ready(Err(error.io()));
            }
            if state.write_shutdown {
                return Poll::Ready(Ok(()));
            }
            if let Some(error) = &state.write_shutdown_error {
                return Poll::Ready(Err(error.io()));
            }
            if state.write_shutdown_pending {
                state.write_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
        }
        std::task::ready!(self.poll_flush_pending(cx))?;
        let mut state = lock(&self.shared.state);
        if let Some(error) = &state.terminal {
            return Poll::Ready(Err(error.io()));
        }
        state.write_shutdown_pending = true;
        state.write_waker = Some(cx.waker().clone());
        if let Err(error) = self
            .inner
            .submit(|ptr| unsafe { naive_sys::naive_engine_shutdown_write(ptr, self.id) })
        {
            state.write_shutdown_pending = false;
            state.write_shutdown_error = Some(error.clone());
            return Poll::Ready(Err(error.io()));
        }
        Poll::Pending
    }
    pub fn poll_flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = lock(&self.shared.state);
        if let Some(error) = &state.terminal {
            return Poll::Ready(Err(error.io()));
        }
        if !state.connected {
            if expired(state.write_deadline) {
                return Poll::Ready(Err(Error::native(-7).io()));
            }
            state.write_wait_flush = true;
            state.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        if !state.write_pending && !state.owned_write_pending {
            debug_assert!(state.write_queued.is_none());
            return Poll::Ready(Ok(()));
        }
        if expired(state.write_deadline) {
            return Poll::Ready(Err(Error::native(-7).io()));
        }
        state.write_wait_flush = true;
        state.write_waker = Some(cx.waker().clone());
        Poll::Pending
    }
    /// Flush accepted bytes and close both directions.
    pub fn poll_close_stream(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Ok(()));
        }
        std::task::ready!(self.poll_flush_pending(cx))?;
        self.close();
        Poll::Ready(Ok(()))
    }
}

#[cfg(feature = "tokio")]
impl tokio::io::AsyncRead for NaiveStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.poll_read_with(cx, buffer.remaining(), |bytes| buffer.put_slice(bytes))
            .map_ok(|_| ())
    }
}
#[cfg(feature = "tokio")]
impl tokio::io::AsyncWrite for NaiveStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_write_slices(cx, &[IoSlice::new(bytes)])
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.poll_write_slices(cx, buffers)
    }
    fn is_write_vectored(&self) -> bool {
        true
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush_pending(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_shutdown_write(cx)
    }
}
#[cfg(feature = "futures-io")]
impl futures_io::AsyncRead for NaiveStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_read_slice(cx, buffer)
    }
}
#[cfg(feature = "futures-io")]
impl futures_io::AsyncWrite for NaiveStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_write_slices(cx, &[IoSlice::new(bytes)])
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.poll_write_slices(cx, buffers)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush_pending(cx)
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_shutdown_write(cx)
    }
}

fn expired(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|deadline| Instant::now() >= deadline)
}
