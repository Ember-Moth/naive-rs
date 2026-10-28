//! Runtime-independent owned IO. Local operations accept `!Send` owners and
//! copy through the ordinary stream path. Native operations require `Send` and
//! keep the owner inside the actual native IOBuffer until its last reference
//! disappears. Neither API requires a Rust runtime handle.
//!
//! Thread-local owners are valid for `read_local`/`write_local`, but cannot be
//! handed to a native IO thread:
//! ```compile_fail
//! use naive::{NaiveStream, owned::Guarded};
//! use std::rc::Rc;
//! fn cannot_cross_threads(stream: &mut NaiveStream) {
//!     let buffer = Guarded::new(vec![1u8], Rc::new(()));
//!     let _operation = stream.write_owned(buffer);
//! }
//! ```
use crate::{
    Error, NaiveStream,
    client::{Inner, lock},
    stream::{MAX_IO, Shared},
};
use futures_channel::oneshot;
use std::{
    ffi::c_void,
    future::{Future, poll_fn},
    io::IoSlice,
    pin::Pin,
    sync::{Arc, Weak},
    task::Poll,
    time::Instant,
};

/// A buffer whose initialized prefix can be lent to an IO operation.
///
/// # Safety
/// Once the owner has been placed in a `Box`, `as_ptr` must identify the same
/// allocation until that owner is returned or dropped. `bytes_init` bytes must
/// be initialized and readable. No alias may mutate/reallocate them during IO.
/// Methods must not invalidate previously returned pointers. `Send` is a
/// separate bound: implementing this trait does not authorize changing threads.
pub unsafe trait IoBuf: 'static {
    fn as_ptr(&self) -> *const u8;
    fn bytes_init(&self) -> usize;
}

/// Exclusive writable storage, with a possibly uninitialized tail.
///
/// # Safety
/// The `IoBuf` guarantees also apply to `as_mut_ptr`. `bytes_total` bytes must
/// be writable, and no other reference may access that region during the IO.
/// `set_init(n)` must expose only the initialized prefix written by the operation
/// (fixed-size already-initialized arrays may keep their length).
pub unsafe trait IoBufMut: 'static {
    fn as_mut_ptr(&mut self) -> *mut u8;
    fn bytes_total(&mut self) -> usize;
    /// # Safety
    /// The first `initialized` bytes were written and fit inside `bytes_total`.
    unsafe fn set_init(&mut self, initialized: usize);
}

// SAFETY: a native read lease owns an immutable allocation with a stable
// address, so it can be handed directly to another stream without Bytes.
unsafe impl IoBuf for crate::ReadChunk {
    fn as_ptr(&self) -> *const u8 {
        self.as_ref().as_ptr()
    }
    fn bytes_init(&self) -> usize {
        self.len()
    }
}

/// Couples a host's permit/lease to its buffer without depending on a specific
/// pool or budget implementation. Both fields stay owned until native release.
pub struct Guarded<B, G> {
    pub buffer: B,
    pub guard: G,
}
impl<B, G> Guarded<B, G> {
    pub fn new(buffer: B, guard: G) -> Self {
        Self { buffer, guard }
    }
    pub fn into_parts(self) -> (B, G) {
        (self.buffer, self.guard)
    }
}
// SAFETY: the wrapper forwards the underlying buffer's invariants and never
// moves either field while native IO owns the boxed wrapper.
unsafe impl<B: IoBuf, G: 'static> IoBuf for Guarded<B, G> {
    fn as_ptr(&self) -> *const u8 {
        self.buffer.as_ptr()
    }
    fn bytes_init(&self) -> usize {
        self.buffer.bytes_init()
    }
}
unsafe impl<B: IoBufMut, G: 'static> IoBufMut for Guarded<B, G> {
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.buffer.as_mut_ptr()
    }
    fn bytes_total(&mut self) -> usize {
        self.buffer.bytes_total()
    }
    unsafe fn set_init(&mut self, n: usize) {
        unsafe {
            self.buffer.set_init(n);
        }
    }
}

// SAFETY: Vec owns a stable heap allocation; it is not modified while lent.
unsafe impl IoBuf for Vec<u8> {
    fn as_ptr(&self) -> *const u8 {
        self.as_slice().as_ptr()
    }
    fn bytes_init(&self) -> usize {
        self.len()
    }
}
// SAFETY: capacity is exclusively writable, and set_len publishes filled bytes.
unsafe impl IoBufMut for Vec<u8> {
    fn as_mut_ptr(&mut self) -> *mut u8 {
        Vec::as_mut_ptr(self)
    }
    fn bytes_total(&mut self) -> usize {
        self.capacity()
    }
    unsafe fn set_init(&mut self, initialized: usize) {
        assert!(initialized <= self.capacity());
        unsafe { self.set_len(initialized) };
    }
}
// SAFETY: the boxed slice has a fixed address and fully initialized contents.
unsafe impl IoBuf for Box<[u8]> {
    fn as_ptr(&self) -> *const u8 {
        self.as_ref().as_ptr()
    }
    fn bytes_init(&self) -> usize {
        self.len()
    }
}
// SAFETY: a unique boxed slice is exclusively writable.
unsafe impl IoBufMut for Box<[u8]> {
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.as_mut().as_mut_ptr()
    }
    fn bytes_total(&mut self) -> usize {
        self.len()
    }
    unsafe fn set_init(&mut self, initialized: usize) {
        assert!(initialized <= self.len());
    }
}
// SAFETY: native operations box the owner before taking its pointer, so inline
// array storage is not moved until the native lease ends.
unsafe impl<const N: usize> IoBuf for [u8; N] {
    fn as_ptr(&self) -> *const u8 {
        self.as_slice().as_ptr()
    }
    fn bytes_init(&self) -> usize {
        N
    }
}
// SAFETY: the array is initialized and exclusively writable while lent.
unsafe impl<const N: usize> IoBufMut for [u8; N] {
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.as_mut_slice().as_mut_ptr()
    }
    fn bytes_total(&mut self) -> usize {
        N
    }
    unsafe fn set_init(&mut self, initialized: usize) {
        assert!(initialized <= N);
    }
}

#[cfg(feature = "bytes")]
// SAFETY: Bytes exposes stable immutable shared storage, with atomic ownership.
unsafe impl IoBuf for bytes::Bytes {
    fn as_ptr(&self) -> *const u8 {
        self.as_ref().as_ptr()
    }
    fn bytes_init(&self) -> usize {
        self.len()
    }
}
#[cfg(feature = "bytes")]
// SAFETY: BytesMut owns its disjoint region; it is not resized while lent.
unsafe impl IoBuf for bytes::BytesMut {
    fn as_ptr(&self) -> *const u8 {
        self.as_ref().as_ptr()
    }
    fn bytes_init(&self) -> usize {
        self.len()
    }
}
#[cfg(feature = "bytes")]
// SAFETY: its capacity is exclusively writable and filled bytes are published.
unsafe impl IoBufMut for bytes::BytesMut {
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.as_mut().as_mut_ptr()
    }
    fn bytes_total(&mut self) -> usize {
        self.capacity()
    }
    unsafe fn set_init(&mut self, initialized: usize) {
        assert!(initialized <= self.capacity());
        unsafe { self.set_len(initialized) };
    }
}

/// A completion always returns the original owner. `transferred` also reports
/// a known prefix on error. Further progress can be unknown after cancellation;
/// neither the whole buffer nor its apparent remainder is automatically replayable.
#[derive(Debug)]
pub struct IoResult<B> {
    pub result: Result<usize, Error>,
    pub buffer: B,
    pub transferred: usize,
}
impl<B> IoResult<B> {
    pub fn into_parts(self) -> (Result<usize, Error>, B) {
        (self.result, self.buffer)
    }
    pub fn map_buffer<T>(self, f: impl FnOnce(B) -> T) -> IoResult<T> {
        IoResult {
            result: self.result,
            buffer: f(self.buffer),
            transferred: self.transferred,
        }
    }
    fn ready(buffer: B, result: Result<usize, Error>) -> Self {
        let transferred = result.as_ref().copied().unwrap_or(0);
        Self {
            result,
            buffer,
            transferred,
        }
    }
}

/// The read direction of a split stream. The owning stream is kept alive until
/// both halves are dropped. There can be only one reader and one writer.
pub struct ReadHalf {
    view: NaiveStream,
    _owner: Arc<NaiveStream>,
}
pub struct WriteHalf {
    view: NaiveStream,
    _owner: Arc<NaiveStream>,
}
pub(crate) fn split(stream: NaiveStream) -> (ReadHalf, WriteHalf) {
    let owner = Arc::new(stream);
    (
        ReadHalf {
            view: owner.io_view(),
            _owner: owner.clone(),
        },
        WriteHalf {
            view: owner.io_view(),
            _owner: owner,
        },
    )
}
impl ReadHalf {
    pub async fn read_owned<B: IoBufMut + Send>(&mut self, buffer: B) -> IoResult<B> {
        self.view.read_owned(buffer).await
    }
    pub async fn read_local<B: IoBufMut>(&mut self, buffer: B) -> IoResult<B> {
        self.view.read_local(buffer).await
    }
    pub async fn read_chunk(&mut self) -> Result<Option<crate::ReadChunk>, Error> {
        self.view.read_chunk().await
    }
    pub fn poll_read_chunk(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<Option<crate::ReadChunk>, Error>> {
        self.view.poll_read_chunk(cx)
    }
    pub fn poll_read_slice(
        &mut self,
        cx: &mut std::task::Context<'_>,
        bytes: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        self.view.poll_read_slice(cx, bytes)
    }
    pub fn deadline_handle(&self) -> crate::DeadlineHandle {
        self.view.deadline_handle()
    }
    pub fn close(&mut self) {
        self.view.close();
    }
}
impl WriteHalf {
    pub async fn write_owned<B: IoBuf + Send>(&mut self, buffer: B) -> IoResult<B> {
        self.view.write_owned(buffer).await
    }
    pub async fn write_local<B: IoBuf>(&mut self, buffer: B) -> IoResult<B> {
        self.view.write_local(buffer).await
    }
    pub fn poll_write_slices(
        &mut self,
        cx: &mut std::task::Context<'_>,
        bytes: &[IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        self.view.poll_write_slices(cx, bytes)
    }
    pub fn poll_flush_pending(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.view.poll_flush_pending(cx)
    }
    pub async fn flush(&mut self) -> Result<(), Error> {
        poll_fn(|cx| self.view.poll_flush_pending(cx))
            .await
            .map_err(Into::into)
    }
    pub async fn shutdown_write(&mut self) -> Result<(), Error> {
        self.view.shutdown_write().await
    }
    pub fn deadline_handle(&self) -> crate::DeadlineHandle {
        self.view.deadline_handle()
    }
    pub fn close(&mut self) {
        self.view.close();
    }
}

#[cfg(feature = "tokio")]
impl tokio::io::AsyncRead for ReadHalf {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        tokio::io::AsyncRead::poll_read(Pin::new(&mut self.view), cx, buf)
    }
}
#[cfg(feature = "tokio")]
impl tokio::io::AsyncWrite for WriteHalf {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(Pin::new(&mut self.view), cx, bytes)
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write_vectored(Pin::new(&mut self.view), cx, bytes)
    }
    fn is_write_vectored(&self) -> bool {
        true
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.view.poll_flush_pending(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.view.poll_shutdown_write(cx)
    }
}
#[cfg(feature = "futures-io")]
impl futures_io::AsyncRead for ReadHalf {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        self.view.poll_read_slice(cx, bytes)
    }
}
#[cfg(feature = "futures-io")]
impl futures_io::AsyncWrite for WriteHalf {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.view.poll_write_slices(cx, &[IoSlice::new(bytes)])
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        self.view.poll_write_slices(cx, bytes)
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.view.poll_flush_pending(cx)
    }
    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.view.poll_shutdown_write(cx)
    }
}

struct Request<B> {
    buffer: B,
    shared: Weak<Shared>,
    id: u64,
    read: bool,
    send: oneshot::Sender<IoResult<B>>,
}

// A custom unsafe buffer implementation can still panic while exposing its
// pointer. Until ownership has crossed C, unwind must release the direction
// slot instead of leaving all later operations permanently pending.
struct PendingSlot {
    shared: Arc<Shared>,
    read: bool,
    armed: bool,
}
impl Drop for PendingSlot {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut state = lock(&self.shared.state);
        let wake = if self.read {
            state.owned_read_pending = false;
            state.read_waker.take()
        } else {
            state.owned_write_pending = false;
            state.write_waker.take()
        };
        drop(state);
        if let Some(waker) = wake {
            waker.wake();
        }
    }
}
unsafe extern "C" fn completed<B: Send + 'static>(
    context: *mut c_void,
    code: i32,
    transferred: usize,
) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: native owns this box from submission until its final IOBuffer
        // destruction, and calls us once, even when submission is rejected.
        let request = unsafe { Box::from_raw(context.cast::<Request<B>>()) };
        if let Some(shared) = request.shared.upgrade() {
            let mut state = lock(&shared.state);
            let error = (code < 0).then(|| {
                state
                    .terminal
                    .clone()
                    .unwrap_or_else(|| Error::native(code))
            });
            let waker = if request.read {
                state.owned_read_pending = false;
                if code == 0 && transferred == 0 {
                    state.eof = true;
                }
                state.read_waker.take()
            } else {
                state.owned_write_pending = false;
                state.write_waker.take()
            };
            drop(state);
            if let Some(waker) = waker {
                waker.wake();
            }
            if let Some(error) = error {
                crate::observability::notify(
                    &shared.observer,
                    crate::Event::StreamError {
                        id: request.id,
                        operation: if request.read {
                            crate::Operation::Read
                        } else {
                            crate::Operation::Write
                        },
                        error,
                    },
                );
            }
        }
        let _ = request.send.send(IoResult {
            result: if code == 0 {
                Ok(transferred)
            } else {
                Err(Error::native(code))
            },
            buffer: request.buffer,
            transferred,
        });
    }));
    if result.is_err() {
        std::process::abort();
    }
}

struct CancelOnDrop {
    inner: Arc<Inner>,
    shared: Arc<Shared>,
    id: u64,
    armed: bool,
}
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if self.armed {
            self.shared.fail(Error::native(-3));
            self.inner.cancel(self.id);
        }
    }
}

impl NaiveStream {
    /// Reads without an intermediate payload copy into a `Send` owner. At most
    /// 64 KiB is requested. Dropping this future AFTER submission aborts the
    /// stream; native retains the owner until all IOBuffer references are gone.
    /// A read deadline also aborts this stream before returning the owner.
    pub async fn read_owned<B: IoBufMut + Send>(&mut self, mut buffer: B) -> IoResult<B> {
        let capacity = buffer.bytes_total().min(MAX_IO);
        if capacity == 0 {
            return IoResult::ready(buffer, Ok(0));
        }
        let ready = poll_fn(|cx| {
            let mut state = lock(&self.shared.state);
            if state.read_deadline.is_some_and(|d| Instant::now() >= d) {
                return Poll::Ready(Err(Error::native(-7)));
            }
            if let Some(chunk) = &mut state.read_data {
                let n = capacity.min(chunk.length - chunk.offset);
                // SAFETY: the owner is exclusive, the destination fits, and the
                // stored read lease is immutable. Mixing APIs drains old data.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        chunk.buffer.bytes(chunk.offset, chunk.offset + n).as_ptr(),
                        buffer.as_mut_ptr(),
                        n,
                    );
                }
                chunk.offset += n;
                if chunk.offset == chunk.length {
                    state.read_data = None;
                }
                return Poll::Ready(Ok(Some(n)));
            }
            if let Some(error) = &state.terminal {
                return Poll::Ready(Err(error.clone()));
            }
            if state.eof {
                return Poll::Ready(Ok(Some(0)));
            }
            if !state.connected || state.read_pending || state.owned_read_pending {
                state.read_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            state.owned_read_pending = true;
            Poll::Ready(Ok(None))
        })
        .await;
        match ready {
            Err(error) => return IoResult::ready(buffer, Err(error)),
            Ok(Some(n)) => {
                unsafe {
                    buffer.set_init(n);
                }
                return IoResult::ready(buffer, Ok(n));
            }
            Ok(None) => {}
        }
        let recv = {
            let mut slot = PendingSlot {
                shared: self.shared.clone(),
                read: true,
                armed: true,
            };
            let (send, recv) = oneshot::channel();
            let mut request = Box::new(Request {
                buffer,
                shared: Arc::downgrade(&self.shared),
                id: self.id,
                read: true,
                send,
            });
            let data = request.buffer.as_mut_ptr();
            let context = Box::into_raw(request).cast();
            if self
                .inner
                .submit(|engine| unsafe {
                    naive_sys::naive_engine_read_owned(
                        engine,
                        self.id,
                        data,
                        capacity,
                        context,
                        completed::<B>,
                    );
                })
                .is_err()
            {
                unsafe {
                    completed::<B>(context, -3, 0);
                }
            }
            slot.armed = false;
            recv
        };
        let mut result = self.wait_owned(recv, true).await;
        if result.result.is_ok() || result.transferred != 0 {
            assert!(result.transferred <= capacity);
            unsafe {
                result.buffer.set_init(result.transferred);
            }
        }
        result
    }

    /// Writes an initialized prefix (up to 64 KiB) without copying it into a
    /// bridge buffer. Waits for earlier buffered writes before submission.
    /// Cancellation/deadline after submission aborts the stream. On error the
    /// returned `transferred` prefix may already have been sent.
    pub async fn write_owned<B: IoBuf + Send>(&mut self, buffer: B) -> IoResult<B> {
        let length = buffer.bytes_init().min(MAX_IO);
        if length == 0 {
            return IoResult::ready(buffer, Ok(0));
        }
        if let Err(error) = poll_fn(|cx| self.poll_flush_pending(cx)).await {
            return IoResult::ready(buffer, Err(error.into()));
        }
        {
            let mut state = lock(&self.shared.state);
            if let Some(error) = &state.terminal {
                return IoResult::ready(buffer, Err(error.clone()));
            }
            if state.write_shutdown || state.write_shutdown_pending {
                return IoResult::ready(
                    buffer,
                    Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe).into()),
                );
            }
            if state.write_deadline.is_some_and(|d| Instant::now() >= d) {
                return IoResult::ready(buffer, Err(Error::native(-7)));
            }
            state.owned_write_pending = true;
        }
        let recv = {
            let mut slot = PendingSlot {
                shared: self.shared.clone(),
                read: false,
                armed: true,
            };
            let (send, recv) = oneshot::channel();
            let request = Box::new(Request {
                buffer,
                shared: Arc::downgrade(&self.shared),
                id: self.id,
                read: false,
                send,
            });
            let data = request.buffer.as_ptr();
            let context = Box::into_raw(request).cast();
            if self
                .inner
                .submit(|engine| unsafe {
                    naive_sys::naive_engine_write_owned(
                        engine,
                        self.id,
                        data,
                        length,
                        context,
                        completed::<B>,
                    );
                })
                .is_err()
            {
                unsafe {
                    completed::<B>(context, -3, 0);
                }
            }
            slot.armed = false;
            recv
        };
        self.wait_owned(recv, false).await
    }

    async fn wait_owned<B>(
        &mut self,
        mut recv: oneshot::Receiver<IoResult<B>>,
        read: bool,
    ) -> IoResult<B> {
        let mut cancel = CancelOnDrop {
            inner: self.inner.clone(),
            shared: self.shared.clone(),
            id: self.id,
            armed: true,
        };
        let mut override_error = None;
        let mut result = poll_fn(|cx| {
            if let Poll::Ready(result) = Pin::new(&mut recv).poll(cx) {
                return Poll::Ready(result.expect("native owned IO lost its buffer completion"));
            }
            let mut state = lock(&self.shared.state);
            let deadline = if read {
                state.read_deadline
            } else {
                state.write_deadline
            };
            let timed_out = deadline.is_some_and(|d| Instant::now() >= d);
            let terminal = state.terminal.clone();
            if read {
                state.read_waker = Some(cx.waker().clone());
            } else {
                state.write_waker = Some(cx.waker().clone());
            }
            drop(state);
            if override_error.is_none() && (timed_out || terminal.is_some()) {
                let error = terminal.unwrap_or_else(|| Error::native(-7));
                self.shared.fail(error.clone());
                self.inner.cancel(self.id);
                override_error = Some(error);
            }
            Poll::Pending
        })
        .await;
        cancel.armed = false;
        if let Some(error) = override_error {
            result.result = Err(error);
        }
        result
    }

    /// Completion-style compatibility for local (`!Send`) owners. This copies
    /// from the native read lease on the polling thread and keeps the normal
    /// non-destructive read-cancellation behavior.
    pub async fn read_local<B: IoBufMut>(&mut self, mut buffer: B) -> IoResult<B> {
        let capacity = buffer.bytes_total().min(MAX_IO);
        let result = poll_fn(|cx| {
            self.poll_read_with(cx, capacity, |bytes| unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer.as_mut_ptr(), bytes.len());
            })
        })
        .await
        .map_err(Error::from);
        if let Ok(n) = result {
            unsafe {
                buffer.set_init(n);
            }
        }
        IoResult::ready(buffer, result)
    }
    /// Copies an initialized prefix on the polling thread; no `Send` owner is
    /// needed. Success means accepted, as for AsyncWrite; call flush to drain.
    pub async fn write_local<B: IoBuf>(&mut self, buffer: B) -> IoResult<B> {
        if buffer.bytes_init() == 0 {
            return IoResult::ready(buffer, Ok(0));
        }
        let result = poll_fn(|cx| {
            let bytes = unsafe { std::slice::from_raw_parts(buffer.as_ptr(), buffer.bytes_init()) };
            self.poll_write_slices(cx, &[IoSlice::new(bytes)])
        })
        .await
        .map_err(Error::from);
        IoResult::ready(buffer, result)
    }
}
