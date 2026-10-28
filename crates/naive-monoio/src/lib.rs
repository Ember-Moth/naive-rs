//! Unix monoio adapter. Enables monoio's `sync` feature for native-thread wakes.
//! Trait methods accept local `!Send` buffers through the copying path. Explicit
//! owned methods require `Send` and transfer the allocation to native IO.
#![cfg(unix)]
#![deny(unsafe_op_in_unsafe_fn)]
use monoio::{
    BufResult,
    buf::{IoBuf, IoBufMut, IoVecBuf, IoVecBufMut},
    io::{AsyncReadRent, AsyncWriteRent},
};
use naive::{
    NaiveStream,
    owned::{IoBuf as NativeBuf, IoBufMut as NativeBufMut, IoResult},
};
use std::{
    future::poll_fn,
    io::{self, IoSlice},
    ptr::NonNull,
};

pub struct Stream {
    inner: NaiveStream,
}
pub struct ReadHalf {
    inner: naive::owned::ReadHalf,
}
pub struct WriteHalf {
    inner: naive::owned::WriteHalf,
}
impl ReadHalf {
    pub fn inner_mut(&mut self) -> &mut naive::owned::ReadHalf {
        &mut self.inner
    }
    pub async fn read_owned<B: IoBufMut + Send>(&mut self, buffer: B) -> IoResult<B> {
        self.inner
            .read_owned(ReadBuffer::new(buffer))
            .await
            .map_buffer(|b| *b.owner)
    }
}
impl WriteHalf {
    pub fn inner_mut(&mut self) -> &mut naive::owned::WriteHalf {
        &mut self.inner
    }
    pub async fn write_owned<B: IoBuf + Send>(&mut self, buffer: B) -> IoResult<B> {
        self.inner
            .write_owned(WriteBuffer::new(buffer))
            .await
            .map_buffer(|b| *b.owner)
    }
}
impl From<NaiveStream> for Stream {
    fn from(inner: NaiveStream) -> Self {
        Self { inner }
    }
}
impl Stream {
    pub fn into_split(self) -> (ReadHalf, WriteHalf) {
        let (read, write) = self.inner.into_split();
        (ReadHalf { inner: read }, WriteHalf { inner: write })
    }

    pub fn inner_mut(&mut self) -> &mut NaiveStream {
        &mut self.inner
    }
    pub fn into_inner(self) -> NaiveStream {
        self.inner
    }
    pub async fn read_owned<B: IoBufMut + Send>(&mut self, buffer: B) -> IoResult<B> {
        self.inner
            .read_owned(ReadBuffer::new(buffer))
            .await
            .map_buffer(|b| *b.owner)
    }
    pub async fn write_owned<B: IoBuf + Send>(&mut self, buffer: B) -> IoResult<B> {
        self.inner
            .write_owned(WriteBuffer::new(buffer))
            .await
            .map_buffer(|b| *b.owner)
    }
}
macro_rules! impl_read {
    ($ty:ty) => {
        impl AsyncReadRent for $ty {
            async fn read<B: IoBufMut>(&mut self, buffer: B) -> BufResult<usize, B> {
                let (result, b) = self
                    .inner
                    .read_local(ReadBuffer::new(buffer))
                    .await
                    .into_parts();
                (result.map_err(Into::into), *b.owner)
            }
            async fn readv<B: IoVecBufMut>(&mut self, buffer: B) -> BufResult<usize, B> {
                let mut owner = Box::new(buffer);
                let count = owner.write_iovec_len();
                let (data, capacity) = if count == 0 {
                    (NonNull::<u8>::dangling().as_ptr(), 0)
                } else {
                    // SAFETY: monoio's unsafe trait guarantees a valid iovec array.
                    let vectors =
                        unsafe { std::slice::from_raw_parts(owner.write_iovec_ptr(), count) };
                    vectors
                        .iter()
                        .find(|v| v.iov_len != 0)
                        .map(|v| (v.iov_base.cast::<u8>(), v.iov_len))
                        .unwrap_or((NonNull::<u8>::dangling().as_ptr(), 0))
                };
                // A vectored read may return a short read into its first nonempty buffer.
                let (result, b) = self
                    .inner
                    .read_local(ReadVector {
                        owner,
                        data,
                        capacity,
                    })
                    .await
                    .into_parts();
                (result.map_err(Into::into), *b.owner)
            }
        }
    };
}
impl_read!(Stream);
impl_read!(ReadHalf);
macro_rules! impl_write {
    ($ty:ty) => {
        impl AsyncWriteRent for $ty {
            async fn write<B: IoBuf>(&mut self, buffer: B) -> BufResult<usize, B> {
                let (result, b) = self
                    .inner
                    .write_local(WriteBuffer::new(buffer))
                    .await
                    .into_parts();
                (result.map_err(Into::into), *b.owner)
            }
            async fn writev<B: IoVecBuf>(&mut self, buffer: B) -> BufResult<usize, B> {
                let owner = Box::new(buffer);
                let count = owner.read_iovec_len();
                if count == 0 {
                    return (Ok(0), *owner);
                }
                // SAFETY: the boxed owner keeps the iovec array and its initialized
                // payloads stable for this local future; poll_write never retains them.
                let vectors = unsafe { std::slice::from_raw_parts(owner.read_iovec_ptr(), count) };
                let slices: Vec<_> = vectors
                    .iter()
                    .filter(|v| v.iov_len != 0)
                    .map(|v| {
                        IoSlice::new(unsafe {
                            std::slice::from_raw_parts(v.iov_base.cast(), v.iov_len)
                        })
                    })
                    .collect();
                let result = poll_fn(|cx| self.inner.poll_write_slices(cx, &slices)).await;
                (result, *owner)
            }
            async fn flush(&mut self) -> io::Result<()> {
                poll_fn(|cx| self.inner.poll_flush_pending(cx)).await
            }
            async fn shutdown(&mut self) -> io::Result<()> {
                self.inner.shutdown_write().await.map_err(Into::into)
            }
        }
    };
}
impl_write!(Stream);
impl_write!(WriteHalf);
struct WriteBuffer<B> {
    owner: Box<B>,
    data: *const u8,
    len: usize,
}
impl<B: IoBuf> WriteBuffer<B> {
    fn new(buffer: B) -> Self {
        let owner = Box::new(buffer);
        let (data, len) = (owner.read_ptr(), owner.bytes_init());
        Self { owner, data, len }
    }
}
// SAFETY: monoio's trait guarantees a stable initialized slice while boxed.
unsafe impl<B: Send> Send for WriteBuffer<B> {}
unsafe impl<B: IoBuf> NativeBuf for WriteBuffer<B> {
    fn as_ptr(&self) -> *const u8 {
        self.data
    }
    fn bytes_init(&self) -> usize {
        self.len
    }
}
struct ReadBuffer<B> {
    owner: Box<B>,
    data: *mut u8,
    capacity: usize,
}
impl<B: IoBufMut> ReadBuffer<B> {
    fn new(buffer: B) -> Self {
        let mut owner = Box::new(buffer);
        let capacity = owner.bytes_total();
        let data = owner.write_ptr();
        Self {
            owner,
            data,
            capacity,
        }
    }
}
// SAFETY: the owner is stable, exclusive, and only moved after IO completes.
unsafe impl<B: Send> Send for ReadBuffer<B> {}
unsafe impl<B: IoBufMut> NativeBufMut for ReadBuffer<B> {
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data
    }
    fn bytes_total(&mut self) -> usize {
        self.capacity
    }
    unsafe fn set_init(&mut self, initialized: usize) {
        assert!(initialized <= self.capacity);
        unsafe {
            self.owner.set_init(initialized);
        }
    }
}
struct ReadVector<B> {
    owner: Box<B>,
    data: *mut u8,
    capacity: usize,
}
// SAFETY: the first nonempty iovec is stable and writable while B is held.
unsafe impl<B: IoVecBufMut> NativeBufMut for ReadVector<B> {
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data
    }
    fn bytes_total(&mut self) -> usize {
        self.capacity
    }
    unsafe fn set_init(&mut self, initialized: usize) {
        assert!(initialized <= self.capacity);
        unsafe {
            self.owner.set_init(initialized);
        }
    }
}
