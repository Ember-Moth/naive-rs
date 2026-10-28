//! Optional compio IO traits, without depending on the compio runtime.
//! Trait methods support local `!Send` buffers through the copying path.
//! Explicit owned methods additionally require `Send` and avoid payload copies.
#![deny(unsafe_op_in_unsafe_fn)]
use compio_buf::{BufResult, IoBuf, IoBufMut};
use naive::{
    NaiveStream,
    owned::{IoBuf as NativeBuf, IoBufMut as NativeBufMut, IoResult},
};
use std::{future::poll_fn, io};

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
        impl compio_io::AsyncRead for $ty {
            async fn read<B: IoBufMut>(&mut self, buffer: B) -> BufResult<usize, B> {
                let (result, b) = self
                    .inner
                    .read_local(ReadBuffer::new(buffer))
                    .await
                    .into_parts();
                BufResult(result.map_err(Into::into), *b.owner)
            }
        }
    };
}
impl_read!(Stream);
impl_read!(ReadHalf);
macro_rules! impl_write {
    ($ty:ty) => {
        impl compio_io::AsyncWrite for $ty {
            async fn write<B: IoBuf>(&mut self, buffer: B) -> BufResult<usize, B> {
                let (result, b) = self
                    .inner
                    .write_local(WriteBuffer::new(buffer))
                    .await
                    .into_parts();
                BufResult(result.map_err(Into::into), *b.owner)
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
        // Borrow once, after the owner reaches its stable heap address.
        let bytes = owner.as_init();
        let (data, len) = (bytes.as_ptr(), bytes.len());
        Self { owner, data, len }
    }
}
// SAFETY: the private wrapper never moves/touches B while its cached slice is
// lent; B owns that slice. Dropping B on another thread requires B: Send.
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
        let bytes = owner.as_uninit();
        let (data, capacity) = (bytes.as_mut_ptr().cast(), bytes.len());
        Self {
            owner,
            data,
            capacity,
        }
    }
}
// SAFETY: B is boxed before the one exclusive slice is taken. The owner is
// inaccessible until completion; the adapter then unwraps it immediately.
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
            self.owner.set_len(initialized);
        }
    }
}
