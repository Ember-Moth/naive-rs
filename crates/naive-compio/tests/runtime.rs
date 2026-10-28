use compio_buf::{IoBuf, IoBufMut, SetLen};
use compio_io::{AsyncRead, AsyncWrite};
use naive_compio::Stream;
#[path = "../../../tests/support/io_fixture.rs"]
mod fixture;
fn run(future: impl std::future::Future<Output = ()>) {
    compio::runtime::Runtime::new().unwrap().block_on(future);
}
fn parts<T, B>(result: compio_buf::BufResult<T, B>) -> (std::io::Result<T>, B) {
    result.into_parts()
}
impl IoBuf for LocalBuffer {
    fn as_init(&self) -> &[u8] {
        self.check_thread();
        &self.bytes
    }
}
impl SetLen for LocalBuffer {
    unsafe fn set_len(&mut self, n: usize) {
        unsafe { self.publish(n) }
    }
}
impl IoBufMut for LocalBuffer {
    fn as_uninit(&mut self) -> &mut [std::mem::MaybeUninit<u8>] {
        self.check_thread();
        // SAFETY: the exclusive Vec capacity is represented as uninitialized storage.
        unsafe {
            std::slice::from_raw_parts_mut(self.bytes.as_mut_ptr().cast(), self.bytes.capacity())
        }
    }
}
impl IoBuf for fixture::Buffer {
    fn as_init(&self) -> &[u8] {
        &self.bytes
    }
}
impl SetLen for fixture::Buffer {
    unsafe fn set_len(&mut self, n: usize) {
        assert!(n <= self.bytes.capacity());
        unsafe { self.bytes.set_len(n) }
    }
}
impl IoBufMut for fixture::Buffer {
    fn as_uninit(&mut self) -> &mut [std::mem::MaybeUninit<u8>] {
        // SAFETY: the exclusive Vec capacity is represented as uninitialized storage.
        unsafe {
            std::slice::from_raw_parts_mut(self.bytes.as_mut_ptr().cast(), self.bytes.capacity())
        }
    }
}
include!("../../../tests/support/completion_cases.rs");
