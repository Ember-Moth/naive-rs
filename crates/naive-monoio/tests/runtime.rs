#![cfg(unix)]
use monoio::{
    buf::{IoBuf, IoBufMut},
    io::{AsyncReadRent, AsyncWriteRent},
};
use naive_monoio::Stream;
#[path = "../../../tests/support/io_fixture.rs"]
mod fixture;
fn run(future: impl std::future::Future<Output = ()>) {
    monoio::RuntimeBuilder::<monoio::LegacyDriver>::new()
        .build()
        .unwrap()
        .block_on(future);
}
fn parts<T, B>(result: monoio::BufResult<T, B>) -> (std::io::Result<T>, B) {
    result
}
// SAFETY: these owners retain exclusive Vec storage while lent to the adapter.
unsafe impl IoBuf for LocalBuffer {
    fn read_ptr(&self) -> *const u8 {
        self.check_thread();
        self.bytes.as_ptr()
    }
    fn bytes_init(&self) -> usize {
        self.check_thread();
        self.bytes.len()
    }
}
unsafe impl IoBufMut for LocalBuffer {
    fn write_ptr(&mut self) -> *mut u8 {
        self.check_thread();
        self.bytes.as_mut_ptr()
    }
    fn bytes_total(&mut self) -> usize {
        self.check_thread();
        self.bytes.capacity()
    }
    unsafe fn set_init(&mut self, n: usize) {
        unsafe { self.publish(n) }
    }
}
unsafe impl IoBuf for fixture::Buffer {
    fn read_ptr(&self) -> *const u8 {
        self.bytes.as_ptr()
    }
    fn bytes_init(&self) -> usize {
        self.bytes.len()
    }
}
unsafe impl IoBufMut for fixture::Buffer {
    fn write_ptr(&mut self) -> *mut u8 {
        self.bytes.as_mut_ptr()
    }
    fn bytes_total(&mut self) -> usize {
        self.bytes.capacity()
    }
    unsafe fn set_init(&mut self, n: usize) {
        assert!(n <= self.bytes.capacity());
        unsafe { self.bytes.set_len(n) }
    }
}
include!("../../../tests/support/completion_cases.rs");
