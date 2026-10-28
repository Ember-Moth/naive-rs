//! Native buffer leases. No pointer into a caller's suspended future crosses FFI.
use naive_sys as sys;
use std::ptr::NonNull;

pub(crate) struct Buffer {
    owner: NonNull<sys::Buffer>,
    data: NonNull<u8>,
    pub capacity: usize,
}

// SAFETY: native references are atomic. A read lease is immutable while any
// reader holds it; a write lease has one owner until transferred to native code.
unsafe impl Send for Buffer {}

impl Buffer {
    pub fn allocate(capacity: usize) -> Self {
        // SAFETY: a valid bounded capacity creates one exclusively owned buffer.
        let owner = NonNull::new(unsafe { sys::naive_buffer_alloc(capacity) })
            .expect("native buffer allocation failed");
        let data = NonNull::new(unsafe { sys::naive_buffer_data(owner.as_ptr()) }).unwrap();
        Self {
            owner,
            data,
            capacity,
        }
    }
    /// Takes the single reference transferred by a native completion event.
    pub unsafe fn from_event(
        owner: *mut sys::Buffer,
        data: *mut u8,
        capacity: usize,
    ) -> Option<Self> {
        NonNull::new(owner).map(|owner| {
            assert!(capacity > 0 && capacity <= crate::stream::MAX_IO);
            Self {
                owner,
                data: NonNull::new(data).expect("native buffer data is null"),
                capacity,
            }
        })
    }
    pub fn into_raw(self) -> *mut sys::Buffer {
        let pointer = self.owner.as_ptr();
        std::mem::forget(self);
        pointer
    }
    pub fn bytes(&self, start: usize, end: usize) -> &[u8] {
        assert!(start <= end && end <= self.capacity);
        // SAFETY: this owner keeps the allocation alive, including after shutdown.
        // Native code never overwrites a still-leased read buffer.
        unsafe { std::slice::from_raw_parts(self.data.as_ptr().add(start), end - start) }
    }
    /// Requires exclusive writable ownership (allocated or returned in WRITTEN).
    unsafe fn copy(&mut self, offset: usize, input: &[u8]) {
        assert!(offset <= self.capacity && input.len() <= self.capacity - offset);
        // SAFETY: checked bounds, exclusively owned destination, and caller input
        // cannot alias this private native allocation.
        unsafe {
            std::ptr::copy_nonoverlapping(
                input.as_ptr(),
                self.data.as_ptr().add(offset),
                input.len(),
            );
        }
    }
}
impl Drop for Buffer {
    fn drop(&mut self) {
        // SAFETY: exactly one owned reference; release is valid on any thread.
        unsafe {
            sys::naive_buffer_release(self.owner.as_ptr());
        }
    }
}

/// Immutable native read lease. Keeps only the payload allocation alive, not
/// the stream or client. Retaining many chunks retains their allocations; hosts
/// should bound retained chunks using `allocated_capacity`, not just `len`.
pub struct ReadChunk {
    pub(crate) buffer: Buffer,
    pub(crate) length: usize,
    pub(crate) offset: usize,
}

// SAFETY: native never overwrites a read allocation while a lease exists, and
// this type exposes no mutable access to its data.
unsafe impl Sync for ReadChunk {}
impl ReadChunk {
    pub fn len(&self) -> usize {
        self.length - self.offset
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn allocated_capacity(&self) -> usize {
        self.buffer.capacity
    }
    #[cfg(feature = "bytes")]
    pub fn into_bytes(self) -> bytes::Bytes {
        bytes::Bytes::from_owner(self)
    }
}
impl AsRef<[u8]> for ReadChunk {
    fn as_ref(&self) -> &[u8] {
        self.buffer.bytes(self.offset, self.length)
    }
}
impl std::fmt::Debug for ReadChunk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadChunk")
            .field("len", &self.len())
            .field("allocated_capacity", &self.allocated_capacity())
            .finish()
    }
}

/// Process-wide counters for bridge-allocated native payload storage. Foreign
/// owned IO storage and Chromium's TLS/HTTP/QUIC allocations are excluded.
pub fn buffer_stats() -> sys::BufferStats {
    let mut stats = sys::BufferStats::default();
    // SAFETY: native synchronously fills the POD with atomic snapshots.
    unsafe { sys::naive_get_buffer_stats(&mut stats) };
    stats
}

pub(crate) struct WriteBatch {
    pub buffer: Buffer,
    pub length: usize,
}
impl WriteBatch {
    pub fn new(spare: Option<Buffer>, capacity: usize) -> Self {
        let buffer = match spare {
            Some(buffer) if buffer.capacity >= capacity => buffer,
            _ => Buffer::allocate(capacity),
        };
        Self { buffer, length: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.buffer.capacity - self.length
    }
    pub fn append(&mut self, input: &[u8]) -> usize {
        let n = input.len().min(self.remaining());
        // SAFETY: WriteBatch is only made from exclusive allocations or WRITTEN
        // returns; it cannot be accessed after into_raw transfers it to C++.
        unsafe {
            self.buffer.copy(self.length, &input[..n]);
        }
        self.length += n;
        n
    }
}
