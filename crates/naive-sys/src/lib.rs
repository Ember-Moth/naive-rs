//! Raw C ABI. See native/include/naive.h for ownership and thread requirements.
use std::ffi::{c_char, c_void};

#[repr(C)]
pub struct Engine {
    _private: [u8; 0],
}
#[repr(C)]
pub struct Buffer {
    _private: [u8; 0],
}
pub type Callback =
    unsafe extern "C" fn(*mut c_void, u64, i32, i32, *mut Buffer, *mut u8, usize, usize);
pub type OwnedCallback = unsafe extern "C" fn(*mut c_void, i32, usize);
pub const CONNECTED: i32 = 1;
pub const READ: i32 = 2;
pub const WRITTEN: i32 = 3;
pub const CLOSED: i32 = 4;
pub const DESTROYED: i32 = 5;
pub const READ_DEADLINE: i32 = 6;
pub const WRITE_DEADLINE: i32 = 7;
pub const WRITE_SHUTDOWN: i32 = 8;
pub const ABI_VERSION: u32 = 4;

#[derive(Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct BufferStats {
    pub allocations: u64,
    pub live_buffers: u64,
    pub live_capacity: u64,
    pub peak_capacity: u64,
}

unsafe extern "C" {
    pub fn naive_abi_version() -> u32;
    pub fn naive_version() -> *const c_char;
    pub fn naive_error_name(error: i32) -> *const c_char;
    pub fn naive_buffer_alloc(capacity: usize) -> *mut Buffer;
    pub fn naive_buffer_data(buffer: *mut Buffer) -> *mut u8;
    pub fn naive_buffer_release(buffer: *mut Buffer);
    pub fn naive_get_buffer_stats(output: *mut BufferStats);
    pub fn naive_engine_create(
        json: *const c_char,
        callback: Callback,
        hooks: *const NetworkHooks,
        output: *mut *mut Engine,
    ) -> i32;
    pub fn naive_engine_shutdown(engine: *mut Engine);
    pub fn naive_engine_reset_connections(engine: *mut Engine) -> i32;
    pub fn naive_engine_destroy(engine: *mut Engine);
    pub fn naive_engine_connect(
        engine: *mut Engine,
        id: u64,
        hostname: *const c_char,
        port: u16,
        context: *mut c_void,
    );
    pub fn naive_engine_read(engine: *mut Engine, id: u64, capacity: usize);
    pub fn naive_engine_write(engine: *mut Engine, id: u64, buffer: *mut Buffer, length: usize);
    pub fn naive_engine_close(engine: *mut Engine, id: u64);
    pub fn naive_engine_shutdown_write(engine: *mut Engine, id: u64);
    pub fn naive_engine_read_owned(
        engine: *mut Engine,
        id: u64,
        data: *mut u8,
        capacity: usize,
        context: *mut c_void,
        completed: OwnedCallback,
    );
    pub fn naive_engine_write_owned(
        engine: *mut Engine,
        id: u64,
        data: *const u8,
        length: usize,
        context: *mut c_void,
        completed: OwnedCallback,
    );
}

#[repr(C)]
pub struct NetworkRequest {
    _private: [u8; 0],
}
#[repr(C)]
pub struct NetworkHooks {
    pub context: *mut c_void,
    pub retain: unsafe extern "C" fn(*mut c_void),
    pub release: unsafe extern "C" fn(*mut c_void),
    pub resolve: Option<unsafe extern "C" fn(*mut c_void, *const c_char, i32, *mut NetworkRequest)>,
    pub control: Option<unsafe extern "C" fn(*mut c_void, isize, i32, *const c_char) -> i32>,
    pub dial_tcp: Option<unsafe extern "C" fn(*mut c_void, *const c_char, *mut NetworkRequest)>,
    pub dial_udp:
        Option<unsafe extern "C" fn(*mut c_void, *const c_char, i64, *mut NetworkRequest)>,
}
unsafe extern "C" {
    pub fn naive_network_request_retain(request: *mut NetworkRequest);
    pub fn naive_network_request_release(request: *mut NetworkRequest);
    pub fn naive_network_request_is_cancelled(request: *mut NetworkRequest) -> i32;
    pub fn naive_resolve_complete(
        request: *mut NetworkRequest,
        result: i32,
        addresses: *const c_char,
    );
    pub fn naive_dial_udp_complete(request: *mut NetworkRequest, result: i32, socket: isize);
    pub fn naive_dial_tcp_complete(request: *mut NetworkRequest, result: i32, socket: isize);
}

#[derive(Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct ClientStats {
    pub connect_attempts: u64,
    pub connect_successes: u64,
    pub connect_failures: u64,
    pub closed_streams: u64,
    pub active_streams: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
}
#[repr(C)]
pub struct StreamInfo {
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub pooled_socket_reused: u32,
    pub write_shutdown_supported: u32,
    pub ech_accepted: u32,
    pub tls_version: u16,
    pub cipher_suite: u16,
    pub protocol: [c_char; 16],
    pub local_address: [c_char; 128],
    pub peer_address: [c_char; 128],
}
impl Default for StreamInfo {
    fn default() -> Self {
        Self {
            bytes_read: 0,
            bytes_written: 0,
            pooled_socket_reused: 0,
            write_shutdown_supported: 0,
            ech_accepted: 0,
            tls_version: 0,
            cipher_suite: 0,
            protocol: [0; 16],
            local_address: [0; 128],
            peer_address: [0; 128],
        }
    }
}
unsafe extern "C" {
    pub fn naive_engine_get_stats(
        engine: *mut Engine,
        output: *mut ClientStats,
        output_size: usize,
    ) -> i32;
    pub fn naive_engine_get_stream_info(
        engine: *mut Engine,
        id: u64,
        output: *mut StreamInfo,
        output_size: usize,
    ) -> i32;
    pub fn naive_engine_set_deadline(
        engine: *mut Engine,
        id: u64,
        mask: u32,
        timeout_us: i64,
    ) -> i32;
}
