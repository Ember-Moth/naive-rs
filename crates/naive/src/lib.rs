//! Safe asynchronous TCP streams backed by the native NaiveProxy network stack.
//!
//! Uses standard futures and native-thread wakeups; Tokio and futures-io adapters
//! are optional. Executors must support waking tasks from native threads.
//! HTTP/2 and HTTP/3 are upstream transports; this
//! crate does not expose arbitrary UDP forwarding. Native Chromium process
//! globals remain alive until exit. Call [`NaiveClient::shutdown`] to await
//! release of a client's streams and network context.
//!
//! Writes are buffered (at most two 64 KiB payload buffers per stream). Use `flush().await` to
//! observe completion/errors. Writer shutdown sends a FIN on H2/H3 CONNECT;
//! unsupported transports return an error. Explicit close aborts both directions.
#![deny(unsafe_op_in_unsafe_fn)]

pub mod browser;
mod buffer;
pub mod certificate;
mod client;
mod config;
mod error;
pub mod network;
mod observability;
pub mod owned;
mod stream;
pub use network::NetworkConfig;
pub use observability::{ClientStats, ConnectionInfo, Event, Observer, Operation};

pub use buffer::{ReadChunk, buffer_stats};
pub use certificate::{
    CertificateCancellation, CertificateDecision, CertificateInfo, CertificateVerification,
    CertificateVerifier,
};
pub use client::NaiveClient;
pub use config::{Config, EchMode, EchOptions, Http2Options, QuicCongestionControl, QuicOptions};
pub use error::Error;
pub use naive_sys::BufferStats;
pub use stream::{DeadlineHandle, NaiveStream};

/// Chromium version embedded in the linked native library.
pub fn native_version() -> &'static str {
    // SAFETY: the native library returns a process-lifetime constant string.
    unsafe { std::ffi::CStr::from_ptr(naive_sys::naive_version()) }
        .to_str()
        .unwrap_or("unknown")
}
