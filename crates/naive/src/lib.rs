//! Safe asynchronous TCP streams backed by the native NaiveProxy network stack.
//!
//! Works with any executor; Tokio and futures-io adapters are optional.
//! HTTP/2 and HTTP/3 are upstream transports; this
//! crate does not expose arbitrary UDP forwarding. Native Chromium process
//! globals remain alive until exit. Call [`NaiveClient::shutdown`] to await
//! release of a client's streams and network context.
//!
//! Writes are buffered (at most two 64 KiB payload buffers per stream). Use `flush().await` to
//! observe completion/errors. `AsyncWrite::shutdown` closes both directions;
//! TCP half-close is not currently exposed by the native bridge.
#![deny(unsafe_op_in_unsafe_fn)]

mod buffer;
mod client;
mod config;
mod error;
pub mod network;
mod observability;
mod stream;
pub use network::NetworkConfig;
pub use observability::{ClientStats, ConnectionInfo, Event, Observer, Operation};

pub use client::NaiveClient;
pub use config::{Config, EchMode, EchOptions, Http2Options, QuicCongestionControl, QuicOptions};
pub use error::Error;
pub use stream::{DeadlineHandle, NaiveStream};

/// Chromium version embedded in the linked native library.
pub fn native_version() -> &'static str {
    // SAFETY: the native library returns a process-lifetime constant string.
    unsafe { std::ffi::CStr::from_ptr(naive_sys::naive_version()) }
        .to_str()
        .unwrap_or("unknown")
}
