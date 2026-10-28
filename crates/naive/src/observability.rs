use crate::Error;
use std::{net::SocketAddr, sync::Arc};

/// Counts logical CONNECT streams and application payload bytes, not physical
/// TCP/QUIC connections, framing bytes or TLS overhead. Snapshots are ordered
/// on the native IO sequence and remain available after client shutdown.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ClientStats {
    pub connect_attempts: u64,
    pub connect_successes: u64,
    /// Includes cancellation and timeout before CONNECT succeeds.
    pub connect_failures: u64,
    pub closed_streams: u64,
    /// Includes CONNECT requests still in progress.
    pub active_streams: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
}
impl From<naive_sys::ClientStats> for ClientStats {
    fn from(value: naive_sys::ClientStats) -> Self {
        Self {
            connect_attempts: value.connect_attempts,
            connect_successes: value.connect_successes,
            connect_failures: value.connect_failures,
            closed_streams: value.closed_streams,
            active_streams: value.active_streams,
            bytes_read: value.bytes_read,
            bytes_written: value.bytes_written,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionInfo {
    /// The protocol reported by the proxy socket; absent if not available.
    pub protocol: Option<String>,
    pub local_address: Option<SocketAddr>,
    pub peer_address: Option<SocketAddr>,
    /// Wire TLS version (e.g. 0x0304 for TLS 1.3), when reported by the socket.
    pub tls_version: Option<u16>,
    pub cipher_suite: Option<u16>,
    pub ech_accepted: Option<bool>,
    /// Socket-handle reuse, not a claim about multiplexed session reuse.
    pub pooled_socket_reused: bool,
    pub bytes_read: u64,
    pub bytes_written: u64,
}
impl From<naive_sys::StreamInfo> for ConnectionInfo {
    fn from(value: naive_sys::StreamInfo) -> Self {
        fn text(bytes: &[std::ffi::c_char]) -> String {
            // Keep even explicitly constructed raw records bounded; From is a
            // safe public conversion and must not assume a terminating NUL.
            let bytes: Vec<u8> = bytes
                .iter()
                .map(|byte| *byte as u8)
                .take_while(|byte| *byte != 0)
                .collect();
            String::from_utf8_lossy(&bytes).into_owned()
        }
        let protocol = text(&value.protocol);
        Self {
            protocol: (!protocol.is_empty() && protocol != "unknown").then_some(protocol),
            local_address: text(&value.local_address).parse().ok(),
            peer_address: text(&value.peer_address).parse().ok(),
            tls_version: (value.tls_version != 0).then_some(value.tls_version),
            cipher_suite: (value.cipher_suite != 0).then_some(value.cipher_suite),
            pooled_socket_reused: value.pooled_socket_reused != 0,
            ech_accepted: (value.tls_version != 0).then_some(value.ech_accepted != 0),
            bytes_read: value.bytes_read,
            bytes_written: value.bytes_written,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Connect,
    Read,
    Write,
}

/// Lifecycle and error events. Credentials and request contents are omitted.
/// Stream identifiers are scoped to a single client (including its clones).
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Event {
    ClientReady,
    StreamStarted {
        id: u64,
        hostname: String,
        port: u16,
    },
    StreamConnected {
        id: u64,
    },
    StreamError {
        id: u64,
        operation: Operation,
        error: Error,
    },
    StreamClosed {
        id: u64,
        reason: Error,
    },
    ConnectionsReset,
    ShutdownComplete,
}
/// May be invoked concurrently on caller, control or native IO threads. Return promptly; dispatch
/// slow work to the host. Never synchronously wait for a client operation from
/// this callback. Panics are contained and that event delivery is discarded.
pub trait Observer: Send + Sync + 'static {
    fn on_event(&self, event: &Event);
}
impl<F: Fn(&Event) + Send + Sync + 'static> Observer for F {
    fn on_event(&self, event: &Event) {
        self(event);
    }
}
pub(crate) fn notify(observer: &Option<Arc<dyn Observer>>, event: Event) {
    if let Some(observer) = observer {
        let _ =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| observer.on_event(&event)));
    }
}
