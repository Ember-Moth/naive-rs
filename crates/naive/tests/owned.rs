//! Owned IO and cancellation contracts. No executor-specific APIs are used.
use futures_executor::block_on;
use futures_util::FutureExt;
use naive::{
    Config, NaiveClient,
    owned::{IoBuf, IoBufMut},
};
use std::{
    future::poll_fn,
    io::{IoSlice, Read, Write},
    net::TcpListener,
    sync::{Mutex, mpsc},
    time::{Duration, Instant},
};

static SERIAL: Mutex<()> = Mutex::new(());

#[path = "../../../tests/support/io_fixture.rs"]
mod fixture;

use fixture::{Releases, Server, proxy_config};
use naive::owned::Guarded;

#[test]
fn public_handles_satisfy_thread_safe_host_stream_requirements() {
    fn host_handle<T: Send + Sync + Unpin>() {}
    host_handle::<naive::NaiveStream>();
    host_handle::<naive::owned::ReadHalf>();
    host_handle::<naive::owned::WriteHalf>();
    host_handle::<naive::ReadChunk>();
    fn check_futures(stream: &mut naive::NaiveStream) {
        fn send_future<T: Send>(_: T) {}
        send_future(stream.read_owned(Vec::<u8>::with_capacity(8)));
        send_future(stream.write_owned(vec![1]));
        // A host permit can be Send without Sync; neither owned future should
        // accidentally strengthen the buffer bound to Sync.
        send_future(stream.read_owned(naive::owned::Guarded::new(
            Vec::<u8>::with_capacity(8),
            std::cell::Cell::new(()),
        )));
        send_future(stream.write_owned(naive::owned::Guarded::new(
            vec![1],
            std::cell::Cell::new(()),
        )));
    }
    let _: fn(&mut naive::NaiveStream) = check_futures;
}
fn server() -> (u16, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            header.push(byte[0]);
        }
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .unwrap();
        let mut bytes = [0; 8192];
        loop {
            match stream.read(&mut bytes) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if stream.write_all(&bytes[..n]).is_err() {
                        break;
                    }
                }
            }
        }
    });
    (port, task)
}

#[test]
fn owned_transfer_reuses_host_storage_and_allocates_no_bridge_payload() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let (port, server) = server();
    block_on(async {
        let client = NaiveClient::new(Config::new(format!("http://127.0.0.1:{port}")))
            .await
            .unwrap();
        let mut stream = client.connect("remote.invalid", 443).await.unwrap();
        let before = naive::buffer_stats().allocations;
        let data = b"owned bytes".to_vec();
        let pointer = data.as_ptr();
        let sent = stream.write_owned(data).await;
        assert_eq!(sent.result.unwrap(), 11);
        assert_eq!(sent.buffer.as_ptr(), pointer);
        let mut reply = Vec::new();
        while reply.len() < 11 {
            let data = Vec::with_capacity(4096);
            let pointer = data.as_ptr();
            let received = stream.read_owned(data).await;
            assert!(received.result.unwrap() > 0);
            assert_eq!(received.buffer.as_ptr(), pointer);
            reply.extend_from_slice(&received.buffer);
        }
        assert_eq!(&reply, b"owned bytes");
        assert_eq!(naive::buffer_stats().allocations, before);
        // Unsupported half-close is observable and does not destroy the stream.
        assert_eq!(
            stream.shutdown_write().await.unwrap_err().kind(),
            std::io::ErrorKind::Unsupported
        );
        let sent = stream.write_owned(b"still open".to_vec()).await;
        assert_eq!(sent.result.unwrap(), 10);
        let mut reply = Vec::new();
        while reply.len() < 10 {
            let received = stream.read_owned(Vec::with_capacity(4096)).await;
            assert!(received.result.unwrap() > 0);
            reply.extend_from_slice(&received.buffer);
        }
        assert_eq!(&reply, b"still open");
        client.shutdown().await.unwrap();
    });
    server.join().unwrap();
}

struct HostBuffer {
    bytes: Vec<u8>,
    released: mpsc::Sender<()>,
}
impl Drop for HostBuffer {
    fn drop(&mut self) {
        let _ = self.released.send(());
    }
}
// SAFETY: the Vec allocation is exclusive and never resized while lent.
unsafe impl IoBuf for HostBuffer {
    fn as_ptr(&self) -> *const u8 {
        self.bytes.as_ptr()
    }
    fn bytes_init(&self) -> usize {
        self.bytes.len()
    }
}
unsafe impl IoBufMut for HostBuffer {
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.bytes.as_mut_ptr()
    }
    fn bytes_total(&mut self) -> usize {
        self.bytes.capacity()
    }
    unsafe fn set_init(&mut self, n: usize) {
        unsafe {
            self.bytes.set_len(n);
        }
    }
}

#[test]
fn canceled_owned_read_releases_the_host_owner_after_native_teardown() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let (port, server) = server();
    let (released, wait) = mpsc::channel();
    block_on(async {
        let client = NaiveClient::new(Config::new(format!("http://127.0.0.1:{port}")))
            .await
            .unwrap();
        let mut stream = client.connect("remote.invalid", 443).await.unwrap();
        let operation = stream.read_owned(HostBuffer {
            bytes: Vec::with_capacity(4096),
            released,
        });
        assert!(operation.now_or_never().is_none()); // polls once, then cancels
        client.shutdown().await.unwrap();
        assert!(stream.write_owned(vec![1]).await.result.is_err());
    });
    wait.recv_timeout(Duration::from_secs(3)).unwrap();
    assert!(wait.try_recv().is_err(), "owner returned more than once");
    server.join().unwrap();
}

#[test]
fn owned_read_deadline_returns_buffer_only_after_the_native_lease_ends() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let (port, server) = server();
    block_on(async {
        let client = NaiveClient::new(Config::new(format!("http://127.0.0.1:{port}")))
            .await
            .unwrap();
        let mut stream = client.connect("remote.invalid", 443).await.unwrap();
        stream
            .set_read_deadline(Some(Instant::now() + Duration::from_millis(30)))
            .unwrap();
        let data = Vec::with_capacity(4096);
        let ptr = data.as_ptr();
        let result = stream.read_owned(data).await;
        assert_eq!(
            result.result.unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
        assert_eq!(result.buffer.as_ptr(), ptr);
        client.shutdown().await.unwrap();
    });
    server.join().unwrap();
}

#[test]
fn leased_chunks_survive_shutdown_and_do_not_get_overwritten() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let (port, server) = server();
    block_on(async {
        let client = NaiveClient::new(Config::new(format!("http://127.0.0.1:{port}")))
            .await
            .unwrap();
        let mut stream = client.connect("remote.invalid", 443).await.unwrap();
        stream.write_owned(b"a".to_vec()).await.result.unwrap();
        let first = stream.read_chunk().await.unwrap().unwrap();
        stream.write_owned(b"b".to_vec()).await.result.unwrap();
        let second = stream.read_chunk().await.unwrap().unwrap();
        assert_ne!(first.as_ref().as_ptr(), second.as_ref().as_ptr());
        client.shutdown().await.unwrap();
        assert_eq!(first.as_ref(), b"a");
        assert_eq!(second.as_ref(), b"b");
        #[cfg(feature = "bytes")]
        {
            let ptr = first.as_ref().as_ptr();
            let bytes = first.into_bytes();
            assert_eq!(ptr, bytes.as_ptr());
        }
    });
    server.join().unwrap();
}

#[test]
fn owned_and_borrowed_apis_share_read_order_and_write_order() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let (port, server) = server();
    block_on(async {
        let client = NaiveClient::new(Config::new(format!("http://127.0.0.1:{port}")))
            .await
            .unwrap();
        let mut stream = client.connect("remote.invalid", 443).await.unwrap();
        poll_fn(|cx| stream.poll_write_slices(cx, &[IoSlice::new(b"a")]))
            .await
            .unwrap();
        stream.write_owned(b"bcdef".to_vec()).await.result.unwrap();
        let mut first = [0];
        poll_fn(|cx| stream.poll_read_slice(cx, &mut first))
            .await
            .unwrap();
        assert_eq!(first, *b"a");
        let mut rest = Vec::new();
        while rest.len() < 5 {
            let received = stream.read_owned(Vec::with_capacity(16)).await;
            assert!(received.result.unwrap() > 0);
            rest.extend_from_slice(&received.buffer);
        }
        assert_eq!(rest, b"bcdef");
        client.shutdown().await.unwrap();
    });
    server.join().unwrap();
}

#[test]
fn split_owned_halves_progress_concurrently_and_keep_the_stream_alive() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let (port, server) = server();
    block_on(async {
        let client = NaiveClient::new(Config::new(format!("http://127.0.0.1:{port}")))
            .await
            .unwrap();
        let stream = client.connect("remote.invalid", 443).await.unwrap();
        let (mut read, mut write) = stream.into_split();
        let (received, sent) = futures_util::join!(
            read.read_owned(Vec::with_capacity(8)),
            write.write_owned(vec![71])
        );
        assert_eq!(sent.result.unwrap(), 1);
        assert_eq!(received.result.unwrap(), 1);
        assert_eq!(received.buffer, [71]);
        drop(read); // The surviving writer still owns the connection.
        assert_eq!(write.write_owned(vec![72]).await.result.unwrap(), 1);
        write.close();
        client.shutdown().await.unwrap();
    });
    server.join().unwrap();
}

#[test]
fn a_native_read_chunk_can_be_written_without_a_bytes_adapter() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let (a_port, a_server) = server();
    let (b_port, b_server) = server();
    block_on(async {
        let a = NaiveClient::new(Config::new(format!("http://127.0.0.1:{a_port}")))
            .await
            .unwrap();
        let b = NaiveClient::new(Config::new(format!("http://127.0.0.1:{b_port}")))
            .await
            .unwrap();
        let mut source = a.connect("remote.invalid", 443).await.unwrap();
        let mut destination = b.connect("remote.invalid", 443).await.unwrap();
        source.write_owned(vec![91]).await.result.unwrap();
        let chunk = source.read_chunk().await.unwrap().unwrap();
        let pointer = chunk.as_ref().as_ptr();
        a.shutdown().await.unwrap();
        let before = naive::buffer_stats().allocations;
        let written = destination.write_owned(chunk).await;
        assert_eq!(written.result.unwrap(), 1);
        assert_eq!(written.buffer.as_ref().as_ptr(), pointer);
        let received = destination.read_owned(Vec::with_capacity(8)).await;
        assert_eq!(received.result.unwrap(), 1);
        assert_eq!(received.buffer, [91]);
        assert_eq!(naive::buffer_stats().allocations, before);
        b.shutdown().await.unwrap();
        assert_eq!(written.buffer.as_ref(), [91]);
    });
    a_server.join().unwrap();
    b_server.join().unwrap();
}

#[test]
fn cancel_submitted_read_reclaims_its_guard_without_shutting_down_the_client() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let server = Server::echo();
    let released = Releases::default();
    block_on(async {
        let client = NaiveClient::new(proxy_config(server.port)).await.unwrap();
        let mut stream = client.connect("remote.invalid", 443).await.unwrap();
        let mut read = Box::pin(stream.read_owned(Guarded::new(
            Vec::<u8>::with_capacity(4096),
            released.guard(),
        )));
        assert!(futures_util::poll!(&mut read).is_pending());
        // Stats is a barrier on the native IO sequence: the read has reached
        // the socket, rather than merely being queued on the caller thread.
        assert_eq!(client.stats().await.unwrap().active_streams, 1);
        assert_eq!(released.count(), 0);
        drop(read);
        assert_eq!(client.stats().await.unwrap().active_streams, 0);
        released.wait_for(1);
        assert!(stream.write_owned(vec![1]).await.result.is_err());
        client.shutdown().await.unwrap();
        assert_eq!(released.count(), 1);
    });
    server.finish();
}

#[test]
fn dropping_a_completed_but_unobserved_write_reclaims_its_owner_once() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let server = Server::echo();
    let released = Releases::default();
    block_on(async {
        let client = NaiveClient::new(proxy_config(server.port)).await.unwrap();
        let mut stream = client.connect("remote.invalid", 443).await.unwrap();
        let mut write = Box::pin(stream.write_owned(Guarded::new(vec![9], released.guard())));
        assert!(futures_util::poll!(&mut write).is_pending());
        let deadline = Instant::now() + fixture::WAIT;
        while client.stats().await.unwrap().bytes_written != 1 {
            assert!(
                Instant::now() < deadline,
                "write never completed on native IO"
            );
        }
        assert_eq!(
            released.count(),
            0,
            "unobserved result still owns the guard"
        );
        drop(write);
        assert_eq!(client.stats().await.unwrap().active_streams, 0);
        released.wait_for(1);
        assert!(stream.write_owned(vec![2]).await.result.is_err());
        client.shutdown().await.unwrap();
        assert_eq!(released.count(), 1);
    });
    server.finish();
}

#[test]
fn shutdown_returns_an_inflight_owner_before_the_caller_recycles_it() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let server = Server::echo();
    let released = Releases::default();
    block_on(async {
        let client = NaiveClient::new(proxy_config(server.port)).await.unwrap();
        let mut stream = client.connect("remote.invalid", 443).await.unwrap();
        let buffer = Vec::<u8>::with_capacity(4096);
        let pointer = buffer.as_ptr();
        let mut read = Box::pin(stream.read_owned(Guarded::new(buffer, released.guard())));
        assert!(futures_util::poll!(&mut read).is_pending());
        client.stats().await.unwrap();
        client.shutdown().await.unwrap();
        let result = read.await;
        assert!(result.result.is_err());
        assert_eq!(result.transferred, 0);
        assert_eq!(result.buffer.buffer.as_ptr(), pointer);
        assert_eq!(released.count(), 0);
        drop(result);
        released.wait_for(1);
    });
    server.finish();
}

#[test]
fn an_expired_presubmission_deadline_does_not_abort_the_stream() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let server = Server::echo();
    let released = Releases::default();
    block_on(async {
        let client = NaiveClient::new(proxy_config(server.port)).await.unwrap();
        let mut stream = client.connect("remote.invalid", 443).await.unwrap();
        stream.set_read_deadline(Some(Instant::now())).unwrap();
        let result = stream
            .read_owned(Guarded::new(Vec::<u8>::with_capacity(8), released.guard()))
            .await;
        assert_eq!(
            result.result.unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
        assert_eq!(released.count(), 0);
        drop(result.buffer);
        released.wait_for(1);
        assert_eq!(client.stats().await.unwrap().active_streams, 1);
        stream.set_read_deadline(None).unwrap();
        stream.write_owned(vec![37]).await.result.unwrap();
        let reply = stream.read_owned(Vec::with_capacity(8)).await;
        assert_eq!(reply.result.unwrap(), 1);
        assert_eq!(reply.buffer, [37]);
        client.shutdown().await.unwrap();
    });
    server.finish();
}

struct PanickingPointer(Vec<u8>);
// SAFETY: no pointer is ever exposed, so unwinding cannot leave a live borrow.
unsafe impl IoBufMut for PanickingPointer {
    fn bytes_total(&mut self) -> usize {
        self.0.capacity()
    }
    fn as_mut_ptr(&mut self) -> *mut u8 {
        panic!("test pointer acquisition panic")
    }
    unsafe fn set_init(&mut self, _: usize) {
        unreachable!()
    }
}

#[test]
fn a_panicking_buffer_does_not_leave_the_read_slot_pending() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let server = Server::echo();
    block_on(async {
        let client = NaiveClient::new(proxy_config(server.port)).await.unwrap();
        let mut stream = client.connect("remote.invalid", 443).await.unwrap();
        let panic = std::panic::AssertUnwindSafe(
            stream.read_owned(PanickingPointer(Vec::with_capacity(8))),
        )
        .catch_unwind()
        .await;
        assert!(panic.is_err());
        stream.write_owned(vec![38]).await.result.unwrap();
        let reply = stream.read_owned(Vec::with_capacity(8)).await;
        assert_eq!(reply.result.unwrap(), 1);
        assert_eq!(reply.buffer, [38]);
        client.shutdown().await.unwrap();
    });
    server.finish();
}

#[cfg(unix)]
#[test]
fn a_backpressured_owned_write_deadline_returns_its_buffer_and_known_prefix() {
    backpressured_write(WriteEnd::Deadline);
}

#[cfg(unix)]
#[test]
fn canceling_a_backpressured_owned_write_reclaims_its_guard_once() {
    backpressured_write(WriteEnd::Cancel);
}

#[cfg(unix)]
#[test]
fn a_remote_reset_returns_the_pending_write_owner_and_known_prefix() {
    backpressured_write(WriteEnd::Reset);
}

#[cfg(unix)]
#[derive(Clone, Copy, PartialEq)]
enum WriteEnd {
    Deadline,
    Cancel,
    Reset,
}

#[cfg(unix)]
fn backpressured_write(end: WriteEnd) {
    use std::{
        os::fd::{AsFd, AsRawFd},
        sync::Arc,
    };
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let (release, wait) = mpsc::channel();
    let server = Server::proxy(move |stream| {
        let size: libc::c_int = 1024;
        // SAFETY: socket and pointer are valid for this synchronous call.
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    (&size as *const libc::c_int).cast(),
                    std::mem::size_of_val(&size) as _,
                )
            },
            0
        );
        let _ = wait.recv_timeout(fixture::WAIT);
        if end == WriteEnd::Reset {
            let linger = libc::linger {
                l_onoff: 1,
                l_linger: 0,
            };
            // SAFETY: this option asks the fixture to reset its own socket on close.
            assert_eq!(
                unsafe {
                    libc::setsockopt(
                        stream.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_LINGER,
                        (&linger as *const libc::linger).cast(),
                        std::mem::size_of_val(&linger) as _,
                    )
                },
                0
            );
        }
    });
    block_on(async {
        let mut config = proxy_config(server.port);
        config.network.socket_control = Some(Arc::new(|socket: naive::network::Socket<'_>, _| {
            let size: libc::c_int = 1024;
            // SAFETY: the borrowed socket and option storage outlive the call.
            let result = unsafe {
                libc::setsockopt(
                    socket.as_fd().as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    (&size as *const libc::c_int).cast(),
                    std::mem::size_of_val(&size) as _,
                )
            };
            if result == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        }));
        let client = NaiveClient::new(config).await.unwrap();
        let mut stream = client.connect("remote.invalid", 443).await.unwrap();
        let mut terminated = false;
        for _ in 0..128 {
            let released = Releases::default();
            let data = vec![71; 65536];
            let pointer = data.as_ptr();
            let before = client.stats().await.unwrap().bytes_written;
            let timeout = if end == WriteEnd::Deadline {
                Duration::from_millis(50)
            } else {
                fixture::WAIT
            };
            stream
                .set_write_deadline(Some(Instant::now() + timeout))
                .unwrap();
            let mut operation = Box::pin(stream.write_owned(Guarded::new(data, released.guard())));
            let result = if end != WriteEnd::Deadline {
                assert!(futures_util::poll!(&mut operation).is_pending());
                // Observe the socket after submission before testing backpressure.
                client.stats().await.unwrap();
                match futures_util::poll!(&mut operation) {
                    std::task::Poll::Ready(result) => result,
                    std::task::Poll::Pending => {
                        assert_eq!(released.count(), 0);
                        if end == WriteEnd::Reset {
                            release.send(()).unwrap();
                            operation.await
                        } else {
                            drop(operation);
                            assert_eq!(client.stats().await.unwrap().active_streams, 0);
                            released.wait_for(1);
                            terminated = true;
                            break;
                        }
                    }
                }
            } else {
                operation.await
            };
            assert_eq!(result.buffer.buffer.as_ptr(), pointer);
            assert_eq!(released.count(), 0);
            assert!(result.transferred <= 65536);
            let stats = client.stats().await.unwrap();
            assert_eq!(stats.bytes_written - before, result.transferred as u64);
            if let Err(error) = &result.result {
                assert!(
                    end != WriteEnd::Cancel,
                    "write failed before explicit cancellation"
                );
                if end == WriteEnd::Deadline {
                    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
                } else {
                    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
                }
                assert_eq!(stats.active_streams, 0);
                terminated = true;
            }
            drop(result);
            released.wait_for(1);
            if terminated {
                break;
            }
        }
        assert!(terminated, "fixture failed to apply write backpressure");
        assert!(stream.write_owned(vec![1]).await.result.is_err());
        client.shutdown().await.unwrap();
    });
    let _ = release.send(());
    server.finish();
}
