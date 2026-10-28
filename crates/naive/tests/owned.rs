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
    let _serial = SERIAL.lock().unwrap();
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
    let _serial = SERIAL.lock().unwrap();
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
    let _serial = SERIAL.lock().unwrap();
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
    let _serial = SERIAL.lock().unwrap();
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
    let _serial = SERIAL.lock().unwrap();
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
    let _serial = SERIAL.lock().unwrap();
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
    let _serial = SERIAL.lock().unwrap();
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
