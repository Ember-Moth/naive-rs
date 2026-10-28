// Identical contracts run on actual monoio and compio executors. The including
// crate supplies its IO traits, run(), and parts() for its completion result.
use fixture::{Buffer, Releases, Server, proxy_config, tls_config};
use naive::NaiveClient;
use std::{
    cell::Cell,
    io::{Read, Write},
    rc::Rc,
    thread::{self, ThreadId},
    time::{Duration, Instant},
};

struct LocalBuffer {
    bytes: Vec<u8>,
    initialized: Rc<Cell<usize>>,
    drops: Rc<Cell<usize>>,
    thread: ThreadId,
}
impl LocalBuffer {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            initialized: Rc::new(Cell::new(0)),
            drops: Rc::new(Cell::new(0)),
            thread: thread::current().id(),
        }
    }
    fn check_thread(&self) {
        assert_eq!(self.thread, thread::current().id());
    }
    unsafe fn publish(&mut self, n: usize) {
        self.check_thread();
        assert!(n <= self.bytes.capacity());
        unsafe { self.bytes.set_len(n) }
        self.initialized.set(n);
    }
}
impl Drop for LocalBuffer {
    fn drop(&mut self) {
        self.check_thread();
        self.drops.set(self.drops.get() + 1);
    }
}

#[test]
fn local_buffers_and_native_completions() {
    let server = Server::echo();
    run(async {
        let client = NaiveClient::new(proxy_config(server.port)).await.unwrap();
        let mut stream = Stream::from(client.connect("remote.invalid", 443).await.unwrap());
        let data = LocalBuffer::new(vec![42]);
        let pointer = data.bytes.as_ptr();
        let drops = data.drops.clone();
        let (result, returned) = parts(stream.write(data).await);
        assert_eq!(result.unwrap(), 1);
        assert_eq!(returned.bytes.as_ptr(), pointer);
        drop(returned);
        assert_eq!(drops.get(), 1);
        stream.flush().await.unwrap();
        let data = LocalBuffer::new(Vec::with_capacity(16));
        let initialized = data.initialized.clone();
        let (result, returned) = parts(stream.read(data).await);
        assert_eq!(result.unwrap(), 1);
        assert_eq!(returned.bytes, [42]);
        assert_eq!(initialized.get(), 1);
        let sent = stream.write_owned(vec![43]).await;
        assert_eq!(sent.result.unwrap(), 1);
        let received = stream.read_owned(Vec::with_capacity(16)).await;
        assert_eq!(received.result.unwrap(), 1);
        assert_eq!(received.buffer, [43]);
        let (mut reader, mut writer) = stream.into_split();
        let (read, write) = futures_util::join!(
            reader.read_owned(Vec::with_capacity(8)),
            writer.write_owned(vec![44])
        );
        assert_eq!(read.result.unwrap(), 1);
        assert_eq!(read.buffer, [44]);
        assert_eq!(write.result.unwrap(), 1);
        assert_eq!(
            writer.shutdown().await.unwrap_err().kind(),
            std::io::ErrorKind::Unsupported
        );
        assert_eq!(writer.write_owned(vec![45]).await.result.unwrap(), 1);
        assert_eq!(reader.read_owned(Vec::with_capacity(8)).await.buffer, [45]);
        drop(reader);
        assert_eq!(writer.write_owned(vec![46]).await.result.unwrap(), 1);
        client.shutdown().await.unwrap();
    });
    server.finish();
}

#[test]
fn canceling_a_local_read_keeps_the_connection_and_thread_local_owner_safe() {
    let server = Server::echo();
    run(async {
        let client = NaiveClient::new(proxy_config(server.port)).await.unwrap();
        let mut stream = Stream::from(client.connect("remote.invalid", 443).await.unwrap());
        let data = LocalBuffer::new(Vec::with_capacity(16));
        let drops = data.drops.clone();
        let mut operation = Box::pin(stream.read(data));
        assert!(futures_util::poll!(&mut operation).is_pending());
        client.stats().await.unwrap();
        assert_eq!(drops.get(), 0);
        drop(operation);
        assert_eq!(drops.get(), 1);
        assert_eq!(client.stats().await.unwrap().active_streams, 1);
        assert_eq!(stream.write_owned(vec![57]).await.result.unwrap(), 1);
        let (result, received) = parts(stream.read(LocalBuffer::new(Vec::with_capacity(8))).await);
        assert_eq!(result.unwrap(), 1);
        assert_eq!(received.bytes, [57]);
        client.shutdown().await.unwrap();
    });
    server.finish();
}

#[test]
fn native_cancel_and_deadline_reclaim_each_owner_once() {
    for deadline in [false, true] {
        let server = Server::echo();
        let releases = Releases::default();
        run(async {
            let client = NaiveClient::new(proxy_config(server.port)).await.unwrap();
            let mut stream = Stream::from(client.connect("remote.invalid", 443).await.unwrap());
            if deadline {
                stream
                    .inner_mut()
                    .set_read_deadline(Some(Instant::now() + Duration::from_millis(50)))
                    .unwrap();
            }
            let buffer = Buffer {
                bytes: Vec::with_capacity(4096),
                guard: releases.guard(),
            };
            let pointer = buffer.bytes.as_ptr();
            let mut operation = Box::pin(stream.read_owned(buffer));
            assert!(futures_util::poll!(&mut operation).is_pending());
            client.stats().await.unwrap();
            assert_eq!(releases.count(), 0);
            if deadline {
                let result = operation.await;
                assert_eq!(
                    result.result.unwrap_err().kind(),
                    std::io::ErrorKind::TimedOut
                );
                assert_eq!(result.buffer.bytes.as_ptr(), pointer);
                assert_eq!(releases.count(), 0);
                drop(result.buffer);
                assert_eq!(releases.threads(), [thread::current().id()]);
            } else {
                drop(operation);
            }
            assert_eq!(client.stats().await.unwrap().active_streams, 0);
            releases.wait_for(1);
            assert!(stream.write_owned(vec![1]).await.result.is_err());
            client.shutdown().await.unwrap();
            assert_eq!(releases.count(), 1);
        });
        server.finish();
    }
}

#[test]
fn split_local_io_preserves_large_partial_transfers() {
    let server = Server::echo();
    run(async {
        let client = NaiveClient::new(proxy_config(server.port)).await.unwrap();
        let stream = Stream::from(client.connect("remote.invalid", 443).await.unwrap());
        let (mut reader, mut writer) = stream.into_split();
        assert_eq!(
            parts(reader.read(LocalBuffer::new(Vec::new())).await)
                .0
                .unwrap(),
            0
        );
        assert_eq!(
            parts(writer.write(LocalBuffer::new(Vec::new())).await)
                .0
                .unwrap(),
            0
        );
        let payload: Vec<u8> = (0..196_613).map(|n| (n % 251) as u8).collect();
        let send = async {
            let mut offset = 0;
            while offset < payload.len() {
                let (result, buffer) = parts(
                    writer
                        .write(LocalBuffer::new(payload[offset..].to_vec()))
                        .await,
                );
                let n = result.unwrap();
                assert!(n > 0 && n <= 65536);
                assert_eq!(&buffer.bytes[..n], &payload[offset..offset + n]);
                offset += n;
            }
            writer.flush().await.unwrap();
        };
        let receive = async {
            let mut received = Vec::new();
            while received.len() < payload.len() {
                let (result, buffer) = parts(
                    reader
                        .read(LocalBuffer::new(Vec::with_capacity(13_007)))
                        .await,
                );
                let n = result.unwrap();
                assert!(n > 0);
                assert_eq!(buffer.bytes.len(), n);
                received.extend_from_slice(&buffer.bytes);
            }
            assert_eq!(received, payload);
        };
        futures_util::join!(send, receive);
        client.shutdown().await.unwrap();
    });
    server.finish();
}

#[test]
#[ignore = "requires the loopback Caddy fixture; run python3 tests/interop.py --owned-io"]
fn h2_h3_trait_shutdown_drains_writes_and_preserves_the_response() {
    for scheme in ["https", "quic"] {
        let native: Vec<u8> = (0..32_771).map(|n| (n % 251) as u8).collect();
        let mut expected = b"before-".to_vec();
        expected.extend_from_slice(&native);
        expected.extend_from_slice(b"-after");
        let origin_expected = expected.clone();
        let origin = Server::origin(move |socket| {
            let mut request = Vec::new();
            socket.read_to_end(&mut request).unwrap();
            assert_eq!(request, origin_expected);
            request.reverse();
            socket.write_all(&request).unwrap();
        });
        run(async {
            let client = NaiveClient::new(tls_config(scheme)).await.unwrap();
            let raw = client.connect("127.0.0.1", origin.port).await.unwrap();
            let info = raw.info().await.unwrap();
            assert_eq!(
                info.protocol.as_deref(),
                Some(if scheme == "https" { "h2" } else { "h3" })
            );
            assert_eq!(info.tls_version, Some(0x0304));
            assert!(info.write_shutdown_supported);
            let mut stream = Stream::from(raw);
            assert_eq!(
                parts(stream.write(LocalBuffer::new(b"before-".to_vec())).await)
                    .0
                    .unwrap(),
                7
            );
            assert_eq!(stream.write_owned(native).await.result.unwrap(), 32_771);
            assert_eq!(
                parts(stream.write(LocalBuffer::new(b"-after".to_vec())).await)
                    .0
                    .unwrap(),
                6
            );
            stream.shutdown().await.unwrap();
            stream.shutdown().await.unwrap();
            assert_eq!(
                parts(stream.write(LocalBuffer::new(vec![1])).await)
                    .0
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::BrokenPipe
            );
            assert_eq!(
                stream.write_owned(vec![1]).await.result.unwrap_err().kind(),
                std::io::ErrorKind::BrokenPipe
            );
            let mut received = Vec::new();
            loop {
                let (result, buffer) = parts(stream.read(LocalBuffer::new(vec![99; 1024])).await);
                let n = result.unwrap();
                assert_eq!(buffer.bytes.len(), n);
                received.extend_from_slice(&buffer.bytes);
                if n == 0 {
                    break;
                }
            }
            expected.reverse();
            assert_eq!(received, expected);
            let eof = stream.read_owned(vec![99; 8]).await;
            assert_eq!(eof.result.unwrap(), 0);
            assert!(eof.buffer.is_empty());
            client.shutdown().await.unwrap();
        });
        origin.finish();
        eprintln!("{scheme}: adapter half-close, ordered writes and complete response passed");
    }
}
