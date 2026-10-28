//! These tests intentionally create no Tokio runtime or reactor.
use futures_executor::block_on;
use naive::{Config, NaiveClient};
use std::{
    future::poll_fn,
    io::{IoSlice, Read, Write},
    net::TcpListener,
    time::{Duration, Instant},
};

fn server() -> (u16, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            socket.read_exact(&mut byte).unwrap();
            headers.push(byte[0]);
        }
        socket
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .unwrap();
        let mut buffer = [0; 8192];
        loop {
            let n = socket.read(&mut buffer).unwrap();
            if n == 0 {
                break;
            }
            socket.write_all(&buffer[..n]).unwrap();
        }
    });
    (port, task)
}

#[test]
fn core_poll_api_and_shutdown_need_no_runtime() {
    let (port, server) = server();
    block_on(async {
        let client = NaiveClient::new(Config::new(format!("http://127.0.0.1:{port}")))
            .await
            .unwrap();
        let mut stream = client.connect("remote.invalid", 443).await.unwrap();
        let n = poll_fn(|cx| stream.poll_write_slices(cx, &[IoSlice::new(b"runtime free")]))
            .await
            .unwrap();
        assert_eq!(n, 12);
        poll_fn(|cx| stream.poll_flush_pending(cx)).await.unwrap();
        let mut reply = [0; 12];
        let mut received = 0;
        while received < reply.len() {
            received += poll_fn(|cx| stream.poll_read_slice(cx, &mut reply[received..]))
                .await
                .unwrap();
        }
        assert_eq!(&reply, b"runtime free");
        poll_fn(|cx| stream.poll_close_stream(cx)).await.unwrap();
        let (first, second) = futures_util::join!(client.shutdown(), client.shutdown());
        first.unwrap();
        second.unwrap();
        client.shutdown().await.unwrap();
    });
    server.join().unwrap();
}

#[test]
fn native_connect_timeout_cancels_host_work_without_a_reactor() {
    use naive::network::{ResolveCompletion, ResolveRequest};
    let (send, recv) = std::sync::mpsc::channel();
    let mut config = Config::new("http://unresolved.invalid:443");
    config.connect_timeout = Duration::from_millis(30);
    config.network.resolver = Some(std::sync::Arc::new(
        move |_: ResolveRequest, done: ResolveCompletion| {
            send.send(done).unwrap();
        },
    ));
    block_on(async {
        let client = NaiveClient::new(config).await.unwrap();
        let start = Instant::now();
        assert_eq!(
            client
                .connect("remote.invalid", 443)
                .await
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::TimedOut
        );
        assert!(start.elapsed() < Duration::from_secs(1));
        let completion = recv.recv_timeout(Duration::from_secs(1)).unwrap();
        client.shutdown().await.unwrap();
        assert!(completion.cancellation().is_cancelled());
        drop(completion);
    });
}

#[cfg(feature = "futures-io")]
#[test]
fn futures_io_adapter_transfers_and_closes_without_tokio() {
    use futures_util::io::{AsyncReadExt, AsyncWriteExt};
    let (port, server) = server();
    block_on(async {
        let client = NaiveClient::new(Config::new(format!("http://127.0.0.1:{port}")))
            .await
            .unwrap();
        let mut stream = client.connect("remote.invalid", 443).await.unwrap();
        stream.write_all(b"futures io").await.unwrap();
        stream.flush().await.unwrap();
        let mut reply = [0; 10];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"futures io");
        futures_util::io::AsyncWriteExt::close(&mut stream)
            .await
            .unwrap();
        client.shutdown().await.unwrap();
    });
    server.join().unwrap();
}
