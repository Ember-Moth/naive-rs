#![cfg(feature = "tokio")]
use naive::{Config, NaiveClient};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

struct Proxy {
    port: u16,
    frames: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}
impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn proxy(padded: bool, reject: bool, stall: bool) -> Proxy {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let frames = Arc::new(AtomicUsize::new(0));
    let observed = frames.clone();
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                break;
            };
            let frames = observed.clone();
            connections.spawn(async move {
                let _ = serve(socket, padded, reject, stall, frames).await;
            });
            while connections.try_join_next().is_some() {}
        }
    });
    Proxy { port, frames, task }
}

async fn serve(
    mut socket: TcpStream,
    padded: bool,
    reject: bool,
    stall: bool,
    frames: Arc<AtomicUsize>,
) -> io::Result<()> {
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        if headers.len() > 32768 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        headers.push(socket.read_u8().await?);
    }
    assert!(headers.starts_with(b"CONNECT example.com:443 HTTP/1.1\r\n"));
    if stall {
        std::future::pending::<()>().await;
    }
    if reject {
        socket.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"test\"\r\nContent-Length: 0\r\n\r\n").await?;
        return Ok(());
    }
    if padded {
        assert!(
            String::from_utf8_lossy(&headers)
                .to_ascii_lowercase()
                .contains("padding:")
        );
        socket.write_all(b"HTTP/1.1 200 Connection Established\r\nPadding: test\r\npadding-type-reply: 1\r\n\r\n").await?;
        // Echo decoded payloads using deliberately fragmented padded frames.
        for index in 0..8 {
            let size = socket.read_u16().await? as usize;
            let padding = socket.read_u8().await? as usize;
            let mut bytes = vec![0; size];
            socket.read_exact(&mut bytes).await?;
            let mut skip = vec![0; padding];
            socket.read_exact(&mut skip).await?;
            frames.fetch_add(1, Ordering::Relaxed);
            let header = [(size >> 8) as u8, size as u8, index + 1];
            for byte in header {
                socket.write_all(&[byte]).await?;
                tokio::task::yield_now().await;
            }
            socket.write_all(&bytes).await?;
            socket.write_all(&vec![0; (index + 1) as usize]).await?;
        }
    } else {
        socket
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
    }
    let (mut read, mut write) = socket.split();
    tokio::io::copy(&mut read, &mut write).await?;
    Ok(())
}

fn config(proxy: &Proxy) -> Config {
    Config::new(format!("http://127.0.0.1:{}", proxy.port))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn padding_fragmentation_large_transfer_and_plain_fallback() {
    for padded in [true, false] {
        let proxy = proxy(padded, false, false).await;
        let client = NaiveClient::new(config(&proxy)).await.unwrap();
        let mut stream = client.connect("example.com", 443).await.unwrap();
        // Cross the native eight-frame boundary with distinct messages.
        for index in 0..12 {
            let bytes = vec![index as u8; 73 + index * 51];
            stream.write_all(&bytes).await.unwrap();
            stream.flush().await.unwrap();
            let mut response = vec![0; bytes.len()];
            tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut response))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(response, bytes);
        }
        let bytes: Vec<u8> = (0..1024 * 1024).map(|n| (n % 251) as u8).collect();
        let (mut read, mut write) = tokio::io::split(stream);
        let send = async {
            write.write_all(&bytes).await.unwrap();
            write.flush().await.unwrap();
        };
        let recv = async {
            let mut data = vec![0; bytes.len()];
            read.read_exact(&mut data).await.unwrap();
            assert_eq!(data, bytes);
        };
        tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(send, recv);
        })
        .await
        .unwrap();
        assert_eq!(
            proxy.frames.load(Ordering::Relaxed),
            if padded { 8 } else { 0 }
        );
        drop(read);
        drop(write);
        client.shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canceled_read_preserves_data_and_shutdown_wakes_waiters() {
    let proxy = proxy(false, false, false).await;
    let client = NaiveClient::new(config(&proxy)).await.unwrap();
    let mut stream = client.connect("example.com", 443).await.unwrap();
    let mut abandoned = vec![0; 64];
    assert!(
        tokio::time::timeout(Duration::from_millis(30), stream.read(&mut abandoned))
            .await
            .is_err()
    );
    drop(abandoned);
    stream.write_all(b"after cancellation").await.unwrap();
    stream.flush().await.unwrap();
    let mut received = [0; 18];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&received, b"after cancellation");
    let waiting = tokio::spawn(async move {
        let mut byte = [0];
        stream.read(&mut byte).await
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    let (a, b) = tokio::join!(client.shutdown(), client.shutdown());
    a.unwrap();
    b.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert!(client.connect("example.com", 443).await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_auth_and_canceled_connects_release_native_state() {
    let reject = proxy(false, true, false).await;
    let client = NaiveClient::new(config(&reject)).await.unwrap();
    let error = client.connect("example.com", 443).await.unwrap_err();
    assert!(error.code().is_some());
    client.shutdown().await.unwrap();
    let stalled = proxy(false, false, true).await;
    let mut cfg = config(&stalled);
    cfg.connect_timeout = Duration::from_millis(30);
    let client = NaiveClient::new(cfg).await.unwrap();
    assert_eq!(
        client.connect("example.com", 443).await.unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    for _ in 0..20 {
        assert!(
            tokio::time::timeout(Duration::from_millis(2), client.connect("example.com", 443))
                .await
                .is_err()
        );
    }
    tokio::time::timeout(Duration::from_secs(5), client.shutdown())
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multiple_clients_and_rapid_stream_drop() {
    let proxy = proxy(false, false, false).await;
    for _ in 0..3 {
        let a = NaiveClient::new(config(&proxy)).await.unwrap();
        let b = NaiveClient::new(config(&proxy)).await.unwrap();
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..30 {
            let client = a.clone();
            tasks.spawn(async move {
                let mut stream = client.connect("example.com", 443).await.unwrap();
                stream
                    .write_all(b"drop with pending read/write")
                    .await
                    .unwrap();
                let mut bytes = [0; 10];
                let _ =
                    tokio::time::timeout(Duration::from_millis(1), stream.read(&mut bytes)).await;
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
        a.shutdown().await.unwrap();
        // The other client's context remains valid after the first shuts down.
        let mut stream = b.connect("example.com", 443).await.unwrap();
        stream.write_all(b"ok").await.unwrap();
        stream.flush().await.unwrap();
        let mut response = [0; 2];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ok");
        drop(stream);
        b.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn invalid_config_and_input() {
    assert!(NaiveClient::new(Config::new("direct://")).await.is_err());
    let proxy = proxy(false, false, false).await;
    let mut cfg = config(&proxy);
    cfg.extra_root_certificates = Some("invalid PEM".into());
    assert!(NaiveClient::new(cfg).await.is_err());
    let mut cfg = config(&proxy);
    cfg.insecure_concurrency = 0;
    assert!(NaiveClient::new(cfg).await.is_err());
    let client = NaiveClient::new(config(&proxy)).await.unwrap();
    assert!(client.connect("", 443).await.is_err());
    assert!(client.connect("bad\0host", 443).await.is_err());
    assert!(client.connect("example.com", 0).await.is_err());
    client.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canceled_initialization_and_stream_owned_client() {
    let proxy = proxy(false, false, false).await;
    for _ in 0..20 {
        if let Ok(Ok(client)) =
            tokio::time::timeout(Duration::from_nanos(1), NaiveClient::new(config(&proxy))).await
        {
            client.shutdown().await.unwrap();
        }
    }
    let client = NaiveClient::new(config(&proxy)).await.unwrap();
    let mut stream = client.connect("example.com", 443).await.unwrap();
    drop(client);
    stream.write_all(b"owned by stream").await.unwrap();
    stream.flush().await.unwrap();
    let mut response = [0; 15];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"owned by stream");
    stream.shutdown().await.unwrap();
}
