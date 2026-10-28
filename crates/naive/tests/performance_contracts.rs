#![cfg(feature = "tokio")]
//! Ownership/backpressure regression contracts for the optimized data path.
use naive::{Config, NaiveClient};
use std::{
    io::{self, IoSlice},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

fn stats() -> naive_sys::BufferStats {
    let mut result = naive_sys::BufferStats::default();
    // SAFETY: the native function writes this POD record; reads are atomic.
    unsafe {
        naive_sys::naive_get_buffer_stats(&mut result);
    }
    result
}

async fn serve(mut socket: TcpStream, echo: bool) -> io::Result<()> {
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
        request.push(socket.read_u8().await?);
    }
    socket
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    if !echo {
        std::future::pending::<()>().await;
    }
    let (mut read, mut write) = socket.split();
    tokio::io::copy(&mut read, &mut write).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reuse_leases_pipeline_backpressure_and_shutdown_races() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            tasks.spawn(async move {
                let _ = serve(socket, true).await;
            });
            while tasks.try_join_next().is_some() {}
        }
    });
    let mut config = Config::new(format!("http://127.0.0.1:{port}"));
    config.io_workers = 4;
    let client = NaiveClient::new(config.clone()).await.unwrap();
    let mut stream = client.connect("example.com", 443).await.unwrap();
    let mut receive = [0; 64];
    for _ in 0..20 {
        stream.write_all(&[0x5a; 64]).await.unwrap();
        stream.read_exact(&mut receive).await.unwrap();
    }
    stream.flush().await.unwrap();
    let before = stats();
    for _ in 0..200 {
        stream.write_all(&[0x5a; 64]).await.unwrap();
        stream.read_exact(&mut receive).await.unwrap();
        assert_eq!(receive, [0x5a; 64]);
    }
    stream.flush().await.unwrap();
    let after = stats();
    assert!(
        after.allocations <= before.allocations + 1,
        "steady small IO must reuse native buffers: {before:?} -> {after:?}"
    );
    assert!(
        after.live_capacity <= 3 * 4096,
        "small flow buffers must stay adaptive: {after:?}"
    );

    // Vectored/small writes advance without flush and preserve ordering through
    // the two-buffer pipeline. No per-message packet boundary is assumed.
    let expected = b"first-second-third";
    let slices = [
        IoSlice::new(b"first-"),
        IoSlice::new(b"second-"),
        IoSlice::new(b"third"),
    ];
    assert_eq!(
        stream.write_vectored(&slices).await.unwrap(),
        expected.len()
    );
    let mut actual = vec![0; expected.len()];
    stream.read_exact(&mut actual).await.unwrap();
    assert_eq!(actual, expected);
    let mut borrowed = vec![0x2a; 1024];
    stream.write_all(&borrowed).await.unwrap();
    borrowed.fill(0xee);
    let mut copied = [0; 1024];
    stream.read_exact(&mut copied).await.unwrap();
    assert_eq!(
        copied, [0x2a; 1024],
        "accepted writes must not retain caller memory"
    );
    for _ in 0..32 {
        stream.write_all(&[0x31; 64]).await.unwrap();
    }
    let mut actual = vec![0; 32 * 64];
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut actual))
        .await
        .unwrap()
        .unwrap();
    assert!(actual.iter().all(|b| *b == 0x31));

    // A partially consumed READ lease must outlive native context shutdown.
    stream.write_all(&[0x77; 1024]).await.unwrap();
    stream.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    let mut one = [0];
    stream.read_exact(&mut one).await.unwrap();
    assert_eq!(one, [0x77]);
    client.shutdown().await.unwrap();
    let mut rest = [0; 1023];
    stream.read_exact(&mut rest).await.unwrap();
    assert_eq!(rest, [0x77; 1023]);
    let error = stream.write(b"closed").await.unwrap_err();
    assert_ne!(
        error.kind(),
        io::ErrorKind::Interrupted,
        "terminal cancellation must not make write_all retry forever"
    );
    drop(stream);
    drop(client);

    // Multi-worker callbacks race sends/cancels/shutdown. Every raw callback
    // context and every transferred buffer must eventually be released.
    for _ in 0..10 {
        let client = NaiveClient::new(config.clone()).await.unwrap();
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..32 {
            let client = client.clone();
            tasks.spawn(async move {
                if let Ok(mut stream) = client.connect("example.com", 443).await {
                    if let Err(error) = stream.write(&[0x22; 65536]).await {
                        assert_ne!(error.kind(), io::ErrorKind::Interrupted);
                    }
                    let mut read = [0; 32];
                    let _ = tokio::time::timeout(Duration::from_millis(1), stream.read(&mut read))
                        .await;
                }
            });
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
        client.shutdown().await.unwrap();
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
    }

    // Backpressure is bounded even if a peer accepts CONNECT then stops reading.
    let stalled = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = stalled.local_addr().unwrap().port();
    let blocked = tokio::spawn(async move {
        let (socket, _) = stalled.accept().await.unwrap();
        let _ = serve(socket, false).await;
    });
    let client = NaiveClient::new(Config::new(format!("http://127.0.0.1:{port}")))
        .await
        .unwrap();
    let mut stream = client.connect("example.com", 443).await.unwrap();
    let bytes = vec![0x11; 32 * 1024 * 1024];
    assert!(
        tokio::time::timeout(Duration::from_millis(100), stream.write_all(&bytes))
            .await
            .is_err()
    );
    assert!(
        stats().live_capacity <= 2 * 65536,
        "write buffering must be bounded: {:?}",
        stats()
    );
    drop(stream);
    client.shutdown().await.unwrap();
    drop(client);
    blocked.abort();
    server.abort();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if stats().live_buffers == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(stats().live_capacity, 0);
}
