#![cfg(feature = "tokio")]
use naive::{Config, Event, NaiveClient};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
};

async fn gated_proxy() -> (u16, oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (ready, waiting) = oneshot::channel();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            headers.push(socket.read_u8().await.unwrap());
        }
        waiting.await.unwrap();
        socket
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        let (mut read, mut write) = socket.split();
        let _ = tokio::io::copy(&mut read, &mut write).await;
    });
    (port, ready, task)
}

#[tokio::test]
async fn early_handle_waits_for_handshake_and_reports_real_stream_stats() {
    let (port, ready, server) = gated_proxy().await;
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = events.clone();
    let mut config = Config::new(format!("http://127.0.0.1:{port}"));
    config.observer = Some(Arc::new(move |event: &Event| {
        sink.lock().unwrap().push(event.clone())
    }));
    let client = NaiveClient::new(config).await.unwrap();
    let mut stream = client.connect_early("remote.invalid", 443).unwrap();
    let id = stream.id();
    assert!(
        tokio::time::timeout(Duration::from_millis(20), stream.write(b"must wait"))
            .await
            .is_err()
    );
    ready.send(()).unwrap();
    stream.handshake().await.unwrap();
    stream.handshake().await.unwrap();
    let initial = stream.info().await.unwrap();
    assert_eq!(initial.protocol.as_deref(), Some("http/1.1"));
    assert_eq!(initial.tls_version, None);
    assert_eq!(
        initial.bytes_written, 0,
        "canceled pre-handshake write sent data"
    );
    stream.write_all(b"payload").await.unwrap();
    stream.flush().await.unwrap();
    let mut reply = [0; 7];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"payload");
    let stats = client.stats().await.unwrap();
    assert_eq!(
        (
            stats.connect_attempts,
            stats.connect_successes,
            stats.active_streams
        ),
        (1, 1, 1)
    );
    assert_eq!((stats.bytes_read, stats.bytes_written), (7, 7));
    let info = stream.info().await.unwrap();
    assert_eq!((info.bytes_read, info.bytes_written), (7, 7));
    drop(stream);
    client.shutdown().await.unwrap();
    let stats = client.stats().await.unwrap();
    assert_eq!(
        (
            stats.active_streams,
            stats.closed_streams,
            stats.connect_failures
        ),
        (0, 1, 0)
    );
    {
        let events = events.lock().unwrap();
        assert!(
            events
                .iter()
                .any(|e| matches!(e,Event::StreamConnected{id: seen} if *seen == id))
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e,Event::StreamClosed{id: seen,..} if *seen == id))
        );
        assert!(events.iter().any(|e| matches!(e, Event::ShutdownComplete)));
    }
    server.await.unwrap();
}

#[tokio::test]
async fn deadlines_can_change_while_read_is_pending_and_do_not_close_stream() {
    let (port, ready, server) = gated_proxy().await;
    let client = NaiveClient::new(Config::new(format!("http://127.0.0.1:{port}")))
        .await
        .unwrap();
    ready.send(()).unwrap();
    let mut stream = client.connect("remote.invalid", 443).await.unwrap();
    let deadline = stream.deadline_handle();
    let task = tokio::spawn(async move {
        let mut byte = [0];
        let error = stream.read(&mut byte).await.unwrap_err();
        (stream, error)
    });
    deadline
        .set_read_deadline(Some(Instant::now() + Duration::from_millis(20)))
        .unwrap();
    let (mut stream, error) = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    deadline.set_read_deadline(None).unwrap();
    deadline.set_write_deadline(Some(Instant::now())).unwrap();
    assert_eq!(
        stream.write(b"not accepted").await.unwrap_err().kind(),
        std::io::ErrorKind::TimedOut
    );
    deadline.set_write_deadline(None).unwrap();
    stream.write_all(b"retained read").await.unwrap();
    stream.flush().await.unwrap();
    let mut reply = [0; 13];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"retained read");
    drop(stream);
    assert!(deadline.set_deadline(None).is_err());
    client.shutdown().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn deadline_handle_does_not_retain_client_or_native_stream() {
    let (port, ready, server) = gated_proxy().await;
    let (done, mut finished) = tokio::sync::mpsc::unbounded_channel();
    let mut config = Config::new(format!("http://127.0.0.1:{port}"));
    config.observer = Some(Arc::new(move |event: &Event| {
        if matches!(event, Event::ShutdownComplete) {
            let _ = done.send(());
        }
    }));
    let client = NaiveClient::new(config).await.unwrap();
    ready.send(()).unwrap();
    let stream = client.connect("remote.invalid", 443).await.unwrap();
    let deadlines = stream.deadline_handle();
    drop(stream);
    drop(client);
    tokio::time::timeout(Duration::from_secs(2), finished.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(deadlines.set_read_deadline(None).is_err());
    server.await.unwrap();
}

#[tokio::test]
async fn ech_discovery_uses_host_dns_and_strict_mode_does_not_dial_without_records() {
    use naive::network::{
        DialCompletion, DialRequest, ResolveCompletion, ResolveQuery, ResolveRequest,
    };
    use naive::{EchMode, EchOptions};
    use std::sync::atomic::{AtomicUsize, Ordering};
    for mode in [EchMode::Strict, EchMode::Opportunistic] {
        let queries = Arc::new(Mutex::new(Vec::new()));
        let seen = queries.clone();
        let calls = Arc::new(AtomicUsize::new(0));
        let dials = calls.clone();
        let mut config = Config::new("https://proxy.invalid:8443");
        config.ech = Some(EchOptions {
            mode,
            query_name: Some("cover.invalid".into()),
            config_list: None,
        });
        config.network.resolver = Some(Arc::new(
            move |request: ResolveRequest, completion: ResolveCompletion| {
                seen.lock()
                    .unwrap()
                    .push((request.query, request.hostname.clone()));
                if request.query == ResolveQuery::HttpsRecord {
                    completion.complete_https(Err(std::io::ErrorKind::NotFound.into()));
                } else {
                    completion.complete(Ok(vec!["127.0.0.1".parse().unwrap()]));
                }
            },
        ));
        config.network.tcp_dialer = Some(Arc::new(
            move |_: DialRequest, completion: DialCompletion| {
                dials.fetch_add(1, Ordering::Relaxed);
                completion.complete(Err(std::io::ErrorKind::ConnectionRefused.into()));
            },
        ));
        let client = NaiveClient::new(config).await.unwrap();
        assert!(client.connect("remote.invalid", 443).await.is_err());
        client.shutdown().await.unwrap();
        assert!(queries.lock().unwrap().contains(&(
            ResolveQuery::HttpsRecord,
            "_8443._https.cover.invalid".into()
        )));
        if mode == EchMode::Strict {
            assert_eq!(calls.load(Ordering::Relaxed), 0);
        } else {
            assert!(calls.load(Ordering::Relaxed) > 0);
        }
    }
}
