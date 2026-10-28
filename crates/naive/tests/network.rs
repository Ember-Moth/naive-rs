#![cfg(feature = "tokio")]
use naive::{Config, NaiveClient, network::*};
use std::{
    io,
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::mpsc,
};

async fn fixture() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let mut peers = tokio::task::JoinSet::new();
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            peers.spawn(async move {
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") {
                    let Ok(byte) = socket.read_u8().await else {
                        return;
                    };
                    headers.push(byte);
                    assert!(headers.len() < 65536);
                }
                assert!(headers.starts_with(b"CONNECT remote.invalid:443 HTTP/1.1\r\n"));
                socket
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .unwrap();
                let (mut read, mut write) = socket.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    (port, task)
}
fn config(port: u16) -> Config {
    let mut config = Config::new(format!("http://proxy.invalid:{port}"));
    config.connect_timeout = Duration::from_secs(2);
    config
}
async fn round_trip(client: &NaiveClient) {
    let mut stream = client.connect("remote.invalid", 443).await.unwrap();
    stream.write_all(b"host hooks").await.unwrap();
    stream.flush().await.unwrap();
    let mut bytes = [0; 10];
    stream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"host hooks");
}
async fn cancelled(token: &Cancellation) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !token.is_cancelled() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("native request was not canceled");
}

#[tokio::test]
async fn dns_is_client_local_and_does_not_resolve_connect_destination() {
    let (port, server) = fixture().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let mut options = config(port);
    options.network.resolver = Some(Arc::new(
        move |request: ResolveRequest, done: ResolveCompletion| {
            assert_eq!(request.hostname, "proxy.invalid");
            seen.fetch_add(1, Ordering::Relaxed);
            done.complete(Ok(vec!["127.0.0.1".parse().unwrap()]));
        },
    ));
    let client = NaiveClient::new(options).await.unwrap();
    round_trip(&client).await;
    assert!(calls.load(Ordering::Relaxed) > 0);
    let mut denied = config(port);
    // Even a normally resolvable name must not fall back to system DNS.
    denied.proxy = format!("http://localhost:{port}");
    denied.network.resolver = Some(Arc::new(|_: ResolveRequest, done: ResolveCompletion| {
        done.complete(Err(io::ErrorKind::NotFound.into()));
    }));
    let other = NaiveClient::new(denied).await.unwrap();
    assert_eq!(
        other
            .connect("remote.invalid", 443)
            .await
            .unwrap_err()
            .code(),
        Some(-130)
    );
    round_trip(&client).await;
    client.shutdown().await.unwrap();
    other.shutdown().await.unwrap();
    server.abort();
}

#[tokio::test]
async fn native_socket_control_runs_before_connect_and_can_reject() {
    let (port, server) = fixture().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let mut options = config(port);
    options.network.resolver = Some(Arc::new(|_: ResolveRequest, done: ResolveCompletion| {
        done.complete(Ok(vec!["127.0.0.1".parse().unwrap()]));
    }));
    options.network.socket_control = Some(Arc::new(move |socket: Socket<'_>, info: SocketInfo| {
        assert_eq!(info.transport, Transport::Tcp);
        assert_eq!(info.peer.port(), port);
        check_unconnected_socket(&socket);
        seen.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }));
    let client = NaiveClient::new(options.clone()).await.unwrap();
    round_trip(&client).await;
    assert!(calls.load(Ordering::Relaxed) > 0);
    options.network.socket_control = Some(Arc::new(|_: Socket<'_>, _: SocketInfo| {
        Err(io::ErrorKind::PermissionDenied.into())
    }));
    let denied = NaiveClient::new(options).await.unwrap();
    assert_eq!(
        denied
            .connect("remote.invalid", 443)
            .await
            .unwrap_err()
            .code(),
        Some(-130)
    );
    denied.shutdown().await.unwrap();
    client.shutdown().await.unwrap();
    server.abort();
}

#[tokio::test]
async fn host_tcp_dialer_can_route_to_a_different_socket() {
    let (port, server) = fixture().await;
    let mut options = config(54321);
    options.network.resolver = Some(Arc::new(|_: ResolveRequest, done: ResolveCompletion| {
        done.complete(Ok(vec!["127.0.0.2".parse().unwrap()]));
    }));
    options.network.tcp_dialer = Some(Arc::new(
        move |request: DialRequest, done: DialCompletion| {
            assert_eq!(request.addresses, vec!["127.0.0.2:54321".parse().unwrap()]);
            std::thread::spawn(move || {
                done.complete(std::net::TcpStream::connect(("127.0.0.1", port)))
            });
        },
    ));
    // Custom dialers own protection before connecting. Never run it too late.
    options.network.socket_control = Some(Arc::new(|_: Socket<'_>, _: SocketInfo| {
        panic!("control called after host dial")
    }));
    let client = NaiveClient::new(options).await.unwrap();
    round_trip(&client).await;
    client.shutdown().await.unwrap();
    server.abort();
}

#[tokio::test]
async fn canceled_resolve_can_complete_after_engine_destruction() {
    let (send, mut recv) = mpsc::unbounded_channel();
    let mut options = config(443);
    options.network.resolver = Some(Arc::new(
        move |_: ResolveRequest, done: ResolveCompletion| {
            send.send(done).unwrap();
        },
    ));
    let client = NaiveClient::new(options).await.unwrap();
    let connection = tokio::spawn({
        let client = client.clone();
        async move { client.connect("remote.invalid", 443).await }
    });
    let completion = recv.recv().await.unwrap();
    let token = completion.cancellation();
    connection.abort();
    assert!(connection.await.unwrap_err().is_cancelled());
    cancelled(&token).await;
    client.shutdown().await.unwrap();
    drop(client);
    completion.complete(Ok(vec![IpAddr::from([127, 0, 0, 1])]));
    assert!(token.is_cancelled());
}

#[tokio::test]
async fn canceled_dial_closes_a_late_socket() {
    let (send, mut recv) = mpsc::unbounded_channel();
    let mut options = config(443);
    options.host_resolver_rules = Some("MAP proxy.invalid 127.0.0.1".into());
    options.network.tcp_dialer = Some(Arc::new(move |_: DialRequest, done: DialCompletion| {
        send.send(done).unwrap();
    }));
    let client = NaiveClient::new(options).await.unwrap();
    let connection = tokio::spawn({
        let client = client.clone();
        async move { client.connect("remote.invalid", 443).await }
    });
    let completion = recv.recv().await.unwrap();
    let token = completion.cancellation();
    client.shutdown().await.unwrap();
    assert!(connection.await.unwrap().is_err());
    cancelled(&token).await;
    drop(client);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let outbound = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut inbound, _) = listener.accept().await.unwrap();
    completion.complete(Ok(outbound));
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), inbound.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn dropping_or_panicking_a_hook_fails_without_hanging() {
    for panic in [false, true] {
        let mut options = config(443);
        options.network.resolver =
            Some(Arc::new(move |_: ResolveRequest, _: ResolveCompletion| {
                assert!(!panic, "intentional host callback panic");
            }));
        let client = NaiveClient::new(options).await.unwrap();
        assert_eq!(
            client
                .connect("remote.invalid", 443)
                .await
                .unwrap_err()
                .code(),
            Some(-130)
        );
        client.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn reset_cancels_old_streams_and_preserves_client_hooks() {
    let (port, server) = fixture().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let mut options = config(port);
    options.network.resolver = Some(Arc::new(
        move |_: ResolveRequest, done: ResolveCompletion| {
            seen.fetch_add(1, Ordering::Relaxed);
            done.complete(Ok(vec!["127.0.0.1".parse().unwrap()]));
        },
    ));
    let client = NaiveClient::new(options).await.unwrap();
    let clone = client.clone();
    let mut old = client.connect("remote.invalid", 443).await.unwrap();
    clone.close_all_connections().await.unwrap();
    assert!(old.write(b"old").await.is_err());
    round_trip(&client).await;
    assert!(calls.load(Ordering::Relaxed) >= 2);
    let (a, b) = tokio::join!(
        client.close_all_connections(),
        clone.close_all_connections()
    );
    a.unwrap();
    b.unwrap();
    round_trip(&clone).await;
    client.shutdown().await.unwrap();
    assert!(clone.close_all_connections().await.is_err());
    server.abort();
}

#[tokio::test]
async fn canceling_last_preamble_waiter_cancels_host_resolution() {
    for scheme in ["https", "quic"] {
        let (send, mut recv) = mpsc::unbounded_channel();
        let mut options = config(443);
        options.proxy = format!("{scheme}://proxy.invalid:443");
        options.network.resolver = Some(Arc::new(
            move |_: ResolveRequest, done: ResolveCompletion| {
                send.send(done).unwrap();
            },
        ));
        let client = NaiveClient::new(options).await.unwrap();
        let connect = tokio::spawn({
            let client = client.clone();
            async move { client.connect("remote.invalid", 443).await }
        });
        let completion = recv.recv().await.unwrap();
        let token = completion.cancellation();
        connect.abort();
        assert!(connect.await.unwrap_err().is_cancelled());
        cancelled(&token).await;
        completion.complete(Ok(vec!["127.0.0.1".parse().unwrap()]));
        client.shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reset_connect_and_shutdown_races_finish() {
    let (port, server) = fixture().await;
    for _ in 0..8 {
        let mut options = config(port);
        options.host_resolver_rules = Some("MAP proxy.invalid 127.0.0.1".into());
        options.io_workers = 4;
        let client = NaiveClient::new(options).await.unwrap();
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let client = client.clone();
            tasks.spawn(async move {
                let _ = client.connect("remote.invalid", 443).await;
                let _ = client.close_all_connections().await;
            });
        }
        client.shutdown().await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while let Some(result) = tasks.join_next().await {
                result.unwrap();
            }
        })
        .await
        .unwrap();
    }
    server.abort();
}

#[tokio::test]
async fn mapping_precedes_custom_dns_and_addresses_fall_back() {
    let (port, server) = fixture().await;
    let mut options = config(port);
    options.host_resolver_rules = Some("MAP proxy.invalid mapped.invalid".into());
    options.network.resolver = Some(Arc::new(
        |request: ResolveRequest, done: ResolveCompletion| {
            assert_eq!(request.hostname, "mapped.invalid");
            done.complete(Ok(vec![
                "::1".parse().unwrap(),
                "127.0.0.1".parse().unwrap(),
            ]));
        },
    ));
    let client = NaiveClient::new(options).await.unwrap();
    round_trip(&client).await;
    client.shutdown().await.unwrap();
    server.abort();
}

#[tokio::test]
async fn held_host_completion_does_not_keep_client_hooks_alive() {
    let (send, mut recv) = mpsc::unbounded_channel();
    let sentinel = Arc::new(());
    let weak = Arc::downgrade(&sentinel);
    let mut options = config(443);
    options.network.resolver = Some(Arc::new(
        move |_: ResolveRequest, done: ResolveCompletion| {
            let _hold = sentinel.clone();
            send.send(done).unwrap();
        },
    ));
    let client = NaiveClient::new(options).await.unwrap();
    let task = tokio::spawn({
        let client = client.clone();
        async move { client.connect("remote.invalid", 443).await }
    });
    let done = recv.recv().await.unwrap();
    client.shutdown().await.unwrap();
    assert!(task.await.unwrap().is_err());
    assert!(
        weak.upgrade().is_none(),
        "host completion retained client hook context"
    );
    assert!(done.cancellation().is_cancelled());
    drop(done);
}

#[tokio::test]
async fn reset_cancels_pending_udp_dial_and_closes_late_socket() {
    let (send, mut recv) = mpsc::unbounded_channel();
    let sentinel = Arc::new(());
    let weak = Arc::downgrade(&sentinel);
    let mut options = config(443);
    options.proxy = "quic://proxy.invalid:443".into();
    options.host_resolver_rules = Some("MAP proxy.invalid 127.0.0.1".into());
    options.network.udp_dialer = Some(Arc::new(move |_: UdpDialRequest, done: UdpCompletion| {
        let _hold = sentinel.clone();
        send.send(done).unwrap();
    }));
    let client = NaiveClient::new(options).await.unwrap();
    let task = tokio::spawn({
        let client = client.clone();
        async move { client.connect("remote.invalid", 443).await }
    });
    let done = recv.recv().await.unwrap();
    let token = done.cancellation();
    client.close_all_connections().await.unwrap();
    assert!(task.await.unwrap().is_err());
    cancelled(&token).await;
    client.shutdown().await.unwrap();
    assert!(
        weak.upgrade().is_none(),
        "pending UDP callback retained its client"
    );
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    done.complete(Ok(socket));
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if std::net::UdpSocket::bind(address).is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("late UDP socket was not closed");
}

#[cfg(unix)]
fn check_unconnected_socket(socket: &Socket<'_>) {
    use std::os::fd::{AsFd, AsRawFd};
    let fd = socket.as_fd().as_raw_fd();
    let mut peer: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of_val(&peer) as libc::socklen_t;
    assert_eq!(
        unsafe {
            libc::getpeername(
                fd,
                (&mut peer as *mut libc::sockaddr_storage).cast(),
                &mut len,
            )
        },
        -1
    );
    let size: libc::c_int = 64 * 1024;
    assert_eq!(
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&size as *const libc::c_int).cast(),
                std::mem::size_of_val(&size) as _,
            )
        },
        0
    );
}
#[cfg(windows)]
fn check_unconnected_socket(socket: &Socket<'_>) {
    use std::os::windows::io::{AsRawSocket, AsSocket};
    use windows_sys::Win32::Networking::WinSock::*;
    let handle = socket.as_socket().as_raw_socket() as SOCKET;
    let mut peer: SOCKADDR_STORAGE = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of_val(&peer) as i32;
    assert_eq!(
        unsafe {
            getpeername(
                handle,
                (&mut peer as *mut SOCKADDR_STORAGE).cast(),
                &mut len,
            )
        },
        SOCKET_ERROR
    );
    let size: i32 = 64 * 1024;
    assert_eq!(
        unsafe {
            setsockopt(
                handle,
                SOL_SOCKET,
                SO_RCVBUF,
                (&size as *const i32).cast(),
                std::mem::size_of_val(&size) as i32,
            )
        },
        0
    );
}
