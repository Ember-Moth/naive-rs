#![cfg(feature = "tokio")]
//! Run with `python3 tests/interop.py` (starts an isolated Caddy + local origin).
use naive::{Config, NaiveClient};
use std::{env, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[path = "../../../tests/support/io_fixture.rs"]
mod fixture;

fn config(scheme: &str, trusted: bool, password: &str) -> Config {
    let port = env::var("NAIVE_TEST_PROXY_PORT").expect("run tests/interop.py");
    let mut config = Config::new(format!("{scheme}://test:{password}@localhost:{port}"));
    config.host_resolver_rules = Some(format!(
        "MAP localhost {}",
        env::var("NAIVE_TEST_PROXY_IP").unwrap_or_else(|_| "127.0.0.1".into())
    ));
    if trusted {
        config.extra_root_certificates = Some(env::var("NAIVE_TEST_CA_PEM").unwrap());
    }
    config.connect_timeout = Duration::from_secs(8);
    config.io_workers = 4;
    config
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the local Caddy fixture; run python3 tests/interop.py"]
async fn caddy_https_and_quic() {
    let origin: u16 = env::var("NAIVE_TEST_ORIGIN_PORT").unwrap().parse().unwrap();
    for scheme in ["https", "quic"] {
        let client = NaiveClient::new(config(scheme, true, "test"))
            .await
            .unwrap();
        for index in 0..12 {
            let mut stream = client.connect("127.0.0.1", origin).await.unwrap();
            let info = stream.info().await.unwrap();
            assert_eq!(
                info.protocol.as_deref(),
                Some(if scheme == "https" { "h2" } else { "h3" })
            );
            assert_eq!(info.tls_version, Some(0x0304));
            let bytes: Vec<u8> = (0..131_071).map(|n| ((n + index) % 251) as u8).collect();
            let (mut read, mut write) = tokio::io::split(&mut stream);
            tokio::time::timeout(Duration::from_secs(10), async {
                let send = async {
                    write.write_all(&bytes).await.unwrap();
                    write.flush().await.unwrap();
                };
                let recv = async {
                    let mut response = vec![0; bytes.len()];
                    read.read_exact(&mut response).await.unwrap();
                    assert_eq!(response, bytes);
                };
                tokio::join!(send, recv);
            })
            .await
            .unwrap();
        }
        eprintln!("{scheme}: trusted certificate and 12 padded data streams passed");
        // The shared cache is only the immutable compiled root set. An unrelated
        // user CA in another client must not inherit this client's trust.
        let trace = std::path::PathBuf::from(env::var("NAIVE_TEST_TRACE_DIR").unwrap())
            .join(format!("{scheme}-isolated-ca.ndjson"));
        let mut isolated = config(scheme, true, "test");
        isolated.extra_root_certificates = Some(env::var("NAIVE_TEST_UNRELATED_CA").unwrap());
        isolated.net_log = Some(trace.clone());
        let other = NaiveClient::new(isolated).await.unwrap();
        assert!(other.connect("127.0.0.1", origin).await.is_err());
        other.shutdown().await.unwrap();
        assert!(
            std::fs::read_to_string(trace)
                .unwrap()
                .lines()
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .any(|value| net_error(&value, -202)),
            "per-client CA trust leaked"
        );
        let mut still_trusted = client.connect("127.0.0.1", origin).await.unwrap();
        still_trusted.write_all(b"isolated").await.unwrap();
        let mut received = [0; 8];
        still_trusted.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"isolated");
        drop(still_trusted);
        client.shutdown().await.unwrap();
        eprintln!("{scheme}: per-client CA isolation passed");
        // QUIC can surface a generic protocol error. Require the underlying
        // verifier's ERR_CERT_AUTHORITY_INVALID in the flushed native trace.
        let trace = std::path::PathBuf::from(env::var("NAIVE_TEST_TRACE_DIR").unwrap())
            .join(format!("{scheme}-untrusted.ndjson"));
        let mut untrusted = config(scheme, false, "test");
        untrusted.net_log = Some(trace.clone());
        let client = NaiveClient::new(untrusted).await.unwrap();
        let error = client.connect("127.0.0.1", origin).await.unwrap_err();
        client.shutdown().await.unwrap();
        let trace = std::fs::read_to_string(trace).unwrap();
        assert!(
            trace
                .lines()
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .any(|value| net_error(&value, -202)),
            "{scheme}: verifier did not report ERR_CERT_AUTHORITY_INVALID; got {error:?}"
        );
        eprintln!("{scheme}: untrusted CA rejected by verifier ({error})");

        let trace = std::path::PathBuf::from(env::var("NAIVE_TEST_TRACE_DIR").unwrap())
            .join(format!("{scheme}-hostname.ndjson"));
        let mut wrong_host = config(scheme, true, "test");
        wrong_host.proxy = wrong_host.proxy.replace("@localhost:", "@wrong.invalid:");
        wrong_host.host_resolver_rules = Some(format!(
            "MAP wrong.invalid {}",
            env::var("NAIVE_TEST_PROXY_IP").unwrap_or_else(|_| "127.0.0.1".into())
        ));
        wrong_host.net_log = Some(trace.clone());
        let client = NaiveClient::new(wrong_host).await.unwrap();
        let error = client.connect("127.0.0.1", origin).await.unwrap_err();
        client.shutdown().await.unwrap();
        assert!(
            std::fs::read_to_string(trace)
                .unwrap()
                .lines()
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .any(|value| net_error(&value, -200)),
            "{scheme}: trusted CA must not bypass hostname verification: {error:?}"
        );
        eprintln!("{scheme}: certificate hostname mismatch rejected");

        let client = NaiveClient::new(config(scheme, true, "wrong"))
            .await
            .unwrap();
        let error = client.connect("127.0.0.1", origin).await.unwrap_err();
        assert!(
            matches!(error.code(), Some(-115) | Some(-127)),
            "expected native authentication rejection, got {error:?}"
        );
        client.shutdown().await.unwrap();
        eprintln!("{scheme}: incorrect password rejected ({error})");
    }
}

fn net_error(value: &serde_json::Value, code: i64) -> bool {
    match value {
        serde_json::Value::Object(map) => {
            map.get("net_error").and_then(serde_json::Value::as_i64) == Some(code)
                || map.values().any(|value| net_error(value, code))
        }
        serde_json::Value::Array(values) => values.iter().any(|value| net_error(value, code)),
        _ => false,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the local Caddy fixture; compile-only gates do not run it"]
async fn owned_io_keeps_read_direction_open_after_local_fin() {
    use tokio::net::TcpListener;
    for scheme in ["https", "quic"] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let origin = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            socket.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, b"request before FIN");
            socket.write_all(b"response after FIN").await.unwrap();
            socket.shutdown().await.unwrap();
        });
        let client = NaiveClient::new(config(scheme, true, "test"))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut stream = client.connect("127.0.0.1", port).await.unwrap();
            assert!(stream.info().await.unwrap().write_shutdown_supported);
            let sent = stream.write_owned(b"request before FIN".to_vec()).await;
            assert_eq!(sent.result.unwrap(), 18);
            stream.shutdown_write().await.unwrap();
            let mut response = Vec::new();
            while let Some(chunk) = stream.read_chunk().await.unwrap() {
                response.extend_from_slice(chunk.as_ref());
            }
            assert_eq!(response, b"response after FIN");
            assert_eq!(
                stream.write_owned(vec![1]).await.result.unwrap_err().kind(),
                std::io::ErrorKind::BrokenPipe
            );
            origin.await.unwrap();
        })
        .await
        .unwrap();
        client.shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the local Caddy fixture; run python3 tests/interop.py --owned-io"]
async fn half_close_drains_mixed_writes_and_preserves_split_owned_reads() {
    use std::{
        future::poll_fn,
        io::{IoSlice, Read, Write},
    };
    for scheme in ["https", "quic"] {
        for size in [0, 1, 65_537, 196_613] {
            let request: Vec<u8> = (0..size).map(|n| (n % 251) as u8).collect();
            let expected_request = request.clone();
            let mut expected_response = request.clone();
            expected_response.reverse();
            expected_response.extend_from_slice(b"after FIN");
            let reply = expected_response.clone();
            let origin = fixture::Server::origin(move |socket| {
                let mut bytes = Vec::new();
                socket.read_to_end(&mut bytes).unwrap();
                assert_eq!(bytes, expected_request);
                socket.write_all(&reply).unwrap();
            });
            let client = NaiveClient::new(config(scheme, true, "test"))
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(10), async {
                let stream = client.connect("127.0.0.1", origin.port).await.unwrap();
                let info = stream.info().await.unwrap();
                assert_eq!(
                    info.protocol.as_deref(),
                    Some(if scheme == "https" { "h2" } else { "h3" })
                );
                assert!(info.write_shutdown_supported);
                let (mut reader, mut writer) = stream.into_split();
                let send = async {
                    let first = request.len().min(7);
                    let mut offset = if first > 0 {
                        poll_fn(|cx| {
                            writer.poll_write_slices(cx, &[IoSlice::new(&request[..first])])
                        })
                        .await
                        .unwrap()
                    } else {
                        0
                    };
                    while offset < request.len() {
                        let result = writer.write_owned(request[offset..].to_vec()).await;
                        let n = result.result.unwrap();
                        assert!(n > 0 && n <= 65536);
                        assert_eq!(result.transferred, n);
                        offset += n;
                    }
                    writer.shutdown_write().await.unwrap();
                    writer.shutdown_write().await.unwrap();
                    assert_eq!(
                        writer.write_owned(vec![1]).await.result.unwrap_err().kind(),
                        std::io::ErrorKind::BrokenPipe
                    );
                    assert_eq!(
                        poll_fn(|cx| writer.poll_write_slices(cx, &[IoSlice::new(b"x")]))
                            .await
                            .unwrap_err()
                            .kind(),
                        std::io::ErrorKind::BrokenPipe
                    );
                };
                let receive = async {
                    let mut bytes = Vec::new();
                    loop {
                        let result = reader.read_owned(Vec::with_capacity(8191)).await;
                        let n = result.result.unwrap();
                        assert_eq!(result.buffer.len(), n);
                        bytes.extend_from_slice(&result.buffer);
                        if n == 0 {
                            break;
                        }
                    }
                    assert_eq!(bytes, expected_response);
                };
                tokio::join!(send, receive);
                drop((reader, writer));
                assert_eq!(client.stats().await.unwrap().active_streams, 0);
            })
            .await
            .unwrap();
            client.shutdown().await.unwrap();
            origin.finish();
        }
        eprintln!(
            "{scheme}: empty/short/large FIN, split owned reads and mixed write ordering passed"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the local Caddy fixture; run python3 tests/interop.py --owned-io"]
async fn h2_h3_owned_read_cancel_deadline_and_shutdown_release_guards() {
    use std::{io::Read, time::Instant};
    for scheme in ["https", "quic"] {
        for mode in ["cancel", "deadline", "shutdown"] {
            let origin = fixture::Server::origin(|socket| {
                let mut byte = [0];
                assert_eq!(socket.read(&mut byte).unwrap(), 0);
            });
            let client = NaiveClient::new(config(scheme, true, "test"))
                .await
                .unwrap();
            let releases = fixture::Releases::default();
            tokio::time::timeout(Duration::from_secs(10), async {
                let mut stream = client.connect("127.0.0.1", origin.port).await.unwrap();
                if mode == "deadline" {
                    stream
                        .set_read_deadline(Some(Instant::now() + Duration::from_millis(50)))
                        .unwrap();
                }
                let data = Vec::<u8>::with_capacity(4096);
                let pointer = data.as_ptr();
                let mut operation =
                    Box::pin(stream.read_owned(naive::owned::Guarded::new(data, releases.guard())));
                assert!(futures_util::poll!(&mut operation).is_pending());
                client.stats().await.unwrap();
                assert_eq!(releases.count(), 0);
                if mode == "cancel" {
                    drop(operation);
                } else {
                    if mode == "shutdown" {
                        client.shutdown().await.unwrap();
                    }
                    let result = operation.await;
                    let error = result.result.unwrap_err();
                    if mode == "deadline" {
                        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
                    }
                    assert_eq!(result.transferred, 0);
                    assert_eq!(result.buffer.buffer.as_ptr(), pointer);
                    assert_eq!(releases.count(), 0);
                    drop(result.buffer);
                }
                assert_eq!(client.stats().await.unwrap().active_streams, 0);
                releases.wait_for(1);
                assert!(stream.write_owned(vec![1]).await.result.is_err());
                client.shutdown().await.unwrap();
                assert_eq!(releases.count(), 1);
            })
            .await
            .unwrap();
            origin.finish();
        }
        eprintln!("{scheme}: owned cancel/deadline/shutdown guards released exactly once");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the local Caddy fixture; run python3 tests/interop.py --owned-io"]
async fn canceling_a_shutdown_waiter_does_not_lose_fin_completion() {
    use std::io::{Read, Write};
    for scheme in ["https", "quic"] {
        let origin = fixture::Server::origin(|socket| {
            let mut request = Vec::new();
            socket.read_to_end(&mut request).unwrap();
            assert_eq!(request, b"done");
            socket.write_all(b"reply").unwrap();
        });
        let client = NaiveClient::new(config(scheme, true, "test"))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut stream = client.connect("127.0.0.1", origin.port).await.unwrap();
            stream.write_owned(b"done".to_vec()).await.result.unwrap();
            let mut shutdown = Box::pin(stream.shutdown_write());
            assert!(futures_util::poll!(&mut shutdown).is_pending());
            client.stats().await.unwrap();
            drop(shutdown);
            stream.shutdown_write().await.unwrap();
            let mut response = Vec::new();
            while let Some(chunk) = stream.read_chunk().await.unwrap() {
                response.extend_from_slice(chunk.as_ref());
            }
            assert_eq!(response, b"reply");
            client.shutdown().await.unwrap();
        })
        .await
        .unwrap();
        origin.finish();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the local Caddy fixture; run python3 tests/interop.py"]
async fn host_network_hooks_https_and_quic() {
    use naive::network::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let origin: u16 = env::var("NAIVE_TEST_ORIGIN_PORT").unwrap().parse().unwrap();
    for scheme in ["https", "quic"] {
        for custom_dial in [false, true] {
            let resolved = Arc::new(AtomicUsize::new(0));
            let controlled = Arc::new(AtomicUsize::new(0));
            let dialed = Arc::new(AtomicUsize::new(0));
            let mut options = config(scheme, true, "test");
            options.host_resolver_rules = None;
            let observed = resolved.clone();
            options.network.resolver = Some(Arc::new(
                move |request: ResolveRequest, done: ResolveCompletion| {
                    assert_eq!(request.hostname, "localhost");
                    observed.fetch_add(1, Ordering::Relaxed);
                    done.complete(Ok(vec![
                        env::var("NAIVE_TEST_PROXY_IP")
                            .unwrap_or_else(|_| "127.0.0.1".into())
                            .parse()
                            .unwrap(),
                    ]));
                },
            ));
            let observed = controlled.clone();
            options.network.socket_control = Some(Arc::new(move |_: Socket<'_>, _: SocketInfo| {
                observed.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }));
            if custom_dial {
                let observed = dialed.clone();
                if scheme == "https" {
                    options.network.tcp_dialer = Some(Arc::new(
                        move |request: DialRequest, done: DialCompletion| {
                            observed.fetch_add(1, Ordering::Relaxed);
                            std::thread::spawn(move || {
                                done.complete(std::net::TcpStream::connect(
                                    request.addresses.as_slice(),
                                ))
                            });
                        },
                    ));
                } else {
                    options.network.udp_dialer = Some(Arc::new(
                        move |request: UdpDialRequest, done: UdpCompletion| {
                            let attempt = observed.fetch_add(1, Ordering::Relaxed);
                            let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
                            // Cover adoption of both bound and already-connected UDP.
                            if attempt % 2 == 0 {
                                socket.connect(request.peer).unwrap();
                            }
                            done.complete(Ok(socket));
                        },
                    ));
                }
            }
            let client = NaiveClient::new(options).await.unwrap();
            for _ in 0..3 {
                let mut stream = client.connect("127.0.0.1", origin).await.unwrap();
                stream.write_all(b"host networking").await.unwrap();
                let mut bytes = [0; 15];
                stream.read_exact(&mut bytes).await.unwrap();
                assert_eq!(&bytes, b"host networking");
                client.close_all_connections().await.unwrap();
                assert!(stream.write(b"retired").await.is_err());
            }
            client.shutdown().await.unwrap();
            assert!(resolved.load(Ordering::Relaxed) >= 3);
            if custom_dial {
                assert!(dialed.load(Ordering::Relaxed) >= 3);
                assert_eq!(controlled.load(Ordering::Relaxed), 0);
            } else {
                assert!(controlled.load(Ordering::Relaxed) >= 3);
            }
            eprintln!(
                "{scheme}: custom resolver, {} and repeated connection reset passed",
                if custom_dial {
                    "host dialer"
                } else {
                    "socket control"
                }
            );
        }
        let mut denied = config(scheme, true, "test");
        let controlled = Arc::new(AtomicUsize::new(0));
        let count = controlled.clone();
        denied.network.socket_control = Some(Arc::new(move |_: Socket<'_>, _: SocketInfo| {
            count.fetch_add(1, Ordering::Relaxed);
            Err(std::io::ErrorKind::PermissionDenied.into())
        }));
        let client = NaiveClient::new(denied).await.unwrap();
        assert!(client.connect("127.0.0.1", origin).await.is_err());
        assert!(controlled.load(Ordering::Relaxed) > 0);
        client.shutdown().await.unwrap();
    }
}
