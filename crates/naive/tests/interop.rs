#![cfg(feature = "tokio")]
//! Run with `python3 tests/interop.py` (starts an isolated Caddy + local origin).
use naive::{Config, NaiveClient};
use std::{env, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
