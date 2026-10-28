#![cfg(feature = "tokio")]
//! Run with tests/browser.py. Every origin and certificate is local to that run.
use naive::{
    Error,
    browser::{
        BrowserClient, BrowserConfig, HttpRequest, Message, RedirectPolicy, WebSocketRequest,
    },
};
use std::{
    env,
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[path = "../../../tests/support/io_fixture.rs"]
mod fixture;

fn port(name: &str) -> u16 {
    env::var(name)
        .expect("run tests/browser.py")
        .parse()
        .unwrap()
}
fn config() -> BrowserConfig {
    BrowserConfig {
        extra_root_certificates: Some(env::var("BROWSER_CA").expect("run tests/browser.py")),
        host_resolver_rules: Some("MAP localhost 127.0.0.1, MAP wrong.invalid 127.0.0.1".into()),
        ..BrowserConfig::default()
    }
}
fn bases() -> [String; 3] {
    [
        format!("http://localhost:{}", port("BROWSER_HTTP_PORT")),
        format!("https://localhost:{}", port("BROWSER_H1_PORT")),
        format!("https://localhost:{}", port("BROWSER_HTTPS_PORT")),
    ]
}
async fn bounded(f: impl Future<Output = ()>) {
    tokio::time::timeout(Duration::from_secs(30), f)
        .await
        .unwrap();
}
async fn idle(client: &BrowserClient) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while client.stats().await.unwrap().active_streams != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires loopback browser fixture"]
async fn direct_tls_uses_native_validation_and_owned_io() {
    bounded(async {
        let client = BrowserClient::new(config()).await.unwrap();
        let mut stream = client
            .connect_tls("localhost", port("BROWSER_TLS_PORT"))
            .await
            .unwrap();
        let info = stream.info().await.unwrap();
        assert_eq!(info.tls_version, Some(0x0304));
        assert_eq!(info.protocol.as_deref(), Some("http/1.1"));
        let data = b"native TLS bytes without CONNECT or padding".to_vec();
        let expected_length = data.len();
        let pointer = data.as_ptr();
        let sent = stream.write_owned(data).await;
        assert_eq!(sent.result.unwrap(), expected_length);
        assert_eq!(sent.buffer.as_ptr(), pointer);
        let mut reply = Vec::new();
        while reply.len() < expected_length {
            let result = stream.read_owned(Vec::with_capacity(4096)).await;
            assert!(result.result.unwrap() > 0);
            reply.extend_from_slice(&result.buffer);
        }
        assert_eq!(reply, sent.buffer);
        assert!(
            client
                .connect_tls("wrong.invalid", port("BROWSER_TLS_PORT"))
                .await
                .is_err()
        );
        let mut untrusted = config();
        untrusted.extra_root_certificates = None;
        let bad = BrowserClient::new(untrusted).await.unwrap();
        assert!(
            bad.connect_tls("localhost", port("BROWSER_TLS_PORT"))
                .await
                .is_err()
        );
        bad.shutdown().await.unwrap();
        stream.close();
        client.shutdown().await.unwrap();
    })
    .await;
}

#[tokio::test]
#[ignore = "requires loopback browser fixture"]
async fn native_http_streams_uploads_redirects_cookies_and_compression() {
    bounded(async {
        let client = BrowserClient::new(config()).await.unwrap();
        for (i, base) in bases().into_iter().enumerate() {
            let upload: Vec<u8> = (0..131_077).map(|n| (n % 251) as u8).collect();
            let response = client
                .execute(
                    HttpRequest::post(format!("{base}/echo"), upload.clone())
                        .header("x-fixture", "native"),
                )
                .await
                .unwrap();
            assert_eq!(response.status, 200);
            assert_eq!(response.header("x-method"), Some("POST"));
            assert_eq!(
                response.header("x-protocol"),
                Some(if i == 2 { "HTTP/2.0" } else { "HTTP/1.1" })
            );
            assert_eq!(response.bytes(200_000).await.unwrap(), upload);
            let response = client.get(format!("{base}/redirect")).await.unwrap();
            assert_eq!(response.status, 200);
            assert!(response.url.ends_with("/profile"));
            assert_eq!(response.redirects, 1);
            let profile: serde_json::Value =
                serde_json::from_slice(&response.bytes(65536).await.unwrap()).unwrap();
            assert_eq!(
                profile["headers"]["User-Agent"][0],
                client.profile().user_agent
            );
            let mut request = HttpRequest::get(format!("{base}/redirect"));
            request.redirects = RedirectPolicy::Manual;
            let response = client.execute(request).await.unwrap();
            assert_eq!(response.status, 302);
            assert!(response.bytes(1024).await.unwrap().is_empty());
            let mut request = HttpRequest::get(format!("{base}/redirect-loop"));
            request.redirects = RedirectPolicy::Follow(2);
            assert!(client.execute(request).await.is_err());
            client
                .get(format!("{base}/cookie/set"))
                .await
                .unwrap()
                .bytes(1024)
                .await
                .unwrap();
            assert!(
                String::from_utf8(
                    client
                        .get(format!("{base}/cookie/get"))
                        .await
                        .unwrap()
                        .bytes(1024)
                        .await
                        .unwrap()
                )
                .unwrap()
                .contains("fixture=ok")
            );
            let isolated = BrowserClient::new(config()).await.unwrap();
            assert!(
                isolated
                    .get(format!("{base}/cookie/get"))
                    .await
                    .unwrap()
                    .bytes(1024)
                    .await
                    .unwrap()
                    .is_empty()
            );
            isolated.shutdown().await.unwrap();
            assert_eq!(
                client
                    .get(format!("{base}/gzip"))
                    .await
                    .unwrap()
                    .bytes(1024)
                    .await
                    .unwrap(),
                b"native decompression"
            );
            let response = client.get(format!("{base}/stream")).await.unwrap();
            let data = response.bytes(600_000).await.unwrap();
            assert_eq!(data.len(), 524_288);
            assert!(data.iter().enumerate().all(|(i, b)| *b == (i % 251) as u8));
            assert!(
                client
                    .get(format!("{base}/stream"))
                    .await
                    .unwrap()
                    .bytes(1000)
                    .await
                    .is_err()
            );
        }
        idle(&client).await;
        client.shutdown().await.unwrap();
    })
    .await;
}

#[tokio::test]
#[ignore = "requires loopback browser fixture"]
async fn http_cancel_timeout_and_retained_body_leases() {
    bounded(async {
        let client = BrowserClient::new(config()).await.unwrap();
        let base = bases()[2].clone();
        let mut pending = Box::pin(client.get(format!("{base}/wait")));
        assert!(futures_util::poll!(&mut pending).is_pending());
        assert_eq!(client.stats().await.unwrap().active_streams, 1);
        drop(pending);
        idle(&client).await;
        let mut options = config();
        options.connect_timeout = Duration::from_millis(50);
        let timed = BrowserClient::new(options).await.unwrap();
        let error = match timed.get(format!("{base}/wait")).await {
            Err(e) => e,
            Ok(_) => panic!("request did not time out"),
        };
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        timed.shutdown().await.unwrap();
        let mut response = client.get(format!("{base}/stream")).await.unwrap();
        let buffer = Vec::with_capacity(4096);
        let pointer = buffer.as_ptr();
        let first = response.body.read_owned(buffer).await;
        assert!(first.result.unwrap() > 0);
        assert_eq!(first.buffer.as_ptr(), pointer);
        assert!(
            first
                .buffer
                .iter()
                .enumerate()
                .all(|(i, b)| *b == (i % 251) as u8)
        );
        let chunk = response.body.read_chunk().await.unwrap().unwrap();
        let bytes = chunk.as_ref().to_vec();
        client.shutdown().await.unwrap();
        assert_eq!(chunk.as_ref(), bytes);
        assert!(response.body.read_chunk().await.is_err());
    })
    .await;
}

#[tokio::test]
#[ignore = "requires loopback browser fixture"]
async fn websocket_native_frames_split_ping_close_and_validation() {
    bounded(async {
        for base in [
            format!("ws://localhost:{}", port("BROWSER_HTTP_PORT")),
            format!("wss://localhost:{}", port("BROWSER_H1_PORT")),
        ] {
            let client = BrowserClient::new(config()).await.unwrap();
            let mut request =
                WebSocketRequest::new(format!("{base}/ws-fragment"), "https://localhost");
            request.protocols.push("echo".into());
            let socket = client.connect_websocket(request).await.unwrap();
            assert_eq!(socket.handshake().status, 101);
            assert_eq!(socket.handshake().subprotocol, "echo");
            let (mut reader, mut writer) = socket.into_split();
            let sending = async {
                for i in 0..8 {
                    writer
                        .send(Message::Text(format!("message {i} 漢字 🧭")))
                        .await
                        .unwrap();
                }
            };
            let reading = async {
                for i in 0..8 {
                    assert_eq!(
                        reader.recv().await.unwrap(),
                        Some(Message::Text(format!("message {i} 漢字 🧭")))
                    );
                }
            };
            tokio::join!(sending, reading);
            let bytes = vec![77; 100_003];
            writer.send(Message::Binary(bytes.clone())).await.unwrap();
            assert_eq!(reader.recv().await.unwrap(), Some(Message::Binary(bytes)));
            writer.send(Message::Text(String::new())).await.unwrap();
            assert_eq!(
                reader.recv().await.unwrap(),
                Some(Message::Text(String::new()))
            );
            assert!(writer.close(1005, "").await.is_err());
            let close = writer.close(1000, "complete\0native").await.unwrap();
            assert!(close.clean);
            assert_eq!(close.code, 1000);
            assert_eq!(close.reason, "complete\0native");
            assert!(reader.recv().await.unwrap().is_none());
            idle(&client).await;
            client.shutdown().await.unwrap();
        }
    })
    .await;
}

#[tokio::test]
#[ignore = "requires loopback browser fixture"]
async fn websocket_receive_cancel_and_protocol_error_are_bounded() {
    bounded(async {
        let mut options = config();
        options.max_websocket_message = 1024;
        let client = BrowserClient::new(options).await.unwrap();
        let base = format!("ws://localhost:{}", port("BROWSER_HTTP_PORT"));
        let socket = client
            .connect_websocket(WebSocketRequest::new(
                format!("{base}/ws"),
                "https://localhost",
            ))
            .await
            .unwrap();
        let (mut reader, mut writer) = socket.into_split();
        let mut read = Box::pin(reader.recv());
        assert!(futures_util::poll!(&mut read).is_pending());
        drop(read);
        assert!(writer.send(Message::Binary(vec![1; 1025])).await.is_err());
        writer
            .send(Message::Text("after cancelled receive".into()))
            .await
            .unwrap();
        assert_eq!(
            reader.recv().await.unwrap(),
            Some(Message::Text("after cancelled receive".into()))
        );
        writer.close(1000, "").await.unwrap();
        let mut bad = client
            .connect_websocket(WebSocketRequest::new(
                format!("{base}/ws-invalid"),
                "https://localhost",
            ))
            .await
            .unwrap();
        assert!(bad.recv().await.is_err());
        drop(bad);
        let mut big = client
            .connect_websocket(WebSocketRequest::new(
                format!("{base}/ws-big"),
                "https://localhost",
            ))
            .await
            .unwrap();
        assert!(big.recv().await.is_err());
        drop(big);
        let mut abrupt = client
            .connect_websocket(WebSocketRequest::new(
                format!("{base}/ws-abrupt"),
                "https://localhost",
            ))
            .await
            .unwrap();
        assert!(abrupt.recv().await.is_err());
        assert!(!abrupt.close_frame().unwrap().clean);
        client.shutdown().await.unwrap();
    })
    .await;
}

#[tokio::test]
#[ignore = "requires loopback browser fixture"]
async fn direct_clients_and_naive_tunnels_share_runtime_without_sharing_policy() {
    bounded(async {
        let count = Arc::new(AtomicUsize::new(0));
        let observed = count.clone();
        let mut options = config();
        options.network.socket_control = Some(Arc::new(move |_: naive::network::Socket<'_>, _| {
            observed.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }));
        let browser = BrowserClient::new(options).await.unwrap();
        let base = bases()[0].clone();
        browser
            .get(format!("{base}/profile"))
            .await
            .unwrap()
            .bytes(65536)
            .await
            .unwrap();
        let proxy = fixture::Server::echo();
        let naive = naive::NaiveClient::new(fixture::proxy_config(proxy.port))
            .await
            .unwrap();
        let mut stream = naive.connect("remote.invalid", 443).await.unwrap();
        stream.write_all(b"naive retained").await.unwrap();
        stream.flush().await.unwrap();
        let mut bytes = [0; 14];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"naive retained");
        browser
            .get(format!("{base}/profile"))
            .await
            .unwrap()
            .bytes(65536)
            .await
            .unwrap();
        assert!(count.load(Ordering::Relaxed) > 0);
        naive.shutdown().await.unwrap();
        browser.shutdown().await.unwrap();
        proxy.finish();
    })
    .await;
}

#[test]
fn browser_handles_can_cross_executor_threads() {
    fn assert_send<T: Send + Sync>() {}
    assert_send::<BrowserClient>();
    fn assert_error(_: Error) {}
    let _ = assert_error;
}

#[tokio::test]
#[ignore = "requires loopback browser fixture"]
async fn navigation_headers_and_http3_are_native() {
    bounded(async {
        for base in [bases()[1].clone(), bases()[2].clone()] {
            let client = BrowserClient::new(config()).await.unwrap();
            let response = client.navigate(format!("{base}/profile")).await.unwrap();
            let value: serde_json::Value =
                serde_json::from_slice(&response.bytes(65536).await.unwrap()).unwrap();
            assert_eq!(value["headers"]["Sec-Fetch-Dest"][0], "document");
            assert_eq!(value["headers"]["Sec-Fetch-Mode"][0], "navigate");
            assert!(
                value["headers"]["Sec-Ch-Ua"][0]
                    .as_str()
                    .unwrap()
                    .contains("Chromium")
            );
            client.shutdown().await.unwrap();
        }
        let mut options = config();
        options.force_http3_origins.push(bases()[2].clone());
        let client = BrowserClient::new(options.clone()).await.unwrap();
        let response = client.get(format!("{}/profile", bases()[2])).await.unwrap();
        assert_eq!(response.header("x-protocol"), Some("HTTP/3.0"));
        assert_eq!(response.tls_version, Some(0x0304));
        assert_eq!(response.protocol, "h3");
        response.bytes(65536).await.unwrap();
        client.shutdown().await.unwrap();
        options.extra_root_certificates = None;
        let untrusted = BrowserClient::new(options).await.unwrap();
        assert!(
            untrusted
                .get(format!("{}/profile", bases()[2]))
                .await
                .is_err()
        );
        untrusted.shutdown().await.unwrap();
    })
    .await;
}

#[tokio::test]
#[ignore = "requires loopback browser fixture"]
async fn websocket_cancelled_handshake_send_and_close_have_distinct_lifetimes() {
    bounded(async {
        let client = BrowserClient::new(config()).await.unwrap();
        let base = format!("ws://localhost:{}", port("BROWSER_HTTP_PORT"));
        let mut pending = Box::pin(client.connect_websocket(WebSocketRequest::new(
            format!("{base}/ws-wait"),
            "https://localhost",
        )));
        assert!(futures_util::poll!(&mut pending).is_pending());
        client.stats().await.unwrap();
        drop(pending);
        idle(&client).await;
        let mut socket = client
            .connect_websocket(WebSocketRequest::new(
                format!("{base}/ws"),
                "https://localhost",
            ))
            .await
            .unwrap();
        let mut send = Box::pin(socket.send(Message::Binary(vec![3; 65536])));
        assert!(futures_util::poll!(&mut send).is_pending());
        client.stats().await.unwrap();
        drop(send);
        idle(&client).await;
        assert!(socket.recv().await.is_err());
        let mut socket = client
            .connect_websocket(WebSocketRequest::new(
                format!("{base}/ws"),
                "https://localhost",
            ))
            .await
            .unwrap();
        let mut close = Box::pin(socket.close(1000, "cancelled wait"));
        assert!(futures_util::poll!(&mut close).is_pending());
        client.stats().await.unwrap();
        drop(close);
        assert!(socket.close(1000, "cancelled wait").await.unwrap().clean);
        client.shutdown().await.unwrap();
    })
    .await;
}

#[test]
#[ignore = "requires loopback browser fixture"]
fn direct_http_does_not_require_a_tokio_reactor() {
    futures_executor::block_on(async {
        let client = BrowserClient::new(config()).await.unwrap();
        let response = client.get(format!("{}/profile", bases()[2])).await.unwrap();
        assert_eq!(response.status, 200);
        assert!(!response.bytes(65536).await.unwrap().is_empty());
        client.shutdown().await.unwrap();
    });
}

#[tokio::test]
#[ignore = "requires loopback browser fixture"]
async fn cached_http_body_releases_owned_buffers_on_every_synchronous_read() {
    bounded(async {
        let client = BrowserClient::new(config()).await.unwrap();
        let mut response_id = None;
        for _ in 0..2 {
            let mut response = client.get(format!("{}/cached", bases()[2])).await.unwrap();
            let id = response.header("x-fixture-response").unwrap().to_owned();
            if let Some(first) = &response_id {
                assert_eq!(first, &id);
            }
            response_id = Some(id);
            let mut body = Vec::new();
            loop {
                let released = fixture::Releases::default();
                let buffer = Vec::with_capacity(127);
                let pointer = buffer.as_ptr();
                let result = response
                    .body
                    .read_owned(naive::owned::Guarded::new(buffer, released.guard()))
                    .await;
                let n = result.result.unwrap();
                assert_eq!(result.buffer.buffer.as_ptr(), pointer);
                assert_eq!(released.count(), 0);
                body.extend_from_slice(&result.buffer.buffer);
                drop(result.buffer);
                released.wait_for(1);
                if n == 0 {
                    break;
                }
            }
            assert_eq!(body, b"cache".repeat(1024));
        }
        client.shutdown().await.unwrap();
    })
    .await;
}

#[tokio::test]
#[ignore = "requires loopback browser fixture"]
async fn cross_origin_redirect_does_not_forward_explicit_credentials() {
    bounded(async {
        let client = BrowserClient::new(config()).await.unwrap();
        let same = client
            .execute(
                HttpRequest::get(format!("{}/redirect", bases()[2]))
                    .header("Authorization", "Bearer fixture-secret"),
            )
            .await
            .unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(&same.bytes(65536).await.unwrap()).unwrap();
        assert_eq!(
            value["headers"]["Authorization"][0],
            "Bearer fixture-secret"
        );
        let response = client
            .execute(
                HttpRequest::get(format!("{}/redirect-cross", bases()[2]))
                    .header("Authorization", "Bearer fixture-secret")
                    .header("Cookie", "private=fixture-secret"),
            )
            .await
            .unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(&response.bytes(65536).await.unwrap()).unwrap();
        assert!(
            value["headers"].get("Authorization").is_none(),
            "credentials crossed origins"
        );
        assert!(
            value["headers"].get("Cookie").is_none(),
            "explicit cookie crossed origins"
        );
        client.shutdown().await.unwrap();
    })
    .await;
}

#[tokio::test]
#[ignore = "requires loopback browser fixture"]
async fn websocket_tls_rejects_unknown_roots_and_wrong_hostnames() {
    bounded(async {
        let mut options = config();
        options.extra_root_certificates = None;
        let untrusted = BrowserClient::new(options).await.unwrap();
        let url = format!("wss://localhost:{}/ws", port("BROWSER_H1_PORT"));
        assert!(
            untrusted
                .connect_websocket(WebSocketRequest::new(url, "https://localhost"))
                .await
                .is_err()
        );
        untrusted.shutdown().await.unwrap();
        let client = BrowserClient::new(config()).await.unwrap();
        let url = format!("wss://wrong.invalid:{}/ws", port("BROWSER_H1_PORT"));
        assert!(
            client
                .connect_websocket(WebSocketRequest::new(url, "https://localhost"))
                .await
                .is_err()
        );
        client.shutdown().await.unwrap();
    })
    .await;
}
