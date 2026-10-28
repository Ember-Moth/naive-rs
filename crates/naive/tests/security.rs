#![cfg(feature = "tokio")]
//! Real TLS/ECH handshakes against the loopback-only Go security fixture.
use naive::{
    CertificateDecision as Decision, CertificateInfo, CertificateVerification, Config, EchMode,
    EchOptions, Error, NaiveClient,
    browser::{BrowserClient, BrowserConfig, Message, WebSocketRequest},
    network::{ResolveCompletion, ResolveQuery, ResolveRequest},
};
use std::{
    env,
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SECRET: &str = "secret.ech.test";
const OTHER: &str = "other.ech.test";
struct DropWatch(Arc<AtomicUsize>);
impl Drop for DropWatch {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
fn port(name: &str) -> u16 {
    env::var(name)
        .expect("run tests/browser.py")
        .parse()
        .unwrap()
}
fn config_bytes(name: &str) -> Vec<u8> {
    let hex = env::var(name).expect("run tests/browser.py");
    hex.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn ca() -> String {
    env::var("BROWSER_CA").expect("run tests/browser.py")
}
fn rules() -> String {
    "MAP *.ech.test 127.0.0.1".into()
}
fn config() -> BrowserConfig {
    BrowserConfig {
        extra_root_certificates: Some(ca()),
        host_resolver_rules: Some(rules()),
        connect_timeout: Duration::from_secs(5),
        ..Default::default()
    }
}
fn ech() -> EchOptions {
    EchOptions {
        config_list: Some(config_bytes("BROWSER_ECH_CONFIG")),
        ..Default::default()
    }
}
async fn bounded(work: impl Future<Output = ()>) {
    tokio::time::timeout(Duration::from_secs(45), work)
        .await
        .expect("security test timed out");
}
#[derive(Clone, Copy, Debug)]
enum Api {
    Tls,
    H1,
    H2,
    H3,
    Wss,
}
const APIS: [Api; 5] = [Api::Tls, Api::H1, Api::H2, Api::H3, Api::Wss];
fn options(api: Api) -> BrowserConfig {
    let mut c = config();
    if matches!(api, Api::H3) {
        c.force_http3_origins.push(format!(
            "https://{SECRET}:{}",
            port("BROWSER_ECH_HTTPS_PORT")
        ));
    }
    c
}
async fn exchange(client: &BrowserClient, api: Api, expected_ech: bool) -> Result<(), Error> {
    match api {
        Api::Tls => {
            let mut stream = client
                .connect_tls(SECRET, port("BROWSER_ECH_TLS_PORT"))
                .await?;
            assert_eq!(stream.info().await?.ech_accepted, Some(expected_ech));
            let payload = b"real native TLS with certificate policy";
            stream.write_all(payload).await?;
            let mut received = vec![0; payload.len()];
            stream.read_exact(&mut received).await?;
            assert_eq!(received, payload);
            stream.close();
        }
        Api::Wss => {
            let p = port("BROWSER_ECH_H1_PORT");
            let mut socket = client
                .connect_websocket(WebSocketRequest::new(
                    format!("wss://{SECRET}:{p}/ws"),
                    format!("https://{SECRET}:{p}"),
                ))
                .await?;
            let expected = if expected_ech { "true" } else { "false" };
            assert!(
                socket
                    .handshake()
                    .headers
                    .iter()
                    .any(|(n, v)| n.eq_ignore_ascii_case("x-ech-accepted") && v == expected)
            );
            socket.send(Message::Text("native WSS".into())).await?;
            assert_eq!(
                socket.recv().await?,
                Some(Message::Text("native WSS".into()))
            );
            assert!(socket.close(1000, "").await?.clean);
        }
        Api::H1 | Api::H2 | Api::H3 => {
            let p = port(if matches!(api, Api::H1) {
                "BROWSER_ECH_H1_PORT"
            } else {
                "BROWSER_ECH_HTTPS_PORT"
            });
            let response = client.get(format!("https://{SECRET}:{p}/ech")).await?;
            assert_eq!(response.status, 200);
            assert_eq!(response.ech_accepted, Some(expected_ech));
            let expected = match api {
                Api::H1 => "HTTP/1.1",
                Api::H2 => "HTTP/2.0",
                _ => "HTTP/3.0",
            };
            let value: serde_json::Value =
                serde_json::from_slice(&response.bytes(4096).await?).unwrap();
            assert_eq!(value["protocol"], expected);
            assert_eq!(value["ech_accepted"], expected_ech);
            assert_eq!(value["server_name"], SECRET);
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires loopback browser fixture"]
async fn certificate_decisions_apply_to_tls_http_h3_and_wss() {
    bounded(async {
        for api in APIS {
            for (trusted, decision, success) in [
                (true, Decision::UseDefault, true),
                (false, Decision::UseDefault, false),
                (true, Decision::Reject, false),
                (false, Decision::Accept, true),
            ] {
                let seen = Arc::new(Mutex::new(Vec::new()));
                let records = seen.clone();
                let mut c = options(api);
                if !trusted {
                    c.extra_root_certificates = None;
                }
                c.certificate_verifier = Some(Arc::new(
                    move |info: CertificateInfo, done: CertificateVerification| {
                        records.lock().unwrap().push(info);
                        done.complete(decision);
                    },
                ));
                let client = BrowserClient::new(c).await.unwrap();
                let result = exchange(&client, api, false).await;
                assert_eq!(
                    result.is_ok(),
                    success,
                    "{api:?} trusted={trusted} decision={decision:?}: {result:?}"
                );
                client.shutdown().await.unwrap();
                let records = seen.lock().unwrap();
                assert!(!records.is_empty(), "{api:?}");
                for info in records.iter() {
                    assert_eq!(info.hostname, SECRET);
                    assert_eq!(info.default_error.is_none(), trusted);
                    assert!(!info.issued_by_known_root);
                    assert!(!info.verified_chain.is_empty());
                    assert_eq!(info.certificate_chain[0][0], 0x30);
                }
            }
        }
    })
    .await;
}

async fn naive_exchange(client: &NaiveClient, expected_ech: bool) -> Result<(), Error> {
    let mut stream = client.connect("echo.invalid", 443).await?;
    assert_eq!(stream.info().await?.ech_accepted, Some(expected_ech));
    let payload = vec![0x5a; 8192];
    stream.write_all(&payload).await?;
    let mut read = vec![0; payload.len()];
    stream.read_exact(&mut read).await?;
    assert_eq!(payload, read);
    stream.shutdown_write().await?;
    let mut byte = [0];
    assert_eq!(stream.read(&mut byte).await?, 0);
    Ok(())
}
fn naive_config(quic: bool) -> Config {
    let scheme = if quic { "quic" } else { "https" };
    let mut c = Config::new(format!(
        "{scheme}://user:pass@{SECRET}:{}",
        port("BROWSER_ECH_HTTPS_PORT")
    ));
    c.host_resolver_rules = Some(rules());
    c.extra_root_certificates = Some(ca());
    c.connect_timeout = Duration::from_secs(5);
    c
}
#[tokio::test]
#[ignore = "requires loopback browser fixture"]
async fn certificate_callback_applies_to_naive_https_and_quic() {
    bounded(async {
        for quic in [false, true] {
            for decision in [Decision::UseDefault, Decision::Accept, Decision::Reject] {
                let seen = Arc::new(AtomicUsize::new(0));
                let calls = seen.clone();
                let mut c = naive_config(quic);
                if decision != Decision::Reject {
                    c.extra_root_certificates = None;
                }
                c.certificate_verifier = Some(Arc::new(
                    move |info: CertificateInfo, done: CertificateVerification| {
                        assert_eq!(info.hostname, SECRET);
                        calls.fetch_add(1, Ordering::Relaxed);
                        done.complete(decision);
                    },
                ));
                let client = NaiveClient::new(c).await.unwrap();
                let result = naive_exchange(&client, false).await;
                assert_eq!(
                    result.is_ok(),
                    decision == Decision::Accept,
                    "QUIC={quic} {decision:?}: {result:?}"
                );
                client.shutdown().await.unwrap();
                assert!(seen.load(Ordering::Relaxed) > 0);
            }
        }
    })
    .await;
}

#[tokio::test]
#[ignore = "requires loopback browser fixture"]
async fn certificate_callback_can_finish_on_another_thread() {
    bounded(async {
        let tokens = Arc::new(Mutex::new(Vec::new()));
        let observed = tokens.clone();
        let mut c = config();
        c.certificate_verifier = Some(Arc::new(
            move |info: CertificateInfo, done: CertificateVerification| {
                observed.lock().unwrap().push(done.cancellation());
                std::thread::spawn(move || {
                    assert!(info.default_error.is_none());
                    done.complete(Decision::UseDefault);
                });
            },
        ));
        let client = BrowserClient::new(c).await.unwrap();
        exchange(&client, Api::H2, false).await.unwrap();
        client.shutdown().await.unwrap();
        assert!(!tokens.lock().unwrap().is_empty());
        assert!(
            tokens
                .lock()
                .unwrap()
                .iter()
                .all(|token| !token.is_cancelled())
        );
    })
    .await;
}

#[tokio::test]
#[ignore = "requires loopback browser fixture"]
async fn certificate_callback_drop_and_panic_fail_closed() {
    bounded(async {
        for panic in [false, true] {
            let mut c = config();
            c.certificate_verifier = Some(Arc::new(
                move |_: CertificateInfo, _: CertificateVerification| {
                    assert!(!panic, "intentional verifier panic");
                },
            ));
            let client = BrowserClient::new(c).await.unwrap();
            let error = exchange(&client, Api::Tls, false).await.unwrap_err();
            assert_eq!(error.code(), Some(-207)); // ERR_CERT_INVALID
            client.shutdown().await.unwrap();
        }
    })
    .await;
}

#[tokio::test]
#[ignore = "requires loopback browser fixture"]
async fn pending_verification_cancels_and_late_results_are_safe() {
    bounded(async {
        for api in APIS {
            for mode in ["cancel", "deadline", "reset", "shutdown"] {
                let (send, recv) = tokio::sync::oneshot::channel();
                let send = Mutex::new(Some(send));
                let drops = Arc::new(AtomicUsize::new(0));
                let guard = DropWatch(drops.clone());
                let mut c = options(api);
                if mode == "deadline" {
                    c.connect_timeout = Duration::from_millis(150);
                }
                c.certificate_verifier = Some(Arc::new(
                    move |info: CertificateInfo, done: CertificateVerification| {
                        let _keepalive = &guard;
                        let sender = send.lock().unwrap().take().unwrap();
                        let _ = sender.send((info, done));
                    },
                ));
                let client = BrowserClient::new(c).await.unwrap();
                let task_client = client.clone();
                let task = tokio::spawn(async move { exchange(&task_client, api, false).await });
                let (info, done) = recv.await.unwrap();
                assert!(info.default_error.is_none());
                let cancellation = done.cancellation();
                match mode {
                    "cancel" => {
                        task.abort();
                        assert!(matches!(task.await, Err(error) if error.is_cancelled()));
                    }
                    "deadline" => {
                        assert!(task.await.unwrap().is_err());
                    }
                    "reset" => {
                        client.close_all_connections().await.unwrap();
                        assert!(task.await.unwrap().is_err());
                    }
                    _ => {
                        client.shutdown().await.unwrap();
                        assert!(task.await.unwrap().is_err());
                    }
                }
                tokio::time::timeout(Duration::from_secs(3), async {
                    while !cancellation.is_cancelled() {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap_or_else(|_| panic!("verification not cancelled: {api:?}, {mode}"));
                client.shutdown().await.unwrap();
                drop(client);
                tokio::time::timeout(Duration::from_secs(3), async {
                    while drops.load(Ordering::SeqCst) == 0 {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap_or_else(|_| panic!("verifier retained after shutdown: {api:?}, {mode}"));
                assert_eq!(drops.load(Ordering::SeqCst), 1);
                std::thread::spawn(move || done.complete(Decision::Accept))
                    .join()
                    .unwrap();
                assert!(cancellation.is_cancelled());
            }
        }
    })
    .await;
}

#[tokio::test]
#[ignore = "requires loopback browser fixture"]
async fn cancelling_http_does_not_abort_another_tls_verification() {
    bounded(async {
        let (send, mut recv) = tokio::sync::mpsc::unbounded_channel();
        let mut c = config();
        c.certificate_verifier = Some(Arc::new(
            move |info: CertificateInfo, done: CertificateVerification| {
                let _ = send.send((info.hostname, done));
            },
        ));
        let client = BrowserClient::new(c).await.unwrap();
        let http_client = client.clone();
        let http = tokio::spawn(async move {
            http_client
                .get(format!(
                    "https://{SECRET}:{}/ech",
                    port("BROWSER_ECH_HTTPS_PORT")
                ))
                .await
        });
        let (name, http_done) = recv.recv().await.unwrap();
        assert_eq!(name, SECRET);
        let tls_client = client.clone();
        let tls = tokio::spawn(async move {
            tls_client
                .connect_tls(OTHER, port("BROWSER_ECH_TLS_PORT"))
                .await
        });
        let (name, tls_done) = recv.recv().await.unwrap();
        assert_eq!(name, OTHER);
        let tls_cancel = tls_done.cancellation();
        http.abort();
        assert!(matches!(http.await, Err(error) if error.is_cancelled()));
        // The stats call is a native IO barrier after the canceled request's close.
        assert_eq!(client.stats().await.unwrap().active_streams, 1);
        assert!(!tls_cancel.is_cancelled());
        tls_done.complete(Decision::UseDefault);
        let mut stream = tls.await.unwrap().unwrap();
        stream.write_all(b"live").await.unwrap();
        let mut bytes = [0; 4];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"live");
        stream.close();
        let http_cancel = http_done.cancellation();
        tokio::time::timeout(Duration::from_secs(3), async {
            while !http_cancel.is_cancelled() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        http_done.complete(Decision::Accept);
        client.shutdown().await.unwrap();
    })
    .await;
}

#[tokio::test]
#[ignore = "requires loopback browser fixture"]
async fn ech_rules_canonicalize_absolute_dns_names() {
    bounded(async {
        let mut c = config();
        c.ech.insert(format!("{SECRET}."), ech());
        let client = BrowserClient::new(c).await.unwrap();
        let hostname = SECRET.to_string();
        let mut stream = client
            .connect_tls(&hostname, port("BROWSER_ECH_TLS_PORT"))
            .await
            .unwrap();
        assert_eq!(stream.info().await.unwrap().ech_accepted, Some(true));
        stream.close();
        assert!(
            client
                .get(format!(
                    "https://{hostname}:{}/ech",
                    port("BROWSER_NO_ECH_PORT")
                ))
                .await
                .is_err()
        );
        client.shutdown().await.unwrap();
    })
    .await;
}

#[tokio::test]
#[ignore = "requires loopback browser fixture"]
async fn direct_static_ech_succeeds_on_tls_http_h3_and_wss() {
    bounded(async {
        for api in APIS {
            let mut c = options(api);
            c.ech.insert(SECRET.into(), ech());
            let client = BrowserClient::new(c).await.unwrap();
            exchange(&client, api, true).await.unwrap();
            client.shutdown().await.unwrap();
        }
    })
    .await;
}

#[tokio::test]
#[ignore = "requires loopback browser fixture"]
async fn direct_ech_dns_discovery_uses_host_resolver_and_actual_port() {
    bounded(async {
        for api in APIS {
            let seen = Arc::new(Mutex::new(Vec::new()));
            let records = seen.clone();
            let mut c = options(api);
            c.ech.insert(
                SECRET.into(),
                EchOptions {
                    query_name: Some("public.ech.test".into()),
                    ..Default::default()
                },
            );
            c.network.resolver = Some(Arc::new(
                move |request: ResolveRequest, done: ResolveCompletion| {
                    if request.query == ResolveQuery::HttpsRecord {
                        records.lock().unwrap().push(request.hostname);
                        done.complete_https(Ok(config_bytes("BROWSER_ECH_CONFIG")));
                    } else {
                        done.complete(Ok(vec!["127.0.0.1".parse().unwrap()]));
                    }
                },
            ));
            let client = BrowserClient::new(c).await.unwrap();
            exchange(&client, api, true).await.unwrap();
            client.shutdown().await.unwrap();
            let p = port(match api {
                Api::Tls => "BROWSER_ECH_TLS_PORT",
                Api::H1 | Api::Wss => "BROWSER_ECH_H1_PORT",
                _ => "BROWSER_ECH_HTTPS_PORT",
            });
            assert!(
                seen.lock()
                    .unwrap()
                    .contains(&format!("_{p}._https.public.ech.test")),
                "{api:?}"
            );
        }
    })
    .await;
}

#[tokio::test]
#[ignore = "requires loopback browser fixture"]
async fn naive_ech_succeeds_with_static_and_dns_configs() {
    bounded(async {
        for quic in [false, true] {
            for dns in [false, true] {
                let mut c = naive_config(quic);
                c.ech = Some(if dns { EchOptions::default() } else { ech() });
                if dns {
                    c.network.resolver = Some(Arc::new(
                        |request: ResolveRequest, done: ResolveCompletion| {
                            if request.query == ResolveQuery::HttpsRecord {
                                done.complete_https(Ok(config_bytes("BROWSER_ECH_CONFIG")));
                            } else {
                                done.complete(Ok(vec!["127.0.0.1".parse().unwrap()]));
                            }
                        },
                    ));
                }
                let client = NaiveClient::new(c).await.unwrap();
                naive_exchange(&client, true).await.unwrap();
                client.shutdown().await.unwrap();
            }
        }
    })
    .await;
}

#[tokio::test]
#[ignore = "requires loopback browser fixture"]
async fn ech_retry_authenticates_the_public_name_then_accepts_the_inner_name() {
    bounded(async {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let records = seen.clone();
        let mut c = config();
        c.ech.insert(
            SECRET.into(),
            EchOptions {
                config_list: Some(config_bytes("BROWSER_ECH_STALE_CONFIG")),
                ..Default::default()
            },
        );
        c.certificate_verifier = Some(Arc::new(
            move |info: CertificateInfo, done: CertificateVerification| {
                records.lock().unwrap().push(info.hostname);
                done.complete(Decision::UseDefault);
            },
        ));
        let client = BrowserClient::new(c).await.unwrap();
        exchange(&client, Api::Tls, true).await.unwrap();
        client.shutdown().await.unwrap();
        let records = seen.lock().unwrap();
        assert!(
            records.iter().any(|h| h == "public.ech.test"),
            "{records:?}"
        );
        assert!(records.iter().any(|h| h == SECRET), "{records:?}");
    })
    .await;
}

#[tokio::test]
#[ignore = "requires loopback browser fixture"]
async fn ech_strict_does_not_fall_back_when_server_has_no_ech() {
    bounded(async {
        for mode in [EchMode::Strict, EchMode::Opportunistic, EchMode::Disabled] {
            let mut c = config();
            let mut policy = ech();
            policy.mode = mode;
            if mode == EchMode::Disabled {
                policy.config_list = None;
            }
            c.ech.insert(SECRET.into(), policy);
            // Even accepting a certificate cannot override the ECH policy.
            c.certificate_verifier = Some(Arc::new(
                |_: CertificateInfo, done: CertificateVerification| done.complete(Decision::Accept),
            ));
            let client = BrowserClient::new(c).await.unwrap();
            let response = client
                .get(format!(
                    "https://{SECRET}:{}/ech",
                    port("BROWSER_NO_ECH_PORT")
                ))
                .await;
            if mode == EchMode::Strict {
                assert!(response.is_err());
            } else {
                let response = response.unwrap();
                assert_eq!(response.ech_accepted, Some(false));
                let body: serde_json::Value =
                    serde_json::from_slice(&response.bytes(4096).await.unwrap()).unwrap();
                assert_eq!(body["ech_accepted"], false);
            }
            client.shutdown().await.unwrap();
        }
    })
    .await;
}

#[tokio::test]
#[ignore = "requires loopback browser fixture"]
async fn cross_host_pooling_cannot_bypass_certificate_or_ech_policy() {
    bounded(async {
        let p = port("BROWSER_NO_ECH_PORT");
        for certificate in [false, true] {
            let mut c = config();
            if certificate {
                c.certificate_verifier = Some(Arc::new(
                    |info: CertificateInfo, done: CertificateVerification| {
                        done.complete(if info.hostname == OTHER {
                            Decision::Reject
                        } else {
                            Decision::UseDefault
                        });
                    },
                ));
            } else {
                c.ech.insert(
                    SECRET.into(),
                    EchOptions {
                        mode: EchMode::Disabled,
                        ..Default::default()
                    },
                );
                c.ech.insert(OTHER.into(), ech());
            }
            let client = BrowserClient::new(c).await.unwrap();
            client
                .get(format!("https://{SECRET}:{p}/ech"))
                .await
                .unwrap()
                .bytes(4096)
                .await
                .unwrap();
            assert!(
                client
                    .get(format!("https://{OTHER}:{p}/ech"))
                    .await
                    .is_err()
            );
            client.shutdown().await.unwrap();
        }
        let mut c = config();
        c.ech.insert(SECRET.into(), ech());
        c.ech.insert(
            OTHER.into(),
            EchOptions {
                mode: EchMode::Disabled,
                ..Default::default()
            },
        );
        let client = BrowserClient::new(c).await.unwrap();
        let response = client
            .get(format!(
                "https://{SECRET}:{}/redirect-other",
                port("BROWSER_ECH_HTTPS_PORT")
            ))
            .await
            .unwrap();
        assert_eq!(response.ech_accepted, Some(false));
        let value: serde_json::Value =
            serde_json::from_slice(&response.bytes(4096).await.unwrap()).unwrap();
        assert_eq!(value["server_name"], OTHER);
        assert_eq!(value["ech_accepted"], false);
        client.shutdown().await.unwrap();
    })
    .await;
}
