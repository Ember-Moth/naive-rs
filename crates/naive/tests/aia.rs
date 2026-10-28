#![cfg(feature = "tokio")]
use naive::{Config, NaiveClient, network::*};
use std::{
    env,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the local missing-intermediate certificate fixture; run tests/aia_interop.py"]
async fn missing_intermediate_is_rejected_without_issuer_network_fetch() {
    let proxy: u16 = env::var("NAIVE_AIA_PROXY_PORT").unwrap().parse().unwrap();
    let aia: u16 = env::var("NAIVE_AIA_PORT").unwrap().parse().unwrap();
    let origin: u16 = env::var("NAIVE_AIA_ORIGIN_PORT").unwrap().parse().unwrap();
    for scheme in ["https", "quic"] {
        let names = Arc::new(Mutex::new(Vec::new()));
        let sockets = Arc::new(Mutex::new(Vec::new()));
        let mut config = Config::new(format!("{scheme}://test:test@aia-proxy.test:{proxy}"));
        config.extra_root_certificates = Some(env::var("NAIVE_AIA_ROOT").unwrap());
        config.connect_timeout = Duration::from_secs(8);
        let seen = names.clone();
        config.network.resolver = Some(Arc::new(
            move |request: ResolveRequest, done: ResolveCompletion| {
                assert!(
                    ["aia-proxy.test", "aia-issuer.invalid"].contains(&request.hostname.as_str())
                );
                seen.lock().unwrap().push(request.hostname);
                done.complete(Ok(vec![
                    env::var("NAIVE_TEST_PROXY_IP")
                        .unwrap_or_else(|_| "127.0.0.1".into())
                        .parse()
                        .unwrap(),
                ]));
            },
        ));
        let seen = sockets.clone();
        config.network.socket_control = Some(Arc::new(move |_: Socket<'_>, info: SocketInfo| {
            seen.lock().unwrap().push(info.peer.port());
            Ok(())
        }));
        let trace = std::path::PathBuf::from(env::var("NAIVE_AIA_TRACE").unwrap())
            .join(format!("{scheme}.ndjson"));
        config.net_log = Some(trace.clone());
        #[cfg(target_os = "ios")]
        {
            let mut system = config.clone();
            system.extra_root_certificates = None;
            system.net_log = None;
            let client = NaiveClient::new(system).await.unwrap();
            assert!(client.connect("127.0.0.1", origin).await.is_err());
            client.shutdown().await.unwrap();
        }
        let client = NaiveClient::new(config.clone()).await.unwrap();
        assert!(client.connect("127.0.0.1", origin).await.is_err());
        client.shutdown().await.unwrap();
        let log = std::fs::read_to_string(trace).unwrap();
        assert!(
            log.lines()
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .any(|value| cert_error(&value)),
            "failure must be certificate validation"
        );
        assert!(
            !names
                .lock()
                .unwrap()
                .iter()
                .any(|name| name == "aia-issuer.invalid")
        );
        assert!(!sockets.lock().unwrap().contains(&aia));

        // Trusting the omitted issuer explicitly makes the same endpoint work;
        // the negative case above is not an unrelated connection failure.
        config
            .extra_root_certificates
            .as_mut()
            .unwrap()
            .push_str(&env::var("NAIVE_AIA_ISSUER").unwrap());
        config.net_log = None;
        let client = NaiveClient::new(config).await.unwrap();
        let mut stream = client.connect("127.0.0.1", origin).await.unwrap();
        stream.write_all(b"aia").await.unwrap();
        let mut bytes = [0; 3];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"aia");
        client.shutdown().await.unwrap();
        assert!(
            !names
                .lock()
                .unwrap()
                .iter()
                .any(|name| name == "aia-issuer.invalid")
        );
        assert!(!sockets.lock().unwrap().contains(&aia));
        assert!(sockets.lock().unwrap().contains(&proxy));
        eprintln!(
            "{scheme}: incomplete proxy chain rejected, explicit issuer trusted, no AIA network fetch"
        );
    }
}

fn cert_error(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(map) => {
            map.get("net_error").and_then(|value| value.as_i64()) == Some(-202)
                || map.values().any(cert_error)
        }
        serde_json::Value::Array(values) => values.iter().any(cert_error),
        _ => false,
    }
}
