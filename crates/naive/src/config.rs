use crate::Error;
use std::{collections::BTreeMap, fmt, path::PathBuf, time::Duration};

/// Configuration for one proxy chain. Credentials in `proxy` must be URL-encoded.
#[derive(Clone)]
pub struct Config {
    pub proxy: String,
    pub network: crate::NetworkConfig,
    pub observer: Option<std::sync::Arc<dyn crate::Observer>>,
    pub http2: Http2Options,
    pub quic: QuicOptions,
    /// ECH for the outermost HTTPS/QUIC proxy. None preserves upstream behavior.
    pub ech: Option<EchOptions>,
    /// Extra PEM trust anchors for this client only. Hostname/chain validation
    /// remains enabled; no system trust-store changes are made.
    pub extra_root_certificates: Option<String>,
    pub host_resolver_rules: Option<String>,
    pub extra_headers: BTreeMap<String, String>,
    /// More sessions change the traffic signature. The default is one.
    pub insecure_concurrency: usize,
    /// Width of the shared native IO worker pool used for assigning this client.
    /// An individual client/context stays on one worker; multiple clients spread
    /// round-robin across this many workers. Does not add proxy tunnels.
    pub io_workers: usize,
    /// Positive timeout, rounded up to milliseconds; less than i32::MAX ms.
    pub connect_timeout: Duration,
    pub tunnel_timeout: Duration,
    pub idle_timeout: Duration,
    pub no_post_quantum: bool,
    /// Optional process-wide Chromium NetLog, bounded to approximately 16 MiB.
    /// Contains metadata from all clients active during capture; shutdown flushes it.
    pub net_log: Option<PathBuf>,
}

impl Config {
    pub fn new(proxy: impl Into<String>) -> Self {
        Self {
            proxy: proxy.into(),
            network: crate::NetworkConfig::default(),
            observer: None,
            http2: Http2Options::default(),
            quic: QuicOptions::default(),
            ech: None,
            extra_root_certificates: None,
            host_resolver_rules: None,
            extra_headers: BTreeMap::new(),
            insecure_concurrency: 1,
            io_workers: 1,
            connect_timeout: Duration::from_secs(30),
            tunnel_timeout: Duration::from_secs(1800),
            idle_timeout: Duration::from_secs(600),
            no_post_quantum: false,
            net_log: None,
        }
    }

    pub(crate) fn json(&self) -> Result<String, Error> {
        if self.proxy.contains('\0')
            || self.proxy.is_empty()
            || !self.proxy.split(',').all(|p| {
                p.starts_with("https://")
                    || p.starts_with("quic://")
                    || p.starts_with("http://")
                    || p.starts_with("socks://")
            })
        {
            return Err(Error::invalid(
                "proxy must be an HTTP, HTTPS, QUIC or SOCKS proxy URL",
            ));
        }
        if !(1..=64).contains(&self.insecure_concurrency) {
            return Err(Error::invalid("insecure_concurrency must be in 1..=64"));
        }
        if !(1..=8).contains(&self.io_workers) {
            return Err(Error::invalid("io_workers must be in 1..=8"));
        }
        if self.connect_timeout.is_zero() || self.connect_timeout.as_millis() >= i32::MAX as u128 {
            return Err(Error::invalid(
                "connect_timeout must be positive and less than i32::MAX milliseconds",
            ));
        }
        for duration in [self.tunnel_timeout, self.idle_timeout] {
            if duration.as_secs() == 0
                || duration.as_secs() > i32::MAX as u64
                || duration.subsec_nanos() != 0
            {
                return Err(Error::invalid(
                    "tunnel/idle timeouts must be whole seconds in 1..=i32::MAX",
                ));
            }
        }
        if self.extra_root_certificates.as_deref() == Some("") {
            return Err(Error::invalid("extra_root_certificates cannot be empty"));
        }
        if self
            .http2
            .stream_receive_window
            .is_some_and(|v| v == 0 || v > i32::MAX as u32)
        {
            return Err(Error::invalid(
                "HTTP/2 stream receive window must be in 1..=2^31-1",
            ));
        }
        if self
            .http2
            .connection_receive_window
            .is_some_and(|v| v < 65_535 || v > i32::MAX as u32)
        {
            return Err(Error::invalid(
                "HTTP/2 connection receive window must be in 65535..=2^31-1",
            ));
        }
        for window in [
            self.quic.stream_receive_window,
            self.quic.session_receive_window,
        ]
        .into_iter()
        .flatten()
        {
            if !(16_384..=(1u64 << 62) - 1).contains(&window) {
                return Err(Error::invalid(
                    "QUIC receive windows must be in 16384..=2^62-1",
                ));
            }
        }
        if let Some(ech) = &self.ech {
            if ech.mode == EchMode::Disabled
                && (ech.config_list.is_some() || ech.query_name.is_some())
            {
                return Err(Error::invalid(
                    "disabled ECH cannot include configuration or a query name",
                ));
            }
            if ech.config_list.is_some() && ech.query_name.is_some() {
                return Err(Error::invalid(
                    "select either a static ECHConfigList or DNS query name",
                ));
            }
            if ech
                .config_list
                .as_ref()
                .is_some_and(|v| v.is_empty() || v.len() > 65537)
            {
                return Err(Error::invalid(
                    "ECHConfigList must contain 1..=65537 encoded bytes",
                ));
            }
            if ech
                .query_name
                .as_ref()
                .is_some_and(|name| name.is_empty() || name.contains('\0'))
            {
                return Err(Error::invalid(
                    "ECH query name must be nonempty and contain no NUL",
                ));
            }
        }
        let mut headers = String::new();
        for (name, value) in &self.extra_headers {
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c))
                || value.bytes().any(|c| c == b'\r' || c == b'\n' || c == 0)
            {
                return Err(Error::invalid("invalid extra HTTP header"));
            }
            headers.push_str(name);
            headers.push_str(": ");
            headers.push_str(value);
            headers.push_str("\r\n");
        }
        let mut json = serde_json::json!({
            "proxy": self.proxy, "insecure-concurrency": self.insecure_concurrency,
            "io-workers": self.io_workers,
            "connect-timeout-ms": self.connect_timeout.as_nanos().div_ceil(1_000_000),
            "tunnel-timeout": self.tunnel_timeout.as_secs(), "idle-timeout": self.idle_timeout.as_secs(),
            "no-post-quantum": self.no_post_quantum,
        });
        if let Some(window) = self.http2.stream_receive_window {
            json["http2-stream-window"] = window.into();
        }
        if let Some(window) = self.http2.connection_receive_window {
            json["http2-connection-window"] = window.into();
        }
        if let Some(window) = self.quic.stream_receive_window {
            json["quic-stream-window"] = window.to_string().into();
        }
        if let Some(window) = self.quic.session_receive_window {
            json["quic-session-window"] = window.to_string().into();
        }
        if let Some(name) = self.quic.congestion_control.name() {
            json["quic-congestion"] = name.into();
        }
        if let Some(ech) = &self.ech {
            json["ech-mode"] = match ech.mode {
                EchMode::Disabled => 0,
                EchMode::Opportunistic => 1,
                EchMode::Strict => 2,
            }
            .into();
            if let Some(list) = &ech.config_list {
                json["ech-config-list"] = serde_json::json!(list);
            }
            if let Some(name) = &ech.query_name {
                json["ech-query-name"] = name.clone().into();
            }
        }
        if !headers.is_empty() {
            json["extra-headers"] = headers.into();
        }
        if let Some(rules) = &self.host_resolver_rules {
            json["host-resolver-rules"] = rules.clone().into();
        }
        if let Some(roots) = &self.extra_root_certificates {
            json["extra-root-certs"] = roots.clone().into();
        }
        if let Some(path) = &self.net_log {
            json["log-net-log"] = path
                .to_str()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| Error::invalid("net_log must be a nonempty UTF-8 path"))?
                .into();
        }
        Ok(json.to_string())
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("proxy", &"<redacted>")
            .field("insecure_concurrency", &self.insecure_concurrency)
            .field("connect_timeout", &self.connect_timeout)
            .finish_non_exhaustive()
    }
}

/// Receive windows in bytes. Unset values preserve the upstream Naïve defaults.
#[derive(Clone, Debug, Default)]
pub struct Http2Options {
    pub stream_receive_window: Option<u32>,
    pub connection_receive_window: Option<u32>,
}
#[derive(Clone, Debug, Default)]
pub struct QuicOptions {
    pub stream_receive_window: Option<u64>,
    pub session_receive_window: Option<u64>,
    /// Local sender congestion control; does not reconfigure the proxy server.
    pub congestion_control: QuicCongestionControl,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum QuicCongestionControl {
    #[default]
    Default,
    Bbr,
    Bbr2,
    Cubic,
    Reno,
}
impl QuicCongestionControl {
    fn name(self) -> Option<&'static str> {
        match self {
            Self::Default => None,
            Self::Bbr => Some("bbr"),
            Self::Bbr2 => Some("bbr2"),
            Self::Cubic => Some("cubic"),
            Self::Reno => Some("reno"),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum EchMode {
    Disabled,
    /// Missing/rejected configurations may fall back according to Chromium policy.
    Opportunistic,
    /// Refuse a connection unless ECH succeeds, including after authenticated retry.
    #[default]
    Strict,
}
/// ECH policy for the first secure proxy in the configured chain. It must be
/// the outermost hop and use a DNS hostname (address mapping remains available).
#[derive(Clone, Debug, Default)]
pub struct EchOptions {
    pub mode: EchMode,
    /// Serialized TLS ECHConfigList, including its two-byte list length.
    pub config_list: Option<Vec<u8>>,
    /// HTTPS-record lookup name; None uses the proxy hostname. The proxy port
    /// is preserved. Mutually exclusive with a static config_list.
    pub query_name: Option<String>,
}
