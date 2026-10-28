//! Direct TLS, HTTP and WebSocket clients implemented by Chromium.
//!
//! These contexts never use a proxy. Keep using `NaiveClient` for Naive tunnels.
//! The pinned Chromium implementation is the basis for network-profile matching;
//! an identical browser fingerprint still requires a matching browser configuration
//! and a measured baseline. This module does not implement a browser DOM or CORS.
mod websocket;
pub use websocket::{
    CloseFrame, Message, WebSocket, WebSocketHandshake, WebSocketReadHalf, WebSocketRequest,
    WebSocketWriteHalf,
};

use crate::{ClientStats, Error, NaiveClient, NaiveStream, NetworkConfig, ReadChunk, client::lock};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    ffi::{CStr, CString},
    ops::{Deref, DerefMut},
    sync::Arc,
    time::{Duration, Instant},
};
#[cfg(any(feature = "tokio", feature = "futures-io"))]
use std::{
    pin::Pin,
    task::{Context, Poll},
};

pub type Headers = Vec<(String, String)>;
pub(crate) const MAX_PAYLOAD: usize = 64 * 1024 * 1024;

#[derive(Clone)]
pub struct BrowserConfig {
    pub network: NetworkConfig,
    pub certificate_verifier: Option<Arc<dyn crate::CertificateVerifier>>,
    pub extra_root_certificates: Option<String>,
    pub host_resolver_rules: Option<String>,
    /// Per-host ECH policy, shared across TLS, HTTP and WSS. Keys are DNS names.
    /// Empty preserves Chromium defaults. No wildcard matching or policy mutation.
    pub ech: BTreeMap<String, crate::EchOptions>,
    pub accept_language: String,
    pub connect_timeout: Duration,
    pub io_workers: usize,
    pub cache_bytes: usize,
    pub max_websocket_message: usize,
    /// Explicit HTTPS origins that must use H3. Empty keeps normal Alt-Svc
    /// selection. Configured private roots are permitted for these hosts;
    /// certificate-chain and hostname validation remain enabled.
    pub force_http3_origins: Vec<String>,
}
impl Default for BrowserConfig {
    fn default() -> Self {
        Self {
            network: NetworkConfig::default(),
            certificate_verifier: None,
            extra_root_certificates: None,
            host_resolver_rules: None,
            ech: BTreeMap::new(),
            accept_language: "en-US,en;q=0.9".into(),
            connect_timeout: Duration::from_secs(30),
            io_workers: 1,
            cache_bytes: 16 * 1024 * 1024,
            max_websocket_message: 16 * 1024 * 1024,
            force_http3_origins: Vec::new(),
        }
    }
}
impl BrowserConfig {
    fn json(&self) -> Result<String, Error> {
        if !(1..=8).contains(&self.io_workers)
            || self.connect_timeout.is_zero()
            || self.connect_timeout.as_millis() >= i32::MAX as u128
            || self.cache_bytes > 256 * 1024 * 1024
            || !(1..=MAX_PAYLOAD).contains(&self.max_websocket_message)
            || !valid_value(&self.accept_language)
            || self.extra_root_certificates.as_deref() == Some("")
            || self
                .host_resolver_rules
                .as_ref()
                .is_some_and(|v| v.contains('\0'))
            || self
                .force_http3_origins
                .iter()
                .any(|v| !valid_url(v, &["https://"]))
        {
            return Err(Error::invalid("invalid browser context configuration"));
        }
        if self.ech.len() > 128
            || self.ech.keys().any(|host| {
                host.is_empty()
                    || host.len() > 253
                    || host.parse::<std::net::IpAddr>().is_ok()
                    || host
                        .chars()
                        .any(|c| c.is_whitespace() || "/:#?\\@*\0".contains(c))
            })
        {
            return Err(Error::invalid(
                "ECH keys must be DNS hostnames (at most 128)",
            ));
        }
        let mut ech = serde_json::Map::new();
        for (host, options) in &self.ech {
            ech.insert(host.clone(), options.json()?);
        }
        let mut value = serde_json::json!({
            "browser-client":true, "io-workers":self.io_workers, "ech-hosts":ech,
            "connect-timeout-ms":self.connect_timeout.as_nanos().div_ceil(1_000_000),
            "cache-bytes":self.cache_bytes, "max-websocket-message":self.max_websocket_message,
            "accept-language":self.accept_language,
            "force-http3-origins":self.force_http3_origins,
        });
        if let Some(roots) = &self.extra_root_certificates {
            value["extra-root-certs"] = roots.clone().into();
        }
        if let Some(rules) = &self.host_resolver_rules {
            value["host-resolver-rules"] = rules.clone().into();
        }
        Ok(value.to_string())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkProfile {
    pub chromium_version: String,
    pub user_agent: String,
    pub accept_language: String,
    pub forced_http3_origins: Vec<String>,
}

/// Cloneable direct client. Contexts have separate cookies, caches and pools.
/// Chromium supplies all origin TLS/HTTP/WebSocket protocol implementations.
#[derive(Clone)]
pub struct BrowserClient {
    pub(crate) transport: NaiveClient,
    pub(crate) max_message: usize,
    profile: Arc<NetworkProfile>,
}
impl BrowserClient {
    pub async fn new(config: BrowserConfig) -> Result<Self, Error> {
        let transport = NaiveClient::new_native(
            config.json()?,
            crate::network::ClientHooks {
                network: config.network,
                certificate_verifier: config.certificate_verifier,
            },
            None,
        )
        .await?;
        // SAFETY: native initialization has completed and the returned string
        // remains immutable for the process lifetime.
        let user_agent = unsafe { CStr::from_ptr(naive_sys::naive_browser_user_agent()) }
            .to_string_lossy()
            .into_owned();
        Ok(Self {
            transport,
            max_message: config.max_websocket_message,
            profile: Arc::new(NetworkProfile {
                chromium_version: crate::native_version().into(),
                user_agent,
                accept_language: config.accept_language,
                forced_http3_origins: config.force_http3_origins,
            }),
        })
    }
    pub fn profile(&self) -> &NetworkProfile {
        &self.profile
    }
    /// Origin TLS with Chromium's HTTP ALPN policy. Inspect `info()` before
    /// speaking an application protocol; a server can negotiate h2 or HTTP/1.1.
    pub async fn connect_tls(
        &self,
        hostname: impl AsRef<str>,
        port: u16,
    ) -> Result<TlsStream, Error> {
        self.transport.connect(hostname, port).await.map(TlsStream)
    }
    /// Starts a native URLRequest. Dropping the future or unread response body
    /// cancels the request. `connect_timeout` covers response-header readiness.
    pub async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, Error> {
        let json = request.json()?;
        let json = CString::new(json).map_err(|_| Error::invalid("NUL in request JSON"))?;
        let mut stream = self.transport.response_stream()?;
        {
            let context = Arc::into_raw(stream.shared.clone());
            let data = request.body.as_deref().unwrap_or_default();
            let result = stream.inner.submit(|engine| unsafe {
                // Native copies request/upload bytes before this call returns.
                naive_sys::naive_browser_http(
                    engine,
                    stream.id,
                    json.as_ptr(),
                    data.as_ptr(),
                    data.len(),
                    context.cast_mut().cast(),
                );
            });
            if let Err(error) = result {
                // SAFETY: submit rejected without crossing the native boundary.
                unsafe {
                    drop(Arc::from_raw(context));
                }
                return Err(error);
            }
        }
        stream.handshake().await?;
        let text = lock(&stream.shared.state)
            .response_metadata
            .take()
            .ok_or_else(|| Error::runtime("HTTP response metadata missing".into()))?;
        let metadata: ResponseMetadata = serde_json::from_str(&text)
            .map_err(|_| Error::runtime("invalid HTTP response metadata".into()))?;
        Ok(HttpResponse {
            status: metadata.status,
            headers: metadata.headers,
            url: metadata.url,
            protocol: metadata.protocol,
            redirects: metadata.redirects,
            tls_version: metadata.tls_version,
            cipher_suite: metadata.cipher_suite.filter(|v| *v != 0),
            ech_accepted: metadata.tls_version.map(|_| metadata.ech_accepted),
            body: HttpBody(stream),
        })
    }
    pub async fn get(&self, url: impl Into<String>) -> Result<HttpResponse, Error> {
        self.execute(HttpRequest::get(url)).await
    }
    /// Explicit top-level GET headers, using native UA and Client Hints data.
    /// This does not create a document, execute scripts or fetch subresources.
    pub async fn navigate(&self, url: impl Into<String>) -> Result<HttpResponse, Error> {
        self.execute(HttpRequest::navigation(url)).await
    }
    pub async fn connect_websocket(&self, request: WebSocketRequest) -> Result<WebSocket, Error> {
        websocket::connect(self, request).await
    }
    /// Cancels all operations and resets native pools while preserving config.
    pub async fn close_all_connections(&self) -> Result<(), Error> {
        self.transport.close_all_connections().await
    }
    pub async fn shutdown(&self) -> Result<(), Error> {
        self.transport.shutdown().await
    }
    /// Logical operations/payload bytes, rather than physical connections.
    pub async fn stats(&self) -> Result<ClientStats, Error> {
        self.transport.stats().await
    }
}

/// Direct native TLS. Owned IO and runtime adapters use the same stream core as
/// Naive tunnels. TLS write-half-close is not exposed; `close` aborts the stream.
pub struct TlsStream(NaiveStream);
impl TlsStream {
    pub fn into_inner(self) -> NaiveStream {
        self.0
    }
}
impl Deref for TlsStream {
    type Target = NaiveStream;
    fn deref(&self) -> &NaiveStream {
        &self.0
    }
}
impl DerefMut for TlsStream {
    fn deref_mut(&mut self) -> &mut NaiveStream {
        &mut self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedirectPolicy {
    Follow(u16),
    Manual,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestContext {
    Bare,
    Navigation,
}
#[derive(Clone, Debug)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Headers,
    pub body: Option<Vec<u8>>,
    pub redirects: RedirectPolicy,
    pub context: RequestContext,
}
impl HttpRequest {
    pub fn new(method: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            url: url.into(),
            headers: Vec::new(),
            body: None,
            redirects: RedirectPolicy::Follow(20),
            context: RequestContext::Bare,
        }
    }
    pub fn get(url: impl Into<String>) -> Self {
        Self::new("GET", url)
    }
    pub fn navigation(url: impl Into<String>) -> Self {
        Self {
            context: RequestContext::Navigation,
            ..Self::get(url)
        }
    }
    pub fn post(url: impl Into<String>, body: impl Into<Vec<u8>>) -> Self {
        Self {
            body: Some(body.into()),
            ..Self::new("POST", url)
        }
    }
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
    fn json(&self) -> Result<String, Error> {
        if !valid_token(&self.method)
            || !valid_url(&self.url, &["http://", "https://"])
            || self.body.as_ref().is_some_and(|b| b.len() > MAX_PAYLOAD)
        {
            return Err(Error::invalid("invalid HTTP request or oversized upload"));
        }
        validate_headers(&self.headers)?;
        if self.context == RequestContext::Navigation
            && !matches!(self.method.as_str(), "GET" | "HEAD")
        {
            return Err(Error::invalid("navigation profile requires GET or HEAD"));
        }
        let redirects = match self.redirects {
            RedirectPolicy::Manual => -1,
            RedirectPolicy::Follow(n) if n <= 100 => i32::from(n),
            _ => return Err(Error::invalid("redirect limit must be <= 100")),
        };
        Ok(serde_json::json!({"method":self.method,"url":self.url,"headers":self.headers,"has-body":self.body.is_some(),"max-redirects":redirects,
            "navigation":self.context == RequestContext::Navigation}).to_string())
    }
}

#[derive(Deserialize)]
struct ResponseMetadata {
    status: u16,
    url: String,
    headers: Headers,
    protocol: String,
    redirects: u16,
    #[serde(default)]
    tls_version: Option<u16>,
    #[serde(default)]
    cipher_suite: Option<u16>,
    #[serde(default)]
    ech_accepted: bool,
}

pub struct HttpResponse {
    pub status: u16,
    pub url: String,
    pub headers: Headers,
    pub protocol: String,
    pub redirects: u16,
    pub tls_version: Option<u16>,
    pub cipher_suite: Option<u16>,
    pub ech_accepted: Option<bool>,
    pub body: HttpBody,
}
impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    pub async fn bytes(self, limit: usize) -> Result<Vec<u8>, Error> {
        self.body.bytes(limit).await
    }
}

/// Pull-driven response body. Leases stay valid after response/client shutdown.
pub struct HttpBody(NaiveStream);
impl HttpBody {
    pub async fn read_chunk(&mut self) -> Result<Option<ReadChunk>, Error> {
        self.0.read_chunk().await
    }
    pub async fn read_owned<B: crate::owned::IoBufMut + Send>(
        &mut self,
        buffer: B,
    ) -> crate::owned::IoResult<B> {
        self.0.read_owned(buffer).await
    }
    pub async fn read_local<B: crate::owned::IoBufMut>(
        &mut self,
        buffer: B,
    ) -> crate::owned::IoResult<B> {
        self.0.read_local(buffer).await
    }
    pub fn set_read_deadline(&self, deadline: Option<Instant>) -> Result<(), Error> {
        self.0.set_read_deadline(deadline)
    }
    pub fn close(&mut self) {
        self.0.close();
    }
    pub async fn bytes(mut self, limit: usize) -> Result<Vec<u8>, Error> {
        let mut output = Vec::new();
        while let Some(chunk) = self.read_chunk().await? {
            if chunk.len() > limit.saturating_sub(output.len()) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "HTTP body exceeds requested limit",
                )
                .into());
            }
            output.extend_from_slice(chunk.as_ref());
        }
        Ok(output)
    }
}

pub(crate) fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c))
}
pub(crate) fn valid_value(value: &str) -> bool {
    !value.bytes().any(|c| matches!(c, b'\r' | b'\n' | 0))
}
pub(crate) fn valid_url(value: &str, schemes: &[&str]) -> bool {
    value.len() <= 64 * 1024 && valid_value(value) && schemes.iter().any(|p| value.starts_with(p))
}
pub(crate) fn validate_headers(headers: &Headers) -> Result<(), Error> {
    if headers.len() > 256
        || headers
            .iter()
            .any(|(n, v)| !valid_token(n) || !valid_value(v))
        || headers
            .iter()
            .map(|(n, v)| n.len() + v.len())
            .sum::<usize>()
            > 48 * 1024
    {
        return Err(Error::invalid("invalid or oversized HTTP headers"));
    }
    Ok(())
}

#[cfg(feature = "tokio")]
impl tokio::io::AsyncRead for TlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        tokio::io::AsyncRead::poll_read(Pin::new(&mut self.0), cx, buf)
    }
}
#[cfg(feature = "tokio")]
impl tokio::io::AsyncWrite for TlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(Pin::new(&mut self.0), cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_flush(Pin::new(&mut self.0), cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_shutdown(Pin::new(&mut self.0), cx)
    }
}
#[cfg(feature = "tokio")]
impl tokio::io::AsyncRead for HttpBody {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        tokio::io::AsyncRead::poll_read(Pin::new(&mut self.0), cx, buf)
    }
}
#[cfg(feature = "futures-io")]
impl futures_io::AsyncRead for TlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        self.0.poll_read_slice(cx, buf)
    }
}
#[cfg(feature = "futures-io")]
impl futures_io::AsyncWrite for TlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        futures_io::AsyncWrite::poll_write(Pin::new(&mut self.0), cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        futures_io::AsyncWrite::poll_flush(Pin::new(&mut self.0), cx)
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        futures_io::AsyncWrite::poll_close(Pin::new(&mut self.0), cx)
    }
}
#[cfg(feature = "futures-io")]
impl futures_io::AsyncRead for HttpBody {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        self.0.poll_read_slice(cx, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_client_futures_support_multithreaded_executors() {
        fn send<T: Send>(_: T) {}
        fn check(client: &BrowserClient, socket: &mut WebSocket) {
            send(client.get("https://example.com/"));
            send(client.connect_tls("example.com", 443));
            send(client.connect_websocket(WebSocketRequest::new(
                "wss://example.com/",
                "https://example.com",
            )));
            send(socket.send(Message::Binary(Vec::new())));
            send(socket.recv());
            send(socket.close(1000, ""));
        }
        let _: fn(&BrowserClient, &mut WebSocket) = check;
        send(BrowserClient::new(BrowserConfig::default()));
    }

    #[test]
    fn request_validation_rejects_injection_and_invalid_navigation() {
        assert!(HttpRequest::get("file:///tmp/input").json().is_err());
        assert!(
            HttpRequest::get("https://example.com/")
                .header("x-test", "ok\r\ninjected: true")
                .json()
                .is_err()
        );
        assert!(
            HttpRequest::new("GET\nPOST", "https://example.com/")
                .json()
                .is_err()
        );
        let mut request = HttpRequest::post("https://example.com/", Vec::new());
        request.context = RequestContext::Navigation;
        assert!(request.json().is_err());
        assert!(
            HttpRequest::navigation("https://example.com/")
                .json()
                .is_ok()
        );
    }

    #[test]
    fn context_limits_are_checked_before_native_creation() {
        let mut config = BrowserConfig {
            io_workers: 0,
            ..BrowserConfig::default()
        };
        assert!(config.json().is_err());
        config.io_workers = 1;
        config.max_websocket_message = 0;
        assert!(config.json().is_err());
        config.max_websocket_message = 1024;
        config
            .force_http3_origins
            .push("http://example.com/".into());
        assert!(config.json().is_err());
    }
}
