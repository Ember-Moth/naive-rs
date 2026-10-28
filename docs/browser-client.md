# Native Chromium clients

## Scope and ownership

Keep `NaiveClient` and its CONNECT/padding/preamble policy intact. Add a separate
`BrowserClient` context for native TLS, HTTP and WebSocket operations. Both use
the same Chromium initialization and IO workers; a browser context must not use
Naive's enlarged HTTP/2 windows or proxy preambles for direct origin requests.
The new APIs are **direct-only**, as requested. They do not accept a proxy URL;
the existing Naive API remains the separate proxy entrypoint.
Rust owns public handles and futures. Chromium owns TLS, HTTP/1/2/3, connection
pooling, HTTP parsing and WebSocket framing. No Rust TLS/HTTP/WebSocket engine is
inserted on the origin connection.

The native ABI is **6**. Existing public
Naive stream APIs remain available, including owned IO and runtime adapters.
`TlsStream` reuses the established stream/lease machinery. `HttpResponse` exposes
headers and a bounded, pull-driven body. WebSocket reception is pull-driven and
message size is bounded. Dropping an unfinished operation cancels its native
work; shutdown waits for callbacks before releasing the context. Native callback
buffers never refer to suspended Rust stack frames.

## Public API shape

- `BrowserClient::new(BrowserConfig)` creates an isolated in-memory context.
- `connect_tls(host, port)` establishes origin TLS and reports negotiated ALPN.
- `execute(HttpRequest)` returns status, repeated headers, final URL, protocol
  and a streaming response body. Redirect and body limits are explicit.
- `connect_websocket(WebSocketRequest)` returns negotiated handshake metadata,
  text/binary message operations and a close handshake.
- Custom trust anchors and host DNS/socket/dialer hooks are context-local.
- `certificate_verifier` provides asynchronous Rust certificate decisions;
  `ech` configures direct ECH by hostname. See [TLS policy](tls-policy.md).

```rust,no_run
use naive::browser::{BrowserClient, BrowserConfig, HttpRequest, Message, WebSocketRequest};

# async fn example() -> Result<(), naive::Error> {
let client = BrowserClient::new(BrowserConfig::default()).await?;

// General HTTP: caller headers plus native UA, compression, TLS and HTTP stack.
let response = client.execute(
    HttpRequest::post("https://example.com/upload", b"payload".to_vec())
        .header("content-type", "application/octet-stream")
).await?;
let status = response.status;
let bytes = response.bytes(2 * 1024 * 1024).await?;

// An explicit navigation header profile; no browser application is launched.
let response = client.navigate("https://example.com/").await?;
let html = response.bytes(4 * 1024 * 1024).await?;

let mut socket = client.connect_websocket(WebSocketRequest::new(
    "wss://example.com/socket", "https://example.com"
)).await?;
socket.send(Message::Text("hello".into())).await?;
let reply = socket.recv().await?;
let closed = socket.close(1000, "complete").await?;

client.shutdown().await?;
# Ok(())
# }
```

Enable `features = ["tokio"]` or `features = ["futures-io"]` to use those IO
traits on `TlsStream` and `HttpBody`. The operations themselves do not need a
Tokio reactor. `TlsStream` also exposes the existing owned-buffer/read-lease
methods through its stream core. Its ALPN offer follows the native HTTP policy,
so inspect `info().protocol` before sending an application protocol. Raw TLS
does not expose an independent write FIN: `shutdown_write` reports Unsupported;
use `close` or `close_after_flush` for full stream closure.

### HTTP behavior

Uploads are owned byte buffers, limited to 64 MiB. `None` and an explicitly empty
body remain distinct. Response metadata is limited to 64 KiB and preserves
repeated response headers. Request header names use Chromium's overwrite
semantics. Native reads are pull-driven in chunks of at most 64 KiB;
`HttpBody::read_owned` lends caller storage through the final native IOBuffer
release, including on cache hits. `bytes(limit)` rejects oversized bodies.

`RedirectPolicy::Follow(n)` follows at most `n` redirects, with Chromium's
method/body transformations. Cross-origin redirects remove explicit
Authorization, Proxy-Authorization, Cookie and Host headers. `Manual` returns
the redirect status/headers with an empty body. Cookies and the bounded memory
cache are per context. Dropping a request future or response body cancels it.
The configured connect timeout covers response-header readiness; body reads can
have their own deadlines. Retained read leases remain valid after shutdown.

### Certificates and HTTP/3

`BrowserConfig::extra_root_certificates` contains PEM trust anchors for the
direct origin connections. It does not change the system store or bypass
certificate-chain/hostname checks. HTTP/3 normally follows Chromium's Alt-Svc
and certificate policies. Chromium imposes an additional known-root restriction
for automatically selected QUIC alternatives.

For an explicitly selected private-CA HTTP/3 origin, configure both the PEM
anchors and `force_http3_origins`, for example `https://localhost:8443`. Entries
must be HTTPS origins with no path beyond `/`, query or fragment. This is an
explicit protocol/profile override; it does not disable certificate validation.
The local suite verifies that the trusted H3 origin succeeds and the same
forced origin with no trusted anchor fails.

### WebSocket behavior

`WebSocketRequest` requires an explicit HTTP(S) Origin and optional subprotocols.
Chromium handles handshake validation, masking, UTF-8, fragments and control
frames. Poll `recv` to drive incoming traffic and automatic Pong responses.
`into_split` provides independently owned send and receive halves.

The message limit defaults to 16 MiB, with a 64 MiB maximum. Decoded messages
already present in one native read batch are bounded to twice the configured
payload limit and 1024 messages. A canceled receive keeps any arriving message
for the next receive. Canceling a submitted send aborts the channel, because
delivery cannot safely be inferred. Canceling a close waiter leaves the native
close handshake running; a later close call observes its result. An abnormal
peer close produces an error and retains its close metadata in `close_frame()`.
Client close codes follow the browser API: 1000 or 3000–4999, with at most 123
UTF-8 bytes of reason text. Dropping the last handle aborts remaining work.

The first browser profile uses the pinned Chromium version, its HTTP session
defaults, native user-agent generation and supported compression. Browser
request context remains explicit: a general native HTTP client cannot infer a
document's navigation, origin, user activation or Client Hints permissions.
`HttpRequest::navigation` selects a top-level GET/HEAD header profile. Ordinary
`get`/`execute` remain general HTTP requests. Navigation does not create a
document, execute JavaScript or perform renderer/subresource scheduling.

## Fingerprint acceptance

The target is network behavior matching a specified Chrome version, platform,
feature configuration and request scenario. A shared codebase is not itself a
passing result. Compare ClientHello and negotiated ALPN, HTTP/2 SETTINGS and
frame behavior, HTTP/3/QUIC parameters, request headers, WebSocket handshake and
extension negotiation. Normalize only genuinely variable values such as random
nonces, key shares and session tickets; retain their presence and structure.

Local regression fixtures must exercise the actual Chromium entrypoints,
certificate success/failure, redirects, streaming/backpressure, cancellation,
shutdown and WebSocket close semantics. They must also rerun the established
Naive tests. A comparison report must say whether a real Chrome baseline was
provided and must never label an absent or partial baseline as a full match.
Browser JS/Canvas/WebGL identity is outside this network library.

`tests/browser.py` starts local TLS/HTTP/2/HTTP/3 and WebSocket origins. The Go
fixture records inbound TLS bytes and the HTTP/2 preface/frames before its
handler sees a request. `tests/network_profile.py` extracts the observed TLS
and HTTP fields and compares an explicitly supplied baseline. It rejects empty
captures rather than considering two absent profiles equal. TLS extension
order is retained for inspection, but a single permutation is not an invariant.

No full application, simulator or VM is needed for these library fixtures.

## Reproduce and compare

```sh
cargo xtask build --target aarch64-apple-darwin --jobs 8
python3 tests/browser.py --build-fixture --repeat 3
python3 -m unittest discover -s tests -p test_network_profile.py
```

`target/browser-runtime/` contains the runtime logs, source/native hashes, raw
loopback observations and extracted navigation profiles. The Go fixture is only
a test server; the shipped library has no Go, rustls, Hyper or Tungstenite
dependency. The initial host result is in `browser-runtime-results.json`.

To obtain a real Chrome baseline separately, serve the same origin using a
certificate that the chosen browser already trusts. This command only starts
the local test server; it never starts a browser or changes trust settings:

```sh
python3 tests/browser.py --serve-only --cert localhost.pem --key localhost-key.pem \
  --output target/chrome-baseline
```

Visit the printed HTTPS origin's `/profile` in the selected Chrome version and
platform, then stop the fixture and extract the navigation request:

```sh
python3 tests/network_profile.py extract target/chrome-baseline/capture.jsonl \
  --protocol HTTP/2.0 --require-header sec-fetch-mode=navigate \
  --label 'Chrome VERSION PLATFORM' --output target/chrome-baseline/profile.json
python3 tests/network_profile.py compare target/chrome-baseline/profile.json \
  target/browser-runtime/http2-profile.json --output target/network-comparison.json
```

The comparison includes the observed TLS parameter lists, stable extension
payloads, header order, initial H2 SETTINGS/window increment and header END_STREAM
flag. It does not establish equivalence of extension permutation distributions,
session resumption/0-RTT, QUIC transport parameters, priorities, timing or packet
sizes. High-entropy Client Hints permission policy, Fetch/CORS, browser disk
cache, HSTS preload configuration and renderer scheduling are not reproduced by
this library. Shared initialization still enables the existing Naive runtime's
network-isolation and QUIC IO features; they must be accounted for in a strict
Chrome configuration comparison. No real Chrome baseline was collected as part
of the local library-only tests.
