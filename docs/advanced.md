# Advanced stream and transport APIs

These APIs extend the native-backed stream library. Validation follows the
requested compile/link scope; API and regression fixtures are compiled without
launching an application, emulator or VM.

## Early streams and explicit readiness

`NaiveClient::connect_early(host, port)` starts a CONNECT attempt and returns its
`NaiveStream` immediately. `stream.handshake().await` waits for proxy negotiation
and padding readiness. The IO adapters wait for the same readiness before
reading or accepting application writes. This API does not enable TLS 0-RTT.
Dropping the stream cancels it. Canceling only the handshake future leaves the
stream available for a later handshake/read/write attempt.

`connect(host, port).await` remains the convenience form that waits before
returning the stream. The configured native CONNECT timeout covers resolution,
dialing, preamble and proxy negotiation.

## Read/write deadlines

`set_read_deadline`, `set_write_deadline` and `set_deadline` accept
`Option<std::time::Instant>`. `None` clears a deadline. Expiry returns a timeout
for the affected operation and wakes its waiter without closing the stream.
A canceled or expired read retains received data for subsequent reads.

Accepted buffered writes continue to progress after a write deadline expires;
the deadline controls waiting and accepting more bytes. Call `close()` to abort
queued work. `flush()` observes completion of all accepted bytes.

Use `stream.deadline_handle()` to obtain a clonable controller before splitting
the stream. It can update deadlines while read/write futures are pending on
other tasks. It holds weak references and does not prolong the stream, client
or buffer lifetime. Deadline changes and native timer updates are serialized so
concurrent controllers cannot leave the native timer behind the Rust deadline.
CONNECT readiness has its own timeout; stream IO deadlines do not alter it.

## Connection information, counters and events

- `stream.info().await` reports the protocol used by the CONNECT proxy, local and
  peer endpoints, TLS wire version/cipher, ECH acceptance and payload byte counts.
  It requires a successful handshake. Protocol/TLS metadata is captured from
  the actual proxy socket, separately from the tunneled origin's metadata.
- `client.stats().await` reports logical CONNECT attempts, successes, failures,
  closed/active streams and native payload byte totals. It remains available
  after shutdown. Counters exclude HTTP framing, TLS and Naïve padding overhead;
  they are not counts of physical TCP connections or multiplexed sessions.
- `Config::observer` accepts an `Arc<dyn Observer>` (closures work). Events cover
  stream start/readiness/error/close, connection resets and completed shutdown.
  Credentials and payload contents are not included. Callbacks may arrive on
  caller, control or native IO threads and may run concurrently. Return promptly
  and forward expensive work to the host; do not synchronously wait for a client
  operation inside a callback. Callback panics are contained.

## Network parameters

Unset fields retain upstream defaults. `Config::http2` exposes stream and
connection receive windows. The stream window accepts 1..=2^31-1 bytes; the
connection window accepts 65535..=2^31-1 bytes.

`Config::quic` exposes initial stream/session receive windows, each in
16384..=2^62-1 bytes. Upstream flow-control adaptation may grow them later.
`QuicCongestionControl` selects Default, Bbr, Bbr2, Cubic or Reno for the local
sender. It does not change the proxy server's congestion controller. Settings
can change traffic characteristics and should be selected for the actual link.

## ECH

`Config::ech = Some(EchOptions::default())` requires ECH for the outermost
HTTPS/QUIC proxy, using its DNS HTTPS record. Supply `config_list` for a static
serialized ECHConfigList, or `query_name` to query another DNS name while keeping
the proxy's actual address and TLS hostname. Static address-mapping rules apply
to address resolution; HTTPS-record lookup uses the configured query name
directly through the same DNS backend. The two sources are mutually
exclusive. Nonstandard proxy ports retain the `_port._https.` record prefix.

The default configured mode is `Strict`: missing/unusable configuration or a
failed ECH negotiation cannot silently establish a non-ECH connection.
`Opportunistic` explicitly permits Chromium's fallback behavior, while
`Disabled` disables ECH for that proxy. `None` preserves the ordinary upstream
policy without introducing an additional lookup.

ECH requires a DNS hostname in the proxy URL. Use address mapping or a custom
resolver when dialing a fixed IP. The policy applies to the outermost secure
hop; a repeated same-host inner hop is rejected because the host-scoped TLS
policy cannot distinguish it.

With a custom `NetworkConfig::resolver`, HTTPS-record requests use the same
host callback with `ResolveQuery::HttpsRecord`. Respond with
`ResolveCompletion::complete_https`, returning the serialized ECHConfigList.
An address-only callback does not implicitly fall back to system DNS for ECH.
Without a host callback, discovery uses Chromium's built-in DNS support where
available. Hosts whose native DNS integration cannot retrieve HTTPS records
must provide the callback or a static list. Discovery does not change the
configured proxy IPs based on HTTPS-record address hints or target redirects.

Owned IO, runtime adapters and directional-close contracts are documented in
[owned IO](owned-io.md). Owned-operation cancellation and deadlines may abort the
stream; the borrowed IO deadline behavior described above remains unchanged.
