# Host networking

`Config::network` provides four independent, client-local hooks. The same hooks
are installed in the proxy network context and the certificate-fetch context.
They do not install process-global DNS or alter the host network configuration.

| Hook | Role |
|---|---|
| `Resolver` | Resolve a hostname to IPv4/IPv6 addresses asynchronously. Errors never fall back to system DNS. Literal IPs need no callback. Static mapping rules apply before the callback. |
| `SocketControl` | Borrow each native-created TCP/UDP socket before it connects, for options, binding or VPN protection. Returning an error prevents the connection. |
| `TcpDialer` | Supply an owned, connected `std::net::TcpStream`; native TLS, proxy negotiation, pooling and data IO proceed on that socket. |
| `UdpDialer` | Supply an owned, bound `std::net::UdpSocket`. If it is connected, its chosen peer is retained; otherwise native connects it to the requested peer. Used for the outer QUIC transport. |

Hook entry points run on Chromium IO threads and must return promptly. For DNS
or dialing that may block, dispatch work to a host worker/executor and move the
completion there. The library does not force a host executor or create a thread
per request. Closures implementing the corresponding signatures can be used
directly inside `Arc`.

```rust,no_run
use naive::{Config, NaiveClient};
use naive::network::{ResolveRequest, ResolveCompletion};
use std::{net::IpAddr, sync::Arc};

let mut config = Config::new("https://user:password@proxy.example:443");
config.network.resolver = Some(Arc::new(
    |request: ResolveRequest, completion: ResolveCompletion| {
        // A host resolver can retain completion while dispatching async work.
        // This example supplies an already-known address synchronously.
        let address: IpAddr = "127.0.0.1".parse().unwrap();
        completion.complete(Ok(vec![address]));
    },
));
```

A custom resolver sees names required by the local transport and any permitted
certificate fetching. Chromium deliberately disables AIA/OCSP/CRL network
fetches while verifying proxy certificates to avoid recursive proxy resolution.
This wrapper preserves that policy: a server must present a usable chain, or
the missing issuer must be an explicit client trust anchor. Injecting hooks into
the separate certificate-fetch context does not enable these prohibited fetches. The target hostname of the remote CONNECT is still sent to the proxy;
it is not resolved locally solely because it is a CONNECT target. The callback
receives the requested address family; native also filters results by family.
When ECH discovery is configured, the same resolver receives
`ResolveQuery::HttpsRecord`; return an encoded ECHConfigList using
`complete_https`. The wrapper does not substitute IP hints from those records.

`SocketControl` receives a borrowed `Socket` implementing `AsFd` on Unix or
`AsSocket` on Windows, plus the transport and intended peer. Never close or retain
the raw descriptor. Native DNS may also create sockets for reachability probes;
control callbacks should use `SocketInfo` rather than assuming every socket is
a proxy TCP connection. Proxy connection failures can wrap a hook error as
`ERR_PROXY_CONNECTION_FAILED`; record hook diagnostics where the policy runs.
Custom dialers own socket creation and must apply their own
protection/binding before connecting: the control hook is not called after a
custom dial has already connected a socket.

## Ownership, cancellation and reset

A completion can move between threads and must be completed once. Dropping it
fails the request; panicking during a hook cannot unwind across the C ABI. A
`completion.cancellation()` observer reports native cancellation without keeping
the client alive. Native shutdown does not wait for blocked host work. A late
completion is safe: addresses are discarded and returned sockets are closed.
Keeping a completion indefinitely keeps only its request state; hosts should
release or finish abandoned work.

`close_all_connections().await` cancels active streams, retires preambles and
empties TCP/HTTP2/QUIC pools and native DNS caches. A host-supplied resolver
continues to own and manage its own caches. It preserves the client configuration,
credentials, trust settings and hooks. Await the barrier before starting new
connections on a changed network. Connections started concurrently may be
included in the reset. Once the reset future has been polled, dropping it does
not cancel the reset operation. Final `shutdown()` still makes the client unusable.

CONNECT timeouts run on the native IO sequence and include DNS, dialing,
preamble and proxy negotiation. They do not depend on a Tokio timer. They cancel
native work; they cannot forcibly terminate an arbitrary host callback/task.

Custom UDP dialing requires Chromium's asynchronous QUIC session creation path,
which this library enables at process initialization. An embedder that already
initialized Chromium with that feature disabled receives an initialization error
rather than an ignored callback.

## Verification boundary

The focused tests are `tests/network.rs`, `tests/runtime.rs` and the host-hook
cases in `tests/interop.rs`. The missing-intermediate certificate policy is checked by
`tests/aia.rs` with `python3 tests/aia_interop.py`. `python3 tests/interop.py` supplies the local Caddy
HTTPS/QUIC fixture. Passing these tests establishes local socket/transport
behavior; it does not establish Android VPN protection, iOS routing or a real
network-interface handover on a device.
