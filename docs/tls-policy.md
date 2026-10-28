# Certificate verification and ECH

Both `Config` (Naive proxy connections) and `BrowserConfig` (direct TLS, HTTP and
WebSocket connections) accept `certificate_verifier`. This is an asynchronous
Rust callback over Chromium's native server-certificate verifier. Native ABI 6
adds its completion/cancellation entrypoints; rebuild native artifacts together
with the Rust wrapper.

## Certificate decisions

Chromium first verifies the certificate using the context's normal trust store
and any `extra_root_certificates`. The callback receives owned DER chains, the
verification hostname, the original error/status, public-root status, stapled
OCSP response and SCT list. `certificate_chain` is the chain sent by the peer;
`verified_chain` is the chain Chromium built and can be incomplete on failure.

- `CertificateDecision::UseDefault` preserves the native result.
- `CertificateDecision::Reject` fails verification with `ERR_CERT_INVALID`.
- `CertificateDecision::Accept` explicitly overrides certificate errors. The
  caller takes responsibility for the trust, hostname, expiry and other
  certificate policies being overridden. It does not bypass TLS handshake
  signatures, ECH strict mode, or non-certificate errors. An overridden private
  certificate is not relabeled as publicly trusted.

For example, add an application pin check without weakening normal validation:

```rust,no_run
use naive::{CertificateDecision, CertificateInfo, CertificateVerification};
use naive::browser::BrowserConfig;
use std::sync::Arc;

# fn configure(pinned_leaf_der: Vec<u8>) -> BrowserConfig {
let mut config = BrowserConfig::default();
config.certificate_verifier = Some(Arc::new(
    move |info: CertificateInfo, done: CertificateVerification| {
        let pin_matches = info.certificate_chain.first() == Some(&pinned_leaf_der);
        done.complete(if pin_matches {
            CertificateDecision::UseDefault
        } else {
            CertificateDecision::Reject
        });
    }
));
# config
# }
```

The entrypoint runs on a native IO thread and must return promptly. Move `info`
and `done` to a host executor for slow work; no particular Rust runtime is
required. Complete exactly once, from any thread. Dropping a completion without
deciding rejects the certificate. Unwinding is caught at the Rust FFI entrypoint
and also rejects; an application compiled with panic=abort still aborts.

`done.cancellation()` provides a cloneable observer. Closing/canceling a native
verification sets it; the host should abandon unnecessary work. Native shutdown
does not wait for user work. Late completion after cancellation or context
destruction safely releases the token without changing any connection.
Verification belongs to a TLS connection, which the HTTP pool may share or
retain. Canceling one HTTP request does not necessarily cancel every associated
connection job while other operations remain active. When the client has no
remaining operations, pending host work is canceled; an unrelated active TLS,
HTTP or WebSocket operation is not aborted.

The callback runs for certificate verifications, not for every request. Existing
connections and TLS sessions can be reused. Treat policy as immutable for the
client lifetime; recreate the client when changing trust decisions. Direct
contexts with a callback disable H2/H3 connection coalescing across different
hostnames, so one host's decision cannot authorize another hostname without
verification. Same-host reuse remains enabled. Auxiliary certificate-fetch
connections use their existing native trust policy; the callback controls the
requested origin/proxy TLS connection and is not recursively installed on its
certificate-fetch context.

## ECH for direct clients

`BrowserConfig::ech` maps a DNS hostname to `EchOptions`. A rule applies to direct
TLS, HTTPS (including H3), and WSS connections to that hostname on any port.
Hostnames are canonicalized natively (including a trailing DNS dot), duplicate
canonical names are rejected,
and IP literals, wildcard rules and URL strings are not accepted. There are at
most 128 rules. Rules are fixed when the client is created.

```rust,no_run
use naive::{EchMode, EchOptions};
use naive::browser::BrowserConfig;

# fn configure(ech_config_list: Vec<u8>) -> BrowserConfig {
let mut config = BrowserConfig::default();
config.ech.insert("private.example".into(), EchOptions {
    mode: EchMode::Strict,
    config_list: Some(ech_config_list),
    query_name: None,
});
# config
# }
```

`config_list` is the serialized TLS ECHConfigList, including the two-byte list
length. Without a static list, discovery queries DNS HTTPS records for the rule's
hostname, or its explicit `query_name`. Non-default ports retain the
`_port._https.` prefix. Address mapping and alternate DNS query names do not
change the intended TLS hostname or select a different proxy/origin address.

If `NetworkConfig::resolver` is provided, the same callback handles address and
`ResolveQuery::HttpsRecord` queries. Complete the latter with
`ResolveCompletion::complete_https`. No implicit system fallback is made for a
custom resolver. Otherwise the native built-in DNS backend performs discovery
where the platform supplies DNS configuration; a static list or host resolver
works independently of that backend.

`Strict` requires ECH to succeed; missing configuration or final rejection fails
the connection. Authenticated server retry configurations remain supported.
`Opportunistic` permits Chromium's fallback behavior. `Disabled` suppresses ECH
for that hostname and cannot contain a static list or query name. Unconfigured
hosts keep Chromium's default behavior. An explicit rule set disables cross-host
H2/H3 coalescing to prevent a connection established under a different rule
from bypassing the destination's ECH policy. Redirects use the new destination's
rule, not the original host's configuration.

Naive's existing `Config::ech` applies to the outermost HTTPS/QUIC proxy. It has
the same source and mode choices; it does not configure the target inside the
CONNECT tunnel. ECH and certificate trust are independent. Private-CA direct
H3 origins still require `force_http3_origins` as described in
[browser-client.md](browser-client.md).

## Validation

`python3 tests/browser.py --build-fixture --repeat 3` runs the browser and security
suites against temporary loopback TLS/H2/H3 endpoints. The security fixture
generates an ephemeral X25519 ECH key, exposes only its public configuration to
the client, and records the server TLS stack's `ECHAccepted` result. Tests check
client metadata and successful application traffic, including WSS and Naive
CONNECT, along with certificate decisions, cancellation, authenticated retry,
strict rejection and host policy isolation. No browser app or system trust
modification is involved.

The recorded macOS arm64 run is in [tls-policy-runtime-results.json](tls-policy-runtime-results.json).
