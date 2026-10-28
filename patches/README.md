# Patch queue

Base: upstream NaïveProxy `v154.0.8037.49-5`, commit
`d04efe1ea4477c2db24a7d0e2f068b3bee931e45`.

1. **0001-extract-network-context.patch** moves the existing URLRequestContext
   construction functions from the CLI into `naive_context.{h,cc}`. The CLI uses
   the same functions. An optional verifier parameter allows per-client extra
   trust anchors without modifying system trust.
2. **0002-library-build.patch** exposes `naive_core` as a reusable source set,
   keeps the CLI target, and registers the `naive_rs` overlay build targets.
3. **0003-lazy-padding-buffers.patch** allocates padding read scratch only when
   needed, sizes it to the read request, releases it after the padding phase,
   and sizes padded-write scratch to the actual frame. Wire framing and padding
   distributions are unchanged.
4. **0004-cache-compiled-root-data.patch** shares the parsed representation of
   immutable, compiled-in Chrome roots. Cache entries are separated by the MTC
   and test-root feature switches used during parsing. Explicit component root
   data bypasses the cache; user CA anchors, verifier result caches, certificate
   fetchers and connection state remain per-client.

The bridge lives in `native/` rather than being embedded into a large patch.
Apply patches only to prepared source copies, in `series` order. Never apply them
directly to the submodule. `cargo xtask check-patches` verifies the complete
sequence against a fresh archive of the pinned commit.

When editing an existing patch, regenerate it against the state immediately
before that patch; run the complete queue check afterwards. Update the recorded
base and `upstream.lock.json` together when upgrading.

5. **0005-context-network-hooks.patch** adds an optional context-builder callback
   for library-owned DNS/socket factories, plus per-instance TCP/UDP socket
   controls before connect. CLI callers leave the callback unset.
6. **0006-cancel-abandoned-preamble.patch** adds explicit preamble cancellation,
   so library owners can cancel orphaned connection attempts without leaving
   them warming a socket pool. Ordinary CLI preamble destruction is unchanged.

7. **0007-ios-extra-roots.patch** preserves SecTrust as the iOS default while
   enabling the optional builtin verifier for explicitly supplied client roots.
8. **0008-ios-certificate-network-policy.patch** passes the network-fetch policy
   to SecTrust so proxy verification can prohibit dependent network requests.
9. **0009-ios-user-agent-platform.patch** obtains iPhone/iPad form factor through
   UIKit without requiring the Chromium UI tree in this native-only checkout.
10. **0010-ios-uppercase-symbol.patch** aligns the existing CoreFoundation
    uppercase implementation with the symbol declared by the current network
    library, fixing final linking of the iOS archive.
11. **0011-android-macos-host.patch** permits the trimmed native Android build
    to use a macOS host and its installed NDK; no Android application tooling is
    added to the native dependency graph.
12. **0012-proxy-connection-info.patch** exposes proxy-hop protocol and TLS
    metadata separately from the tunneled origin's existing socket interface.
13. **0013-network-context-options.patch** adds per-context HTTP/2 receive
    windows, QUIC initial windows/local congestion options, and host-scoped ECH
    mode while preserving unset upstream defaults.
14. **0014-android-archive-link.patch** disables Chromium loader code-ordering
    anchors in the embedded Cronet-style build, keeping the exported Android
    archive independent of source-tree linker scripts at the final Rust link.
    It also removes the Java-stack lookup from fatal logging; native stacks and
    Android logcat output remain available without initializing a JVM.

15. **0015-connect-half-close.patch** adds opt-in H2/H3 write-direction FIN
    while retaining reads. Unsupported sockets explicitly return an error;
    upstream CLI callers that do not opt in retain their existing close policy.
`0016-release-synchronous-http-read-buffer.patch` makes the synchronous HTTP
cache read path release its IOBuffer reference, matching the async path. This
lets owned response reads return after the final native reference disappears
without disabling the HTTP cache or weakening buffer lifetime guarantees.

`0017-scope-cross-host-connection-pooling.patch` adds an opt-in SSL policy hook
for cross-host H2/H3 connection coalescing. Direct contexts with certificate
callbacks or explicit ECH rules use it to require verification under each
destination hostname's policy. Default contexts retain existing pooling.
