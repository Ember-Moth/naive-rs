# Functional gap implementation and evidence

Scope: implement the prioritized gaps from the naive-rs / cronet-go comparison.
The existing performance work in `performance.md` remains part of the baseline.
Native behavior stays in NaïveProxy/Chromium; the submodule remains clean and
changes to it are maintained as ordered patches.

All listed APIs and build/distribution workflows are implemented. ABI 4 adds
[generic owned IO and completion-runtime adapters](owned-io.md); its compilation
evidence is recorded separately in `owned-io-results.json`. Ten native
targets pass compilation, final Rust linking and packaging. Windows configuration
is supplied with native builds explicitly unverified, as requested.

Runtime results in the first four rows and the first P1 batch below refer to the
snapshot recorded in `functional-results.json`. Subsequent P2 and platform work
was initially validated by compilation/linking only. The later macOS arm64
owned-IO/runtime-adapter/half-close execution is recorded separately in
`owned-io-runtime-results.json`. Earlier cross-platform compilation snapshots
remain tied to their recorded revisions; this runtime pass does not replace them.

| Priority | Requirement | Current implementation | Evidence / remaining work |
|---|---|---|---|
| P1 | Custom dialing and socket control | Implemented; verified on macOS arm64 | 12 network tests plus Caddy HTTPS/QUIC success, rejection, cancellation, late owned-socket release and hook lifetime |
| P1 | Custom DNS | Implemented; verified on macOS arm64 | No system fallback for a rejected localhost resolution, mixed IPv4/IPv6 fallback, mapping rules, cancellation and client isolation. Proxy certificate network fetch remains disabled by upstream policy |
| P1 | Runtime independence | Implemented; verified on macOS arm64 | No Tokio in the no-default-features normal dependency tree; core and futures-io transfer/timeout/shutdown tests run without a Tokio runtime |
| P1 | Retain client while clearing connections | Implemented; verified on macOS arm64 | Existing streams fail, subsequent connections work, reset/shutdown races finish, pending UDP completion is canceled, HTTPS/QUIC reconnect tests pass |
| P1 | Platform support | Build recipes implemented for all 12 targets | Native build, Rust link and package pass for all 10 macOS/iOS/Android/Linux targets; both Windows native targets remain explicitly unverified |
| P1 | Native binary distribution | Package/fetch and release workflow implemented; final macOS source snapshot verified | Deterministic packaging, install/replace, 12 rejection cases and independent Rust consumer link pass; no remote release published |
| P2 | ECH | Static lists, HTTPS query names and strict/opportunistic/disabled policies implemented | Native/Rust linking passes on all 10 verified targets; runtime handshake fixtures were not run |
| P2 | Network tuning | HTTP/2 windows, QUIC initial windows and local congestion selection implemented with validation | Final native build and Rust linking pass on all 10 verified targets |
| P2 | Early connect and explicit handshake | Early handles, explicit handshake and automatic IO readiness implemented | Fixtures compile and link on all 10 verified targets; cancellation/close paths reviewed, no new runtime execution |
| P2 | Stream read/write deadlines | Native timers, independent deadlines and weak concurrent deadline controller implemented | macOS arm64 owned-read and backpressured-write deadlines execute successfully, including owner return and stream termination; earlier cross-platform evidence is compilation/linking |
| P2 | Observability | Structured events, native logical-stream counters and actual proxy protocol/TLS snapshots implemented | Final native build and Rust linking pass on all 10 verified targets |
| P2 | Owned buffer handoff | Generic buffer/guard contracts, native owned IO, local !Send copying fallback, read leases and split halves | 16 core runtime tests pass on macOS arm64, including pending and unobserved-completion cancellation, backpressure, remote reset, guard release and shutdown |
| P2 | Completion runtime adapters | Separate monoio and compio crates; no mandatory Tokio dependency | Four ordinary tests and one H2/H3 interop test per actual monoio/compio runtime pass on macOS arm64; local buffer access and Drop stay on the caller thread |
| P2 | Directional close | Opt-in H2/H3 FIN; explicit Unsupported on other transports | macOS arm64 runtime tests pass for FIN/response, empty and large payloads, repeated/canceled FIN waits and mixed write ordering, through core and both adapters |

General UDP forwarding and a generic HTTP client remain outside the selected
scope. Independent write close is now exposed for H2/H3 CONNECT streams. Custom UDP dialing controls the outer QUIC
socket; exposed Naïve streams continue to carry TCP payloads.

## Verified commands for the first P1 batch (2026-10-28)

- `cargo xtask build --jobs 8` — native ABI 3 archive and link probe built
- `cargo xtask check-patches` — all six patches apply to the pinned commit
- `cargo test --workspace --all-features --locked` — 23 tests pass; 3 fixture-only tests intentionally ignored here
- `cargo test -p naive-rs --no-default-features --locked`
- `cargo test -p naive-rs --no-default-features --features futures-io --locked`
- `cargo tree -p naive-rs --no-default-features -e normal`
- `python3 tests/interop.py` — both fixture tests pass, covering HTTPS and QUIC
- `python3 tests/aia_interop.py` — missing issuer rejected, explicit issuer accepted, no AIA fetch for either transport
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` — passes

The no-default-features suites run 2 core tests without adapters and 3 with
futures-io. Build/test logs are in `target/network-*.log`; the source fingerprint
and summarized results are recorded in `functional-results.json`.

The cancellation work also fixes abandoned connect jobs: streams use
`ResetAndCloseSocket`, preambles expose explicit cancellation, and pending host
operations are canceled before reset/shutdown completes. The host-completion
registry breaks the upstream asynchronous QUIC callback/socket ownership cycle.
Preamble completion is dispatched after the upstream callback returns, avoiding
retired-tunnel destruction inside that callback's stack.

The requested implementation and local compilation gate are complete. Exact
archive digests, source fingerprints, target lists and checks are recorded in
`platform-build-results.json`. The local checks did not publish a release. Remote CI status is recorded
separately in [GitHub Actions](https://github.com/Ember-Moth/naive-rs/actions).


The interleaved performance preservation check used the recorded prior optimized
binary (its SHA-256 was verified first). In the extended five-sample small-write
comparison, HTTPS throughput medians were 259.48 → 258.92 MiB/s and QUIC medians
were 99.12 → 97.54 MiB/s. Both variants showed substantial common drift, so these
samples are not a speedup claim. All measured bridge buffers were released after
shutdown. Raw measurements are under `functional/`.


Platform validation scope: compilation and final linking only. The temporary
Android image/AVD, iOS test device and Linux VM created during setup have been
removed. No complete-app or simulator runtime validation is required.

Current compilation evidence is recorded in `platform-build-results.json`.
Successful targets are macOS arm64/x86_64; Linux GNU arm64/x86_64; Android
arm64/x86_64/armv7; and iOS arm64 device plus arm64/x86_64 simulator ABIs. All
include the ECH, tuning, handshake, deadline and observability additions, with
one final native-source/build-tool fingerprint. Earlier link evidence is retained
only when the final archive SHA-256, linker metadata and GN arguments are exactly
unchanged; the record identifies those cases. No target application was executed.

The final macOS bundle passes deterministic packaging, fresh install/replacement,
12 rejection cases and a separate Rust consumer link. Linux toolchain setup also
passes a fresh download, SHA-256 validation and installation check. Default CI
and the native-artifact matrix compile/link test targets with `--no-run`.
