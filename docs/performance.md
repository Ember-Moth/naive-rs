# Performance implementation and validation

These results are from the local macOS arm64 host. They verify the changes below; they are not a WAN, device VPN, or universal Rust-versus-Go performance claim. The default native profile remains `portable`.

## Scope completed

| Gap | Change / evidence |
|---|---|
| Two write-side copies | Caller bytes are copied once into a reusable native allocation; ownership is transferred directly to the IO sequence. No intermediate C++ vector/payload copy remains. |
| Two read-side copies | Native completions transfer a refcounted read lease. Rust copies only into the caller buffer. The lease survives canceled futures and native context shutdown. |
| Repeated/fixed payload allocation | Read buffers use 4–64 KiB size classes; read and two write buffers are reused. Padding scratch is lazy, appropriately sized, and released after the padding phase. Steady small-IO regression checks allocation counts and capacity. |
| Spurious wakeups | Read events wake readers; write events wake capacity/flush waiters only when the corresponding condition changes. A deterministic direction-isolation test covers this. |
| Global IO-thread bottleneck | `Config::io_workers` selects a lazily created shared pool (1–8); each client keeps stable sequence affinity. Independent clients can run in parallel without adding tunnels. Measured 1/2/4-worker results are below. |
| Hot client lock/map | The callback context directly owns a stream reference until the final DESTROYED event. The global callback map and exclusive handle mutex are removed. An atomic admission gate orders shutdown; a short per-stream ownership/waker lock remains. |
| Small writes | One in-flight plus one queued batch coalesces small writes, progresses without a timer/explicit flush, and is bounded to two 64 KiB payload buffers. Vectored writes use the same path. |
| Client churn | One control worker replaces per-close threads and per-init Tokio blocking tasks. Compiled roots are parsed once per relevant feature combination; user trust and verifier state remain isolated. |
| Release tuning | Native PGO and Rust ThinLTO were built and measured. No consistently better general profile emerged; native PGO regressed HTTP/2 workloads. Native ThinLTO is incompatible with this host default linker. Defaults were kept deliberately. |
| Missing measurements | A reproducible interleaved runner now records throughput, client CPU, RTT percentiles, RSS, native buffer counters, churn and bounded-duration soak data. |

The native ABI is now **2**. Wrapper copies above exclude TLS/HTTP framing, encryption, and initial protocol padding copies. The buffer limits apply to bridge payload storage, not the entire Chromium protocol stack or its flow-control windows.

## Controlled baseline → final comparison

Both Rust builds use Chromium `154.0.8037.49`, the same local Caddy/echo fixture, one native IO worker and four Tokio workers. Each final run transfers 512 MiB for bulk or 128 MiB for small-write cases. Variants were interleaved in deterministic randomized order; numbers below are medians of three runs. The baseline source/archive were frozen before optimization. [Raw runs and executable hashes](performance/results/comparison.json).

| Transport / workload | Baseline | Final | Change | Client CPU change |
|---|---:|---:|---:|---:|
| https / 1 stream, 64 KiB writes | 663.1 MiB/s | 902.4 MiB/s | +36.1% | -18.7% |
| https / 16 streams, 64 KiB writes | 569.3 MiB/s | 603.8 MiB/s | +6.1% | -3.0% |
| https / 128 streams / 4 clients | 411.8 MiB/s | 422.5 MiB/s | +2.6% | -4.7% |
| https / 16 streams, 1 KiB writes | 93.8 MiB/s | 315.5 MiB/s | +236.3% | -70.8% |
| quic / 1 stream, 64 KiB writes | 210.0 MiB/s | 212.6 MiB/s | +1.2% | -1.4% |
| quic / 16 streams, 64 KiB writes | 178.1 MiB/s | 182.5 MiB/s | +2.5% | -4.7% |
| quic / 128 streams / 4 clients | 155.5 MiB/s | 162.5 MiB/s | +4.5% | -7.9% |
| quic / 16 streams, 1 KiB writes | 55.2 MiB/s | 132.6 MiB/s | +140.4% | -62.3% |

Throughput is one-way application payload echoed back. CPU is process user+system time for the measured transfer. Small-write improvements are substantial; changes of a few percent should be treated cautiously given the loopback workload and host scheduling noise.

| Transport / measurement | Baseline | Final |
|---|---:|---:|
| https / client create + shutdown, P50 | 1.71 ms | 0.21 ms |
| https / 128 idle/read-waiting streams, RSS | 28.91 MiB | 23.41 MiB |
| https / single-stream 64-byte RTT, P50 | 64.71 µs | 64.12 µs |
| https / 16-stream 64-byte RTT, P99 | 444.58 µs | 427.38 µs |
| quic / client create + shutdown, P50 | 1.71 ms | 0.21 ms |
| quic / 128 idle/read-waiting streams, RSS | 30.83 MiB | 25.28 MiB |
| quic / single-stream 64-byte RTT, P50 | 74.58 µs | 74.79 µs |
| quic / 16-stream 64-byte RTT, P99 | 480.71 µs | 466.29 µs |

Churn uses a custom test CA. Sampling identified repeated parsing of compiled roots in the default certificate-verifier path as a major cost. Patch 0004 caches only immutable parsed compiled data, keyed by the MTC/test-root feature switches; explicit component root data bypasses it. Per-client CA isolation, hostname checks and untrusted-root rejection passed over both transports.

## Native IO worker policy

One connection/session remains on one worker. Client clones share their engine; create independent clients to use multiple workers. No extra proxy sessions are created merely by increasing the pool width. These are medians of three runs of the same final implementation. [Raw worker sweep](performance/results/io-workers.json).

| Transport / workload | 1 worker | 2 workers | 4 workers |
|---|---:|---:|---:|
| https / 128 streams / 4 clients | 512.50 MiB/s | 705.83 MiB/s | 1100.58 MiB/s |
| https / 128-stream RTT P50 | 1322.12 µs | 1117.92 µs | 1060.75 µs |
| https / 512 idle streams / 8 clients RSS | 34.22 MiB | 34.06 MiB | 34.00 MiB |
| quic / 128 streams / 4 clients | 192.88 MiB/s | 218.42 MiB/s | 209.40 MiB/s |
| quic / 128-stream RTT P50 | 1547.17 µs | 1158.04 µs | 1092.62 µs |
| quic / 512 idle streams / 8 clients RSS | 39.14 MiB | 39.36 MiB | 37.44 MiB |

More workers trade CPU/scheduling cost for parallelism. Four workers substantially improved the multi-client HTTP/2 throughput on this host; QUIC bulk favored two in this sweep. The conservative default is still one, with an explicit tuning option.

## Release-profile experiments

[Profile measurements](performance/results/build-profiles.json) compare the same data-path implementation with portable native code, Chromium browser PGO data, and Rust ThinLTO/codegen-units=1. The profile sweep preceded the final compiled-root cache refinement, so its churn numbers are not the final implementation’s initialization results.

- Browser PGO increased HTTP/2 CPU time by roughly 9–41% in the measured bulk/small-write cases. It is available only as an explicit experimental profile, not enabled by default.
- Rust ThinLTO had mixed small effects and no stable overall win; it was not made the default.
- A minimal native ThinLTO archive could not link through the host Apple linker (`Invalid summary version 14`, supported range `1–12`). [Compatibility record](performance/results/native-thinlto.txt). Native ThinLTO remains disabled to preserve normal Cargo consumer linking.

A final-source PGO recheck also covered bulk, small writes and parallel client churn. Values below are throughput in MiB/s, except churn is P50 µs. It confirms that PGO is not a uniformly better default. [Final-source profile runs](performance/results/build-profiles-final.json).

| Workload | Portable | PGO | PGO client CPU change |
|---|---:|---:|---:|
| https / bulk-16-64k | 481.31 | 420.93 | +13.5% |
| https / small-16-1k | 294.37 | 191.42 | +39.9% |
| https / churn-parallel-32 | 6563.38 | 6459.50 | -1.2% |
| quic / bulk-16-64k | 174.81 | 180.61 | -1.3% |
| quic / small-16-1k | 142.12 | 148.35 | -2.5% |
| quic / churn-parallel-32 | 6602.21 | 6708.08 | +1.6% |

## Soak, cancellation and fixture limits

Final soak runs used 32 streams, four clients/workers, 4 KiB ping-pong, frequent canceled reads, and about one staggered reconnect per second per stream. Each transport ran for 60 seconds. [Raw samples](performance/results/soak.json).

| Transport | Payload echoed | RSS first → last sample | Peak bridge capacity | Live bridge buffers after shutdown |
|---|---:|---:|---:|---:|
| https | 17.49 GiB | 21.42 → 21.55 MiB | 256 KiB | 0 |
| quic | 7.47 GiB | 23.09 → 23.36 MiB | 260 KiB | 0 |

This bounded-duration test showed no sustained RSS growth and no surviving bridge payload allocations after shutdown. It is not a claim of days-long production validation. Chromium globals/workers and immutable compiled roots intentionally remain process-lifetime resources.

The earlier reconnect-every-127-messages workload exceeded the fixture’s available outgoing TCP addresses after roughly 16,000 upstream connections. Diagnostic logging around Caddy’s original dialer recorded `connect: can’t assign requested address`; CONNECT 200 precedes dialing in that server, explaining the client EOF. No host socket settings were changed. The final fixed-time cadence preserves transfer/cancellation pressure while keeping reconnection pressure comparable across faster/slower variants. [Failure record](performance/results/soak-fixture-limit.json).

The new shutdown-race test also found a terminal-cancellation mapping issue: Chromium `ERR_ABORTED` must map to `ConnectionAborted`, not retryable `Interrupted`. Otherwise `write_all()` can spin forever after cancellation. This was fixed and is covered by the regression suite.

## cronet-go reference

The optional reference pins `SagerNet/cronet-go` commit `0d28acc44093df24b2526dea3d6ffefd6b0a54f0`, Chromium 150, CGO and its prebuilt native archive. [Build provenance](performance/results/reference-build.json). It differs in Chromium version, native flags, trust-store construction and threading. In particular, multiple Go clients have separate Cronet network threads, whereas the main Rust comparison deliberately used one shared IO worker.

| Transport / workload | Final Rust default | cronet-go reference |
|---|---:|---:|
| https / single-stream bulk | 902.37 MiB/s | 620.26 MiB/s |
| https / 128 streams / 4 clients | 422.50 MiB/s | 739.36 MiB/s |
| https / 1 KiB writes / 16 streams | 315.55 MiB/s | 131.31 MiB/s |
| https / 64-byte RTT P50 | 64.12 µs | 1569.62 µs |
| quic / single-stream bulk | 212.59 MiB/s | 160.70 MiB/s |
| quic / 128 streams / 4 clients | 162.46 MiB/s | 184.55 MiB/s |
| quic / 1 KiB writes / 16 streams | 132.59 MiB/s | 56.11 MiB/s |
| quic / 64-byte RTT P50 | 74.79 µs | 75.58 µs |

Cronet’s HTTP/2 bidirectional-stream implementation intentionally buffers read notifications for 1 ms (`kBufferTimeMs`), explaining much of that reference’s small-message RTT. See the [pinned native source](https://github.com/SagerNet/naiveproxy/blob/72a06c9fca0e2d228588c7f3074bf7efff3ff686/src/net/spdy/bidirectional_stream_spdy_impl.cc). Do not attribute these reference differences to Rust versus Go alone.

## Reproduction and validation

See [tests/perf/README.md](../tests/perf/README.md) for build, A/B, worker-sweep, soak and optional reference commands. Result JSON retains per-run values, executable hashes and workload settings rather than only summary percentages.

Validation gates: clean patch application; macOS arm64 native build; Rust tests including wake direction, buffer ownership/reuse, queue backpressure, caller-buffer independence and shutdown races; Caddy HTTPS/QUIC success and trust/authentication negatives; Clippy with warnings denied; allocator-scribble stress; and the patched original CLI baseline tests. All these gates passed on the local host: eight Rust tests, real-server interop for both native profiles, allocator-scribble stress, and 52 upstream CLI cases (eight default-port cases skipped). [Validation receipt](performance/results/validation.json). Hosted CI has not been run.

Limits: macOS arm64 only, local loopback, one pinned upstream version. Other platforms, real VPN/device routing and WAN congestion/loss are not validated by these measurements. Functional gaps outside this performance task remain unchanged (for example custom DNS/dialer hooks and general async-runtime adapters).
