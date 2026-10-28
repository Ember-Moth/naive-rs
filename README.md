# naive-rs

Rust asynchronous TCP streams backed by the native NaïveProxy/Chromium network
stack. This is a library, with no application entrypoint or local proxy listener.
The `xtask` binary is a development/build tool only.

NaïveProxy is pinned as a clean Git submodule. Ordered patches extract its network
context and add reusable build targets. The C++ bridge uses the upstream proxy
delegate, socket pools, padding socket and browser preamble implementation.
Rust provides ownership, cancellation and optional Tokio/futures-io adapters.

## Build

Prerequisites: Rust 1.85+, Python 3, Ninja, Git, curl, tar and unzip. macOS needs
Xcode. The native preparation command downloads the pinned Chromium Clang/GN
toolchain and required target headers/libraries. Some upstream setup paths also
fetch their PGO bundle. Ordinary `cargo build` does not
download or build Chromium or modify the submodule.

```sh
git submodule update --init --recursive
cargo xtask check-patches
cargo xtask toolchain
cargo xtask build --jobs 8
cargo test --workspace --all-features --no-run --locked
```

Build recipes cover macOS, Linux GNU, Android, iOS and Windows MSVC targets;
list them with `cargo xtask targets`. A configured recipe is not proof that every
target has built successfully. See [platform requirements and validation](docs/platforms.md).
Cross-platform acceptance is native compilation and final Rust linking; no
emulator, VM image or complete application test is required.

Use `--target <Rust triple>` consistently for `xtask toolchain`, `xtask build`
and Cargo cross compilation. Artifacts are placed in
`target/native/lib/<triple>/`. `NAIVE_NATIVE_DIR` can select a directory containing
`libnaive_native.a` and its `manifest.json`. The build script validates the ABI,
target, archive digest and, in a source checkout, the native source/patch digest.

The native ABI is version 4. Rebuild the native artifact after updating from an
earlier wrapper; the build script rejects mismatched artifacts.

The default `portable` native profile keeps PGO and native ThinLTO disabled.
`cargo xtask build --native-profile pgo` creates an experimental PGO artifact in
`target/native/lib/<triple>/pgo/`; select it explicitly with `NAIVE_NATIVE_DIR`.
This profile is for measurement, not a recommendation: the current browser PGO
data regressed several proxy workloads. See [performance results](docs/performance.md).

This checkout is intended for workspace/path dependencies. A Cargo package alone does not contain Chromium or fetch its Git submodule.
The native archive packaging, verified download and release workflow are described
in [native distribution](docs/native-distribution.md).

## Use

Depend on `crates/naive` (Cargo package `naive-rs`, Rust library name `naive`) and
Tokio with the opt-in IO adapter (native networking itself needs no Tokio reactor):

```toml
[dependencies]
naive-rs = { path = "/path/to/naive-rs/crates/naive", features = ["tokio"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread", "io-util"] }
```

```rust,no_run
use naive::{Config, NaiveClient};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = NaiveClient::new(Config::new(
        "https://user:password@proxy.example.com:443",
    )).await?;
    let mut stream = client.connect("example.com", 80).await?;
    stream.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n").await?;
    stream.flush().await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    drop(stream);
    client.shutdown().await?;
    Ok(())
}
```

`https://` uses the upstream HTTPS proxy path; `quic://` selects HTTP/3. HTTP and
SOCKS upstreams and upstream-supported proxy chains are also accepted. These
remain **TCP streams**, including when the transport is QUIC. Proxy usernames and
passwords must be URL-encoded. Configuration `Debug` output redacts credentials.

`Config::extra_root_certificates` adds client-local PEM trust anchors, without
changing the system store or disabling hostname/chain validation. When configured,
verification uses Chromium's builtin verifier and Chrome roots plus the extra
anchors. Otherwise the upstream platform-default verifier is used.

Optional `Config::net_log` writes bounded NDJSON diagnostics and flushes them
before shutdown completes. Chromium NetLog capture is process-wide: it can
include network metadata from other clients active during the capture interval.

## Host networking and runtime adapters

`Config::network` accepts independent custom address resolution, socket control,
TCP dialing and UDP dialing hooks. They apply to both proxy connections and
certificate fetches. `NaiveClient::close_all_connections().await` closes active
streams and pooled connections and clears DNS caches while retaining configuration.
See [host networking and cancellation](docs/networking.md).

Default features are empty. The opt-in `tokio` feature supplies Tokio IO traits. Use
`default-features = false, features = ["futures-io"]` for futures-io, or disable
both features and drive the stream's `poll_read_slice`, `poll_write_slices`,
`poll_flush_pending` and `poll_close_stream` methods with an executor that supports
native-thread wakeups. The monoio adapter enables its required `sync` support. Creation,
CONNECT timeouts, cancellation and shutdown do not require a Tokio runtime.

`connect_early()` and `NaiveStream::handshake()` separate stream creation from
CONNECT readiness. Streams also expose read/write deadlines, a weak deadline
controller for split IO, and native connection information. Client counters and
structured lifecycle events are available through `stats()` and `Config::observer`.
ECH and HTTP/2/QUIC tuning are documented in [advanced APIs](docs/advanced.md).

Optional `naive-monoio` and `naive-compio` crates adapt the same core to their
completion-based IO traits, including local `!Send` buffers. Native owned IO and
immutable read chunks avoid staging payload copies; their cancellation and
memory-accounting contracts are documented in [owned IO](docs/owned-io.md).

## Ownership and async behavior

- One shared control worker performs native initialization and teardown.
  Canceled initialization requests that have not started are skipped; completed
  contexts are destroyed even if their waiting future has been dropped.
- `connect()` waits for CONNECT and padding negotiation, with a configurable
  timeout (30 seconds by default). Dropping the future cancels that stream.
- Read completions transfer a native-owned buffer lease. Rust copies its bytes
  only into the caller's `ReadBuf`; there is no intermediate `Vec` copy. Buffers
  are reused and sized in 4–64 KiB classes. A lease remains valid after native
  context shutdown, and canceling a read retains received bytes for the next read.
- Writes copy directly into reusable native buffers. There is one in-flight and
  one queued batch, bounded to two 64 KiB payload buffers. The first write is
  submitted immediately; subsequent small writes coalesce behind it and progress
  automatically without a flush timer. Vectored writes use the same owned buffer.
  `flush()` waits for all accepted bytes; close/drop may discard unflushed bytes.
- `shutdown_write()` and IO-trait writer shutdown send an independent FIN on
  negotiated H2/H3 streams. Other transports return `Unsupported` without
  closing the read side. `close_after_flush()` drains and closes both directions;
  `close()` aborts both immediately.
- Streams hold their client alive. `NaiveClient::shutdown` cancels all streams
  across client clones and waits for context destruction. Concurrent shutdowns
  wait for the same barrier. Drop schedules cleanup without blocking an async
  executor; explicitly await shutdown when deterministic cleanup is required.
- Chromium globals, parsed compiled roots and native workers live for the process
  lifetime. `Config::io_workers` selects a shared IO pool width from 1 to 8 (default
  1). Clients are assigned round-robin; each context stays on one worker, so this
  scales independent clients without adding proxy tunnels. Increasing it does not
  parallelize one HTTP/2 or QUIC session. The host allocator is not replaced.
  Embedding this alongside a second
  independently linked Chromium runtime is not a supported configuration.
- The wrapper preserves the upstream preamble/padding implementations and session
  rotation policy. Packet-level fingerprint equivalence with the CLI has not been
  established. The wrapper does not implement CLI listeners, transparent DNS or
  TUN/VPN device management. Host networking callbacks can apply the host
  application's routing and socket-protection policy; see [networking](docs/networking.md).

## Source and patch management

`upstream.lock.json` records the URL, stable tag, exact Git commit and ABI version.
`patches/series` gives patch order. `cargo xtask prepare` checks that the submodule
HEAD matches the lock and has no tracked edits, archives that commit into a
fingerprinted build directory, applies patches in order, then copies the native
bridge overlay. Toolchain downloads are cached separately by upstream commit.

All generated sources, downloads and binaries remain under ignored `target/`.
Concurrent native preparation/build commands are rejected by a PID lock. After an
interrupted process, inspect the recorded PID before removing `target/native/.lock`.

For an upgrade, select an upstream stable tag, update the submodule and lock in
the same change, rebase the patch queue, run `check-patches`, rebuild, and run both
test suites below. Upstream may rewrite `master` for new Chromium releases; never
use an unpinned branch head for a reproducible native artifact.

## Tests

The native platform matrix compiles and links test targets with `--no-run`.
Library CI also runs the focused owned IO, monoio/compio and H2/H3 half-close
regressions on macOS, using loopback fixtures. It starts no full application,
simulator or VM. Run the same suite locally after building the native library:

```sh
python3 tests/build_caddy.py
python3 tests/owned_io.py --repeat 5
```

The suite checks in-flight cancellation, native owner/guard release, read/write
deadlines, thread-local buffers, split IO, partial transfers and FIN/response
ordering. Its receipt and logs are written to `target/owned-runtime/final/`;
the recorded local result is [here](docs/owned-io-runtime-results.json).
Other library runtime checks remain available below.

`cargo test --workspace --all-features` runs local HTTP CONNECT fixtures covering fragmented
padding, the eight-frame boundary, unpadded compatibility, large full-duplex
transfers, cancellation, authentication failure and client/stream destruction.
Additional contracts cover directed wakeups, steady-state buffer reuse, bounded
backpressure, vectored/queued write progress, caller-buffer independence, read
leases surviving shutdown and concurrent cancellation on multiple native workers.

Real HTTPS and QUIC interoperability uses a separately built, pinned Caddy with
the Naïve forwardproxy plugin:

```sh
python3 tests/build_caddy.py
python3 tests/interop.py
```

The harness creates temporary certificates and a loopback echo server, then tests
both transports, isolated per-client custom trust, rejection of untrusted certificates, hostname
mismatches and wrong credentials. Certificate failures are verified against the
underlying NetLog verifier result, including when QUIC reports a generic error.
It never changes system trust or contacts a public test origin.
Its ignored Cargo test runs only through this explicit fixture setup. Go is
needed for the Caddy test fixture, not for the Rust library.

Performance methodology, frozen baseline comparisons and validation are recorded
in [docs/performance.md](docs/performance.md). The benchmark runner lives in
`tests/perf/`; it runs on loopback and does not measure WAN or device VPN behavior.
Other platforms and hosted CI have not been run locally.

## License

Wrapper code is BSD-3-Clause. NaïveProxy, Chromium and bundled dependencies retain
their upstream notices and licenses in `vendor/naiveproxy`. Binary distributors
must carry the notices for the linked dependencies as well as this wrapper.
