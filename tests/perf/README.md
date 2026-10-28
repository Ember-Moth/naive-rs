# Performance harness

Build the library and the separate loopback servers:

```sh
cargo xtask toolchain
cargo xtask build
python3 tests/build_caddy.py
mkdir -p target/perf
go build -o target/perf/echo tests/perf/echo.go
cargo build -p naive-rs --bench transport --release --features perf-tuning
```

Cargo prints the benchmark executable under `target/release/deps/transport-*`.
Copy each build to a distinct path before building another profile: Cargo may
reuse the same executable filename after changing `NAIVE_NATIVE_DIR`.

```sh
python3 tests/perf/run.py \
  --variant baseline=/absolute/path/to/frozen-baseline \
  --variant optimized=/absolute/path/to/frozen-optimized \
  --repeats 5 --bytes-scale 4 --iterations-scale 2 \
  --output target/perf/comparison.json
python3 tests/perf/summarize.py target/perf/comparison.json
```

The runner interleaves variants in a deterministic randomized order. It uses
one Caddy, one echo server and one certificate for the entire matrix. Proxy
addresses are literal IPv4 to avoid different `localhost` resolution policies.
Each client is a fresh process, uses four Tokio workers, establishes its streams
and warms the eight-frame padding phase before measurement. The origin uses two
Go workers; Caddy uses four. Do not compile or run another load generator during
measurement.

Throughput is **one-way application payload echoed back** (wire traffic includes
both directions and protocol overhead). CPU is client process user+system time.
RSS is the entire client process, not just wrapper buffers. Native buffer counters
cover bridge payload allocations; they exclude TLS/HTTP buffers, padding scratch,
system libraries and process-lifetime caches. Results are loopback measurements,
not WAN bandwidth or device VPN measurements.

Use `--cases` to select cases. Additional opt-in cases include
`churn-parallel-32`, `ping-128-64b`, `idle-512`, and `soak-60`. Example:

```sh
python3 tests/perf/run.py \
  --variant io1=/absolute/optimized --variant io4=/absolute/optimized \
  --variant-io-workers io1=1 --variant-io-workers io4=4 \
  --cases bulk-128-64k,ping-128-64b,idle-512 \
  --repeats 3 --output target/perf/workers.json

python3 tests/perf/run.py --variant optimized=/absolute/optimized \
  --io-workers 4 --cases soak-60 --repeats 1 --output target/perf/soak.json
```

Soak tests keep data pressure and frequent canceled reads while reconnecting each
stream about once per second, staggered across streams. A prior message-count
cadence exhausted the test server's available TCP source addresses after roughly
16,000 upstream connections and surfaced EOF after CONNECT 200. The diagnostic
server confirmed `connect: can't assign requested address`. Fixed-time reconnects
avoid mistaking this fixture limit for a buffer/lifecycle defect and make the
reconnect rate independent of the implementation's throughput. Failure logs and
endpoint diagnostics are preserved beside the output JSON.

For release experiments, compare the default portable artifact with
`cargo xtask build --native-profile pgo` and separately build Rust code with
`CARGO_PROFILE_RELEASE_LTO=thin CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1`. Native
ThinLTO is deliberately disabled: the Chromium LLVM 24 archive format does not
link through this host's default Apple linker. The PGO profile is experimental;
browser training data is not necessarily suitable for a proxy workload.

## Optional cronet-go reference

```sh
python3 tests/perf/build_reference.py
python3 tests/perf/run.py --variant reference="$PWD/target/perf/cronet-go" \
  --variant optimized=/absolute/optimized --repeats 3 \
  --output target/perf/reference.json
```

The reference recipe currently supports macOS arm64 with CGO. It pins
`SagerNet/cronet-go` commit `0d28acc44093df24b2526dea3d6ffefd6b0a54f0` and uses its
matching prebuilt archive. It has Chromium 150, different native compiler flags,
different trust-store construction, and Cronet's bidirectional-stream path. That
HTTP/2 path includes a 1 ms buffered-read notification timer. This is a useful
reference, **not a controlled Rust-versus-Go language benchmark**. The dependency
is confined to this optional test module and is not part of naive-rs.

The original pre-optimization wrapper and native archive were frozen locally in
`target/perf/baseline-src` and `target/perf/baseline-native` before implementation
changes. Published result JSON records exact executable hashes. No baseline
commit was created in the initially uncommitted repository.
