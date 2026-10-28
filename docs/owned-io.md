# Owned IO and runtime adapters

The core is independent of the host application and Rust runtime. It does not
import Sonar buffer types, call a Rust runtime's `spawn`, or require a Tokio
reactor. The native Chromium IO workers remain responsible for networking.
Default Cargo features are empty; Tokio, futures-io and bytes integrations are
explicit opt-ins. These interfaces were introduced in ABI **4**; current ABI
**6** retains them together with the direct native client APIs introduced in ABI 5.

## API and ownership

| API | Buffer owner during IO | Payload copies at the bridge |
|---|---|---|
| Standard poll/Tokio/futures-io reads and writes | Internal native storage | One copy to/from the borrowed caller slice |
| `read_chunk()` / `poll_read_chunk()` | Native immutable lease returned to caller | No copy when the lease is returned |
| `read_owned(B)` / `write_owned(B)` | Native IOBuffer holds `B: Send` | No staging payload copy on a fresh operation |
| `read_local(B)` / `write_local(B)` | Future keeps `B`, including `!Send` buffers | Uses the standard copying path on the polling thread |

`owned::IoBuf` describes a stable initialized prefix. `owned::IoBufMut` describes
stable, exclusively writable storage and how to publish its initialized prefix.
They are separate unsafe extension contracts; neither imposes `Send` itself.
A returned `ReadChunk` also implements the immutable contract, so another Naive
stream can consume it with `write_owned` without enabling the bytes feature.
Only native owned operations require `Send`. Implementations are supplied for
`Vec<u8>`, boxed byte slices and byte arrays, and optionally `Bytes`/`BytesMut`.
Inline array owners can move their data when boxed; use an already heap-backed
buffer when avoiding that move matters. Metadata allocation is not eliminated.

Each operation transfers at most 64 KiB and returns an `IoResult<B>` containing
`result`, the original `buffer`, and `transferred`. The latter preserves the
known prefix on an error. Cancellation can leave additional transport progress
unknown, so neither the whole buffer nor its apparent remainder is automatically
safe to replay. Large transfers must advance their owned view using the returned count.
`write_local` and standard writes report bytes accepted by the bridge; call flush
to wait for all accepted writes. Native `write_owned` waits for the submitted
prefix's native write completion. Neither indicates that the remote application
has consumed the bytes.

The owner is held by the **actual native IOBuffer**, not merely by the Rust
future, stream object or wrapper request. Lower layers may retain that IOBuffer
after cancellation. The Rust completion runs exactly once after its final native
reference disappears. It may run on any thread. Owners and budget guards handed
to native IO must therefore be safe to drop there and must not panic in `Drop`.

Before submission, dropping an owned future simply drops its locally held
buffer. After submission, dropping it aborts that stream; the owner is released
later by the native lease. An owned-operation deadline also aborts the stream and
waits for the buffer's release before returning it. This differs deliberately
from the borrowed-read/read-chunk path, where canceling a waiter retains received
data for a later read. A client shutdown does not invalidate already returned
read chunks, and does not force an external caller to release its chunks.

Owned and borrowed operations use the same direction slots and ordering. An
owned write waits for prior buffered writes. Later writers wait for the owned
operation to release its slot. If `read_owned` encounters data already fetched
by a borrowed read, it first copies that retained prefix into the supplied owner;
it does not discard or reorder data to force a zero-copy claim.

`NaiveStream::into_split()` returns independent owned read/write halves so a
pending read does not block an upload. The runtime adapters expose the same
split operation and retain their native IO traits on each half. Dropping one
half keeps the other alive; dropping the last half closes the stream. Explicit
writer shutdown sends FIN, and canceling an in-flight native owned operation
still aborts the shared stream.

For example, both directions can make progress without borrowing the same
stream twice (inside any compatible executor):

```rust,no_run
# async fn transfer(stream: naive::NaiveStream) -> Result<(), naive::Error> {
let (mut reader, mut writer) = stream.into_split();
let upload = writer.write_owned(vec![1, 2, 3]);
let download = reader.read_owned(Vec::with_capacity(4096));
// Poll these futures concurrently using the host executor's join/select tools.
// Each IoResult returns the original buffer; inspect transferred on an error.
# drop((upload, download));
# Ok(())
# }
```

## Host pools and memory budgets

The library does not prescribe an allocator or global application pool.
`owned::Guarded<B, G>` couples a host permit or lease to its buffer. The guard
travels with the owner through completion and cancellation. Sonar can implement
the buffer contract in its own newtype and retain its `PooledBuffer`/`BytePermit`
there; these types do not belong in naive-rs. A frozen Sonar pooled buffer can
also be supplied as `Bytes` with the `bytes` feature.

`ReadChunk::allocated_capacity()` reports the underlying native allocation size;
`len()` reports only the remaining initialized payload. `into_bytes()` returns a
shared view without copying when the `bytes` feature is enabled. Callers must
bound outstanding chunks. A small slice can keep its entire backing allocation
alive. Native read caches may retain storage after the exported lease is dropped.

`buffer_stats()` measures process-wide bridge-allocated payload buffers only.
It excludes foreign host-owned buffers, TLS/HTTP/QUIC state and allocator
metadata. A guard around an exported chunk accounts its host retention period,
not all Chromium memory. This API does not promise a whole-process memory cap.

## Runtime integration

`naive-monoio::Stream` implements monoio 0.2 `AsyncReadRent` and `AsyncWriteRent`.
It is currently a Unix adapter and enables monoio's `sync` support for native
cross-thread wakeups, plus its legacy driver; the optional `iouring` feature
adds that driver. No Tokio compatibility layer is used.

`naive-compio::Stream` implements compio-io 0.10 `AsyncRead` and `AsyncWrite`.
Its normal dependencies contain the IO/buffer traits, not the compio runtime.
Both adapters retain local owners on the polling thread for trait operations,
so thread-local `Rc`-based buffers remain usable. Their explicit `read_owned`
and `write_owned` methods require `Send` and use the native owned path. Buffer
initialization lengths are updated only when data has been written.

Cross-linking complete Linux runtime fixtures may require the unmodified glibc
link SDK described in [platform integration](platforms.md).

Both adapters expose `inner_mut()` and `into_inner()` to access core handshake,
read chunks, deadlines and close operations. The `bytes` adapter feature enables
matching buffer implementations. Native resolver/dialer/observer callbacks still
enter on native/control threads: a host with a local executor must enqueue work
to its owning thread, not call its local `spawn` directly from the callback.

## Directional close

`shutdown_write()` and the adapters' writer shutdown/close methods drain prior
writes and send an independent FIN for negotiated HTTP/2 and HTTP/3 CONNECT
streams. H2 half-close behavior is opt-in so unrelated upstream CLI users retain
their existing policy. The read direction remains available. Connection info
reports `write_shutdown_supported` for the actual negotiated transport.

Other transports, including the current HTTP/1 proxy path, return `Unsupported`
without disconnecting. They do not silently turn a half-close into a full close.
Use `close()` to abort both directions or `close_after_flush()` to drain accepted
writes and then close both. Hosts must not assume every configured HTTPS proxy
negotiates H2; check the actual capability when half-close is required.

## Validation scope

Run `python3 tests/owned_io.py --repeat 5` after building the native library and
the pinned Caddy fixture (`python3 tests/build_caddy.py`). This executes 16 core
owned IO tests, four ordinary tests per adapter, six core H2/H3 interop tests and
one H2/H3 test per adapter on the current host. The two adapter interop tests are
ignored in the ordinary batch and then explicitly executed with Caddy running.
Each process group has a timeout, and the receipt binds results to source and
native-archive hashes. Failures retain their logs.

The regression coverage includes actual socket backpressure, cancellation both
before observing a completed write and while IO is pending, exactly-once host
guard release, read/write deadlines, remote reset with partial write progress,
shutdown with outstanding owners, retained
read leases, mixed read/write APIs, caller-thread access/drop of `!Send` buffers,
large partial transfers and split directions. H2 and H3 both exercise empty and
large requests, buffered/native write ordering, repeated shutdown calls, canceled FIN
waiters, rejection of writes after FIN and complete responses sent after FIN.

The local macOS arm64 result is recorded in `owned-io-runtime-results.json`.
Library CI runs this focused suite; the cross-platform native matrix still uses
`--no-run`. Other target runtimes, including Linux io_uring, are not established
by the macOS result. No application, simulator, emulator or VM is launched.

## Migration from ABI 3

- Rebuild or install an ABI 4 native archive; the build script rejects ABI 3.
- Enable `features = ["tokio"]` explicitly for Tokio IO traits. Use the separate
  adapter crates for monoio and compio, or the core poll/owned APIs directly.
- Calls that used writer `shutdown` as a full close should use
  `close_after_flush()` instead. `shutdown_write()` now represents only a FIN
  and can return `Unsupported` for a transport that cannot provide it.
- Keep owning buffers alive through their returned `IoResult`, or let their
  owner drop after cancellation. Never recycle a raw pointer from a close event.
