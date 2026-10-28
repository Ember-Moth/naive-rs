#ifndef NAIVE_RS_H
#define NAIVE_RS_H
#include <stddef.h>
#include <stdint.h>
#include "naive_network.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef struct naive_engine naive_engine;
typedef struct naive_buffer naive_buffer;
enum naive_event {
  NAIVE_CONNECTED = 1,
  NAIVE_READ = 2,
  NAIVE_WRITTEN = 3,
  NAIVE_CLOSED = 4,
  NAIVE_DESTROYED = 5,
  NAIVE_READ_DEADLINE = 6,
  NAIVE_WRITE_DEADLINE = 7
};

// Runs on the engine IO sequence. Never block or unwind. Context belongs to
// this STREAM, not to the engine. DESTROYED is exactly once and is the final
// callback for context (including failed/canceled connects).
//
// Each non-null buffer transfers ONE reference to the callback, even on errors.
// Release it with naive_buffer_release. READ data is immutable until release;
// it stays valid after stream/engine shutdown. WRITTEN returns an exclusively
// owned buffer that can be reused for a later write. data and capacity describe
// that owner; length is the valid payload length, not the allocation capacity.
typedef void (*naive_callback)(void* context,
                               uint64_t stream_id,
                               int32_t event,
                               int32_t result,
                               naive_buffer* buffer,
                               uint8_t* data,
                               size_t length,
                               size_t capacity);

uint32_t naive_abi_version(void);
const char* naive_version(void);
const char* naive_error_name(int32_t error);

// Buffers are refcounted independently of engines and may be released from any
// thread. New data is uninitialized: initialize the submitted prefix. A newly
// allocated buffer is exclusively owned and writable. Once submitted, no caller
// may access it until it returns in WRITTEN.
naive_buffer* naive_buffer_alloc(size_t capacity);
uint8_t* naive_buffer_data(naive_buffer* buffer);
void naive_buffer_release(naive_buffer* buffer);
typedef struct naive_buffer_stats {
  uint64_t allocations;
  uint64_t live_buffers;
  uint64_t live_capacity;
  uint64_t peak_capacity;
} naive_buffer_stats;
void naive_get_buffer_stats(naive_buffer_stats* output);

// Counters are logical payload bytes, excluding TLS/HTTP/padding overhead.
// Failed connects include cancellation/timeouts before CONNECT succeeds.
typedef struct naive_client_stats {
  uint64_t connect_attempts;
  uint64_t connect_successes;
  uint64_t connect_failures;
  uint64_t closed_streams;
  uint64_t active_streams;
  uint64_t bytes_read;
  uint64_t bytes_written;
} naive_client_stats;
typedef struct naive_stream_info {
  uint64_t bytes_read;
  uint64_t bytes_written;
  uint32_t pooled_socket_reused;
  uint32_t ech_accepted;  // Meaningful when TLS information is available.
  uint16_t tls_version;   // TLS wire version, or 0 if unavailable.
  uint16_t cipher_suite;
  char protocol[16];
  char local_address[128];
  char peer_address[128];
} naive_stream_info;

// create/shutdown/destroy may block and must not run in a callback. Serialize
// shutdown calls for a handle. Read/write submissions may race shutdown;
// destroy must not race any handle access.
int32_t naive_engine_create(const char* json,
                            naive_callback callback,
                            const naive_network_hooks* hooks,
                            naive_engine** output);
// Closes all streams, releases contexts and flushes logging. Leaves the handle
// alive; subsequent queued operations are ignored and any owned buffers freed.
void naive_engine_shutdown(naive_engine* engine);
// Synchronous IO barrier: cancel streams/preambles, empty socket pools and DNS
// caches, preserve configuration. Never call from a callback. New connections
// can be made after this returns; concurrent ones may be included in the reset.
int32_t naive_engine_reset_connections(naive_engine* engine);
// Synchronous snapshots; use a control thread, never a native callback.
// Stats remain available after shutdown until the handle is destroyed.
int32_t naive_engine_get_stats(naive_engine* engine,
                               naive_client_stats* output,
                               size_t output_size);
int32_t naive_engine_get_stream_info(naive_engine* engine,
                                     uint64_t id,
                                     naive_stream_info* output,
                                     size_t output_size);
// Nonblocking: mask 1 = read, 2 = write, 3 = both. timeout_us is measured
// from this call, -1 clears the selected deadline, 0 expires immediately.
// Expiry wakes the matching direction; it does not destroy pending IO or data.
int32_t naive_engine_set_deadline(naive_engine* engine,
                                  uint64_t id,
                                  uint32_t mask,
                                  int64_t timeout_us);
void naive_engine_destroy(naive_engine* engine);
// IDs must be nonzero and never reused. The context must survive until
// DESTROYED.
void naive_engine_connect(naive_engine* engine,
                          uint64_t id,
                          const char* hostname,
                          uint16_t port,
                          void* context);
// At most one read and one write may be in flight per stream. A READ callback
// transfers a lease; another read is permitted even if an older lease survives.
void naive_engine_read(naive_engine* engine, uint64_t id, size_t capacity);
// Consumes buffer ownership unconditionally, including if the stream is closed.
void naive_engine_write(naive_engine* engine,
                        uint64_t id,
                        naive_buffer* buffer,
                        size_t length);
void naive_engine_close(naive_engine* engine, uint64_t id);

#ifdef __cplusplus
}
#endif
#endif
