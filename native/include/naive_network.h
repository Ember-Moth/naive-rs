#ifndef NAIVE_RS_NETWORK_H
#define NAIVE_RS_NETWORK_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef struct naive_network_request naive_network_request;

// Hooks are scoped to a client, including its certificate-fetching context.
// Native retains context once and releases it after the last hook user goes
// away. Hook entry points run on an IO thread: do not block or unwind.
typedef struct naive_network_hooks {
  void* context;
  void (*retain)(void* context);
  void (*release)(void* context);
  // family/query: 0 = both, 4 = IPv4, 6 = IPv6, 65 = HTTPS record.
  // HTTPS owner names include _port._https. when the port is not 443.
  // No system DNS fallback is made when a host callback is configured.
  // A non-null callback receives ONE request reference. It must eventually
  // complete it, even if canceled. Completion can run on any thread.
  void (*resolve)(void* context,
                  const char* hostname,
                  int32_t family,
                  naive_network_request* request);
  // Borrows the socket before connect. protocol: 6 = TCP, 17 = UDP. Return 0
  // or a negative Chromium error, never IO_PENDING. Do not close or retain it.
  int32_t (*control)(void* context,
                     intptr_t socket,
                     int32_t protocol,
                     const char* peer);
  // Replaces TCP dialing only. addresses is a JSON array of IP:port strings.
  // The host owns network binding/protection for sockets created by this hook;
  // control is NOT called after the host has already connected the socket.
  void (*dial_tcp)(void* context,
                   const char* addresses,
                   naive_network_request* request);
  // Returns a bound UDP socket. It may already be connected (including to a
  // host-selected peer); otherwise native connects it to peer. The host owns
  // protection/network binding. network == -1 means no requested network.
  void (*dial_udp)(void* context,
                   const char* peer,
                   int64_t network,
                   naive_network_request* request);
} naive_network_hooks;

// Optional extra references for cancellation observers.
void naive_network_request_retain(naive_network_request* request);
void naive_network_request_release(naive_network_request* request);
int32_t naive_network_request_is_cancelled(naive_network_request* request);

// Both completions consume ONE request reference. Must be called exactly once
// for the reference received by resolve/dial_tcp. Late completion is harmless.
// Address success is a nonempty JSON array of IP literals (max 64 entries).
// HTTPS success is {"addresses":[],"ech":[byte,...]} (max 65537 bytes).
void naive_resolve_complete(naive_network_request* request,
                            int32_t result,
                            const char* addresses);
// Consumes socket on EVERY path, including cancellation/errors. Use -1 on
// failure. Socket must be connected TCP, nonblocking on POSIX, and support
// overlapped IO on Windows. Native closes it if adoption cannot complete.
void naive_dial_tcp_complete(naive_network_request* request,
                             int32_t result,
                             intptr_t socket);
void naive_dial_udp_complete(naive_network_request* request,
                             int32_t result,
                             intptr_t socket);

#ifdef __cplusplus
}
#endif
#endif
