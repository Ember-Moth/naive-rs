#ifndef NAIVE_RS_BROWSER_H_
#define NAIVE_RS_BROWSER_H_
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include "base/memory/ref_counted.h"
#include "base/time/time.h"
#include "base/values.h"
#include "naive_rs/buffers.h"
#include "naive_rs/network.h"
namespace base {
class SingleThreadTaskRunner;
}
namespace net {
class URLRequestContext;
class CertVerifier;
}  // namespace net

namespace naive {
std::unique_ptr<net::URLRequestContext> BuildBrowserContext(
    const base::DictValue& config,
    std::unique_ptr<net::CertVerifier> verifier,
    std::shared_ptr<NetworkHooks> hooks,
    const EchPolicies& ech);
const std::string& BrowserUserAgent();

class BrowserOperations {
 public:
  BrowserOperations(net::URLRequestContext* context,
                    naive_callback callback,
                    scoped_refptr<base::SingleThreadTaskRunner> runner,
                    base::TimeDelta timeout,
                    size_t max_message_bytes,
                    base::RepeatingClosure on_idle);
  ~BrowserOperations();
  void Http(uint64_t id,
            std::string json,
            std::vector<char> upload,
            void* context);
  void WebSocket(uint64_t id,
                 std::string json,
                 naive_websocket_callback callback,
                 void* context);
  void Read(uint64_t id, size_t capacity);
  void ReadOwned(uint64_t id, scoped_refptr<OwnedIOBuffer> buffer);
  void SetDeadline(uint64_t id,
                   uint32_t mask,
                   std::optional<base::TimeTicks> deadline);
  void WebSocketReceive(uint64_t id);
  void WebSocketSend(uint64_t id, bool text, std::vector<char> data);
  void WebSocketClose(uint64_t id, uint16_t code, std::string reason);
  void Close(uint64_t id, int reason);
  void CancelAll(int reason);
  naive_client_stats Stats() const;

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};
}  // namespace naive
#endif
