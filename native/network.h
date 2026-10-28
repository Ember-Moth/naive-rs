#ifndef NAIVE_RS_NETWORK_INTERNAL_H
#define NAIVE_RS_NETWORK_INTERNAL_H
#include <map>
#include <memory>
#include <string>
#include "base/functional/callback.h"
#include "naive_rs/ech.h"
#include "naive_rs/include/naive_network.h"
namespace net {
class URLRequestContextBuilder;
}
namespace naive {
struct EchPolicy;
class NetworkHooks {
 public:
  explicit NetworkHooks(const naive_network_hooks& value);
  ~NetworkHooks();
  // Accessed only on the assigned IO sequence. Callbacks are weak: the
  // registry does not extend request lifetime. CancelPending breaks upstream
  // async QUIC socket/callback ownership cycles before context destruction.
  void Track(void* key, base::RepeatingClosure cancel);
  void Untrack(void* key);
  void CancelPending();
  const naive_network_hooks value;

 private:
  std::map<void*, base::RepeatingClosure> pending_;
};
void ConfigureNetwork(std::shared_ptr<NetworkHooks> hooks,
                      std::string rules,
                      std::shared_ptr<const EchPolicy> ech,
                      net::URLRequestContextBuilder& builder);
void ConfigureEchNetwork(std::shared_ptr<NetworkHooks> hooks,
                         std::string rules,
                         EchPolicies policies,
                         net::URLRequestContextBuilder& builder);
}  // namespace naive
#endif
