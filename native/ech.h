#ifndef NAIVE_RS_ECH_H
#define NAIVE_RS_ECH_H
#include <map>
#include <memory>
#include <string>
#include <vector>
#include "base/containers/span.h"
#include "base/functional/callback.h"
#include "base/values.h"
#include "net/base/ech_mode.h"
#include "net/dns/host_resolver.h"
#include "net/dns/system_dns_config_change_notifier.h"
namespace naive {
struct EchPolicy {
  std::string host;
  std::string query_name;
  uint16_t port = 443;
  bool quic = false;
  bool all_protocols = false;
  net::EchMode mode = net::EchMode::kStrict;
  std::vector<uint8_t> config_list;
};
using EchPolicies = std::vector<std::shared_ptr<const EchPolicy>>;
bool ReadBrowserEchPolicies(const base::DictValue& config,
                            EchPolicies* policies);
class DnsReadiness final : public net::SystemDnsConfigChangeNotifier::Observer {
 public:
  DnsReadiness(net::SystemDnsConfigChangeNotifier* notifier,
               bool supported,
               std::shared_ptr<net::HostResolverManager> manager);
  ~DnsReadiness();
  bool ready() const { return ready_; }
  void WhenReady(void* key, base::OnceClosure callback);
  void CancelWaiter(void* key);
  void OnSystemDnsConfigChanged(const net::DnsConfig& config) override;

 private:
  net::SystemDnsConfigChangeNotifier* notifier_;
  std::shared_ptr<net::HostResolverManager> manager_;
  bool ready_;
  std::map<void*, base::OnceClosure> waiting_;
};
bool ValidEchConfig(base::span<const uint8_t> bytes);
// query_base is owned by address_resolver (possibly via MappedHostResolver).
// HTTPS-record queries bypass address mapping but use the same DNS policy and
// cache. IP hints/target redirects from the ECH query never replace proxy IPs.
std::unique_ptr<net::HostResolver> WrapEchResolver(
    std::unique_ptr<net::HostResolver> address_resolver,
    net::HostResolver* query_base,
    std::shared_ptr<const EchPolicy> policy,
    std::shared_ptr<DnsReadiness> readiness = {});
}  // namespace naive
#endif
