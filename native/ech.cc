#include "naive_rs/ech.h"

#include <optional>
#include <set>
#include <utility>
#include "base/functional/bind.h"
#include "base/memory/weak_ptr.h"
#include "base/strings/string_util.h"
#include "base/task/single_thread_task_runner.h"
#include "net/base/address_list.h"
#include "net/base/ip_address.h"
#include "net/base/net_errors.h"
#include "net/base/url_util.h"
#include "net/dns/host_resolver_manager.h"
#include "net/dns/public/host_resolver_results.h"
#include "net/dns/public/resolve_error_info.h"
#include "third_party/boringssl/src/include/openssl/err.h"
#include "third_party/boringssl/src/include/openssl/ssl.h"

namespace naive {
bool ReadBrowserEchPolicies(const base::DictValue& config,
                            EchPolicies* policies) {
  if (!config.contains("ech-hosts"))
    return true;
  const auto* hosts = config.FindDict("ech-hosts");
  if (!hosts || hosts->size() > 128)
    return false;
  std::set<std::string> names;
  for (const auto [host, value] : *hosts) {
    if (host.empty() || host.size() > 253 ||
        host.find_first_of("/:#?\\@* \t\r\n") != std::string::npos)
      return false;
    url::CanonHostInfo info;
    auto policy = std::make_shared<EchPolicy>();
    policy->host = net::CanonicalizeHost(host, &info);
    if (policy->host.ends_with('.'))
      policy->host.pop_back();
    net::IPAddress ip;
    if (info.family == url::CanonHostInfo::BROKEN || policy->host.empty() ||
        ip.AssignFromIPLiteral(policy->host) ||
        !names.insert(policy->host).second)
      return false;
    const auto* options = value.GetIfDict();
    auto mode = options ? options->FindInt("ech-mode") : std::nullopt;
    if (!mode || *mode < 0 || *mode > 2)
      return false;
    policy->mode = static_cast<net::EchMode>(*mode);
    policy->query_name = policy->host;
    policy->port =
        0;  // Resolve HTTPS records using the actual destination port.
    policy->all_protocols = true;
    if (*mode == 0 && (options->contains("ech-config-list") ||
                       options->contains("ech-query-name")))
      return false;
    if (options->contains("ech-query-name")) {
      const auto* query = options->FindString("ech-query-name");
      if (!query || query->empty() || query->size() > 253 ||
          query->find_first_of("/:#?\\@* \t\r\n") != std::string::npos ||
          options->contains("ech-config-list"))
        return false;
      policy->query_name = net::CanonicalizeHost(*query, &info);
      if (policy->query_name.ends_with('.'))
        policy->query_name.pop_back();
      if (info.family == url::CanonHostInfo::BROKEN ||
          policy->query_name.empty() ||
          ip.AssignFromIPLiteral(policy->query_name))
        return false;
    }
    if (options->contains("ech-config-list")) {
      const auto* list = options->FindList("ech-config-list");
      if (!list || list->empty() || list->size() > 65537)
        return false;
      for (const auto& byte : *list) {
        if (!byte.is_int() || byte.GetInt() < 0 || byte.GetInt() > 255)
          return false;
        policy->config_list.push_back(static_cast<uint8_t>(byte.GetInt()));
      }
      if (!ValidEchConfig(policy->config_list))
        return false;
    }
    policies->push_back(std::move(policy));
  }
  return true;
}
DnsReadiness::DnsReadiness(net::SystemDnsConfigChangeNotifier* notifier,
                           bool supported,
                           std::shared_ptr<net::HostResolverManager> manager)
    : notifier_(supported ? notifier : nullptr),
      manager_(std::move(manager)),
      ready_(!supported) {
  if (notifier_)
    notifier_->AddObserver(this);
}
DnsReadiness::~DnsReadiness() {
  if (notifier_)
    notifier_->RemoveObserver(this);
}
void DnsReadiness::WhenReady(void* key, base::OnceClosure callback) {
  if (ready_)
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, std::move(callback));
  else
    waiting_.insert_or_assign(key, std::move(callback));
}
void DnsReadiness::CancelWaiter(void* key) {
  waiting_.erase(key);
}
void DnsReadiness::OnSystemDnsConfigChanged(const net::DnsConfig& config) {
  // Updating the manager can complete requests and release their owners. Take
  // everything needed before that call; do not access this object afterwards.
  ready_ = true;
  auto waiting = std::move(waiting_);
  auto manager = manager_;
  auto runner = base::SingleThreadTaskRunner::GetCurrentDefault();
  static_cast<net::SystemDnsConfigChangeNotifier::Observer*>(manager.get())
      ->OnSystemDnsConfigChanged(config);
  for (auto& [key, callback] : waiting)
    runner->PostTask(FROM_HERE, std::move(callback));
}

bool ValidEchConfig(base::span<const uint8_t> bytes) {
  if (bytes.empty() || bytes.size() > 65537)
    return false;
  ERR_clear_error();
  bssl::UniquePtr<SSL_CTX> context(SSL_CTX_new(TLS_method()));
  if (!context) {
    ERR_clear_error();
    return false;
  }
  bssl::UniquePtr<SSL> ssl(SSL_new(context.get()));
  bool valid = ssl && SSL_set1_ech_config_list(ssl.get(), bytes.data(),
                                               bytes.size()) == 1;
  ERR_clear_error();
  return valid;
}
namespace {
using Parameters = net::HostResolver::ResolveHostParameters;
using AddressRequest = net::HostResolver::ResolveHostRequest;
using EndpointRequest = net::HostResolver::ServiceEndpointRequest;

void Apply(net::ConnectionEndpointMetadata& metadata,
           const EchPolicy& policy,
           const std::vector<uint8_t>& config) {
  metadata.ech_config_list = config;
  if (config.empty())
    return;
  metadata.target_name = policy.host;
  metadata.supported_protocol_alpns =
      policy.all_protocols ? std::vector<std::string>{"h3", "h2", "http/1.1"}
      : policy.quic        ? std::vector<std::string>{"h3"}
                           : std::vector<std::string>{"h2", "http/1.1"};
}

class Lookup {
 public:
  Lookup(net::HostResolver* resolver,
         std::shared_ptr<const EchPolicy> policy,
         net::NetworkAnonymizationKey key,
         net::handles::NetworkHandle network,
         net::NetLogWithSource log,
         std::optional<Parameters> params,
         std::shared_ptr<DnsReadiness> readiness,
         std::shared_ptr<bool> closed)
      : resolver_(resolver),
        policy_(std::move(policy)),
        key_(std::move(key)),
        network_(network),
        log_(std::move(log)),
        params_(std::move(params)),
        readiness_(std::move(readiness)),
        closed_(std::move(closed)) {}
  ~Lookup() { Cancel(); }
  int Start(net::CompletionOnceCallback callback) {
    if (!policy_->config_list.empty()) {
      configs = policy_->config_list;
      ready = true;
      return result = net::OK;
    }
    callback_ = std::move(callback);
    if (readiness_ && !readiness_->ready()) {
      readiness_->WhenReady(
          this, base::BindOnce(&Lookup::DeferredStart, weak_.GetWeakPtr()));
      return net::ERR_IO_PENDING;
    }
    int rv = StartQuery();
    if (rv != net::ERR_IO_PENDING)
      callback_.Reset();
    return rv;
  }
  void Cancel() {
    if (readiness_)
      readiness_->CancelWaiter(this);
    weak_.InvalidateWeakPtrs();
    callback_.Reset();
    request_.reset();
  }
  void ChangePriority(net::RequestPriority priority) {
    if (request_ && !ready)
      request_->ChangeRequestPriority(priority);
  }
  bool ready = false;
  int result = net::ERR_IO_PENDING;
  std::vector<uint8_t> configs;

 private:
  int StartQuery() {
    auto params = params_.value_or(Parameters());
    params.dns_query_type = net::DnsQueryType::HTTPS;
    if (params.source != net::HostResolverSource::LOCAL_ONLY)
      params.source = net::HostResolverSource::DNS;
    params.include_canonical_name = false;
    params.is_speculative = false;
    params.loopback_only = false;
    request_ = resolver_->CreateRequest(
        url::SchemeHostPort("https", policy_->query_name, policy_->port), key_,
        network_, log_, params);
    int rv =
        request_->Start(base::BindOnce(&Lookup::Done, base::Unretained(this)));
    if (rv != net::ERR_IO_PENDING)
      Complete(rv);
    return ready ? result : net::ERR_IO_PENDING;
  }
  void DeferredStart() {
    if (*closed_) {
      Cancel();
      return;
    }
    int rv = StartQuery();
    if (rv != net::ERR_IO_PENDING)
      std::move(callback_).Run(rv);
  }
  void Complete(int rv) {
    if (rv == net::OK) {
      for (const auto& endpoint : request_->GetEndpointResults()) {
        if (ValidEchConfig(endpoint.metadata.ech_config_list)) {
          configs = endpoint.metadata.ech_config_list;
          break;
        }
      }
    }
    ready = true;
    if (policy_->mode == net::EchMode::kStrict && configs.empty())
      result = rv == net::OK ? net::ERR_ECH_NOT_NEGOTIATED : rv;
    else
      result = net::OK;  // Explicit opportunistic mode permits missing records.
  }
  void Done(int rv) {
    if (*closed_) {
      Cancel();
      return;
    }
    Complete(rv);
    std::move(callback_).Run(result);
  }
  net::HostResolver* resolver_;
  std::shared_ptr<const EchPolicy> policy_;
  net::NetworkAnonymizationKey key_;
  net::handles::NetworkHandle network_;
  net::NetLogWithSource log_;
  std::optional<Parameters> params_;
  std::unique_ptr<AddressRequest> request_;
  net::CompletionOnceCallback callback_;
  std::shared_ptr<DnsReadiness> readiness_;
  std::shared_ptr<bool> closed_;
  base::WeakPtrFactory<Lookup> weak_{this};
};

class Request : public AddressRequest {
 public:
  Request(std::unique_ptr<AddressRequest> address,
          net::HostResolver* query,
          std::shared_ptr<const EchPolicy> policy,
          std::shared_ptr<bool> closed,
          net::NetworkAnonymizationKey key,
          net::handles::NetworkHandle network,
          net::NetLogWithSource log,
          std::optional<Parameters> params,
          std::shared_ptr<DnsReadiness> readiness)
      : address_(std::move(address)),
        policy_(std::move(policy)),
        closed_(std::move(closed)),
        lookup_(query,
                policy_,
                std::move(key),
                network,
                std::move(log),
                std::move(params),
                std::move(readiness),
                closed_) {}
  int Start(net::CompletionOnceCallback callback) override {
    if (*closed_)
      return error_.error = net::ERR_CONTEXT_SHUT_DOWN;
    callback_ = std::move(callback);
    address_result_ = address_->Start(
        base::BindOnce(&Request::AddressDone, base::Unretained(this)));
    if (address_result_ != net::ERR_IO_PENDING && address_result_ != net::OK) {
      finished_ = true;
      callback_.Reset();
      return error_.error = address_result_;
    }
    lookup_.Start(base::BindOnce(&Request::LookupDone, base::Unretained(this)));
    int rv = ReadyResult();
    if (rv != net::ERR_IO_PENDING) {
      Finish(rv);
      callback_.Reset();
    }
    return rv;
  }
  const net::AddressList& GetAddressResults() const override {
    return addresses_;
  }
  base::span<const net::HostResolverEndpointResult> GetEndpointResults()
      const override {
    return endpoints_;
  }
  base::span<const std::string> GetTextResults() const override { return {}; }
  base::span<const net::HostPortPair> GetHostnameResults() const override {
    return {};
  }
  const std::set<std::string>& GetDnsAliasResults() const override {
    return aliases_;
  }
  net::ResolveErrorInfo GetResolveErrorInfo() const override { return error_; }
  const std::optional<net::HostCache::EntryStaleness>& GetStaleInfo()
      const override {
    return stale_;
  }
  std::optional<net::ResolutionDetails> GetResolutionDetails() const override {
    return details_;
  }
  void ChangeRequestPriority(net::RequestPriority priority) override {
    if (!finished_ && address_result_ == net::ERR_IO_PENDING)
      address_->ChangeRequestPriority(priority);
    lookup_.ChangePriority(priority);
  }

 private:
  int ReadyResult() const {
    if (address_result_ != net::ERR_IO_PENDING && address_result_ != net::OK)
      return address_result_;
    if (lookup_.ready && lookup_.result != net::OK)
      return lookup_.result;
    return address_result_ == net::OK && lookup_.ready ? net::OK
                                                       : net::ERR_IO_PENDING;
  }
  void Finish(int rv) {
    finished_ = true;
    error_ = net::ResolveErrorInfo(rv);
    if (rv != net::OK) {
      lookup_.Cancel();
      return;
    }
    addresses_ = address_->GetAddressResults();
    auto endpoints = address_->GetEndpointResults();
    endpoints_.assign(endpoints.begin(), endpoints.end());
    if (endpoints_.empty() && !addresses_.empty()) {
      endpoints_.emplace_back();
      endpoints_.back().ip_endpoints.assign(addresses_.begin(),
                                            addresses_.end());
    }
    for (auto& endpoint : endpoints_)
      Apply(endpoint.metadata, *policy_, lookup_.configs);
    aliases_ = address_->GetDnsAliasResults();
    stale_ = address_->GetStaleInfo();
    details_ = address_->GetResolutionDetails();
  }
  void MaybeComplete() {
    if (finished_ || *closed_)
      return;
    int rv = ReadyResult();
    if (rv == net::ERR_IO_PENDING)
      return;
    Finish(rv);
    std::move(callback_).Run(rv);
  }
  void AddressDone(int rv) {
    address_result_ = rv;
    MaybeComplete();
  }
  void LookupDone(int) { MaybeComplete(); }
  std::unique_ptr<AddressRequest> address_;
  std::shared_ptr<const EchPolicy> policy_;
  std::shared_ptr<bool> closed_;
  Lookup lookup_;
  bool finished_ = false;
  int address_result_ = net::ERR_IO_PENDING;
  net::CompletionOnceCallback callback_;
  net::AddressList addresses_;
  std::vector<net::HostResolverEndpointResult> endpoints_;
  std::set<std::string> aliases_;
  std::optional<net::HostCache::EntryStaleness> stale_;
  std::optional<net::ResolutionDetails> details_;
  net::ResolveErrorInfo error_;
};

class ServiceRequest : public EndpointRequest,
                       public EndpointRequest::Delegate {
 public:
  ServiceRequest(std::unique_ptr<EndpointRequest> address,
                 net::HostResolver* query,
                 std::shared_ptr<const EchPolicy> policy,
                 std::shared_ptr<bool> closed,
                 net::NetworkAnonymizationKey key,
                 net::handles::NetworkHandle network,
                 net::NetLogWithSource log,
                 Parameters params,
                 std::shared_ptr<DnsReadiness> readiness)
      : address_(std::move(address)),
        policy_(std::move(policy)),
        closed_(std::move(closed)),
        lookup_(query,
                policy_,
                std::move(key),
                network,
                std::move(log),
                std::move(params),
                std::move(readiness),
                closed_) {}
  int Start(EndpointRequest::Delegate* delegate) override {
    if (*closed_)
      return error_.error = net::ERR_CONTEXT_SHUT_DOWN;
    delegate_ = delegate;
    address_result_ = address_->Start(this);
    if (address_result_ != net::ERR_IO_PENDING && address_result_ != net::OK) {
      finished_ = true;
      return error_.error = address_result_;
    }
    lookup_.Start(
        base::BindOnce(&ServiceRequest::LookupDone, base::Unretained(this)));
    Refresh();
    int rv = ReadyResult();
    if (rv != net::ERR_IO_PENDING) {
      finished_ = true;
      error_ = net::ResolveErrorInfo(rv);
    }
    return rv;
  }
  base::span<const net::ServiceEndpoint> GetEndpointResults() override {
    return endpoints_;
  }
  const std::set<std::string>& GetDnsAliasResults() override {
    return address_->GetDnsAliasResults();
  }
  bool EndpointsCryptoReady() override {
    return lookup_.ready && lookup_.result == net::OK &&
           address_->EndpointsCryptoReady();
  }
  net::ResolveErrorInfo GetResolveErrorInfo() override { return error_; }
  const net::HostCache::EntryStaleness* GetStaleInfo() const override {
    return address_->GetStaleInfo();
  }
  bool IsStaleWhileRefreshing() const override {
    return address_->IsStaleWhileRefreshing();
  }
  void ChangeRequestPriority(net::RequestPriority priority) override {
    if (!finished_)
      address_->ChangeRequestPriority(priority);
    lookup_.ChangePriority(priority);
  }
  std::optional<net::ResolutionDetails> GetResolutionDetails() const override {
    return address_->GetResolutionDetails();
  }
  void OnServiceEndpointsUpdated() override {
    if (finished_ || *closed_)
      return;
    Refresh();
    if (lookup_.ready && lookup_.result == net::OK)
      delegate_->OnServiceEndpointsUpdated();
  }
  void OnServiceEndpointRequestFinished(int rv) override {
    address_result_ = rv;
    MaybeComplete();
  }

 private:
  void Refresh() {
    endpoints_.clear();
    if (!lookup_.ready || lookup_.result != net::OK)
      return;
    auto endpoints = address_->GetEndpointResults();
    endpoints_.assign(endpoints.begin(), endpoints.end());
    for (auto& endpoint : endpoints_)
      Apply(endpoint.metadata, *policy_, lookup_.configs);
  }
  int ReadyResult() const {
    if (address_result_ != net::ERR_IO_PENDING && address_result_ != net::OK)
      return address_result_;
    if (lookup_.ready && lookup_.result != net::OK)
      return lookup_.result;
    return address_result_ == net::OK && lookup_.ready ? net::OK
                                                       : net::ERR_IO_PENDING;
  }
  void MaybeComplete() {
    if (finished_ || *closed_)
      return;
    Refresh();
    int rv = ReadyResult();
    if (rv == net::ERR_IO_PENDING)
      return;
    finished_ = true;
    error_ = net::ResolveErrorInfo(rv);
    if (rv != net::OK)
      lookup_.Cancel();
    delegate_->OnServiceEndpointRequestFinished(rv);
  }
  void LookupDone(int) {
    if (finished_ || *closed_)
      return;
    if (ReadyResult() != net::ERR_IO_PENDING) {
      MaybeComplete();
      return;
    }
    Refresh();
    if (lookup_.result == net::OK)
      delegate_->OnServiceEndpointsUpdated();
  }
  std::unique_ptr<EndpointRequest> address_;
  std::shared_ptr<const EchPolicy> policy_;
  std::shared_ptr<bool> closed_;
  Lookup lookup_;
  EndpointRequest::Delegate* delegate_ = nullptr;
  bool finished_ = false;
  int address_result_ = net::ERR_IO_PENDING;
  net::ResolveErrorInfo error_;
  std::vector<net::ServiceEndpoint> endpoints_;
};

std::optional<Parameters> AddressParameters(std::optional<Parameters> params) {
  auto value = params.value_or(Parameters());
  // The wrapper obtains ECH separately. Preserve Naïve's explicit system-DNS
  // address path instead of making strict ECH demand an additional HTTPS RR
  // from getaddrinfo. This does not relax the TLS ECH policy or change a host
  // resolver callback into a system resolver.
  if (value.source == net::HostResolverSource::ANY &&
      value.secure_dns_policy == net::SecureDnsPolicy::kDisable)
    value.source = net::HostResolverSource::SYSTEM;
  return value;
}

class Resolver : public net::HostResolver {
 public:
  Resolver(std::unique_ptr<net::HostResolver> address,
           net::HostResolver* query,
           std::shared_ptr<const EchPolicy> policy,
           std::shared_ptr<DnsReadiness> readiness)
      : address_(std::move(address)),
        query_(query),
        policy_(std::move(policy)),
        closed_(std::make_shared<bool>(false)),
        readiness_(std::move(readiness)) {}
  ~Resolver() override {
    OnShutdown();
    // The readiness object owns the manager used by the context resolver.
    address_.reset();
  }
  void OnShutdown() override {
    if (!*closed_) {
      *closed_ = true;
      address_->OnShutdown();
    }
  }
  std::unique_ptr<ResolveHostRequest> CreateRequest(
      url::SchemeHostPort host,
      net::NetworkAnonymizationKey key,
      net::handles::NetworkHandle network,
      net::NetLogWithSource log,
      std::optional<Parameters> params) override {
    const bool matches = Matches(host.host(), params);
    auto request = address_->CreateRequest(
        host, key, network, log, matches ? AddressParameters(params) : params);
    if (!matches)
      return request;
    return std::make_unique<Request>(
        std::move(request), query_, ForPort(host.port()), closed_,
        std::move(key), network, std::move(log), std::move(params), readiness_);
  }
  std::unique_ptr<ResolveHostRequest> CreateRequest(
      const net::HostPortPair& host,
      const net::NetworkAnonymizationKey& key,
      net::handles::NetworkHandle network,
      const net::NetLogWithSource& log,
      const std::optional<Parameters>& params) override {
    const bool matches = Matches(host.host(), params);
    auto request = address_->CreateRequest(
        host, key, network, log, matches ? AddressParameters(params) : params);
    if (!matches)
      return request;
    return std::make_unique<Request>(std::move(request), query_,
                                     ForPort(host.port()), closed_, key,
                                     network, log, params, readiness_);
  }
  std::unique_ptr<ServiceEndpointRequest> CreateServiceEndpointRequest(
      Host host,
      net::NetworkAnonymizationKey key,
      net::handles::NetworkHandle network,
      net::NetLogWithSource log,
      Parameters params) override {
    const bool matches = Matches(host.GetHostnameWithoutBrackets(), params);
    const auto port = host.GetPort();
    auto request = address_->CreateServiceEndpointRequest(
        std::move(host), key, network, log,
        matches ? *AddressParameters(params) : params);
    if (!matches)
      return request;
    return std::make_unique<ServiceRequest>(
        std::move(request), query_, ForPort(port), closed_, std::move(key),
        network, std::move(log), std::move(params), readiness_);
  }
  std::unique_ptr<ProbeRequest> CreateDohProbeRequest() override {
    return address_->CreateDohProbeRequest();
  }
  std::unique_ptr<MdnsListener> CreateMdnsListener(
      const net::HostPortPair& host,
      net::DnsQueryType query) override {
    return address_->CreateMdnsListener(host, query);
  }
  net::HostCache* GetHostCache() override { return address_->GetHostCache(); }
  base::DictValue GetDnsConfigAsValue() const override {
    return address_->GetDnsConfigAsValue();
  }
  void SetRequestContext(net::URLRequestContext* context) override {
    address_->SetRequestContext(context);
  }
  bool IsHappyEyeballsV3Enabled() const override {
    return address_->IsHappyEyeballsV3Enabled();
  }

 private:
  std::shared_ptr<const EchPolicy> ForPort(uint16_t port) const {
    if (policy_->port)
      return policy_;
    auto policy = std::make_shared<EchPolicy>(*policy_);
    policy->port = port;
    return policy;
  }
  bool Matches(std::string_view host,
               const std::optional<Parameters>& params) const {
    if (host.ends_with('.'))
      host.remove_suffix(1);
    std::string_view expected = policy_->host;
    if (expected.ends_with('.'))
      expected.remove_suffix(1);
    auto type =
        params ? params->dns_query_type : net::DnsQueryType::UNSPECIFIED;
    return base::EqualsCaseInsensitiveASCII(host, expected) &&
           (type == net::DnsQueryType::UNSPECIFIED ||
            type == net::DnsQueryType::A || type == net::DnsQueryType::AAAA);
  }
  std::unique_ptr<net::HostResolver> address_;
  net::HostResolver*
      query_;  // Owned by address_, including its optional mapping wrapper.
  std::shared_ptr<const EchPolicy> policy_;
  std::shared_ptr<bool> closed_;
  std::shared_ptr<DnsReadiness> readiness_;
};
}  // namespace
std::unique_ptr<net::HostResolver> WrapEchResolver(
    std::unique_ptr<net::HostResolver> address_resolver,
    net::HostResolver* query_base,
    std::shared_ptr<const EchPolicy> policy,
    std::shared_ptr<DnsReadiness> readiness) {
  return std::make_unique<Resolver>(std::move(address_resolver), query_base,
                                    std::move(policy), std::move(readiness));
}
}  // namespace naive
