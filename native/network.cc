#include "naive_rs/network.h"
#include "naive_rs/ech.h"

#include <atomic>
#include <set>
#include <utility>
#include "base/functional/bind.h"
#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/no_destructor.h"
#include "base/task/single_thread_task_runner.h"
#include "base/task/thread_pool.h"
#include "build/build_config.h"
#include "net/base/address_list.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/base/network_change_notifier.h"
#include "net/base/port_util.h"
#include "net/dns/context_host_resolver.h"
#include "net/dns/dns_config_service.h"
#include "net/dns/host_resolver.h"
#include "net/dns/host_resolver_manager.h"
#include "net/dns/mapped_host_resolver.h"
#include "net/dns/public/host_resolver_results.h"
#include "net/dns/resolve_context.h"
#include "net/dns/system_dns_config_change_notifier.h"
#include "net/log/net_log.h"
#include "net/socket/client_socket_factory.h"
#include "net/socket/ssl_client_socket.h"
#include "net/socket/tcp_client_socket.h"
#include "net/socket/tcp_socket.h"
#include "net/socket/udp_client_socket.h"
#include "net/url_request/url_request_context_builder.h"
#if BUILDFLAG(IS_WIN)
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace {
#if BUILDFLAG(IS_WIN)
using SocketAddressLength = int;
#else
using SocketAddressLength = socklen_t;
#endif
// Unlike a bare descriptor, the completion payload closes unadopted sockets
// even if the recipient was canceled or the callback's WeakPtr is invalid.
class OwnedSocket {
 public:
  explicit OwnedSocket(intptr_t fd = -1) : fd_(fd) {}
  OwnedSocket(OwnedSocket&& other) : fd_(other.release()) {}
  ~OwnedSocket() {
    if (fd_ == -1)
      return;
#if BUILDFLAG(IS_WIN)
    closesocket(static_cast<SOCKET>(fd_));
#else
    close(static_cast<int>(fd_));
#endif
  }
  intptr_t get() const { return fd_; }
  intptr_t release() { return std::exchange(fd_, -1); }

 private:
  intptr_t fd_;
};
using NetworkResult = base::OnceCallback<void(int, std::string, OwnedSocket)>;
}  // namespace

struct naive_network_request
    : public base::RefCountedThreadSafe<naive_network_request> {
  explicit naive_network_request(NetworkResult done)
      : runner(base::SingleThreadTaskRunner::GetCurrentDefault()),
        done(std::move(done)) {}
  void Cancel() {
    DCHECK(runner->BelongsToCurrentThread());
    cancelled.store(true, std::memory_order_release);
    done.Reset();
  }
  void Complete(int result, std::string addresses, OwnedSocket socket) {
    runner->PostTask(
        FROM_HERE, base::BindOnce(
                       [](scoped_refptr<naive_network_request> self, int result,
                          std::string addresses, OwnedSocket socket) {
                         if (self->done &&
                             !self->cancelled.load(std::memory_order_acquire))
                           std::move(self->done)
                               .Run(result, std::move(addresses),
                                    std::move(socket));
                       },
                       base::WrapRefCounted(this), result, std::move(addresses),
                       std::move(socket)));
  }
  std::atomic<bool> cancelled{false};

 private:
  friend class base::RefCountedThreadSafe<naive_network_request>;
  ~naive_network_request() = default;
  scoped_refptr<base::SingleThreadTaskRunner> runner;
  NetworkResult done;
};

namespace naive {
NetworkHooks::NetworkHooks(const naive_network_hooks& value) : value(value) {
  value.retain(value.context);
}
NetworkHooks::~NetworkHooks() {
  value.release(value.context);
}
void NetworkHooks::Track(void* key, base::RepeatingClosure cancel) {
  pending_.insert_or_assign(key, std::move(cancel));
}
void NetworkHooks::Untrack(void* key) {
  pending_.erase(key);
}
void NetworkHooks::CancelPending() {
  while (!pending_.empty()) {
    auto it = pending_.begin();
    auto cancel = std::move(it->second);
    pending_.erase(it);
    cancel.Run();
  }
}
namespace {
struct NativeDnsSource {
  NativeDnsSource() {
    auto service = net::DnsConfigService::CreateSystemService();
    supported = !!service;
    notifier = std::make_unique<net::SystemDnsConfigChangeNotifier>(
        base::ThreadPool::CreateSequencedTaskRunner({base::MayBlock()}),
        std::move(service));
  }
  bool supported = false;
  std::unique_ptr<net::SystemDnsConfigChangeNotifier> notifier;
};
struct DnsBackend {
  std::unique_ptr<net::HostResolver> resolver;
  std::shared_ptr<DnsReadiness> readiness;
};
DnsBackend BuiltinEchResolver() {
  // The library has no process NetworkChangeNotifier. Supply its DNS watcher
  // and wait for the initial read rather than racing an empty configuration.
  static base::NoDestructor<NativeDnsSource> source;
  net::HostResolver::ManagerOptions options;
  options.insecure_dns_mode = net::InsecureDnsMode::kEnabledBuiltIn;
  auto manager = std::make_shared<net::HostResolverManager>(options, nullptr,
                                                            net::NetLog::Get());
  auto resolver = std::make_unique<net::ContextHostResolver>(
      manager.get(), std::make_unique<net::ResolveContext>(nullptr, true));
  auto readiness = std::make_shared<DnsReadiness>(
      source->notifier.get(), source->supported, std::move(manager));
  return {std::move(resolver), std::move(readiness)};
}

class ResolveRequest;
struct ResolverState {
  bool closed = false;
  std::set<ResolveRequest*> requests;
  std::shared_ptr<NetworkHooks> hooks;
};

class ResolveRequest : public net::HostResolver::ResolveHostRequest {
 public:
  ResolveRequest(std::shared_ptr<ResolverState> state,
                 net::HostPortPair host,
                 std::optional<net::HostResolver::ResolveHostParameters> params)
      : state_(std::move(state)), host_(std::move(host)), params_(params) {
    state_->requests.insert(this);
  }
  ~ResolveRequest() override {
    Cancel();
    state_->requests.erase(this);
  }
  void Cancel() {
    state_->hooks->Untrack(this);
    if (pending_)
      pending_->Cancel();
    pending_.reset();
    callback_.Reset();
  }
  int Start(net::CompletionOnceCallback callback) override {
    if (state_->closed)
      return Fail(net::ERR_CONTEXT_SHUT_DOWN);
    auto type =
        params_ ? params_->dns_query_type : net::DnsQueryType::UNSPECIFIED;
    https_query_ = type == net::DnsQueryType::HTTPS;
    family_ = type == net::DnsQueryType::A      ? 4
              : type == net::DnsQueryType::AAAA ? 6
                                                : 0;
    if (type != net::DnsQueryType::UNSPECIFIED &&
        type != net::DnsQueryType::A && type != net::DnsQueryType::AAAA &&
        type != net::DnsQueryType::HTTPS)
      return Fail(net::ERR_NAME_NOT_RESOLVED);
    net::IPAddress literal;
    std::string hostname = host_.host();
    if (!https_query_ && literal.AssignFromIPLiteral(hostname)) {
      if (Accept(literal)) {
        addresses_.push_back(net::IPEndPoint(literal, host_.port()));
        FinishResults();
        return net::OK;
      }
      return Fail(net::ERR_NAME_NOT_RESOLVED);
    }
    // LOCAL_ONLY requests must never cause network activity.
    if (params_ && params_->source == net::HostResolverSource::LOCAL_ONLY)
      return Fail(net::ERR_DNS_CACHE_MISS);
    callback_ = std::move(callback);
    pending_ = base::MakeRefCounted<naive_network_request>(
        base::BindOnce(&ResolveRequest::Completed, weak_.GetWeakPtr()));
    state_->hooks->Track(
        this, base::BindRepeating(&ResolveRequest::Abort, weak_.GetWeakPtr()));
    pending_->AddRef();  // transferred to the host completion
    if (https_query_ && host_.port() != 443)
      hostname = "_" + std::to_string(host_.port()) + "._https." + hostname;
    state_->hooks->value.resolve(state_->hooks->value.context, hostname.c_str(),
                                 https_query_ ? 65 : family_, pending_.get());
    return net::ERR_IO_PENDING;
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
    return std::nullopt;
  }

 private:
  int Fail(int result) {
    error_ = net::ResolveErrorInfo(result);
    return result;
  }
  bool Accept(const net::IPAddress& ip) const {
    return (!family_ || (family_ == 4 && ip.IsIPv4()) ||
            (family_ == 6 && ip.IsIPv6())) &&
           (!params_ || !params_->loopback_only || ip.IsLoopback());
  }
  void FinishResults() {
    endpoints_.emplace_back();
    endpoints_.back().ip_endpoints.assign(addresses_.begin(), addresses_.end());
    endpoints_.back().metadata.ech_config_list = ech_config_;
    endpoints_.back().metadata.target_name = host_.host();
    aliases_.insert(host_.host());
  }
  void Abort() {
    auto callback = std::move(callback_);
    Cancel();
    error_ = net::ResolveErrorInfo(net::ERR_ABORTED);
    if (callback)
      std::move(callback).Run(net::ERR_ABORTED);
  }
  void Completed(int result, std::string json, OwnedSocket) {
    state_->hooks->Untrack(this);
    pending_.reset();
    if (result == net::OK) {
      auto value = base::JSONReader::Read(json, base::JSON_PARSE_RFC);
      const base::ListValue* values = nullptr;
      const base::ListValue* ech = nullptr;
      if (value && value->is_list())
        values = &value->GetList();
      if (value && value->is_dict()) {
        values = value->GetDict().FindList("addresses");
        ech = value->GetDict().FindList("ech");
      }
      if (!values || values->size() > 64 ||
          (!https_query_ && values->empty())) {
        result = net::ERR_NAME_NOT_RESOLVED;
      } else {
        for (const auto& item : *values) {
          net::IPAddress ip;
          if (!item.is_string() || !ip.AssignFromIPLiteral(item.GetString())) {
            result = net::ERR_NAME_NOT_RESOLVED;
            break;
          }
          if (Accept(ip))
            addresses_.push_back(net::IPEndPoint(ip, host_.port()));
        }
        if (ech) {
          if (ech->size() > 65537)
            result = net::ERR_DNS_MALFORMED_RESPONSE;
          else
            for (const auto& byte : *ech) {
              if (!byte.is_int() || byte.GetInt() < 0 || byte.GetInt() > 255) {
                result = net::ERR_DNS_MALFORMED_RESPONSE;
                break;
              }
              ech_config_.push_back(static_cast<uint8_t>(byte.GetInt()));
            }
        }
        if (addresses_.empty() && ech_config_.empty())
          result = net::ERR_NAME_NOT_RESOLVED;
      }
    }
    if (result == net::OK)
      FinishResults();
    else
      addresses_ = net::AddressList();
    error_ = net::ResolveErrorInfo(result);
    std::move(callback_).Run(result);
  }
  std::shared_ptr<ResolverState> state_;
  net::HostPortPair host_;
  std::optional<net::HostResolver::ResolveHostParameters> params_;
  int family_ = 0;
  bool https_query_ = false;
  std::vector<uint8_t> ech_config_;
  net::AddressList addresses_;
  net::HostResolverEndpointResults endpoints_;
  std::set<std::string> aliases_;
  net::ResolveErrorInfo error_;
  std::optional<net::HostCache::EntryStaleness> stale_;
  scoped_refptr<naive_network_request> pending_;
  net::CompletionOnceCallback callback_;
  base::WeakPtrFactory<ResolveRequest> weak_{this};
};

class ServiceRequest : public net::HostResolver::ServiceEndpointRequest {
 public:
  explicit ServiceRequest(std::unique_ptr<ResolveRequest> request)
      : request_(std::move(request)) {}
  int Start(Delegate* delegate) override {
    delegate_ = delegate;
    int rv = request_->Start(
        base::BindOnce(&ServiceRequest::Completed, base::Unretained(this)));
    if (rv != net::ERR_IO_PENDING)
      BuildResults();
    return rv;
  }
  base::span<const net::ServiceEndpoint> GetEndpointResults() override {
    return endpoints_;
  }
  const std::set<std::string>& GetDnsAliasResults() override {
    return request_->GetDnsAliasResults();
  }
  bool EndpointsCryptoReady() override { return ready_; }
  net::ResolveErrorInfo GetResolveErrorInfo() override {
    return request_->GetResolveErrorInfo();
  }
  const net::HostCache::EntryStaleness* GetStaleInfo() const override {
    return nullptr;
  }
  bool IsStaleWhileRefreshing() const override { return false; }
  void ChangeRequestPriority(net::RequestPriority) override {}
  std::optional<net::ResolutionDetails> GetResolutionDetails() const override {
    return std::nullopt;
  }

 private:
  void BuildResults() {
    ready_ = true;
    if (request_->GetAddressResults().empty())
      return;
    endpoints_.emplace_back();
    for (const auto& address : request_->GetAddressResults()) {
      auto& list = address.address().IsIPv4()
                       ? endpoints_.back().ipv4_endpoints
                       : endpoints_.back().ipv6_endpoints;
      list.push_back(address);
    }
  }
  void Completed(int rv) {
    BuildResults();
    delegate_->OnServiceEndpointRequestFinished(rv);
  }
  std::unique_ptr<ResolveRequest> request_;
  Delegate* delegate_ = nullptr;
  bool ready_ = false;
  std::vector<net::ServiceEndpoint> endpoints_;
};

class Resolver : public net::HostResolver {
 public:
  explicit Resolver(std::shared_ptr<NetworkHooks> hooks)
      : state_(std::make_shared<ResolverState>()) {
    state_->hooks = std::move(hooks);
  }
  ~Resolver() override { OnShutdown(); }
  // Resolution is delegated to host hooks, with no URLRequestContext IO.
  void SetRequestContext(net::URLRequestContext*) override {}
  void OnShutdown() override {
    state_->closed = true;
    for (auto* request : state_->requests)
      request->Cancel();
  }
  std::unique_ptr<ResolveHostRequest> CreateRequest(
      url::SchemeHostPort host,
      net::NetworkAnonymizationKey key,
      net::handles::NetworkHandle network,
      net::NetLogWithSource log,
      std::optional<ResolveHostParameters> params) override {
    return std::make_unique<ResolveRequest>(
        state_, net::HostPortPair::FromSchemeHostPort(host), params);
  }
  std::unique_ptr<ResolveHostRequest> CreateRequest(
      const net::HostPortPair& host,
      const net::NetworkAnonymizationKey& key,
      net::handles::NetworkHandle network,
      const net::NetLogWithSource& log,
      const std::optional<ResolveHostParameters>& params) override {
    return std::make_unique<ResolveRequest>(state_, host, params);
  }
  std::unique_ptr<ServiceEndpointRequest> CreateServiceEndpointRequest(
      Host host,
      net::NetworkAnonymizationKey key,
      net::handles::NetworkHandle network,
      net::NetLogWithSource log,
      ResolveHostParameters params) override {
    return std::make_unique<ServiceRequest>(std::make_unique<ResolveRequest>(
        state_,
        net::HostPortPair(std::string(host.GetHostnameWithoutBrackets()),
                          host.GetPort()),
        params));
  }
  bool IsHappyEyeballsV3Enabled() const override { return false; }

 private:
  std::shared_ptr<ResolverState> state_;
};

// Host dialing replaces only TCP connection establishment. Once adopted, IO,
// TLS, HTTP/2, pooling and proxy negotiation use Chromium's ordinary sockets.
class DialSocket : public net::TransportClientSocket {
 public:
  DialSocket(std::shared_ptr<NetworkHooks> hooks,
             net::AddressList addresses,
             net::NetLog* log,
             const net::NetLogSource& source)
      : hooks_(std::move(hooks)),
        addresses_(std::move(addresses)),
        log_(net::NetLogWithSource::Make(log, net::NetLogSourceType::SOCKET)) {}
  ~DialSocket() override { Disconnect(); }
  int Bind(const net::IPEndPoint&) override { return net::ERR_NOT_IMPLEMENTED; }
  void SetBeforeConnectCallback(
      const BeforeConnectCallback& callback) override {
    before_ = callback;
  }
  int Connect(net::CompletionOnceCallback callback) override {
    if (socket_ && socket_->IsConnected())
      return net::OK;
    if (pending_)
      return net::ERR_UNEXPECTED;
    for (const auto& address : addresses_)
      if (!net::IsPortAllowedForIpEndpoint(address))
        return net::ERR_UNSAFE_PORT;
    callback_ = std::move(callback);
    pending_ = base::MakeRefCounted<naive_network_request>(
        base::BindOnce(&DialSocket::Completed, weak_.GetWeakPtr()));
    base::ListValue list;
    for (const auto& address : addresses_)
      list.Append(address.ToString());
    std::string json;
    base::JSONWriter::Write(list, &json);
    hooks_->Track(this,
                  base::BindRepeating(&DialSocket::Abort, weak_.GetWeakPtr()));
    pending_->AddRef();
    hooks_->value.dial_tcp(hooks_->value.context, json.c_str(), pending_.get());
    return net::ERR_IO_PENDING;
  }
  void Disconnect() override {
    hooks_->Untrack(this);
    if (pending_)
      pending_->Cancel();
    pending_.reset();
    callback_.Reset();
    if (socket_)
      socket_->Disconnect();
    socket_.reset();
  }
  bool IsConnected() const override {
    return socket_ && socket_->IsConnected();
  }
  bool IsConnectedAndIdle() const override {
    return socket_ && socket_->IsConnectedAndIdle();
  }
  int GetPeerAddress(net::IPEndPoint* address) const override {
    return socket_ ? socket_->GetPeerAddress(address)
                   : net::ERR_SOCKET_NOT_CONNECTED;
  }
  int GetLocalAddress(net::IPEndPoint* address) const override {
    return socket_ ? socket_->GetLocalAddress(address)
                   : net::ERR_SOCKET_NOT_CONNECTED;
  }
  const net::NetLogWithSource& NetLog() const override { return log_; }
  bool WasEverUsed() const override {
    return socket_ && socket_->WasEverUsed();
  }
  net::NextProto GetNegotiatedProtocol() const override {
    return net::NextProto::kProtoUnknown;
  }
  bool GetSSLInfo(net::SSLInfo*) override { return false; }
  int64_t GetTotalReceivedBytes() const override {
    return socket_ ? socket_->GetTotalReceivedBytes() : 0;
  }
  void ApplySocketTag(const net::SocketTag& tag) override {
    tag_ = tag;
    if (socket_)
      socket_->ApplySocketTag(tag);
  }
  bool SetNoDelay(bool value) override {
    return socket_ && socket_->SetNoDelay(value);
  }
  bool SetKeepAlive(bool value, int delay) override {
    return socket_ && socket_->SetKeepAlive(value, delay);
  }
  int Read(net::IOBuffer* buffer,
           int size,
           net::CompletionOnceCallback callback) override {
    return socket_ ? socket_->Read(buffer, size, std::move(callback))
                   : net::ERR_SOCKET_NOT_CONNECTED;
  }
  int ReadIfReady(net::IOBuffer* buffer,
                  int size,
                  net::CompletionOnceCallback callback) override {
    return socket_ ? socket_->ReadIfReady(buffer, size, std::move(callback))
                   : net::ERR_SOCKET_NOT_CONNECTED;
  }
  int CancelReadIfReady() override {
    return socket_ ? socket_->CancelReadIfReady()
                   : net::ERR_SOCKET_NOT_CONNECTED;
  }
  int Write(net::IOBuffer* buffer,
            int size,
            net::CompletionOnceCallback callback,
            const net::NetworkTrafficAnnotationTag& annotation) override {
    return socket_
               ? socket_->Write(buffer, size, std::move(callback), annotation)
               : net::ERR_SOCKET_NOT_CONNECTED;
  }
  int SetReceiveBufferSize(int32_t size) override {
    return socket_ ? socket_->SetReceiveBufferSize(size)
                   : net::ERR_SOCKET_NOT_CONNECTED;
  }
  int SetSendBufferSize(int32_t size) override {
    return socket_ ? socket_->SetSendBufferSize(size)
                   : net::ERR_SOCKET_NOT_CONNECTED;
  }

 private:
  void Abort() {
    auto callback = std::move(callback_);
    Disconnect();
    if (callback)
      std::move(callback).Run(net::ERR_ABORTED);
  }
  void Completed(int result, std::string, OwnedSocket fd) {
    hooks_->Untrack(this);
    pending_.reset();
    if (result == net::OK) {
      sockaddr_storage storage{};
      SocketAddressLength length = sizeof(storage);
      net::IPEndPoint peer;
      if (fd.get() == -1 ||
          getpeername(static_cast<net::SocketDescriptor>(fd.get()),
                      reinterpret_cast<sockaddr*>(&storage), &length) != 0 ||
          !peer.FromSockAddr(reinterpret_cast<sockaddr*>(&storage), length)) {
        result = net::ERR_SOCKET_NOT_CONNECTED;
      } else {
        auto tcp = net::TCPSocket::Create(nullptr, log_);
        result = tcp->AdoptConnectedSocket(
            static_cast<net::SocketDescriptor>(fd.release()), peer);
        if (result == net::OK) {
          tcp->SetDefaultOptionsForClient();
          socket_ =
              std::make_unique<net::TCPClientSocket>(std::move(tcp), peer);
          socket_->ApplySocketTag(tag_);
          if (before_)
            result = before_.Run();
        }
      }
    }
    if (result == net::ERR_IO_PENDING || result > 0)
      result = net::ERR_FAILED;
    if (result != net::OK)
      socket_.reset();
    std::move(callback_).Run(result);
  }
  std::shared_ptr<NetworkHooks> hooks_;
  net::AddressList addresses_;
  net::NetLogWithSource log_;
  net::SocketTag tag_;
  BeforeConnectCallback before_;
  std::unique_ptr<net::TCPClientSocket> socket_;
  scoped_refptr<naive_network_request> pending_;
  net::CompletionOnceCallback callback_;
  base::WeakPtrFactory<DialSocket> weak_{this};
};

class DialDatagramSocket : public net::DatagramClientSocket {
 public:
  DialDatagramSocket(std::shared_ptr<NetworkHooks> hooks,
                     net::DatagramSocket::BindType bind,
                     net::handles::NetworkHandle network,
                     net::NetLog* log,
                     const net::NetLogSource& source)
      : hooks_(std::move(hooks)),
        network_(network),
        socket_(std::make_unique<net::UDPClientSocket>(
            bind,
            log,
            source,
            net::handles::kInvalidNetworkHandle)) {}
  ~DialDatagramSocket() override { Close(); }
  // Host callbacks are asynchronous; QUIC's async session path is required.
  int Connect(const net::IPEndPoint&) override {
    return net::ERR_NOT_IMPLEMENTED;
  }
  int ConnectUsingNetwork(net::handles::NetworkHandle,
                          const net::IPEndPoint&) override {
    return net::ERR_NOT_IMPLEMENTED;
  }
  int ConnectUsingDefaultNetwork(const net::IPEndPoint&) override {
    return net::ERR_NOT_IMPLEMENTED;
  }
  int ConnectAsync(const net::IPEndPoint& peer,
                   net::CompletionOnceCallback callback) override {
    if (started_)
      return net::ERR_UNEXPECTED;
    if (!net::IsPortAllowedForIpEndpoint(peer))
      return net::ERR_UNSAFE_PORT;
    started_ = true;
    peer_ = peer;
    callback_ = std::move(callback);
    pending_ = base::MakeRefCounted<naive_network_request>(
        base::BindOnce(&DialDatagramSocket::Completed, weak_.GetWeakPtr()));
    hooks_->Track(this, base::BindRepeating(&DialDatagramSocket::Abort,
                                            weak_.GetWeakPtr()));
    pending_->AddRef();
    hooks_->value.dial_udp(hooks_->value.context, peer.ToString().c_str(),
                           network_, pending_.get());
    return net::ERR_IO_PENDING;
  }
  int ConnectUsingNetworkAsync(net::handles::NetworkHandle network,
                               const net::IPEndPoint& peer,
                               net::CompletionOnceCallback callback) override {
    network_ = network;
    return ConnectAsync(peer, std::move(callback));
  }
  int ConnectUsingDefaultNetworkAsync(
      const net::IPEndPoint& peer,
      net::CompletionOnceCallback callback) override {
    network_ = net::NetworkChangeNotifier::GetDefaultNetwork();
    return ConnectAsync(peer, std::move(callback));
  }
  net::handles::NetworkHandle GetBoundNetwork() const override {
    return network_;
  }
  void Close() override {
    hooks_->Untrack(this);
    if (pending_)
      pending_->Cancel();
    pending_.reset();
    callback_.Reset();
    socket_->Close();
  }
  int GetPeerAddress(net::IPEndPoint* address) const override {
    return socket_->GetPeerAddress(address);
  }
  int GetLocalAddress(net::IPEndPoint* address) const override {
    return socket_->GetLocalAddress(address);
  }
  void UseNonBlockingIO() override { socket_->UseNonBlockingIO(); }
  int SetReceiveBufferSize(int32_t size) override {
    return socket_->SetReceiveBufferSize(size);
  }
  int SetSendBufferSize(int32_t size) override {
    return socket_->SetSendBufferSize(size);
  }
  int SetDoNotFragment() override { return socket_->SetDoNotFragment(); }
  int SetRecvTos() override { return socket_->SetRecvTos(); }
  int SetTos(net::DiffServCodePoint dscp, net::EcnCodePoint ecn) override {
    return socket_->SetTos(dscp, ecn);
  }
  void SetMsgConfirm(bool value) override { socket_->SetMsgConfirm(value); }
  const net::NetLogWithSource& NetLog() const override {
    return socket_->NetLog();
  }
  net::DscpAndEcn GetLastTos() const override { return socket_->GetLastTos(); }
  int Read(net::IOBuffer* buffer,
           int size,
           net::CompletionOnceCallback callback) override {
    return socket_->Read(buffer, size, std::move(callback));
  }
  base::expected<net::DatagramsMetadata, net::Error> ReadMultiple(
      net::IOBuffer* buffer,
      size_t size,
      size_t packet,
      base::OnceCallback<void(base::expected<net::DatagramsMetadata,
                                             net::Error>)> callback) override {
    return socket_->ReadMultiple(buffer, size, packet, std::move(callback));
  }
  int Write(net::IOBuffer* buffer,
            int size,
            net::CompletionOnceCallback callback,
            const net::NetworkTrafficAnnotationTag& annotation) override {
    return socket_->Write(buffer, size, std::move(callback), annotation);
  }
  void ApplySocketTag(const net::SocketTag& tag) override {
    socket_->ApplySocketTag(tag);
  }
  void EnableRecvOptimization() override { socket_->EnableRecvOptimization(); }
  int SetMulticastInterface(uint32_t index) override {
    return socket_->SetMulticastInterface(index);
  }
  void SetIOSNetworkServiceType(int value) override {
    socket_->SetIOSNetworkServiceType(value);
  }
  void RegisterQuicConnectionClosePayload(
      base::span<uint8_t> payload) override {
    socket_->RegisterQuicConnectionClosePayload(payload);
  }
  void UnregisterQuicConnectionClosePayload() override {
    socket_->UnregisterQuicConnectionClosePayload();
  }

 private:
  void Abort() {
    // callback owns the socket during async QUIC creation. Move it out before
    // closing, then report failure to release that owner even without a host
    // completion. Do not access members after invoking it.
    auto callback = std::move(callback_);
    Close();
    if (callback)
      std::move(callback).Run(net::ERR_ABORTED);
  }
  void Completed(int result, std::string, OwnedSocket fd) {
    hooks_->Untrack(this);
    pending_.reset();
    if (result == net::OK) {
      if (fd.get() == -1)
        result = net::ERR_INVALID_HANDLE;
      else {
        sockaddr_storage storage{};
        SocketAddressLength length = sizeof(storage);
        net::IPEndPoint peer = peer_;
        if (getpeername(static_cast<net::SocketDescriptor>(fd.get()),
                        reinterpret_cast<sockaddr*>(&storage), &length) == 0 &&
            !peer.FromSockAddr(reinterpret_cast<sockaddr*>(&storage), length))
          result = net::ERR_ADDRESS_INVALID;
        if (result == net::OK) {
          result = socket_->AdoptOpenedSocket(
              peer.GetFamily(), static_cast<net::SocketDescriptor>(fd.get()));
          // Both pinned POSIX and Windows implementations leave ownership with
          // the caller ONLY when the global UDP-socket limit is reached. All
          // other results consume the descriptor (including setup failures).
          if (result != net::ERR_INSUFFICIENT_RESOURCES)
            fd.release();
          if (result == net::OK)
            result = socket_->Connect(peer);
        }
      }
    }
    if (result != net::OK)
      socket_->Close();
    std::move(callback_).Run(result);
  }
  std::shared_ptr<NetworkHooks> hooks_;
  net::handles::NetworkHandle network_;
  std::unique_ptr<net::UDPClientSocket> socket_;
  net::IPEndPoint peer_;
  bool started_ = false;
  net::CompletionOnceCallback callback_;
  scoped_refptr<naive_network_request> pending_;
  base::WeakPtrFactory<DialDatagramSocket> weak_{this};
};

class SocketFactory : public net::ClientSocketFactory {
 public:
  explicit SocketFactory(std::shared_ptr<NetworkHooks> hooks)
      : hooks_(std::move(hooks)) {}
  std::unique_ptr<net::DatagramClientSocket> CreateDatagramClientSocket(
      net::DatagramSocket::BindType bind,
      net::handles::NetworkHandle network,
      net::NetLog* log,
      const net::NetLogSource& source) override {
    if (hooks_->value.dial_udp)
      return std::make_unique<DialDatagramSocket>(hooks_, bind, network, log,
                                                  source);
    auto socket =
        std::make_unique<net::UDPClientSocket>(bind, log, source, network);
    if (hooks_->value.control)
      socket->SetSocketControlCallback(Control(17));
    return socket;
  }
  std::unique_ptr<net::TransportClientSocket> CreateTransportClientSocket(
      const net::AddressList& addresses,
      net::handles::NetworkHandle network,
      std::unique_ptr<net::SocketPerformanceWatcher> watcher,
      net::NetworkQualityEstimator* estimator,
      net::NetLog* log,
      const net::NetLogSource& source) override {
    if (hooks_->value.dial_tcp)
      return std::make_unique<DialSocket>(hooks_, addresses, log, source);
    auto socket = std::make_unique<net::TCPClientSocket>(
        addresses, std::move(watcher), estimator, log, source, network);
    if (hooks_->value.control)
      socket->SetSocketControlCallback(Control(6));
    return socket;
  }
  std::unique_ptr<net::SSLClientSocket> CreateSSLClientSocket(
      net::SSLClientContext* context,
      std::unique_ptr<net::StreamSocket> socket,
      const net::HostPortPair& host,
      const net::SSLConfig& config) override {
    return net::ClientSocketFactory::GetDefaultFactory()->CreateSSLClientSocket(
        context, std::move(socket), host, config);
  }

 private:
  net::TCPClientSocket::SocketControlCallback Control(int protocol) {
    return base::BindRepeating(
        [](std::shared_ptr<NetworkHooks> hooks, int protocol,
           net::SocketDescriptor socket, const net::IPEndPoint& peer) {
          int rv = hooks->value.control(hooks->value.context,
                                        static_cast<intptr_t>(socket), protocol,
                                        peer.ToString().c_str());
          return rv == net::ERR_IO_PENDING || rv > 0 ? net::ERR_FAILED : rv;
        },
        hooks_, protocol);
  }
  std::shared_ptr<NetworkHooks> hooks_;
};
}  // namespace

void ConfigureNetwork(std::shared_ptr<NetworkHooks> hooks,
                      std::string rules,
                      std::shared_ptr<const EchPolicy> ech,
                      net::URLRequestContextBuilder& builder) {
  if ((hooks && hooks->value.resolve) ||
      (ech && ech->mode != net::EchMode::kDisabled)) {
    std::unique_ptr<net::HostResolver> resolver;
    std::shared_ptr<DnsReadiness> readiness;
    if (hooks && hooks->value.resolve) {
      resolver = std::make_unique<Resolver>(hooks);
    } else if (ech && ech->config_list.empty()) {
      auto backend = BuiltinEchResolver();
      resolver = std::move(backend.resolver);
      readiness = std::move(backend.readiness);
    } else {
      resolver =
          net::HostResolver::CreateStandaloneResolver(net::NetLog::Get());
    }
    auto* query_base = resolver.get();
    if (!rules.empty()) {
      auto mapped =
          std::make_unique<net::MappedHostResolver>(std::move(resolver));
      mapped->SetRulesFromString(rules);
      resolver = std::move(mapped);
    }
    if (ech && ech->mode != net::EchMode::kDisabled)
      resolver = WrapEchResolver(std::move(resolver), query_base,
                                 std::move(ech), std::move(readiness));
    builder.set_host_mapping_rules("");
    builder.set_host_resolver(std::move(resolver));
  } else if (!rules.empty()) {
    builder.set_host_mapping_rules(rules);
  }
  if (hooks &&
      (hooks->value.control || hooks->value.dial_tcp || hooks->value.dial_udp))
    builder.set_client_socket_factory(
        std::make_unique<SocketFactory>(std::move(hooks)));
}

}  // namespace naive

extern "C" {
void naive_network_request_retain(naive_network_request* request) {
  request->AddRef();
}
void naive_network_request_release(naive_network_request* request) {
  request->Release();
}
int32_t naive_network_request_is_cancelled(naive_network_request* request) {
  return request->cancelled.load(std::memory_order_acquire);
}
void naive_resolve_complete(naive_network_request* request,
                            int32_t result,
                            const char* addresses) {
  if (result == net::ERR_IO_PENDING || result > 0)
    result = net::ERR_NAME_NOT_RESOLVED;
  request->Complete(result, addresses ? addresses : "", OwnedSocket());
  request->Release();
}
void naive_dial_udp_complete(naive_network_request* request,
                             int32_t result,
                             intptr_t socket) {
  if (result == net::ERR_IO_PENDING || result > 0)
    result = net::ERR_FAILED;
  request->Complete(result, "", OwnedSocket(socket));
  request->Release();
}
void naive_dial_tcp_complete(naive_network_request* request,
                             int32_t result,
                             intptr_t socket) {
  if (result == net::ERR_IO_PENDING || result > 0)
    result = net::ERR_FAILED;
  request->Complete(result, "", OwnedSocket(socket));
  request->Release();
}
}
