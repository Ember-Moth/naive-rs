#include "base/task/bind_post_task.h"
#include "naive_rs/ech.h"
#include "naive_rs/network.h"
#include "net/base/features.h"
#include "net/dns/host_cache.h"
#include "net/dns/host_resolver.h"
// Copyright 2026 naive-rs contributors. BSD-3-Clause.
#include "naive_rs/include/naive.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/compiler_specific.h"
#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/json/json_reader.h"
#include "base/logging.h"
#include "base/memory/weak_ptr.h"
#include "base/strings/string_number_conversions.h"
#include "base/task/single_thread_task_runner.h"
#include "base/task/thread_pool/thread_pool_instance.h"
#include "base/threading/thread.h"
#include "base/timer/timer.h"
#include "components/version_info/version_info.h"
#include "net/base/io_buffer.h"
#include "net/base/load_flags.h"
#include "net/base/net_errors.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/url_util.h"
#include "net/cert/caching_cert_verifier.h"
#include "net/cert/cert_verify_proc.h"
#include "net/cert/crl_set.h"
#include "net/cert/do_nothing_ct_verifier.h"
#include "net/cert/multi_threaded_cert_verifier.h"
#include "net/cert/x509_util.h"
#include "net/cert_net/cert_net_fetcher_url_request.h"
#include "net/http/http_network_session.h"
#include "net/http/http_transaction_factory.h"
#include "net/log/file_net_log_observer.h"
#include "net/log/net_log.h"
#include "net/log/net_log_with_source.h"
#include "net/proxy_resolution/proxy_info.h"
#include "net/socket/client_socket_handle.h"
#include "net/socket/client_socket_pool_manager.h"
#include "net/socket/stream_socket.h"
#include "net/ssl/ssl_connection_status_flags.h"
#include "net/ssl/ssl_info.h"
#include "net/tools/naive/naive_config.h"
#include "net/tools/naive/naive_context.h"
#include "net/tools/naive/naive_padding_socket.h"
#include "net/tools/naive/naive_proxy_delegate.h"
#include "net/tools/naive/preamble_getter.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "net/url_request/url_request_context.h"
#include "third_party/boringssl/src/include/openssl/pool.h"
#include "url/url_util.h"

namespace {
std::atomic<uint64_t> buffer_allocations{0}, live_buffers{0}, live_capacity{0},
    peak_capacity{0};
}

// The payload has no thread affinity. READ leases survive engine shutdown;
// WRITTEN returns sole ownership to Rust for reuse in a later submission.
struct naive_buffer : base::RefCountedThreadSafe<naive_buffer> {
  explicit naive_buffer(size_t size)
      : io(base::MakeRefCounted<net::IOBufferWithSize>(static_cast<int>(size))),
        capacity(size) {
    buffer_allocations.fetch_add(1, std::memory_order_relaxed);
    live_buffers.fetch_add(1, std::memory_order_relaxed);
    auto current =
        live_capacity.fetch_add(size, std::memory_order_relaxed) + size;
    auto peak = peak_capacity.load(std::memory_order_relaxed);
    while (peak < current && !peak_capacity.compare_exchange_weak(
                                 peak, current, std::memory_order_relaxed)) {
    }
  }
  scoped_refptr<net::IOBufferWithSize> io;
  const size_t capacity;

 private:
  friend class base::RefCountedThreadSafe<naive_buffer>;
  ~naive_buffer() {
    live_buffers.fetch_sub(1, std::memory_order_relaxed);
    live_capacity.fetch_sub(capacity, std::memory_order_relaxed);
  }
};

namespace {
constexpr size_t kMaxIO = 64 * 1024;

// Ownership belongs to the IOBuffer itself, not just the Stream or its task.
// Lower layers may keep this object after Stream::Close has returned.
class OwnedIOBuffer final : public net::IOBuffer {
 public:
  OwnedIOBuffer(uint8_t* data, size_t capacity, void* context,
                naive_owned_callback completed)
      : net::IOBuffer(base::span(data, capacity)), context_(context),
        completed_(completed) {}
  void Complete(int result, size_t transferred) {
    if (finished_)
      return;
    finished_ = true;
    result_ = result;
    transferred_ = transferred;
  }

 private:
  ~OwnedIOBuffer() override {
    ClearSpan();
    completed_(context_, result_, transferred_);
  }
  void* context_;
  naive_owned_callback completed_;
  int result_ = net::ERR_ABORTED;
  size_t transferred_ = 0;
  bool finished_ = false;
};
constexpr auto kAnnotation = net::DefineNetworkTrafficAnnotation("naive", "");

// Chromium process globals and the IO runner intentionally live until process
// exit. Each client owns and explicitly destroys only its network context.
// The host allocator is never replaced (use_allocator_shim=false).
class Runtime {
 public:
  static Runtime& Get() {
    static Runtime* runtime = new Runtime;
    return *runtime;
  }
  scoped_refptr<base::SingleThreadTaskRunner> SelectRunner(size_t width) {
    if (!width || width > workers_.size())
      return nullptr;
    std::lock_guard guard(lock_);
    size_t index = next_++ % width;
    if (!workers_[index]) {
      auto thread = std::make_unique<base::Thread>("naive-rs-io-" +
                                                   std::to_string(index));
      base::Thread::Options options;
      options.message_pump_type = base::MessagePumpType::IO;
      if (!thread->StartWithOptions(std::move(options)))
        return nullptr;
      workers_[index] = std::move(thread);
    }
    return workers_[index]->task_runner();
  }

 private:
  Runtime() {
    if (!base::CommandLine::InitializedForCurrentProcess())
      base::CommandLine::Init(0, nullptr);
    if (!base::FeatureList::GetInstance()) {
      base::FeatureList::InitInstance(
          "PartitionConnectionsByNetworkIsolationKey,QuicUseReadMultiple,"
          "EnableUdpGro,IgnoreQuicCryptoConfigMemoryPressure,AsyncQuicSession",
          "");
    }
    if (!base::ThreadPoolInstance::Get())
      base::ThreadPoolInstance::CreateAndStartWithDefaultParams("naive-rs");
    url::AddStandardScheme("quic",
                           url::SCHEME_WITH_HOST_PORT_AND_USER_INFORMATION);
    url::AddStandardScheme("socks",
                           url::SCHEME_WITH_HOST_PORT_AND_USER_INFORMATION);
    logging::LoggingSettings settings;
    settings.logging_dest = logging::LOG_NONE;
    logging::InitLogging(settings);
    net::ClientSocketPoolManager::set_socket_soft_cap_per_pool_for_test(
        net::HttpNetworkSession::SocketPoolType::kNormal, 2048);
    net::ClientSocketPoolManager::set_max_sockets_per_proxy_chain(
        net::HttpNetworkSession::SocketPoolType::kNormal, 2048);
    net::ClientSocketPoolManager::set_max_sockets_per_group_for_test(
        net::HttpNetworkSession::SocketPoolType::kNormal, 2040);
    net::ClientSocketPool::set_used_idle_socket_timeout(base::Seconds(60));
  }
  base::AtExitManager at_exit_;
  std::mutex lock_;
  std::array<std::unique_ptr<base::Thread>, 8> workers_;
  size_t next_ = 0;
};

class FixedVerifierFactory final : public net::CertVerifyProcFactory {
 public:
  explicit FixedVerifierFactory(scoped_refptr<net::CertVerifyProc> proc)
      : proc_(std::move(proc)) {}
  scoped_refptr<net::CertVerifyProc> CreateCertVerifyProc(
      scoped_refptr<net::CertNetFetcher>,
      const net::CertVerifyProc::ImplParams&,
      const net::CertVerifyProc::InstanceParams&) override {
    return proc_;
  }

 private:
  ~FixedVerifierFactory() override = default;
  scoped_refptr<net::CertVerifyProc> proc_;
};

std::unique_ptr<net::CertVerifier> AdditionalRoots(
    std::string_view pem,
    scoped_refptr<net::CertNetFetcher> fetcher) {
#if BUILDFLAG(CHROME_ROOT_STORE_SUPPORTED)
  auto certs = net::X509Certificate::CreateCertificateListFromBytes(
      base::as_byte_span(pem), net::X509Certificate::FORMAT_PEM_CERT_SEQUENCE);
  if (certs.empty())
    return nullptr;
  net::CertVerifyProc::InstanceParams params;
  for (const auto& cert : certs) {
    auto parsed = bssl::ParsedCertificate::Create(
        bssl::UpRef(cert->cert_buffer()),
        net::x509_util::DefaultParseCertificateOptions(), nullptr);
    if (!parsed)
      return nullptr;
    params.additional_trust_anchors.push_back(std::move(parsed));
  }
  auto proc = net::CertVerifyProc::CreateBuiltinWithChromeRootStore(
      std::move(fetcher), net::CRLSet::BuiltinCRLSet(),
      std::make_unique<net::DoNothingCTVerifier>(),
      base::MakeRefCounted<net::DefaultCTPolicyEnforcer>(), nullptr, nullptr,
      params, std::nullopt);
  auto factory = base::MakeRefCounted<FixedVerifierFactory>(proc);
  return std::make_unique<net::CachingCertVerifier>(
      std::make_unique<net::MultiThreadedCertVerifier>(proc, factory));
#else
  return nullptr;
#endif
}

bool ReadContextOptions(const base::DictValue& json,
                        net::NaiveContextOptions* options) {
  auto http = [&](const char* key, int minimum,
                  std::optional<int32_t>* output) {
    if (!json.Find(key))
      return true;
    auto value = json.FindInt(key);
    if (!value || *value < minimum)
      return false;
    *output = *value;
    return true;
  };
  auto quic_window = [&](const char* key, std::optional<uint64_t>* output) {
    if (!json.Find(key))
      return true;
    const auto* value = json.FindString(key);
    uint64_t window;
    if (!value || !base::StringToUint64(*value, &window) || window < 16384 ||
        window > ((uint64_t{1} << 62) - 1))
      return false;
    *output = window;
    return true;
  };
  if (!http("http2-stream-window", 1, &options->http2_stream_window) ||
      !http("http2-connection-window", 65535,
            &options->http2_connection_window) ||
      !quic_window("quic-stream-window", &options->quic_stream_window) ||
      !quic_window("quic-session-window", &options->quic_session_window))
    return false;
  if (json.Find("quic-congestion")) {
    const auto* value = json.FindString("quic-congestion");
    if (!value || (*value != "bbr" && *value != "bbr2" && *value != "cubic" &&
                   *value != "reno"))
      return false;
    options->quic_congestion = *value;
  }
  return true;
}

bool ReadEchPolicy(const base::DictValue& json,
                   const net::ProxyChain& chain,
                   net::NaiveContextOptions* options,
                   std::shared_ptr<const naive::EchPolicy>* output) {
  if (!json.Find("ech-mode"))
    return !json.Find("ech-config-list") && !json.Find("ech-query-name");
  auto mode = json.FindInt("ech-mode");
  if (!mode || *mode < 0 || *mode > 2 || !chain.First().is_secure_http_like())
    return false;
  auto policy = std::make_shared<naive::EchPolicy>();
  policy->mode = static_cast<net::EchMode>(*mode);
  policy->host = chain.First().host_port_pair().host();
  policy->port = chain.First().host_port_pair().port();
  policy->quic = chain.First().is_quic();
  policy->query_name = policy->host;
  options->ech_host = policy->host;
  options->ech_mode = *mode;
  if (*mode == 0) {
    if (json.Find("ech-config-list") || json.Find("ech-query-name"))
      return false;
    *output = std::move(policy);
    return true;
  }
  for (size_t i = 1; i < chain.length(); ++i) {
    if (chain.GetProxyServer(i).host_port_pair().host() == policy->host)
      return false;  // Host-scoped ECH cannot distinguish a repeated inner hop.
  }
  net::IPAddress ip;
  if (ip.AssignFromIPLiteral(policy->host))
    return false;
  if (json.Find("ech-query-name")) {
    const auto* name = json.FindString("ech-query-name");
    if (!name || name->empty())
      return false;
    url::CanonHostInfo info;
    policy->query_name = net::CanonicalizeHost(*name, &info);
    if (info.family == url::CanonHostInfo::BROKEN ||
        policy->query_name.empty() ||
        ip.AssignFromIPLiteral(policy->query_name))
      return false;
  }
  if (json.Find("ech-config-list")) {
    if (json.Find("ech-query-name"))
      return false;
    const auto* list = json.FindList("ech-config-list");
    if (!list || list->empty() || list->size() > 65537)
      return false;
    for (const auto& value : *list) {
      if (!value.is_int() || value.GetInt() < 0 || value.GetInt() > 255)
        return false;
      policy->config_list.push_back(static_cast<uint8_t>(value.GetInt()));
    }
    if (!naive::ValidEchConfig(policy->config_list))
      return false;
  }
  *output = std::move(policy);
  return true;
}

class Engine;
struct Tunnel {
  ~Tunnel() {
    if (preamble)
      preamble->Cancel();
  }
  net::NetworkAnonymizationKey key =
      net::NetworkAnonymizationKey::CreateTransient();
  base::TimeTicks deadline;
  bool ready = false;
  std::unique_ptr<net::PreambleGetter> preamble;
  std::vector<uint64_t> waiting;
};

class Stream {
 public:
  Stream(Engine* engine,
         uint64_t id,
         std::string hostname,
         uint16_t port,
         std::shared_ptr<Tunnel> tunnel,
         naive_callback callback,
         void* context);
  ~Stream() { Close(net::ERR_ABORTED); }
  void Connect();
  void StartTimeout(base::TimeDelta timeout);
  void SetDeadline(uint32_t mask, std::optional<base::TimeTicks> deadline);
  int GetInfo(naive_stream_info* output);
  void Read(size_t capacity);
  void Write(scoped_refptr<naive_buffer> buffer, size_t length);
  void ReadOwned(scoped_refptr<OwnedIOBuffer> buffer);
  void WriteOwned(scoped_refptr<OwnedIOBuffer> buffer);
  void ShutdownWrite();
  void Close(int reason);
  const std::shared_ptr<Tunnel>& tunnel() const { return tunnel_; }
  base::TimeTicks last_activity() const { return last_activity_; }

 private:
  void Connected(int result);
  void CaptureInfo();
  void ReadCompleted(int result);
  void ReadOwnedCompleted(int result);
  void ShutdownWriteCompleted(int result);
  void WriteNext();
  void WriteCompleted(int result);
  void Emit(int event,
            int result,
            scoped_refptr<naive_buffer> buffer = {},
            size_t length = 0);
  Engine* engine_;
  uint64_t id_;
  std::string hostname_;
  uint16_t port_;
  std::shared_ptr<Tunnel> tunnel_;
  naive_callback callback_;
  void* context_;
  net::ClientSocketHandle handle_;
  std::unique_ptr<net::NaivePaddingSocket> socket_;
  scoped_refptr<naive_buffer> read_buffer_;
  bool read_pending_ = false;
  scoped_refptr<naive_buffer> write_payload_;
  scoped_refptr<OwnedIOBuffer> owned_read_;
  scoped_refptr<OwnedIOBuffer> owned_write_;
  scoped_refptr<net::DrainableIOBuffer> write_buffer_;
  int write_size_ = 0;
  base::TimeTicks last_activity_ = base::TimeTicks::Now();
  bool connect_reported_ = false;
  bool connected_ = false;
  bool write_shutdown_ = false;
  naive_stream_info info_{};
  uint64_t bytes_read_ = 0;
  uint64_t bytes_written_ = 0;
  base::OneShotTimer read_deadline_;
  base::OneShotTimer write_deadline_;
  base::OneShotTimer connect_timer_;
  base::WeakPtrFactory<Stream> weak_{this};
};

class Engine {
 public:
  Engine(naive_callback callback,
         scoped_refptr<base::SingleThreadTaskRunner> runner)
      : callback_(callback),
        runner_(std::move(runner)),
        log_(net::NetLogWithSource::Make(net::NetLog::Get(),
                                         net::NetLogSourceType::NONE)) {}
  ~Engine() { Shutdown(); }
  int Init(const std::string& json,
           std::shared_ptr<naive::NetworkHooks> hooks) {
    auto dict = base::JSONReader::ReadDict(json, base::JSON_PARSE_RFC);
    if (!dict || !config_.Parse(*dict) || config_.proxy_chains.size() != 1 ||
        config_.insecure_concurrency > 64)
      return net::ERR_INVALID_ARGUMENT;
    net::NaiveContextOptions options;
    if (!ReadContextOptions(*dict, &options))
      return net::ERR_INVALID_ARGUMENT;
    int timeout_ms = dict->FindInt("connect-timeout-ms").value_or(30000);
    if (timeout_ms <= 0)
      return net::ERR_INVALID_ARGUMENT;
    connect_timeout_ = base::Milliseconds(timeout_ms);
    proxy_info_.UseProxyChain(config_.proxy_chains[0]);
    if (proxy_info_.is_direct())
      return net::ERR_INVALID_ARGUMENT;
    std::shared_ptr<const naive::EchPolicy> ech;
    if (!ReadEchPolicy(*dict, config_.proxy_chains[0], &options, &ech))
      return net::ERR_INVALID_ARGUMENT;
    const auto& last = config_.proxy_chains[0].Last();
    secure_ = last.is_secure_http_like();
    // Deliberately expose proxy streams only, with no local listener.
    if (hooks && hooks->value.dial_udp &&
        !base::FeatureList::IsEnabled(net::features::kAsyncQuicSession))
      return net::ERR_NOT_IMPLEMENTED;
    hooks_ = hooks;
    net::ConfigureContext configure;
    if (hooks || ech)
      configure = base::BindRepeating(&naive::ConfigureNetwork, hooks,
                                      config_.host_resolver_rules, ech);
    cert_context_ =
        net::BuildCertURLRequestContext(net::NetLog::Get(), configure);
    fetcher_ = base::MakeRefCounted<net::CertNetFetcherURLRequest>();
    fetcher_->SetURLRequestContext(cert_context_.get());
    std::unique_ptr<net::CertVerifier> verifier;
    if (const auto* roots = dict->FindString("extra-root-certs")) {
      verifier = AdditionalRoots(*roots, fetcher_);
      if (!verifier)
        return net::ERR_INVALID_ARGUMENT;
    }
    context_ =
        net::BuildURLRequestContext(config_, fetcher_, net::NetLog::Get(), 0,
                                    std::move(verifier), configure, options);
    if (!config_.log_net_log.empty()) {
      netlog_ = net::FileNetLogObserver::CreateBounded(
          config_.log_net_log, 16 * 1024 * 1024,
          net::NetLogCaptureMode::kDefault, nullptr,
          net::NetLogFileFormat::kNdjson);
      netlog_->StartObserving(net::NetLog::Get());
    }
    tunnels_.resize(config_.insecure_concurrency);
    cleanup_.Start(FROM_HERE, base::Minutes(1), this, &Engine::CleanUp);
    return net::OK;
  }
  void Connect(uint64_t id,
               std::string hostname,
               uint16_t port,
               void* context) {
    if (closed_ || !id || streams_.contains(id) || hostname.empty() || !port) {
      callback_(context, id, NAIVE_CONNECTED,
                closed_ ? net::ERR_ABORTED : net::ERR_INVALID_ARGUMENT, nullptr,
                nullptr, 0, 0);
      callback_(context, id, NAIVE_DESTROYED, 0, nullptr, nullptr, 0, 0);
      return;
    }
    ++stats_.connect_attempts;
    auto& slot = tunnels_[next_tunnel_++ % tunnels_.size()];
    const auto now = base::TimeTicks::Now();
    bool fresh = !slot || (secure_ && now > slot->deadline);
    if (fresh) {
      slot = std::make_shared<Tunnel>();
      slot->deadline = now + base::Seconds(config_.tunnel_timeout);
      slot->ready = !secure_;
    }
    auto tunnel = slot;
    auto stream = std::make_unique<Stream>(this, id, std::move(hostname), port,
                                           tunnel, callback_, context);
    auto* ptr = stream.get();
    ptr->StartTimeout(connect_timeout_);
    streams_.emplace(id, std::move(stream));
    if (tunnel->ready) {
      if (tunnel->preamble)
        tunnel->preamble->StartOne();
      ptr->Connect();
      return;
    }
    tunnel->waiting.push_back(id);
    if (fresh) {
      tunnel->preamble = std::make_unique<net::PreambleGetter>(
          proxy_info_, session(), tunnel->key, log_);
      int rv = tunnel->preamble->Start(
          base::BindOnce(&Engine::PreambleDone, weak_.GetWeakPtr(),
                         std::weak_ptr<Tunnel>(tunnel)));
      if (rv != net::ERR_IO_PENDING)
        PreambleDone(tunnel, rv);
    }
  }
  naive_client_stats Stats() const {
    auto result = stats_;
    result.active_streams = streams_.size();
    return result;
  }
  int StreamInfo(uint64_t id, naive_stream_info* output) {
    auto it = streams_.find(id);
    return it == streams_.end() ? net::ERR_SOCKET_NOT_CONNECTED
                                : it->second->GetInfo(output);
  }
  void SetDeadline(uint64_t id,
                   uint32_t mask,
                   std::optional<base::TimeTicks> deadline) {
    auto it = streams_.find(id);
    if (it != streams_.end())
      it->second->SetDeadline(mask, deadline);
  }
  void RecordConnect(bool success) {
    if (success)
      ++stats_.connect_successes;
    else
      ++stats_.connect_failures;
  }
  void RecordClose(bool connect_reported) {
    ++stats_.closed_streams;
    if (!connect_reported)
      ++stats_.connect_failures;
  }
  void RecordRead(uint64_t bytes) { stats_.bytes_read += bytes; }
  void RecordWrite(uint64_t bytes) { stats_.bytes_written += bytes; }
  void PreambleDone(std::weak_ptr<Tunnel> weak_tunnel, int result) {
    // A CONNECT failure can release the last retired tunnel. Do not destroy
    // its preamble while PreambleGetter::DoCallback still uses the request.
    runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&Engine::StartWaiting, weak_.GetWeakPtr(), weak_tunnel));
  }
  void StartWaiting(std::weak_ptr<Tunnel> weak_tunnel) {
    auto tunnel = weak_tunnel.lock();
    if (closed_ || !tunnel)
      return;
    // Upstream intentionally attempts CONNECT even if the preamble failed.
    tunnel->ready = true;
    auto waiting = std::move(tunnel->waiting);
    for (uint64_t id : waiting) {
      auto it = streams_.find(id);
      if (it != streams_.end())
        it->second->Connect();
    }
  }
  void Read(uint64_t id, size_t capacity) {
    if (closed_)
      return;
    auto it = streams_.find(id);
    if (it != streams_.end())
      it->second->Read(capacity);
  }
  void Write(uint64_t id, scoped_refptr<naive_buffer> buffer, size_t length) {
    if (closed_)
      return;
    auto it = streams_.find(id);
    if (it != streams_.end())
      it->second->Write(std::move(buffer), length);
  }
  void OwnedIO(uint64_t id, bool read, scoped_refptr<OwnedIOBuffer> buffer) {
    auto it = streams_.find(id);
    if (closed_ || it == streams_.end()) {
      buffer->Complete(net::ERR_SOCKET_NOT_CONNECTED, 0);
      return;
    }
    if (read)
      it->second->ReadOwned(std::move(buffer));
    else
      it->second->WriteOwned(std::move(buffer));
  }
  void ShutdownWrite(uint64_t id) {
    auto it = streams_.find(id);
    if (!closed_ && it != streams_.end())
      it->second->ShutdownWrite();
  }
  void Close(uint64_t id, int reason) {
    if (closed_)
      return;
    auto it = streams_.find(id);
    if (it == streams_.end())
      return;
    auto stream = std::move(it->second);
    streams_.erase(it);
    auto tunnel = stream->tunnel();
    if (tunnel && !tunnel->ready) {
      std::erase(tunnel->waiting, id);
      if (tunnel->waiting.empty()) {
        if (tunnel->preamble)
          tunnel->preamble->Cancel();
        tunnel->preamble.reset();
        for (auto& slot : tunnels_) {
          if (slot == tunnel)
            slot.reset();
        }
      }
    }
    stream->Close(reason);
    if (streams_.empty() && hooks_)
      hooks_->CancelPending();
    // The close can originate inside a stream/socket callback.
    runner_->DeleteSoon(FROM_HERE, std::move(stream));
  }
  int ResetConnections() {
    if (closed_)
      return net::ERR_CONTEXT_SHUT_DOWN;
    weak_.InvalidateWeakPtrs();
    for (auto& [id, stream] : streams_)
      stream->Close(net::ERR_NETWORK_CHANGED);
    streams_.clear();
    tunnels_.clear();
    tunnels_.resize(config_.insecure_concurrency);
    next_tunnel_ = 0;
    if (hooks_)
      hooks_->CancelPending();
    for (auto* context : {context_.get(), cert_context_.get()}) {
      context->http_transaction_factory()->GetSession()->CloseAllConnections(
          net::ERR_NETWORK_CHANGED, "naive-rs host network reset");
      if (auto* cache = context->host_resolver()->GetHostCache())
        cache->clear();
    }
    return net::OK;
  }
  void Shutdown(base::OnceClosure completed = {}) {
    if (closed_) {
      if (completed)
        std::move(completed).Run();
      return;
    }
    closed_ = true;
    weak_.InvalidateWeakPtrs();
    cleanup_.Stop();
    for (auto& [id, stream] : streams_)
      stream->Close(net::ERR_ABORTED);
    streams_.clear();
    tunnels_.clear();
    if (hooks_)
      hooks_->CancelPending();
    context_.reset();
    if (fetcher_)
      fetcher_->Shutdown();
    fetcher_.reset();
    cert_context_.reset();
    hooks_.reset();
    if (netlog_) {
      netlog_->StopObserving(nullptr, std::move(completed));
      netlog_.reset();
    } else if (completed) {
      std::move(completed).Run();
    }
  }
  void CleanUp() {
    auto now = base::TimeTicks::Now();
    std::vector<uint64_t> expired;
    for (const auto& [id, stream] : streams_) {
      auto limit = base::Seconds(config_.idle_timeout);
      if (secure_ && now > stream->tunnel()->deadline)
        limit /= 10;
      if (now - stream->last_activity() > limit)
        expired.push_back(id);
    }
    for (uint64_t id : expired)
      Close(id, net::ERR_TIMED_OUT);
    session()->CloseIdleConnections("naive-rs tunnel retirement");
  }
  net::HttpNetworkSession* session() {
    return context_->http_transaction_factory()->GetSession();
  }
  const net::ProxyInfo& proxy_info() const { return proxy_info_; }
  const net::NetLogWithSource& log() const { return log_; }
  std::optional<net::PaddingType> padding() {
    return static_cast<net::NaiveProxyDelegate*>(context_->proxy_delegate())
        ->GetProxyChainPaddingType(proxy_info_.proxy_chain());
  }

 private:
  naive_client_stats stats_{};
  base::TimeDelta connect_timeout_;
  bool closed_ = false;
  bool secure_ = false;
  size_t next_tunnel_ = 0;
  naive_callback callback_;
  std::shared_ptr<naive::NetworkHooks> hooks_;
  scoped_refptr<base::SingleThreadTaskRunner> runner_;
  net::NaiveConfig config_;
  net::ProxyInfo proxy_info_;
  net::NetLogWithSource log_;
  std::unique_ptr<net::URLRequestContext> cert_context_;
  scoped_refptr<net::CertNetFetcherURLRequest> fetcher_;
  std::unique_ptr<net::URLRequestContext> context_;
  std::unique_ptr<net::FileNetLogObserver> netlog_;
  std::vector<std::shared_ptr<Tunnel>> tunnels_;
  std::map<uint64_t, std::unique_ptr<Stream>> streams_;
  base::RepeatingTimer cleanup_;
  base::WeakPtrFactory<Engine> weak_{this};
};

Stream::Stream(Engine* engine,
               uint64_t id,
               std::string hostname,
               uint16_t port,
               std::shared_ptr<Tunnel> tunnel,
               naive_callback callback,
               void* context)
    : engine_(engine),
      id_(id),
      hostname_(std::move(hostname)),
      port_(port),
      tunnel_(std::move(tunnel)),
      callback_(callback),
      context_(context) {}

void Stream::Emit(int event,
                  int result,
                  scoped_refptr<naive_buffer> buffer,
                  size_t length) {
  if (!context_)
    return;
  auto* data = buffer ? buffer->io->span().data() : nullptr;
  size_t capacity = buffer ? buffer->capacity : 0;
  callback_(context_, id_, event, result, buffer.release(), data, length,
            capacity);
}

void Stream::StartTimeout(base::TimeDelta timeout) {
  connect_timer_.Start(FROM_HERE, timeout,
                       base::BindOnce(
                           [](Stream* stream) {
                             stream->engine_->Close(stream->id_,
                                                    net::ERR_TIMED_OUT);
                           },
                           base::Unretained(this)));
}

void Stream::SetDeadline(uint32_t mask,
                         std::optional<base::TimeTicks> deadline) {
  auto set = [&](base::OneShotTimer& timer, int event) {
    timer.Stop();
    if (deadline) {
      timer.Start(
          FROM_HERE,
          std::max(base::TimeDelta(), *deadline - base::TimeTicks::Now()),
          base::BindOnce(
              [](base::WeakPtr<Stream> stream, int event) {
                if (stream)
                  stream->Emit(event, net::OK);
              },
              weak_.GetWeakPtr(), event));
    }
  };
  if (mask & 1)
    set(read_deadline_, NAIVE_READ_DEADLINE);
  if (mask & 2)
    set(write_deadline_, NAIVE_WRITE_DEADLINE);
}

int Stream::GetInfo(naive_stream_info* output) {
  if (!connected_)
    return net::ERR_SOCKET_NOT_CONNECTED;
  *output = info_;
  output->bytes_read = bytes_read_;
  output->bytes_written = bytes_written_;
  return net::OK;
}

void Stream::CaptureInfo() {
  auto* output = &info_;
  output->write_shutdown_supported = handle_.socket()->EnableHalfClose();
  output->pooled_socket_reused = handle_.is_reused();
  auto copy = [](auto& target, std::string_view text) {
    size_t count = std::min(text.size(), sizeof(target) - 1);
    std::copy_n(text.begin(), count, std::begin(target));
    target[count] = 0;
  };
  auto protocol = handle_.socket()->GetProxyNegotiatedProtocol();
  copy(output->protocol, protocol == net::NextProto::kProtoQUIC
                             ? "h3"
                             : net::NextProtoToString(protocol));
  net::IPEndPoint address;
  if (handle_.socket()->GetLocalAddress(&address) == net::OK)
    copy(output->local_address, address.ToString());
  if (handle_.socket()->GetPeerAddress(&address) == net::OK)
    copy(output->peer_address, address.ToString());
  net::SSLInfo ssl;
  if (handle_.socket()->GetProxySSLInfo(&ssl)) {
    auto version = net::SSLConnectionStatusToVersion(ssl.connection_status);
    if (version >= net::SSL_CONNECTION_VERSION_TLS1 &&
        version <= net::SSL_CONNECTION_VERSION_TLS1_3)
      output->tls_version =
          0x0301 + (version - net::SSL_CONNECTION_VERSION_TLS1);
    // Chromium uses a separate connection-status sentinel for QUIC. The
    // negotiated IETF QUIC proxy session uses TLS 1.3 on the wire.
    else if (version == net::SSL_CONNECTION_VERSION_QUIC &&
             protocol == net::NextProto::kProtoQUIC)
      output->tls_version = 0x0304;
    output->ech_accepted = ssl.encrypted_client_hello;
    output->cipher_suite =
        net::SSLConnectionStatusToCipherSuite(ssl.connection_status);
  }
}

void Stream::Connect() {
  url::CanonHostInfo info;
  auto host = net::HostPortPair(hostname_, port_).HostForURL();
  url::SchemeHostPort endpoint("http", net::CanonicalizeHost(host, &info),
                               port_,
                               url::SchemeHostPort::ALREADY_CANONICALIZED);
  if (!endpoint.IsValid()) {
    Connected(net::ERR_INVALID_ARGUMENT);
    return;
  }
  int rv = net::InitSocketHandleForHttpRequest(
      std::move(endpoint), net::LOAD_IGNORE_LIMITS, net::MAXIMUM_PRIORITY,
      engine_->session(), engine_->proxy_info(), {}, net::PRIVACY_MODE_DISABLED,
      tunnel_->key, net::SecureDnsPolicy::kDisable, net::SocketTag(),
      net::handles::kInvalidNetworkHandle, engine_->log(), &handle_,
      base::BindOnce(&Stream::Connected, weak_.GetWeakPtr()),
      net::ClientSocketPool::ProxyAuthCallback());
  if (rv != net::ERR_IO_PENDING)
    Connected(rv);
}
void Stream::Connected(int result) {
  connect_timer_.Stop();
  if (result >= 0) {
    auto padding = engine_->padding();
    if (!padding)
      result = net::ERR_INVALID_RESPONSE;
    else
      socket_ = std::make_unique<net::NaivePaddingSocket>(
          handle_.socket(), *padding, net::kServer);
  }
  last_activity_ = base::TimeTicks::Now();
  connect_reported_ = true;
  connected_ = result >= 0;
  if (connected_)
    CaptureInfo();
  engine_->RecordConnect(connected_);
  Emit(NAIVE_CONNECTED, result);
  if (result < 0)
    engine_->Close(id_, result);
}
void Stream::Read(size_t capacity) {
  if (!socket_ || read_pending_ || !capacity || capacity > kMaxIO) {
    Emit(NAIVE_READ, net::ERR_INVALID_ARGUMENT);
    return;
  }
  // An older lease may outlive consumption/close. Never overwrite leased bytes.
  if (!read_buffer_ || read_buffer_->capacity < capacity ||
      !read_buffer_->HasOneRef())
    read_buffer_ = base::MakeRefCounted<naive_buffer>(capacity);
  read_pending_ = true;
  int rv =
      socket_->Read(read_buffer_->io.get(), static_cast<int>(capacity),
                    base::BindOnce(&Stream::ReadCompleted, weak_.GetWeakPtr()));
  if (rv != net::ERR_IO_PENDING)
    ReadCompleted(rv);
}
void Stream::ReadOwned(scoped_refptr<OwnedIOBuffer> buffer) {
  if (!socket_ || read_pending_) {
    buffer->Complete(net::ERR_UNEXPECTED, 0);
    return;
  }
  read_pending_ = true;
  owned_read_ = std::move(buffer);
  int rv = socket_->Read(owned_read_.get(), owned_read_->size(),
                         base::BindOnce(&Stream::ReadOwnedCompleted,
                                        weak_.GetWeakPtr()));
  if (rv != net::ERR_IO_PENDING)
    ReadOwnedCompleted(rv);
}
void Stream::ReadOwnedCompleted(int result) {
  read_pending_ = false;
  auto buffer = std::move(owned_read_);
  if (result > 0) {
    last_activity_ = base::TimeTicks::Now();
    bytes_read_ += result;
    engine_->RecordRead(result);
  }
  buffer->Complete(result < 0 ? result : net::OK,
                   result > 0 ? static_cast<size_t>(result) : 0);
  if (result < 0)
    engine_->Close(id_, result);
}
void Stream::ReadCompleted(int result) {
  read_pending_ = false;
  if (result > 0) {
    last_activity_ = base::TimeTicks::Now();
    bytes_read_ += result;
    engine_->RecordRead(result);
  }
  Emit(NAIVE_READ, result, result > 0 ? read_buffer_ : nullptr,
       result > 0 ? static_cast<size_t>(result) : 0);
  if (result < 0)
    engine_->Close(id_, result);
}
void Stream::Write(scoped_refptr<naive_buffer> buffer, size_t length) {
  if (!socket_ || write_shutdown_ || write_buffer_ || !buffer || !length ||
      length > buffer->capacity || length > kMaxIO) {
    Emit(NAIVE_WRITTEN, net::ERR_INVALID_ARGUMENT, std::move(buffer));
    return;
  }
  write_size_ = static_cast<int>(length);
  write_payload_ = std::move(buffer);
  write_buffer_ = base::MakeRefCounted<net::DrainableIOBuffer>(
      write_payload_->io, write_size_);
  WriteNext();
}
void Stream::WriteOwned(scoped_refptr<OwnedIOBuffer> buffer) {
  if (!socket_ || write_shutdown_ || write_buffer_) {
    buffer->Complete(net::ERR_UNEXPECTED, 0);
    return;
  }
  write_size_ = buffer->size();
  owned_write_ = std::move(buffer);
  write_buffer_ = base::MakeRefCounted<net::DrainableIOBuffer>(owned_write_,
                                                             write_size_);
  WriteNext();
}
void Stream::ShutdownWrite() {
  if (!connected_ || !socket_) {
    Emit(NAIVE_WRITE_SHUTDOWN, net::ERR_SOCKET_NOT_CONNECTED);
    return;
  }
  if (!info_.write_shutdown_supported) {
    Emit(NAIVE_WRITE_SHUTDOWN, net::ERR_NOT_IMPLEMENTED);
    return;
  }
  if (write_buffer_) {
    Emit(NAIVE_WRITE_SHUTDOWN, net::ERR_UNEXPECTED);
    return;
  }
  if (write_shutdown_) {
    Emit(NAIVE_WRITE_SHUTDOWN, net::OK);
    return;
  }
  write_shutdown_ = true;
  int result = handle_.socket()->ShutdownWrite(base::BindOnce(
      &Stream::ShutdownWriteCompleted, weak_.GetWeakPtr()));
  if (result != net::ERR_IO_PENDING)
    ShutdownWriteCompleted(result);
}
void Stream::ShutdownWriteCompleted(int result) {
  if (result == net::ERR_NOT_IMPLEMENTED)
    write_shutdown_ = false;
  Emit(NAIVE_WRITE_SHUTDOWN, result);
  if (result < 0 && result != net::ERR_NOT_IMPLEMENTED)
    engine_->Close(id_, result);
}
void Stream::WriteNext() {
  while (write_buffer_ && write_buffer_->BytesRemaining() > 0) {
    int rv = socket_->Write(
        write_buffer_.get(), write_buffer_->BytesRemaining(),
        base::BindOnce(&Stream::WriteCompleted, weak_.GetWeakPtr()),
        kAnnotation);
    if (rv == net::ERR_IO_PENDING)
      return;
    if (rv <= 0) {
      WriteCompleted(rv);
      return;
    }
    last_activity_ = base::TimeTicks::Now();
    bytes_written_ += rv;
    engine_->RecordWrite(rv);
    write_buffer_->DidConsume(rv);
  }
  // Release transport views before transferring the writable owner back to
  // Rust.
  write_buffer_.reset();
  if (owned_write_) {
    owned_write_->Complete(net::OK, write_size_);
    owned_write_.reset();
  } else {
    Emit(NAIVE_WRITTEN, write_size_, std::move(write_payload_), write_size_);
  }
}
void Stream::WriteCompleted(int result) {
  if (result <= 0) {
    int error = result < 0 ? result : net::ERR_CONNECTION_CLOSED;
    if (owned_write_)
      owned_write_->Complete(error, write_size_ - write_buffer_->BytesRemaining());
    write_buffer_.reset();
    if (owned_write_)
      owned_write_.reset();
    else
      Emit(NAIVE_WRITTEN, error, std::move(write_payload_));
    engine_->Close(id_, error);
    return;
  }
  last_activity_ = base::TimeTicks::Now();
  bytes_written_ += result;
  engine_->RecordWrite(result);
  write_buffer_->DidConsume(result);
  WriteNext();
}
void Stream::Close(int reason) {
  if (owned_read_)
    owned_read_->Complete(reason, 0);
  if (owned_write_)
    owned_write_->Complete(reason,
        write_buffer_ ? write_size_ - write_buffer_->BytesRemaining() : 0);
  connect_timer_.Stop();
  read_deadline_.Stop();
  write_deadline_.Stop();
  weak_.InvalidateWeakPtrs();
  socket_.reset();
  handle_.ResetAndCloseSocket();
  read_buffer_.reset();
  read_pending_ = false;
  write_buffer_.reset();
  write_payload_.reset();
  owned_read_.reset();
  owned_write_.reset();
  // Destroy retired preambles before the engine URLRequestContext goes away.
  tunnel_.reset();
  if (context_) {
    engine_->RecordClose(connect_reported_);
    void* context = std::exchange(context_, nullptr);
    callback_(context, id_, NAIVE_CLOSED, reason, nullptr, nullptr, 0, 0);
    callback_(context, id_, NAIVE_DESTROYED, 0, nullptr, nullptr, 0, 0);
  }
}
}  // namespace

struct naive_engine {
  scoped_refptr<base::SingleThreadTaskRunner> runner;
  std::shared_ptr<Engine> state;
};

extern "C" {
uint32_t naive_abi_version() {
  return 4;
}
const char* naive_version() {
  return version_info::GetVersionNumber().data();
}
const char* naive_error_name(int32_t error) {
  switch (error) {
    case net::OK:
      return "OK";
#define NET_ERROR(label, value) \
  case value:                   \
    return "ERR_" #label;
#include "net/base/net_error_list.h"
#undef NET_ERROR
    default:
      return "ERR_UNKNOWN";
  }
}
naive_buffer* naive_buffer_alloc(size_t capacity) {
  if (!capacity || capacity > kMaxIO)
    return nullptr;
  return base::MakeRefCounted<naive_buffer>(capacity).release();
}
uint8_t* naive_buffer_data(naive_buffer* buffer) {
  return buffer->io->span().data();
}
void naive_buffer_release(naive_buffer* buffer) {
  if (buffer)
    buffer->Release();
}
void naive_get_buffer_stats(naive_buffer_stats* output) {
  output->allocations = buffer_allocations.load(std::memory_order_relaxed);
  output->live_buffers = live_buffers.load(std::memory_order_relaxed);
  output->live_capacity = live_capacity.load(std::memory_order_relaxed);
  output->peak_capacity = peak_capacity.load(std::memory_order_relaxed);
}
int32_t naive_engine_create(const char* json,
                            naive_callback callback,
                            const naive_network_hooks* hooks,
                            naive_engine** output) {
  if (!json || !callback || !output)
    return net::ERR_INVALID_ARGUMENT;
  *output = nullptr;
  if (hooks && (!hooks->retain || !hooks->release))
    return net::ERR_INVALID_ARGUMENT;
  auto network =
      hooks ? std::make_shared<naive::NetworkHooks>(*hooks) : nullptr;
  auto& runtime = Runtime::Get();
  auto dict = base::JSONReader::ReadDict(json, base::JSON_PARSE_RFC);
  if (!dict)
    return net::ERR_INVALID_ARGUMENT;
  int width = dict->FindInt("io-workers").value_or(1);
  if (width < 1 || width > 8)
    return net::ERR_INVALID_ARGUMENT;
  auto runner = runtime.SelectRunner(width);
  if (!runner)
    return net::ERR_FAILED;
  auto engine = std::make_unique<naive_engine>();
  engine->runner = runner;
  std::promise<int> done;
  auto result = done.get_future();
  runner->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](naive_engine* handle, std::string json, naive_callback callback,
             std::shared_ptr<naive::NetworkHooks> network,
             std::promise<int>* done) {
            handle->state = std::make_shared<Engine>(callback, handle->runner);
            int rv = handle->state->Init(json, std::move(network));
            if (rv != net::OK)
              handle->state.reset();
            done->set_value(rv);
          },
          engine.get(), std::string(json), callback, std::move(network),
          &done));
  int rv = result.get();
  if (rv == net::OK)
    *output = engine.release();
  return rv;
}
void naive_engine_shutdown(naive_engine* engine) {
  if (!engine)
    return;
  std::promise<void> done;
  auto result = done.get_future();
  engine->runner->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](std::shared_ptr<Engine> state,
             scoped_refptr<base::SingleThreadTaskRunner> runner,
             std::promise<void>* done) {
            state->Shutdown(base::BindPostTask(
                runner, base::BindOnce(
                            [](std::promise<void>* done) { done->set_value(); },
                            done)));
          },
          engine->state, engine->runner, &done));
  result.get();
}
int32_t naive_engine_reset_connections(naive_engine* engine) {
  if (!engine)
    return net::ERR_INVALID_ARGUMENT;
  std::promise<int> done;
  auto result = done.get_future();
  engine->runner->PostTask(
      FROM_HERE, base::BindOnce(
                     [](std::shared_ptr<Engine> state,
                        scoped_refptr<base::SingleThreadTaskRunner> runner,
                        std::promise<int>* done) {
                       int rv = state->ResetConnections();
                       runner->PostTask(
                           FROM_HERE,
                           base::BindOnce([](std::promise<int>* done,
                                             int rv) { done->set_value(rv); },
                                          done, rv));
                     },
                     engine->state, engine->runner, &done));
  return result.get();
}
int32_t naive_engine_get_stats(naive_engine* engine,
                               naive_client_stats* output,
                               size_t output_size) {
  if (!engine || !output || output_size != sizeof(*output))
    return net::ERR_INVALID_ARGUMENT;
  std::promise<naive_client_stats> done;
  auto result = done.get_future();
  engine->runner->PostTask(FROM_HERE,
                           base::BindOnce(
                               [](std::shared_ptr<Engine> state,
                                  std::promise<naive_client_stats>* done) {
                                 done->set_value(state->Stats());
                               },
                               engine->state, &done));
  *output = result.get();
  return net::OK;
}
int32_t naive_engine_get_stream_info(naive_engine* engine,
                                     uint64_t id,
                                     naive_stream_info* output,
                                     size_t output_size) {
  if (!engine || !output || output_size != sizeof(*output))
    return net::ERR_INVALID_ARGUMENT;
  std::promise<int> done;
  auto result = done.get_future();
  engine->runner->PostTask(
      FROM_HERE, base::BindOnce(
                     [](std::shared_ptr<Engine> state, uint64_t id,
                        naive_stream_info* output, std::promise<int>* done) {
                       done->set_value(state->StreamInfo(id, output));
                     },
                     engine->state, id, output, &done));
  return result.get();
}
int32_t naive_engine_set_deadline(naive_engine* engine,
                                  uint64_t id,
                                  uint32_t mask,
                                  int64_t timeout_us) {
  if (!engine || !mask || mask > 3 || timeout_us < -1)
    return net::ERR_INVALID_ARGUMENT;
  std::optional<base::TimeTicks> deadline;
  if (timeout_us >= 0)
    deadline = base::TimeTicks::Now() + base::Microseconds(timeout_us);
  engine->runner->PostTask(
      FROM_HERE,
      base::BindOnce(&Engine::SetDeadline, engine->state, id, mask, deadline));
  return net::OK;
}
void naive_engine_destroy(naive_engine* engine) {
  if (!engine)
    return;
  naive_engine_shutdown(engine);
  std::promise<void> done;
  auto result = done.get_future();
  engine->runner->PostTask(FROM_HERE, base::BindOnce(
                                          [](std::shared_ptr<Engine> state,
                                             std::promise<void>* done) {
                                            state.reset();
                                            done->set_value();
                                          },
                                          std::move(engine->state), &done));
  result.get();
  delete engine;
}
void naive_engine_connect(naive_engine* engine,
                          uint64_t id,
                          const char* hostname,
                          uint16_t port,
                          void* context) {
  engine->runner->PostTask(
      FROM_HERE,
      base::BindOnce(&Engine::Connect, engine->state, id,
                     std::string(hostname ? hostname : ""), port, context));
}
void naive_engine_read(naive_engine* engine, uint64_t id, size_t capacity) {
  engine->runner->PostTask(
      FROM_HERE, base::BindOnce(&Engine::Read, engine->state, id, capacity));
}
void naive_engine_write(naive_engine* engine,
                        uint64_t id,
                        naive_buffer* buffer,
                        size_t length) {
  // Consume the reference supplied by Rust; the posted task owns it from here.
  scoped_refptr<naive_buffer> owned(buffer);
  if (buffer)
    buffer->Release();
  engine->runner->PostTask(FROM_HERE,
                           base::BindOnce(&Engine::Write, engine->state, id,
                                          std::move(owned), length));
}
void naive_engine_close(naive_engine* engine, uint64_t id) {
  engine->runner->PostTask(
      FROM_HERE,
      base::BindOnce(&Engine::Close, engine->state, id, net::ERR_ABORTED));
}
void naive_engine_shutdown_write(naive_engine* engine, uint64_t id) {
  engine->runner->PostTask(FROM_HERE,
      base::BindOnce(&Engine::ShutdownWrite, engine->state, id));
}

void naive_engine_read_owned(naive_engine* engine, uint64_t id, uint8_t* data,
                             size_t capacity, void* context,
                             naive_owned_callback completed) {
  if (!completed)
    return;  // A valid callback is a caller precondition.
  if (!engine || !data || !capacity || capacity > kMaxIO) {
    completed(context, net::ERR_INVALID_ARGUMENT, 0);
    return;
  }
  auto buffer = base::MakeRefCounted<OwnedIOBuffer>(data, capacity, context,
                                                  completed);
  engine->runner->PostTask(FROM_HERE,
      base::BindOnce(&Engine::OwnedIO, engine->state, id, true, std::move(buffer)));
}
void naive_engine_write_owned(naive_engine* engine, uint64_t id,
                              const uint8_t* data, size_t length, void* context,
                              naive_owned_callback completed) {
  if (!completed)
    return;
  if (!engine || !data || !length || length > kMaxIO) {
    completed(context, net::ERR_INVALID_ARGUMENT, 0);
    return;
  }
  // Socket::Write observes this storage as immutable. It is never used for Read.
  auto buffer = base::MakeRefCounted<OwnedIOBuffer>(const_cast<uint8_t*>(data),
                                                  length, context, completed);
  engine->runner->PostTask(FROM_HERE,
      base::BindOnce(&Engine::OwnedIO, engine->state, id, false, std::move(buffer)));
}
}
