#include "naive_rs/browser.h"

#include <algorithm>
#include <cstring>
#include <deque>
#include <map>
#include <utility>

#include "base/containers/extend.h"
#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "base/memory/weak_ptr.h"
#include "base/task/single_thread_task_runner.h"
#include "base/timer/timer.h"
#include "components/embedder_support/user_agent_utils.h"
#include "net/base/elements_upload_data_stream.h"
#include "net/base/features.h"
#include "net/base/http_user_agent_settings.h"
#include "net/base/isolation_info.h"
#include "net/base/load_flags.h"
#include "net/base/upload_bytes_element_reader.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/x509_util.h"
#include "net/net_buildflags.h"
#if BUILDFLAG(CHROME_ROOT_STORE_SUPPORTED)
#include "net/cert/internal/trust_store_chrome.h"
#endif
#include "net/base/auth.h"
#include "net/cookies/site_for_cookies.h"
#include "net/http/http_auth.h"
#include "net/http/http_auth_cache.h"
#include "net/http/http_connection_info.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_response_info.h"
#include "net/http/http_util.h"
#include "net/log/net_log.h"
#include "net/proxy_resolution/configured_proxy_resolution_service.h"
#include "net/proxy_resolution/proxy_config_service_fixed.h"
#include "net/quic/quic_context.h"
#include "net/ssl/ssl_config_service_defaults.h"
#include "net/ssl/ssl_connection_status_flags.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "net/url_request/redirect_info.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "net/websockets/websocket_channel.h"
#include "net/websockets/websocket_handshake_request_info.h"
#include "net/websockets/websocket_handshake_response_info.h"
#include "url/origin.h"

namespace naive {
namespace {
constexpr auto kTraffic =
    net::DefineNetworkTrafficAnnotation("naive_rs_browser", "");

class ProfileSSLConfig final : public net::SSLConfigServiceDefaults {
 public:
  ProfileSSLConfig(const EchPolicies& ech, bool custom_verifier)
      : isolate_hosts_(custom_verifier || !ech.empty()) {
    for (const auto& policy : ech)
      ech_.emplace(policy->host, policy->mode);
    config_ = net::SSLConfigServiceDefaults::GetSSLContextConfig();
#if BUILDFLAG(CHROME_ROOT_STORE_SUPPORTED)
    // Same trust-anchor advertisement as Chrome's SSL config manager and the
    // pinned Naive implementation; bare SSLConfigServiceDefaults omits it.
    if (base::FeatureList::IsEnabled(net::features::kTLSTrustAnchorIDs)) {
      std::vector<std::vector<uint8_t>> anchors;
      if (base::FeatureList::IsEnabled(net::features::kNonMtcTrustAnchorIDs))
        base::Extend(
            anchors,
            net::TrustStoreChrome::GetTrustAnchorIDsFromCompiledInRootStore());
      if (base::FeatureList::IsEnabled(net::features::kVerifyMTCs))
        base::Extend(
            anchors,
            net::TrustStoreChrome::GetTrustedMtcCaIDsFromCompiledInRootStore());
      config_.trust_anchor_ids =
          net::x509_util::EncodeTlsRequestedTrustAnchorIDList(
              std::move(anchors));
    }
#endif
  }
  net::SSLContextConfig GetSSLContextConfig() override { return config_; }
  net::EchMode GetEchMode(std::string_view host) const override {
    if (host.ends_with('.'))
      host.remove_suffix(1);
    auto it = ech_.find(host);
    return it == ech_.end() ? net::SSLConfigServiceDefaults::GetEchMode(host)
                            : it->second;
  }
  bool CanPoolConnection(std::string_view first,
                         std::string_view second) const override {
    return !isolate_hosts_ || first == second;
  }

 private:
  net::SSLContextConfig config_;
  bool isolate_hosts_;
  std::map<std::string, net::EchMode, std::less<>> ech_;
};

void NavigationHeaders(const GURL& url,
                       net::URLRequestContext* context,
                       net::HttpRequestHeaders* headers) {
  if (url.SchemeIs("https")) {
    auto metadata = embedder_support::GetUserAgentMetadata();
    headers->SetHeader("sec-ch-ua", metadata.SerializeBrandMajorVersionList());
    headers->SetHeader("sec-ch-ua-mobile", metadata.mobile ? "?1" : "?0");
    headers->SetHeader("sec-ch-ua-platform", "\"" + metadata.platform + "\"");
  }
  // Header policy for an explicit top-level GET, matching the pinned native
  // navigation/preamble profile. URLRequest still owns protocol serialization.
  headers->SetHeader("upgrade-insecure-requests", "1");
  headers->SetHeader("user-agent", BrowserUserAgent());
  headers->SetHeader(
      "accept",
      "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/"
      "webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7");
  headers->SetHeader("sec-fetch-site", "none");
  headers->SetHeader("sec-fetch-mode", "navigate");
  headers->SetHeader("sec-fetch-user", "?1");
  headers->SetHeader("sec-fetch-dest", "document");
  headers->SetHeader("accept-encoding", url.SchemeIs("https")
                                            ? "gzip, deflate, br, zstd"
                                            : "gzip, deflate");
  headers->SetHeader("accept-language",
                     context->http_user_agent_settings()->GetAcceptLanguage());
}

bool ReadHeaders(const base::DictValue& json,
                 net::HttpRequestHeaders* headers) {
  const auto* values = json.FindList("headers");
  if (!values)
    return !json.contains("headers");
  if (values->size() > 256)
    return false;
  size_t total = 0;
  for (const auto& value : *values) {
    const auto* pair = value.GetIfList();
    if (!pair || pair->size() != 2 || !(*pair)[0].is_string() ||
        !(*pair)[1].is_string())
      return false;
    const auto& name = (*pair)[0].GetString();
    const auto& content = (*pair)[1].GetString();
    total += name.size() + content.size();
    if (total > 48 * 1024)
      return false;
    if (!net::HttpUtil::IsValidHeaderName(name) ||
        !net::HttpUtil::IsValidHeaderValue(content))
      return false;
    headers->SetHeader(name, content);
  }
  return true;
}

base::ListValue Headers(const net::HttpResponseHeaders* headers) {
  base::ListValue result;
  if (!headers)
    return result;
  size_t iter = 0;
  std::string name, value;
  while (headers->EnumerateHeaderLines(&iter, &name, &value)) {
    base::ListValue pair;
    pair.Append(name);
    pair.Append(value);
    result.Append(std::move(pair));
  }
  return result;
}

std::string Json(base::DictValue value) {
  return base::WriteJson(value).value_or("{}");
}

void Emit(naive_callback callback,
          void* context,
          uint64_t id,
          int event,
          int result,
          scoped_refptr<naive_buffer> buffer = {},
          size_t length = 0) {
  auto* data = buffer ? buffer->io->span().data() : nullptr;
  auto capacity = buffer ? buffer->capacity : 0;
  callback(context, id, event, result, buffer.release(), data, length,
           capacity);
}

void TlsInfo(base::DictValue& meta, const net::SSLInfo& ssl) {
  auto version = net::SSLConnectionStatusToVersion(ssl.connection_status);
  if (version >= net::SSL_CONNECTION_VERSION_TLS1 &&
      version <= net::SSL_CONNECTION_VERSION_TLS1_3)
    meta.Set("tls_version",
             0x0301 + (version - net::SSL_CONNECTION_VERSION_TLS1));
  else if (version == net::SSL_CONNECTION_VERSION_QUIC)
    meta.Set("tls_version", 0x0304);
  meta.Set("cipher_suite",
           static_cast<int>(
               net::SSLConnectionStatusToCipherSuite(ssl.connection_status)));
  meta.Set("ech_accepted", ssl.encrypted_client_hello);
}

bool HttpUrl(const GURL& url) {
  return url.is_valid() && url.SchemeIsHTTPOrHTTPS() && !url.has_username() &&
         !url.has_password();
}
}  // namespace

const std::string& BrowserUserAgent() {
  static const auto* value = new std::string(embedder_support::GetUserAgent());
  return *value;
}

std::unique_ptr<net::URLRequestContext> BuildBrowserContext(
    const base::DictValue& config,
    std::unique_ptr<net::CertVerifier> verifier,
    std::shared_ptr<NetworkHooks> hooks,
    const EchPolicies& ech) {
  // Origin clients are deliberately direct. Naive proxy behavior belongs to
  // separate contexts and must not leak proxy windows or padding into this one.
  if (config.contains("proxy"))
    return nullptr;
  net::URLRequestContextBuilder builder;
  builder.set_net_log(net::NetLog::Get());
  builder.set_user_agent(BrowserUserAgent());
  builder.set_accept_language(config.FindString("accept-language")
                                  ? *config.FindString("accept-language")
                                  : "en-US,en;q=0.9");
  builder.set_enable_brotli(true);
  builder.set_enable_zstd(true);
  builder.SetSpdyAndQuicEnabled(true, true);
  if (const auto* origins = config.FindList("force-http3-origins");
      origins && !origins->empty()) {
    auto quic = std::make_unique<net::QuicContext>();
    for (const auto& value : *origins) {
      if (!value.is_string())
        return nullptr;
      GURL origin(value.GetString());
      if (!HttpUrl(origin) || !origin.SchemeIs("https") || origin.has_query() ||
          origin.has_ref() || origin.path() != "/")
        return nullptr;
      quic->params()->origins_to_force_quic_on.insert(
          url::SchemeHostPort(origin));
    }
    builder.set_quic_context(std::move(quic));
  }
  builder.set_ssl_config_service(std::make_unique<ProfileSSLConfig>(
      ech, hooks && hooks->value.verify_certificate));
  builder.set_proxy_resolution_service(
      net::ConfiguredProxyResolutionService::CreateWithoutProxyResolver(
          std::make_unique<net::ProxyConfigServiceFixed>(
              net::ProxyConfigWithAnnotation::CreateDirect()),
          nullptr, net::NetLog::Get()));
  if (verifier)
    builder.SetCertVerifier(std::move(verifier));
  const auto* rules = config.FindString("host-resolver-rules");
  ConfigureEchNetwork(std::move(hooks), rules ? *rules : "", ech, builder);
  net::URLRequestContextBuilder::HttpCacheParams cache;
  cache.type = net::URLRequestContextBuilder::HttpCacheParams::IN_MEMORY;
  cache.max_size = config.FindInt("cache-bytes").value_or(16 * 1024 * 1024);
  if (cache.max_size < 0 || cache.max_size > 256 * 1024 * 1024)
    return nullptr;
  if (cache.max_size)
    builder.EnableHttpCache(cache);
  else
    builder.DisableHttpCache();
  return builder.Build();
}

class BrowserOperations::Impl {
 public:
  class Http;
  class WebSocket;
  Impl(net::URLRequestContext* context,
       naive_callback callback,
       scoped_refptr<base::SingleThreadTaskRunner> runner,
       base::TimeDelta timeout,
       size_t max_message_bytes,
       base::RepeatingClosure on_idle)
      : context(context),
        callback(callback),
        runner(std::move(runner)),
        timeout(timeout),
        max_message_bytes(max_message_bytes),
        on_idle(std::move(on_idle)) {}
  ~Impl();
  void Close(uint64_t id, int reason);
  void CloseSoon(uint64_t id, int reason) {
    runner->PostTask(
        FROM_HERE, base::BindOnce(&Impl::Close, weak.GetWeakPtr(), id, reason));
  }
  void CancelAll(int reason);
  net::URLRequestContext* context;
  naive_callback callback;
  scoped_refptr<base::SingleThreadTaskRunner> runner;
  base::TimeDelta timeout;
  size_t max_message_bytes;
  base::RepeatingClosure on_idle;
  naive_client_stats stats{};
  std::map<uint64_t, std::unique_ptr<Http>> http;
  std::map<uint64_t, std::unique_ptr<WebSocket>> websocket;
  base::WeakPtrFactory<Impl> weak{this};
};

class BrowserOperations::Impl::Http final : public net::URLRequest::Delegate {
 public:
  Http(Impl* owner, uint64_t id, void* context)
      : owner_(owner), id_(id), context_(context) {}
  ~Http() override { Close(net::ERR_ABORTED); }
  void Start(const std::string& json, std::vector<char> upload) {
    auto value = base::JSONReader::ReadDict(json, base::JSON_PARSE_RFC);
    const auto* url_text = value ? value->FindString("url") : nullptr;
    const auto* method = value ? value->FindString("method") : nullptr;
    GURL url(url_text ? *url_text : "");
    net::HttpRequestHeaders headers;
    const bool navigation =
        value && value->FindBool("navigation").value_or(false);
    if (navigation)
      NavigationHeaders(url, owner_->context, &headers);
    if (!value || !HttpUrl(url) || !method ||
        !net::HttpUtil::IsToken(*method) || !ReadHeaders(*value, &headers) ||
        upload.size() > 64 * 1024 * 1024) {
      Fail(net::ERR_INVALID_ARGUMENT);
      return;
    }
    redirects_ = value->FindInt("max-redirects").value_or(20);
    if (redirects_ < -1 || redirects_ > 100) {
      Fail(net::ERR_INVALID_ARGUMENT);
      return;
    }
    if (navigation && *method != "GET" && *method != "HEAD") {
      Fail(net::ERR_INVALID_ARGUMENT);
      return;
    }
    request_ = owner_->context->CreateRequest(
        url, navigation ? net::HIGHEST : net::DEFAULT_PRIORITY, this, kTraffic,
        net::handles::kInvalidNetworkHandle);
    request_->set_method(*method);
    auto origin = url::Origin::Create(url);
    request_->set_isolation_info(
        navigation ? net::IsolationInfo::Create(
                         net::IsolationInfo::RequestType::kMainFrame, origin,
                         origin, net::SiteForCookies::FromOrigin(origin),
                         std::nullopt, net::NetworkIsolationPartition::kGeneral,
                         net::IsolationInfo::FrameAncestorRelation::kSameOrigin)
                   : net::IsolationInfo::CreateForInternalRequest(origin));
    request_->set_site_for_cookies(net::SiteForCookies::FromUrl(url));
    request_->SetExtraRequestHeaders(headers);
    if (!upload.empty() || value->FindBool("has-body").value_or(false))
      request_->set_upload(net::ElementsUploadDataStream::CreateWithReader(
          std::make_unique<net::UploadOwnedBytesElementReader>(&upload)));
    timeout_.Start(
        FROM_HERE, owner_->timeout,
        base::BindOnce(&Http::Fail, weak_.GetWeakPtr(), net::ERR_TIMED_OUT));
    request_->Start();
  }
  void OnReceivedRedirect(net::URLRequest* request,
                          const net::RedirectInfo& info,
                          bool* defer) override {
    if (!HttpUrl(info.new_url)) {
      *defer = true;
      Fail(net::ERR_UNSAFE_REDIRECT);
      return;
    }
    if (redirects_ == -1) {
      *defer = true;
      manual_redirect_ = true;
      Ready();
      return;
    }
    if (redirect_count_++ >= redirects_) {
      *defer = true;
      Fail(net::ERR_TOO_MANY_REDIRECTS);
      return;
    }
    // URLRequest is below Fetch's credential policy. Never forward explicit
    // origin credentials (or a caller-selected Host) to a different origin.
    if (url::Origin::Create(request->url()) !=
        url::Origin::Create(info.new_url)) {
      for (const char* name :
           {"Authorization", "Proxy-Authorization", "Cookie", "Host"})
        request->RemoveRequestHeaderByName(name);
    }
  }
  void OnAuthRequired(net::URLRequest* request,
                      const net::AuthChallengeInfo&) override {
    request->CancelAuth();
  }
  void OnSSLCertificateError(net::URLRequest*,
                             int error,
                             const net::SSLInfo&,
                             bool) override {
    Fail(error);
  }
  void OnResponseStarted(net::URLRequest*, int result) override {
    if (closed_)
      return;
    if (result != net::OK) {
      Fail(result);
      return;
    }
    Ready();
  }
  void Ready() {
    if (closed_ || ready_)
      return;
    ready_ = true;
    timeout_.Stop();
    ++owner_->stats.connect_successes;
    base::DictValue meta;
    meta.Set("status", request_->GetResponseCode());
    meta.Set("url", request_->url().spec());
    meta.Set("headers", Headers(request_->response_headers()));
    meta.Set("redirects", redirect_count_);
    const auto& info = request_->response_info();
    std::string protocol = info.alpn_negotiated_protocol;
    if (protocol.empty())
      protocol =
          std::string(net::HttpConnectionInfoToString(info.connection_info));
    meta.Set("protocol", protocol);
    TlsInfo(meta, info.ssl_info);
    auto text = Json(std::move(meta));
    if (text.size() > kMaxIO) {
      Fail(net::ERR_RESPONSE_HEADERS_TOO_BIG);
      return;
    }
    auto buffer = base::MakeRefCounted<naive_buffer>(text.size());
    buffer->io->span().copy_from(base::as_byte_span(text));
    Emit(owner_->callback, context_, id_, NAIVE_HTTP_HEADERS, net::OK,
         std::move(buffer), text.size());
  }
  void Read(size_t capacity, scoped_refptr<OwnedIOBuffer> owned = {}) {
    if (closed_ || !ready_ || pending_ || !capacity || capacity > kMaxIO) {
      if (owned)
        owned->Complete(net::ERR_UNEXPECTED, 0);
      else if (!closed_)
        Emit(owner_->callback, context_, id_, NAIVE_READ, net::ERR_UNEXPECTED);
      return;
    }
    owned_ = std::move(owned);
    if (!owned_)
      buffer_ = base::MakeRefCounted<naive_buffer>(capacity);
    pending_ = true;
    int result =
        manual_redirect_
            ? 0
            : request_->Read(owned_ ? static_cast<net::IOBuffer*>(owned_.get())
                                    : buffer_->io.get(),
                             capacity);
    if (result != net::ERR_IO_PENDING)
      OnReadCompleted(request_.get(), result);
  }
  void OnReadCompleted(net::URLRequest*, int result) override {
    if (closed_)
      return;
    pending_ = false;
    if (result > 0)
      owner_->stats.bytes_read += result;
    if (owned_) {
      auto owned = std::move(owned_);
      owned->Complete(result < 0 ? result : net::OK, result > 0 ? result : 0);
    } else {
      Emit(owner_->callback, context_, id_, NAIVE_READ, result,
           result > 0 ? std::move(buffer_) : nullptr, result > 0 ? result : 0);
      buffer_.reset();
    }
    if (result < 0)
      owner_->CloseSoon(id_, result);
  }
  void SetDeadline(uint32_t mask, std::optional<base::TimeTicks> when) {
    if (!(mask & 1) || closed_)
      return;
    read_timeout_.Stop();
    if (when)
      read_timeout_.Start(
          FROM_HERE,
          std::max(base::TimeDelta(), *when - base::TimeTicks::Now()),
          base::BindOnce(
              [](base::WeakPtr<Http> self) {
                if (self && !self->closed_)
                  Emit(self->owner_->callback, self->context_, self->id_,
                       NAIVE_READ_DEADLINE, net::OK);
              },
              weak_.GetWeakPtr()));
  }
  void Fail(int error) {
    if (closed_ || failed_)
      return;
    failed_ = true;
    Emit(owner_->callback, context_, id_, ready_ ? NAIVE_READ : NAIVE_CONNECTED,
         error);
    owner_->CloseSoon(id_, error);
  }
  void Close(int error) {
    if (closed_)
      return;
    closed_ = true;
    timeout_.Stop();
    read_timeout_.Stop();
    weak_.InvalidateWeakPtrs();
    if (owned_)
      owned_->Complete(error, 0);
    request_.reset();
    owned_.reset();
    buffer_.reset();
    ++owner_->stats.closed_streams;
    if (!ready_)
      ++owner_->stats.connect_failures;
    auto* callback_context = std::exchange(context_, nullptr);
    Emit(owner_->callback, callback_context, id_, NAIVE_CLOSED, error);
    Emit(owner_->callback, callback_context, id_, NAIVE_DESTROYED, net::OK);
  }

 private:
  Impl* owner_;
  uint64_t id_;
  void* context_;
  bool closed_ = false, failed_ = false, ready_ = false, pending_ = false;
  bool manual_redirect_ = false;
  int redirects_ = 20, redirect_count_ = 0;
  std::unique_ptr<net::URLRequest> request_;
  scoped_refptr<naive_buffer> buffer_;
  scoped_refptr<OwnedIOBuffer> owned_;
  base::OneShotTimer timeout_, read_timeout_;
  base::WeakPtrFactory<Http> weak_{this};
};

class BrowserOperations::Impl::WebSocket final
    : public net::WebSocketEventInterface {
 public:
  // The channel owns a forwarding event interface, never this operation.
  class Events final : public net::WebSocketEventInterface {
   public:
    explicit Events(WebSocket* owner) : owner_(owner) {}
    void OnCreateURLRequest(net::URLRequest* r) override {
      owner_->OnCreateURLRequest(r);
    }
    int OnURLRequestConnected(net::URLRequest* r,
                              const net::TransportInfo& i,
                              net::CompletionOnceCallback c) override {
      return owner_->OnURLRequestConnected(r, i, std::move(c));
    }
    void OnAddChannelResponse(
        std::unique_ptr<net::WebSocketHandshakeResponseInfo> r,
        const std::string& p,
        const std::string& e) override {
      owner_->OnAddChannelResponse(std::move(r), p, e);
    }
    void OnDataFrame(bool f, int t, base::span<const char> p) override {
      owner_->OnDataFrame(f, t, p);
    }
    bool HasPendingDataFrames() override {
      return owner_->HasPendingDataFrames();
    }
    void OnSendDataFrameDone() override { owner_->OnSendDataFrameDone(); }
    void OnClosingHandshake() override { owner_->OnClosingHandshake(); }
    void OnDropChannel(bool c,
                       uint16_t code,
                       const std::string& reason) override {
      owner_->OnDropChannel(c, code, reason);
    }
    void OnFailChannel(const std::string& m,
                       int n,
                       std::optional<int> c) override {
      owner_->OnFailChannel(m, n, c);
    }
    void OnStartOpeningHandshake(
        std::unique_ptr<net::WebSocketHandshakeRequestInfo> r) override {
      owner_->OnStartOpeningHandshake(std::move(r));
    }
    void OnSSLCertificateError(std::unique_ptr<SSLErrorCallbacks> c,
                               const GURL& u,
                               int n,
                               const net::SSLInfo& s,
                               bool f) override {
      owner_->OnSSLCertificateError(std::move(c), u, n, s, f);
    }
    int OnAuthRequired(const net::AuthChallengeInfo& a,
                       scoped_refptr<net::HttpResponseHeaders> h,
                       const net::IPEndPoint& s,
                       base::OnceCallback<void(const net::AuthCredentials*)> c,
                       std::optional<net::AuthCredentials>* r) override {
      return owner_->OnAuthRequired(a, std::move(h), s, std::move(c), r);
    }

   private:
    WebSocket* owner_;
  };
  WebSocket(Impl* owner,
            uint64_t id,
            naive_websocket_callback callback,
            void* context)
      : owner_(owner), id_(id), callback_(callback), context_(context) {}
  ~WebSocket() override { Close(net::ERR_ABORTED); }
  void EmitEvent(int event, int code, std::string_view payload = {}) {
    if (context_)
      callback_(context_, id_, event, code,
                reinterpret_cast<const uint8_t*>(payload.data()),
                payload.size());
  }
  void Start(const std::string& json) {
    auto value = base::JSONReader::ReadDict(json, base::JSON_PARSE_RFC);
    const auto* url_text = value ? value->FindString("url") : nullptr;
    const auto* origin_text = value ? value->FindString("origin") : nullptr;
    GURL url(url_text ? *url_text : ""),
        origin_url(origin_text ? *origin_text : "");
    net::HttpRequestHeaders headers;
    if (!value || !url.is_valid() ||
        !(url.SchemeIs("ws") || url.SchemeIs("wss")) || url.has_username() ||
        url.has_password() || url.has_ref() || !HttpUrl(origin_url) ||
        !ReadHeaders(*value, &headers)) {
      Fail(net::ERR_INVALID_ARGUMENT, "invalid WebSocket request");
      return;
    }
    std::vector<std::string> protocols;
    if (auto* list = value->FindList("protocols")) {
      for (const auto& p : *list) {
        if (!p.is_string() || !net::HttpUtil::IsToken(p.GetString())) {
          Fail(net::ERR_INVALID_ARGUMENT, "invalid subprotocol");
          return;
        }
        if (std::find(protocols.begin(), protocols.end(), p.GetString()) !=
            protocols.end()) {
          Fail(net::ERR_INVALID_ARGUMENT, "duplicate subprotocol");
          return;
        }
        protocols.push_back(p.GetString());
      }
    }
    auto origin = url::Origin::Create(origin_url);
    channel_ = std::make_unique<net::WebSocketChannel>(
        std::make_unique<Events>(this), owner_->context);
    timer_.Start(
        FROM_HERE, owner_->timeout,
        base::BindOnce(&WebSocket::Fail, weak_.GetWeakPtr(), net::ERR_TIMED_OUT,
                       std::string("WebSocket handshake timed out")));
    channel_->SendAddChannelRequest(
        url, protocols, origin, net::StorageAccessApiStatus::kNone,
        net::IsolationInfo::CreateForInternalRequest(origin), headers,
        net::WebSocketPriorityHint::kDefault, kTraffic);
  }
  void OnCreateURLRequest(net::URLRequest*) override {}
  int OnURLRequestConnected(net::URLRequest*,
                            const net::TransportInfo&,
                            net::CompletionOnceCallback) override {
    return net::OK;
  }
  void OnStartOpeningHandshake(
      std::unique_ptr<net::WebSocketHandshakeRequestInfo>) override {}
  void OnAddChannelResponse(
      std::unique_ptr<net::WebSocketHandshakeResponseInfo> response,
      const std::string& protocol,
      const std::string& extensions) override {
    if (closed_)
      return;
    open_ = true;
    timer_.Stop();
    ++owner_->stats.connect_successes;
    base::DictValue meta;
    meta.Set("url", response->url.spec());
    meta.Set("status", response->headers->response_code());
    meta.Set("headers", Headers(response->headers.get()));
    meta.Set("subprotocol", protocol);
    meta.Set("extensions", extensions);
    meta.Set("remote_address", response->remote_endpoint.ToString());
    EmitEvent(NAIVE_WS_OPEN, net::OK, Json(std::move(meta)));
  }
  void OnDataFrame(bool fin,
                   int type,
                   base::span<const char> payload) override {
    if (closed_ || failed_ || closing_)
      return;
    if (type == net::WebSocketFrameHeader::kOpCodeText ||
        type == net::WebSocketFrameHeader::kOpCodeBinary)
      message_type_ = type;
    if (message_.size() + payload.size() > owner_->max_message_bytes ||
        queued_bytes_ + message_.size() + payload.size() >
            owner_->max_message_bytes * 2) {
      Fail(net::ERR_MSG_TOO_BIG, "WebSocket receive limit exceeded");
      return;
    }
    if (!payload.empty())
      message_.append(payload.data(), payload.size());
    if (fin) {
      if (messages_.size() >= 1024) {
        Fail(net::ERR_INSUFFICIENT_RESOURCES,
             "WebSocket receive queue limit exceeded");
        return;
      }
      queued_bytes_ += message_.size();
      messages_.emplace_back(message_type_, std::move(message_));
      message_.clear();
      Deliver();
    }
  }
  bool HasPendingDataFrames() override {
    return closed_ || failed_ || (!closing_ && !receiving_);
  }
  void Deliver() {
    if (!receiving_ || messages_.empty() || closed_)
      return;
    receiving_ = false;
    auto message = std::move(messages_.front());
    messages_.pop_front();
    queued_bytes_ -= message.second.size();
    owner_->stats.bytes_read += message.second.size();
    EmitEvent(NAIVE_WS_MESSAGE, message.first, message.second);
  }
  void Receive() {
    if (closed_ || failed_ || !open_ || closing_ || receiving_)
      return;
    receiving_ = true;
    Deliver();
    if (receiving_)
      static_cast<void>(channel_->ReadFrames());
  }
  void Send(bool text, std::vector<char> data) {
    if (closed_ || failed_)
      return;
    if (!open_ || closing_ || sending_ ||
        data.size() > owner_->max_message_bytes) {
      Fail(net::ERR_UNEXPECTED, "WebSocket send unavailable or too large");
      return;
    }
    sending_ = true;
    sending_bytes_ = data.size();
    auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(data.size());
    if (!data.empty())
      buffer->span().copy_from(base::as_byte_span(data));
    static_cast<void>(
        channel_->SendFrame(true,
                            text ? net::WebSocketFrameHeader::kOpCodeText
                                 : net::WebSocketFrameHeader::kOpCodeBinary,
                            std::move(buffer), data.size()));
  }
  void OnSendDataFrameDone() override {
    if (closed_ || failed_ || !sending_)
      return;
    sending_ = false;
    owner_->stats.bytes_written += sending_bytes_;
    EmitEvent(NAIVE_WS_SENT, net::OK);
  }
  void BeginClose(uint16_t code, const std::string& reason) {
    if (closed_ || failed_ || closing_)
      return;
    closing_ = true;
    messages_.clear();
    queued_bytes_ = 0;
    message_.clear();
    timer_.Start(
        FROM_HERE, owner_->timeout,
        base::BindOnce(&WebSocket::Fail, weak_.GetWeakPtr(), net::ERR_TIMED_OUT,
                       std::string("WebSocket close timed out")));
    if (channel_->StartClosingHandshake(code, reason) ==
            net::WebSocketChannel::CHANNEL_ALIVE &&
        open_)
      static_cast<void>(channel_->ReadFrames());
  }
  void OnClosingHandshake() override { closing_ = true; }
  void OnDropChannel(bool clean,
                     uint16_t code,
                     const std::string& reason) override {
    if (closed_ || failed_)
      return;
    finished_ = true;
    closing_ = true;
    timer_.Stop();
    base::DictValue meta;
    meta.Set("clean", clean);
    meta.Set("code", code);
    meta.Set("reason", reason);
    EmitEvent(NAIVE_WS_CLOSED, net::OK, Json(std::move(meta)));
    owner_->CloseSoon(id_, net::OK);
  }
  void OnFailChannel(const std::string& message,
                     int error,
                     std::optional<int>) override {
    Fail(error < 0 ? error : net::ERR_WS_PROTOCOL_ERROR, message);
  }
  void OnSSLCertificateError(std::unique_ptr<SSLErrorCallbacks> callbacks,
                             const GURL&,
                             int error,
                             const net::SSLInfo& ssl,
                             bool) override {
    callbacks->CancelSSLRequest(error, &ssl);
  }
  int OnAuthRequired(
      const net::AuthChallengeInfo&,
      scoped_refptr<net::HttpResponseHeaders>,
      const net::IPEndPoint&,
      base::OnceCallback<void(const net::AuthCredentials*)>,
      std::optional<net::AuthCredentials>* credentials) override {
    credentials->reset();
    return net::OK;
  }
  void Fail(int error, std::string message) {
    if (closed_ || failed_)
      return;
    failed_ = true;
    EmitEvent(NAIVE_WS_ERROR, error, message);
    owner_->CloseSoon(id_, error);
  }
  void Close(int error) {
    if (closed_)
      return;
    closed_ = true;
    timer_.Stop();
    weak_.InvalidateWeakPtrs();
    channel_.reset();
    if (!finished_ && !failed_)
      EmitEvent(NAIVE_WS_ERROR, error ? error : net::ERR_ABORTED);
    ++owner_->stats.closed_streams;
    if (!open_)
      ++owner_->stats.connect_failures;
    EmitEvent(NAIVE_WS_DESTROYED, net::OK);
    context_ = nullptr;
  }

 private:
  Impl* owner_;
  uint64_t id_;
  naive_websocket_callback callback_;
  void* context_;
  std::unique_ptr<net::WebSocketChannel> channel_;
  bool open_ = false, closed_ = false, failed_ = false, finished_ = false;
  bool closing_ = false, receiving_ = false, sending_ = false;
  int message_type_ = 0;
  size_t queued_bytes_ = 0, sending_bytes_ = 0;
  std::string message_;
  std::deque<std::pair<int, std::string>> messages_;
  base::OneShotTimer timer_;
  base::WeakPtrFactory<WebSocket> weak_{this};
};

BrowserOperations::Impl::~Impl() {
  CancelAll(net::ERR_ABORTED);
}
void BrowserOperations::Impl::Close(uint64_t id, int reason) {
  if (auto it = http.find(id); it != http.end()) {
    auto operation = std::move(it->second);
    http.erase(it);
    operation->Close(reason);
  } else if (auto socket_it = websocket.find(id);
             socket_it != websocket.end()) {
    auto operation = std::move(socket_it->second);
    websocket.erase(socket_it);
    operation->Close(reason);
  }
  if (http.empty() && websocket.empty())
    on_idle.Run();
}
void BrowserOperations::Impl::CancelAll(int reason) {
  weak.InvalidateWeakPtrs();
  while (!http.empty())
    Close(http.begin()->first, reason);
  while (!websocket.empty())
    Close(websocket.begin()->first, reason);
}
BrowserOperations::BrowserOperations(
    net::URLRequestContext* context,
    naive_callback callback,
    scoped_refptr<base::SingleThreadTaskRunner> runner,
    base::TimeDelta timeout,
    size_t max_message_bytes,
    base::RepeatingClosure on_idle)
    : impl_(std::make_unique<Impl>(context,
                                   callback,
                                   std::move(runner),
                                   timeout,
                                   max_message_bytes,
                                   std::move(on_idle))) {}
BrowserOperations::~BrowserOperations() = default;
void BrowserOperations::Http(uint64_t id,
                             std::string json,
                             std::vector<char> upload,
                             void* context) {
  if (!id || impl_->http.contains(id) || impl_->websocket.contains(id)) {
    Emit(impl_->callback, context, id, NAIVE_CONNECTED,
         net::ERR_INVALID_ARGUMENT);
    Emit(impl_->callback, context, id, NAIVE_DESTROYED, net::OK);
    return;
  }
  ++impl_->stats.connect_attempts;
  auto operation = std::make_unique<Impl::Http>(impl_.get(), id, context);
  auto* pointer = operation.get();
  impl_->http.emplace(id, std::move(operation));
  pointer->Start(json, std::move(upload));
}
void BrowserOperations::WebSocket(uint64_t id,
                                  std::string json,
                                  naive_websocket_callback callback,
                                  void* context) {
  if (!id || impl_->http.contains(id) || impl_->websocket.contains(id)) {
    callback(context, id, NAIVE_WS_ERROR, net::ERR_INVALID_ARGUMENT, nullptr,
             0);
    callback(context, id, NAIVE_WS_DESTROYED, net::OK, nullptr, 0);
    return;
  }
  ++impl_->stats.connect_attempts;
  auto operation =
      std::make_unique<Impl::WebSocket>(impl_.get(), id, callback, context);
  auto* pointer = operation.get();
  impl_->websocket.emplace(id, std::move(operation));
  pointer->Start(json);
}
void BrowserOperations::Read(uint64_t id, size_t capacity) {
  auto it = impl_->http.find(id);
  if (it != impl_->http.end())
    it->second->Read(capacity);
}
void BrowserOperations::ReadOwned(uint64_t id,
                                  scoped_refptr<OwnedIOBuffer> buffer) {
  auto it = impl_->http.find(id);
  if (it != impl_->http.end()) {
    const auto capacity = buffer->size();
    it->second->Read(capacity, std::move(buffer));
  } else
    buffer->Complete(net::ERR_SOCKET_NOT_CONNECTED, 0);
}
void BrowserOperations::SetDeadline(uint64_t id,
                                    uint32_t mask,
                                    std::optional<base::TimeTicks> deadline) {
  auto it = impl_->http.find(id);
  if (it != impl_->http.end())
    it->second->SetDeadline(mask, deadline);
}
void BrowserOperations::WebSocketReceive(uint64_t id) {
  auto it = impl_->websocket.find(id);
  if (it != impl_->websocket.end())
    it->second->Receive();
}
void BrowserOperations::WebSocketSend(uint64_t id,
                                      bool text,
                                      std::vector<char> data) {
  auto it = impl_->websocket.find(id);
  if (it != impl_->websocket.end())
    it->second->Send(text, std::move(data));
}
void BrowserOperations::WebSocketClose(uint64_t id,
                                       uint16_t code,
                                       std::string reason) {
  auto it = impl_->websocket.find(id);
  if (it != impl_->websocket.end())
    it->second->BeginClose(code, reason);
}
void BrowserOperations::Close(uint64_t id, int reason) {
  impl_->Close(id, reason);
}
void BrowserOperations::CancelAll(int reason) {
  impl_->CancelAll(reason);
}
naive_client_stats BrowserOperations::Stats() const {
  auto stats = impl_->stats;
  stats.active_streams = impl_->http.size() + impl_->websocket.size();
  return stats;
}
}  // namespace naive
