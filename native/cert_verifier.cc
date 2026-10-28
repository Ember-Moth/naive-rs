#include "naive_rs/cert_verifier.h"

#include <atomic>
#include <set>
#include <utility>
#include "base/functional/bind.h"
#include "base/json/json_writer.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/task/single_thread_task_runner.h"
#include "base/values.h"
#include "net/base/net_errors.h"
#include "net/cert/cert_status_flags.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/x509_util.h"
#include "third_party/boringssl/src/include/openssl/pool.h"

struct naive_cert_request : base::RefCountedThreadSafe<naive_cert_request> {
  explicit naive_cert_request(base::OnceCallback<void(int)> callback)
      : runner(base::SingleThreadTaskRunner::GetCurrentDefault()),
        callback(std::move(callback)) {}
  void Cancel() {
    DCHECK(runner->BelongsToCurrentThread());
    cancelled.store(true, std::memory_order_release);
    callback.Reset();
  }
  void Complete(int decision) {
    runner->PostTask(
        FROM_HERE,
        base::BindOnce(
            [](scoped_refptr<naive_cert_request> request, int decision) {
              if (request->callback &&
                  !request->cancelled.load(std::memory_order_acquire))
                std::move(request->callback).Run(decision);
            },
            base::WrapRefCounted(this), decision));
  }
  std::atomic<bool> cancelled{false};

 private:
  friend class base::RefCountedThreadSafe<naive_cert_request>;
  ~naive_cert_request() = default;
  scoped_refptr<base::SingleThreadTaskRunner> runner;
  base::OnceCallback<void(int)> callback;
};

namespace naive {
namespace {
base::ListValue Bytes(base::span<const uint8_t> bytes) {
  base::ListValue value;
  value.reserve(bytes.size());
  for (uint8_t byte : bytes)
    value.Append(static_cast<int>(byte));
  return value;
}
base::ListValue Chain(const scoped_refptr<net::X509Certificate>& certificate) {
  base::ListValue value;
  if (certificate) {
    value.Append(
        Bytes(net::x509_util::CryptoBufferAsSpan(certificate->cert_buffer())));
    for (const auto& intermediate : certificate->intermediate_buffers())
      value.Append(
          Bytes(net::x509_util::CryptoBufferAsSpan(intermediate.get())));
  }
  return value;
}

class Verification;
struct State {
  std::shared_ptr<NetworkHooks> hooks;
  std::set<Verification*> requests;
};
class Verification final : public net::CertVerifier::Request {
 public:
  Verification(std::shared_ptr<State> state,
               const net::CertVerifier::RequestParams& params,
               net::CertVerifyResult* output,
               net::CompletionOnceCallback callback)
      : state_(std::move(state)),
        params_(params),
        output_(output),
        callback_(std::move(callback)) {
    state_->requests.insert(this);
  }
  ~Verification() override {
    Cancel();
    state_->requests.erase(this);
  }
  void Start(net::CertVerifier* native, const net::NetLogWithSource& log) {
    state_->hooks->Track(
        this, base::BindRepeating(&Verification::Abort, weak_.GetWeakPtr()));
    int result = native->Verify(
        params_, &result_,
        base::BindOnce(&Verification::NativeDone, weak_.GetWeakPtr()),
        &native_request_, log);
    if (result != net::ERR_IO_PENDING)
      NativeDone(result);
  }
  void Cancel() {
    state_->hooks->Untrack(this);
    weak_.InvalidateWeakPtrs();
    native_request_.reset();
    if (request_)
      request_->Cancel();
    request_.reset();
    callback_.Reset();
    output_ = nullptr;
  }

 private:
  void Abort() {
    auto callback = std::move(callback_);
    if (output_)
      *output_ = result_;
    Cancel();
    if (callback)
      std::move(callback).Run(net::ERR_ABORTED);
  }
  void NativeDone(int result) {
    native_result_ = result;
    native_request_.reset();
    if (!result_.verified_cert)
      result_.verified_cert = params_.certificate();
    base::DictValue info;
    info.Set("hostname", params_.hostname());
    info.Set("certificate_chain", Chain(params_.certificate()));
    info.Set("verified_chain", Chain(result_.verified_cert));
    info.Set("default_result", result);
    info.Set("certificate_status", static_cast<int>(result_.cert_status));
    info.Set("issued_by_known_root", result_.is_issued_by_known_root);
    info.Set("ocsp_response",
             Bytes(base::as_byte_span(params_.ocsp_response())));
    info.Set("sct_list", Bytes(base::as_byte_span(params_.sct_list())));
    auto json = base::WriteJson(info);
    if (!json) {
      // Complete asynchronously even when native verification was synchronous.
      base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
          FROM_HERE,
          base::BindOnce(&Verification::Decide, weak_.GetWeakPtr(), 2));
      return;
    }
    request_ = base::MakeRefCounted<naive_cert_request>(
        base::BindOnce(&Verification::Decide, weak_.GetWeakPtr()));
    request_->AddRef();
    state_->hooks->value.verify_certificate(state_->hooks->value.context,
                                            json->c_str(), request_.get());
  }
  void Decide(int decision) {
    int result = native_result_;
    if (decision == 1 &&
        (result == net::OK || net::IsCertificateError(result))) {
      if (result != net::OK)
        result_.is_issued_by_known_root = false;
      result_.cert_status &= ~net::CERT_STATUS_ALL_ERRORS;
      result = net::OK;
    } else if (decision != 0 && decision != 1) {
      result_.cert_status |= net::CERT_STATUS_INVALID;
      result = net::ERR_CERT_INVALID;
    }
    *output_ = result_;
    auto callback = std::move(callback_);
    // A completed decision is not a cancellation. Observers may retain the
    // token after the host has completed it.
    request_.reset();
    Cancel();
    std::move(callback).Run(result);
  }
  std::shared_ptr<State> state_;
  net::CertVerifier::RequestParams params_;
  net::CertVerifyResult* output_;
  net::CertVerifyResult result_;
  int native_result_ = net::ERR_CERT_INVALID;
  net::CompletionOnceCallback callback_;
  std::unique_ptr<net::CertVerifier::Request> native_request_;
  scoped_refptr<naive_cert_request> request_;
  base::WeakPtrFactory<Verification> weak_{this};
};

class Verifier final : public net::CertVerifier {
 public:
  Verifier(std::unique_ptr<net::CertVerifier> native,
           std::shared_ptr<NetworkHooks> hooks)
      : native_(std::move(native)), state_(std::make_shared<State>()) {
    state_->hooks = std::move(hooks);
  }
  ~Verifier() override {
    auto requests = state_->requests;
    for (auto* request : requests)
      request->Cancel();
  }
  int Verify(const RequestParams& params,
             net::CertVerifyResult* output,
             net::CompletionOnceCallback callback,
             std::unique_ptr<Request>* request,
             const net::NetLogWithSource& log) override {
    auto pending = std::make_unique<Verification>(state_, params, output,
                                                  std::move(callback));
    auto* pointer = pending.get();
    *request = std::move(pending);
    pointer->Start(native_.get(), log);
    return net::ERR_IO_PENDING;
  }
  void Verify2QwacBinding(
      const std::string& binding,
      const std::string& hostname,
      const scoped_refptr<net::X509Certificate>& cert,
      base::OnceCallback<void(const scoped_refptr<net::X509Certificate>&)>
          callback,
      const net::NetLogWithSource& log) override {
    native_->Verify2QwacBinding(binding, hostname, cert, std::move(callback),
                                log);
  }
  void SetConfig(const Config& config) override { native_->SetConfig(config); }
  void AddObserver(Observer* observer) override {
    native_->AddObserver(observer);
  }
  void RemoveObserver(Observer* observer) override {
    native_->RemoveObserver(observer);
  }

 private:
  std::unique_ptr<net::CertVerifier> native_;
  std::shared_ptr<State> state_;
};
}  // namespace

std::unique_ptr<net::CertVerifier> WrapCertificateVerifier(
    std::unique_ptr<net::CertVerifier> native,
    std::shared_ptr<NetworkHooks> hooks) {
  if (!hooks || !hooks->value.verify_certificate)
    return native;
  return std::make_unique<Verifier>(std::move(native), std::move(hooks));
}
}  // namespace naive

extern "C" {
void naive_cert_request_retain(naive_cert_request* request) {
  request->AddRef();
}
void naive_cert_request_release(naive_cert_request* request) {
  request->Release();
}
int32_t naive_cert_request_is_cancelled(naive_cert_request* request) {
  return request->cancelled.load(std::memory_order_acquire);
}
void naive_cert_verify_complete(naive_cert_request* request, int32_t decision) {
  request->Complete(decision);
  request->Release();
}
}
