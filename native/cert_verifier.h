#ifndef NAIVE_RS_CERT_VERIFIER_H_
#define NAIVE_RS_CERT_VERIFIER_H_
#include <memory>
#include "naive_rs/network.h"
#include "net/cert/cert_verifier.h"
namespace naive {
std::unique_ptr<net::CertVerifier> WrapCertificateVerifier(
    std::unique_ptr<net::CertVerifier> native,
    std::shared_ptr<NetworkHooks> hooks);
}  // namespace naive
#endif
