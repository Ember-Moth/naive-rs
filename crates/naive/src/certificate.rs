//! Asynchronous server-certificate decisions, scoped to one client context.
//!
//! Chromium performs its normal verification first. The callback can preserve
//! that result, reject it (for example for pinning), or explicitly accept the
//! certificate. This does not bypass TLS proof of private-key possession, ECH
//! requirements, or turn a private certificate into a publicly trusted root.
use crate::Error;
use naive_sys as sys;
use serde::Deserialize;
use std::{
    ffi::{CStr, c_char, c_void},
    ptr::NonNull,
};

#[derive(Clone, Debug)]
pub struct CertificateInfo {
    /// TLS verification hostname, including the public name on ECH rejection.
    pub hostname: String,
    /// Peer-supplied DER chain, leaf first.
    pub certificate_chain: Vec<Vec<u8>>,
    /// Chain produced by Chromium. It can be incomplete when verification failed.
    pub verified_chain: Vec<Vec<u8>>,
    pub default_error: Option<Error>,
    /// Chromium CertStatus flags, before applying the custom decision.
    pub certificate_status: u32,
    pub issued_by_known_root: bool,
    pub ocsp_response: Vec<u8>,
    pub sct_list: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CertificateDecision {
    /// Preserve Chromium's result, including hostname and trust failures.
    #[default]
    UseDefault,
    /// Override certificate validation errors. The caller assumes responsibility
    /// for trust, hostname, expiry, and any other certificate policy it overrides.
    Accept,
    Reject,
}

pub trait CertificateVerifier: Send + Sync + 'static {
    /// Called on a native IO thread. Dispatch slow/asynchronous work and return.
    /// Completion can run on any thread. Dropping it without a decision rejects
    /// the certificate; a panic is contained and also rejects the certificate.
    /// Decisions apply to new certificate verifications, not every HTTP request:
    /// existing TLS sessions and pooled connections can be reused.
    fn verify(&self, info: CertificateInfo, completion: CertificateVerification);
}
impl<F> CertificateVerifier for F
where
    F: Fn(CertificateInfo, CertificateVerification) + Send + Sync + 'static,
{
    fn verify(&self, info: CertificateInfo, completion: CertificateVerification) {
        self(info, completion);
    }
}

pub struct CertificateCancellation(NonNull<sys::CertificateRequest>);
// SAFETY: native tokens use atomic reference counting and a cancellation flag.
unsafe impl Send for CertificateCancellation {}
unsafe impl Sync for CertificateCancellation {}
impl CertificateCancellation {
    pub fn is_cancelled(&self) -> bool {
        unsafe { sys::naive_cert_request_is_cancelled(self.0.as_ptr()) != 0 }
    }
}
impl Clone for CertificateCancellation {
    fn clone(&self) -> Self {
        unsafe { sys::naive_cert_request_retain(self.0.as_ptr()) };
        Self(self.0)
    }
}
impl Drop for CertificateCancellation {
    fn drop(&mut self) {
        unsafe { sys::naive_cert_request_release(self.0.as_ptr()) };
    }
}

pub struct CertificateVerification(Option<CertificateCancellation>);
impl CertificateVerification {
    pub fn cancellation(&self) -> CertificateCancellation {
        self.0.as_ref().expect("completion consumed").clone()
    }
    /// Consumes this completion. A result arriving after cancellation is ignored.
    pub fn complete(mut self, decision: CertificateDecision) {
        let owner = self.0.take().unwrap();
        let decision = match decision {
            CertificateDecision::UseDefault => 0,
            CertificateDecision::Accept => 1,
            CertificateDecision::Reject => 2,
        };
        unsafe { sys::naive_cert_verify_complete(owner.0.as_ptr(), decision) };
        std::mem::forget(owner);
    }
}
impl Drop for CertificateVerification {
    fn drop(&mut self) {
        if let Some(owner) = self.0.take() {
            unsafe { sys::naive_cert_verify_complete(owner.0.as_ptr(), 2) };
            std::mem::forget(owner);
        }
    }
}

#[derive(Deserialize)]
struct WireInfo {
    hostname: String,
    certificate_chain: Vec<Vec<u8>>,
    verified_chain: Vec<Vec<u8>>,
    default_result: i32,
    certificate_status: i32,
    issued_by_known_root: bool,
    ocsp_response: Vec<u8>,
    sct_list: Vec<u8>,
}

pub(crate) unsafe extern "C" fn verify(
    context: *mut c_void,
    info: *const c_char,
    request: *mut sys::CertificateRequest,
) {
    let completion = CertificateVerification(Some(CertificateCancellation(
        NonNull::new(request).expect("native certificate token"),
    )));
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let hooks = unsafe { &*context.cast::<crate::network::ClientHooks>() };
        let bytes = unsafe { CStr::from_ptr(info) }.to_bytes();
        let wire: WireInfo = serde_json::from_slice(bytes).expect("native certificate metadata");
        hooks.certificate_verifier.as_ref().unwrap().verify(
            CertificateInfo {
                hostname: wire.hostname,
                certificate_chain: wire.certificate_chain,
                verified_chain: wire.verified_chain,
                default_error: (wire.default_result != 0)
                    .then(|| Error::native(wire.default_result)),
                certificate_status: wire.certificate_status as u32,
                issued_by_known_root: wire.issued_by_known_root,
                ocsp_response: wire.ocsp_response,
                sct_list: wire.sct_list,
            },
            completion,
        );
    }));
}
