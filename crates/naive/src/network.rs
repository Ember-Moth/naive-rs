//! Host networking hooks. DNS and TCP dialing may finish on any thread or
//! executor; callback entry points must return promptly. A dropped completion
//! fails its request. Client/stream shutdown cancels native work immediately,
//! and late host completions safely release their results.
use naive_sys as sys;
use std::{
    ffi::{CStr, CString, c_char, c_void},
    io,
    marker::PhantomData,
    net::{IpAddr, SocketAddr, TcpStream, UdpSocket},
    ptr::NonNull,
    sync::Arc,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressFamily {
    Any,
    Ipv4,
    Ipv6,
}
#[derive(Clone, Debug)]
pub struct ResolveRequest {
    pub hostname: String,
    pub family: AddressFamily,
    pub query: ResolveQuery,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolveQuery {
    Address,
    /// Return an encoded ECHConfigList with complete_https(). Nonstandard
    /// ports are represented as _port._https.hostname in the request name.
    HttpsRecord,
}
#[derive(Clone, Debug)]
pub struct DialRequest {
    /// Candidate addresses for the outer TCP connection. A custom dialer owns
    /// selection, connection timing and socket protection/network binding.
    pub addresses: Vec<SocketAddr>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transport {
    Tcp,
    Udp,
}
#[derive(Clone, Copy, Debug)]
pub struct SocketInfo {
    pub transport: Transport,
    pub peer: SocketAddr,
}

/// Borrowed socket, valid only during `SocketControl::configure`. Never close
/// it or retain its raw descriptor. Use AsFd/AsSocket for platform APIs.
pub struct Socket<'a> {
    raw: isize,
    _borrow: PhantomData<&'a ()>,
}
#[cfg(unix)]
impl std::os::fd::AsFd for Socket<'_> {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        // SAFETY: the native callback lends an open socket for this borrow.
        unsafe { std::os::fd::BorrowedFd::borrow_raw(self.raw as _) }
    }
}
#[cfg(windows)]
impl std::os::windows::io::AsSocket for Socket<'_> {
    fn as_socket(&self) -> std::os::windows::io::BorrowedSocket<'_> {
        // SAFETY: the native callback lends an open socket for this borrow.
        unsafe { std::os::windows::io::BorrowedSocket::borrow_raw(self.raw as _) }
    }
}

pub trait Resolver: Send + Sync + 'static {
    /// Called on a native IO thread. Dispatch asynchronous work and return;
    /// address queries use `complete`, while HTTPS-record queries use
    /// `complete_https`. There is no implicit DNS fallback.
    fn resolve(&self, request: ResolveRequest, completion: ResolveCompletion);
}
impl<F> Resolver for F
where
    F: Fn(ResolveRequest, ResolveCompletion) + Send + Sync + 'static,
{
    fn resolve(&self, request: ResolveRequest, completion: ResolveCompletion) {
        self(request, completion);
    }
}
pub trait TcpDialer: Send + Sync + 'static {
    /// Called on a native IO thread. The supplied socket must already be
    /// connected. Its routing/protection is the dialer's responsibility.
    fn dial(&self, request: DialRequest, completion: DialCompletion);
}
impl<F> TcpDialer for F
where
    F: Fn(DialRequest, DialCompletion) + Send + Sync + 'static,
{
    fn dial(&self, request: DialRequest, completion: DialCompletion) {
        self(request, completion);
    }
}
pub trait SocketControl: Send + Sync + 'static {
    /// Runs synchronously before connect for each native-created TCP/UDP socket.
    /// Must return promptly. An error prevents this socket from connecting.
    fn configure(&self, socket: Socket<'_>, info: SocketInfo) -> io::Result<()>;
}
impl<F> SocketControl for F
where
    F: for<'a> Fn(Socket<'a>, SocketInfo) -> io::Result<()> + Send + Sync + 'static,
{
    fn configure(&self, socket: Socket<'_>, info: SocketInfo) -> io::Result<()> {
        self(socket, info)
    }
}

/// Optional hooks shared by a client's proxy and certificate-fetch contexts.
/// Each hook can be used independently. Custom dialing replaces TCP only;
/// QUIC can use a host UDP socket or Chromium UDP with `socket_control`.
#[derive(Clone, Default)]
pub struct NetworkConfig {
    pub resolver: Option<Arc<dyn Resolver>>,
    pub socket_control: Option<Arc<dyn SocketControl>>,
    pub tcp_dialer: Option<Arc<dyn TcpDialer>>,
    pub udp_dialer: Option<Arc<dyn UdpDialer>>,
}
impl std::fmt::Debug for NetworkConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkConfig")
            .field("resolver", &self.resolver.is_some())
            .field("socket_control", &self.socket_control.is_some())
            .field("tcp_dialer", &self.tcp_dialer.is_some())
            .field("udp_dialer", &self.udp_dialer.is_some())
            .finish()
    }
}
impl NetworkConfig {
    pub(crate) fn hooks(self: &Arc<Self>) -> Option<sys::NetworkHooks> {
        if self.resolver.is_none()
            && self.socket_control.is_none()
            && self.tcp_dialer.is_none()
            && self.udp_dialer.is_none()
        {
            return None;
        }
        Some(sys::NetworkHooks {
            context: Arc::as_ptr(self).cast_mut().cast(),
            retain: retain_context,
            release: release_context,
            resolve: self.resolver.as_ref().map(|_| resolve as _),
            control: self.socket_control.as_ref().map(|_| control as _),
            dial_tcp: self.tcp_dialer.as_ref().map(|_| dial as _),
            dial_udp: self.udp_dialer.as_ref().map(|_| dial_udp as _),
        })
    }
}

/// A cancellation observer. It can outlive both the completion and the client.
/// Native cancellation never waits for host work to stop. Hosts should abandon
/// unnecessary work when this flag is set; late results remain safe to submit.
pub struct Cancellation(NonNull<sys::NetworkRequest>);
// SAFETY: the native reference count and cancellation flag are thread-safe.
unsafe impl Send for Cancellation {}
unsafe impl Sync for Cancellation {}
impl Cancellation {
    pub fn is_cancelled(&self) -> bool {
        unsafe { sys::naive_network_request_is_cancelled(self.0.as_ptr()) != 0 }
    }
}
impl Clone for Cancellation {
    fn clone(&self) -> Self {
        unsafe { sys::naive_network_request_retain(self.0.as_ptr()) };
        Self(self.0)
    }
}
impl Drop for Cancellation {
    fn drop(&mut self) {
        unsafe { sys::naive_network_request_release(self.0.as_ptr()) };
    }
}

pub struct ResolveCompletion(Option<Cancellation>);
impl ResolveCompletion {
    pub fn cancellation(&self) -> Cancellation {
        self.0.as_ref().expect("completion consumed").clone()
    }
    /// Completes an HTTPS-record request used by ECH discovery. The same host
    /// resolver owns both address and ECH queries; no system-DNS fallback occurs.
    pub fn complete_https(mut self, result: io::Result<Vec<u8>>) {
        let owner = self.0.take().unwrap();
        let (code, json) = match result {
            Ok(config) if !config.is_empty() && config.len() <= 65537 => (
                0,
                serde_json::json!({"addresses": [], "ech": config}).to_string(),
            ),
            Ok(_) => (-105, String::new()),
            Err(error) => (error_code(&error), String::new()),
        };
        let json = CString::new(json).unwrap();
        unsafe { sys::naive_resolve_complete(owner.0.as_ptr(), code, json.as_ptr()) };
        std::mem::forget(owner);
    }
    pub fn complete(mut self, result: io::Result<Vec<IpAddr>>) {
        let owner = self.0.take().unwrap();
        let (code, json) = match result {
            Ok(addresses) if !addresses.is_empty() && addresses.len() <= 64 => (
                0,
                serde_json::to_string(
                    &addresses
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>(),
                )
                .unwrap(),
            ),
            Ok(_) => (-105, String::new()),
            Err(error) => (error_code(&error), String::new()),
        };
        let json = CString::new(json).unwrap();
        // SAFETY: transfers this reference; native copies JSON before returning.
        unsafe { sys::naive_resolve_complete(owner.0.as_ptr(), code, json.as_ptr()) };
        std::mem::forget(owner);
    }
}
impl Drop for ResolveCompletion {
    fn drop(&mut self) {
        if let Some(owner) = self.0.take() {
            unsafe { sys::naive_resolve_complete(owner.0.as_ptr(), -3, std::ptr::null()) };
            std::mem::forget(owner);
        }
    }
}

pub struct DialCompletion(Option<Cancellation>);
impl DialCompletion {
    pub fn cancellation(&self) -> Cancellation {
        self.0.as_ref().expect("completion consumed").clone()
    }
    pub fn complete(mut self, result: io::Result<TcpStream>) {
        let owner = self.0.take().unwrap();
        let result = result.and_then(|stream| {
            stream.set_nonblocking(true)?;
            Ok(stream)
        });
        let (code, socket) = match result {
            #[cfg(unix)]
            Ok(stream) => {
                use std::os::fd::IntoRawFd;
                (0, stream.into_raw_fd() as isize)
            }
            #[cfg(windows)]
            Ok(stream) => {
                use std::os::windows::io::IntoRawSocket;
                (0, stream.into_raw_socket() as isize)
            }
            Err(error) => (error_code(&error), -1),
        };
        // SAFETY: transfers the completion reference and the owned socket.
        unsafe { sys::naive_dial_tcp_complete(owner.0.as_ptr(), code, socket) };
        std::mem::forget(owner);
    }
}
impl Drop for DialCompletion {
    fn drop(&mut self) {
        if let Some(owner) = self.0.take() {
            unsafe { sys::naive_dial_tcp_complete(owner.0.as_ptr(), -3, -1) };
            std::mem::forget(owner);
        }
    }
}

pub struct UdpCompletion(Option<Cancellation>);
impl UdpCompletion {
    pub fn cancellation(&self) -> Cancellation {
        self.0.as_ref().expect("completion consumed").clone()
    }
    pub fn complete(mut self, result: io::Result<UdpSocket>) {
        let owner = self.0.take().unwrap();
        let result = result.and_then(|stream| {
            stream.set_nonblocking(true)?;
            Ok(stream)
        });
        let (code, socket) = match result {
            #[cfg(unix)]
            Ok(stream) => {
                use std::os::fd::IntoRawFd;
                (0, stream.into_raw_fd() as isize)
            }
            #[cfg(windows)]
            Ok(stream) => {
                use std::os::windows::io::IntoRawSocket;
                (0, stream.into_raw_socket() as isize)
            }
            Err(error) => (error_code(&error), -1),
        };
        // SAFETY: transfers the completion reference and the owned socket.
        unsafe { sys::naive_dial_udp_complete(owner.0.as_ptr(), code, socket) };
        std::mem::forget(owner);
    }
}
impl Drop for UdpCompletion {
    fn drop(&mut self) {
        if let Some(owner) = self.0.take() {
            unsafe { sys::naive_dial_udp_complete(owner.0.as_ptr(), -3, -1) };
            std::mem::forget(owner);
        }
    }
}

fn error_code(error: &io::Error) -> i32 {
    match error.kind() {
        io::ErrorKind::PermissionDenied => -10,
        io::ErrorKind::TimedOut => -7,
        io::ErrorKind::ConnectionRefused => -102,
        io::ErrorKind::NotFound => -105,
        io::ErrorKind::InvalidInput => -4,
        io::ErrorKind::ConnectionAborted | io::ErrorKind::Interrupted => -3,
        _ => -2,
    }
}
unsafe extern "C" fn retain_context(context: *mut c_void) {
    unsafe { Arc::increment_strong_count(context.cast::<NetworkConfig>()) };
}
unsafe extern "C" fn release_context(context: *mut c_void) {
    // User hook destructors must not unwind over FFI.
    if std::panic::catch_unwind(|| unsafe {
        drop(Arc::from_raw(context.cast::<NetworkConfig>()));
    })
    .is_err()
    {
        std::process::abort();
    }
}
unsafe extern "C" fn resolve(
    context: *mut c_void,
    host: *const c_char,
    family: i32,
    request: *mut sys::NetworkRequest,
) {
    let completion = ResolveCompletion(Some(Cancellation(NonNull::new(request).unwrap())));
    // On panic the owned completion fails the request during unwinding.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let config = unsafe { &*context.cast::<NetworkConfig>() };
        let hostname = unsafe { CStr::from_ptr(host) }
            .to_string_lossy()
            .into_owned();
        let query = if family == 65 {
            ResolveQuery::HttpsRecord
        } else {
            ResolveQuery::Address
        };
        let family = match family {
            4 => AddressFamily::Ipv4,
            6 => AddressFamily::Ipv6,
            _ => AddressFamily::Any,
        };
        config.resolver.as_ref().unwrap().resolve(
            ResolveRequest {
                hostname,
                family,
                query,
            },
            completion,
        );
    }));
}
unsafe extern "C" fn dial(
    context: *mut c_void,
    addresses: *const c_char,
    request: *mut sys::NetworkRequest,
) {
    let completion = DialCompletion(Some(Cancellation(NonNull::new(request).unwrap())));
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let config = unsafe { &*context.cast::<NetworkConfig>() };
        let json = unsafe { CStr::from_ptr(addresses) }.to_bytes();
        let addresses: Vec<SocketAddr> = serde_json::from_slice(json).unwrap();
        config
            .tcp_dialer
            .as_ref()
            .unwrap()
            .dial(DialRequest { addresses }, completion);
    }));
}
unsafe extern "C" fn control(
    context: *mut c_void,
    socket: isize,
    protocol: i32,
    peer: *const c_char,
) -> i32 {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let config = unsafe { &*context.cast::<NetworkConfig>() };
        let peer: SocketAddr = unsafe { CStr::from_ptr(peer) }
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        let transport = if protocol == 6 {
            Transport::Tcp
        } else {
            Transport::Udp
        };
        let socket = Socket {
            raw: socket,
            _borrow: PhantomData,
        };
        config
            .socket_control
            .as_ref()
            .unwrap()
            .configure(socket, SocketInfo { transport, peer })
            .map_or_else(|error| error_code(&error), |_| 0)
    }))
    .unwrap_or(-2)
}

#[derive(Clone, Debug)]
pub struct UdpDialRequest {
    pub peer: SocketAddr,
    /// Platform network handle, when Chromium explicitly requested a network.
    pub network: Option<i64>,
}
pub trait UdpDialer: Send + Sync + 'static {
    /// Return a bound UDP socket, optionally already connected to a chosen
    /// peer. Otherwise native connects it to request.peer. The host must apply
    /// protection and network binding before completing this request.
    fn dial(&self, request: UdpDialRequest, completion: UdpCompletion);
}
impl<F> UdpDialer for F
where
    F: Fn(UdpDialRequest, UdpCompletion) + Send + Sync + 'static,
{
    fn dial(&self, request: UdpDialRequest, completion: UdpCompletion) {
        self(request, completion);
    }
}
unsafe extern "C" fn dial_udp(
    context: *mut c_void,
    peer: *const c_char,
    network: i64,
    request: *mut sys::NetworkRequest,
) {
    let completion = UdpCompletion(Some(Cancellation(NonNull::new(request).unwrap())));
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let config = unsafe { &*context.cast::<NetworkConfig>() };
        let peer: SocketAddr = unsafe { CStr::from_ptr(peer) }
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        config.udp_dialer.as_ref().unwrap().dial(
            UdpDialRequest {
                peer,
                network: (network != -1).then_some(network),
            },
            completion,
        );
    }));
}
