use crate::{
    ClientStats, Config, ConnectionInfo, Error, Event, NaiveStream, NetworkConfig, Observer,
    Operation,
    buffer::{Buffer, ReadChunk, WriteBatch},
    observability::notify,
    stream::{Shared, State},
};
use event_listener::Event as SyncEvent;
use futures_channel::oneshot;
use naive_sys as sys;
use std::{
    ffi::{CString, c_void},
    ptr::NonNull,
    sync::{
        Arc, Mutex, MutexGuard, OnceLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc,
    },
};

pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct Handle(NonNull<sys::Engine>);
// SAFETY: handles are immutable after creation, submitted operations post to the
// assigned native IO sequence, and destroy runs only after the last Rust owner.
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}
struct Native {
    handle: Handle,
    closing: AtomicBool,
    submitting: AtomicUsize,
    observer: Option<Arc<dyn Observer>>,
}

impl Native {
    fn create(
        config: String,
        network: NetworkConfig,
        observer: Option<Arc<dyn Observer>>,
    ) -> Result<Self, Error> {
        if unsafe { sys::naive_abi_version() } != sys::ABI_VERSION {
            return Err(Error::runtime("native ABI mismatch".into()));
        }
        let json =
            CString::new(config).map_err(|_| Error::invalid("NUL in serialized configuration"))?;
        let mut output = std::ptr::null_mut();
        // SAFETY: synchronous creation copies config; no stream contexts exist yet.
        let network = Arc::new(network);
        let hooks = network.hooks();
        let result = unsafe {
            sys::naive_engine_create(
                json.as_ptr(),
                on_event,
                hooks.as_ref().map_or(std::ptr::null(), |h| h),
                &mut output,
            )
        };
        if result != 0 {
            return Err(Error::native(result));
        }
        Ok(Self {
            handle: Handle(NonNull::new(output).expect("native create returned null")),
            closing: AtomicBool::new(false),
            submitting: AtomicUsize::new(0),
            observer,
        })
    }
}
impl Drop for Native {
    fn drop(&mut self) {
        // The control worker also handles canceled initialization results. No OS
        // thread is created per drop and no async executor is blocked by teardown.
        control()
            .send(Control::Destroy(Handle(self.handle.0)))
            .expect("native control worker stopped");
    }
}

enum Control {
    Create(
        String,
        NetworkConfig,
        Option<Arc<dyn Observer>>,
        oneshot::Sender<Result<Arc<Native>, Error>>,
    ),
    Shutdown(Arc<Native>, Arc<Completion>),
    Destroy(Handle),
    Reset(Arc<Native>, oneshot::Sender<Result<(), Error>>),
    Stats(Arc<Native>, oneshot::Sender<Result<ClientStats, Error>>),
    Info(
        Arc<Native>,
        u64,
        oneshot::Sender<Result<ConnectionInfo, Error>>,
    ),
}
fn control() -> &'static mpsc::Sender<Control> {
    static CONTROL: OnceLock<mpsc::Sender<Control>> = OnceLock::new();
    CONTROL.get_or_init(|| {
        let (send, recv) = mpsc::channel();
        std::thread::Builder::new()
            .name("naive-rs-control".into())
            .spawn(move || {
                while let Ok(operation) = recv.recv() {
                    match operation {
                        Control::Create(config, network, observer, reply) => {
                            if !reply.is_canceled() {
                                let _ = reply
                                    .send(Native::create(config, network, observer).map(Arc::new));
                            }
                        }
                        Control::Shutdown(native, done) => {
                            // The admission gate prevents a late post after shutdown's
                            // IO barrier. Submissions contain only a short native post.
                            while native.submitting.load(Ordering::SeqCst) != 0 {
                                std::thread::yield_now();
                            }
                            // SAFETY: this Arc keeps the handle alive. Shutdown does
                            // not delete it and can race queued read/write requests.
                            unsafe {
                                sys::naive_engine_shutdown(native.handle.0.as_ptr());
                            }
                            notify(&native.observer, Event::ShutdownComplete);
                            done.finish();
                        }
                        Control::Reset(native, reply) => {
                            let result = unsafe {
                                sys::naive_engine_reset_connections(native.handle.0.as_ptr())
                            };
                            if result == 0 {
                                notify(&native.observer, Event::ConnectionsReset);
                            }
                            let _ = reply.send(if result == 0 {
                                Ok(())
                            } else {
                                Err(Error::native(result))
                            });
                        }
                        Control::Stats(native, reply) => {
                            let mut stats = sys::ClientStats::default();
                            let result = unsafe {
                                sys::naive_engine_get_stats(
                                    native.handle.0.as_ptr(),
                                    &mut stats,
                                    std::mem::size_of::<sys::ClientStats>(),
                                )
                            };
                            let _ = reply.send(if result == 0 {
                                Ok(stats.into())
                            } else {
                                Err(Error::native(result))
                            });
                        }
                        Control::Info(native, id, reply) => {
                            let mut info = sys::StreamInfo::default();
                            let result = unsafe {
                                sys::naive_engine_get_stream_info(
                                    native.handle.0.as_ptr(),
                                    id,
                                    &mut info,
                                    std::mem::size_of::<sys::StreamInfo>(),
                                )
                            };
                            let _ = reply.send(if result == 0 {
                                Ok(info.into())
                            } else {
                                Err(Error::native(result))
                            });
                        }
                        Control::Destroy(handle) => {
                            // SAFETY: only Native::drop sends Destroy, after the final
                            // Rust handle reference and all synchronous FFI borrows.
                            unsafe {
                                sys::naive_engine_destroy(handle.0.as_ptr());
                            }
                        }
                    }
                }
            })
            .expect("could not start native control worker");
        send
    })
}

pub(crate) struct Inner {
    native: Arc<Native>,
    next_id: AtomicU64,
    shutdown_done: Arc<Completion>,
}
impl Inner {
    pub(crate) fn submit(&self, f: impl FnOnce(*mut sys::Engine)) -> Result<(), Error> {
        if self.native.closing.load(Ordering::SeqCst) {
            return Err(Error::closed());
        }
        self.native.submitting.fetch_add(1, Ordering::SeqCst);
        let _submission = Submission(&self.native.submitting);
        // SeqCst across both atomics makes a racing close either observe this
        // submission or cause this second check to reject it before posting.
        if self.native.closing.load(Ordering::SeqCst) {
            return Err(Error::closed());
        }
        f(self.native.handle.0.as_ptr());
        Ok(())
    }
    pub(crate) fn write(&self, id: u64, batch: WriteBatch) -> Result<(), Error> {
        self.submit(move |ptr| {
            let length = batch.length;
            // SAFETY: transfers one immutable native buffer reference; no caller
            // borrows it while queued/in flight. Native consumes on all paths.
            unsafe {
                sys::naive_engine_write(ptr, id, batch.buffer.into_raw(), length);
            }
        })
    }
    pub(crate) async fn info(&self, id: u64) -> Result<ConnectionInfo, Error> {
        let (send, recv) = oneshot::channel();
        control()
            .send(Control::Info(self.native.clone(), id, send))
            .map_err(|_| Error::closed())?;
        recv.await.map_err(|_| Error::closed())?
    }
    pub(crate) fn cancel(&self, id: u64) {
        let _ = self.submit(|ptr| unsafe { sys::naive_engine_close(ptr, id) });
    }
    fn start_shutdown(&self) {
        if !self.native.closing.swap(true, Ordering::SeqCst) {
            control()
                .send(Control::Shutdown(
                    self.native.clone(),
                    self.shutdown_done.clone(),
                ))
                .expect("native control worker stopped");
        }
    }
}
impl Drop for Inner {
    fn drop(&mut self) {
        self.start_shutdown();
    }
}

/// Cloneable client. Streams retain the native handle. Explicit shutdown closes
/// all stream resources and waits for the callback/NetLog completion barrier.
#[derive(Clone)]
pub struct NaiveClient {
    pub(crate) inner: Arc<Inner>,
}
impl NaiveClient {
    pub async fn new(config: Config) -> Result<Self, Error> {
        let (send, recv) = oneshot::channel();
        control()
            .send(Control::Create(
                config.json()?,
                config.network.clone(),
                config.observer.clone(),
                send,
            ))
            .map_err(|_| Error::runtime("native control worker stopped".into()))?;
        let native = recv.await.map_err(|_| Error::closed())??;
        notify(&native.observer, Event::ClientReady);
        let shutdown_done = Arc::new(Completion::default());
        Ok(Self {
            inner: Arc::new(Inner {
                native,
                next_id: AtomicU64::new(1),
                shutdown_done,
            }),
        })
    }
    /// Waits for CONNECT. Dropping this future cancels its stream.
    pub async fn connect(
        &self,
        hostname: impl AsRef<str>,
        port: u16,
    ) -> Result<NaiveStream, Error> {
        let mut stream = self.connect_early(hostname, port)?;
        stream.handshake().await?;
        Ok(stream)
    }
    /// Starts CONNECT and returns its stream immediately. Call `handshake()`
    /// to wait explicitly, or read/write to wait automatically. This does not
    /// enable TLS 0-RTT or send application data before proxy negotiation.
    pub fn connect_early(
        &self,
        hostname: impl AsRef<str>,
        port: u16,
    ) -> Result<NaiveStream, Error> {
        let hostname = hostname.as_ref();
        if hostname.is_empty() || port == 0 {
            return Err(Error::invalid("hostname and port must be nonempty"));
        }
        let hostname =
            CString::new(hostname).map_err(|_| Error::invalid("hostname contains NUL"))?;
        let mut id = self.inner.next_id.load(Ordering::Relaxed);
        loop {
            let next = id
                .checked_add(1)
                .ok_or_else(|| Error::runtime("stream ID space exhausted".into()))?;
            match self.inner.next_id.compare_exchange_weak(
                id,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(current) => id = current,
            }
        }
        let shared = Arc::new(Shared {
            state: Mutex::new(State::new()),
            inner: Arc::downgrade(&self.inner),
            observer: self.inner.native.observer.clone(),
        });
        if self.inner.native.closing.load(Ordering::SeqCst) {
            return Err(Error::closed());
        }
        if shared.observer.is_some() {
            notify(
                &shared.observer,
                Event::StreamStarted {
                    id,
                    hostname: hostname.to_string_lossy().into_owned(),
                    port,
                },
            );
        }
        // Each stream owns its callback Arc until native DESTROYED. No global
        // callback map/lock is consulted for read/write completions.
        {
            let context = Arc::into_raw(shared.clone());
            let result = self.inner.submit(|ptr| unsafe {
                sys::naive_engine_connect(
                    ptr,
                    id,
                    hostname.as_ptr(),
                    port,
                    context.cast_mut().cast(),
                )
            });
            if let Err(error) = result {
                // SAFETY: submit never called C, so ownership was not transferred.
                unsafe {
                    drop(Arc::from_raw(context));
                }
                notify(
                    &shared.observer,
                    Event::StreamError {
                        id,
                        operation: Operation::Connect,
                        error: error.clone(),
                    },
                );
                notify(
                    &shared.observer,
                    Event::StreamClosed {
                        id,
                        reason: error.clone(),
                    },
                );
                return Err(error);
            }
        }
        Ok(NaiveStream {
            inner: self.inner.clone(),
            shared,
            id,
            closed: false,
            owns_close: true,
        })
    }
    /// Cancels current streams and empties connection pools and DNS caches.
    /// Configuration and host hooks survive. Await this barrier before opening
    /// connections on the new network; racing connects may also be canceled.
    /// Once polled, dropping this future does not cancel the reset itself.
    pub async fn close_all_connections(&self) -> Result<(), Error> {
        if self.inner.native.closing.load(Ordering::SeqCst) {
            return Err(Error::closed());
        }
        let (send, recv) = oneshot::channel();
        control()
            .send(Control::Reset(self.inner.native.clone(), send))
            .map_err(|_| Error::closed())?;
        recv.await.map_err(|_| Error::closed())?
    }
    pub async fn stats(&self) -> Result<ClientStats, Error> {
        let (send, recv) = oneshot::channel();
        control()
            .send(Control::Stats(self.inner.native.clone(), send))
            .map_err(|_| Error::closed())?;
        recv.await.map_err(|_| Error::closed())?
    }
    pub async fn shutdown(&self) -> Result<(), Error> {
        self.inner.start_shutdown();
        self.inner.shutdown_done.wait().await;
        Ok(())
    }
}

#[derive(Default)]
struct Completion {
    done: AtomicBool,
    event: SyncEvent,
}
impl Completion {
    fn finish(&self) {
        self.done.store(true, Ordering::Release);
        self.event.notify(usize::MAX);
    }
    async fn wait(&self) {
        loop {
            let listener = self.event.listen();
            if self.done.load(Ordering::Acquire) {
                return;
            }
            listener.await;
        }
    }
}

struct Submission<'a>(&'a AtomicUsize);
impl Drop for Submission<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

unsafe extern "C" fn on_event(
    context: *mut c_void,
    id: u64,
    event: i32,
    result: i32,
    owner: *mut sys::Buffer,
    data: *mut u8,
    length: usize,
    capacity: usize,
) {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Even a failed/canceled completion transfers ownership of its buffer.
        let mut buffer = unsafe { Buffer::from_event(owner, data, capacity) };
        if event == sys::DESTROYED {
            assert!(buffer.is_none());
            // SAFETY: final callback; releases the one Arc transferred at connect.
            unsafe {
                drop(Arc::from_raw(context.cast::<Shared>()));
            }
            return;
        }
        // SAFETY: the native stream keeps the context Arc until DESTROYED.
        let shared = unsafe { &*context.cast::<Shared>() };
        if event == sys::WRITE_SHUTDOWN {
            let mut state = lock(&shared.state);
            state.write_shutdown_pending = false;
            if result == 0 {
                state.write_shutdown = true;
            } else {
                state.write_shutdown_error = Some(Error::native(result));
            }
            let write = state.write_waker.take();
            drop(state);
            if let Some(waker) = write {
                waker.wake();
            }
            return;
        }
        if result < 0 || event == sys::CLOSED {
            let error = if result < 0 {
                Error::native(result)
            } else {
                Error::closed()
            };
            shared.fail(error.clone());
            if event == sys::CLOSED {
                notify(&shared.observer, Event::StreamClosed { id, reason: error });
            } else {
                let operation = match event {
                    sys::CONNECTED => Operation::Connect,
                    sys::READ => Operation::Read,
                    _ => Operation::Write,
                };
                notify(
                    &shared.observer,
                    Event::StreamError {
                        id,
                        operation,
                        error,
                    },
                );
            }
            return;
        }
        let mut state = lock(&shared.state);
        if state.terminal.is_some() {
            return;
        }
        let mut handshake = None;
        let mut connected = false;
        let mut read = None;
        let mut write = None;
        let mut dispatch = None;
        match event {
            sys::CONNECTED => {
                state.connected = true;
                connected = true;
                handshake = state.handshake_waker.take();
                read = state.read_waker.take();
                write = state.write_waker.take();
            }
            sys::READ_DEADLINE => read = state.read_waker.take(),
            sys::WRITE_DEADLINE => write = state.write_waker.take(),
            sys::READ => {
                state.read_pending = false;
                if result == 0 {
                    state.eof = true;
                } else {
                    assert_eq!(length, result as usize);
                    let buffer = buffer.take().expect("native read owner missing");
                    assert!(length <= buffer.capacity && state.read_data.is_none());
                    state.read_data = Some(ReadChunk {
                        buffer,
                        length,
                        offset: 0,
                    });
                }
                read = state.read_waker.take();
            }
            sys::WRITTEN => {
                state.write_pending = false;
                state.recycle(buffer.take());
                if let Some(batch) = state.write_queued.take() {
                    state.write_pending = true;
                    dispatch = Some(batch);
                }
                // Capacity waiters can append behind the newly dispatched batch;
                // flush waiters wake only once ALL acknowledged bytes are sent.
                if !state.write_pending || !state.write_wait_flush {
                    write = state.write_waker.take();
                }
            }
            _ => return,
        }
        drop(state);
        if connected {
            notify(&shared.observer, Event::StreamConnected { id });
        }
        if let Some(waker) = handshake {
            waker.wake();
        }
        if let Some(batch) = dispatch {
            shared.dispatch(id, batch);
        }
        if let Some(waker) = read {
            waker.wake();
        }
        if let Some(waker) = write {
            waker.wake();
        }
    }));
    if outcome.is_err() {
        std::process::abort();
    }
}

#[cfg(test)]
mod wake_tests {
    use super::*;
    use std::{
        sync::atomic::AtomicUsize,
        task::{Wake, Waker},
    };

    struct Count(AtomicUsize);
    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn completions_only_wake_the_matching_direction() {
        let shared = Arc::new(Shared {
            state: Mutex::new(State::new()),
            inner: std::sync::Weak::new(),
            observer: None,
        });
        let read = Arc::new(Count(AtomicUsize::new(0)));
        let write = Arc::new(Count(AtomicUsize::new(0)));
        {
            let mut state = lock(&shared.state);
            state.read_pending = true;
            state.write_pending = true;
            state.read_waker = Some(Waker::from(read.clone()));
            state.write_waker = Some(Waker::from(write.clone()));
        }
        let context = Arc::into_raw(shared.clone()).cast_mut().cast();
        let mut batch = WriteBatch::new(None, 4096);
        batch.append(b"x");
        let data = batch.buffer.bytes(0, 1).as_ptr().cast_mut();
        // SAFETY: synthetic completion transfers the same ownership as native;
        // the final DESTROYED below balances the context Arc exactly once.
        unsafe {
            on_event(
                context,
                1,
                sys::READ,
                1,
                batch.buffer.into_raw(),
                data,
                1,
                4096,
            );
        }
        assert_eq!(read.0.load(Ordering::Relaxed), 1);
        assert_eq!(write.0.load(Ordering::Relaxed), 0);
        {
            let mut state = lock(&shared.state);
            state.read_waker = Some(Waker::from(read.clone()));
        }
        let mut batch = WriteBatch::new(None, 4096);
        batch.append(b"y");
        let data = batch.buffer.bytes(0, 1).as_ptr().cast_mut();
        unsafe {
            on_event(
                context,
                1,
                sys::WRITTEN,
                1,
                batch.buffer.into_raw(),
                data,
                1,
                4096,
            );
        }
        assert_eq!(read.0.load(Ordering::Relaxed), 1);
        assert_eq!(write.0.load(Ordering::Relaxed), 1);
        unsafe {
            on_event(
                context,
                1,
                sys::DESTROYED,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
                0,
            );
        }
    }
}
