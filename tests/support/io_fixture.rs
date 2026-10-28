//! Bounded loopback fixtures shared by the core and completion-adapter tests.
#![allow(dead_code)]

use std::{
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle, ThreadId},
    time::{Duration, Instant},
};

pub const WAIT: Duration = Duration::from_secs(5);

pub struct Server {
    pub port: u16,
    stop: Arc<AtomicBool>,
    socket: Arc<Mutex<Option<TcpStream>>>,
    task: Option<JoinHandle<()>>,
}

impl Server {
    fn spawn(proxy: bool, body: impl FnOnce(&mut TcpStream) + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let socket = Arc::new(Mutex::new(None::<TcpStream>));
        let stopped = stop.clone();
        let active = socket.clone();
        let task = thread::spawn(move || {
            let deadline = Instant::now() + WAIT;
            let mut stream = loop {
                if stopped.load(Ordering::Relaxed) {
                    return;
                }
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "fixture accept timed out");
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("fixture accept: {error}"),
                }
            };
            // BSD/macOS may inherit O_NONBLOCK from the listening socket.
            stream.set_nonblocking(false).unwrap();
            stream.set_read_timeout(Some(WAIT)).unwrap();
            stream.set_write_timeout(Some(WAIT)).unwrap();
            *active.lock().unwrap() = Some(stream.try_clone().unwrap());
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if proxy {
                    let mut header = Vec::new();
                    while !header.ends_with(b"\r\n\r\n") {
                        assert!(header.len() < 16 * 1024, "oversized CONNECT header");
                        let mut byte = [0];
                        stream.read_exact(&mut byte).unwrap();
                        header.push(byte[0]);
                    }
                    assert!(header.starts_with(b"CONNECT "));
                    stream
                        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .unwrap();
                }
                body(&mut stream);
            }));
            active.lock().unwrap().take();
            drop(stream);
            if let Err(error) = result {
                std::panic::resume_unwind(error);
            }
        });
        Self {
            port,
            stop,
            socket,
            task: Some(task),
        }
    }

    pub fn proxy(body: impl FnOnce(&mut TcpStream) + Send + 'static) -> Self {
        Self::spawn(true, body)
    }

    pub fn origin(body: impl FnOnce(&mut TcpStream) + Send + 'static) -> Self {
        Self::spawn(false, body)
    }

    pub fn echo() -> Self {
        Self::proxy(|stream| {
            let mut bytes = [0; 8192];
            while let Ok(n) = stream.read(&mut bytes) {
                if n == 0 || stream.write_all(&bytes[..n]).is_err() {
                    break;
                }
            }
        })
    }

    pub fn finish(mut self) {
        self.task.take().unwrap().join().unwrap();
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(socket) = self.socket.lock().unwrap().take() {
            let _ = socket.shutdown(Shutdown::Both);
        }
        if let Some(task) = self.task.take() {
            let _ = task.join();
        }
    }
}

#[derive(Clone, Default)]
pub struct Releases(Arc<ReleaseState>);

#[derive(Default)]
struct ReleaseState {
    threads: Mutex<Vec<ThreadId>>,
    changed: Condvar,
}

impl Releases {
    pub fn guard(&self) -> ReleaseGuard {
        ReleaseGuard(self.clone())
    }
    pub fn count(&self) -> usize {
        self.0.threads.lock().unwrap().len()
    }
    pub fn threads(&self) -> Vec<ThreadId> {
        self.0.threads.lock().unwrap().clone()
    }
    pub fn wait_for(&self, count: usize) {
        let deadline = Instant::now() + WAIT;
        let mut released = self.0.threads.lock().unwrap();
        while released.len() < count {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "buffer was not released");
            released = self.0.changed.wait_timeout(released, remaining).unwrap().0;
        }
        assert_eq!(released.len(), count, "buffer released more than once");
    }
}

pub struct ReleaseGuard(Releases);
impl Drop for ReleaseGuard {
    fn drop(&mut self) {
        let state = &self.0.0;
        state.threads.lock().unwrap().push(thread::current().id());
        state.changed.notify_all();
    }
}

pub struct Buffer {
    pub bytes: Vec<u8>,
    pub guard: ReleaseGuard,
}

pub fn proxy_config(port: u16) -> naive::Config {
    let mut config = naive::Config::new(format!("http://127.0.0.1:{port}"));
    config.connect_timeout = WAIT;
    config
}

pub fn tls_config(scheme: &str) -> naive::Config {
    let port = std::env::var("NAIVE_TEST_PROXY_PORT").expect("run tests/interop.py");
    let mut config = naive::Config::new(format!("{scheme}://test:test@localhost:{port}"));
    config.host_resolver_rules = Some("MAP localhost 127.0.0.1".into());
    config.extra_root_certificates = Some(std::env::var("NAIVE_TEST_CA_PEM").unwrap());
    config.connect_timeout = WAIT;
    config
}
