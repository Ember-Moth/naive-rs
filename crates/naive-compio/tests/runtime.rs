use compio_buf::{IoBuf, IoBufMut, SetLen};
use compio_io::{AsyncRead, AsyncWrite};
use naive::{Config, NaiveClient};
use naive_compio::Stream;
use std::{
    cell::Cell,
    io::{Read, Write},
    mem::MaybeUninit,
    net::TcpListener,
    rc::Rc,
    time::Duration,
};

fn server() -> (u16, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            socket.read_exact(&mut byte).unwrap();
            header.push(byte[0]);
        }
        socket
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .unwrap();
        let mut byte = [0];
        while socket.read_exact(&mut byte).is_ok() {
            socket.write_all(&byte).unwrap();
        }
    });
    (port, task)
}
struct LocalBuffer {
    bytes: Vec<u8>,
    marker: Rc<Cell<usize>>,
}
impl IoBuf for LocalBuffer {
    fn as_init(&self) -> &[u8] {
        &self.bytes
    }
}
impl SetLen for LocalBuffer {
    unsafe fn set_len(&mut self, n: usize) {
        unsafe {
            self.bytes.set_len(n);
        }
        self.marker.set(n);
    }
}
impl IoBufMut for LocalBuffer {
    fn as_uninit(&mut self) -> &mut [MaybeUninit<u8>] {
        // SAFETY: this exclusive borrow spans the Vec's allocated capacity,
        // including its uninitialized tail, represented as MaybeUninit.
        unsafe {
            std::slice::from_raw_parts_mut(self.bytes.as_mut_ptr().cast(), self.bytes.capacity())
        }
    }
}
#[test]
fn compio_local_buffers_and_native_completions() {
    let (port, server) = server();
    let runtime = compio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let client = NaiveClient::new(Config::new(format!("http://127.0.0.1:{port}")))
            .await
            .unwrap();
        let mut stream = Stream::from(client.connect("remote.invalid", 443).await.unwrap());
        let marker = Rc::new(Cell::new(0));
        let (result, _) = stream
            .write(LocalBuffer {
                bytes: vec![42],
                marker: marker.clone(),
            })
            .await
            .into_parts();
        assert_eq!(result.unwrap(), 1);
        stream.flush().await.unwrap();
        let (result, received) = stream
            .read(LocalBuffer {
                bytes: Vec::with_capacity(16),
                marker: marker.clone(),
            })
            .await
            .into_parts();
        assert_eq!(result.unwrap(), 1);
        assert_eq!(received.bytes, [42]);
        assert_eq!(marker.get(), 1);
        let sent = stream.write_owned(vec![43]).await;
        assert_eq!(sent.result.unwrap(), 1);
        let received = stream.read_owned(Vec::with_capacity(16)).await;
        assert_eq!(received.result.unwrap(), 1);
        assert_eq!(received.buffer, [43]);
        let (mut reader, mut writer) = stream.into_split();
        let (read, write) = futures_util::join!(
            reader.read_owned(Vec::with_capacity(8)),
            writer.write_owned(vec![44])
        );
        assert_eq!(read.result.unwrap(), 1);
        assert_eq!(read.buffer, [44]);
        assert_eq!(write.result.unwrap(), 1);
        assert_eq!(
            writer.shutdown().await.unwrap_err().kind(),
            std::io::ErrorKind::Unsupported
        );
        client.shutdown().await.unwrap();
    });
    server.join().unwrap();
}
