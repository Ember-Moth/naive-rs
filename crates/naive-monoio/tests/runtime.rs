#![cfg(unix)]
use monoio::{
    buf::{IoBuf, IoBufMut},
    io::{AsyncReadRent, AsyncWriteRent},
};
use naive::{Config, NaiveClient};
use naive_monoio::Stream;
use std::{
    cell::Cell,
    io::{Read, Write},
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
// SAFETY: owned Vec storage stays stable while the adapter holds this value.
unsafe impl IoBuf for LocalBuffer {
    fn read_ptr(&self) -> *const u8 {
        self.bytes.as_ptr()
    }
    fn bytes_init(&self) -> usize {
        self.bytes.len()
    }
}
unsafe impl IoBufMut for LocalBuffer {
    fn write_ptr(&mut self) -> *mut u8 {
        self.bytes.as_mut_ptr()
    }
    fn bytes_total(&mut self) -> usize {
        self.bytes.capacity()
    }
    unsafe fn set_init(&mut self, n: usize) {
        unsafe {
            self.bytes.set_len(n);
        }
        self.marker.set(n);
    }
}
#[test]
fn monoio_local_buffers_and_native_completions() {
    let (port, server) = server();
    let mut runtime = monoio::RuntimeBuilder::<monoio::LegacyDriver>::new()
        .build()
        .unwrap();
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
            .await;
        assert_eq!(result.unwrap(), 1);
        stream.flush().await.unwrap();
        let (result, received) = stream
            .read(LocalBuffer {
                bytes: Vec::with_capacity(16),
                marker: marker.clone(),
            })
            .await;
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
