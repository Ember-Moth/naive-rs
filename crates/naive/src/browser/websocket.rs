use super::{BrowserClient, Headers, valid_token, valid_url, validate_headers};
use crate::{
    Error,
    client::{Inner, lock},
};
use serde::Deserialize;
use std::{
    ffi::{CString, c_void},
    future::poll_fn,
    sync::{Arc, Mutex},
    task::{Poll, Waker},
};

#[derive(Clone, Debug)]
pub struct WebSocketRequest {
    pub url: String,
    /// Explicit document origin for the native handshake (HTTP or HTTPS).
    pub origin: String,
    pub protocols: Vec<String>,
    pub headers: Headers,
}
impl WebSocketRequest {
    pub fn new(url: impl Into<String>, origin: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            origin: origin.into(),
            protocols: Vec::new(),
            headers: Vec::new(),
        }
    }
    fn json(&self) -> Result<CString, Error> {
        if !valid_url(&self.url, &["ws://", "wss://"])
            || !valid_url(&self.origin, &["http://", "https://"])
            || self.protocols.len() > 64
            || self.protocols.iter().any(|p| !valid_token(p))
        {
            return Err(Error::invalid(
                "invalid WebSocket URL, origin or subprotocol",
            ));
        }
        let mut protocols = self.protocols.clone();
        protocols.sort();
        protocols.dedup();
        if protocols.len() != self.protocols.len() {
            return Err(Error::invalid("duplicate WebSocket subprotocol"));
        }
        validate_headers(&self.headers)?;
        CString::new(serde_json::json!({"url":self.url,"origin":self.origin,"protocols":self.protocols,"headers":self.headers}).to_string())
            .map_err(|_|Error::invalid("invalid WebSocket JSON"))
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct WebSocketHandshake {
    pub url: String,
    pub status: u16,
    pub headers: Headers,
    pub subprotocol: String,
    pub extensions: String,
    pub remote_address: String,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Message {
    Text(String),
    Binary(Vec<u8>),
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct CloseFrame {
    pub clean: bool,
    pub code: u16,
    pub reason: String,
}

#[derive(Default)]
struct State {
    handshake: Option<WebSocketHandshake>,
    message: Option<Message>,
    receiving: bool,
    sending: bool,
    sent: bool,
    closing: bool,
    close: Option<CloseFrame>,
    error: Option<Error>,
    destroyed: bool,
    open_waker: Option<Waker>,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    close_waker: Option<Waker>,
}
struct Shared {
    state: Mutex<State>,
    max_message: usize,
}
impl Shared {
    fn fail(&self, error: Error) {
        let mut state = lock(&self.state);
        if state.error.is_none() {
            state.error = Some(error);
        }
        let wakes = [
            state.open_waker.take(),
            state.read_waker.take(),
            state.write_waker.take(),
            state.close_waker.take(),
        ];
        drop(state);
        for waker in wakes.into_iter().flatten() {
            waker.wake();
        }
    }
}
struct Owner {
    inner: Arc<Inner>,
    shared: Arc<Shared>,
    id: u64,
}
impl Drop for Owner {
    fn drop(&mut self) {
        self.inner.cancel(self.id);
    }
}

/// A native Chromium WebSocket. Control frames and UTF-8 validation are handled
/// natively. Poll `recv` to process peer messages/ping/close traffic.
pub struct WebSocket {
    owner: Arc<Owner>,
    handshake: WebSocketHandshake,
}
pub struct WebSocketReadHalf {
    owner: Arc<Owner>,
}
pub struct WebSocketWriteHalf {
    owner: Arc<Owner>,
}
impl WebSocket {
    pub fn handshake(&self) -> &WebSocketHandshake {
        &self.handshake
    }
    pub fn close_frame(&self) -> Option<CloseFrame> {
        lock(&self.owner.shared.state).close.clone()
    }
    pub async fn recv(&mut self) -> Result<Option<Message>, Error> {
        receive(&self.owner).await
    }
    /// Completion means passed to the native transport, not acknowledged by the
    /// peer. Canceling a submitted send aborts the channel, avoiding replay.
    pub async fn send(&mut self, message: Message) -> Result<(), Error> {
        send(&self.owner, message).await
    }
    /// Cancelling this wait does not undo a close already sent. Calling again
    /// observes the same handshake. Unread incoming messages may be discarded.
    pub async fn close(&mut self, code: u16, reason: &str) -> Result<CloseFrame, Error> {
        close(&self.owner, code, reason).await
    }
    pub fn abort(&self) {
        self.owner.shared.fail(Error::native(-3));
        self.owner.inner.cancel(self.owner.id);
    }
    pub fn into_split(self) -> (WebSocketReadHalf, WebSocketWriteHalf) {
        (
            WebSocketReadHalf {
                owner: self.owner.clone(),
            },
            WebSocketWriteHalf { owner: self.owner },
        )
    }
}
impl WebSocketReadHalf {
    pub async fn recv(&mut self) -> Result<Option<Message>, Error> {
        receive(&self.owner).await
    }
}
impl WebSocketWriteHalf {
    pub async fn send(&mut self, message: Message) -> Result<(), Error> {
        send(&self.owner, message).await
    }
    pub async fn close(&mut self, code: u16, reason: &str) -> Result<CloseFrame, Error> {
        close(&self.owner, code, reason).await
    }
    pub fn abort(&self) {
        self.owner.shared.fail(Error::native(-3));
        self.owner.inner.cancel(self.owner.id);
    }
}

pub(super) async fn connect(
    client: &BrowserClient,
    request: WebSocketRequest,
) -> Result<WebSocket, Error> {
    let json = request.json()?;
    let shared = Arc::new(Shared {
        state: Mutex::new(State::default()),
        max_message: client.max_message,
    });
    let owner = Arc::new(Owner {
        inner: client.transport.inner.clone(),
        id: client.transport.inner.next_id()?,
        shared: shared.clone(),
    });
    {
        let context = Arc::into_raw(shared.clone());
        if let Err(error) = owner.inner.submit(|engine| unsafe {
            naive_sys::naive_browser_websocket(
                engine,
                owner.id,
                json.as_ptr(),
                on_event,
                context.cast_mut().cast(),
            );
        }) {
            // SAFETY: native was not called and did not take this context.
            unsafe {
                drop(Arc::from_raw(context));
            }
            return Err(error);
        }
    }
    let handshake = poll_fn(|cx| {
        let mut state = lock(&shared.state);
        if let Some(error) = &state.error {
            return Poll::Ready(Err(error.clone()));
        }
        if let Some(handshake) = &state.handshake {
            return Poll::Ready(Ok(handshake.clone()));
        }
        if state.destroyed || state.close.is_some() {
            return Poll::Ready(Err(Error::closed()));
        }
        state.open_waker = Some(cx.waker().clone());
        Poll::Pending
    })
    .await?;
    Ok(WebSocket { owner, handshake })
}

async fn receive(owner: &Arc<Owner>) -> Result<Option<Message>, Error> {
    poll_fn(|cx| {
        let mut state = lock(&owner.shared.state);
        if let Some(message) = state.message.take() {
            return Poll::Ready(Ok(Some(message)));
        }
        if let Some(error) = &state.error {
            return Poll::Ready(Err(error.clone()));
        }
        if state.close.is_some() || state.destroyed {
            return Poll::Ready(Ok(None));
        }
        state.read_waker = Some(cx.waker().clone());
        if !state.receiving {
            state.receiving = true;
            // Native only posts work, so no callback runs under this lock.
            if let Err(error) = owner
                .inner
                .submit(|e| unsafe { naive_sys::naive_browser_ws_receive(e, owner.id) })
            {
                state.receiving = false;
                return Poll::Ready(Err(error));
            }
        }
        Poll::Pending
    })
    .await
}

struct SendGuard {
    owner: Arc<Owner>,
    armed: bool,
}
impl Drop for SendGuard {
    fn drop(&mut self) {
        if self.armed {
            self.owner.shared.fail(Error::native(-3));
            self.owner.inner.cancel(self.owner.id);
        }
    }
}
async fn send(owner: &Arc<Owner>, message: Message) -> Result<(), Error> {
    let (text, data) = match message {
        Message::Text(s) => (true, s.into_bytes()),
        Message::Binary(b) => (false, b),
    };
    if data.len() > owner.shared.max_message {
        return Err(Error::invalid("WebSocket message limit exceeded"));
    }
    {
        let mut state = lock(&owner.shared.state);
        if let Some(error) = &state.error {
            return Err(error.clone());
        }
        if state.closing || state.close.is_some() || state.destroyed {
            return Err(Error::closed());
        }
        if state.sending {
            return Err(Error::invalid("WebSocket send already pending"));
        }
        state.sending = true;
        state.sent = false;
    }
    let mut guard = SendGuard {
        owner: owner.clone(),
        armed: true,
    };
    if let Err(error) = owner.inner.submit(|engine| unsafe {
        naive_sys::naive_browser_ws_send(
            engine,
            owner.id,
            i32::from(text),
            data.as_ptr(),
            data.len(),
        );
    }) {
        guard.armed = false;
        owner.shared.fail(error.clone());
        return Err(error);
    }
    let result = poll_fn(|cx| {
        let mut state = lock(&owner.shared.state);
        if let Some(error) = &state.error {
            return Poll::Ready(Err(error.clone()));
        }
        if state.sent {
            state.sent = false;
            return Poll::Ready(Ok(()));
        }
        if state.close.is_some() || state.destroyed {
            return Poll::Ready(Err(Error::closed()));
        }
        state.write_waker = Some(cx.waker().clone());
        Poll::Pending
    })
    .await;
    guard.armed = false;
    result
}

async fn close(owner: &Arc<Owner>, code: u16, reason: &str) -> Result<CloseFrame, Error> {
    if !(code == 1000 || (3000..=4999).contains(&code)) || reason.len() > 123 {
        return Err(Error::invalid(
            "WebSocket close requires code 1000 or 3000..=4999 and <=123 UTF-8 bytes",
        ));
    }
    poll_fn(|cx| {
        let mut state = lock(&owner.shared.state);
        if let Some(frame) = &state.close {
            return Poll::Ready(Ok(frame.clone()));
        }
        if let Some(error) = &state.error {
            return Poll::Ready(Err(error.clone()));
        }
        if state.destroyed {
            return Poll::Ready(Err(Error::closed()));
        }
        if state.sending {
            return Poll::Ready(Err(Error::invalid(
                "finish the WebSocket send before closing",
            )));
        }
        state.close_waker = Some(cx.waker().clone());
        if !state.closing {
            state.closing = true;
            if let Err(error) = owner.inner.submit(|e| unsafe {
                naive_sys::naive_browser_ws_close(e, owner.id, code, reason.as_ptr(), reason.len())
            }) {
                return Poll::Ready(Err(error));
            }
        }
        Poll::Pending
    })
    .await
}

unsafe extern "C" fn on_event(
    context: *mut c_void,
    _id: u64,
    event: i32,
    code: i32,
    data: *const u8,
    len: usize,
) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: native retains one strong reference through final DESTROYED.
        let shared = unsafe { &*context.cast::<Shared>() };
        let mut state = lock(&shared.state);
        let bytes = if len == 0 {
            &[][..]
        } else {
            assert!(!data.is_null());
            // SAFETY: payload is borrowed for this callback; copy/parse before returning.
            unsafe { std::slice::from_raw_parts(data, len) }
        };
        match event {
            naive_sys::WS_OPEN => match serde_json::from_slice(bytes) {
                Ok(value) => state.handshake = Some(value),
                Err(_) => {
                    state.error = Some(Error::runtime(
                        "invalid native WebSocket handshake metadata".into(),
                    ))
                }
            },
            naive_sys::WS_MESSAGE => {
                state.receiving = false;
                if len > shared.max_message || state.message.is_some() {
                    state.error =
                        Some(Error::runtime("WebSocket receive boundary exceeded".into()));
                } else {
                    state.message = Some(if code == 1 {
                        Message::Text(
                            String::from_utf8(bytes.to_vec()).expect("native UTF-8 validation"),
                        )
                    } else {
                        Message::Binary(bytes.to_vec())
                    });
                }
            }
            naive_sys::WS_SENT => {
                state.sending = false;
                state.sent = true;
            }
            naive_sys::WS_CLOSED => match serde_json::from_slice::<CloseFrame>(bytes) {
                Ok(frame) => {
                    if !frame.clean && state.error.is_none() {
                        state.error = Some(Error::native(-100));
                    }
                    state.close = Some(frame);
                }
                Err(_) => {
                    state.error = Some(Error::runtime(
                        "invalid native WebSocket close metadata".into(),
                    ))
                }
            },
            naive_sys::WS_ERROR => {
                if state.error.is_none() {
                    state.error = Some(Error::native(if code < 0 { code } else { -145 }));
                }
            }
            naive_sys::WS_DESTROYED => {
                state.destroyed = true;
            }
            _ => state.error = Some(Error::runtime("unknown native WebSocket event".into())),
        }
        let wakes = [
            state.open_waker.take(),
            state.read_waker.take(),
            state.write_waker.take(),
            state.close_waker.take(),
        ];
        drop(state);
        for waker in wakes.into_iter().flatten() {
            waker.wake();
        }
        if event == naive_sys::WS_DESTROYED {
            // SAFETY: exactly the reference handed to native at connect.
            unsafe {
                drop(Arc::from_raw(context.cast::<Shared>()));
            }
        }
    }));
    if result.is_err() {
        std::process::abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn handshake_inputs_are_validated_before_native_submission() {
        let mut request = WebSocketRequest::new("wss://example.com/", "https://example.com");
        assert!(request.json().is_ok());
        request.protocols = vec!["echo".into(), "echo".into()];
        assert!(request.json().is_err());
        request.protocols.clear();
        request
            .headers
            .push(("authorization".into(), "token\r\nx: y".into()));
        assert!(request.json().is_err());
    }
}
