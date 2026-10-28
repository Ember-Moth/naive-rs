use std::{ffi::CStr, fmt, io};

/// Native errors retain their negative Chromium net error code.
#[derive(Debug, Clone)]
pub struct Error {
    code: Option<i32>,
    kind: io::ErrorKind,
    message: String,
}

impl Error {
    pub fn code(&self) -> Option<i32> {
        self.code
    }
    pub fn kind(&self) -> io::ErrorKind {
        self.kind
    }
    pub(crate) fn native(code: i32) -> Self {
        // SAFETY: Chromium returns a constant string, including for unknown codes.
        let name = unsafe { CStr::from_ptr(naive_sys::naive_error_name(code)) }
            .to_string_lossy()
            .into_owned();
        let kind = match code {
            // Chromium ERR_ABORTED terminates this operation/stream. Interrupted
            // means a retryable OS signal to read_exact/write_all and can spin
            // forever once the stream is permanently canceled.
            -3 => io::ErrorKind::ConnectionAborted,
            -10 => io::ErrorKind::PermissionDenied,
            -4 => io::ErrorKind::InvalidInput,
            -7 | -118 => io::ErrorKind::TimedOut,
            -100 => io::ErrorKind::UnexpectedEof,
            -21 | -101 => io::ErrorKind::ConnectionReset,
            -102 => io::ErrorKind::ConnectionRefused,
            -15 | -26 => io::ErrorKind::NotConnected,
            -105 => io::ErrorKind::NotFound,
            _ => io::ErrorKind::Other,
        };
        Self {
            code: Some(code),
            kind,
            message: name,
        }
    }
    pub(crate) fn invalid(message: &str) -> Self {
        Self {
            code: None,
            kind: io::ErrorKind::InvalidInput,
            message: message.into(),
        }
    }
    pub(crate) fn closed() -> Self {
        Self {
            code: None,
            kind: io::ErrorKind::NotConnected,
            message: "Naive client or stream is closed".into(),
        }
    }
    pub(crate) fn runtime(message: String) -> Self {
        Self {
            code: None,
            kind: io::ErrorKind::Other,
            message,
        }
    }
    pub(crate) fn io(&self) -> io::Error {
        io::Error::new(self.kind, self.clone())
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for Error {}
