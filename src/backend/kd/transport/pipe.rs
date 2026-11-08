//! The KD serial transport on Windows: one duplex named pipe.
//!
//! QEMU's `-chardev pipe` creates `\\.\pipe\<name>` with a single client
//! slot and blocks in `ConnectNamedPipe` until the debugger opens it, so the
//! pipe is the Windows counterpart of the Unix socket KDCOM uses elsewhere.
//!
//! The stream is built on `windows-sys` rather than `std::fs::File` because
//! KD framing polls with 1 ms to 8 s read timeouts, and a file handle offers
//! none. Every transfer is overlapped: an event per call, waited on with the
//! configured timeout, and cancelled when it fires.

use std::io::{self, ErrorKind, Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_BROKEN_PIPE, ERROR_IO_PENDING, ERROR_OPERATION_ABORTED,
    ERROR_PIPE_NOT_CONNECTED, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
    WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, ReadFile, WriteFile,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Threading::{CreateEventW, INFINITE, WaitForSingleObject};

/// No share mode: a KD pipe belongs to the one debugger QEMU let in.
const EXCLUSIVE: u32 = 0;

pub struct PipeStream {
    inner: Arc<PipeInner>,
}

struct PipeInner {
    handle: HANDLE,
    read_timeout: Mutex<Option<Duration>>,
}

// SAFETY: a duplex pipe handle serves one reader and one writer at a time,
// which is how KD uses it (the pump thread reads, the owner writes), and the
// timeout is behind a mutex.
unsafe impl Send for PipeInner {}
// SAFETY: as above.
unsafe impl Sync for PipeInner {}

impl Drop for PipeInner {
    fn drop(&mut self) {
        // SAFETY: the handle came from `CreateFileW` or `CreateNamedPipeW`
        // and is closed exactly once, here.
        unsafe { CloseHandle(self.handle) };
    }
}

/// `endpoint` as a full pipe path: one that already names a pipe is kept, a
/// bare name is taken relative to `\\.\pipe\`.
pub fn pipe_path(endpoint: &str) -> String {
    if endpoint.starts_with(r"\\") {
        endpoint.to_string()
    } else {
        format!(r"\\.\pipe\{endpoint}")
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

impl PipeStream {
    /// Open the other end of the pipe the target created and waits on.
    pub fn open(endpoint: &str) -> io::Result<Self> {
        let name = wide(&pipe_path(endpoint));
        // SAFETY: `name` is NUL-terminated and outlives the call; the default
        // security descriptor and no template file are what a client wants.
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                EXCLUSIVE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(Self::from_handle(handle))
    }

    fn from_handle(handle: HANDLE) -> Self {
        Self {
            inner: Arc::new(PipeInner {
                handle,
                read_timeout: Mutex::new(None),
            }),
        }
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            inner: Arc::clone(&self.inner),
        })
    }

    /// Set how long a read waits, `None` for no limit. A read that times out
    /// with nothing to show fails with [`ErrorKind::WouldBlock`].
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        *self
            .inner
            .read_timeout
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = timeout;
        Ok(())
    }

    fn read_timeout(&self) -> Option<Duration> {
        *self
            .inner
            .read_timeout
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Abandon a read whose timeout fired. A transfer that completed as the
    /// timeout arrived still yields its bytes.
    fn cancel(&self, overlapped: &OVERLAPPED) -> io::Result<usize> {
        let mut count = 0u32;
        // SAFETY: `overlapped` names the pending read on this handle, and it
        // outlives both calls.
        unsafe {
            CancelIoEx(self.inner.handle, overlapped);
            if GetOverlappedResult(self.inner.handle, overlapped, &mut count, 1) != 0 {
                return Ok(count as usize);
            }
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_OPERATION_ABORTED as i32) {
            return Err(io::Error::from(ErrorKind::WouldBlock));
        }
        read_outcome(error)
    }
}

/// A read error as the stream semantics KD expects: the end of the stream
/// for a closed or disconnected pipe, `WouldBlock` for a cancelled transfer.
fn read_outcome(error: io::Error) -> io::Result<usize> {
    match raw_code(&error) {
        Some(ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED) => Ok(0),
        Some(ERROR_OPERATION_ABORTED) => Err(io::Error::from(ErrorKind::WouldBlock)),
        _ => Err(error),
    }
}

fn write_error(error: io::Error) -> io::Error {
    match raw_code(&error) {
        Some(ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED) => {
            io::Error::from(ErrorKind::BrokenPipe)
        }
        Some(ERROR_OPERATION_ABORTED) => io::Error::from(ErrorKind::WouldBlock),
        _ => error,
    }
}

fn raw_code(error: &io::Error) -> Option<u32> {
    error.raw_os_error().map(|code| code as u32)
}

fn is_pending(error: &io::Error) -> bool {
    error.raw_os_error() == Some(ERROR_IO_PENDING as i32)
}

/// `len` as the `u32` a Win32 transfer takes, or `None` for nothing to move.
fn byte_count(len: usize) -> Option<u32> {
    (len != 0).then(|| len.min(u32::MAX as usize) as u32)
}

/// The bytes a completed overlapped operation moved.
fn transferred(handle: HANDLE, overlapped: &OVERLAPPED) -> io::Result<usize> {
    let mut count = 0u32;
    // SAFETY: `overlapped` names an operation on `handle` whose event is
    // signalled, so no wait is needed.
    if unsafe { GetOverlappedResult(handle, overlapped, &mut count, 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(count as usize)
}

/// An event handle, closed when it drops.
struct Event(HANDLE);

impl Event {
    fn new() -> io::Result<Self> {
        // SAFETY: a manual-reset, initially unsignalled, unnamed event.
        let handle = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(handle))
    }
}

impl Drop for Event {
    fn drop(&mut self) {
        // SAFETY: the handle came from `CreateEventW` and is closed once.
        unsafe { CloseHandle(self.0) };
    }
}

impl Read for PipeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some(request) = byte_count(buf.len()) else {
            return Ok(0);
        };
        let event = Event::new()?;
        let mut overlapped = OVERLAPPED {
            hEvent: event.0,
            ..Default::default()
        };
        let mut read = 0u32;
        // SAFETY: `buf` is writable for `request` bytes, and both the
        // `OVERLAPPED` and the event outlive every wait below.
        let started = unsafe {
            ReadFile(
                self.inner.handle,
                buf.as_mut_ptr(),
                request,
                &mut read,
                &mut overlapped,
            )
        };
        if started != 0 {
            return Ok(read as usize);
        }
        let error = io::Error::last_os_error();
        if !is_pending(&error) {
            return read_outcome(error);
        }
        let wait = match self.read_timeout() {
            None => INFINITE,
            // A zero timeout is a poll: the shortest wait a pipe takes.
            Some(timeout) => (timeout.as_millis().min(u128::from(u32::MAX - 1)) as u32).max(1),
        };
        // SAFETY: the event is valid until `event` drops.
        let status = unsafe { WaitForSingleObject(event.0, wait) };
        if status == WAIT_TIMEOUT {
            return self.cancel(&overlapped);
        }
        if status == WAIT_FAILED {
            return Err(io::Error::last_os_error());
        }
        debug_assert_eq!(status, WAIT_OBJECT_0);
        transferred(self.inner.handle, &overlapped).or_else(read_outcome)
    }
}

impl Write for PipeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let Some(request) = byte_count(buf.len()) else {
            return Ok(0);
        };
        let event = Event::new()?;
        let mut overlapped = OVERLAPPED {
            hEvent: event.0,
            ..Default::default()
        };
        let mut written = 0u32;
        // SAFETY: `buf` is readable for `request` bytes, and both the
        // `OVERLAPPED` and the event outlive the wait below.
        let started = unsafe {
            WriteFile(
                self.inner.handle,
                buf.as_ptr(),
                request,
                &mut written,
                &mut overlapped,
            )
        };
        if started != 0 {
            return Ok(written as usize);
        }
        let error = io::Error::last_os_error();
        if !is_pending(&error) {
            return Err(write_error(error));
        }
        // A write waits for room in the pipe: KD framing never times one out.
        // SAFETY: the event is valid until `event` drops.
        let status = unsafe { WaitForSingleObject(event.0, INFINITE) };
        if status == WAIT_FAILED {
            return Err(io::Error::last_os_error());
        }
        transferred(self.inner.handle, &overlapped).map_err(write_error)
    }

    fn flush(&mut self) -> io::Result<()> {
        // KD reads whole frames as they arrive; a pipe needs no flush.
        Ok(())
    }
}

/// Two connected ends of a private pipe, as `UnixStream::pair` gives on Unix.
#[cfg(test)]
pub fn pair() -> io::Result<(PipeStream, PipeStream)> {
    use std::sync::atomic::{AtomicU64, Ordering};

    use windows_sys::Win32::Foundation::ERROR_PIPE_CONNECTED;
    use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
    };

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let name = format!(
        r"\\.\pipe\ntoseye-kd-test-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    let wide_name = wide(&name);
    // SAFETY: `wide_name` is NUL-terminated and outlives the call; one
    // duplex byte-mode instance with nothing special about its security.
    let handle = unsafe {
        CreateNamedPipeW(
            wide_name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            65536,
            65536,
            0,
            std::ptr::null(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let server = PipeStream::from_handle(handle);
    let event = Event::new()?;
    let mut overlapped = OVERLAPPED {
        hEvent: event.0,
        ..Default::default()
    };
    // SAFETY: `overlapped` outlives the wait below.
    let connected = unsafe { ConnectNamedPipe(server.inner.handle, &mut overlapped) };
    if connected == 0 {
        let error = io::Error::last_os_error();
        // A client that connects between the two calls leaves the wait
        // satisfied, which is success, not failure.
        if !is_pending(&error) && error.raw_os_error() != Some(ERROR_PIPE_CONNECTED as i32) {
            return Err(error);
        }
    }
    let client = PipeStream::open(&name)?;
    let mut count = 0u32;
    // SAFETY: the same connection request, satisfied by `client` above.
    if unsafe { GetOverlappedResult(server.inner.handle, &overlapped, &mut count, 1) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((server, client))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_written_on_one_end_are_read_on_the_other() {
        let (mut server, mut client) = pair().unwrap();
        server.write_all(b"kd").unwrap();
        let mut read = [0u8; 2];
        client.read_exact(&mut read).unwrap();
        assert_eq!(&read, b"kd");

        client.write_all(b"ack").unwrap();
        let mut back = [0u8; 3];
        server.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"ack");
    }

    #[test]
    fn a_read_timeout_with_no_data_is_would_block() {
        let (mut server, mut client) = pair().unwrap();
        server
            .set_read_timeout(Some(Duration::from_millis(10)))
            .unwrap();
        let error = server.read(&mut [0u8; 1]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::WouldBlock);

        // The timeout cancelled one transfer, not the pipe.
        client.write_all(b"x").unwrap();
        let mut read = [0u8; 1];
        assert_eq!(server.read(&mut read).unwrap(), 1);
        assert_eq!(&read, b"x");
    }

    #[test]
    fn a_read_after_the_peer_closes_the_pipe_is_end_of_stream() {
        let (mut server, client) = pair().unwrap();
        drop(client);
        server
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        assert_eq!(server.read(&mut [0u8; 1]).unwrap(), 0);
        assert_eq!(server.read(&mut [0u8; 1]).unwrap(), 0);
    }

    #[test]
    fn a_bare_name_is_taken_relative_to_the_pipe_namespace() {
        assert_eq!(pipe_path("ntoseye-kd"), r"\\.\pipe\ntoseye-kd");
        assert_eq!(pipe_path(r"\\.\pipe\ntoseye-kd"), r"\\.\pipe\ntoseye-kd");
    }
}
