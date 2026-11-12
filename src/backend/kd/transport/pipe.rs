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

use std::ffi::c_void;
use std::io::{self, ErrorKind, Read, Write};
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_BROKEN_PIPE, ERROR_FILE_NOT_FOUND, ERROR_IO_PENDING,
    ERROR_OPERATION_ABORTED, ERROR_PIPE_BUSY, ERROR_PIPE_NOT_CONNECTED, GENERIC_READ,
    GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, ReadFile, WriteFile,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Threading::{CreateEventW, INFINITE, WaitForSingleObject};

/// No share mode: a KD pipe belongs to the one debugger QEMU let in.
const EXCLUSIVE: u32 = 0;

/// How long a write may wait for room in the pipe before it is abandoned.
const WRITE_TIMEOUT_MS: u32 = 5_000;

/// How long a disconnected pipe waits for its server to be re-created, and how
/// often it looks. Hyper-V destroys and re-creates its COM pipe across a guest
/// restart; WinDbg's `reconnect` option exists for exactly this.
const RECONNECT_TIMEOUT: Duration = Duration::from_secs(120);
const RECONNECT_RETRY: Duration = Duration::from_millis(50);

pub struct PipeStream {
    inner: Arc<PipeInner>,
}

struct PipeInner {
    /// Swapped when the peer re-creates the pipe; I/O paths take a snapshot.
    handle: AtomicPtr<c_void>,
    /// The full `\\.\pipe\...` path to re-open, when reconnecting is allowed.
    endpoint: Option<String>,
    reconnect: bool,
    read_timeout: Mutex<Option<Duration>>,
    reconnect_lock: Mutex<()>,
}

// SAFETY: a duplex pipe handle serves one reader and one writer at a time,
// which is how KD uses it (the pump thread reads, the owner writes), and the
// timeout is behind a mutex.
unsafe impl Send for PipeInner {}
// SAFETY: as above.
unsafe impl Sync for PipeInner {}

impl Drop for PipeInner {
    fn drop(&mut self) {
        let handle = self.handle.load(Ordering::Relaxed);
        if !handle.is_null() {
            // SAFETY: the handle came from `CreateFileW`/`CreateNamedPipeW`
            // and is closed exactly once, here.
            unsafe { CloseHandle(handle) };
        }
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

/// One `CreateFileW` attempt at a full pipe path.
fn connect(path: &str) -> io::Result<HANDLE> {
    let name = wide(path);
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
    Ok(handle)
}

fn is_disconnect(error: &io::Error) -> bool {
    matches!(
        raw_code(error),
        Some(ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED)
    )
}

impl PipeStream {
    /// Open the other end of the pipe the target created and waits on.
    ///
    /// The endpoint is remembered: Hyper-V closes and re-creates the COM pipe
    /// across a guest restart, and this stream re-opens it instead of failing.
    pub fn open(endpoint: &str) -> io::Result<Self> {
        let path = pipe_path(endpoint);
        let handle = connect(&path)?;
        Ok(Self::from_parts(handle, Some(path), true))
    }

    #[cfg(test)]
    fn from_handle(handle: HANDLE) -> Self {
        Self::from_parts(handle, None, false)
    }

    fn from_parts(handle: HANDLE, endpoint: Option<String>, reconnect: bool) -> Self {
        Self {
            inner: Arc::new(PipeInner {
                handle: AtomicPtr::new(handle),
                endpoint,
                reconnect,
                read_timeout: Mutex::new(None),
                reconnect_lock: Mutex::new(()),
            }),
        }
    }

    fn current(&self) -> HANDLE {
        self.inner.handle.load(Ordering::Relaxed)
    }

    /// Re-open after a disconnect and report the operation as a timeout, so the
    /// caller retries it against the new handle.
    fn reconnect_outcome(&self, dead: HANDLE) -> io::Result<usize> {
        match self.reconnect(dead) {
            Ok(()) => Err(io::Error::from(ErrorKind::WouldBlock)),
            Err(error) => Err(error),
        }
    }

    /// Re-open the endpoint after the server end went away, waiting for the
    /// hypervisor to re-create it. The caller's operation is not retried here.
    fn reconnect(&self, dead: HANDLE) -> io::Result<()> {
        let _guard = self
            .inner
            .reconnect_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.current() != dead {
            return Ok(());
        }
        let Some(endpoint) = self.inner.endpoint.as_deref() else {
            return Err(io::Error::from(ErrorKind::BrokenPipe));
        };
        // SAFETY: the handle is ours; cancelling makes a waiting transfer fail
        // with `ERROR_OPERATION_ABORTED` before it is closed.
        unsafe {
            if !dead.is_null() {
                CancelIoEx(dead, std::ptr::null_mut());
                CloseHandle(dead);
            }
        }
        self.inner.handle.store(std::ptr::null_mut(), Ordering::Relaxed);
        kd_trace!("pipe: {endpoint} disconnected; waiting for it to come back");
        let deadline = Instant::now() + RECONNECT_TIMEOUT;
        loop {
            match connect(endpoint) {
                Ok(handle) => {
                    self.inner.handle.store(handle, Ordering::Relaxed);
                    kd_trace!("pipe: reconnected to {endpoint}");
                    return Ok(());
                }
                Err(error) => {
                    let retryable = matches!(
                        raw_code(&error),
                        Some(
                            ERROR_FILE_NOT_FOUND
                                | ERROR_PIPE_BUSY
                                | ERROR_PIPE_NOT_CONNECTED
                                | ERROR_BROKEN_PIPE
                        )
                    );
                    if !retryable || Instant::now() >= deadline {
                        return Err(error);
                    }
                    std::thread::sleep(RECONNECT_RETRY);
                }
            }
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
    fn cancel(&self, handle: HANDLE, overlapped: &OVERLAPPED) -> io::Result<usize> {
        let mut count = 0u32;
        // SAFETY: `overlapped` names the pending read on this handle, and it
        // outlives both calls.
        unsafe {
            CancelIoEx(handle, overlapped);
            if GetOverlappedResult(handle, overlapped, &mut count, 1) != 0 {
                return Ok(count as usize);
            }
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_OPERATION_ABORTED as i32) {
            return Err(io::Error::from(ErrorKind::WouldBlock));
        }
        if is_disconnect(&error) && self.inner.reconnect {
            return match self.reconnect(handle) {
                Ok(()) => Err(io::Error::from(ErrorKind::WouldBlock)),
                Err(error) => Err(error),
            };
        }
        kd_trace!("pipe: cancelled read failed: {error}");
        read_outcome(error)
    }
}

/// A read error as the stream semantics KD expects: the end of the stream
/// for a closed or disconnected pipe, `WouldBlock` for a cancelled transfer.
fn read_outcome(error: io::Error) -> io::Result<usize> {
    kd_trace!("pipe: read ended: {error}");
    match raw_code(&error) {
        Some(ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED) => Ok(0),
        Some(ERROR_OPERATION_ABORTED) => Err(io::Error::from(ErrorKind::WouldBlock)),
        _ => Err(error),
    }
}

fn write_error(error: io::Error) -> io::Error {
    kd_trace!("pipe: write failed: {error}");
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
        let handle = self.current();
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
                handle,
                buf.as_mut_ptr(),
                request,
                &mut read,
                &mut overlapped,
            )
        };
        if started != 0 {
            if read == 0 && self.inner.reconnect {
                return self.reconnect_outcome(handle);
            }
            return Ok(read as usize);
        }
        let error = io::Error::last_os_error();
        if !is_pending(&error) {
            if is_disconnect(&error) && self.inner.reconnect {
                return self.reconnect_outcome(handle);
            }
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
            return self.cancel(handle, &overlapped);
        }
        if status == WAIT_FAILED {
            return Err(io::Error::last_os_error());
        }
        debug_assert_eq!(status, WAIT_OBJECT_0);
        match transferred(handle, &overlapped) {
            // A pipe that reports a zero-byte completion has no peer left.
            Ok(0) if self.inner.reconnect => self.reconnect_outcome(handle),
            other => other.or_else(read_outcome),
        }
    }
}

impl Write for PipeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let Some(request) = byte_count(buf.len()) else {
            return Ok(0);
        };
        let mut retried = false;
        loop {
            let handle = self.current();
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
                    handle,
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
                if is_disconnect(&error) && self.inner.reconnect && !retried {
                    retried = true;
                    self.reconnect(handle)?;
                    continue;
                }
                return Err(write_error(error));
            }
            kd_trace!("pipe: write pending {request} bytes");
            // A write normally waits for room in the pipe. Hyper-V's COM pipe can stop
            // accepting data (the guest debugger is stopped and not draining the UART), so
            // bound it: a stuck write would otherwise wedge the whole command forever.
            // SAFETY: the event is valid until `event` drops.
            let status = unsafe { WaitForSingleObject(event.0, WRITE_TIMEOUT_MS) };
            if status == WAIT_TIMEOUT {
                kd_trace!("pipe: write timed out after {WRITE_TIMEOUT_MS} ms");
                // SAFETY: the overlapped write belongs to this handle.
                unsafe {
                    CancelIoEx(handle, &overlapped);
                    let mut count = 0u32;
                    GetOverlappedResult(handle, &overlapped, &mut count, 1);
                }
                return Err(io::Error::from(ErrorKind::WouldBlock));
            }
            if status == WAIT_FAILED {
                return Err(io::Error::last_os_error());
            }
            match transferred(handle, &overlapped) {
                Ok(count) => return Ok(count),
                Err(error) if is_disconnect(&error) && self.inner.reconnect && !retried => {
                    retried = true;
                    self.reconnect(handle)?;
                    continue;
                }
                Err(error) => return Err(write_error(error)),
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        // KD reads whole frames as they arrive; a pipe needs no flush.
        Ok(())
    }
}

/// Two connected ends of a private pipe, as `UnixStream::pair` gives on Unix.
#[cfg(test)]
pub fn pair() -> io::Result<(PipeStream, PipeStream)> {
    let (server, client, _) = pair_with_name()?;
    Ok((server, client))
}

/// The same pair, plus the name the client can reconnect to.
#[cfg(test)]
fn pair_with_name() -> io::Result<(PipeStream, PipeStream, String)> {
    let name = new_test_name();
    let server = create_test_server(&name)?;
    let client = PipeStream::open(&name)?;
    wait_for_client(&server)?;
    Ok((server, client, name))
}

#[cfg(test)]
fn new_test_name() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    format!(
        r"\\.\pipe\ntoseye-kd-test-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}

#[cfg(test)]
fn create_test_server(name: &str) -> io::Result<PipeStream> {
    use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows_sys::Win32::System::Pipes::{CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT};

    let wide_name = wide(name);
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
    Ok(PipeStream::from_handle(handle))
}

/// Complete the server side of the connection a client just made.
#[cfg(test)]
fn wait_for_client(server: &PipeStream) -> io::Result<()> {
    use windows_sys::Win32::Foundation::ERROR_PIPE_CONNECTED;
    use windows_sys::Win32::System::Pipes::ConnectNamedPipe;

    let event = Event::new()?;
    let mut overlapped = OVERLAPPED {
        hEvent: event.0,
        ..Default::default()
    };
    // SAFETY: `overlapped` outlives the wait below.
    let connected = unsafe { ConnectNamedPipe(server.current(), &mut overlapped) };
    if connected != 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    // A client that connected before this call already satisfies the pipe.
    if error.raw_os_error() == Some(ERROR_PIPE_CONNECTED as i32) {
        return Ok(());
    }
    if !is_pending(&error) {
        return Err(error);
    }
    // SAFETY: the event is valid until `event` drops.
    let status = unsafe { WaitForSingleObject(event.0, 10_000) };
    if status == WAIT_TIMEOUT {
        return Err(io::Error::from(ErrorKind::TimedOut));
    }
    if status == WAIT_FAILED {
        return Err(io::Error::last_os_error());
    }
    let mut count = 0u32;
    // SAFETY: the same connection request, now satisfied.
    if unsafe { GetOverlappedResult(server.current(), &overlapped, &mut count, 1) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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
    fn a_recreated_server_is_reconnected_to() {
        let (server, mut client, name) = pair_with_name().unwrap();
        drop(server);
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            let mut server = create_test_server(&name).unwrap();
            wait_for_client(&server).unwrap();
            server.write_all(b"kd").unwrap();
            server
        });
        // The old server is gone: wait for the replacement instead of EOF.
        let mut read = [0u8; 2];
        let error = client.read(&mut read).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::WouldBlock, "{error}");
        client.read_exact(&mut read).unwrap();
        assert_eq!(&read, b"kd");
        let _server = writer.join().unwrap();
    }

    #[test]
    fn a_bare_name_is_taken_relative_to_the_pipe_namespace() {
        assert_eq!(pipe_path("ntoseye-kd"), r"\\.\pipe\ntoseye-kd");
        assert_eq!(pipe_path(r"\\.\pipe\ntoseye-kd"), r"\\.\pipe\ntoseye-kd");
    }
}
