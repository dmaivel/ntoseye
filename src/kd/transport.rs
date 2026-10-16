use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use super::kdnet::KdNetStream;

pub enum KdTransport {
    Serial(UnixStream),
    Network(KdNetStream),
}

impl KdTransport {
    pub fn try_clone(&self) -> io::Result<Self> {
        match self {
            Self::Serial(stream) => stream.try_clone().map(Self::Serial),
            Self::Network(stream) => stream.try_clone().map(Self::Network),
        }
    }

    /// Set how long a read waits, `None` for no limit. A zero timeout, as a
    /// poll once a deadline is reached asks for, is the shortest a socket
    /// takes, as sockets refuse zero.
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        let timeout = timeout.map(|timeout| timeout.max(Duration::from_millis(1)));
        match self {
            Self::Serial(stream) => stream.set_read_timeout(timeout),
            Self::Network(stream) => stream.set_read_timeout(timeout),
        }
    }

    /// KDNET session generation handle, bumped whenever the transport
    /// renegotiates with a restarted target.
    pub fn network_session_generation(&self) -> Option<Arc<AtomicU64>> {
        match self {
            Self::Network(stream) => Some(stream.session_generation()),
            Self::Serial(_) => None,
        }
    }

    pub fn network_datagrams_received(&self) -> Option<u64> {
        match self {
            Self::Network(stream) => Some(stream.received_datagrams()),
            Self::Serial(_) => None,
        }
    }
}

impl From<UnixStream> for KdTransport {
    fn from(stream: UnixStream) -> Self {
        Self::Serial(stream)
    }
}

impl From<KdNetStream> for KdTransport {
    fn from(stream: KdNetStream) -> Self {
        Self::Network(stream)
    }
}

impl Read for KdTransport {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Serial(stream) => stream.read(output),
            Self::Network(stream) => stream.read(output),
        }
    }
}

impl Write for KdTransport {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        match self {
            Self::Serial(stream) => stream.write(input),
            Self::Network(stream) => stream.write(input),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Serial(stream) => stream.flush(),
            Self::Network(stream) => stream.flush(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A zero read timeout, a poll once a deadline is reached, is taken: a
    /// read with nothing to read then times out, where the socket would
    /// refuse the timeout itself.
    #[test]
    fn a_zero_read_timeout_polls() {
        let (host, _kernel) = UnixStream::pair().unwrap();
        let mut transport = KdTransport::from(host);

        transport.set_read_timeout(Some(Duration::ZERO)).unwrap();
        let read = transport.read(&mut [0u8; 1]);

        assert_eq!(read.unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }
}
