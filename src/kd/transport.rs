use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
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

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Self::Serial(stream) => stream.set_read_timeout(timeout),
            Self::Network(stream) => stream.set_read_timeout(timeout),
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
