//! The client socket: RSP framing around gdbstub, the polling reads that
//! keep the serving thread free, and the packets the server answers itself.

use std::fmt::Write as _;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use gdbstub::conn::{Connection, ConnectionExt};

use crate::error::Error;
use crate::gdb::{append_packet, packet_checksum, trace_packet};

use super::{IDLE_POLL, PACKET_SIZE};

/// Console text carried per `O` packet, before hex encoding.
const CONSOLE_CHUNK: usize = 1024;
/// Appended to gdbstub's `qSupported` reply so clients ask for it.
const THREADS_FEATURE: &[u8] = b";qXfer:threads:read+";

pub(super) fn connection_error(error: io::Error) -> Error {
    Error::DebugInfo(format!("connection lost: {error}"))
}

/// A client socket. Writes are buffered until gdbstub ends a packet, and a
/// blocking read gives up periodically so the caller can do other work.
pub(super) struct Client {
    stream: TcpStream,
    out: Vec<u8>,
    inbox: Vec<u8>,
    pub(super) next: usize,
    /// The client turned off acknowledgments (`QStartNoAckMode`).
    no_ack: bool,
    /// A `qSupported` went to gdbstub, whose reply must advertise the
    /// thread-list transfer the server answers itself.
    advertise_threads: bool,
    /// The client negotiated `multiprocess+`, so thread ids carry a pid.
    pub(super) multiprocess: bool,
    terminating: Arc<AtomicBool>,
}

impl Client {
    pub(super) fn new(stream: TcpStream, terminating: Arc<AtomicBool>) -> io::Result<Self> {
        // The listener is non-blocking so accept can poll; the client is not.
        stream.set_nonblocking(false)?;
        Ok(Self {
            stream,
            out: Vec::new(),
            inbox: Vec::new(),
            next: 0,
            no_ack: false,
            advertise_threads: false,
            multiprocess: false,
            terminating,
        })
    }

    /// The rest of a packet whose `$` was just read: its body, and the whole
    /// packet as received.
    pub(super) fn read_packet(&mut self) -> io::Result<(Vec<u8>, Vec<u8>)> {
        let mut raw = vec![b'$'];
        loop {
            let byte = ConnectionExt::read(self)?;
            raw.push(byte);
            if byte == b'#' {
                break;
            }
        }
        for _ in 0..2 {
            raw.push(ConnectionExt::read(self)?);
        }
        let body = raw[1..raw.len() - 3].to_vec();
        Ok((body, raw))
    }

    /// Track what a packet headed for gdbstub changes about framing.
    pub(super) fn observe(&mut self, body: &[u8]) {
        if body.starts_with(b"qSupported") {
            self.advertise_threads = true;
            self.multiprocess = body
                .split(|byte| matches!(byte, b':' | b';'))
                .any(|feature| feature == b"multiprocess+");
        }
        if body == b"QStartNoAckMode" {
            self.no_ack = true;
        }
    }

    /// Answer a packet the server handled itself.
    pub(super) fn reply(&mut self, body: &[u8]) -> io::Result<()> {
        if !self.no_ack {
            self.out.push(b'+');
        }
        append_packet(&mut self.out, body);
        Connection::flush(self)
    }

    /// Refill the inbox from the socket, waiting at most `timeout` (`None`:
    /// not at all). Returns whether a byte is available.
    fn fill(&mut self, timeout: Option<Duration>) -> io::Result<bool> {
        if self.next < self.inbox.len() {
            return Ok(true);
        }
        match timeout {
            Some(timeout) => {
                self.stream.set_nonblocking(false)?;
                self.stream.set_read_timeout(Some(timeout))?;
            }
            None => self.stream.set_nonblocking(true)?,
        }
        self.inbox.resize(PACKET_SIZE, 0);
        self.next = 0;
        // gdbstub implements its own `Connection` for `TcpStream`, so the
        // socket's `io` methods are named explicitly.
        let read = match Read::read(&mut self.stream, &mut self.inbox) {
            Ok(0) => {
                self.inbox.clear();
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            Ok(read) => read,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                0
            }
            Err(error) => {
                self.inbox.clear();
                return Err(error);
            }
        };
        self.inbox.truncate(read);
        Ok(read > 0)
    }

    /// One byte, or `None` when nothing arrived within `timeout`.
    pub(super) fn read_byte(&mut self, timeout: Duration) -> io::Result<Option<u8>> {
        if !self.fill(Some(timeout))? {
            return Ok(None);
        }
        let byte = self.inbox[self.next];
        self.next += 1;
        Ok(Some(byte))
    }

    /// Send console text as `O` packets, which a client shows while the
    /// target runs. The client's acknowledgment (in ack mode) is a bare `+`
    /// that gdbstub skips as noise.
    pub(super) fn console(&mut self, text: &str) -> io::Result<()> {
        for chunk in text.as_bytes().chunks(CONSOLE_CHUNK) {
            let mut body = String::with_capacity(chunk.len() * 2 + 1);
            body.push('O');
            for byte in chunk {
                let _ = write!(body, "{byte:02x}");
            }
            append_packet(&mut self.out, body.as_bytes());
        }
        Connection::flush(self)
    }
}

/// Append `feature` to the `qSupported` reply packet in `out`, fixing its
/// checksum. `None` when `out` holds no such reply.
fn advertise(out: &[u8], feature: &[u8]) -> Option<Vec<u8>> {
    let start = out
        .windows(12)
        .position(|window| window == b"$PacketSize=")?;
    let hash = start + out[start..].iter().position(|byte| *byte == b'#')?;
    let digits = std::str::from_utf8(out.get(hash + 1..hash + 3)?).ok()?;
    let checksum = u8::from_str_radix(digits, 16).ok()?;
    let checksum = checksum.wrapping_add(packet_checksum(feature));
    let mut rewritten = out[..hash].to_vec();
    rewritten.extend_from_slice(feature);
    rewritten.extend_from_slice(format!("#{checksum:02x}").as_bytes());
    rewritten.extend_from_slice(&out[hash + 3..]);
    Some(rewritten)
}

/// The `offset,length` (hex) of a `qXfer` read.
pub(super) fn xfer_window(window: &[u8]) -> Option<(usize, usize)> {
    let (offset, length) = std::str::from_utf8(window).ok()?.split_once(',')?;
    Some((
        usize::from_str_radix(offset, 16).ok()?,
        usize::from_str_radix(length, 16).ok()?,
    ))
}

/// A `qXfer` read reply for `[offset, offset + length)` of `data`: `m` when
/// more follows, `l` at the end, with the binary escapes the protocol needs.
pub(super) fn xfer_reply(data: &[u8], offset: usize, length: usize) -> Vec<u8> {
    let start = offset.min(data.len());
    let end = start.saturating_add(length).min(data.len());
    let mut reply = vec![if end < data.len() { b'm' } else { b'l' }];
    for &byte in &data[start..end] {
        if matches!(byte, b'#' | b'$' | b'}' | b'*') {
            reply.extend_from_slice(&[b'}', byte ^ 0x20]);
        } else {
            reply.push(byte);
        }
    }
    reply
}

impl Connection for Client {
    type Error = io::Error;

    fn write(&mut self, byte: u8) -> io::Result<()> {
        self.out.push(byte);
        Ok(())
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.out.extend_from_slice(buf);
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.advertise_threads
            && let Some(rewritten) = advertise(&self.out, THREADS_FEATURE)
        {
            self.out = rewritten;
            self.advertise_threads = false;
        }
        trace_packet("client", "->", &self.out);
        self.stream.set_nonblocking(false)?;
        Write::write_all(&mut self.stream, &self.out)?;
        self.out.clear();
        Write::flush(&mut self.stream)
    }

    fn on_session_start(&mut self) -> io::Result<()> {
        self.stream.set_nodelay(true)
    }
}

impl ConnectionExt for Client {
    fn read(&mut self) -> io::Result<u8> {
        loop {
            if self.terminating.load(Ordering::SeqCst) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "termination signal received",
                ));
            }
            if let Some(byte) = self.read_byte(IDLE_POLL)? {
                return Ok(byte);
            }
        }
    }

    fn peek(&mut self) -> io::Result<Option<u8>> {
        Ok(self.fill(None)?.then(|| self.inbox[self.next]))
    }
}

#[cfg(test)]
mod tests {
    use super::{advertise, xfer_reply};
    use crate::gdb::{append_packet, packet_checksum};

    fn checksum_valid(packet: &[u8]) -> bool {
        let start = packet.iter().position(|byte| *byte == b'$').unwrap();
        let hash = packet.iter().rposition(|byte| *byte == b'#').unwrap();
        let sum = packet_checksum(&packet[start + 1..hash]);
        let digits = std::str::from_utf8(&packet[hash + 1..hash + 3]).unwrap();
        u8::from_str_radix(digits, 16).unwrap() == sum
    }

    /// The feature is spliced into gdbstub's reply after the fact: a stale
    /// checksum makes the client reject the whole handshake. A leading ack must
    /// survive, and a packet that is not the reply must be left alone.
    #[test]
    fn advertised_feature_keeps_the_qsupported_reply_valid() {
        let mut out = vec![b'+'];
        append_packet(&mut out, b"PacketSize=4000;vContSupported+");
        let rewritten = advertise(&out, b";qXfer:threads:read+").unwrap();

        assert!(rewritten.starts_with(b"+$PacketSize=4000;vContSupported+;qXfer:threads:read+#"));
        assert!(checksum_valid(&rewritten));

        let mut other = Vec::new();
        append_packet(&mut other, b"OK");
        assert_eq!(advertise(&other, b";qXfer:threads:read+"), None);
    }

    /// Chunked reads must reassemble to the object exactly: `m` while more
    /// follows, `l` on the last window, and RSP's reserved bytes escaped.
    #[test]
    fn xfer_windows_reassemble_the_escaped_object() {
        let data = b"<threads name=\"a*b#c$d}e\"/>";
        let mut reassembled = Vec::new();
        let mut offset = 0;
        loop {
            let reply = xfer_reply(data, offset, 5);
            let mut unescaped = Vec::new();
            let mut bytes = reply[1..].iter();
            while let Some(&byte) = bytes.next() {
                assert!(!matches!(byte, b'#' | b'$' | b'*'), "unescaped {byte}");
                unescaped.push(if byte == b'}' {
                    bytes.next().unwrap() ^ 0x20
                } else {
                    byte
                });
            }
            offset += unescaped.len();
            reassembled.extend(unescaped);
            match reply[0] {
                b'm' => continue,
                b'l' => break,
                other => panic!("bad reply kind {other}"),
            }
        }
        assert_eq!(reassembled, data);
    }
}
