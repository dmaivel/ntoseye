//! The client socket: framing, acknowledgments and their retransmissions,
//! the polling reads that keep the serving thread free, and the packet
//! trace.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use gdb_remote::frame::{self, Corruption, Decoder, Frame, Kind};
use gdb_remote::stop::StopReply;

use crate::backend::gdb::trace_packet;
use crate::base::error::Error;

use super::PACKET_SIZE;

/// Console text carried per `O` packet, before hex encoding: the packet
/// fits the size the server advertises.
const CONSOLE_CHUNK: usize = PACKET_SIZE / 2 - 1;
/// Frames a client may send while the target runs, which wait for the
/// stop. A client in all-stop mode sends the interrupt byte and little
/// else (acknowledgments of console output); past this many, it is
/// dropped rather than held without bound.
const HELD_WHILE_RUNNING: usize = 256;

pub(super) fn connection_error(error: io::Error) -> Error {
    Error::DebugInfo(format!("connection lost: {error}"))
}

/// What the client sent that the server acts on.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Incoming {
    /// A request: the packet's body.
    Packet(Vec<u8>),
    /// The interrupt byte.
    Interrupt,
}

/// A client socket. Reads give up periodically so the caller can do other
/// work; what they bring is decoded a frame at a time.
pub(super) struct Connection {
    stream: TcpStream,
    decoder: Decoder,
    /// Frames read and not yet taken, in order.
    frames: VecDeque<Frame>,
    /// The client turned acknowledgments off (`QStartNoAckMode`).
    no_ack: bool,
    /// The last packet sent, framed, for a `-` to ask for again.
    last: Vec<u8>,
    terminating: Arc<AtomicBool>,
}

impl Connection {
    pub(super) fn new(stream: TcpStream, terminating: Arc<AtomicBool>) -> io::Result<Self> {
        // The listener is non-blocking so accept can poll; the client is not.
        stream.set_nonblocking(false)?;
        stream.set_nodelay(true)?;
        Ok(Self {
            stream,
            decoder: Decoder::new(),
            frames: VecDeque::new(),
            no_ack: false,
            last: Vec::new(),
            terminating,
        })
    }

    /// From the next packet on, neither side acknowledges.
    pub(super) fn stop_acknowledging(&mut self) {
        self.no_ack = true;
    }

    /// Read what the socket has, waiting at most `timeout` (`None`: not at
    /// all), into frames. Returns whether anything arrived.
    fn fill(&mut self, timeout: Option<Duration>) -> io::Result<bool> {
        match timeout {
            Some(timeout) => {
                self.stream.set_nonblocking(false)?;
                self.stream.set_read_timeout(Some(timeout))?;
            }
            None => self.stream.set_nonblocking(true)?,
        }
        let mut buffer = [0u8; PACKET_SIZE];
        let read = match self.stream.read(&mut buffer) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(read) => read,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        for frame in self.decoder.decode(&buffer[..read]) {
            match &frame {
                Frame::Packet(body) => {
                    let mut packet = Vec::with_capacity(body.len() + 4);
                    frame::write_packet(&mut packet, body);
                    trace_packet("client", "<-", &packet);
                }
                Frame::Interrupt => trace_packet("client", "<-", &[frame::INTERRUPT]),
                Frame::Corrupt(corruption) => {
                    trace_packet("client", "<-", format!("{corruption:?}").as_bytes());
                }
                Frame::Ack | Frame::Nack | Frame::Notification(_) => {}
            }
            self.frames.push_back(frame);
        }
        Ok(true)
    }

    /// The next request or interrupt, waiting at most `timeout` for one.
    /// Acknowledgments are handled here: a packet is acknowledged as it
    /// arrives, a corrupt one asked for again, and a `-` answered with the
    /// last packet sent. Reads go on until the timeout: what one read
    /// brings (an ack, a corrupt packet, part of a packet) may not hold a
    /// request yet.
    pub(super) fn next(&mut self, timeout: Duration) -> io::Result<Option<Incoming>> {
        let deadline = Instant::now() + timeout;
        loop {
            while let Some(frame) = self.frames.pop_front() {
                if let Some(incoming) = self.take(frame)? {
                    return Ok(Some(incoming));
                }
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() || self.terminating.load(Ordering::SeqCst) {
                return Ok(None);
            }
            self.fill(Some(left))?;
        }
    }

    /// What `frame` asks of the server, after acknowledging it.
    fn take(&mut self, frame: Frame) -> io::Result<Option<Incoming>> {
        let body = match frame {
            Frame::Packet(body) => body,
            Frame::Interrupt => return Ok(Some(Incoming::Interrupt)),
            // Only a `-` read after the last packet went out asks for it:
            // one sent before it (gdb sends `-` whenever a reply outlasts
            // its timeout, in either mode) was dropped when it went out.
            Frame::Nack if !self.no_ack && !self.last.is_empty() => {
                let last = std::mem::take(&mut self.last);
                let sent = self.write(&last);
                self.last = last;
                sent?;
                return Ok(None);
            }
            Frame::Ack | Frame::Nack | Frame::Notification(_) => return Ok(None),
            // gdbserver's rule: with acknowledgments off nothing can ask
            // for the packet again, so its body is taken as it came.
            Frame::Corrupt(Corruption::Checksum {
                kind: Kind::Packet,
                body,
                ..
            }) if self.no_ack => body,
            Frame::Corrupt(_) if self.no_ack => return Ok(None),
            Frame::Corrupt(_) => {
                self.write(&[frame::NACK])?;
                return Ok(None);
            }
        };
        if !self.no_ack {
            self.write(&[frame::ACK])?;
        }
        Ok(Some(Incoming::Packet(body)))
    }

    /// Whether the client sent the interrupt byte; what else it sent waits
    /// for [`Self::next`], up to [`HELD_WHILE_RUNNING`] frames. Never
    /// blocks.
    pub(super) fn interrupted(&mut self) -> io::Result<bool> {
        self.fill(None)?;
        match self
            .frames
            .iter()
            .position(|frame| *frame == Frame::Interrupt)
        {
            Some(at) => {
                self.frames.remove(at);
                Ok(true)
            }
            None if self.frames.len() > HELD_WHILE_RUNNING => Err(io::Error::other(format!(
                "the client sent more than {HELD_WHILE_RUNNING} packets while the target ran"
            ))),
            None => Ok(false),
        }
    }

    /// Send `body` as a packet. Acknowledgments that arrived before it
    /// cannot be about it, and are dropped.
    pub(super) fn send(&mut self, body: &[u8]) -> io::Result<()> {
        self.fill(None)?;
        self.frames
            .retain(|frame| !matches!(frame, Frame::Ack | Frame::Nack));
        let mut packet = Vec::with_capacity(body.len() + 4);
        frame::write_packet(&mut packet, body);
        self.write(&packet)?;
        self.last = packet;
        Ok(())
    }

    /// Send console text as `O` packets, which a client shows while the
    /// target runs and as a `monitor` command's output.
    pub(super) fn console(&mut self, text: &str) -> io::Result<()> {
        let mut body = Vec::new();
        for chunk in text.as_bytes().chunks(CONSOLE_CHUNK) {
            body.clear();
            StopReply::Output(chunk.to_vec()).write(&mut body);
            self.send(&body)?;
        }
        Ok(())
    }

    fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        trace_packet("client", "->", bytes);
        self.stream.set_nonblocking(false)?;
        self.stream.write_all(bytes)?;
        self.stream.flush()
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;

    use gdb_remote::frame::{Decoder, Frame, write_packet};
    use gdb_remote::stop::StopReply;

    use super::{CONSOLE_CHUNK, Connection, HELD_WHILE_RUNNING, Incoming, PACKET_SIZE};

    const WAIT: Duration = Duration::from_millis(200);

    /// A server connection and the client's end of it.
    fn connected() -> (Connection, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (stream, _) = listener.accept().unwrap();
        client.set_read_timeout(Some(WAIT)).unwrap();
        let connection = Connection::new(stream, Arc::new(AtomicBool::new(false))).unwrap();
        (connection, client)
    }

    fn packet(body: &[u8]) -> Vec<u8> {
        let mut packet = Vec::new();
        write_packet(&mut packet, body);
        packet
    }

    /// Every frame the client received, until it stops arriving.
    fn received(client: &mut TcpStream) -> Vec<Frame> {
        let mut decoder = Decoder::new();
        let mut frames = Vec::new();
        let mut buffer = [0u8; 4096];
        while let Ok(read @ 1..) = client.read(&mut buffer) {
            frames.extend(decoder.decode(&buffer[..read]));
        }
        frames
    }

    /// In acknowledgment mode a request is acknowledged before it is
    /// answered (so a slow answer does not make gdb send the request
    /// again), a corrupt one is asked for again, and a `-` after a reply
    /// gets that reply again. A request that comes in a later read than the
    /// corrupt one, within the wait, is still the one returned.
    #[test]
    fn acknowledgment_mode_acks_naks_and_resends() {
        let (mut connection, mut client) = connected();
        let mut corrupt = packet(b"g");
        *corrupt.last_mut().unwrap() = b'0';
        client.write_all(&corrupt).unwrap();
        let mut late = client.try_clone().unwrap();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            late.write_all(&packet(b"?")).unwrap();
        });
        assert_eq!(
            connection.next(WAIT).unwrap(),
            Some(Incoming::Packet(b"?".to_vec()))
        );
        writer.join().unwrap();
        connection.send(b"S05").unwrap();
        assert_eq!(
            received(&mut client),
            [Frame::Nack, Frame::Ack, Frame::Packet(b"S05".to_vec())]
        );

        client.write_all(b"-").unwrap();
        assert_eq!(connection.next(WAIT).unwrap(), None);
        assert_eq!(received(&mut client), [Frame::Packet(b"S05".to_vec())]);
    }

    /// gdb sends `-` each time a reply outlasts its timeout, before the
    /// reply exists. Resending the reply for it would answer the next
    /// request with this one, and every reply after would be one off.
    #[test]
    fn a_nak_sent_before_the_reply_does_not_resend_it() {
        let (mut connection, mut client) = connected();
        client.write_all(&packet(b"qRcmd,6c6d")).unwrap();
        connection.next(WAIT).unwrap();
        // The client times out while the command runs.
        client.write_all(b"-").unwrap();
        std::thread::sleep(Duration::from_millis(50));
        connection.send(b"OK").unwrap();
        client.write_all(&packet(b"g")).unwrap();
        assert_eq!(
            connection.next(WAIT).unwrap(),
            Some(Incoming::Packet(b"g".to_vec()))
        );
        assert_eq!(
            received(&mut client),
            [Frame::Ack, Frame::Packet(b"OK".to_vec()), Frame::Ack]
        );
    }

    /// Without acknowledgments nothing is acknowledged or resent, and a
    /// packet whose checksum is wrong is taken as it came, as gdbserver
    /// takes it: nothing could ask for it again.
    #[test]
    fn no_ack_mode_takes_packets_as_they_come() {
        let (mut connection, mut client) = connected();
        connection.stop_acknowledging();
        let mut corrupt = packet(b"g");
        *corrupt.last_mut().unwrap() = b'0';
        client.write_all(&corrupt).unwrap();
        assert_eq!(
            connection.next(WAIT).unwrap(),
            Some(Incoming::Packet(b"g".to_vec()))
        );
        connection.send(b"OK").unwrap();
        client.write_all(b"-+").unwrap();
        assert_eq!(connection.next(WAIT).unwrap(), None);
        assert_eq!(received(&mut client), [Frame::Packet(b"OK".to_vec())]);
    }

    /// While the target runs only the interrupt is taken; a request sent
    /// meanwhile waits its turn instead of being lost.
    #[test]
    fn an_interrupt_is_found_behind_a_waiting_request() {
        let (mut connection, mut client) = connected();
        connection.stop_acknowledging();
        client.write_all(&packet(b"qC")).unwrap();
        client.write_all(&[0x03]).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        assert!(connection.interrupted().unwrap());
        assert!(!connection.interrupted().unwrap());
        assert_eq!(
            connection.next(WAIT).unwrap(),
            Some(Incoming::Packet(b"qC".to_vec()))
        );
    }

    /// What waits for the stop is bounded: a client that keeps sending
    /// requests while the target runs is dropped, not buffered forever.
    #[test]
    fn a_client_flooding_a_running_target_is_dropped() {
        let (mut connection, mut client) = connected();
        connection.stop_acknowledging();
        let flood = packet(b"qC").repeat(HELD_WHILE_RUNNING + 1);
        client.write_all(&flood).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        let mut outcome = Ok(false);
        // The socket may hand the flood over in several reads.
        for _ in 0..10 {
            outcome = connection.interrupted();
            if outcome.is_err() {
                break;
            }
        }
        assert!(outcome.is_err());
    }

    /// Console text is split into `O` packets that fit the advertised
    /// packet size and reassemble to the text.
    #[test]
    fn console_text_fits_the_packet_size() {
        let (mut connection, mut client) = connected();
        connection.stop_acknowledging();
        let text = "x".repeat(CONSOLE_CHUNK * 2 + 3);
        connection.console(&text).unwrap();
        let mut decoder = Decoder::new();
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 65536];
        while let Ok(read @ 1..) = client.read(&mut chunk) {
            buffer.extend_from_slice(&chunk[..read]);
        }
        let mut reassembled = Vec::new();
        for frame in decoder.decode(&buffer) {
            let Frame::Packet(body) = frame else {
                panic!("{frame:?}");
            };
            assert!(body.len() <= PACKET_SIZE);
            let Ok(StopReply::Output(text)) = StopReply::parse(&body) else {
                panic!("not console output");
            };
            reassembled.extend(text);
        }
        assert_eq!(reassembled, text.as_bytes());
    }
}
