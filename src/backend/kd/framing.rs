// KD packet framing:
// data:    [ leader=0x30303030 | type | bytecount | id | checksum ] [ payload ] [ 0xAA ]
// control: [ leader=0x69696969 | type | 0         | id | 0        ]

use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::backend::dbg_backend::BugcheckInfo;
use crate::base::bytes::{read_u16, read_u32};
use crate::base::error::{Error, Result};

pub const DATA_PACKET_LEADER: u32 = 0x30303030;
pub const CONTROL_PACKET_LEADER: u32 = 0x69696969;
const DATA_LEADER_BYTE: u8 = DATA_PACKET_LEADER as u8;
const CONTROL_LEADER_BYTE: u8 = CONTROL_PACKET_LEADER as u8;
pub const PACKET_TRAILING_BYTE: u8 = 0xAA;
pub const BREAKIN_BYTE: u8 = 0x62;

pub const INITIAL_PACKET_ID: u32 = 0x80800000;
pub const SYNC_PACKET_ID: u32 = 0x00000800;
const KDNET_INITIAL_PACKET_ID: u32 = 0x80000000;

pub const PACKET_MAX_SIZE: usize = 4000;
pub const HEADER_SIZE: usize = 16;

pub const PACKET_TYPE_KD_STATE_CHANGE64: u16 = 7;
pub const PACKET_TYPE_KD_STATE_MANIPULATE: u16 = 2;
pub const PACKET_TYPE_KD_DEBUG_IO: u16 = 3;
pub const PACKET_TYPE_KD_ACKNOWLEDGE: u16 = 4;
pub const PACKET_TYPE_KD_RESEND: u16 = 5;
pub const PACKET_TYPE_KD_RESET: u16 = 6;
pub const PACKET_TYPE_KD_FILE_IO: u16 = 11;

/// The header opening every KD packet, data and control alike.
#[derive(Debug, Clone, Copy)]
pub struct Header {
    pub leader: u32,
    pub packet_type: u16,
    pub byte_count: u16,
    pub packet_id: u32,
    pub checksum: u32,
}

impl Header {
    pub fn data(packet_type: u16, packet_id: u32, payload: &[u8]) -> Self {
        Self {
            leader: DATA_PACKET_LEADER,
            packet_type,
            byte_count: payload.len() as u16,
            packet_id,
            checksum: checksum(payload),
        }
    }

    pub fn control(packet_type: u16, packet_id: u32) -> Self {
        Self {
            leader: CONTROL_PACKET_LEADER,
            packet_type,
            byte_count: 0,
            packet_id,
            checksum: 0,
        }
    }

    pub fn encode(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..4].copy_from_slice(&self.leader.to_le_bytes());
        buf[4..6].copy_from_slice(&self.packet_type.to_le_bytes());
        buf[6..8].copy_from_slice(&self.byte_count.to_le_bytes());
        buf[8..12].copy_from_slice(&self.packet_id.to_le_bytes());
        buf[12..16].copy_from_slice(&self.checksum.to_le_bytes());
        buf
    }

    pub fn decode(buf: &[u8; HEADER_SIZE]) -> Self {
        Self {
            leader: read_u32(buf, 0),
            packet_type: read_u16(buf, 4),
            byte_count: read_u16(buf, 6),
            packet_id: read_u32(buf, 8),
            checksum: read_u32(buf, 12),
        }
    }

    /// The header at the start of `bytes`, if they are long enough to hold one.
    pub fn peek(bytes: &[u8]) -> Option<Self> {
        bytes.first_chunk::<HEADER_SIZE>().map(Self::decode)
    }

    pub fn is_data(&self) -> bool {
        self.leader == DATA_PACKET_LEADER
    }

    /// Wire size of the packet this header opens, trailer included.
    pub fn packet_len(&self) -> usize {
        if self.is_data() {
            HEADER_SIZE + self.byte_count as usize + 1
        } else {
            HEADER_SIZE
        }
    }
}

pub fn checksum(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .fold(0u32, |acc, &b| acc.wrapping_add(b as u32))
}

fn write_data_packet(
    out: &mut impl Write,
    packet_type: u16,
    packet_id: u32,
    payload: &[u8],
) -> std::io::Result<()> {
    out.write_all(&Header::data(packet_type, packet_id, payload).encode())?;
    out.write_all(payload)?;
    out.write_all(&[PACKET_TRAILING_BYTE])
}

/// A complete data packet as the target would put it on the wire.
#[cfg(test)]
pub fn data_packet(packet_type: u16, packet_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_SIZE + payload.len() + 1);
    write_data_packet(&mut out, packet_type, packet_id, payload).expect("Vec writes cannot fail");
    out
}

/// A complete control packet as the target would put it on the wire.
#[cfg(test)]
pub fn control_packet(packet_type: u16, packet_id: u32) -> Vec<u8> {
    Header::control(packet_type, packet_id).encode().to_vec()
}

pub fn is_temporary_io_error(kind: ErrorKind) -> bool {
    matches!(kind, ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

#[derive(Debug, Clone)]
pub struct DataPacket {
    pub packet_type: u16,
    pub payload: Vec<u8>,
}

/// A state change the target sent while it answered a request: a new stop
/// it reached while halted, as when the processor bugchecks in the debugger
/// itself, kept for the next wait for a stop (see [`KdFraming::hold_stop`]).
#[derive(Debug, Clone)]
pub struct HeldStop {
    pub key: StopKey,
    pub payload: Vec<u8>,
    /// The bugcheck a `*** Fatal System Error` print before it named.
    pub bugcheck: Option<BugcheckInfo>,
}

/// Which stop a state change reports: its processor, program counter and
/// exception code. The target reports the stop it is at again (after a
/// reconnect, or as it goes back to waiting on the debugger) under a new
/// packet id; only another key is another stop.
pub type StopKey = (u16, u64, u32);

/// Send retry budget for RESEND or missing ACK
const MAX_SEND_RETRIES: usize = 5;

/// How many times [`KdFraming::recv_reply`] sends a request again for want
/// of its reply.
const REPLY_RESENDS: usize = 3;

pub struct KdFraming<T> {
    transport: T,
    current_packet_id: u32,
    remote_packet_id: u32,
    queued_data: VecDeque<DataPacket>,
    awaiting_reset_ack: bool,
    peer_reset_seen: bool,
    kdnet_packet_ids: bool,
    /// KDNET remote-ID high-water mark; targets retransmit with identical
    /// IDs, so anything not strictly greater is a duplicate to ACK and drop.
    /// `None` until the first packet: the target counts from 0.
    kdnet_remote_high_water: Option<u32>,
    /// KDNET session generation, bumped by the transport on every rollover.
    kdnet_generation: Option<Arc<AtomicU64>>,
    kdnet_generation_seen: u64,
    /// The manipulate request the target took last, while what answers it
    /// has not come, and its payload in [`Self::unanswered_payload`]. A
    /// target that sends its own last packet again meanwhile never had our
    /// ACK of it, and drops what it receives before that ACK: the request is
    /// sent again (see [`Self::recv_data`]). `None` for one nothing answers
    /// (see [`Self::forget_unanswered`]).
    unanswered: Option<Unanswered>,
    unanswered_payload: Vec<u8>,
    /// See [`HeldStop`]. A reset drops it with the target's other packets.
    held_stop: Option<HeldStop>,
    /// The stop the last wait for one reported (see [`StopKey`]).
    current_stop: Option<StopKey>,
}

/// A manipulate request the target took (see [`KdFraming::unanswered`]).
#[derive(Clone, Copy)]
struct Unanswered {
    packet_id: u32,
    /// The kind of data packet that answers it: a manipulate reply for a
    /// request, the next state change for a continue.
    answer: u16,
}

impl<T> KdFraming<T> {
    /// Mutable access to the wrapped transport
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Test-only transport accessor
    #[cfg(test)]
    pub fn transport_ref(&self) -> &T {
        &self.transport
    }

    /// Whether a stop the target reached while answering a request waits
    /// for the next wait for a stop.
    pub fn holds_stop(&self) -> bool {
        self.held_stop.is_some()
    }

    /// Whether a state change reporting `key` is a stop the target has
    /// already reported: the one it is at, or the one held for the next
    /// wait.
    pub fn knows_stop(&self, key: StopKey) -> bool {
        self.current_stop == Some(key)
            || self.held_stop.as_ref().is_some_and(|held| held.key == key)
    }

    /// Note the stop a wait for one reports.
    pub fn note_current_stop(&mut self, key: StopKey) {
        self.current_stop = Some(key);
    }

    /// Keep `stop` for the next wait for a stop: the target reached it while
    /// answering a request, which has no way to report it.
    pub fn hold_stop(&mut self, stop: HeldStop) {
        self.held_stop = Some(stop);
    }

    pub fn take_held_stop(&mut self) -> Option<HeldStop> {
        self.held_stop.take()
    }
}

impl<T: Read + Write> KdFraming<T> {
    pub fn new(transport: T) -> Self {
        // First kernel packet may have SYNC set; mask it on compare/ack
        Self {
            transport,
            current_packet_id: INITIAL_PACKET_ID,
            remote_packet_id: INITIAL_PACKET_ID,
            queued_data: VecDeque::new(),
            awaiting_reset_ack: false,
            peer_reset_seen: false,
            kdnet_packet_ids: false,
            kdnet_remote_high_water: None,
            kdnet_generation: None,
            kdnet_generation_seen: 0,
            unanswered: None,
            unanswered_payload: Vec::new(),
            held_stop: None,
            current_stop: None,
        }
    }

    /// Returns whether the target reset its packet stream since the last call.
    /// KD does this with RESET control packets or SYNC-flagged data packets.
    pub fn take_peer_reset_seen(&mut self) -> bool {
        std::mem::take(&mut self.peer_reset_seen)
    }

    /// Returns whether the target reset its packet stream without clearing the
    /// flag. Used by the running pump to assist reboot reconnects while waiting
    /// for the target's next state-change.
    pub fn peer_reset_seen(&self) -> bool {
        self.peer_reset_seen
    }

    /// Select KDNET's packet-ID dialect: the debugger uses high-bit,
    /// monotonically increasing even IDs while the target uses its own
    /// monotonically increasing IDs. KD ACKs still echo the target's exact ID.
    pub fn use_kdnet_packet_ids(&mut self, generation: Arc<AtomicU64>) {
        self.kdnet_packet_ids = true;
        self.current_packet_id = KDNET_INITIAL_PACKET_ID;
        self.kdnet_generation_seen = generation.load(Ordering::Relaxed);
        self.kdnet_generation = Some(generation);
    }

    /// Adopt a rolled-over KDNET session. The peer is a target that restarted
    /// under the listener, so its packet ids begin again: the old high-water
    /// mark would reject everything it sends as a duplicate, and our own id
    /// would carry a value it link-ACKs but discards.
    fn sync_kdnet_session(&mut self) {
        let Some(generation) = &self.kdnet_generation else {
            return;
        };
        let current = generation.load(Ordering::Relaxed);
        if current == self.kdnet_generation_seen {
            return;
        }
        self.kdnet_generation_seen = current;
        kd_trace!("kd: KDNET session rolled over; restarting the packet-id stream");
        self.reset_outbound_packet_id();
        self.kdnet_remote_high_water = None;
        self.queued_data.clear();
        self.unanswered = None;
        self.held_stop = None;
        self.peer_reset_seen = true;
    }

    fn reset_outbound_packet_id(&mut self) {
        self.current_packet_id = if self.kdnet_packet_ids {
            KDNET_INITIAL_PACKET_ID
        } else {
            INITIAL_PACKET_ID
        };
    }

    /// Whether an inbound ACK answers the packet in flight. KDCOM masks SYNC
    /// on both sides; KDNET ids are plain counters stepping by two, so the
    /// same masking would let an ACK from 1024 packets ago pass for this one.
    fn ack_matches(&self, packet_id: u32) -> bool {
        if self.kdnet_packet_ids {
            packet_id == self.current_packet_id
        } else {
            (packet_id & !SYNC_PACKET_ID) == (self.current_packet_id & !SYNC_PACKET_ID)
        }
    }

    /// Whether an inbound ACK answers a KDNET packet sent before the one in
    /// flight: a late copy, as the target ACKs a packet once for each time
    /// it is sent. KDNET ids count up by two in the low 31 bits; KDCOM's
    /// two alternating ids cannot tell a late ACK from a wrong one.
    fn acks_earlier_kdnet_packet(&self, packet_id: u32) -> bool {
        let behind = self.current_packet_id.wrapping_sub(packet_id) & !KDNET_INITIAL_PACKET_ID;
        self.kdnet_packet_ids
            && packet_id & KDNET_INITIAL_PACKET_ID != 0
            && (1..=64).contains(&behind)
    }

    fn remote_ack_id(&self, packet_id: u32) -> u32 {
        if self.kdnet_packet_ids {
            packet_id
        } else {
            packet_id & !SYNC_PACKET_ID
        }
    }

    /// Send an unframed break-in byte
    pub fn send_breakin(&mut self) -> Result<()> {
        self.transport.write_all(&[BREAKIN_BYTE])?;
        self.transport.flush()?;
        Ok(())
    }

    /// Send KD_RESET and reset local packet IDs. KDCOM ignores the id and
    /// restarts both streams at `INITIAL_PACKET_ID`; kdnet.dll adopts the
    /// RESET's id as the next one it expects from the host.
    pub fn send_reset(&mut self) -> Result<()> {
        self.reset_outbound_packet_id();
        self.remote_packet_id = INITIAL_PACKET_ID;
        self.kdnet_remote_high_water = None;
        self.queued_data.clear();
        self.unanswered = None;
        self.held_stop = None;
        self.awaiting_reset_ack = true;
        self.send_control(PACKET_TYPE_KD_RESET, self.current_packet_id)
    }

    fn handle_reset(&mut self, context: &str) -> Result<()> {
        kd_trace!("kd: {context}: got RESET, resyncing ids");
        self.reset_outbound_packet_id();
        self.remote_packet_id = INITIAL_PACKET_ID;
        // The target restarts its id counter too, so the old high-water mark
        // would reject everything it sends next.
        self.kdnet_remote_high_water = None;
        self.queued_data.clear();
        self.unanswered = None;
        self.held_stop = None;
        self.peer_reset_seen = true;
        if self.awaiting_reset_ack {
            self.awaiting_reset_ack = false;
        } else {
            self.send_control(PACKET_TYPE_KD_RESET, self.current_packet_id)?;
        }
        Ok(())
    }

    pub fn send_data(&mut self, packet_type: u16, payload: &[u8]) -> Result<()> {
        self.send_answered_by(packet_type, payload, PACKET_TYPE_KD_STATE_MANIPULATE)
    }

    /// Send a continue (`payload`, a manipulate request): no reply answers
    /// it, but the stop the target reports after running does, so that stop
    /// arriving before the ACK proves the continue arrived. Sent again
    /// then, the target would take it for another continue.
    pub fn send_continue(&mut self, payload: &[u8]) -> Result<()> {
        self.send_answered_by(
            PACKET_TYPE_KD_STATE_MANIPULATE,
            payload,
            PACKET_TYPE_KD_STATE_CHANGE64,
        )
    }

    /// [`Self::send_data`], a manipulate request being answered by a data
    /// packet of type `answer`.
    fn send_answered_by(&mut self, packet_type: u16, payload: &[u8], answer: u16) -> Result<()> {
        if payload.len() > PACKET_MAX_SIZE {
            return Err(Error::Kd(format!(
                "outbound packet too large: {} bytes",
                payload.len()
            )));
        }

        let mut resend_streak = 0usize;
        let attempts = MAX_SEND_RETRIES.max(if self.kdnet_packet_ids { 24 } else { 0 });
        for attempt in 0..attempts {
            kd_trace!(
                "kd: send_data: type={} id={:#x} len={} attempt={}",
                packet_type,
                self.current_packet_id,
                payload.len(),
                attempt
            );

            write_data_packet(
                &mut self.transport,
                packet_type,
                self.current_packet_id,
                payload,
            )?;
            self.transport.flush()?;

            // Inner loop: drain any non-ACK packets queued in the buffer
            // (typically kernel retransmissions of a prior state-change
            // that arrived before we ACKed it). We ACK stale packets and queue
            // fresh packets for the next `recv_data`; breaking out of this
            // inner loop triggers a resend via the outer loop
            loop {
                match self.recv_any() {
                    Err(Error::Io(e)) if is_temporary_io_error(e.kind()) => {
                        kd_trace!("kd: send_data: no ACK before read timeout, retransmitting");
                        break;
                    }
                    Err(e) => return Err(e),
                    Ok(Received::Ack { packet_id }) if self.ack_matches(packet_id) => {
                        kd_trace!("kd: send_data: ACKed id={:#x}", packet_id);
                        // A packet of another kind (a file-I/O answer)
                        // leaves the request it came amid unanswered.
                        if packet_type == PACKET_TYPE_KD_STATE_MANIPULATE {
                            self.unanswered = Some(Unanswered {
                                packet_id: self.current_packet_id,
                                answer,
                            });
                            self.unanswered_payload.clear();
                            self.unanswered_payload.extend_from_slice(payload);
                        }
                        self.next_packet_id();
                        return Ok(());
                    }
                    Ok(Received::Reset) => {
                        self.handle_reset("send_data")?;
                        break;
                    }
                    Ok(Received::Resend) => {
                        resend_streak += 1;
                        // Retransmit with a fresh KDNET sequence while keeping
                        // the KD packet ID stable. Bound a persistently
                        // out-of-sync link instead of looping forever.
                        if self.kdnet_packet_ids && resend_streak >= 24 {
                            return Err(Error::KdSendExhausted(format!(
                                "target requested RESEND {resend_streak} times for a {}-byte KD packet; \
                                 the KD packet stream did not resynchronize",
                                payload.len()
                            )));
                        }
                        kd_trace!("kd: send_data: got RESEND, retransmitting");
                        break;
                    }
                    // Sending this one again would only draw another late
                    // ACK for the next to trip on.
                    Ok(Received::Ack { packet_id })
                        if self.acks_earlier_kdnet_packet(packet_id) =>
                    {
                        kd_trace!(
                            "kd: send_data: late ACK of earlier id={:#x}, waiting on for {:#x}",
                            packet_id,
                            self.current_packet_id
                        );
                    }
                    Ok(Received::Ack { packet_id }) => {
                        kd_trace!(
                            "kd: send_data: stray ACK id={:#x} (expected {:#x}), retransmitting",
                            packet_id,
                            self.current_packet_id
                        );
                        break;
                    }
                    Ok(Received::Data {
                        packet_id,
                        packet_type: received_type,
                        payload,
                    }) => {
                        let ack_id = self.remote_ack_id(packet_id);
                        self.send_control(PACKET_TYPE_KD_ACKNOWLEDGE, ack_id)?;
                        if !self.accept_remote_packet(packet_id) {
                            kd_trace!(
                                "kd: send_data: skip stale queued data type={} id={:#x} (expected {:#x}), ACKed",
                                received_type,
                                packet_id,
                                self.remote_packet_id
                            );
                            continue;
                        }
                        kd_trace!(
                            "kd: send_data: accepted queued data type={} id={:#x} len={}",
                            received_type,
                            packet_id,
                            payload.len()
                        );
                        self.queued_data.push_back(DataPacket {
                            packet_type: received_type,
                            payload,
                        });
                        // Windows answers a manipulate request with one and
                        // sends none unasked, and reports a stop only after
                        // a continue: a fresh answer proves this request
                        // arrived, whatever became of its ACK. Sent again,
                        // the request is one the target has done and never
                        // answers, or a continue it runs again.
                        if packet_type == PACKET_TYPE_KD_STATE_MANIPULATE && received_type == answer
                        {
                            kd_trace!(
                                "kd: send_data: the answer stands for the lost ACK of id={:#x}",
                                self.current_packet_id
                            );
                            self.unanswered = None;
                            self.next_packet_id();
                            return Ok(());
                        }
                    }
                }
            }
        }

        Err(Error::KdSendExhausted(format!(
            "no ACK for a {}-byte KD packet after {attempts} attempts",
            payload.len()
        )))
    }

    /// The id of the packet after the one just delivered.
    fn next_packet_id(&mut self) {
        if self.kdnet_packet_ids {
            self.current_packet_id =
                self.current_packet_id.wrapping_add(2) | KDNET_INITIAL_PACKET_ID;
        } else {
            self.current_packet_id ^= 1;
            self.current_packet_id &= !SYNC_PACKET_ID;
        }
    }

    /// Nothing answers the packet just sent (a reboot): a later repeat of
    /// the target's last packet is not about it, and it is not sent again.
    pub fn forget_unanswered(&mut self) {
        self.unanswered = None;
    }

    /// Send the unanswered request again, with its id: a target that took it
    /// treats it as the duplicate it is, ACKing it and sending its answer
    /// again, and one that dropped it takes it now.
    fn send_unanswered_again(&mut self, why: &str) -> Result<()> {
        let Some(unanswered) = self.unanswered else {
            return Ok(());
        };
        kd_trace!("kd: {why}; sending id={:#x} again", unanswered.packet_id);
        write_data_packet(
            &mut self.transport,
            PACKET_TYPE_KD_STATE_MANIPULATE,
            unanswered.packet_id,
            &self.unanswered_payload,
        )?;
        self.transport.flush()?;
        Ok(())
    }

    /// [`Self::recv_data`] for the reply to the request just sent. A reply
    /// that does not come before the read timeout sends the request again,
    /// [`REPLY_RESENDS`] times: the target may have dropped it (taken while
    /// it waited for our ACK of its own last packet, which was lost), or its
    /// reply may have been lost.
    pub fn recv_reply(&mut self) -> Result<DataPacket> {
        let mut resends = 0;
        loop {
            match self.recv_data() {
                Err(Error::Io(error))
                    if is_temporary_io_error(error.kind())
                        && resends < REPLY_RESENDS
                        && self.unanswered.is_some() =>
                {
                    resends += 1;
                    self.send_unanswered_again("no reply before the read timeout")?;
                }
                result => return result,
            }
        }
    }

    /// A data packet of `packet_type` came in, which may be the answer to
    /// the unanswered request. Anything else (a stop the target announces
    /// again while a request waits, a print) leaves it unanswered.
    fn note_answered(&mut self, packet_type: u16) {
        if self
            .unanswered
            .is_some_and(|unanswered| unanswered.answer == packet_type)
        {
            self.unanswered = None;
        }
    }

    /// Decide whether an incoming data packet should be accepted, advancing
    /// `remote_packet_id` if so. A packet with `SYNC_PACKET_ID` set means the
    /// kernel reset its send-id stream (e.g. it re-entered the debugger after
    /// thinking we were gone), so we realign to it unconditionally. A plain
    /// id that doesn't match the expected one is a stale retransmit to skip.
    ///
    /// KDNET has no such flag: its ids are a plain counter that steps by two,
    /// so bit `SYNC_PACKET_ID` is simply set for half of them. There, a
    /// restarted stream is signaled by the session rollover or by RESET.
    fn accept_remote_packet(&mut self, packet_id: u32) -> bool {
        if self.kdnet_packet_ids {
            // Serial-number order: ids are a u32 counter that wraps, so a
            // fresh id is one a short (non-negative) distance ahead of the
            // high-water mark, not one that is numerically larger.
            let stale = self
                .kdnet_remote_high_water
                .is_some_and(|high| (packet_id.wrapping_sub(high) as i32) <= 0);
            if stale {
                return false;
            }
            self.kdnet_remote_high_water = Some(packet_id);
            // Live data from the peer proves the streams are in sync; a RESET we
            // sent no longer needs an explicit RESET back (KDCOM answers with a
            // retransmitted state-change instead), so a later peer-initiated
            // RESET must be echoed rather than swallowed as our ack.
            self.awaiting_reset_ack = false;
            return true;
        }
        let base = packet_id & !SYNC_PACKET_ID;
        let is_sync = packet_id & SYNC_PACKET_ID != 0;
        if is_sync {
            self.peer_reset_seen = true;
            // The kernel reset *both* its packet ids, so our outbound stream
            // must restart at INITIAL too (like handle_reset). Realigning only
            // the inbound id leaves the next request carrying a stale id that
            // the kernel link-ACKs but discards, so the reply never comes
            self.current_packet_id = INITIAL_PACKET_ID;
        }
        if !is_sync && base != self.remote_packet_id {
            return false;
        }
        self.remote_packet_id = (base ^ 1) & !SYNC_PACKET_ID;
        self.awaiting_reset_ack = false;
        true
    }

    /// Receive the next data packet, ACK'ing it. Discards (but ACKs) any
    /// out-of-order data packets whose id doesn't match `remote_packet_id`
    pub fn recv_data(&mut self) -> Result<DataPacket> {
        if let Some(pkt) = self.queued_data.pop_front() {
            kd_trace!(
                "kd: recv_data: returning queued type={} len={}",
                pkt.packet_type,
                pkt.payload.len()
            );
            self.note_answered(pkt.packet_type);
            return Ok(pkt);
        }

        loop {
            match self.recv_any()? {
                Received::Data {
                    packet_type,
                    packet_id,
                    payload,
                } => {
                    // KDCOM masks SYNC in ACKs; KDNET requires the exact ID.
                    let ack_id = self.remote_ack_id(packet_id);
                    self.send_control(PACKET_TYPE_KD_ACKNOWLEDGE, ack_id)?;
                    if !self.accept_remote_packet(packet_id) {
                        kd_trace!(
                            "kd: recv_data: skip stale type={} id={:#x} (expected {:#x}), ACKed",
                            packet_type,
                            packet_id,
                            self.remote_packet_id
                        );
                        // A target that ran on a continue cannot send the
                        // stop it ran from again: it never had our ACK of
                        // that stop, and dropped the continue it took
                        // meanwhile. (A request proves nothing this way:
                        // a target resends its stop before our ACK of it
                        // reaches it on a sound link, and then takes the
                        // request; see [`Self::recv_reply`].)
                        if self.unanswered.is_some_and(|unanswered| {
                            unanswered.answer == PACKET_TYPE_KD_STATE_CHANGE64
                        }) {
                            self.send_unanswered_again(
                                "the target sent the stop it ran from again",
                            )?;
                        }
                        continue;
                    }
                    kd_trace!(
                        "kd: recv_data: accepted type={} id={:#x} len={}",
                        packet_type,
                        packet_id,
                        payload.len()
                    );
                    self.note_answered(packet_type);
                    return Ok(DataPacket {
                        packet_type,
                        payload,
                    });
                }
                Received::Reset => {
                    self.handle_reset("recv_data")?;
                }
                Received::Ack { .. } | Received::Resend => {
                    // stray control packet; keep waiting for data
                }
            }
        }
    }

    fn send_control(&mut self, packet_type: u16, packet_id: u32) -> Result<()> {
        self.transport
            .write_all(&Header::control(packet_type, packet_id).encode())?;
        self.transport.flush()?;
        Ok(())
    }

    fn recv_any(&mut self) -> Result<Received> {
        loop {
            let leader = self.read_packet_leader()?;
            // Reading the leader pulled in the datagram that carries this
            // packet, so a rollover it proved is visible now, before its id
            // is judged against the superseded stream.
            self.sync_kdnet_session();
            let mut tail = [0u8; HEADER_SIZE - 4];
            self.transport.read_exact(&mut tail)?;

            let mut header_buf = [0u8; HEADER_SIZE];
            header_buf[0..4].copy_from_slice(&leader.to_le_bytes());
            header_buf[4..].copy_from_slice(&tail);
            let header = Header::decode(&header_buf);

            if !header.is_data() {
                return Ok(match header.packet_type {
                    PACKET_TYPE_KD_ACKNOWLEDGE => Received::Ack {
                        packet_id: header.packet_id,
                    },
                    PACKET_TYPE_KD_RESEND => Received::Resend,
                    PACKET_TYPE_KD_RESET => Received::Reset,
                    other => {
                        return Err(Error::Kd(format!(
                            "unknown control packet type {:#x}",
                            other
                        )));
                    }
                });
            }

            // data packet
            let len = header.byte_count as usize;
            if len > PACKET_MAX_SIZE {
                return Err(Error::Kd(format!(
                    "inbound packet too large: {} bytes",
                    len
                )));
            }

            let mut payload = vec![0u8; len];
            self.transport.read_exact(&mut payload)?;
            let mut trailer = [0u8; 1];
            self.transport.read_exact(&mut trailer)?;
            if trailer[0] != PACKET_TRAILING_BYTE {
                self.send_control(PACKET_TYPE_KD_RESEND, 0)?;
                continue;
            }

            let computed = checksum(&payload);
            if computed != header.checksum {
                self.send_control(PACKET_TYPE_KD_RESEND, 0)?;
                continue;
            }

            return Ok(Received::Data {
                packet_type: header.packet_type,
                packet_id: header.packet_id,
                payload,
            });
        }
    }

    /// Synchronize to a packet leader: read bytes until we see four identical
    /// leader bytes in a row. Mirrors `KdpReceivePacketLeader` in ReactOS
    fn read_packet_leader(&mut self) -> Result<u32> {
        // The per-byte trace is its own, `kd-bytes`: the packet-level `kd`
        // trace would drown in raw byte noise from kernel retransmissions
        loop {
            let mut byte = [0u8; 1];
            match self.transport.read_exact(&mut byte) {
                Ok(()) => {}
                Err(e) => {
                    if !is_temporary_io_error(e.kind()) {
                        kd_trace!("kd-trace: read error: {e}");
                    }
                    return Err(e.into());
                }
            }
            kd_trace_bytes!("kd-trace: <- {:02x}\n", byte[0]);
            if byte[0] != DATA_LEADER_BYTE && byte[0] != CONTROL_LEADER_BYTE {
                continue;
            }
            let mut want = byte[0];
            let mut matched = 1usize;
            while matched < 4 {
                self.transport.read_exact(&mut byte)?;
                kd_trace_bytes!("kd-trace: <- {:02x}\n", byte[0]);
                if byte[0] == want {
                    matched += 1;
                } else if byte[0] == DATA_LEADER_BYTE || byte[0] == CONTROL_LEADER_BYTE {
                    // start over with the new candidate
                    want = byte[0];
                    matched = 1;
                } else {
                    matched = 0;
                    break;
                }
            }
            if matched == 4 {
                return Ok(u32::from_le_bytes([want; 4]));
            }
        }
    }
}

#[derive(Debug)]
enum Received {
    Ack {
        packet_id: u32,
    },
    Resend,
    Reset,
    Data {
        packet_type: u16,
        packet_id: u32,
        payload: Vec<u8>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::kd::event_loop::is_initial_resync_error;
    use std::io::{Cursor, Read, Write};

    /// In-memory transport: reads from a queued buffer, writes to a captured
    /// buffer. Lets us hand-assemble byte sequences and verify what our code
    /// emits
    struct Loopback {
        inbound: Cursor<Vec<u8>>,
        outbound: Vec<u8>,
        /// Offsets into `inbound` where a read times out once first.
        timeouts: VecDeque<u64>,
    }

    impl Loopback {
        fn new(inbound: Vec<u8>) -> Self {
            Self {
                inbound: Cursor::new(inbound),
                outbound: Vec::new(),
                timeouts: VecDeque::new(),
            }
        }

        /// `chunks` in turn, a read timing out between each and the next.
        fn timing_out_between(chunks: &[Vec<u8>]) -> Self {
            let mut inbound = Vec::new();
            let mut timeouts = VecDeque::new();
            for (index, chunk) in chunks.iter().enumerate() {
                if index > 0 {
                    timeouts.push_back(inbound.len() as u64);
                }
                inbound.extend_from_slice(chunk);
            }
            Self {
                inbound: Cursor::new(inbound),
                outbound: Vec::new(),
                timeouts,
            }
        }
    }

    impl Read for Loopback {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.timeouts.front() == Some(&self.inbound.position()) {
                self.timeouts.pop_front();
                return Err(std::io::Error::from(ErrorKind::WouldBlock));
            }
            self.inbound.read(buf)
        }
    }

    impl Write for Loopback {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.outbound.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn ack_for(id: u32) -> Vec<u8> {
        control_packet(PACKET_TYPE_KD_ACKNOWLEDGE, id)
    }

    #[test]
    fn send_data_writes_header_payload_trailer_and_consumes_ack() {
        let mut framing = KdFraming::new(Loopback::new(ack_for(
            (INITIAL_PACKET_ID | SYNC_PACKET_ID) & !SYNC_PACKET_ID,
        )));
        framing
            .send_data(PACKET_TYPE_KD_STATE_MANIPULATE, b"hello")
            .unwrap();

        let out = &framing.transport.outbound;
        assert_eq!(out.len(), HEADER_SIZE + 5 + 1);
        assert_eq!(&out[0..4], &DATA_PACKET_LEADER.to_le_bytes());
        assert_eq!(&out[HEADER_SIZE..HEADER_SIZE + 5], b"hello");
        assert_eq!(out[HEADER_SIZE + 5], PACKET_TRAILING_BYTE);
    }

    #[test]
    fn send_data_toggles_packet_id_after_ack() {
        let mut framing = KdFraming::new(Loopback::new(ack_for(
            (INITIAL_PACKET_ID | SYNC_PACKET_ID) & !SYNC_PACKET_ID,
        )));
        let before = framing.current_packet_id;
        framing
            .send_data(PACKET_TYPE_KD_STATE_MANIPULATE, &[])
            .unwrap();
        let after = framing.current_packet_id;
        assert_eq!(after, (before & !SYNC_PACKET_ID) ^ 1);
    }

    #[test]
    fn send_data_advances_kdnet_packet_ids_by_two() {
        let mut framing = KdFraming::new(Loopback::new(ack_for(KDNET_INITIAL_PACKET_ID)));
        framing.use_kdnet_packet_ids(Arc::new(AtomicU64::new(0)));
        framing
            .send_data(PACKET_TYPE_KD_STATE_MANIPULATE, &[])
            .unwrap();

        let sent = Header::decode(
            framing.transport.outbound[..HEADER_SIZE]
                .try_into()
                .unwrap(),
        );
        assert_eq!(sent.packet_id, KDNET_INITIAL_PACKET_ID);
        assert_eq!(
            framing.current_packet_id,
            KDNET_INITIAL_PACKET_ID.wrapping_add(2)
        );
    }

    #[test]
    fn kdnet_rollover_restarts_the_remote_packet_id_stream() {
        let generation = Arc::new(AtomicU64::new(0));
        let mut inbound = data_packet(PACKET_TYPE_KD_STATE_CHANGE64, 0xb6, b"old");
        inbound.extend(data_packet(PACKET_TYPE_KD_STATE_CHANGE64, 0x04, b"new"));
        let mut framing = KdFraming::new(Loopback::new(inbound));
        framing.use_kdnet_packet_ids(Arc::clone(&generation));

        assert_eq!(framing.recv_data().unwrap().payload, b"old");
        assert!(!framing.take_peer_reset_seen());

        generation.fetch_add(1, Ordering::Relaxed);
        let after_reboot = framing.recv_data().unwrap();
        assert_eq!(after_reboot.payload, b"new");
        assert!(
            framing.take_peer_reset_seen(),
            "a rolled-over session is a target reload"
        );
        assert_eq!(framing.current_packet_id, KDNET_INITIAL_PACKET_ID);
    }

    #[test]
    fn kdnet_ids_carrying_the_sync_bit_are_ordinary_ids() {
        let mut inbound = data_packet(PACKET_TYPE_KD_STATE_CHANGE64, 0x2008a, b"before");
        inbound.extend(data_packet(
            PACKET_TYPE_KD_STATE_CHANGE64,
            0x25f4c,
            b"after",
        ));
        inbound.extend(ack_for(KDNET_INITIAL_PACKET_ID));
        let mut framing = KdFraming::new(Loopback::new(inbound));
        framing.use_kdnet_packet_ids(Arc::new(AtomicU64::new(0)));

        assert_eq!(framing.recv_data().unwrap().payload, b"before");
        assert_eq!(framing.recv_data().unwrap().payload, b"after");
        assert!(
            !framing.take_peer_reset_seen(),
            "a set SYNC bit in a KDNET id is not a target reload"
        );
        let second_ack = Header::decode(
            framing.transport.outbound[HEADER_SIZE..2 * HEADER_SIZE]
                .try_into()
                .unwrap(),
        );
        assert_eq!(second_ack.packet_type, PACKET_TYPE_KD_ACKNOWLEDGE);
        assert_eq!(
            second_ack.packet_id, 0x25f4c,
            "KDNET ACKs echo the id whole"
        );

        framing
            .send_data(PACKET_TYPE_KD_STATE_MANIPULATE, &[])
            .unwrap();
        assert_eq!(
            framing.current_packet_id,
            KDNET_INITIAL_PACKET_ID.wrapping_add(2)
        );
    }

    #[test]
    fn kdnet_ack_ids_must_match_exactly() {
        let mut inbound = ack_for(KDNET_INITIAL_PACKET_ID | SYNC_PACKET_ID);
        inbound.extend(ack_for(KDNET_INITIAL_PACKET_ID));
        let mut framing = KdFraming::new(Loopback::new(inbound));
        framing.use_kdnet_packet_ids(Arc::new(AtomicU64::new(0)));

        framing
            .send_data(PACKET_TYPE_KD_STATE_MANIPULATE, b"x")
            .unwrap();

        let packet_len = HEADER_SIZE + 1 + 1;
        assert_eq!(framing.transport.outbound.len(), 2 * packet_len);
        assert_eq!(
            framing.current_packet_id,
            KDNET_INITIAL_PACKET_ID.wrapping_add(2)
        );
    }

    #[test]
    fn kdnet_replayed_packet_ids_are_still_dropped() {
        let mut inbound = data_packet(PACKET_TYPE_KD_STATE_CHANGE64, 0x25f4c, b"first");
        inbound.extend(data_packet(
            PACKET_TYPE_KD_STATE_CHANGE64,
            0x25f4c,
            b"replay",
        ));
        inbound.extend(data_packet(PACKET_TYPE_KD_STATE_CHANGE64, 0x25f4e, b"next"));
        let mut framing = KdFraming::new(Loopback::new(inbound));
        framing.use_kdnet_packet_ids(Arc::new(AtomicU64::new(0)));

        assert_eq!(framing.recv_data().unwrap().payload, b"first");
        assert_eq!(framing.recv_data().unwrap().payload, b"next");
    }

    #[test]
    fn kdnet_first_packet_may_carry_id_zero() {
        let mut inbound = data_packet(PACKET_TYPE_KD_STATE_CHANGE64, 0x0, b"boot");
        inbound.extend(data_packet(PACKET_TYPE_KD_STATE_CHANGE64, 0x0, b"replay"));
        inbound.extend(data_packet(PACKET_TYPE_KD_STATE_CHANGE64, 0x2, b"next"));
        let mut framing = KdFraming::new(Loopback::new(inbound));
        framing.use_kdnet_packet_ids(Arc::new(AtomicU64::new(0)));

        assert_eq!(framing.recv_data().unwrap().payload, b"boot");
        assert_eq!(framing.recv_data().unwrap().payload, b"next");
    }

    #[test]
    fn recv_data_returns_payload_and_acks() {
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let inbound = data_packet(PACKET_TYPE_KD_STATE_CHANGE64, INITIAL_PACKET_ID, &payload);
        let mut framing = KdFraming::new(Loopback::new(inbound));

        let pkt = framing.recv_data().unwrap();
        assert_eq!(pkt.packet_type, PACKET_TYPE_KD_STATE_CHANGE64);
        assert_eq!(pkt.payload, payload);

        let out = &framing.transport.outbound;
        assert_eq!(out.len(), HEADER_SIZE);
        let h = Header::decode(out.as_slice().try_into().unwrap());
        assert_eq!(h.leader, CONTROL_PACKET_LEADER);
        assert_eq!(h.packet_type, PACKET_TYPE_KD_ACKNOWLEDGE);
        assert_eq!(h.packet_id, INITIAL_PACKET_ID);
    }

    #[test]
    fn recv_data_accepts_kdnet_monotonic_packet_ids() {
        let inbound = data_packet(PACKET_TYPE_KD_STATE_CHANGE64, 0xb6, b"kdnet");
        let mut framing = KdFraming::new(Loopback::new(inbound));
        framing.use_kdnet_packet_ids(Arc::new(AtomicU64::new(0)));

        let pkt = framing.recv_data().unwrap();
        assert_eq!(pkt.payload, b"kdnet");

        let ack = Header::decode(
            framing.transport.outbound[..HEADER_SIZE]
                .try_into()
                .unwrap(),
        );
        assert_eq!(ack.packet_type, PACKET_TYPE_KD_ACKNOWLEDGE);
        assert_eq!(ack.packet_id, 0xb6);
    }

    #[test]
    fn recv_data_skips_garbage_before_leader() {
        let payload = vec![0x01, 0x02];
        let mut inbound = vec![0xAA, 0x55, 0x12, 0x34]; // garbage
        inbound.extend(data_packet(
            PACKET_TYPE_KD_STATE_CHANGE64,
            INITIAL_PACKET_ID,
            &payload,
        ));
        let mut framing = KdFraming::new(Loopback::new(inbound));
        let pkt = framing.recv_data().unwrap();
        assert_eq!(pkt.payload, payload);
    }

    #[test]
    fn recv_data_resyncs_when_leader_byte_changes_mid_match() {
        let mut inbound = vec![DATA_LEADER_BYTE, DATA_LEADER_BYTE];
        inbound.extend(ack_for(0));
        inbound.extend(data_packet(
            PACKET_TYPE_KD_STATE_CHANGE64,
            INITIAL_PACKET_ID,
            b"good",
        ));

        let mut framing = KdFraming::new(Loopback::new(inbound));
        let pkt = framing.recv_data().unwrap();
        assert_eq!(pkt.payload, b"good");
    }

    #[test]
    fn recv_data_acks_and_skips_unexpected_packet_id() {
        let payload = vec![0xAB];
        let mut inbound = data_packet(
            PACKET_TYPE_KD_STATE_CHANGE64,
            INITIAL_PACKET_ID ^ 1, // wrong id, should be ACK'd then ignored
            &payload,
        );
        inbound.extend(data_packet(
            PACKET_TYPE_KD_STATE_CHANGE64,
            INITIAL_PACKET_ID,
            b"good",
        ));
        let mut framing = KdFraming::new(Loopback::new(inbound));
        let pkt = framing.recv_data().unwrap();
        assert_eq!(pkt.payload, b"good");
        assert_eq!(framing.transport.outbound.len(), 2 * HEADER_SIZE);
    }

    #[test]
    fn recv_data_accepts_sync_flagged_packet_despite_id_mismatch() {
        let inbound = data_packet(
            PACKET_TYPE_KD_STATE_CHANGE64,
            INITIAL_PACKET_ID | SYNC_PACKET_ID,
            b"bugcheck",
        );
        let mut framing = KdFraming::new(Loopback::new(inbound));
        framing.remote_packet_id = INITIAL_PACKET_ID ^ 1;

        framing.current_packet_id = INITIAL_PACKET_ID ^ 1;

        let pkt = framing.recv_data().unwrap();
        assert_eq!(pkt.payload, b"bugcheck");
        assert_eq!(framing.remote_packet_id, INITIAL_PACKET_ID ^ 1);
        assert_eq!(framing.current_packet_id, INITIAL_PACKET_ID);

        let out = &framing.transport.outbound;
        assert_eq!(out.len(), HEADER_SIZE);
        let ack = Header::decode(out[0..HEADER_SIZE].try_into().unwrap());
        assert_eq!(ack.packet_type, PACKET_TYPE_KD_ACKNOWLEDGE);
        assert_eq!(ack.packet_id, INITIAL_PACKET_ID);
        assert!(framing.take_peer_reset_seen());
        assert!(!framing.take_peer_reset_seen());
    }

    #[test]
    fn recv_data_requests_resend_after_bad_checksum() {
        let payload = vec![0x11, 0x22];
        let mut inbound = data_packet(PACKET_TYPE_KD_STATE_CHANGE64, INITIAL_PACKET_ID, &payload);
        inbound[12] = inbound[12].wrapping_add(1);
        inbound.extend(data_packet(
            PACKET_TYPE_KD_STATE_CHANGE64,
            INITIAL_PACKET_ID,
            b"resent",
        ));

        let mut framing = KdFraming::new(Loopback::new(inbound));
        let pkt = framing.recv_data().unwrap();
        assert_eq!(pkt.payload, b"resent");

        let out = &framing.transport.outbound;
        assert_eq!(out.len(), 2 * HEADER_SIZE);
        let resend = Header::decode(out[0..HEADER_SIZE].try_into().unwrap());
        assert_eq!(resend.packet_type, PACKET_TYPE_KD_RESEND);
        let ack = Header::decode(out[HEADER_SIZE..2 * HEADER_SIZE].try_into().unwrap());
        assert_eq!(ack.packet_type, PACKET_TYPE_KD_ACKNOWLEDGE);
    }

    #[test]
    fn recv_data_echoes_peer_initiated_reset_before_data() {
        let mut inbound = control_packet(PACKET_TYPE_KD_RESET, 0);
        inbound.extend(data_packet(
            PACKET_TYPE_KD_STATE_CHANGE64,
            INITIAL_PACKET_ID,
            b"stop",
        ));
        let mut framing = KdFraming::new(Loopback::new(inbound));
        framing.current_packet_id = INITIAL_PACKET_ID ^ 1;
        framing.remote_packet_id = INITIAL_PACKET_ID ^ 1;

        let pkt = framing.recv_data().unwrap();
        assert_eq!(pkt.payload, b"stop");
        assert_eq!(framing.current_packet_id, INITIAL_PACKET_ID);
        assert_eq!(framing.remote_packet_id, INITIAL_PACKET_ID ^ 1);
        assert!(framing.take_peer_reset_seen());

        let out = &framing.transport.outbound;
        assert_eq!(out.len(), 2 * HEADER_SIZE);
        let reset = Header::decode(out[0..HEADER_SIZE].try_into().unwrap());
        assert_eq!(reset.leader, CONTROL_PACKET_LEADER);
        assert_eq!(reset.packet_type, PACKET_TYPE_KD_RESET);
        let ack = Header::decode(out[HEADER_SIZE..2 * HEADER_SIZE].try_into().unwrap());
        assert_eq!(ack.packet_type, PACKET_TYPE_KD_ACKNOWLEDGE);
        assert_eq!(ack.packet_id, INITIAL_PACKET_ID);
    }

    #[test]
    fn recv_data_does_not_echo_reset_ack_after_local_reset() {
        let mut inbound = control_packet(PACKET_TYPE_KD_RESET, 0);
        inbound.extend(data_packet(
            PACKET_TYPE_KD_STATE_CHANGE64,
            INITIAL_PACKET_ID,
            b"stop",
        ));
        let mut framing = KdFraming::new(Loopback::new(inbound));
        framing.send_reset().unwrap();

        let pkt = framing.recv_data().unwrap();
        assert_eq!(pkt.payload, b"stop");
        assert!(!framing.awaiting_reset_ack);

        let out = &framing.transport.outbound;
        assert_eq!(out.len(), 2 * HEADER_SIZE);
        let local_reset = Header::decode(out[0..HEADER_SIZE].try_into().unwrap());
        assert_eq!(local_reset.packet_type, PACKET_TYPE_KD_RESET);
        let ack = Header::decode(out[HEADER_SIZE..2 * HEADER_SIZE].try_into().unwrap());
        assert_eq!(ack.packet_type, PACKET_TYPE_KD_ACKNOWLEDGE);
        assert_eq!(ack.packet_id, INITIAL_PACKET_ID);
    }

    #[test]
    fn send_data_retries_on_resend() {
        let resend = control_packet(PACKET_TYPE_KD_RESEND, 0);
        let mut inbound = resend;
        inbound.extend(ack_for(
            (INITIAL_PACKET_ID | SYNC_PACKET_ID) & !SYNC_PACKET_ID,
        ));
        let mut framing = KdFraming::new(Loopback::new(inbound));
        framing
            .send_data(PACKET_TYPE_KD_STATE_MANIPULATE, b"x")
            .unwrap();
        let expected_per_attempt = HEADER_SIZE + 1 + 1;
        assert_eq!(framing.transport.outbound.len(), expected_per_attempt * 2);
    }

    #[test]
    fn persistent_kdnet_resend_is_a_resync_error() {
        let inbound = (0..24)
            .flat_map(|_| control_packet(PACKET_TYPE_KD_RESEND, 0))
            .collect();
        let mut framing = KdFraming::new(Loopback::new(inbound));
        framing.use_kdnet_packet_ids(Arc::new(AtomicU64::new(0)));
        let err = framing
            .send_data(PACKET_TYPE_KD_STATE_MANIPULATE, b"x")
            .unwrap_err();
        assert!(matches!(err, Error::KdSendExhausted(_)), "{err}");
        assert!(is_initial_resync_error(&err));
    }

    #[test]
    fn send_data_retries_on_missing_ack_timeout() {
        struct TimeoutThenAck {
            ack: Cursor<Vec<u8>>,
            timed_out: bool,
            outbound: Vec<u8>,
        }

        impl Read for TimeoutThenAck {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if !self.timed_out {
                    self.timed_out = true;
                    return Err(std::io::Error::from(ErrorKind::WouldBlock));
                }
                self.ack.read(buf)
            }
        }

        impl Write for TimeoutThenAck {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.outbound.write(buf)
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let transport = TimeoutThenAck {
            ack: Cursor::new(ack_for(INITIAL_PACKET_ID)),
            timed_out: false,
            outbound: Vec::new(),
        };
        let mut framing = KdFraming::new(transport);

        framing
            .send_data(PACKET_TYPE_KD_STATE_MANIPULATE, b"x")
            .unwrap();

        let expected_per_attempt = HEADER_SIZE + 1 + 1;
        assert_eq!(framing.transport.outbound.len(), expected_per_attempt * 2);
    }

    #[test]
    fn send_data_queues_fresh_data_received_before_ack() {
        let mut inbound = data_packet(PACKET_TYPE_KD_STATE_CHANGE64, INITIAL_PACKET_ID, b"stop");
        inbound.extend(ack_for(
            (INITIAL_PACKET_ID | SYNC_PACKET_ID) & !SYNC_PACKET_ID,
        ));
        let mut framing = KdFraming::new(Loopback::new(inbound));

        framing
            .send_data(PACKET_TYPE_KD_STATE_MANIPULATE, b"x")
            .unwrap();
        let pkt = framing.recv_data().unwrap();

        assert_eq!(pkt.packet_type, PACKET_TYPE_KD_STATE_CHANGE64);
        assert_eq!(pkt.payload, b"stop");
        assert_eq!(framing.remote_packet_id, INITIAL_PACKET_ID ^ 1);
        let out = &framing.transport.outbound;
        assert_eq!(out.len(), (HEADER_SIZE + 1 + 1) + HEADER_SIZE);
    }

    /// A manipulate reply that arrives without its request's ACK (the ACK
    /// lost) delivers the request: it is not sent again, the reply is the
    /// next data, and the next request takes the next id. Sent again, the
    /// request would never be answered, and nor would any after it.
    #[test]
    fn a_reply_without_its_ack_delivers_the_request() {
        let mut inbound = data_packet(PACKET_TYPE_KD_STATE_MANIPULATE, INITIAL_PACKET_ID, b"reply");
        inbound.extend(ack_for(INITIAL_PACKET_ID ^ 1));
        let mut framing = KdFraming::new(Loopback::new(inbound));

        framing
            .send_data(PACKET_TYPE_KD_STATE_MANIPULATE, b"x")
            .unwrap();
        let reply = framing.recv_data().unwrap();
        assert_eq!(reply.payload, b"reply");
        // One request and the reply's ACK.
        assert_eq!(
            framing.transport.outbound.len(),
            (HEADER_SIZE + 1 + 1) + HEADER_SIZE
        );

        framing
            .send_data(PACKET_TYPE_KD_STATE_MANIPULATE, b"y")
            .unwrap();
        let next = Header::decode(
            framing.transport.outbound[2 * HEADER_SIZE + 2..3 * HEADER_SIZE + 2]
                .try_into()
                .unwrap(),
        );
        assert_eq!(next.packet_id, INITIAL_PACKET_ID ^ 1);
    }

    /// The packets `out` holds, as `(type, id)`, data and control alike.
    fn sent_packets(out: &[u8]) -> Vec<(u16, u32)> {
        let mut packets = Vec::new();
        let mut at = 0;
        while at < out.len() {
            let header = Header::decode(out[at..at + HEADER_SIZE].try_into().unwrap());
            packets.push((header.packet_type, header.packet_id));
            at += if header.is_data() {
                header.packet_len()
            } else {
                HEADER_SIZE
            };
        }
        packets
    }

    /// A request whose reply does not come before the read timeout is sent
    /// again with its id, and its reply taken; a stop the target announces
    /// again meanwhile is no reply. The target sending its own last packet
    /// again is no reason to: it does so before our ACK of it reaches it on
    /// a sound link, and then takes the request.
    #[test]
    fn a_request_is_sent_again_for_want_of_its_reply() {
        let stop = |id| data_packet(PACKET_TYPE_KD_STATE_CHANGE64, id, b"stop");
        let reply = data_packet(
            PACKET_TYPE_KD_STATE_MANIPULATE,
            INITIAL_PACKET_ID ^ 1,
            b"reply",
        );
        let request = (PACKET_TYPE_KD_STATE_MANIPULATE, INITIAL_PACKET_ID);
        let ack = |id| (PACKET_TYPE_KD_ACKNOWLEDGE, id);

        let mut inbound = ack_for(INITIAL_PACKET_ID);
        inbound.extend(stop(INITIAL_PACKET_ID));
        inbound.extend(&reply);
        let mut framing = KdFraming::new(Loopback::new(inbound));
        framing.remote_packet_id = INITIAL_PACKET_ID ^ 1;
        framing
            .send_data(PACKET_TYPE_KD_STATE_MANIPULATE, b"x")
            .unwrap();
        assert_eq!(framing.recv_reply().unwrap().payload, b"reply");
        assert_eq!(
            sent_packets(&framing.transport.outbound),
            [request, ack(INITIAL_PACKET_ID), ack(INITIAL_PACKET_ID ^ 1)]
        );

        let mut announced = ack_for(INITIAL_PACKET_ID);
        announced.extend(stop(INITIAL_PACKET_ID));
        let mut framing = KdFraming::new(Loopback::timing_out_between(&[announced, reply.clone()]));
        framing
            .send_data(PACKET_TYPE_KD_STATE_MANIPULATE, b"x")
            .unwrap();
        assert_eq!(framing.recv_reply().unwrap().payload, b"stop");
        assert_eq!(framing.recv_reply().unwrap().payload, b"reply");
        assert_eq!(
            sent_packets(&framing.transport.outbound),
            [
                request,
                ack(INITIAL_PACKET_ID),
                request,
                ack(INITIAL_PACKET_ID ^ 1)
            ]
        );
    }

    /// A continue is answered by the next stop: the target sending the stop
    /// it ran from again after the continue's ACK dropped the continue,
    /// which is sent again; a new stop arriving before the ACK stands for
    /// it, the continue not sent again to run the target twice.
    #[test]
    fn a_stop_answers_a_continue() {
        let request = (PACKET_TYPE_KD_STATE_MANIPULATE, INITIAL_PACKET_ID);
        let ack = |id| (PACKET_TYPE_KD_ACKNOWLEDGE, id);

        let mut inbound = ack_for(INITIAL_PACKET_ID);
        inbound.extend(data_packet(
            PACKET_TYPE_KD_STATE_CHANGE64,
            INITIAL_PACKET_ID,
            b"stop",
        ));
        inbound.extend(data_packet(
            PACKET_TYPE_KD_STATE_CHANGE64,
            INITIAL_PACKET_ID ^ 1,
            b"next",
        ));
        let mut framing = KdFraming::new(Loopback::new(inbound));
        framing.remote_packet_id = INITIAL_PACKET_ID ^ 1;
        framing.send_continue(b"continue").unwrap();
        assert_eq!(framing.recv_data().unwrap().payload, b"next");
        assert_eq!(
            sent_packets(&framing.transport.outbound),
            [
                request,
                ack(INITIAL_PACKET_ID),
                request,
                ack(INITIAL_PACKET_ID ^ 1)
            ]
        );

        let inbound = data_packet(PACKET_TYPE_KD_STATE_CHANGE64, INITIAL_PACKET_ID, b"next");
        let mut framing = KdFraming::new(Loopback::new(inbound));
        framing.send_continue(b"continue").unwrap();
        assert_eq!(framing.recv_data().unwrap().payload, b"next");
        assert_eq!(
            sent_packets(&framing.transport.outbound),
            [request, ack(INITIAL_PACKET_ID)]
        );
    }

    /// Over KDNET a late ACK of an earlier packet (one sent twice) is no
    /// reason to send the packet in flight again; any other ACK is.
    #[test]
    fn a_late_kdnet_ack_of_an_earlier_packet_is_waited_past() {
        let mut framing = KdFraming::new(Loopback::new(Vec::new()));
        framing.use_kdnet_packet_ids(Arc::new(AtomicU64::new(0)));
        let current = framing.current_packet_id;
        let mut inbound = ack_for(current.wrapping_sub(2) | KDNET_INITIAL_PACKET_ID);
        inbound.extend(ack_for(current));
        framing.transport = Loopback::new(inbound);
        framing
            .send_data(PACKET_TYPE_KD_STATE_MANIPULATE, b"x")
            .unwrap();
        assert_eq!(sent_packets(&framing.transport.outbound).len(), 1);

        let current = framing.current_packet_id;
        let mut inbound = ack_for(current.wrapping_add(2));
        inbound.extend(ack_for(current));
        framing.transport = Loopback::new(inbound);
        framing
            .send_data(PACKET_TYPE_KD_STATE_MANIPULATE, b"y")
            .unwrap();
        assert_eq!(sent_packets(&framing.transport.outbound).len(), 2);
    }
}
