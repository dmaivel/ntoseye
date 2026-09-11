use std::io::{self, ErrorKind, Read, Write};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use aes::Aes256;
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::{Error, Result};
use crate::kd::framing::BREAKIN_BYTE;

const MAGIC: &[u8; 4] = b"MDBG";
const HEADER_SIZE: usize = 6;
const METADATA_SIZE: usize = 8;
const AUTH_TAG_SIZE: usize = 16;
const CONTROL_RESPONSE_SIZE: usize = 322;
/// Offset within a target poke of the host port its data channel is bound
/// to, big-endian; zero until the target has accepted a host response.
const POKE_HOST_PORT_OFFSET: usize = 86;
const MAX_DATAGRAM_SIZE: usize = 8192;
const MAX_KD_STREAM_SIZE: usize = 4017;
const CHANNEL_DATA: u8 = 0;
const CHANNEL_CONTROL: u8 = 1;
const HOST_DIRECTION: u64 = 0x80;
const DATA_PACKET_LEADER: u32 = 0x3030_3030;
const PACKET_TRAILING_BYTE: u8 = 0xaa;

type Aes256CbcEncryptor = cbc::Encryptor<Aes256>;
type Aes256CbcDecryptor = cbc::Decryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

/// Session state negotiated from control pokes.
///
/// kdnet.dll pokes every three seconds whether or not it has a data channel,
/// and it accepts any response that echoes a recent poke: the response rekeys
/// it and zeroes its sequence state. Answering a connected target's keepalive
/// would therefore rotate the data key under a working session. The poke says
/// which case this is: once the target has accepted a response, its pokes
/// carry the host port its data channel is bound to; a rebooted target has no
/// data channel and pokes with that field zero, so answering it is a rollover.
struct SessionState {
    control_key: [u8; 32],
    hmac_key: [u8; 32],
    data_key: RwLock<Option<[u8; 32]>>,
    peer: RwLock<Option<SocketAddr>>,
    version: AtomicU8,
    /// Never rewound: the target drops any datagram whose sequence does not
    /// advance its high-water mark, and accepting a response zeroes that
    /// mark, so a counter that only grows is right before and after rollover.
    send_sequence: AtomicU64,
    /// Bumped on every rollover, so the KD framing layer restarts its
    /// packet-id stream for the rebooted target.
    generation: Arc<AtomicU64>,
}

/// A stream adapter for Microsoft's encrypted KDNET-over-UDP transport.
///
/// KDNET carries one trailer-less KD packet per authenticated UDP datagram.
/// This adapter restores KDCOM's stream and trailer semantics so the existing
/// KD packet state machine can be shared without a second protocol stack.
pub struct KdNetStream {
    socket: UdpSocket,
    state: Arc<SessionState>,
    inbound: Vec<u8>,
    inbound_offset: usize,
    datagram: Vec<u8>,
    received_datagrams: u64,
    encoded: Vec<u8>,
    outbound: Vec<u8>,
    /// A break-in written before the target had negotiated a session; sent
    /// the moment it has one, so attach does not wait for the next attempt.
    deferred_breakin: bool,
}

impl KdNetStream {
    pub fn bind(endpoint: &str, key: &str) -> Result<Self> {
        let control_key = parse_key(key)?;
        let bind_addr = resolve_bind_addr(endpoint)?;
        let socket = UdpSocket::bind(bind_addr).map_err(|err| {
            Error::Kd(format!(
                "failed to bind KDNET listener on '{endpoint}': {err}"
            ))
        })?;
        let mut hmac_key = control_key;
        for byte in &mut hmac_key {
            *byte = !*byte;
        }
        Ok(Self {
            socket,
            state: Arc::new(SessionState {
                control_key,
                hmac_key,
                data_key: RwLock::new(None),
                peer: RwLock::new(None),
                version: AtomicU8::new(0),
                send_sequence: AtomicU64::new(1),
                generation: Arc::new(AtomicU64::new(0)),
            }),
            inbound: Vec::with_capacity(MAX_KD_STREAM_SIZE),
            inbound_offset: 0,
            datagram: vec![0u8; MAX_DATAGRAM_SIZE],
            received_datagrams: 0,
            encoded: Vec::with_capacity(MAX_DATAGRAM_SIZE),
            outbound: Vec::with_capacity(MAX_KD_STREAM_SIZE),
            deferred_breakin: false,
        })
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            socket: self.socket.try_clone()?,
            state: Arc::clone(&self.state),
            inbound: Vec::with_capacity(MAX_KD_STREAM_SIZE),
            inbound_offset: 0,
            datagram: vec![0u8; MAX_DATAGRAM_SIZE],
            received_datagrams: 0,
            encoded: Vec::with_capacity(MAX_DATAGRAM_SIZE),
            outbound: Vec::with_capacity(MAX_KD_STREAM_SIZE),
            deferred_breakin: false,
        })
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.socket.set_read_timeout(timeout)
    }

    pub fn received_datagrams(&self) -> u64 {
        self.received_datagrams
    }

    fn receive_packet(&mut self) -> io::Result<()> {
        let mut datagram = std::mem::take(&mut self.datagram);
        let result = self.receive_packet_with(&mut datagram);
        self.datagram = datagram;
        result
    }

    fn receive_packet_with(&mut self, datagram: &mut Vec<u8>) -> io::Result<()> {
        loop {
            datagram.resize(MAX_DATAGRAM_SIZE, 0);
            let (size, source) = self.socket.recv_from(datagram)?;
            self.received_datagrams = self.received_datagrams.saturating_add(1);
            kd_trace!("kdnet: received {size}-byte UDP datagram from {source}");
            if size < HEADER_SIZE + METADATA_SIZE + AUTH_TAG_SIZE {
                continue;
            }
            datagram.truncate(size);
            if &datagram[..4] != MAGIC {
                continue;
            }

            let version = datagram[4];
            let channel = datagram[5];
            if let Some(peer) = *read_lock(&self.state.peer)?
                && peer != source
                && channel != CHANNEL_CONTROL
            {
                continue;
            }
            match channel {
                CHANNEL_CONTROL => {
                    decrypt_payload(datagram, self.state.control_key)?;
                    verify_authentication(datagram, &self.state.hmac_key)?;
                    self.handle_control_packet(datagram, source, version)?;
                    if self.deferred_breakin && read_lock(&self.state.data_key)?.is_some() {
                        self.deferred_breakin = false;
                        self.outbound.push(BREAKIN_BYTE);
                        self.flush()?;
                    }
                    continue;
                }
                CHANNEL_DATA => {
                    let Some(data_key) = *read_lock(&self.state.data_key)? else {
                        // Pre-negotiation data is a target still talking to a
                        // session this listener does not hold. It would poke
                        // on its own within three seconds; poking it makes it
                        // offer now.
                        kd_trace!("kdnet: data datagram before key negotiation; poking {source}");
                        self.poke(source, version)?;
                        continue;
                    };
                    decrypt_payload(datagram, data_key)?;
                    if let Err(err) = verify_authentication(datagram, &self.state.hmac_key) {
                        kd_trace!("kdnet: dropping stale-session datagram: {err}");
                        continue;
                    }
                }
                other => {
                    kd_trace!("kdnet: dropping datagram on unknown channel {other:#x}");
                    continue;
                }
            }

            let metadata =
                u64::from_be_bytes(datagram[HEADER_SIZE..HEADER_SIZE + 8].try_into().unwrap());
            if metadata & HOST_DIRECTION != 0 {
                return Err(invalid_data(
                    "KDNET packet has debugger-to-target direction",
                ));
            }
            let padding = (metadata & 0x0f) as usize;
            let payload_start = HEADER_SIZE + METADATA_SIZE;
            let payload_end = datagram
                .len()
                .checked_sub(AUTH_TAG_SIZE + padding)
                .filter(|end| *end >= payload_start)
                .ok_or_else(|| invalid_data("KDNET packet has invalid padding"))?;

            self.inbound.clear();
            self.inbound
                .extend_from_slice(&datagram[payload_start..payload_end]);
            if self.inbound.len() >= 4
                && u32::from_le_bytes(self.inbound[..4].try_into().unwrap()) == DATA_PACKET_LEADER
            {
                self.inbound.push(PACKET_TRAILING_BYTE);
            }
            self.inbound_offset = 0;
            return Ok(());
        }
    }

    fn handle_control_packet(
        &self,
        datagram: &[u8],
        source: SocketAddr,
        version: u8,
    ) -> io::Result<()> {
        // A restarted target keeps its address but picks a new source port, so
        // a poke from a different host is a different machine - two guests
        // sharing a KDNET key, say - and must not take over the session.
        if let Some(peer) = *read_lock(&self.state.peer)?
            && peer.ip() != source.ip()
        {
            kd_trace!("kdnet: ignoring poke from {source}; session belongs to {peer}");
            return Ok(());
        }
        let payload_end = datagram
            .len()
            .checked_sub(AUTH_TAG_SIZE)
            .ok_or_else(|| invalid_data("truncated KDNET control packet"))?;
        let plaintext = &datagram[HEADER_SIZE..payload_end];
        if plaintext.len() < METADATA_SIZE + POKE_HOST_PORT_OFFSET + 2 {
            return Err(invalid_data("truncated KDNET control handshake"));
        }
        let metadata = u64::from_be_bytes(plaintext[..METADATA_SIZE].try_into().unwrap());
        if metadata & HOST_DIRECTION != 0 {
            return Err(invalid_data("KDNET control packet has wrong direction"));
        }
        let rollover = read_lock(&self.state.data_key)?.is_some();
        if rollover {
            // A target that accepted a response has a data channel, and its
            // pokes name the host port it is bound to: those are keepalives
            // (see `SessionState`). A rebooted target pokes with it zero.
            let port_field = METADATA_SIZE + POKE_HOST_PORT_OFFSET;
            let host_port =
                u16::from_be_bytes(plaintext[port_field..port_field + 2].try_into().unwrap());
            if host_port != 0 {
                return Ok(());
            }
            kd_trace!("kdnet: poke from a target without a data channel; renegotiating");
        }

        let client_key: &[u8] = &plaintext[METADATA_SIZE + 2..METADATA_SIZE + 2 + 32];
        let sequence = metadata >> 8;

        let mut response = [0u8; CONTROL_RESPONSE_SIZE];
        response[0] = 1;
        response[1] = 2;
        response[2..34].copy_from_slice(client_key);
        getrandom::fill(&mut response[34..66]).map_err(|err| {
            io::Error::other(format!("KDNET random key generation failed: {err}"))
        })?;

        let mut hasher = Sha256::new();
        hasher.update(self.state.control_key);
        hasher.update(response);
        let data_key: [u8; 32] = hasher.finalize().into();

        let packet = create_packet(
            &response,
            sequence,
            CHANNEL_CONTROL,
            version,
            self.state.control_key,
            &self.state.hmac_key,
            true,
        )?;
        let sent = self.socket.send_to(&packet, source)?;
        if sent != packet.len() {
            return Err(io::Error::new(
                ErrorKind::WriteZero,
                "short KDNET control response",
            ));
        }

        *write_lock(&self.state.peer)? = Some(source);
        *write_lock(&self.state.data_key)? = Some(data_key);
        self.state.version.store(version, Ordering::Relaxed);
        if rollover {
            self.state.generation.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Ask the target to offer now rather than on its three-second timer:
    /// kdnet.dll answers an empty control datagram with a poke of its own.
    fn poke(&self, target: SocketAddr, version: u8) -> io::Result<()> {
        let sequence = self.state.send_sequence.fetch_add(1, Ordering::Relaxed);
        let packet = create_packet(
            &[],
            sequence,
            CHANNEL_CONTROL,
            version,
            self.state.control_key,
            &self.state.hmac_key,
            true,
        )?;
        self.socket.send_to(&packet, target)?;
        Ok(())
    }

    /// Handle to the session generation, bumped on every rollover. The KD
    /// framing layer watches it to restart its packet-id stream for the
    /// rebooted target.
    pub fn session_generation(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.state.generation)
    }

    #[cfg(test)]
    fn local_addr(&self) -> SocketAddr {
        self.socket.local_addr().unwrap()
    }
}

impl Read for KdNetStream {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.inbound_offset == self.inbound.len() {
            self.receive_packet()?;
        }
        let count = output
            .len()
            .min(self.inbound.len().saturating_sub(self.inbound_offset));
        output[..count]
            .copy_from_slice(&self.inbound[self.inbound_offset..self.inbound_offset + count]);
        self.inbound_offset += count;
        if self.inbound_offset == self.inbound.len() {
            self.inbound.clear();
            self.inbound_offset = 0;
        }
        Ok(count)
    }
}
impl Write for KdNetStream {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.outbound.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.outbound.is_empty() {
            return Ok(());
        }

        let peer = *read_lock(&self.state.peer)?;
        let data_key = *read_lock(&self.state.data_key)?;
        let (Some(peer), Some(data_key)) = (peer, data_key) else {
            // The target initiates KDNET with a control poke, so nothing can
            // be sent yet. A break-in is kept for the moment a session exists;
            // anything else the initial handshake writes is a KDCOM stimulus
            // with no KDNET meaning.
            self.deferred_breakin |= self.outbound == [BREAKIN_BYTE];
            self.outbound.clear();
            return Ok(());
        };

        if self.outbound.len() >= 16
            && u32::from_le_bytes(self.outbound[..4].try_into().unwrap()) == DATA_PACKET_LEADER
        {
            let payload_len = u16::from_le_bytes(self.outbound[6..8].try_into().unwrap()) as usize;
            let expected = 16 + payload_len + 1;
            if self.outbound.len() != expected
                || self.outbound.last().copied() != Some(PACKET_TRAILING_BYTE)
            {
                self.outbound.clear();
                return Err(invalid_data("incomplete KDCOM data packet passed to KDNET"));
            }
            self.outbound.pop();
        }

        if self.outbound.len() >= 16 {
            let packet_id = u32::from_le_bytes(self.outbound[8..12].try_into().unwrap());
            let wire_checksum = u32::from_le_bytes(self.outbound[12..16].try_into().unwrap());
            let computed_checksum = self.outbound[16..]
                .iter()
                .fold(0u32, |sum, byte| sum.wrapping_add(*byte as u32));
            kd_trace!(
                "kdnet: send KD bytes={} id={packet_id:#x} checksum={wire_checksum:#x}/{computed_checksum:#x}",
                self.outbound.len()
            );
        }

        // Always mint a fresh sequence: the target treats a repeated KDNET
        // sequence as a duplicate to discard, so byte-identical replays would
        // never be re-examined after a RESEND.
        let sequence = self.state.send_sequence.fetch_add(1, Ordering::Relaxed);
        create_packet_into(
            &mut self.encoded,
            &self.outbound,
            sequence,
            CHANNEL_DATA,
            self.state.version.load(Ordering::Relaxed),
            data_key,
            &self.state.hmac_key,
            true,
        )?;
        let sent = self.socket.send_to(&self.encoded, peer)?;
        self.outbound.clear();
        if sent != self.encoded.len() {
            return Err(io::Error::new(
                ErrorKind::WriteZero,
                "short KDNET packet write",
            ));
        }
        Ok(())
    }
}

fn resolve_bind_addr(endpoint: &str) -> Result<SocketAddr> {
    endpoint
        .to_socket_addrs()
        .map_err(|err| Error::Kd(format!("invalid KDNET listen address '{endpoint}': {err}")))?
        .next()
        .ok_or_else(|| {
            Error::Kd(format!(
                "KDNET listen address '{endpoint}' resolved to nothing"
            ))
        })
}

fn parse_key(key: &str) -> Result<[u8; 32]> {
    let mut components = key.split('.');
    let mut decoded = [0u8; 32];
    for index in 0..4 {
        let component = components.next().ok_or_else(|| {
            Error::Kd(
                "invalid KDNET key: expected four base-36 components separated by periods".into(),
            )
        })?;
        if component.is_empty()
            || component.len() > 13
            || !component.bytes().all(|byte| byte.is_ascii_alphanumeric())
        {
            return Err(Error::Kd(format!(
                "invalid KDNET key component '{}': expected 1-13 base-36 characters",
                component
            )));
        }
        let normalized = component.to_ascii_lowercase();
        let value = u64::from_str_radix(&normalized, 36).map_err(|_| {
            Error::Kd(format!(
                "invalid KDNET key component '{}': value exceeds 64 bits",
                component
            ))
        })?;
        decoded[index * 8..index * 8 + 8].copy_from_slice(&value.to_le_bytes());
    }
    if components.next().is_some() {
        return Err(Error::Kd(
            "invalid KDNET key: expected four base-36 components separated by periods".into(),
        ));
    }
    Ok(decoded)
}

fn create_packet(
    kd_packet: &[u8],
    sequence: u64,
    channel: u8,
    version: u8,
    key: [u8; 32],
    hmac_key: &[u8; 32],
    from_host: bool,
) -> io::Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(MAX_DATAGRAM_SIZE);
    create_packet_into(
        &mut packet,
        kd_packet,
        sequence,
        channel,
        version,
        key,
        hmac_key,
        from_host,
    )?;
    Ok(packet)
}

fn create_packet_into(
    packet: &mut Vec<u8>,
    kd_packet: &[u8],
    sequence: u64,
    channel: u8,
    version: u8,
    key: [u8; 32],
    hmac_key: &[u8; 32],
    from_host: bool,
) -> io::Result<()> {
    let padding = (16 - ((METADATA_SIZE + kd_packet.len()) % 16)) % 16;
    let authenticated_len = HEADER_SIZE + METADATA_SIZE + kd_packet.len() + padding;
    packet.clear();
    packet.resize(authenticated_len + AUTH_TAG_SIZE, 0);
    packet[..4].copy_from_slice(MAGIC);
    packet[4] = version;
    packet[5] = channel;
    let metadata = (sequence << 8) | if from_host { HOST_DIRECTION } else { 0 } | padding as u64;
    packet[HEADER_SIZE..HEADER_SIZE + 8].copy_from_slice(&metadata.to_be_bytes());
    packet[HEADER_SIZE + METADATA_SIZE..HEADER_SIZE + METADATA_SIZE + kd_packet.len()]
        .copy_from_slice(kd_packet);

    let mut mac = HmacSha256::new_from_slice(hmac_key)
        .map_err(|_| io::Error::other("invalid KDNET HMAC key"))?;
    mac.update(&packet[..authenticated_len]);
    let tag = mac.finalize().into_bytes();
    packet[authenticated_len..].copy_from_slice(&tag[..AUTH_TAG_SIZE]);

    let (encrypted, tag) = packet[HEADER_SIZE..].split_at_mut(authenticated_len - HEADER_SIZE);
    Aes256CbcEncryptor::new((&key).into(), (&tag[..AUTH_TAG_SIZE]).into())
        .encrypt_padded_mut::<NoPadding>(encrypted, encrypted.len())
        .map_err(|_| io::Error::other("KDNET encryption failed"))?;
    Ok(())
}

fn decrypt_payload(packet: &mut [u8], key: [u8; 32]) -> io::Result<()> {
    let encrypted_len = packet
        .len()
        .checked_sub(HEADER_SIZE + AUTH_TAG_SIZE)
        .filter(|len| *len != 0 && len.is_multiple_of(16))
        .ok_or_else(|| invalid_data("KDNET encrypted payload is not block-aligned"))?;
    let (encrypted, tag) = packet[HEADER_SIZE..].split_at_mut(encrypted_len);
    Aes256CbcDecryptor::new((&key).into(), (&tag[..AUTH_TAG_SIZE]).into())
        .decrypt_padded_mut::<NoPadding>(encrypted)
        .map_err(|_| invalid_data("KDNET decryption failed"))?;
    Ok(())
}

fn verify_authentication(packet: &[u8], hmac_key: &[u8; 32]) -> io::Result<()> {
    let authenticated_len = packet
        .len()
        .checked_sub(AUTH_TAG_SIZE)
        .ok_or_else(|| invalid_data("truncated KDNET authentication tag"))?;
    let mut mac = HmacSha256::new_from_slice(hmac_key)
        .map_err(|_| io::Error::other("invalid KDNET HMAC key"))?;
    mac.update(&packet[..authenticated_len]);
    let expected = mac.finalize().into_bytes();
    if bool::from(expected[..AUTH_TAG_SIZE].ct_eq(&packet[authenticated_len..])) {
        Ok(())
    } else {
        Err(invalid_data("KDNET packet authentication failed"))
    }
}

fn read_lock<T>(lock: &RwLock<T>) -> io::Result<std::sync::RwLockReadGuard<'_, T>> {
    lock.read()
        .map_err(|_| io::Error::other("KDNET session lock poisoned"))
}

fn write_lock<T>(lock: &RwLock<T>) -> io::Result<std::sync::RwLockWriteGuard<'_, T>> {
    lock.write()
        .map_err(|_| io::Error::other("KDNET session lock poisoned"))
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kd::framing::KdFraming;
    use crate::kd::transport::KdTransport;

    /// Body size of the poke kdnet.dll sends.
    const POKE_SIZE: usize = 344;

    fn test_keys() -> ([u8; 32], [u8; 32]) {
        let key = parse_key("1.2.3.4").unwrap();
        let mut hmac_key = key;
        hmac_key.iter_mut().for_each(|byte| *byte = !*byte);
        (key, hmac_key)
    }

    /// A poke from a target with no data channel: the host-port field is zero.
    fn poke_datagram(
        client_byte: u8,
        sequence: u64,
        key: [u8; 32],
        hmac_key: &[u8; 32],
    ) -> Vec<u8> {
        keepalive_datagram(client_byte, sequence, 0, key, hmac_key)
    }

    /// A poke from a target whose data channel is bound to `host_port`.
    fn keepalive_datagram(
        client_byte: u8,
        sequence: u64,
        host_port: u16,
        key: [u8; 32],
        hmac_key: &[u8; 32],
    ) -> Vec<u8> {
        let mut body = [0u8; POKE_SIZE];
        body[0] = 1;
        body[1] = 1;
        body[2..34].fill(client_byte);
        body[POKE_HOST_PORT_OFFSET..POKE_HOST_PORT_OFFSET + 2]
            .copy_from_slice(&host_port.to_be_bytes());
        create_packet(&body, sequence, CHANNEL_CONTROL, 5, key, hmac_key, false).unwrap()
    }

    fn kd_data_packet(payload: &[u8]) -> Vec<u8> {
        kd_data_packet_with_id(0x8080_0000, payload)
    }

    fn kd_data_packet_with_id(packet_id: u32, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 16];
        packet[..4].copy_from_slice(&DATA_PACKET_LEADER.to_le_bytes());
        packet[4..6].copy_from_slice(&7u16.to_le_bytes());
        packet[6..8].copy_from_slice(&(payload.len() as u16).to_le_bytes());
        packet[8..12].copy_from_slice(&packet_id.to_le_bytes());
        let checksum = payload
            .iter()
            .fold(0u32, |sum, b| sum.wrapping_add(*b as u32));
        packet[12..16].copy_from_slice(&checksum.to_le_bytes());
        packet.extend_from_slice(payload);
        packet
    }

    fn recv_datagram(socket: &UdpSocket) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];
        let (len, _) = socket.recv_from(&mut buf).ok()?;
        buf.truncate(len);
        Some(buf)
    }

    /// Decrypt, authenticate and unpad a KDNET datagram, yielding its payload.
    fn open_datagram(mut datagram: Vec<u8>, key: [u8; 32], hmac_key: &[u8; 32]) -> Option<Vec<u8>> {
        decrypt_payload(&mut datagram, key).ok()?;
        verify_authentication(&datagram, hmac_key).ok()?;
        let metadata =
            u64::from_be_bytes(datagram[HEADER_SIZE..HEADER_SIZE + 8].try_into().unwrap());
        let padding = (metadata & 0x0f) as usize;
        let end = datagram.len() - AUTH_TAG_SIZE - padding;
        Some(datagram[HEADER_SIZE + METADATA_SIZE..end].to_vec())
    }

    fn derive_data_key(control_key: [u8; 32], host_response: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(control_key);
        hasher.update(host_response);
        hasher.finalize().into()
    }

    #[test]
    fn parses_four_little_endian_base36_key_components() {
        let key = parse_key("1.z.10.3w5e11264sgsf").unwrap();
        assert_eq!(u64::from_le_bytes(key[0..8].try_into().unwrap()), 1);
        assert_eq!(u64::from_le_bytes(key[8..16].try_into().unwrap()), 35);
        assert_eq!(u64::from_le_bytes(key[16..24].try_into().unwrap()), 36);
        assert_eq!(
            u64::from_le_bytes(key[24..32].try_into().unwrap()),
            u64::MAX
        );
    }

    #[test]
    fn rejects_malformed_keys() {
        for key in [
            "1.2.3",
            "1.2.3.4.5",
            "1..3.4",
            "1.2.3.!",
            "1.2.3.3w5e11264sgsg",
        ] {
            assert!(parse_key(key).is_err(), "accepted {key}");
        }
    }

    #[test]
    fn packet_round_trip_authenticates_and_decrypts() {
        let (key, hmac_key) = test_keys();
        let payload = b"0000kd-payload";
        let mut packet = create_packet(payload, 7, CHANNEL_DATA, 5, key, &hmac_key, true).unwrap();
        decrypt_payload(&mut packet, key).unwrap();
        verify_authentication(&packet, &hmac_key).unwrap();
        let metadata = u64::from_be_bytes(packet[6..14].try_into().unwrap());
        let padding = (metadata & 0x0f) as usize;
        assert_eq!(&packet[14..packet.len() - AUTH_TAG_SIZE - padding], payload);
        assert_eq!(metadata >> 8, 7);
        assert_ne!(metadata & HOST_DIRECTION, 0);
    }

    #[test]
    fn negotiates_session_and_bridges_kd_stream_over_udp() {
        let (key, hmac_key) = test_keys();
        let mut host = KdNetStream::bind("127.0.0.1:0", "1.2.3.4").unwrap();
        host.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let host_addr = host.local_addr();
        let target = UdpSocket::bind("127.0.0.1:0").unwrap();
        target
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let mut kd_packet = vec![0u8; 19];
        kd_packet[..4].copy_from_slice(&DATA_PACKET_LEADER.to_le_bytes());
        kd_packet[4..6].copy_from_slice(&7u16.to_le_bytes());
        kd_packet[6..8].copy_from_slice(&3u16.to_le_bytes());
        kd_packet[8..12].copy_from_slice(&0x8080_0000u32.to_le_bytes());
        kd_packet[12..16].copy_from_slice(&6u32.to_le_bytes());
        kd_packet[16..].copy_from_slice(&[1, 2, 3]);
        let target_kd_packet = kd_packet.clone();

        let target_thread = std::thread::spawn(move || -> io::Result<Vec<u8>> {
            let mut poke = [0u8; POKE_SIZE];
            poke[0] = 1;
            poke[1] = 1;
            for (index, byte) in poke[2..34].iter_mut().enumerate() {
                *byte = index as u8;
            }
            let control = create_packet(&poke, 9, CHANNEL_CONTROL, 5, key, &hmac_key, false)?;
            target.send_to(&control, host_addr)?;

            let mut response = vec![0u8; MAX_DATAGRAM_SIZE];
            let (response_len, _) = target.recv_from(&mut response)?;
            response.truncate(response_len);
            decrypt_payload(&mut response, key)?;
            verify_authentication(&response, &hmac_key)?;
            let metadata = u64::from_be_bytes(response[6..14].try_into().unwrap());
            assert_ne!(metadata & HOST_DIRECTION, 0);
            assert_eq!(metadata >> 8, 9);
            let padding = (metadata & 0x0f) as usize;
            let body = &response[14..response.len() - AUTH_TAG_SIZE - padding];
            assert_eq!(body.len(), CONTROL_RESPONSE_SIZE);
            assert_eq!(&body[2..34], &poke[2..34]);

            let mut hasher = Sha256::new();
            hasher.update(key);
            hasher.update(body);
            let data_key: [u8; 32] = hasher.finalize().into();
            // Once the target holds a data channel, its pokes name the host
            // port and must be left unanswered.
            let mut periodic_poke = poke;
            periodic_poke[POKE_HOST_PORT_OFFSET..POKE_HOST_PORT_OFFSET + 2]
                .copy_from_slice(&host_addr.port().to_be_bytes());
            let periodic = create_packet(
                &periodic_poke,
                10,
                CHANNEL_CONTROL,
                5,
                key,
                &hmac_key,
                false,
            )?;
            target.send_to(&periodic, host_addr)?;
            let data = create_packet(
                &target_kd_packet,
                1,
                CHANNEL_DATA,
                5,
                data_key,
                &hmac_key,
                false,
            )?;
            target.send_to(&data, host_addr)?;

            let mut outbound = vec![0u8; MAX_DATAGRAM_SIZE];
            let (outbound_len, _) = target.recv_from(&mut outbound)?;
            outbound.truncate(outbound_len);
            decrypt_payload(&mut outbound, data_key)?;
            verify_authentication(&outbound, &hmac_key)?;
            let metadata = u64::from_be_bytes(outbound[6..14].try_into().unwrap());
            assert_ne!(metadata & HOST_DIRECTION, 0);
            let padding = (metadata & 0x0f) as usize;
            Ok(outbound[14..outbound.len() - AUTH_TAG_SIZE - padding].to_vec())
        });

        let mut bridged = vec![0u8; kd_packet.len() + 1];
        host.read_exact(&mut bridged).unwrap();
        assert_eq!(&bridged[..kd_packet.len()], kd_packet);
        assert_eq!(bridged.last().copied(), Some(PACKET_TRAILING_BYTE));
        assert_eq!(host.received_datagrams(), 3);
        host.write_all(&bridged).unwrap();
        host.flush().unwrap();
        assert_eq!(target_thread.join().unwrap().unwrap(), kd_packet);
    }

    #[test]
    fn resend_mints_fresh_sequence_with_same_kd_payload() {
        let mut host = KdNetStream::bind("127.0.0.1:0", "1.2.3.4").unwrap();
        let (key2, _) = test_keys();
        let target = UdpSocket::bind("127.0.0.1:0").unwrap();
        target
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        *write_lock(&host.state.peer).unwrap() = Some(target.local_addr().unwrap());
        *write_lock(&host.state.data_key).unwrap() = Some(key2);
        host.state.version.store(5, Ordering::Relaxed);

        let mut kd_packet = vec![0u8; 17];
        kd_packet[..4].copy_from_slice(&DATA_PACKET_LEADER.to_le_bytes());
        kd_packet[4..6].copy_from_slice(&2u16.to_le_bytes());
        kd_packet[8..12].copy_from_slice(&0x8080_0000u32.to_le_bytes());
        kd_packet[16] = PACKET_TRAILING_BYTE;

        host.write_all(&kd_packet).unwrap();
        host.flush().unwrap();
        let mut first = vec![0u8; MAX_DATAGRAM_SIZE];
        let (first_len, _) = target.recv_from(&mut first).unwrap();
        first.truncate(first_len);

        host.write_all(&kd_packet).unwrap();
        host.flush().unwrap();
        let mut second = vec![0u8; MAX_DATAGRAM_SIZE];
        let (second_len, _) = target.recv_from(&mut second).unwrap();
        second.truncate(second_len);

        // Fresh sequence: datagrams differ, but decrypt to the same KD payload.
        assert_ne!(second, first);
        assert_eq!(host.state.send_sequence.load(Ordering::Relaxed), 3);
        for pkt in [&mut first, &mut second] {
            decrypt_payload(pkt, key2).unwrap();
            verify_authentication(pkt, &host.state.hmac_key).unwrap();
            assert_eq!(
                &pkt[HEADER_SIZE + METADATA_SIZE..HEADER_SIZE + METADATA_SIZE + 16],
                &kd_packet[..16]
            );
        }
    }

    /// A rebooted target has no data channel, so its pokes carry no host
    /// port. Answering the first one rolls the session over instead of
    /// forcing the user to reattach.
    #[test]
    fn reboot_pokes_roll_the_session_over_and_restore_kd_traffic() {
        let (key, hmac_key) = test_keys();
        let mut host = KdNetStream::bind("127.0.0.1:0", "1.2.3.4").unwrap();
        host.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let host_addr = host.local_addr();
        let target = UdpSocket::bind("127.0.0.1:0").unwrap();
        target
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let before_reboot = kd_data_packet(b"pre");
        let after_reboot = kd_data_packet(b"post");
        let expected_before = before_reboot.clone();
        let expected_after = after_reboot.clone();

        let target_thread = std::thread::spawn(move || {
            target
                .send_to(&poke_datagram(0x11, 9, key, &hmac_key), host_addr)
                .unwrap();
            let response = recv_datagram(&target).expect("first poke answered");
            let first_key = derive_data_key(key, &open_datagram(response, key, &hmac_key).unwrap());
            let data = create_packet(
                &before_reboot,
                1,
                CHANNEL_DATA,
                5,
                first_key,
                &hmac_key,
                false,
            )
            .unwrap();
            target.send_to(&data, host_addr).unwrap();
            // The host request this target will never answer: it reboots here.
            let request = recv_datagram(&target).expect("host request");
            open_datagram(request, first_key, &hmac_key).expect("host used the session key");

            target
                .send_to(&poke_datagram(0x22, 1, key, &hmac_key), host_addr)
                .unwrap();
            let response = recv_datagram(&target).expect("reboot poke answered");
            let rolled = derive_data_key(key, &open_datagram(response, key, &hmac_key).unwrap());
            assert_ne!(rolled, first_key, "rollover must mint a new data key");
            let data =
                create_packet(&after_reboot, 1, CHANNEL_DATA, 5, rolled, &hmac_key, false).unwrap();
            target.send_to(&data, host_addr).unwrap();
        });

        let mut bridged = vec![0u8; expected_before.len() + 1];
        host.read_exact(&mut bridged).unwrap();
        assert_eq!(&bridged[..expected_before.len()], &expected_before[..]);
        host.write_all(&bridged).unwrap();
        host.flush().unwrap();

        let mut post_reboot = vec![0u8; expected_after.len() + 1];
        host.read_exact(&mut post_reboot).unwrap();
        assert_eq!(&post_reboot[..expected_after.len()], &expected_after[..]);
        assert_eq!(
            host.session_generation().load(Ordering::Relaxed),
            1,
            "a rollover tells the KD layer to restart its packet ids"
        );
        target_thread.join().unwrap();
    }

    /// A target that accepted a response pokes on regardless, naming the host
    /// port its data channel is bound to. Those are keepalives: answering one
    /// would rekey the target under a working session, and the target need not
    /// have sent any data yet for the session to be working.
    #[test]
    fn keepalive_pokes_from_a_connected_target_are_not_answered() {
        let (key, hmac_key) = test_keys();
        let mut host = KdNetStream::bind("127.0.0.1:0", "1.2.3.4").unwrap();
        host.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let host_addr = host.local_addr();
        let target = UdpSocket::bind("127.0.0.1:0").unwrap();
        target
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();

        let state_change = kd_data_packet(b"boot");
        let expected = state_change.clone();

        let target_thread = std::thread::spawn(move || {
            target
                .send_to(&poke_datagram(0x11, 1, key, &hmac_key), host_addr)
                .unwrap();
            let response = recv_datagram(&target).expect("first poke answered");
            let accepted = derive_data_key(key, &open_datagram(response, key, &hmac_key).unwrap());

            let mut answered = 0usize;
            for sequence in 2..=5 {
                target
                    .send_to(
                        &keepalive_datagram(0x11, sequence, host_addr.port(), key, &hmac_key),
                        host_addr,
                    )
                    .unwrap();
                if recv_datagram(&target).is_some() {
                    answered += 1;
                }
            }

            // KD comes up, still using the key accepted at the start.
            target
                .send_to(
                    &create_packet(
                        &state_change,
                        1,
                        CHANNEL_DATA,
                        5,
                        accepted,
                        &hmac_key,
                        false,
                    )
                    .unwrap(),
                    host_addr,
                )
                .unwrap();
            (accepted, answered)
        });

        let mut bridged = vec![0u8; expected.len() + 1];
        host.read_exact(&mut bridged).unwrap();
        assert_eq!(&bridged[..expected.len()], &expected[..]);
        let (accepted, answered) = target_thread.join().unwrap();
        assert_eq!(answered, 0, "keepalive pokes must not be answered");
        assert_eq!(*read_lock(&host.state.data_key).unwrap(), Some(accepted));
        assert_eq!(host.session_generation().load(Ordering::Relaxed), 0);
    }

    /// A restarted target keeps its address and changes only its source port.
    /// A poke from another host is another machine, such as a second guest
    /// sharing one KDNET key, and must not take a live session from its owner.
    #[test]
    fn pokes_from_another_host_cannot_take_over_the_session() {
        let (key, hmac_key) = test_keys();
        let mut host = KdNetStream::bind("127.0.0.1:0", "1.2.3.4").unwrap();
        // Short enough that each read below returns after servicing the poke
        // it was woken for.
        host.set_read_timeout(Some(Duration::from_millis(80)))
            .unwrap();
        let host_addr = host.local_addr();
        let owner = UdpSocket::bind("127.0.0.1:0").unwrap();
        owner
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let stranger = UdpSocket::bind("127.0.0.2:0").unwrap();
        stranger
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut scratch = [0u8; 8];

        owner
            .send_to(&poke_datagram(0x11, 9, key, &hmac_key), host_addr)
            .unwrap();
        assert!(host.read(&mut scratch).is_err(), "poke yields no KD bytes");
        let response = recv_datagram(&owner).expect("first poke answered");
        let owner_key = derive_data_key(key, &open_datagram(response, key, &hmac_key).unwrap());
        let owner_packet = kd_data_packet(b"owner");
        owner
            .send_to(
                &create_packet(
                    &owner_packet,
                    1,
                    CHANNEL_DATA,
                    5,
                    owner_key,
                    &hmac_key,
                    false,
                )
                .unwrap(),
                host_addr,
            )
            .unwrap();
        let mut bridged = vec![0u8; owner_packet.len() + 1];
        host.read_exact(&mut bridged).unwrap();

        // A second machine with the same key and no data channel pokes.
        for sequence in 1..=2 {
            stranger
                .send_to(&poke_datagram(0x22, sequence, key, &hmac_key), host_addr)
                .unwrap();
            let _ = host.read(&mut scratch);
        }

        assert!(
            recv_datagram(&stranger).is_none(),
            "a stranger's pokes must go unanswered"
        );
        assert_eq!(*read_lock(&host.state.data_key).unwrap(), Some(owner_key));
        assert_eq!(host.session_generation().load(Ordering::Relaxed), 0);

        owner
            .send_to(
                &create_packet(
                    &owner_packet,
                    2,
                    CHANNEL_DATA,
                    5,
                    owner_key,
                    &hmac_key,
                    false,
                )
                .unwrap(),
                host_addr,
            )
            .unwrap();
        host.read_exact(&mut bridged).unwrap();
        assert_eq!(&bridged[..owner_packet.len()], &owner_packet[..]);
    }

    /// The initial handshake writes its break-in before any target has poked.
    /// It cannot go anywhere yet, but it must go out as soon as the session
    /// exists, not on the handshake's next attempt seconds later.
    #[test]
    fn break_in_written_before_negotiation_is_sent_once_the_session_exists() {
        let (key, hmac_key) = test_keys();
        let mut host = KdNetStream::bind("127.0.0.1:0", "1.2.3.4").unwrap();
        host.set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let host_addr = host.local_addr();
        let target = UdpSocket::bind("127.0.0.1:0").unwrap();
        target
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        host.write_all(&[BREAKIN_BYTE]).unwrap();
        host.flush().unwrap();

        target
            .send_to(&poke_datagram(0x11, 1, key, &hmac_key), host_addr)
            .unwrap();
        let mut scratch = [0u8; 8];
        assert!(host.read(&mut scratch).is_err(), "poke yields no KD bytes");

        // The first datagram the target sees is the response, not the break-in.
        let response = recv_datagram(&target).expect("poke answered");
        let data_key = derive_data_key(key, &open_datagram(response, key, &hmac_key).unwrap());
        let breakin = recv_datagram(&target).expect("deferred break-in sent");
        assert_eq!(breakin[5], CHANNEL_DATA);
        assert_eq!(
            open_datagram(breakin, data_key, &hmac_key).unwrap(),
            [BREAKIN_BYTE]
        );
    }

    /// A target still sending data for a session this listener does not hold
    /// would offer on its own timer within three seconds; an empty control
    /// datagram from the host makes kdnet.dll offer immediately.
    #[test]
    fn stale_data_before_negotiation_is_answered_with_a_host_poke() {
        let (key, hmac_key) = test_keys();
        let mut host = KdNetStream::bind("127.0.0.1:0", "1.2.3.4").unwrap();
        host.set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let host_addr = host.local_addr();
        let target = UdpSocket::bind("127.0.0.1:0").unwrap();
        target
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let stale = create_packet(
            &kd_data_packet(b"old"),
            7,
            CHANNEL_DATA,
            5,
            [0x42; 32],
            &hmac_key,
            false,
        )
        .unwrap();
        target.send_to(&stale, host_addr).unwrap();
        let mut scratch = [0u8; 8];
        assert!(
            host.read(&mut scratch).is_err(),
            "stale data yields no KD bytes"
        );

        let poke = recv_datagram(&target).expect("host poked the target");
        assert_eq!(poke[5], CHANNEL_CONTROL);
        assert_eq!(poke[4], 5, "the poke echoes the target's version");
        let mut poke = poke;
        decrypt_payload(&mut poke, key).unwrap();
        verify_authentication(&poke, &hmac_key).unwrap();
        let metadata = u64::from_be_bytes(poke[HEADER_SIZE..HEADER_SIZE + 8].try_into().unwrap());
        assert_ne!(metadata & HOST_DIRECTION, 0);
        assert_eq!(
            poke.len(),
            HEADER_SIZE + METADATA_SIZE + 8 + AUTH_TAG_SIZE,
            "an empty body pads to one block"
        );
        assert_eq!(metadata & 0x0f, 8);
    }

    /// The whole reattach path, transport and KD framing together: a target
    /// that restarts under the listener renegotiates and then resumes KD with
    /// a packet-id stream that begins again. The framing layer must adopt the
    /// new session before judging the first post-reboot packet, otherwise its
    /// low id is rejected as a duplicate of the old stream.
    #[test]
    fn rolled_over_session_is_adopted_by_the_kd_framing_layer() {
        let (key, hmac_key) = test_keys();
        let host = KdNetStream::bind("127.0.0.1:0", "1.2.3.4").unwrap();
        let host_addr = host.local_addr();
        let generation = host.session_generation();
        let mut framing = KdFraming::new(KdTransport::Network(host));
        framing.use_kdnet_packet_ids(Arc::clone(&generation));
        framing
            .transport_mut()
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let target = UdpSocket::bind("127.0.0.1:0").unwrap();
        target
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        // The old session runs its packet ids up high; the restarted target
        // starts over from a low id.
        let before = kd_data_packet_with_id(0x2_f000, b"before");
        let after = kd_data_packet_with_id(0x4, b"after");

        let target_thread = std::thread::spawn(move || {
            let negotiate = |client_byte: u8| -> [u8; 32] {
                target
                    .send_to(&poke_datagram(client_byte, 1, key, &hmac_key), host_addr)
                    .unwrap();
                let response = recv_datagram(&target).expect("poke answered");
                derive_data_key(key, &open_datagram(response, key, &hmac_key).unwrap())
            };

            let first_key = negotiate(0x11);
            target
                .send_to(
                    &create_packet(&before, 1, CHANNEL_DATA, 5, first_key, &hmac_key, false)
                        .unwrap(),
                    host_addr,
                )
                .unwrap();
            recv_datagram(&target).expect("framing ACKs the pre-reboot packet");

            let rolled = negotiate(0x22);
            target
                .send_to(
                    &create_packet(&after, 1, CHANNEL_DATA, 5, rolled, &hmac_key, false).unwrap(),
                    host_addr,
                )
                .unwrap();
            recv_datagram(&target).expect("framing ACKs the post-reboot packet");
        });

        assert_eq!(framing.recv_data().unwrap().payload, b"before");
        assert!(!framing.take_peer_reset_seen());

        let after_reboot = framing.recv_data().unwrap();
        assert_eq!(
            after_reboot.payload, b"after",
            "the restarted target's low packet id must not look like a duplicate"
        );
        assert!(
            framing.take_peer_reset_seen(),
            "a rolled-over session is a target reload"
        );
        assert_eq!(generation.load(Ordering::Relaxed), 1);
        target_thread.join().unwrap();
    }

    #[test]
    fn listener_binds_requested_udp_endpoint() {
        let stream = KdNetStream::bind("127.0.0.1:0", "1.2.3.4").unwrap();
        assert!(stream.local_addr().port() != 0);
    }
}
