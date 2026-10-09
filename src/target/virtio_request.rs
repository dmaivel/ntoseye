//! What a virtqueue buffer asks the device to do, and what the device
//! answered, decoded from the request and response layouts the virtio
//! specification fixes for each device type. They are the device's wire
//! format, not the driver's, so they need no PDB and read the same for any
//! driver.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::backend::MemoryOps;
use crate::target::Target;
use crate::target::virtio::{VRING_DESC_F_INDIRECT, VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};

/// How many bytes of each direction of a request are read for decoding.
const HEAD_BYTES: usize = 128;
/// The most buffers one request is expanded to, indirect tables included.
const MAX_SEGMENTS: usize = 4096;

/// What a queue's buffers hold, which decides how they are read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    Block,
    ScsiRequest,
    ScsiControl,
    ScsiEvent,
    /// A packet on a virtio-net data queue, behind its `virtio_net_hdr`,
    /// which is 12 bytes on a modern device and 10 on a legacy one.
    NetPacket {
        modern: bool,
    },
    NetControl,
    Gpu,
    Vsock,
}

impl RequestKind {
    /// The name `!vring /r ... /t` takes for it ([`request_kind_named`]).
    pub fn name(self) -> &'static str {
        match self {
            RequestKind::Block => "blk",
            RequestKind::ScsiRequest => "scsi",
            RequestKind::ScsiControl => "scsi-control",
            RequestKind::ScsiEvent => "scsi-event",
            RequestKind::NetPacket { .. } => "net",
            RequestKind::NetControl => "net-control",
            RequestKind::Gpu => "gpu",
            RequestKind::Vsock => "vsock",
        }
    }
}

/// What the buffers of queue `index` of a device of type `virtio_id` with
/// `queues` queues hold. `transitional` devices may use the legacy header.
pub fn request_kind(
    virtio_id: u16,
    index: u32,
    queues: u32,
    transitional: bool,
) -> Option<RequestKind> {
    Some(match (virtio_id, index) {
        (1, _) if queues % 2 == 1 && index == queues - 1 => RequestKind::NetControl,
        (1, _) => RequestKind::NetPacket {
            modern: !transitional,
        },
        (2, _) => RequestKind::Block,
        (8, 0) => RequestKind::ScsiControl,
        (8, 1) => RequestKind::ScsiEvent,
        (8, _) => RequestKind::ScsiRequest,
        (16, 0 | 1) => RequestKind::Gpu,
        (19, 0 | 1) => RequestKind::Vsock,
        _ => return None,
    })
}

/// The kind a `/t` name gives `!vring /r`.
pub fn request_kind_named(name: &str) -> Option<RequestKind> {
    Some(match name {
        "blk" | "block" => RequestKind::Block,
        "scsi" => RequestKind::ScsiRequest,
        "scsi-control" => RequestKind::ScsiControl,
        "scsi-event" => RequestKind::ScsiEvent,
        "net" => RequestKind::NetPacket { modern: true },
        "net-control" => RequestKind::NetControl,
        "gpu" => RequestKind::Gpu,
        "vsock" => RequestKind::Vsock,
        _ => return None,
    })
}

/// One buffer of a request: its guest-physical address and length, and
/// whether the device writes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    pub addr: u64,
    pub len: u32,
    pub device_writes: bool,
}

/// The entries of an indirect table `table`, as (address, length, flags):
/// a packed ring's in order, a split ring's along their `next` links from
/// the first.
pub fn indirect_entries(table: &[u8], packed: bool) -> Vec<(u64, u32, u16)> {
    let entries = table.as_chunks::<16>().0;
    let entry = |bytes: &[u8; 16]| {
        let addr = u64::from_le_bytes(bytes[0..8].try_into().unwrap_or_default());
        let len = u32::from_le_bytes(bytes[8..12].try_into().unwrap_or_default());
        let flags_at = if packed { 14 } else { 12 };
        let flags = u16::from_le_bytes([bytes[flags_at], bytes[flags_at + 1]]);
        (addr, len, flags)
    };
    if packed {
        return entries.iter().map(entry).collect();
    }
    let mut out = Vec::new();
    let mut index = 0usize;
    while let Some(bytes) = entries.get(index) {
        let (addr, len, flags) = entry(bytes);
        out.push((addr, len, flags));
        if flags & VRING_DESC_F_NEXT == 0 || out.len() >= entries.len() {
            break;
        }
        index = usize::from(u16::from_le_bytes([bytes[14], bytes[15]]));
    }
    out
}

/// What was read of a request: the start of what the driver wrote and of
/// what the device writes, each across its buffers, with their totals.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestBytes {
    pub out_head: Vec<u8>,
    pub out_total: u64,
    pub in_head: Vec<u8>,
    pub in_total: u64,
    /// The last byte the device writes, where virtio-blk and virtio-net's
    /// control queue put their status.
    pub in_last: Option<u8>,
    /// The length of the request's first buffer, which on virtio-net is
    /// the packet header alone when the driver keeps it apart.
    pub first_len: Option<u32>,
    /// The bytes the device said it wrote, for a returned buffer.
    pub written: Option<u32>,
}

/// Gather `segments` into [`RequestBytes`], reading guest-physical memory
/// through `read`.
pub fn gather(
    segments: &[Segment],
    written: Option<u32>,
    read: impl Fn(u64, &mut [u8]) -> bool,
) -> RequestBytes {
    let mut bytes = RequestBytes {
        first_len: segments.first().map(|segment| segment.len),
        written,
        ..Default::default()
    };
    for segment in segments {
        let (head, total) = if segment.device_writes {
            (&mut bytes.in_head, &mut bytes.in_total)
        } else {
            (&mut bytes.out_head, &mut bytes.out_total)
        };
        *total += u64::from(segment.len);
        let want = (HEAD_BYTES - head.len()).min(segment.len as usize);
        if want > 0 {
            let mut chunk = vec![0u8; want];
            if read(segment.addr, &mut chunk) {
                head.extend_from_slice(&chunk);
            }
        }
    }
    if let Some(last) = segments.iter().rev().find(|segment| segment.device_writes)
        && last.len > 0
    {
        let mut byte = [0u8; 1];
        if read(last.addr + u64::from(last.len) - 1, &mut byte) {
            bytes.in_last = Some(byte[0]);
        }
    }
    bytes
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

fn be(bytes: &[u8], at: usize, len: usize) -> Option<u64> {
    Some(
        bytes
            .get(at..at + len)?
            .iter()
            .fold(0u64, |value, byte| value << 8 | u64::from(*byte)),
    )
}

/// A size in bytes, in the largest unit that keeps it whole or to one
/// decimal.
pub fn size_text(bytes: u64) -> String {
    const UNITS: [(u64, &str); 3] = [(1 << 30, "GiB"), (1 << 20, "MiB"), (1 << 10, "KiB")];
    for (unit, name) in UNITS {
        if bytes >= unit {
            return if bytes.is_multiple_of(unit) {
                format!("{} {name}", bytes / unit)
            } else {
                format!("{:.1} {name}", bytes as f64 / unit as f64)
            };
        }
    }
    format!("{bytes} bytes")
}

/// One line saying what the request asks and, once the device `returned`
/// it, what it answered. `None` when the bytes do not hold the request.
pub fn describe(kind: RequestKind, bytes: &RequestBytes, returned: bool) -> Option<String> {
    let (request, outcome) = match kind {
        RequestKind::Block => block(bytes)?,
        RequestKind::ScsiRequest => scsi_request(bytes)?,
        RequestKind::ScsiControl => scsi_control(bytes)?,
        RequestKind::ScsiEvent => (scsi_event(&bytes.in_head)?, None),
        RequestKind::NetPacket { modern } => (net_packet(bytes, modern, returned)?, None),
        RequestKind::NetControl => net_control(bytes)?,
        RequestKind::Gpu => gpu(bytes)?,
        RequestKind::Vsock => (vsock(bytes, returned)?, None),
    };
    Some(match (returned, outcome) {
        (true, Some(outcome)) => format!("{request} -> {outcome}"),
        _ => request,
    })
}

type Decoded = (String, Option<String>);

/// `virtio_blk_req`: the type and sector, the data, and the status byte
/// the device writes last.
fn block(bytes: &RequestBytes) -> Option<Decoded> {
    let kind = u32_at(&bytes.out_head, 0)?;
    let sector = u64_at(&bytes.out_head, 8)?;
    let status = || {
        Some(
            match bytes.in_last? {
                0 => "OK",
                1 => "IOERR",
                2 => "UNSUPP",
                _ => return bytes.in_last.map(|code| format!("status {code:#x}")),
            }
            .to_string(),
        )
    };
    let request = match kind {
        0 => format!(
            "blk read sector {sector:#x}, {}",
            size_text(bytes.in_total.saturating_sub(1))
        ),
        1 => format!(
            "blk write sector {sector:#x}, {}",
            size_text(bytes.out_total.saturating_sub(16))
        ),
        4 => "blk flush".to_string(),
        8 => "blk get id".to_string(),
        10 => "blk get lifetime".to_string(),
        11 | 13 | 14 => {
            let name = match kind {
                11 => "discard",
                13 => "write zeroes",
                _ => "secure erase",
            };
            let ranges = bytes.out_total.saturating_sub(16) / 16;
            match (u64_at(&bytes.out_head, 16), u32_at(&bytes.out_head, 24)) {
                (Some(first), Some(sectors)) => format!(
                    "blk {name} sector {first:#x}, {sectors} sectors{}",
                    if ranges > 1 {
                        format!(" (+{} more ranges)", ranges - 1)
                    } else {
                        String::new()
                    }
                ),
                _ => format!("blk {name}"),
            }
        }
        other => format!("blk type {other}"),
    };
    Some((request, status()))
}

/// A SCSI command's name and, for one that addresses blocks, its LBA and
/// block count.
pub fn scsi_command(cdb: &[u8]) -> Option<String> {
    let opcode = *cdb.first()?;
    let blocks = |name: &str, lba: Option<u64>, count: Option<u64>| match (lba, count) {
        (Some(lba), Some(count)) => format!("{name} LBA {lba:#x}, {count} blocks"),
        _ => name.to_string(),
    };
    Some(match opcode {
        0x00 => "TEST UNIT READY".into(),
        0x03 => "REQUEST SENSE".into(),
        0x04 => "FORMAT UNIT".into(),
        0x08 | 0x0a => {
            let lba = be(cdb, 1, 3).map(|lba| lba & 0x1f_ffff);
            let count = cdb
                .get(4)
                .map(|count| if *count == 0 { 256 } else { u64::from(*count) });
            blocks(
                if opcode == 0x08 {
                    "READ(6)"
                } else {
                    "WRITE(6)"
                },
                lba,
                count,
            )
        }
        0x12 => match cdb.get(1) {
            Some(flags) if flags & 1 != 0 => {
                format!("INQUIRY page {:#04x}", cdb.get(2).copied().unwrap_or(0))
            }
            _ => "INQUIRY".into(),
        },
        0x15 => "MODE SELECT(6)".into(),
        0x1a => format!(
            "MODE SENSE(6) page {:#04x}",
            cdb.get(2).map_or(0, |page| page & 0x3f)
        ),
        0x1b => "START STOP UNIT".into(),
        0x1d => "SEND DIAGNOSTIC".into(),
        0x1e => "PREVENT ALLOW MEDIUM REMOVAL".into(),
        0x25 => "READ CAPACITY(10)".into(),
        0x28 | 0x2a | 0x2f | 0x35 | 0x41 => {
            let name = match opcode {
                0x28 => "READ(10)",
                0x2a => "WRITE(10)",
                0x2f => "VERIFY(10)",
                0x35 => "SYNCHRONIZE CACHE(10)",
                _ => "WRITE SAME(10)",
            };
            blocks(name, be(cdb, 2, 4), be(cdb, 7, 2))
        }
        0x3b => "WRITE BUFFER".into(),
        0x3c => "READ BUFFER".into(),
        0x42 => "UNMAP".into(),
        0x4d => "LOG SENSE".into(),
        0x55 => "MODE SELECT(10)".into(),
        0x5a => format!(
            "MODE SENSE(10) page {:#04x}",
            cdb.get(2).map_or(0, |page| page & 0x3f)
        ),
        0x5e => "PERSISTENT RESERVE IN".into(),
        0x5f => "PERSISTENT RESERVE OUT".into(),
        0x85 => "ATA PASS-THROUGH(16)".into(),
        0x88 | 0x8a | 0x8f | 0x91 | 0x93 => {
            let name = match opcode {
                0x88 => "READ(16)",
                0x8a => "WRITE(16)",
                0x8f => "VERIFY(16)",
                0x91 => "SYNCHRONIZE CACHE(16)",
                _ => "WRITE SAME(16)",
            };
            blocks(name, be(cdb, 2, 8), be(cdb, 10, 4))
        }
        0x9e => match cdb.get(1).map(|action| action & 0x1f) {
            Some(0x10) => "READ CAPACITY(16)".into(),
            Some(0x12) => "GET LBA STATUS".into(),
            Some(action) => format!("SERVICE ACTION IN(16) {action:#04x}"),
            None => "SERVICE ACTION IN(16)".into(),
        },
        0xa0 => "REPORT LUNS".into(),
        0xa1 => "ATA PASS-THROUGH(12)".into(),
        0xa3 => "MAINTENANCE IN".into(),
        0xa8 | 0xaa => blocks(
            if opcode == 0xa8 {
                "READ(12)"
            } else {
                "WRITE(12)"
            },
            be(cdb, 2, 4),
            be(cdb, 6, 4),
        ),
        other => format!("SCSI opcode {other:#04x}"),
    })
}

/// A SCSI status byte's name.
pub fn scsi_status(status: u8) -> String {
    match status {
        0x00 => "GOOD".into(),
        0x02 => "CHECK CONDITION".into(),
        0x04 => "CONDITION MET".into(),
        0x08 => "BUSY".into(),
        0x18 => "RESERVATION CONFLICT".into(),
        0x28 => "TASK SET FULL".into(),
        0x30 => "ACA ACTIVE".into(),
        0x40 => "TASK ABORTED".into(),
        other => format!("status {other:#04x}"),
    }
}

/// A virtio-scsi response code's name; the task management ones are
/// 10-12.
fn scsi_response(code: u8) -> String {
    match code {
        0 => "OK".into(),
        1 => "OVERRUN".into(),
        2 => "ABORTED".into(),
        3 => "BAD_TARGET".into(),
        4 => "RESET".into(),
        5 => "BUSY".into(),
        6 => "TRANSPORT_FAILURE".into(),
        7 => "TARGET_FAILURE".into(),
        8 => "NEXUS_FAILURE".into(),
        9 => "FAILURE".into(),
        10 => "FUNCTION_SUCCEEDED".into(),
        11 => "FUNCTION_REJECTED".into(),
        12 => "INCORRECT_LUN".into(),
        other => format!("response {other}"),
    }
}

/// Sense data's key, with its name, and additional sense code and
/// qualifier, from fixed (0x70/0x71) or descriptor (0x72/0x73) format.
pub fn sense_text(sense: &[u8]) -> Option<String> {
    let (key, asc, ascq) = match sense.first()? & 0x7f {
        0x70 | 0x71 => (sense.get(2)? & 0x0f, *sense.get(12)?, *sense.get(13)?),
        0x72 | 0x73 => (sense.get(1)? & 0x0f, *sense.get(2)?, *sense.get(3)?),
        _ => return None,
    };
    let name = match key {
        0x0 => "NO SENSE",
        0x1 => "RECOVERED ERROR",
        0x2 => "NOT READY",
        0x3 => "MEDIUM ERROR",
        0x4 => "HARDWARE ERROR",
        0x5 => "ILLEGAL REQUEST",
        0x6 => "UNIT ATTENTION",
        0x7 => "DATA PROTECT",
        0x8 => "BLANK CHECK",
        0x9 => "VENDOR SPECIFIC",
        0xa => "COPY ABORTED",
        0xb => "ABORTED COMMAND",
        0xd => "VOLUME OVERFLOW",
        0xe => "MISCOMPARE",
        _ => "RESERVED",
    };
    Some(format!("sense {name} {asc:02x}/{ascq:02x}"))
}

/// A virtio-scsi LUN field: `target T lun L`.
fn scsi_lun(lun: &[u8]) -> Option<String> {
    let target = *lun.get(1)?;
    let number = u16::from(lun.get(2)? & 0x3f) << 8 | u16::from(*lun.get(3)?);
    Some(format!("target {target} lun {number}"))
}

/// `virtio_scsi_cmd_req` (LUN, tag, task attributes, CDB) and
/// `virtio_scsi_cmd_resp` (sense length, residual, status, response,
/// sense).
fn scsi_request(bytes: &RequestBytes) -> Option<Decoded> {
    const HEADER: usize = 19;
    let head = &bytes.out_head;
    let lun = scsi_lun(head.get(0..8)?)?;
    let command = scsi_command(head.get(HEADER..)?)?;
    let request = format!("scsi {lun} {command}");
    let response = &bytes.in_head;
    let outcome = (|| {
        let sense_len = u32_at(response, 0)?;
        let resid = u32_at(response, 4)?;
        let status = *response.get(10)?;
        let code = *response.get(11)?;
        if code != 0 {
            return Some(scsi_response(code));
        }
        let mut text = scsi_status(status);
        if sense_len > 0
            && let Some(sense) = response.get(12..).and_then(sense_text)
        {
            text.push_str(&format!(", {sense}"));
        }
        if resid != 0 {
            text.push_str(&format!(
                ", {} not transferred",
                size_text(u64::from(resid))
            ));
        }
        Some(text)
    })();
    Some((request, outcome))
}

/// The control queue's task management functions and asynchronous
/// notification requests.
fn scsi_control(bytes: &RequestBytes) -> Option<Decoded> {
    let head = &bytes.out_head;
    let request = match u32_at(head, 0)? {
        0 => {
            let function = match u32_at(head, 4)? {
                0 => "ABORT_TASK",
                1 => "ABORT_TASK_SET",
                2 => "CLEAR_ACA",
                3 => "CLEAR_TASK_SET",
                4 => "I_T_NEXUS_RESET",
                5 => "LOGICAL_UNIT_RESET",
                6 => "QUERY_TASK",
                7 => "QUERY_TASK_SET",
                _ => "task management",
            };
            let lun = head.get(8..16).and_then(scsi_lun).unwrap_or_default();
            match u64_at(head, 16) {
                Some(tag) if tag != 0 => format!("scsi {function} {lun} tag {tag:#x}"),
                _ => format!("scsi {function} {lun}"),
            }
        }
        1 => "scsi asynchronous notification query".into(),
        2 => "scsi asynchronous notification subscribe".into(),
        other => format!("scsi control type {other}"),
    };
    let outcome = bytes.in_head.first().map(|code| scsi_response(*code));
    Some((request, outcome))
}

/// `virtio_scsi_event`: the event, the LUN it is about, and its reason.
fn scsi_event(event: &[u8]) -> Option<String> {
    let code = u32_at(event, 0)?;
    let missed = if code & 0x8000_0000 != 0 {
        " (events missed)"
    } else {
        ""
    };
    let name = match code & 0x7fff_ffff {
        0 => return Some(format!("scsi no event{missed}")),
        1 => "TRANSPORT_RESET",
        2 => "ASYNC_NOTIFY",
        3 => "PARAM_CHANGE",
        _ => "event",
    };
    let lun = event.get(4..12).and_then(scsi_lun).unwrap_or_default();
    let reason = u32_at(event, 12).unwrap_or(0);
    Some(format!("scsi {name} {lun} reason {reason:#x}{missed}"))
}

/// `virtio_net_hdr` and, after it, the frame's Ethernet and IP headers in
/// one line.
fn net_packet(bytes: &RequestBytes, modern: bool, returned: bool) -> Option<String> {
    // A received packet is in what the device wrote, a sent one in what
    // the driver wrote.
    let sent = bytes.out_total > 0;
    let (head, total) = if sent {
        (&bytes.out_head, bytes.out_total)
    } else if returned {
        (
            &bytes.in_head,
            bytes.written.map_or(bytes.in_total, u64::from),
        )
    } else {
        return None;
    };
    let header = match bytes.first_len {
        Some(len @ (10 | 12 | 20)) => len as usize,
        _ if modern => 12,
        _ => 10,
    };
    let flags = *head.first()?;
    let gso = *head.get(1)?;
    let mut parts = vec![frame_text(
        head.get(header..)?,
        total.saturating_sub(header as u64),
    )];
    if flags & 1 != 0 {
        parts.push(format!(
            "checksum offload (start {}, offset {})",
            u16_at(head, 6)?,
            u16_at(head, 8)?
        ));
    }
    if flags & 2 != 0 {
        parts.push("checksum valid".into());
    }
    let gso_name = match gso & 0x7f {
        0 => None,
        1 => Some("TCPv4"),
        3 => Some("UDP"),
        4 => Some("TCPv6"),
        5 => Some("UDP L4"),
        _ => Some("unknown"),
    };
    if let Some(name) = gso_name {
        parts.push(format!(
            "segmentation {name}{} size {}",
            if gso & 0x80 != 0 { " ECN" } else { "" },
            u16_at(head, 4)?
        ));
    }
    // The device sets num_buffers on a received packet; on a sent one the
    // field is unused, and drivers leave whatever was there.
    if !sent
        && header >= 12
        && let Some(buffers) = u16_at(head, 10).filter(|buffers| *buffers > 1)
    {
        parts.push(format!("{buffers} buffers"));
    }
    Some(format!("net {}", parts.join(", ")))
}

/// An Ethernet frame's type and, for IP, its protocol and addresses.
fn frame_text(frame: &[u8], length: u64) -> String {
    let size = format!("{length} bytes");
    let Some(mut ethertype) = frame
        .get(12..14)
        .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
    else {
        return size;
    };
    let mut payload = 14;
    if ethertype == 0x8100 {
        ethertype = frame
            .get(16..18)
            .map_or(0, |bytes| u16::from_be_bytes([bytes[0], bytes[1]]));
        payload = 18;
    }
    let ip = frame.get(payload..).unwrap_or_default();
    let ports = |at: usize| -> Option<(u16, u16)> {
        let bytes = ip.get(at..at + 4)?;
        Some((
            u16::from_be_bytes([bytes[0], bytes[1]]),
            u16::from_be_bytes([bytes[2], bytes[3]]),
        ))
    };
    let flow = |protocol: u8, source: String, destination: String, at: usize| {
        let name = match protocol {
            1 => "ICMP",
            6 => "TCP",
            17 => "UDP",
            58 => "ICMPv6",
            _ => "",
        };
        match (protocol, ports(at)) {
            (6 | 17, Some((from, to))) => format!("{name} {source}:{from} -> {destination}:{to}"),
            (1 | 58, _) => match ip.get(at).and_then(|kind| icmp_type(protocol, *kind)) {
                Some(kind) => format!("{name} {kind} {source} -> {destination}"),
                None => format!("{name} {source} -> {destination}"),
            },
            _ if !name.is_empty() => format!("{name} {source} -> {destination}"),
            _ => format!("protocol {protocol} {source} -> {destination}"),
        }
    };
    let text = match ethertype {
        0x0800 if ip.len() >= 20 => {
            let header = usize::from(ip[0] & 0x0f) * 4;
            let source = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
            let destination = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
            format!(
                "IPv4 {}",
                flow(ip[9], source.to_string(), destination.to_string(), header)
            )
        }
        0x86dd if ip.len() >= 40 => {
            let address = |at: usize| {
                let octets: [u8; 16] = ip[at..at + 16].try_into().unwrap_or_default();
                format!("[{}]", Ipv6Addr::from(octets))
            };
            format!("IPv6 {}", flow(ip[6], address(8), address(24), 40))
        }
        0x0806 => "ARP".into(),
        other => format!("ethertype {other:#06x}"),
    };
    format!("{text}, {size}")
}

/// The common message types of ICMP (`protocol` 1) and ICMPv6 (58).
fn icmp_type(protocol: u8, kind: u8) -> Option<&'static str> {
    Some(match (protocol, kind) {
        (1, 0) | (58, 129) => "echo reply",
        (1, 8) | (58, 128) => "echo request",
        (1, 3) | (58, 1) => "destination unreachable",
        (1, 5) => "redirect",
        (1, 11) | (58, 3) => "time exceeded",
        (58, 2) => "packet too big",
        (58, 133) => "router solicitation",
        (58, 134) => "router advertisement",
        (58, 135) => "neighbor solicitation",
        (58, 136) => "neighbor advertisement",
        _ => return None,
    })
}

/// `virtio_net_ctrl_hdr` (class and command), the command's data, and the
/// ack byte the device writes.
fn net_control(bytes: &RequestBytes) -> Option<Decoded> {
    let head = &bytes.out_head;
    let class = *head.first()?;
    let command = *head.get(1)?;
    let data = head.get(2..).unwrap_or_default();
    let on_off = |name: &str| {
        format!(
            "{name} {}",
            if data.first().copied().unwrap_or(0) != 0 {
                "on"
            } else {
                "off"
            }
        )
    };
    let request = match (class, command) {
        (0, 0) => on_off("promiscuous"),
        (0, 1) => on_off("all multicast"),
        (0, 2) => on_off("all unicast"),
        (0, 3) => on_off("no multicast"),
        (0, 4) => on_off("no unicast"),
        (0, 5) => on_off("no broadcast"),
        (1, 0) => "MAC filter table".into(),
        (1, 1) => match data.get(..6) {
            Some(mac) => format!(
                "MAC address {}",
                mac.iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<Vec<_>>()
                    .join(":")
            ),
            None => "MAC address".into(),
        },
        (2, 0 | 1) => format!(
            "VLAN {} {}",
            if command == 0 { "add" } else { "remove" },
            u16_at(data, 0).map_or_else(String::new, |id| id.to_string())
        ),
        (3, 0) => "announce ack".into(),
        (4, 0) => format!(
            "queue pairs {}",
            u16_at(data, 0).map_or_else(String::new, |pairs| pairs.to_string())
        ),
        (4, 1) => "RSS configuration".into(),
        (4, 2) => "hash configuration".into(),
        (5, 0) => format!(
            "guest offloads {}",
            u64_at(data, 0).map_or_else(String::new, |mask| format!("{mask:#x}"))
        ),
        (6, _) => "notification coalescing".into(),
        (7, _) => "statistics".into(),
        _ => format!("class {class} command {command}"),
    };
    let outcome = bytes.in_last.map(|ack| match ack {
        0 => "OK".to_string(),
        1 => "ERR".to_string(),
        other => format!("ack {other}"),
    });
    Some((format!("net control {request}"), outcome))
}

/// The name of a virtio-gpu command or response type.
fn gpu_type(kind: u32) -> String {
    match kind {
        0x0100 => "GET_DISPLAY_INFO",
        0x0101 => "RESOURCE_CREATE_2D",
        0x0102 => "RESOURCE_UNREF",
        0x0103 => "SET_SCANOUT",
        0x0104 => "RESOURCE_FLUSH",
        0x0105 => "TRANSFER_TO_HOST_2D",
        0x0106 => "RESOURCE_ATTACH_BACKING",
        0x0107 => "RESOURCE_DETACH_BACKING",
        0x0108 => "GET_CAPSET_INFO",
        0x0109 => "GET_CAPSET",
        0x010a => "GET_EDID",
        0x010b => "RESOURCE_ASSIGN_UUID",
        0x010c => "RESOURCE_CREATE_BLOB",
        0x010d => "SET_SCANOUT_BLOB",
        0x0200 => "CTX_CREATE",
        0x0201 => "CTX_DESTROY",
        0x0202 => "CTX_ATTACH_RESOURCE",
        0x0203 => "CTX_DETACH_RESOURCE",
        0x0204 => "RESOURCE_CREATE_3D",
        0x0205 => "TRANSFER_TO_HOST_3D",
        0x0206 => "TRANSFER_FROM_HOST_3D",
        0x0207 => "SUBMIT_3D",
        0x0208 => "RESOURCE_MAP_BLOB",
        0x0209 => "RESOURCE_UNMAP_BLOB",
        0x0300 => "UPDATE_CURSOR",
        0x0301 => "MOVE_CURSOR",
        0x1100 => "OK_NODATA",
        0x1101 => "OK_DISPLAY_INFO",
        0x1102 => "OK_CAPSET_INFO",
        0x1103 => "OK_CAPSET",
        0x1104 => "OK_EDID",
        0x1105 => "OK_RESOURCE_UUID",
        0x1106 => "OK_MAP_INFO",
        0x1200 => "ERR_UNSPEC",
        0x1201 => "ERR_OUT_OF_MEMORY",
        0x1202 => "ERR_INVALID_SCANOUT_ID",
        0x1203 => "ERR_INVALID_RESOURCE_ID",
        0x1204 => "ERR_INVALID_CONTEXT_ID",
        0x1205 => "ERR_INVALID_PARAMETER",
        other => return format!("type {other:#x}"),
    }
    .into()
}

/// `virtio_gpu_ctrl_hdr` of the command and of the response.
fn gpu(bytes: &RequestBytes) -> Option<Decoded> {
    let head = &bytes.out_head;
    let kind = u32_at(head, 0)?;
    let fenced = u32_at(head, 4)? & 1 != 0;
    let mut request = format!("gpu {}", gpu_type(kind));
    if fenced {
        request.push_str(&format!(" (fence {})", u64_at(head, 8)?));
    }
    let outcome = u32_at(&bytes.in_head, 0).map(gpu_type);
    Some((request, outcome))
}

/// `virtio_vsock_hdr`: the operation and the addresses, with the payload's
/// length.
fn vsock(bytes: &RequestBytes, returned: bool) -> Option<String> {
    let head = if bytes.out_total > 0 {
        &bytes.out_head
    } else if returned {
        &bytes.in_head
    } else {
        return None;
    };
    let operation = match u16_at(head, 30)? {
        1 => "REQUEST",
        2 => "RESPONSE",
        3 => "RST",
        4 => "SHUTDOWN",
        5 => "RW",
        6 => "CREDIT_UPDATE",
        7 => "CREDIT_REQUEST",
        _ => "INVALID",
    };
    Some(format!(
        "vsock {operation} {}:{} -> {}:{}, {}",
        u64_at(head, 0)?,
        u32_at(head, 16)?,
        u64_at(head, 8)?,
        u32_at(head, 20)?,
        size_text(u64::from(u32_at(head, 24)?))
    ))
}

impl Target {
    /// The buffers of a request whose descriptors are `descriptors`
    /// (address, length, flags), with each indirect table expanded into
    /// the buffers it lists.
    pub fn request_segments(
        &self,
        descriptors: impl IntoIterator<Item = (u64, u32, u16)>,
        packed: bool,
    ) -> Vec<Segment> {
        let mut segments = Vec::new();
        for (addr, len, flags) in descriptors {
            let entries = if flags & VRING_DESC_F_INDIRECT != 0 {
                let mut table = vec![0u8; (len as usize).min(MAX_SEGMENTS * 16)];
                if self.read_physical(addr, &mut table).is_err() {
                    continue;
                }
                indirect_entries(&table, packed)
            } else {
                vec![(addr, len, flags)]
            };
            segments.extend(entries.into_iter().map(|(addr, len, flags)| Segment {
                addr,
                len,
                device_writes: flags & VRING_DESC_F_WRITE != 0,
            }));
            if segments.len() >= MAX_SEGMENTS {
                break;
            }
        }
        segments
    }

    /// Decode the request of `kind` whose descriptors are `descriptors`,
    /// with the response once the device `returned` it, having written
    /// `written` bytes.
    pub fn describe_request(
        &self,
        kind: RequestKind,
        descriptors: impl IntoIterator<Item = (u64, u32, u16)>,
        packed: bool,
        returned: bool,
        written: Option<u32>,
    ) -> Option<String> {
        let segments = self.request_segments(descriptors, packed);
        let bytes = gather(&segments, written, |addr, buf| {
            self.phys.read_bytes(addr, buf).is_ok()
        });
        describe(kind, &bytes, returned)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        RequestBytes, RequestKind, Segment, describe, gather, indirect_entries, request_kind,
        scsi_command, sense_text, size_text,
    };

    fn bytes(out: &[u8], out_total: u64, response: &[u8], in_total: u64) -> RequestBytes {
        RequestBytes {
            out_head: out.to_vec(),
            out_total,
            in_head: response.to_vec(),
            in_total,
            in_last: response.last().copied(),
            first_len: None,
            written: None,
        }
    }

    fn blk_header(kind: u32, sector: u64) -> Vec<u8> {
        let mut header = kind.to_le_bytes().to_vec();
        header.extend(0u32.to_le_bytes());
        header.extend(sector.to_le_bytes());
        header
    }

    /// A block request reads its type and sector from the header, its
    /// length from the data around the header and the status byte, and its
    /// status from the last byte the device wrote, once returned.
    #[test]
    fn a_block_request_decodes_type_sector_length_and_status() {
        let write = bytes(&blk_header(1, 0x3a28), 16 + 4096, &[0], 1);
        assert_eq!(
            describe(RequestKind::Block, &write, false).as_deref(),
            Some("blk write sector 0x3a28, 4 KiB")
        );
        assert_eq!(
            describe(RequestKind::Block, &write, true).as_deref(),
            Some("blk write sector 0x3a28, 4 KiB -> OK")
        );
        let read = bytes(&blk_header(0, 8192), 16, &[1], 65536 + 1);
        assert_eq!(
            describe(RequestKind::Block, &read, true).as_deref(),
            Some("blk read sector 0x2000, 64 KiB -> IOERR")
        );
        let flush = bytes(&blk_header(4, 0), 16, &[2], 1);
        assert_eq!(
            describe(RequestKind::Block, &flush, true).as_deref(),
            Some("blk flush -> UNSUPP")
        );
    }

    #[test]
    fn scsi_commands_decode_lba_and_length_by_cdb_size() {
        let read10 = [0x28, 0, 0, 0x01, 0xf4, 0x00, 0, 0x00, 0x80, 0];
        assert_eq!(
            scsi_command(&read10).as_deref(),
            Some("READ(10) LBA 0x1f400, 128 blocks")
        );
        let mut write16 = [0u8; 16];
        write16[0] = 0x8a;
        write16[2..10].copy_from_slice(&0x1_0000_0000u64.to_be_bytes());
        write16[10..14].copy_from_slice(&8u32.to_be_bytes());
        assert_eq!(
            scsi_command(&write16).as_deref(),
            Some("WRITE(16) LBA 0x100000000, 8 blocks")
        );
        assert_eq!(
            scsi_command(&[0x08, 0x1f, 0xff, 0xff, 0]).as_deref(),
            Some("READ(6) LBA 0x1fffff, 256 blocks")
        );
        assert_eq!(
            scsi_command(&[0x12, 1, 0x83]).as_deref(),
            Some("INQUIRY page 0x83")
        );
        assert_eq!(
            scsi_command(&[0x9e, 0x10]).as_deref(),
            Some("READ CAPACITY(16)")
        );
    }

    #[test]
    fn sense_data_decodes_fixed_and_descriptor_formats() {
        let mut fixed = [0u8; 18];
        fixed[0] = 0x70;
        fixed[2] = 0x05;
        fixed[12] = 0x24;
        assert_eq!(
            sense_text(&fixed).as_deref(),
            Some("sense ILLEGAL REQUEST 24/00")
        );
        assert_eq!(
            sense_text(&[0x72, 0x06, 0x29, 0x00]).as_deref(),
            Some("sense UNIT ATTENTION 29/00")
        );
        assert_eq!(sense_text(&[0x00, 0x05]), None);
    }

    /// A SCSI request's LUN and CDB come after the 8-byte LUN and the tag
    /// and task fields; its response gives the virtio response first, then
    /// the SCSI status and sense.
    #[test]
    fn a_scsi_request_decodes_lun_command_and_response() {
        let mut request = vec![1, 0, 0x40, 0x01, 0, 0, 0, 0];
        request.extend(0x2cu64.to_le_bytes());
        request.extend([0, 0, 0]);
        request.extend([0x2a, 0, 0, 0x01, 0xf4, 0x00, 0, 0x00, 0x80, 0]);
        request.resize(51, 0);
        let mut response = 18u32.to_le_bytes().to_vec();
        response.extend(512u32.to_le_bytes());
        response.extend([0, 0, 0x02, 0]);
        let mut sense = [0u8; 18];
        sense[0] = 0x70;
        sense[2] = 0x05;
        sense[12] = 0x24;
        response.extend(sense);
        let decoded = describe(
            RequestKind::ScsiRequest,
            &bytes(&request, 51 + 65536, &response, 108),
            true,
        );
        assert_eq!(
            decoded.as_deref(),
            Some(
                "scsi target 0 lun 1 WRITE(10) LBA 0x1f400, 128 blocks -> CHECK CONDITION, \
                 sense ILLEGAL REQUEST 24/00, 512 bytes not transferred"
            )
        );
        let mut failed = vec![0u8; 12];
        failed[11] = 3;
        assert!(
            describe(
                RequestKind::ScsiRequest,
                &bytes(&request, 51, &failed, 108),
                true
            )
            .is_some_and(|text| text.ends_with("-> BAD_TARGET"))
        );
    }

    #[test]
    fn a_scsi_task_management_request_names_its_function() {
        let mut request = 0u32.to_le_bytes().to_vec();
        request.extend(5u32.to_le_bytes());
        request.extend([1, 2, 0x40, 0x00, 0, 0, 0, 0]);
        request.extend(0u64.to_le_bytes());
        assert_eq!(
            describe(
                RequestKind::ScsiControl,
                &bytes(&request, 24, &[0], 1),
                true
            )
            .as_deref(),
            Some("scsi LOGICAL_UNIT_RESET target 2 lun 0 -> OK")
        );
    }

    fn ipv4_tcp_frame() -> Vec<u8> {
        let mut frame = vec![0u8; 12];
        frame.extend([0x08, 0x00]);
        let mut ip = vec![0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0];
        ip.extend([10, 0, 2, 15, 1, 2, 3, 4]);
        frame.extend(ip);
        frame.extend(50123u16.to_be_bytes());
        frame.extend(443u16.to_be_bytes());
        frame
    }

    /// A sent packet's header, after which its frame starts: the 12-byte
    /// header of a modern device, its offload fields, and the IP flow. Its
    /// num_buffers is unused on transmit; NetKVM leaves stale bytes there,
    /// as these, read from a live send, are.
    #[test]
    fn a_net_packet_decodes_header_offloads_and_flow() {
        let mut packet = vec![1, 1, 54, 0, 0xa8, 0x05, 34, 0, 16, 0, 0xba, 0xc4];
        packet.extend(ipv4_tcp_frame());
        let sent = RequestBytes {
            out_head: packet,
            out_total: 12 + 1514,
            ..Default::default()
        };
        assert_eq!(
            describe(RequestKind::NetPacket { modern: true }, &sent, false).as_deref(),
            Some(
                "net IPv4 TCP 10.0.2.15:50123 -> 1.2.3.4:443, 1514 bytes, checksum offload \
                 (start 34, offset 16), segmentation TCPv4 size 1448"
            )
        );
        let empty_receive = RequestBytes {
            in_total: 1530,
            ..Default::default()
        };
        assert_eq!(
            describe(
                RequestKind::NetPacket { modern: true },
                &empty_receive,
                false
            ),
            None,
            "a receive buffer the device has not filled holds nothing"
        );
    }

    /// A received frame, as the device wrote it with its 12-byte header:
    /// the ICMP "destination unreachable" user-mode networking sent back
    /// for a NetBIOS broadcast, its length from what the device wrote.
    #[test]
    fn a_received_frame_names_its_icmp_message() {
        let mut frame = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0];
        frame.extend([
            0x52, 0x54, 0, 0x7e, 0x57, 0x01, 0x52, 0x55, 0x0a, 0, 2, 2, 0x08, 0,
        ]);
        frame.extend([0x45, 0xc0, 0, 0x7c, 0, 0x1b, 0, 0, 0xff, 1, 0xfc, 0xb8]);
        frame.extend([10, 240, 166, 237, 10, 0, 2, 16, 3, 13]);
        let received = RequestBytes {
            in_head: frame,
            in_total: 1530,
            first_len: Some(1530),
            written: Some(0x96),
            ..Default::default()
        };
        assert_eq!(
            describe(RequestKind::NetPacket { modern: true }, &received, true).as_deref(),
            Some("net IPv4 ICMP destination unreachable 10.240.166.237 -> 10.0.2.16, 138 bytes")
        );
        let mut merged = received.clone();
        merged.in_head[10] = 3;
        assert!(
            describe(RequestKind::NetPacket { modern: true }, &merged, true)
                .is_some_and(|text| text.ends_with(", 3 buffers")),
            "a received packet over merged buffers says how many"
        );
    }

    #[test]
    fn a_net_control_command_decodes_its_class_data_and_ack() {
        let pairs = bytes(&[4, 0, 4, 0], 4, &[0], 1);
        assert_eq!(
            describe(RequestKind::NetControl, &pairs, true).as_deref(),
            Some("net control queue pairs 4 -> OK")
        );
        let promiscuous = bytes(&[0, 0, 1], 3, &[1], 1);
        assert_eq!(
            describe(RequestKind::NetControl, &promiscuous, true).as_deref(),
            Some("net control promiscuous on -> ERR")
        );
    }

    #[test]
    fn a_gpu_command_names_its_type_fence_and_response() {
        let mut command = 0x0104u32.to_le_bytes().to_vec();
        command.extend(1u32.to_le_bytes());
        command.extend(12u64.to_le_bytes());
        let response = 0x1203u32.to_le_bytes();
        assert_eq!(
            describe(RequestKind::Gpu, &bytes(&command, 48, &response, 24), true).as_deref(),
            Some("gpu RESOURCE_FLUSH (fence 12) -> ERR_INVALID_RESOURCE_ID")
        );
    }

    #[test]
    fn a_vsock_header_decodes_operation_and_addresses() {
        let mut header = 3u64.to_le_bytes().to_vec();
        header.extend(2u64.to_le_bytes());
        header.extend(1024u32.to_le_bytes());
        header.extend(9999u32.to_le_bytes());
        header.extend(4096u32.to_le_bytes());
        header.extend(1u16.to_le_bytes());
        header.extend(5u16.to_le_bytes());
        let sent = RequestBytes {
            out_head: header,
            out_total: 44 + 4096,
            ..Default::default()
        };
        assert_eq!(
            describe(RequestKind::Vsock, &sent, false).as_deref(),
            Some("vsock RW 3:1024 -> 2:9999, 4 KiB")
        );
    }

    /// A split ring's indirect table follows its `next` links; a packed
    /// ring's is read in order.
    #[test]
    fn indirect_tables_follow_their_layout() {
        let entry = |addr: u64, len: u32, flags: u16, next_or_id: u16, packed: bool| {
            let mut bytes = addr.to_le_bytes().to_vec();
            bytes.extend(len.to_le_bytes());
            if packed {
                bytes.extend(next_or_id.to_le_bytes());
                bytes.extend(flags.to_le_bytes());
            } else {
                bytes.extend(flags.to_le_bytes());
                bytes.extend(next_or_id.to_le_bytes());
            }
            bytes
        };
        let split = [
            entry(0x1000, 16, 1, 2, false),
            entry(0x3000, 1, 2, 0, false),
            entry(0x2000, 4096, 1, 1, false),
        ]
        .concat();
        let addresses: Vec<u64> = indirect_entries(&split, false)
            .iter()
            .map(|(addr, _, _)| *addr)
            .collect();
        assert_eq!(addresses, [0x1000, 0x2000, 0x3000]);
        let packed = [entry(0x1000, 16, 0, 7, true), entry(0x2000, 1, 2, 7, true)].concat();
        assert_eq!(
            indirect_entries(&packed, true),
            [(0x1000, 16, 0), (0x2000, 1, 2)]
        );
    }

    /// The driver's and the device's bytes are each gathered across their
    /// buffers, and the status is the last byte the device writes.
    #[test]
    fn gathering_splits_by_direction_and_finds_the_last_device_byte() {
        let segments = [
            Segment {
                addr: 0x1000,
                len: 16,
                device_writes: false,
            },
            Segment {
                addr: 0x2000,
                len: 4096,
                device_writes: true,
            },
            Segment {
                addr: 0x3000,
                len: 1,
                device_writes: true,
            },
        ];
        let read = |addr: u64, buf: &mut [u8]| {
            buf.fill((addr >> 12) as u8);
            true
        };
        let gathered = gather(&segments, Some(4097), read);
        assert_eq!((gathered.out_total, gathered.in_total), (16, 4097));
        assert_eq!(gathered.out_head, [1u8; 16]);
        assert_eq!(gathered.in_head.len(), 128);
        assert_eq!(gathered.in_last, Some(3));
    }

    #[test]
    fn queue_kinds_follow_the_device_layout() {
        assert_eq!(request_kind(8, 0, 6, false), Some(RequestKind::ScsiControl));
        assert_eq!(request_kind(8, 3, 6, false), Some(RequestKind::ScsiRequest));
        assert_eq!(request_kind(1, 2, 3, false), Some(RequestKind::NetControl));
        assert_eq!(
            request_kind(1, 2, 4, true),
            Some(RequestKind::NetPacket { modern: false })
        );
        assert_eq!(request_kind(5, 0, 3, false), None);
    }

    #[test]
    fn sizes_use_the_largest_whole_unit() {
        assert_eq!(size_text(512), "512 bytes");
        assert_eq!(size_text(65536), "64 KiB");
        assert_eq!(size_text(1536), "1.5 KiB");
        assert_eq!(size_text(3 << 20), "3 MiB");
    }
}
