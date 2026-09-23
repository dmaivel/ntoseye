use super::layout::Layout;
use super::{
    address_layout, advertise, current_thread_step, frame, library_list_xml, memory_map_xml,
    proc_maps, xfer_reply,
};
use crate::kd::context::{REGISTER_BUFFER_SIZE, build_register_map};
use crate::types::Arch;

/// Byte offset of a register on the wire: its position in the AMD64
/// description (rax..r15, rip, eflags, six segments, eight x87 stack
/// registers, eight x87 control registers, sixteen xmm, mxcsr, ...).
fn wire_offset(name: &str) -> usize {
    let widths: &[(&str, usize)] = &[
        ("rax", 8),
        ("rbx", 8),
        ("rcx", 8),
        ("rdx", 8),
        ("rsi", 8),
        ("rdi", 8),
        ("rbp", 8),
        ("rsp", 8),
        ("r8", 8),
        ("r9", 8),
        ("r10", 8),
        ("r11", 8),
        ("r12", 8),
        ("r13", 8),
        ("r14", 8),
        ("r15", 8),
        ("rip", 8),
        ("eflags", 4),
        ("cs", 4),
        ("ss", 4),
        ("ds", 4),
        ("es", 4),
        ("fs", 4),
        ("gs", 4),
    ];
    let mut offset = 0;
    for (register, width) in widths {
        if *register == name {
            return offset;
        }
        offset += width;
    }
    panic!("{name} is not in the core feature prefix");
}

/// KD carries no x87 state and 2-byte selectors. The wire must still put
/// every register at gdb's fixed offset, widen the selectors, and mark the
/// x87 registers unavailable rather than zero, or a client reads garbage
/// into every register after the first mismatch.
#[test]
fn kd_register_file_encodes_at_gdb_offsets() {
    let map = build_register_map();
    let mut file = vec![0u8; REGISTER_BUFFER_SIZE];
    map.write_u64("rip", &mut file, 0xffff_f800_1234_5678)
        .unwrap();
    map.write_u64("cs", &mut file, 0x10).unwrap();
    map.write_u64("xmm0l", &mut file, 0x1122_3344_5566_7788)
        .unwrap();

    let layout = Layout::new(Arch::Amd64, &map);
    let wire = layout.encode(&map, &file);

    let rip = wire_offset("rip");
    let rip_bytes: Vec<u8> = wire[rip..rip + 8].iter().map(|b| b.unwrap()).collect();
    assert_eq!(
        u64::from_le_bytes(rip_bytes.try_into().unwrap()),
        0xffff_f800_1234_5678
    );

    let cs = wire_offset("cs");
    assert_eq!(&wire[cs..cs + 4], &[Some(0x10), Some(0), Some(0), Some(0)]);

    let st0 = wire_offset("gs") + 4;
    assert!(
        wire[st0..st0 + 10].iter().all(Option::is_none),
        "st0 is unavailable over KD"
    );

    // Eight 10-byte x87 stack registers and eight 4-byte control registers.
    let xmm0 = st0 + 8 * 10 + 8 * 4;
    assert_eq!(wire[xmm0], Some(0x88));
}

/// A `G` write must land in the transport's register file at the transport's
/// offsets and widths, skipping what the transport lacks.
#[test]
fn register_payload_round_trips_through_the_kd_file() {
    let map = build_register_map();
    let mut file = vec![0u8; REGISTER_BUFFER_SIZE];
    map.write_u64("rsp", &mut file, 0xffff_8000_0000_1000)
        .unwrap();
    let layout = Layout::new(Arch::Amd64, &map);

    let mut wire: Vec<u8> = layout
        .encode(&map, &file)
        .into_iter()
        .map(|byte| byte.unwrap_or(0xAA))
        .collect();
    let rip = wire_offset("rip");
    wire[rip..rip + 8].copy_from_slice(&0xffff_f800_0000_4000u64.to_le_bytes());
    layout.decode(&map, &mut file, &wire).unwrap();

    assert_eq!(map.read_u64("rip", &file).unwrap(), 0xffff_f800_0000_4000);
    assert_eq!(map.read_u64("rsp", &file).unwrap(), 0xffff_8000_0000_1000);
    assert!(layout.decode(&map, &mut file, &wire[1..]).is_err());
}

/// IDA subtracts 0x1000 from an x86 library's segment address before
/// rebasing (gdb's PE convention) and takes ARM64's as the image base. A
/// wrong bias rebases every module one page off. gdb fetches a library
/// through the server only under an absolute path.
#[test]
fn library_segment_addresses_follow_the_pe_convention_per_arch() {
    let modules = [
        ("ntoskrnl.exe", 0xffff_f800_0000_0000u64),
        ("a&b.sys", 0x1000),
    ];
    let amd64 = library_list_xml(Arch::Amd64, modules);
    assert!(amd64.contains(
        "<library name=\"/ntoskrnl.exe\"><segment address=\"0xfffff80000001000\"/></library>"
    ));
    assert!(amd64.contains("name=\"/a&amp;b.sys\""));

    let arm64 = library_list_xml(Arch::Arm64, modules);
    assert!(arm64.contains("<segment address=\"0xfffff80000000000\"/>"));
}

fn regions(xml: &str) -> Vec<(u64, u64)> {
    xml.split("<memory ")
        .skip(1)
        .map(|region| {
            let field = |key: &str| {
                let start = region.find(&format!("{key}=\"0x")).unwrap() + key.len() + 4;
                let end = start + region[start..].find('"').unwrap();
                u64::from_str_radix(&region[start..end], 16).unwrap()
            };
            (field("start"), field("length"))
        })
        .collect()
}

/// gdb reads only inside the map, so it must cover both halves, images
/// included. IDA lays out module segments first and drops any map region
/// overlapping one, so each image must be a region of its own, and IDA
/// rejects zero-length or 64-bit-overflowing regions.
#[test]
fn memory_map_covers_the_halves_with_each_image_its_own_region() {
    let nt = (0xffff_f800_0000_0000u64, 0x100_0000u64);
    // Adjacent to nt, so no zero-length gap may appear between them.
    let hal = (nt.0 + nt.1, 0x1000);
    let user_dll = (0x7ff8_0000_0000u64, 0x2000);
    let images = [
        (hal.0, hal.1, "hal.dll"),
        (user_dll.0, user_dll.1, "ntdll.dll"),
        (nt.0, nt.1, "ntoskrnl.exe"),
    ];
    let xml = memory_map_xml(&address_layout(Arch::Amd64, &images));
    let regions = regions(&xml);

    assert_eq!(
        regions,
        [
            (0, user_dll.0),
            user_dll,
            (
                user_dll.0 + user_dll.1,
                0x8000_0000_0000 - (user_dll.0 + user_dll.1)
            ),
            (0xffff_8000_0000_0000, nt.0 - 0xffff_8000_0000_0000),
            nt,
            hal,
            (hal.0 + hal.1, 0xffff_ffff_ffff_f000 - (hal.0 + hal.1)),
        ]
    );
    for (start, length) in regions {
        assert!(length > 0 && start.checked_add(length).is_some());
    }
}

fn checksum_valid(packet: &[u8]) -> bool {
    let start = packet.iter().position(|byte| *byte == b'$').unwrap();
    let hash = packet.iter().rposition(|byte| *byte == b'#').unwrap();
    let sum = packet[start + 1..hash]
        .iter()
        .fold(0u8, |sum, byte| sum.wrapping_add(*byte));
    let digits = std::str::from_utf8(&packet[hash + 1..hash + 3]).unwrap();
    u8::from_str_radix(digits, 16).unwrap() == sum
}

/// The feature is spliced into gdbstub's reply after the fact: a stale
/// checksum makes the client reject the whole handshake. A leading ack must
/// survive, and a packet that is not the reply must be left alone.
#[test]
fn advertised_feature_keeps_the_qsupported_reply_valid() {
    let mut out = vec![b'+'];
    frame(&mut out, b"PacketSize=4000;vContSupported+");
    let rewritten = advertise(&out, b";qXfer:threads:read+").unwrap();

    assert!(rewritten.starts_with(b"+$PacketSize=4000;vContSupported+;qXfer:threads:read+#"));
    assert!(checksum_valid(&rewritten));

    let mut other = Vec::new();
    frame(&mut other, b"OK");
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

/// Binary Ninja's GDB adapter takes modules only from `/proc/<pid>/maps`:
/// a line ending in a `/`-rooted path is a module, named by that path, and
/// the open database is matched to it by base name to find where to rebase.
/// Every image must appear once at its exact range, and RAM must not look
/// like a module.
#[test]
fn proc_maps_names_each_image_at_its_range() {
    let images = [
        (0xffff_f800_0000_0000u64, 0x100_0000u64, "ntoskrnl.exe"),
        (0xffff_f800_0100_0000, 0x1000, "hal.dll"),
    ];
    let maps = proc_maps(&address_layout(Arch::Amd64, &images));

    let mut modules = Vec::new();
    for line in maps.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (start, end) = fields[0].split_once('-').unwrap();
        let start = u64::from_str_radix(start, 16).unwrap();
        let end = u64::from_str_radix(end, 16).unwrap();
        assert!(end > start, "{line}");
        assert_eq!(fields[2..5], ["00000000", "00:00", "0"], "{line}");
        match fields.get(5) {
            Some(path) => modules.push((start, end, *path)),
            None => assert_eq!(fields[1], "rw-p", "{line}"),
        }
    }
    assert_eq!(
        modules,
        [
            (
                0xffff_f800_0000_0000,
                0xffff_f800_0100_0000,
                "/ntoskrnl.exe"
            ),
            (0xffff_f800_0100_0000, 0xffff_f800_0100_1000, "/hal.dll"),
        ]
    );
}

/// A step with no thread id (Binary Ninja's `vCont;s`) becomes a plain
/// current-thread step instead of a protocol error that drops the client;
/// a step naming its thread (IDA, gdb) must reach gdbstub unchanged.
#[test]
fn only_thread_less_steps_become_current_thread_steps() {
    assert_eq!(current_thread_step(b"vCont;s"), Some(&b"s"[..]));
    assert_eq!(current_thread_step(b"vCont;S05"), Some(&b"S05"[..]));
    assert_eq!(current_thread_step(b"vCont;s;c"), Some(&b"s"[..]));
    assert_eq!(current_thread_step(b"vCont;s:p1.3;c"), None);
    assert_eq!(current_thread_step(b"vCont;c"), None);
    assert_eq!(current_thread_step(b"vCont;S"), None);
}

/// gdb files the segment bases and system registers under `general`, which
/// clients read on every stop; Ghidra's gdb agent gives up at the first
/// unavailable one. So an optional register the transport lacks (KD has no
/// segment bases) must not be described at all, while a required one (x87)
/// stays and reads as unavailable.
#[test]
fn optional_registers_the_transport_lacks_are_not_described() {
    let map = build_register_map();
    let xml = Layout::new(Arch::Amd64, &map).target_xml().to_string();
    for absent in ["\"fs_base\"", "\"gs_base\"", "\"k_gs_base\""] {
        assert!(!xml.contains(absent), "{absent} described");
    }
    for present in ["\"dr7\"", "\"cr3\"", "\"st0\"", "\"rip\""] {
        assert!(xml.contains(present), "{present} missing");
    }
}
