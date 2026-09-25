//! Tests for guest memory access and its per-halt line caches.

use super::*;

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::thread::{JoinHandle, spawn};

use crate::backend::MemoryOps;
use crate::guest::{Guest, Image};
use crate::kd::framing::{
    INITIAL_PACKET_ID, PACKET_TYPE_KD_ACKNOWLEDGE, PACKET_TYPE_KD_STATE_MANIPULATE, control_packet,
    data_packet,
};
use crate::kd::memory::KD_VIRTUAL_LINE;
use crate::kd::registers::{KSPECIAL_REGISTERS_CR3_OFFSET, KSPECIAL_REGISTERS_MIN_SIZE};
use crate::layout::{FieldInfo, ParsedType, TypeInfo};
use crate::memory::PAGE_SIZE;
use crate::phys::PhysMem;
use crate::symbols::SymbolStore;

fn physical_memory_reply_payload(processor: u16, addr: u64, data: &[u8]) -> Vec<u8> {
    const MANIPULATE_UNION_OFFSET: usize = 16;

    let mut payload = vec![0u8; api::MANIPULATE_HEADER_SIZE];
    payload[0..4].copy_from_slice(&api::DBGKD_READ_PHYSICAL_MEMORY.to_le_bytes());
    payload[6..8].copy_from_slice(&processor.to_le_bytes());
    payload[MANIPULATE_UNION_OFFSET..MANIPULATE_UNION_OFFSET + 8]
        .copy_from_slice(&addr.to_le_bytes());
    payload[MANIPULATE_UNION_OFFSET + 8..MANIPULATE_UNION_OFFSET + 12]
        .copy_from_slice(&(data.len() as u32).to_le_bytes());
    payload[MANIPULATE_UNION_OFFSET + 12..MANIPULATE_UNION_OFFSET + 16]
        .copy_from_slice(&(data.len() as u32).to_le_bytes());
    payload.extend_from_slice(data);
    payload
}

#[test]
fn kd_memory_reads_physical_bytes_through_shared_backend() {
    let (mut kernel, host) = UnixStream::pair().unwrap();
    let mut backend = kd_backend_with_framing(host);
    backend.link.halt();
    backend.exit_prepared = true;
    let inner = Arc::new(Mutex::new(backend));
    let memory = KdMemory {
        inner: Arc::clone(&inner),
        translations: Arc::new(TranslationCache::default()),
    };
    let expected = [0xde, 0xad, 0xbe, 0xef];

    let worker = spawn(move || {
        let request = read_wire_packet(&mut kernel);
        let packet_id = wire_header(&request).packet_id;
        assert_eq!(
            u32::from_le_bytes(request[16..20].try_into().unwrap()),
            api::DBGKD_READ_PHYSICAL_MEMORY
        );
        assert_eq!(
            u64::from_le_bytes(request[32..40].try_into().unwrap()),
            0x1234_5000
        );
        kernel
            .write_all(&control_packet(PACKET_TYPE_KD_ACKNOWLEDGE, packet_id))
            .unwrap();
        let reply = physical_memory_reply_payload(0, 0x1234_5000, &expected);
        kernel
            .write_all(&data_packet(
                PACKET_TYPE_KD_STATE_MANIPULATE,
                INITIAL_PACKET_ID,
                &reply,
            ))
            .unwrap();
        let ack = read_wire_packet(&mut kernel);
        assert_eq!(wire_header(&ack).packet_type, PACKET_TYPE_KD_ACKNOWLEDGE);
    });

    let mut actual = [0u8; 4];
    memory.read_bytes(0x1234_5000, &mut actual).unwrap();
    worker.join().unwrap();
    assert_eq!(actual, expected);
}

/// A reload revalidates host memory while holding the backend lock. With KD
/// as the memory source, a read through it needed that same lock and the
/// reload never returned.
#[test]
fn a_reload_over_kd_memory_does_not_wait_on_its_own_backend() {
    let (_kernel, host) = UnixStream::pair().unwrap();
    let mut backend = kd_backend_with_framing(host);
    backend.link.halt();
    backend.exit_prepared = true;
    let (mut handle, memory) = backend.into_remote_memory();
    let phys = PhysMem::remote(memory);

    let (done, finished) = std::sync::mpsc::channel();
    spawn(move || {
        let result = handle.revalidate_host_memory(&phys);
        let _ = done.send(result.is_ok());
    });
    assert_eq!(
        finished.recv_timeout(std::time::Duration::from_secs(5)),
        Ok(true)
    );
}

#[test]
fn kd_memory_rejects_reads_while_target_runs() {
    let (_kernel, host) = UnixStream::pair().unwrap();
    let mut backend = kd_backend_with_framing(host);
    backend.exit_prepared = true;
    let memory = KdMemory {
        inner: Arc::new(Mutex::new(backend)),
        translations: Arc::new(TranslationCache::default()),
    };
    let error = memory.read_bytes(0x1000, &mut [0u8; 8]).unwrap_err();
    assert!(matches!(error, Error::TargetRunning(_)), "{error}");
}

/// A halted fake kernel serving `DbgKd{Read,Write}VirtualMemory` and
/// `DbgKdReadPhysicalMemory` from one map of regions (a region's address
/// is whichever kind the request names) until the host hangs up; returns
/// the request count so tests can assert how many round trips a guest
/// walk costs.
/// Like a real one it answers a request that touches mapped memory in
/// full, with zeros where no region says otherwise, and refuses one that
/// touches none.
fn serve_virtual_memory(kernel: UnixStream, regions: Vec<(u64, Vec<u8>)>) -> JoinHandle<usize> {
    serve_virtual_memory_capped(kernel, regions, usize::MAX)
}

/// [`serve_virtual_memory`] over a transport whose reply carries at most
/// `reply_cap` bytes of data, as a KDNET datagram does.
fn serve_virtual_memory_capped(
    mut kernel: UnixStream,
    mut regions: Vec<(u64, Vec<u8>)>,
    reply_cap: usize,
) -> JoinHandle<usize> {
    const UNION: usize = 16;
    spawn(move || {
        let mut kernel_id = INITIAL_PACKET_ID;
        let mut served = 0usize;
        loop {
            let Some(request) = recv_host_request(&mut kernel) else {
                return served;
            };

            let api_number = u32::from_le_bytes(request[0..4].try_into().unwrap());
            let addr = u64::from_le_bytes(request[UNION..UNION + 8].try_into().unwrap());
            let wanted =
                u32::from_le_bytes(request[UNION + 8..UNION + 12].try_into().unwrap()) as usize;
            served += 1;

            let mut reply = vec![0u8; api::MANIPULATE_HEADER_SIZE];
            reply[0..4].copy_from_slice(&api_number.to_le_bytes());
            reply[UNION..UNION + 8].copy_from_slice(&addr.to_le_bytes());
            reply[UNION + 8..UNION + 12].copy_from_slice(&(wanted as u32).to_le_bytes());
            if api_number == api::DBGKD_WRITE_VIRTUAL_MEMORY {
                let payload = &request[api::MANIPULATE_HEADER_SIZE..][..wanted];
                for (base, bytes) in &mut regions {
                    if let Some(start) = addr.checked_sub(*base)
                        && let Some(slot) = bytes.get_mut(start as usize..start as usize + wanted)
                    {
                        slot.copy_from_slice(payload);
                    }
                }
                reply[UNION + 12..UNION + 16].copy_from_slice(&(wanted as u32).to_le_bytes());
                kernel
                    .write_all(&data_packet(
                        PACKET_TYPE_KD_STATE_MANIPULATE,
                        kernel_id,
                        &reply,
                    ))
                    .unwrap();
                kernel_id ^= 1;
                continue;
            }
            assert!(matches!(
                api_number,
                api::DBGKD_READ_VIRTUAL_MEMORY | api::DBGKD_READ_PHYSICAL_MEMORY
            ));
            let mut data = vec![0u8; wanted];
            let mut mapped = false;
            for (base, bytes) in &regions {
                let start = (*base).max(addr);
                let end = (*base + bytes.len() as u64).min(addr + wanted as u64);
                if start < end {
                    mapped = true;
                    let from = (start - *base) as usize;
                    let to = (start - addr) as usize;
                    let len = (end - start) as usize;
                    data[to..to + len].copy_from_slice(&bytes[from..from + len]);
                }
            }
            if mapped {
                let sent = wanted.min(reply_cap);
                reply[UNION + 12..UNION + 16].copy_from_slice(&(sent as u32).to_le_bytes());
                reply.extend_from_slice(&data[..sent]);
            } else {
                reply[8..12].copy_from_slice(&0xC000_0005u32.to_le_bytes());
            }
            kernel
                .write_all(&data_packet(
                    PACKET_TYPE_KD_STATE_MANIPULATE,
                    kernel_id,
                    &reply,
                ))
                .unwrap();
            kernel_id ^= 1;
        }
    })
}

const FAKE_KERNEL_DTB: u64 = 0x1ad000;
const FAKE_KERNEL_BASE: u64 = 0xffff_f800_0000_0000;
const FAKE_GUID: u128 = 0x51;

fn field(offset: u32, size: u64, type_data: ParsedType) -> FieldInfo {
    FieldInfo {
        offset,
        size,
        type_data,
    }
}

fn primitive(offset: u32, size: u64) -> FieldInfo {
    field(offset, size, ParsedType::Primitive("u".into()))
}

fn layout(name: &str, size: usize, fields: &[(&str, FieldInfo)]) -> TypeInfo {
    TypeInfo {
        name: name.to_string(),
        pointer_size: 8,
        size,
        fields: fields
            .iter()
            .map(|(name, info)| (name.to_string(), info.clone()))
            .collect(),
    }
}

/// Build a halted KD-backed guest over `regions` with `types` and
/// `symbols` standing in for the kernel PDB. The backend is returned so a
/// test can resume it; the join handle yields the request count.
fn synthetic_guest(
    regions: Vec<(u64, Vec<u8>)>,
    types: Vec<TypeInfo>,
    symbols: &[(&str, u32)],
) -> (Guest, Arc<Mutex<KdBackend>>, JoinHandle<usize>) {
    let (kernel, host) = UnixStream::pair().unwrap();
    let mut backend = kd_backend_with_framing(host);
    backend.link.halt();
    backend.exit_prepared = true;
    backend.kernel_dtb_override = FAKE_KERNEL_DTB;
    let translations = Arc::clone(&backend.translations);
    let inner = Arc::new(Mutex::new(backend));
    let phys = Arc::new(PhysMem::remote(KdMemory {
        inner: Arc::clone(&inner),
        translations,
    }));
    let store = Arc::new(SymbolStore::new());
    store.inject_module_for_test(FAKE_GUID, types, symbols);
    let mut ntoskrnl = Image::new(
        phys,
        store,
        FAKE_KERNEL_DTB,
        VirtAddr(FAKE_KERNEL_BASE),
        Arch::Amd64,
    );
    ntoskrnl.guid = Some(FAKE_GUID);
    let worker = serve_virtual_memory(kernel, regions);
    (Guest::from_kernel(ntoskrnl), inner, worker)
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn resume_and_halt(backend: &Arc<Mutex<KdBackend>>) {
    let mut backend = backend.lock().unwrap();
    backend.record_running();
    backend.link.halt();
}

const SMSS_EPROCESS: u64 = 0xffff_e000_0002_0000;

/// A halted guest whose process list is System (root `0x1ad000`) and
/// smss.exe (`SMSS_EPROCESS`, root `0x2be000`, KVA-shadow user root
/// `0x2bf000` stored with PCID bits).
fn two_process_guest() -> (Guest, Arc<Mutex<KdBackend>>, JoinHandle<usize>) {
    const PID: u32 = 0x440;
    const LINKS: u32 = 0x448;
    const NAME: u32 = 0x5a8;
    const DTB: u32 = 0x28;
    const USER_DTB: u32 = 0x388;
    let eprocess = layout(
        "_EPROCESS",
        0x600,
        &[
            (
                "Pcb",
                field(0, 0x438, ParsedType::Struct("_KPROCESS".into())),
            ),
            ("UniqueProcessId", primitive(PID, 8)),
            ("ActiveProcessLinks", primitive(LINKS, 16)),
            ("ImageFileName", primitive(NAME, 15)),
        ],
    );
    let kprocess = layout(
        "_KPROCESS",
        0x438,
        &[
            ("DirectoryTableBase", primitive(DTB, 8)),
            ("UserDirectoryTableBase", primitive(USER_DTB, 8)),
        ],
    );

    let head = FAKE_KERNEL_BASE + 0x1008;
    let system = 0xffff_e000_0001_0000u64;
    let mut nt = vec![0u8; 0x2000];
    put_u64(&mut nt, 0x1000, system);
    put_u64(&mut nt, 0x1008, system + LINKS as u64);
    let process = |pid: u64, dtb: u64, user_dtb: u64, name: &[u8], next: u64| {
        let mut bytes = vec![0u8; 0x600];
        put_u64(&mut bytes, PID as usize, pid);
        put_u64(&mut bytes, DTB as usize, dtb);
        put_u64(&mut bytes, USER_DTB as usize, user_dtb);
        put_u64(&mut bytes, LINKS as usize, next + LINKS as u64);
        bytes[NAME as usize..NAME as usize + name.len()].copy_from_slice(name);
        bytes
    };
    let regions = vec![
        (FAKE_KERNEL_BASE, nt),
        (system, process(4, 0x1ad000, 0, b"System", SMSS_EPROCESS)),
        (
            SMSS_EPROCESS,
            process(0x1d8, 0x2be000, 0x2bf002, b"smss.exe", head - LINKS as u64),
        ),
    ];
    synthetic_guest(
        regions,
        vec![eprocess, kprocess],
        &[
            ("PsInitialSystemProcess", 0x1000),
            ("PsActiveProcessHead", 0x1008),
        ],
    )
}

#[test]
fn process_walk_reads_one_span_per_process_and_memoizes_per_halt() {
    let (guest, backend, worker) = two_process_guest();

    let first = guest.enumerate_processes().unwrap();
    let names: Vec<_> = first.iter().map(|p| (p.name.as_str(), p.pid)).collect();
    assert_eq!(names, [("System", 4), ("smss.exe", 0x1d8)]);
    assert_eq!(first[1].dtb, 0x2be000);

    let second = guest.enumerate_processes().unwrap();
    assert_eq!(second.len(), 2);
    let one = guest.process_at(VirtAddr(SMSS_EPROCESS)).unwrap();
    assert_eq!(
        (one.name.as_str(), one.pid, one.dtb),
        ("smss.exe", 0x1d8, 0x2be000)
    );

    resume_and_halt(&backend);
    assert_eq!(guest.enumerate_processes().unwrap().len(), 2);

    drop(guest);
    drop(backend);
    // The list head and each process span are one fill apiece, the
    // single-process lookup is served from the halt's lines, and the
    // resume drops them: three fills per halt.
    assert_eq!(worker.join().unwrap(), 3 + 3);
}

/// A KVA-shadow user root, what CR3 holds at a user-mode stop, names the
/// process whose `UserDirectoryTableBase` it is.
#[test]
fn kva_shadow_user_root_resolves_to_its_process() {
    let (guest, backend, worker) = two_process_guest();
    let mask = Arch::Amd64.dtb_page_mask();

    let owner = guest.process_for_user_root(0x2bf000, mask).unwrap();

    assert_eq!((owner.pid, owner.dtb), (0x1d8, 0x2be000));
    assert!(guest.process_for_user_root(0x3c0000, mask).is_none());

    drop(guest);
    drop(backend);
    worker.join().unwrap();
}

#[test]
fn user_space_of_the_current_process_is_read_in_one_request() {
    const USER_VA: u64 = 0x7ff6_1234_5000;
    const CURRENT_CR3: u64 = 0x2be000;
    let regions = vec![(USER_VA, b"PEB!".to_vec())];
    let (guest, backend, worker) = synthetic_guest(regions, Vec::new(), &[]);
    {
        let mut backend = backend.lock().unwrap();
        let mut special = vec![0u8; KSPECIAL_REGISTERS_MIN_SIZE];
        // PCID bits in CR3 do not distinguish roots.
        put_u64(
            &mut special,
            KSPECIAL_REGISTERS_CR3_OFFSET,
            CURRENT_CR3 | 0x1,
        );
        let processor = backend.current_processor;
        backend.registers.set_special(processor, special);

        let mut out = [0u8; 4];
        // Another process's user space still needs the host walk.
        assert!(
            backend
                .read_virtual_direct(VirtAddr(USER_VA), 0x3cf000, &mut out)
                .is_none()
        );
        backend
            .read_virtual_direct(VirtAddr(USER_VA), CURRENT_CR3, &mut out)
            .unwrap()
            .unwrap();
        assert_eq!(&out, b"PEB!");
    }
    drop(guest);
    drop(backend);
    assert_eq!(worker.join().unwrap(), 1);
}

#[test]
fn kernel_module_walk_prefetches_each_record() {
    const DLL_BASE: u32 = 0x30;
    const SIZE: u32 = 0x40;
    const NAME: u32 = 0x58;
    const TIME_DATE_STAMP: u32 = 0x9c;
    const CHECK_SUM: u32 = 0x100;
    let entry = layout(
        "_KLDR_DATA_TABLE_ENTRY",
        0x120,
        &[
            ("InLoadOrderLinks", primitive(0, 16)),
            ("DllBase", primitive(DLL_BASE, 8)),
            ("SizeOfImage", primitive(SIZE, 4)),
            (
                "BaseDllName",
                field(NAME, 16, ParsedType::Struct("_UNICODE_STRING".into())),
            ),
            ("TimeDateStamp", primitive(TIME_DATE_STAMP, 4)),
            ("CheckSum", primitive(CHECK_SUM, 4)),
        ],
    );
    let unicode = layout(
        "_UNICODE_STRING",
        16,
        &[("Length", primitive(0, 2)), ("Buffer", primitive(8, 8))],
    );

    let head = FAKE_KERNEL_BASE + 0x2000;
    let names = 0xffff_e000_0009_0000u64;
    let entries = 0xffff_e000_000a_0000u64;
    let mut nt = vec![0u8; 0x3000];
    put_u64(&mut nt, 0x2000, entries);
    let name_bytes: Vec<u8> = "ntoskrnl.exe\0\0\0\0hal.dll"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let mut records = vec![0u8; 0x240];
    let mut record = |at: usize, next: u64, base: u64, name_off: u64, name_len: u16| {
        put_u64(&mut records, at, next);
        put_u64(&mut records, at + DLL_BASE as usize, base);
        records[at + SIZE as usize..at + SIZE as usize + 4]
            .copy_from_slice(&0x1000u32.to_le_bytes());
        records[at + NAME as usize..at + NAME as usize + 2]
            .copy_from_slice(&name_len.to_le_bytes());
        put_u64(&mut records, at + NAME as usize + 8, names + name_off);
    };
    record(0, entries + 0x120, FAKE_KERNEL_BASE, 0, 24);
    record(0x120, head, 0xffff_f800_1000_0000, 32, 14);
    let regions = vec![
        (FAKE_KERNEL_BASE, nt),
        (names, name_bytes),
        (entries, records),
    ];
    let (guest, backend, worker) = synthetic_guest(
        regions,
        vec![entry, unicode],
        &[("PsLoadedModuleList", 0x2000)],
    );

    let modules = guest.kernel_modules().unwrap();
    let seen: Vec<_> = modules
        .iter()
        .map(|m| (m.name.as_str(), m.base_address.0))
        .collect();
    assert_eq!(
        seen,
        [
            ("ntoskrnl.exe", FAKE_KERNEL_BASE),
            ("hal.dll", 0xffff_f800_1000_0000)
        ]
    );
    assert_eq!(guest.kernel_modules().unwrap().len(), 2);

    drop(guest);
    drop(backend);
    // The list head; the first record and both names fill their lines,
    // and the second record's tail spills into one more.
    assert_eq!(worker.join().unwrap(), 1 + 2 + 1);
}

#[test]
fn virtual_lines_serve_a_halt_and_drop_on_write_and_resume() {
    const FIELD: u64 = FAKE_KERNEL_BASE + 0x1010;
    let mut nt = vec![0u8; 0x2000];
    put_u64(&mut nt, 0x1010, 0x1111);
    put_u64(&mut nt, 0x1018, 0x2222);
    let (guest, backend, worker) = synthetic_guest(vec![(FAKE_KERNEL_BASE, nt)], Vec::new(), &[]);
    let read = |at: u64| {
        let mut out = [0u8; 8];
        backend
            .lock()
            .unwrap()
            .read_virtual_bytes(VirtAddr(at), &mut out)
            .unwrap();
        u64::from_le_bytes(out)
    };

    // Two fields of one line: one request.
    assert_eq!(read(FIELD), 0x1111);
    assert_eq!(read(FIELD + 8), 0x2222);
    // A debugger write is visible to the next read.
    backend
        .lock()
        .unwrap()
        .write_virtual_bytes(VirtAddr(FIELD), &0x3333u64.to_le_bytes())
        .unwrap();
    assert_eq!(read(FIELD), 0x3333);
    // A line does not outlive the halt.
    resume_and_halt(&backend);
    assert_eq!(read(FIELD + 8), 0x2222);
    // A read past the last line is refused, not served with a hole.
    let mut out = [0u8; 8];
    let error = backend
        .lock()
        .unwrap()
        .read_virtual_bytes(VirtAddr(FAKE_KERNEL_BASE + 0x2000), &mut out)
        .unwrap_err();
    assert!(matches!(error, Error::BadVirtualAddress(_)), "{error}");

    drop(guest);
    drop(backend);
    // read, write, read, read, refused read
    assert_eq!(worker.join().unwrap(), 5);
}

#[test]
fn page_table_lines_serve_a_halt_and_drop_on_write_and_resume() {
    const TABLE: u64 = 0x1ad000;
    let mut table = vec![0u8; PAGE_SIZE];
    put_u64(&mut table, 0x10, 0x1111);
    put_u64(&mut table, 0x18, 0x2222);
    put_u64(&mut table, 0x800, 0x3333);
    let (guest, backend, worker) = synthetic_guest(vec![(TABLE, table)], Vec::new(), &[]);
    let read = |at: u64| {
        let mut out = [0u8; 8];
        backend
            .lock()
            .unwrap()
            .read_page_table_bytes(at, &mut out)
            .unwrap();
        u64::from_le_bytes(out)
    };

    // Two entries of one line: one request; another line: one more.
    assert_eq!(read(TABLE + 0x10), 0x1111);
    assert_eq!(read(TABLE + 0x18), 0x2222);
    assert_eq!(read(TABLE + 0x800), 0x3333);
    // A virtual write may land in a table: the lines are dropped.
    backend
        .lock()
        .unwrap()
        .write_virtual_bytes(VirtAddr(FAKE_KERNEL_BASE), &[0u8; 8])
        .unwrap();
    assert_eq!(read(TABLE + 0x10), 0x1111);
    resume_and_halt(&backend);
    assert_eq!(read(TABLE + 0x18), 0x2222);

    drop(guest);
    drop(backend);
    // two lines, write, line, line
    assert_eq!(worker.join().unwrap(), 5);
}

#[test]
fn truncated_fills_keep_whole_lines_and_finish_the_read() {
    let (kernel, host) = UnixStream::pair().unwrap();
    let mut backend = kd_backend_with_framing(host);
    backend.link.halt();
    backend.exit_prepared = true;
    let bytes: Vec<u8> = (0..0x1000u32).map(|i| i as u8 ^ (i >> 8) as u8).collect();
    let worker =
        serve_virtual_memory_capped(kernel, vec![(FAKE_KERNEL_BASE, bytes.clone())], 0x300);

    let mut out = vec![0u8; 0x800];
    backend
        .read_virtual_bytes(VirtAddr(FAKE_KERNEL_BASE), &mut out)
        .unwrap();
    assert_eq!(out, bytes[..0x800]);
    // The tail of the truncated reply was not kept as a short line.
    let mut tail = [0u8; 8];
    backend
        .read_virtual_bytes(VirtAddr(FAKE_KERNEL_BASE + 0x2f8), &mut tail)
        .unwrap();
    assert_eq!(tail, bytes[0x2f8..0x300]);
    // Later fills stay within what the transport returns.
    assert_eq!(backend.virtual_fill_cap, KD_VIRTUAL_LINE);

    drop(backend);
    // 0x800 asked and 0x300 answered, then one line per request.
    assert_eq!(worker.join().unwrap(), 1 + 3);
}
