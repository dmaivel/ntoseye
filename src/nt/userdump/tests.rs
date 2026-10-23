//! Synthetic minidumps, laid out as `MiniDumpWriteDump` lays them out, to
//! check the parser's bounds, both memory list encodings, the module and
//! thread records, and the refusals.

use std::collections::HashMap;

use memmap2::MmapMut;

use super::*;
use crate::arch::{amd64, arm64};
use crate::backend::dbg_backend::DebugBackend;
use crate::base::error::Error;
use crate::base::memory::read_page_chunks;

const AMD64: u16 = 9;
const ARM64: u16 = 12;
const WIN32_NT: u32 = 2;

/// A minidump under construction: blobs are appended after the header and
/// a directory sized for every stream, and the streams that point at them
/// are appended last.
struct Builder {
    data: Vec<u8>,
    streams: Vec<(u32, u32, u32)>,
    capacity: usize,
}

impl Builder {
    fn new(capacity: usize) -> Self {
        Self {
            data: vec![0; 32 + capacity * 12],
            streams: Vec::new(),
            capacity,
        }
    }

    /// Append `bytes` 8-byte aligned, returning their RVA.
    fn blob(&mut self, bytes: &[u8]) -> u32 {
        while !self.data.len().is_multiple_of(8) {
            self.data.push(0);
        }
        let rva = self.data.len() as u32;
        self.data.extend_from_slice(bytes);
        rva
    }

    fn string(&mut self, text: &str) -> u32 {
        let units: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut bytes = (units.len() as u32).to_le_bytes().to_vec();
        bytes.extend_from_slice(&units);
        bytes.extend_from_slice(&[0, 0]);
        self.blob(&bytes)
    }

    fn stream(&mut self, kind: u32, bytes: &[u8]) {
        let rva = self.blob(bytes);
        self.streams.push((kind, bytes.len() as u32, rva));
    }

    fn system_info(&mut self, architecture: u16, platform: u32) {
        let mut info = vec![0u8; 56];
        info[0..2].copy_from_slice(&architecture.to_le_bytes());
        info[6] = 4;
        info[8..12].copy_from_slice(&10u32.to_le_bytes());
        info[16..20].copy_from_slice(&26100u32.to_le_bytes());
        info[20..24].copy_from_slice(&platform.to_le_bytes());
        self.stream(7, &info);
    }

    fn finish(mut self) -> Vec<u8> {
        assert!(self.streams.len() <= self.capacity);
        let header = &mut self.data[..32];
        header[0..4].copy_from_slice(b"MDMP");
        header[4..8].copy_from_slice(&0xa793u32.to_le_bytes());
        header[8..12].copy_from_slice(&(self.capacity as u32).to_le_bytes());
        header[12..16].copy_from_slice(&32u32.to_le_bytes());
        for (index, (kind, size, rva)) in self.streams.iter().enumerate() {
            let at = 32 + index * 12;
            self.data[at..at + 4].copy_from_slice(&kind.to_le_bytes());
            self.data[at + 4..at + 8].copy_from_slice(&size.to_le_bytes());
            self.data[at + 8..at + 12].copy_from_slice(&rva.to_le_bytes());
        }
        self.data
    }
}

fn open(bytes: &[u8]) -> Result<UserDump> {
    let mut mmap = MmapMut::map_anon(bytes.len()).unwrap();
    mmap.copy_from_slice(bytes);
    UserDump::from_mmap(mmap.make_read_only().unwrap())
}

fn u32s(values: &[u32]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

fn u64s(values: &[u64]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

/// An AMD64 CONTEXT with `flags`, `rip`, and `rsp`.
fn amd64_context(flags: u32, rip: u64, rsp: u64) -> Vec<u8> {
    let mut context = vec![0u8; amd64::CONTEXT_SIZE];
    context[amd64::OFFSET_CONTEXT_FLAGS..amd64::OFFSET_CONTEXT_FLAGS + 4]
        .copy_from_slice(&flags.to_le_bytes());
    context[amd64::OFFSET_RIP..amd64::OFFSET_RIP + 8].copy_from_slice(&rip.to_le_bytes());
    context[amd64::OFFSET_RSP..amd64::OFFSET_RSP + 8].copy_from_slice(&rsp.to_le_bytes());
    context
}

/// A `MINIDUMP_THREAD` whose stack is `stack` at `stack_start` and whose
/// context is at `context_rva`.
fn thread_record(
    tid: u32,
    teb: u64,
    stack_start: u64,
    stack: (u32, u32),
    context: (u32, u32),
) -> Vec<u8> {
    let mut record = u32s(&[tid, 0, 0x20, 0]);
    record.extend(u64s(&[teb, stack_start]));
    record.extend(u32s(&[stack.0, stack.1, context.0, context.1]));
    record
}

#[test]
fn both_memory_lists_and_thread_stacks_serve_reads_with_holes_reported() {
    let mut builder = Builder::new(4);
    builder.system_info(AMD64, WIN32_NT);
    // Memory64List: two ranges stored back to back from BaseRva.
    let first: Vec<u8> = (0..0x100u32).map(|byte| byte as u8).collect();
    let second = vec![0xbb; 0x80];
    let mut contiguous = first.clone();
    contiguous.extend_from_slice(&second);
    let base_rva = builder.blob(&contiguous);
    let mut list64 = u64s(&[2, u64::from(base_rva)]);
    list64.extend(u64s(&[0x10000, 0x100, 0x10200, 0x80]));
    builder.stream(9, &list64);
    // MemoryList: overlaps the first range's tail; only the part past it is
    // new, so the Memory64List bytes win where both have one.
    let overlapping = builder.blob(&[0xcc; 0x40]);
    let mut list = u32s(&[1]);
    list.extend(u64s(&[0x100e0]));
    list.extend(u32s(&[0x40, overlapping]));
    builder.stream(5, &list);
    // A thread whose stack is in no list.
    let stack = builder.blob(&[0x5a; 0x30]);
    let context = amd64_context(amd64::CONTEXT_CONTROL | amd64::CONTEXT_INTEGER, 1, 2);
    let context_rva = builder.blob(&context);
    let mut threads = u32s(&[1]);
    threads.extend(thread_record(
        0x44,
        0x7000,
        0x20010,
        (0x30, stack),
        (context.len() as u32, context_rva),
    ));
    builder.stream(3, &threads);
    let dump = open(&builder.finish()).unwrap();

    let mut buf = [0u8; 0x20];
    dump.read_virtual(VirtAddr(0x100f0), &mut buf).unwrap();
    assert_eq!(&buf[..0x10], &first[0xf0..]);
    assert_eq!(&buf[0x10..], &[0xcc; 0x10]);

    let mut stack_bytes = [0u8; 0x30];
    dump.read_virtual(VirtAddr(0x20010), &mut stack_bytes)
        .unwrap();
    assert_eq!(stack_bytes, [0x5a; 0x30]);
    let stack = dump.info().threads[0].stack.unwrap();
    assert_eq!((stack.start, stack.size), (0x20010, 0x30));

    // A read running off the first block stops at the hole and names where
    // the capture resumes.
    let mut across = [0u8; 0x200];
    match dump.read_virtual(VirtAddr(0x10100), &mut across) {
        Err(Error::NotCaptured { address, resumes }) => {
            assert_eq!(address, VirtAddr(0x10120));
            assert_eq!(resumes, Some(VirtAddr(0x10200)));
        }
        other => panic!("expected a hole, got {other:?}"),
    }
    assert!(matches!(
        dump.read_virtual(VirtAddr(0x30000), &mut buf),
        Err(Error::NotCaptured { resumes: None, .. })
    ));

    // The page holding both Memory64List ranges reads in part.
    let (bytes, valid) = read_page_chunks(VirtAddr(0x10000), 0x1000, |address, buf| {
        dump.read_virtual(address, buf)
    })
    .unwrap();
    assert!(valid[..0x120].iter().all(|byte| *byte));
    assert!(!valid[0x120..0x200].iter().any(|byte| *byte));
    assert!(valid[0x200..0x280].iter().all(|byte| *byte));
    assert!(!valid[0x280..].iter().any(|byte| *byte));
    assert_eq!(&bytes[0x200..0x280], &second[..]);
}

#[test]
fn a_memory_range_cut_short_by_the_file_keeps_what_is_there() {
    let mut builder = Builder::new(2);
    builder.system_info(AMD64, WIN32_NT);
    let mut list = u32s(&[1]);
    list.extend(u64s(&[0x5000]));
    // Stored at the very end of the file, claiming more than follows.
    let data_rva = builder.data.len() as u32 + 4 + 16 + 4;
    list.extend(u32s(&[0x1000, data_rva]));
    builder.stream(5, &list);
    let mut bytes = builder.finish();
    let end = data_rva as usize;
    bytes.resize(end, 0);
    bytes.extend_from_slice(&[0x77; 0x10]);
    let dump = open(&bytes).unwrap();
    assert_eq!(
        dump.memory_ranges(),
        &[MemoryRange {
            start: 0x5000,
            length: 0x10,
            offset: end as u64,
        }]
    );
}

#[test]
fn directory_and_stream_bounds_are_checked() {
    // A directory claiming more entries than the file holds.
    let mut builder = Builder::new(1);
    builder.system_info(AMD64, WIN32_NT);
    let mut bytes = builder.finish();
    bytes[8..12].copy_from_slice(&0x0fffu32.to_le_bytes());
    assert!(matches!(open(&bytes), Err(Error::InvalidDump(_))));

    // A module list whose location leaves the file is noted and skipped.
    let mut builder = Builder::new(2);
    builder.system_info(AMD64, WIN32_NT);
    builder.streams.push((4, 0x1000, 0x7fff_0000));
    let dump = open(&builder.finish()).unwrap();
    assert!(dump.info().modules.is_empty());
    assert!(
        dump.info()
            .notes
            .iter()
            .any(|note| note.contains("ModuleListStream") && note.contains("leaves the file"))
    );

    // No SystemInfoStream: the architecture is unknown.
    let builder = Builder::new(0);
    assert!(matches!(
        open(&builder.finish()),
        Err(Error::InvalidDump(_))
    ));
}

#[test]
fn breakpad_and_unsupported_architectures_are_refused() {
    let mut builder = Builder::new(1);
    builder.system_info(AMD64, 0x8201);
    let error = open(&builder.finish())
        .err()
        .expect("a Linux minidump is refused");
    assert!(matches!(error, Error::UnsupportedDump(_)));
    assert!(error.to_string().contains("Linux"));

    let mut builder = Builder::new(1);
    builder.system_info(0, WIN32_NT);
    let error = open(&builder.finish())
        .err()
        .expect("an x86 minidump is refused");
    assert!(matches!(error, Error::UnsupportedArchitecture(_)));
    assert!(error.to_string().contains("x86"));
}

#[test]
fn module_records_carry_name_version_and_codeview_identity() {
    let mut builder = Builder::new(2);
    builder.system_info(AMD64, WIN32_NT);
    let name = builder.string(r"C:\Windows\System32\ntdll.dll");
    let mut codeview = b"RSDS".to_vec();
    codeview.extend_from_slice(&0x1234_5678u32.to_le_bytes());
    codeview.extend_from_slice(&0x9abcu16.to_le_bytes());
    codeview.extend_from_slice(&0xdef0u16.to_le_bytes());
    codeview.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    codeview.extend_from_slice(&3u32.to_le_bytes());
    codeview.extend_from_slice(b"ntdll.pdb\0");
    let codeview_rva = builder.blob(&codeview);
    let mut version = [0u32; 13];
    version[0] = 0xfeef_04bd;
    version[2] = 10 << 16;
    version[3] = (26100 << 16) | 9444;
    version[4] = 10 << 16;
    version[5] = 26100 << 16;
    let mut module = u64s(&[0x7ff9_4926_0000]);
    module.extend(u32s(&[0x267000, 0xabcd, 0x1122_3344, name]));
    module.extend(u32s(&version));
    module.extend(u32s(&[codeview.len() as u32, codeview_rva, 0, 0]));
    module.extend(u64s(&[0, 0]));
    assert_eq!(module.len(), 108);
    let mut list = u32s(&[1]);
    list.extend(module);
    builder.stream(4, &list);
    let dump = open(&builder.finish()).unwrap();

    let module = &dump.info().modules[0];
    assert_eq!(module.path, r"C:\Windows\System32\ntdll.dll");
    assert_eq!(module.version.as_ref().unwrap().0, "10.0.26100.9444");
    let info = module.to_module_info();
    assert_eq!(info.name, "ntdll.dll");
    assert_eq!(info.short_name, "ntdll");
    assert_eq!(info.time_date_stamp, Some(0x1122_3344));
    assert_eq!(info.size, 0x267000);
    match info.codeview {
        Some(CodeView::Rsds { guid, age, path }) => {
            assert_eq!(guid.Data1, 0x1234_5678);
            assert_eq!(guid.Data4, [1, 2, 3, 4, 5, 6, 7, 8]);
            assert_eq!(age, 3);
            assert_eq!(path, "ntdll.pdb");
        }
        other => panic!("expected an RSDS record, got {other:?}"),
    }
    assert_eq!(dump.info().process_name(), Some("ntdll.dll"));
}

#[test]
fn amd64_contexts_are_checked_and_thread_streams_merge_by_thread_id() {
    let mut builder = Builder::new(5);
    builder.system_info(AMD64, WIN32_NT);
    let good = amd64_context(
        amd64::CONTEXT_CONTROL | amd64::CONTEXT_INTEGER,
        0x7ff9_4651_1344,
        0xf3_5cfa_f788,
    );
    let good_rva = builder.blob(&good);
    // Control registers but no integer ones: not enough to place a thread.
    let partial = amd64_context(amd64::CONTEXT_CONTROL, 1, 2);
    let partial_rva = builder.blob(&partial);
    let size = amd64::CONTEXT_SIZE as u32;
    let mut threads = u32s(&[3]);
    threads.extend(thread_record(0x10, 0, 0, (0, 0), (size, good_rva)));
    threads.extend(thread_record(0x20, 0, 0, (0, 0), (size, partial_rva)));
    threads.extend(thread_record(0x30, 0, 0, (0, 0), (0x100, good_rva)));
    builder.stream(3, &threads);
    // Thread info and names, in another order than the thread list.
    let mut info = u32s(&[12, 64, 2]);
    for tid in [0x30u32, 0x10] {
        info.extend(u32s(&[tid, 0, 0, 0]));
        info.extend(u64s(&[0, 0, 0, 0, 0x1000 + u64::from(tid), 0xf]));
    }
    builder.stream(17, &info);
    let name = builder.string("worker");
    let mut names = u32s(&[1, 0x20]);
    names.extend(u64s(&[u64::from(name)]));
    builder.stream(24, &names);
    let dump = open(&builder.finish()).unwrap();
    let threads = &dump.info().threads;

    let map = Arch::Amd64.register_map();
    let registers = Arch::Amd64.register_buffer(threads[0].context.as_ref().unwrap());
    assert_eq!(map.read_u64("rip", &registers).unwrap(), 0x7ff9_4651_1344);
    assert_eq!(map.read_u64("rsp", &registers).unwrap(), 0xf3_5cfa_f788);
    assert_eq!(map.read_u64("cr3", &registers).unwrap(), 0);
    // Lacking integer registers, or shorter than a CONTEXT: unusable.
    assert!(threads[1].context.is_err());
    assert!(threads[2].context.is_err());

    assert_eq!(threads[0].times.as_ref().unwrap().start_address, 0x1010);
    assert_eq!(threads[2].times.as_ref().unwrap().start_address, 0x1030);
    assert!(threads[1].times.is_none());
    assert_eq!(threads[1].name.as_deref(), Some("worker"));

    // Only the groups the flags mark are registers of the context.
    let values = Arch::Amd64.context_registers(threads[0].context.as_ref().unwrap());
    assert_eq!(values.get("rip"), Some(&0x7ff9_4651_1344));
    assert!(!values.contains_key("dr7"));
    assert!(!values.contains_key("xmm0l"));
    assert!(!values.contains_key("cr3"));
}

#[test]
fn arm64_threads_and_the_exception_stream_carry_their_contexts() {
    let mut builder = Builder::new(3);
    builder.system_info(ARM64, WIN32_NT);
    let mut thread_context = vec![0u8; arm64::CONTEXT_SIZE];
    thread_context[..4]
        .copy_from_slice(&(arm64::CONTEXT_CONTROL | arm64::CONTEXT_INTEGER).to_le_bytes());
    thread_context[arm64::OFFSET_PC..arm64::OFFSET_PC + 8]
        .copy_from_slice(&0x7ffa_0000_1000u64.to_le_bytes());
    let thread_rva = builder.blob(&thread_context);
    let mut exception_context = thread_context.clone();
    exception_context[arm64::OFFSET_PC..arm64::OFFSET_PC + 8]
        .copy_from_slice(&0x7ffa_0000_2000u64.to_le_bytes());
    let exception_rva = builder.blob(&exception_context);
    let size = arm64::CONTEXT_SIZE as u32;
    let mut threads = u32s(&[2]);
    threads.extend(thread_record(0x100, 0, 0, (0, 0), (size, thread_rva)));
    threads.extend(thread_record(0x200, 0, 0, (0, 0), (size, thread_rva)));
    builder.stream(3, &threads);
    let mut exception = u32s(&[0x200, 0, 0xe0d7_e5e1, 1]);
    exception.extend(u64s(&[0, 0x7ffa_0000_2000]));
    exception.extend(u32s(&[2, 0]));
    let mut information = [0u64; 15];
    information[..2].copy_from_slice(&[7, 9]);
    exception.extend(u64s(&information));
    exception.extend(u32s(&[size, exception_rva]));
    assert_eq!(exception.len(), 168);
    builder.stream(6, &exception);
    let dump = open(&builder.finish()).unwrap();
    let info = dump.info();

    assert_eq!(info.arch, Arch::Arm64);
    let map = Arch::Arm64.register_map();
    let thread = Arch::Arm64.register_buffer(info.threads[0].context.as_ref().unwrap());
    assert_eq!(map.read_u64("pc", &thread).unwrap(), 0x7ffa_0000_1000);

    let exception = info.exception.as_ref().unwrap();
    assert_eq!(exception.thread_id, 0x200);
    assert_eq!(exception.code, 0xe0d7_e5e1);
    assert_eq!(exception.parameters, vec![7, 9]);
    let registers = Arch::Arm64.context_registers(exception.context.as_ref().unwrap());
    assert_eq!(registers.get("pc"), Some(&0x7ffa_0000_2000));

    // The backend starts on the exception's thread.
    let mut backend = UserDumpBackend::new(info);
    assert_eq!(backend.stopped_thread_id().unwrap(), "200");
    let registers = backend.read_registers().unwrap();
    assert_eq!(map.read_u64("pc", &registers).unwrap(), 0x7ffa_0000_1000);
    assert!(backend.set_current_thread("300").is_err());
    assert!(backend.write_registers(&registers).is_err());
}

/// A `MINIDUMP_HANDLE_DESCRIPTOR`, padded to `size` bytes (40 for
/// `MINIDUMP_HANDLE_DESCRIPTOR_2`).
fn handle_descriptor(handle: u64, names: (u32, u32), counts: [u32; 4], size: usize) -> Vec<u8> {
    let mut record = u64s(&[handle]);
    record.extend(u32s(&[names.0, names.1]));
    record.extend(u32s(&counts));
    record.resize(size, 0);
    record
}

#[test]
fn handle_data_reads_both_descriptor_sizes_and_keeps_a_handle_whose_name_is_unreadable() {
    for size in [32usize, 40] {
        let mut builder = Builder::new(2);
        builder.system_info(AMD64, WIN32_NT);
        let file = builder.string("File");
        let path = builder.string("\\Device\\HarddiskVolume3\\Windows");
        let mut stream = u32s(&[16, size as u32, 3, 0]);
        stream.extend(handle_descriptor(
            4,
            (file, path),
            [0, 0x10_0020, 1, 32769],
            size,
        ));
        // An object name outside the file.
        stream.extend(handle_descriptor(
            8,
            (file, 0x7fff_0000),
            [2, 0x1f_0003, 1, 2],
            size,
        ));
        // The third descriptor is cut off by the stream's end.
        stream.extend(vec![0u8; size / 2]);
        builder.stream(12, &stream);
        let dump = open(&builder.finish()).unwrap();
        let info = dump.info();
        let handles = info.handles.as_ref().unwrap();

        assert_eq!(handles.len(), 2, "descriptor size {size}");
        assert_eq!(handles[0].handle, 4);
        assert_eq!(handles[0].type_name.as_deref(), Some("File"));
        assert_eq!(
            handles[0].object_name.as_deref(),
            Some("\\Device\\HarddiskVolume3\\Windows")
        );
        assert_eq!(handles[0].granted_access, 0x10_0020);
        assert_eq!(
            (handles[0].handle_count, handles[0].pointer_count),
            (1, 32769)
        );
        assert_eq!(handles[1].attributes, 2);
        assert_eq!(handles[1].object_name, None);
        assert!(
            info.notes
                .iter()
                .any(|note| note.contains("handle 0x8 object name"))
        );
        assert!(
            info.notes
                .iter()
                .any(|note| note.contains("holds 2 of its 3"))
        );
    }

    // A descriptor size too small for the record is refused as a whole; a
    // dump without the stream has no handle list at all.
    let mut builder = Builder::new(2);
    builder.system_info(AMD64, WIN32_NT);
    builder.stream(12, &u32s(&[16, 24, 1, 0, 0, 0, 0, 0, 0, 0]));
    let dump = open(&builder.finish()).unwrap();
    assert_eq!(dump.info().handles.as_deref().map(<[_]>::len), Some(0));
    let mut builder = Builder::new(1);
    builder.system_info(AMD64, WIN32_NT);
    assert!(open(&builder.finish()).unwrap().info().handles.is_none());
}

#[test]
fn memory_info_regions_are_sorted_and_overlaps_and_empty_regions_dropped() {
    let mut builder = Builder::new(2);
    builder.system_info(AMD64, WIN32_NT);
    let region = |base: u64, size: u64, state: u32, protect: u32, kind: u32| {
        let mut entry = u64s(&[base, base]);
        entry.extend(u32s(&[protect, 0]));
        entry.extend(u64s(&[size]));
        entry.extend(u32s(&[state, protect, kind, 0]));
        entry
    };
    let mut stream = u32s(&[16, 48]);
    stream.extend(u64s(&[4]));
    stream.extend(region(0x20000, 0x3000, 0x1000, 0x04, 0x20000));
    stream.extend(region(0x10000, 0x10000, 0x10000, 0x01, 0));
    // Overlaps the region at 0x20000.
    stream.extend(region(0x21000, 0x1000, 0x1000, 0x20, 0x100_0000));
    stream.extend(region(0x40000, 0, 0x1000, 0x04, 0x20000));
    builder.stream(16, &stream);
    let dump = open(&builder.finish()).unwrap();
    let info = dump.info();
    let regions = info.regions.as_ref().unwrap();

    assert_eq!(
        regions.iter().map(|region| region.base).collect::<Vec<_>>(),
        [0x10000, 0x20000]
    );
    assert_eq!(
        info.region(0x22fff).map(|region| region.base),
        Some(0x20000)
    );
    assert_eq!(
        info.region(0x1ffff).map(|region| region.state),
        Some(0x10000)
    );
    assert!(info.region(0x23000).is_none());
    assert!(info.notes.iter().any(|note| note.contains("invalid size")));
    assert!(info.notes.iter().any(|note| note.contains("overlapping")));
}

#[test]
fn function_tables_follow_their_padding_and_resolve_code_outside_modules() {
    let mut builder = Builder::new(2);
    builder.system_info(AMD64, WIN32_NT);
    let native = vec![0xaau8; 136];
    let descriptor = |minimum: u64, maximum: u64, base: u64, count: u32, pad: u32| {
        let mut bytes = u64s(&[minimum, maximum, base]);
        bytes.extend(u32s(&[count, pad]));
        bytes.extend_from_slice(&native);
        bytes
    };
    // A header followed by 4 bytes of padding, as dbghelp writes it.
    let mut stream = u32s(&[24, 32, 136, 12, 3, 4, 0]);
    // Entries out of order, one empty and one overlapping its neighbour;
    // then 4 bytes of padding.
    stream.extend(descriptor(
        0x7ff8_0000_0020,
        0x7ff8_0001_0000,
        0x7ff8_0000_0020,
        4,
        4,
    ));
    stream.extend(u32s(&[0x200, 0x280, 0x900]));
    stream.extend(u32s(&[0x100, 0x180, 0x800]));
    stream.extend(u32s(&[0x300, 0x300, 0xa00]));
    stream.extend(u32s(&[0x150, 0x1a0, 0xb00]));
    stream.extend(u32s(&[0]));
    // No padding after this one.
    stream.extend(descriptor(
        0x7ff8_0002_0000,
        0x7ff8_0003_0000,
        0x7ff8_0002_0000,
        1,
        0,
    ));
    stream.extend(u32s(&[0x10, 0x40, 0x1000]));
    // Claims more entries than the stream holds.
    stream.extend(descriptor(
        0x7ff8_0004_0000,
        0x7ff8_0005_0000,
        0x7ff8_0004_0000,
        99,
        0,
    ));
    builder.stream(13, &stream);
    let dump = open(&builder.finish()).unwrap();
    let info = dump.info();

    assert_eq!(info.function_tables.len(), 2);
    assert_eq!(
        info.function_tables[0]
            .entries
            .iter()
            .map(|entry| entry.begin)
            .collect::<Vec<_>>(),
        [0x100, 0x200]
    );
    let (base, function) = info.dynamic_function(0x7ff8_0000_0020 + 0x17f).unwrap();
    assert_eq!(base, 0x7ff8_0000_0020);
    assert_eq!(function.unwind_data, 0x800);
    assert_eq!(
        info.dynamic_function(0x7ff8_0002_0030)
            .map(|(_, function)| function.unwind_data),
        Some(0x1000)
    );
    // Between entries, and in the table that was dropped.
    assert!(info.dynamic_function(0x7ff8_0000_0020 + 0x1c0).is_none());
    assert!(info.dynamic_function(0x7ff8_0004_0010).is_none());
    assert!(
        info.notes
            .iter()
            .any(|note| note.contains("2 of its 4 entries"))
    );
    assert!(
        info.notes
            .iter()
            .any(|note| note.contains("more than the stream holds"))
    );
}

/// An ARM64 entry records no end: a packed entry's length is in its unwind
/// data, and an `.xdata` entry's in its header in process memory, so an
/// entry whose header the dump did not capture covers nothing.
#[test]
fn arm64_function_tables_take_their_lengths_from_the_unwind_data() {
    const BASE: u64 = 0x7ff8_0000_0000;
    let mut builder = Builder::new(3);
    builder.system_info(ARM64, WIN32_NT);
    // The .xdata header at BASE + 0x800: a 0x20-instruction function.
    let header = builder.blob(&u32s(&[0x20, 0]));
    let mut list = u32s(&[1]);
    list.extend(u64s(&[BASE + 0x800]));
    list.extend(u32s(&[8, header]));
    builder.stream(5, &list);

    let mut stream = u32s(&[24, 32, 0, 8, 1, 0]);
    stream.extend(u64s(&[BASE, BASE + 0x1_0000, BASE]));
    stream.extend(u32s(&[3, 0]));
    // Packed (flag 1), 0x10 instructions.
    stream.extend(u32s(&[0x100, 1 | 0x10 << 2]));
    // .xdata at 0x800, captured.
    stream.extend(u32s(&[0x200, 0x800]));
    // .xdata at 0x900, not captured.
    stream.extend(u32s(&[0x300, 0x900]));
    builder.stream(13, &stream);
    let dump = open(&builder.finish()).unwrap();
    let info = dump.info();

    let unwind_data = |address: u64| {
        info.dynamic_function(address)
            .map(|(base, function)| (base, function.unwind_data))
    };
    assert_eq!(unwind_data(BASE + 0x13c), Some((BASE, 0x41)));
    assert_eq!(unwind_data(BASE + 0x140), None);
    assert_eq!(unwind_data(BASE + 0x27c), Some((BASE, 0x800)));
    assert_eq!(unwind_data(BASE + 0x280), None);
    assert_eq!(unwind_data(BASE + 0x300), None);
    assert!(
        info.notes
            .iter()
            .any(|note| note.contains("1 of its 3 entries"))
    );
}

/// A stack in ARM64 code no module holds, which a dynamic function table
/// describes (`stp fp, lr, [sp, #-16]!; mov fp, sp`, packed): the walk
/// unwinds by the table, and through a recursive call, whose frame returns
/// to the same call site as the one before it, until the zero lr that ends
/// the thread's stack.
#[test]
fn an_arm64_stack_unwinds_through_jit_code_and_recursion() {
    use crate::backend::phys::PhysMem;
    use crate::nt::target::Target;
    use crate::nt::unwind::{FrameSource, build_stacktrace_with_register_values};
    use std::sync::Arc;

    const BASE: u64 = 0x7ff8_0000_0000;
    const STACK: u64 = 0x50_0000;
    // The function at BASE + 0x100 calls itself at +0x130.
    const RETURN: u64 = BASE + 0x134;
    let mut builder = Builder::new(3);
    builder.system_info(ARM64, WIN32_NT);
    // Three frame records: the stopped frame's, the recursive call's, and
    // the outermost one's, whose saved lr is zero.
    let stack = builder.blob(&u64s(&[STACK + 0x10, RETURN, STACK + 0x20, RETURN, 0, 0]));
    let mut list = u32s(&[1]);
    list.extend(u64s(&[STACK]));
    list.extend(u32s(&[0x30, stack]));
    builder.stream(5, &list);
    let mut table = u32s(&[24, 32, 0, 8, 1, 0]);
    table.extend(u64s(&[BASE, BASE + 0x1_0000, BASE]));
    table.extend(u32s(&[1, 0]));
    // Packed (flag 1): 0x10 instructions, CR = 3 (fp and lr saved as a
    // pair, fp set), a 16-byte frame.
    table.extend(u32s(&[0x100, 1 | 0x10 << 2 | 3 << 21 | 1 << 23]));
    builder.stream(13, &table);
    let dump = open(&builder.finish()).unwrap();
    let target = Target::with_user_dump(Arc::new(PhysMem::minidump(dump))).unwrap();

    let values = HashMap::from([
        ("pc".to_string(), BASE + 0x120),
        ("sp".to_string(), STACK),
        ("fp".to_string(), STACK),
        ("lr".to_string(), RETURN),
    ]);
    let trace =
        build_stacktrace_with_register_values(&target, Arch::Arm64.register_map(), &values, 8);
    let frames: Vec<_> = trace
        .frames
        .iter()
        .map(|frame| (frame.frame.ip, frame.frame.sp, frame.frame.source))
        .collect();
    assert_eq!(
        frames,
        [
            (BASE + 0x120, STACK, FrameSource::Current),
            (RETURN, STACK + 0x10, FrameSource::Unwind),
            (RETURN, STACK + 0x20, FrameSource::Unwind),
        ]
    );
}

#[test]
fn misc_info_records_process_times_and_the_time_zone_in_effect() {
    let mut builder = Builder::new(2);
    builder.system_info(AMD64, WIN32_NT);
    let mut misc = vec![0u8; 232];
    // MISC1_PROCESS_ID | MISC1_PROCESS_TIMES | MISC3_TIMEZONE.
    misc[..24].copy_from_slice(&u32s(&[232, 0x43, 0x10f4, 1_791_700_000, 12, 3]));
    misc[56..60].copy_from_slice(&2u32.to_le_bytes());
    misc[60..64].copy_from_slice(&300i32.to_le_bytes());
    let name = |text: &str| -> Vec<u8> { text.encode_utf16().flat_map(u16::to_le_bytes).collect() };
    let standard = name("Eastern Standard Time");
    misc[64..64 + standard.len()].copy_from_slice(&standard);
    let daylight = name("Eastern Daylight Time");
    misc[148..148 + daylight.len()].copy_from_slice(&daylight);
    misc[228..232].copy_from_slice(&(-60i32).to_le_bytes());
    builder.stream(15, &misc);
    let dump = open(&builder.finish()).unwrap();
    let info = dump.info();

    assert_eq!(info.process_id, Some(0x10f4));
    assert_eq!(info.process_create_time, Some(1_791_700_000));
    assert_eq!(info.process_cpu_times, Some((12, 3)));
    let zone = info.time_zone.as_ref().unwrap();
    assert_eq!(zone.bias, 240);
    assert_eq!(zone.name, "Eastern Daylight Time");
}
