//! Synthetic minidumps, laid out as `MiniDumpWriteDump` lays them out, to
//! check the parser's bounds, both memory list encodings, the module and
//! thread records, and the refusals.

use memmap2::MmapMut;

use super::*;
use crate::dbg_backend::DebugBackend;
use crate::error::Error;
use crate::memory::read_page_chunks;

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
    let mut context = vec![0u8; context::CONTEXT_SIZE];
    context[context::OFFSET_CONTEXT_FLAGS..context::OFFSET_CONTEXT_FLAGS + 4]
        .copy_from_slice(&flags.to_le_bytes());
    context[context::OFFSET_RIP..context::OFFSET_RIP + 8].copy_from_slice(&rip.to_le_bytes());
    context[context::OFFSET_RSP..context::OFFSET_RSP + 8].copy_from_slice(&rsp.to_le_bytes());
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
    let context = amd64_context(context::CONTEXT_CONTROL | context::CONTEXT_INTEGER, 1, 2);
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
    assert_eq!(dump.info().threads[0].stack, Some((0x20010, 0x30)));

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
        context::CONTEXT_CONTROL | context::CONTEXT_INTEGER,
        0x7ff9_4651_1344,
        0xf3_5cfa_f788,
    );
    let good_rva = builder.blob(&good);
    // Control registers but no integer ones: not enough to place a thread.
    let partial = amd64_context(context::CONTEXT_CONTROL, 1, 2);
    let partial_rva = builder.blob(&partial);
    let size = context::CONTEXT_SIZE as u32;
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

    let map = context::build_register_map();
    let registers = register_buffer(Arch::Amd64, threads[0].context.as_ref().unwrap());
    assert_eq!(map.read_u64("rip", &registers).unwrap(), 0x7ff9_4651_1344);
    assert_eq!(map.read_u64("rsp", &registers).unwrap(), 0xf3_5cfa_f788);
    assert_eq!(map.read_u64("cr3", &registers).unwrap(), 0);
    // Lacking integer registers, or shorter than a CONTEXT: unusable.
    assert!(threads[1].context.is_err());
    assert!(threads[2].context.is_err());

    assert_eq!(threads[0].info.as_ref().unwrap().start_address, 0x1010);
    assert_eq!(threads[2].info.as_ref().unwrap().start_address, 0x1030);
    assert!(threads[1].info.is_none());
    assert_eq!(threads[1].name.as_deref(), Some("worker"));

    // Only the groups the flags mark are registers of the context.
    let values = context_registers(Arch::Amd64, &map, threads[0].context.as_ref().unwrap());
    assert_eq!(values.get("rip"), Some(&0x7ff9_4651_1344));
    assert!(!values.contains_key("dr7"));
    assert!(!values.contains_key("xmm0l"));
    assert!(!values.contains_key("cr3"));
}

#[test]
fn arm64_threads_and_the_exception_stream_carry_their_contexts() {
    let mut builder = Builder::new(3);
    builder.system_info(ARM64, WIN32_NT);
    let mut thread_context = vec![0u8; context_arm64::CONTEXT_SIZE];
    thread_context[..4].copy_from_slice(
        &(context_arm64::CONTEXT_CONTROL | context_arm64::CONTEXT_INTEGER).to_le_bytes(),
    );
    thread_context[context_arm64::OFFSET_PC..context_arm64::OFFSET_PC + 8]
        .copy_from_slice(&0x7ffa_0000_1000u64.to_le_bytes());
    let thread_rva = builder.blob(&thread_context);
    let mut exception_context = thread_context.clone();
    exception_context[context_arm64::OFFSET_PC..context_arm64::OFFSET_PC + 8]
        .copy_from_slice(&0x7ffa_0000_2000u64.to_le_bytes());
    let exception_rva = builder.blob(&exception_context);
    let size = context_arm64::CONTEXT_SIZE as u32;
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
    let map = context_arm64::build_register_map();
    let thread = register_buffer(Arch::Arm64, info.threads[0].context.as_ref().unwrap());
    assert_eq!(map.read_u64("pc", &thread).unwrap(), 0x7ffa_0000_1000);

    let exception = info.exception.as_ref().unwrap();
    assert_eq!(exception.thread_id, 0x200);
    assert_eq!(exception.code, 0xe0d7_e5e1);
    assert_eq!(exception.parameters, vec![7, 9]);
    let registers = context_registers(Arch::Arm64, &map, exception.context.as_ref().unwrap());
    assert_eq!(registers.get("pc"), Some(&0x7ffa_0000_2000));

    // The backend starts on the exception's thread.
    let mut backend = UserDumpBackend::new(info);
    assert_eq!(backend.stopped_thread_id().unwrap(), "200");
    let registers = backend.read_registers().unwrap();
    assert_eq!(map.read_u64("pc", &registers).unwrap(), 0x7ffa_0000_1000);
    assert!(backend.set_current_thread("300").is_err());
    assert!(backend.write_registers(&registers).is_err());
}
