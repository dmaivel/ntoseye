use ntoseye_macros::record;
use std::fs::File;
use std::path::Path;
use std::time::Duration;

use memmap2::Mmap;

use crate::arch::{Arch, RegisterFile, RegisterMap, machine_name};
use crate::backend::dbg_backend::{
    BackendCapability, DebugBackend, DebugCapability, StopEvent,
    processor_index_from_backend_thread_id,
};
use crate::backend::debugger_data::{DebuggerDataCandidate, MetadataSource};
use crate::base::error::{Error, Result};
use crate::base::memory::{MemoryOps, PAGE_SIZE};
use crate::base::notice::Notice;
use crate::base::ntstatus::exception_code_name;
use crate::base::time::filetime_to_iso;
use crate::base::types::{MAX_PROCESSORS, PhysAddr, VirtAddr};

pub mod parse;
pub mod structs;
pub mod tagged;
pub mod triage;

use parse::ParsedDump;
use tagged::{TaggedBlock, tagged_blocks_at};
use triage::{
    TriageBlock, TriageDriver, TriagePrcbInfo, is_triage_dump, parse_drivers, parse_triage,
};

/// The architecture a dump header's machine type names, or why ntoseye
/// cannot read the dump.
pub fn dump_arch(machine_type: u32) -> Result<Arch> {
    let machine = u16::try_from(machine_type).ok();
    machine.and_then(Arch::from_machine_type).ok_or_else(|| {
        Error::UnsupportedArchitecture(format!(
            "{} crash dump (machine {machine_type:#06x})",
            machine.map_or("Unknown", machine_name)
        ))
    })
}

/// The exception a crash dump recorded.
#[record(impl)]
#[derive(Debug, Clone, Default)]
pub struct DmpException {
    /// The exception code (NTSTATUS).
    #[record(hex)]
    pub code: u32,
    pub flags: u32,
    /// Where the exception occurred.
    #[record(hex)]
    pub address: u64,
    /// The exception's `ExceptionInformation` parameters.
    #[record(hex)]
    pub parameters: Vec<u64>,
}

#[record]
impl DmpException {
    /// The code's symbolic name.
    #[record(getter)]
    pub fn code_name(&self) -> &'static str {
        exception_code_name(self.code)
    }
}

/// The system that a crash dump comes from, as the system-info stream of
/// the dump records it.
#[record(impl)]
#[derive(Debug, Clone, Default)]
pub struct DmpSystemInfo {
    pub major_version: u32,
    /// The build number.
    pub minor_version: u32,
    /// When the dump was taken (FILETIME), 0 if the dump does not record it.
    pub system_time: i64,
    /// The system uptime, in 100 ns units.
    pub system_up_time: i64,
    /// `VER_NT_*`: 1 workstation, 2 domain controller, 3 server.
    pub product_type: u32,
    /// The product suite (`VER_SUITE_*`) bits.
    #[record(hex)]
    pub suite_mask: u32,
    /// The machine type (`IMAGE_FILE_MACHINE_*`).
    #[record(hex)]
    pub machine_image_type: u32,
    pub service_pack_build: u32,
}

#[record]
impl DmpSystemInfo {
    /// `I386`, `AMD64`, `ARM64`, or `Unknown`.
    #[record(getter)]
    pub fn machine(&self) -> &'static str {
        u16::try_from(self.machine_image_type).map_or("Unknown", machine_name)
    }

    /// `Workstation`, `DomainController`, `Server`, or `Unknown`.
    #[record(getter)]
    pub fn product(&self) -> &'static str {
        match self.product_type {
            1 => "Workstation",
            2 => "DomainController",
            3 => "Server",
            _ => "Unknown",
        }
    }

    /// When the dump was taken (ISO 8601 UTC). `None` if the dump does not
    /// record it.
    #[record(getter)]
    pub fn system_time_utc(&self) -> Option<String> {
        (self.system_time != 0)
            .then(|| filetime_to_iso(self.system_time as u64))
            .flatten()
    }

    /// The system uptime in seconds. `None` if the dump does not record it.
    #[record(getter)]
    pub fn system_up_time_secs(&self) -> Option<u64> {
        (self.system_up_time > 0)
            .then(|| u64::try_from(self.system_up_time / 10_000_000).ok())
            .flatten()
    }
}

/// A driver that the system unloaded recently, as the crash dump records it.
#[record]
#[derive(Debug, Clone)]
pub struct UnloadedDriver {
    pub name: String,
    #[record(hex)]
    pub start_address: u64,
    #[record(hex)]
    pub end_address: u64,
}

/// Clamp the untrusted header's processor count so a malformed dump can't
/// drive an unbounded per-CPU register-buffer allocation.
pub fn clamp_processors(n: u32) -> u32 {
    n.clamp(1, u32::from(MAX_PROCESSORS))
}

#[derive(Debug, Clone)]
pub struct DmpInfo {
    pub directory_table_base: u64,
    pub bug_check_code: u32,
    pub bug_check_parameters: [u64; 4],
    pub context: RegisterFile,
    pub offset_prcb_context: Option<u16>,
    pub number_processors: u32,
    pub is_triage: bool,
    pub ps_loaded_module_list: u64,
    pub debugger_data_block: Option<u64>,
    pub triage_drivers: Vec<TriageDriver>,
    pub exception: Option<DmpException>,
    pub system_info: Option<DmpSystemInfo>,
    pub unloaded_drivers: Vec<UnloadedDriver>,
    /// The blocks bugcheck callbacks added to the dump (see [`tagged`]).
    pub tagged_blocks: Vec<TaggedBlock>,
    pub triage_process_snapshot: Option<Vec<u8>>,
    pub triage_thread_snapshot: Option<Vec<u8>>,
    pub triage_prcb_info: Option<TriagePrcbInfo>,
    pub broken_driver: Option<String>,
    pub triage_overflowed: bool,
    /// Whether the DGRT integrity signature at `ValidOffset` was present and
    /// intact; false means the triage dump may be truncated or corrupt.
    pub triage_signature_valid: bool,
    pub kern_base: Option<u64>,
}

impl DmpInfo {
    /// The dumped machine's architecture, from its header's machine type.
    pub fn arch(&self) -> Option<Arch> {
        let machine = self.system_info.as_ref()?.machine_image_type;
        Arch::from_machine_type(u16::try_from(machine).ok()?)
    }
}

pub struct DmpMem {
    mmap: Mmap,
    storage: DmpStorage,
    info: DmpInfo,
}

enum DmpStorage {
    /// Full/BMP/kernel dump: sorted by page-aligned GPA
    Pages(Vec<(u64, u64)>),
    /// Triage dump: sorted by VA, variable-size regions
    Blocks(Vec<TriageBlock>),
}

impl DmpMem {
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };

        if is_triage_dump(&mmap) {
            return Self::open_triage(mmap);
        }

        let parsed = parse::parse(&mmap)?;
        Self::open_full(mmap, parsed)
    }

    fn open_full(mmap: Mmap, parsed: ParsedDump) -> Result<Self> {
        let hdr = &parsed.headers;
        let arch = dump_arch(hdr.machine_image_type)?;
        // `PhysmemMap` is a `BTreeMap` keyed by GPA, so this is already sorted
        // ascending -- which `lookup` relies on for its binary search.
        let pages: Vec<(u64, u64)> = parsed.physmem.into_iter().collect();
        // Page contents are packed in file order, so the tagged blocks start
        // right after the page with the highest file offset.
        let tagged_blocks = pages
            .iter()
            .map(|(_, offset)| *offset)
            .max()
            .and_then(|last| usize::try_from(last).ok())
            .map(|last| tagged_blocks_at(&mmap, last + PAGE_SIZE))
            .unwrap_or_default();

        let context = RegisterFile::from_context(arch, &hdr.context_record_buffer);

        let exc = &hdr.exception;
        let n_params = (exc.number_parameters as usize).min(15);
        let exception = if exc.exception_code != 0 || exc.exception_address != 0 {
            Some(DmpException {
                code: exc.exception_code,
                flags: exc.exception_flags,
                address: exc.exception_address,
                parameters: exc.exception_information[..n_params].to_vec(),
            })
        } else {
            None
        };

        let system_info = Some(DmpSystemInfo {
            major_version: hdr.major_version,
            minor_version: hdr.minor_version,
            system_time: hdr.system_time,
            system_up_time: hdr.system_up_time,
            product_type: hdr.product_type,
            suite_mask: hdr.suite_mask,
            machine_image_type: hdr.machine_image_type,
            service_pack_build: 0,
        });

        let info = DmpInfo {
            directory_table_base: hdr.directory_table_base,
            bug_check_code: hdr.bug_check_code,
            bug_check_parameters: hdr.bug_check_code_parameters,
            // Read from KDBG by the session once guest virtual-memory
            // translation is available.
            offset_prcb_context: None,
            number_processors: clamp_processors(hdr.number_processors),
            is_triage: false,
            ps_loaded_module_list: hdr.ps_loaded_module_list,
            debugger_data_block: (hdr.kd_debugger_data_block != 0)
                .then_some(hdr.kd_debugger_data_block),
            triage_drivers: Vec::new(),
            exception,
            system_info,
            unloaded_drivers: Vec::new(),
            tagged_blocks,
            triage_process_snapshot: None,
            triage_thread_snapshot: None,
            triage_prcb_info: None,
            broken_driver: None,
            triage_overflowed: false,
            triage_signature_valid: true,
            kern_base: None,
            context,
        };

        Ok(Self {
            mmap,
            storage: DmpStorage::Pages(pages),
            info,
        })
    }

    fn open_triage(mmap: Mmap) -> Result<Self> {
        let (mut info, blocks) = parse_triage(&mmap)?;
        info.triage_drivers = parse_drivers(&mmap);
        Ok(Self {
            mmap,
            storage: DmpStorage::Blocks(blocks),
            info,
        })
    }

    pub fn info(&self) -> &DmpInfo {
        &self.info
    }

    #[cfg(test)]
    pub fn new_for_test(pages: Vec<(u64, u64)>, info: DmpInfo) -> Self {
        use memmap2::MmapMut;
        let mmap = MmapMut::map_anon(1).unwrap().make_read_only().unwrap();
        Self {
            mmap,
            storage: DmpStorage::Pages(pages),
            info,
        }
    }

    #[cfg(test)]
    pub fn new_triage_for_test(data: Vec<u8>, blocks: Vec<TriageBlock>, info: DmpInfo) -> Self {
        use memmap2::MmapMut;
        let mut mmap_mut = MmapMut::map_anon(data.len()).unwrap();
        mmap_mut.copy_from_slice(&data);
        let mmap = mmap_mut.make_read_only().unwrap();
        Self {
            mmap,
            storage: DmpStorage::Blocks(blocks),
            info,
        }
    }

    /// Resolve an address to `(file_offset, max_bytes)` — the exact file
    /// position and the number of contiguous bytes available from there.
    fn lookup(&self, addr: u64) -> Option<(u64, usize)> {
        match &self.storage {
            DmpStorage::Pages(pages) => {
                let page_gpa = addr & !(PAGE_SIZE as u64 - 1);
                let page_offset = (addr as usize) & (PAGE_SIZE - 1);
                let idx = pages.binary_search_by_key(&page_gpa, |&(g, _)| g).ok()?;
                Some((pages[idx].1 + page_offset as u64, PAGE_SIZE - page_offset))
            }
            DmpStorage::Blocks(blocks) => {
                let idx = blocks.partition_point(|b| b.address <= addr);
                // Scan backwards: the nearest-start block may not contain addr
                // when a smaller overlapping block shadows a larger one.
                for i in (0..idx).rev() {
                    let block = &blocks[i];
                    let offset_in_block = addr - block.address;
                    if offset_in_block < block.size as u64 {
                        return Some((
                            block.offset + offset_in_block,
                            (block.size as u64 - offset_in_block) as usize,
                        ));
                    }
                }
                None
            }
        }
    }
}

impl DmpMem {
    fn bad_address_error(&self, addr: u64) -> Error {
        match &self.storage {
            DmpStorage::Blocks(_) => Error::AddressNotInDump(VirtAddr(addr)),
            DmpStorage::Pages(_) => Error::BadPhysicalAddress(addr),
        }
    }
}

impl MemoryOps<PhysAddr> for DmpMem {
    fn read_bytes(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
        let mut offset = 0usize;
        while offset < buf.len() {
            let cur_addr = addr
                .checked_add(offset as u64)
                .ok_or_else(|| self.bad_address_error(addr))?;
            let (file_offset, available) = self
                .lookup(cur_addr)
                .ok_or_else(|| self.bad_address_error(cur_addr))?;
            let chunk = available.min(buf.len() - offset);

            let start = file_offset as usize;
            let end = start + chunk;
            if end > self.mmap.len() {
                return Err(self.bad_address_error(cur_addr));
            }
            buf[offset..offset + chunk].copy_from_slice(&self.mmap[start..end]);
            offset += chunk;
        }
        Ok(())
    }

    fn write_bytes(&self, _addr: PhysAddr, _buf: &[u8]) -> Result<()> {
        Err(Error::ReadOnlyDump)
    }
}

pub struct DmpBackend {
    register_map: RegisterMap,
    per_cpu_registers: Vec<Vec<u8>>,
    current_processor: usize,
    number_processors: u32,
    // The dump header's CONTEXT record (the crashing CPU's), kept so the
    // crash context can be re-seated after the PRCB pass (see
    // `select_crash_processor`)
    header_context: RegisterFile,
    debugger_data_hint: Option<DebuggerDataCandidate>,
    /// Dump-integrity and per-CPU context warnings raised while opening,
    /// drained by the session through [`DebugBackend::take_notices`].
    notices: Vec<Notice>,
}

impl DmpBackend {
    pub fn new(info: &DmpInfo) -> Self {
        let arch = info.context.arch();
        let register_map = arch.register_map().clone();
        let n = info.number_processors.max(1) as usize;

        let mut per_cpu = Vec::with_capacity(n);
        per_cpu.push(info.context.with_kernel_dtb(info.directory_table_base));
        for _ in 1..n {
            per_cpu.push(RegisterFile::empty(arch).with_kernel_dtb(info.directory_table_base));
        }

        Self {
            register_map,
            per_cpu_registers: per_cpu,
            current_processor: 0,
            number_processors: info.number_processors,
            header_context: info.context.clone(),
            debugger_data_hint: info
                .debugger_data_block
                .map(|address| DebuggerDataCandidate {
                    address: VirtAddr(address),
                    source: MetadataSource::DumpHeader,
                }),
            notices: (!info.triage_signature_valid)
                .then(|| {
                    Notice::warning(
                        "triage dump DGRT integrity signature mismatch; the dump may be \
                         truncated or corrupt",
                    )
                })
                .into_iter()
                .collect(),
        }
    }

    /// Select the bugchecking CPU by matching the header CONTEXT against the
    /// per-CPU PRCB contexts; with no match, re-seat the header context on CPU 0.
    fn select_crash_processor(&mut self) {
        // Live-system dumps (bugcheck 0x161) carry no exception context
        if self.header_context.instruction_pointer() == 0 {
            return;
        }

        let arch = self.header_context.arch();
        let read = |regs: &[u8], name| arch.register_map().read_u64(name, regs).ok();
        let matches_header = |regs: &Vec<u8>| {
            read(regs, arch.pc_register()) == Some(self.header_context.instruction_pointer())
                && read(regs, arch.sp_register()) == Some(self.header_context.stack_pointer())
        };
        match self.per_cpu_registers.iter().position(matches_header) {
            Some(i) => self.current_processor = i,
            None => {
                // Only the `CONTEXT`: the slots past it hold what the PRCB
                // saved, which the header does not carry.
                let context = arch.context_size();
                self.per_cpu_registers[0][..context]
                    .copy_from_slice(&self.header_context.bytes()[..context]);
                self.current_processor = 0;
            }
        }
    }

    /// Whether the dump header's CONTEXT is empty, which leaves the PRCB
    /// contexts nothing to match: a live-system dump's, or that of a dump
    /// QEMU wrote (`dump-guest-memory -w`, as libvirt does on a guest crash),
    /// whose header holds the context the guest pre-filled.
    pub fn header_context_is_empty(&self) -> bool {
        self.header_context.instruction_pointer() == 0
    }

    /// Select processor `index` as the one that bugchecked, when the header
    /// context could not tell (see [`Self::header_context_is_empty`]).
    pub fn select_bugcheck_processor(&mut self, index: u16) {
        if usize::from(index) < self.per_cpu_registers.len() {
            self.current_processor = usize::from(index);
        }
    }

    /// The number of processors this dump holds a register context for.
    pub fn processor_count(&self) -> usize {
        self.per_cpu_registers.len()
    }

    /// Take each processor's register context, by index, as the kernel saved
    /// it in the processor's PRCB, with warnings for those that could not be
    /// read, and select the processor that bugchecked. The dump header holds
    /// only the crashing processor's context, and finding the others takes
    /// the kernel's symbols, so the session reads them once it has located
    /// the kernel. A `None` context keeps what the processor had.
    ///
    /// `special_registers` are each processor's registers that lie past the
    /// `CONTEXT`, which the PRCB saves apart from it. A slot past the
    /// `CONTEXT` that no processor's are given for, other than the page-table
    /// roots the backend serves, leaves the register map, so it reads as
    /// unavailable rather than as zero.
    pub fn set_processor_contexts(
        &mut self,
        contexts: Vec<Option<Vec<u8>>>,
        special_registers: Vec<Vec<(&'static str, u64)>>,
        warnings: Vec<String>,
    ) {
        for (registers, context) in self.per_cpu_registers.iter_mut().zip(contexts) {
            if let Some(context) = context {
                registers[..context.len()].copy_from_slice(&context);
            }
        }
        let mut recorded = Vec::new();
        for (registers, special) in self.per_cpu_registers.iter_mut().zip(special_registers) {
            for (name, value) in special {
                if self.register_map.write_u64(name, registers, value).is_ok()
                    && let Some(info) = self.register_map.info(name)
                {
                    recorded.push(info.offset);
                }
            }
        }
        let arch = self.header_context.arch();
        for root in [arch.kernel_dtb_register(), arch.dtb_register()] {
            recorded.extend(self.register_map.info(root).map(|info| info.offset));
        }
        self.register_map = RegisterMap::from_registers(
            self.register_map
                .registers()
                .iter()
                .filter(|info| info.offset < arch.context_size() || recorded.contains(&info.offset))
                .cloned()
                .collect(),
        );
        self.notices
            .extend(warnings.into_iter().map(Notice::warning));
        self.select_crash_processor();
    }

    fn unsupported(operation: &str) -> Error {
        Error::DebugInfo(format!(
            "crash dump is a static snapshot; {operation} is not available"
        ))
    }
}

impl DebugBackend for DmpBackend {
    fn name(&self) -> &'static str {
        "dmp"
    }
    fn registers_are_context(&self) -> bool {
        true
    }
    fn take_notices(&mut self) -> Vec<Notice> {
        std::mem::take(&mut self.notices)
    }
    fn target_debugger_data_hint(&mut self) -> Result<Option<DebuggerDataCandidate>> {
        Ok(self.debugger_data_hint)
    }

    fn register_map(&self) -> &RegisterMap {
        &self.register_map
    }

    fn capabilities(&self) -> Vec<BackendCapability> {
        vec![
            BackendCapability::supported(DebugCapability::MemoryIntrospection),
            BackendCapability::supported(DebugCapability::ReadRegisters),
            BackendCapability::unsupported(DebugCapability::ExecutionControl),
            BackendCapability::unsupported(DebugCapability::InterruptTarget),
            BackendCapability::unsupported(DebugCapability::SingleStep),
            BackendCapability::unsupported(DebugCapability::WriteRegisters),
            BackendCapability::supported(DebugCapability::ThreadList),
            BackendCapability::supported(DebugCapability::ThreadSelection),
            BackendCapability::unsupported(DebugCapability::KernelBreakpoints),
            BackendCapability::unsupported(DebugCapability::UserModeBreakpoints),
            BackendCapability::unsupported(DebugCapability::Watchpoints),
            BackendCapability::unsupported(DebugCapability::TargetReloadDetection),
            BackendCapability::unsupported(DebugCapability::KernelBaseHint),
            BackendCapability::supported(DebugCapability::BugcheckDetection),
            BackendCapability::supported(DebugCapability::BugcheckDetails),
            BackendCapability::unsupported(DebugCapability::ModuleLoadEvents),
            BackendCapability::unsupported(DebugCapability::DebugOutput),
            BackendCapability::unsupported(DebugCapability::Msr),
            BackendCapability::unsupported(DebugCapability::IoPorts),
            BackendCapability::unsupported(DebugCapability::PciConfig),
            BackendCapability::unsupported(DebugCapability::TargetControl),
            BackendCapability::unsupported(DebugCapability::TargetFileIo),
        ]
    }

    fn read_registers(&mut self) -> Result<Vec<u8>> {
        Ok(self.per_cpu_registers[self.current_processor].clone())
    }

    fn write_registers(&mut self, _data: &[u8]) -> Result<()> {
        Err(Self::unsupported("register writes"))
    }

    fn set_breakpoint(&mut self, _addr: u64) -> Result<()> {
        Err(Self::unsupported("breakpoints"))
    }

    fn remove_breakpoint(&mut self, _addr: u64) -> Result<()> {
        Err(Self::unsupported("breakpoints"))
    }

    fn continue_execution(&mut self) -> Result<()> {
        Err(Self::unsupported("continue"))
    }

    fn step(&mut self) -> Result<()> {
        Err(Self::unsupported("single-step"))
    }

    fn interrupt(&mut self) -> Result<StopEvent> {
        Err(Self::unsupported("target interrupt"))
    }

    fn wait_for_stop(&mut self) -> Result<StopEvent> {
        Err(Self::unsupported("waiting for target stops"))
    }

    fn try_wait_for_stop(&mut self, _timeout: Duration) -> Result<Option<StopEvent>> {
        Ok(None)
    }

    fn thread_list(&mut self) -> Result<Vec<String>> {
        Ok((0..self.number_processors as u16)
            .map(|i| format!("p1.{:x}", i + 1))
            .collect())
    }

    fn set_current_thread(&mut self, thread_id: &str) -> Result<()> {
        let processor = processor_index_from_backend_thread_id(thread_id)
            .ok_or_else(|| Error::DebugInfo(format!("invalid thread id: {thread_id}")))?;
        if (processor as u32) >= self.number_processors {
            return Err(Error::DebugInfo(format!(
                "processor {} out of range (dump has {} processor(s))",
                processor, self.number_processors
            )));
        }
        self.current_processor = processor as usize;
        Ok(())
    }

    fn stopped_thread_id(&mut self) -> Result<String> {
        Ok(format!("p1.{:x}", self.current_processor as u16 + 1))
    }

    fn is_running(&self) -> bool {
        false
    }

    // The default tries to leave the VM running, which a static snapshot can't
    // (and needn't) do
    fn prepare_for_exit(&mut self, _leave_running: bool) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::{
        IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_I386,
    };
    use crate::arch::{amd64, arm64};

    #[test]
    fn dump_open_rejects_unsupported_machine_types() {
        assert!(matches!(
            dump_arch(u32::from(IMAGE_FILE_MACHINE_AMD64)),
            Ok(Arch::Amd64)
        ));
        assert!(matches!(
            dump_arch(u32::from(IMAGE_FILE_MACHINE_ARM64)),
            Ok(Arch::Arm64)
        ));
        let error = dump_arch(u32::from(IMAGE_FILE_MACHINE_I386)).unwrap_err();
        assert!(error.to_string().contains("I386 crash dump"));
    }

    #[test]
    fn arm64_context_header_round_trips_registers_and_debug_state() {
        let mut raw = vec![0u8; arm64::CONTEXT_SIZE];
        raw[arm64::OFFSET_CPSR..arm64::OFFSET_CPSR + 4]
            .copy_from_slice(&0x6000_03c5u32.to_le_bytes());
        raw[arm64::OFFSET_X0..arm64::OFFSET_X0 + 8]
            .copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        raw[arm64::OFFSET_SP..arm64::OFFSET_SP + 8]
            .copy_from_slice(&0xffff_0000_1234_5000u64.to_le_bytes());
        raw[arm64::OFFSET_PC..arm64::OFFSET_PC + 8]
            .copy_from_slice(&0xffff_0000_0000_1000u64.to_le_bytes());
        raw[arm64::OFFSET_BCR0..arm64::OFFSET_BCR0 + 4]
            .copy_from_slice(&0x0000_e9e1u32.to_le_bytes());
        raw[arm64::OFFSET_WVR0..arm64::OFFSET_WVR0 + 8].copy_from_slice(&0x4000u64.to_le_bytes());
        let data = RegisterFile::from_context(Arch::Arm64, &raw).with_kernel_dtb(0x1234_5000);
        let map = Arch::Arm64.register_map();
        assert_eq!(map.read_u64("x0", &data).unwrap(), 0x1122_3344_5566_7788);
        assert_eq!(map.read_u64("pc", &data).unwrap(), 0xffff_0000_0000_1000);
        assert_eq!(map.read_u64("sp", &data).unwrap(), 0xffff_0000_1234_5000);
        assert_eq!(map.read_u64("bcr0", &data).unwrap(), 0x0000_e9e1);
        assert_eq!(map.read_u64("wvr0", &data).unwrap(), 0x4000);
        assert_eq!(map.read_u64("cr3", &data).unwrap(), 0x1234_5000);
    }

    /// An AMD64 register file holding `values`, by name.
    fn amd64_registers(values: &[(&str, u64)]) -> RegisterFile {
        let map = Arch::Amd64.register_map();
        let mut record = vec![0u8; amd64::CONTEXT_SIZE];
        for &(name, value) in values {
            map.write_u64(name, &mut record, value).unwrap();
        }
        RegisterFile::from_context(Arch::Amd64, &record)
    }

    fn make_test_info() -> DmpInfo {
        DmpInfo {
            directory_table_base: 0x1ad000,
            bug_check_code: 0x50,
            bug_check_parameters: [0xdead, 0, 0, 0],
            offset_prcb_context: None,
            number_processors: 1,
            is_triage: false,
            ps_loaded_module_list: 0,
            debugger_data_block: None,
            triage_drivers: Vec::new(),
            exception: None,
            system_info: None,
            unloaded_drivers: Vec::new(),
            tagged_blocks: Vec::new(),
            triage_process_snapshot: None,
            triage_thread_snapshot: None,
            triage_prcb_info: None,
            broken_driver: None,
            triage_overflowed: false,
            triage_signature_valid: true,
            kern_base: None,
            context: amd64_registers(&[
                ("rax", 0x1111111111111111),
                ("rbx", 0x2222222222222222),
                ("rcx", 0x3333333333333333),
                ("rdx", 0x4444444444444444),
                ("rsi", 0x5555555555555555),
                ("rdi", 0x6666666666666666),
                ("rbp", 0x7777777777777777),
                ("rsp", 0x8888888888888888),
                ("r8", 0x0808080808080808),
                ("r9", 0x0909090909090909),
                ("r10", 0x1010101010101010),
                ("r11", 0x1111111111111111),
                ("r12", 0x1212121212121212),
                ("r13", 0x1313131313131313),
                ("r14", 0x1414141414141414),
                ("r15", 0x1515151515151515),
                ("rip", 0xfffff80012345678),
                ("eflags", 0x246),
                ("cs", 0x10),
                ("ds", 0x2b),
                ("es", 0x2b),
                ("fs", 0x53),
                ("gs", 0x2b),
                ("ss", 0x18),
            ]),
        }
    }

    #[test]
    fn dmp_backend_register_round_trip() {
        let info = make_test_info();
        let mut backend = DmpBackend::new(&info);
        let map = backend.register_map().clone();
        let data = backend.read_registers().unwrap();

        assert_eq!(map.read_u64("rax", &data).unwrap(), 0x1111111111111111);
        assert_eq!(map.read_u64("rbx", &data).unwrap(), 0x2222222222222222);
        assert_eq!(map.read_u64("rcx", &data).unwrap(), 0x3333333333333333);
        assert_eq!(map.read_u64("rdx", &data).unwrap(), 0x4444444444444444);
        assert_eq!(map.read_u64("rsi", &data).unwrap(), 0x5555555555555555);
        assert_eq!(map.read_u64("rdi", &data).unwrap(), 0x6666666666666666);
        assert_eq!(map.read_u64("rbp", &data).unwrap(), 0x7777777777777777);
        assert_eq!(map.read_u64("rsp", &data).unwrap(), 0x8888888888888888);
        assert_eq!(map.read_u64("r8", &data).unwrap(), 0x0808080808080808);
        assert_eq!(map.read_u64("r9", &data).unwrap(), 0x0909090909090909);
        assert_eq!(map.read_u64("r10", &data).unwrap(), 0x1010101010101010);
        assert_eq!(map.read_u64("r11", &data).unwrap(), 0x1111111111111111);
        assert_eq!(map.read_u64("r12", &data).unwrap(), 0x1212121212121212);
        assert_eq!(map.read_u64("r13", &data).unwrap(), 0x1313131313131313);
        assert_eq!(map.read_u64("r14", &data).unwrap(), 0x1414141414141414);
        assert_eq!(map.read_u64("r15", &data).unwrap(), 0x1515151515151515);
        assert_eq!(map.read_u64("rip", &data).unwrap(), 0xfffff80012345678);
        assert_eq!(map.read_u64("eflags", &data).unwrap(), 0x246);
        assert_eq!(map.read_u64("cs", &data).unwrap(), 0x10);
        assert_eq!(map.read_u64("ss", &data).unwrap(), 0x18);
        assert_eq!(
            map.read_u64("cr3", &data).unwrap(),
            info.directory_table_base
        );
    }

    #[test]
    fn dmp_backend_thread_list_and_switching() {
        let mut info = make_test_info();
        info.number_processors = 4;
        let mut backend = DmpBackend::new(&info);

        let threads = backend.thread_list().unwrap();
        assert_eq!(threads, vec!["p1.1", "p1.2", "p1.3", "p1.4"]);

        assert_eq!(backend.stopped_thread_id().unwrap(), "p1.1");

        backend.set_current_thread("p1.3").unwrap();
        assert_eq!(backend.stopped_thread_id().unwrap(), "p1.3");

        assert!(backend.set_current_thread("p1.5").is_err());
        assert!(backend.set_current_thread("garbage").is_err());
    }

    #[test]
    fn dmp_mem_lookup() {
        let pages = vec![
            (0x0000u64, 0x2000u64),
            (0x1000, 0x3000),
            (0x2000, 0x4000),
            (0x5000, 0x5000),
            (0x10000, 0x6000),
        ];
        let mem = DmpMem::new_for_test(pages, make_test_info());

        assert_eq!(mem.lookup(0x0000), Some((0x2000, 0x1000)));
        assert_eq!(mem.lookup(0x0100), Some((0x2100, 0x0F00)));
        assert_eq!(mem.lookup(0x0FFF), Some((0x2FFF, 0x0001)));
        assert_eq!(mem.lookup(0x1000), Some((0x3000, 0x1000)));
        assert_eq!(mem.lookup(0x1500), Some((0x3500, 0x0B00)));
        assert_eq!(mem.lookup(0x5000), Some((0x5000, 0x1000)));
        assert_eq!(mem.lookup(0x3000), None);
        assert_eq!(mem.lookup(0x4000), None);
        assert_eq!(mem.lookup(0x8000), None);
    }

    #[test]
    fn physical_read_overflow_returns_bad_address() {
        use memmap2::MmapMut;

        let mut mmap = MmapMut::map_anon(PAGE_SIZE).unwrap();
        mmap.fill(0x5a);
        let mmap = mmap.make_read_only().unwrap();
        let page = u64::MAX - (PAGE_SIZE as u64 - 1);
        let mem = DmpMem {
            mmap,
            storage: DmpStorage::Pages(vec![(page, 0)]),
            info: make_test_info(),
        };

        let mut bytes = [0; 4];
        assert!(matches!(
            mem.read_bytes(u64::MAX - 1, &mut bytes),
            Err(Error::BadPhysicalAddress(_))
        ));
    }

    #[test]
    fn crash_processor_selected_from_matching_prcb_context() {
        let mut info = make_test_info();
        info.number_processors = 4;
        let mut backend = DmpBackend::new(&info);

        for (i, regs) in backend.per_cpu_registers.iter_mut().enumerate() {
            let (rip, rsp) = if i == 2 {
                (
                    info.context.instruction_pointer(),
                    info.context.stack_pointer(),
                )
            } else {
                (0xfffff800aaaa0000 + i as u64, 0xfffff800bbbb0000 + i as u64)
            };
            regs[amd64::OFFSET_RIP..amd64::OFFSET_RIP + 8].copy_from_slice(&rip.to_le_bytes());
            regs[amd64::OFFSET_RSP..amd64::OFFSET_RSP + 8].copy_from_slice(&rsp.to_le_bytes());
        }

        backend.select_crash_processor();
        assert_eq!(backend.current_processor, 2);
        assert_eq!(backend.stopped_thread_id().unwrap(), "p1.3");
    }

    #[test]
    fn crash_processor_falls_back_to_header_context() {
        let mut info = make_test_info();
        info.number_processors = 2;
        let mut backend = DmpBackend::new(&info);

        for regs in backend.per_cpu_registers.iter_mut() {
            regs[amd64::OFFSET_RIP..amd64::OFFSET_RIP + 8]
                .copy_from_slice(&0xfffff800cccc0000u64.to_le_bytes());
        }

        backend.select_crash_processor();
        assert_eq!(backend.current_processor, 0);
        assert!(!backend.header_context_is_empty());
        let data = backend.read_registers().unwrap();
        let map = backend.register_map().clone();
        assert_eq!(
            map.read_u64("rip", &data).unwrap(),
            info.context.instruction_pointer()
        );
        assert_eq!(map.read_u64("rax", &data).ok(), info.context.read("rax"));
        assert_eq!(
            map.read_u64("cr3", &data).unwrap(),
            info.directory_table_base
        );
    }

    #[test]
    fn triage_mem_read_within_block() {
        let mut data = vec![0u8; 0x4000];
        for i in 0..0x100usize {
            data[0x3000 + i] = i as u8;
        }

        let blocks = vec![TriageBlock {
            address: 0xfffff80000001000,
            offset: 0x3000,
            size: 0x100,
        }];

        let mut info = make_test_info();
        info.is_triage = true;

        let mem = DmpMem::new_triage_for_test(data, blocks, info);

        let mut buf = [0u8; 4];
        mem.read_bytes(0xfffff80000001010u64, &mut buf).unwrap();
        assert_eq!(buf, [0x10, 0x11, 0x12, 0x13]);

        let mut buf = [0u8; 1];
        assert!(mem.read_bytes(0xfffff80000001100u64, &mut buf).is_err());
    }

    #[test]
    fn triage_overlapping_blocks_fallback() {
        let mut data = vec![0u8; 0x8000];
        for i in 0..0x3000usize {
            data[0x2000 + i] = 0xAA;
        }
        for i in 0..0x1000usize {
            data[0x5000 + i] = 0xBB;
        }

        let blocks = vec![
            TriageBlock {
                address: 0x1000,
                offset: 0x2000,
                size: 0x3000,
            },
            TriageBlock {
                address: 0x2000,
                offset: 0x5000,
                size: 0x1000,
            },
        ];

        let mut info = make_test_info();
        info.is_triage = true;
        let mem = DmpMem::new_triage_for_test(data, blocks, info);

        let mut buf = [0u8; 1];
        mem.read_bytes(0x1500u64, &mut buf).unwrap();
        assert_eq!(buf[0], 0xAA);

        mem.read_bytes(0x2500u64, &mut buf).unwrap();
        assert_eq!(buf[0], 0xBB);

        mem.read_bytes(0x3100u64, &mut buf).unwrap();
        assert_eq!(buf[0], 0xAA);

        assert!(mem.read_bytes(0x4100u64, &mut buf).is_err());
    }
}
