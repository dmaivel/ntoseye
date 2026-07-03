use std::fs::File;
use std::path::Path;
use std::time::Duration;

use kdmp_parser::gxa::Gva;
use kdmp_parser::parse::KernelDumpParser;
use kdmp_parser::structs::KdDebuggerData64;
use kdmp_parser::virt;
use memmap2::Mmap;

use crate::backend::MemoryOps;
use crate::dbg_backend::{BackendCapability, DebugBackend, DebugCapability, StopEvent};
use crate::diagnostics;
use crate::error::{Error, Result};
use crate::gdb::RegisterMap;
use crate::kd::context;
use crate::memory::PAGE_SIZE;
use crate::session::processor_index_from_backend_thread_id;
use crate::target::Target;
use crate::types::{PhysAddr, VirtAddr};

#[derive(Debug, Clone)]
pub struct DmpContext {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub eflags: u32,
    pub cs: u16,
    pub ds: u16,
    pub es: u16,
    pub fs: u16,
    pub gs: u16,
    pub ss: u16,
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr6: u64,
    pub dr7: u64,
}

#[derive(Debug, Clone)]
pub struct DmpInfo {
    pub directory_table_base: u64,
    pub bug_check_code: u32,
    pub bug_check_parameters: [u64; 4],
    pub context: DmpContext,
    pub offset_prcb_context: Option<u16>,
    pub number_processors: u32,
}

pub struct DmpMem {
    mmap: Mmap,
    // Sorted by GPA; each entry is (page-aligned GPA, file byte offset)
    pages: Vec<(u64, u64)>,
    info: DmpInfo,
}

impl DmpMem {
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };

        let parser = KernelDumpParser::new(path).map_err(|e| Error::InvalidDump(e.to_string()))?;

        let mut pages: Vec<(u64, u64)> = parser
            .physmem()
            .map(|(gpa, offset)| (u64::from(gpa), offset))
            .collect();
        pages.sort_unstable_by_key(|&(gpa, _)| gpa);

        let hdr = parser.headers();
        let ctx = parser.context_record();

        let offset_prcb_context = Self::read_prcb_context_offset(&parser);

        let info = DmpInfo {
            directory_table_base: hdr.directory_table_base,
            bug_check_code: hdr.bug_check_code,
            bug_check_parameters: hdr.bug_check_code_parameters,
            offset_prcb_context,
            number_processors: hdr.number_processors.max(1),
            context: DmpContext {
                rax: ctx.rax,
                rbx: ctx.rbx,
                rcx: ctx.rcx,
                rdx: ctx.rdx,
                rsi: ctx.rsi,
                rdi: ctx.rdi,
                rbp: ctx.rbp,
                rsp: ctx.rsp,
                r8: ctx.r8,
                r9: ctx.r9,
                r10: ctx.r10,
                r11: ctx.r11,
                r12: ctx.r12,
                r13: ctx.r13,
                r14: ctx.r14,
                r15: ctx.r15,
                rip: ctx.rip,
                eflags: ctx.eflags,
                cs: ctx.seg_cs,
                ds: ctx.seg_ds,
                es: ctx.seg_es,
                fs: ctx.seg_fs,
                gs: ctx.seg_gs,
                ss: ctx.seg_ss,
                dr0: ctx.dr0,
                dr1: ctx.dr1,
                dr2: ctx.dr2,
                dr3: ctx.dr3,
                dr6: ctx.dr6,
                dr7: ctx.dr7,
            },
        };

        Ok(Self { mmap, pages, info })
    }

    fn read_prcb_context_offset(parser: &KernelDumpParser) -> Option<u16> {
        let reader = virt::Reader::new(parser);
        let kdbg_va: Gva = parser.headers().kd_debugger_data_block.into();
        let kdbg: KdDebuggerData64 = reader.try_read_struct(kdbg_va).ok()??;
        let off = kdbg.offset_prcb_context;
        if off > 0 { Some(off) } else { None }
    }

    pub fn info(&self) -> &DmpInfo {
        &self.info
    }

    #[cfg(test)]
    pub fn new_for_test(pages: Vec<(u64, u64)>, info: DmpInfo) -> Self {
        use memmap2::MmapMut;
        let mmap = MmapMut::map_anon(1).unwrap().make_read_only().unwrap();
        Self { mmap, pages, info }
    }

    fn lookup_page(&self, gpa: u64) -> Option<u64> {
        let page_gpa = gpa & !(PAGE_SIZE as u64 - 1);
        self.pages
            .binary_search_by_key(&page_gpa, |&(g, _)| g)
            .ok()
            .map(|idx| self.pages[idx].1)
    }
}

impl MemoryOps<PhysAddr> for DmpMem {
    fn read_bytes(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
        let mut offset = 0usize;
        while offset < buf.len() {
            let cur_addr = addr + offset as u64;
            let page_offset = (cur_addr as usize) & (PAGE_SIZE - 1);
            let chunk = (PAGE_SIZE - page_offset).min(buf.len() - offset);

            let file_offset = self
                .lookup_page(cur_addr)
                .ok_or(Error::BadPhysicalAddress(cur_addr))?;

            let start = file_offset as usize + page_offset;
            let end = start + chunk;
            if end > self.mmap.len() {
                return Err(Error::BadPhysicalAddress(cur_addr));
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

// ---------------------------------------------------------------------------
// DmpBackend — DebugBackend for crash dump analysis
// ---------------------------------------------------------------------------

pub struct DmpBackend {
    register_map: RegisterMap,
    per_cpu_registers: Vec<Vec<u8>>,
    current_processor: usize,
    number_processors: u32,
    prcb_context_offset: Option<u16>,
    // The dump header's CONTEXT record (the crashing CPU's) and DTB, kept so
    // the crash context can be re-seated after the PRCB pass (see
    // `select_crash_processor`)
    header_context: DmpContext,
    directory_table_base: u64,
}

impl DmpBackend {
    pub fn new(info: &DmpInfo) -> Self {
        let register_map = context::build_register_map();
        let n = info.number_processors.max(1) as usize;

        let cpu0_data = Self::build_register_buffer(&info.context, info.directory_table_base);

        let mut per_cpu = Vec::with_capacity(n);
        per_cpu.push(cpu0_data);
        for _ in 1..n {
            let mut data = vec![0u8; context::REGISTER_BUFFER_SIZE];
            data[context::OFFSET_CR3..context::OFFSET_CR3 + 8]
                .copy_from_slice(&info.directory_table_base.to_le_bytes());
            per_cpu.push(data);
        }

        Self {
            register_map,
            per_cpu_registers: per_cpu,
            current_processor: 0,
            number_processors: info.number_processors,
            prcb_context_offset: info.offset_prcb_context,
            header_context: info.context.clone(),
            directory_table_base: info.directory_table_base,
        }
    }

    fn build_register_buffer(ctx: &DmpContext, directory_table_base: u64) -> Vec<u8> {
        let mut data = vec![0u8; context::REGISTER_BUFFER_SIZE];

        macro_rules! put_u64 {
            ($off:expr, $val:expr) => {
                data[$off..$off + 8].copy_from_slice(&($val).to_le_bytes());
            };
        }
        macro_rules! put_u32 {
            ($off:expr, $val:expr) => {
                data[$off..$off + 4].copy_from_slice(&($val).to_le_bytes());
            };
        }
        macro_rules! put_u16 {
            ($off:expr, $val:expr) => {
                data[$off..$off + 2].copy_from_slice(&($val).to_le_bytes());
            };
        }

        put_u64!(context::OFFSET_RAX, ctx.rax);
        put_u64!(context::OFFSET_RBX, ctx.rbx);
        put_u64!(context::OFFSET_RCX, ctx.rcx);
        put_u64!(context::OFFSET_RDX, ctx.rdx);
        put_u64!(context::OFFSET_RSI, ctx.rsi);
        put_u64!(context::OFFSET_RDI, ctx.rdi);
        put_u64!(context::OFFSET_RBP, ctx.rbp);
        put_u64!(context::OFFSET_RSP, ctx.rsp);
        put_u64!(context::OFFSET_R8, ctx.r8);
        put_u64!(context::OFFSET_R9, ctx.r9);
        put_u64!(context::OFFSET_R10, ctx.r10);
        put_u64!(context::OFFSET_R11, ctx.r11);
        put_u64!(context::OFFSET_R12, ctx.r12);
        put_u64!(context::OFFSET_R13, ctx.r13);
        put_u64!(context::OFFSET_R14, ctx.r14);
        put_u64!(context::OFFSET_R15, ctx.r15);
        put_u64!(context::OFFSET_RIP, ctx.rip);
        put_u32!(context::OFFSET_EFLAGS, ctx.eflags);
        put_u16!(context::OFFSET_SEG_CS, ctx.cs);
        put_u16!(context::OFFSET_SEG_DS, ctx.ds);
        put_u16!(context::OFFSET_SEG_ES, ctx.es);
        put_u16!(context::OFFSET_SEG_FS, ctx.fs);
        put_u16!(context::OFFSET_SEG_GS, ctx.gs);
        put_u16!(context::OFFSET_SEG_SS, ctx.ss);
        put_u64!(context::OFFSET_DR0, ctx.dr0);
        put_u64!(context::OFFSET_DR1, ctx.dr1);
        put_u64!(context::OFFSET_DR2, ctx.dr2);
        put_u64!(context::OFFSET_DR3, ctx.dr3);
        put_u64!(context::OFFSET_DR6, ctx.dr6);
        put_u64!(context::OFFSET_DR7, ctx.dr7);
        put_u64!(context::OFFSET_CR3, directory_table_base);

        data
    }

    fn read_prcb_contexts(&mut self, target: &Target, prcb_ctx_offset: u16) -> Result<()> {
        let memory = target.guest.ntoskrnl.memory();
        let processor_block = target.guest.ntoskrnl.symbol("KiProcessorBlock")?.address();

        for i in 0..self.per_cpu_registers.len() {
            let prcb: VirtAddr = memory.read(processor_block + (i as u64) * 8)?;
            if prcb.is_zero() {
                diagnostics::eprint_warning(format!("KiProcessorBlock[{i}] is null, skipping"));
                continue;
            }

            let context_ptr: VirtAddr = memory.read(prcb + prcb_ctx_offset as u64)?;
            if context_ptr.is_zero() {
                diagnostics::eprint_warning(format!("PRCB[{i}] Context pointer is null, skipping"));
                continue;
            }

            let mut ctx_buf = vec![0u8; context::CONTEXT_SIZE];
            if let Err(e) = memory.read_bytes(context_ptr, &mut ctx_buf) {
                diagnostics::eprint_warning(format!("failed to read PRCB[{i}] context: {e}"));
                continue;
            }

            // The copy stops at CONTEXT_SIZE, so the control-register tail
            // (CR3, seeded at construction) is untouched
            self.per_cpu_registers[i][..context::CONTEXT_SIZE].copy_from_slice(&ctx_buf);
        }

        Ok(())
    }

    /// Land the user on the bugchecking CPU, the way WinDbg opens a dump. The
    /// header CONTEXT record belongs to the crashing processor but doesn't say
    /// which one it is, so match it against the per-CPU PRCB contexts. If
    /// nothing matches (odd dump), re-seat the header context on CPU 0 so the
    /// crash registers are what the user sees first, not whatever PRCB[0] held.
    fn select_crash_processor(&mut self) {
        // Live-system dumps (bugcheck 0x161) carry no exception context
        if self.header_context.rip == 0 {
            return;
        }

        let matches_header = |regs: &Vec<u8>| {
            buffer_u64(regs, context::OFFSET_RIP) == self.header_context.rip
                && buffer_u64(regs, context::OFFSET_RSP) == self.header_context.rsp
        };
        match self.per_cpu_registers.iter().position(matches_header) {
            Some(i) => self.current_processor = i,
            None => {
                self.per_cpu_registers[0] =
                    Self::build_register_buffer(&self.header_context, self.directory_table_base);
                self.current_processor = 0;
            }
        }
    }

    fn unsupported(operation: &str) -> Error {
        Error::DebugInfo(format!(
            "crash dump is a static snapshot; {operation} is not available"
        ))
    }
}

fn buffer_u64(buf: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(buf[offset..offset + 8].try_into().unwrap())
}

impl DebugBackend for DmpBackend {
    fn initialize_from_target(&mut self, target: &Target) {
        let Some(offset) = self.prcb_context_offset else {
            return;
        };
        if let Err(e) = self.read_prcb_contexts(target, offset) {
            diagnostics::eprint_warning(format!("could not read PRCB contexts from dump: {e}"));
        }
        self.select_crash_processor();
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
            BackendCapability::unsupported(DebugCapability::TargetReloadDetection),
            BackendCapability::unsupported(DebugCapability::KernelBaseHint),
            BackendCapability::unsupported(DebugCapability::BugcheckDetection),
            BackendCapability::unsupported(DebugCapability::BugcheckDetails),
            BackendCapability::unsupported(DebugCapability::DebugOutput),
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

    fn target_kernel_base_hint(&mut self) -> Result<Option<VirtAddr>> {
        Ok(None)
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

    fn make_test_info() -> DmpInfo {
        DmpInfo {
            directory_table_base: 0x1ad000,
            bug_check_code: 0x50,
            bug_check_parameters: [0xdead, 0, 0, 0],
            offset_prcb_context: None,
            number_processors: 1,
            context: DmpContext {
                rax: 0x1111111111111111,
                rbx: 0x2222222222222222,
                rcx: 0x3333333333333333,
                rdx: 0x4444444444444444,
                rsi: 0x5555555555555555,
                rdi: 0x6666666666666666,
                rbp: 0x7777777777777777,
                rsp: 0x8888888888888888,
                r8: 0x0808080808080808,
                r9: 0x0909090909090909,
                r10: 0x1010101010101010,
                r11: 0x1111111111111111,
                r12: 0x1212121212121212,
                r13: 0x1313131313131313,
                r14: 0x1414141414141414,
                r15: 0x1515151515151515,
                rip: 0xfffff80012345678,
                eflags: 0x246,
                cs: 0x10,
                ds: 0x2b,
                es: 0x2b,
                fs: 0x53,
                gs: 0x2b,
                ss: 0x18,
                dr0: 0,
                dr1: 0,
                dr2: 0,
                dr3: 0,
                dr6: 0,
                dr7: 0,
            },
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
        assert_eq!(map.read_u64("rsp", &data).unwrap(), 0x8888888888888888);
        assert_eq!(map.read_u64("rip", &data).unwrap(), 0xfffff80012345678);
        assert_eq!(map.read_u64("eflags", &data).unwrap(), 0x246);
        assert_eq!(map.read_u64("cs", &data).unwrap(), 0x10);
        assert_eq!(
            map.read_u64("cr3", &data).unwrap(),
            info.directory_table_base
        );
    }

    #[test]
    fn dmp_backend_capabilities() {
        let info = make_test_info();
        let backend = DmpBackend::new(&info);
        let caps = backend.capabilities();

        let is_supported = |cap: DebugCapability| -> bool {
            caps.iter().any(|c| c.capability == cap && c.supported)
        };

        assert!(is_supported(DebugCapability::MemoryIntrospection));
        assert!(is_supported(DebugCapability::ReadRegisters));
        assert!(is_supported(DebugCapability::ThreadList));
        assert!(is_supported(DebugCapability::ThreadSelection));
        assert!(!is_supported(DebugCapability::ExecutionControl));
        assert!(!is_supported(DebugCapability::SingleStep));
        assert!(!is_supported(DebugCapability::WriteRegisters));
        assert!(!is_supported(DebugCapability::KernelBreakpoints));
    }

    #[test]
    fn dmp_backend_is_halted() {
        let info = make_test_info();
        let backend = DmpBackend::new(&info);
        assert!(!backend.is_running());
    }

    #[test]
    fn dmp_backend_write_registers_rejected() {
        let info = make_test_info();
        let mut backend = DmpBackend::new(&info);
        let result = backend.write_registers(&[0u8; 100]);
        assert!(result.is_err());
    }

    #[test]
    fn dmp_backend_execution_rejected() {
        let info = make_test_info();
        let mut backend = DmpBackend::new(&info);
        assert!(backend.continue_execution().is_err());
        assert!(backend.step().is_err());
        assert!(backend.set_breakpoint(0x1000).is_err());
        assert!(backend.remove_breakpoint(0x1000).is_err());
    }

    #[test]
    fn dmp_backend_exit_is_clean() {
        // Frontend quit must not trip over the default "leave the VM running"
        // exit behavior (a dump can't continue)
        let info = make_test_info();
        let mut backend = DmpBackend::new(&info);
        assert!(backend.prepare_for_exit(true).is_ok());
    }

    #[test]
    fn dmp_backend_all_registers_round_trip() {
        let info = make_test_info();
        let mut backend = DmpBackend::new(&info);
        let map = backend.register_map().clone();
        let data = backend.read_registers().unwrap();

        assert_eq!(map.read_u64("r8", &data).unwrap(), 0x0808080808080808);
        assert_eq!(map.read_u64("r9", &data).unwrap(), 0x0909090909090909);
        assert_eq!(map.read_u64("r10", &data).unwrap(), 0x1010101010101010);
        assert_eq!(map.read_u64("r11", &data).unwrap(), 0x1111111111111111);
        assert_eq!(map.read_u64("r12", &data).unwrap(), 0x1212121212121212);
        assert_eq!(map.read_u64("r13", &data).unwrap(), 0x1313131313131313);
        assert_eq!(map.read_u64("r14", &data).unwrap(), 0x1414141414141414);
        assert_eq!(map.read_u64("r15", &data).unwrap(), 0x1515151515151515);
        assert_eq!(map.read_u64("rdx", &data).unwrap(), 0x4444444444444444);
        assert_eq!(map.read_u64("rsi", &data).unwrap(), 0x5555555555555555);
        assert_eq!(map.read_u64("rdi", &data).unwrap(), 0x6666666666666666);
        assert_eq!(map.read_u64("rbp", &data).unwrap(), 0x7777777777777777);
        assert_eq!(map.read_u64("ss", &data).unwrap(), 0x18);
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
    fn dmp_mem_lookup_page() {
        let pages = vec![
            (0x0000u64, 0x2000u64),
            (0x1000, 0x3000),
            (0x2000, 0x4000),
            (0x5000, 0x5000),
            (0x10000, 0x6000),
        ];
        let mem = DmpMem::new_for_test(pages, make_test_info());

        assert_eq!(mem.lookup_page(0x0000), Some(0x2000));
        assert_eq!(mem.lookup_page(0x0100), Some(0x2000));
        assert_eq!(mem.lookup_page(0x0FFF), Some(0x2000));
        assert_eq!(mem.lookup_page(0x1000), Some(0x3000));
        assert_eq!(mem.lookup_page(0x1500), Some(0x3000));
        assert_eq!(mem.lookup_page(0x5000), Some(0x5000));
        // Page not present in dump
        assert_eq!(mem.lookup_page(0x3000), None);
        assert_eq!(mem.lookup_page(0x4000), None);
        assert_eq!(mem.lookup_page(0x8000), None);
    }

    #[test]
    fn crash_processor_selected_from_matching_prcb_context() {
        let mut info = make_test_info();
        info.number_processors = 4;
        let mut backend = DmpBackend::new(&info);

        // Simulate the PRCB pass: CPU 2 holds the crashing context, the others
        // (including CPU 0, which starts as the header context) hold idle ones
        for (i, regs) in backend.per_cpu_registers.iter_mut().enumerate() {
            let (rip, rsp) = if i == 2 {
                (info.context.rip, info.context.rsp)
            } else {
                (0xfffff800aaaa0000 + i as u64, 0xfffff800bbbb0000 + i as u64)
            };
            regs[context::OFFSET_RIP..context::OFFSET_RIP + 8].copy_from_slice(&rip.to_le_bytes());
            regs[context::OFFSET_RSP..context::OFFSET_RSP + 8].copy_from_slice(&rsp.to_le_bytes());
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

        // No PRCB context matches the header record (CPU 0's got clobbered)
        for regs in backend.per_cpu_registers.iter_mut() {
            regs[context::OFFSET_RIP..context::OFFSET_RIP + 8]
                .copy_from_slice(&0xfffff800cccc0000u64.to_le_bytes());
        }

        backend.select_crash_processor();
        assert_eq!(backend.current_processor, 0);
        let data = backend.read_registers().unwrap();
        let map = backend.register_map().clone();
        assert_eq!(map.read_u64("rip", &data).unwrap(), info.context.rip);
        assert_eq!(map.read_u64("rax", &data).unwrap(), info.context.rax);
        assert_eq!(
            map.read_u64("cr3", &data).unwrap(),
            info.directory_table_base
        );
    }
}
