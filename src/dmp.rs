use std::fs::File;
use std::path::Path;
use std::time::Duration;

use kdmp_parser::gxa::Gva;
use kdmp_parser::parse::KernelDumpParser;
use kdmp_parser::structs::KdDebuggerData64;
use kdmp_parser::virt;
use memmap2::Mmap;

use crate::kd::wire::{read_u16, read_u32, read_u64, read_u64 as buffer_u64};

use crate::backend::MemoryOps;
use crate::dbg_backend::{BackendCapability, DebugBackend, DebugCapability, StopEvent};
use crate::debugger_data::{DebuggerDataCandidate, MetadataSource};
use crate::diagnostics;
use crate::error::{Error, Result};
use crate::gdb::RegisterMap;
use crate::kd::context;
use crate::memory::PAGE_SIZE;
use crate::session::processor_index_from_backend_thread_id;
use crate::symbols::TypeInfo;
use crate::target::Target;
use crate::triage::{
    TriageBlock, TriageDriver, TriagePrcbInfo, is_triage_dump, parse_drivers, parse_triage,
};
use crate::types::{PhysAddr, VirtAddr};

const IMAGE_FILE_MACHINE_AMD64: u32 = 0x8664;

fn require_amd64_dump(machine_type: u32) -> Result<()> {
    if machine_type == IMAGE_FILE_MACHINE_AMD64 {
        return Ok(());
    }
    let name = match machine_type {
        0x014c => "I386",
        0xaa64 => "ARM64",
        _ => "unknown",
    };
    Err(Error::UnsupportedArchitecture(format!(
        "{name} crash dump (machine {machine_type:#06x})"
    )))
}

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
    pub mxcsr: u32,
    pub xmm: [u128; 16],
    pub debug_control: u64,
    pub last_branch_to_rip: u64,
    pub last_branch_from_rip: u64,
    pub last_exception_to_rip: u64,
    pub last_exception_from_rip: u64,
}

#[derive(Debug, Clone, Default)]
pub struct DmpException {
    pub code: u32,
    pub flags: u32,
    pub address: u64,
    pub parameters: Vec<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct DmpSystemInfo {
    pub major_version: u32,
    pub minor_version: u32,
    pub system_time: i64,
    pub system_up_time: i64,
    pub product_type: u32,
    pub suite_mask: u32,
    pub machine_image_type: u32,
    pub service_pack_build: u32,
}

#[derive(Debug, Clone)]
pub struct UnloadedDriver {
    pub name: String,
    pub start_address: u64,
    pub end_address: u64,
}
/// Metadata for a named secondary/blackbox stream. The current kdmp-parser
/// exposes no stream payload API, so this intentionally records only facts a
/// parser can prove without inventing a payload schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmpBlackboxStream {
    pub name: String,
    pub size: u64,
}

impl DmpContext {
    pub fn from_bytes(buf: &[u8]) -> Self {
        let mut xmm = [0u128; 16];
        if buf.len() >= context::OFFSET_XMM0 + 16 * 16 {
            for (i, slot) in xmm.iter_mut().enumerate() {
                let off = context::OFFSET_XMM0 + i * 16;
                *slot = u128::from_le_bytes(buf[off..off + 16].try_into().unwrap());
            }
        }

        let has_lbr = buf.len() >= context::OFFSET_LAST_EXCEPTION_FROM_RIP + 8;

        Self {
            rax: read_u64(buf, context::OFFSET_RAX),
            rbx: read_u64(buf, context::OFFSET_RBX),
            rcx: read_u64(buf, context::OFFSET_RCX),
            rdx: read_u64(buf, context::OFFSET_RDX),
            rsi: read_u64(buf, context::OFFSET_RSI),
            rdi: read_u64(buf, context::OFFSET_RDI),
            rbp: read_u64(buf, context::OFFSET_RBP),
            rsp: read_u64(buf, context::OFFSET_RSP),
            r8: read_u64(buf, context::OFFSET_R8),
            r9: read_u64(buf, context::OFFSET_R9),
            r10: read_u64(buf, context::OFFSET_R10),
            r11: read_u64(buf, context::OFFSET_R11),
            r12: read_u64(buf, context::OFFSET_R12),
            r13: read_u64(buf, context::OFFSET_R13),
            r14: read_u64(buf, context::OFFSET_R14),
            r15: read_u64(buf, context::OFFSET_R15),
            rip: read_u64(buf, context::OFFSET_RIP),
            eflags: read_u32(buf, context::OFFSET_EFLAGS),
            cs: read_u16(buf, context::OFFSET_SEG_CS),
            ds: read_u16(buf, context::OFFSET_SEG_DS),
            es: read_u16(buf, context::OFFSET_SEG_ES),
            fs: read_u16(buf, context::OFFSET_SEG_FS),
            gs: read_u16(buf, context::OFFSET_SEG_GS),
            ss: read_u16(buf, context::OFFSET_SEG_SS),
            dr0: read_u64(buf, context::OFFSET_DR0),
            dr1: read_u64(buf, context::OFFSET_DR1),
            dr2: read_u64(buf, context::OFFSET_DR2),
            dr3: read_u64(buf, context::OFFSET_DR3),
            dr6: read_u64(buf, context::OFFSET_DR6),
            dr7: read_u64(buf, context::OFFSET_DR7),
            mxcsr: read_u32(buf, context::OFFSET_MX_CSR),
            xmm,
            debug_control: if has_lbr {
                read_u64(buf, context::OFFSET_DEBUG_CONTROL)
            } else {
                0
            },
            last_branch_to_rip: if has_lbr {
                read_u64(buf, context::OFFSET_LAST_BRANCH_TO_RIP)
            } else {
                0
            },
            last_branch_from_rip: if has_lbr {
                read_u64(buf, context::OFFSET_LAST_BRANCH_FROM_RIP)
            } else {
                0
            },
            last_exception_to_rip: if has_lbr {
                read_u64(buf, context::OFFSET_LAST_EXCEPTION_TO_RIP)
            } else {
                0
            },
            last_exception_from_rip: if has_lbr {
                read_u64(buf, context::OFFSET_LAST_EXCEPTION_FROM_RIP)
            } else {
                0
            },
        }
    }

    pub fn to_register_buffer(&self, directory_table_base: u64) -> Vec<u8> {
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

        put_u64!(context::OFFSET_RAX, self.rax);
        put_u64!(context::OFFSET_RBX, self.rbx);
        put_u64!(context::OFFSET_RCX, self.rcx);
        put_u64!(context::OFFSET_RDX, self.rdx);
        put_u64!(context::OFFSET_RSI, self.rsi);
        put_u64!(context::OFFSET_RDI, self.rdi);
        put_u64!(context::OFFSET_RBP, self.rbp);
        put_u64!(context::OFFSET_RSP, self.rsp);
        put_u64!(context::OFFSET_R8, self.r8);
        put_u64!(context::OFFSET_R9, self.r9);
        put_u64!(context::OFFSET_R10, self.r10);
        put_u64!(context::OFFSET_R11, self.r11);
        put_u64!(context::OFFSET_R12, self.r12);
        put_u64!(context::OFFSET_R13, self.r13);
        put_u64!(context::OFFSET_R14, self.r14);
        put_u64!(context::OFFSET_R15, self.r15);
        put_u64!(context::OFFSET_RIP, self.rip);
        put_u32!(context::OFFSET_EFLAGS, self.eflags);
        put_u16!(context::OFFSET_SEG_CS, self.cs);
        put_u16!(context::OFFSET_SEG_DS, self.ds);
        put_u16!(context::OFFSET_SEG_ES, self.es);
        put_u16!(context::OFFSET_SEG_FS, self.fs);
        put_u16!(context::OFFSET_SEG_GS, self.gs);
        put_u16!(context::OFFSET_SEG_SS, self.ss);
        put_u64!(context::OFFSET_DR0, self.dr0);
        put_u64!(context::OFFSET_DR1, self.dr1);
        put_u64!(context::OFFSET_DR2, self.dr2);
        put_u64!(context::OFFSET_DR3, self.dr3);
        put_u64!(context::OFFSET_DR6, self.dr6);
        put_u64!(context::OFFSET_DR7, self.dr7);
        put_u64!(context::OFFSET_CR3, directory_table_base);
        put_u32!(context::OFFSET_MX_CSR, self.mxcsr);
        for (i, &val) in self.xmm.iter().enumerate() {
            let off = context::OFFSET_XMM0 + i * 16;
            data[off..off + 16].copy_from_slice(&val.to_le_bytes());
        }
        // Keep the buffer symmetric with from_bytes: PRCB-sourced raw CONTEXT
        // copies carry these, so the header-context buffer must too.
        put_u64!(context::OFFSET_DEBUG_CONTROL, self.debug_control);
        put_u64!(context::OFFSET_LAST_BRANCH_TO_RIP, self.last_branch_to_rip);
        put_u64!(
            context::OFFSET_LAST_BRANCH_FROM_RIP,
            self.last_branch_from_rip
        );
        put_u64!(
            context::OFFSET_LAST_EXCEPTION_TO_RIP,
            self.last_exception_to_rip
        );
        put_u64!(
            context::OFFSET_LAST_EXCEPTION_FROM_RIP,
            self.last_exception_from_rip
        );

        data
    }
}

/// Clamp the untrusted header's processor count so a malformed dump can't
/// drive an unbounded per-CPU register-buffer allocation (Windows tops out
/// at 2048 logical processors).
pub fn clamp_processors(n: u32) -> u32 {
    n.clamp(1, 2048)
}

#[derive(Debug, Clone)]
pub struct DmpInfo {
    pub directory_table_base: u64,
    pub bug_check_code: u32,
    pub bug_check_parameters: [u64; 4],
    pub context: DmpContext,
    pub offset_prcb_context: Option<u16>,
    pub number_processors: u32,
    pub is_triage: bool,
    pub ps_loaded_module_list: u64,
    pub debugger_data_block: Option<u64>,
    pub ps_active_process_head: u64,
    pub triage_drivers: Vec<TriageDriver>,
    pub exception: Option<DmpException>,
    pub system_info: Option<DmpSystemInfo>,
    pub unloaded_drivers: Vec<UnloadedDriver>,
    pub blackbox_streams: Vec<DmpBlackboxStream>,
    pub triage_process_snapshot: Option<Vec<u8>>,
    pub triage_thread_snapshot: Option<Vec<u8>>,
    pub triage_prcb_info: Option<TriagePrcbInfo>,
    pub broken_driver: Option<String>,
    pub triage_overflowed: bool,
    pub kern_base: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct TriageCrashInfo {
    pub process_name: Option<String>,
    pub process_id: Option<u64>,
    pub parent_process_id: Option<u64>,
    pub exit_status: Option<i32>,
    pub create_time: Option<u64>,
    pub thread_id: Option<u64>,
    pub thread_exit_status: Option<i32>,
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

        match KernelDumpParser::new(path) {
            Ok(parser) => Self::open_full(mmap, parser),
            Err(e) => Err(Error::InvalidDump(e.to_string())),
        }
    }

    fn open_full(mmap: Mmap, parser: KernelDumpParser) -> Result<Self> {
        let hdr = parser.headers();
        require_amd64_dump(hdr.machine_image_type)?;
        let mut pages: Vec<(u64, u64)> = parser
            .physmem()
            .map(|(gpa, offset)| (u64::from(gpa), offset))
            .collect();
        pages.sort_unstable_by_key(|&(gpa, _)| gpa);

        let ctx = parser.context_record();

        let offset_prcb_context = Self::read_prcb_context_offset(&parser);

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
            offset_prcb_context,
            number_processors: clamp_processors(hdr.number_processors),
            is_triage: false,
            ps_loaded_module_list: hdr.ps_loaded_module_list,
            ps_active_process_head: hdr.ps_active_process_head,
            debugger_data_block: (hdr.kd_debugger_data_block != 0)
                .then_some(hdr.kd_debugger_data_block),
            triage_drivers: Vec::new(),
            exception,
            system_info,
            unloaded_drivers: Vec::new(),
            blackbox_streams: Vec::new(),
            triage_process_snapshot: None,
            triage_thread_snapshot: None,
            triage_prcb_info: None,
            broken_driver: None,
            triage_overflowed: false,
            kern_base: None,
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
                mxcsr: ctx.mxcsr,
                xmm: ctx.xmm_registers,
                debug_control: ctx.debug_control,
                last_branch_to_rip: ctx.last_branch_to_rip,
                last_branch_from_rip: ctx.last_branch_from_rip,
                last_exception_to_rip: ctx.last_exception_to_rip,
                last_exception_from_rip: ctx.last_exception_from_rip,
            },
        };

        Ok(Self {
            mmap,
            storage: DmpStorage::Pages(pages),
            info,
        })
    }

    fn open_triage(mmap: Mmap) -> Result<Self> {
        let (mut info, blocks) = parse_triage(&mmap)?;
        if let Some(system_info) = info.system_info.as_ref() {
            require_amd64_dump(system_info.machine_image_type)?;
        }
        info.triage_drivers = parse_drivers(&mmap);
        Ok(Self {
            mmap,
            storage: DmpStorage::Blocks(blocks),
            info,
        })
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
            let cur_addr = addr + offset as u64;
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
    triage_crash_info: Option<TriageCrashInfo>,
    debugger_data_hint: Option<DebuggerDataCandidate>,
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
            debugger_data_hint: info
                .debugger_data_block
                .map(|address| DebuggerDataCandidate {
                    address: crate::types::VirtAddr(address),
                    source: MetadataSource::DumpHeader,
                }),
            triage_crash_info: None,
        }
    }

    fn build_register_buffer(ctx: &DmpContext, directory_table_base: u64) -> Vec<u8> {
        ctx.to_register_buffer(directory_table_base)
    }

    fn read_prcb_contexts(&mut self, target: &Target, prcb_ctx_offset: u16) -> Result<()> {
        let memory = target.guest()?.ntoskrnl.memory();
        let processor_block = target
            .guest()?
            .ntoskrnl
            .symbol("KiProcessorBlock")?
            .address();

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

    fn read_u64_field(snap: &[u8], layout: &TypeInfo, field: &str) -> Option<u64> {
        let off = layout.field_offset(field).ok()? as usize;
        if off + 8 <= snap.len() {
            Some(u64::from_le_bytes(snap[off..off + 8].try_into().ok()?))
        } else {
            None
        }
    }

    fn read_i32_field(snap: &[u8], layout: &TypeInfo, field: &str) -> Option<i32> {
        let off = layout.field_offset(field).ok()? as usize;
        if off + 4 <= snap.len() {
            Some(i32::from_le_bytes(snap[off..off + 4].try_into().ok()?))
        } else {
            None
        }
    }

    fn extract_triage_crash_info(target: &Target, info: &DmpInfo) -> Option<TriageCrashInfo> {
        let proc_snap = info.triage_process_snapshot.as_deref()?;
        let dtb = target.kernel_dtb();

        let eprocess_layout = target.symbols.find_type_across_modules(dtb, "_EPROCESS")?;

        let process_name = eprocess_layout
            .field_offset("ImageFileName")
            .ok()
            .and_then(|off| {
                let off = off as usize;
                if off + 15 <= proc_snap.len() {
                    let name_buf = &proc_snap[off..off + 15];
                    let end = name_buf.iter().position(|&c| c == 0).unwrap_or(15);
                    let s = String::from_utf8_lossy(&name_buf[..end]).to_string();
                    if s.is_empty() { None } else { Some(s) }
                } else {
                    None
                }
            });

        let process_id = Self::read_u64_field(proc_snap, &eprocess_layout, "UniqueProcessId");
        let parent_process_id =
            Self::read_u64_field(proc_snap, &eprocess_layout, "InheritedFromUniqueProcessId");
        let exit_status = Self::read_i32_field(proc_snap, &eprocess_layout, "ExitStatus");
        let create_time = Self::read_u64_field(proc_snap, &eprocess_layout, "CreateTime");

        let (thread_id, thread_exit_status) = info
            .triage_thread_snapshot
            .as_deref()
            .and_then(|thread_snap| {
                let ethread_layout = target.symbols.find_type_across_modules(dtb, "_ETHREAD")?;
                let cid_off = ethread_layout.field_offset("Cid").ok()? as usize;
                let client_id_layout =
                    target.symbols.find_type_across_modules(dtb, "_CLIENT_ID")?;
                let ut_off = client_id_layout.field_offset("UniqueThread").ok()? as usize;
                let off = cid_off + ut_off;
                let tid = if off + 8 <= thread_snap.len() {
                    Some(u64::from_le_bytes(
                        thread_snap[off..off + 8].try_into().ok()?,
                    ))
                } else {
                    None
                };
                let exit_st = Self::read_i32_field(thread_snap, &ethread_layout, "ExitStatus");
                Some((tid, exit_st))
            })
            .unwrap_or((None, None));

        Some(TriageCrashInfo {
            process_name,
            process_id,
            parent_process_id,
            exit_status,
            create_time,
            thread_id,
            thread_exit_status,
        })
    }

    pub fn triage_crash_info(&self) -> Option<&TriageCrashInfo> {
        self.triage_crash_info.as_ref()
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
    fn initialize_from_target(&mut self, target: &Target) {
        if let Some(offset) = self.prcb_context_offset {
            if let Err(e) = self.read_prcb_contexts(target, offset) {
                diagnostics::eprint_warning(format!("could not read PRCB contexts from dump: {e}"));
            }
            self.select_crash_processor();
        }

        if let Some(info) = target.phys.dmp_info() {
            self.triage_crash_info = Self::extract_triage_crash_info(target, info);
        }
    }

    fn triage_crash_info(&self) -> Option<&TriageCrashInfo> {
        self.triage_crash_info.as_ref()
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
            BackendCapability::unsupported(DebugCapability::TargetReloadDetection),
            BackendCapability::unsupported(DebugCapability::KernelBaseHint),
            BackendCapability::supported(DebugCapability::BugcheckDetection),
            BackendCapability::supported(DebugCapability::BugcheckDetails),
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

    #[test]
    fn dump_open_rejects_non_amd64_machine_types() {
        assert!(require_amd64_dump(IMAGE_FILE_MACHINE_AMD64).is_ok());
        let error = require_amd64_dump(0x014c).unwrap_err();
        assert!(error.to_string().contains("I386 crash dump"));
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
            ps_active_process_head: 0,
            debugger_data_block: None,
            triage_drivers: Vec::new(),
            exception: None,
            system_info: None,
            unloaded_drivers: Vec::new(),
            blackbox_streams: Vec::new(),
            triage_process_snapshot: None,
            triage_thread_snapshot: None,
            triage_prcb_info: None,
            broken_driver: None,
            triage_overflowed: false,
            kern_base: None,
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
                mxcsr: 0,
                xmm: [0; 16],
                debug_control: 0,
                last_branch_to_rip: 0,
                last_branch_from_rip: 0,
                last_exception_to_rip: 0,
                last_exception_from_rip: 0,
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
        // Page not present in dump
        assert_eq!(mem.lookup(0x3000), None);
        assert_eq!(mem.lookup(0x4000), None);
        assert_eq!(mem.lookup(0x8000), None);
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

    #[test]
    fn triage_mem_read_within_block() {
        let mut data = vec![0u8; 0x4000];
        // Block at VA 0xfffff80000001000, file offset 0x3000, size 0x100
        // Fill the file region with recognizable data
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

        // Read from the middle of the block
        let mut buf = [0u8; 4];
        mem.read_bytes(0xfffff80000001010u64, &mut buf).unwrap();
        assert_eq!(buf, [0x10, 0x11, 0x12, 0x13]);

        // Read past the block should fail
        let mut buf = [0u8; 1];
        assert!(mem.read_bytes(0xfffff80000001100u64, &mut buf).is_err());
    }

    #[test]
    fn triage_overlapping_blocks_fallback() {
        let mut data = vec![0u8; 0x8000];
        // Large block A: VA 0x1000, size 0x3000, at file offset 0x2000
        for i in 0..0x3000usize {
            data[0x2000 + i] = 0xAA;
        }
        // Small block B: VA 0x2000, size 0x1000, at file offset 0x5000
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

        // Address in block A only (before B starts)
        let mut buf = [0u8; 1];
        mem.read_bytes(0x1500u64, &mut buf).unwrap();
        assert_eq!(buf[0], 0xAA);

        // Address in the overlap region — B wins (highest start <= addr)
        mem.read_bytes(0x2500u64, &mut buf).unwrap();
        assert_eq!(buf[0], 0xBB);

        // Address past B's end but still within A — must fall back to A
        mem.read_bytes(0x3100u64, &mut buf).unwrap();
        assert_eq!(buf[0], 0xAA);

        // Address past both blocks
        assert!(mem.read_bytes(0x4100u64, &mut buf).is_err());
    }
}
