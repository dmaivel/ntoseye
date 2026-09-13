//! On-disk structures for Windows kernel crash dumps.
//!
//! Adapted from `kdmp-parser` 0.8.1 (MIT). See `THIRD-PARTY.md` for attribution.

use std::fmt::{self, Debug};

use zerocopy::{FromBytes, Immutable, KnownLayout};

use crate::error::{Error, Result};

/// Types of kernel crash dump.
///
/// Triage dumps (`0x4`) have no physical-memory map; [`crate::triage`] handles them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DumpType {
    // Old dump types from `dbgeng.dll`.
    Full = 0x1,
    Bmp = 0x5,
    /// (22H2+) Produced by `TaskMgr > System > Create live kernel Memory Dump`.
    LiveKernelMemory = 0x6,
    /// Produced by `.dump /k`.
    KernelMemory = 0x8,
    /// Produced by `.dump /ka`.
    KernelAndUserMemory = 0x9,
    /// Produced by `.dump /f`.
    CompleteMemory = 0xa,
}

impl TryFrom<u32> for DumpType {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self> {
        match value {
            x if x == Self::Full as u32 => Ok(Self::Full),
            x if x == Self::Bmp as u32 => Ok(Self::Bmp),
            x if x == Self::LiveKernelMemory as u32 => Ok(Self::LiveKernelMemory),
            x if x == Self::KernelMemory as u32 => Ok(Self::KernelMemory),
            x if x == Self::KernelAndUserMemory as u32 => Ok(Self::KernelAndUserMemory),
            x if x == Self::CompleteMemory as u32 => Ok(Self::CompleteMemory),
            _ => Err(Error::InvalidDump(format!("unknown dump type {value:#x}"))),
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, Immutable, KnownLayout)]
pub struct ExceptionRecord64 {
    pub exception_code: u32,
    pub exception_flags: u32,
    pub exception_record: u64,
    pub exception_address: u64,
    pub number_parameters: u32,
    unused_alignment1: u32,
    pub exception_information: [u64; 15],
}

pub const DUMP_HEADER64_EXPECTED_SIGNATURE: u32 = 0x45_47_41_50; // 'EGAP'
pub const DUMP_HEADER64_EXPECTED_VALID_DUMP: u32 = 0x34_36_55_44; // '46UD'

/// `DUMP_HEADER64`, with padding derived from `nt!IoFillDumpHeader`.
// https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Diagnostics/Debug/struct.DUMP_HEADER64.html#structfield.DumpType
#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout)]
pub struct Header64 {
    pub signature: u32,
    pub valid_dump: u32,
    pub major_version: u32,
    pub minor_version: u32,
    pub directory_table_base: u64,
    pub pfn_database: u64,
    pub ps_loaded_module_list: u64,
    pub ps_active_process_head: u64,
    pub machine_image_type: u32,
    pub number_processors: u32,
    pub bug_check_code: u32,
    padding1: u32,
    pub bug_check_code_parameters: [u64; 4],
    pub version_user: [u8; 32],
    pub kd_debugger_data_block: u64,
    pub physical_memory_block_buffer: [u8; 700],
    padding2: u32,
    pub context_record_buffer: [u8; 3_000],
    pub exception: ExceptionRecord64,
    pub dump_type: u32,
    padding3: u32,
    pub required_dump_space: i64,
    pub system_time: i64,
    pub comment: [u8; 128],
    pub system_up_time: i64,
    pub minidump_fields: u32,
    pub secondary_data_state: u32,
    pub product_type: u32,
    pub suite_mask: u32,
    pub writer_status: u32,
    unused1: u8,
    pub kd_secondary_version: u8,
    unused2: [u8; 2],
    pub attributes: u32,
    pub boot_id: u32,
    reserved1: [u8; 4008],
}

impl Debug for Header64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Header64")
            .field("signature", &self.signature)
            .field("valid_dump", &self.valid_dump)
            .field("major_version", &self.major_version)
            .field("minor_version", &self.minor_version)
            .field("directory_table_base", &self.directory_table_base)
            .field("pfn_database", &self.pfn_database)
            .field("ps_loaded_module_list", &self.ps_loaded_module_list)
            .field("ps_active_process_head", &self.ps_active_process_head)
            .field("machine_image_type", &self.machine_image_type)
            .field("number_processors", &self.number_processors)
            .field("bug_check_code", &self.bug_check_code)
            .field("bug_check_code_parameters", &self.bug_check_code_parameters)
            .field("kd_debugger_data_block", &self.kd_debugger_data_block)
            .field("exception", &self.exception)
            .field("dump_type", &self.dump_type)
            .field("system_time", &self.system_time)
            .field("system_up_time", &self.system_up_time)
            .field("product_type", &self.product_type)
            .field("suite_mask", &self.suite_mask)
            .field("writer_status", &self.writer_status)
            .field("kd_secondary_version", &self.kd_secondary_version)
            .field("attributes", &self.attributes)
            .field("boot_id", &self.boot_id)
            .finish_non_exhaustive()
    }
}

const BMPHEADER64_EXPECTED_SIGNATURE: u32 = 0x50_4D_44_53; // 'PMDS'
const BMPHEADER64_EXPECTED_SIGNATURE2: u32 = 0x50_4D_44_46; // 'PMDF'
const BMPHEADER64_EXPECTED_VALID_DUMP: u32 = 0x50_4D_55_44; // 'PMUD'

#[repr(C)]
#[derive(Debug, Default, FromBytes, Immutable, KnownLayout)]
pub struct BmpHeader64 {
    pub signature: u32,
    pub valid_dump: u32,
    // Rekall places `FirstPage` at offset 0x20.
    padding1: [u8; 0x20 - (0x4 + size_of::<u32>())],
    /// The offset of the first page in the file.
    pub first_page: u64,
    /// Number of set bits in the bitmap (stored pages).
    pub total_present_pages: u64,
    /// Number of PFNs covered by the bitmap, including absent pages.
    pub pages: u64,
    // Bitmap follows.
}

impl BmpHeader64 {
    #[must_use]
    pub fn looks_good(&self) -> bool {
        (self.signature == BMPHEADER64_EXPECTED_SIGNATURE
            || self.signature == BMPHEADER64_EXPECTED_SIGNATURE2)
            && self.valid_dump == BMPHEADER64_EXPECTED_VALID_DUMP
    }
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, Immutable, KnownLayout)]
pub struct PhysmemRun {
    pub base_page: u64,
    pub page_count: u64,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, Immutable, KnownLayout)]
pub struct PhysmemDesc {
    pub number_of_runs: u32,
    padding1: u32,
    pub number_of_pages: u64,
    // PHYSMEM_RUN Run[1] follows.
}

const RDMP_HEADER64_EXPECTED_MARKER: u32 = 0x40;
const RDMP_HEADER64_EXPECTED_SIGNATURE: u32 = 0x50_4D_44_52; // 'PMDR'
const RDMP_HEADER64_EXPECTED_VALID_DUMP: u32 = 0x50_4D_55_44; // 'PMUD'

#[repr(C)]
#[derive(Debug, Default, FromBytes, Immutable, KnownLayout)]
pub struct RdmpHeader64 {
    pub marker: u32,
    pub signature: u32,
    pub valid_dump: u32,
    reserved1: u32,
    pub metadata_size: u64,
    pub first_page_offset: u64,
}

impl RdmpHeader64 {
    #[must_use]
    pub fn looks_good(&self) -> bool {
        self.marker == RDMP_HEADER64_EXPECTED_MARKER
            && self.signature == RDMP_HEADER64_EXPECTED_SIGNATURE
            && self.valid_dump == RDMP_HEADER64_EXPECTED_VALID_DUMP
            // `metadata_size` and `first_page_offset` both start after a fixed
            // prologue, so their deltas must agree. Wrapping arithmetic keeps a
            // malformed header from panicking in debug builds.
            && self.metadata_size.wrapping_sub(0x20)
                == self.first_page_offset.wrapping_sub(0x20_40)
    }
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, Immutable, KnownLayout)]
pub struct KernelRdmpHeader64 {
    pub hdr: RdmpHeader64,
    unknown1: u64,
    unknown2: u64,
    // PFN ranges follow.
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, Immutable, KnownLayout)]
pub struct FullRdmpHeader64 {
    pub hdr: RdmpHeader64,
    pub number_of_ranges: u32,
    reserved1: u16,
    reserved2: u16,
    pub total_number_of_pages: u64,
    // PFN ranges follow.
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, Immutable, KnownLayout)]
pub struct PfnRange {
    pub page_file_number: u64,
    pub number_of_pages: u64,
}

/// The AMD64 `CONTEXT` record embedded in [`Header64::context_record_buffer`].
///
/// For ARM64, see [`crate::dmp::DmpContext::from_arm64_bytes`].
#[repr(C)]
#[derive(PartialEq, Eq, FromBytes, Immutable, KnownLayout)]
pub struct Context {
    pub p1_home: u64,
    pub p2_home: u64,
    pub p3_home: u64,
    pub p4_home: u64,
    pub p5_home: u64,
    pub p6_home: u64,
    pub context_flags: u32,
    pub mxcsr: u32,
    pub seg_cs: u16,
    pub seg_ds: u16,
    pub seg_es: u16,
    pub seg_fs: u16,
    pub seg_gs: u16,
    pub seg_ss: u16,
    pub eflags: u32,
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr6: u64,
    pub dr7: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub control_word: u16,
    pub status_word: u16,
    pub tag_word: u8,
    reserved1: u8,
    pub error_opcode: u16,
    pub error_offset: u32,
    pub error_selector: u16,
    reserved2: u16,
    pub data_offset: u32,
    pub data_selector: u16,
    reserved3: u16,
    pub mxcsr2: u32,
    pub mxcsr_mask: u32,
    pub float_registers: [u128; 8],
    pub xmm_registers: [u128; 16],
    reserved4: [u8; 96],
    pub vector_register: [u128; 26],
    pub vector_control: u64,
    pub debug_control: u64,
    pub last_branch_to_rip: u64,
    pub last_branch_from_rip: u64,
    pub last_exception_to_rip: u64,
    pub last_exception_from_rip: u64,
}

impl Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Context")
            .field("context_flags", &self.context_flags)
            .field("rax", &self.rax)
            .field("rcx", &self.rcx)
            .field("rdx", &self.rdx)
            .field("rbx", &self.rbx)
            .field("rsp", &self.rsp)
            .field("rbp", &self.rbp)
            .field("rsi", &self.rsi)
            .field("rdi", &self.rdi)
            .field("r8", &self.r8)
            .field("r9", &self.r9)
            .field("r10", &self.r10)
            .field("r11", &self.r11)
            .field("r12", &self.r12)
            .field("r13", &self.r13)
            .field("r14", &self.r14)
            .field("r15", &self.r15)
            .field("rip", &self.rip)
            .field("eflags", &self.eflags)
            .field("seg_cs", &self.seg_cs)
            .field("seg_ss", &self.seg_ss)
            .finish_non_exhaustive()
    }
}

/// 64-bit `LIST_ENTRY`.
#[repr(C)]
#[derive(Debug, Default, FromBytes, Immutable, KnownLayout)]
pub struct ListEntry64 {
    pub flink: u64,
    pub blink: u64,
}

// Copied from `WDBGEXTS.H`.
#[repr(C)]
#[derive(Debug, Default, FromBytes, Immutable, KnownLayout)]
pub struct DbgKdDebugDataHeader64 {
    /// Link to other blocks.
    pub list: ListEntry64,
    /// Tag identifying the block's owner.
    pub owner_tag: u32,
    /// Size of the data block in bytes, including this header.
    pub size: u32,
}

// https://github.com/tpn/winsdk-10/blob/9b69fd26ac0c7d0b83d378dba01080e93349c2ed/Include/10.0.14393.0/um/WDBGEXTS.H#L1206C16-L1206C34
#[repr(C)]
#[derive(Debug, Default, FromBytes, Immutable, KnownLayout)]
pub struct KdDebuggerData64 {
    pub header: DbgKdDebugDataHeader64,
    /// Base address of kernel image
    pub kern_base: u64,
    /// `DbgBreakPointWithStatus` is a function which takes an argument
    /// and hits a breakpoint. This field contains the address of the
    /// breakpoint instruction. When the debugger sees a breakpoint
    /// at this address, it may retrieve the argument from the first
    /// argument register, or on x86 the eax register.
    pub breakpoint_with_status: u64,
    /// Address of the saved context record during a bugcheck
    /// N.B. This is an automatic in `KeBugcheckEx`'s frame, and
    /// is only valid after a bugcheck.
    pub saved_context: u64,
    /// The address of the thread structure is provided in the
    /// `WAIT_STATE_CHANGE` packet.  This is the offset from the base of
    /// the thread structure to the pointer to the kernel stack frame
    /// for the currently active usermode callback.
    pub th_callback_stack: u16,
    /// saved pointer to next callback frame
    pub next_callback: u16,
    /// saved frame pointer
    pub frame_pointer: u16,
    /// pad to a quad boundary
    pub pae_enabled: u16,
    /// Address of the kernel callout routine.
    pub ki_call_user_mode: u64,
    /// Address of the usermode entry point for callbacks (in ntdll).
    pub ke_user_callback_dispatcher: u64,
    pub ps_loaded_module_list: u64,
    pub ps_active_process_head: u64,
    pub psp_cid_table: u64,
    pub exp_system_resources_list: u64,
    pub exp_paged_pool_descriptor: u64,
    pub exp_number_of_paged_pools: u64,
    pub ke_time_increment: u64,
    pub ke_bug_check_callback_list_head: u64,
    pub ki_bugcheck_data: u64,
    pub iop_error_log_list_head: u64,
    pub obp_root_directory_object: u64,
    pub obp_type_object_type: u64,
    pub mm_system_cache_start: u64,
    pub mm_system_cache_end: u64,
    pub mm_system_cache_ws: u64,
    pub mm_pfn_database: u64,
    pub mm_system_ptes_start: u64,
    pub mm_system_ptes_end: u64,
    pub mm_subsection_base: u64,
    pub mm_number_of_paging_files: u64,
    pub mm_lowest_physical_page: u64,
    pub mm_highest_physical_page: u64,
    pub mm_number_of_physical_pages: u64,
    pub mm_maximum_non_paged_pool_in_bytes: u64,
    pub mm_non_paged_system_start: u64,
    pub mm_non_paged_pool_start: u64,
    pub mm_non_paged_pool_end: u64,
    pub mm_paged_pool_start: u64,
    pub mm_paged_pool_end: u64,
    pub mm_paged_pool_information: u64,
    pub mm_page_size: u64,
    pub mm_size_of_paged_pool_in_bytes: u64,
    pub mm_total_commit_limit: u64,
    pub mm_total_committed_pages: u64,
    pub mm_shared_commit: u64,
    pub mm_driver_commit: u64,
    pub mm_process_commit: u64,
    pub mm_paged_pool_commit: u64,
    pub mm_extended_commit: u64,
    pub mm_zeroed_page_list_head: u64,
    pub mm_free_page_list_head: u64,
    pub mm_standby_page_list_head: u64,
    pub mm_modified_page_list_head: u64,
    pub mm_modified_no_write_page_list_head: u64,
    pub mm_available_pages: u64,
    pub mm_resident_available_pages: u64,
    pub pool_track_table: u64,
    pub non_paged_pool_descriptor: u64,
    pub mm_highest_user_address: u64,
    pub mm_system_range_start: u64,
    pub mm_user_probe_address: u64,
    pub kd_print_circular_buffer: u64,
    pub kd_print_circular_buffer_end: u64,
    pub kd_print_write_pointer: u64,
    pub kd_print_rollover_count: u64,
    pub mm_loaded_user_image_list: u64,
    // NT 5.1 addition
    pub nt_build_lab: u64,
    pub ki_normal_system_call: u64,
    // NT 5.0 hotfix addition
    pub ki_processor_block: u64,
    pub mm_unloaded_drivers: u64,
    pub mm_last_unloaded_driver: u64,
    pub mm_triage_action_taken: u64,
    pub mm_special_pool_tag: u64,
    pub kernel_verifier: u64,
    pub mm_verifier_data: u64,
    pub mm_allocated_non_paged_pool: u64,
    pub mm_peak_commitment: u64,
    pub mm_total_commit_limit_maximum: u64,
    pub cm_nt_csd_version: u64,
    // NT 5.1 addition
    pub mm_physical_memory_block: u64,
    pub mm_session_base: u64,
    pub mm_session_size: u64,
    pub mm_system_parent_table_page: u64,
    // Server 2003 addition
    pub mm_virtual_translation_base: u64,
    pub offset_kthread_next_processor: u16,
    pub offset_kthread_teb: u16,
    pub offset_kthread_kernel_stack: u16,
    pub offset_kthread_initial_stack: u16,
    pub offset_kthread_apc_process: u16,
    pub offset_kthread_state: u16,
    pub offset_kthread_b_store: u16,
    pub offset_kthread_b_store_limit: u16,
    pub size_eprocess: u16,
    pub offset_eprocess_peb: u16,
    pub offset_eprocess_parent_cid: u16,
    pub offset_eprocess_directory_table_base: u16,
    pub size_prcb: u16,
    pub offset_prcb_dpc_routine: u16,
    pub offset_prcb_current_thread: u16,
    pub offset_prcb_mhz: u16,
    pub offset_prcb_cpu_type: u16,
    pub offset_prcb_vendor_string: u16,
    pub offset_prcb_proc_state_context: u16,
    pub offset_prcb_number: u16,
    pub size_ethread: u16,
    pub kd_print_circular_buffer_ptr: u64,
    pub kd_print_buffer_size: u64,
    pub ke_loader_block: u64,
    pub size_pcr: u16,
    pub offset_pcr_self_pcr: u16,
    pub offset_pcr_current_prcb: u16,
    pub offset_pcr_contained_prcb: u16,
    pub offset_pcr_initial_b_store: u16,
    pub offset_pcr_b_store_limit: u16,
    pub offset_pcr_initial_stack: u16,
    pub offset_pcr_stack_limit: u16,
    pub offset_prcb_pcr_page: u16,
    pub offset_prcb_proc_state_special_reg: u16,
    pub gdt_r0_code: u16,
    pub gdt_r0_data: u16,
    pub gdt_r0_pcr: u16,
    pub gdt_r3_code: u16,
    pub gdt_r3_data: u16,
    pub gdt_r3_teb: u16,
    pub gdt_ldt: u16,
    pub gdt_tss: u16,
    pub gdt64_r3_cm_code: u16,
    pub gdt64_r3_cm_teb: u16,
    pub iop_num_triage_dump_data_blocks: u64,
    pub iop_triage_dump_data_blocks: u64,
    // Longhorn addition
    pub vf_crash_data_block: u64,
    pub mm_bad_pages_detected: u64,
    pub mm_zeroed_page_single_bit_errors_detected: u64,
    // Windows 7 addition
    pub etwp_debugger_data: u64,
    pub offset_prcb_context: u16,
    // ...
}

const _: () = assert!(size_of::<PhysmemDesc>() == 0x10);
const _: () = assert!(size_of::<PhysmemRun>() == 0x10);
const _: () = assert!(size_of::<Header64>() == 0x2_000);
const _: () = assert!(size_of::<Context>() == 0x4d0);
const _: () = assert!(size_of::<DbgKdDebugDataHeader64>() == 0x18);
