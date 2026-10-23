//! On-disk structures for Windows kernel crash dumps.
//!
//! Adapted from `kdmp-parser` 0.8.1 (MIT). See `THIRD-PARTY.md` for attribution.

use std::fmt::{self, Debug};

use zerocopy::{FromBytes, Immutable, KnownLayout};

use crate::base::error::{Error, Result};

/// Types of kernel crash dump.
///
/// Triage dumps (`0x4`) have no physical-memory map; [`crate::nt::dmp::triage`] handles them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DumpType {
    // Old dump types from `dbgeng.dll`.
    Full = 0x1,
    Bmp = 0x5,
    /// Bitmap kernel dump (`SDMPDUMP`): a bugcheck's kernel or automatic memory dump, or a live kernel dump.
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

const _: () = assert!(size_of::<PhysmemDesc>() == 0x10);
const _: () = assert!(size_of::<PhysmemRun>() == 0x10);
const _: () = assert!(size_of::<Header64>() == 0x2_000);
