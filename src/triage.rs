use crate::diagnostics;
use crate::dmp::{
    DmpContext, DmpException, DmpInfo, DmpSystemInfo, UnloadedDriver, clamp_processors,
};
use crate::error::{Error, Result};
use crate::guest::ModuleInfo;
use crate::kd::context;
use crate::kd::wire::{read_u16, read_u32, read_u64};
use crate::types::VirtAddr;
use kdmp_parser::structs::KdDebuggerData64;

const DUMP_HEADER64_SIZE: usize = 0x2000;
const SIGNATURE_PAGEDU64: &[u8; 8] = b"PAGEDU64";
const DUMP_TYPE_TRIAGE: u32 = 0x4;

// DUMP_HEADER64 field offsets
const OFF_MAJOR_VERSION: usize = 0x08;
const OFF_MINOR_VERSION: usize = 0x0C;
const OFF_DIRECTORY_TABLE_BASE: usize = 0x10;
const OFF_PS_LOADED_MODULE_LIST: usize = 0x20;
const OFF_PS_ACTIVE_PROCESS_HEAD: usize = 0x28;
const OFF_MACHINE_IMAGE_TYPE: usize = 0x30;
const OFF_NUMBER_PROCESSORS: usize = 0x34;
const OFF_BUG_CHECK_CODE: usize = 0x38;
const OFF_BUG_CHECK_PARAMETERS: usize = 0x40;
const OFF_CONTEXT_RECORD: usize = 0x88 + 700 + 4; // after physical_memory_block_buffer + padding2
const OFF_EXCEPTION_RECORD: usize = OFF_CONTEXT_RECORD + 3000; // after context_record_buffer
const OFF_DUMP_TYPE: usize = 0xF98;
const OFF_SYSTEM_TIME: usize = 0xFA8;
const OFF_SYSTEM_UP_TIME: usize = 0x1030;
const OFF_PRODUCT_TYPE: usize = 0x1040;
const OFF_SUITE_MASK: usize = 0x1044;

// ExceptionRecord64 layout (136 bytes)
const EXCEPTION_CODE: usize = 0x00;
const EXCEPTION_FLAGS: usize = 0x04;
const EXCEPTION_ADDRESS: usize = 0x10;
const EXCEPTION_NUM_PARAMS: usize = 0x18;
const EXCEPTION_INFORMATION: usize = 0x20;

// TRIAGE_DUMP64 field offsets (within the triage header, relative to 0x2000).
// Layout confirmed against Singularity RDK Dump.h and nforest/dumplib.
const TRIAGE_SERVICE_PACK_BUILD: usize = 0x00;
#[cfg(test)]
const TRIAGE_SIZE_OF_DUMP: usize = 0x04;
const TRIAGE_VALID_OFFSET: usize = 0x08;
const TRIAGE_CONTEXT_OFFSET: usize = 0x0C;
const TRIAGE_EXCEPTION_OFFSET: usize = 0x10;
const TRIAGE_UNLOADED_DRIVERS_OFFSET: usize = 0x18;
const TRIAGE_PRCB_OFFSET: usize = 0x1C;
const TRIAGE_PROCESS_OFFSET: usize = 0x20;
const TRIAGE_THREAD_OFFSET: usize = 0x24;
const TRIAGE_CALL_STACK_OFFSET: usize = 0x28;
const TRIAGE_SIZE_OF_CALL_STACK: usize = 0x2C;
const TRIAGE_DRIVER_LIST_OFFSET: usize = 0x30;
const TRIAGE_DRIVER_COUNT: usize = 0x34;
const TRIAGE_STRING_POOL_OFFSET: usize = 0x38;
const TRIAGE_STRING_POOL_SIZE: usize = 0x3C;
const TRIAGE_BROKEN_DRIVER_OFFSET: usize = 0x40;
const TRIAGE_OPTIONS: usize = 0x44;
const TRIAGE_OPTION_OVERFLOWED: u32 = 0x0100;
const TRIAGE_TOP_OF_STACK: usize = 0x48;
const TRIAGE_DATA_PAGE_ADDRESS: usize = 0x60;
const TRIAGE_DATA_PAGE_OFFSET: usize = 0x68;
const TRIAGE_DATA_PAGE_SIZE: usize = 0x6C;
const TRIAGE_DEBUGGER_DATA_OFFSET: usize = 0x70;
const TRIAGE_DEBUGGER_DATA_SIZE: usize = 0x74;
const TRIAGE_DATA_BLOCKS_OFFSET: usize = 0x78;
const TRIAGE_DATA_BLOCKS_COUNT: usize = 0x7C;

// Each TRIAGE_DATA_BLOCK is 16 bytes: Address(u64) + Offset(u32) + Size(u32)
const DATA_BLOCK_SIZE: usize = 16;

// Driver list: DRIVER_ENTRY64 structures, 0x90 bytes each.
// Layout: NameOffset(u32) reserved[52] DllBase(u64) EntryPoint(u64)
//         SizeOfImage(u64) reserved[48] CheckSum(u64) TimeDateStamp(u64)
const DRIVER_ENTRY_SIZE: usize = 0x90;
const DRIVER_OFF_NAME_OFFSET: usize = 0x00;
const DRIVER_OFF_DLL_BASE: usize = 0x38;
const DRIVER_OFF_ENTRY_POINT: usize = 0x40;
const DRIVER_OFF_SIZE_OF_IMAGE: usize = 0x48;
const DRIVER_OFF_CHECKSUM: usize = 0x80;
const DRIVER_OFF_TIME_DATE_STAMP: usize = 0x88;

// Unloaded driver entry: DUMP_UNLOADED_DRIVERS64 (0x38 bytes)
// Layout: UNICODE_STRING64(16) DriverName(WCHAR[12]=24) StartAddress(u64) EndAddress(u64)
const UNLOADED_DRIVER_ENTRY_SIZE: usize = 0x38;
const UNLOADED_DRIVER_OFF_NAME: usize = 0x10;
const UNLOADED_DRIVER_NAME_LEN: usize = 12;
const UNLOADED_DRIVER_OFF_START: usize = 0x28;
const UNLOADED_DRIVER_OFF_END: usize = 0x30;
const MAX_UNLOADED_DRIVERS: usize = 50;

#[derive(Debug, Clone)]
pub struct TriageBlock {
    pub address: u64,
    pub offset: u64,
    pub size: u32,
}

#[derive(Debug, Clone)]
pub struct TriageDriver {
    pub name: String,
    pub base: u64,
    pub entry_point: u64,
    pub size: u32,
    pub checksum: u32,
    pub time_date_stamp: u32,
}

impl TriageDriver {
    pub fn to_module_info(&self) -> ModuleInfo {
        ModuleInfo::new(self.name.clone(), VirtAddr(self.base), self.size)
            .with_time_date_stamp(self.time_date_stamp)
            .with_checksum(self.checksum)
    }
}

#[derive(Debug, Clone, Default)]
pub struct TriagePrcbInfo {
    pub current_thread: u64,
    pub processor_number: u16,
    pub mhz: u32,
    pub cpu_type: u16,
    pub vendor_string: String,
}

/// Returns true if the mmap looks like a PAGEDU64 triage dump.
pub fn is_triage_dump(mmap: &[u8]) -> bool {
    mmap.len() > DUMP_HEADER64_SIZE + 0x80
        && &mmap[..8] == SIGNATURE_PAGEDU64
        && read_u32(mmap, OFF_DUMP_TYPE) == DUMP_TYPE_TRIAGE
}

/// Parse a kernel triage dump from a raw memory-mapped file.
///
/// Returns `(DmpInfo, Vec<TriageBlock>)` — the same `DmpInfo` that the
/// full-dump path produces (so `DmpBackend` works unchanged), plus the
/// sorted block map for memory reads.
pub fn parse_triage(mmap: &[u8]) -> Result<(DmpInfo, Vec<TriageBlock>)> {
    if !is_triage_dump(mmap) {
        return Err(Error::InvalidDump("not a PAGEDU64 triage dump".into()));
    }

    // --- DUMP_HEADER64 fields ---
    let directory_table_base = read_u64(mmap, OFF_DIRECTORY_TABLE_BASE);
    let number_processors = read_u32(mmap, OFF_NUMBER_PROCESSORS);
    let bug_check_code = read_u32(mmap, OFF_BUG_CHECK_CODE);
    let bug_check_parameters = [
        read_u64(mmap, OFF_BUG_CHECK_PARAMETERS),
        read_u64(mmap, OFF_BUG_CHECK_PARAMETERS + 8),
        read_u64(mmap, OFF_BUG_CHECK_PARAMETERS + 16),
        read_u64(mmap, OFF_BUG_CHECK_PARAMETERS + 24),
    ];

    // --- TRIAGE_DUMP64 directory (at offset 0x2000) ---
    // Read header fields from the triage struct (field offsets are relative to
    // 0x2000), but the VALUES of all offset fields are absolute file offsets.
    let triage_hdr = &mmap[DUMP_HEADER64_SIZE..];

    // Prefer the triage-specific ContextOffset over the DUMP_HEADER64 fixed
    // position — in practice they point to the same data, but the triage
    // offset is authoritative for minidumps.
    let ctx_offset = read_u32(triage_hdr, TRIAGE_CONTEXT_OFFSET) as usize;
    let ctx_offset = if ctx_offset > 0 && ctx_offset + context::OFFSET_RIP + 8 <= mmap.len() {
        ctx_offset
    } else {
        OFF_CONTEXT_RECORD
    };
    if mmap.len() < ctx_offset + context::OFFSET_RIP + 8 {
        return Err(Error::InvalidDump(
            "dump too small for context record".into(),
        ));
    }
    let context = DmpContext::from_bytes(&mmap[ctx_offset..]);

    let call_stack_offset = read_u32(triage_hdr, TRIAGE_CALL_STACK_OFFSET) as u64;
    let size_of_call_stack = read_u32(triage_hdr, TRIAGE_SIZE_OF_CALL_STACK);
    let top_of_stack = read_u64(triage_hdr, TRIAGE_TOP_OF_STACK);
    let data_blocks_offset = read_u32(triage_hdr, TRIAGE_DATA_BLOCKS_OFFSET) as usize;
    let data_blocks_count = read_u32(triage_hdr, TRIAGE_DATA_BLOCKS_COUNT) as usize;

    // --- Build the block map ---

    // Validate data block bounds before allocating, to avoid OOM on
    // malformed dumps with a huge data_blocks_count.
    let blocks_end = data_blocks_offset + data_blocks_count * DATA_BLOCK_SIZE;
    if blocks_end > mmap.len() {
        return Err(Error::InvalidDump(
            "data blocks extend past dump file".into(),
        ));
    }
    if data_blocks_count > 0 && data_blocks_offset < DUMP_HEADER64_SIZE {
        return Err(Error::InvalidDump(
            "data blocks offset falls inside the dump header".into(),
        ));
    }

    let mut blocks = Vec::with_capacity(data_blocks_count + 1);

    // Add the call stack as a memory region (with the same bounds check
    // that data blocks receive below).  call_stack_offset is an absolute
    // file offset.
    if size_of_call_stack > 0
        && call_stack_offset > 0
        && top_of_stack > size_of_call_stack as u64
        && call_stack_offset + size_of_call_stack as u64 <= mmap.len() as u64
    {
        blocks.push(TriageBlock {
            address: top_of_stack - size_of_call_stack as u64,
            offset: call_stack_offset,
            size: size_of_call_stack,
        });
    }

    // Parse TRIAGE_DATA_BLOCK entries (data_blocks_offset is an absolute
    // file offset, so read entries directly from mmap).
    for i in 0..data_blocks_count {
        let base = data_blocks_offset + i * DATA_BLOCK_SIZE;
        let address = read_u64(mmap, base);
        let offset = read_u32(mmap, base + 8) as u64;
        let size = read_u32(mmap, base + 12);

        if size == 0 || offset + size as u64 > mmap.len() as u64 {
            continue;
        }

        blocks.push(TriageBlock {
            address,
            offset,
            size,
        });
    }

    // DataPage: a contiguous region of additional memory captured alongside
    // the call stack and data blocks.
    let dp_address = read_u64(triage_hdr, TRIAGE_DATA_PAGE_ADDRESS);
    let dp_offset = read_u32(triage_hdr, TRIAGE_DATA_PAGE_OFFSET) as u64;
    let dp_size = read_u32(triage_hdr, TRIAGE_DATA_PAGE_SIZE);
    if dp_size > 0 && dp_offset + dp_size as u64 <= mmap.len() as u64 && dp_address != 0 {
        blocks.push(TriageBlock {
            address: dp_address,
            offset: dp_offset,
            size: dp_size,
        });
    }

    blocks.sort_by_key(|b| b.address);
    blocks.dedup_by(|b, a| {
        if a.address == b.address {
            if b.size > a.size {
                a.size = b.size;
                a.offset = b.offset;
            }
            true
        } else {
            false
        }
    });

    validate_triage_signature(mmap, triage_hdr);

    let exception = parse_exception_record(mmap, triage_hdr);

    let service_pack_build = read_u32(triage_hdr, TRIAGE_SERVICE_PACK_BUILD);

    let system_info = Some(DmpSystemInfo {
        major_version: read_u32(mmap, OFF_MAJOR_VERSION),
        minor_version: read_u32(mmap, OFF_MINOR_VERSION),
        system_time: read_u64(mmap, OFF_SYSTEM_TIME) as i64,
        system_up_time: read_u64(mmap, OFF_SYSTEM_UP_TIME) as i64,
        product_type: read_u32(mmap, OFF_PRODUCT_TYPE),
        suite_mask: read_u32(mmap, OFF_SUITE_MASK),
        machine_image_type: read_u32(mmap, OFF_MACHINE_IMAGE_TYPE),
        service_pack_build,
    });

    let unloaded_drivers = parse_unloaded_drivers(mmap, triage_hdr);
    let debugger_data = parse_debugger_data(mmap, triage_hdr);

    // Extract EPROCESS / ETHREAD snapshots if the embedded
    // KDDEBUGGER_DATA64 tells us their sizes.
    let (triage_process_snapshot, triage_thread_snapshot) = match &debugger_data {
        Some(dd) => {
            let proc = extract_snapshot(
                mmap,
                read_u32(triage_hdr, TRIAGE_PROCESS_OFFSET) as usize,
                dd.size_eprocess as usize,
            );
            let thread = extract_snapshot(
                mmap,
                read_u32(triage_hdr, TRIAGE_THREAD_OFFSET) as usize,
                dd.size_ethread as usize,
            );
            (proc, thread)
        }
        None => (None, None),
    };

    let info = DmpInfo {
        directory_table_base,
        bug_check_code,
        bug_check_parameters,
        offset_prcb_context: debugger_data.as_ref().and_then(|d| d.offset_prcb_context),
        number_processors: clamp_processors(number_processors),
        is_triage: true,
        ps_loaded_module_list: read_u64(mmap, OFF_PS_LOADED_MODULE_LIST),
        ps_active_process_head: read_u64(mmap, OFF_PS_ACTIVE_PROCESS_HEAD),
        triage_drivers: Vec::new(),
        exception,
        system_info,
        unloaded_drivers,
        triage_process_snapshot,
        triage_thread_snapshot,
        triage_prcb_info: debugger_data
            .as_ref()
            .and_then(|dd| parse_prcb_info(mmap, triage_hdr, dd)),
        broken_driver: parse_broken_driver(mmap, triage_hdr),
        triage_overflowed: read_u32(triage_hdr, TRIAGE_OPTIONS) & TRIAGE_OPTION_OVERFLOWED != 0,
        kern_base: debugger_data.as_ref().and_then(|d| d.kern_base),
        context,
    };

    Ok((info, blocks))
}

/// Parse the driver list from a triage dump.
///
/// Each DRIVER_ENTRY64 is 0x90 bytes with NameOffset at +0x00, DllBase at
/// +0x38, SizeOfImage at +0x48, and TimeDateStamp at +0x88.  NameOffset
/// points into the string pool (null-terminated UTF-16LE strings).
pub fn parse_drivers(mmap: &[u8]) -> Vec<TriageDriver> {
    let mmap_len = mmap.len();
    if mmap_len <= DUMP_HEADER64_SIZE {
        return Vec::new();
    }

    // Read header fields from the triage struct (field offsets are relative
    // to 0x2000), but the VALUES are absolute file offsets — index mmap, not
    // the triage slice.
    let triage_hdr = &mmap[DUMP_HEADER64_SIZE..];
    let dl_offset = read_u32(triage_hdr, TRIAGE_DRIVER_LIST_OFFSET) as usize;
    let dl_count = read_u32(triage_hdr, TRIAGE_DRIVER_COUNT) as usize;
    let sp_offset = read_u32(triage_hdr, TRIAGE_STRING_POOL_OFFSET) as usize;
    let sp_size = read_u32(triage_hdr, TRIAGE_STRING_POOL_SIZE) as usize;

    if dl_offset >= mmap_len || sp_offset >= mmap_len || dl_count == 0 || dl_count > 4096 {
        return Vec::new();
    }

    let mut drivers = Vec::with_capacity(dl_count);

    for i in 0..dl_count {
        let entry_off = dl_offset + i * DRIVER_ENTRY_SIZE;
        if entry_off + DRIVER_ENTRY_SIZE > mmap_len {
            break;
        }

        let base = read_u64(mmap, entry_off + DRIVER_OFF_DLL_BASE);
        if base >> 48 != 0xFFFF {
            break;
        }

        let entry_point = read_u64(mmap, entry_off + DRIVER_OFF_ENTRY_POINT);
        let size = read_u32(mmap, entry_off + DRIVER_OFF_SIZE_OF_IMAGE);
        let checksum = read_u32(mmap, entry_off + DRIVER_OFF_CHECKSUM);
        let time_date_stamp = read_u32(mmap, entry_off + DRIVER_OFF_TIME_DATE_STAMP);
        let name_offset = read_u32(mmap, entry_off + DRIVER_OFF_NAME_OFFSET) as usize;

        let name = read_string_pool_entry(mmap, sp_offset, sp_size, name_offset, mmap_len)
            .unwrap_or_default();
        if name.is_empty() {
            break;
        }

        drivers.push(TriageDriver {
            name,
            base,
            entry_point,
            size,
            checksum,
            time_date_stamp,
        });
    }
    drivers
}

fn read_string_pool_entry(
    data: &[u8],
    sp_offset: usize,
    sp_size: usize,
    name_offset: usize,
    data_len: usize,
) -> Option<String> {
    // NameOffset is an absolute file offset. Each entry is:
    //   u32(char_count)  WCHAR[char_count]  \0  [padding]
    let pos = name_offset;
    let sp_end = (sp_offset + sp_size).min(data_len);
    if pos < sp_offset || pos + 4 > sp_end {
        return None;
    }
    let char_count = read_u32(data, pos) as usize;
    if char_count == 0 || char_count > 500 || pos + 4 + char_count * 2 > sp_end {
        return None;
    }
    let wchar_buf = &data[pos + 4..pos + 4 + char_count * 2];
    let code_units: Vec<u16> = wchar_buf
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .take_while(|&c| c != 0)
        .collect();
    if code_units.is_empty() {
        return None;
    }
    Some(String::from_utf16_lossy(&code_units))
}

/// Validate the triage dump integrity by checking the DGRT ('TRGD' LE)
/// signature at the offset stored in ValidOffset.
fn validate_triage_signature(mmap: &[u8], triage_hdr: &[u8]) {
    let valid_offset = read_u32(triage_hdr, TRIAGE_VALID_OFFSET) as usize;
    if valid_offset == 0 || valid_offset + 4 > mmap.len() {
        return;
    }
    let sig = &mmap[valid_offset..valid_offset + 4];
    if sig != b"TRGD" {
        diagnostics::eprint_warning(
            "triage dump DGRT integrity signature mismatch — dump may be truncated or corrupt",
        );
    }
}

fn parse_broken_driver(mmap: &[u8], triage_hdr: &[u8]) -> Option<String> {
    let name_offset = read_u32(triage_hdr, TRIAGE_BROKEN_DRIVER_OFFSET) as usize;
    if name_offset == 0 {
        return None;
    }
    let sp_offset = read_u32(triage_hdr, TRIAGE_STRING_POOL_OFFSET) as usize;
    let sp_size = read_u32(triage_hdr, TRIAGE_STRING_POOL_SIZE) as usize;
    read_string_pool_entry(mmap, sp_offset, sp_size, name_offset, mmap.len())
}

fn parse_exception_record(mmap: &[u8], triage_hdr: &[u8]) -> Option<DmpException> {
    // Try triage-specific exception offset first, fall back to header position
    let exc_offset = read_u32(triage_hdr, TRIAGE_EXCEPTION_OFFSET) as usize;
    let exc_buf = if exc_offset > 0 && exc_offset + EXCEPTION_INFORMATION + 15 * 8 <= mmap.len() {
        &mmap[exc_offset..]
    } else if mmap.len() >= OFF_EXCEPTION_RECORD + EXCEPTION_INFORMATION + 15 * 8 {
        &mmap[OFF_EXCEPTION_RECORD..]
    } else {
        return None;
    };

    let code = read_u32(exc_buf, EXCEPTION_CODE);
    let address = read_u64(exc_buf, EXCEPTION_ADDRESS);
    if code == 0 && address == 0 {
        return None;
    }

    let n_params = (read_u32(exc_buf, EXCEPTION_NUM_PARAMS) as usize).min(15);
    let parameters: Vec<u64> = (0..n_params)
        .map(|i| read_u64(exc_buf, EXCEPTION_INFORMATION + i * 8))
        .collect();

    Some(DmpException {
        code,
        flags: read_u32(exc_buf, EXCEPTION_FLAGS),
        address,
        parameters,
    })
}

fn extract_snapshot(mmap: &[u8], offset: usize, size: usize) -> Option<Vec<u8>> {
    if offset == 0 || size == 0 {
        return None;
    }
    let end = offset.checked_add(size)?;
    if end > mmap.len() {
        return None;
    }
    Some(mmap[offset..end].to_vec())
}

/// Extract `offset_prcb_context` from the embedded KDDEBUGGER_DATA64 blob.
///
/// Returns `Some(offset)` when the blob is large enough and the field is
/// non-zero — this enables multi-CPU register reading on triage dumps.
fn parse_debugger_data(mmap: &[u8], triage_hdr: &[u8]) -> Option<DebuggerDataFields> {
    let offset = read_u32(triage_hdr, TRIAGE_DEBUGGER_DATA_OFFSET) as usize;
    let size = read_u32(triage_hdr, TRIAGE_DEBUGGER_DATA_SIZE) as usize;
    let min_size = std::mem::offset_of!(KdDebuggerData64, offset_prcb_context) + 2;
    if offset == 0 || size < min_size {
        return None;
    }
    let end = offset.checked_add(size)?;
    if end > mmap.len() {
        return None;
    }

    // Read individual fields at their repr(C) offsets rather than transmuting
    // the whole struct — avoids alignment concerns on mmap'd data.
    let base = offset;
    let off_prcb_ctx = base + std::mem::offset_of!(KdDebuggerData64, offset_prcb_context);
    let off_sz_eprocess = base + std::mem::offset_of!(KdDebuggerData64, size_eprocess);
    let off_sz_ethread = base + std::mem::offset_of!(KdDebuggerData64, size_ethread);

    let kern_base_raw = read_u64(
        mmap,
        base + std::mem::offset_of!(KdDebuggerData64, kern_base),
    );
    let kern_base = if kern_base_raw >= 0xfffff800_00000000 {
        Some(kern_base_raw)
    } else {
        None
    };

    let prcb_context = read_u16(mmap, off_prcb_ctx);
    let size_eprocess = read_u16(mmap, off_sz_eprocess);
    let size_ethread = read_u16(mmap, off_sz_ethread);

    let size_prcb = read_u16(
        mmap,
        base + std::mem::offset_of!(KdDebuggerData64, size_prcb),
    );
    let offset_prcb_current_thread = read_u16(
        mmap,
        base + std::mem::offset_of!(KdDebuggerData64, offset_prcb_current_thread),
    );
    let offset_prcb_mhz = read_u16(
        mmap,
        base + std::mem::offset_of!(KdDebuggerData64, offset_prcb_mhz),
    );
    let offset_prcb_cpu_type = read_u16(
        mmap,
        base + std::mem::offset_of!(KdDebuggerData64, offset_prcb_cpu_type),
    );
    let offset_prcb_vendor_string = read_u16(
        mmap,
        base + std::mem::offset_of!(KdDebuggerData64, offset_prcb_vendor_string),
    );
    let offset_prcb_number = read_u16(
        mmap,
        base + std::mem::offset_of!(KdDebuggerData64, offset_prcb_number),
    );

    Some(DebuggerDataFields {
        kern_base,
        offset_prcb_context: if prcb_context > 0 {
            Some(prcb_context)
        } else {
            None
        },
        size_eprocess,
        size_ethread,
        size_prcb,
        offset_prcb_current_thread,
        offset_prcb_mhz,
        offset_prcb_cpu_type,
        offset_prcb_vendor_string,
        offset_prcb_number,
    })
}

struct DebuggerDataFields {
    kern_base: Option<u64>,
    offset_prcb_context: Option<u16>,
    size_eprocess: u16,
    size_ethread: u16,
    size_prcb: u16,
    offset_prcb_current_thread: u16,
    offset_prcb_mhz: u16,
    offset_prcb_cpu_type: u16,
    offset_prcb_vendor_string: u16,
    offset_prcb_number: u16,
}

fn parse_prcb_info(
    mmap: &[u8],
    triage_hdr: &[u8],
    dd: &DebuggerDataFields,
) -> Option<TriagePrcbInfo> {
    let prcb_offset = read_u32(triage_hdr, TRIAGE_PRCB_OFFSET) as usize;
    if prcb_offset == 0 || dd.size_prcb == 0 {
        return None;
    }
    let prcb_size = dd.size_prcb as usize;
    let end = prcb_offset.checked_add(prcb_size)?;
    if end > mmap.len() {
        return None;
    }
    let prcb = &mmap[prcb_offset..];

    let current_thread = if dd.offset_prcb_current_thread > 0
        && (dd.offset_prcb_current_thread as usize) + 8 <= prcb_size
    {
        read_u64(prcb, dd.offset_prcb_current_thread as usize)
    } else {
        0
    };

    let processor_number =
        if dd.offset_prcb_number > 0 && (dd.offset_prcb_number as usize) + 2 <= prcb_size {
            read_u16(prcb, dd.offset_prcb_number as usize)
        } else {
            0
        };

    let mhz = if dd.offset_prcb_mhz > 0 && (dd.offset_prcb_mhz as usize) + 4 <= prcb_size {
        read_u32(prcb, dd.offset_prcb_mhz as usize)
    } else {
        0
    };

    let cpu_type =
        if dd.offset_prcb_cpu_type > 0 && (dd.offset_prcb_cpu_type as usize) + 2 <= prcb_size {
            read_u16(prcb, dd.offset_prcb_cpu_type as usize)
        } else {
            0
        };

    let vendor_string = if dd.offset_prcb_vendor_string > 0
        && (dd.offset_prcb_vendor_string as usize) + 13 <= prcb_size
    {
        let off = dd.offset_prcb_vendor_string as usize;
        let bytes = &prcb[off..off + 13];
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(13);
        String::from_utf8_lossy(&bytes[..end]).to_string()
    } else {
        String::new()
    };

    Some(TriagePrcbInfo {
        current_thread,
        processor_number,
        mhz,
        cpu_type,
        vendor_string,
    })
}

fn parse_unloaded_drivers(mmap: &[u8], triage_hdr: &[u8]) -> Vec<UnloadedDriver> {
    let offset = read_u32(triage_hdr, TRIAGE_UNLOADED_DRIVERS_OFFSET) as usize;
    if offset == 0 {
        return Vec::new();
    }

    let mut drivers = Vec::new();
    for i in 0..MAX_UNLOADED_DRIVERS {
        let entry = offset + i * UNLOADED_DRIVER_ENTRY_SIZE;
        if entry + UNLOADED_DRIVER_ENTRY_SIZE > mmap.len() {
            break;
        }

        let start = read_u64(mmap, entry + UNLOADED_DRIVER_OFF_START);
        let end = read_u64(mmap, entry + UNLOADED_DRIVER_OFF_END);
        if start == 0 && end == 0 {
            break;
        }

        let name_buf = &mmap[entry + UNLOADED_DRIVER_OFF_NAME..];
        let code_units: Vec<u16> = (0..UNLOADED_DRIVER_NAME_LEN)
            .map(|j| read_u16(name_buf, j * 2))
            .take_while(|&c| c != 0)
            .collect();
        if code_units.is_empty() {
            break;
        }

        drivers.push(UnloadedDriver {
            name: String::from_utf16_lossy(&code_units),
            start_address: start,
            end_address: end,
        });
    }
    drivers
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_triage_dump(blocks: &[TriageBlock], mem_regions: &[(u64, &[u8])]) -> Vec<u8> {
        // DUMP_HEADER64 (0x2000) + TRIAGE_DUMP64 + data
        let mut buf = vec![0u8; 0x10000];
        // Signature
        buf[..8].copy_from_slice(SIGNATURE_PAGEDU64);
        // DumpType = 4
        buf[OFF_DUMP_TYPE..OFF_DUMP_TYPE + 4].copy_from_slice(&DUMP_TYPE_TRIAGE.to_le_bytes());
        // BugCheckCode
        buf[OFF_BUG_CHECK_CODE..OFF_BUG_CHECK_CODE + 4].copy_from_slice(&0x50u32.to_le_bytes());
        // NumberProcessors = 1
        buf[OFF_NUMBER_PROCESSORS..OFF_NUMBER_PROCESSORS + 4].copy_from_slice(&1u32.to_le_bytes());
        // DTB
        buf[OFF_DIRECTORY_TABLE_BASE..OFF_DIRECTORY_TABLE_BASE + 8]
            .copy_from_slice(&0x1ad000u64.to_le_bytes());
        // Context: set RIP
        let ctx_base = OFF_CONTEXT_RECORD;
        buf[ctx_base + context::OFFSET_RIP..ctx_base + context::OFFSET_RIP + 8]
            .copy_from_slice(&0xfffff80012345678u64.to_le_bytes());

        // TRIAGE_DUMP64 at 0x2000
        let triage_base = DUMP_HEADER64_SIZE;

        // SizeOfDump — we'll set this after placing data
        // CallStackOffset / SizeOfCallStack / TopOfStack — leave zeroed for this test

        // DataBlocksOffset — absolute file offset, right after triage header
        let db_offset: u32 = (DUMP_HEADER64_SIZE + 0x80) as u32;
        buf[triage_base + TRIAGE_DATA_BLOCKS_OFFSET..triage_base + TRIAGE_DATA_BLOCKS_OFFSET + 4]
            .copy_from_slice(&db_offset.to_le_bytes());
        buf[triage_base + TRIAGE_DATA_BLOCKS_COUNT..triage_base + TRIAGE_DATA_BLOCKS_COUNT + 4]
            .copy_from_slice(&(blocks.len() as u32).to_le_bytes());

        // Write data block entries — all offsets are absolute file offsets
        let mut data_cursor = (DUMP_HEADER64_SIZE + 0x200) as u32;
        for (i, block) in blocks.iter().enumerate() {
            let entry_off = db_offset as usize + i * DATA_BLOCK_SIZE;
            buf[entry_off..entry_off + 8].copy_from_slice(&block.address.to_le_bytes());
            buf[entry_off + 8..entry_off + 12].copy_from_slice(&data_cursor.to_le_bytes());
            buf[entry_off + 12..entry_off + 16].copy_from_slice(&block.size.to_le_bytes());

            // Place actual memory content at the absolute file offset
            if let Some((_, content)) = mem_regions.iter().find(|(a, _)| *a == block.address) {
                let file_off = data_cursor as usize;
                let len = content.len().min(block.size as usize);
                buf[file_off..file_off + len].copy_from_slice(&content[..len]);
            }

            data_cursor += block.size;
        }

        // SizeOfDump (triage section size)
        let total = data_cursor as usize - DUMP_HEADER64_SIZE + 0x200;
        buf[triage_base + TRIAGE_SIZE_OF_DUMP..triage_base + TRIAGE_SIZE_OF_DUMP + 4]
            .copy_from_slice(&(total as u32).to_le_bytes());

        buf
    }

    #[test]
    fn is_triage_dump_detects_signature_and_type() {
        let dump = make_triage_dump(&[], &[]);
        assert!(is_triage_dump(&dump));

        // Wrong signature
        let mut bad = dump.clone();
        bad[0] = b'X';
        assert!(!is_triage_dump(&bad));

        // Wrong dump type
        let mut bad = dump.clone();
        bad[OFF_DUMP_TYPE] = 0x01;
        assert!(!is_triage_dump(&bad));
    }

    #[test]
    fn parse_triage_extracts_header_fields() {
        let dump = make_triage_dump(&[], &[]);
        let (info, blocks) = parse_triage(&dump).unwrap();
        assert_eq!(info.bug_check_code, 0x50);
        assert_eq!(info.number_processors, 1);
        assert!(info.is_triage);
        assert_eq!(info.context.rip, 0xfffff80012345678);
        assert!(blocks.is_empty());
    }

    #[test]
    fn parse_triage_builds_sorted_block_map() {
        let blk_b = TriageBlock {
            address: 0x2000,
            offset: 0,
            size: 0x100,
        };
        let blk_a = TriageBlock {
            address: 0x1000,
            offset: 0,
            size: 0x80,
        };
        let data_a = vec![0xAAu8; 0x80];
        let data_b = vec![0xBBu8; 0x100];

        let dump = make_triage_dump(
            &[blk_b.clone(), blk_a.clone()],
            &[(0x2000, &data_b), (0x1000, &data_a)],
        );
        let (_, blocks) = parse_triage(&dump).unwrap();

        assert_eq!(blocks.len(), 2);
        // Sorted by address
        assert!(blocks[0].address < blocks[1].address);
        assert_eq!(blocks[0].address, 0x1000);
        assert_eq!(blocks[1].address, 0x2000);
    }
}
