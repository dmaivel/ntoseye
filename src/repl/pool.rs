use owo_colors::OwoColorize;
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::backend::MemoryOps;
use crate::cpu_state::MAX_PROCESSORS;
use crate::error::{Error, Result};
use crate::memory::PAGE_SIZE;
use crate::repl::INTERRUPT_REQUESTED;
use crate::symbols::{FieldInfo, ParsedType, TypeInfo, format_symbol_with_offset, le_uint};
use crate::target::Target;
use crate::types::VirtAddr;
use crate::ui;

pub const POOL_ALIGN: u64 = 0x10;

pub const POOL_PAGE_SIZE: u64 = PAGE_SIZE as u64;

pub const POOL_FREE_TAG: u32 = 0x6565_7246;

pub const POOL_MAX_GAP_UNITS: u64 = 4;

#[derive(Clone, Copy)]
pub struct PoolHeader {
    pub(crate) header: VirtAddr,
    pub(crate) body: VirtAddr,
    pub(crate) size: u64,
    pub(crate) previous_size: u64,
    pub(crate) pool_type: u8,
    pub(crate) tag: u32,
    pub(crate) synthetic_free: bool,
}

#[derive(Clone, Copy)]
pub struct BigPoolEntry {
    pub(crate) va: VirtAddr,
    pub(crate) entry: VirtAddr,
    pub(crate) index: u64,
    pub(crate) freed: bool,
    pub(crate) nonpaged: bool,
    pub(crate) size: u64,
    pub(crate) tag: u32,
    pub(crate) pattern: u8,
    pub(crate) pool_flags: u16,
    pub(crate) slush_size: u16,
}

/// PDB-driven layout for `_POOL_HEADER` and `_POOL_TRACKER_BIG_PAGES`. Field
/// presence varies across Windows builds; the `*_uses_struct` flags say whether
/// we can decode each entry field-by-field or have to fall back to fixed offsets
pub struct PoolLayout {
    pool_header: Arc<TypeInfo>,
    header_size: u64,
    pool_tag_offset: u64,
    pool_header_uses_struct: bool,
    pub(crate) big_pool_type: Option<Arc<TypeInfo>>,
    pub(crate) big_pool_uses_struct: bool,
    pub(crate) big_pool_has_pool_type: bool,
    pub(crate) big_pool_has_slush: bool,
}

pub fn pool_layout(debugger: &Target) -> Result<PoolLayout> {
    let pool_header = debugger
        .symbols
        .find_type_across_modules(debugger.current_dtb(), "_POOL_HEADER")
        .or_else(|| {
            debugger
                .symbols
                .find_type_across_modules(debugger.kernel_dtb(), "_POOL_HEADER")
        })
        .ok_or_else(|| Error::StructNotFound("_POOL_HEADER".to_string()))?;
    let pool_tag_offset = pool_header.field_offset("PoolTag")?;
    let pool_header_uses_struct = [
        "PreviousSize",
        "PoolIndex",
        "BlockSize",
        "PoolType",
        "PoolTag",
    ]
    .iter()
    .all(|name| pool_header.fields.contains_key(*name));

    let big_pool_type = debugger
        .symbols
        .find_type_across_modules(debugger.current_dtb(), "_POOL_TRACKER_BIG_PAGES")
        .or_else(|| {
            debugger
                .symbols
                .find_type_across_modules(debugger.kernel_dtb(), "_POOL_TRACKER_BIG_PAGES")
        });
    let (big_pool_uses_struct, big_pool_has_pool_type, big_pool_has_slush) = match &big_pool_type {
        Some(ti) => (
            ["Va", "Key", "NumberOfBytes", "Pattern"]
                .iter()
                .all(|name| ti.fields.contains_key(*name)),
            ti.fields.contains_key("PoolType") || ti.fields.contains_key("PoolFlags"),
            ti.fields.contains_key("SlushSize"),
        ),
        None => (false, false, false),
    };
    Ok(PoolLayout {
        header_size: pool_header.size as u64,
        pool_header,
        pool_tag_offset,
        pool_header_uses_struct,
        big_pool_type,
        big_pool_uses_struct,
        big_pool_has_pool_type,
        big_pool_has_slush,
    })
}

/// Resolve only the big-page entry type.  Some stripped kernels retain
/// `PoolBigPageTable` while omitting `_POOL_HEADER`; callers can still report
/// big allocations instead of losing the independent source entirely.
pub fn big_pool_layout(debugger: &Target) -> Result<(Arc<TypeInfo>, bool, bool, bool)> {
    let big_pool_type = debugger
        .symbols
        .find_type_across_modules(debugger.current_dtb(), "_POOL_TRACKER_BIG_PAGES")
        .or_else(|| {
            debugger
                .symbols
                .find_type_across_modules(debugger.kernel_dtb(), "_POOL_TRACKER_BIG_PAGES")
        })
        .ok_or_else(|| Error::StructNotFound("_POOL_TRACKER_BIG_PAGES".to_string()))?;
    let big_pool_uses_struct = ["Va", "Key", "NumberOfBytes", "Pattern"]
        .iter()
        .all(|name| big_pool_type.fields.contains_key(*name));
    let big_pool_has_pool_type = big_pool_type.fields.contains_key("PoolType")
        || big_pool_type.fields.contains_key("PoolFlags");
    let big_pool_has_slush = big_pool_type.fields.contains_key("SlushSize");
    Ok((
        big_pool_type,
        big_pool_uses_struct,
        big_pool_has_pool_type,
        big_pool_has_slush,
    ))
}

const MAX_POOL_TABLE_ENTRIES: u64 = 1 << 20;
const MAX_POOL_USAGE_ROWS: usize = 65_536;
const MAX_POOL_TABLE_BYTES: u64 = 256 * 1024 * 1024;
const POOL_TABLE_READ_CHUNK: usize = 16 * 1024 * 1024;
const BIG_POOL_ENTRY_CHUNK: u64 = 1024;
const BIG_POOL_FLAG_MASK: u16 = 0x0fff;

#[derive(Clone, Debug)]
pub struct PoolUsageRow {
    pub tag: u32,
    pub nonpaged_allocs: Option<i64>,
    pub nonpaged_frees: Option<i64>,
    pub nonpaged_bytes: Option<i64>,
    pub paged_allocs: Option<i64>,
    pub paged_frees: Option<i64>,
    pub paged_bytes: Option<i64>,
}

impl PoolUsageRow {
    fn new(tag: u32) -> Self {
        Self {
            tag,
            nonpaged_allocs: None,
            nonpaged_frees: None,
            nonpaged_bytes: None,
            paged_allocs: None,
            paged_frees: None,
            paged_bytes: None,
        }
    }
}

fn add_counter(slot: &mut Option<i64>, value: Option<i64>) {
    if let Some(value) = value {
        *slot = Some(slot.unwrap_or_default().saturating_add(value));
    }
}

/// Result metadata for a bounded big-page-table walk.
#[derive(Clone, Debug)]
pub struct BigPoolScanSummary {
    pub status: String,
}

/// Aggregate pool tracker rows plus large-page allocations.  Missing symbols,
/// fields, or unreadable entries are recorded in status strings rather than
/// preventing rows from the other source from being displayed.
#[derive(Clone, Debug)]
pub struct PoolUsageSummary {
    pub rows: Vec<PoolUsageRow>,
    pub rows_truncated: bool,
    pub tracker_status: String,
    pub big: BigPoolScanSummary,
}

pub(crate) fn kernel_symbol_address(debugger: &Target, name: &str) -> Result<VirtAddr> {
    let qualified = format!("nt!{name}");
    let address = debugger
        .symbols
        .find_symbol_across_modules(debugger.kernel_dtb(), &qualified)
        .ok()
        .flatten()
        .or_else(|| {
            debugger
                .symbols
                .find_symbol_across_modules(debugger.current_dtb(), &qualified)
                .ok()
                .flatten()
        })
        .ok_or_else(|| Error::SymbolNotFound(name.to_string()))?;
    Ok(address)
}

pub(crate) fn read_kernel_global_u64(debugger: &Target, name: &str) -> Result<u64> {
    let address = kernel_symbol_address(debugger, name)?;
    debugger.kernel_address_space().read(address)
}

fn read_kernel_global_u32(debugger: &Target, name: &str) -> Result<u32> {
    let address = kernel_symbol_address(debugger, name)?;
    debugger.kernel_address_space().read(address)
}

pub(crate) fn read_kernel_global_ptr(debugger: &Target, name: &str) -> Result<VirtAddr> {
    read_kernel_global_u64(debugger, name).map(VirtAddr)
}

/// Read a contiguous table in a handful of large requests.  A request that
/// crosses an unreadable page is retried one page at a time, preserving the
/// readable entries while zeroing only the missing pages.
fn read_pool_table(
    memory: &impl MemoryOps<VirtAddr>,
    table: VirtAddr,
    count: u64,
    entry_size: u64,
) -> Result<(Vec<u8>, u64)> {
    let total = count
        .checked_mul(entry_size)
        .ok_or_else(|| Error::DebugInfo("pool table byte count overflows".to_string()))?;
    if total > MAX_POOL_TABLE_BYTES {
        return Err(Error::DebugInfo(format!(
            "pool table size {total:#x} exceeds safety bound {MAX_POOL_TABLE_BYTES:#x}"
        )));
    }
    let total_usize = usize::try_from(total)
        .map_err(|_| Error::DebugInfo("pool table byte count does not fit usize".to_string()))?;
    let mut bytes = vec![0u8; total_usize];
    let mut unreadable_pages = 0u64;
    let mut offset = 0usize;
    while offset < total_usize {
        let request_len = POOL_TABLE_READ_CHUNK.min(total_usize - offset);
        let address = table
            .0
            .checked_add(offset as u64)
            .ok_or_else(|| Error::DebugInfo("pool table address overflows".to_string()))?;
        let request = &mut bytes[offset..offset + request_len];
        if memory.read_bytes(VirtAddr(address), request).is_ok() {
            offset += request_len;
            continue;
        }

        request.fill(0);
        let mut page_offset = 0usize;
        while page_offset < request_len {
            let page_address = address
                .checked_add(page_offset as u64)
                .ok_or_else(|| Error::DebugInfo("pool table page address overflows".to_string()))?;
            let page_len = ((POOL_PAGE_SIZE - (page_address & (POOL_PAGE_SIZE - 1))) as usize)
                .min(request_len - page_offset);
            let page = &mut request[page_offset..page_offset + page_len];
            if memory.read_bytes(VirtAddr(page_address), page).is_err() {
                page.fill(0);
                unreadable_pages = unreadable_pages.saturating_add(1);
            }
            page_offset += page_len;
        }
        offset += request_len;
    }
    Ok((bytes, unreadable_pages))
}

struct BigPoolWalkReport {
    advertised: u64,
    scanned: u64,
    unreadable_pages: u64,
    stopped: bool,
}

fn walk_big_pool_entries<F>(
    debugger: &Target,
    big_pool_type: &TypeInfo,
    big_pool_uses_struct: bool,
    big_pool_has_pool_type: bool,
    big_pool_has_slush: bool,
    mut visit: F,
) -> std::result::Result<BigPoolWalkReport, String>
where
    F: FnMut(&BigPoolEntry) -> bool,
{
    let table = read_kernel_global_ptr(debugger, "PoolBigPageTable")
        .map_err(|error| format!("PoolBigPageTable unavailable: {error}"))?;
    if table.is_zero() {
        return Err("PoolBigPageTable is null".to_string());
    }
    let advertised = u64::from(
        read_kernel_global_u32(debugger, "PoolBigPageTableSize")
            .map_err(|error| format!("PoolBigPageTableSize unavailable: {error}"))?,
    );
    if advertised == 0 {
        return Err("PoolBigPageTableSize is zero".to_string());
    }
    if advertised > MAX_POOL_TABLE_ENTRIES {
        return Err(format!(
            "PoolBigPageTableSize {advertised:#x} exceeds safety bound"
        ));
    }
    let entry_size = u64::try_from(big_pool_type.size)
        .ok()
        .filter(|size| *size > 0)
        .ok_or_else(|| "invalid big-page entry size 0x0".to_string())?;
    let entry_size_usize = match usize::try_from(entry_size) {
        Ok(size) if size as u64 <= POOL_PAGE_SIZE => size,
        _ => return Err(format!("invalid big-page entry size {entry_size:#x}")),
    };
    let mem = debugger.kernel_address_space();
    let mut scanned = 0u64;
    let mut unreadable_pages = 0u64;
    let mut stopped = false;
    let mut index = 0u64;
    'scan: while index < advertised {
        if INTERRUPT_REQUESTED.load(Ordering::Relaxed) {
            break;
        }
        let count = BIG_POOL_ENTRY_CHUNK.min(advertised - index);
        let chunk_address = index
            .checked_mul(entry_size)
            .and_then(|offset| table.0.checked_add(offset))
            .map(VirtAddr)
            .ok_or_else(|| "PoolBigPageTable address overflows".to_string())?;
        let (table_bytes, unreadable) = read_pool_table(&mem, chunk_address, count, entry_size)
            .map_err(|error| error.to_string())?;
        unreadable_pages = unreadable_pages.saturating_add(unreadable);
        for (chunk_index, entry_buf) in table_bytes.chunks_exact(entry_size_usize).enumerate() {
            if INTERRUPT_REQUESTED.load(Ordering::Relaxed) {
                break 'scan;
            }
            let entry_index = index + chunk_index as u64;
            let entry_address = match entry_index
                .checked_mul(entry_size)
                .and_then(|offset| table.0.checked_add(offset))
            {
                Some(address) => VirtAddr(address),
                None => {
                    scanned = scanned.saturating_add(1);
                    continue;
                }
            };
            scanned = scanned.saturating_add(1);
            if let Some(mut entry) = parse_big_pool_entry(
                big_pool_type,
                big_pool_uses_struct,
                big_pool_has_pool_type,
                big_pool_has_slush,
                entry_address,
                entry_buf,
            ) {
                entry.index = entry_index;
                if !entry.freed && visit(&entry) {
                    stopped = true;
                    break 'scan;
                }
            }
        }
        index += count;
    }

    Ok(BigPoolWalkReport {
        advertised,
        scanned,
        unreadable_pages,
        stopped,
    })
}

/// Walk `PoolBigPageTable` in bounded chunks, invoking `visit` for each valid
/// entry. Returning true from `visit` stops the walk immediately.
pub fn scan_big_pool_entries<F>(
    debugger: &Target,
    big_pool_type: Option<&TypeInfo>,
    big_pool_uses_struct: bool,
    big_pool_has_pool_type: bool,
    big_pool_has_slush: bool,
    visit: F,
) -> BigPoolScanSummary
where
    F: FnMut(&BigPoolEntry) -> bool,
{
    let Some(big_pool_type) = big_pool_type else {
        return BigPoolScanSummary {
            status: "_POOL_TRACKER_BIG_PAGES type unavailable".to_string(),
        };
    };
    let report = match walk_big_pool_entries(
        debugger,
        big_pool_type,
        big_pool_uses_struct,
        big_pool_has_pool_type,
        big_pool_has_slush,
        visit,
    ) {
        Ok(report) => report,
        Err(error) => {
            return BigPoolScanSummary { status: error };
        }
    };
    let mut status = format!("scanned {}/{} entries", report.scanned, report.advertised);
    if report.stopped {
        status.push_str(" (stopped)");
    }
    if INTERRUPT_REQUESTED.load(Ordering::Relaxed) {
        status.push_str(" (interrupted)");
    }
    if report.unreadable_pages != 0 {
        status.push_str(&format!(", {} unreadable pages", report.unreadable_pages));
    }
    BigPoolScanSummary { status }
}

fn tracker_counter_from_buf(ti: &TypeInfo, buf: &[u8], field: &str) -> Option<i64> {
    let value = pool_field_from_buf(ti, buf, field)?;
    if matches!(field, "NonPagedBytes" | "PagedBytes") {
        Some(value as i64)
    } else {
        i64::try_from(value).ok()
    }
}

fn aggregate_tracker_table(
    rows: &mut BTreeMap<u32, PoolUsageRow>,
    rows_truncated: &mut bool,
    ti: &TypeInfo,
    table_bytes: &[u8],
    entry_size: usize,
) -> u64 {
    let mut scanned = 0u64;
    for entry in table_bytes.chunks_exact(entry_size) {
        if INTERRUPT_REQUESTED.load(Ordering::Relaxed) {
            break;
        }
        let Some(tag) =
            pool_field_from_buf(ti, entry, "Key").and_then(|tag| u32::try_from(tag).ok())
        else {
            scanned = scanned.saturating_add(1);
            continue;
        };
        if tag == 0 {
            scanned = scanned.saturating_add(1);
            continue;
        }
        let row = if let Some(row) = rows.get_mut(&tag) {
            row
        } else if rows.len() < MAX_POOL_USAGE_ROWS {
            rows.entry(tag).or_insert_with(|| PoolUsageRow::new(tag))
        } else {
            *rows_truncated = true;
            scanned = scanned.saturating_add(1);
            continue;
        };
        add_counter(
            &mut row.nonpaged_allocs,
            tracker_counter_from_buf(ti, entry, "NonPagedAllocs"),
        );
        add_counter(
            &mut row.nonpaged_frees,
            tracker_counter_from_buf(ti, entry, "NonPagedFrees"),
        );
        add_counter(
            &mut row.nonpaged_bytes,
            tracker_counter_from_buf(ti, entry, "NonPagedBytes"),
        );
        add_counter(
            &mut row.paged_allocs,
            tracker_counter_from_buf(ti, entry, "PagedAllocs"),
        );
        add_counter(
            &mut row.paged_frees,
            tracker_counter_from_buf(ti, entry, "PagedFrees"),
        );
        add_counter(
            &mut row.paged_bytes,
            tracker_counter_from_buf(ti, entry, "PagedBytes"),
        );
        scanned = scanned.saturating_add(1);
    }
    scanned
}

fn collect_tracker_usage(
    debugger: &Target,
    rows: &mut BTreeMap<u32, PoolUsageRow>,
    rows_truncated: &mut bool,
) -> std::result::Result<String, String> {
    let tracker_type = debugger
        .symbols
        .find_type_across_modules(debugger.current_dtb(), "_POOL_TRACKER_TABLE")
        .or_else(|| {
            debugger
                .symbols
                .find_type_across_modules(debugger.kernel_dtb(), "_POOL_TRACKER_TABLE")
        });
    let ti = tracker_type.ok_or_else(|| "_POOL_TRACKER_TABLE type unavailable".to_string())?;
    let entry_size = u64::try_from(ti.size).unwrap_or(0);
    if entry_size == 0 || entry_size > POOL_PAGE_SIZE {
        return Err(format!("invalid _POOL_TRACKER_TABLE size {entry_size:#x}"));
    }
    let count = u64::from(
        read_kernel_global_u32(debugger, "PoolTrackTableSize")
            .map_err(|error| format!("PoolTrackTableSize unavailable: {error}"))?,
    );
    if count == 0 {
        return Err("PoolTrackTableSize is zero".to_string());
    }

    let memory = debugger.kernel_address_space();
    let mut tables = Vec::new();
    let mut seen_tables = HashSet::new();
    if let Some(table) = read_kernel_global_ptr(debugger, "PoolTrackTable")
        .ok()
        .filter(|table| !table.is_zero())
    {
        seen_tables.insert(table.0);
        tables.push(table);
    }
    let mut source = "PoolTrackTable";
    if let (Ok(array), Ok(processors)) = (
        kernel_symbol_address(debugger, "ExPoolTagTables"),
        read_kernel_global_u32(debugger, "KeNumberProcessors"),
    ) && processors > 0
    {
        source = "ExPoolTagTables";
        for index in 0..u64::from(processors).min(u64::from(MAX_PROCESSORS)) {
            let Some(pointer_address) = array.0.checked_add(index.saturating_mul(8)).map(VirtAddr)
            else {
                break;
            };
            let Ok(table) = memory.read::<VirtAddr>(pointer_address) else {
                continue;
            };
            if !table.is_zero() && seen_tables.insert(table.0) {
                tables.push(table);
            }
        }
    }
    if tables.is_empty() {
        return Err("PoolTrackTable is null or unreadable".to_string());
    }

    let scan_count = count.min(MAX_POOL_TABLE_ENTRIES);
    let entry_size_usize = entry_size as usize;
    let advertised_total = count.saturating_mul(tables.len() as u64);
    let mut scanned = 0u64;
    let mut unreadable_pages = 0u64;
    let mut unreadable_tables = 0u64;
    for table in &tables {
        if INTERRUPT_REQUESTED.load(Ordering::Relaxed) {
            break;
        }
        match read_pool_table(&memory, *table, scan_count, entry_size) {
            Ok((table_bytes, unreadable)) => {
                unreadable_pages = unreadable_pages.saturating_add(unreadable);
                scanned = scanned.saturating_add(aggregate_tracker_table(
                    rows,
                    rows_truncated,
                    &ti,
                    &table_bytes,
                    entry_size_usize,
                ));
            }
            Err(_) => unreadable_tables = unreadable_tables.saturating_add(1),
        }
    }
    let mut status = format!(
        "{source}: scanned {scanned}/{advertised_total} entries across {} tables",
        tables.len()
    );
    if scan_count < count {
        status.push_str(" (bounded)");
    }
    if INTERRUPT_REQUESTED.load(Ordering::Relaxed) {
        status.push_str(" (interrupted)");
    }
    if unreadable_tables != 0 {
        status.push_str(&format!(", {unreadable_tables} unreadable tables"));
    }
    if unreadable_pages != 0 {
        status.push_str(&format!(", {unreadable_pages} unreadable pages"));
    }
    Ok(status)
}

fn aggregate_big_pool_entry(
    rows: &mut BTreeMap<u32, PoolUsageRow>,
    rows_truncated: &mut bool,
    entry: &BigPoolEntry,
) {
    let row = if let Some(row) = rows.get_mut(&entry.tag) {
        row
    } else if rows.len() < MAX_POOL_USAGE_ROWS {
        rows.entry(entry.tag)
            .or_insert_with(|| PoolUsageRow::new(entry.tag))
    } else {
        *rows_truncated = true;
        return;
    };
    if entry.nonpaged {
        add_counter(&mut row.nonpaged_allocs, Some(1));
        add_counter(&mut row.nonpaged_bytes, i64::try_from(entry.size).ok());
    } else {
        add_counter(&mut row.paged_allocs, Some(1));
        add_counter(&mut row.paged_bytes, i64::try_from(entry.size).ok());
    }
}

/// Aggregate all per-processor tracker tables and the big-page table without
/// retaining every entry.
pub fn collect_pool_usage(debugger: &Target) -> PoolUsageSummary {
    let mut rows = BTreeMap::<u32, PoolUsageRow>::new();
    let mut rows_truncated = false;
    let tracker_status = collect_tracker_usage(debugger, &mut rows, &mut rows_truncated)
        .unwrap_or_else(|error| error);

    let big = match pool_layout(debugger) {
        Ok(layout) => scan_big_pool_entries(
            debugger,
            layout.big_pool_type.as_deref(),
            layout.big_pool_uses_struct,
            layout.big_pool_has_pool_type,
            layout.big_pool_has_slush,
            |entry| {
                aggregate_big_pool_entry(&mut rows, &mut rows_truncated, entry);
                false
            },
        ),
        Err(layout_error) => match big_pool_layout(debugger) {
            Ok((big_pool_type, uses_struct, has_pool_type, has_slush)) => scan_big_pool_entries(
                debugger,
                Some(&big_pool_type),
                uses_struct,
                has_pool_type,
                has_slush,
                |entry| {
                    aggregate_big_pool_entry(&mut rows, &mut rows_truncated, entry);
                    false
                },
            ),
            Err(big_error) => BigPoolScanSummary {
                status: format!(
                    "pool layout unavailable: {layout_error}; big-page layout: {big_error}"
                ),
            },
        },
    };

    PoolUsageSummary {
        rows: rows.into_values().collect(),
        rows_truncated,
        tracker_status,
        big,
    }
}

pub fn read_pool_field(
    ti: &TypeInfo,
    mem: &impl MemoryOps<VirtAddr>,
    addr: VirtAddr,
    field: &str,
) -> Option<u64> {
    let f = ti.fields.get(field)?;
    let field_addr = addr + f.offset as u64;
    let size = usize::try_from(f.size).ok()?.clamp(1, 8);
    let mut buf = [0u8; 8];
    mem.read_bytes(field_addr, &mut buf[..size]).ok()?;
    pool_field_from_storage(f, &buf[..size])
}

/// `read_pool_field` against an already-read entry buffer
pub fn pool_field_from_buf(ti: &TypeInfo, buf: &[u8], field: &str) -> Option<u64> {
    let f = ti.fields.get(field)?;
    let offset = f.offset as usize;
    let size = usize::try_from(f.size).ok()?.clamp(1, 8);
    pool_field_from_storage(f, buf.get(offset..offset.checked_add(size)?)?)
}

fn pool_raw_from_buf(ti: &TypeInfo, buf: &[u8], field: &str) -> Option<u64> {
    let f = ti.fields.get(field)?;
    let offset = f.offset as usize;
    let size = usize::try_from(f.size).ok()?.clamp(1, 8);
    Some(le_uint(buf.get(offset..offset.checked_add(size)?)?))
}

fn pool_field_from_storage(f: &FieldInfo, buf: &[u8]) -> Option<u64> {
    let raw = le_uint(buf);
    if let ParsedType::Bitfield { pos, len, .. } = &f.type_data {
        let mask = if *len >= 64 {
            u64::MAX
        } else {
            (1u64 << *len) - 1
        };
        Some((raw >> *pos) & mask)
    } else {
        Some(raw)
    }
}

pub fn tag_string(tag: u32) -> String {
    let mut s = String::with_capacity(4);
    for i in 0..4 {
        let c = ((tag >> (i * 8)) & 0xff) as u8;
        s.push(if (0x20..=0x7e).contains(&c) {
            c as char
        } else {
            '.'
        });
    }
    s
}

pub fn tag_looks_printable(tag: u32) -> bool {
    (0..4).all(|i| (0x20..=0x7e).contains(&((tag >> (i * 8)) & 0xff)))
}

pub fn plausible_pool_tag(tag: u32) -> bool {
    tag == POOL_FREE_TAG || tag_looks_printable(tag)
}

pub fn pool_block_state(h: &PoolHeader) -> &'static str {
    if h.synthetic_free || h.tag == POOL_FREE_TAG {
        "Free"
    } else if tag_looks_printable(h.tag) {
        "Allocated"
    } else {
        "Allocated?"
    }
}

pub fn parse_pool_header(
    debugger: &Target,
    layout: &PoolLayout,
    header: VirtAddr,
) -> Option<PoolHeader> {
    let mem = debugger.current_process().ok()?.memory();
    let (previous_size, block_units, pool_type, tag) = if layout.pool_header_uses_struct {
        let previous_size =
            read_pool_field(&layout.pool_header, &mem, header, "PreviousSize")? as u8;
        let block_units = read_pool_field(&layout.pool_header, &mem, header, "BlockSize")? as u8;
        let pool_type = read_pool_field(&layout.pool_header, &mem, header, "PoolType")? as u8;
        let tag = read_pool_field(&layout.pool_header, &mem, header, "PoolTag")? as u32;
        (previous_size, block_units, pool_type, tag)
    } else {
        let word0: u32 = mem.read(header).ok()?;
        let tag: u32 = mem.read(header + layout.pool_tag_offset).ok()?;
        (
            (word0 & 0xff) as u8,
            ((word0 >> 16) & 0xff) as u8,
            ((word0 >> 24) & 0xff) as u8,
            tag,
        )
    };
    if block_units == 0 {
        return None;
    }
    Some(PoolHeader {
        header,
        body: header + layout.header_size,
        size: block_units as u64 * POOL_ALIGN,
        previous_size: previous_size as u64 * POOL_ALIGN,
        pool_type,
        tag,
        synthetic_free: false,
    })
}

pub fn pool_header_plausible(layout: &PoolLayout, h: &PoolHeader) -> bool {
    let Some(end) = h
        .header
        .0
        .checked_add(h.size)
        .and_then(|value| value.checked_sub(1))
    else {
        return false;
    };
    h.size >= layout.header_size
        && h.size <= POOL_PAGE_SIZE
        && (h.header.0 & !(POOL_PAGE_SIZE - 1)) == (end & !(POOL_PAGE_SIZE - 1))
        && (plausible_pool_tag(h.tag) || (h.pool_type == 0 && h.previous_size == 0))
}

pub fn try_pool_header_lax(
    debugger: &Target,
    layout: &PoolLayout,
    addr: VirtAddr,
) -> Option<PoolHeader> {
    let h = parse_pool_header(debugger, layout, addr)?;
    pool_header_plausible(layout, &h).then_some(h)
}

pub fn gap_free_pool_block(
    debugger: &Target,
    layout: &PoolLayout,
    header: VirtAddr,
    size: u64,
) -> PoolHeader {
    let tag: u32 = debugger
        .current_process()
        .ok()
        .and_then(|p| p.memory().read(header + layout.pool_tag_offset).ok())
        .unwrap_or(0);
    PoolHeader {
        header,
        body: header + layout.header_size,
        size,
        previous_size: 0,
        pool_type: 0,
        tag,
        synthetic_free: true,
    }
}

pub fn walk_pool_page_lax(
    debugger: &Target,
    layout: &PoolLayout,
    base: VirtAddr,
) -> Vec<PoolHeader> {
    let Some(page_end) = base.0.checked_add(POOL_PAGE_SIZE) else {
        return Vec::new();
    };
    let mut blocks = Vec::new();
    let mut addr = base;
    while addr.0 < page_end && !INTERRUPT_REQUESTED.load(Ordering::Relaxed) {
        if let Some(h) = try_pool_header_lax(debugger, layout, addr).filter(|h| {
            h.header
                .0
                .checked_add(h.size)
                .is_some_and(|end| end <= page_end)
        }) {
            let Some(next) = addr.0.checked_add(h.size) else {
                break;
            };
            addr = VirtAddr(next);
            blocks.push(h);
        } else {
            let mut advanced = false;
            for step in 1..=POOL_MAX_GAP_UNITS {
                if INTERRUPT_REQUESTED.load(Ordering::Relaxed) {
                    break;
                }
                let Some(probe) = addr
                    .0
                    .checked_add(step.saturating_mul(POOL_ALIGN))
                    .map(VirtAddr)
                else {
                    break;
                };
                if probe.0 >= page_end {
                    break;
                }
                if let Some(h2) = try_pool_header_lax(debugger, layout, probe).filter(|h| {
                    h.header
                        .0
                        .checked_add(h.size)
                        .is_some_and(|end| end <= page_end)
                }) {
                    addr = h2.header;
                    advanced = true;
                    break;
                }
            }
            if !advanced {
                break;
            }
        }
    }
    blocks
}

pub fn scan_pool_page_lax(
    debugger: &Target,
    layout: &PoolLayout,
    base: VirtAddr,
) -> Vec<PoolHeader> {
    let Some(page_end) = base.0.checked_add(POOL_PAGE_SIZE) else {
        return Vec::new();
    };
    let mut candidates = Vec::new();
    let mut off = 0;
    while off < POOL_PAGE_SIZE && !INTERRUPT_REQUESTED.load(Ordering::Relaxed) {
        let Some(addr) = base.0.checked_add(off).map(VirtAddr) else {
            break;
        };
        if let Some(h) = try_pool_header_lax(debugger, layout, addr).filter(|h| {
            h.header
                .0
                .checked_add(h.size)
                .is_some_and(|end| end <= page_end)
        }) {
            candidates.push(h);
        }
        off += POOL_ALIGN;
    }
    let mut blocks = Vec::new();
    let mut cursor = base;
    for (i, h) in candidates.iter().copied().enumerate() {
        if h.header < cursor {
            continue;
        }
        if h.header == cursor
            && h.size == POOL_ALIGN
            // A minimal block with no pool type is a free-list stub, not a
            // real allocation (PoolType 0 is otherwise ordinary NonPagedPool).
            && !h.synthetic_free
            && h.tag != POOL_FREE_TAG
            && h.pool_type == 0
            && let Some(next) = candidates.get(i + 1)
            && next.header.0 > h.header.0.saturating_add(POOL_ALIGN)
        {
            let free_size = next
                .header
                .0
                .saturating_sub(h.header.0.saturating_add(POOL_ALIGN));
            blocks.push(gap_free_pool_block(debugger, layout, h.header, free_size));
            cursor = VirtAddr(h.header.0.saturating_add(free_size));
        } else {
            if h.header > cursor {
                let free_size = h
                    .header
                    .0
                    .saturating_sub(cursor.0.saturating_add(POOL_ALIGN));
                if free_size >= POOL_ALIGN * 2 {
                    blocks.push(gap_free_pool_block(debugger, layout, cursor, free_size));
                }
            }
            blocks.push(h);
            cursor = VirtAddr(h.header.0.saturating_add(h.size));
        }
    }
    blocks
}

pub fn find_pool_block_index(blocks: &[PoolHeader], needle: &PoolHeader) -> Option<usize> {
    blocks
        .iter()
        .position(|h| h.header == needle.header && h.size == needle.size)
}

pub fn locate_pool_block_in_page(
    debugger: &Target,
    layout: &PoolLayout,
    target: VirtAddr,
) -> (Vec<PoolHeader>, Option<usize>, VirtAddr) {
    let base = VirtAddr(target.0 & !(POOL_PAGE_SIZE - 1));
    let aligned = VirtAddr(target.0 & !(POOL_ALIGN - 1));
    let mut anchor = None;
    let mut addr = aligned;
    loop {
        if let Some(h) = try_pool_header_lax(debugger, layout, addr)
            .filter(|h| target >= h.header && target.0 < h.header.0 + h.size)
        {
            anchor = Some(h);
            break;
        }
        if addr <= base {
            break;
        }
        addr -= POOL_ALIGN;
    }
    let Some(anchor) = anchor else {
        return (Vec::new(), None, base);
    };
    let blocks = walk_pool_page_lax(debugger, layout, base);
    if let Some(idx) = find_pool_block_index(&blocks, &anchor) {
        return (blocks, Some(idx), base);
    }
    let blocks = scan_pool_page_lax(debugger, layout, base);
    if let Some(idx) = find_pool_block_index(&blocks, &anchor) {
        return (blocks, Some(idx), base);
    }
    (vec![anchor], Some(0), base)
}

pub fn classify_pool_region(
    debugger: &Target,
    addr: VirtAddr,
) -> Option<(&'static str, VirtAddr, VirtAddr)> {
    let dtb = debugger.current_dtb();
    let mem = debugger.current_process().ok()?.memory();
    let bound = |symbol: &str| {
        let address = debugger
            .symbols
            .find_symbol_across_modules(dtb, &format!("nt!{symbol}"))
            .ok()
            .flatten()?;
        mem.read::<u64>(address).ok().map(VirtAddr)
    };
    for (name, start, stop) in [
        ("NonPagedPool", "MmNonPagedPoolStart", "MmNonPagedPoolEnd"),
        ("PagedPool", "MmPagedPoolStart", "MmPagedPoolEnd"),
        ("SpecialPool", "MmSpecialPoolStart", "MmSpecialPoolEnd"),
    ] {
        // A range whose symbols this build lacks says nothing about the
        // others; keep looking.
        let (Some(s), Some(e)) = (bound(start), bound(stop)) else {
            continue;
        };
        if (s..e).contains(&addr) {
            return Some((name, s, e));
        }
    }
    None
}

fn parse_big_pool_entry(
    big_pool_type: &TypeInfo,
    big_pool_uses_struct: bool,
    big_pool_has_pool_type: bool,
    big_pool_has_slush: bool,
    entry: VirtAddr,
    buf: &[u8],
) -> Option<BigPoolEntry> {
    let (va_raw, size, tag, pattern, pool_flags, slush_size) = if big_pool_uses_struct {
        let va_raw = pool_field_from_buf(big_pool_type, buf, "Va")?;
        let size = pool_field_from_buf(big_pool_type, buf, "NumberOfBytes")?;
        let tag = pool_field_from_buf(big_pool_type, buf, "Key")? as u32;
        let pattern = pool_field_from_buf(big_pool_type, buf, "Pattern")? as u8;
        let pool_flags = if big_pool_has_pool_type {
            pool_field_from_buf(big_pool_type, buf, "PoolType")
                .or_else(|| pool_field_from_buf(big_pool_type, buf, "PoolFlags"))
                .unwrap_or(0) as u16
                & BIG_POOL_FLAG_MASK
        } else {
            pool_raw_from_buf(big_pool_type, buf, "Pattern")
                .unwrap_or(0)
                .wrapping_shr(8) as u16
                & BIG_POOL_FLAG_MASK
        };
        let slush_size = if big_pool_has_slush {
            pool_field_from_buf(big_pool_type, buf, "SlushSize").unwrap_or(0) as u16
                & BIG_POOL_FLAG_MASK
        } else {
            0
        };
        (va_raw, size, tag, pattern, pool_flags, slush_size)
    } else {
        let va_raw = pool_field_from_buf(big_pool_type, buf, "Va")?;
        let size = pool_field_from_buf(big_pool_type, buf, "NumberOfBytes")?;
        let tag = pool_field_from_buf(big_pool_type, buf, "Key")? as u32;
        let flags_word = pool_raw_from_buf(big_pool_type, buf, "Pattern")?;
        (
            va_raw,
            size,
            tag,
            (flags_word & 0xff) as u8,
            ((flags_word >> 8) as u16) & BIG_POOL_FLAG_MASK,
            ((flags_word >> 20) as u16) & BIG_POOL_FLAG_MASK,
        )
    };
    let va = VirtAddr(va_raw & !1);
    if va.is_zero() || size == 0 || !plausible_pool_tag(tag) {
        return None;
    }
    Some(BigPoolEntry {
        va,
        entry,
        index: 0,
        freed: va_raw & 1 != 0,
        nonpaged: pool_flags & 1 == 0,
        size,
        tag,
        pattern,
        pool_flags,
        slush_size,
    })
}

pub fn find_big_pool(
    debugger: &Target,
    layout: &PoolLayout,
    target: VirtAddr,
) -> Option<BigPoolEntry> {
    let big_pool_type = layout.big_pool_type.as_deref()?;
    let mut found = None;
    let _ = walk_big_pool_entries(
        debugger,
        big_pool_type,
        layout.big_pool_uses_struct,
        layout.big_pool_has_pool_type,
        layout.big_pool_has_slush,
        |entry| {
            if target >= entry.va
                && target
                    .0
                    .checked_sub(entry.va.0)
                    .is_some_and(|offset| offset < entry.size)
            {
                found = Some(*entry);
                true
            } else {
                false
            }
        },
    );
    found
}

pub fn segment_heap_hint(debugger: &Target) -> Option<&'static str> {
    debugger
        .symbols
        .find_symbol_across_modules(debugger.current_dtb(), "nt!RtlpHpHeapGlobals")
        .ok()
        .flatten()?;
    Some(
        "kernel has RtlpHpHeapGlobals (segment heap is enabled); address may be a _HEAP_VS_CHUNK_HEADER / LFH chunk instead of a _POOL_HEADER",
    )
}

pub fn annotate_near_symbol(debugger: &Target, addr: VirtAddr) -> Option<String> {
    let (module, name, offset) = debugger
        .symbols
        .find_closest_symbol_for_address(debugger.current_dtb(), addr)?;
    (offset <= 0x1000).then(|| format_symbol_with_offset(&module, &name, offset))
}

pub fn print_pool_page_listing(blocks: &[PoolHeader], target_idx: Option<usize>, target: VirtAddr) {
    if blocks.is_empty() {
        outln!("  (no plausible pool block found for this address)");
        return;
    }
    outln!(
        "    {:<16} {:<8} {:<8} {:<12} {:<6} tag",
        "header",
        "size",
        "prev",
        "state",
        "type"
    );
    for (i, h) in blocks.iter().enumerate() {
        let marker = if Some(i) == target_idx {
            ">".yellow().to_string()
        } else {
            " ".to_string()
        };
        outln!(
            "  {} {} 0x{:<6x} 0x{:<6x} {:<12} 0x{:<4x} '{}'",
            marker,
            ui::addr(h.header.0),
            h.size,
            h.previous_size,
            pool_block_state(h),
            h.pool_type,
            tag_string(h.tag)
        );
    }
    if let Some(idx) = target_idx {
        let h = &blocks[idx];
        let offset = target.0.saturating_sub(h.body.0);
        outln!(
            "  target offset : 0x{:x} into body (block @ {}, body @ {})",
            offset,
            ui::addr(h.header.0),
            ui::addr(h.body.0)
        );
    }
}

pub fn print_big_pool(target: VirtAddr, entry: &BigPoolEntry) {
    let offset = target.0 - entry.va.0;
    let end_addr = entry.va + entry.size;
    outln!("big pool @ {}", ui::addr(entry.va.0));
    outln!("  target        : {}", ui::addr(target.0));
    outln!(
        "  range         : {} - {} ({} bytes)",
        ui::addr(entry.va.0),
        ui::addr(end_addr.0),
        entry.size
    );
    outln!("  offset        : 0x{:x} / 0x{:x}", offset, entry.size);
    outln!(
        "  tag           : '{}' (0x{:08x})",
        tag_string(entry.tag),
        entry.tag
    );
    outln!(
        "  table entry   : {}[{}]",
        ui::addr(entry.entry.0),
        entry.index
    );
    outln!(
        "  nonpaged      : {}",
        if entry.nonpaged { "yes" } else { "no" }
    );
    outln!("  pattern       : 0x{:x}", entry.pattern);
    outln!("  pool flags    : 0x{:x}", entry.pool_flags);
    outln!("  slush size    : 0x{:x}", entry.slush_size);
}
