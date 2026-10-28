use std::collections::{BTreeMap, HashSet};
use std::ops::ControlFlow;
use std::sync::Arc;

use ntoseye_macros::record;

use crate::base::error::{Error, Result};
use crate::base::memory::{MemoryOps, PAGE_SIZE};
use crate::base::types::{MAX_PROCESSORS, PAGE_SHIFT, VirtAddr};
use crate::nt::layout::{FieldInfo, ParsedType, TypeInfo, le_uint};
use crate::nt::symbols::format_symbol_with_offset;
use crate::nt::target::Target;
use crate::nt::target::heap::{
    LfhSubsegment, RANGE_ALLOCATED, RANGE_FIRST, RANGE_SUBSEGMENT, RANGE_VS, lfh_geometry,
};
use crate::nt::target::mm::{PoolBlockState, PoolType, find_mi_state_fields};

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
    /// On a page of a segment-heap LFH subsegment, whether the subsegment's
    /// bitmap has the block busy. A freed LFH block keeps its header, so
    /// only the bitmap tells it from an allocated one. `None` elsewhere.
    pub lfh_busy: Option<bool>,
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
    pub(crate) header_size: u64,
    pub(crate) pool_tag_offset: u64,
    pool_header_uses_struct: bool,
    pub(crate) big_pool_type: Option<Arc<TypeInfo>>,
    pub(crate) big_pool_uses_struct: bool,
    pub(crate) big_pool_has_pool_type: bool,
    pub(crate) big_pool_has_slush: bool,
    /// How a segment-heap kernel encodes its VS chunk headers; `None` on a
    /// kernel without the segment heap, or whose PDB lacks its types.
    vs_chunks: Option<VsChunkHeaders>,
    /// What finds the LFH subsegment holding a page; `None` on a kernel
    /// without the segment heap, or whose PDB lacks its types.
    lfh: Option<LfhSubsegments>,
    /// How a block header's `PoolType` names its pool (see
    /// [`header_pool_type`]); `None` when the PDB has no `_POOL_TYPE`.
    pub header_pool: Option<HeaderPoolEncoding>,
}

/// How a build's block headers encode the pool in `PoolType`: the
/// allocation's `POOL_TYPE`, of which `paged_pool` (`PagedPool`'s value in
/// the PDB's `_POOL_TYPE`) is the bit that says paged, with a bit set while
/// the block is allocated. Vista on keep the type itself (nonpaged blocks
/// read 2, paged 3); Windows Server 2003 keeps the type plus one (5 and 6).
/// The PDBs lay out `_POOL_HEADER` and `_POOL_TYPE` alike, and differ in
/// the big-page table: from Vista each entry records its pool type too.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderPoolEncoding {
    pub paged_pool: u8,
    /// Whether the header holds the `POOL_TYPE` plus one.
    pub plus_one: bool,
}

/// What decodes the `_HEAP_VS_CHUNK_HEADER` that precedes each block the
/// segment heap's variable-size allocator hands out. Its `Sizes` are stored
/// XORed with `nt!RtlpHpHeapGlobals.HeapKey` and the header's own address,
/// so to a scan its bytes are random, and can read as a `_POOL_HEADER` whose
/// block covers the real one behind it. Decoded, it says where the real
/// block is.
struct VsChunkHeaders {
    /// `_HEAP_VS_CHUNK_HEADER_SIZE`, the layout of the decoded `Sizes`.
    sizes: Arc<TypeInfo>,
    /// Where `Sizes` sits in the chunk header.
    sizes_offset: u64,
    /// The size of the chunk header, which is also the unit of the chunk's
    /// size.
    header_size: u64,
    heap_key: u64,
}

impl VsChunkHeaders {
    /// Whether the chunk header at `chunk`, whose bytes begin `bytes`, is an
    /// allocated chunk's that holds exactly the pool block `block` after it.
    fn holds(&self, chunk: VirtAddr, bytes: &[u8], block: &PoolHeader) -> bool {
        let at = self.sizes_offset as usize;
        let Some(encoded) = bytes
            .get(at..at + self.sizes.size)
            .filter(|encoded| encoded.len() <= 8)
        else {
            return false;
        };
        let decoded = (le_uint(encoded) ^ self.heap_key ^ chunk.0).to_le_bytes();
        let field = |name| pool_field_from_buf(&self.sizes, &decoded[..encoded.len()], name);
        field("Allocated").is_some_and(|allocated| allocated != 0)
            && field("UnsafeSize").is_some_and(|units| {
                units.checked_mul(self.header_size) == block.size.checked_add(self.header_size)
            })
    }
}

/// The segment heap's VS chunk header encoding, from the kernel's PDB and
/// `nt!RtlpHpHeapGlobals`.
fn vs_chunk_headers(debugger: &Target) -> Option<VsChunkHeaders> {
    let find = |name| {
        debugger
            .symbols
            .find_type_across_modules(debugger.kernel_dtb(), name)
    };
    let globals = find("_RTLP_HP_HEAP_GLOBALS")?;
    let chunk = find("_HEAP_VS_CHUNK_HEADER")?;
    let sizes = find("_HEAP_VS_CHUNK_HEADER_SIZE")?;
    let key = globals.field("HeapKey").ok()?;
    let mut bytes = [0u8; 8];
    let bytes = bytes.get_mut(..key.size as usize)?;
    debugger
        .kernel_address_space()
        .read_bytes(
            kernel_symbol_address(debugger, "RtlpHpHeapGlobals").ok()? + u64::from(key.offset),
            bytes,
        )
        .ok()?;
    Some(VsChunkHeaders {
        sizes_offset: chunk.field_offset("Sizes").ok()?,
        header_size: chunk.size as u64,
        heap_key: le_uint(bytes),
        sizes,
    })
}

/// A `_HEAP_SEG_CONTEXT`'s segment geometry: the segment holding a page
/// starts at the page's address under `mask`, and from its unit
/// `first_descriptor` on, a `_HEAP_PAGE_RANGE_DESCRIPTOR` of the segment's
/// `_HEAP_PAGE_SEGMENT` describes each unit of `1 << unit_shift` bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
struct SegmentGeometry {
    mask: u64,
    unit_shift: u32,
    first_descriptor: u64,
}

/// What finds the segment-heap LFH subsegment that holds a pool page and
/// decodes it: the segment geometries of the kernel's pool heaps, the
/// PDB's layouts, and `nt!RtlpHpHeapGlobals.LfhKey`.
struct LfhSubsegments {
    segments: Vec<SegmentGeometry>,
    /// `_HEAP_PAGE_RANGE_DESCRIPTOR`, where `_HEAP_PAGE_SEGMENT.DescArray`
    /// begins, and how many descriptors it holds.
    descriptor: Arc<TypeInfo>,
    descriptors_offset: u64,
    descriptor_count: u64,
    /// `_HEAP_LFH_SUBSEGMENT` and its `_HEAP_LFH_SUBSEGMENT_ENCODED_OFFSETS`.
    subsegment: Arc<TypeInfo>,
    offsets: Arc<TypeInfo>,
    lfh_key: u64,
}

impl LfhSubsegments {
    /// The page range `[start, end)` holding `page` in `segment`, laid out
    /// by `geometry` and described by `descriptors`, when the range is an
    /// LFH subsegment's.
    fn lfh_range(
        &self,
        geometry: &SegmentGeometry,
        segment: u64,
        descriptors: &[u8],
        page: u64,
    ) -> Option<(u64, u64)> {
        let field = |unit: u64, name| {
            let at = usize::try_from(unit.checked_mul(self.descriptor.size as u64)?).ok()?;
            pool_field_from_buf(&self.descriptor, descriptors.get(at..)?, name)
        };
        let shift = geometry.unit_shift;
        let unit = (page - segment).checked_shr(shift)?;
        if unit < geometry.first_descriptor || unit >= self.descriptor_count {
            return None;
        }
        // Only a range's first descriptor carries its flags and size; the
        // others count back to it.
        let head = if field(unit, "RangeFlags")? as u8 & RANGE_FIRST != 0 {
            unit
        } else {
            unit.checked_sub(field(unit, "UnitOffset")?)?
        };
        let lfh = RANGE_ALLOCATED | RANGE_FIRST | RANGE_SUBSEGMENT;
        if head < geometry.first_descriptor
            || field(head, "RangeFlags")? as u8 & (lfh | RANGE_VS) != lfh
        {
            return None;
        }
        let start = segment.checked_add(head.checked_shl(shift)?)?;
        let end = start.checked_add(field(head, "UnitSize")?.checked_shl(shift)?)?;
        (page < end).then_some((start, end))
    }

    /// The LFH subsegment at `start`, whose page range ends at `end`, when
    /// its header decodes to blocks that fit the range.
    fn decode(
        &self,
        debugger: &Target,
        layout: &PoolLayout,
        start: VirtAddr,
        end: u64,
    ) -> Option<PoolLfhSubsegment> {
        let memory = debugger.kernel_address_space();
        let mut image = vec![0u8; self.subsegment.size];
        memory.read_bytes(start, &mut image).ok()?;
        let geometry = lfh_geometry(
            &self.subsegment,
            &self.offsets,
            &image,
            self.lfh_key,
            start,
            end - start.0,
            POOL_ALIGN,
        )?;
        let field = |name| pool_field_from_buf(&self.subsegment, &image, name);
        let free_count = field("FreeCount")?;
        if geometry.block_size < layout.header_size
            || free_count > geometry.blocks - geometry.withheld
        {
            return None;
        }
        let mut bitmap = vec![0u8; usize::try_from(geometry.words * geometry.word_size).ok()?];
        memory
            .read_bytes(start + geometry.bitmap_offset, &mut bitmap)
            .ok()?;
        let subsegment = PoolLfhSubsegment {
            blocks: LfhSubsegment {
                address: start,
                block_size: geometry.block_size,
                block_count: u32::try_from(geometry.blocks).ok()?,
                free_count: u32::try_from(free_count).ok()?,
                bucket: field("BucketRef").map(|bucket| bucket as u16),
                first_block: start + geometry.first_offset,
                bitmap: bitmap
                    .chunks_exact(geometry.word_size as usize)
                    .map(le_uint)
                    .collect(),
                blocks_per_word: u32::try_from(geometry.blocks_per_word).ok()?,
                bit_stride: u32::try_from(geometry.bit_stride).ok()?,
            },
            withholds: geometry.withheld != 0,
        };
        // Those it withholds must be the blocks across a page boundary, or
        // it does not lay its blocks out as read.
        let crossing = (0..subsegment.blocks.block_count)
            .filter(|&index| subsegment.withheld(index))
            .count();
        (crossing as u64 == geometry.withheld).then_some(subsegment)
    }
}

/// An LFH subsegment of the pool, its `blocks` counting every block. One
/// that withholds blocks (`WitheldBlockCount`) withholds those across a
/// page boundary: its bitmap keeps them busy, but they are never handed
/// out and hold no header, only what the page held before.
pub struct PoolLfhSubsegment {
    pub blocks: LfhSubsegment,
    pub withholds: bool,
}

impl PoolLfhSubsegment {
    /// Whether the subsegment withholds block `index`.
    pub fn withheld(&self, index: u32) -> bool {
        let start = self.blocks.block(index).0;
        let last = start + self.blocks.block_size - 1;
        self.withholds && start >> PAGE_SHIFT != last >> PAGE_SHIFT
    }
}

/// The element count of an array field.
fn array_count(field: &FieldInfo) -> Option<u64> {
    match field.type_data {
        ParsedType::Array(_, count) => Some(u64::from(count)),
        _ => None,
    }
}

/// The LFH subsegment decoding of a segment-heap kernel, from its PDB and
/// its pool heaps, `nt!ExPoolState`'s, whose segment contexts give the
/// geometries. The pool heaps of every node are configured alike, so the
/// first node's serve.
fn lfh_subsegments(debugger: &Target) -> Option<LfhSubsegments> {
    let find = |name| {
        debugger
            .symbols
            .find_type_across_modules(debugger.kernel_dtb(), name)
    };
    let memory = debugger.kernel_address_space();
    let read = |address: VirtAddr, size: u64| {
        let mut bytes = vec![0u8; usize::try_from(size).ok()?];
        memory.read_bytes(address, &mut bytes).ok()?;
        Some(bytes)
    };
    let globals = find("_RTLP_HP_HEAP_GLOBALS")?;
    let globals_image = read(
        kernel_symbol_address(debugger, "RtlpHpHeapGlobals").ok()?,
        globals.size as u64,
    )?;
    let state = find("_EX_POOL_HEAP_MANAGER_STATE")?;
    let node = find("_EX_HEAP_POOL_NODE")?;
    let heap = find("_SEGMENT_HEAP")?;
    let context = find("_HEAP_SEG_CONTEXT")?;
    let heaps = node.field("Heaps").ok()?;
    let pointer = usize::from(node.pointer_size);
    let heaps = read(
        kernel_symbol_address(debugger, "ExPoolState").ok()?
            + state.field_offset("PoolNode").ok()?
            + u64::from(heaps.offset),
        array_count(heaps)? * pointer as u64,
    )?;
    let contexts = heap.field("SegContexts").ok()?;
    let contexts_size = array_count(contexts)? * context.size as u64;
    let mut segments = Vec::new();
    for address in heaps
        .chunks_exact(pointer)
        .map(le_uint)
        .filter(|&address| address != 0)
    {
        let Some(image) = read(
            VirtAddr(address) + u64::from(contexts.offset),
            contexts_size,
        ) else {
            continue;
        };
        for bytes in image.chunks_exact(context.size) {
            let field = |name| pool_field_from_buf(&context, bytes, name);
            let geometry = SegmentGeometry {
                mask: field("SegmentMask")?,
                unit_shift: u32::try_from(field("UnitShift")?).ok()?,
                first_descriptor: field("FirstDescriptorIndex")?,
            };
            if !segments.contains(&geometry) {
                segments.push(geometry);
            }
        }
    }
    if segments.is_empty() {
        return None;
    }
    let page_segment = find("_HEAP_PAGE_SEGMENT")?;
    let descriptors = page_segment.field("DescArray").ok()?;
    Some(LfhSubsegments {
        segments,
        descriptor: find("_HEAP_PAGE_RANGE_DESCRIPTOR")?,
        descriptors_offset: u64::from(descriptors.offset),
        descriptor_count: array_count(descriptors)?,
        offsets: find("_HEAP_LFH_SUBSEGMENT_ENCODED_OFFSETS")?,
        subsegment: find("_HEAP_LFH_SUBSEGMENT")?,
        lfh_key: pool_field_from_buf(&globals, &globals_image, "LfhKey")?,
    })
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
    let plus_one = big_pool_type.is_some() && !big_pool_has_pool_type;
    Ok(PoolLayout {
        header_size: pool_header.size as u64,
        pool_header,
        pool_tag_offset,
        pool_header_uses_struct,
        big_pool_type,
        big_pool_uses_struct,
        big_pool_has_pool_type,
        big_pool_has_slush,
        vs_chunks: vs_chunk_headers(debugger),
        lfh: lfh_subsegments(debugger),
        header_pool: debugger
            .symbols
            .find_enum_across_modules(debugger.kernel_dtb(), "_POOL_TYPE")
            .and_then(|values| values.into_iter().find(|(name, _)| name == "PagedPool"))
            .and_then(|(_, value)| u8::try_from(value).ok())
            .map(|paged_pool| HeaderPoolEncoding {
                paged_pool,
                plus_one,
            }),
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

/// The pool usage of one tag (`!poolused`), summed over the processors'
/// tracker tables and the big-pool table. A value is `None` if no source
/// has an entry for that pool.
#[record(impl)]
#[derive(Clone, Debug)]
pub struct PoolUsageRow {
    #[record(hex)]
    pub tag: u32,
    pub nonpaged_allocs: Option<i64>,
    pub nonpaged_frees: Option<i64>,
    /// In bytes.
    pub nonpaged_bytes: Option<i64>,
    pub paged_allocs: Option<i64>,
    pub paged_frees: Option<i64>,
    /// In bytes.
    pub paged_bytes: Option<i64>,
}

#[record]
impl PoolUsageRow {
    /// The tag as its four characters.
    #[record(getter)]
    pub fn tag_name(&self) -> String {
        tag_string(self.tag)
    }
}

impl PoolUsageRow {
    /// Whether an allocation with the tag is outstanding in either pool:
    /// more allocations than frees, or bytes in use where no counts are
    /// kept.
    pub fn in_use(&self) -> bool {
        let outstanding =
            |allocs: Option<i64>, frees: Option<i64>, bytes: Option<i64>| match (allocs, frees) {
                (Some(allocs), Some(frees)) => allocs != frees,
                _ => bytes.unwrap_or(0) != 0,
            };
        outstanding(
            self.nonpaged_allocs,
            self.nonpaged_frees,
            self.nonpaged_bytes,
        ) || outstanding(self.paged_allocs, self.paged_frees, self.paged_bytes)
    }

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

pub fn read_kernel_global_u32(debugger: &Target, name: &str) -> Result<u32> {
    let address = kernel_symbol_address(debugger, name)?;
    debugger.kernel_address_space().read(address)
}

pub(crate) fn read_kernel_global_ptr(debugger: &Target, name: &str) -> Result<VirtAddr> {
    let address = kernel_symbol_address(debugger, name)?;
    debugger.kernel_address_space().read_pointer(address)
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
        if debugger.interrupted() {
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
            if debugger.interrupted() {
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
/// entry. Returning true from `visit` stops the walk immediately; so does the
/// host's interrupt flag.
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
    if debugger.interrupted() {
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
    debugger: &Target,
    rows: &mut BTreeMap<u32, PoolUsageRow>,
    rows_truncated: &mut bool,
    ti: &TypeInfo,
    table_bytes: &[u8],
    entry_size: usize,
) -> u64 {
    let mut scanned = 0u64;
    for entry in table_bytes.chunks_exact(entry_size) {
        if debugger.interrupted() {
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
    let pointer_size = memory.arch().pointer_size();
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
        crate::nt::cpu_state::processor_count(debugger),
    ) && processors > 0
    {
        source = "ExPoolTagTables";
        for index in 0..u64::from(processors).min(u64::from(MAX_PROCESSORS)) {
            let Some(pointer_address) = array
                .0
                .checked_add(index.saturating_mul(pointer_size))
                .map(VirtAddr)
            else {
                break;
            };
            let Ok(table) = memory.read_pointer(pointer_address) else {
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
        if debugger.interrupted() {
            break;
        }
        match read_pool_table(&memory, *table, scan_count, entry_size) {
            Ok((table_bytes, unreadable)) => {
                unreadable_pages = unreadable_pages.saturating_add(unreadable);
                scanned = scanned.saturating_add(aggregate_tracker_table(
                    debugger,
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
    if debugger.interrupted() {
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

/// Aggregate the per-processor tracker tables without retaining every
/// entry. The tracker counts every allocation, big ones too, as WinDbg's
/// `!poolused` reads it alone: the big-page table stands in only when the
/// tracker cannot be read, and then gives the big allocations alone.
pub fn collect_pool_usage(debugger: &Target) -> PoolUsageSummary {
    let mut rows = BTreeMap::<u32, PoolUsageRow>::new();
    let mut rows_truncated = false;
    let tracker = collect_tracker_usage(debugger, &mut rows, &mut rows_truncated);
    let big = match &tracker {
        Ok(_) => BigPoolScanSummary {
            status: "counted by the tracker".to_string(),
        },
        Err(_) => collect_big_pool_usage(debugger, &mut rows, &mut rows_truncated),
    };
    PoolUsageSummary {
        rows: rows.into_values().collect(),
        rows_truncated,
        tracker_status: tracker.unwrap_or_else(|error| error),
        big,
    }
}

/// The big-page table's allocations, by tag, into `rows`.
fn collect_big_pool_usage(
    debugger: &Target,
    rows: &mut BTreeMap<u32, PoolUsageRow>,
    rows_truncated: &mut bool,
) -> BigPoolScanSummary {
    match pool_layout(debugger) {
        Ok(layout) => scan_big_pool_entries(
            debugger,
            layout.big_pool_type.as_deref(),
            layout.big_pool_uses_struct,
            layout.big_pool_has_pool_type,
            layout.big_pool_has_slush,
            |entry| {
                aggregate_big_pool_entry(rows, rows_truncated, entry);
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
                    aggregate_big_pool_entry(rows, rows_truncated, entry);
                    false
                },
            ),
            Err(big_error) => BigPoolScanSummary {
                status: format!(
                    "pool layout unavailable: {layout_error}; big-page layout: {big_error}"
                ),
            },
        },
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
    Some(f.decode(le_uint(&buf[..size])))
}

/// `read_pool_field` against an already-read entry buffer
pub fn pool_field_from_buf(ti: &TypeInfo, buf: &[u8], field: &str) -> Option<u64> {
    let (f, raw) = pool_storage_from_buf(ti, buf, field)?;
    Some(f.decode(raw))
}

fn pool_raw_from_buf(ti: &TypeInfo, buf: &[u8], field: &str) -> Option<u64> {
    pool_storage_from_buf(ti, buf, field).map(|(_, raw)| raw)
}

/// A field and the integer its storage holds in `buf`, up to 8 bytes.
fn pool_storage_from_buf<'a>(
    ti: &'a TypeInfo,
    buf: &[u8],
    field: &str,
) -> Option<(&'a FieldInfo, u64)> {
    let f = ti.fields.get(field)?;
    let offset = f.offset as usize;
    let size = usize::try_from(f.size).ok()?.clamp(1, 8);
    Some((f, le_uint(buf.get(offset..offset.checked_add(size)?)?)))
}

/// The bit Windows 7 sets in the tag of a protected allocation (an object's,
/// for one): `PROTECTED_POOL`. The tag's characters are the rest.
pub const PROTECTED_POOL: u32 = 0x8000_0000;

/// A tag's four characters, `.` for one that does not print; the
/// protected bit is not part of the last.
pub fn tag_string(tag: u32) -> String {
    let tag = tag & !PROTECTED_POOL;
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
    let tag = tag & !PROTECTED_POOL;
    (0..4).all(|i| (0x20..=0x7e).contains(&((tag >> (i * 8)) & 0xff)))
}

pub fn plausible_pool_tag(tag: u32) -> bool {
    tag == POOL_FREE_TAG || tag_looks_printable(tag)
}

/// A block's state: an LFH block's as its subsegment's bitmap has it; any
/// other's from its header, free where the scan found none or the tag says
/// `Free` or where `encoding` holds the pool type plus one and the header's
/// is 0 (which names no pool, so the block was freed), and allocated where
/// the tag reads (unverified where it does not).
pub fn pool_block_state(h: &PoolHeader, encoding: Option<HeaderPoolEncoding>) -> PoolBlockState {
    match h.lfh_busy {
        Some(true) => PoolBlockState::Allocated,
        Some(false) => PoolBlockState::Free,
        None if h.synthetic_free || h.tag == POOL_FREE_TAG => PoolBlockState::Free,
        None if h.pool_type == 0 && encoding.is_some_and(|encoding| encoding.plus_one) => {
            PoolBlockState::Free
        }
        None if tag_looks_printable(h.tag) => PoolBlockState::Allocated,
        None => PoolBlockState::AllocatedUnverified,
    }
}

/// The pool a block header's `PoolType` names, as `encoding` says the
/// build encodes it. A classic pool clears a free block's to 0, which names
/// neither.
pub fn header_pool_type(pool_type: u8, encoding: HeaderPoolEncoding) -> Option<PoolType> {
    let allocation_type = match pool_type {
        0 => return None,
        _ if encoding.plus_one => pool_type - 1,
        _ => pool_type,
    };
    Some(if allocation_type & encoding.paged_pool != 0 {
        PoolType::Paged
    } else {
        PoolType::NonPaged
    })
}

/// Largest `_POOL_HEADER` [`parse_pool_header`] reads (16 bytes on x64).
const MAX_POOL_HEADER_SIZE: usize = 0x20;

pub fn parse_pool_header(
    debugger: &Target,
    layout: &PoolLayout,
    header: VirtAddr,
) -> Option<PoolHeader> {
    let mut bytes = [0u8; MAX_POOL_HEADER_SIZE];
    let bytes = &mut bytes[..(layout.header_size as usize).min(MAX_POOL_HEADER_SIZE)];
    debugger
        .kernel_address_space()
        .read_bytes(header, bytes)
        .ok()?;
    pool_header_in(layout, header, bytes)
}

/// The `_POOL_HEADER` at `header`, from `bytes` read there.
fn pool_header_in(layout: &PoolLayout, header: VirtAddr, bytes: &[u8]) -> Option<PoolHeader> {
    let (previous_size, block_units, pool_type, tag) = pool_header_fields(layout, bytes)?;
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
        lfh_busy: None,
    })
}

/// `PreviousSize` and `BlockSize` (in pool units), `PoolType`, and
/// `PoolTag` of the `_POOL_HEADER` whose bytes begin `bytes`.
fn pool_header_fields(layout: &PoolLayout, bytes: &[u8]) -> Option<(u8, u8, u8, u32)> {
    Some(if layout.pool_header_uses_struct {
        let field = |name| pool_field_from_buf(&layout.pool_header, bytes, name);
        (
            field("PreviousSize")? as u8,
            field("BlockSize")? as u8,
            field("PoolType")? as u8,
            field("PoolTag")? as u32,
        )
    } else {
        let word0 = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?);
        (
            (word0 & 0xff) as u8,
            ((word0 >> 16) & 0xff) as u8,
            ((word0 >> 24) & 0xff) as u8,
            pool_tag_in(layout, bytes)?,
        )
    })
}

/// Block `index` of the LFH subsegment `subsegment`, its header read from
/// `bytes`, busy or free as the subsegment's bitmap has it; none for a
/// block the subsegment withholds. Its size is the subsegment's: a block
/// never allocated has no header to give one.
fn lfh_block(
    layout: &PoolLayout,
    subsegment: &PoolLfhSubsegment,
    index: u32,
    bytes: &[u8],
) -> Option<PoolHeader> {
    if subsegment.withheld(index) {
        return None;
    }
    let (previous_size, _, pool_type, tag) = pool_header_fields(layout, bytes)?;
    let header = subsegment.blocks.block(index);
    Some(PoolHeader {
        header,
        body: header + layout.header_size,
        size: subsegment.blocks.block_size,
        previous_size: u64::from(previous_size) * POOL_ALIGN,
        pool_type,
        tag,
        synthetic_free: false,
        lfh_busy: Some(subsegment.blocks.is_busy(index)),
    })
}

/// The blocks of the LFH subsegment `subsegment` whose headers lie in the
/// pool page at `base`, read from its bytes `page`. The subsegment's own
/// header and bitmap, before its first block, are no block.
fn lfh_page_blocks(
    layout: &PoolLayout,
    subsegment: &PoolLfhSubsegment,
    base: VirtAddr,
    page: &[u8],
) -> Vec<PoolHeader> {
    let blocks = &subsegment.blocks;
    let page_end = base.0 + page.len() as u64;
    let first = base
        .0
        .saturating_sub(blocks.first_block.0)
        .div_ceil(blocks.block_size) as u32;
    (first..blocks.block_count)
        .map(|index| (index, blocks.block(index)))
        .take_while(|(_, header)| header.0 < page_end)
        .filter_map(|(index, header)| {
            let bytes = page.get(usize::try_from(header.0 - base.0).ok()?..)?;
            lfh_block(layout, subsegment, index, bytes)
        })
        .collect()
}

/// The tag of the `_POOL_HEADER` whose bytes begin `bytes`.
fn pool_tag_in(layout: &PoolLayout, bytes: &[u8]) -> Option<u32> {
    let at = layout.pool_tag_offset as usize;
    Some(u32::from_le_bytes(
        bytes.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

pub fn pool_header_plausible(layout: &PoolLayout, h: &PoolHeader) -> bool {
    pool_header_fits(layout, h) && pool_header_tagged(h)
}

/// Whether `h`'s tag reads as one, or its header is a cleared free one.
fn pool_header_tagged(h: &PoolHeader) -> bool {
    plausible_pool_tag(h.tag) || (h.pool_type == 0 && h.previous_size == 0)
}

/// Whether `h` is the header of the block that follows `before`, by its
/// PreviousSize. A free fragment too small for a list entry keeps stale
/// bytes where its tag goes (Windows XP x64 splits them off an allocation's
/// tail), so this is what vouches for it.
fn pool_header_chained(before: &PoolHeader, h: &PoolHeader) -> bool {
    h.previous_size != 0
        && h.previous_size == before.size
        && before.header.0.checked_add(before.size) == Some(h.header.0)
}

/// Whether `h`'s block is at least a header long and ends on its page.
fn pool_header_fits(layout: &PoolLayout, h: &PoolHeader) -> bool {
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
}

pub fn try_pool_header_lax(
    debugger: &Target,
    layout: &PoolLayout,
    addr: VirtAddr,
) -> Option<PoolHeader> {
    let h = parse_pool_header(debugger, layout, addr)?;
    pool_header_plausible(layout, &h).then_some(h)
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
    while addr.0 < page_end && !debugger.interrupted() {
        if let Some(h) = parse_pool_header(debugger, layout, addr).filter(|h| {
            pool_header_fits(layout, h)
                && (pool_header_tagged(h)
                    || blocks
                        .last()
                        .is_some_and(|before| pool_header_chained(before, h)))
                && h.header
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
                if debugger.interrupted() {
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

/// The blocks of the pool page at `base`: every plausible header, overlaps
/// dropped, with the gaps between them as free blocks.
pub fn scan_pool_page_lax(
    debugger: &Target,
    layout: &PoolLayout,
    base: VirtAddr,
) -> Vec<PoolHeader> {
    let mut page = vec![0u8; PAGE_SIZE];
    if debugger
        .kernel_address_space()
        .read_bytes(base, &mut page)
        .is_err()
    {
        return Vec::new();
    }
    pool_page_blocks(layout, base, &page)
}

/// Every 16-byte-aligned slot of the pool page `page` (at `base`) that reads
/// as a plausible `_POOL_HEADER` whose block ends inside the page, in address
/// order. Overlapping candidates are all kept: data inside a block can look
/// like a header.
pub fn pool_header_candidates(layout: &PoolLayout, base: VirtAddr, page: &[u8]) -> Vec<PoolHeader> {
    let Some(page_end) = base.0.checked_add(page.len() as u64) else {
        return Vec::new();
    };
    let mut candidates: Vec<PoolHeader> = Vec::new();
    for h in (0..page.len() as u64)
        .step_by(POOL_ALIGN as usize)
        .filter_map(|offset| pool_header_in(layout, base + offset, &page[offset as usize..]))
        .filter(|h| {
            pool_header_fits(layout, h)
                && h.header
                    .0
                    .checked_add(h.size)
                    .is_some_and(|end| end <= page_end)
        })
    {
        if pool_header_tagged(&h)
            || candidates
                .iter()
                .any(|before| pool_header_chained(before, &h))
        {
            candidates.push(h);
        }
    }
    candidates
}

/// [`scan_pool_page_lax`] of the page at `base` already read into `page`.
pub fn pool_page_blocks(layout: &PoolLayout, base: VirtAddr, page: &[u8]) -> Vec<PoolHeader> {
    let tag_at = |header: VirtAddr| {
        page.get((header.0 - base.0) as usize..)
            .and_then(|bytes| pool_tag_in(layout, bytes))
            .unwrap_or(0)
    };
    let gap_free_block = |header: VirtAddr, size: u64| PoolHeader {
        header,
        body: header + layout.header_size,
        size,
        previous_size: 0,
        pool_type: 0,
        tag: tag_at(header),
        synthetic_free: true,
        lfh_busy: None,
    };
    let candidates = pool_header_candidates(layout, base, page);
    // On a segment-heap page, a block whose VS chunk header vouches for it
    // is real, and a candidate that runs into its chunk (the chunk header
    // itself, for one) is data that reads as a header.
    let chunks: Vec<(u64, VirtAddr, u64)> = layout
        .vs_chunks
        .as_ref()
        .map(|vs| {
            candidates
                .iter()
                .filter_map(|h| {
                    let chunk = h.header.0.checked_sub(vs.header_size)?;
                    let bytes = page.get(usize::try_from(chunk.checked_sub(base.0)?).ok()?..)?;
                    vs.holds(VirtAddr(chunk), bytes, h).then_some((
                        chunk,
                        h.header,
                        h.header.0 + h.size,
                    ))
                })
                .collect()
        })
        .unwrap_or_default();
    let candidates: Vec<PoolHeader> = candidates
        .into_iter()
        .filter(|h| {
            chunks.iter().all(|&(start, header, end)| {
                h.header == header || h.header.0 + h.size <= start || h.header.0 >= end
            })
        })
        .collect();
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
            blocks.push(gap_free_block(h.header, next.header.0 - h.header.0));
            cursor = next.header;
        } else {
            // A gap between two blocks is free. One narrower than three
            // units is a segment-heap chunk header and slack before the
            // next block. What precedes the first block is no block of the
            // page: a subsegment's header, or the tail of a block that
            // began on the page before.
            let gap = h.header.0 - cursor.0;
            if !blocks.is_empty() && gap >= POOL_ALIGN * 3 {
                blocks.push(gap_free_block(cursor, gap));
            }
            blocks.push(h);
            cursor = VirtAddr(h.header.0.saturating_add(h.size));
        }
    }
    blocks
}

/// Each 16-byte-aligned slot of the pool page `page` read as a
/// `_POOL_HEADER`: its offset and the tag it would carry. Segment-heap
/// blocks still begin with a header carrying the tag, so a tag match marks
/// a candidate where the block chain does not walk.
pub fn pool_header_tags<'p>(
    layout: &PoolLayout,
    page: &'p [u8],
) -> impl Iterator<Item = (u64, u32)> + 'p {
    let tag_offset = layout.pool_tag_offset as usize;
    (0..page.len())
        .step_by(POOL_ALIGN as usize)
        .filter_map(move |at| {
            let tag = page.get(at + tag_offset..at + tag_offset + 4)?;
            Some((at as u64, u32::from_le_bytes(tag.try_into().ok()?)))
        })
}

/// How far [`scan_present_pool_pages`] got.
pub struct PoolPageScan {
    /// Present pages read (or found unreadable).
    pub pages: u64,
    /// The present page the scan stopped at, unread, when the visitor or a
    /// host interrupt ended it early.
    pub stopped_at: Option<VirtAddr>,
}

/// Read each present page of `[start, end)` and hand `visit` its address
/// and bytes. The page tables are walked, so a region of terabytes mapped
/// sparsely costs only its mapped pages. After `visit` returns `Break`, or
/// once the host interrupts, the scan stops at the next present page.
pub fn scan_present_pool_pages(
    debugger: &Target,
    start: VirtAddr,
    end: VirtAddr,
    mut visit: impl FnMut(VirtAddr, &[u8]) -> ControlFlow<()>,
) -> Result<PoolPageScan> {
    let mut scan = PoolPageScan {
        pages: 0,
        stopped_at: None,
    };
    let mut stop = false;
    let mut page = vec![0u8; PAGE_SIZE];
    debugger
        .kernel_address_space()
        .for_each_present_page(start, end, |va, physical, length| {
            for offset in (0..length).step_by(PAGE_SIZE) {
                if stop || debugger.interrupted() {
                    scan.stopped_at = Some(va + offset);
                    return ControlFlow::Break(());
                }
                scan.pages += 1;
                if debugger
                    .phys
                    .read_bytes(physical + offset, &mut page)
                    .is_ok()
                {
                    stop = visit(va + offset, &page).is_break();
                }
            }
            ControlFlow::Continue(())
        })?;
    Ok(scan)
}

pub fn find_pool_block_index(blocks: &[PoolHeader], needle: &PoolHeader) -> Option<usize> {
    blocks
        .iter()
        .position(|h| h.header == needle.header && h.size == needle.size)
}

/// Reads the blocks of pool pages: on a page of a segment-heap LFH
/// subsegment, the subsegment's blocks, busy or free as its bitmap has
/// them; elsewhere, what a scan of the page's headers finds
/// ([`pool_page_blocks`]). It keeps the descriptors of the segment each
/// geometry located last and the subsegment found last, so a scan in
/// address order reads each once.
pub struct PoolPageReader<'a> {
    debugger: &'a Target,
    layout: &'a PoolLayout,
    /// Per segment geometry, the segment located last and its descriptors,
    /// `None` where they did not read.
    descriptors: Vec<Option<(u64, Option<Vec<u8>>)>>,
    /// The page range `[start, end)` of the LFH subsegment found last, and
    /// the subsegment.
    subsegment: Option<(u64, u64, PoolLfhSubsegment)>,
}

impl<'a> PoolPageReader<'a> {
    pub fn new(debugger: &'a Target, layout: &'a PoolLayout) -> Self {
        Self {
            debugger,
            layout,
            descriptors: vec![None; layout.lfh.as_ref().map_or(0, |lfh| lfh.segments.len())],
            subsegment: None,
        }
    }

    /// The blocks of the pool page at `base`, whose bytes are `page`.
    pub fn page_blocks(&mut self, base: VirtAddr, page: &[u8]) -> Vec<PoolHeader> {
        let layout = self.layout;
        match self.lfh_subsegment(base) {
            Some(subsegment) => lfh_page_blocks(layout, subsegment, base, page),
            None => pool_page_blocks(layout, base, page),
        }
    }

    /// The LFH subsegment whose page range holds `page`, as the range
    /// descriptors of the segment holding it say.
    pub fn lfh_subsegment(&mut self, page: VirtAddr) -> Option<&PoolLfhSubsegment> {
        let layout = self.layout;
        let debugger = self.debugger;
        let lfh = layout.lfh.as_ref()?;
        if !self
            .subsegment
            .as_ref()
            .is_some_and(|(start, end, _)| (*start..*end).contains(&page.0))
        {
            let found = lfh
                .segments
                .iter()
                .enumerate()
                .find_map(|(index, geometry)| {
                    let segment = page.0 & geometry.mask;
                    let descriptors = self.descriptors(index, segment)?;
                    let (start, end) = lfh.lfh_range(geometry, segment, descriptors, page.0)?;
                    let subsegment = lfh.decode(debugger, layout, VirtAddr(start), end)?;
                    Some((start, end, subsegment))
                });
            self.subsegment = Some(found?);
        }
        self.subsegment
            .as_ref()
            .map(|(_, _, subsegment)| subsegment)
    }

    /// The range descriptors of `segment`, located by geometry `index`.
    fn descriptors(&mut self, index: usize, segment: u64) -> Option<&[u8]> {
        let lfh = self.layout.lfh.as_ref()?;
        let slot = self.descriptors.get_mut(index)?;
        if !slot.as_ref().is_some_and(|(read, _)| *read == segment) {
            let size = lfh.descriptor_count * lfh.descriptor.size as u64;
            let mut bytes = vec![0u8; usize::try_from(size).ok()?];
            let read = self
                .debugger
                .kernel_address_space()
                .read_bytes(VirtAddr(segment) + lfh.descriptors_offset, &mut bytes)
                .is_ok();
            *slot = Some((segment, read.then_some(bytes)));
        }
        slot.as_ref()?.1.as_deref()
    }
}

pub fn locate_pool_block_in_page(
    debugger: &Target,
    layout: &PoolLayout,
    target: VirtAddr,
) -> (Vec<PoolHeader>, Option<usize>, VirtAddr) {
    let base = VirtAddr(target.0 & !(POOL_PAGE_SIZE - 1));
    let memory = debugger.kernel_address_space();
    let mut reader = PoolPageReader::new(debugger, layout);
    let mut page = vec![0u8; PAGE_SIZE];
    if let Some(subsegment) = reader.lfh_subsegment(base)
        && memory.read_bytes(base, &mut page).is_ok()
    {
        let mut blocks = lfh_page_blocks(layout, subsegment, base, &page);
        // The block that began on the page before and runs into this one,
        // unless the subsegment withholds it.
        let lfh = &subsegment.blocks;
        if let Some(offset) = base.0.checked_sub(lfh.first_block.0)
            && offset % lfh.block_size != 0
            && let Ok(index) = u32::try_from(offset / lfh.block_size)
            && index < lfh.block_count
        {
            let mut header = vec![0u8; layout.header_size as usize];
            if memory.read_bytes(lfh.block(index), &mut header).is_ok()
                && let Some(block) = lfh_block(layout, subsegment, index, &header)
            {
                blocks.insert(0, block);
            }
        }
        let index = blocks
            .iter()
            .position(|block| (block.header.0..block.header.0 + block.size).contains(&target.0));
        return (blocks, index, base);
    }
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

/// A pool with a virtual range of its own, and what locates that range.
pub struct PoolRange {
    pub name: &'static str,
    /// The `_MI_ASSIGNED_REGION_TYPES` value naming its
    /// `MiState.Vs.SystemVaRegions` entry, when it has one.
    assigned_region: Option<&'static str>,
    /// The `nt!Mm*Start`/`nt!Mm*End` globals of builds before those regions.
    start_symbol: &'static str,
    end_symbol: &'static str,
    /// Another global for the end, where a build names it so instead
    /// (Windows 7's `MiNonPagedPoolEnd`).
    other_end_symbol: Option<&'static str>,
    /// Where AMD64 kernels with no start global put the pool, by release;
    /// the start is the highest of these below the end.
    amd64_fixed_starts: &'static [u64],
    /// The pool's size, for an end where no global gives one (8.1's
    /// nonpaged pool: its start plus `MmMaximumNonPagedPoolInBytes`).
    size_symbol: Option<&'static str>,
}

pub const NONPAGED_POOL: PoolRange = PoolRange {
    name: "NonPagedPool",
    assigned_region: Some("AssignedRegionNonPagedPool"),
    start_symbol: "MmNonPagedPoolStart",
    end_symbol: "MmNonPagedPoolEnd",
    other_end_symbol: Some("MiNonPagedPoolEnd"),
    // Windows 8.1.
    amd64_fixed_starts: &[0xffff_e000_0000_0000],
    size_symbol: Some("MmMaximumNonPagedPoolInBytes"),
};

pub const PAGED_POOL: PoolRange = PoolRange {
    name: "PagedPool",
    assigned_region: Some("AssignedRegionPagedPool"),
    start_symbol: "MmPagedPoolStart",
    end_symbol: "MmPagedPoolEnd",
    other_end_symbol: None,
    // Windows 7 (128 GiB below 0xfffff8c000000000) and 8.1.
    amd64_fixed_starts: &[0xffff_f8a0_0000_0000, 0xffff_c000_0000_0000],
    size_symbol: None,
};

pub const SPECIAL_POOL: PoolRange = PoolRange {
    name: "SpecialPool",
    assigned_region: None,
    start_symbol: "MmSpecialPoolStart",
    end_symbol: "MmSpecialPoolEnd",
    other_end_symbol: None,
    amd64_fixed_starts: &[],
    size_symbol: None,
};

/// The virtual range `[start, end)` of `pool`. Windows 10 1803 and later
/// give nonpaged and paged pool a fixed region each in
/// `MiState.Vs.SystemVaRegions`, which the `MmNonPagedPoolStart`-style
/// globals of older builds (or the `MiState` fields named like them) no
/// longer describe; those are the fallback.
pub fn pool_range(debugger: &Target, pool: &PoolRange) -> Result<(VirtAddr, VirtAddr)> {
    let assigned = match pool.assigned_region {
        Some(region) => assigned_system_va_region(debugger, region),
        None => Err(Error::DebugInfo("no system-VA region of its own".into())),
    };
    let why = match assigned {
        Ok(range) => return Ok(range),
        Err(error) => error,
    };
    legacy_pool_range(debugger, pool).ok_or_else(|| {
        Error::DebugInfo(format!(
            "cannot locate {} ({why}; nor nt!{}/nt!{})",
            pool.name, pool.start_symbol, pool.end_symbol
        ))
    })
}

/// Base and end of the `MiState.Vs.SystemVaRegions` entry `region` (an
/// `_MI_ASSIGNED_REGION_TYPES` name).
fn assigned_system_va_region(debugger: &Target, region: &str) -> Result<(VirtAddr, VirtAddr)> {
    let ntos = &debugger.guest()?.ntoskrnl;
    let types = ntos.types();
    let missing = |why: String| {
        Error::DebugInfo(format!(
            "no {region} system-VA region, which Windows 10 1803 and later assign: {why}"
        ))
    };
    let index = debugger
        .symbols
        .find_enum_across_modules(ntos.dtb(), "_MI_ASSIGNED_REGION_TYPES")
        .and_then(|values| values.into_iter().find(|(name, _)| name == region))
        .map(|(_, value)| value as u64)
        .ok_or_else(|| missing("no _MI_ASSIGNED_REGION_TYPES value".into()))?;
    let visible = types
        .layout("_MI_VISIBLE_STATE")
        .map_err(|error| missing(error.to_string()))?;
    let regions = visible
        .field("SystemVaRegions")
        .map_err(|error| missing(error.to_string()))?;
    let count = match &regions.type_data {
        ParsedType::Array(_, count) => u64::from(*count),
        _ => return Err(missing("SystemVaRegions is not an array".into())),
    };
    if index >= count {
        return Err(missing(format!("index {index} past {count} regions")));
    }
    let entry_size = regions.size / count;
    let entry = debugger.visible_state()? + regions.offset as u64 + index * entry_size;
    let assignment = types.struct_at("_MI_SYSTEM_VA_ASSIGNMENT", entry)?;
    let base = assignment.read_pointer("BaseAddress")?;
    let size = assignment.read_uint("NumberOfBytes")?;
    let end = base
        .0
        .checked_add(size)
        .filter(|_| !base.is_zero() && size != 0)
        .ok_or_else(|| missing("the region is not assigned".into()))?;
    Ok((base, VirtAddr(end)))
}

/// `pool`'s range from its `nt!Mm*Start`/`nt!Mm*End` globals, else from the
/// `MiState` fields named like them.
fn legacy_pool_range(debugger: &Target, pool: &PoolRange) -> Option<(VirtAddr, VirtAddr)> {
    let end = read_kernel_global_u64(debugger, pool.end_symbol)
        .or_else(|error| {
            pool.other_end_symbol.map_or(Err(error), |symbol| {
                read_kernel_global_u64(debugger, symbol)
            })
        })
        .ok();
    let start = read_kernel_global_u64(debugger, pool.start_symbol)
        .ok()
        .or_else(|| {
            if debugger.arch() != crate::arch::Arch::Amd64 {
                return None;
            }
            let fixed = pool.amd64_fixed_starts.iter().copied();
            match end {
                Some(end) => fixed.filter(|start| *start < end).max(),
                None => fixed.max(),
            }
        });
    let end = end.or_else(|| {
        let size = read_kernel_global_u64(debugger, pool.size_symbol?).ok()?;
        start?.checked_add(size)
    });
    let globals = start.zip(end).filter(|(start, end)| start < end);
    let (start, end) = globals.or_else(|| {
        let fields = find_mi_state_fields(debugger, &["pool", "start", "end"]);
        // `MmPagedPoolStart` names `pagedpoolstart`, which a
        // `NonPagedPoolStart` field also contains.
        let field = |symbol: &str| {
            let key = symbol.trim_start_matches("Mm").to_ascii_lowercase();
            let shadowed = format!("non{key}");
            fields.iter().find_map(|(name, value)| {
                let name = name.to_ascii_lowercase();
                (name.contains(&key) && !name.contains(&shadowed)).then_some(*value)
            })
        };
        Some((field(pool.start_symbol)?, field(pool.end_symbol)?)).filter(|(s, e)| s < e)
    })?;
    Some((VirtAddr(start), VirtAddr(end)))
}

/// The pool range holding `addr`, if any: its name, start, and end.
pub fn classify_pool_region(
    debugger: &Target,
    addr: VirtAddr,
) -> Option<(&'static str, VirtAddr, VirtAddr)> {
    // A range this build cannot locate says nothing about the others.
    [NONPAGED_POOL, PAGED_POOL, SPECIAL_POOL]
        .iter()
        .find_map(|pool| {
            let (start, end) = pool_range(debugger, pool).ok()?;
            (start..end)
                .contains(&addr)
                .then_some((pool.name, start, end))
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Windows 7 sets the protected bit in an object's tag: 'Proc' is
    /// stored 0xe36f7250, and still reads, and passes, as Proc.
    #[test]
    fn a_protected_tag_reads_as_its_characters() {
        assert_eq!(tag_string(0xe36f_7250), "Proc");
        assert!(tag_looks_printable(0xe36f_7250));
        assert!(!tag_looks_printable(0x8000_0001));
    }

    const BASE: VirtAddr = VirtAddr(0xffff_d00c_db19_4000);

    /// An x64 `_POOL_HEADER`, read by its fixed offsets, and, given a heap
    /// key, the segment heap's VS chunk header.
    fn layout(heap_key: Option<u64>) -> PoolLayout {
        let ulong_bits = |offset, pos, len| FieldInfo {
            offset,
            size: 4,
            type_data: ParsedType::Bitfield {
                underlying: Box::new(ParsedType::Primitive("ULONG".into())),
                pos,
                len,
            },
        };
        let sizes = TypeInfo {
            name: "_HEAP_VS_CHUNK_HEADER_SIZE".into(),
            size: 8,
            fields: [
                ("UnsafeSize".to_string(), ulong_bits(0, 16, 16)),
                ("Allocated".to_string(), ulong_bits(4, 16, 8)),
            ]
            .into_iter()
            .collect(),
            pointer_size: 8,
        };
        PoolLayout {
            pool_header: Arc::new(TypeInfo {
                name: "_POOL_HEADER".into(),
                size: 0x10,
                fields: Default::default(),
                pointer_size: 8,
            }),
            header_size: 0x10,
            pool_tag_offset: 4,
            pool_header_uses_struct: false,
            big_pool_type: None,
            big_pool_uses_struct: false,
            big_pool_has_pool_type: false,
            big_pool_has_slush: false,
            vs_chunks: heap_key.map(|heap_key| VsChunkHeaders {
                sizes: Arc::new(sizes),
                sizes_offset: 0,
                header_size: 0x10,
                heap_key,
            }),
            lfh: None,
            header_pool: Some(HeaderPoolEncoding {
                paged_pool: 1,
                plus_one: false,
            }),
        }
    }

    fn put_header(page: &mut [u8], offset: usize, size: u64, pool_type: u8, tag: &[u8; 4]) {
        page[offset..offset + 4].copy_from_slice(&[0, 0, (size / POOL_ALIGN) as u8, pool_type]);
        page[offset + 4..offset + 8].copy_from_slice(tag);
    }

    fn blocks(layout: &PoolLayout, page: &[u8]) -> Vec<(u64, u64, bool)> {
        pool_page_blocks(layout, BASE, page)
            .iter()
            .map(|block| (block.header.0 - BASE.0, block.size, block.synthetic_free))
            .collect()
    }

    /// Each block of a VS subsegment follows its chunk header, whose encoded
    /// bytes here read as a header (protected tag `+mPk`) whose block covers
    /// the real one, as does UTF-16 text before it. Decoded, the chunk
    /// header vouches for the real block, and neither covers it.
    #[test]
    fn a_vs_chunk_header_vouches_for_its_block() {
        let mut page = vec![0u8; POOL_PAGE_SIZE as usize];
        page[0x20..0x28].copy_from_slice(&[0, 0, 0x53, 0, b'y', 0, b's', 0]);
        let chunk = 0xb0;
        let encoded = [0xbc, 0x9a, 0x51, 0x1a, b'+', b'm', b'P', 0xeb];
        page[chunk..chunk + 8].copy_from_slice(&encoded);
        put_header(&mut page, 0xc0, 0xe00, 2, b"Proc");
        // UnsafeSize 0xe1 units (the chunk header and the block), Allocated.
        let sizes = 0xe1 << 16 | 1 << 48;
        let key = u64::from_le_bytes(encoded) ^ sizes ^ (BASE.0 + chunk as u64);
        assert_eq!(blocks(&layout(Some(key)), &page), [(0xc0, 0xe00, false)]);
        // A chunk header one unit short of the block vouches for nothing.
        assert_eq!(
            blocks(&layout(Some(key ^ 1 << 16)), &page),
            [(0x20, 0x530, false)]
        );
    }

    /// The space between two blocks is a free block reaching the next
    /// header; what precedes the first (an LFH subsegment's header) is none.
    #[test]
    fn gaps_between_blocks_are_free_and_reach_the_next_header() {
        let mut page = vec![0u8; POOL_PAGE_SIZE as usize];
        for offset in [0xc0, 0x120, 0x200] {
            put_header(&mut page, offset, 0x60, 3, b"NtFd");
        }
        assert_eq!(
            blocks(&layout(None), &page),
            [
                (0xc0, 0x60, false),
                (0x120, 0x60, false),
                (0x180, 0x80, true),
                (0x200, 0x60, false),
            ]
        );
    }

    /// Windows XP x64 splits a 16-byte free fragment off an allocation's
    /// tail without a tag (the bytes there are stale), and clears a freed
    /// block's pool type to 0, which in its plus-one encoding names no pool.
    /// The fragment's PreviousSize chains it to the block before, so it is a
    /// block of the page, and both read as free.
    #[test]
    fn a_tagless_fragment_chained_to_the_block_before_is_a_free_block() {
        let mut page = vec![0u8; POOL_PAGE_SIZE as usize];
        put_header(&mut page, 0, 0x450, 5, b"Thre");
        page[0x450..0x458].copy_from_slice(&[0x45, 0, 1, 0, 0xd0, 0x64, 0xdd, 0x01]);
        put_header(&mut page, 0x460, 0x60, 5, b"Vad ");
        page[0x460] = 1;
        put_header(&mut page, 0x4c0, 0x20, 0, b"Wait");
        page[0x4c0] = 6;
        let xp = PoolLayout {
            header_pool: Some(HeaderPoolEncoding {
                paged_pool: 1,
                plus_one: true,
            }),
            ..layout(None)
        };
        let listed: Vec<(u64, u64, PoolBlockState)> = pool_page_blocks(&xp, BASE, &page)
            .iter()
            .take(4)
            .map(|block| {
                (
                    block.header.0 - BASE.0,
                    block.size,
                    pool_block_state(block, xp.header_pool),
                )
            })
            .collect();
        assert_eq!(
            listed,
            [
                (0, 0x450, PoolBlockState::Allocated),
                (0x450, 0x10, PoolBlockState::Free),
                (0x460, 0x60, PoolBlockState::Allocated),
                (0x4c0, 0x20, PoolBlockState::Free),
            ]
        );
        // Unchained, the same bytes are data, not a header.
        page[0x450] = 0x44;
        assert!(
            pool_page_blocks(&xp, BASE, &page)
                .iter()
                .all(|block| block.header.0 - BASE.0 != 0x450 || block.synthetic_free)
        );
    }

    /// A page that begins an LFH subsegment: its header and bitmap, whose
    /// counts can read as a header, are no block; the blocks run from the
    /// first one, each busy or free as the bitmap says, though a freed one
    /// keeps its header and tag. The block across the page end is the
    /// subsegment's only where it withholds none.
    #[test]
    fn an_lfh_page_lists_the_subsegments_blocks_in_their_bitmap_state() {
        let mut page = vec![0u8; POOL_PAGE_SIZE as usize];
        put_header(&mut page, 0x20, 0xe0, 0, b"\0\0\0\x01");
        let starts: Vec<u64> = (0..15).map(|index| 0x50 + index * 0x110).collect();
        for &start in &starts {
            put_header(&mut page, start as usize, 0x110, 3, b"CMSc");
        }
        let mut subsegment = PoolLfhSubsegment {
            blocks: LfhSubsegment {
                address: BASE,
                block_size: 0x110,
                block_count: 16,
                free_count: 1,
                bucket: None,
                first_block: BASE + 0x50u64,
                bitmap: vec![!(1 << 2)],
                blocks_per_word: 64,
                bit_stride: 1,
            },
            withholds: true,
        };
        let listed = |subsegment: &PoolLfhSubsegment| -> Vec<(u64, u64, PoolBlockState)> {
            lfh_page_blocks(&layout(None), subsegment, BASE, &page)
                .iter()
                .map(|block| {
                    (
                        block.header.0 - BASE.0,
                        block.size,
                        pool_block_state(block, None),
                    )
                })
                .collect()
        };
        let expected: Vec<(u64, u64, PoolBlockState)> = starts
            .iter()
            .enumerate()
            .map(|(index, &start)| {
                let state = if index == 2 {
                    PoolBlockState::Free
                } else {
                    PoolBlockState::Allocated
                };
                (start, 0x110, state)
            })
            .collect();
        assert_eq!(listed(&subsegment), expected[..14]);
        subsegment.withholds = false;
        assert_eq!(listed(&subsegment), expected);
        // The next page begins inside block 14; its first block is 15.
        let next = lfh_page_blocks(&layout(None), &subsegment, BASE + POOL_PAGE_SIZE, &page);
        assert_eq!(
            next.first().map(|block| block.header),
            Some(subsegment.blocks.block(15))
        );
    }
}
