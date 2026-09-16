//! User-mode heap decoding for `!heap`: the NT heap (`_HEAP`, front-ended by
//! the legacy LFH) and the segment heap (`_SEGMENT_HEAP`, with VS and LFH
//! sub-allocators and large allocations). Layouts come from the PDB; the
//! encodings ntdll applies to headers are the one thing the PDB cannot say
//! and are pinned here, verified against live targets.

use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::memory::AddressSpace;
use crate::phys::PhysMem;
use crate::repl::INTERRUPT_REQUESTED;
use crate::symbols::{ParsedType, TypeInfo, le_uint};
use crate::target::Target;
use crate::types::{Dtb, VirtAddr};

pub const NT_HEAP_SIGNATURE: u32 = 0xEEFF_EEFF;
pub const SEGMENT_HEAP_SIGNATURE: u32 = 0xDDEE_DDEE;
/// `_HEAP_USERDATA_HEADER.Signature` of a legacy-LFH user block region.
const NT_USERDATA_SIGNATURE: u32 = 0xF0E0_D0C0;
/// `_HEAP_VS_SUBSEGMENT.Signature` is `Size ^ VS_SUBSEGMENT_SIGNATURE_KEY`.
const VS_SUBSEGMENT_SIGNATURE_KEY: u16 = 0x2BED;
/// `_HEAP.EncodeFlagMask` bit that says `_HEAP.Encoding` is applied.
const NT_HEAP_ENCODING_ACTIVE: u32 = 0x0010_0000;

/// `_HEAP_ENTRY.Flags`.
pub const NT_ENTRY_BUSY: u8 = 0x01;
pub const NT_ENTRY_EXTRA_PRESENT: u8 = 0x02;
pub const NT_ENTRY_FILL_PATTERN: u8 = 0x04;
pub const NT_ENTRY_VIRTUAL_ALLOC: u8 = 0x08;
pub const NT_ENTRY_LAST: u8 = 0x10;
/// `_HEAP_ENTRY.UnusedBytes` bit marking a block carved by the legacy LFH.
const NT_ENTRY_LFH_BLOCK: u8 = 0x80;

/// `_HEAP_PAGE_RANGE_DESCRIPTOR.RangeFlags`, as ntdll sets them: a range in
/// use keeps `ALLOCATED` on every descriptor, its head adds `FIRST`, and a
/// head handed to a sub-allocator adds `SUBSEGMENT` (with `VS` for the
/// variable-size one). A free range's head keeps only `FIRST`.
const RANGE_ALLOCATED: u8 = 0x01;
const RANGE_FIRST: u8 = 0x02;
const RANGE_VS: u8 = 0x04;
const RANGE_SUBSEGMENT: u8 = 0x08;

const HEAP_GRANULE: u64 = 16;
const PAGE: u64 = 0x1000;
/// Bound on entries decoded from one NT segment, VS subsegment, or LFH
/// subsegment before the walk gives up on a corrupt chain.
const MAX_ENTRIES: usize = 1 << 20;
const MAX_LIST: usize = 4096;
const MAX_HEAPS: usize = 1024;
const MAX_TREE: usize = 1 << 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeapKind {
    Nt,
    Segment,
    Unknown(u32),
}

#[derive(Clone, Copy, Debug)]
pub struct ProcessHeap {
    pub index: usize,
    pub address: VirtAddr,
    pub kind: HeapKind,
}

/// A resolved struct layout with buffer-relative field reads.
#[derive(Clone)]
struct Layout(Arc<TypeInfo>);

impl Layout {
    fn size(&self) -> usize {
        self.0.size
    }

    fn offset(&self, field: &str) -> Result<usize> {
        self.0.field_offset(field).map(|offset| offset as usize)
    }

    /// Read a scalar or bitfield out of a buffer holding the struct at `at`.
    fn read(&self, buf: &[u8], at: usize, field: &str) -> Result<u64> {
        let info = self
            .0
            .fields
            .get(field)
            .ok_or_else(|| Error::FieldNotFound(field.to_string()))?;
        let start = at + info.offset as usize;
        let size = info.size.clamp(1, 8) as usize;
        let slice = buf.get(start..start + size).ok_or_else(|| {
            Error::DebugInfo(format!("{}.{field} is outside the read", self.0.name))
        })?;
        let raw = le_uint(slice);
        Ok(match &info.type_data {
            ParsedType::Bitfield { pos, len, .. } => {
                let mask = if *len >= 64 {
                    u64::MAX
                } else {
                    (1u64 << len) - 1
                };
                (raw >> pos) & mask
            }
            _ => raw,
        })
    }

    /// Element count of an array field, from its byte size and the element layout.
    fn array_len(&self, field: &str, element: &Layout) -> Result<usize> {
        let info = self
            .0
            .fields
            .get(field)
            .ok_or_else(|| Error::FieldNotFound(field.to_string()))?;
        match &info.type_data {
            ParsedType::Array(_, count) => Ok(*count as usize),
            _ if element.size() != 0 => Ok(info.size as usize / element.size()),
            _ => Err(Error::FieldTypeMismatch(field.to_string(), "array".into())),
        }
    }
}

/// Everything a walk needs: the process address space and the kernel PDB's
/// heap layouts (ntdll and ntoskrnl share the heap source, so the layouts
/// match the build).
pub struct HeapReader<'a> {
    target: &'a Target,
    dtb: Dtb,
    memory: AddressSpace<'a, PhysMem>,
}

impl<'a> HeapReader<'a> {
    pub fn new(target: &'a Target, dtb: Dtb) -> Self {
        Self {
            target,
            dtb,
            memory: target.address_space(dtb),
        }
    }

    fn layout(&self, name: &str) -> Result<Layout> {
        self.target
            .symbols
            .find_type_across_modules(self.dtb, name)
            .map(Layout)
            .ok_or_else(|| Error::StructNotFound(name.to_string()))
    }

    fn read(&self, address: VirtAddr, size: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; size];
        self.memory.read_bytes(address, &mut buf)?;
        Ok(buf)
    }

    fn read_struct(&self, layout: &Layout, address: VirtAddr) -> Result<Vec<u8>> {
        self.read(address, layout.size())
    }

    /// Read as much of `[address, address + size)` as is mapped, a page at a
    /// time, stopping at the first page that is not. Regions are committed
    /// lazily and paged out independently, so a walk covers what is there.
    fn read_prefix(&self, address: VirtAddr, size: usize) -> Vec<u8> {
        let mut buf = vec![0u8; size];
        let mut read = 0;
        while read < size {
            let next_page = (address.0 + read as u64 + 1).next_multiple_of(PAGE) - address.0;
            let end = (next_page as usize).min(size);
            if self
                .memory
                .read_bytes(address + read as u64, &mut buf[read..end])
                .is_err()
            {
                break;
            }
            read = end;
        }
        buf.truncate(read);
        buf
    }

    fn read_u64(&self, address: VirtAddr) -> Result<u64> {
        self.memory.read(address)
    }

    fn symbol(&self, name: &str) -> Result<VirtAddr> {
        self.target
            .symbols
            .find_symbol_across_modules(self.dtb, name)?
            .ok_or_else(|| {
                Error::DebugInfo(format!(
                    "{name} is not resolvable; ntdll symbols are required"
                ))
            })
    }

    /// Records of an intrusive `_LIST_ENTRY` list, given the head and the
    /// link's offset inside each record. Bounded and cycle-safe.
    fn list(&self, head: VirtAddr, link_offset: u64) -> Result<Vec<VirtAddr>> {
        let mut records = Vec::new();
        let mut link = VirtAddr(self.read_u64(head)?);
        while link != head && !link.is_zero() && records.len() < MAX_LIST {
            let record = VirtAddr(link.0.wrapping_sub(link_offset));
            if records.contains(&record) {
                break;
            }
            records.push(record);
            link = VirtAddr(self.read_u64(link)?);
        }
        Ok(records)
    }

    /// The heaps `_PEB.ProcessHeaps` lists, classified by signature.
    pub fn process_heaps(&self, peb: VirtAddr) -> Result<Vec<ProcessHeap>> {
        let peb_layout = self.layout("_PEB")?;
        let image = self.read_struct(&peb_layout, peb)?;
        let count = peb_layout.read(&image, 0, "NumberOfHeaps")? as usize;
        let table = VirtAddr(peb_layout.read(&image, 0, "ProcessHeaps")?);
        if count == 0 || table.is_zero() {
            return Ok(Vec::new());
        }
        let count = count.min(MAX_HEAPS);
        let pointers = self.read(table, count * 8)?;
        pointers
            .chunks_exact(8)
            .enumerate()
            .map(|(index, bytes)| {
                let address = VirtAddr(le_uint(bytes));
                Ok(ProcessHeap {
                    index,
                    address,
                    kind: self.classify(address)?,
                })
            })
            .collect()
    }

    pub fn classify(&self, heap: VirtAddr) -> Result<HeapKind> {
        let segment = self.layout("_SEGMENT_HEAP")?;
        let signature_offset = segment.offset("Signature")?;
        let signature: u32 = self.memory.read(heap + signature_offset as u64)?;
        if signature == SEGMENT_HEAP_SIGNATURE {
            return Ok(HeapKind::Segment);
        }
        let nt = self.layout("_HEAP")?;
        let nt_signature: u32 = self.memory.read(heap + nt.offset("Signature")? as u64)?;
        if nt_signature == NT_HEAP_SIGNATURE {
            return Ok(HeapKind::Nt);
        }
        Ok(HeapKind::Unknown(nt_signature))
    }
}

// ---------------------------------------------------------------- NT heap

#[derive(Clone, Debug)]
pub struct NtHeap {
    pub address: VirtAddr,
    pub flags: u32,
    pub force_flags: u32,
    /// XOR mask over the second qword of every `_HEAP_ENTRY`, when active.
    pub encoding: Option<u64>,
    pub total_free_units: u64,
    pub virtual_threshold: u32,
    pub front_end: Option<VirtAddr>,
    pub front_end_type: u8,
    pub segments: Vec<NtSegment>,
    pub virtual_blocks: Vec<NtVirtualBlock>,
}

#[derive(Clone, Debug)]
pub struct NtSegment {
    pub address: VirtAddr,
    pub base: VirtAddr,
    pub pages: u32,
    pub uncommitted_pages: u32,
    pub first_entry: VirtAddr,
    pub last_valid_entry: VirtAddr,
    /// Uncommitted ranges the entry chain skips over.
    pub uncommitted: Vec<Range<u64>>,
}

impl NtSegment {
    pub fn end(&self) -> VirtAddr {
        VirtAddr(self.base.0 + u64::from(self.pages) * PAGE)
    }

    pub fn contains(&self, address: VirtAddr) -> bool {
        (self.base.0..self.end().0).contains(&address.0)
    }
}

#[derive(Clone, Debug)]
pub struct NtVirtualBlock {
    pub entry: VirtAddr,
    pub commit_size: u64,
    pub reserve_size: u64,
    /// First user byte: the header's `BusyBlock` is the last thing before it.
    pub user: VirtAddr,
}

#[derive(Clone, Copy, Debug)]
pub struct NtEntry {
    pub address: VirtAddr,
    pub size: u64,
    pub previous_size: u64,
    pub flags: u8,
    pub unused_bytes: u8,
    /// The header's own XOR checksum held.
    pub checksum_ok: bool,
}

impl NtEntry {
    pub fn busy(&self) -> bool {
        self.flags & NT_ENTRY_BUSY != 0
    }

    pub fn user(&self) -> VirtAddr {
        self.address + HEAP_GRANULE
    }

    pub fn end(&self) -> VirtAddr {
        self.address + self.size
    }

    /// Bytes the caller asked for: the block less its header and slack.
    pub fn user_size(&self) -> u64 {
        self.size
            .saturating_sub(HEAP_GRANULE)
            .saturating_sub(u64::from(self.unused_bytes & !NT_ENTRY_LFH_BLOCK))
    }
}

/// One segment's entry chain and, when it ended before `LastValidEntry`,
/// where and why.
#[derive(Clone, Debug)]
pub struct NtWalk {
    pub entries: Vec<NtEntry>,
    pub stopped: Option<(VirtAddr, &'static str)>,
}

/// A legacy-LFH user block region living inside one busy backend entry.
#[derive(Clone, Debug)]
pub struct NtUserBlocks {
    pub header: VirtAddr,
    pub subsegment: VirtAddr,
    pub block_size: u64,
    pub block_count: u32,
    pub first_block: VirtAddr,
    pub stride: u64,
    /// One bit per block, set when busy.
    pub busy: Vec<u64>,
}

impl NtUserBlocks {
    pub fn is_busy(&self, index: u32) -> bool {
        self.busy
            .get(index as usize / 64)
            .is_some_and(|word| word >> (index % 64) & 1 != 0)
    }

    pub fn busy_count(&self) -> u32 {
        (0..self.block_count).filter(|i| self.is_busy(*i)).count() as u32
    }

    pub fn block(&self, index: u32) -> VirtAddr {
        self.first_block + u64::from(index) * self.stride
    }
}

impl HeapReader<'_> {
    pub fn nt_heap(&self, address: VirtAddr) -> Result<NtHeap> {
        let heap = self.layout("_HEAP")?;
        let image = self.read_struct(&heap, address)?;
        if heap.read(&image, 0, "Signature")? as u32 != NT_HEAP_SIGNATURE {
            return Err(Error::DebugInfo(format!(
                "{} is not an NT heap (no _HEAP signature)",
                address
            )));
        }
        let encode_mask = heap.read(&image, 0, "EncodeFlagMask")? as u32;
        let encoding = (encode_mask & NT_HEAP_ENCODING_ACTIVE != 0).then(|| {
            let at = heap.offset("Encoding").unwrap_or(0) + 8;
            le_uint(&image[at..at + 8])
        });
        let segment_layout = self.layout("_HEAP_SEGMENT")?;
        let segment_link = segment_layout.offset("SegmentListEntry")? as u64;
        let mut segments = Vec::new();
        for record in self.list(address + heap.offset("SegmentList")? as u64, segment_link)? {
            segments.push(self.nt_segment(&segment_layout, record)?);
        }
        let virtual_layout = self.layout("_HEAP_VIRTUAL_ALLOC_ENTRY")?;
        let virtual_link = virtual_layout.offset("Entry")? as u64;
        let mut virtual_blocks = Vec::new();
        for record in self.list(
            address + heap.offset("VirtualAllocdBlocks")? as u64,
            virtual_link,
        )? {
            let entry = self.read_struct(&virtual_layout, record)?;
            virtual_blocks.push(NtVirtualBlock {
                entry: record,
                commit_size: virtual_layout.read(&entry, 0, "CommitSize")?,
                reserve_size: virtual_layout.read(&entry, 0, "ReserveSize")?,
                user: record + virtual_layout.size() as u64,
            });
        }
        let front_end = VirtAddr(heap.read(&image, 0, "FrontEndHeap")?);
        Ok(NtHeap {
            address,
            flags: heap.read(&image, 0, "Flags")? as u32,
            force_flags: heap.read(&image, 0, "ForceFlags")? as u32,
            encoding,
            total_free_units: heap.read(&image, 0, "TotalFreeSize")?,
            virtual_threshold: heap.read(&image, 0, "VirtualMemoryThreshold")? as u32,
            front_end: (!front_end.is_zero()).then_some(front_end),
            front_end_type: heap.read(&image, 0, "FrontEndHeapType")? as u8,
            segments,
            virtual_blocks,
        })
    }

    fn nt_segment(&self, layout: &Layout, address: VirtAddr) -> Result<NtSegment> {
        let image = self.read_struct(layout, address)?;
        let ucr_layout = self.layout("_HEAP_UCR_DESCRIPTOR")?;
        let ucr_link = ucr_layout.offset("SegmentEntry")? as u64;
        let mut uncommitted = Vec::new();
        for record in self.list(address + layout.offset("UCRSegmentList")? as u64, ucr_link)? {
            let ucr = self.read_struct(&ucr_layout, record)?;
            let start = ucr_layout.read(&ucr, 0, "Address")?;
            let size = ucr_layout.read(&ucr, 0, "Size")?;
            uncommitted.push(start..start.saturating_add(size));
        }
        uncommitted.sort_by_key(|range| range.start);
        Ok(NtSegment {
            address,
            base: VirtAddr(layout.read(&image, 0, "BaseAddress")?),
            pages: layout.read(&image, 0, "NumberOfPages")? as u32,
            uncommitted_pages: layout.read(&image, 0, "NumberOfUnCommittedPages")? as u32,
            first_entry: VirtAddr(layout.read(&image, 0, "FirstEntry")?),
            last_valid_entry: VirtAddr(layout.read(&image, 0, "LastValidEntry")?),
            uncommitted,
        })
    }

    /// Walk a segment's entry chain from `FirstEntry` to `LastValidEntry`,
    /// stepping over uncommitted ranges. The chain only links forward, so a
    /// header that cannot be read (a paged-out page) or does not verify ends
    /// the walk; `stopped` says where and why.
    pub fn nt_segment_entries(&self, heap: &NtHeap, segment: &NtSegment) -> NtWalk {
        let mut entries = Vec::new();
        let mut stopped = None;
        let mut cursor = segment.first_entry;
        let end = segment.last_valid_entry;
        // One read per committed run rather than one per entry.
        let mut run: Option<(VirtAddr, Vec<u8>)> = None;
        while cursor < end && entries.len() < MAX_ENTRIES {
            if INTERRUPT_REQUESTED.load(Ordering::Relaxed) {
                stopped = Some((cursor, "interrupted"));
                break;
            }
            if let Some(gap) = segment
                .uncommitted
                .iter()
                .find(|range| range.contains(&cursor.0))
            {
                cursor = VirtAddr(gap.end);
                run = None;
                continue;
            }
            let raw = match &run {
                Some((start, bytes))
                    if cursor >= *start && cursor.0 + 16 <= start.0 + bytes.len() as u64 =>
                {
                    let at = (cursor.0 - start.0) as usize + 8;
                    le_uint(&bytes[at..at + 8])
                }
                _ => {
                    let run_end = segment
                        .uncommitted
                        .iter()
                        .map(|range| range.start)
                        .filter(|start| *start > cursor.0)
                        .min()
                        .unwrap_or(end.0)
                        .min(end.0);
                    let bytes = self.read_prefix(cursor, (run_end - cursor.0) as usize);
                    if bytes.len() < 16 {
                        stopped = Some((cursor, "header is not readable (page not resident)"));
                        break;
                    }
                    let raw = le_uint(&bytes[8..16]);
                    run = Some((cursor, bytes));
                    raw
                }
            };
            let entry = decode_nt_entry(cursor, raw, heap.encoding);
            let reason = if entry.size == 0 {
                Some("header has a zero size")
            } else if !entry.checksum_ok {
                Some("header checksum does not verify")
            } else {
                None
            };
            entries.push(entry);
            if let Some(reason) = reason {
                stopped = Some((cursor, reason));
                break;
            }
            cursor = entry.end();
        }
        NtWalk { entries, stopped }
    }

    /// The legacy-LFH user block region a busy backend entry holds, if any.
    pub fn nt_user_blocks(&self, heap: &NtHeap, entry: &NtEntry) -> Result<Option<NtUserBlocks>> {
        let Some(lfh) = heap.front_end.filter(|_| entry.busy()) else {
            return Ok(None);
        };
        let header_layout = self.layout("_HEAP_USERDATA_HEADER")?;
        let header = entry.user();
        if entry.size < header_layout.size() as u64 + HEAP_GRANULE {
            return Ok(None);
        }
        let image = self.read_struct(&header_layout, header)?;
        if header_layout.read(&image, 0, "Signature")? as u32 != NT_USERDATA_SIGNATURE {
            return Ok(None);
        }
        let subsegment = VirtAddr(header_layout.read(&image, 0, "SubSegment")?);
        let subsegment_layout = self.layout("_HEAP_SUBSEGMENT")?;
        let subsegment_image = self.read_struct(&subsegment_layout, subsegment)?;
        let block_count = subsegment_layout.read(&subsegment_image, 0, "BlockCount")? as u32;
        let block_size = subsegment_layout.read(&subsegment_image, 0, "BlockSize")? * HEAP_GRANULE;
        // `EncodedOffsets` is XORed with the region, the LFH key, and the front
        // end it belongs to.
        let key: u64 = self.read_u64(self.symbol("ntdll!RtlpLFHKey")?)?;
        let encoded = header_layout.read(&image, 0, "EncodedOffsets")? as u32;
        let decoded = encoded ^ header.0 as u32 ^ key as u32 ^ lfh.0 as u32;
        let first_offset = u64::from(decoded & 0xFFFF);
        let stride = u64::from(decoded >> 16);
        if stride == 0 || first_offset == 0 {
            return Ok(None);
        }
        let bitmap_layout = self.layout("_RTL_BITMAP_EX")?;
        let bitmap_at = header_layout.offset("BusyBitmap")?;
        let bits = bitmap_layout.read(&image, bitmap_at, "SizeOfBitMap")? as u32;
        let buffer = VirtAddr(bitmap_layout.read(&image, bitmap_at, "Buffer")?);
        let words = (bits.max(block_count) as usize).div_ceil(64);
        let busy = self
            .read(buffer, words * 8)?
            .chunks_exact(8)
            .map(le_uint)
            .collect();
        Ok(Some(NtUserBlocks {
            header,
            subsegment,
            block_size,
            block_count,
            first_block: header + first_offset,
            stride,
            busy,
        }))
    }
}

fn decode_nt_entry(address: VirtAddr, raw: u64, encoding: Option<u64>) -> NtEntry {
    let decoded = raw ^ encoding.unwrap_or(0);
    let bytes = decoded.to_le_bytes();
    let checksum = bytes[0] ^ bytes[1] ^ bytes[2];
    NtEntry {
        address,
        size: u64::from(u16::from_le_bytes([bytes[0], bytes[1]])) * HEAP_GRANULE,
        previous_size: u64::from(u16::from_le_bytes([bytes[4], bytes[5]])) * HEAP_GRANULE,
        flags: bytes[2],
        unused_bytes: bytes[7],
        checksum_ok: encoding.is_none() || checksum == bytes[3],
    }
}

// ----------------------------------------------------------- segment heap

#[derive(Clone, Debug)]
pub struct SegmentHeap {
    pub address: VirtAddr,
    pub global_flags: u32,
    pub reserved_pages: u64,
    pub committed_pages: u64,
    pub free_committed_pages: u64,
    pub lfh_free_committed_pages: u64,
    pub vs_free_committed_pages: u64,
    pub large_reserved_pages: u64,
    pub large_committed_pages: u64,
    pub contexts: Vec<SegContext>,
    pub large_allocations: Vec<LargeAllocation>,
    /// `ntdll!RtlpHpHeapGlobals`: the VS header key and the LFH offsets key.
    pub keys: SegmentKeys,
}

#[derive(Clone, Copy, Debug)]
pub struct SegmentKeys {
    pub heap_key: u64,
    pub lfh_key: u64,
}

#[derive(Clone, Debug)]
pub struct SegContext {
    pub index: usize,
    pub unit_shift: u8,
    pub segment_mask: u64,
    pub max_allocation_size: u32,
    pub segments: Vec<PageSegment>,
}

impl SegContext {
    pub fn unit_size(&self) -> u64 {
        1 << self.unit_shift
    }

    pub fn segment_size(&self) -> u64 {
        (!self.segment_mask).wrapping_add(1)
    }
}

#[derive(Clone, Debug)]
pub struct PageSegment {
    pub address: VirtAddr,
    pub ranges: Vec<PageRange>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RangeKind {
    /// Never handed out; past the segment's high-water mark.
    Unused,
    Free,
    /// Pages allocated straight from the segment for one block.
    Direct,
    Vs,
    Lfh,
}

#[derive(Clone, Copy, Debug)]
pub struct PageRange {
    pub address: VirtAddr,
    pub units: u64,
    pub unit_size: u64,
    pub flags: u8,
    pub committed_pages: u8,
    pub unused_bytes: u32,
    pub kind: RangeKind,
}

impl PageRange {
    pub fn size(&self) -> u64 {
        self.units * self.unit_size
    }

    pub fn end(&self) -> VirtAddr {
        self.address + self.size()
    }

    pub fn contains(&self, address: VirtAddr) -> bool {
        (self.address.0..self.end().0).contains(&address.0)
    }
}

#[derive(Clone, Debug)]
pub struct VsSubsegment {
    pub address: VirtAddr,
    pub signature_ok: bool,
    pub chunks: Vec<VsChunk>,
}

#[derive(Clone, Copy, Debug)]
pub struct VsChunk {
    pub address: VirtAddr,
    pub size: u64,
    pub previous_size: u64,
    pub busy: bool,
    /// Slack recorded in the chunk's last word, when the header says so.
    pub unused_bytes: Option<u16>,
}

impl VsChunk {
    pub fn user(&self) -> VirtAddr {
        self.address + HEAP_GRANULE
    }

    pub fn end(&self) -> VirtAddr {
        self.address + self.size
    }

    pub fn user_size(&self) -> u64 {
        self.size
            .saturating_sub(HEAP_GRANULE)
            .saturating_sub(u64::from(self.unused_bytes.unwrap_or(0)))
    }
}

#[derive(Clone, Debug)]
pub struct LfhSubsegment {
    pub address: VirtAddr,
    pub block_size: u64,
    pub block_count: u32,
    pub free_count: u32,
    pub bucket: u16,
    pub first_block: VirtAddr,
    /// Bitmap words, 32 blocks per word: the low half's bit is set while the
    /// block is busy.
    pub bitmap: Vec<u64>,
}

impl LfhSubsegment {
    pub fn is_busy(&self, index: u32) -> bool {
        self.bitmap
            .get(index as usize / 32)
            .is_some_and(|word| word >> (index % 32) & 1 != 0)
    }

    pub fn busy_count(&self) -> u32 {
        (0..self.block_count).filter(|i| self.is_busy(*i)).count() as u32
    }

    pub fn block(&self, index: u32) -> VirtAddr {
        self.first_block + u64::from(index) * self.block_size
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LargeAllocation {
    pub metadata: VirtAddr,
    pub address: VirtAddr,
    pub pages: u64,
    pub unused_bytes: u16,
    pub extra_present: bool,
}

impl LargeAllocation {
    pub fn size(&self) -> u64 {
        self.pages * PAGE
    }

    pub fn contains(&self, address: VirtAddr) -> bool {
        (self.address.0..self.address.0 + self.size()).contains(&address.0)
    }
}

impl HeapReader<'_> {
    pub fn segment_heap(&self, address: VirtAddr) -> Result<SegmentHeap> {
        let heap = self.layout("_SEGMENT_HEAP")?;
        let image = self.read_struct(&heap, address)?;
        if heap.read(&image, 0, "Signature")? as u32 != SEGMENT_HEAP_SIGNATURE {
            return Err(Error::DebugInfo(format!(
                "{address} is not a segment heap (no _SEGMENT_HEAP signature)"
            )));
        }
        let keys = self.segment_keys()?;
        let stats = self.layout("_HEAP_RUNTIME_MEMORY_STATS")?;
        let stats_at = heap.offset("MemStats")?;
        let context_layout = self.layout("_HEAP_SEG_CONTEXT")?;
        let contexts_at = heap.offset("SegContexts")?;
        let context_count = heap.array_len("SegContexts", &context_layout)?;
        let mut contexts = Vec::with_capacity(context_count);
        for index in 0..context_count {
            let at = contexts_at + index * context_layout.size();
            let context =
                self.seg_context(&context_layout, &image, at, address + at as u64, index)?;
            contexts.push(context);
        }
        let tree = self.layout("_RTL_RB_TREE")?;
        let root = VirtAddr(tree.read(&image, heap.offset("LargeAllocMetadata")?, "Root")?);
        let large_allocations = self.large_allocations(root)?;
        Ok(SegmentHeap {
            address,
            global_flags: heap.read(&image, 0, "GlobalFlags")? as u32,
            reserved_pages: stats.read(&image, stats_at, "TotalReservedPages")?,
            committed_pages: stats.read(&image, stats_at, "TotalCommittedPages")?,
            free_committed_pages: stats.read(&image, stats_at, "FreeCommittedPages")?,
            lfh_free_committed_pages: stats.read(&image, stats_at, "LfhFreeCommittedPages")?,
            vs_free_committed_pages: stats.read(&image, stats_at, "VsFreeCommittedPages")?,
            large_reserved_pages: heap.read(&image, 0, "LargeReservedPages")?,
            large_committed_pages: heap.read(&image, 0, "LargeCommittedPages")?,
            contexts,
            large_allocations,
            keys,
        })
    }

    fn segment_keys(&self) -> Result<SegmentKeys> {
        let globals = self.layout("_RTLP_HP_HEAP_GLOBALS")?;
        let address = self.symbol("ntdll!RtlpHpHeapGlobals")?;
        let image = self.read_struct(&globals, address)?;
        Ok(SegmentKeys {
            heap_key: globals.read(&image, 0, "HeapKey")?,
            lfh_key: globals.read(&image, 0, "LfhKey")?,
        })
    }

    fn seg_context(
        &self,
        layout: &Layout,
        image: &[u8],
        at: usize,
        address: VirtAddr,
        index: usize,
    ) -> Result<SegContext> {
        let unit_shift = layout.read(image, at, "UnitShift")? as u8;
        let first_descriptor = layout.read(image, at, "FirstDescriptorIndex")? as u8;
        let head = address + layout.offset("SegmentListHead")? as u64;
        let mut segments = Vec::new();
        for segment in self.list(head, 0)? {
            segments.push(self.page_segment(segment, unit_shift, first_descriptor)?);
        }
        Ok(SegContext {
            index,
            unit_shift,
            segment_mask: layout.read(image, at, "SegmentMask")?,
            max_allocation_size: layout.read(image, at, "MaxAllocationSize")? as u32,
            segments,
        })
    }

    fn page_segment(
        &self,
        address: VirtAddr,
        unit_shift: u8,
        first_descriptor: u8,
    ) -> Result<PageSegment> {
        let segment = self.layout("_HEAP_PAGE_SEGMENT")?;
        let descriptor = self.layout("_HEAP_PAGE_RANGE_DESCRIPTOR")?;
        let count = segment.array_len("DescArray", &descriptor)?;
        let array_at = segment.offset("DescArray")?;
        let image = self.read(address + array_at as u64, count * descriptor.size())?;
        let unit_size = 1u64 << unit_shift;
        let mut ranges = Vec::new();
        let mut index = first_descriptor as usize;
        while index < count {
            let at = index * descriptor.size();
            let flags = descriptor.read(&image, at, "RangeFlags")? as u8;
            let units = descriptor.read(&image, at, "UnitSize")?.max(1);
            let kind = if flags & RANGE_FIRST == 0 {
                RangeKind::Unused
            } else if flags & RANGE_ALLOCATED == 0 {
                RangeKind::Free
            } else if flags & RANGE_SUBSEGMENT == 0 {
                RangeKind::Direct
            } else if flags & RANGE_VS != 0 {
                RangeKind::Vs
            } else {
                RangeKind::Lfh
            };
            // Unused descriptors carry no size; they run to the segment's end.
            let units = if kind == RangeKind::Unused {
                (count - index) as u64
            } else {
                units
            };
            ranges.push(PageRange {
                address: address + index as u64 * unit_size,
                units,
                unit_size,
                flags,
                committed_pages: descriptor.read(&image, at, "CommittedPageCount")? as u8,
                unused_bytes: descriptor.read(&image, at, "UnusedBytes")? as u32,
                kind,
            });
            index += units as usize;
        }
        Ok(PageSegment { address, ranges })
    }

    fn large_allocations(&self, root: VirtAddr) -> Result<Vec<LargeAllocation>> {
        let node = self.layout("_RTL_BALANCED_NODE")?;
        let data = self.layout("_HEAP_LARGE_ALLOC_DATA")?;
        let node_at = data.offset("TreeNode")? as u64;
        let (left, right) = (node.offset("Left")? as u64, node.offset("Right")? as u64);
        let mut out = Vec::new();
        let mut stack = vec![root];
        let mut seen = std::collections::HashSet::new();
        while let Some(current) = stack.pop() {
            if current.is_zero() || !seen.insert(current.0) || seen.len() > MAX_TREE {
                continue;
            }
            let record = VirtAddr(current.0.wrapping_sub(node_at));
            let image = self.read_struct(&data, record)?;
            let virtual_address = data.read(&image, 0, "VirtualAddress")?;
            let extra_at = data.offset("ExtraPresent")?;
            let packed = le_uint(&image[extra_at..extra_at + 8]);
            out.push(LargeAllocation {
                metadata: record,
                address: VirtAddr(virtual_address & !0xFFFF),
                pages: packed >> 12,
                unused_bytes: virtual_address as u16,
                extra_present: packed & 1 != 0,
            });
            stack.push(VirtAddr(
                le_uint(&image[node_at as usize + right as usize..][..8]) & !0x7,
            ));
            stack.push(VirtAddr(
                le_uint(&image[node_at as usize + left as usize..][..8]) & !0x7,
            ));
        }
        out.sort_by_key(|allocation| allocation.address.0);
        Ok(out)
    }

    /// Decode the VS subsegment occupying a page range: header, then the
    /// chunk chain, each header XORed with the heap key and its own address.
    pub fn vs_subsegment(&self, heap: &SegmentHeap, range: &PageRange) -> Result<VsSubsegment> {
        let layout = self.layout("_HEAP_VS_SUBSEGMENT")?;
        let image = self.read_struct(&layout, range.address)?;
        let size_units = layout.read(&image, 0, "Size")?;
        let signature = layout.read(&image, 0, "Signature")? as u16;
        let signature_ok = signature == (size_units as u16 ^ VS_SUBSEGMENT_SIGNATURE_KEY) & 0x7FFF;
        let first_chunk = range.address + (layout.size() as u64).next_multiple_of(HEAP_GRANULE);
        let size = (size_units * HEAP_GRANULE)
            .min(range.size().saturating_sub(first_chunk.0 - range.address.0));
        let bytes = self.read_prefix(first_chunk, size as usize);
        let mut chunks = Vec::new();
        let mut at = 0u64;
        while at + HEAP_GRANULE <= bytes.len() as u64 && chunks.len() < MAX_ENTRIES {
            let address = first_chunk + at;
            let header =
                le_uint(&bytes[at as usize..at as usize + 8]) ^ heap.keys.heap_key ^ address.0;
            let chunk_size = ((header >> 16) & 0xFFFF) * HEAP_GRANULE;
            let bits = le_uint(&bytes[at as usize + 8..at as usize + 12]) as u32;
            let unused_flagged = bits & 0x100 != 0;
            let busy = (header >> 48) & 0xFF != 0;
            let unused_bytes = (busy && unused_flagged && chunk_size >= HEAP_GRANULE + 2)
                .then(|| {
                    let tail = (at + chunk_size - 2) as usize;
                    bytes
                        .get(tail..tail + 2)
                        .map(|word| le_uint(word) as u16 & 0x1FFF)
                })
                .flatten();
            chunks.push(VsChunk {
                address,
                size: chunk_size,
                previous_size: ((header >> 32) & 0xFFFF) * HEAP_GRANULE,
                busy,
                unused_bytes,
            });
            if chunk_size == 0 {
                break;
            }
            at += chunk_size;
        }
        Ok(VsSubsegment {
            address: range.address,
            signature_ok,
            chunks,
        })
    }

    /// Decode the LFH subsegment occupying a page range. The block geometry
    /// is XORed with the LFH key and the subsegment's page number.
    pub fn lfh_subsegment(&self, heap: &SegmentHeap, range: &PageRange) -> Result<LfhSubsegment> {
        let layout = self.layout("_HEAP_LFH_SUBSEGMENT")?;
        let image = self.read_struct(&layout, range.address)?;
        let block_count = layout.read(&image, 0, "BlockCount")? as u32;
        let encoded = layout.read(&image, 0, "BlockOffsets")? as u32;
        let decoded = encoded ^ heap.keys.lfh_key as u32 ^ (range.address.0 >> 12) as u32;
        let block_size = u64::from(decoded & 0xFFFF);
        let first_offset = u64::from(decoded >> 16);
        let words = (block_count as usize).div_ceil(32);
        let bitmap = self
            .read(
                range.address + layout.offset("BlockBitmap")? as u64,
                words * 8,
            )?
            .chunks_exact(8)
            .map(le_uint)
            .collect();
        Ok(LfhSubsegment {
            address: range.address,
            block_size,
            block_count,
            free_count: layout.read(&image, 0, "FreeCount")? as u32,
            bucket: layout.read(&image, 0, "BucketRef")? as u16,
            first_block: range.address + first_offset,
            bitmap,
        })
    }
}

// ------------------------------------------------------------- lookup

/// Where an address lands inside a heap.
#[derive(Clone, Debug)]
pub enum BlockMatch {
    NtEntry {
        segment: VirtAddr,
        entry: NtEntry,
    },
    NtLfhBlock {
        segment: VirtAddr,
        entry: NtEntry,
        region: NtUserBlocks,
        index: u32,
    },
    NtVirtual(NtVirtualBlock),
    /// Inside a segment but not on the chain: the heap header, an
    /// uncommitted range, or past where the walk had to stop.
    NtSegmentOnly {
        segment: VirtAddr,
        stopped: Option<(VirtAddr, &'static str)>,
    },
    Direct(PageRange),
    VsChunk {
        range: PageRange,
        subsegment: VirtAddr,
        chunk: VsChunk,
    },
    LfhBlock {
        range: PageRange,
        subsegment: LfhSubsegment,
        index: u32,
    },
    /// Inside a page range but outside its subsegment's blocks (header,
    /// bitmap, or trailing slack).
    RangeOnly(PageRange),
    Large(LargeAllocation),
}

impl HeapReader<'_> {
    pub fn find_in_nt(&self, heap: &NtHeap, address: VirtAddr) -> Result<Option<BlockMatch>> {
        for block in &heap.virtual_blocks {
            if (block.entry.0..block.entry.0 + block.reserve_size.max(block.commit_size))
                .contains(&address.0)
            {
                return Ok(Some(BlockMatch::NtVirtual(block.clone())));
            }
        }
        let Some(segment) = heap
            .segments
            .iter()
            .find(|segment| segment.contains(address))
        else {
            return Ok(None);
        };
        if segment
            .uncommitted
            .iter()
            .any(|range| range.contains(&address.0))
        {
            return Ok(Some(BlockMatch::NtSegmentOnly {
                segment: segment.address,
                stopped: None,
            }));
        }
        let walk = self.nt_segment_entries(heap, segment);
        let Some(entry) = walk
            .entries
            .iter()
            .find(|entry| (entry.address.0..entry.end().0).contains(&address.0))
            .copied()
        else {
            return Ok(Some(BlockMatch::NtSegmentOnly {
                segment: segment.address,
                stopped: walk.stopped,
            }));
        };
        if let Some(region) = self.nt_user_blocks(heap, &entry)? {
            let first = region.first_block.0;
            if address.0 >= first {
                let index = (address.0 - first) / region.stride;
                if index < u64::from(region.block_count) {
                    return Ok(Some(BlockMatch::NtLfhBlock {
                        segment: segment.address,
                        entry,
                        region,
                        index: index as u32,
                    }));
                }
            }
        }
        Ok(Some(BlockMatch::NtEntry {
            segment: segment.address,
            entry,
        }))
    }

    pub fn find_in_segment(
        &self,
        heap: &SegmentHeap,
        address: VirtAddr,
    ) -> Result<Option<BlockMatch>> {
        if let Some(large) = heap
            .large_allocations
            .iter()
            .find(|allocation| allocation.contains(address))
        {
            return Ok(Some(BlockMatch::Large(*large)));
        }
        let Some(range) = heap
            .contexts
            .iter()
            .flat_map(|context| &context.segments)
            .flat_map(|segment| &segment.ranges)
            .find(|range| range.contains(address))
            .copied()
        else {
            return Ok(None);
        };
        match range.kind {
            RangeKind::Vs => {
                let subsegment = self.vs_subsegment(heap, &range)?;
                Ok(Some(
                    match subsegment
                        .chunks
                        .iter()
                        .find(|chunk| (chunk.address.0..chunk.end().0).contains(&address.0))
                    {
                        Some(chunk) => BlockMatch::VsChunk {
                            range,
                            subsegment: subsegment.address,
                            chunk: *chunk,
                        },
                        None => BlockMatch::RangeOnly(range),
                    },
                ))
            }
            RangeKind::Lfh => {
                let subsegment = self.lfh_subsegment(heap, &range)?;
                let first = subsegment.first_block.0;
                if subsegment.block_size != 0 && address.0 >= first {
                    let index = (address.0 - first) / subsegment.block_size;
                    if index < u64::from(subsegment.block_count) {
                        return Ok(Some(BlockMatch::LfhBlock {
                            range,
                            subsegment,
                            index: index as u32,
                        }));
                    }
                }
                Ok(Some(BlockMatch::RangeOnly(range)))
            }
            RangeKind::Direct => Ok(Some(BlockMatch::Direct(range))),
            RangeKind::Free | RangeKind::Unused => Ok(Some(BlockMatch::RangeOnly(range))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nt_entry_headers_decode_through_the_heap_encoding() {
        // spoolsv.exe on a live target: the raw header XOR 0x8b99e6560e37 is
        // size 0x50, busy, checksum-clean, previous 0x740, 0x14 unused.
        let encoding = 0x8b99_e656_0e37u64;
        let plain = [0x05u8, 0x00, 0x01, 0x04, 0x74, 0x00, 0x00, 0x14];
        let raw = u64::from_le_bytes(plain) ^ encoding;
        let entry = decode_nt_entry(VirtAddr(0x1190740), raw, Some(encoding));
        assert_eq!(entry.size, 0x50);
        assert_eq!(entry.previous_size, 0x740);
        assert!(entry.busy());
        assert!(entry.checksum_ok);
        assert_eq!(entry.unused_bytes, 0x14);
        assert_eq!(entry.user_size(), 0x50 - 0x10 - 0x14);

        let corrupt = decode_nt_entry(VirtAddr(0x1190740), raw ^ 0x100, Some(encoding));
        assert!(!corrupt.checksum_ok);
    }

    #[test]
    fn lfh_bitmaps_hold_thirty_two_blocks_per_word() {
        let subsegment = LfhSubsegment {
            address: VirtAddr(0x1000),
            block_size: 0x30,
            block_count: 40,
            free_count: 3,
            bucket: 0,
            first_block: VirtAddr(0x1060),
            // Blocks 0 and 33 busy; the high halves are not block state.
            bitmap: vec![0xFFFF_FFFF_0000_0001, 0xFFFF_FFFF_0000_0002],
        };
        assert!(subsegment.is_busy(0));
        assert!(!subsegment.is_busy(1));
        assert!(!subsegment.is_busy(32));
        assert!(subsegment.is_busy(33));
        assert_eq!(subsegment.busy_count(), 2);
        assert_eq!(subsegment.block(33), VirtAddr(0x1060 + 33 * 0x30));
    }
}
