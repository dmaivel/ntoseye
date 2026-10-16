//! User-mode heap decoding for `!heap`: the NT heap (`_HEAP`, front-ended by
//! the legacy LFH) and the segment heap (`_SEGMENT_HEAP`, with VS and LFH
//! sub-allocators and large allocations). Layouts come from the PDB; the
//! encodings ntdll applies to headers are the one thing the PDB cannot say
//! and are pinned here, verified against live targets.

use std::sync::Arc;

use ntoseye_macros::record;

use crate::error::{Error, Result};
use crate::layout::{ParsedType, TypeInfo, le_uint};
use crate::memory::{AddressSpace, MemoryOps};
use crate::phys::PhysMem;
use crate::target::{DiagnosticValue, ListCursor, Target};
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

/// `nt`, `segment`, or `unknown (<signature>)`.
impl std::fmt::Display for HeapKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Nt => f.write_str("nt"),
            Self::Segment => f.write_str("segment"),
            Self::Unknown(signature) => write!(f, "unknown ({signature:#x})"),
        }
    }
}

fn busy_state(busy: bool) -> &'static str {
    if busy { "busy" } else { "free" }
}

#[derive(Clone, Debug)]
pub struct ProcessHeap {
    pub index: usize,
    pub address: VirtAddr,
    pub kind: HeapKind,
    /// Classification can fail when one heap pointer is unreadable; callers
    /// can keep that item in a listing instead of losing the whole PEB list.
    pub classification_error: Option<String>,
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
        let info = self.0.field(field)?;
        let start = at + info.offset as usize;
        let size = info.size.clamp(1, 8) as usize;
        let slice = buf.get(start..start + size).ok_or_else(|| {
            Error::DebugInfo(format!("{}.{field} is outside the read", self.0.name))
        })?;
        Ok(info.decode(le_uint(slice)))
    }

    /// Element count of an array field, from its byte size and the element layout.
    fn array_len(&self, field: &str, element: &Layout) -> Result<usize> {
        let info = self.0.field(field)?;
        match &info.type_data {
            ParsedType::Array(_, count) => Ok(*count as usize),
            _ if element.size() != 0 => Ok(info.size as usize / element.size()),
            _ => Err(Error::FieldTypeMismatch(field.to_string(), "array".into())),
        }
    }
}

/// Everything a walk needs: the process address space and the heap layouts.
/// A native process uses the kernel PDB's (ntdll and ntoskrnl share the heap
/// source, so the layouts match the build); a WOW64 process's heaps are the
/// 32-bit ntdll's, so its layouts, keys, and pointer width come from
/// `ntdll32`.
pub struct HeapReader<'a> {
    target: &'a Target,
    dtb: Dtb,
    memory: AddressSpace<'a, PhysMem>,
    ntdll: &'static str,
    pointer_size: usize,
}

impl<'a> HeapReader<'a> {
    pub fn new(target: &'a Target, dtb: Dtb, wow64: bool) -> Self {
        Self {
            target,
            dtb,
            memory: target.address_space(dtb),
            ntdll: if wow64 { "ntdll32" } else { "ntdll" },
            pointer_size: if wow64 { 4 } else { 8 },
        }
    }

    fn layout(&self, name: &str) -> Result<Layout> {
        let qualified;
        let name = if self.pointer_size == 4 {
            qualified = format!("{}!{name}", self.ntdll);
            qualified.as_str()
        } else {
            name
        };
        self.target
            .symbols
            .find_type_across_modules(self.dtb, name)
            .map(Layout)
            .ok_or_else(|| Error::StructNotFound(name.to_string()))
    }

    /// The layout a struct-typed field of `layout` has (`BusyBitmap` is an
    /// `_RTL_BITMAP_EX` on x64 and an `_RTL_BITMAP` on x86).
    fn field_layout(&self, layout: &Layout, field: &str) -> Result<Layout> {
        let info = layout.0.field(field)?;
        let name = match &info.type_data {
            ParsedType::Struct(name) | ParsedType::Union(name) => name,
            _ => return Err(Error::FieldTypeMismatch(field.to_string(), "struct".into())),
        };
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

    fn read_pointer(&self, address: VirtAddr) -> Result<u64> {
        let mut bytes = [0u8; 8];
        self.memory
            .read_bytes(address, &mut bytes[..self.pointer_size])?;
        Ok(le_uint(&bytes[..self.pointer_size]))
    }

    /// A symbol of the ntdll this process's heaps belong to.
    fn symbol(&self, name: &str) -> Result<VirtAddr> {
        let name = format!("{}!{name}", self.ntdll);
        self.target
            .symbols
            .find_symbol_across_modules(self.dtb, &name)?
            .ok_or_else(|| {
                Error::DebugInfo(format!(
                    "{name} is not resolvable; {} symbols are required",
                    self.ntdll
                ))
            })
    }

    /// Records of an intrusive `_LIST_ENTRY` list, given the head and the
    /// link's offset inside each record. Bounded and cycle-safe.
    fn list(&self, head: VirtAddr, link_offset: u64) -> Result<Vec<VirtAddr>> {
        let mut records = Vec::new();
        let mut cursor = ListCursor::new(head, MAX_LIST);
        cursor.advance(Ok(VirtAddr(self.read_pointer(head)?)));
        while let Some(link) = cursor.take_current() {
            records.push(VirtAddr(link.0.wrapping_sub(link_offset)));
            cursor.advance(Ok(VirtAddr(self.read_pointer(link)?)));
        }
        Ok(records)
    }

    /// The heaps `_PEB.ProcessHeaps` lists, classified by signature. `peb` is
    /// the 32-bit PEB for a WOW64 process.
    pub fn process_heaps(&self, peb: VirtAddr) -> Result<Vec<ProcessHeap>> {
        self.process_heaps_with_status(peb).map(|(heaps, _)| heaps)
    }

    /// As [`Self::process_heaps`], also reporting whether `MAX_HEAPS` clipped
    /// the advertised PEB list.
    pub fn process_heaps_with_status(&self, peb: VirtAddr) -> Result<(Vec<ProcessHeap>, bool)> {
        let peb_layout = self.layout("_PEB")?;
        let image = self.read_struct(&peb_layout, peb)?;
        let count = peb_layout.read(&image, 0, "NumberOfHeaps")? as usize;
        let table = VirtAddr(peb_layout.read(&image, 0, "ProcessHeaps")?);
        if count == 0 || table.is_zero() {
            return Ok((Vec::new(), false));
        }
        let truncated = count > MAX_HEAPS;
        let count = count.min(MAX_HEAPS);
        let pointers = self.read(table, count * self.pointer_size)?;
        let heaps = pointers
            .chunks_exact(self.pointer_size)
            .enumerate()
            .map(|(index, bytes)| {
                let address = VirtAddr(le_uint(bytes));
                let (kind, classification_error) = match self.classify(address) {
                    Ok(kind) => (kind, None),
                    Err(error) => (HeapKind::Unknown(0), Some(error.to_string())),
                };
                Ok(ProcessHeap {
                    index,
                    address,
                    kind,
                    classification_error,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok((heaps, truncated))
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

/// An NT (`_HEAP`) heap.
#[record]
pub struct NtHeap {
    pub address: VirtAddr,
    /// `_HEAP.Flags`.
    #[record(hex)]
    pub flags: u32,
    /// `_HEAP.ForceFlags`.
    #[record(hex)]
    pub force_flags: u32,
    /// The size in bytes of the `_HEAP_ENTRY` that starts each block: 16 on
    /// x64 (a private-data qword, then the metadata qword), 8 on x86 (the
    /// metadata qword alone). Block sizes are in this unit.
    pub granule: u64,
    /// The XOR mask on the metadata of each entry header. None if the
    /// headers are not encoded.
    #[record(hex)]
    pub encoding: Option<u64>,
    /// The free space, in granules.
    pub total_free_units: u64,
    /// `_HEAP.VirtualMemoryThreshold`, in granules.
    pub virtual_threshold: u32,
    /// The front-end (LFH) heap. None if the heap has no front end.
    pub front_end: Option<VirtAddr>,
    /// `_HEAP.FrontEndHeapType`.
    pub front_end_type: u8,
    /// The segments, as decoded; `NtHeapDetail.segments` has them with
    /// their entries.
    #[record(skip)]
    pub segments: Vec<NtSegment>,
    /// Blocks that are too large for a segment, which the heap allocates
    /// separately.
    pub virtual_blocks: Vec<NtVirtualBlock>,
}

/// One `_HEAP_SEGMENT` of an NT heap.
#[record(impl)]
pub struct NtSegment {
    /// The segment header.
    pub address: VirtAddr,
    /// The first byte of the segment.
    pub base: VirtAddr,
    pub pages: u32,
    pub uncommitted_pages: u32,
    pub first_entry: VirtAddr,
    pub last_valid_entry: VirtAddr,
    /// The uncommitted ranges that the entry chain skips.
    pub uncommitted: Vec<NtUncommittedRange>,
}

#[record]
impl NtSegment {
    /// The first byte after the last page of the segment.
    #[record(getter)]
    pub fn end(&self) -> VirtAddr {
        VirtAddr(self.base.0 + u64::from(self.pages) * PAGE)
    }

    pub fn contains(&self, address: VirtAddr) -> bool {
        (self.base.0..self.end().0).contains(&address.0)
    }
}

/// An uncommitted range of an NT-heap segment.
#[record]
#[derive(Copy)]
pub struct NtUncommittedRange {
    #[record(hex)]
    pub start: u64,
    /// The first byte after the range.
    #[record(hex)]
    pub end: u64,
}

impl NtUncommittedRange {
    pub fn contains(&self, address: u64) -> bool {
        (self.start..self.end).contains(&address)
    }
}

/// An NT-heap block with a separate allocation (`_HEAP_VIRTUAL_ALLOC_ENTRY`).
#[record]
pub struct NtVirtualBlock {
    /// The block header.
    pub entry: VirtAddr,
    /// Committed bytes.
    pub commit_size: u64,
    /// Reserved bytes.
    pub reserve_size: u64,
    /// First user byte: the header's `BusyBlock` is the last thing before
    /// it.
    pub user: VirtAddr,
}

/// An NT-heap entry (`_HEAP_ENTRY`), decoded from its header.
#[record(impl)]
#[derive(Copy)]
pub struct NtEntry {
    /// The entry header.
    pub address: VirtAddr,
    /// The size in bytes, with the header.
    pub size: u64,
    /// The size in bytes of the previous entry.
    pub previous_size: u64,
    /// The flags byte of the header.
    #[record(hex)]
    pub flags: u8,
    /// The number of unused bytes at the end of the block.
    pub unused_bytes: u8,
    /// The header size in bytes (see [`NtHeap::granule`]).
    pub granule: u64,
    /// Whether the XOR checksum of the header is correct. Always true if the
    /// headers are not encoded.
    pub checksum_ok: bool,
}

#[record]
impl NtEntry {
    pub fn busy(&self) -> bool {
        self.flags & NT_ENTRY_BUSY != 0
    }

    /// `busy` or `free`.
    #[record(getter)]
    pub fn state(&self) -> &'static str {
        busy_state(self.busy())
    }

    /// First user byte.
    #[record(getter)]
    pub fn user(&self) -> VirtAddr {
        self.address + self.granule
    }

    pub fn end(&self) -> VirtAddr {
        self.address + self.size
    }

    /// The number of bytes that the caller requested: the block size minus
    /// the header and the unused bytes.
    #[record(getter)]
    pub fn user_size(&self) -> u64 {
        self.size
            .saturating_sub(self.granule)
            .saturating_sub(u64::from(self.unused_bytes & !NT_ENTRY_LFH_BLOCK))
    }
}

/// One segment's entry chain and, when it ended before `LastValidEntry`,
/// where and why.
#[derive(Clone, Debug)]
pub struct NtWalk {
    pub entries: Vec<NtEntry>,
    pub stopped: Option<HeapWalkStop>,
}

/// A legacy-LFH user block region in one busy NT-heap entry.
#[record(impl)]
pub struct NtUserBlocks {
    /// The `_HEAP_USERDATA_HEADER`.
    pub header: VirtAddr,
    /// The `_HEAP_SUBSEGMENT` that owns the region.
    pub subsegment: VirtAddr,
    /// Bytes per block.
    pub block_size: u64,
    pub block_count: u32,
    pub first_block: VirtAddr,
    /// The distance in bytes between consecutive blocks.
    pub stride: u64,
    /// One bit for each block, set if the block is busy (`_RTL_BITMAP` bit
    /// order: block `i` is byte `i / 8`, bit `i % 8`).
    #[record(bytes)]
    pub busy: Vec<u8>,
}

#[record]
impl NtUserBlocks {
    pub fn is_busy(&self, index: u32) -> bool {
        self.busy
            .get(index as usize / 8)
            .is_some_and(|byte| byte >> (index % 8) & 1 != 0)
    }

    #[record(getter)]
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
        let granule = self.layout("_HEAP_ENTRY")?.size() as u64;
        let encoding = decode_nt_heap_encoding(
            &image,
            encode_mask & NT_HEAP_ENCODING_ACTIVE != 0,
            heap.offset("Encoding"),
            granule,
        )?;
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
            granule,
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
            uncommitted.push(NtUncommittedRange {
                start,
                end: start.saturating_add(size),
            });
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
        let granule = heap.granule;
        let metadata = granule as usize - 8;
        // One read per committed run rather than one per entry.
        let mut run: Option<(VirtAddr, Vec<u8>)> = None;
        while cursor < end && entries.len() < MAX_ENTRIES {
            if self.target.interrupted() {
                stopped = Some((cursor, "interrupted"));
                break;
            }
            if let Some(gap) = segment
                .uncommitted
                .iter()
                .find(|range| range.contains(cursor.0))
            {
                cursor = VirtAddr(gap.end);
                run = None;
                continue;
            }
            let raw = match &run {
                Some((start, bytes))
                    if cursor >= *start && cursor.0 + granule <= start.0 + bytes.len() as u64 =>
                {
                    let at = (cursor.0 - start.0) as usize + metadata;
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
                    if bytes.len() < granule as usize {
                        stopped = Some((cursor, "header is not readable (page not resident)"));
                        break;
                    }
                    let raw = le_uint(&bytes[metadata..metadata + 8]);
                    run = Some((cursor, bytes));
                    raw
                }
            };
            let entry = decode_nt_entry(cursor, raw, heap.encoding, granule);
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
        if stopped.is_none() && cursor < end && entries.len() >= MAX_ENTRIES {
            stopped = Some((cursor, "entry walk reached its bound"));
        }
        NtWalk {
            entries,
            stopped: stopped.map(|(address, reason)| HeapWalkStop {
                address,
                reason: reason.to_string(),
            }),
        }
    }

    /// The legacy-LFH user block region a busy backend entry holds, if any.
    pub fn nt_user_blocks(&self, heap: &NtHeap, entry: &NtEntry) -> Result<Option<NtUserBlocks>> {
        let Some(lfh) = heap.front_end.filter(|_| entry.busy()) else {
            return Ok(None);
        };
        let header_layout = self.layout("_HEAP_USERDATA_HEADER")?;
        let header = entry.user();
        if entry.size < header_layout.size() as u64 + heap.granule {
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
        let block_size = subsegment_layout.read(&subsegment_image, 0, "BlockSize")? * heap.granule;
        // `EncodedOffsets` is XORed with the region, the LFH key, and the front
        // end it belongs to.
        let key = self.read_pointer(self.symbol("RtlpLFHKey")?)?;
        let encoded = header_layout.read(&image, 0, "EncodedOffsets")? as u32;
        let decoded = encoded ^ header.0 as u32 ^ key as u32 ^ lfh.0 as u32;
        let first_offset = u64::from(decoded & 0xFFFF);
        let stride = u64::from(decoded >> 16);
        if stride == 0 || first_offset == 0 {
            return Ok(None);
        }
        let bitmap_layout = self.field_layout(&header_layout, "BusyBitmap")?;
        let bitmap_at = header_layout.offset("BusyBitmap")?;
        let bits = bitmap_layout.read(&image, bitmap_at, "SizeOfBitMap")? as u32;
        let buffer = VirtAddr(bitmap_layout.read(&image, bitmap_at, "Buffer")?);
        let words = (bits.max(block_count) as usize).div_ceil(self.pointer_size * 8);
        let busy = self.read(buffer, words * self.pointer_size)?;
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

fn decode_nt_heap_encoding(
    image: &[u8],
    active: bool,
    encoding_offset: Result<usize>,
    granule: u64,
) -> Result<Option<u64>> {
    if !active {
        return Ok(None);
    }
    let encoding_offset = encoding_offset?;
    let granule = usize::try_from(granule)
        .map_err(|_| Error::DebugInfo("NT heap granule does not fit host address size".into()))?;
    let at = encoding_offset
        .checked_add(granule)
        .and_then(|offset| offset.checked_sub(8))
        .ok_or_else(|| Error::DebugInfo("invalid NT heap encoding offset".into()))?;
    let end = at
        .checked_add(8)
        .ok_or_else(|| Error::DebugInfo("NT heap encoding offset overflow".into()))?;
    let bytes = image
        .get(at..end)
        .ok_or_else(|| Error::DebugInfo("NT heap encoding extends beyond heap image".into()))?;
    Ok(Some(le_uint(bytes)))
}

fn decode_nt_entry(address: VirtAddr, raw: u64, encoding: Option<u64>, granule: u64) -> NtEntry {
    let decoded = raw ^ encoding.unwrap_or(0);
    let bytes = decoded.to_le_bytes();
    let checksum = bytes[0] ^ bytes[1] ^ bytes[2];
    NtEntry {
        address,
        size: u64::from(u16::from_le_bytes([bytes[0], bytes[1]])) * granule,
        previous_size: u64::from(u16::from_le_bytes([bytes[4], bytes[5]])) * granule,
        flags: bytes[2],
        unused_bytes: bytes[7],
        granule,
        checksum_ok: encoding.is_none() || checksum == bytes[3],
    }
}

/// A segment heap (`_SEGMENT_HEAP`).
#[record]
pub struct SegmentHeap {
    pub address: VirtAddr,
    /// `_SEGMENT_HEAP.GlobalFlags`.
    #[record(hex)]
    pub global_flags: u32,
    pub reserved_pages: u64,
    pub committed_pages: u64,
    pub free_committed_pages: u64,
    pub lfh_free_committed_pages: u64,
    pub vs_free_committed_pages: u64,
    pub large_reserved_pages: u64,
    pub large_committed_pages: u64,
    /// The segment contexts, as decoded; `SegmentHeapDetail.contexts` has
    /// them with their ranges.
    #[record(skip)]
    pub contexts: Vec<SegContext>,
    pub large_allocations: Vec<LargeAllocation>,
    /// `ntdll!RtlpHpHeapGlobals`: the VS header key and the LFH offsets key.
    #[record(rename = "keys")]
    pub encoding_keys: SegmentKeys,
    /// The size in bytes of the `_HEAP_VS_CHUNK_HEADER` that starts each VS
    /// chunk: 16 on x64, 8 on x86. Chunk sizes are in this unit.
    pub granule: u64,
}

/// `ntdll!RtlpHpHeapGlobals`: the encoding keys of a segment heap.
#[record]
#[derive(Copy)]
pub struct SegmentKeys {
    /// The VS chunk header key (`HeapKey`).
    #[record(hex)]
    pub heap_key: u64,
    /// The LFH block-offsets key (`LfhKey`).
    #[record(hex)]
    pub lfh_key: u64,
}

/// A segment context (`_HEAP_SEG_CONTEXT`) of a segment heap.
#[record(impl)]
pub struct SegContext {
    /// Position in `SegContexts`.
    pub index: usize,
    /// log2 of `unit_size`.
    pub unit_shift: u8,
    #[record(hex)]
    pub segment_mask: u64,
    /// The maximum allocation size for this context, in bytes.
    pub max_allocation_size: u32,
    /// The page segments, as decoded; `SegmentContextDetail.segments` has
    /// them with their ranges.
    #[record(skip)]
    pub segments: Vec<PageSegment>,
}

#[record]
impl SegContext {
    /// Bytes per page-range unit.
    #[record(getter)]
    pub fn unit_size(&self) -> u64 {
        1 << self.unit_shift
    }

    /// Bytes per page segment.
    #[record(getter)]
    pub fn segment_size(&self) -> u64 {
        (!self.segment_mask).wrapping_add(1)
    }
}

/// A page segment (`_HEAP_PAGE_SEGMENT`) of a segment context.
#[record]
pub struct PageSegment {
    pub address: VirtAddr,
    /// The page ranges, as decoded; `SegmentPageDetail.ranges` has them
    /// with their subsegments.
    #[record(skip)]
    pub ranges: Vec<PageRange>,
}

/// What a page range holds: `unused`, `free`, `page` (allocated directly
/// from the segment), `vs`, or `lfh`.
#[record]
#[derive(Copy, PartialEq, Eq)]
pub enum RangeKind {
    /// Never handed out; past the segment's high-water mark.
    Unused,
    Free,
    /// Pages allocated straight from the segment for one block.
    Direct,
    Vs,
    Lfh,
}

impl RangeKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Unused => "unused",
            Self::Free => "free",
            Self::Direct => "page",
            Self::Vs => "vs",
            Self::Lfh => "lfh",
        }
    }
}

impl std::fmt::Display for RangeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// A page range (`_HEAP_PAGE_RANGE_DESCRIPTOR`) of a page segment.
#[record(impl)]
#[derive(Copy)]
pub struct PageRange {
    pub address: VirtAddr,
    pub units: u64,
    /// Bytes per unit.
    pub unit_size: u64,
    /// The descriptor's `RangeFlags`.
    #[record(hex)]
    pub flags: u8,
    pub committed_pages: u8,
    /// The number of unused bytes at the end of the range.
    pub unused_bytes: u32,
    pub kind: RangeKind,
}

#[record]
impl PageRange {
    /// The size in bytes: `units * unit_size`.
    #[record(getter)]
    pub fn size(&self) -> u64 {
        self.units * self.unit_size
    }

    /// The first byte after the range.
    #[record(getter)]
    pub fn end(&self) -> VirtAddr {
        self.address + self.size()
    }

    pub fn contains(&self, address: VirtAddr) -> bool {
        (self.address.0..self.end().0).contains(&address.0)
    }
}

/// A segment-heap variable-size subsegment (`_HEAP_VS_SUBSEGMENT`).
#[record(impl)]
pub struct VsSubsegment {
    pub address: VirtAddr,
    /// Whether the signature of the subsegment matches the expected value.
    pub signature_ok: bool,
    /// The chunks, as decoded; `SegmentRangeDetail.blocks` lists them when
    /// the entries were listed.
    #[record(skip)]
    pub chunks: Vec<VsChunk>,
}

#[record]
impl VsSubsegment {
    /// The number of chunks that the walk found.
    #[record(getter)]
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }
}

/// A segment-heap VS chunk, decoded from its header.
#[record(impl)]
#[derive(Copy)]
pub struct VsChunk {
    pub address: VirtAddr,
    /// The size in bytes, with the header.
    pub size: u64,
    /// The size in bytes of the previous chunk.
    pub previous_size: u64,
    pub busy: bool,
    /// The header size in bytes (see [`SegmentHeap::granule`]).
    pub granule: u64,
    /// The number of unused bytes, as recorded in the last word of the
    /// chunk. None if the header records no unused bytes.
    pub unused_bytes: Option<u16>,
}

#[record]
impl VsChunk {
    /// First user byte.
    #[record(getter)]
    pub fn user(&self) -> VirtAddr {
        self.address + self.granule
    }

    pub fn end(&self) -> VirtAddr {
        self.address + self.size
    }

    /// The number of bytes that the caller can use.
    #[record(getter)]
    pub fn user_size(&self) -> u64 {
        self.size
            .saturating_sub(self.granule)
            .saturating_sub(u64::from(self.unused_bytes.unwrap_or(0)))
    }
}

/// A segment-heap LFH subsegment (`_HEAP_LFH_SUBSEGMENT`).
#[record(impl)]
pub struct LfhSubsegment {
    pub address: VirtAddr,
    /// Bytes per block.
    pub block_size: u64,
    pub block_count: u32,
    pub free_count: u32,
    /// The LFH bucket of the subsegment.
    pub bucket: u16,
    pub first_block: VirtAddr,
    /// The `BlockBitmap` words (a qword on x64, a dword on x86), each
    /// holding `blocks_per_word` blocks: the low bit for a block is set
    /// while the block is busy.
    #[record(hex)]
    pub bitmap: Vec<u64>,
    pub blocks_per_word: u32,
}

#[record]
impl LfhSubsegment {
    pub fn is_busy(&self, index: u32) -> bool {
        self.bitmap
            .get((index / self.blocks_per_word) as usize)
            .is_some_and(|word| word >> (index % self.blocks_per_word) & 1 != 0)
    }

    #[record(getter)]
    pub fn busy_count(&self) -> u32 {
        (0..self.block_count).filter(|i| self.is_busy(*i)).count() as u32
    }

    pub fn block(&self, index: u32) -> VirtAddr {
        self.first_block + u64::from(index) * self.block_size
    }
}

/// A segment-heap large allocation (`_HEAP_LARGE_ALLOC_DATA`).
#[record(impl)]
#[derive(Copy)]
pub struct LargeAllocation {
    /// The metadata record of the allocation.
    pub metadata: VirtAddr,
    pub address: VirtAddr,
    pub pages: u64,
    /// The number of unused bytes at the end of the allocation.
    pub unused_bytes: u16,
    pub extra_present: bool,
}

#[record]
impl LargeAllocation {
    /// The size in bytes: `pages` pages.
    #[record(getter)]
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
        let granule = self.layout("_HEAP_VS_CHUNK_HEADER")?.size() as u64;
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
            encoding_keys: keys,
            granule,
        })
    }

    fn segment_keys(&self) -> Result<SegmentKeys> {
        let globals = self.layout("_RTLP_HP_HEAP_GLOBALS")?;
        let address = self.symbol("RtlpHpHeapGlobals")?;
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
        // A 32-bit mask (`0xFFF00000`) must complement within its own width.
        let width_mask = u64::MAX >> (64 - 8 * self.pointer_size);
        Ok(SegContext {
            index,
            unit_shift,
            segment_mask: layout.read(image, at, "SegmentMask")? | !width_mask,
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
        let child = |image: &[u8], at: u64| {
            let at = (node_at + at) as usize;
            VirtAddr(le_uint(&image[at..at + self.pointer_size]) & !0x7)
        };
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
            out.push(LargeAllocation {
                metadata: record,
                address: VirtAddr(virtual_address & !0xFFFF),
                pages: data.read(&image, 0, "AllocatedPages")?,
                unused_bytes: data.read(&image, 0, "UnusedBytes")? as u16,
                extra_present: data.read(&image, 0, "ExtraPresent")? != 0,
            });
            stack.push(child(&image, right));
            stack.push(child(&image, left));
        }
        out.sort_by_key(|allocation| allocation.address.0);
        Ok(out)
    }

    /// Decode the VS subsegment occupying a page range: header, then the
    /// chunk chain, each header's `Sizes` XORed with the heap key and its own
    /// address; the bit layout of the decoded sizes is the PDB's.
    pub fn vs_subsegment(&self, heap: &SegmentHeap, range: &PageRange) -> Result<VsSubsegment> {
        let layout = self.layout("_HEAP_VS_SUBSEGMENT")?;
        let image = self.read_struct(&layout, range.address)?;
        let size_units = layout.read(&image, 0, "Size")?;
        let signature = layout.read(&image, 0, "Signature")? as u16;
        let signature_ok = signature == (size_units as u16 ^ VS_SUBSEGMENT_SIGNATURE_KEY) & 0x7FFF;
        let granule = heap.granule;
        let chunk_layout = self.layout("_HEAP_VS_CHUNK_HEADER")?;
        let sizes_layout = self.field_layout(&chunk_layout, "Sizes")?;
        let sizes_at = chunk_layout.offset("Sizes")?;
        let sizes_len = sizes_layout.size();
        let first_chunk = range.address + (layout.size() as u64).next_multiple_of(granule);
        let size = (size_units * granule)
            .min(range.size().saturating_sub(first_chunk.0 - range.address.0));
        let bytes = self.read_prefix(first_chunk, size as usize);
        let mut chunks = Vec::new();
        let mut at = 0u64;
        while at + granule <= bytes.len() as u64 && chunks.len() < MAX_ENTRIES {
            let address = first_chunk + at;
            let header = &bytes[at as usize..at as usize + granule as usize];
            let mut decoded = header.to_vec();
            let sizes = le_uint(&header[sizes_at..sizes_at + sizes_len])
                ^ heap.encoding_keys.heap_key
                ^ address.0;
            decoded[sizes_at..sizes_at + sizes_len]
                .copy_from_slice(&sizes.to_le_bytes()[..sizes_len]);
            let chunk_size = sizes_layout.read(&decoded, sizes_at, "UnsafeSize")? * granule;
            let previous_size = sizes_layout.read(&decoded, sizes_at, "UnsafePrevSize")? * granule;
            let busy = sizes_layout.read(&decoded, sizes_at, "Allocated")? != 0;
            let unused_flagged = chunk_layout.read(header, 0, "UnusedBytes")? != 0;
            let unused_bytes = (busy && unused_flagged && chunk_size >= granule + 2)
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
                previous_size,
                busy,
                granule,
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
        let decoded = encoded ^ heap.encoding_keys.lfh_key as u32 ^ (range.address.0 >> 12) as u32;
        let block_size = u64::from(decoded & 0xFFFF);
        let first_offset = u64::from(decoded >> 16);
        let word_size = layout
            .0
            .fields
            .get("BlockBitmap")
            .and_then(|info| match &info.type_data {
                ParsedType::Array(_, count) if *count > 0 => Some(info.size / u64::from(*count)),
                _ => None,
            })
            .filter(|size| matches!(size, 4 | 8))
            .ok_or_else(|| Error::FieldTypeMismatch("BlockBitmap".into(), "word array".into()))?
            as usize;
        let blocks_per_word = (word_size * 4) as u32;
        let words = (block_count as usize).div_ceil(word_size * 4);
        let bitmap = self
            .read(
                range.address + layout.offset("BlockBitmap")? as u64,
                words * word_size,
            )?
            .chunks_exact(word_size)
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
            blocks_per_word,
        })
    }
}

/// Where a searched address lands inside a heap, told apart by `kind`.
#[record(tagged)]
pub enum BlockMatch {
    /// Inside an NT-heap entry.
    #[record(rename = "nt-entry")]
    NtEntry {
        /// The `_HEAP_SEGMENT` that contains the entry.
        segment: VirtAddr,
        entry: NtEntry,
    },
    /// Inside a legacy-LFH block of an NT heap: block `index` of the user
    /// block `region` in the busy `entry`.
    #[record(rename = "nt-lfh-block")]
    NtLfhBlock {
        segment: VirtAddr,
        entry: NtEntry,
        region: NtUserBlocks,
        index: u32,
    },
    /// Inside an NT-heap virtually allocated block.
    #[record(rename = "nt-virtual")]
    NtVirtual(#[record(rename = "block")] NtVirtualBlock),
    /// Inside a segment but not on the chain: the heap header, an
    /// uncommitted range, or past where the walk had to stop.
    #[record(rename = "nt-segment")]
    NtSegmentOnly {
        segment: VirtAddr,
        /// Where the entry walk stopped, and why. None if the walk did not
        /// stop early.
        stopped: Option<HeapWalkStop>,
    },
    /// A segment-heap range that the heap allocated directly from its
    /// segment.
    #[record(rename = "page")]
    Direct(#[record(rename = "range")] PageRange),
    /// Inside a segment-heap VS chunk.
    #[record(rename = "vs-chunk")]
    VsChunk {
        range: PageRange,
        /// The `_HEAP_VS_SUBSEGMENT` that contains the chunk.
        #[record(rename = "vs_subsegment")]
        subsegment: VirtAddr,
        chunk: VsChunk,
    },
    /// Inside block `index` of a segment-heap LFH subsegment.
    #[record(rename = "lfh-block")]
    LfhBlock {
        range: PageRange,
        subsegment: LfhSubsegment,
        index: u32,
    },
    /// Inside a page range but outside its subsegment's blocks (header,
    /// bitmap, or trailing slack).
    #[record(rename = "range")]
    RangeOnly(#[record(rename = "range")] PageRange),
    /// Inside a segment-heap large allocation.
    #[record(rename = "large")]
    Large(#[record(rename = "allocation")] LargeAllocation),
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
            .any(|range| range.contains(address.0))
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

#[derive(Debug, Clone)]
pub struct HeapSummaryDetail {
    pub peb: VirtAddr,
    pub heaps: Vec<HeapSummaryItem>,
    /// True when the PEB advertised more than `MAX_HEAPS` entries.
    pub truncated: bool,
}

#[derive(Debug, Clone)]
pub struct HeapSummaryItem {
    pub index: usize,
    pub address: VirtAddr,
    pub kind: HeapKind,
    /// Heap-wide sizes and allocator counts.  An unavailable value contains
    /// the layout, memory, or symbol error for this heap only.
    pub stats: DiagnosticValue<HeapSummaryStats>,
}

#[derive(Debug, Clone)]
pub struct HeapSummaryStats {
    pub flags: u32,
    pub reserved: u64,
    pub committed: u64,
    pub free: u64,
    pub segments: u64,
    pub virtual_blocks: u64,
    pub front_end: Option<VirtAddr>,
    pub vs_subsegments: u64,
    pub lfh_subsegments: u64,
    pub page_allocations: u64,
    pub large_allocations: u64,
}

/// One decoded heap (`!heap -h|-a <heap>`, `Heap.inspect()`).
#[record(impl)]
pub struct HeapDetail {
    /// Position in the PEB heap list.
    pub index: usize,
    pub address: VirtAddr,
    #[record(skip)]
    pub kind: HeapKind,
    /// Whether ntoseye walked and listed the entries, chunks, and blocks.
    pub list_entries: bool,
    /// The NT (`_HEAP`) decoding. None for other heap kinds or if the
    /// decoding failed.
    pub nt: Option<NtHeapDetail>,
    /// The segment-heap decoding. None for other heap kinds or if the
    /// decoding failed.
    pub segment: Option<SegmentHeapDetail>,
    /// The reason that ntoseye could not decode the heap.
    pub error: Option<String>,
}

#[record]
impl HeapDetail {
    /// `nt`, `segment`, or `unknown (<signature>)`.
    #[record(getter, rename = "kind")]
    pub fn kind_name(&self) -> String {
        self.kind.to_string()
    }
}

/// An NT heap with its segments.
#[record]
pub struct NtHeapDetail {
    pub heap: NtHeap,
    pub segments: Vec<NtSegmentDetail>,
}

/// An NT-heap segment with its entry chain.
#[record]
pub struct NtSegmentDetail {
    pub segment: NtSegment,
    /// The entry chain of the segment. Empty unless the entries were listed.
    pub entries: Vec<NtEntryDetail>,
    /// Where the chain walk stopped before `last_valid_entry`, and why. None
    /// if the walk did not stop before `last_valid_entry`.
    pub stopped: Option<HeapWalkStop>,
}

/// An NT-heap entry with the legacy-LFH region it holds.
#[record]
pub struct NtEntryDetail {
    pub entry: NtEntry,
    /// The legacy-LFH user block region in this busy entry. `None` if the
    /// entry has no region or ntoseye cannot read it.
    pub lfh: Option<NtUserBlocks>,
    /// The blocks of the region.
    pub lfh_blocks: Vec<HeapBlock>,
    /// Whether `lfh_blocks` stops at the walk limit.
    pub lfh_truncated: bool,
    /// The reason that ntoseye could not read the LFH region of the entry.
    pub lfh_error: Option<String>,
}

/// The address where a heap walk stopped, and the reason.
#[record]
pub struct HeapWalkStop {
    pub address: VirtAddr,
    pub reason: String,
}

/// A segment heap with its segment contexts.
#[record]
pub struct SegmentHeapDetail {
    pub heap: SegmentHeap,
    pub contexts: Vec<SegmentContextDetail>,
}

/// A segment context with its page segments.
#[record]
pub struct SegmentContextDetail {
    pub context: SegContext,
    pub segments: Vec<SegmentPageDetail>,
}

/// A page segment with its page ranges.
#[record]
pub struct SegmentPageDetail {
    pub segment: PageSegment,
    pub ranges: Vec<SegmentRangeDetail>,
}

/// A page range with its decoded subsegment.
#[record]
pub struct SegmentRangeDetail {
    pub range: PageRange,
    /// The VS or LFH subsegment in the range. `None` for other kinds, or if
    /// ntoseye cannot read the subsegment.
    pub subsegment: Option<SegmentSubsegment>,
    /// The VS chunks or LFH blocks of the subsegment. Empty unless the
    /// entries were listed.
    pub blocks: Vec<HeapBlock>,
    /// The reason that ntoseye could not read the subsegment.
    pub error: Option<String>,
    /// Whether the subsegment has more blocks than the walk limit.
    pub truncated: bool,
}

/// A page range's subsegment: VS or LFH.
#[record]
pub enum SegmentSubsegment {
    Vs(VsSubsegment),
    Lfh(LfhSubsegment),
}

/// One block of a heap walk: an NT legacy-LFH block, a segment-heap VS
/// chunk, or a segment-heap LFH block.
#[record]
pub struct HeapBlock {
    pub address: VirtAddr,
    /// The size in bytes, with the header.
    pub size: u64,
    /// The size in bytes of the previous block. None if the block kind
    /// does not record it.
    pub previous_size: Option<u64>,
    /// The header flags. None if the block kind has no header of its own.
    #[record(hex)]
    pub flags: Option<u32>,
    /// `busy` or `free`.
    pub state: &'static str,
    /// `nt-lfh-block`, `vs-chunk`, or `lfh-block`.
    pub kind: &'static str,
    /// The number of unused bytes at the end of the block. None if the
    /// block does not record them.
    pub unused_bytes: Option<u64>,
    /// Whether the header checksum is correct. None if the block kind has
    /// no checksum.
    pub checksum_ok: Option<bool>,
    /// First user byte.
    pub user: Option<VirtAddr>,
    /// The number of bytes that the caller can use.
    pub user_size: Option<u64>,
    /// The position in the region or subsegment. None for VS chunks.
    pub index: Option<u32>,
}

/// A heap, identified by its PEB-list position, address, and kind.
#[record(impl)]
pub struct HeapIdentity {
    /// Position in the PEB heap list.
    pub index: usize,
    pub address: VirtAddr,
    #[record(skip)]
    pub kind: HeapKind,
}

#[record]
impl HeapIdentity {
    /// `nt`, `segment`, or `unknown (<signature>)`.
    #[record(getter, rename = "kind")]
    pub fn kind_name(&self) -> String {
        self.kind.to_string()
    }
}

/// The heap block that contains an address (`!heap -x <addr>`,
/// `Heaps.find_block()`).
#[record]
pub struct HeapBlockSearch {
    /// The search address.
    pub address: VirtAddr,
    /// Whether a heap contains the address.
    pub found: bool,
    /// Whether the PEB listed more heaps than the search bound, in which
    /// case the search may have missed the block.
    pub truncated: bool,
    /// The heap that contains the address. None if no heap contains it.
    pub heap: Option<HeapIdentity>,
    /// The location of the address in the heap. None if no heap contains
    /// it.
    pub block: Option<BlockMatch>,
    /// The heaps that ntoseye could not search, and the reasons.
    pub errors: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeapSelector {
    Index(usize),
    Address(VirtAddr),
}

fn heap_summary_stats(
    reader: &HeapReader<'_>,
    heap: &ProcessHeap,
) -> DiagnosticValue<HeapSummaryStats> {
    if let Some(error) = heap.classification_error.as_ref() {
        return DiagnosticValue::unavailable(error.clone());
    }
    match heap.kind {
        HeapKind::Nt => DiagnosticValue::from_result(reader.nt_heap(heap.address).map(|nt| {
            let reserved: u64 = nt
                .segments
                .iter()
                .map(|segment| u64::from(segment.pages) * PAGE)
                .sum();
            let uncommitted: u64 = nt
                .segments
                .iter()
                .map(|segment| u64::from(segment.uncommitted_pages) * PAGE)
                .sum();
            HeapSummaryStats {
                flags: nt.flags,
                reserved,
                committed: reserved.saturating_sub(uncommitted),
                free: nt.total_free_units.saturating_mul(16),
                segments: nt.segments.len() as u64,
                virtual_blocks: nt.virtual_blocks.len() as u64,
                front_end: nt.front_end,
                vs_subsegments: 0,
                lfh_subsegments: 0,
                page_allocations: 0,
                large_allocations: 0,
            }
        })),
        HeapKind::Segment => {
            DiagnosticValue::from_result(reader.segment_heap(heap.address).map(|segment| {
                let count = |kind: RangeKind| {
                    segment
                        .contexts
                        .iter()
                        .flat_map(|context| &context.segments)
                        .flat_map(|page_segment| &page_segment.ranges)
                        .filter(|range| range.kind == kind)
                        .count() as u64
                };
                HeapSummaryStats {
                    flags: segment.global_flags,
                    reserved: segment.reserved_pages.saturating_mul(PAGE),
                    committed: segment.committed_pages.saturating_mul(PAGE),
                    free: segment.free_committed_pages.saturating_mul(PAGE),
                    segments: segment
                        .contexts
                        .iter()
                        .map(|context| context.segments.len() as u64)
                        .sum(),
                    virtual_blocks: 0,
                    front_end: None,
                    vs_subsegments: count(RangeKind::Vs),
                    lfh_subsegments: count(RangeKind::Lfh),
                    page_allocations: count(RangeKind::Direct),
                    large_allocations: segment.large_allocations.len() as u64,
                }
            }))
        }
        HeapKind::Unknown(signature) => DiagnosticValue::unavailable(format!(
            "heap carries neither heap signature (found {signature:#x})"
        )),
    }
}

fn nt_lfh_block_detail(region: &NtUserBlocks, entry: &NtEntry, index: u32) -> HeapBlock {
    let address = region.block(index);
    HeapBlock {
        address,
        size: region.block_size,
        previous_size: None,
        flags: None,
        state: if region.is_busy(index) {
            "busy"
        } else {
            "free"
        },
        kind: "nt-lfh-block",
        unused_bytes: None,
        checksum_ok: None,
        user: Some(address + entry.granule),
        user_size: Some(region.block_size.saturating_sub(entry.granule)),
        index: Some(index),
    }
}

fn vs_block_detail(chunk: &VsChunk) -> HeapBlock {
    HeapBlock {
        address: chunk.address,
        size: chunk.size,
        previous_size: Some(chunk.previous_size),
        flags: None,
        state: if chunk.busy { "busy" } else { "free" },
        kind: "vs-chunk",
        unused_bytes: chunk.unused_bytes.map(u64::from),
        checksum_ok: None,
        user: Some(chunk.user()),
        user_size: Some(chunk.user_size()),
        index: None,
    }
}

fn lfh_block_detail(subsegment: &LfhSubsegment, index: u32) -> HeapBlock {
    let address = subsegment.block(index);
    HeapBlock {
        address,
        size: subsegment.block_size,
        previous_size: None,
        flags: None,
        state: if subsegment.is_busy(index) {
            "busy"
        } else {
            "free"
        },
        kind: "lfh-block",
        unused_bytes: None,
        checksum_ok: None,
        user: Some(address),
        user_size: Some(subsegment.block_size),
        index: Some(index),
    }
}

fn nt_heap_detail(reader: &HeapReader<'_>, heap: &NtHeap, list_entries: bool) -> NtHeapDetail {
    let segments = heap
        .segments
        .iter()
        .map(|segment| {
            let (entries, stopped) = if list_entries {
                let walk = reader.nt_segment_entries(heap, segment);
                let entries = walk
                    .entries
                    .iter()
                    .map(|entry| {
                        let (lfh, lfh_error) = match reader.nt_user_blocks(heap, entry) {
                            Ok(region) => (region, None),
                            Err(error) => (None, Some(error.to_string())),
                        };
                        let (lfh_blocks, lfh_truncated) =
                            lfh.as_ref().map_or((Vec::new(), false), |region| {
                                let count = region.block_count.min(MAX_ENTRIES as u32);
                                (
                                    (0..count)
                                        .map(|index| nt_lfh_block_detail(region, entry, index))
                                        .collect(),
                                    region.block_count > count,
                                )
                            });
                        NtEntryDetail {
                            entry: *entry,
                            lfh,
                            lfh_blocks,
                            lfh_truncated,
                            lfh_error,
                        }
                    })
                    .collect();
                (entries, walk.stopped)
            } else {
                (Vec::new(), None)
            };
            NtSegmentDetail {
                segment: segment.clone(),
                entries,
                stopped,
            }
        })
        .collect();
    NtHeapDetail {
        heap: heap.clone(),
        segments,
    }
}

fn segment_heap_detail(
    reader: &HeapReader<'_>,
    heap: &SegmentHeap,
    list_entries: bool,
) -> SegmentHeapDetail {
    let contexts = heap
        .contexts
        .iter()
        .map(|context| {
            let segments = context
                .segments
                .iter()
                .map(|segment| {
                    let ranges = segment
                        .ranges
                        .iter()
                        .map(|range| {
                            let (subsegment, error) = match range.kind {
                                RangeKind::Vs => match reader.vs_subsegment(heap, range) {
                                    Ok(subsegment) => {
                                        (Some(SegmentSubsegment::Vs(subsegment)), None)
                                    }
                                    Err(error) => (None, Some(error.to_string())),
                                },
                                RangeKind::Lfh => match reader.lfh_subsegment(heap, range) {
                                    Ok(subsegment) => {
                                        (Some(SegmentSubsegment::Lfh(subsegment)), None)
                                    }
                                    Err(error) => (None, Some(error.to_string())),
                                },
                                RangeKind::Unused | RangeKind::Free | RangeKind::Direct => {
                                    (None, None)
                                }
                            };
                            let truncated = match &subsegment {
                                Some(SegmentSubsegment::Vs(subsegment)) => {
                                    subsegment.chunks.len() >= MAX_ENTRIES
                                }
                                Some(SegmentSubsegment::Lfh(subsegment)) => {
                                    u64::from(subsegment.block_count) > MAX_ENTRIES as u64
                                }
                                None => false,
                            };
                            let blocks = if list_entries {
                                match &subsegment {
                                    Some(SegmentSubsegment::Vs(subsegment)) => {
                                        subsegment.chunks.iter().map(vs_block_detail).collect()
                                    }
                                    Some(SegmentSubsegment::Lfh(subsegment)) => {
                                        let count = subsegment.block_count.min(MAX_ENTRIES as u32);
                                        (0..count)
                                            .map(|index| lfh_block_detail(subsegment, index))
                                            .collect()
                                    }
                                    None => Vec::new(),
                                }
                            } else {
                                Vec::new()
                            };
                            SegmentRangeDetail {
                                range: *range,
                                subsegment,
                                blocks,
                                error,
                                truncated,
                            }
                        })
                        .collect();
                    SegmentPageDetail {
                        segment: segment.clone(),
                        ranges,
                    }
                })
                .collect();
            SegmentContextDetail {
                context: context.clone(),
                segments,
            }
        })
        .collect();
    SegmentHeapDetail {
        heap: heap.clone(),
        contexts,
    }
}

impl Target {
    fn heap_context(&self) -> Result<(Dtb, VirtAddr, bool)> {
        // A user-mode minidump is its one process: the selected thread's TEB
        // names the PEB, and the captured memory serves every root.
        if let Some(peb) = self.user_dump_pseudo_register("peb") {
            let peb = peb.ok_or_else(|| {
                Error::DebugInfo(
                    "the PEB's address is unknown: the minidump does not hold the selected thread's TEB"
                        .into(),
                )
            })?;
            return Ok((self.current_dtb(), VirtAddr(peb), false));
        }
        let process = self.attached_process().ok_or_else(|| {
            Error::DebugInfo("this command requires an attached user process".into())
        })?;
        let wow64 = process.wow64_peb.is_some();
        let peb = if let Some(peb) = process.wow64_peb {
            peb
        } else {
            let eprocess = self
                .guest()?
                .ntoskrnl
                .types_in(process.dtb)
                .struct_at("_EPROCESS", process.eprocess)?;
            let peb = eprocess.follow("Peb")?.addr();
            if peb.is_zero() {
                return Err(Error::MissingPEB);
            }
            peb
        };
        Ok((process.dtb, peb, wow64))
    }

    /// Decode the attached process's PEB heap list.  `stats` is unavailable
    /// for an individual heap when its signature, layout, memory, or required
    /// symbols cannot be read; other heaps remain in the returned list.
    pub fn heap_summary(&self) -> Result<HeapSummaryDetail> {
        let (dtb, peb, wow64) = self.heap_context()?;
        let reader = HeapReader::new(self, dtb, wow64);
        let (heaps, truncated) = reader.process_heaps_with_status(peb)?;
        Ok(HeapSummaryDetail {
            peb,
            truncated,
            heaps: heaps
                .iter()
                .map(|heap| HeapSummaryItem {
                    index: heap.index,
                    address: heap.address,
                    kind: heap.kind,
                    stats: heap_summary_stats(&reader, heap),
                })
                .collect(),
        })
    }

    /// Decode one selected NT or segment heap, including its segments and,
    /// when `list_entries` is true, every bounded entry/chunk/block.  The
    /// selected heap's `error` contains an unavailable layout, memory, or
    /// symbol failure; per-entry LFH and subsegment failures stay beside the
    /// affected item instead of discarding the rest of the detail.
    pub fn inspect_heap(&self, heap: HeapSelector, list_entries: bool) -> Result<HeapDetail> {
        let (dtb, peb, wow64) = self.heap_context()?;
        let reader = HeapReader::new(self, dtb, wow64);
        let heaps = reader.process_heaps(peb)?;
        let selected = match heap {
            HeapSelector::Index(index) => heaps.iter().find(|heap| heap.index == index),
            HeapSelector::Address(address) => heaps.iter().find(|heap| heap.address == address),
        }
        .ok_or_else(|| {
            let value = match heap {
                HeapSelector::Index(index) => index as u64,
                HeapSelector::Address(address) => address.0,
            };
            Error::DebugInfo(format!(
                "{} is neither a heap index (0..{}) nor a heap in the PEB list",
                VirtAddr(value),
                heaps.len()
            ))
        })?;
        let mut detail = HeapDetail {
            index: selected.index,
            address: selected.address,
            kind: selected.kind,
            list_entries,
            nt: None,
            segment: None,
            error: selected.classification_error.clone(),
        };
        if detail.error.is_some() {
            return Ok(detail);
        }
        match selected.kind {
            HeapKind::Nt => match reader.nt_heap(selected.address) {
                Ok(heap) => detail.nt = Some(nt_heap_detail(&reader, &heap, list_entries)),
                Err(error) => detail.error = Some(error.to_string()),
            },
            HeapKind::Segment => match reader.segment_heap(selected.address) {
                Ok(heap) => {
                    detail.segment = Some(segment_heap_detail(&reader, &heap, list_entries))
                }
                Err(error) => detail.error = Some(error.to_string()),
            },
            HeapKind::Unknown(signature) => {
                detail.error = Some(format!(
                    "heap carries neither heap signature (found {signature:#x})"
                ));
            }
        }
        Ok(detail)
    }

    /// Find the heap and allocator block containing `address`.  `errors`
    /// records per-heap layout, memory, and symbol failures encountered while
    /// searching; `found` is false with no `heap`/`block` when no allocation
    /// contains the address.
    pub fn find_heap_block(&self, address: VirtAddr) -> Result<HeapBlockSearch> {
        let (dtb, peb, wow64) = self.heap_context()?;
        let reader = HeapReader::new(self, dtb, wow64);
        let (heaps, truncated) = reader.process_heaps_with_status(peb)?;
        let mut errors = Vec::new();
        for heap in heaps {
            if let Some(error) = heap.classification_error {
                errors.push(format!("heap {}: {error}", heap.address));
                continue;
            }
            let found = match heap.kind {
                HeapKind::Nt => match reader.nt_heap(heap.address) {
                    Ok(nt) => reader.find_in_nt(&nt, address),
                    Err(error) => {
                        errors.push(format!("heap {}: {error}", heap.address));
                        continue;
                    }
                },
                HeapKind::Segment => match reader.segment_heap(heap.address) {
                    Ok(segment) => reader.find_in_segment(&segment, address),
                    Err(error) => {
                        errors.push(format!("heap {}: {error}", heap.address));
                        continue;
                    }
                },
                HeapKind::Unknown(_) => Ok(None),
            };
            let block = match found {
                Ok(block) => block,
                Err(error) => {
                    errors.push(format!("heap {}: {error}", heap.address));
                    continue;
                }
            };
            if let Some(block) = block {
                return Ok(HeapBlockSearch {
                    address,
                    found: true,
                    truncated,
                    heap: Some(HeapIdentity {
                        index: heap.index,
                        address: heap.address,
                        kind: heap.kind,
                    }),
                    block: Some(block),
                    errors,
                });
            }
        }
        Ok(HeapBlockSearch {
            address,
            found: false,
            truncated,
            heap: None,
            block: None,
            errors,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_nt_heap_encoding_requires_its_layout_field() {
        assert!(
            decode_nt_heap_encoding(
                &[0; 16],
                true,
                Err(Error::DebugInfo("missing Encoding".to_string())),
                16,
            )
            .is_err()
        );
    }

    #[test]
    fn active_nt_heap_encoding_rejects_truncated_metadata() {
        assert!(decode_nt_heap_encoding(&[0; 16], true, Ok(0x100), 16).is_err());
    }

    #[test]
    fn nt_entry_headers_decode_through_the_heap_encoding() {
        // spoolsv.exe on a live target: the raw header XOR 0x8b99e6560e37 is
        // size 0x50, busy, checksum-clean, previous 0x740, 0x14 unused.
        let encoding = 0x8b99_e656_0e37u64;
        let plain = [0x05u8, 0x00, 0x01, 0x04, 0x74, 0x00, 0x00, 0x14];
        let raw = u64::from_le_bytes(plain) ^ encoding;
        let entry = decode_nt_entry(VirtAddr(0x1190740), raw, Some(encoding), 16);
        assert_eq!(entry.size, 0x50);
        assert_eq!(entry.previous_size, 0x740);
        assert!(entry.busy());
        assert!(entry.checksum_ok);
        assert_eq!(entry.unused_bytes, 0x14);
        assert_eq!(entry.user_size(), 0x50 - 0x10 - 0x14);

        let corrupt = decode_nt_entry(VirtAddr(0x1190740), raw ^ 0x100, Some(encoding), 16);
        assert!(!corrupt.checksum_ok);

        // The same header bytes in an x86 heap are 8-byte units behind an
        // 8-byte header.
        let x86 = decode_nt_entry(VirtAddr(0x1190740), raw, Some(encoding), 8);
        assert_eq!(x86.size, 0x28);
        assert_eq!(x86.user(), VirtAddr(0x1190748));
        assert_eq!(x86.user_size(), 0x28 - 8 - 0x14);
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
            blocks_per_word: 32,
        };
        assert!(subsegment.is_busy(0));
        assert!(!subsegment.is_busy(1));
        assert!(!subsegment.is_busy(32));
        assert!(subsegment.is_busy(33));
        assert_eq!(subsegment.busy_count(), 2);
        assert_eq!(subsegment.block(33), VirtAddr(0x1060 + 33 * 0x30));
    }
}
