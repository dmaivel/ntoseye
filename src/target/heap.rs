//! User-mode heap decoding for `!heap`: the NT heap (`_HEAP`, front-ended by
//! the legacy LFH) and the segment heap (`_SEGMENT_HEAP`, with VS and LFH
//! sub-allocators and large allocations). Layouts come from the PDB; the
//! encodings ntdll applies to headers are the one thing the PDB cannot say
//! and are pinned here, verified against live targets.

use std::ops::Range;
use std::sync::Arc;

use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::layout::{ParsedType, TypeInfo, le_uint};
use crate::memory::AddressSpace;
use crate::phys::PhysMem;
use crate::target::{DiagnosticValue, Target};
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

impl HeapKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Nt => "nt",
            Self::Segment => "segment",
            Self::Unknown(_) => "unknown",
        }
    }
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
        let mut link = VirtAddr(self.read_pointer(head)?);
        while link != head && !link.is_zero() && records.len() < MAX_LIST {
            let record = VirtAddr(link.0.wrapping_sub(link_offset));
            if records.contains(&record) {
                break;
            }
            records.push(record);
            link = VirtAddr(self.read_pointer(link)?);
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

#[derive(Clone, Debug)]
pub struct NtHeap {
    pub address: VirtAddr,
    pub flags: u32,
    pub force_flags: u32,
    /// Size of `_HEAP_ENTRY`: 16 on x64 (a private-data qword, then the
    /// metadata qword), 8 on x86 (the metadata qword alone). Block sizes are
    /// in this unit and it is the header every block starts with.
    pub granule: u64,
    /// XOR mask over the metadata qword of every `_HEAP_ENTRY`, when active.
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
    /// See [`NtHeap::granule`].
    pub granule: u64,
    /// The header's own XOR checksum held.
    pub checksum_ok: bool,
}

impl NtEntry {
    pub fn busy(&self) -> bool {
        self.flags & NT_ENTRY_BUSY != 0
    }

    pub fn user(&self) -> VirtAddr {
        self.address + self.granule
    }

    pub fn end(&self) -> VirtAddr {
        self.address + self.size
    }

    /// Bytes the caller asked for: the block less its header and slack.
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
    /// One bit per block, set when busy (`_RTL_BITMAP` bit order: bit `i`
    /// is byte `i / 8`, bit `i % 8`).
    pub busy: Vec<u8>,
}

impl NtUserBlocks {
    pub fn is_busy(&self, index: u32) -> bool {
        self.busy
            .get(index as usize / 8)
            .is_some_and(|byte| byte >> (index % 8) & 1 != 0)
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
                .find(|range| range.contains(&cursor.0))
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
        NtWalk { entries, stopped }
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
    /// Size of `_HEAP_VS_CHUNK_HEADER`: 16 on x64, 8 on x86. Chunk sizes are
    /// in this unit and it is the header every chunk starts with.
    pub granule: u64,
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
    /// See [`SegmentHeap::granule`].
    pub granule: u64,
    /// Slack recorded in the chunk's last word, when the header says so.
    pub unused_bytes: Option<u16>,
}

impl VsChunk {
    pub fn user(&self) -> VirtAddr {
        self.address + self.granule
    }

    pub fn end(&self) -> VirtAddr {
        self.address + self.size
    }

    pub fn user_size(&self) -> u64 {
        self.size
            .saturating_sub(self.granule)
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
    /// Bitmap words (`BlockBitmap`'s element width: a qword on x64, a dword
    /// on x86), each holding `blocks_per_word` blocks: the low half's bit is
    /// set while the block is busy.
    pub bitmap: Vec<u64>,
    pub blocks_per_word: u32,
}

impl LfhSubsegment {
    pub fn is_busy(&self, index: u32) -> bool {
        self.bitmap
            .get((index / self.blocks_per_word) as usize)
            .is_some_and(|word| word >> (index % self.blocks_per_word) & 1 != 0)
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
            keys,
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
            let sizes =
                le_uint(&header[sizes_at..sizes_at + sizes_len]) ^ heap.keys.heap_key ^ address.0;
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
        let decoded = encoded ^ heap.keys.lfh_key as u32 ^ (range.address.0 >> 12) as u32;
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
    pub front_end_type: u8,
    pub vs_subsegments: u64,
    pub lfh_subsegments: u64,
    pub page_allocations: u64,
    pub large_allocations: u64,
}

#[derive(Debug, Clone)]
pub struct HeapDetail {
    pub index: usize,
    pub address: VirtAddr,
    pub kind: HeapKind,
    pub list_entries: bool,
    pub nt: Option<NtHeapDetail>,
    pub segment: Option<SegmentHeapDetail>,
    /// A failed decode for the selected heap.  The summary path instead
    /// records the same failure in its per-item [`DiagnosticValue`].
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NtHeapDetail {
    pub heap: NtHeap,
    pub segments: Vec<NtSegmentDetail>,
}

#[derive(Debug, Clone)]
pub struct NtSegmentDetail {
    pub segment: NtSegment,
    pub entries: Vec<NtEntryDetail>,
    pub stopped: Option<HeapWalkStop>,
}

#[derive(Debug, Clone)]
pub struct NtEntryDetail {
    pub entry: NtEntry,
    pub lfh: Option<NtUserBlocks>,
    /// Materialized legacy-LFH blocks when entry listing was requested.
    pub lfh_blocks: Vec<HeapBlockDetail>,
    pub lfh_truncated: bool,
    pub lfh_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HeapWalkStop {
    pub address: VirtAddr,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct SegmentHeapDetail {
    pub heap: SegmentHeap,
    pub contexts: Vec<SegmentContextDetail>,
}

#[derive(Debug, Clone)]
pub struct SegmentContextDetail {
    pub context: SegContext,
    pub segments: Vec<SegmentPageDetail>,
}

#[derive(Debug, Clone)]
pub struct SegmentPageDetail {
    pub segment: PageSegment,
    pub ranges: Vec<SegmentRangeDetail>,
}

#[derive(Debug, Clone)]
pub struct SegmentRangeDetail {
    pub range: PageRange,
    pub subsegment: Option<SegmentSubsegment>,
    /// Materialized VS chunks or segment-LFH blocks when entry listing was
    /// requested.  The allocator-specific subsegment retains its raw data.
    pub blocks: Vec<HeapBlockDetail>,
    pub error: Option<String>,
    /// True when the VS chunk walk reached `MAX_ENTRIES`.
    pub truncated: bool,
}

#[derive(Debug, Clone)]
pub enum SegmentSubsegment {
    Vs(VsSubsegment),
    Lfh(LfhSubsegment),
}

#[derive(Debug, Clone)]
pub struct HeapBlockDetail {
    pub address: VirtAddr,
    pub size: u64,
    pub previous_size: Option<u64>,
    pub flags: Option<u32>,
    pub state: &'static str,
    pub kind: &'static str,
    pub unused_bytes: Option<u64>,
    pub checksum_ok: Option<bool>,
    pub user: Option<VirtAddr>,
    pub user_size: Option<u64>,
    pub index: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct HeapIdentity {
    pub index: usize,
    pub address: VirtAddr,
    pub kind: HeapKind,
}

#[derive(Debug, Clone)]
pub struct HeapBlockSearchDetail {
    pub address: VirtAddr,
    pub found: bool,
    /// True when the PEB advertised more than `MAX_HEAPS` and the search
    /// could not inspect entries past that bound.
    pub truncated: bool,
    pub heap: Option<HeapIdentity>,
    pub block: Option<BlockMatch>,
    /// Decode failures from heaps examined before a match (or before the
    /// not-found result).  A malformed heap does not hide later heaps.
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
        return DiagnosticValue::Unavailable(error.clone());
    }
    match heap.kind {
        HeapKind::Nt => match reader.nt_heap(heap.address) {
            Ok(nt) => {
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
                DiagnosticValue::Available(HeapSummaryStats {
                    flags: nt.flags,
                    reserved,
                    committed: reserved.saturating_sub(uncommitted),
                    free: nt.total_free_units.saturating_mul(16),
                    segments: nt.segments.len() as u64,
                    virtual_blocks: nt.virtual_blocks.len() as u64,
                    front_end: nt.front_end,
                    front_end_type: nt.front_end_type,
                    vs_subsegments: 0,
                    lfh_subsegments: 0,
                    page_allocations: 0,
                    large_allocations: 0,
                })
            }
            Err(error) => DiagnosticValue::Unavailable(error.to_string()),
        },
        HeapKind::Segment => match reader.segment_heap(heap.address) {
            Ok(segment) => {
                let count = |kind: RangeKind| {
                    segment
                        .contexts
                        .iter()
                        .flat_map(|context| &context.segments)
                        .flat_map(|page_segment| &page_segment.ranges)
                        .filter(|range| range.kind == kind)
                        .count() as u64
                };
                DiagnosticValue::Available(HeapSummaryStats {
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
                    front_end_type: 0,
                    vs_subsegments: count(RangeKind::Vs),
                    lfh_subsegments: count(RangeKind::Lfh),
                    page_allocations: count(RangeKind::Direct),
                    large_allocations: segment.large_allocations.len() as u64,
                })
            }
            Err(error) => DiagnosticValue::Unavailable(error.to_string()),
        },
        HeapKind::Unknown(signature) => DiagnosticValue::Unavailable(format!(
            "heap carries neither heap signature (found {signature:#x})"
        )),
    }
}

fn nt_lfh_block_detail(region: &NtUserBlocks, entry: &NtEntry, index: u32) -> HeapBlockDetail {
    let address = region.block(index);
    HeapBlockDetail {
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

fn vs_block_detail(chunk: &VsChunk) -> HeapBlockDetail {
    HeapBlockDetail {
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

fn lfh_block_detail(subsegment: &LfhSubsegment, index: u32) -> HeapBlockDetail {
    let address = subsegment.block(index);
    HeapBlockDetail {
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
                (
                    entries,
                    walk.stopped.map(|(address, reason)| HeapWalkStop {
                        address,
                        reason: reason.to_string(),
                    }),
                )
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
                .struct_at("_EPROCESS", process.eprocess_va)?;
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
    pub fn find_heap_block(&self, address: VirtAddr) -> Result<HeapBlockSearchDetail> {
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
                return Ok(HeapBlockSearchDetail {
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
        Ok(HeapBlockSearchDetail {
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
