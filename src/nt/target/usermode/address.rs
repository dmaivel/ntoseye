//! `!address` on a user-mode minidump: the regions its memory-info list
//! records, what each is used for as far as the dump shows it, and how much
//! of each the dump captured.
//!
//! Usage comes only from what the dump already holds: its module list
//! (images), its threads' stacks and TEBs, the PEB, and the heaps the PEB's
//! `ProcessHeaps` array names when that array was captured. A region none
//! of these explain is `<unknown>`, not guessed at.

use ntoseye_macros::record;

use crate::base::error::{Error, Result};
use crate::base::memory::MemoryOps;
use crate::base::types::VirtAddr;
use crate::nt::target::Target;
use crate::nt::target::mm::{
    MEM_COMMIT, MEM_FREE, MEM_IMAGE, memory_state_name, memory_type_name, page_protection_name,
};
use crate::nt::userdump::{MemoryRange, MemoryRegion};

/// The bytes a 64-bit TEB spans: two pages (the structure is 0x1878 bytes on
/// Windows 10 and 11, on AMD64 and ARM64).
const TEB_SPAN: u64 = 0x2000;
/// The bytes a 64-bit PEB spans: one page.
const PEB_SPAN: u64 = 0x1000;
/// `NT_TIB64.StackBase` and `NT_TIB64.StackLimit`, at the start of a 64-bit
/// TEB (the `NT_TIB` layout is part of the Windows ABI).
const TIB64_STACK_BASE: u64 = 0x8;
const TIB64_STACK_LIMIT: u64 = 0x10;
/// The most `ProcessHeaps` entries read; the loader's own limit is far
/// lower.
const MAX_PROCESS_HEAPS: u32 = 1024;

/// What a region of the address space is used for: `Free`, `Image`,
/// `Stack`, `TEB`, `PEB`, `Heap`, or `<unknown>` (in use, for nothing the
/// dump identifies).
#[record]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RegionUsage {
    #[record(label = "Free")]
    Free,
    #[record(label = "Image")]
    Image,
    #[record(label = "Stack")]
    Stack,
    #[record(label = "TEB")]
    Teb,
    #[record(label = "PEB")]
    Peb,
    #[record(label = "Heap")]
    Heap,
    /// In use, for nothing the dump identifies.
    #[record(label = "<unknown>")]
    Unknown,
}

/// A thread's stack, as its TEB's `NT_TIB` bounds it, else as far as the
/// dump captured it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackSource {
    pub low: u64,
    pub high: u64,
    /// `~0; 10f4.cc4`.
    pub thread: String,
}

/// What the dump shows of the address space's users.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UsageSources {
    /// `(base, end, name)` of each module the dump's module list records.
    pub modules: Vec<(u64, u64, String)>,
    pub stacks: Vec<StackSource>,
    /// `(TEB, thread)` of each thread.
    pub tebs: Vec<(u64, String)>,
    pub peb: Option<u64>,
    /// The heap handles `PEB.ProcessHeaps` holds, in its order.
    pub heaps: Vec<u64>,
}

/// One region of a user-mode minidump's memory-info list (`!address`),
/// with what the dump shows uses it and how much of it the dump holds.
#[record(impl)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRegion {
    /// The region, as `VirtualQueryEx` reported it.
    #[record(rename = "info")]
    pub region: MemoryRegion,
    pub usage: RegionUsage,
    /// The module, thread, or heap the usage names.
    pub detail: Option<String>,
    /// Bytes of the region the dump captured.
    #[record(hex)]
    pub captured: u64,
}

#[record]
impl UserRegion {
    /// The end of the region (exclusive).
    #[record(getter, hex)]
    pub fn end(&self) -> u64 {
        self.region.base.saturating_add(self.region.size)
    }
}

/// One captured range of a dump without a memory-info list, with the usage
/// the dump shows for its start.
#[record]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedRange {
    #[record(hex)]
    pub start: u64,
    #[record(hex)]
    pub length: u64,
    pub usage: RegionUsage,
    /// The module, thread, or heap the usage names.
    pub detail: Option<String>,
}

/// A user-mode minidump's address space, as `!address` shows it.
#[derive(Debug, Clone)]
pub struct UserAddressMap {
    pub regions: Vec<UserRegion>,
}

impl UserAddressMap {
    /// The region holding `address`.
    pub fn region_at(&self, address: u64) -> Option<&UserRegion> {
        let index = self
            .regions
            .partition_point(|region| region.region.base <= address);
        let region = self.regions.get(index.checked_sub(1)?)?;
        (address - region.region.base < region.region.size).then_some(region)
    }
}

/// Count and total size of the regions in one summary row.
#[record]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SummaryRow {
    pub label: String,
    pub regions: usize,
    #[record(hex)]
    pub size: u64,
}

/// WinDbg's `!address` summary: regions by usage, by type and protection of
/// those in use, and by state.
#[record]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressSummary {
    pub by_usage: Vec<SummaryRow>,
    /// Regions in use (not free), by `MEM_*` type.
    pub by_type: Vec<SummaryRow>,
    pub by_state: Vec<SummaryRow>,
    /// Committed regions, by protection.
    pub by_protect: Vec<SummaryRow>,
    /// The size of every region listed.
    #[record(hex)]
    pub total: u64,
    /// The size of the regions not free.
    #[record(hex)]
    pub busy: u64,
}

/// `!address` on a user-mode minidump: what its memory-info list records,
/// or, for a dump without one, the memory ranges it captured.
#[record(tagged)]
pub enum UserAddressReport {
    /// The memory-info list's region that holds `address` (`None` when no
    /// region does), and whether the dump captured the byte at `address`.
    Region {
        address: VirtAddr,
        region: Option<UserRegion>,
        address_captured: bool,
    },
    /// Every region of the memory-info list, with their summary.
    Map {
        regions: Vec<UserRegion>,
        summary: AddressSummary,
    },
    /// A dump without a memory-info list: the captured range that holds
    /// `address`, if one does.
    CapturedRange {
        address: VirtAddr,
        range: Option<CapturedRange>,
    },
    /// A dump without a memory-info list: every range it captured.
    CapturedRanges { ranges: Vec<CapturedRange> },
}

impl UsageSources {
    /// The usage the dump shows for `address` by containment alone: what a
    /// captured range is attributed by when no memory-info list says where
    /// regions begin.
    pub fn usage_at(&self, address: u64) -> Option<(RegionUsage, Option<String>)> {
        let within = |start: u64, length: u64| address.wrapping_sub(start) < length;
        if let Some((_, _, name)) = self
            .modules
            .iter()
            .find(|(base, end, _)| (*base..*end).contains(&address))
        {
            return Some((RegionUsage::Image, Some(name.clone())));
        }
        if self.peb.is_some_and(|peb| within(peb, PEB_SPAN)) {
            return Some((RegionUsage::Peb, None));
        }
        let tebs = self
            .tebs
            .iter()
            .filter(|(teb, _)| within(*teb, TEB_SPAN))
            .map(|(_, thread)| thread.as_str())
            .collect::<Vec<_>>();
        if !tebs.is_empty() {
            return Some((RegionUsage::Teb, Some(tebs.join(", "))));
        }
        if let Some(stack) = self
            .stacks
            .iter()
            .find(|stack| (stack.low..stack.high).contains(&address))
        {
            return Some((RegionUsage::Stack, Some(stack.thread.clone())));
        }
        self.heaps
            .iter()
            .position(|heap| *heap == address)
            .map(|index| {
                (
                    RegionUsage::Heap,
                    Some(heap_label(index, self.heaps[index])),
                )
            })
    }
}

fn heap_label(index: usize, handle: u64) -> String {
    format!("heap {index}; handle {handle:#x}")
}

/// Attribute each region of a memory-info list (sorted by base) to its use.
/// A stack, heap, or image covers its whole allocation (every region of the
/// allocation holding its base), as `VirtualAlloc` reserved it: a stack's
/// guard and reserved pages are the stack's too.
pub fn attribute_regions(
    regions: &[MemoryRegion],
    sources: &UsageSources,
    captured: &[MemoryRange],
) -> Vec<UserRegion> {
    let containing = |address: u64| {
        let index = regions.partition_point(|region| region.base <= address);
        let region = regions.get(index.checked_sub(1)?)?;
        (address - region.base < region.size).then_some(region)
    };
    let stack_allocations: Vec<(u64, &str)> = sources
        .stacks
        .iter()
        .filter_map(|stack| {
            let region = containing(stack.high.checked_sub(1)?)?;
            (region.state != MEM_FREE).then_some((region.allocation_base, stack.thread.as_str()))
        })
        .collect();
    let heap_allocations: Vec<(u64, usize, u64)> = sources
        .heaps
        .iter()
        .enumerate()
        .filter_map(|(index, heap)| {
            let region = containing(*heap)?;
            (region.state != MEM_FREE).then_some((region.allocation_base, index, *heap))
        })
        .collect();
    regions
        .iter()
        .map(|region| {
            let (usage, detail) =
                region_usage(region, sources, &stack_allocations, &heap_allocations);
            UserRegion {
                region: *region,
                usage,
                detail,
                captured: captured_bytes(
                    captured,
                    region.base,
                    region.base.saturating_add(region.size),
                ),
            }
        })
        .collect()
}

fn region_usage(
    region: &MemoryRegion,
    sources: &UsageSources,
    stack_allocations: &[(u64, &str)],
    heap_allocations: &[(u64, usize, u64)],
) -> (RegionUsage, Option<String>) {
    if region.state == MEM_FREE {
        return (RegionUsage::Free, None);
    }
    let end = region.base.saturating_add(region.size);
    let overlaps =
        |start: u64, length: u64| start < end && region.base < start.saturating_add(length);
    if region.kind == MEM_IMAGE {
        let module = sources
            .modules
            .iter()
            .find(|(base, module_end, _)| *base < end && region.base < *module_end)
            .map(|(_, _, name)| name.clone());
        return (RegionUsage::Image, module);
    }
    let tebs = sources
        .tebs
        .iter()
        .filter(|(teb, _)| overlaps(*teb, TEB_SPAN))
        .map(|(_, thread)| thread.as_str())
        .collect::<Vec<_>>();
    // The PEB and the TEBs allocated after it share a region when their
    // pages' protection is the same.
    if sources.peb.is_some_and(|peb| overlaps(peb, PEB_SPAN)) {
        let detail = (!tebs.is_empty()).then(|| format!("and TEB {}", tebs.join(", ")));
        return (RegionUsage::Peb, detail);
    }
    if !tebs.is_empty() {
        return (RegionUsage::Teb, Some(tebs.join(", ")));
    }
    if let Some((_, thread)) = stack_allocations
        .iter()
        .find(|(allocation, _)| *allocation == region.allocation_base)
    {
        return (RegionUsage::Stack, Some((*thread).to_string()));
    }
    if let Some((_, index, heap)) = heap_allocations
        .iter()
        .find(|(allocation, _, _)| *allocation == region.allocation_base)
    {
        return (RegionUsage::Heap, Some(heap_label(*index, *heap)));
    }
    (RegionUsage::Unknown, None)
}

/// The bytes of `start..end` that `ranges` (disjoint, sorted by start) cover.
pub fn captured_bytes(ranges: &[MemoryRange], start: u64, end: u64) -> u64 {
    let first = ranges.partition_point(|range| range.start.saturating_add(range.length) <= start);
    ranges[first..]
        .iter()
        .take_while(|range| range.start < end)
        .map(|range| {
            let low = range.start.max(start);
            let high = range.start.saturating_add(range.length).min(end);
            high.saturating_sub(low)
        })
        .sum()
}

/// Group `regions` into WinDbg's `!address` summary.
pub fn summarize(regions: &[UserRegion]) -> AddressSummary {
    fn add(rows: &mut Vec<SummaryRow>, label: &str, size: u64) {
        match rows.iter_mut().find(|row| row.label == label) {
            Some(row) => {
                row.regions += 1;
                row.size = row.size.saturating_add(size);
            }
            None => rows.push(SummaryRow {
                label: label.to_string(),
                regions: 1,
                size,
            }),
        }
    }
    let mut summary = AddressSummary {
        by_usage: Vec::new(),
        by_type: Vec::new(),
        by_state: Vec::new(),
        by_protect: Vec::new(),
        total: 0,
        busy: 0,
    };
    for entry in regions {
        let region = &entry.region;
        summary.total = summary.total.saturating_add(region.size);
        add(&mut summary.by_usage, &entry.usage.to_string(), region.size);
        add(
            &mut summary.by_state,
            &state_label(region.state),
            region.size,
        );
        if region.state == MEM_FREE {
            continue;
        }
        summary.busy = summary.busy.saturating_add(region.size);
        add(&mut summary.by_type, &type_label(region.kind), region.size);
        if region.state == MEM_COMMIT {
            add(
                &mut summary.by_protect,
                &page_protection_name(region.protect),
                region.size,
            );
        }
    }
    for rows in [
        &mut summary.by_usage,
        &mut summary.by_type,
        &mut summary.by_state,
        &mut summary.by_protect,
    ] {
        rows.sort_by(|a, b| b.size.cmp(&a.size).then_with(|| a.label.cmp(&b.label)));
    }
    summary
}

/// `MEM_COMMIT`, or the raw value of a state Windows does not define.
pub fn state_label(state: u32) -> String {
    match memory_state_name(state) {
        "" => format!("{state:#x}"),
        name => name.to_string(),
    }
}

/// `MEM_IMAGE`, or the raw value of a type Windows does not define; empty
/// for 0, which a free region has.
pub fn type_label(kind: u32) -> String {
    match memory_type_name(kind) {
        "" if kind != 0 => format!("{kind:#x}"),
        name => name.to_string(),
    }
}

/// `125.974 TiB`: a size in the largest binary unit it reaches, as
/// `!address`'s summary writes them.
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["bytes", "KiB", "MiB", "GiB", "TiB"];
    let mut unit = 0;
    let mut scaled = bytes as f64;
    while scaled >= 1024.0 && unit + 1 < UNITS.len() {
        scaled /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} bytes")
    } else {
        format!("{scaled:.3} {}", UNITS[unit])
    }
}

impl Target {
    /// What the dump shows of the address space's users: modules, thread
    /// stacks and TEBs, the PEB, and the heaps its `ProcessHeaps` names.
    pub fn user_usage_sources(&self) -> Result<UsageSources> {
        let info = self.user_dump_info().ok_or_else(not_a_user_dump)?;
        let memory = self.context_memory();
        let mut sources = UsageSources {
            modules: self
                .user_modules()
                .unwrap_or_default()
                .iter()
                .map(|module| {
                    (
                        module.base_address.0,
                        module.base_address.0.saturating_add(u64::from(module.size)),
                        module.name.clone(),
                    )
                })
                .collect(),
            ..UsageSources::default()
        };
        for (index, thread) in info.threads.iter().enumerate() {
            let label = format!("~{index}; {}", info.backend_thread_id(thread.tid));
            if thread.teb != 0 {
                sources.tebs.push((thread.teb, label.clone()));
            }
            let tib = (thread.teb != 0)
                .then(|| {
                    let base = memory
                        .read::<u64>(VirtAddr(thread.teb + TIB64_STACK_BASE))
                        .ok()?;
                    let limit = memory
                        .read::<u64>(VirtAddr(thread.teb + TIB64_STACK_LIMIT))
                        .ok()?;
                    (limit < base).then_some((limit, base))
                })
                .flatten();
            let bounds = tib.or_else(|| {
                thread
                    .stack
                    .map(|stack| (stack.start, stack.start.saturating_add(stack.size)))
            });
            if let Some((low, high)) = bounds {
                sources.stacks.push(StackSource {
                    low,
                    high,
                    thread: label,
                });
            }
        }
        sources.peb = self.user_process_peb();
        if let Some(peb) = sources.peb {
            sources.heaps = self.user_process_heaps(VirtAddr(peb)).unwrap_or_default();
        }
        Ok(sources)
    }

    /// The process's PEB, through the selected thread's TEB, else the first
    /// TEB the dump captured.
    fn user_process_peb(&self) -> Option<u64> {
        let types = self.user_mode_types(self.current_dtb()).ok()?;
        let selected = self.user_teb().ok();
        let info = self.user_dump_info()?;
        selected
            .into_iter()
            .chain(
                info.threads
                    .iter()
                    .filter(|thread| thread.teb != 0)
                    .map(|thread| VirtAddr(thread.teb)),
            )
            .find_map(|teb| self.user_peb(types, teb).ok())
            .map(|peb| peb.0)
    }

    /// The heap handles of `PEB.ProcessHeaps`, when the PEB and the array
    /// are captured.
    fn user_process_heaps(&self, peb: VirtAddr) -> Result<Vec<u64>> {
        let types = self.user_mode_types(self.current_dtb())?;
        let peb = types.struct_at("_PEB", peb)?;
        let count = peb
            .read_field::<u32>("NumberOfHeaps")?
            .min(MAX_PROCESS_HEAPS);
        let array = peb.read_pointer("ProcessHeaps")?;
        let mut bytes = vec![0u8; count as usize * 8];
        self.context_memory().read_bytes(array, &mut bytes)?;
        Ok(bytes
            .as_chunks::<8>()
            .0
            .iter()
            .map(|chunk| u64::from_le_bytes(*chunk))
            .filter(|heap| *heap != 0)
            .collect())
    }

    /// The regions the dump's memory-info list records, attributed to their
    /// use. Fails, naming the missing stream, when the dump has none.
    pub fn user_address_map(&self) -> Result<UserAddressMap> {
        let dump = self.user_dump().ok_or_else(not_a_user_dump)?;
        let regions = dump.info().regions.as_deref().ok_or_else(|| {
            Error::DebugInfo(
                "the minidump records no memory-info list (MemoryInfoListStream)".into(),
            )
        })?;
        let sources = self.user_usage_sources()?;
        Ok(UserAddressMap {
            regions: attribute_regions(regions, &sources, dump.memory_ranges()),
        })
    }

    /// `!address` on a user-mode minidump: the region holding `address`, or
    /// every region and their summary; for a dump without a memory-info
    /// list, the captured range holding `address`, or every one.
    pub fn user_address_report(&self, address: Option<VirtAddr>) -> Result<UserAddressReport> {
        let dump = self.user_dump().ok_or_else(not_a_user_dump)?;
        if dump.info().regions.is_none() {
            let ranges = self.user_captured_ranges()?;
            return Ok(match address {
                Some(address) => UserAddressReport::CapturedRange {
                    address,
                    range: ranges
                        .into_iter()
                        .find(|range| address.0.wrapping_sub(range.start) < range.length),
                },
                None => UserAddressReport::CapturedRanges { ranges },
            });
        }
        let map = self.user_address_map()?;
        Ok(match address {
            Some(address) => UserAddressReport::Region {
                address,
                region: map.region_at(address.0).cloned(),
                address_captured: dump.read_virtual(address, &mut [0u8; 1]).is_ok(),
            },
            None => UserAddressReport::Map {
                summary: summarize(&map.regions),
                regions: map.regions,
            },
        })
    }

    /// The memory ranges the dump captured, attributed by what holds their
    /// start: what `!address` lists when the dump has no memory-info list.
    pub fn user_captured_ranges(&self) -> Result<Vec<CapturedRange>> {
        let dump = self.user_dump().ok_or_else(not_a_user_dump)?;
        let sources = self.user_usage_sources()?;
        Ok(dump
            .memory_ranges()
            .iter()
            .map(|range| {
                let (usage, detail) = sources
                    .usage_at(range.start)
                    .unwrap_or((RegionUsage::Unknown, None));
                CapturedRange {
                    start: range.start,
                    length: range.length,
                    usage,
                    detail,
                }
            })
            .collect())
    }
}

fn not_a_user_dump() -> Error {
    Error::DebugInfo("this target is not a user-mode minidump".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE_READWRITE: u32 = 0x04;
    const PAGE_GUARD: u32 = 0x100;
    const MEM_RESERVE: u32 = 0x2000;
    const MEM_PRIVATE: u32 = 0x2_0000;
    const MEM_MAPPED: u32 = 0x4_0000;

    fn region(base: u64, size: u64, allocation_base: u64, state: u32, kind: u32) -> MemoryRegion {
        MemoryRegion {
            base,
            allocation_base,
            allocation_protect: PAGE_READWRITE,
            size,
            state,
            protect: if state == MEM_COMMIT {
                PAGE_READWRITE
            } else {
                0
            },
            kind,
        }
    }

    fn range(start: u64, length: u64) -> MemoryRange {
        MemoryRange {
            start,
            length,
            offset: 0,
        }
    }

    #[test]
    fn a_stack_covers_its_whole_allocation_and_other_regions_keep_their_own_use() {
        // A stack reservation (reserved, guard, committed), its TEB, the
        // PEB, an image, a heap, and an unexplained private region.
        let mut guard = region(0x10_2000, 0x3000, 0x10_0000, MEM_COMMIT, MEM_PRIVATE);
        guard.protect = PAGE_READWRITE | PAGE_GUARD;
        let regions = [
            region(0x1_0000, 0xf_0000, 0, MEM_FREE, 0),
            region(0x10_0000, 0x2000, 0x10_0000, MEM_RESERVE, MEM_PRIVATE),
            guard,
            region(0x10_5000, 0xb000, 0x10_0000, MEM_COMMIT, MEM_PRIVATE),
            region(0x20_0000, 0x1000, 0x20_0000, MEM_COMMIT, MEM_PRIVATE),
            region(0x20_1000, 0x2000, 0x20_0000, MEM_COMMIT, MEM_PRIVATE),
            region(0x30_0000, 0x1000, 0x30_0000, MEM_COMMIT, MEM_IMAGE),
            region(0x30_1000, 0x4000, 0x30_0000, MEM_COMMIT, MEM_IMAGE),
            region(0x40_0000, 0x1_0000, 0x40_0000, MEM_COMMIT, MEM_PRIVATE),
            region(0x41_0000, 0x1_0000, 0x40_0000, MEM_RESERVE, MEM_PRIVATE),
            region(0x50_0000, 0x1000, 0x50_0000, MEM_COMMIT, MEM_PRIVATE),
        ];
        let sources = UsageSources {
            modules: vec![(0x30_0000, 0x30_5000, "app.exe".into())],
            stacks: vec![StackSource {
                low: 0x10_c000,
                high: 0x11_0000,
                thread: "~0; 10.20".into(),
            }],
            tebs: vec![(0x20_1000, "~0; 10.20".into())],
            peb: Some(0x20_0000),
            heaps: vec![0x40_0000],
        };
        let attributed = attribute_regions(&regions, &sources, &[range(0x10_c000, 0x4000)]);
        let usages: Vec<_> = attributed
            .iter()
            .map(|region| (region.usage, region.detail.as_deref()))
            .collect();
        assert_eq!(
            usages,
            [
                (RegionUsage::Free, None),
                (RegionUsage::Stack, Some("~0; 10.20")),
                (RegionUsage::Stack, Some("~0; 10.20")),
                (RegionUsage::Stack, Some("~0; 10.20")),
                (RegionUsage::Peb, None),
                (RegionUsage::Teb, Some("~0; 10.20")),
                (RegionUsage::Image, Some("app.exe")),
                (RegionUsage::Image, Some("app.exe")),
                (RegionUsage::Heap, Some("heap 0; handle 0x400000")),
                (RegionUsage::Heap, Some("heap 0; handle 0x400000")),
                (RegionUsage::Unknown, None),
            ]
        );
        assert_eq!(attributed[3].captured, 0x4000);
        assert_eq!(attributed[2].captured, 0);

        let map = UserAddressMap {
            regions: attributed,
        };
        assert_eq!(map.region_at(0x10_5000).unwrap().region.base, 0x10_5000);
        assert_eq!(map.region_at(0x10_4fff).unwrap().region.base, 0x10_2000);
        assert!(map.region_at(0x60_0000).is_none());
    }

    #[test]
    fn captured_bytes_counts_only_the_overlap_of_each_range() {
        let ranges = [
            range(0x1000, 0x1000),
            range(0x3000, 0x2000),
            range(0x8000, 0x1000),
        ];
        assert_eq!(captured_bytes(&ranges, 0, 0x10000), 0x4000);
        assert_eq!(captured_bytes(&ranges, 0x1800, 0x4000), 0x1800);
        assert_eq!(captured_bytes(&ranges, 0x5000, 0x8000), 0);
        assert_eq!(captured_bytes(&ranges, 0x8800, 0x9800), 0x800);
    }

    #[test]
    fn a_region_the_peb_shares_with_tebs_is_the_pebs_and_names_them() {
        // VirtualQuery merges the PEB's page with the TEBs after it when
        // their protection matches; a TEB in its own region stays a TEB.
        let regions = [
            region(0x20_0000, 0x5000, 0x20_0000, MEM_COMMIT, MEM_PRIVATE),
            region(0x20_5000, 0x2000, 0x20_0000, MEM_COMMIT, MEM_PRIVATE),
        ];
        let sources = UsageSources {
            tebs: vec![
                (0x20_1000, "~0; 10.20".into()),
                (0x20_3000, "~1; 10.24".into()),
                (0x20_5000, "~2; 10.28".into()),
            ],
            peb: Some(0x20_0000),
            ..UsageSources::default()
        };
        let attributed = attribute_regions(&regions, &sources, &[]);
        let usages: Vec<_> = attributed
            .iter()
            .map(|region| (region.usage, region.detail.as_deref()))
            .collect();
        assert_eq!(
            usages,
            [
                (RegionUsage::Peb, Some("and TEB ~0; 10.20, ~1; 10.24")),
                (RegionUsage::Teb, Some("~2; 10.28")),
            ]
        );
    }

    #[test]
    fn the_summary_counts_busy_types_and_committed_protections_only() {
        let regions = [
            region(0, 0x10_0000, 0, MEM_FREE, 0),
            region(0x10_0000, 0x2000, 0x10_0000, MEM_RESERVE, MEM_PRIVATE),
            region(0x10_2000, 0x1000, 0x10_0000, MEM_COMMIT, MEM_PRIVATE),
            region(0x20_0000, 0x3000, 0x20_0000, MEM_COMMIT, MEM_MAPPED),
        ];
        let attributed = attribute_regions(&regions, &UsageSources::default(), &[]);
        let summary = summarize(&attributed);
        assert_eq!(summary.total, 0x10_6000);
        assert_eq!(summary.busy, 0x6000);
        let rows = |rows: &[SummaryRow]| {
            rows.iter()
                .map(|row| (row.label.clone(), row.regions, row.size))
                .collect::<Vec<_>>()
        };
        // Equal sizes fall back to the label's order.
        assert_eq!(
            rows(&summary.by_type),
            [
                ("MEM_MAPPED".to_string(), 1, 0x3000),
                ("MEM_PRIVATE".to_string(), 2, 0x3000)
            ]
        );
        assert_eq!(
            rows(&summary.by_protect),
            [("PAGE_READWRITE".to_string(), 2, 0x4000)]
        );
        assert_eq!(
            rows(&summary.by_usage),
            [
                ("Free".to_string(), 1, 0x10_0000),
                ("<unknown>".to_string(), 3, 0x6000)
            ]
        );
    }

    #[test]
    fn a_captured_range_is_attributed_by_what_holds_its_start() {
        let sources = UsageSources {
            modules: vec![(0x30_0000, 0x30_5000, "app.exe".into())],
            stacks: vec![StackSource {
                low: 0x10_0000,
                high: 0x11_0000,
                thread: "~1; 10.24".into(),
            }],
            tebs: vec![(0x20_2000, "~1; 10.24".into())],
            peb: Some(0x20_0000),
            heaps: vec![0x40_0000],
        };
        assert_eq!(
            sources.usage_at(0x30_4fff),
            Some((RegionUsage::Image, Some("app.exe".into())))
        );
        assert_eq!(sources.usage_at(0x30_5000), None);
        assert_eq!(sources.usage_at(0x20_0800), Some((RegionUsage::Peb, None)));
        assert_eq!(
            sources.usage_at(0x20_3fff),
            Some((RegionUsage::Teb, Some("~1; 10.24".into())))
        );
        assert_eq!(
            sources.usage_at(0x10_8000),
            Some((RegionUsage::Stack, Some("~1; 10.24".into())))
        );
        assert_eq!(
            sources.usage_at(0x40_0000).map(|(usage, _)| usage),
            Some(RegionUsage::Heap)
        );
    }

    #[test]
    fn sizes_take_the_largest_binary_unit_they_reach() {
        assert_eq!(human_size(512), "512 bytes");
        assert_eq!(human_size(0x1800), "6.000 KiB");
        assert_eq!(human_size(0x7df9_6c3d_6000), "125.974 TiB");
    }
}
