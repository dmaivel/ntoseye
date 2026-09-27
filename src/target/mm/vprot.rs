//! `!vprot`: what `VirtualQuery` reports for a user address, from the VAD
//! holding it and the page-table and prototype PTEs of its pages.

use super::paging::PteSelfMap;
use super::{MemoryRegionInfo, VadType, VprotDetail};
use crate::backend::MemoryOps;
use crate::bugchecks::looks_like_kernel_pointer;
use crate::error::{Error, Result};
use crate::guest::ProcessInfo;
use crate::layout::{FieldInfo, ParsedType, TypeInfo};
use crate::memory::{AddressSpace, PAGE_SIZE};
use crate::phys::PhysMem;
use crate::target::Target;
use crate::types::{Arch, PageTableEntry, PageTableLevel, VirtAddr};

pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_RESERVE: u32 = 0x2000;
pub const MEM_FREE: u32 = 0x1_0000;
pub const MEM_PRIVATE: u32 = 0x2_0000;
pub const MEM_MAPPED: u32 = 0x4_0000;
pub const MEM_IMAGE: u32 = 0x100_0000;

pub const PAGE_NOACCESS: u32 = 0x01;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_WRITECOPY: u32 = 0x08;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
const PAGE_GUARD: u32 = 0x100;
const PAGE_NOCACHE: u32 = 0x200;
const PAGE_WRITECOMBINE: u32 = 0x400;

/// The MM protection a software PTE of a decommitted page carries
/// (`MM_DECOMMIT`: guard with no access).
const MM_DECOMMIT: u64 = 0x10;
const PTE_TABLE_SPAN: u64 = 1 << 21;
const PDE_TABLE_SPAN: u64 = 1 << 30;
const PPE_TABLE_SPAN: u64 = 1 << 39;
/// Page-table steps one region scan may take; each covers a page, or a
/// whole table's span when the table above it is absent. Past it the region
/// size is a lower bound.
const MAX_VPROT_STEPS: u64 = 1 << 18;

/// NT's `MmProtectToValue`: the `PAGE_*` value of a 5-bit MM protection,
/// whose low three bits are the access and whose 0x8 and 0x10 bits add no
/// caching, guard, or (both) write combining.
pub fn page_protection(mm: u64) -> u32 {
    const ACCESS: [u32; 8] = [
        PAGE_NOACCESS,
        PAGE_READONLY,
        PAGE_EXECUTE,
        PAGE_EXECUTE_READ,
        PAGE_READWRITE,
        PAGE_WRITECOPY,
        PAGE_EXECUTE_READWRITE,
        PAGE_EXECUTE_WRITECOPY,
    ];
    let access = ACCESS[(mm & 7) as usize];
    if mm & 7 == 0 {
        return PAGE_NOACCESS;
    }
    match mm & 0x18 {
        0 => access,
        0x08 => access | PAGE_NOCACHE,
        0x10 => access | PAGE_GUARD,
        _ => access | PAGE_WRITECOMBINE,
    }
}

/// `PAGE_READWRITE | PAGE_GUARD`-style name of a `PAGE_*` value; empty for 0.
pub fn page_protection_name(value: u32) -> String {
    let access = match value & 0xff {
        0 => None,
        PAGE_NOACCESS => Some("PAGE_NOACCESS"),
        PAGE_READONLY => Some("PAGE_READONLY"),
        PAGE_READWRITE => Some("PAGE_READWRITE"),
        PAGE_WRITECOPY => Some("PAGE_WRITECOPY"),
        PAGE_EXECUTE => Some("PAGE_EXECUTE"),
        PAGE_EXECUTE_READ => Some("PAGE_EXECUTE_READ"),
        PAGE_EXECUTE_READWRITE => Some("PAGE_EXECUTE_READWRITE"),
        PAGE_EXECUTE_WRITECOPY => Some("PAGE_EXECUTE_WRITECOPY"),
        _ => return format!("{value:#x}"),
    };
    let modifiers = [
        (PAGE_GUARD, "PAGE_GUARD"),
        (PAGE_NOCACHE, "PAGE_NOCACHE"),
        (PAGE_WRITECOMBINE, "PAGE_WRITECOMBINE"),
    ];
    access
        .into_iter()
        .chain(
            modifiers
                .into_iter()
                .filter(|(bit, _)| value & bit != 0)
                .map(|(_, name)| name),
        )
        .collect::<Vec<_>>()
        .join(" | ")
}

pub fn memory_state_name(state: u32) -> &'static str {
    match state {
        MEM_COMMIT => "MEM_COMMIT",
        MEM_RESERVE => "MEM_RESERVE",
        MEM_FREE => "MEM_FREE",
        _ => "",
    }
}

pub fn memory_type_name(kind: u32) -> &'static str {
    match kind {
        MEM_PRIVATE => "MEM_PRIVATE",
        MEM_MAPPED => "MEM_MAPPED",
        MEM_IMAGE => "MEM_IMAGE",
        _ => "",
    }
}

/// The PTE bitfields the walk decodes, from the kernel PDB. The software
/// formats are laid out alike on AMD64 and ARM64; the hardware ones differ
/// in names, and ARM64's has no separate dirty or cache-disable bit.
struct PteFormat {
    arch: Arch,
    /// `_MMPTE_SOFTWARE.Protection`; transition, prototype, and subsection
    /// PTEs keep theirs in the same bits.
    protection: FieldInfo,
    prototype: FieldInfo,
    proto_address: FieldInfo,
    /// AMD64's software `Write`, ARM64's `Writable`.
    write: FieldInfo,
    /// AMD64's hardware write bit (`Dirty1`).
    hardware_write: Option<FieldInfo>,
    copy_on_write: FieldInfo,
    cache_disable: Option<FieldInfo>,
    /// AMD64's `NoExecute`, ARM64's `UserNoExecute`.
    no_execute: FieldInfo,
}

impl PteFormat {
    fn load(target: &Target) -> Result<Self> {
        let types = target.guest()?.ntoskrnl.types();
        let software = types.layout("_MMPTE_SOFTWARE")?;
        let prototype = types.layout("_MMPTE_PROTOTYPE")?;
        let hardware = types.layout("_MMPTE_HARDWARE")?;
        let field = |layout: &TypeInfo, name: &str| layout.field(name).cloned();
        let either = |first: &str, second: &str| {
            hardware
                .field(first)
                .or_else(|_| hardware.field(second))
                .cloned()
        };
        Ok(Self {
            arch: target.arch(),
            protection: field(&software, "Protection")?,
            prototype: field(&software, "Prototype")?,
            proto_address: field(&prototype, "ProtoAddress")?,
            write: either("Write", "Writable")?,
            hardware_write: field(&hardware, "Dirty1").ok(),
            copy_on_write: field(&hardware, "CopyOnWrite")?,
            cache_disable: field(&hardware, "CacheDisable").ok(),
            no_execute: either("NoExecute", "UserNoExecute")?,
        })
    }

    /// Whether a present upper-level entry maps a large page itself.
    fn maps_large_page(&self, entry: u64, va: u64) -> bool {
        let attributes =
            PageTableEntry(entry).attributes(self.arch, PageTableLevel::Pde, VirtAddr(va));
        attributes.present && attributes.large_page
    }

    /// The protection of a valid PTE, from its hardware and software bits:
    /// NT keeps a writable page's hardware write bit clear until it is
    /// dirtied, with the software `Write` bit saying it may be.
    fn valid_protection(&self, pte: u64) -> u32 {
        let execute = self.no_execute.decode(pte) == 0;
        let access = if self.copy_on_write.decode(pte) != 0 {
            if execute {
                PAGE_EXECUTE_WRITECOPY
            } else {
                PAGE_WRITECOPY
            }
        } else if self.write.decode(pte) != 0
            || self
                .hardware_write
                .as_ref()
                .is_some_and(|field| field.decode(pte) != 0)
        {
            if execute {
                PAGE_EXECUTE_READWRITE
            } else {
                PAGE_READWRITE
            }
        } else if execute {
            PAGE_EXECUTE_READ
        } else {
            PAGE_READONLY
        };
        if self
            .cache_disable
            .as_ref()
            .is_some_and(|field| field.decode(pte) != 0)
        {
            access | PAGE_NOCACHE
        } else {
            access
        }
    }

    /// The prototype PTE a prototype-format PTE points at, `None` for the
    /// "look it up in the VAD" marker or anything else not a kernel address.
    fn proto_address(&self, pte: u64) -> Option<u64> {
        let raw = self.proto_address.decode(pte);
        let bits = match self.proto_address.type_data {
            ParsedType::Bitfield { len, .. } => len,
            _ => 48,
        };
        let address = if bits < 64 && raw >> (bits - 1) & 1 != 0 {
            raw | (u64::MAX << bits)
        } else {
            raw
        };
        (looks_like_kernel_pointer(address) && address != u64::MAX && address & 7 == 0)
            .then_some(address)
    }
}

/// Page state: `Some(PAGE_*)` committed, `None` reserved.
type PageState = Option<u32>;

/// What the scan needs of the VAD holding the address.
struct VadPages {
    start: VirtAddr,
    private: bool,
    image: bool,
    /// The VAD's MM protection.
    protection: u64,
    /// A private VAD committed whole at allocation (`MemCommit`).
    committed: bool,
    first_proto: u64,
    last_proto: u64,
}

struct PageWalk<'a> {
    memory: AddressSpace<'a, PhysMem>,
    kernel: AddressSpace<'a, PhysMem>,
    format: PteFormat,
    self_map: PteSelfMap,
    vad: VadPages,
    /// The page-table page last read: its self-map address and entries.
    table: Option<(u64, Vec<u8>)>,
}

impl PageWalk<'_> {
    /// The state of the page at `va` and the end of the span sharing it:
    /// one page, or the rest of a table that is not there (a zero entry
    /// above it). A table trimmed to its transition entry is still read; one
    /// in the page file makes the page an `Err`.
    fn state_at(&mut self, va: u64) -> Result<(PageState, u64)> {
        let span_end = |span: u64| (va | (span - 1)).saturating_add(1);
        let [pxe, ppe, pde, pte] = self.self_map.entries(va);
        let mut entry = 0;
        for (address, span) in [
            (pxe, PPE_TABLE_SPAN),
            (ppe, PDE_TABLE_SPAN),
            (pde, PTE_TABLE_SPAN),
        ] {
            entry = self.memory.read(address)?;
            if entry == 0 {
                return self.untouched(va, span_end(span));
            }
        }
        // The PDE: valid and large, it maps the whole span.
        if self.format.maps_large_page(entry, va) {
            return Ok((
                Some(self.format.valid_protection(entry)),
                span_end(PTE_TABLE_SPAN),
            ));
        }
        let table = pte.0 & !(PAGE_SIZE as u64 - 1);
        if self.table.as_ref().is_none_or(|(at, _)| *at != table) {
            let mut entries = vec![0u8; PAGE_SIZE];
            self.memory.read_bytes(VirtAddr(table), &mut entries)?;
            self.table = Some((table, entries));
        }
        let offset = (pte.0 - table) as usize;
        let pte = self
            .table
            .as_ref()
            .and_then(|(_, entries)| entries.get(offset..offset + 8))
            .map_or(0, |bytes| {
                u64::from_le_bytes(bytes.try_into().unwrap_or_default())
            });
        let next = va.saturating_add(PAGE_SIZE as u64);
        if pte == 0 {
            return self.untouched(va, next);
        }
        if pte & 1 != 0 {
            return Ok((Some(self.format.valid_protection(pte)), next));
        }
        let protection = self.format.protection.decode(pte);
        if self.format.prototype.decode(pte) != 0 {
            // A protection here overrides the prototype's (the page was
            // re-protected while not resident).
            if protection != 0 {
                return Ok((software_state(protection), next));
            }
            let proto = self
                .format
                .proto_address(pte)
                .or_else(|| self.vad_proto(va));
            return Ok((self.proto_state(proto), next));
        }
        if protection == 0 {
            return self.untouched(va, next);
        }
        Ok((software_state(protection), next))
    }

    /// Pages with no PTE yet: a private VAD's are committed when it was
    /// committed whole, a section view's are what its prototype PTEs say.
    fn untouched(&self, va: u64, span_end: u64) -> Result<(PageState, u64)> {
        if self.vad.private {
            let state = self
                .vad
                .committed
                .then(|| page_protection(self.vad.protection));
            return Ok((state, span_end));
        }
        let next = va.saturating_add(PAGE_SIZE as u64);
        Ok((self.proto_state(self.vad_proto(va)), next))
    }

    /// The prototype PTE for `va` from the VAD, while it lies in the
    /// contiguous run the VAD records.
    fn vad_proto(&self, va: u64) -> Option<u64> {
        if self.vad.first_proto == 0 {
            return None;
        }
        let index = (va - self.vad.start.0) >> PAGE_SIZE.trailing_zeros();
        let proto = self.vad.first_proto.checked_add(index.checked_mul(8)?)?;
        (self.vad.last_proto == 0 || proto <= self.vad.last_proto).then_some(proto)
    }

    /// A section page's state from its prototype PTE: an image's protection
    /// is the section's, a data view's the view's. A zero prototype is an
    /// uncommitted page of a reserved section. Without a readable prototype
    /// the page is taken as committed with the VAD's protection.
    fn proto_state(&self, proto: Option<u64>) -> PageState {
        let view = Some(page_protection(self.vad.protection));
        let Some(pte) = proto.and_then(|proto| self.kernel.read::<u64>(VirtAddr(proto)).ok())
        else {
            return view;
        };
        if pte == 0 {
            return None;
        }
        if !self.vad.image {
            return view;
        }
        if pte & 1 != 0 {
            return Some(self.format.valid_protection(pte));
        }
        match self.format.protection.decode(pte) {
            0 => view,
            protection => software_state(protection),
        }
    }
}

/// The state a non-zero software protection gives a page.
fn software_state(protection: u64) -> PageState {
    (protection != MM_DECOMMIT).then(|| page_protection(protection))
}

impl Target {
    /// `!vprot`: the region of `process`'s address space starting at the page
    /// holding `address` whose pages share one state and protection, as
    /// `VirtualQuery` reports it. The VAD gives the allocation base,
    /// protection, and type; the page tables (and the prototype PTEs of a
    /// section view) give each page's state and protection.
    pub fn virtual_query(&self, process: &ProcessInfo, address: VirtAddr) -> Result<VprotDetail> {
        if !matches!(self.arch(), Arch::Amd64 | Arch::Arm64) {
            return Err(Error::UnsupportedArchitecture(
                "!vprot decodes AMD64 and ARM64 page tables only".into(),
            ));
        }
        let guest = self.guest()?;
        let user_end = guest
            .ntoskrnl
            .symbol("MmHighestUserAddress")
            .and_then(|symbol| symbol.read::<VirtAddr>())
            .map_or(0x7FFF_FFFF_0000, |highest| {
                (highest.0 | (PAGE_SIZE as u64 - 1)).saturating_add(1)
            });
        if address.0 >= user_end {
            return Err(Error::InvalidArgument(format!(
                "{:#x} is not a user-mode address",
                address.0
            )));
        }
        let base = VirtAddr(address.0 & !(PAGE_SIZE as u64 - 1));
        let regions = self.enumerate_vad_regions_for_process_info(process)?;
        let Some(region) = regions
            .iter()
            .find(|region| region.start <= base && base < region.end)
        else {
            let end = regions
                .iter()
                .map(|region| region.start.0)
                .filter(|start| *start > base.0)
                .min()
                .unwrap_or(user_end);
            return Ok(VprotDetail {
                process: process.clone(),
                address,
                base_address: base,
                allocation_base: VirtAddr(0),
                allocation_protect: 0,
                region_size: end - base.0,
                state: MEM_FREE,
                protect: PAGE_NOACCESS,
                kind: 0,
                vad: None,
                truncated: false,
            });
        };
        let mut walk = self.page_walk(process, region)?;
        let (state, mut end) = walk.state_at(base.0)?;
        let mut truncated = false;
        let mut steps = 1;
        while end < region.end.0 {
            if steps >= MAX_VPROT_STEPS || self.interrupted() {
                truncated = true;
                break;
            }
            steps += 1;
            match walk.state_at(end) {
                Ok((next, next_end)) if next == state => end = next_end,
                Ok(_) => break,
                Err(_) => {
                    truncated = true;
                    break;
                }
            }
        }
        let end = end.min(region.end.0);
        let kind = if region.vad_type == Some(VadType::ImageMap) {
            MEM_IMAGE
        } else if walk.vad.private {
            MEM_PRIVATE
        } else {
            MEM_MAPPED
        };
        Ok(VprotDetail {
            process: process.clone(),
            address,
            base_address: base,
            allocation_base: region.start,
            allocation_protect: page_protection(walk.vad.protection),
            region_size: end - base.0,
            state: if state.is_some() {
                MEM_COMMIT
            } else {
                MEM_RESERVE
            },
            protect: state.unwrap_or(0),
            kind,
            vad: Some(region.node_address),
            truncated,
        })
    }

    fn page_walk<'a>(
        &'a self,
        process: &ProcessInfo,
        region: &MemoryRegionInfo,
    ) -> Result<PageWalk<'a>> {
        let guest = self.guest()?;
        let types = guest.ntoskrnl.types();
        let kernel = self.kernel_address_space();
        let vad_short = types.layout("_MMVAD_SHORT")?;
        let vad = region.node_address - vad_short.field_offset("VadNode").unwrap_or(0);
        let flags_offset = vad_short.field_offset("u")?;
        let flags: u32 = kernel.read(vad + flags_offset)?;
        let private = region.private_memory.unwrap_or(false);
        // `MemCommit` sits in the private-VAD flags on Windows 10 and later,
        // in `u1`'s `_MMVAD_FLAGS1` before.
        let committed = private
            && match types.layout("_MM_PRIVATE_VAD_FLAGS") {
                Ok(layout) => layout
                    .field("MemCommit")
                    .is_ok_and(|field| field.decode(flags.into()) != 0),
                Err(_) => types
                    .layout("_MMVAD_FLAGS1")
                    .ok()
                    .zip(vad_short.field_offset("u1").ok())
                    .and_then(|(layout, offset)| {
                        let flags1: u32 = kernel.read(vad + offset).ok()?;
                        Some(layout.field("MemCommit").ok()?.decode(flags1.into()) != 0)
                    })
                    .unwrap_or(false),
            };
        let (first_proto, last_proto) = if private {
            (0, 0)
        } else {
            let mmvad = types.layout("_MMVAD")?;
            let read = |name: &str| -> u64 {
                mmvad
                    .field_offset(name)
                    .and_then(|offset| kernel.read::<u64>(vad + offset))
                    .unwrap_or(0)
            };
            (read("FirstPrototypePte"), read("LastContiguousPte"))
        };
        Ok(PageWalk {
            // The self-map maps the root it is read through; on ARM64 a
            // process's root is its TTBR1 as well as its TTBR0 (see
            // `pte_traverse_in`).
            memory: AddressSpace::for_arch(&self.phys, process.dtb, process.dtb, self.arch()),
            kernel,
            format: PteFormat::load(self)?,
            self_map: self.pte_self_map()?,
            vad: VadPages {
                start: region.start,
                private,
                image: region.vad_type == Some(VadType::ImageMap),
                protection: region.protection.map_or(0, |protection| protection.raw()),
                committed,
                first_proto,
                last_proto,
            },
            table: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mm_protections_map_like_mm_protect_to_value() {
        assert_eq!(page_protection(0), PAGE_NOACCESS);
        assert_eq!(page_protection(3), PAGE_EXECUTE_READ);
        assert_eq!(page_protection(7), PAGE_EXECUTE_WRITECOPY);
        assert_eq!(page_protection(0x0c), PAGE_READWRITE | PAGE_NOCACHE);
        assert_eq!(page_protection(0x14), PAGE_READWRITE | PAGE_GUARD);
        assert_eq!(page_protection(0x1c), PAGE_READWRITE | PAGE_WRITECOMBINE);
        // No access with any modifier is still no access.
        assert_eq!(page_protection(0x18), PAGE_NOACCESS);
        assert_eq!(page_protection(0x08), PAGE_NOACCESS);
    }

    #[test]
    fn decommitted_software_pte_is_reserved() {
        assert_eq!(software_state(MM_DECOMMIT), None);
        assert_eq!(software_state(0x14), Some(PAGE_READWRITE | PAGE_GUARD));
    }
}
