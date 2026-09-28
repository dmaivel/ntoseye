//! Rebuilding a PDB from the guest's memory: the pages of the file the
//! memory manager still holds after the linker wrote and closed it.
//!
//! A file the cache manager has open is on one of the system partition's
//! shared cache map lists (`_CC_PARTITION`, clean or dirty); once it is
//! closed, a file whose pages are still cached keeps its data section's
//! control area on the partition's unused segment list
//! (`MiSystemPartition.Segments.UnusedSegmentList`, linked through
//! `_CONTROL_AREA.ListHead`). The file's pages are what the section's
//! prototype PTEs, in its subsections, say: resident, on the standby or
//! modified list (transition), or gone. Every layout comes from the kernel's
//! PDB; a control area is used only when its flags and its segment's back
//! pointer say it is a data file's, and a rebuilt file only when its MSF
//! header bounds it and its PDB identity is the one the image records.

use crate::backend::MemoryOps;
use crate::layout::{ParsedType, TypeInfo};
use crate::memory::AddressSpace;
use crate::phys::PhysMem;
use crate::symbols::{PdbIdentity, SymbolStore, download::pdb_bytes_identity};
use crate::types::{Arch, PageTableEntry, PhysAddr, VirtAddr};
use std::sync::Arc;

/// A PDB to rebuild: the path the image records for it and the identity it
/// must have.
pub struct WantedPdb<'a> {
    pub recorded_path: &'a str,
    pub identity: PdbIdentity,
}

const PAGE: usize = 0x1000;
/// Entries walked on one list before giving up on it.
const MAX_LIST_ENTRIES: usize = 1 << 20;
/// Subsections followed from one control area.
const MAX_SUBSECTIONS: usize = 1024;
/// Largest PDB rebuilt.
const MAX_PDB_BYTES: u64 = 1 << 30;
const MSF_MAGIC: &[u8] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0";
/// `_FILE_OBJECT.Type` of a file object (`IO_TYPE_FILE`).
const IO_TYPE_FILE: u16 = 5;

/// Rebuild each of `wanted` from guest memory: its bytes, or why not.
pub fn recover_pdbs(
    phys: &PhysMem,
    symbols: &SymbolStore,
    arch: Arch,
    wanted: &[WantedPdb<'_>],
) -> Vec<Result<Vec<u8>, String>> {
    let tails: Vec<Option<String>> = wanted
        .iter()
        .map(|pdb| volume_relative(pdb.recorded_path))
        .collect();
    let walker = match Walker::new(phys, symbols, arch) {
        Ok(walker) => walker,
        Err(error) => return wanted.iter().map(|_| Err(error.clone())).collect(),
    };
    let candidates = walker.candidates(&tails);
    wanted
        .iter()
        .zip(tails)
        .enumerate()
        .map(|(index, (pdb, tail))| {
            if tail.is_none() {
                return Err(format!(
                    "{} is not a path on a local volume",
                    pdb.recorded_path
                ));
            }
            let candidates = candidates.as_ref().map_err(Clone::clone)?;
            let mut reasons = Vec::new();
            for (control_area, name) in &candidates[index] {
                match walker.rebuild(*control_area) {
                    Ok(bytes) => match pdb_bytes_identity(&bytes) {
                        Ok(identity) => match pdb.identity.matches(identity) {
                            Ok(()) => return Ok(bytes),
                            Err(reason) => reasons.push(format!("{name}: {reason}")),
                        },
                        Err(error) => reasons.push(format!("{name}: not a PDB ({error})")),
                    },
                    Err(reason) => reasons.push(format!("{name}: {reason}")),
                }
            }
            Err(if reasons.is_empty() {
                "not in memory (no cached file by that name)".to_string()
            } else {
                reasons.join("; ")
            })
        })
        .collect()
}

/// The path a file object on the recorded path's volume would name,
/// lowercased: `C:\build\drv.pdb` is `\build\drv.pdb`. `None` for a path
/// with no drive letter.
pub fn volume_relative(recorded: &str) -> Option<String> {
    let bytes = recorded.as_bytes();
    (bytes.len() > 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\')
        .then(|| recorded[2..].to_ascii_lowercase())
}

/// Whether file object name `name` (lowercased) is the file `tail` names,
/// or the temporary file a linker wrote it as before renaming it
/// (`drv.pdb.tmp1a2b3c`, as LLVM's lld-link does). A redirector's name may
/// carry more ahead of the path, so the name need only end with it.
pub fn names_file(name: &str, tail: &str) -> bool {
    if name.ends_with(tail) {
        return true;
    }
    name.rsplit_once(".tmp").is_some_and(|(base, suffix)| {
        base.ends_with(tail) && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
    })
}

/// The file size an MSF header (the first page of a PDB) gives: its block
/// size times its block count. `None` when the page is not an MSF 7.00
/// header or the size is implausible.
pub fn msf_file_size(first_page: &[u8]) -> Option<u64> {
    if !first_page.starts_with(MSF_MAGIC) {
        return None;
    }
    let word = |offset: usize| {
        first_page
            .get(offset..offset + 4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
    };
    let block_size = word(32)?;
    let blocks = word(40)?;
    let size = u64::from(block_size) * u64::from(blocks);
    (block_size.is_power_of_two() && (512..=65536).contains(&block_size) && blocks > 0)
        .then_some(size)
        .filter(|size| *size <= MAX_PDB_BYTES)
}

struct Offsets {
    ca_size: u64,
    ca_segment: u64,
    ca_list_head: u64,
    ca_flags: u64,
    ca_file_pointer: u64,
    segment_control_area: u64,
    sub_control_area: u64,
    sub_base: u64,
    sub_next: u64,
    sub_ptes: u64,
    file_type: u64,
    file_name: u64,
    flag_image: u32,
    flag_file: u32,
    flag_unused: u32,
    unused_list: u64,
    file_section_pointers: u64,
    cache: Option<CacheOffsets>,
}

/// Where the system partition's shared cache maps are listed.
struct CacheOffsets {
    /// The list heads in `_CC_PARTITION`.
    lists: Vec<u64>,
    map_size: u64,
    map_node_size: u64,
    map_links: u64,
    map_file_object: u64,
    pointers_data_section: u64,
    pointers_cache_map: u64,
}

struct Walker<'a> {
    phys: &'a PhysMem,
    memory: AddressSpace<'a, PhysMem>,
    offsets: Offsets,
}

impl<'a> Walker<'a> {
    fn new(phys: &'a PhysMem, symbols: &SymbolStore, arch: Arch) -> Result<Self, String> {
        let guid = symbols.kernel_guid().ok_or("no kernel symbols")?;
        let dtb = symbols.kernel_dtb().ok_or("no kernel address space")?;
        let layout = |name: &str| -> Result<Arc<TypeInfo>, String> {
            symbols
                .dump_struct_with_types(guid, name)
                .ok_or_else(|| format!("the kernel's PDB does not describe {name}"))
        };
        let offset = |info: &TypeInfo, field: &str| -> Result<u64, String> {
            info.field_offset(field)
                .map_err(|_| format!("{} has no {field}", info.name))
        };
        let bit = |info: &TypeInfo, field: &str| -> Result<u32, String> {
            match info.field(field).map(|field| &field.type_data) {
                Ok(ParsedType::Bitfield { pos, .. }) => Ok(u32::from(*pos)),
                _ => Err(format!("{} has no {field} bit", info.name)),
            }
        };
        let control_area = layout("_CONTROL_AREA")?;
        let segment = layout("_SEGMENT")?;
        let subsection = layout("_SUBSECTION")?;
        let file_object = layout("_FILE_OBJECT")?;
        let section_flags = layout("_MMSECTION_FLAGS")?;
        let partition = layout("_MI_PARTITION")?;
        let segments = layout("_MI_PARTITION_SEGMENTS")?;
        let cache = Self::cache_offsets(symbols, dtb, phys, arch, &layout, &offset).ok();
        let system_partition = symbols
            .find_symbol_across_modules(dtb, "nt!MiSystemPartition")
            .ok()
            .flatten()
            .ok_or("nt!MiSystemPartition is not in the kernel's symbols")?;
        let offsets = Offsets {
            ca_size: control_area.size as u64,
            ca_segment: offset(&control_area, "Segment")?,
            ca_list_head: offset(&control_area, "ListHead")?,
            ca_flags: offset(&control_area, "u")?,
            ca_file_pointer: offset(&control_area, "FilePointer")?,
            segment_control_area: offset(&segment, "ControlArea")?,
            sub_control_area: offset(&subsection, "ControlArea")?,
            sub_base: offset(&subsection, "SubsectionBase")?,
            sub_next: offset(&subsection, "NextSubsection")?,
            sub_ptes: offset(&subsection, "PtesInSubsection")?,
            file_type: offset(&file_object, "Type")?,
            file_section_pointers: offset(&file_object, "SectionObjectPointer")?,
            file_name: offset(&file_object, "FileName")?,
            flag_image: bit(&section_flags, "Image")?,
            flag_file: bit(&section_flags, "File")?,
            flag_unused: bit(&section_flags, "ControlAreaOnUnusedList")?,
            unused_list: system_partition.0
                + offset(&partition, "Segments")?
                + offset(&segments, "UnusedSegmentList")?,
            cache,
        };
        Ok(Self {
            phys,
            memory: AddressSpace::for_arch(phys, dtb, dtb, arch),
            offsets,
        })
    }

    /// The system partition's shared cache map lists: `PspSystemPartition`
    /// names its `_EPARTITION`, whose `CcPartition` holds them.
    fn cache_offsets(
        symbols: &SymbolStore,
        dtb: u64,
        phys: &PhysMem,
        arch: Arch,
        layout: &dyn Fn(&str) -> Result<Arc<TypeInfo>, String>,
        offset: &dyn Fn(&TypeInfo, &str) -> Result<u64, String>,
    ) -> Result<CacheOffsets, String> {
        let memory = AddressSpace::for_arch(phys, dtb, dtb, arch);
        let partition_pointer = symbols
            .find_symbol_across_modules(dtb, "nt!PspSystemPartition")
            .ok()
            .flatten()
            .ok_or("nt!PspSystemPartition is not in the kernel's symbols")?;
        let partition: u64 = memory
            .read(partition_pointer)
            .map_err(|error| error.to_string())?;
        let cc_partition: u64 = memory
            .read(VirtAddr(
                partition + offset(&*layout("_EPARTITION")?, "CcPartition")?,
            ))
            .map_err(|error| error.to_string())?;
        let cc = layout("_CC_PARTITION")?;
        let cursor = layout("_SHARED_CACHE_MAP_LIST_CURSOR")?;
        let map = layout("_SHARED_CACHE_MAP")?;
        let pointers = layout("_SECTION_OBJECT_POINTERS")?;
        let mut lists = Vec::new();
        for list in [
            "CleanSharedCacheMapList",
            "CleanSharedCacheMapWithLogHandleList",
            "DirtySharedCacheMapWithLogHandleList",
        ] {
            lists.push(cc_partition + offset(&cc, list)?);
        }
        lists.push(
            cc_partition
                + offset(&cc, "DirtySharedCacheMapList")?
                + offset(&cursor, "SharedCacheMapLinks")?,
        );
        Ok(CacheOffsets {
            lists,
            map_size: map.size as u64,
            map_node_size: offset(&map, "NodeByteSize")?,
            map_links: offset(&map, "SharedCacheMapLinks")?,
            map_file_object: offset(&map, "FileObjectFastRef")?,
            pointers_data_section: offset(&pointers, "DataSectionObject")?,
            pointers_cache_map: offset(&pointers, "SharedCacheMap")?,
        })
    }

    fn u64_at(&self, address: u64) -> Option<u64> {
        self.memory.read::<u64>(VirtAddr(address)).ok()
    }

    /// For each tail, the data control areas of files it names, with the
    /// file's name: files the cache manager has open first, then closed
    /// ones on the unused segment list.
    #[allow(clippy::type_complexity)]
    fn candidates(&self, tails: &[Option<String>]) -> Result<Vec<Vec<(u64, String)>>, String> {
        let o = &self.offsets;
        let mut found: Vec<Vec<(u64, String)>> = vec![Vec::new(); tails.len()];
        let shortest = tails.iter().flatten().map(String::len).min().unwrap_or(0);
        let mut record = |control_area: u64, name: String| {
            let lowered = name.to_lowercase();
            for (tail, hits) in tails.iter().zip(found.iter_mut()) {
                if tail
                    .as_deref()
                    .is_some_and(|tail| names_file(&lowered, tail))
                    && !hits.iter().any(|(seen, _)| *seen == control_area)
                {
                    hits.push((control_area, name.clone()));
                }
            }
        };
        if let Some(cache) = &o.cache {
            for &head in &cache.lists {
                self.walk_list(head, |link| {
                    let map = link.wrapping_sub(cache.map_links);
                    if let Some((control_area, name)) = self.cached_file(cache, map, shortest) {
                        record(control_area, name);
                    }
                })?;
            }
        }
        self.walk_list(o.unused_list, |link| {
            let control_area = link.wrapping_sub(o.ca_list_head);
            if !self.is_data_control_area(control_area, true) {
                return;
            }
            let file_object = self.u64_at(control_area + o.ca_file_pointer).unwrap_or(0) & !0xF;
            if let Some(name) = self.file_name(file_object, shortest) {
                record(control_area, name);
            }
        })?;
        Ok(found)
    }

    /// Call `visit` with each link of the list headed at `head`.
    fn walk_list(&self, head: u64, mut visit: impl FnMut(u64)) -> Result<(), String> {
        let mut link = self
            .u64_at(head)
            .ok_or_else(|| format!("list {head:#x} is unreadable"))?;
        let mut walked = 0;
        while link != head {
            walked += 1;
            if walked > MAX_LIST_ENTRIES {
                return Err(format!(
                    "list {head:#x} did not end within {MAX_LIST_ENTRIES} entries"
                ));
            }
            visit(link);
            link = self
                .u64_at(link)
                .ok_or_else(|| format!("list {head:#x} is unreadable part way"))?;
        }
        Ok(())
    }

    /// The data control area and name of the file the shared cache map at
    /// `map` caches, when the map, its file object, and the file's section
    /// pointers all point at each other.
    fn cached_file(&self, cache: &CacheOffsets, map: u64, min_len: usize) -> Option<(u64, String)> {
        let node_size = self
            .memory
            .read::<u16>(VirtAddr(map + cache.map_node_size))
            .ok()?;
        if u64::from(node_size) != cache.map_size {
            return None;
        }
        let file_object = self.u64_at(map + cache.map_file_object)? & !0xF;
        let name = self.file_name(file_object, min_len)?;
        let pointers = self.u64_at(file_object + self.offsets.file_section_pointers)?;
        if self.u64_at(pointers + cache.pointers_cache_map)? != map {
            return None;
        }
        let control_area = self.u64_at(pointers + cache.pointers_data_section)?;
        self.is_data_control_area(control_area, false)
            .then_some((control_area, name))
    }

    /// Whether `control_area` is a data file's (not an image's), its
    /// segment pointing back at it, and, with `on_unused_list`, flagged as
    /// on the unused segment list.
    fn is_data_control_area(&self, control_area: u64, on_unused_list: bool) -> bool {
        let o = &self.offsets;
        let (Ok(flags), Some(segment)) = (
            self.memory.read::<u32>(VirtAddr(control_area + o.ca_flags)),
            self.u64_at(control_area + o.ca_segment),
        ) else {
            return false;
        };
        flags >> o.flag_image & 1 == 0
            && flags >> o.flag_file & 1 != 0
            && (!on_unused_list || flags >> o.flag_unused & 1 != 0)
            && segment != 0
            && self.u64_at(segment + o.segment_control_area) == Some(control_area)
    }

    /// The name of file object `file_object`, when it is one and its name
    /// is at least `min_len` characters long.
    fn file_name(&self, file_object: u64, min_len: usize) -> Option<String> {
        let o = &self.offsets;
        if file_object == 0 {
            return None;
        }
        let file_type = self
            .memory
            .read::<u16>(VirtAddr(file_object + o.file_type))
            .ok()?;
        if file_type != IO_TYPE_FILE {
            return None;
        }
        let name = VirtAddr(file_object + o.file_name);
        let length = usize::from(self.memory.read::<u16>(name).ok()?);
        if length / 2 < min_len || length > 0x1000 {
            return None;
        }
        let buffer = self.memory.read::<u64>(name + 8u64).ok()?;
        let mut bytes = vec![0u8; length];
        self.memory.read_bytes(VirtAddr(buffer), &mut bytes).ok()?;
        let units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect();
        Some(String::from_utf16_lossy(&units))
    }

    /// The file whose data section `control_area` is, as its pages are in
    /// memory, sized by its MSF header.
    fn rebuild(&self, control_area: u64) -> Result<Vec<u8>, String> {
        let o = &self.offsets;
        let mut subsections = Vec::new();
        let mut subsection = control_area + o.ca_size;
        while subsection != 0 && subsections.len() < MAX_SUBSECTIONS {
            let read = |offset: u64| self.u64_at(subsection + offset);
            if read(o.sub_control_area) != Some(control_area) {
                break;
            }
            let ptes = self
                .memory
                .read::<u32>(VirtAddr(subsection + o.sub_ptes))
                .map_err(|error| format!("subsection unreadable: {error}"))?;
            let base = read(o.sub_base).ok_or("subsection unreadable")?;
            subsections.push((base, u64::from(ptes)));
            subsection = read(o.sub_next).unwrap_or(0);
        }
        let total_pages: u64 = subsections.iter().map(|(_, ptes)| ptes).sum();

        let frame = |index: u64| -> Option<PhysAddr> {
            let mut index = index;
            for (base, ptes) in &subsections {
                if index < *ptes {
                    // A prototype PTE page that is not present holds no
                    // resident page's PTE.
                    let pte = PageTableEntry(self.u64_at(base + index * 8)?);
                    return if pte.is_present() {
                        Some(pte.page_frame())
                    } else if pte.is_transition() {
                        Some(pte.unswizzled(self.phys.invalid_pte_mask()).page_frame())
                    } else {
                        None
                    };
                }
                index -= ptes;
            }
            None
        };
        let page = |index: u64| -> Option<Vec<u8>> {
            let mut bytes = vec![0u8; PAGE];
            self.phys.read_bytes(frame(index)?, &mut bytes).ok()?;
            Some(bytes)
        };

        let first = page(0).ok_or("its first page is not in memory")?;
        let size = msf_file_size(&first).ok_or("its first page is not an MSF 7.00 header")?;
        let pages = size.div_ceil(PAGE as u64);
        if pages > total_pages {
            return Err(format!(
                "its header gives {size} bytes, more than its section's {total_pages} pages"
            ));
        }
        let mut bytes = first;
        let mut missing = 0;
        for index in 1..pages {
            match page(index) {
                Some(data) => bytes.extend_from_slice(&data),
                None => {
                    missing += 1;
                    bytes.resize(bytes.len() + PAGE, 0);
                }
            }
        }
        if missing > 0 {
            return Err(format!(
                "{missing} of its {pages} pages are no longer in memory"
            ));
        }
        bytes.truncate(size as usize);
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file object names a file on the recorded path's volume without the
    /// drive; a linker's temporary file and a redirector's prefixed name
    /// still count, a different file does not.
    #[test]
    fn file_objects_are_matched_to_the_recorded_path() {
        let tail = volume_relative(r"C:\Users\Me\drv\x64\Debug\Drv.pdb").unwrap();
        assert_eq!(tail, r"\users\me\drv\x64\debug\drv.pdb");
        assert_eq!(volume_relative("Drv.pdb"), None);
        assert_eq!(volume_relative(r"\\host\share\drv.pdb"), None);

        assert!(names_file(r"\users\me\drv\x64\debug\drv.pdb", &tail));
        assert!(names_file(
            r"\users\me\drv\x64\debug\drv.pdb.tmp52894cf",
            &tail
        ));
        assert!(names_file(
            r"\;z:000\host\share\users\me\drv\x64\debug\drv.pdb",
            &tail
        ));
        assert!(!names_file(r"\users\me\drv\x64\debug\drv.pdb.bak", &tail));
        assert!(!names_file(r"\users\me\drv\x64\release\drv.pdb", &tail));
        assert!(!names_file(r"\users\me\drv\x64\debug\olddrv.pdb", &tail));
    }

    fn msf_header(block_size: u32, blocks: u32) -> Vec<u8> {
        let mut page = vec![0u8; PAGE];
        page[..MSF_MAGIC.len()].copy_from_slice(MSF_MAGIC);
        page[32..36].copy_from_slice(&block_size.to_le_bytes());
        page[40..44].copy_from_slice(&blocks.to_le_bytes());
        page
    }

    /// The rebuilt file's size comes from its MSF header, which must be one.
    #[test]
    fn a_pdb_is_sized_by_its_msf_header() {
        assert_eq!(msf_file_size(&msf_header(4096, 69)), Some(282_624));
        assert_eq!(msf_file_size(&msf_header(1024, 3)), Some(3072));
        assert_eq!(msf_file_size(&msf_header(4000, 69)), None);
        assert_eq!(msf_file_size(&msf_header(4096, 0)), None);
        assert_eq!(msf_file_size(&msf_header(65536, u32::MAX)), None);
        let mut not_msf = msf_header(4096, 69);
        not_msf[0] = b'X';
        assert_eq!(msf_file_size(&not_msf), None);
    }
}
