//! File-system views of the memory and cache managers: a section's control
//! area and subsections (`!ca`), a volume parameter block (`!vpb`), and the
//! cache manager's mapped views (`!filecache`).

use std::cmp::Reverse;
use std::collections::{BTreeMap, HashSet};
use std::ops::ControlFlow;

use super::{DiagnosticValue, Target, fast_ref_address};
use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::layout::utf16le_lossy;
use crate::types::VirtAddr;

/// Subsections one `!ca` walks.
const MAX_SUBSECTIONS: usize = 1024;
/// VACB arrays and VACBs per array one `!filecache` reads; the kernel
/// allocates 4,096 VACBs per array.
const MAX_VACB_ARRAYS: u64 = 4096;
const MAX_VACBS_PER_ARRAY: u64 = 4096;
/// The files one `!filecache` lists.
const MAX_CACHED_FILES: usize = 1024;
/// The view one VACB maps (`VACB_MAPPING_GRANULARITY`).
const VACB_MAPPING_GRANULARITY: u64 = 0x4_0000;
/// `_VPB.Type` of a volume parameter block.
const IO_TYPE_VPB: u64 = 10;
/// `_VPB.Flags` (`VPB_*` in wdm.h and ntifs.h).
const VPB_FLAGS: [(u64, &str); 8] = [
    (0x01, "VPB_MOUNTED"),
    (0x02, "VPB_LOCKED"),
    (0x04, "VPB_PERSISTENT"),
    (0x08, "VPB_REMOVE_PENDING"),
    (0x10, "VPB_RAW_MOUNT"),
    (0x20, "VPB_DIRECT_WRITES_ALLOWED"),
    (0x40, "VPB_FLAGS_BYPASSIO_BLOCKED"),
    (0x80, "VPB_DISMOUNTING"),
];

/// `!ca`: a `_CONTROL_AREA`, its segment, and its subsections.
#[derive(Debug, Clone)]
pub struct ControlAreaDetail {
    pub address: VirtAddr,
    pub segment: VirtAddr,
    pub section_references: u64,
    pub pfn_references: u64,
    pub mapped_views: u64,
    pub user_references: u64,
    /// `u.LongFlags` and the `_MMSECTION_FLAGS` bits set in it.
    pub flags: u64,
    pub flag_names: Vec<String>,
    pub file_object: VirtAddr,
    pub file_name: DiagnosticValue<String>,
    pub segment_detail: DiagnosticValue<SegmentDetail>,
    pub subsections: Vec<SubsectionDetail>,
    /// Why the subsection walk stopped before a null `NextSubsection`.
    pub subsections_stopped: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SegmentDetail {
    pub total_ptes: u64,
    pub size: u64,
    pub committed_pages: u64,
    /// `None` for a data file's segment, whose prototype PTEs are in its
    /// subsections.
    pub prototype_ptes: Option<VirtAddr>,
}

#[derive(Debug, Clone)]
pub struct SubsectionDetail {
    pub address: VirtAddr,
    pub base_pte: VirtAddr,
    pub ptes: u64,
    pub unused_ptes: u64,
    pub starting_sector: u64,
    pub sectors: u64,
    /// The MM protection of `SubsectionFlags`.
    pub protection: u64,
}

/// `!vpb`: a volume parameter block.
#[derive(Debug, Clone)]
pub struct VpbDetail {
    pub address: VirtAddr,
    pub flags: u64,
    pub flag_names: Vec<&'static str>,
    /// The mounted file system's volume device object.
    pub device_object: VirtAddr,
    pub device_name: Option<String>,
    /// The storage device the volume is on.
    pub real_device: VirtAddr,
    pub real_device_name: Option<String>,
    pub serial_number: u32,
    pub reference_count: u32,
    pub volume_label: String,
}

/// `!filecache`: the cache manager's mapped views, from its VACB arrays.
#[derive(Debug, Clone)]
pub struct FileCacheDetail {
    pub vacb_arrays: u64,
    /// `CcNumberOfFreeVacbs`.
    pub free_vacbs: DiagnosticValue<u64>,
    /// VACBs mapping a view.
    pub active_vacbs: u64,
    pub mapped_bytes: u64,
    /// Present pages in the mapped views.
    pub valid_bytes: u64,
    /// One entry per shared cache map with a mapped view, most valid first,
    /// up to 1,024.
    pub files: Vec<CachedFile>,
    /// The shared cache maps with a mapped view, listed or not.
    pub file_count: u64,
    pub interrupted: bool,
}

#[derive(Debug, Clone)]
pub struct CachedFile {
    pub shared_cache_map: VirtAddr,
    pub file_object: VirtAddr,
    pub file_name: DiagnosticValue<String>,
    pub file_size: DiagnosticValue<u64>,
    pub valid_data_length: DiagnosticValue<u64>,
    pub open_count: DiagnosticValue<u64>,
    pub dirty_pages: DiagnosticValue<u64>,
    pub mapped_vacbs: u64,
    pub valid_bytes: u64,
}

impl Target {
    /// `_FILE_OBJECT.FileName` of `file_object`.
    fn file_object_name(&self, file_object: VirtAddr) -> Result<String> {
        if file_object.is_zero() {
            return Err(Error::DebugInfo("no file object".into()));
        }
        self.types_in(self.kernel_dtb())
            .struct_at("_FILE_OBJECT", file_object)?
            .unicode_string("FileName")
    }

    /// `!ca`: decode the control area at `address`, its segment, and its
    /// subsections, which follow it in memory and chain by `NextSubsection`.
    pub fn inspect_control_area(&self, address: VirtAddr) -> Result<ControlAreaDetail> {
        let types = self.types_in(self.kernel_dtb());
        let layout = types.layout("_CONTROL_AREA")?;
        let control_area = types.struct_with_layout(layout.clone(), address).prefetch();
        let segment = control_area.read_pointer("Segment")?;
        let flags_offset = layout.field_offset("u")?;
        let flags = u64::from(
            self.kernel_address_space()
                .read::<u32>(address + flags_offset)?,
        );
        let section_flags = types.layout("_MMSECTION_FLAGS")?;
        let flag = |name: &str| {
            section_flags
                .field(name)
                .is_ok_and(|field| field.decode(flags) != 0)
        };
        let data_file = flag("File") && !flag("Image");
        // Every `_MMSECTION_FLAGS` bit shares the word `BeingDeleted` opens.
        let flag_names = section_flags.set_bit_names("BeingDeleted", flags);
        let file_object = fast_ref_address(control_area.read_uint("FilePointer")?);
        let segment_detail = DiagnosticValue::from_result((|| {
            let segment = types.struct_at("_SEGMENT", segment)?;
            Ok(SegmentDetail {
                total_ptes: segment.read_uint("TotalNumberOfPtes")?,
                size: segment.read_uint("SizeOfSegment")?,
                committed_pages: segment.read_uint("NumberOfCommittedPages")?,
                prototype_ptes: if data_file {
                    None
                } else {
                    Some(segment.read_pointer("PrototypePte")?)
                },
            })
        })());

        let subsection_layout = types.layout("_SUBSECTION")?;
        let mut subsections = Vec::new();
        let mut seen = HashSet::new();
        let mut next = address + layout.size as u64;
        let mut stopped = None;
        while !next.is_zero() {
            if subsections.len() >= MAX_SUBSECTIONS {
                stopped = Some(format!("stopped at the {MAX_SUBSECTIONS}-subsection bound"));
                break;
            }
            if !seen.insert(next.0) {
                stopped = Some(format!("NextSubsection cycles back to {:#x}", next.0));
                break;
            }
            let subsection = types
                .struct_with_layout(subsection_layout.clone(), next)
                .prefetch();
            let read = || -> Result<(VirtAddr, SubsectionDetail, VirtAddr)> {
                let flags_offset = subsection_layout.field_offset("SubsectionFlags")?;
                let flags = u64::from(
                    self.kernel_address_space()
                        .read::<u32>(next + flags_offset)?,
                );
                let protection = types
                    .layout("_MMSUBSECTION_FLAGS")?
                    .field("Protection")?
                    .decode(flags);
                Ok((
                    subsection.read_pointer("ControlArea")?,
                    SubsectionDetail {
                        address: next,
                        base_pte: subsection.read_pointer("SubsectionBase")?,
                        ptes: subsection.read_uint("PtesInSubsection")?,
                        unused_ptes: subsection.read_bits("UnusedPtes").unwrap_or(0),
                        starting_sector: subsection.read_uint("StartingSector")?,
                        sectors: subsection.read_uint("NumberOfFullSectors")?,
                        protection,
                    },
                    subsection.read_pointer("NextSubsection")?,
                ))
            };
            match read() {
                Ok((owner, detail, following)) if owner == address => {
                    subsections.push(detail);
                    next = following;
                }
                Ok((owner, ..)) => {
                    stopped = Some(format!(
                        "subsection {:#x} belongs to control area {:#x}",
                        next.0, owner.0
                    ));
                    break;
                }
                Err(error) => {
                    stopped = Some(format!("subsection {:#x}: {error}", next.0));
                    break;
                }
            }
        }

        Ok(ControlAreaDetail {
            address,
            segment,
            section_references: control_area.read_uint("NumberOfSectionReferences")?,
            pfn_references: control_area.read_uint("NumberOfPfnReferences")?,
            mapped_views: control_area.read_uint("NumberOfMappedViews")?,
            user_references: control_area.read_uint("NumberOfUserReferences")?,
            flags,
            flag_names,
            file_object,
            file_name: DiagnosticValue::from_result(self.file_object_name(file_object)),
            segment_detail,
            subsections,
            subsections_stopped: stopped,
        })
    }

    /// `!vpb`: decode the volume parameter block at `address`.
    pub fn inspect_vpb(&self, address: VirtAddr) -> Result<VpbDetail> {
        let vpb = self
            .types_in(self.kernel_dtb())
            .struct_at("_VPB", address)?
            .prefetch();
        let kind = vpb.read_uint("Type")?;
        if kind != IO_TYPE_VPB {
            return Err(Error::DebugInfo(format!(
                "{:#x} is not a VPB: its Type is {kind}, not IO_TYPE_VPB ({IO_TYPE_VPB})",
                address.0
            )));
        }
        let flags = vpb.read_uint("Flags")?;
        let label_bytes = vpb.read_field_bytes("VolumeLabel", 0x100)?;
        let label_length = (vpb.read_uint("VolumeLabelLength")? as usize).min(label_bytes.len());
        let device_name = |device: VirtAddr| {
            (!device.is_zero())
                .then(|| self.inspect_object_header(device).ok()?.name)
                .flatten()
        };
        let device_object = vpb.read_pointer("DeviceObject")?;
        let real_device = vpb.read_pointer("RealDevice")?;
        Ok(VpbDetail {
            address,
            flags,
            flag_names: VPB_FLAGS
                .iter()
                .filter(|(bit, _)| flags & bit != 0)
                .map(|(_, name)| *name)
                .collect(),
            device_object,
            device_name: device_name(device_object),
            real_device,
            real_device_name: device_name(real_device),
            serial_number: vpb.read_uint("SerialNumber")? as u32,
            reference_count: vpb.read_uint("ReferenceCount")? as u32,
            volume_label: utf16le_lossy(&label_bytes[..label_length]),
        })
    }

    /// `!filecache`: walk the cache manager's VACB arrays (`CcVacbArrays`
    /// up to `CcVacbArraysHighestUsedIndex`), count each shared cache map's
    /// mapped views and the present pages in them, and name the files of
    /// the 1,024 with the most.
    pub fn file_cache(&self) -> Result<FileCacheDetail> {
        let guest = self.guest()?;
        let ntos = &guest.ntoskrnl;
        let types = self.types_in(self.kernel_dtb());
        let memory = self.kernel_address_space();
        let arrays: VirtAddr = ntos.symbol("CcVacbArrays")?.read()?;
        let highest: u32 = ntos.symbol("CcVacbArraysHighestUsedIndex")?.read()?;
        let free_vacbs = DiagnosticValue::from_result(
            ntos.symbol("CcNumberOfFreeVacbs")
                .and_then(|symbol| symbol.read::<u32>())
                .map(u64::from),
        );
        let header_layout = types.layout("_VACB_ARRAY_HEADER")?;
        let vacb_layout = types.layout("_VACB")?;
        let array_count = (u64::from(highest) + 1).min(MAX_VACB_ARRAYS);

        let mut views: BTreeMap<u64, Vec<VirtAddr>> = BTreeMap::new();
        let mut vacb_arrays = 0;
        let mut interrupted = false;
        'arrays: for index in 0..array_count {
            let Ok(header) = memory.read::<VirtAddr>(arrays + index * 8) else {
                continue;
            };
            if header.is_zero() {
                continue;
            }
            vacb_arrays += 1;
            let header_ref = types.struct_with_layout(header_layout.clone(), header);
            let Ok(highest_mapped) = header_ref.read_uint("HighestMappedIndex") else {
                continue;
            };
            let first = header + header_layout.size as u64;
            let count = (highest_mapped + 1).min(MAX_VACBS_PER_ARRAY);
            let mut bytes = vec![0u8; count as usize * vacb_layout.size];
            if memory.read_bytes(first, &mut bytes).is_err() {
                continue;
            }
            for vacb_bytes in bytes.chunks_exact(vacb_layout.size) {
                if self.interrupted() {
                    interrupted = true;
                    break 'arrays;
                }
                let field = |name: &str| -> Option<u64> {
                    let offset = vacb_layout.field_offset(name).ok()? as usize;
                    let raw = vacb_bytes.get(offset..offset + 8)?;
                    Some(u64::from_le_bytes(raw.try_into().ok()?))
                };
                let (Some(base), Some(map), Some(head)) = (
                    field("BaseAddress"),
                    field("SharedCacheMap"),
                    field("ArrayHead"),
                ) else {
                    continue;
                };
                if head == header.0 && base != 0 && map != 0 {
                    views.entry(map).or_default().push(VirtAddr(base));
                }
            }
        }

        let active_vacbs: u64 = views.values().map(|bases| bases.len() as u64).sum();
        let mut maps: Vec<(u64, u64, u64)> = views
            .iter()
            .map(|(map, bases)| {
                let mut valid = 0;
                for base in bases {
                    let _ = memory.for_each_present_page(
                        *base,
                        *base + VACB_MAPPING_GRANULARITY,
                        |_, _, length| {
                            valid += length;
                            ControlFlow::Continue(())
                        },
                    );
                }
                (*map, bases.len() as u64, valid)
            })
            .collect();
        let valid_bytes = maps.iter().map(|(.., valid)| valid).sum();
        maps.sort_by_key(|(.., valid)| Reverse(*valid));
        maps.truncate(MAX_CACHED_FILES);
        let map_layout = types.layout("_SHARED_CACHE_MAP")?;
        let files = maps
            .into_iter()
            .map(|(map, mapped_vacbs, valid)| {
                let map_ref = types
                    .struct_with_layout(map_layout.clone(), VirtAddr(map))
                    .prefetch();
                let file_object = map_ref
                    .read_uint("FileObjectFastRef")
                    .map(fast_ref_address)
                    .unwrap_or(VirtAddr(0));
                let read = |name: &str| DiagnosticValue::from_result(map_ref.read_uint(name));
                CachedFile {
                    shared_cache_map: VirtAddr(map),
                    file_object,
                    file_name: DiagnosticValue::from_result(self.file_object_name(file_object)),
                    file_size: read("FileSize"),
                    valid_data_length: read("ValidDataLength"),
                    open_count: read("OpenCount"),
                    dirty_pages: read("DirtyPages"),
                    mapped_vacbs,
                    valid_bytes: valid,
                }
            })
            .collect();
        Ok(FileCacheDetail {
            vacb_arrays,
            free_vacbs,
            active_vacbs,
            mapped_bytes: active_vacbs * VACB_MAPPING_GRANULARITY,
            valid_bytes,
            files,
            file_count: views.len() as u64,
            interrupted,
        })
    }
}
