//! `!irpfind`: find IRPs by scanning pool for `IoAllocateIrp`'s allocations
//! (pool tag `Irp `) and keeping those whose body decodes as a live `_IRP`.
//!
//! Windows 10 and later place pool in fixed system-VA regions
//! (`MiState.Vs.SystemVaRegions`), a few hundred MiB of pages mapped
//! sparsely across terabytes; the page tables are walked so only mapped
//! pages are read. Segment-heap blocks still begin with a `_POOL_HEADER`
//! carrying the tag, so a 16-byte-aligned tag match marks a candidate. Big
//! allocations (a page or more) have no header and come from
//! `PoolBigPageTable` instead.

use std::collections::HashMap;
use std::ops::ControlFlow;

use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::layout::ParsedType;
use crate::memory::PAGE_SIZE;
use crate::target::Target;
use crate::target::object::IrpInfo;
use crate::target::pool::{pool_layout, scan_big_pool_entries, tag_string};
use crate::types::VirtAddr;

/// `IoAllocateIrp`'s tag, as the first three bytes of the little-endian
/// `PoolTag`; the fourth byte is matched loosely so `Irp?` variants count.
const IRP_TAG_PREFIX: &[u8; 3] = b"Irp";
/// `_IRP.Type` of a live IRP (`IO_TYPE_IRP`); `IoFreeIrp` clears it.
const IO_TYPE_IRP: u16 = 6;
const MAX_IRPFIND_RESULTS: usize = 4096;

/// A WinDbg `!irpfind` criterion: only IRPs matching it are listed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrpCriteria {
    /// A stack location whose `Parameters.Others.Argument1..4` holds it.
    Arg(u64),
    /// A stack location whose `DeviceObject` is it.
    Device(VirtAddr),
    /// `Tail.Overlay.OriginalFileObject`.
    FileObject(VirtAddr),
    /// `MdlAddress->Process`.
    MdlProcess(VirtAddr),
    /// `Tail.Overlay.Thread`.
    Thread(VirtAddr),
    /// `UserEvent`.
    UserEvent(VirtAddr),
}

impl IrpCriteria {
    /// The criterion WinDbg names `name`, matching `value`.
    pub fn parse(name: &str, value: u64) -> Result<Self> {
        Ok(match name.to_ascii_lowercase().as_str() {
            "arg" => Self::Arg(value),
            "device" => Self::Device(VirtAddr(value)),
            "fileobject" => Self::FileObject(VirtAddr(value)),
            "mdlprocess" => Self::MdlProcess(VirtAddr(value)),
            "thread" => Self::Thread(VirtAddr(value)),
            "userevent" => Self::UserEvent(VirtAddr(value)),
            other => {
                return Err(Error::InvalidArgument(format!(
                    "unknown !irpfind criteria '{other}' (arg, device, fileobject, mdlprocess, \
                     thread, userevent)"
                )));
            }
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Arg(_) => "arg",
            Self::Device(_) => "device",
            Self::FileObject(_) => "fileobject",
            Self::MdlProcess(_) => "mdlprocess",
            Self::Thread(_) => "thread",
            Self::UserEvent(_) => "userevent",
        }
    }

    pub fn value(self) -> u64 {
        match self {
            Self::Arg(value) => value,
            Self::Device(address)
            | Self::FileObject(address)
            | Self::MdlProcess(address)
            | Self::Thread(address)
            | Self::UserEvent(address) => address.0,
        }
    }
}

/// The pool `!irpfind` searches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrpPool {
    NonPaged,
    Paged,
}

impl IrpPool {
    /// WinDbg's pool-type argument: 0 nonpaged, 1 paged. Special (2) and
    /// session (4) pool have no region of their own on these builds.
    pub fn from_windbg(value: u64) -> Result<Self> {
        match value {
            0 => Ok(Self::NonPaged),
            1 => Ok(Self::Paged),
            2 | 4 => Err(Error::InvalidArgument(format!(
                "pool type {value} ({}) is not searched: Windows 10 and later keep no separate \
                 region for it; use 0 (nonpaged) or 1 (paged)",
                if value == 2 {
                    "special pool"
                } else {
                    "session pool"
                }
            ))),
            other => Err(Error::InvalidArgument(format!(
                "pool type {other} is not 0 (nonpaged), 1 (paged), 2 (special), or 4 (session)"
            ))),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::NonPaged => "NonPaged",
            Self::Paged => "Paged",
        }
    }

    /// The `_MI_ASSIGNED_REGION_TYPES` value naming its system-VA region.
    fn region(self) -> &'static str {
        match self {
            Self::NonPaged => "AssignedRegionNonPagedPool",
            Self::Paged => "AssignedRegionPagedPool",
        }
    }
}

/// One IRP found in pool.
#[derive(Debug, Clone)]
pub struct IrpFindEntry {
    pub irp: IrpInfo,
    /// The `_POOL_HEADER` before it; `None` for a big-pool allocation.
    pub pool_header: Option<VirtAddr>,
    pub tag: String,
    /// `Tail.Overlay.OriginalFileObject`.
    pub original_file_object: VirtAddr,
    /// `MdlAddress->Process`, when there is an MDL.
    pub mdl_process: Option<VirtAddr>,
    /// Name of the driver owning the current stack location's device.
    pub driver: Option<String>,
}

impl IrpFindEntry {
    /// Every stack location is used up: the IRP is being (or was) completed.
    pub fn completed(&self) -> bool {
        self.irp.current_location > self.irp.stack_count
    }
}

/// The result of one `!irpfind` search.
#[derive(Debug, Clone)]
pub struct IrpFindDetail {
    pub pool: IrpPool,
    pub region_start: VirtAddr,
    pub region_end: VirtAddr,
    /// Where the page scan began (the region start or the restart address).
    pub scan_start: VirtAddr,
    pub criteria: Option<IrpCriteria>,
    pub scanned_pages: u64,
    pub big_pool_status: String,
    pub irps: Vec<IrpFindEntry>,
    /// The result bound or an interrupt ended the scan early; `restart` is
    /// where to resume.
    pub truncated: bool,
    pub interrupted: bool,
    pub restart: Option<VirtAddr>,
}

impl Target {
    /// Base and end of the `MiState.Vs.SystemVaRegions` entry `region`
    /// (an `_MI_ASSIGNED_REGION_TYPES` name).
    fn assigned_system_va_region(&self, region: &str) -> Result<(VirtAddr, VirtAddr)> {
        let ntos = &self.guest()?.ntoskrnl;
        let types = ntos.types();
        let missing = |why: String| {
            Error::DebugInfo(format!(
                "cannot locate the {region} system-VA region ({why}); !irpfind scans the fixed \
                 pool regions of Windows 10 1803 and later"
            ))
        };
        let index = self
            .symbols
            .find_enum_across_modules(ntos.dtb(), "_MI_ASSIGNED_REGION_TYPES")
            .and_then(|values| values.into_iter().find(|(name, _)| name == region))
            .map(|(_, value)| value as u64)
            .ok_or_else(|| missing("no _MI_ASSIGNED_REGION_TYPES value".into()))?;
        let info = types
            .layout("_MI_SYSTEM_INFORMATION")
            .map_err(|error| missing(error.to_string()))?;
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
        let entry = ntos.symbol("MiState")?.address()
            + info.field_offset("Vs")?
            + regions.offset as u64
            + index * entry_size;
        let assignment = types.struct_at("_MI_SYSTEM_VA_ASSIGNMENT", entry)?;
        let base = assignment.read_pointer("BaseAddress")?;
        let size = assignment.read_uint("NumberOfBytes")?;
        if base.is_zero() || size == 0 {
            return Err(missing("the region is not assigned".into()));
        }
        Ok((base, base + size))
    }

    /// Scan `pool` for IRPs, from `restart` when given, listing those that
    /// match `criteria`. Stops after 4,096 IRPs or when interrupted, at a
    /// page boundary, and says where to restart.
    pub fn irp_find(
        &self,
        pool: IrpPool,
        restart: Option<VirtAddr>,
        criteria: Option<IrpCriteria>,
    ) -> Result<IrpFindDetail> {
        let layout = pool_layout(self)?;
        let types = self.guest()?.ntoskrnl.types();
        let irp_size = types.layout("_IRP")?.size as u64;
        let stack_size = types.layout("_IO_STACK_LOCATION")?.size as u64;
        let (region_start, region_end) = self.assigned_system_va_region(pool.region())?;
        let scan_start = match restart {
            Some(address) if address < region_start || address >= region_end => {
                return Err(Error::InvalidArgument(format!(
                    "restart address {:#x} is outside {} pool ({:#x} - {:#x})",
                    address.0,
                    pool.name(),
                    region_start.0,
                    region_end.0
                )));
            }
            Some(address) => VirtAddr(address.0 & !(PAGE_SIZE as u64 - 1)),
            None => region_start,
        };

        let header_size = layout.header_size;
        let tag_offset = layout.pool_tag_offset as usize;
        let mut candidates: Vec<(VirtAddr, VirtAddr, u32)> = Vec::new();
        let mut irps = Vec::new();
        let mut scanned_pages = 0u64;
        let mut restart_at = None;
        let mut drivers = HashMap::new();
        let mut page = vec![0u8; PAGE_SIZE];
        let accept = |target: &Target,
                      irps: &mut Vec<IrpFindEntry>,
                      drivers: &mut HashMap<VirtAddr, Option<String>>,
                      header: Option<VirtAddr>,
                      body: VirtAddr,
                      tag: u32| {
            if let Some(entry) =
                target.irp_find_entry(body, header, tag, irp_size, stack_size, drivers)
                && criteria.is_none_or(|criteria| target.irp_matches(&entry, criteria, stack_size))
            {
                irps.push(entry);
            }
        };
        self.kernel_address_space().for_each_present_page(
            scan_start,
            region_end,
            |va, physical, length| {
                for offset in (0..length).step_by(PAGE_SIZE) {
                    if self.interrupted() || irps.len() >= MAX_IRPFIND_RESULTS {
                        restart_at = Some(va + offset);
                        return ControlFlow::Break(());
                    }
                    scanned_pages += 1;
                    if self.phys.read_bytes(physical + offset, &mut page).is_err() {
                        continue;
                    }
                    let page_va = va + offset;
                    candidates.clear();
                    for at in (0..PAGE_SIZE).step_by(header_size as usize) {
                        let tag = &page[at + tag_offset..at + tag_offset + 4];
                        if tag[..3] != IRP_TAG_PREFIX[..] {
                            continue;
                        }
                        let header = page_va + at as u64;
                        let tag = u32::from_le_bytes(tag.try_into().expect("4-byte tag"));
                        candidates.push((header, header + header_size, tag));
                    }
                    for &(header, body, tag) in &candidates {
                        accept(self, &mut irps, &mut drivers, Some(header), body, tag);
                    }
                }
                ControlFlow::Continue(())
            },
        )?;

        let big_pool_status = if restart_at.is_some() {
            "not searched (the page scan stopped first)".to_string()
        } else {
            let mut big = Vec::new();
            let status = scan_big_pool_entries(
                self,
                layout.big_pool_type.as_deref(),
                layout.big_pool_uses_struct,
                layout.big_pool_has_pool_type,
                layout.big_pool_has_slush,
                |entry| {
                    if entry.nonpaged == (pool == IrpPool::NonPaged)
                        && entry.va >= scan_start
                        && entry.va < region_end
                        && entry.tag.to_le_bytes()[..3] == IRP_TAG_PREFIX[..]
                    {
                        big.push((entry.va, entry.tag));
                    }
                    false
                },
            )
            .status;
            for (body, tag) in big {
                if irps.len() >= MAX_IRPFIND_RESULTS {
                    break;
                }
                accept(self, &mut irps, &mut drivers, None, body, tag);
            }
            status
        };
        let interrupted = self.interrupted();
        Ok(IrpFindDetail {
            pool,
            region_start,
            region_end,
            scan_start,
            criteria,
            scanned_pages,
            big_pool_status,
            truncated: restart_at.is_some() && !interrupted,
            interrupted,
            restart: restart_at,
            irps,
        })
    }

    /// Decode the `_IRP` at `body` when it is a live one: `Type` is
    /// `IO_TYPE_IRP`, `Size` is the header plus whole stack locations and at
    /// least `IoSizeOfIrp(StackCount)` (an IRP from a lookaside list keeps
    /// the list's larger packet size), and `CurrentLocation` is at most one
    /// past `StackCount`.
    fn irp_find_entry(
        &self,
        body: VirtAddr,
        pool_header: Option<VirtAddr>,
        tag: u32,
        irp_size: u64,
        stack_size: u64,
        drivers: &mut HashMap<VirtAddr, Option<String>>,
    ) -> Option<IrpFindEntry> {
        let types = self.guest().ok()?.ntoskrnl.types();
        let irp = types.struct_at("_IRP", body).ok()?.prefetch();
        let kind: u16 = irp.read_field("Type").ok()?;
        let size: u16 = irp.read_field("Size").ok()?;
        let stack_count: u8 = irp.read_field("StackCount").ok()?;
        let current: u8 = irp.read_field("CurrentLocation").ok()?;
        let size = u64::from(size);
        if kind != IO_TYPE_IRP
            || size < irp_size + u64::from(stack_count) * stack_size
            || !(size - irp_size).is_multiple_of(stack_size)
            || current > stack_count.saturating_add(1)
        {
            return None;
        }
        let info = self.inspect_irp(body).ok()?;
        let original_file_object = irp
            .embedded("Tail")
            .and_then(|tail| tail.embedded("Overlay"))
            .and_then(|overlay| overlay.read_pointer("OriginalFileObject"))
            .unwrap_or(VirtAddr(0));
        let mdl_process = (!info.mdl_address.is_zero())
            .then(|| {
                types
                    .struct_at("_MDL", info.mdl_address)
                    .and_then(|mdl| mdl.read_pointer("Process"))
                    .ok()
            })
            .flatten();
        let driver = info.current_stack.as_ref().and_then(|stack| {
            let device = stack.device_object;
            if device.is_zero() {
                return None;
            }
            drivers
                .entry(device)
                .or_insert_with(|| {
                    let driver = types
                        .struct_at("_DEVICE_OBJECT", device)
                        .and_then(|device| device.read_pointer("DriverObject"))
                        .ok()?;
                    types
                        .struct_at("_DRIVER_OBJECT", driver)
                        .and_then(|driver| driver.unicode_string("DriverName"))
                        .ok()
                        .filter(|name| !name.is_empty())
                })
                .clone()
        });
        Some(IrpFindEntry {
            irp: info,
            pool_header,
            tag: tag_string(tag),
            original_file_object,
            mdl_process,
            driver,
        })
    }

    fn irp_matches(&self, entry: &IrpFindEntry, criteria: IrpCriteria, stack_size: u64) -> bool {
        let irp = &entry.irp;
        match criteria {
            IrpCriteria::FileObject(address) => entry.original_file_object == address,
            IrpCriteria::MdlProcess(address) => entry.mdl_process == Some(address),
            IrpCriteria::Thread(address) => irp.thread == address,
            IrpCriteria::UserEvent(address) => irp.user_event == address,
            IrpCriteria::Arg(_) | IrpCriteria::Device(_) => {
                let Ok(types) = self.guest().map(|guest| guest.ntoskrnl.types()) else {
                    return false;
                };
                let Ok(irp_layout) = types.layout("_IRP") else {
                    return false;
                };
                let first = irp.address + irp_layout.size as u64;
                (0..u64::from(irp.stack_count)).any(|index| {
                    let Ok(stack) =
                        types.struct_at("_IO_STACK_LOCATION", first + index * stack_size)
                    else {
                        return false;
                    };
                    match criteria {
                        IrpCriteria::Device(address) => {
                            stack.read_pointer("DeviceObject").ok() == Some(address)
                        }
                        IrpCriteria::Arg(value) => stack
                            .embedded("Parameters")
                            .and_then(|parameters| parameters.embedded("Others"))
                            .is_ok_and(|others| {
                                ["Argument1", "Argument2", "Argument3", "Argument4"]
                                    .iter()
                                    .any(|name| others.read_uint(name).ok() == Some(value))
                            }),
                        _ => false,
                    }
                })
            }
        }
    }
}
