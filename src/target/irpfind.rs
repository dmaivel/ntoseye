//! `!irpfind`: find IRPs by scanning pool for `IoAllocateIrp`'s allocations
//! (pool tag `Irp `) and keeping those whose body decodes as a live `_IRP`.
//!
//! The pool's mapped pages are read as [`scan_present_pool_pages`] reads
//! them (on Windows 10 1803 and later a few hundred MiB mapped sparsely
//! across a fixed region of terabytes), and every 16-byte-aligned
//! `_POOL_HEADER` tag is checked (see [`pool_header_tags`]). Big
//! allocations (a page or more) have no header and come from
//! `PoolBigPageTable` instead.

use std::collections::HashMap;
use std::ops::ControlFlow;

use crate::error::{Error, Result};
use crate::layout::{StructRef, Types};
use crate::memory::PAGE_SIZE;
use crate::target::Target;
use crate::target::object::{IrpInfo, irp_thread};
use crate::target::pool::{
    NONPAGED_POOL, PAGED_POOL, PoolRange, pool_header_tags, pool_layout, pool_range,
    scan_big_pool_entries, scan_present_pool_pages, tag_string,
};
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

    /// Its WinDbg pool-type number.
    pub fn windbg(self) -> u8 {
        match self {
            Self::NonPaged => 0,
            Self::Paged => 1,
        }
    }

    fn range(self) -> &'static PoolRange {
        match self {
            Self::NonPaged => &NONPAGED_POOL,
            Self::Paged => &PAGED_POOL,
        }
    }
}

/// A parsed `!irpfind [-v] [pool-type [restart-address [criteria data]]]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IrpFindArgs {
    /// `-v`: the text rendering adds each IRP's details.
    pub verbose: bool,
    pub pool: IrpPool,
    /// Where to resume the page scan; a restart address of 0 is none.
    pub restart: Option<VirtAddr>,
    pub criteria: Option<IrpCriteria>,
}

impl IrpFindArgs {
    pub const USAGE: &str = "!irpfind [-v] [pool-type [restart-address [criteria data]]]";

    /// Parse `argv` as WinDbg does; `eval` evaluates the pool type, restart
    /// address, and criteria data (the criteria name is a word).
    pub fn parse<S: AsRef<str>>(argv: &[S], eval: impl Fn(&str) -> Result<u64>) -> Result<Self> {
        let verbose = argv
            .first()
            .is_some_and(|arg| arg.as_ref().eq_ignore_ascii_case("-v"));
        let rest = &argv[usize::from(verbose)..];
        if rest.len() == 3 || rest.len() > 4 {
            return Err(Error::InvalidArgument(format!("usage: {}", Self::USAGE)));
        }
        let pool = IrpPool::from_windbg(match rest.first() {
            Some(text) => eval(text.as_ref())?,
            None => 0,
        })?;
        let restart = match rest.get(1) {
            Some(text) => Some(VirtAddr(eval(text.as_ref())?)).filter(|at| !at.is_zero()),
            None => None,
        };
        let criteria = match (rest.get(2), rest.get(3)) {
            (Some(name), Some(value)) => {
                Some(IrpCriteria::parse(name.as_ref(), eval(value.as_ref())?)?)
            }
            _ => None,
        };
        Ok(Self {
            verbose,
            pool,
            restart,
            criteria,
        })
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
    /// The result bound left IRPs out: the page scan stopped at `restart`,
    /// or big-pool allocations went unchecked (`big_pool_status` counts
    /// them; no restart reaches those).
    pub truncated: bool,
    pub interrupted: bool,
    pub restart: Option<VirtAddr>,
}

/// What `!irpfind` keeps: `sizeof(_IRP)` and `sizeof(_IO_STACK_LOCATION)`
/// to validate a candidate by, and the criteria it must match.
#[derive(Clone, Copy)]
struct IrpQuery {
    irp_size: u64,
    stack_size: u64,
    criteria: Option<IrpCriteria>,
}

impl Target {
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
        let query = IrpQuery {
            irp_size: types.layout("_IRP")?.size as u64,
            stack_size: types.layout("_IO_STACK_LOCATION")?.size as u64,
            criteria,
        };
        let (region_start, region_end) = pool_range(self, pool.range())?;
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

        let is_irp_tag = |tag: u32| tag.to_le_bytes()[..3] == IRP_TAG_PREFIX[..];
        let mut irps = Vec::new();
        let mut drivers = HashMap::new();
        let mut accept = |irps: &mut Vec<IrpFindEntry>, header, body, tag| {
            irps.extend(self.irp_find_entry(types, body, header, tag, query, &mut drivers));
        };
        let scan = scan_present_pool_pages(self, scan_start, region_end, |page_va, page| {
            for (offset, tag) in pool_header_tags(&layout, page) {
                if is_irp_tag(tag) {
                    let header = page_va + offset;
                    accept(&mut irps, Some(header), header + layout.header_size, tag);
                }
            }
            if irps.len() >= MAX_IRPFIND_RESULTS {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        })?;

        let mut truncated = scan.stopped_at.is_some() && !self.interrupted();
        let big_pool_status = if scan.stopped_at.is_some() {
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
                        && is_irp_tag(entry.tag)
                    {
                        big.push((entry.va, entry.tag));
                    }
                    false
                },
            )
            .status;
            let room = MAX_IRPFIND_RESULTS.saturating_sub(irps.len());
            let unchecked = big.len().saturating_sub(room);
            for (body, tag) in big.into_iter().take(room) {
                accept(&mut irps, None, body, tag);
            }
            if unchecked == 0 {
                status
            } else {
                truncated = true;
                format!(
                    "{status}; {unchecked} tagged allocation(s) not checked (the {MAX_IRPFIND_RESULTS}-IRP bound)"
                )
            }
        };
        Ok(IrpFindDetail {
            pool,
            region_start,
            region_end,
            scan_start,
            criteria,
            scanned_pages: scan.pages,
            big_pool_status,
            truncated,
            interrupted: self.interrupted(),
            restart: scan.stopped_at,
            irps,
        })
    }

    /// The `_IRP` at `body` when it is a live one matching `criteria`:
    /// `Type` is `IO_TYPE_IRP`, `Size` is the header plus whole stack
    /// locations and at least `IoSizeOfIrp(StackCount)` (an IRP from a
    /// lookaside list keeps the list's larger packet size), and
    /// `CurrentLocation` is at most one past `StackCount`. The criteria the
    /// `_IRP` itself answers are tested before anything else is read.
    fn irp_find_entry(
        &self,
        types: Types<'_>,
        body: VirtAddr,
        pool_header: Option<VirtAddr>,
        tag: u32,
        query: IrpQuery,
        drivers: &mut HashMap<VirtAddr, Option<String>>,
    ) -> Option<IrpFindEntry> {
        let irp = types.struct_at("_IRP", body).ok()?.prefetch();
        let kind: u16 = irp.read_field("Type").ok()?;
        let size: u16 = irp.read_field("Size").ok()?;
        let stack_count: u8 = irp.read_field("StackCount").ok()?;
        let current: u8 = irp.read_field("CurrentLocation").ok()?;
        let size = u64::from(size);
        if kind != IO_TYPE_IRP
            || size < query.irp_size + u64::from(stack_count) * query.stack_size
            || !(size - query.irp_size).is_multiple_of(query.stack_size)
            || current > stack_count.saturating_add(1)
        {
            return None;
        }
        let original_file_object = irp
            .embedded("Tail")
            .and_then(|tail| tail.embedded("Overlay"))
            .and_then(|overlay| overlay.read_pointer("OriginalFileObject"))
            .unwrap_or(VirtAddr(0));
        let matches = match query.criteria {
            None | Some(IrpCriteria::MdlProcess(_)) => true,
            Some(IrpCriteria::Thread(address)) => irp_thread(&irp) == address,
            Some(IrpCriteria::UserEvent(address)) => {
                irp.read_pointer("UserEvent").ok() == Some(address)
            }
            Some(IrpCriteria::FileObject(address)) => original_file_object == address,
            Some(criteria @ (IrpCriteria::Arg(_) | IrpCriteria::Device(_))) => {
                irp_stack_matches(types, body, stack_count, query, criteria)
            }
        };
        if !matches {
            return None;
        }
        let info = self.irp_info(&irp).ok()?;
        let mdl_process = (!info.mdl_address.is_zero())
            .then(|| {
                types
                    .struct_at("_MDL", info.mdl_address)
                    .and_then(|mdl| mdl.read_pointer("Process"))
                    .ok()
            })
            .flatten();
        if let Some(IrpCriteria::MdlProcess(address)) = query.criteria
            && mdl_process != Some(address)
        {
            return None;
        }
        let driver = info.current_stack().and_then(|stack| {
            let device = stack.device_object;
            if device.is_zero() {
                return None;
            }
            drivers
                .entry(device)
                .or_insert_with(|| self.device_driver_name(device))
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
}

/// Whether one of the `stack_count` stack locations after the `_IRP` at
/// `irp` matches the `arg` or `device` criterion.
fn irp_stack_matches(
    types: Types<'_>,
    irp: VirtAddr,
    stack_count: u8,
    query: IrpQuery,
    criteria: IrpCriteria,
) -> bool {
    let first = irp + query.irp_size;
    (0..u64::from(stack_count)).any(|index| {
        let Ok(stack) = types
            .struct_at("_IO_STACK_LOCATION", first + index * query.stack_size)
            .map(StructRef::prefetch)
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
