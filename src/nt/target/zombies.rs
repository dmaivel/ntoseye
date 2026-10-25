//! `!zombies`: processes and threads that have exited but whose objects are
//! still referenced, found by scanning nonpaged pool for their allocations.
//!
//! An `_EPROCESS` or `_ETHREAD` lives in a small-pool block tagged `Proc` or
//! `Thre`, behind its `_OBJECT_HEADER` and the optional headers before that.
//! Each 16-byte step past the pool header is tried as the object header: it
//! is the one whose decoded `TypeIndex` is the Process (or Thread) type's and
//! whose body starts with that dispatcher-object type.

use std::ops::ControlFlow;

use crate::base::bytes::c_string_lossy;
use crate::base::error::{Error, Result};
use crate::base::memory::MemoryOps;
use crate::base::types::VirtAddr;
use crate::nt::layout::StructRef;
use crate::nt::target::Target;
use crate::nt::target::pool::{
    NONPAGED_POOL, pool_header_tags, pool_layout, pool_range, scan_present_pool_pages,
};
use ntoseye_macros::record;

/// Stop after this many zombies of each kind.
pub const MAX_ZOMBIES: usize = 4096;

/// How far past the pool header an object header may sit: the optional
/// headers (creator, name, handle, quota, process, audit, extended, and
/// padding info) fit well within it.
const MAX_OPTIONAL_HEADERS: u64 = 0x100;

const PROCESS_TAG: u32 = u32::from_le_bytes(*b"Proc");
const THREAD_TAG: u32 = u32::from_le_bytes(*b"Thre");

/// `_KOBJECTS` values in `_DISPATCHER_HEADER.Type`.
const PROCESS_OBJECT: u8 = 3;
const THREAD_OBJECT: u8 = 6;

/// `_KTHREAD_STATE::Terminated`.
const THREAD_TERMINATED: u64 = 4;

/// Which kinds `!zombies` looks for (WinDbg's flags: 1 processes, 2 threads).
#[record]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZombieKinds {
    pub processes: bool,
    pub threads: bool,
}

impl ZombieKinds {
    /// The kinds `flags` selects; an error when it selects neither.
    pub fn from_flags(flags: u64) -> Result<Self> {
        if flags & 3 == 0 {
            return Err(Error::InvalidArgument(format!(
                "flags {flags:#x} select nothing: 1 processes, 2 threads, 3 both"
            )));
        }
        Ok(Self {
            processes: flags & 1 != 0,
            threads: flags & 2 != 0,
        })
    }
}

/// Reference counts from the object header.
#[derive(Debug, Clone, Copy)]
struct ObjectCounts {
    pointer_count: i64,
    handle_count: i64,
}

/// An exited process whose object still has references.
#[record]
pub struct ZombieProcess {
    pub eprocess: VirtAddr,
    pub pid: u64,
    /// The image name.
    pub image: String,
    /// `_EPROCESS.ExitTime`, a FILETIME.
    #[record(hex)]
    pub exit_time: u64,
    /// The exit NTSTATUS.
    #[record(hex)]
    pub exit_status: u32,
    /// Open handles to the object.
    pub handle_count: i64,
    /// References to the object.
    pub pointer_count: i64,
}

/// A terminated thread whose object still has references.
#[record]
pub struct ZombieThread {
    pub ethread: VirtAddr,
    pub pid: u64,
    pub tid: u64,
    /// The owning `_EPROCESS` (`Tcb.Process`).
    pub process: VirtAddr,
    /// The image name of the owning process. `None` if ntoseye cannot read it.
    pub image: Option<String>,
    /// The exit NTSTATUS.
    #[record(hex)]
    pub exit_status: u32,
    /// Open handles to the object.
    pub handle_count: i64,
    /// References to the object.
    pub pointer_count: i64,
}

/// The exited processes and terminated threads that still have references
/// (`!zombies`), which ntoseye finds with a scan of nonpaged pool.
#[record]
pub struct Zombies {
    /// The kinds the scan looked for; the list of a kind it did not look for
    /// is empty.
    pub kinds: ZombieKinds,
    /// The start of the scanned pool region.
    pub region_start: VirtAddr,
    /// The end of the scanned pool region.
    pub region_end: VirtAddr,
    pub scanned_pages: u64,
    pub processes: Vec<ZombieProcess>,
    pub threads: Vec<ZombieThread>,
    /// The number of live processes that the scan found, to put the zombies
    /// in proportion.
    pub live_processes: usize,
    /// The number of live threads that the scan found.
    pub live_threads: usize,
    /// True if the scan was interrupted before it finished.
    pub interrupted: bool,
    /// True if a result list reached its limit ([`MAX_ZOMBIES`]).
    pub truncated: bool,
}

/// What locating an object in a block needs, resolved once.
struct ObjectQuery {
    header_size: u64,
    body_offset: u64,
    object_type: HeaderType,
    pointer_count_offset: u64,
    handle_count_offset: u64,
    process_type: Option<u64>,
    thread_type: Option<u64>,
}

/// How an object header names its type.
enum HeaderType {
    /// `TypeIndex`, the type's `Index` (Windows 7 on). `cookie` is
    /// `nt!ObHeaderCookie`, which Windows 10 XORs into it with the header
    /// address's second byte; `None` before, where it is stored as is.
    Index { offset: u64, cookie: Option<u8> },
    /// `Type`, the type object's address (Vista and earlier).
    Pointer { offset: u64 },
}

impl ObjectQuery {
    /// The object header in the block whose body starts at `start`, when one
    /// of the headers tried names type `object_type` (an index or a type
    /// object's address, by [`HeaderType`]) and its body starts with
    /// dispatcher type `kind`.
    fn find(
        &self,
        memory: &impl MemoryOps<VirtAddr>,
        start: VirtAddr,
        object_type: u64,
        kind: u8,
    ) -> Option<(VirtAddr, ObjectCounts)> {
        let mut bytes = vec![0u8; (MAX_OPTIONAL_HEADERS + self.header_size + 1) as usize];
        memory.read_bytes(start, &mut bytes).ok()?;
        (0..=MAX_OPTIONAL_HEADERS).step_by(16).find_map(|offset| {
            let header = start + offset;
            let at = |field: u64| bytes.get((offset + field) as usize).copied();
            let word = |field: u64| {
                let from = (offset + field) as usize;
                bytes
                    .get(from..from + 8)
                    .map(|word| i64::from_le_bytes(word.try_into().expect("8 bytes")))
            };
            let named = match self.object_type {
                HeaderType::Index {
                    offset: index,
                    cookie,
                } => {
                    let raw = at(index)?;
                    u64::from(cookie.map_or(raw, |cookie| raw ^ (header.0 >> 8) as u8 ^ cookie))
                }
                HeaderType::Pointer { offset: pointer } => word(pointer)? as u64,
            };
            if named != object_type || at(self.body_offset)? != kind {
                return None;
            }
            Some((
                header,
                ObjectCounts {
                    pointer_count: word(self.pointer_count_offset)?,
                    handle_count: word(self.handle_count_offset)?,
                },
            ))
        })
    }
}

impl Target {
    /// Scan nonpaged pool for exited processes and threads still referenced.
    pub fn zombies(&self, kinds: ZombieKinds) -> Result<Zombies> {
        let guest = self.guest()?;
        let nt = &guest.ntoskrnl;
        let memory = nt.memory();
        let header = nt.types().layout("_OBJECT_HEADER")?;
        let object_type = match header.field_offset("TypeIndex") {
            Ok(offset) => HeaderType::Index {
                offset,
                cookie: match nt.symbol("ObHeaderCookie") {
                    Ok(symbol) => Some(symbol.read::<u8>()?),
                    Err(Error::SymbolNotFound(_)) => None,
                    Err(error) => return Err(error),
                },
            },
            Err(_) => HeaderType::Pointer {
                offset: header.field_offset("Type")?,
            },
        };
        let index_offset = match object_type {
            HeaderType::Index { .. } => {
                Some(nt.types().layout("_OBJECT_TYPE")?.field_offset("Index")?)
            }
            HeaderType::Pointer { .. } => None,
        };
        // What a header of `type_symbol`'s objects holds.
        let named = |type_symbol: &str| -> Result<u64> {
            let object = nt.symbol(type_symbol)?.read_pointer()?;
            match index_offset {
                Some(offset) => memory.read::<u8>(object + offset).map(u64::from),
                None => Ok(object.0),
            }
        };
        let query = ObjectQuery {
            header_size: header.size as u64,
            body_offset: header.field_offset("Body")?,
            object_type,
            pointer_count_offset: header.field_offset("PointerCount")?,
            handle_count_offset: header.field_offset("HandleCount")?,
            process_type: kinds
                .processes
                .then(|| named("PsProcessType"))
                .transpose()?,
            thread_type: kinds.threads.then(|| named("PsThreadType")).transpose()?,
        };
        let layout = pool_layout(self)?;
        let (region_start, region_end) = pool_range(self, &NONPAGED_POOL)?;

        let mut detail = Zombies {
            kinds,
            region_start,
            region_end,
            scanned_pages: 0,
            processes: Vec::new(),
            threads: Vec::new(),
            live_processes: 0,
            live_threads: 0,
            interrupted: false,
            truncated: false,
        };
        let scan = scan_present_pool_pages(self, region_start, region_end, |page_va, page| {
            for (offset, tag) in pool_header_tags(&layout, page) {
                let start = page_va + offset + layout.header_size;
                match (tag & 0x7fff_ffff, query.process_type, query.thread_type) {
                    (PROCESS_TAG, Some(object_type), _) => {
                        let Some((header, counts)) =
                            query.find(&memory, start, object_type, PROCESS_OBJECT)
                        else {
                            continue;
                        };
                        match self.zombie_process(header + query.body_offset, counts) {
                            Ok(Some(zombie)) => detail.processes.push(zombie),
                            Ok(None) => detail.live_processes += 1,
                            Err(_) => {}
                        }
                    }
                    (THREAD_TAG, _, Some(object_type)) => {
                        let Some((header, counts)) =
                            query.find(&memory, start, object_type, THREAD_OBJECT)
                        else {
                            continue;
                        };
                        match self.zombie_thread(header + query.body_offset, counts) {
                            Ok(Some(zombie)) => detail.threads.push(zombie),
                            Ok(None) => detail.live_threads += 1,
                            Err(_) => {}
                        }
                    }
                    _ => {}
                }
            }
            if detail.processes.len() >= MAX_ZOMBIES || detail.threads.len() >= MAX_ZOMBIES {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        })?;
        detail.scanned_pages = scan.pages;
        detail.interrupted = self.interrupted();
        detail.truncated = scan.stopped_at.is_some() && !detail.interrupted;
        Ok(detail)
    }

    /// The process at `eprocess` when it has exited (`ExitTime` set).
    fn zombie_process(
        &self,
        eprocess: VirtAddr,
        counts: ObjectCounts,
    ) -> Result<Option<ZombieProcess>> {
        let types = self.guest()?.ntoskrnl.types();
        let process = types.struct_at("_EPROCESS", eprocess)?.prefetch();
        let exit_time: u64 = process.read_field("ExitTime")?;
        if exit_time == 0 {
            return Ok(None);
        }
        Ok(Some(ZombieProcess {
            eprocess,
            pid: process.read_uint("UniqueProcessId")?,
            image: image_file_name(&process).unwrap_or_default(),
            exit_time,
            exit_status: process.read_field("ExitStatus").unwrap_or(0),
            handle_count: counts.handle_count,
            pointer_count: counts.pointer_count,
        }))
    }

    /// The thread at `ethread` when it has terminated.
    fn zombie_thread(
        &self,
        ethread: VirtAddr,
        counts: ObjectCounts,
    ) -> Result<Option<ZombieThread>> {
        let types = self.guest()?.ntoskrnl.types();
        let thread = types.struct_at("_ETHREAD", ethread)?.prefetch();
        let tcb = thread.embedded("Tcb")?;
        if tcb.read_uint("State")? != THREAD_TERMINATED {
            return Ok(None);
        }
        let process = tcb.read_pointer("Process")?;
        let image = types
            .struct_at("_EPROCESS", process)
            .ok()
            .and_then(|process| image_file_name(&process))
            .filter(|image| !image.is_empty());
        let cid = thread.embedded("Cid")?;
        Ok(Some(ZombieThread {
            ethread,
            pid: cid.read_uint("UniqueProcess")?,
            tid: cid.read_uint("UniqueThread")?,
            process,
            image,
            exit_status: thread.read_field("ExitStatus").unwrap_or(0),
            handle_count: counts.handle_count,
            pointer_count: counts.pointer_count,
        }))
    }
}

/// `_EPROCESS.ImageFileName`, up to its NUL.
fn image_file_name(process: &StructRef<'_>) -> Option<String> {
    let bytes = process.read_field_bytes("ImageFileName", 16).ok()?;
    Some(c_string_lossy(&bytes))
}
