//! `!zombies`: processes and threads that have exited but whose objects are
//! still referenced, found by scanning nonpaged pool for their allocations.
//!
//! An `_EPROCESS` or `_ETHREAD` lives in a small-pool block tagged `Proc` or
//! `Thre`, behind its `_OBJECT_HEADER` and the optional headers before that.
//! Each 16-byte step past the pool header is tried as the object header: it
//! is the one whose decoded `TypeIndex` is the Process (or Thread) type's and
//! whose body starts with that dispatcher-object type.

use std::ops::ControlFlow;

use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::layout::StructRef;
use crate::target::Target;
use crate::target::pool::{
    NONPAGED_POOL, pool_header_tags, pool_layout, pool_range, scan_present_pool_pages,
};
use crate::types::VirtAddr;

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
pub struct ObjectCounts {
    pub pointer_count: i64,
    pub handle_count: i64,
}

#[derive(Debug, Clone)]
pub struct ZombieProcess {
    pub eprocess: VirtAddr,
    pub pid: u64,
    pub image: String,
    /// `ExitTime`, a FILETIME.
    pub exit_time: u64,
    pub exit_status: u32,
    pub counts: ObjectCounts,
}

#[derive(Debug, Clone)]
pub struct ZombieThread {
    pub ethread: VirtAddr,
    pub pid: u64,
    pub tid: u64,
    /// `Tcb.Process`.
    pub process: VirtAddr,
    /// The owning process's image name, when its object is readable.
    pub image: Option<String>,
    pub exit_status: u32,
    pub counts: ObjectCounts,
}

#[derive(Debug, Clone)]
pub struct ZombiesDetail {
    pub kinds: ZombieKinds,
    pub region_start: VirtAddr,
    pub region_end: VirtAddr,
    pub scanned_pages: u64,
    pub processes: Vec<ZombieProcess>,
    pub threads: Vec<ZombieThread>,
    /// Live objects of each kind decoded, to put the zombies in proportion.
    pub live_processes: usize,
    pub live_threads: usize,
    /// The scan stopped early: interrupted, or at the result bound.
    pub interrupted: bool,
    pub truncated: bool,
}

/// What locating an object in a block needs, resolved once.
struct ObjectQuery {
    header_size: u64,
    body_offset: u64,
    type_index_offset: u64,
    pointer_count_offset: u64,
    handle_count_offset: u64,
    cookie: u8,
    process_index: Option<u8>,
    thread_index: Option<u8>,
}

impl ObjectQuery {
    /// The object header in the block whose body starts at `start`, when one
    /// of the headers tried decodes to type `index` and its body starts
    /// with dispatcher type `kind`.
    fn find(
        &self,
        memory: &impl MemoryOps<VirtAddr>,
        start: VirtAddr,
        index: u8,
        kind: u8,
    ) -> Option<(VirtAddr, ObjectCounts)> {
        let mut bytes = vec![0u8; (MAX_OPTIONAL_HEADERS + self.header_size + 1) as usize];
        memory.read_bytes(start, &mut bytes).ok()?;
        (0..=MAX_OPTIONAL_HEADERS).step_by(16).find_map(|offset| {
            let header = start + offset;
            let at = |field: u64| bytes.get((offset + field) as usize).copied();
            let raw = at(self.type_index_offset)?;
            let decoded = raw ^ ((header.0 >> 8) as u8) ^ self.cookie;
            if decoded != index || at(self.body_offset)? != kind {
                return None;
            }
            let word = |field: u64| {
                let from = (offset + field) as usize;
                bytes
                    .get(from..from + 8)
                    .map(|word| i64::from_le_bytes(word.try_into().expect("8 bytes")))
            };
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
    pub fn zombies(&self, kinds: ZombieKinds) -> Result<ZombiesDetail> {
        let guest = self.guest()?;
        let nt = &guest.ntoskrnl;
        let memory = nt.memory();
        let header = nt.types().layout("_OBJECT_HEADER")?;
        let index_offset = nt.types().layout("_OBJECT_TYPE")?.field_offset("Index")?;
        let type_index = |type_symbol: &str| -> Result<u8> {
            let object = nt.symbol(type_symbol)?.read::<VirtAddr>()?;
            memory.read::<u8>(object + index_offset)
        };
        let query = ObjectQuery {
            header_size: header.size as u64,
            body_offset: header.field_offset("Body")?,
            type_index_offset: header.field_offset("TypeIndex")?,
            pointer_count_offset: header.field_offset("PointerCount")?,
            handle_count_offset: header.field_offset("HandleCount")?,
            cookie: match nt.symbol("ObHeaderCookie") {
                Ok(symbol) => symbol.read::<u8>()?,
                Err(Error::SymbolNotFound(_)) => 0,
                Err(error) => return Err(error),
            },
            process_index: kinds
                .processes
                .then(|| type_index("PsProcessType"))
                .transpose()?,
            thread_index: kinds
                .threads
                .then(|| type_index("PsThreadType"))
                .transpose()?,
        };
        let layout = pool_layout(self)?;
        let (region_start, region_end) = pool_range(self, &NONPAGED_POOL)?;

        let mut detail = ZombiesDetail {
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
                match (tag & 0x7fff_ffff, query.process_index, query.thread_index) {
                    (PROCESS_TAG, Some(index), _) => {
                        let Some((header, counts)) =
                            query.find(&memory, start, index, PROCESS_OBJECT)
                        else {
                            continue;
                        };
                        match self.zombie_process(header + query.body_offset, counts) {
                            Ok(Some(zombie)) => detail.processes.push(zombie),
                            Ok(None) => detail.live_processes += 1,
                            Err(_) => {}
                        }
                    }
                    (THREAD_TAG, _, Some(index)) => {
                        let Some((header, counts)) =
                            query.find(&memory, start, index, THREAD_OBJECT)
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
            counts,
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
            counts,
        }))
    }
}

/// `_EPROCESS.ImageFileName`, up to its NUL.
fn image_file_name(process: &StructRef<'_>) -> Option<String> {
    let bytes = process.read_field_bytes("ImageFileName", 16).ok()?;
    let end = bytes
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(bytes.len());
    Some(String::from_utf8_lossy(&bytes[..end]).into_owned())
}
