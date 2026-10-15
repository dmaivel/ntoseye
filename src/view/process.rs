//! Global-flag and zombie [`View`] builders.

use crate::target::DiagnosticValue;
use ntoseye_macros::record;

use crate::guest::ProcessInfo;
use crate::target::gflag::{GlobalFlagsDetail, global_flags_set};

use crate::target::zombies::ZombiesDetail;

use crate::types::VirtAddr;

/// One GFlags flag that is set.
#[record]
pub struct GlobalFlag {
    /// The bit mask of the flag.
    #[record(hex)]
    pub bit: u32,
    /// The GFlags abbreviation (`hpa`, `ust`, ...).
    pub abbreviation: &'static str,
    pub description: &'static str,
}

/// The `_PEB.NtGlobalFlag` of a process.
#[record]
pub struct ProcessGlobalFlags {
    #[record(hex)]
    pub value: u32,
    pub flags: Vec<GlobalFlag>,
}

/// `nt!NtGlobalFlag` and the `_PEB.NtGlobalFlag` of the current process
/// (`!gflag`).
#[record]
pub struct GlobalFlags {
    /// The address of `nt!NtGlobalFlag`.
    pub kernel_address: VirtAddr,
    /// `nt!NtGlobalFlag`.
    #[record(hex)]
    pub kernel: u32,
    pub kernel_flags: Vec<GlobalFlag>,
    /// The current process. `None` if no process is selected.
    pub process: Option<ProcessInfo>,
    /// The flags of the current process, read from its PEB.
    pub process_flags: DiagnosticValue<ProcessGlobalFlags>,
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
    pub handle_count: u64,
    /// References to the object.
    pub pointer_count: u64,
}

/// A terminated thread whose object still has references.
#[record]
pub struct ZombieThread {
    pub ethread: VirtAddr,
    pub pid: u64,
    pub tid: u64,
    /// The owning `_EPROCESS`.
    pub process: VirtAddr,
    /// The image name of the owning process. `None` if ntoseye cannot read it.
    pub image: Option<String>,
    /// The exit NTSTATUS.
    #[record(hex)]
    pub exit_status: u32,
    /// Open handles to the object.
    pub handle_count: u64,
    /// References to the object.
    pub pointer_count: u64,
}

/// The exited processes and terminated threads that still have references
/// (`!zombies`), which ntoseye finds with a scan of nonpaged pool.
#[record]
pub struct Zombies {
    /// `None` if the flags did not ask for processes.
    pub processes: Option<Vec<ZombieProcess>>,
    /// `None` if the flags did not ask for threads.
    pub threads: Option<Vec<ZombieThread>>,
    /// The number of live processes that the scan found.
    pub live_processes: u64,
    /// The number of live threads that the scan found.
    pub live_threads: u64,
    /// The start of the scanned pool region.
    pub region_start: VirtAddr,
    /// The end of the scanned pool region.
    pub region_end: VirtAddr,
    pub scanned_pages: u64,
    /// True if the scan was interrupted before it finished.
    pub interrupted: bool,
    /// True if a result list reached its limit.
    pub truncated: bool,
}

fn global_flag_names(value: u32) -> Vec<GlobalFlag> {
    global_flags_set(value)
        .map(|flag| GlobalFlag {
            bit: flag.bit,
            abbreviation: flag.abbreviation,
            description: flag.description,
        })
        .collect()
}

pub fn global_flags(detail: &GlobalFlagsDetail) -> GlobalFlags {
    GlobalFlags {
        kernel_address: detail.kernel_address,
        kernel: detail.kernel,
        kernel_flags: global_flag_names(detail.kernel),
        process: detail.process.clone(),
        process_flags: detail.process_flags.map(|&flags| ProcessGlobalFlags {
            value: flags,
            flags: global_flag_names(flags),
        }),
    }
}

pub fn zombies(detail: &ZombiesDetail) -> Zombies {
    let processes = detail.processes.iter().map(|process| ZombieProcess {
        eprocess: process.eprocess,
        pid: process.pid,
        image: process.image.clone(),
        exit_time: process.exit_time,
        exit_status: process.exit_status,
        handle_count: process.counts.handle_count as u64,
        pointer_count: process.counts.pointer_count as u64,
    });
    let threads = detail.threads.iter().map(|thread| ZombieThread {
        ethread: thread.ethread,
        pid: thread.pid,
        tid: thread.tid,
        process: thread.process,
        image: thread.image.clone(),
        exit_status: thread.exit_status,
        handle_count: thread.counts.handle_count as u64,
        pointer_count: thread.counts.pointer_count as u64,
    });
    Zombies {
        processes: detail.kinds.processes.then(|| processes.collect()),
        threads: detail.kinds.threads.then(|| threads.collect()),
        live_processes: detail.live_processes as u64,
        live_threads: detail.live_threads as u64,
        region_start: detail.region_start,
        region_end: detail.region_end,
        scanned_pages: detail.scanned_pages,
        interrupted: detail.interrupted,
        truncated: detail.truncated,
    }
}
