//! Process, thread, job, global-flag, and zombie [`View`] builders.

use crate::target::DiagnosticValue;
use ntoseye_macros::record;

use super::list::{ListEnd, list_termination};
use crate::guest::ProcessInfo;
use crate::target::gflag::{GlobalFlagsDetail, global_flags_set};
use crate::target::job::{JobDetail, JobField, job_limit_flag_names};
use crate::target::zombies::ZombiesDetail;
use crate::target::{ThreadInfo, kthread_state_name, wait_reason_name};
use crate::types::VirtAddr;

/// A Windows thread, as `threads`, `!thread`, and all scheduler listings
/// show it. A field that the walk could not read is `None`.
#[record]
pub struct ThreadSummary {
    pub tid: Option<u64>,
    pub pid: Option<u64>,
    /// The image name of the owning process.
    pub process_name: Option<String>,
    pub ethread: VirtAddr,
    pub kthread: VirtAddr,
    /// The owning `_EPROCESS`.
    pub eprocess: Option<VirtAddr>,
    /// `_KTHREAD.State`.
    pub state: Option<u8>,
    /// The name of the state (`Running`, `Waiting`, ...).
    pub state_name: Option<&'static str>,
    /// `_KTHREAD.WaitReason`.
    pub wait_reason: Option<u8>,
    /// The name of the wait reason (`Executive`, `UserRequest`, ...).
    pub wait_reason_name: Option<&'static str>,
    /// The current scheduling priority.
    pub priority: Option<u8>,
    /// The vCPU that runs the thread, if the listing resolves it. `None` if
    /// no vCPU runs it, and while the target runs.
    pub active: Option<String>,
}

/// The identity of a process (`ps`, `!process 0 0`).
#[record]
pub struct ProcessIdentity {
    pub pid: u64,
    /// The image name.
    pub name: String,
    /// The directory table base (page-table root).
    #[record(hex)]
    pub dtb: u64,
    pub eprocess: VirtAddr,
    /// True if it is a 32-bit process that runs under WOW64.
    pub wow64: bool,
}

/// The `_EJOB` accounting of a job. A field that this build does not have is
/// `None`.
#[record]
pub struct JobAccounting {
    /// In 100 ns units.
    pub total_user_time: Option<u64>,
    /// In 100 ns units.
    pub total_kernel_time: Option<u64>,
    /// In CPU cycles.
    pub total_cycle_time: Option<u64>,
    /// In 100 ns units.
    pub this_period_total_user_time: Option<u64>,
    /// In 100 ns units.
    pub this_period_total_kernel_time: Option<u64>,
    pub total_page_fault_count: Option<u64>,
    /// The number of processes that were ever assigned to the job.
    pub total_processes: Option<u64>,
    pub active_processes: Option<u64>,
    /// The number of processes that a job limit violation terminated.
    pub total_terminated_processes: Option<u64>,
    /// In pages.
    pub peak_process_memory_used: Option<u64>,
    /// In pages.
    pub peak_job_memory_used: Option<u64>,
    /// In pages.
    pub current_job_memory_used: Option<u64>,
}

/// The `_EJOB` limit settings of a job. A field that this build does not
/// have is `None`.
#[record]
pub struct JobLimits {
    /// The `JOB_OBJECT_LIMIT_*` bits that are set.
    pub limit_flags: Option<u64>,
    /// The limit bits in effect, with the bits from nesting.
    pub effective_limit_flags: Option<u64>,
    pub active_process_limit: Option<u64>,
    /// In 100 ns units.
    pub per_process_user_time_limit: Option<u64>,
    /// In 100 ns units.
    pub per_job_user_time_limit: Option<u64>,
    /// In pages.
    pub minimum_working_set_size: Option<u64>,
    /// In pages.
    pub maximum_working_set_size: Option<u64>,
    /// In pages.
    pub process_memory_limit: Option<u64>,
    /// In pages.
    pub job_memory_limit: Option<u64>,
    pub priority_class: Option<u64>,
    pub scheduling_class: Option<u64>,
    /// The `JOB_OBJECT_UILIMIT_*` bits that are set.
    pub ui_restrictions_class: Option<u64>,
}

/// A job object (`!job`), with its accounting, limits, flags, nesting, and
/// assigned processes. A field that this build does not have is `None`.
#[record]
pub struct Job {
    /// The `_EJOB`.
    pub address: VirtAddr,
    pub job_id: Option<u64>,
    pub session_id: Option<u64>,
    pub accounting: JobAccounting,
    pub limits: JobLimits,
    /// The `JOB_OBJECT_LIMIT_*` names of the limit flags that are set. A
    /// bit that has no name shows as its hex value.
    pub limit_flag_names: Vec<String>,
    /// `_EJOB.JobFlags`.
    #[record(hex)]
    pub job_flags: Option<u64>,
    /// The `JobFlags` bits that are set, by their PDB names.
    pub job_flag_names: Vec<String>,
    pub nesting_depth: Option<u64>,
    /// `None` for a top-level job.
    pub parent_job: Option<VirtAddr>,
    /// `None` for a top-level job.
    pub root_job: Option<VirtAddr>,
    pub child_jobs: Vec<VirtAddr>,
    pub child_job_list_termination: ListEnd,
    /// True if the job is a silo.
    pub silo: bool,
    /// `None` for a job that is not a server silo.
    pub server_silo_globals: Option<VirtAddr>,
    pub processes: Vec<ProcessIdentity>,
    /// The `_EPROCESS` addresses on the job list that ntoseye could not decode.
    pub unreadable_processes: Vec<VirtAddr>,
    pub process_list_termination: ListEnd,
}

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
    pub process: Option<ProcessIdentity>,
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

/// One Windows thread from the kernel thread walk; `active` is the vCPU id
/// currently running it (only resolved while halted).
pub fn thread_summary(t: &ThreadInfo, active: Option<&str>) -> ThreadSummary {
    ThreadSummary {
        tid: t.tid,
        pid: t.pid,
        process_name: t.process_name.clone(),
        ethread: t.ethread,
        kthread: t.kthread,
        eprocess: t.eprocess,
        state: t.state,
        state_name: t.state.map(kthread_state_name),
        wait_reason: t.wait_reason,
        wait_reason_name: t.wait_reason.map(wait_reason_name),
        priority: t.priority,
        active: active.map(str::to_string),
    }
}

pub fn process(process: &ProcessInfo) -> ProcessIdentity {
    ProcessIdentity {
        pid: process.pid,
        name: process.name.clone(),
        dtb: process.dtb,
        eprocess: process.eprocess_va,
        wow64: process.is_wow64(),
    }
}

/// The value of the job field keyed `key`, if this build has it.
fn job_field(fields: &[JobField], key: &str) -> Option<u64> {
    fields
        .iter()
        .find(|field| field.key == key)
        .map(|field| field.value)
}

fn job_accounting(fields: &[JobField]) -> JobAccounting {
    let field = |key| job_field(fields, key);
    JobAccounting {
        total_user_time: field("total_user_time"),
        total_kernel_time: field("total_kernel_time"),
        total_cycle_time: field("total_cycle_time"),
        this_period_total_user_time: field("this_period_total_user_time"),
        this_period_total_kernel_time: field("this_period_total_kernel_time"),
        total_page_fault_count: field("total_page_fault_count"),
        total_processes: field("total_processes"),
        active_processes: field("active_processes"),
        total_terminated_processes: field("total_terminated_processes"),
        peak_process_memory_used: field("peak_process_memory_used"),
        peak_job_memory_used: field("peak_job_memory_used"),
        current_job_memory_used: field("current_job_memory_used"),
    }
}

fn job_limits(fields: &[JobField]) -> JobLimits {
    let field = |key| job_field(fields, key);
    JobLimits {
        limit_flags: field("limit_flags"),
        effective_limit_flags: field("effective_limit_flags"),
        active_process_limit: field("active_process_limit"),
        per_process_user_time_limit: field("per_process_user_time_limit"),
        per_job_user_time_limit: field("per_job_user_time_limit"),
        minimum_working_set_size: field("minimum_working_set_size"),
        maximum_working_set_size: field("maximum_working_set_size"),
        process_memory_limit: field("process_memory_limit"),
        job_memory_limit: field("job_memory_limit"),
        priority_class: field("priority_class"),
        scheduling_class: field("scheduling_class"),
        ui_restrictions_class: field("ui_restrictions_class"),
    }
}

pub fn job(job: &JobDetail) -> Job {
    let limit_flags = job
        .limits
        .iter()
        .find(|field| field.field == "LimitFlags")
        .map_or(0, |field| field.value);
    Job {
        address: job.address,
        job_id: job.job_id,
        session_id: job.session_id,
        accounting: job_accounting(&job.accounting),
        limits: job_limits(&job.limits),
        limit_flag_names: job_limit_flag_names(limit_flags),
        job_flags: job.job_flags,
        job_flag_names: job.job_flag_names.clone(),
        nesting_depth: job.nesting_depth,
        parent_job: job.parent_job,
        root_job: job.root_job,
        child_jobs: job.child_jobs.clone(),
        child_job_list_termination: list_termination(&job.child_job_termination),
        silo: job.silo,
        server_silo_globals: job.server_silo_globals,
        processes: job.processes.iter().map(process).collect(),
        unreadable_processes: job.unreadable_processes.clone(),
        process_list_termination: list_termination(&job.process_termination),
    }
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
        process: detail.process.as_ref().map(process),
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
