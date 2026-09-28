//! Process, thread, job, global-flag, and zombie [`View`] builders.

use super::shape::{Diag, Hex, shapes};
use super::list::{ListEnd, list_termination};
use crate::types::VirtAddr;
use crate::guest::ProcessInfo;
use crate::target::gflag::{GlobalFlagsDetail, global_flags_set};
use crate::target::job::{JobDetail, JobField, job_limit_flag_names};
use crate::target::zombies::ZombiesDetail;
use crate::target::{ThreadInfo, kthread_state_name, wait_reason_name};

shapes! {
    /// A Windows thread, as `threads`, `!thread`, and every scheduler
    /// listing report it. Fields the walk could not read are `None`.
    ThreadSummary {
        tid: Option<u64>,
        pid: Option<u64>,
        /// The owning process's image name.
        process_name: Option<String>,
        ethread: VirtAddr,
        kthread: VirtAddr,
        /// The owning `_EPROCESS`.
        eprocess: Option<VirtAddr>,
        /// `_KTHREAD.State`.
        state: Option<u8>,
        /// The state's name (`Running`, `Waiting`, ...).
        state_name: Option<&'static str>,
        /// `_KTHREAD.WaitReason`.
        wait_reason: Option<u8>,
        /// The wait reason's name (`Executive`, `UserRequest`, ...).
        wait_reason_name: Option<&'static str>,
        /// Current scheduling priority.
        priority: Option<u8>,
        /// The vCPU running the thread, when the listing resolves it; `None`
        /// when none runs it, and while the target runs.
        active: Option<String>,
    }

    /// A process's identity (`ps`, `!process 0 0`).
    ProcessIdentity {
        pid: u64,
        /// The image name.
        name: String,
        /// The directory table base (page-table root).
        dtb: Hex,
        eprocess: VirtAddr,
        /// Whether it is a 32-bit process running under WOW64.
        wow64: bool,
    }

    /// A job's `_EJOB` accounting; a field this build lacks is `None`.
    JobAccounting {
        /// In 100 ns units.
        total_user_time: Option<u64>,
        /// In 100 ns units.
        total_kernel_time: Option<u64>,
        /// In CPU cycles.
        total_cycle_time: Option<u64>,
        /// In 100 ns units.
        this_period_total_user_time: Option<u64>,
        /// In 100 ns units.
        this_period_total_kernel_time: Option<u64>,
        total_page_fault_count: Option<u64>,
        /// Processes ever assigned.
        total_processes: Option<u64>,
        active_processes: Option<u64>,
        /// Processes terminated by a job limit violation.
        total_terminated_processes: Option<u64>,
        /// In pages.
        peak_process_memory_used: Option<u64>,
        /// In pages.
        peak_job_memory_used: Option<u64>,
        /// In pages.
        current_job_memory_used: Option<u64>,
    }

    /// A job's `_EJOB` limit settings; a field this build lacks is `None`.
    JobLimits {
        /// `JOB_OBJECT_LIMIT_*` bits set.
        limit_flags: Option<u64>,
        /// Limit bits in effect, nesting included.
        effective_limit_flags: Option<u64>,
        active_process_limit: Option<u64>,
        /// In 100 ns units.
        per_process_user_time_limit: Option<u64>,
        /// In 100 ns units.
        per_job_user_time_limit: Option<u64>,
        /// In pages.
        minimum_working_set_size: Option<u64>,
        /// In pages.
        maximum_working_set_size: Option<u64>,
        /// In pages.
        process_memory_limit: Option<u64>,
        /// In pages.
        job_memory_limit: Option<u64>,
        priority_class: Option<u64>,
        scheduling_class: Option<u64>,
        /// `JOB_OBJECT_UILIMIT_*` bits set.
        ui_restrictions_class: Option<u64>,
    }

    /// A job object (`!job`): its accounting, limits, flags, nesting, and
    /// the processes assigned to it. A field this build lacks is `None`.
    Job {
        /// The `_EJOB`.
        address: VirtAddr,
        job_id: Option<u64>,
        session_id: Option<u64>,
        accounting: JobAccounting,
        limits: JobLimits,
        /// The `JOB_OBJECT_LIMIT_*` names of the limit flags set; an
        /// unnamed bit is its hex value.
        limit_flag_names: Vec<String>,
        /// `_EJOB.JobFlags`.
        job_flags: Option<Hex>,
        /// The `JobFlags` bits set, by their PDB names.
        job_flag_names: Vec<String>,
        nesting_depth: Option<u64>,
        /// `None` for a top-level job.
        parent_job: Option<VirtAddr>,
        /// `None` for a top-level job.
        root_job: Option<VirtAddr>,
        child_jobs: Vec<VirtAddr>,
        child_job_list_termination: ListEnd,
        /// Whether the job is a silo.
        silo: bool,
        /// `None` for a job that is not a server silo.
        server_silo_globals: Option<VirtAddr>,
        processes: Vec<ProcessIdentity>,
        /// `_EPROCESS` addresses on the job's list that could not be decoded.
        unreadable_processes: Vec<VirtAddr>,
        process_list_termination: ListEnd,
    }

    /// One GFlags flag set.
    GlobalFlag {
        /// The flag's bit mask.
        bit: Hex<u32>,
        /// The GFlags abbreviation (`hpa`, `ust`, ...).
        abbreviation: &'static str,
        description: &'static str,
    }

    /// A process's `_PEB.NtGlobalFlag`.
    ProcessGlobalFlags {
        value: Hex<u32>,
        flags: Vec<GlobalFlag>,
    }

    /// `nt!NtGlobalFlag` and the current process's `_PEB.NtGlobalFlag`
    /// (`!gflag`).
    GlobalFlags {
        /// `nt!NtGlobalFlag`'s address.
        kernel_address: VirtAddr,
        /// `nt!NtGlobalFlag`.
        kernel: Hex<u32>,
        kernel_flags: Vec<GlobalFlag>,
        /// The current process; `None` with no process selected.
        process: Option<ProcessIdentity>,
        /// The current process's flags, read from its PEB.
        process_flags: Diag<ProcessGlobalFlags>,
    }

    /// An exited process whose object is still referenced.
    ZombieProcess {
        eprocess: VirtAddr,
        pid: u64,
        /// The image name.
        image: String,
        /// `_EPROCESS.ExitTime`, a FILETIME.
        exit_time: Hex,
        /// The exit NTSTATUS.
        exit_status: Hex<u32>,
        /// Open handles to the object.
        handle_count: u64,
        /// References to the object.
        pointer_count: u64,
    }

    /// A terminated thread whose object is still referenced.
    ZombieThread {
        ethread: VirtAddr,
        pid: u64,
        tid: u64,
        /// The owning `_EPROCESS`.
        process: VirtAddr,
        /// The owning process's image name; `None` when unreadable.
        image: Option<String>,
        /// The exit NTSTATUS.
        exit_status: Hex<u32>,
        /// Open handles to the object.
        handle_count: u64,
        /// References to the object.
        pointer_count: u64,
    }

    /// Exited processes and terminated threads still referenced, found by
    /// scanning nonpaged pool (`!zombies`).
    Zombies {
        /// `None` when the flags did not ask for processes.
        processes: Option<Vec<ZombieProcess>>,
        /// `None` when the flags did not ask for threads.
        threads: Option<Vec<ZombieThread>>,
        /// Live processes seen by the scan.
        live_processes: u64,
        /// Live threads seen by the scan.
        live_threads: u64,
        /// The scanned pool region's start.
        region_start: VirtAddr,
        /// The scanned pool region's end.
        region_end: VirtAddr,
        scanned_pages: u64,
        /// Whether the scan was interrupted before it finished.
        interrupted: bool,
        /// Whether a result list hit its cap.
        truncated: bool,
    }
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
