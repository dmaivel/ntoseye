//! Job objects (`!job`): an `_EJOB`'s accounting, limits, flags, nesting,
//! and the processes assigned to it (`ProcessListHead`, linked through
//! `_EPROCESS.JobLinks`). Every field comes from the PDB; one that a build
//! lacks is left out rather than failing the rest.

use ntoseye_macros::record;

use crate::error::{Error, Result};
use crate::guest::ProcessInfo;
use crate::layout::StructRef;
use crate::target::sched::walk_list_records;
use crate::target::{ListTermination, Target};
use crate::types::VirtAddr;

const MAX_JOB_PROCESSES: usize = 4096;
const MAX_CHILD_JOBS: usize = 1024;

/// The `_EJOB` accounting of a job. A field that this build does not have is
/// `None`.
#[record]
#[derive(Default)]
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
#[derive(Default)]
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

/// Each field of a struct of optional `_EJOB` values with its PDB name, in
/// `_EJOB` order: `fields()` to read them, `read()` to fill them from a job.
macro_rules! ejob_fields {
    ($record:ident { $($field:ident: $pdb:literal,)* }) => {
        impl $record {
            /// The fields by their `_EJOB` names, in layout order.
            pub fn fields(&self) -> impl Iterator<Item = (&'static str, Option<u64>)> {
                [$(($pdb, self.$field)),*].into_iter()
            }

            fn read(job: &StructRef<'_>) -> Self {
                Self { $($field: job.read_uint($pdb).ok()),* }
            }
        }
    };
}

ejob_fields!(JobAccounting {
    total_user_time: "TotalUserTime",
    total_kernel_time: "TotalKernelTime",
    total_cycle_time: "TotalCycleTime",
    this_period_total_user_time: "ThisPeriodTotalUserTime",
    this_period_total_kernel_time: "ThisPeriodTotalKernelTime",
    total_page_fault_count: "TotalPageFaultCount",
    total_processes: "TotalProcesses",
    active_processes: "ActiveProcesses",
    total_terminated_processes: "TotalTerminatedProcesses",
    peak_process_memory_used: "PeakProcessMemoryUsed",
    peak_job_memory_used: "PeakJobMemoryUsed",
    current_job_memory_used: "CurrentJobMemoryUsed",
});

ejob_fields!(JobLimits {
    limit_flags: "LimitFlags",
    effective_limit_flags: "EffectiveLimitFlags",
    active_process_limit: "ActiveProcessLimit",
    per_process_user_time_limit: "PerProcessUserTimeLimit",
    per_job_user_time_limit: "PerJobUserTimeLimit",
    minimum_working_set_size: "MinimumWorkingSetSize",
    maximum_working_set_size: "MaximumWorkingSetSize",
    process_memory_limit: "ProcessMemoryLimit",
    job_memory_limit: "JobMemoryLimit",
    priority_class: "PriorityClass",
    scheduling_class: "SchedulingClass",
    ui_restrictions_class: "UIRestrictionsClass",
});

/// `JOB_OBJECT_LIMIT_*` bit names (winnt.h), in bit order.
const LIMIT_FLAG_NAMES: [&str; 18] = [
    "WORKINGSET",
    "PROCESS_TIME",
    "JOB_TIME",
    "ACTIVE_PROCESS",
    "AFFINITY",
    "PRIORITY_CLASS",
    "PRESERVE_JOB_TIME",
    "SCHEDULING_CLASS",
    "PROCESS_MEMORY",
    "JOB_MEMORY",
    "DIE_ON_UNHANDLED_EXCEPTION",
    "BREAKAWAY_OK",
    "SILENT_BREAKAWAY_OK",
    "KILL_ON_JOB_CLOSE",
    "SUBSET_AFFINITY",
    "JOB_MEMORY_LOW",
    "JOB_READ_BYTES",
    "JOB_WRITE_BYTES",
];

/// The `JOB_OBJECT_LIMIT_*` names of the bits set in `flags`; an unnamed bit
/// is shown as its value.
pub fn job_limit_flag_names(flags: u64) -> Vec<String> {
    (0..32)
        .filter(|bit| flags >> bit & 1 != 0)
        .map(|bit| match LIMIT_FLAG_NAMES.get(bit) {
            Some(name) => name.to_string(),
            None => format!("{:#x}", 1u64 << bit),
        })
        .collect()
}

/// A job object (`!job`), with its accounting, limits, flags, nesting, and
/// assigned processes. A field that this build does not have is `None`.
#[record(impl)]
pub struct Job {
    /// The `_EJOB`.
    pub address: VirtAddr,
    pub job_id: Option<u64>,
    pub session_id: Option<u64>,
    pub accounting: JobAccounting,
    pub limits: JobLimits,
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
    pub child_job_list_termination: ListTermination,
    /// True if the job is a silo (`JobFlags.Silo`).
    pub silo: bool,
    /// `None` for a job that is not a server silo.
    pub server_silo_globals: Option<VirtAddr>,
    pub processes: Vec<ProcessInfo>,
    /// The `_EPROCESS` addresses on the job list that ntoseye could not decode.
    pub unreadable_processes: Vec<VirtAddr>,
    pub process_list_termination: ListTermination,
}

#[record]
impl Job {
    /// The `JOB_OBJECT_LIMIT_*` names of the limit flags that are set. A
    /// bit that has no name shows as its hex value.
    #[record(getter)]
    pub fn limit_flag_names(&self) -> Vec<String> {
        job_limit_flag_names(self.limits.limit_flags.unwrap_or(0))
    }
}

impl Target {
    /// The job `address` names: an `_EJOB` itself, or the job of the process
    /// or thread object at it. `None` is the selected process's job.
    pub fn job_address(&self, address: Option<VirtAddr>) -> Result<VirtAddr> {
        let types = self.guest()?.ntoskrnl.types();
        let job_of = |eprocess: VirtAddr| -> Result<VirtAddr> {
            let job = types
                .struct_at("_EPROCESS", eprocess)?
                .read_pointer("Job")?;
            if job.is_zero() {
                return Err(Error::DebugInfo(format!(
                    "process {:#x} is not in a job",
                    eprocess.0
                )));
            }
            Ok(job)
        };
        let Some(address) = address.filter(|address| !address.is_zero()) else {
            return job_of(self.selected_process_info()?.eprocess);
        };
        let header = self.inspect_object_header(address)?;
        match header.type_name.as_deref() {
            Some("Job") => Ok(header.body),
            Some("Process") => job_of(header.body),
            Some("Thread") => job_of(
                types
                    .struct_at("_KTHREAD", header.body)?
                    .read_pointer("Process")?,
            ),
            other => Err(Error::InvalidArgument(format!(
                "{:#x} is not a job, process, or thread (its object type is {})",
                address.0,
                other.unwrap_or("unknown")
            ))),
        }
    }

    /// Decode the `_EJOB` at `address` and walk its process and child-job
    /// lists.
    pub fn inspect_job(&self, address: VirtAddr) -> Result<Job> {
        let guest = self.guest()?;
        let types = guest.ntoskrnl.types();
        let job = types.struct_at("_EJOB", address)?.prefetch();
        // A job's `Event` is a notification event; anything else is not an
        // `_EJOB` (an unreadable one fails here too).
        let event_type: u8 = job
            .embedded("Event")?
            .embedded("Header")?
            .read_field("Type")?;
        if event_type != 0 {
            return Err(Error::DebugInfo(format!(
                "{:#x} is not a job (its Event has dispatcher type {event_type})",
                address.0
            )));
        }
        let pointer = |name| job.read_pointer(name).ok();
        let job_flags = job.read_uint("JobFlags").ok();
        let job_flag_names = job_flags
            .map(|flags| job.layout().set_bit_names("JobFlags", flags))
            .unwrap_or_default();

        let list = |head: &str, record: &str, link: &str, limit| -> (Vec<VirtAddr>, _) {
            let (Ok(head), Ok(link)) = (
                job.layout().field_offset(head),
                types.layout(record).and_then(|ti| ti.field_offset(link)),
            ) else {
                return (
                    Vec::new(),
                    ListTermination::Corrupt(format!("no {head} list")),
                );
            };
            walk_list_records(self, address + head, link, limit)
        };
        let (eprocesses, process_list_termination) = list(
            "ProcessListHead",
            "_EPROCESS",
            "JobLinks",
            MAX_JOB_PROCESSES,
        );
        let (child_jobs, child_job_list_termination) = list(
            "ChildJobListHead",
            "_EJOB",
            "SiblingJobLinks",
            MAX_CHILD_JOBS,
        );
        let mut processes = Vec::new();
        let mut unreadable_processes = Vec::new();
        for eprocess in eprocesses {
            match guest.process_at(eprocess) {
                Ok(process) => processes.push(process),
                Err(_) => unreadable_processes.push(eprocess),
            }
        }
        Ok(Job {
            address,
            job_id: job.read_uint("JobId").ok(),
            session_id: job.read_uint("SessionId").ok(),
            accounting: JobAccounting::read(&job),
            limits: JobLimits::read(&job),
            job_flags,
            silo: job_flag_names.iter().any(|name| name == "Silo"),
            job_flag_names,
            nesting_depth: job.read_uint("NestingDepth").ok(),
            parent_job: pointer("ParentJob").filter(|job| !job.is_zero()),
            root_job: pointer("RootJob").filter(|job| !job.is_zero()),
            child_jobs,
            child_job_list_termination,
            server_silo_globals: pointer("ServerSiloGlobals").filter(|globals| !globals.is_zero()),
            processes,
            unreadable_processes,
            process_list_termination,
        })
    }
}
