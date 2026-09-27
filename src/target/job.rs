//! Job objects (`!job`): an `_EJOB`'s accounting, limits, flags, nesting,
//! and the processes assigned to it (`ProcessListHead`, linked through
//! `_EPROCESS.JobLinks`). Every field comes from the PDB; one that a build
//! lacks is left out rather than failing the rest.

use crate::error::{Error, Result};
use crate::guest::ProcessInfo;
use crate::target::sched::walk_list_nodes;
use crate::target::{ListTermination, Target};
use crate::types::VirtAddr;

const MAX_JOB_PROCESSES: usize = 4096;
const MAX_CHILD_JOBS: usize = 1024;

/// `_EJOB` accounting fields, as (PDB field, key). Times are 100 ns units.
pub const JOB_ACCOUNTING: &[(&str, &str)] = &[
    ("TotalUserTime", "total_user_time"),
    ("TotalKernelTime", "total_kernel_time"),
    ("TotalCycleTime", "total_cycle_time"),
    ("ThisPeriodTotalUserTime", "this_period_total_user_time"),
    ("ThisPeriodTotalKernelTime", "this_period_total_kernel_time"),
    ("TotalPageFaultCount", "total_page_fault_count"),
    ("TotalProcesses", "total_processes"),
    ("ActiveProcesses", "active_processes"),
    ("TotalTerminatedProcesses", "total_terminated_processes"),
    ("PeakProcessMemoryUsed", "peak_process_memory_used"),
    ("PeakJobMemoryUsed", "peak_job_memory_used"),
    ("CurrentJobMemoryUsed", "current_job_memory_used"),
];

/// `_EJOB` limit settings, as (PDB field, key). Memory limits are pages.
pub const JOB_LIMITS: &[(&str, &str)] = &[
    ("LimitFlags", "limit_flags"),
    ("EffectiveLimitFlags", "effective_limit_flags"),
    ("ActiveProcessLimit", "active_process_limit"),
    ("PerProcessUserTimeLimit", "per_process_user_time_limit"),
    ("PerJobUserTimeLimit", "per_job_user_time_limit"),
    ("MinimumWorkingSetSize", "minimum_working_set_size"),
    ("MaximumWorkingSetSize", "maximum_working_set_size"),
    ("ProcessMemoryLimit", "process_memory_limit"),
    ("JobMemoryLimit", "job_memory_limit"),
    ("PriorityClass", "priority_class"),
    ("SchedulingClass", "scheduling_class"),
    ("UIRestrictionsClass", "ui_restrictions_class"),
];

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

/// One `_EJOB` field: its PDB name, its JSON key, and its value.
#[derive(Debug, Clone, Copy)]
pub struct JobField {
    pub field: &'static str,
    pub key: &'static str,
    pub value: u64,
}

/// A decoded `_EJOB`.
#[derive(Debug, Clone)]
pub struct JobDetail {
    pub address: VirtAddr,
    pub job_id: Option<u64>,
    pub session_id: Option<u64>,
    /// [`JOB_ACCOUNTING`] fields this build has, in table order.
    pub accounting: Vec<JobField>,
    /// [`JOB_LIMITS`] fields this build has, in table order.
    pub limits: Vec<JobField>,
    pub job_flags: Option<u64>,
    /// Names of the `JobFlags` bits set, from the PDB's bitfields.
    pub job_flag_names: Vec<String>,
    pub nesting_depth: Option<u64>,
    pub parent_job: Option<VirtAddr>,
    pub root_job: Option<VirtAddr>,
    pub child_jobs: Vec<VirtAddr>,
    /// The job is a silo (`JobFlags.Silo`).
    pub silo: bool,
    pub server_silo_globals: Option<VirtAddr>,
    pub processes: Vec<ProcessInfo>,
    pub process_termination: ListTermination,
    /// Processes on the list that could not be decoded.
    pub unreadable_processes: Vec<VirtAddr>,
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
            return job_of(self.selected_process_info()?.eprocess_va);
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
    pub fn inspect_job(&self, address: VirtAddr) -> Result<JobDetail> {
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
        let fields = |table: &[(&'static str, &'static str)]| -> Vec<JobField> {
            table
                .iter()
                .filter_map(|&(field, key)| {
                    let value = job.read_uint(field).ok()?;
                    Some(JobField { field, key, value })
                })
                .collect()
        };
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
            let (links, termination) = walk_list_nodes(self, address + head, limit);
            (links.into_iter().map(|at| at - link).collect(), termination)
        };
        let (eprocesses, process_termination) = list(
            "ProcessListHead",
            "_EPROCESS",
            "JobLinks",
            MAX_JOB_PROCESSES,
        );
        let (child_jobs, _) = list(
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
        Ok(JobDetail {
            address,
            job_id: job.read_uint("JobId").ok(),
            session_id: job.read_uint("SessionId").ok(),
            accounting: fields(JOB_ACCOUNTING),
            limits: fields(JOB_LIMITS),
            job_flags,
            silo: job_flag_names.iter().any(|name| name == "Silo"),
            job_flag_names,
            nesting_depth: job.read_uint("NestingDepth").ok(),
            parent_job: pointer("ParentJob").filter(|job| !job.is_zero()),
            root_job: pointer("RootJob").filter(|job| !job.is_zero()),
            child_jobs,
            server_silo_globals: pointer("ServerSiloGlobals").filter(|globals| !globals.is_zero()),
            processes,
            process_termination,
            unreadable_processes,
        })
    }
}
