//! Process, thread, and job [`View`] builders.

use super::{View, list_termination};
use crate::guest::ProcessInfo;
use crate::target::job::{JobDetail, JobField, job_limit_flag_names};
use crate::target::{ThreadInfo, kthread_state_name, wait_reason_name};
use crate::types::VirtAddr;

/// One Windows thread from the kernel thread walk; `active` is the vCPU id
/// currently running it (only resolved while halted).
pub fn thread(t: &ThreadInfo, active: Option<&str>) -> View {
    View::Object(vec![
        ("tid", View::OptNum(t.tid)),
        ("pid", View::OptNum(t.pid)),
        ("process_name", View::OptStr(t.process_name.clone())),
        ("ethread", View::Hex(t.ethread.0)),
        ("kthread", View::Hex(t.kthread.0)),
        ("eprocess", View::OptHex(t.eprocess.map(|a| a.0))),
        ("state", View::OptNum(t.state.map(u64::from))),
        (
            "state_name",
            View::OptStr(t.state.map(|s| kthread_state_name(s).to_string())),
        ),
        ("wait_reason", View::OptNum(t.wait_reason.map(u64::from))),
        (
            "wait_reason_name",
            View::OptStr(t.wait_reason.map(|r| wait_reason_name(r).to_string())),
        ),
        ("active", View::OptStr(active.map(str::to_string))),
    ])
}

pub fn process(process: &ProcessInfo) -> View {
    View::Object(vec![
        ("pid", View::Num(process.pid)),
        ("name", View::Str(process.name.clone())),
        ("dtb", View::Hex(process.dtb)),
        ("eprocess", View::Hex(process.eprocess_va.0)),
        ("wow64", View::Bool(process.is_wow64())),
    ])
}

fn job_fields(fields: &[JobField]) -> View {
    View::Object(
        fields
            .iter()
            .map(|field| (field.key, View::Num(field.value)))
            .collect(),
    )
}

/// `!job`; top-level keys: `address`, `job_id`, `session_id`, `accounting`
/// (times in 100 ns, memory in pages), `limits`, `limit_flag_names`,
/// `job_flags`, `job_flag_names`, `nesting_depth`, `parent_job`, `root_job`,
/// `child_jobs`, `silo`, `server_silo_globals`, `processes`,
/// `unreadable_processes`, `process_list_termination`.
pub fn job(job: &JobDetail) -> View {
    let limit_flags = job
        .limits
        .iter()
        .find(|field| field.field == "LimitFlags")
        .map_or(0, |field| field.value);
    let addresses =
        |list: &[VirtAddr]| View::List(list.iter().map(|address| View::Hex(address.0)).collect());
    View::Object(vec![
        ("address", View::Hex(job.address.0)),
        ("job_id", View::OptNum(job.job_id)),
        ("session_id", View::OptNum(job.session_id)),
        ("accounting", job_fields(&job.accounting)),
        ("limits", job_fields(&job.limits)),
        (
            "limit_flag_names",
            View::List(
                job_limit_flag_names(limit_flags)
                    .into_iter()
                    .map(View::Str)
                    .collect(),
            ),
        ),
        ("job_flags", View::OptHex(job.job_flags)),
        (
            "job_flag_names",
            View::List(job.job_flag_names.iter().cloned().map(View::Str).collect()),
        ),
        ("nesting_depth", View::OptNum(job.nesting_depth)),
        ("parent_job", View::OptHex(job.parent_job.map(|job| job.0))),
        ("root_job", View::OptHex(job.root_job.map(|job| job.0))),
        ("child_jobs", addresses(&job.child_jobs)),
        ("silo", View::Bool(job.silo)),
        (
            "server_silo_globals",
            View::OptHex(job.server_silo_globals.map(|globals| globals.0)),
        ),
        (
            "processes",
            View::List(job.processes.iter().map(process).collect()),
        ),
        ("unreadable_processes", addresses(&job.unreadable_processes)),
        (
            "process_list_termination",
            list_termination(&job.process_termination),
        ),
    ])
}
