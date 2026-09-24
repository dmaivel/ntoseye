//! Process and thread [`View`](super::View) builders.

use super::View;
use crate::guest::ProcessInfo;
use crate::target::{ThreadInfo, kthread_state_name, wait_reason_name};

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
