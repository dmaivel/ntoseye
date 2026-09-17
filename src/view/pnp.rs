//! PnP [`View`](super::View) builders for the structured inspectors.

use crate::target::pnp::{
    DevNodeDetail, DevNodeSummary, DeviceStackDetail, DeviceStackEntry, PnpTriageDetail,
    StateHistoryEntry,
};

use super::View;

fn devnode_summary(summary: &DevNodeSummary) -> View {
    View::Object(vec![
        ("address", View::Hex(summary.address.0)),
        ("pdo", View::Hex(summary.pdo.0)),
        ("instance_path", View::Str(summary.instance_path.clone())),
        ("service_name", View::Str(summary.service_name.clone())),
        ("state", View::Hex(summary.state.into())),
        ("state_name", View::Str(summary.state_name.clone())),
        ("problem", View::Hex(summary.problem.into())),
        ("problem_name", View::OptStr(summary.problem_name.clone())),
        ("problem_status", View::Hex(summary.problem_status.into())),
        ("pending_irp", View::Hex(summary.pending_irp.0)),
        ("depth", View::Num(summary.depth.into())),
    ])
}

fn state_history_entry(entry: &StateHistoryEntry) -> View {
    View::Object(vec![
        ("index", View::Num(entry.index.into())),
        ("state", View::Hex(entry.state.into())),
        ("state_name", View::Str(entry.state_name.clone())),
    ])
}

fn device_stack_entry(entry: &DeviceStackEntry) -> View {
    View::Object(vec![
        ("device_object", View::Hex(entry.device_object.0)),
        ("driver_object", View::Hex(entry.driver_object.0)),
        ("driver_name", View::Str(entry.driver_name.clone())),
        ("device_extension", View::Hex(entry.device_extension.0)),
        ("object_name", View::Str(entry.object_name.clone())),
        ("is_argument", View::Bool(entry.is_argument)),
    ])
}

/// `_DEVICE_NODE` fields plus the optional bounded flat subtree. Top-level
/// keys: address, pdo, parent, sibling, child, instance_path, service_name,
/// state, state_name, previous_state, previous_state_name, state_history,
/// state_history_entry, flags, user_flags, completion_status, problem,
/// problem_name, problem_status, pending_irp, subtree, subtree_truncated.
pub fn devnode(detail: &DevNodeDetail) -> View {
    let history = detail
        .state_history
        .iter()
        .map(state_history_entry)
        .collect();
    let subtree = detail.subtree.iter().map(devnode_summary).collect();
    View::Object(vec![
        ("address", View::Hex(detail.address.0)),
        ("pdo", View::Hex(detail.pdo.0)),
        ("parent", View::Hex(detail.parent.0)),
        ("sibling", View::Hex(detail.sibling.0)),
        ("child", View::Hex(detail.child.0)),
        ("instance_path", View::Str(detail.instance_path.clone())),
        ("service_name", View::Str(detail.service_name.clone())),
        ("state", View::Hex(detail.state.into())),
        ("state_name", View::Str(detail.state_name.clone())),
        ("previous_state", View::Hex(detail.previous_state.into())),
        (
            "previous_state_name",
            View::Str(detail.previous_state_name.clone()),
        ),
        ("state_history", View::List(history)),
        (
            "state_history_entry",
            View::Num(detail.state_history_entry.into()),
        ),
        ("flags", View::Hex(detail.flags.into())),
        ("user_flags", View::Hex(detail.user_flags.into())),
        (
            "completion_status",
            View::Hex(detail.completion_status.into()),
        ),
        ("problem", View::Hex(detail.problem.into())),
        ("problem_name", View::OptStr(detail.problem_name.clone())),
        ("problem_status", View::Hex(detail.problem_status.into())),
        ("pending_irp", View::Hex(detail.pending_irp.0)),
        ("subtree", View::List(subtree)),
        ("subtree_truncated", View::Bool(detail.subtree_truncated)),
    ])
}

/// Ordered top-filter-to-PDO device stack and its PDO devnode summary. Top-level
/// keys: argument, requested_device, entries, pdo_devnode, pdo_devnode_error,
/// truncated.
pub fn device_stack(detail: &DeviceStackDetail) -> View {
    let entries = detail.entries.iter().map(device_stack_entry).collect();
    View::Object(vec![
        ("argument", View::Hex(detail.argument.0)),
        ("requested_device", View::Hex(detail.requested_device.0)),
        ("entries", View::List(entries)),
        (
            "pdo_devnode",
            detail
                .pdo_devnode
                .as_ref()
                .map_or(View::Null, devnode_summary),
        ),
        (
            "pdo_devnode_error",
            View::OptStr(detail.pdo_devnode_error.clone()),
        ),
        ("truncated", View::Bool(detail.truncated)),
    ])
}

/// PnP triage partitions of one bounded root tree. Top-level keys: problems,
/// not_started, pending_irps, total, started, truncated.
pub fn pnp_triage(detail: &PnpTriageDetail) -> View {
    let problems = detail.problems.iter().map(devnode_summary).collect();
    let not_started = detail.not_started.iter().map(devnode_summary).collect();
    let pending_irps = detail.pending_irps.iter().map(devnode_summary).collect();
    View::Object(vec![
        ("problems", View::List(problems)),
        ("not_started", View::List(not_started)),
        ("pending_irps", View::List(pending_irps)),
        ("total", View::Num(detail.total)),
        ("started", View::Num(detail.started)),
        ("truncated", View::Bool(detail.truncated)),
    ])
}
