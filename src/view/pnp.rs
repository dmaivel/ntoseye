//! PnP [`View`] builders for the structured inspectors.

use crate::target::pnp::{
    self, DevNodeDetail, DeviceStackDetail, DeviceStackEntry, PnpTriageDetail, StateHistoryEntry,
};

use super::View;
use super::shape::{Hex, ViewValue, shapes};

shapes! {
    /// A device node's identity and state, as subtree and triage listings
    /// show it.
    DevNodeSummary {
        /// The `_DEVICE_NODE`.
        address: Hex,
        /// Its physical device object.
        pdo: Hex,
        instance_path: String,
        service_name: String,
        /// `PNP_DEVNODE_STATE`.
        state: Hex,
        state_name: String,
        /// The `CM_PROB_*` problem code; 0 for none.
        problem: Hex,
        /// The problem code's name, when it is a known one.
        problem_name: Option<String>,
        problem_status: Hex,
        /// The IRP PnP is waiting on; 0 for none.
        pending_irp: Hex,
        /// `Level`: its depth in the device tree.
        depth: u32,
    }

    /// A nonzero entry of a device node's `StateHistory` ring.
    DevNodeHistoryState {
        /// Its slot in the ring.
        index: u32,
        state: Hex,
        state_name: String,
    }

    /// A device object in a device stack.
    DeviceStackLayer {
        device_object: Hex,
        driver_object: Hex,
        driver_name: String,
        device_extension: Hex,
        object_name: String,
        /// Whether this is the device the stack was requested for.
        is_argument: bool,
    }

    /// A decoded `_DEVICE_NODE`, optionally with its flat subtree
    /// (`!devnode`).
    DevNode {
        address: Hex,
        /// Its physical device object.
        pdo: Hex,
        parent: Hex,
        sibling: Hex,
        child: Hex,
        instance_path: String,
        service_name: String,
        /// `PNP_DEVNODE_STATE`.
        state: Hex,
        state_name: String,
        previous_state: Hex,
        previous_state_name: String,
        state_history: Vec<DevNodeHistoryState>,
        /// `StateHistoryEntry`: the ring's next slot.
        state_history_entry: u32,
        flags: Hex,
        user_flags: Hex,
        completion_status: Hex,
        /// The `CM_PROB_*` problem code; 0 for none.
        problem: Hex,
        /// The problem code's name, when it is a known one.
        problem_name: Option<String>,
        problem_status: Hex,
        /// The IRP PnP is waiting on; 0 for none.
        pending_irp: Hex,
        /// The nodes below it, depth first; empty unless recursion was
        /// requested.
        subtree: Vec<DevNodeSummary>,
        /// Whether the subtree walk stopped at its bound.
        subtree_truncated: bool,
    }

    /// A device stack, top filter to PDO, and the PDO's device node
    /// (`!devstack`).
    DeviceStack {
        /// The address given: a device object (or a pointer to one) or a
        /// device node.
        argument: Hex,
        /// The device object the stack was walked from.
        requested_device: Hex,
        /// The stack, top filter first.
        entries: Vec<DeviceStackLayer>,
        /// `None` when the PDO has no device node or it could not be read
        /// (`pdo_devnode_error` says why).
        pdo_devnode: Option<DevNodeSummary>,
        pdo_devnode_error: Option<String>,
        /// Whether the stack walk stopped at its bound.
        truncated: bool,
    }

    /// PnP triage buckets from one bounded walk of the device tree
    /// (`!pnptriage`).
    PnpTriage {
        /// Nodes with a problem code.
        problems: Vec<DevNodeSummary>,
        /// Nodes neither started nor removed or deleted.
        not_started: Vec<DevNodeSummary>,
        /// Nodes with a pending IRP.
        pending_irps: Vec<DevNodeSummary>,
        /// Nodes walked.
        total: u64,
        started: u64,
        /// Whether the walk stopped at its 4096-node bound.
        truncated: bool,
    }
}

fn devnode_summary(summary: &pnp::DevNodeSummary) -> DevNodeSummary {
    DevNodeSummary {
        address: Hex(summary.address.0),
        pdo: Hex(summary.pdo.0),
        instance_path: summary.instance_path.clone(),
        service_name: summary.service_name.clone(),
        state: Hex(summary.state.into()),
        state_name: summary.state_name.clone(),
        problem: Hex(summary.problem.into()),
        problem_name: summary.problem_name.clone(),
        problem_status: Hex(summary.problem_status.into()),
        pending_irp: Hex(summary.pending_irp.0),
        depth: summary.depth,
    }
}

fn state_history_entry(entry: &StateHistoryEntry) -> DevNodeHistoryState {
    DevNodeHistoryState {
        index: entry.index,
        state: Hex(entry.state.into()),
        state_name: entry.state_name.clone(),
    }
}

fn device_stack_entry(entry: &DeviceStackEntry) -> DeviceStackLayer {
    DeviceStackLayer {
        device_object: Hex(entry.device_object.0),
        driver_object: Hex(entry.driver_object.0),
        driver_name: entry.driver_name.clone(),
        device_extension: Hex(entry.device_extension.0),
        object_name: entry.object_name.clone(),
        is_argument: entry.is_argument,
    }
}

/// `_DEVICE_NODE` fields plus the optional bounded flat subtree.
pub fn devnode(detail: &DevNodeDetail) -> View {
    DevNode {
        address: Hex(detail.address.0),
        pdo: Hex(detail.pdo.0),
        parent: Hex(detail.parent.0),
        sibling: Hex(detail.sibling.0),
        child: Hex(detail.child.0),
        instance_path: detail.instance_path.clone(),
        service_name: detail.service_name.clone(),
        state: Hex(detail.state.into()),
        state_name: detail.state_name.clone(),
        previous_state: Hex(detail.previous_state.into()),
        previous_state_name: detail.previous_state_name.clone(),
        state_history: detail
            .state_history
            .iter()
            .map(state_history_entry)
            .collect(),
        state_history_entry: detail.state_history_entry,
        flags: Hex(detail.flags.into()),
        user_flags: Hex(detail.user_flags.into()),
        completion_status: Hex(detail.completion_status.into()),
        problem: Hex(detail.problem.into()),
        problem_name: detail.problem_name.clone(),
        problem_status: Hex(detail.problem_status.into()),
        pending_irp: Hex(detail.pending_irp.0),
        subtree: detail.subtree.iter().map(devnode_summary).collect(),
        subtree_truncated: detail.subtree_truncated,
    }
    .into_view()
}

/// Ordered top-filter-to-PDO device stack and its PDO devnode summary.
pub fn device_stack(detail: &DeviceStackDetail) -> View {
    DeviceStack {
        argument: Hex(detail.argument.0),
        requested_device: Hex(detail.requested_device.0),
        entries: detail.entries.iter().map(device_stack_entry).collect(),
        pdo_devnode: detail.pdo_devnode.as_ref().map(devnode_summary),
        pdo_devnode_error: detail.pdo_devnode_error.clone(),
        truncated: detail.truncated,
    }
    .into_view()
}

/// PnP triage partitions of one bounded root tree.
pub fn pnp_triage(detail: &PnpTriageDetail) -> View {
    PnpTriage {
        problems: detail.problems.iter().map(devnode_summary).collect(),
        not_started: detail.not_started.iter().map(devnode_summary).collect(),
        pending_irps: detail.pending_irps.iter().map(devnode_summary).collect(),
        total: detail.total,
        started: detail.started,
        truncated: detail.truncated,
    }
    .into_view()
}
