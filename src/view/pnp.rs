//! PnP [`View`] builders for the structured inspectors.

use ntoseye_macros::record;

use crate::target::pnp::{
    self, DevNodeDetail, DeviceStackDetail, DeviceStackEntry, PnpTriageDetail, StateHistoryEntry,
};

use crate::types::VirtAddr;

/// The identity and state of a device node, as the subtree and triage
/// lists show them.
#[record]
pub struct DevNodeSummary {
    /// The `_DEVICE_NODE`.
    pub address: VirtAddr,
    /// Its physical device object.
    pub pdo: VirtAddr,
    pub instance_path: String,
    pub service_name: String,
    /// `PNP_DEVNODE_STATE`.
    #[record(hex)]
    pub state: u32,
    pub state_name: String,
    /// The `CM_PROB_*` problem code. 0 for none.
    #[record(hex)]
    pub problem: u32,
    /// The problem code's name, when it is a known one.
    pub problem_name: Option<String>,
    #[record(hex)]
    pub problem_status: u32,
    /// The IRP that PnP waits on. 0 for none.
    pub pending_irp: VirtAddr,
    /// `Level`, the depth of the node in the device tree.
    pub depth: u32,
}

/// A nonzero entry in the `StateHistory` ring of a device node.
#[record]
pub struct DevNodeHistoryState {
    /// Its slot in the ring.
    pub index: u32,
    #[record(hex)]
    pub state: u32,
    pub state_name: String,
}

/// A device object in a device stack.
#[record]
pub struct DeviceStackLayer {
    pub device_object: VirtAddr,
    pub driver_object: VirtAddr,
    pub driver_name: String,
    pub device_extension: VirtAddr,
    pub object_name: String,
    /// Whether this is the device that the stack was requested for.
    pub is_argument: bool,
}

/// A decoded `_DEVICE_NODE` and, if requested, its flat subtree
/// (`!devnode`).
#[record]
pub struct DevNode {
    pub address: VirtAddr,
    /// Its physical device object.
    pub pdo: VirtAddr,
    pub parent: VirtAddr,
    pub sibling: VirtAddr,
    pub child: VirtAddr,
    pub instance_path: String,
    pub service_name: String,
    /// `PNP_DEVNODE_STATE`.
    #[record(hex)]
    pub state: u32,
    pub state_name: String,
    #[record(hex)]
    pub previous_state: u32,
    pub previous_state_name: String,
    pub state_history: Vec<DevNodeHistoryState>,
    /// `StateHistoryEntry`, the next slot in the ring.
    pub state_history_entry: u32,
    #[record(hex)]
    pub flags: u32,
    #[record(hex)]
    pub user_flags: u32,
    #[record(hex)]
    pub completion_status: u32,
    /// The `CM_PROB_*` problem code. 0 for none.
    #[record(hex)]
    pub problem: u32,
    /// The problem code's name, when it is a known one.
    pub problem_name: Option<String>,
    #[record(hex)]
    pub problem_status: u32,
    /// The IRP that PnP waits on. 0 for none.
    pub pending_irp: VirtAddr,
    /// The nodes below this node, in depth-first order. Empty if the
    /// request was not recursive.
    pub subtree: Vec<DevNodeSummary>,
    /// Whether the walk of the subtree stopped at its limit.
    pub subtree_truncated: bool,
}

/// A device stack from the top filter to the PDO, and the device node of
/// the PDO (`!devstack`).
#[record]
pub struct DeviceStack {
    /// The address that you gave: a device object, a pointer to a device
    /// object, or a device node.
    pub argument: VirtAddr,
    /// The device object where the stack walk started.
    pub requested_device: VirtAddr,
    /// The stack, top filter first.
    pub entries: Vec<DeviceStackLayer>,
    /// `None` if the PDO has no device node, or if ntoseye cannot read it.
    /// `pdo_devnode_error` gives the reason.
    pub pdo_devnode: Option<DevNodeSummary>,
    pub pdo_devnode_error: Option<String>,
    /// Whether the stack walk stopped at its limit.
    pub truncated: bool,
}

/// PnP triage groups from one limited walk of the device tree
/// (`!pnptriage`).
#[record]
pub struct PnpTriage {
    /// Nodes with a problem code.
    pub problems: Vec<DevNodeSummary>,
    /// Nodes that are not started, not removed, and not deleted.
    pub not_started: Vec<DevNodeSummary>,
    /// Nodes with a pending IRP.
    pub pending_irps: Vec<DevNodeSummary>,
    /// The number of nodes walked.
    pub total: u64,
    pub started: u64,
    /// Whether the walk stopped at its limit of 4096 nodes.
    pub truncated: bool,
}

fn devnode_summary(summary: &pnp::DevNodeSummary) -> DevNodeSummary {
    DevNodeSummary {
        address: summary.address,
        pdo: summary.pdo,
        instance_path: summary.instance_path.clone(),
        service_name: summary.service_name.clone(),
        state: summary.state,
        state_name: summary.state_name.clone(),
        problem: summary.problem,
        problem_name: summary.problem_name.clone(),
        problem_status: summary.problem_status,
        pending_irp: summary.pending_irp,
        depth: summary.depth,
    }
}

fn state_history_entry(entry: &StateHistoryEntry) -> DevNodeHistoryState {
    DevNodeHistoryState {
        index: entry.index,
        state: entry.state,
        state_name: entry.state_name.clone(),
    }
}

fn device_stack_entry(entry: &DeviceStackEntry) -> DeviceStackLayer {
    DeviceStackLayer {
        device_object: entry.device_object,
        driver_object: entry.driver_object,
        driver_name: entry.driver_name.clone(),
        device_extension: entry.device_extension,
        object_name: entry.object_name.clone(),
        is_argument: entry.is_argument,
    }
}

/// `_DEVICE_NODE` fields plus the optional bounded flat subtree.
pub fn devnode(detail: &DevNodeDetail) -> DevNode {
    DevNode {
        address: detail.address,
        pdo: detail.pdo,
        parent: detail.parent,
        sibling: detail.sibling,
        child: detail.child,
        instance_path: detail.instance_path.clone(),
        service_name: detail.service_name.clone(),
        state: detail.state,
        state_name: detail.state_name.clone(),
        previous_state: detail.previous_state,
        previous_state_name: detail.previous_state_name.clone(),
        state_history: detail
            .state_history
            .iter()
            .map(state_history_entry)
            .collect(),
        state_history_entry: detail.state_history_entry,
        flags: detail.flags,
        user_flags: detail.user_flags,
        completion_status: detail.completion_status,
        problem: detail.problem,
        problem_name: detail.problem_name.clone(),
        problem_status: detail.problem_status,
        pending_irp: detail.pending_irp,
        subtree: detail.subtree.iter().map(devnode_summary).collect(),
        subtree_truncated: detail.subtree_truncated,
    }
}

/// Ordered top-filter-to-PDO device stack and its PDO devnode summary.
pub fn device_stack(detail: &DeviceStackDetail) -> DeviceStack {
    DeviceStack {
        argument: detail.argument,
        requested_device: detail.requested_device,
        entries: detail.entries.iter().map(device_stack_entry).collect(),
        pdo_devnode: detail.pdo_devnode.as_ref().map(devnode_summary),
        pdo_devnode_error: detail.pdo_devnode_error.clone(),
        truncated: detail.truncated,
    }
}

/// PnP triage partitions of one bounded root tree.
pub fn pnp_triage(detail: &PnpTriageDetail) -> PnpTriage {
    PnpTriage {
        problems: detail.problems.iter().map(devnode_summary).collect(),
        not_started: detail.not_started.iter().map(devnode_summary).collect(),
        pending_irps: detail.pending_irps.iter().map(devnode_summary).collect(),
        total: detail.total,
        started: detail.started,
        truncated: detail.truncated,
    }
}
