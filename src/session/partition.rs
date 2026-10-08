//! A view of a guest partition of the Windows hypervisor (`.partition`): the
//! session's target and backend are swapped for the partition's, so every
//! inspection command reads that guest's NT, with its VPs as the threads,
//! until the view is left. The target stays halted while it is shown; a
//! resume leaves the view, and a hit of one of the partition's breakpoints
//! shows it again.

use std::collections::HashMap;
use std::mem;

use crate::breakpoints::{
    Breakpoint, BreakpointConfig, BreakpointHitDisposition, BreakpointManager, PartitionFilter,
    StepFrame,
};
use crate::dbg_backend::{DebugBackend, DebugCapability, StopEvent};
use crate::error::{Error, Result};
use crate::guest::HvPartition;
use crate::notice::Notice;
use crate::partition_backend::{PartitionBackend, PartitionVp};
use crate::session::context::{
    refresh_windows_thread_context_for_backend_thread, update_target_context_from_registers,
};
use crate::session::{Session, StopResolution};
use crate::target::Target;
use crate::types::VirtAddr;

/// What a partition view replaced, put back when it is left. The session's
/// breakpoints are not: every one is the target's, a partition's included,
/// and is programmed through this backend and target (see
/// [`Session::breakpoint_sites`]).
pub struct PartitionView {
    pub partition: u64,
    target: Target,
    backend: Box<dyn DebugBackend>,
    thread: String,
    /// The partition's VTL0 EPT pointer, which keys its target when the
    /// view is left (see [`KeptPartition`]); `None` keeps none.
    ept_pointer: Option<u64>,
    /// The target's vCPU that runs each VP at the stop, by the VP's thread
    /// ID: a register write to the VP goes to it (see
    /// [`Session::write_vp_registers`]).
    vcpus: HashMap<String, String>,
}

/// A guest partition's target, kept from its last view for the next, and
/// for checking its breakpoints' hits (see [`Session::partition_hit`]):
/// building one walks the partition's EPT and finds and loads its kernel,
/// most of what a view costs. What it reads of the guest is memoized per
/// halt of the target (see [`crate::phys::PhysMem::halt_epoch`]), so it is
/// not stale after a run. The partition's ID and VTL0 EPT pointer key it:
/// a reloaded hypervisor can give another partition the ID.
pub struct KeptPartition {
    partition: u64,
    ept_pointer: u64,
    target: Target,
}

impl Session {
    /// Show guest partition `partition` in place of the target: its memory
    /// through its EPT, its NT kernel's symbols, and its VPs as threads
    /// (`p<partition>.<VP index + 1>`) with the VTL0 registers they have now
    /// (see [`Self::vp_registers`]). The target must be halted, and stays so; a
    /// view already shown is left first, and the root partition's ID only
    /// leaves it, as the root partition is the target itself.
    pub fn enter_partition(&mut self, partition: u64) -> Result<()> {
        if self.backend.is_running() {
            return Err(Error::TargetRunning(
                "a partition view shows the partition as the target halted",
            ));
        }
        self.leave_partition();
        let partitions = self.target.hypervisor_partitions()?;
        if partitions
            .iter()
            .any(|candidate| candidate.id == partition && candidate.parent.is_none())
        {
            return Ok(());
        }
        let (target, ept_pointer) = self.take_partition_target(partition, &partitions)?;
        let indexes: Vec<u32> = partitions
            .into_iter()
            .find(|candidate| candidate.id == partition)
            .map(|found| found.virtual_processors.iter().map(|vp| vp.index).collect())
            .unwrap_or_default();
        // The vCPU's register file gives the layout every VP's is written in.
        let layout = self.backend.read_registers()?.len();
        let mut vps = Vec::with_capacity(indexes.len());
        for index in indexes {
            // The view is of VTL0 (its EPT, its kernel), so each VP's state
            // is VTL0's even while the VP runs in VTL1, whose RIP and stack
            // would be the partition's secure kernel's.
            let found = self.vp_registers(partition, index, Some(0))?;
            let id = vp_thread_id(partition, index);
            if let Some(reason) = &found.missing {
                self.notices.push(Notice::warning(format!(
                    "{id} shows only VTL0's RIP, RSP, flags, control and segment registers: {reason}"
                )));
            }
            let mut registers = vec![0u8; layout];
            for (name, value) in &found.registers {
                // A register the vCPU's layout lacks is left out.
                let _ = self
                    .register_map
                    .write_u64(name.as_str(), &mut registers, *value);
            }
            // A VP a vCPU runs has that vCPU's whole register file, the
            // vector registers the map of values leaves out among it.
            if let Some(vcpu) = &found.vcpu {
                let file = self
                    .backend
                    .set_current_thread(vcpu)
                    .and_then(|()| self.backend.read_registers());
                self.backend.set_current_thread(&self.current_thread)?;
                registers = file?;
            }
            vps.push(PartitionVp {
                id,
                registers,
                vcpu: found.vcpu,
            });
        }
        let first = vps
            .first()
            .map(|vp| vp.id.clone())
            .ok_or_else(|| Error::Hypervisor(format!("partition {partition:#x} has no VPs")))?;
        self.show_partition(partition, target, vps, first);
        if let Some(view) = &mut self.partition_view {
            view.ept_pointer = ept_pointer;
        }
        Ok(())
    }

    /// The target of guest partition `partition` of `partitions`, with the
    /// partition's VTL0 EPT pointer: the one kept from its last view when
    /// that pointer is still the partition's, the halt it was shown at
    /// forgotten, otherwise a new one (see [`Target::partition_target`]).
    fn take_partition_target(
        &mut self,
        partition: u64,
        partitions: &[HvPartition],
    ) -> Result<(Target, Option<u64>)> {
        let ept_pointer = partitions
            .iter()
            .find(|candidate| candidate.id == partition)
            .and_then(|found| {
                found
                    .virtual_processors
                    .iter()
                    .find_map(|vp| vp.vtls.iter().find(|vtl| vtl.level == 0)?.state)
            })
            .map(|state| state.ept_pointer);
        if let Some(kept) = self
            .kept_partition
            .take_if(|kept| kept.partition == partition && Some(kept.ept_pointer) == ept_pointer)
        {
            let mut target = kept.target;
            target.selected_frame = None;
            target.registers = None;
            target.breakpoint_stop = None;
            target.clear_context_dtb_override();
            target.clear_current_windows_thread_context();
            target.invalidate_handles();
            return Ok((target, ept_pointer));
        }
        let mut target = self.target.partition_target(partition)?;
        // Handles minted for either guest name nothing in the other.
        target.share_generation(self.target.generation_counter());
        target.share_interrupt(&self.target);
        target.invalidate_handles();
        Ok((target, ept_pointer))
    }

    /// Keep `target`, partition `partition`'s, for its next view (see
    /// [`KeptPartition`]); without its EPT pointer there is no key to keep
    /// it by.
    fn keep_partition_target(&mut self, partition: u64, ept_pointer: Option<u64>, target: Target) {
        self.kept_partition = ept_pointer.map(|ept_pointer| KeptPartition {
            partition,
            ept_pointer,
            target,
        });
    }

    /// Swap `target`, partition `partition`'s, and a backend over its `vps`
    /// in for the target's, and select `thread`.
    pub fn show_partition(
        &mut self,
        partition: u64,
        target: Target,
        vps: Vec<PartitionVp>,
        thread: String,
    ) {
        let vcpus = vps
            .iter()
            .filter_map(|vp| Some((vp.id.clone(), vp.vcpu.clone()?)))
            .collect();
        let backend = Box::new(PartitionBackend::new(self.register_map.clone(), vps));
        self.partition_view = Some(PartitionView {
            partition,
            target: mem::replace(&mut self.target, target),
            backend: mem::replace(&mut self.backend, backend),
            thread: mem::replace(&mut self.current_thread, thread),
            ept_pointer: None,
            vcpus,
        });
        self.refresh_context_for_current_thread();
    }

    /// Put the target back in place of the partition view shown, if any,
    /// keeping the partition's target for its next view. Returns whether one
    /// was.
    pub fn leave_partition(&mut self) -> bool {
        let Some(view) = self.partition_view.take() else {
            return false;
        };
        let shown = mem::replace(&mut self.target, view.target);
        self.keep_partition_target(view.partition, view.ept_pointer, shown);
        self.backend = view.backend;
        self.current_thread = view.thread;
        self.target.invalidate_handles();
        self.refresh_context_for_current_thread();
        true
    }

    /// The partition whose view is shown, if any.
    pub fn partition(&self) -> Option<u64> {
        self.partition_view.as_ref().map(|view| view.partition)
    }

    /// Refuse `operation`, an instruction walk (`tc`, `pa`, `wt`), while a
    /// partition view is shown: each step there is a run of the target to
    /// the partition's breakpoints, too slow to walk with.
    pub fn require_target_view(&self, operation: &str) -> Result<()> {
        match self.partition() {
            Some(partition) => Err(Error::DebugInfo(format!(
                "{operation} is not supported in partition {partition:#x}'s view, where each step runs the target to a breakpoint of the partition's; step with t, p or gu, run to an address with g <address>, or select the root partition (1) to return to the target"
            ))),
            None => Ok(()),
        }
    }

    /// The breakpoints, with the backend and target their sites are
    /// programmed through: the target's, also while a partition view is
    /// shown. Every breakpoint is the target's, a partition's included, as
    /// the target's processors trap it; a view's backend and target are only
    /// the partition's VPs and memory, which no site is written to.
    pub fn breakpoint_sites(&mut self) -> (&mut BreakpointManager, &mut dyn DebugBackend, &Target) {
        match &mut self.partition_view {
            Some(view) => (&mut self.breakpoints, view.backend.as_mut(), &view.target),
            None => (&mut self.breakpoints, self.backend.as_mut(), &self.target),
        }
    }

    /// Write `after`, the register file of the VP selected in a partition
    /// view as patched from `before`, to the target's vCPU that runs the VP
    /// at the stop, whose registers the VP's are: only the registers the two
    /// differ in, so the vCPU keeps its own of any the view did not read. No
    /// vCPU runs a VP whose registers are the hypervisor's record of them,
    /// and that is refused. Nothing to do outside a view.
    pub(super) fn write_vp_registers(&mut self, before: &[u8], after: &[u8]) -> Result<()> {
        let Some(view) = &mut self.partition_view else {
            return Ok(());
        };
        let vcpu = view.vcpus.get(&self.current_thread).cloned().ok_or_else(|| {
            Error::DebugInfo(format!(
                "no vCPU runs {} at the stop, so its registers are the hypervisor's record of them, which is not written",
                self.current_thread
            ))
        })?;
        let host = view.backend.as_mut();
        if !host
            .capabilities()
            .iter()
            .any(|entry| entry.capability == DebugCapability::WriteRegisters && entry.supported)
        {
            return Err(Error::RegisterWriteUnsupported);
        }
        let register_map = &self.register_map;
        host.set_current_thread(&vcpu)?;
        let written = host.read_registers().and_then(|mut live| {
            for register in register_map.registers() {
                let range = register.offset..register.offset + register.size;
                if let (Some(old), Some(new)) =
                    (before.get(range.clone()), after.get(range.clone()))
                    && old != new
                {
                    live.get_mut(range)
                        .ok_or_else(|| {
                            Error::DebugInfo(format!(
                                "{vcpu}'s register file has no {}",
                                register.name
                            ))
                        })?
                        .copy_from_slice(new);
                }
            }
            host.write_registers(&live)
        });
        host.set_current_thread(&view.thread)?;
        written
    }

    /// `config` for a debug-register breakpoint at `address` set in the view
    /// of partition `partition`, made the partition's (see
    /// [`PartitionFilter`]): `/c` names a VP, as the view numbers its
    /// processors, and without `/p` the scope is the one the view gives the
    /// address, as a `/p` names one of its processes.
    pub(super) fn partition_breakpoint_config(
        &mut self,
        partition: u64,
        address: VirtAddr,
        mut config: BreakpointConfig,
    ) -> Result<BreakpointConfig> {
        self.require_partition_traps()?;
        let vp = config.processor.take().map(u32::from);
        if let Some(vp) = vp
            && !self
                .backend
                .thread_list()?
                .contains(&vp_thread_id(partition, vp))
        {
            return Err(Error::InvalidArgument(format!(
                "partition {partition:#x} has no VP {vp}"
            )));
        }
        let scope = config
            .scope
            .take()
            .unwrap_or_else(|| BreakpointManager::automatic_scope(&self.target, address));
        config.scope = Some(scope);
        config.partition = Some(PartitionFilter { partition, vp });
        Ok(config)
    }

    /// Refuse a guest partition's breakpoint, a step's among them, on a
    /// backend whose debug registers the guest programs (KD): those trap in
    /// the target's kernel, never in a partition's code.
    fn require_partition_traps(&mut self) -> Result<()> {
        let (_, backend, _) = self.breakpoint_sites();
        if backend.hardware_breakpoints_trap_in_host() {
            Ok(())
        } else {
            Err(Error::Breakpoint(
                "a guest partition's breakpoints and steps need the gdb backend: only a debug register the host programs traps in a partition's code".into(),
            ))
        }
    }

    /// A one-shot breakpoint for a run to `address`, by the execution
    /// `frame` names when given (see
    /// [`BreakpointManager::add_temporary_code`]). In a partition view it is
    /// the partition's, on its code: a step there runs the target to it, on
    /// whichever VP the stepping thread is.
    pub fn add_temporary_code(
        &mut self,
        address: VirtAddr,
        frame: Option<StepFrame>,
    ) -> Result<u32> {
        let partition = self.partition().map(|partition| PartitionFilter {
            partition,
            vp: None,
        });
        if partition.is_some() {
            self.require_partition_traps()?;
        }
        let (breakpoints, backend, target) = self.breakpoint_sites();
        breakpoints.add_temporary_code(backend, target, address, frame, partition)
    }

    /// Surface the hit of `breakpoint`, partition `partition`'s, by its VP
    /// `vp` (when known), if its thread filter, pass count and condition take
    /// it, in the partition's view with that VP selected. The filter and
    /// condition name the partition's threads and read its memory and
    /// symbols, so they are checked on the partition's target with the
    /// registers the stopped vCPU runs the VP with, and the target is kept
    /// for the view (see [`KeptPartition`]): a declined hit builds no view.
    /// `event` is the stop the target reported the hit with; `None` when the
    /// hit is declined. A hit whose partition cannot be read or shown
    /// surfaces in the target's view, saying what was not checked.
    pub(super) fn partition_hit(
        &mut self,
        breakpoint: Breakpoint,
        partition: u64,
        vp: Option<u32>,
        event: StopEvent,
    ) -> Result<Option<StopResolution>> {
        let mut checked_on = None;
        let mut unchecked = None;
        if breakpoint.thread.is_some() || breakpoint.condition_expr.is_some() {
            match self
                .target
                .hypervisor_partitions()
                .and_then(|partitions| self.take_partition_target(partition, &partitions))
            {
                Ok((mut target, ept_pointer)) => {
                    let registers = self.backend.read_registers();
                    update_target_context_from_registers(
                        &mut target,
                        &self.register_map,
                        registers,
                    );
                    checked_on = Some((target, ept_pointer));
                }
                Err(error) => {
                    unchecked = Some(format!(
                        "its thread filter and condition were not checked: partition {partition:#x}'s kernel cannot be read: {error}"
                    ));
                }
            }
        }
        let verdict = judge_partition_hit(
            &mut self.breakpoints,
            checked_on.as_mut().map(|(target, _)| target),
            &breakpoint,
            partition,
            vp,
        );
        if let Some((target, ept_pointer)) = checked_on {
            self.keep_partition_target(partition, ept_pointer, target);
        }
        let condition_error = match verdict? {
            HitVerdict::Declined(reason) => {
                step_trace!(
                    "#{} declined in partition {partition:#x}: {reason}",
                    breakpoint.id
                );
                return Ok(None);
            }
            HitVerdict::Taken { condition_error } => condition_error.or(unchecked),
        };
        if breakpoint.one_shot {
            let (breakpoints, backend, target) = self.breakpoint_sites();
            breakpoints.remove(backend, target, breakpoint.id)?;
        }
        let shown = self.enter_partition(partition).and_then(|()| match vp {
            Some(vp) => self.set_current_thread(&vp_thread_id(partition, vp)),
            None => Ok(()),
        });
        if let Err(error) = shown {
            self.leave_partition();
            self.notices.push(Notice::warning(format!(
                "breakpoint {} hit in partition {partition:#x}, whose view cannot be shown: {error}",
                breakpoint.id
            )));
        }
        Ok(Some(self.watchpoint_hit(
            breakpoint,
            event,
            condition_error,
        )))
    }
}

/// What a partition breakpoint's thread filter, pass count and condition
/// make of a hit.
enum HitVerdict {
    Declined(&'static str),
    Taken { condition_error: Option<String> },
}

/// Judge `breakpoint`'s hit by VP `vp` of partition `partition` by its
/// thread filter, pass count and condition, in that order, as a target's
/// breakpoint's are, on the partition's `target` set to the VP's registers:
/// `None` when it could not be had, which leaves the filter and condition
/// unchecked. A VP not known runs any thread.
fn judge_partition_hit(
    breakpoints: &mut BreakpointManager,
    mut target: Option<&mut Target>,
    breakpoint: &Breakpoint,
    partition: u64,
    vp: Option<u32>,
) -> Result<HitVerdict> {
    if let (Some(thread), Some(target), Some(vp)) = (&breakpoint.thread, target.as_deref_mut(), vp)
    {
        let running =
            refresh_windows_thread_context_for_backend_thread(target, &vp_thread_id(partition, vp));
        if !thread.matches(running.as_ref()) {
            return Ok(HitVerdict::Declined("another thread"));
        }
    }
    if breakpoints.record_hit(breakpoint.id)? == BreakpointHitDisposition::SkipPass {
        return Ok(HitVerdict::Declined("pass count"));
    }
    let condition_error = match target.map(|target| breakpoint.evaluate_condition(target)) {
        Some(Ok(false)) => return Ok(HitVerdict::Declined("condition false")),
        Some(Err(error)) => Some(error.to_string()),
        Some(Ok(true)) | None => None,
    };
    Ok(HitVerdict::Taken { condition_error })
}

/// The thread ID a partition view gives VP `vp` of partition `partition`.
fn vp_thread_id(partition: u64, vp: u32) -> String {
    format!("p{partition:x}.{:x}", vp + 1)
}
