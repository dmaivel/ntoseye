//! A view of a guest partition of the Windows hypervisor (`.partition`): the
//! session's target and backend are swapped for the partition's, so every
//! inspection command reads that guest's NT, with its VPs as the threads,
//! until the view is left. The target stays halted while it is shown.

use std::mem;

use crate::breakpoints::BreakpointManager;
use crate::dbg_backend::DebugBackend;
use crate::error::{Error, Result};
use crate::partition_backend::{PartitionBackend, PartitionVp};
use crate::session::Session;
use crate::target::Target;

/// What a partition view replaced, put back when it is left. The
/// breakpoints are the target's: in the view, re-resolving their
/// symbols against the partition's would move them into the wrong guest.
pub struct PartitionView {
    pub partition: u64,
    target: Target,
    backend: Box<dyn DebugBackend>,
    thread: String,
    breakpoints: BreakpointManager,
    symbols_reconciled_at: u64,
}

impl Session {
    /// Show guest partition `partition` in place of the target: its memory
    /// through its EPT, its NT kernel's symbols, and its VPs as threads
    /// (`p<partition>.<VP index + 1>`) with the registers they have now (see
    /// [`Self::vp_registers`]). The target must be halted, and stays so; a
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
        let mut target = self.target.partition_target(partition)?;
        // Handles minted for either guest name nothing in the other.
        target.share_generation(self.target.generation_counter());
        target.invalidate_handles();
        let indexes: Vec<u32> = partitions
            .into_iter()
            .find(|candidate| candidate.id == partition)
            .map(|found| found.virtual_processors.iter().map(|vp| vp.index).collect())
            .unwrap_or_default();
        // The vCPU's register file gives the layout every VP's is written in.
        let layout = self.backend.read_registers()?.len();
        let mut vps = Vec::with_capacity(indexes.len());
        for index in indexes {
            let found = self.vp_registers(partition, index, None)?;
            let mut registers = vec![0u8; layout];
            for (name, value) in &found.registers {
                // A register the vCPU's layout lacks is left out.
                let _ = self
                    .register_map
                    .write_u64(name.as_str(), &mut registers, *value);
            }
            vps.push(PartitionVp {
                id: format!("p{partition:x}.{:x}", index + 1),
                registers,
            });
        }
        let first = vps
            .first()
            .map(|vp| vp.id.clone())
            .ok_or_else(|| Error::Hypervisor(format!("partition {partition:#x} has no VPs")))?;
        let backend = Box::new(PartitionBackend::new(self.register_map.clone(), vps));
        let reconciled = target.symbols.load_generation();
        self.partition_view = Some(PartitionView {
            partition,
            target: mem::replace(&mut self.target, target),
            backend: mem::replace(&mut self.backend, backend),
            thread: mem::replace(&mut self.current_thread, first),
            breakpoints: mem::replace(&mut self.breakpoints, BreakpointManager::new()),
            symbols_reconciled_at: mem::replace(&mut self.symbols_reconciled_at, reconciled),
        });
        self.refresh_context_for_current_thread();
        Ok(())
    }

    /// Put the target back in place of the partition view shown, if any.
    /// Returns whether one was.
    pub fn leave_partition(&mut self) -> bool {
        let Some(view) = self.partition_view.take() else {
            return false;
        };
        self.target = view.target;
        self.backend = view.backend;
        self.current_thread = view.thread;
        self.breakpoints = view.breakpoints;
        self.symbols_reconciled_at = view.symbols_reconciled_at;
        self.target.invalidate_handles();
        self.refresh_context_for_current_thread();
        true
    }

    /// The partition whose view is shown, if any.
    pub fn partition(&self) -> Option<u64> {
        self.partition_view.as_ref().map(|view| view.partition)
    }

    /// Refuse `operation`, which runs the target, while a partition view is
    /// shown: before anything a run prepares (traps, parked stops) is
    /// touched, as that state is the target's.
    pub fn require_target_view(&self, operation: &str) -> Result<()> {
        match self.partition() {
            Some(partition) => Err(Error::DebugInfo(format!(
                "{operation} runs the target, and partition {partition:#x} is inspected read-only as the target halted; selecting the root partition (1) returns to the target"
            ))),
            None => Ok(()),
        }
    }
}
