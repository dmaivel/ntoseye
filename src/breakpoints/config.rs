//! Per-breakpoint configuration: the address-space, thread and processor
//! filters a hit must pass, and its condition, pass count, one-shot flag
//! and command action.

use std::sync::Arc;

use super::{Breakpoint, BreakpointConfig, BreakpointManager, BreakpointScope, ThreadScope};
use crate::error::{Error, Result};
use crate::expr::Expr;
use crate::guest::ProcessInfo;
use crate::target::{Target, ThreadInfo};
use crate::types::{Arch, VirtAddr};

impl Breakpoint {
    /// What this breakpoint is restricted to: its address space, plus
    /// whichever of `/t` and `/c` narrowed it further.
    pub fn scope_label(&self) -> String {
        let mut label = self.scope.label();
        if let Some(thread) = &self.thread {
            label.push_str(&format!(", {}", thread.label()));
        }
        if let Some(processor) = self.processor {
            label.push_str(&format!(", cpu {processor}"));
        }
        label
    }

    pub(super) fn should_evaluate_after_hit(&self) -> bool {
        self.remaining_pass_count == 0
    }

    /// Evaluate the condition compiled when this breakpoint was installed.
    /// Unconditional breakpoints always hold.
    pub fn evaluate_condition(&self, target: &Target) -> Result<bool> {
        match &self.condition_expr {
            Some(expr) => Ok(expr.resolve(target)?.0 != 0),
            None => Ok(true),
        }
    }
}

impl BreakpointScope {
    pub fn process(process: &ProcessInfo) -> Self {
        Self::Process {
            pid: process.pid,
            dtb: process.dtb,
            name: process.name.clone(),
        }
    }

    /// Whether `dtb` names the address space this scope is bound to.
    ///
    /// A dtb register carries more than the page-table base: a PCID in CR3's
    /// low bits, an ASID in TTBR0_EL1's bits 48..63. Both sides are masked
    /// down to the base frame, and the mask differs per architecture: AMD64's
    /// leaves ARM64 ASID bits 48..51 in the comparison, so a process-scoped
    /// breakpoint would stop matching its own process when the ASID rolls.
    pub fn matches_dtb(&self, dtb: u64, arch: Arch) -> bool {
        match self {
            Self::Kernel => true,
            Self::Process { dtb: scope, .. } => {
                let mask = arch.dtb_page_mask();
                (dtb & mask) == (*scope & mask)
            }
        }
    }

    pub fn label(&self) -> String {
        match self {
            Self::Kernel => "global".to_string(),
            Self::Process { pid, name, .. } => format!("{name} ({pid})"),
        }
    }
}

impl ThreadScope {
    pub fn new(thread: &ThreadInfo) -> Self {
        Self {
            ethread: thread.ethread,
            tid: thread.tid,
        }
    }

    /// Whether a hit reported by `stopped` belongs to this thread.
    ///
    /// An unresolved stopped thread matches: discarding a hit that cannot be
    /// attributed would lose it silently, and the stop banner names the
    /// thread either way.
    pub fn matches(&self, stopped: Option<&ThreadInfo>) -> bool {
        stopped.is_none_or(|thread| thread.ethread == self.ethread)
    }

    pub fn label(&self) -> String {
        match self.tid {
            Some(tid) => format!("tid {tid}"),
            None => format!("ethread {:#x}", self.ethread.0),
        }
    }
}

impl BreakpointManager {
    /// The compiled condition for a configuration. A host may hand over the
    /// condition already parsed or as text; leaving text uncompiled would
    /// store a condition that is displayed but never evaluated, so the
    /// breakpoint would stop on every hit.
    pub(super) fn configured_condition(config: &BreakpointConfig) -> Result<Option<Arc<Expr>>> {
        if let Some(expr) = &config.condition_expr {
            return Ok(Some(Arc::clone(expr)));
        }
        config
            .condition
            .as_deref()
            .map(Expr::parse)
            .transpose()
            .map(|expr| expr.map(Arc::new))
    }

    pub(super) fn scope_for_current_context(debugger: &Target) -> BreakpointScope {
        match debugger.attached_process() {
            Some(ProcessInfo { pid, name, dtb, .. }) => BreakpointScope::Process {
                pid: *pid,
                dtb: *dtb,
                name: name.clone(),
            },
            None => BreakpointScope::Kernel,
        }
    }

    pub(super) fn scope_for_address(
        debugger: &Target,
        address: VirtAddr,
        fallback: &BreakpointScope,
    ) -> BreakpointScope {
        const WINDOWS_X64_KERNEL_START: u64 = 0xffff_8000_0000_0000;
        if address.0 >= WINDOWS_X64_KERNEL_START
            || Self::find_kernel_module_containing_address(debugger, address).is_some()
        {
            BreakpointScope::Kernel
        } else {
            fallback.clone()
        }
    }

    pub fn set_pass_count(&mut self, id: u32, pass_count: u64) -> Result<()> {
        let bp = self.breakpoints.get_mut(&id).ok_or(Error::BPNotFound(id))?;
        bp.pass_count = pass_count;
        bp.remaining_pass_count = pass_count.saturating_sub(1);
        Ok(())
    }

    pub fn set_one_shot(&mut self, id: u32, one_shot: bool) -> Result<()> {
        self.breakpoints
            .get_mut(&id)
            .ok_or(Error::BPNotFound(id))?
            .one_shot = one_shot;
        Ok(())
    }

    pub fn set_action(&mut self, id: u32, action: Option<String>) -> Result<()> {
        self.breakpoints
            .get_mut(&id)
            .ok_or(Error::BPNotFound(id))?
            .action = action;
        Ok(())
    }

    pub fn set_condition(
        &mut self,
        id: u32,
        condition: Option<String>,
        condition_expr: Option<Arc<Expr>>,
    ) -> Result<()> {
        let bp = self.breakpoints.get_mut(&id).ok_or(Error::BPNotFound(id))?;
        bp.condition = condition;
        bp.condition_expr = condition_expr;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::breakpoints::test_backend::SlotRecorder;
    use crate::breakpoints::{BreakpointConfig, BreakpointManager};
    use crate::session::session_over_memory;
    use crate::types::VirtAddr;

    #[test]
    fn conditions_supplied_as_text_are_enforced() {
        let session = session_over_memory(0x1000, &[0u8; 0x80]);
        let mut client = SlotRecorder::accepting();

        for (condition, holds) in [("0", false), ("1", true)] {
            let mut manager = BreakpointManager::new();
            let id = manager
                .add_configured(
                    &mut client,
                    &session.target,
                    VirtAddr(0x1000),
                    None,
                    BreakpointConfig {
                        condition: Some(condition.to_string()),
                        ..BreakpointConfig::default()
                    },
                )
                .expect("configured breakpoint installs");
            let bp = &manager.breakpoints[&id];
            assert_eq!(
                bp.evaluate_condition(&session.target).unwrap(),
                holds,
                "condition {condition:?} was stored but not evaluated"
            );
        }
    }
}
