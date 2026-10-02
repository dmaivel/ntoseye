//! Per-breakpoint configuration: the address-space, thread, processor and
//! hypercall-caller filters a hit must pass, and its condition, pass count,
//! one-shot flag and command action.

use std::sync::Arc;

use super::{
    Breakpoint, BreakpointConfig, BreakpointManager, BreakpointScope, HypercallFilter, ThreadScope,
};
use crate::error::{Error, Result};
use crate::expr::Expr;
use crate::guest::{
    ProcessInfo,
    hypercalls::{HypercallCaller, HypercallInput, tlfs_hypercall},
};
use crate::target::{KTHREAD_STATE_TERMINATED, Target, ThreadInfo};
use crate::types::{Arch, VirtAddr};

impl Breakpoint {
    /// What this breakpoint is restricted to: its address space, plus
    /// whichever of `/t`, `/c` and a hypercall filter narrowed it further.
    pub fn scope_label(&self) -> String {
        let mut label = self.scope.label();
        if let Some(thread) = &self.thread {
            label.push_str(&format!(", {}", thread.label()));
        }
        if let Some(processor) = self.processor {
            label.push_str(&format!(", cpu {processor}"));
        }
        if let Some(hypercall) = &self.hypercall {
            label.push_str(&format!(", {}", hypercall.label()));
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
    /// thread either way. The TID is compared too where both are known: an
    /// exited thread's `_ETHREAD` is freed, and a new thread can be given
    /// the same address.
    pub fn matches(&self, stopped: Option<&ThreadInfo>) -> bool {
        stopped.is_none_or(|thread| {
            thread.ethread == self.ethread
                && (self.tid.is_none() || thread.tid.is_none() || thread.tid == self.tid)
        })
    }

    /// Whether this thread is gone, its `_ETHREAD` read `now`: terminated,
    /// or freed and given to a new thread (another TID).
    pub fn exited(&self, now: &ThreadInfo) -> bool {
        now.state == Some(KTHREAD_STATE_TERMINATED)
            || matches!((self.tid, now.tid), (Some(tid), Some(current)) if tid != current)
    }

    pub fn label(&self) -> String {
        match self.tid {
            Some(tid) => format!("tid {tid}"),
            None => format!("ethread {:#x}", self.ethread.0),
        }
    }
}

impl HypercallFilter {
    /// Whether a hit whose processor handles `caller`'s exit is this
    /// filter's call from this filter's caller.
    ///
    /// What is not known does not decline a hit, as for the thread filter:
    /// an unknown caller matches, and so does a caller whose partition and
    /// VP match but whose registers are not known. A known exit that is not
    /// a VMCALL declines it: the handler then runs for no hypercall of the
    /// caller's.
    pub fn matches(&self, caller: Option<&HypercallCaller>) -> bool {
        let Some(caller) = caller else {
            return true;
        };
        if self
            .partition
            .is_some_and(|partition| partition != caller.partition)
            || self.vp.is_some_and(|vp| vp != caller.vp)
        {
            return false;
        }
        match &caller.input {
            HypercallInput::Known(call) => call.control.code == self.code,
            HypercallInput::NotHypercall => false,
            HypercallInput::Unknown(_) => true,
        }
    }

    /// `hypercall 0x000b HvCallSendSyntheticClusterIpi from partition 0x3
    /// VP 1`.
    pub fn label(&self) -> String {
        let mut label = format!("hypercall {:#06x}", self.code);
        if let Some((name, _)) = tlfs_hypercall(self.code) {
            label.push_str(&format!(" {name}"));
        }
        if let Some(partition) = self.partition {
            label.push_str(&format!(" from partition {partition:#x}"));
        }
        if let Some(vp) = self.vp {
            label.push_str(&format!(" VP {vp}"));
        }
        label
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
    use crate::breakpoints::{
        Breakpoint, BreakpointConfig, BreakpointManager, HypercallFilter, ThreadScope,
    };
    use crate::guest::EvmcsState;
    use crate::guest::hypercall_input::decode_hypercall;
    use crate::guest::hypercalls::{HypercallCaller, HypercallInput};
    use crate::session::hits::evaluate_hit_condition;
    use crate::session::session_over_memory;
    use crate::target::{Target, ThreadInfo, sample_thread};
    use crate::types::VirtAddr;
    use std::collections::HashMap;

    /// NT's synthetic IPI, as RCX holds it live: fast, code 0x000b.
    const SEND_IPI: u64 = 0x1_000b;

    fn caller(partition: u64, vp: u32, input: HypercallInput) -> HypercallCaller {
        HypercallCaller {
            partition,
            root: partition == 0x1,
            vp,
            vtl: 0,
            input,
            registers: HashMap::new(),
            state: None,
        }
    }

    /// The call of a fast VMCALL whose RCX is `value`.
    fn known(value: u64) -> HypercallInput {
        HypercallInput::Known(Box::new(decode_hypercall(
            value,
            0,
            0,
            Err(String::new()),
            |_, _| Err("no memory".to_string()),
        )))
    }

    /// The code is RCX's low 16 bits, so the fast and rep flags above them
    /// do not hide a call; and the partition, then the VP, must match where
    /// the filter names them, whether the caller is the root or a guest.
    #[test]
    fn a_hypercall_filter_takes_only_its_call_from_its_caller() {
        let root_vp1 = caller(0x1, 1, known(SEND_IPI));
        let guest_vp1 = caller(0x7, 1, known(SEND_IPI));
        let any = HypercallFilter {
            code: 0x000b,
            partition: None,
            vp: None,
        };
        let root = HypercallFilter {
            partition: Some(0x1),
            ..any
        };
        let guest_vp2 = HypercallFilter {
            partition: Some(0x7),
            vp: Some(2),
            ..any
        };
        assert!(any.matches(Some(&root_vp1)) && any.matches(Some(&guest_vp1)));
        assert!(root.matches(Some(&root_vp1)) && !root.matches(Some(&guest_vp1)));
        assert!(!guest_vp2.matches(Some(&guest_vp1)));
        assert!(guest_vp2.matches(Some(&caller(0x7, 2, known(SEND_IPI)))));
        // Another call into a handler the codes share, such as
        // HvCallUnimplemented's.
        let other_code = caller(0x1, 1, known(0x1_000c));
        assert!(!any.matches(Some(&other_code)));
    }

    /// What is not known does not decline a hit, so a filter never loses
    /// one silently; what is known does, even with the call unknown, and an
    /// exit that is no VMCALL is no hypercall of the caller's.
    #[test]
    fn a_hypercall_filter_stops_where_the_caller_or_its_call_is_unknown() {
        let filter = HypercallFilter {
            code: 0x000b,
            partition: Some(0x7),
            vp: None,
        };
        assert!(filter.matches(None));
        let unknown = || HypercallInput::Unknown("registers not saved yet".to_string());
        assert!(filter.matches(Some(&caller(0x7, 0, unknown()))));
        assert!(!filter.matches(Some(&caller(0x1, 0, unknown()))));
        assert!(!filter.matches(Some(&caller(0x7, 0, HypercallInput::NotHypercall))));
    }

    /// An exited thread's `_ETHREAD` can be given to a new thread: the new
    /// one is not the scope's, and the scope's thread is gone, as it is once
    /// terminated.
    #[test]
    fn a_reused_ethread_is_another_thread_and_its_first_owner_has_exited() {
        let original = sample_thread();
        let scope = ThreadScope::new(&original);
        let reused = ThreadInfo {
            tid: Some(0x99),
            ..sample_thread()
        };
        let terminated = ThreadInfo {
            state: Some(4),
            ..sample_thread()
        };
        assert!(scope.matches(Some(&original)) && !scope.exited(&original));
        assert!(!scope.matches(Some(&reused)) && scope.exited(&reused));
        assert!(scope.exited(&terminated));
    }

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

    /// A breakpoint on the hypercall handler at 0x1000 of `target`, for
    /// call 0xb from any caller, with `condition`.
    fn conditional_hypercall_breakpoint(target: &Target, condition: &str) -> Breakpoint {
        let mut client = SlotRecorder::accepting();
        let mut manager = BreakpointManager::new();
        let id = manager
            .add_configured(
                &mut client,
                target,
                VirtAddr(0x1000),
                None,
                BreakpointConfig {
                    condition: Some(condition.to_string()),
                    hypercall: Some(HypercallFilter {
                        code: 0xb,
                        partition: None,
                        vp: None,
                    }),
                    ..BreakpointConfig::default()
                },
            )
            .expect("configured breakpoint installs");
        manager.breakpoints[&id].clone()
    }

    /// A hypercall breakpoint's condition reads its caller's registers, not
    /// those the hypervisor runs the handler with; with the caller unknown
    /// it cannot be evaluated (so the hit stops). The registers in use
    /// afterwards are the hypervisor's again.
    #[test]
    fn a_hypercall_condition_reads_the_callers_registers() {
        let mut session = session_over_memory(0x1000, &[0u8; 0x80]);
        let bp = conditional_hypercall_breakpoint(&session.target, "rdx == 0xfb");
        let hypervisor = HashMap::from([("rdx".to_string(), 0xfb), ("rip".to_string(), 0x1000)]);
        session.target.registers = Some(hypervisor.clone());
        let with_rdx = |rdx| HypercallCaller {
            registers: HashMap::from([("rdx".to_string(), rdx)]),
            ..caller(4, 1, known(SEND_IPI))
        };

        let holds = |target: &mut Target, caller: Option<&HypercallCaller>| {
            evaluate_hit_condition(target, &bp, caller)
        };
        assert!(holds(&mut session.target, Some(&with_rdx(0xfb))).unwrap());
        assert!(
            !holds(&mut session.target, Some(&with_rdx(0x2f))).unwrap(),
            "the hypervisor's rdx is 0xfb"
        );
        assert!(holds(&mut session.target, None).is_err());
        assert_eq!(session.target.registers, Some(hypervisor));
    }

    /// A hypercall breakpoint's condition reads its caller's memory: `$p`
    /// reads its guest physical memory through the calling VTL's EPT (a
    /// slow call's input page, at the GPA in RDX), and `dwo`/`poi` its
    /// virtual memory through its CR3, walked through the EPT too. The
    /// host page at the input's GPA holds other data, which a read of the
    /// target's physical memory would see. With the caller's state not
    /// known, a read fails rather than read the hypervisor's memory; and
    /// afterwards, expressions read the target's memory again.
    #[test]
    fn a_hypercall_condition_reads_the_callers_memory() {
        const BASE: u64 = 0x10000;
        const RWX: u64 = 7;
        const WB: u64 = 6 << 3;
        // The input's GPA, which the EPT maps to the host page after it.
        const INPUT_GPA: u64 = BASE + 0x8000;
        const INPUT_VA: u64 = 0x7ff6_1234_5000;
        let mut memory = vec![0u8; 0xa000];
        let mut put = |at: u64, value: u64| {
            let at = (at - BASE) as usize;
            memory[at..at + 8].copy_from_slice(&value.to_le_bytes());
        };
        // EPT: PML4, PDPT, PD and PT at BASE, identity but for the input.
        put(BASE, (BASE + 0x1000) | RWX);
        put(BASE + 0x1000, (BASE + 0x2000) | RWX);
        put(BASE + 0x2000, (BASE + 0x3000) | RWX);
        for gpa in (BASE..BASE + 0xa000).step_by(0x1000) {
            let host = if gpa == INPUT_GPA { gpa + 0x1000 } else { gpa };
            put(BASE + 0x3000 + (gpa >> 12) * 8, host | RWX | WB);
        }
        // The caller's 4-level page tables, at GPA BASE + 0x4000.
        let va = VirtAddr(INPUT_VA);
        put(
            BASE + 0x4000 + va.pml4_index() as u64 * 8,
            (BASE + 0x5000) | 7,
        );
        put(
            BASE + 0x5000 + va.pdpt_index() as u64 * 8,
            (BASE + 0x6000) | 7,
        );
        put(
            BASE + 0x6000 + va.pd_index() as u64 * 8,
            (BASE + 0x7000) | 7,
        );
        put(BASE + 0x7000 + va.pt_index() as u64 * 8, INPUT_GPA | 7);
        put(INPUT_GPA + 0x10, 0x1111_1111);
        put(INPUT_GPA + 0x1000 + 0x10, 0x2222_2222);
        let mut session = session_over_memory(BASE, &memory);
        let state = EvmcsState {
            ept_pointer: BASE | (3 << 3) | 6,
            cr3: BASE + 0x4000,
            entry_controls: 1 << 9,
            cs_access_rights: 0xa09b,
            ..EvmcsState::at(0, true)
        };
        let caller_in = |state| HypercallCaller {
            registers: HashMap::from([
                ("rdx".to_string(), INPUT_GPA),
                ("r8".to_string(), INPUT_VA),
            ]),
            state,
            ..caller(4, 1, known(0x000b))
        };
        let holds = |target: &mut Target, condition: &str, state| {
            let bp = conditional_hypercall_breakpoint(target, condition);
            evaluate_hit_condition(target, &bp, Some(&caller_in(state)))
        };

        let target = &mut session.target;
        assert!(holds(target, "$pdwo(rdx+0x10) == 0x22222222", Some(state)).unwrap());
        assert!(holds(target, "dwo(r8+0x10) == 0x22222222", Some(state)).unwrap());
        assert!(holds(target, "$pdwo(rdx+0x10) == 0x11111111", None).is_err());
        let after = conditional_hypercall_breakpoint(target, "$pdwo(0x18010) == 0x11111111");
        assert!(after.evaluate_condition(target).unwrap());
    }
}
