//! Debugger execution-state [`View`] builders: run status,
//! vCPUs, breakpoints, exception policies, stacks, call traces, and
//! disassembly.

use ntoseye_macros::record;

use crate::breakpoints::{self, Breakpoint};
use crate::exception_policy::{self, ExceptionPolicyFinalAction, exception_alias};
use crate::guest::exit_reason_name;
use crate::guest::hypercalls::tlfs_hypercall;
use crate::guest::vm_exits;
use crate::session::{self, CallTraceEnd};
use crate::types::VirtAddr;

/// A code breakpoint or data watchpoint (`bl`).
#[record]
pub struct BreakpointStatus {
    pub id: u32,
    /// None while a symbolic or source breakpoint is deferred.
    pub address: Option<VirtAddr>,
    pub enabled: bool,
    /// Whether the breakpoint resolved to an address. Use it to tell a
    /// deferred breakpoint from a disabled one.
    pub resolved: bool,
    /// Whether a symbolic or source specification waits for resolution.
    pub deferred: bool,
    /// The symbolic or source specification (`bu`/`bm`), which ntoseye
    /// keeps when it resolves the breakpoint again.
    pub specification: Option<String>,
    /// The display name of the current resolution.
    pub symbol: Option<String>,
    /// `global`, or the process that the breakpoint is limited to
    /// (`name (pid)`).
    pub scope: String,
    /// The only thread that can report a hit (`/t`: `tid N` or
    /// `ethread 0x...`). None if there is no thread restriction.
    pub thread: Option<String>,
    /// The only processor that can report a hit (`/c`). None if there is no
    /// processor restriction.
    pub processor: Option<u16>,
    /// The hypercall a hit must be handling, and from which caller, for a
    /// hypercall breakpoint (`!hvbp`). None for any other breakpoint.
    pub hypercall: Option<HypercallFilter>,
    /// The VM exit a hit must be handling, and from which caller, for a
    /// VM-exit breakpoint (`!hvexit`). None for any other breakpoint.
    pub vm_exit: Option<ExitFilter>,
    /// The guest partition of the Windows hypervisor whose VPs a hit
    /// must be on, for a breakpoint set in its view (`.partition`). None
    /// for the target's own breakpoints.
    pub partition: Option<PartitionFilter>,
    /// The condition expression that a hit must satisfy.
    pub condition: Option<String>,
    /// The requested hit number. Both 0 and 1 break on the first hit.
    pub pass_count: u64,
    pub hit_count: u64,
    /// The number of hits that remain before the breakpoint breaks.
    pub remaining_pass_count: u64,
    /// Whether ntoseye removes the breakpoint after its first break.
    pub one_shot: bool,
    /// The commands that run when the breakpoint breaks.
    pub action: Option<String>,
    pub temporary: bool,
    /// `write` or `read_write` for a data watchpoint. None for a code
    /// breakpoint.
    pub watch_access: Option<&'static str>,
    /// The watched width in bytes. None for a code breakpoint.
    pub watch_length: Option<u8>,
}

/// What a hypercall breakpoint (`!hvbp`) stops on: one call code, from
/// any caller or from one partition or VP of the Windows hypervisor.
#[record]
pub struct HypercallFilter {
    /// The call code: the low 16 bits of the caller's RCX.
    #[record(hex)]
    pub code: u16,
    /// The TLFS name, or None for a code that the TLFS does not list.
    pub name: Option<&'static str>,
    /// The caller's partition ID. None for any caller.
    pub partition: Option<u64>,
    /// The caller's VP index in `partition`. None for any VP.
    pub vp: Option<u32>,
}

/// What a VM-exit breakpoint (`!hvexit`) stops on: one basic exit
/// reason, from any VP or from one partition or VP of the Windows
/// hypervisor.
#[record]
pub struct ExitFilter {
    /// The basic exit reason (Intel SDM Appendix C).
    pub reason: u16,
    /// Its name, or None for a reason ntoseye does not name.
    pub name: Option<&'static str>,
    /// The caller's partition ID. None for any caller.
    pub partition: Option<u64>,
    /// The caller's VP index in `partition`. None for any VP.
    pub vp: Option<u32>,
}

/// The guest partition a breakpoint set in its view (`.partition`)
/// stops in: a hit by any other VP than the partition's resumes.
#[record]
pub struct PartitionFilter {
    /// The partition ID.
    pub partition: u64,
    /// The VP index a hit must be on (`/c` in the view). None for any of
    /// the partition's VPs.
    pub vp: Option<u32>,
}

/// A `wt` call trace: why it stopped, the instructions that it stepped,
/// and the call tree.
#[record]
pub struct CallTrace {
    /// `returned`, `limit`, `interrupted`, `breakpoint`, `diverted`, or
    /// `failed`. `interrupted` means Ctrl+C or the `timeout` ended it.
    /// `diverted` means that an interrupt diverted a step and the traced
    /// thread is not known. Any value other than `returned` means that
    /// the tree is partial.
    pub end: &'static str,
    /// A description of the failure, for `failed`.
    pub error: Option<String>,
    /// The number of single-stepped instructions.
    pub instructions: usize,
    pub root: CallTraceFrame,
}

/// One call-tree node of a `wt` trace.
#[record]
pub struct CallTraceFrame {
    /// The called function.
    pub name: String,
    /// The number of instructions stepped in the function itself.
    pub instructions: usize,
    /// The calls that the function made.
    pub children: Vec<CallTraceFrame>,
}

/// One exception stop policy (`sx`).
#[record]
pub struct ExceptionPolicy {
    /// The exception code.
    #[record(hex)]
    pub code: u32,
    /// The WinDbg alias of the code (`av`, `bp`, ...), if it has one.
    pub alias: Option<&'static str>,
    /// `break`, `second_chance`, `notify`, or `ignore`.
    pub mode: &'static str,
    /// An explicit final action: `break`, or continue as `handled` or
    /// `not_handled`. None for the default action of the mode.
    pub disposition: Option<&'static str>,
    /// The commands that run when the exception occurs.
    pub command: Option<String>,
}

/// One module load or unload filter (`sx* ld[:<module>]` or
/// `sx* ud[:<module>]`).
#[record]
pub struct ModuleEventPolicy {
    /// `ld` for a load filter, `ud` for an unload filter.
    pub event: &'static str,
    /// The image-name glob that the filter matches, with or without
    /// extension. None for all modules (bare `ld` or `ud`).
    pub module: Option<String>,
    /// `break` stops at the event, and `notify` reports it.
    /// `second_chance` and `ignore` let the load or unload continue with
    /// no output.
    pub mode: &'static str,
    /// The commands that run at a `break` stop.
    pub command: Option<String>,
}

/// An evaluated debugger expression (`?`).
#[record]
pub struct ExpressionValue {
    pub expression: String,
    pub value: VirtAddr,
}

/// What a hypercall breakpoint stops on.
pub fn hypercall_filter(filter: &breakpoints::HypercallFilter) -> HypercallFilter {
    HypercallFilter {
        code: filter.code,
        name: tlfs_hypercall(filter.code).map(|(name, _)| name),
        partition: filter.partition,
        vp: filter.vp,
    }
}

/// What a VM-exit breakpoint stops on.
pub fn exit_filter(filter: &vm_exits::ExitFilter) -> ExitFilter {
    ExitFilter {
        reason: filter.reason,
        name: exit_reason_name(u32::from(filter.reason)),
        partition: filter.partition,
        vp: filter.vp,
    }
}

/// Which guest partition a breakpoint set in its view stops in.
pub fn partition_filter(filter: &breakpoints::PartitionFilter) -> PartitionFilter {
    PartitionFilter {
        partition: filter.partition,
        vp: filter.vp,
    }
}

/// One code-breakpoint/data-watchpoint row.
pub fn breakpoint(bp: &Breakpoint) -> BreakpointStatus {
    BreakpointStatus {
        id: bp.id,
        address: bp.resolved_address(),
        enabled: bp.enabled,
        resolved: bp.resolved,
        deferred: bp.deferred(),
        specification: bp.specification().map(str::to_string),
        symbol: bp.symbol.clone(),
        scope: bp.scope.label(),
        thread: bp.thread.as_ref().map(|thread| thread.label()),
        processor: bp.processor,
        hypercall: bp.hypercall.as_ref().map(hypercall_filter),
        vm_exit: bp.vm_exit.as_ref().map(exit_filter),
        partition: bp.partition.as_ref().map(partition_filter),
        condition: bp.condition.clone(),
        pass_count: bp.pass_count,
        hit_count: bp.hit_count,
        remaining_pass_count: bp.remaining_pass_count,
        one_shot: bp.one_shot,
        action: bp.action.clone(),
        temporary: bp.temporary,
        watch_access: bp.watch_access_name(),
        watch_length: bp.watch_length(),
    }
}

/// A `wt` call trace.
pub fn call_trace(trace: &session::CallTrace) -> CallTrace {
    let (end, error) = match &trace.end {
        CallTraceEnd::Returned => ("returned", None),
        CallTraceEnd::Limit => ("limit", None),
        CallTraceEnd::Interrupted => ("interrupted", None),
        CallTraceEnd::Breakpoint => ("breakpoint", None),
        CallTraceEnd::Diverted => ("diverted", None),
        CallTraceEnd::Failed(error) => ("failed", Some(error.clone())),
    };
    CallTrace {
        end,
        error,
        instructions: trace.instructions,
        root: call_trace_frame(&trace.root),
    }
}

fn call_trace_frame(frame: &session::CallTraceFrame) -> CallTraceFrame {
    CallTraceFrame {
        name: frame.name.clone(),
        instructions: frame.instructions,
        children: frame.children.iter().map(call_trace_frame).collect(),
    }
}

/// One module load or unload filter (`sx`).
pub fn module_event_policy(policy: &exception_policy::ModuleEventPolicy) -> ModuleEventPolicy {
    ModuleEventPolicy {
        event: policy.event.filter_name(),
        module: policy.module.clone(),
        mode: policy.mode.name(),
        command: policy.command.clone(),
    }
}

/// One exception stop policy (`sx`).
pub fn exception_policy(code: u32, policy: &exception_policy::ExceptionPolicy) -> ExceptionPolicy {
    let disposition = match policy.final_action {
        Some(ExceptionPolicyFinalAction::Continue(disposition)) => Some(disposition.name()),
        Some(ExceptionPolicyFinalAction::Break) => Some("break"),
        None => None,
    };
    ExceptionPolicy {
        code,
        alias: exception_alias(code),
        mode: policy.mode.name(),
        disposition,
        command: policy.command.clone(),
    }
}
