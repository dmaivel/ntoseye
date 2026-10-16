//! Debugger execution-state [`View`] builders: run status,
//! vCPUs, exception policies, stacks, and disassembly.

use ntoseye_macros::record;

use crate::exception_policy::{self, ExceptionPolicyFinalAction, exception_alias};
use crate::types::VirtAddr;

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
