//! Run control: resume, break in, step, walk and trace. Each command is the
//! [`Motion`] its host drives through [`Session::run`]: the REPL with its
//! wait loop and stop rendering ([`ReplState::run_motion`]), the SDK with
//! its `timeout` and `when=` callbacks (`python::runcontrol`).

use crate::dbg_backend::ContinueDisposition;
use crate::error::{Error, Result};
use crate::notice::Notice;
use crate::repl::args::{ArgCursor, ArgCx, ArgError};
use crate::repl::*;
use crate::session::{
    CallTrace, CallTraceEnd, CallTraceFrame, Cancel, Motion, Session, StepMode, WalkUntil,
};
use crate::types::VirtAddr;
use ntoseye_macros::command;

/// `g`'s optional address: the rest of the line, one expression. The
/// `.vtl 1` view names addresses in VTL1 but holds no vCPU context to run
/// from, so it refuses one before anything leaves the view.
fn run_address(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Option<VirtAddr>, ArgError> {
    let expression = cursor.rest();
    if expression.is_empty() {
        return Ok(None);
    }
    if cx.state.ctx.target.in_secure_scope() {
        return Err(ArgError::Message(format!(
            "'{name} <address>' is unavailable in the .vtl 1 memory view; set `ba e1 <address>` \
             and resume with plain {name}",
            name = cx.name
        )));
    }
    cx.eval(&expression).map(Some).map_err(|error| match error {
        ArgError::Message(message) => {
            ArgError::Message(format!("invalid {} address: {message}", cx.name))
        }
        missing => missing,
    })
}

/// `pa`'s and `ta`'s address: the rest of the line, one expression.
fn walk_address(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<VirtAddr, ArgError> {
    let expression = cursor.rest();
    if expression.is_empty() {
        return Err(ArgError::Missing);
    }
    cx.eval(&expression)
}

/// Resume VM execution.
///
/// With an address, g runs to a temporary breakpoint at that address.
/// ntoseye checks that an instruction starts there as bp does: it refuses an
/// address inside an instruction and warns when it cannot check. In
/// secure-kernel code, this breakpoint uses a debug register, and ntoseye
/// never patches the code. The .vtl 1 memory view accepts only g without an
/// address, which leaves the view before it resumes the VM. To stop in VTL1,
/// use `ba e1`.
#[command(
    names = ["g", "continue"],
    category = "execution and stack",
    kind = Run,
    run = Run,
    python = Debugger,
    python_name = "run",
    usage = "g [address]",
    completion = Expression
)]
fn go(
    session: &mut Session,
    #[arg(parse = run_address, keyword)] address: Option<VirtAddr>,
    #[arg(sdk, keyword, default = None)] disposition: Option<ContinueDisposition>,
) -> Result<Motion> {
    let disposition = disposition.unwrap_or(ContinueDisposition::Handled);
    let Some(address) = address else {
        return Ok(Motion::Continue { disposition });
    };
    if session.backend.is_running() {
        return Err(Error::DebugInfo("VM is running".to_string()));
    }
    // Secure-kernel code and a partition's take a debug register for the
    // run, which writes nothing.
    if session.partition().is_none() && !session.target.is_secure_address(address) {
        let dtb = session.target.current_dtb();
        if let Some(warning) = session.check_instruction_start(dtb, address)? {
            session.push_notice(Notice::warning(warning));
        }
    }
    Ok(Motion::RunTo {
        address,
        frame: None,
        disposition,
    })
}

/// Resume and mark the current exception handled.
#[command(
    names = ["gh"],
    category = "execution and stack",
    kind = Run,
    run = Run,
    python = none,
    usage = "gh [address]",
    completion = Expression
)]
fn go_handled(
    session: &mut Session,
    #[arg(parse = run_address)] address: Option<VirtAddr>,
) -> Result<Motion> {
    go(session, address, Some(ContinueDisposition::Handled))
}

/// Resume and pass the current exception to Windows (KD only).
#[command(
    names = ["gn"],
    category = "execution and stack",
    kind = Run,
    run = Run,
    python = none,
    usage = "gn [address]",
    completion = Expression
)]
fn go_not_handled(
    session: &mut Session,
    #[arg(parse = run_address)] address: Option<VirtAddr>,
) -> Result<Motion> {
    go(session, address, Some(ContinueDisposition::NotHandled))
}

/// Break in and pause VM execution.
#[command(
    names = ["break"],
    category = "execution and stack",
    kind = Run,
    state = Running,
    python = none,
    usage = "break"
)]
fn break_in(_session: &mut Session) -> Result<Motion> {
    Ok(Motion::Break)
}

/// Step one instruction (step into).
#[command(
    names = ["t", "si"],
    category = "execution and stack",
    kind = Run,
    state = Halted,
    run = Step,
    python = Debugger,
    python_name = "step",
    usage = "t"
)]
fn step(
    _session: &mut Session,
    #[arg(sdk, default = None)] until: Option<WalkUntil>,
) -> Result<Motion> {
    Ok(until.map_or(Motion::Step, |until| Motion::walk(StepMode::Into, until)))
}

/// Step over the current instruction.
///
/// If the instruction is a call, p runs to the instruction after the call and
/// stops there only when the thread that you step returns from that call.
/// Other threads that get to the address, and deeper calls of the same code,
/// continue to run.
#[command(
    names = ["p", "ni"],
    category = "execution and stack",
    kind = Run,
    state = Halted,
    run = Run,
    python = Debugger,
    python_name = "step_over",
    usage = "p or ni"
)]
fn step_over(
    _session: &mut Session,
    #[arg(sdk, default = None)] until: Option<WalkUntil>,
) -> Result<Motion> {
    Ok(until.map_or(Motion::StepOver, |until| {
        Motion::walk(StepMode::Over, until)
    }))
}

/// Run until the current function returns.
///
/// gu stops at the return address only when the thread that you step returns
/// from this call. Other threads that get to the address, and deeper calls of
/// the same function, continue to run.
#[command(
    names = ["gu", "finish"],
    category = "execution and stack",
    kind = Run,
    state = Halted,
    run = Run,
    python = Debugger,
    python_name = "step_out",
    usage = "gu or finish"
)]
fn step_out(_session: &mut Session) -> Result<Motion> {
    Ok(Motion::StepOut)
}

/// Step over repeatedly until execution gets to an address.
#[command(
    names = ["pa"],
    category = "execution and stack",
    kind = Run,
    run = Run,
    python = none,
    usage = "pa <address>",
    completion = Expression
)]
fn step_over_to(
    session: &mut Session,
    #[arg(parse = walk_address)] address: VirtAddr,
) -> Result<Motion> {
    step_over(session, Some(WalkUntil::Address(address)))
}

/// Step into repeatedly until execution gets to an address.
#[command(
    names = ["ta"],
    category = "execution and stack",
    kind = Run,
    state = Halted,
    run = Run,
    python = none,
    usage = "ta <address>",
    completion = Expression
)]
fn step_to(
    session: &mut Session,
    #[arg(parse = walk_address)] address: VirtAddr,
) -> Result<Motion> {
    step(session, Some(WalkUntil::Address(address)))
}

/// Step over until the next call instruction.
#[command(
    names = ["pc"],
    category = "execution and stack",
    kind = Run,
    state = Halted,
    run = Run,
    python = none,
    usage = "pc"
)]
fn step_over_to_call(session: &mut Session) -> Result<Motion> {
    step_over(session, Some(WalkUntil::Call))
}

/// Step into until the next call instruction.
#[command(
    names = ["tc"],
    category = "execution and stack",
    kind = Run,
    state = Halted,
    run = Run,
    python = none,
    usage = "tc"
)]
fn step_to_call(session: &mut Session) -> Result<Motion> {
    step(session, Some(WalkUntil::Call))
}

/// Step over until the next return instruction.
#[command(
    names = ["pt"],
    category = "execution and stack",
    kind = Run,
    state = Halted,
    run = Run,
    python = none,
    usage = "pt"
)]
fn step_over_to_return(session: &mut Session) -> Result<Motion> {
    step_over(session, Some(WalkUntil::Return))
}

/// Step into until the next return instruction.
#[command(
    names = ["tt"],
    category = "execution and stack",
    kind = Run,
    state = Halted,
    run = Run,
    python = none,
    usage = "tt"
)]
fn step_to_return(session: &mut Session) -> Result<Motion> {
    step(session, Some(WalkUntil::Return))
}

/// Step over until the next branch instruction.
#[command(
    names = ["ph"],
    category = "execution and stack",
    kind = Run,
    state = Halted,
    run = Run,
    python = none,
    usage = "ph"
)]
fn step_over_to_branch(session: &mut Session) -> Result<Motion> {
    step_over(session, Some(WalkUntil::Branch))
}

/// Step into until the next branch instruction.
#[command(
    names = ["th"],
    category = "execution and stack",
    kind = Run,
    state = Halted,
    run = Run,
    python = none,
    usage = "th"
)]
fn step_to_branch(session: &mut Session) -> Result<Motion> {
    step(session, Some(WalkUntil::Branch))
}

/// Watch and trace calls until the current function returns.
#[command(
    names = ["wt"],
    category = "execution and stack",
    kind = Run,
    state = Halted,
    run = Run,
    python = Debugger,
    usage = "wt [count]",
    completion = Expression
)]
fn trace_calls(
    session: &mut Session,
    #[arg(cancel)] cancel: &Cancel<'_>,
    #[arg(name = "count", default = 10_000)] limit: usize,
) -> Result<CallTrace> {
    session.trace_calls(limit, cancel)
}

fn render_trace_frame(frame: &CallTraceFrame, depth: usize) {
    outln!(
        "{}{} ({} instructions)",
        "  ".repeat(depth),
        frame.name,
        frame.instructions
    );
    for child in &frame.children {
        render_trace_frame(child, depth + 1);
    }
}

impl Render for CallTrace {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        let count = self.instructions;
        match &self.end {
            CallTraceEnd::Returned => {}
            CallTraceEnd::Limit => outln!("wt instruction cap reached after {count} instructions"),
            CallTraceEnd::Interrupted => outln!("wt interrupted after {count} instructions"),
            CallTraceEnd::Breakpoint => error!("watch-trace stopped at a code breakpoint"),
            CallTraceEnd::Diverted => error!(
                "watch-trace stopped after {count} instructions: a step was diverted into an \
                 interrupt handler, and the traced thread is not known to follow"
            ),
            CallTraceEnd::Failed(error) => {
                error!("watch-trace stopped after {count} instructions: {error}")
            }
        }
        #[cfg(feature = "cli")]
        native::render(
            || native::trees::call_tree(&self.root),
            || render_trace_frame(&self.root, 0),
        );
        #[cfg(not(feature = "cli"))]
        render_trace_frame(&self.root, 0);
    }
}
