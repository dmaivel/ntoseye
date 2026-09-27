//! Instruction-level execution: single steps, step over/out, run-to,
//! step-until walks, and call tracing.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use iced_x86::{
    Code, Decoder, DecoderOptions, FlowControl, Instruction, MemorySize, Mnemonic, OpKind, Register,
};

use crate::backend::MemoryOps;
use crate::breakpoints::BreakpointManager;
use crate::dbg_backend::{
    ContinueDisposition, DebugBackend, HwBreakpointAccess, STEP_UNDER_WINDOWS_HYPERVISOR,
    clear_trap_flag, processor_index_from_backend_thread_id,
};
use crate::disasm::{ControlFlow, classify};
use crate::error::{Error, Result};
use crate::gdb::RegisterMap;
use crate::session::{
    CallTrace, CallTraceEnd, CallTraceFrame, ContinueOutcome, ControlState, CurrentInstruction,
    STATUS_BREAKPOINT, STATUS_SINGLE_STEP, Session, StepKind, StepMode,
};
use crate::target::{DiagnosticValue, Target};
use crate::types::{Arch, Dtb, VirtAddr};
use crate::unwind::{
    build_stacktrace, format_symbol, halted_in_windows_hypervisor, preferred_code_dtb,
    resolve_thread_trace_context, thread_root,
};

impl Session {
    /// Single-step one instruction on the currently selected thread. If RIP sits
    /// on one of our breakpoints, do the disable/step/enable dance; otherwise
    /// plain step + trap-flag clear. Afterward re-arm enabled breakpoints (the
    /// stub can drop non-hit ones on a stop) and re-select the landed-on thread.
    /// The full "step one instruction", shared by the REPL (`si`) and the SDK.
    pub fn step(&mut self) -> Result<u64> {
        self.step_once().map(|(rip, _)| rip)
    }

    /// [`Self::step`], saying whether the vCPU was diverted: resumed alone,
    /// it reached no successor and was broken in on elsewhere, in an
    /// interrupt handler that waits on a held vCPU. Stepping on from there
    /// steps that handler's wait, which no held vCPU will ever end; loops
    /// that step stop instead.
    fn step_once(&mut self) -> Result<(u64, RunPast)> {
        self.require_steppable_vcpu()?;
        self.target.selected_frame = None;
        // Advancing the VM spends any stop `service_idle` parked, so drop it (the
        // other advance paths clear it via `resume`; a bare single-step doesn't).
        self.parked_stop = None;
        self.current_stop = None;
        self.backend.set_current_thread(&self.current_thread)?;
        let stepped = match step_over_current_breakpoint(
            self.backend.as_mut(),
            &self.register_map,
            &self.target,
            &mut self.breakpoints,
            &self.current_thread,
        )? {
            Some(stepped) => stepped,
            None if self.backend.single_step_unsafe() => step_without_trap(
                self.backend.as_mut(),
                &self.register_map,
                &self.target,
                &self.breakpoints,
                &self.current_thread,
            )?,
            None => {
                step_one_and_clear_tf(self.backend.as_mut(), &self.register_map)?;
                RunPast::Reached
            }
        };
        if stepped == RunPast::Diverted {
            self.notices.push(format!(
                "{} did not reach the next instruction within {RUN_PAST_TIMEOUT:?} of running \
                 alone: it took an interrupt first, and stopped in the handler (or in another \
                 thread it switched to); resume with g to let it finish",
                self.current_thread
            ));
        }
        for id in self.breakpoints.one_shot_hit_ids() {
            self.breakpoints
                .remove(self.backend.as_mut(), &self.target, id)?;
        }

        // Re-arm breakpoints the stub may have lost when the VM stopped, then
        // adopt whatever thread we ended up on. A step without the trap flag
        // ends on the vCPU it ran, whichever one the stub last reported.
        if let Err(error) = self
            .breakpoints
            .refresh_enabled(self.backend.as_mut(), &self.target)
        {
            self.notices.push(format!(
                "failed to re-arm breakpoints after the step: {error}"
            ));
        }
        if !self.backend.single_step_unsafe()
            && let Ok(tid) = self.backend.stopped_thread_id()
        {
            self.current_thread = tid;
        }
        self.refresh_context_for_current_thread();
        let rip = self.current_rip();
        self.current_stop = Some(ContinueOutcome::Step { rip });
        // Under VBS the vCPU steps alone; an interrupt taken first can leave
        // it in the Windows hypervisor, waiting on the vCPUs held meanwhile.
        // Nothing can be stepped from there.
        if self.vcpu_halted_in_hypervisor()? {
            return Err(Error::DebugInfo(format!(
                "{} entered the Windows hypervisor before finishing the step, and waits there \
                 on the other vCPUs; the context shows where NT left off. Resume with g",
                self.current_thread
            )));
        }
        Ok((rip, stepped))
    }

    /// Decode the instruction at the current thread's program counter, masking
    /// any software-breakpoint patch and reading through the thread's own root,
    /// which it fetches through. Selects the current thread first; the VM must
    /// be halted.
    pub fn current_instruction(&mut self) -> Result<CurrentInstruction> {
        self.require_steppable_vcpu()?;
        self.backend.set_current_thread(&self.current_thread)?;
        let regs = self.backend.read_registers()?;
        self.target.registers = Some(self.register_map.to_hashmap(&regs));
        let pc = self.register_map.read_u64("rip", &regs)?;
        let (code_dtb, active_dtb) = match self
            .register_map
            .read_u64(self.target.arch().dtb_register(), &regs)
        {
            Ok(cr3) => {
                let root = thread_root(&self.target, cr3);
                (root, root)
            }
            Err(_) => {
                let trace = resolve_thread_trace_context(&self.target, 0);
                (preferred_code_dtb(&trace, pc), trace.active_dtb)
            }
        };
        let memory = self.target.address_space(code_dtb);
        let mut bytes = [0u8; 16];
        memory.read_bytes(VirtAddr(pc), &mut bytes)?;
        self.breakpoints
            .mask_breakpoint_bytes(&self.target, VirtAddr(pc), &mut bytes, active_dtb);
        self.mask_bugcheck_trap(VirtAddr(pc), &mut bytes);

        if self.target.arch() == Arch::Arm64 {
            let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            let Ok(instruction) = bad64::decode(word, pc) else {
                return Err(Error::DebugInfo(format!(
                    "failed to decode instruction at {pc:#x}"
                )));
            };
            let mnem = instruction.op().mnem();
            // `bl`/`blr` are the call forms; AArch64 instructions are 4 bytes.
            return Ok(CurrentInstruction {
                is_call: mnem == "bl" || mnem == "blr",
                next_ip: pc.wrapping_add(4),
            });
        }

        let bitness = self.target.code_bitness(VirtAddr(pc));
        let mut decoder = Decoder::with_ip(bitness, &bytes, pc, DecoderOptions::NONE);
        let instruction = decoder.decode();
        if instruction.code() == Code::INVALID {
            return Err(Error::DebugInfo(format!(
                "failed to decode instruction at {pc:#x}"
            )));
        }
        let next_ip = if bitness == 32 {
            instruction.next_ip() & u64::from(u32::MAX)
        } else {
            instruction.next_ip()
        };
        Ok(CurrentInstruction {
            is_call: instruction.mnemonic() == Mnemonic::Call,
            next_ip,
        })
    }

    /// Compute the step-over plan for the current instruction: run to the
    /// instruction *after* a `call`, otherwise a plain single-step. The shared
    /// decision used by the REPL `p` and [`Self::step_over`].
    pub fn step_over_target(&mut self) -> Result<StepKind> {
        let instruction = self.current_instruction()?;
        if instruction.is_call {
            Ok(StepKind::RunTo(VirtAddr(instruction.next_ip)))
        } else {
            Ok(StepKind::Single)
        }
    }

    /// The current frame's caller return address (the step-out target). Walks a
    /// few frames of the current thread's stack and returns the second frame's
    /// IP. Shared by the REPL `gu` and [`Self::step_out`].
    pub fn step_out_target(&mut self) -> Result<VirtAddr> {
        self.require_steppable_vcpu()?;
        self.backend.set_current_thread(&self.current_thread)?;
        let regs = self.backend.read_registers()?;
        let trace = build_stacktrace(&self.target, &self.register_map, &regs, 4);
        let caller = trace
            .frames
            .get(1)
            .ok_or_else(|| Error::DebugInfo("could not find caller return address".to_string()))?;
        if caller.ip == 0 {
            return Err(Error::DebugInfo(
                "caller return address is null".to_string(),
            ));
        }
        Ok(VirtAddr(caller.ip))
    }

    /// The halted vCPU's [`ControlState`]: IP, SP, page-table root, and the
    /// control flow of the instruction at the IP (read breakpoint-masked).
    pub fn control_state(&mut self) -> Result<ControlState> {
        let registers = self.read_registers()?;
        let ip = self
            .register_map
            .read_u64("rip", &registers)
            .or_else(|_| self.register_map.read_u64("pc", &registers))?;
        let sp = self
            .register_map
            .read_u64("rsp", &registers)
            .or_else(|_| self.register_map.read_u64("sp", &registers))?;
        let dtb = self
            .register_map
            .read_u64(self.target.arch().dtb_register(), &registers)
            .unwrap_or(0);
        let mut bytes = [0u8; 16];
        let length = if self.target.arch() == Arch::Arm64 {
            4
        } else {
            bytes.len()
        };
        self.read_masked(VirtAddr(ip), &mut bytes[..length])?;
        let bitness = self.target.code_bitness(VirtAddr(ip));
        Ok(ControlState {
            ip,
            sp,
            dtb,
            flow: classify(&bytes[..length], self.target.arch(), bitness),
        })
    }

    /// The enabled code breakpoint (in the current context) that a step from
    /// `previous_ip` landed on: one at `ip`, or one just before it when the
    /// trap reported the IP past the breakpoint byte. A step that started on
    /// a breakpoint does not count the one it left.
    pub fn code_breakpoint_after_step(&self, previous_ip: u64, ip: u64) -> Option<u32> {
        let at = |address: u64| {
            self.breakpoints
                .enabled_breakpoint_id_for_current_context(&self.target, VirtAddr(address))
        };
        if let Some(id) = at(ip) {
            return Some(id);
        }
        let step = u64::from(self.target.arch().breakpoint_size());
        if at(previous_ip).is_some() || ip < step {
            return None;
        }
        at(ip - step)
    }

    /// Step until `stop` accepts the instruction about to execute, into or
    /// over calls per `mode`: the SDK's `step(until=)` and `run_to(step=)`.
    /// Returns the `Step` there; a breakpoint, exception, or other stop met on
    /// the way is returned as is. An interrupt request ([`Target::interrupt`]),
    /// an elapsed `timeout`, or a step diverted into an interrupt handler
    /// (see [`Self::step_once`]) ends the walk where it is, as a `Step`;
    /// `limit` instructions without a match is an error.
    pub fn step_until(
        &mut self,
        mode: StepMode,
        limit: usize,
        timeout: Option<Duration>,
        stop: impl Fn(u64, ControlFlow) -> bool,
    ) -> Result<ContinueOutcome> {
        self.require_steppable_vcpu()?;
        self.clear_selected_frame();
        let deadline = timeout.map(|timeout| Instant::now() + timeout);
        let cancel = Arc::clone(&self.target.interrupt);
        for _ in 0..limit {
            if cancel.swap(false, Ordering::SeqCst) {
                let outcome = ContinueOutcome::Step {
                    rip: self.current_rip(),
                };
                self.note_stop(&outcome);
                return Ok(outcome);
            }
            let state = self.control_state()?;
            if stop(state.ip, state.flow)
                || deadline.is_some_and(|deadline| Instant::now() >= deadline)
            {
                let outcome = ContinueOutcome::Step { rip: state.ip };
                self.note_stop(&outcome);
                return Ok(outcome);
            }
            let step = match self.step_over_target()? {
                StepKind::RunTo(next) if mode == StepMode::Over => {
                    let remaining =
                        deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()));
                    self.run_to(next, remaining, &cancel)?
                }
                _ => {
                    let (rip, stepped) = self.step_once()?;
                    if stepped == RunPast::Diverted {
                        let outcome = ContinueOutcome::Step { rip };
                        self.note_stop(&outcome);
                        return Ok(outcome);
                    }
                    ContinueOutcome::Step { rip }
                }
            };
            let rip = match step {
                ContinueOutcome::Step { rip } => rip,
                // `run_to` was cancelled or timed out and halted the target.
                ContinueOutcome::Running => {
                    let outcome = ContinueOutcome::Step {
                        rip: self.current_rip(),
                    };
                    self.note_stop(&outcome);
                    return Ok(outcome);
                }
                other => return Ok(other),
            };
            if let Some(outcome) = self
                .code_breakpoint_after_step(state.ip, rip)
                .and_then(|id| self.breakpoint_outcome(id, rip))
            {
                self.note_stop(&outcome);
                return Ok(outcome);
            }
        }
        Err(Error::StepLimit(limit))
    }

    fn breakpoint_outcome(&self, id: u32, rip: u64) -> Option<ContinueOutcome> {
        let breakpoint = self.breakpoints.get(id)?;
        Some(ContinueOutcome::breakpoint_hit(breakpoint, rip, None))
    }

    /// Single-step the current function and collect its call tree (`wt`), up
    /// to `limit` instructions. A frame closes on a `ret` that moves the stack
    /// pointer above the one it was entered with, so a `ret` that does not
    /// the frame (a retpoline) is not taken for a return. An interrupt
    /// request ([`Target::interrupt`]), a breakpoint, a step diverted into an
    /// interrupt handler, or a failed step ends the trace early;
    /// [`CallTrace::end`] says which.
    pub fn trace_calls(&mut self, limit: usize) -> Result<CallTrace> {
        if limit == 0 {
            return Err(Error::InvalidArgument(
                "the instruction limit must be greater than zero".into(),
            ));
        }
        self.require_steppable_vcpu()?;
        let name = |target: &Target, state: &ControlState| {
            let trace = resolve_thread_trace_context(target, state.dtb);
            format_symbol(target, &trace, state.ip)
        };
        let frame = |name| CallTraceFrame {
            name,
            instructions: 0,
            children: Vec::new(),
        };
        let mut current = self.control_state()?;
        // Each open frame with the stack pointer it was entered with.
        let mut stack = vec![(frame(name(&self.target, &current)), current.sp)];
        let mut instructions = 0usize;
        let arm64 = self.target.arch() == Arch::Arm64;
        let end = loop {
            if instructions >= limit {
                break CallTraceEnd::Limit;
            }
            if self.target.interrupt.swap(false, Ordering::SeqCst) {
                break CallTraceEnd::Interrupted;
            }
            match self.step_once() {
                Ok((_, RunPast::Reached)) => {}
                Ok((_, RunPast::Diverted)) => break CallTraceEnd::Diverted,
                Err(error) => break CallTraceEnd::Failed(error.to_string()),
            }
            instructions += 1;
            let next = match self.control_state() {
                Ok(state) => state,
                Err(error) => break CallTraceEnd::Failed(error.to_string()),
            };
            if self
                .code_breakpoint_after_step(current.ip, next.ip)
                .is_some()
            {
                break CallTraceEnd::Breakpoint;
            }
            let (open, entry_sp) = stack.last_mut().expect("the traced function's frame");
            open.instructions += 1;
            if current.flow == ControlFlow::Call {
                stack.push((frame(name(&self.target, &next)), next.sp));
            } else if current.flow == ControlFlow::Ret
                && (next.sp > *entry_sp || (arm64 && next.sp >= *entry_sp))
            {
                let (completed, _) = stack.pop().expect("an open frame");
                match stack.last_mut() {
                    Some((parent, _)) => parent.children.push(completed),
                    None => {
                        stack.push((completed, 0));
                        break CallTraceEnd::Returned;
                    }
                }
            }
            current = next;
        };

        let (mut root, _) = stack.remove(0);
        // Fold frames still open when the trace ended into their callers.
        let mut open: Vec<CallTraceFrame> = stack.into_iter().map(|(frame, _)| frame).collect();
        while let Some(completed) = open.pop() {
            open.last_mut()
                .unwrap_or(&mut root)
                .children
                .push(completed);
        }
        Ok(CallTrace {
            root,
            instructions,
            end,
        })
    }

    /// Run until `address` is reached. If a breakpoint is already set there in
    /// the current context this is a plain [`Self::continue_until_break`];
    /// otherwise it installs a temporary breakpoint, runs to it, removes it, and
    /// reports reaching it as [`ContinueOutcome::Step`]. A *different* breakpoint,
    /// bugcheck, or exception en route is surfaced as-is. Blocks until a stop,
    /// `timeout`, or `cancel` (checked between polls); the last two halt the
    /// target where it is, remove the temp breakpoint, and return
    /// [`ContinueOutcome::Running`]. The run-to-address primitive behind
    /// [`Self::step_over`] / [`Self::step_out`].
    pub fn run_to(
        &mut self,
        address: VirtAddr,
        timeout: Option<Duration>,
        cancel: &AtomicBool,
    ) -> Result<ContinueOutcome> {
        // Already breakpointed here → just continue; the existing bp will report.
        let temp_id = if self
            .breakpoints
            .enabled_breakpoint_id_for_current_context(&self.target, address)
            .is_some()
        {
            None
        } else {
            Some(self.breakpoints.add_temporary_code(
                self.backend.as_mut(),
                &self.target,
                address,
            )?)
        };
        let outcome = self.continue_until_break(timeout, cancel, ContinueDisposition::Handled);

        // A cancel or timeout leaves the VM running; halt it where it is (the
        // temp breakpoint's removal writes guest memory anyway). A target
        // reload already cleared the manager, so the remove may be a no-op;
        // ignore its error.
        if self.backend.is_running() {
            let _ = self.interrupt();
        }
        if let Some(temp_id) = temp_id {
            let _ = self
                .breakpoints
                .remove(self.backend.as_mut(), &self.target, temp_id);
        }

        let outcome = match outcome? {
            ContinueOutcome::Breakpoint { id, rip, .. } if Some(id) == temp_id => {
                ContinueOutcome::Step { rip }
            }
            other => other,
        };
        self.note_stop(&outcome);
        Ok(outcome)
    }

    /// Step over the current instruction: single-step it, or, if it's a `call`,
    /// run to the instruction after it ([`ContinueOutcome::Step`] on completion).
    /// Shared by the REPL `p` (target only) and the SDKs.
    pub fn step_over(&mut self, cancel: &AtomicBool) -> Result<ContinueOutcome> {
        match self.step_over_target()? {
            StepKind::Single => Ok(ContinueOutcome::Step { rip: self.step()? }),
            StepKind::RunTo(addr) => self.run_to(addr, None, cancel),
        }
    }

    /// Step out of the current function: run to the caller's return address.
    pub fn step_out(&mut self, cancel: &AtomicBool) -> Result<ContinueOutcome> {
        let target = self.step_out_target()?;
        self.run_to(target, None, cancel)
    }
}

/// Single-step the current thread and clear `TF` afterward (KVM leaves it set).
/// A fault or bugcheck instead of the step trap is returned as an error.
pub fn step_one_and_clear_tf(
    backend: &mut dyn DebugBackend,
    register_map: &RegisterMap,
) -> Result<()> {
    backend.step()?;
    let event = backend.wait_for_stop()?;
    clear_trap_flag(backend, register_map)?;
    if event.is_bugcheck {
        return Err(Error::DebugInfo(
            "target bugchecked while single-stepping".into(),
        ));
    }
    if let Some(code) = event
        .exception_code
        .filter(|&code| code != STATUS_SINGLE_STEP && code != STATUS_BREAKPOINT)
    {
        return Err(Error::DebugInfo(format!(
            "target raised exception {code:#x} while single-stepping"
        )));
    }
    Ok(())
}

/// If RIP sits on one of our enabled breakpoints, disable it, step the
/// underlying instruction, then re-enable; returns how, or `None` when there
/// was no breakpoint to step over. A stale breakpoint (its address space gone) is silently
/// discarded. A target that owns its sites (KD) has already dropped the one
/// at the PC while reporting the stop, so the disable is a no-op there and
/// the re-enable is what writes it back. Callers must have selected
/// `thread`, the backend thread to step, first. Shared by the REPL and
/// [`Session::step`].
pub fn step_over_current_breakpoint(
    backend: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    debugger: &Target,
    breakpoints: &mut BreakpointManager,
    thread: &str,
) -> Result<Option<RunPast>> {
    let regs = backend.read_registers()?;
    let rip = register_map.read_u64("rip", &regs)?;
    // Only the shared-page fallback below needs the address space; a stub
    // without its DTB register still gets the plain step-over.
    let cr3 = register_map
        .read_u64(debugger.arch().dtb_register(), &regs)
        .ok();

    // Scope-agnostic: a wrong-process hit on a shared-page BP still needs the
    // disable/step/enable dance so the wrong process can make forward progress.
    let Some(bp_id) = breakpoints.breakpoint_id_at_address(rip) else {
        return Ok(None);
    };

    match (breakpoints.lift(backend, debugger, bp_id), cr3) {
        (Ok(()), _) => {}
        (Err(Error::BadVirtualAddress(_) | Error::AddressNotInDump(_)), Some(cr3)) => {
            breakpoints
                .disable_guest_memory_patch_in_address_space(backend, debugger, bp_id, cr3)?;
        }
        (Err(err), _) => return Err(err),
    }

    let stepped = if backend.single_step_unsafe() {
        run_past_site(backend, register_map, debugger, thread, &regs, rip, cr3)
    } else {
        step_one_and_clear_tf(backend, register_map).map(|()| RunPast::Reached)
    };

    // Re-arm whether or not the step worked: a failed step must not leave the
    // site unpatched with the manager still believing it is enabled.
    match breakpoints.enable(backend, debugger, bp_id) {
        Ok(()) => {}
        Err(Error::BadVirtualAddress(_) | Error::AddressNotInDump(_)) => {
            // Address space no longer exists; drop the breakpoint and move on.
            breakpoints.discard(backend, bp_id)?;
            return stepped.map(Some);
        }
        Err(err) => return stepped.and(Err(err)),
    }
    // Interrupted on the site itself, the execution returns to it and hits
    // the re-armed breakpoint again; that hit is this one, not a new one.
    if matches!(stepped, Ok(RunPast::Diverted))
        && let Some(rsp) = interrupted_on(debugger, register_map, &regs, rip, cr3)
    {
        breakpoints.note_interrupted_hit(bp_id, rsp);
    }
    stepped.map(Some)
}

/// The stack pointer of the execution at `regs` when an interrupt it took on
/// the instruction at `rip`, before executing it, is still pending return:
/// the processor pushed a return frame (RIP, CS, RFLAGS, RSP, SS, behind an
/// error code for some exceptions) below the 16-byte-aligned stack pointer,
/// and NT builds its trap frame below that. `None` without such a frame:
/// the interrupt was taken past the instruction, came from user mode, or
/// switched to an interrupt stack.
fn interrupted_on(
    debugger: &Target,
    register_map: &RegisterMap,
    regs: &[u8],
    rip: u64,
    cr3: Option<u64>,
) -> Option<u64> {
    let rsp = register_map.read_u64("rsp", regs).ok()?;
    let memory = debugger.address_space(code_root(debugger, cr3, rip));
    let mut frame = [0u8; 48];
    let base = (rsp & !0xf).wrapping_sub(frame.len() as u64);
    memory.read_bytes(VirtAddr(base), &mut frame).ok()?;
    let word = |index: usize| {
        u64::from_le_bytes(frame[index * 8..index * 8 + 8].try_into().expect("8 bytes"))
    };
    // Without an error code the frame is the top five words, with one the
    // bottom five.
    [1, 0]
        .into_iter()
        .any(|first| word(first) == rip && word(first + 1) & 3 == 0 && word(first + 3) == rsp)
        .then_some(rsp)
}

/// Where a vCPU on root `cr3` (or, without one, the module of `rip`) reads
/// its code and stack.
fn code_root(debugger: &Target, cr3: Option<u64>, rip: u64) -> Dtb {
    match cr3 {
        Some(cr3) => thread_root(debugger, cr3),
        None => preferred_code_dtb(&resolve_thread_trace_context(debugger, 0), rip),
    }
}

/// Where a vCPU executing one instruction ended up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunPast {
    /// Past the instruction, or at a stop the target reported.
    Reached,
    /// Resumed alone past the instruction, it reached none of its successors
    /// within [`RUN_PAST_TIMEOUT`] and was broken in on elsewhere: it took
    /// an interrupt first, and the handler waits on a held vCPU (or, once the
    /// held vCPUs were let run, the thread was switched out).
    Diverted,
}

/// How long a vCPU resumed alone gets to execute one instruction before the
/// others are broken in on. Measured under VBS
/// over 7761 run-pasts on hot kernel functions: every one that finished did
/// so within 24 ms, and the rest (3-4%, waiting on a held vCPU) never
/// finished alone.
const RUN_PAST_TIMEOUT: Duration = Duration::from_millis(100);

/// How long every vCPU runs when the one executing an instruction waits on
/// the others, so they can answer it.
const RELEASE_WINDOW: Duration = Duration::from_millis(20);

/// How long the held vCPUs are let run, in all, for one instruction before
/// it is given up on. A run ends early when another vCPU reaches a marked
/// site, which in hot code is at once, so the runs are bounded by time
/// rather than counted.
const RELEASE_BUDGET: Duration = Duration::from_secs(1);

/// Execute the instruction under the (already lifted) breakpoint site at
/// `rip` without a single step, which is unsafe on this backend (see
/// [`STEP_UNDER_WINDOWS_HYPERVISOR`]): plant temporary breakpoints on every
/// address it can continue at, resume this vCPU alone, and take the stop.
/// Other vCPUs stay held, so none can run through the lifted site.
fn run_past_site(
    backend: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    debugger: &Target,
    thread: &str,
    regs: &[u8],
    rip: u64,
    cr3: Option<u64>,
) -> Result<RunPast> {
    let successors = site_successors(debugger, register_map, thread, regs, rip, cr3)?;
    run_past(
        backend,
        register_map,
        debugger,
        thread,
        regs,
        &successors,
        &TemporarySites::Software,
    )
}

/// A single step where the trap flag is unsafe: run the vCPU alone past the
/// instruction at its PC, as for a breakpoint site. Secure-kernel code gets
/// debug-register sites in slots no breakpoint holds, so no VTL1 code is
/// written; elsewhere the sites are software, like run-past's.
fn step_without_trap(
    backend: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    debugger: &Target,
    breakpoints: &BreakpointManager,
    thread: &str,
) -> Result<RunPast> {
    let regs = backend.read_registers()?;
    let rip = register_map.read_u64("rip", &regs)?;
    let cr3 = register_map
        .read_u64(debugger.arch().dtb_register(), &regs)
        .ok();
    let successors = site_successors(debugger, register_map, thread, &regs, rip, cr3)?;
    let secure = debugger.is_secure_address(VirtAddr(rip))
        || cr3.is_some_and(|cr3| debugger.recognize_secure_root(cr3))
        || successors
            .iter()
            .any(|&address| debugger.is_secure_address(VirtAddr(address)));
    let sites = if secure {
        let slots = breakpoints.free_execute_slots(backend);
        if slots.len() < successors.len() {
            return Err(Error::Breakpoint(format!(
                "a VTL1 step at {rip:#x} needs {} free hardware breakpoint slot(s) and {} are \
                 free; clear a hardware breakpoint to step",
                successors.len(),
                slots.len()
            )));
        }
        TemporarySites::Hardware(slots)
    } else {
        TemporarySites::Software
    };
    run_past(
        backend,
        register_map,
        debugger,
        thread,
        &regs,
        &successors,
        &sites,
    )
}

/// How [`run_past`] marks an instruction's successors.
enum TemporarySites {
    /// `int3` sites, the target planting and lifting them.
    Software,
    /// Debug-register sites in these free slots, one per successor; one
    /// more, when free, marks the instruction itself while the held vCPUs
    /// run.
    Hardware(Vec<u8>),
}

impl TemporarySites {
    /// Plant the `index`th site at `address`: `Ok(None)` for a software
    /// site, the slot for a hardware one, `Err` when no slot is left.
    fn plant(
        &self,
        backend: &mut dyn DebugBackend,
        index: usize,
        address: u64,
    ) -> Result<Option<u8>> {
        match self {
            Self::Software => {
                backend.set_breakpoint(address)?;
                Ok(None)
            }
            Self::Hardware(slots) => {
                let slot = *slots.get(index).ok_or_else(|| {
                    Error::Breakpoint(format!(
                        "no free hardware breakpoint slot is left to mark {address:#x}"
                    ))
                })?;
                backend.set_hardware_breakpoint(slot, address, HwBreakpointAccess::Execute, 1)?;
                Ok(Some(slot))
            }
        }
    }
}

/// Lift a site [`TemporarySites::plant`] planted.
fn lift_site(backend: &mut dyn DebugBackend, address: u64, slot: Option<u8>) -> Result<()> {
    match slot {
        Some(slot) => backend.clear_hardware_breakpoint(slot),
        None => backend.remove_breakpoint(address),
    }
}

/// Plant `sites` on every successor, run the vCPU alone past the instruction
/// at its PC in `regs`, and lift them again whatever happened.
fn run_past(
    backend: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    debugger: &Target,
    thread: &str,
    regs: &[u8],
    successors: &[u64],
    sites: &TemporarySites,
) -> Result<RunPast> {
    let mut planted = Vec::with_capacity(successors.len());
    let result = run_to_successors(
        backend,
        register_map,
        debugger,
        thread,
        regs,
        successors,
        sites,
        &mut planted,
    );
    for (address, slot) in planted {
        let removed = lift_site(backend, address, slot);
        if result.is_ok() {
            removed?;
        }
    }
    result
}

fn run_to_successors(
    backend: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    debugger: &Target,
    thread: &str,
    regs: &[u8],
    successors: &[u64],
    sites: &TemporarySites,
    planted: &mut Vec<(u64, Option<u8>)>,
) -> Result<RunPast> {
    let rip = register_map.read_u64("rip", regs)?;
    for (index, &address) in successors.iter().enumerate() {
        let slot = sites.plant(backend, index, address)?;
        planted.push((address, slot));
    }
    let mut release = Release {
        rip,
        rsp: register_map.read_u64("rsp", regs).ok(),
        nt_thread: None,
        started: None,
    };
    loop {
        backend.continue_current_thread()?;
        let (event, timed_out) = match backend.try_wait_for_stop(RUN_PAST_TIMEOUT)? {
            Some(event) => (event, false),
            None => (backend.interrupt()?, true),
        };
        if event.is_bugcheck {
            return Err(Error::DebugInfo(format!(
                "target bugchecked while running past the instruction at {rip:#x}"
            )));
        }
        let now_regs = backend.read_registers()?;
        let now = register_map.read_u64("rip", &now_regs)?;
        if !timed_out || successors.contains(&now) {
            if now == rip {
                return Err(Error::DebugInfo(format!(
                    "{thread} could not execute the instruction at {rip:#x}: resumed alone, it \
                     stopped on it again; resume with g, disabling any breakpoint there first"
                )));
            }
            return Ok(RunPast::Reached);
        }
        // Short of the successors, it waits on a vCPU this holds: in the
        // Windows hypervisor, on the instruction, or in the handler of an
        // interrupt taken first. Let them all run so it can finish.
        let mut in_nt = now != rip && !in_windows_hypervisor(debugger, register_map, &now_regs);
        loop {
            if release.exhausted() {
                if in_nt {
                    return Ok(RunPast::Diverted);
                }
                return Err(Error::DebugInfo(format!(
                    "{thread} could not execute the instruction at {rip:#x}: resumed alone, it \
                     did not get past it within {RUN_PAST_TIMEOUT:?}, and letting every vCPU \
                     run for {RELEASE_BUDGET:?} did not free it (it waits on another vCPU, or in \
                     the Windows hypervisor); resume with g, disabling any breakpoint there first"
                )));
            }
            match release.run(backend, register_map, debugger, thread, successors, sites)? {
                Released::Reached => return Ok(RunPast::Reached),
                Released::Diverted => return Ok(RunPast::Diverted),
                Released::Back => break,
                Released::Waiting { in_handler } => in_nt = in_handler,
            }
        }
    }
}

/// Whether a vCPU with registers `regs` is executing the Windows hypervisor.
fn in_windows_hypervisor(debugger: &Target, register_map: &RegisterMap, regs: &[u8]) -> bool {
    let value = |name| register_map.read_u64(name, regs).ok();
    match (value(debugger.arch().dtb_register()), value("rip")) {
        (Some(cr3), Some(rip)) => halted_in_windows_hypervisor(debugger, cr3, rip),
        _ => false,
    }
}

/// Where a vCPU that waited on the held ones stood after they ran.
enum Released {
    /// At a successor, on the same Windows thread.
    Reached,
    /// Back on the instruction, not executed: run it alone again.
    Back,
    /// Still short of the successors on the same thread, in an interrupt
    /// handler (`in_handler`) or the Windows hypervisor: let them run again.
    Waiting { in_handler: bool },
    /// Running another Windows thread: the step's was switched out, and
    /// the step ends where the vCPU is.
    Diverted,
}

/// Letting every vCPU run while one executing an instruction at `rip` waits
/// on them. The instruction stays marked, so the vCPU stops on it if it
/// returns there without executing it; the successors stay marked, so it
/// stops past it. Another vCPU can stop on one of those too, ending that
/// run early; it is simply resumed with the next one, and executes the
/// instruction once the step is over and they are lifted. Holding it
/// instead can hold the very vCPU the hypervisor waits for.
struct Release {
    rip: u64,
    rsp: Option<u64>,
    /// The Windows thread on the vCPU when it first waited.
    nt_thread: Option<Option<u64>>,
    /// When the first run began.
    started: Option<Instant>,
}

impl Release {
    fn exhausted(&self) -> bool {
        self.started
            .is_some_and(|started| started.elapsed() >= RELEASE_BUDGET)
    }

    fn run(
        &mut self,
        backend: &mut dyn DebugBackend,
        register_map: &RegisterMap,
        debugger: &Target,
        thread: &str,
        successors: &[u64],
        sites: &TemporarySites,
    ) -> Result<Released> {
        self.started.get_or_insert_with(Instant::now);
        let nt_thread = *self
            .nt_thread
            .get_or_insert_with(|| nt_thread_on(debugger, thread));
        let site = if successors.contains(&self.rip) {
            None
        } else {
            Some(sites.plant(backend, successors.len(), self.rip)?)
        };
        // Whichever vCPU stops first ends the run, or a break-in does.
        let stop = backend.continue_execution().and_then(|()| {
            if backend.try_wait_for_stop(RELEASE_WINDOW)?.is_none() {
                backend.interrupt()?;
            }
            Ok(())
        });
        if let Some(slot) = site {
            let lifted = lift_site(backend, self.rip, slot);
            if stop.is_ok() {
                lifted?;
            }
        }
        stop?;
        backend.set_current_thread(thread)?;
        let regs = backend.read_registers()?;
        let now = register_map.read_u64("rip", &regs)?;
        if in_windows_hypervisor(debugger, register_map, &regs) {
            return Ok(Released::Waiting { in_handler: false });
        }
        if nt_thread_on(debugger, thread) != nt_thread {
            return Ok(Released::Diverted);
        }
        if successors.contains(&now) {
            return Ok(Released::Reached);
        }
        if now == self.rip {
            // The same thread back on the instruction at another stack
            // depth entered it anew, from the handler it was interrupted by.
            return Ok(if register_map.read_u64("rsp", &regs).ok() == self.rsp {
                Released::Back
            } else {
                Released::Diverted
            });
        }
        Ok(Released::Waiting { in_handler: true })
    }
}

/// The `_ETHREAD` NT runs on the processor backend `thread` stands for.
fn nt_thread_on(debugger: &Target, thread: &str) -> Option<u64> {
    let processor = processor_index_from_backend_thread_id(thread)?;
    debugger
        .current_windows_thread_for_processor(processor)
        .ok()
        .map(|thread| thread.ethread.0)
}

/// Every address execution can continue at after the instruction at `rip`,
/// decoded from the guest (the site is already lifted) and resolved against
/// the stopped vCPU's registers and memory. `thread` is the backend thread
/// of that vCPU, whose processor's IDT an interrupt goes through.
pub fn site_successors(
    debugger: &Target,
    register_map: &RegisterMap,
    thread: &str,
    regs: &[u8],
    rip: u64,
    cr3: Option<u64>,
) -> Result<Vec<u64>> {
    // The vCPU fetches the instruction and follows its pointers through its
    // own root. Without one, a module's own root serves its code.
    let memory = debugger.address_space(code_root(debugger, cr3, rip));
    let mut bytes = [0u8; 16];
    memory.read_bytes(VirtAddr(rip), &mut bytes)?;
    let bitness = debugger.code_bitness(VirtAddr(rip));
    let instruction = Decoder::with_ip(bitness, &bytes, rip, DecoderOptions::NONE).decode();
    if instruction.is_invalid() {
        return Err(Error::DebugInfo(format!(
            "failed to decode instruction at {rip:#x}"
        )));
    }
    let pointer = |address: u64, width: usize| -> Result<u64> {
        let mut value = [0u8; 8];
        memory.read_bytes(VirtAddr(address), &mut value[..width])?;
        Ok(u64::from_le_bytes(value))
    };
    let register = |register: Register| -> Result<u64> {
        let name = format!("{:?}", register.full_register()).to_ascii_lowercase();
        let value = register_map.read_u64(&name, regs)?;
        Ok(if bitness == 32 {
            value & 0xffff_ffff
        } else {
            value
        })
    };
    let unsupported = || {
        Error::DebugInfo(format!(
            "cannot execute the instruction at {rip:#x} without single-stepping: `{}` has no \
             successor known from here; {STEP_UNDER_WINDOWS_HYPERVISOR}",
            format!("{:?}", instruction.mnemonic()).to_ascii_lowercase()
        ))
    };
    let handler = |vector: u8, checks_privilege: bool| {
        interrupt_handler(
            debugger,
            register_map,
            regs,
            thread,
            vector,
            checks_privilege,
        )
    };
    let top_of_stack = |width: usize| pointer(register(Register::RSP)?, width);
    let mut successors = match instruction.code() {
        Code::Syscall => vec![system_call_entry(debugger, bitness)?],
        // `sysret` returns to RCX, `sysexit` to RDX; the 32-bit forms to
        // their low halves.
        Code::Sysretq => vec![register_map.read_u64("rcx", regs)?],
        Code::Sysretd => vec![register_map.read_u64("rcx", regs)? & 0xffff_ffff],
        Code::Sysexitq => vec![register_map.read_u64("rdx", regs)?],
        Code::Sysexitd => vec![register_map.read_u64("rdx", regs)? & 0xffff_ffff],
        // A hypercall returns to the next instruction.
        Code::Vmcall | Code::Vmmcall => vec![instruction.next_ip()],
        Code::Iretw | Code::Retfw | Code::Retfw_imm16 => vec![top_of_stack(2)?],
        Code::Iretd | Code::Retfd | Code::Retfd_imm16 => vec![top_of_stack(4)?],
        Code::Iretq | Code::Retfq | Code::Retfq_imm16 => vec![top_of_stack(8)?],
        Code::Int_imm8 => vec![handler(instruction.immediate8(), true)?],
        Code::Int3 => vec![handler(3, true)?],
        Code::Int1 => vec![handler(1, false)?],
        Code::Into => {
            let overflow = register_map.read_u64("eflags", regs)? & (1 << 11) != 0;
            vec![if overflow {
                handler(4, true)?
            } else {
                instruction.next_ip()
            }]
        }
        Code::Jmp_ptr1616 | Code::Call_ptr1616 => vec![u64::from(instruction.far_branch16())],
        Code::Jmp_ptr1632 | Code::Call_ptr1632 => vec![u64::from(instruction.far_branch32())],
        _ => match instruction.flow_control() {
            FlowControl::Next => vec![instruction.next_ip()],
            FlowControl::ConditionalBranch => {
                vec![instruction.next_ip(), instruction.near_branch_target()]
            }
            FlowControl::UnconditionalBranch | FlowControl::Call
                if instruction.is_jmp_short_or_near() || instruction.is_call_near() =>
            {
                vec![instruction.near_branch_target()]
            }
            FlowControl::IndirectBranch | FlowControl::IndirectCall => {
                vec![
                    indirect_target(&instruction, &register, &pointer)
                        .ok_or_else(unsupported)??,
                ]
            }
            FlowControl::Return if instruction.mnemonic() == Mnemonic::Ret => {
                vec![top_of_stack(if bitness == 64 { 8 } else { 4 })?]
            }
            // `ud0`/`ud1`/`ud2` raise the invalid-opcode fault.
            FlowControl::Exception
                if matches!(
                    instruction.mnemonic(),
                    Mnemonic::Ud0 | Mnemonic::Ud1 | Mnemonic::Ud2
                ) =>
            {
                vec![handler(6, false)?]
            }
            _ => return Err(unsupported()),
        },
    };
    successors.dedup();
    Ok(successors)
}

/// Where `syscall` enters the kernel: the `LSTAR` (64-bit) or `CSTAR`
/// (compatibility mode) entry NT programs, which is the KVA-shadow copy
/// while that mitigation runs. The GDB stub reads no MSR, so it is taken
/// from the kernel's own choice.
fn system_call_entry(debugger: &Target, bitness: u32) -> Result<u64> {
    let nt = &debugger
        .guest
        .as_ref()
        .ok_or_else(|| Error::DebugInfo("no kernel to find the system call entry in".into()))?
        .ntoskrnl;
    let shadow = nt
        .symbol("KiKvaShadow")
        .and_then(|flag| flag.read::<u8>())
        .is_ok_and(|flag| flag != 0);
    let entry = match (bitness, shadow) {
        (64, true) => "KiSystemCall64Shadow",
        (64, false) => "KiSystemCall64",
        (_, true) => "KiSystemCall32Shadow",
        (_, false) => "KiSystemCall32",
    };
    Ok(nt.symbol(entry)?.address().0)
}

/// Where an `int`-class instruction on the vCPU with registers `regs`
/// continues: vector `vector`'s handler in its processor's IDT, or, when
/// the gate is absent, the not-present fault's (11), and when
/// `checks_privilege` and the gate's DPL is below the current privilege
/// level, the general-protection fault's (13).
fn interrupt_handler(
    debugger: &Target,
    register_map: &RegisterMap,
    regs: &[u8],
    thread: &str,
    vector: u8,
    checks_privilege: bool,
) -> Result<u64> {
    let processor = processor_index_from_backend_thread_id(thread).ok_or_else(|| {
        Error::DebugInfo(format!("{thread} names no processor whose IDT to read"))
    })?;
    let gate = |vector: u8| -> Result<(u64, u8, bool)> {
        let detail = debugger.inspect_idt(processor, Some(u16::from(vector)))?;
        let entry = detail.entries.into_iter().next().ok_or_else(|| {
            Error::DebugInfo(format!(
                "processor {processor}'s IDT has no vector {vector:#x}"
            ))
        })?;
        let available = |field: &str| {
            Error::DebugInfo(format!("IDT vector {vector:#x}'s {field} is unreadable"))
        };
        match (entry.handler, entry.dpl, entry.present) {
            (
                DiagnosticValue::Available(handler),
                DiagnosticValue::Available(dpl),
                DiagnosticValue::Available(present),
            ) => Ok((handler.0, dpl, present)),
            (DiagnosticValue::Unavailable(error), _, _) => Err(Error::DebugInfo(format!(
                "{}: {error}",
                available("handler")
            ))),
            _ => Err(available("gate")),
        }
    };
    let (handler, dpl, present) = gate(vector)?;
    let privilege = register_map.read_u64("cs", regs)? as u8 & 3;
    if checks_privilege && privilege > dpl {
        return gate(13).map(|(handler, ..)| handler);
    }
    if !present {
        return gate(11).map(|(handler, ..)| handler);
    }
    Ok(handler)
}

/// Where an indirect `jmp`/`call` goes: a register, or a pointer in memory
/// (the offset of a far one) without a segment override, read `width`
/// bytes wide by `pointer`. `None` for forms this does not evaluate.
fn indirect_target(
    instruction: &Instruction,
    register: &impl Fn(Register) -> Result<u64>,
    pointer: &impl Fn(u64, usize) -> Result<u64>,
) -> Option<Result<u64>> {
    match instruction.op0_kind() {
        OpKind::Register => Some(register(instruction.op0_register())),
        OpKind::Memory if !matches!(instruction.segment_prefix(), Register::FS | Register::GS) => {
            let width = match instruction.memory_size() {
                // A far pointer is its offset, then a 2-byte selector.
                MemorySize::SegPtr16 => 2,
                MemorySize::SegPtr32 => 4,
                MemorySize::SegPtr64 => 8,
                size => size.size().min(8),
            };
            let address = (|| {
                let base = match instruction.memory_base() {
                    Register::None => 0,
                    // The decoder already folded RIP into the displacement.
                    Register::RIP | Register::EIP => 0,
                    base => register(base)?,
                };
                let index = match instruction.memory_index() {
                    Register::None => 0,
                    index => {
                        register(index)?.wrapping_mul(u64::from(instruction.memory_index_scale()))
                    }
                };
                pointer(
                    base.wrapping_add(index)
                        .wrapping_add(instruction.memory_displacement64()),
                    width,
                )
            })();
            Some(address)
        }
        _ => None,
    }
}
