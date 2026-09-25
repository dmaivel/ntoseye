//! Instruction-level execution: single steps, step over/out, run-to,
//! step-until walks, and call tracing.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use iced_x86::{
    Code, Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register,
};

use crate::backend::MemoryOps;
use crate::breakpoints::BreakpointManager;
use crate::dbg_backend::{
    ContinueDisposition, DebugBackend, STEP_UNDER_WINDOWS_HYPERVISOR, clear_trap_flag,
};
use crate::disasm::{ControlFlow, classify};
use crate::error::{Error, Result};
use crate::gdb::RegisterMap;
use crate::session::{
    CallTrace, CallTraceEnd, CallTraceFrame, ContinueOutcome, ControlState, CurrentInstruction,
    STATUS_BREAKPOINT, STATUS_SINGLE_STEP, Session, StepKind, StepMode,
};
use crate::target::Target;
use crate::types::{Arch, VirtAddr};
use crate::unwind::{
    build_stacktrace, format_symbol, preferred_code_dtb, resolve_thread_trace_context,
};

impl Session {
    /// Single-step one instruction on the currently selected thread. If RIP sits
    /// on one of our breakpoints, do the disable/step/enable dance; otherwise
    /// plain step + trap-flag clear. Afterward re-arm enabled breakpoints (the
    /// stub can drop non-hit ones on a stop) and re-select the landed-on thread.
    /// The full "step one instruction", shared by the REPL (`si`) and the SDK.
    pub fn step(&mut self) -> Result<u64> {
        self.require_live_register_context()?;
        // Refused before anything moves, even on a breakpoint site the
        // run-past path could clear: a step is one instruction, not a run.
        if self.backend.single_step_unsafe() {
            return Err(Error::DebugInfo(STEP_UNDER_WINDOWS_HYPERVISOR.to_string()));
        }
        self.target.selected_frame = None;
        // Advancing the VM spends any stop `service_idle` parked, so drop it (the
        // other advance paths clear it via `resume`; a bare single-step doesn't).
        self.parked_stop = None;
        self.current_stop = None;
        self.backend.set_current_thread(&self.current_thread)?;
        if !step_over_current_breakpoint(
            self.backend.as_mut(),
            &self.register_map,
            &self.target,
            &mut self.breakpoints,
        )? {
            step_one_and_clear_tf(self.backend.as_mut(), &self.register_map)?;
        }
        for id in self.breakpoints.one_shot_hit_ids() {
            self.breakpoints
                .remove(self.backend.as_mut(), &self.target, id)?;
        }

        // Re-arm breakpoints the stub may have lost when the VM stopped, then
        // adopt whatever thread we ended up on.
        if let Err(error) = self
            .breakpoints
            .refresh_enabled(self.backend.as_mut(), &self.target)
        {
            self.notices.push(format!(
                "failed to re-arm breakpoints after the step: {error}"
            ));
        }
        if let Ok(tid) = self.backend.stopped_thread_id() {
            self.current_thread = tid;
        }
        self.refresh_context_for_current_thread();
        let rip = self.current_rip();
        self.current_stop = Some(ContinueOutcome::Step { rip });
        Ok(rip)
    }

    /// Decode the instruction at the current thread's program counter, masking
    /// any software-breakpoint patch and reading through the thread's preferred
    /// code DTB. Selects the current thread first; the VM must be halted.
    pub fn current_instruction(&mut self) -> Result<CurrentInstruction> {
        self.require_live_register_context()?;
        self.backend.set_current_thread(&self.current_thread)?;
        let regs = self.backend.read_registers()?;
        self.target.registers = Some(self.register_map.to_hashmap(&regs));
        let pc = self.register_map.read_u64("rip", &regs)?;
        let dtb = self
            .register_map
            .read_u64(self.target.arch().dtb_register(), &regs)
            .unwrap_or(0);
        let trace = resolve_thread_trace_context(&self.target, dtb);
        let code_dtb = preferred_code_dtb(&trace, pc);
        let memory = self.target.address_space(code_dtb);
        let mut bytes = [0u8; 16];
        memory.read_bytes(VirtAddr(pc), &mut bytes)?;
        self.breakpoints.mask_breakpoint_bytes(
            &self.target,
            VirtAddr(pc),
            &mut bytes,
            trace.active_dtb,
        );
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
        self.require_live_register_context()?;
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
    /// the way is returned as is. An interrupt request ([`Target::interrupt`])
    /// or an elapsed `timeout` ends the walk where it is, as a `Step`; `limit`
    /// instructions without a match is an error.
    pub fn step_until(
        &mut self,
        mode: StepMode,
        limit: usize,
        timeout: Option<Duration>,
        stop: impl Fn(u64, ControlFlow) -> bool,
    ) -> Result<ContinueOutcome> {
        self.require_live_register_context()?;
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
                _ => ContinueOutcome::Step { rip: self.step()? },
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
    /// leave the frame (a retpoline) is not taken for a return. An interrupt
    /// request ([`Target::interrupt`]), a breakpoint, or a failed step ends
    /// the trace early; [`CallTrace::end`] says which.
    pub fn trace_calls(&mut self, limit: usize) -> Result<CallTrace> {
        if limit == 0 {
            return Err(Error::InvalidArgument(
                "the instruction limit must be greater than zero".into(),
            ));
        }
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
            if let Err(error) = self.step() {
                break CallTraceEnd::Failed(error.to_string());
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
/// underlying instruction, then re-enable; returns whether a step was
/// performed. A stale breakpoint (its address space gone) is silently
/// discarded. A target that owns its sites (KD) has already dropped the one
/// at the PC while reporting the stop, so the disable is a no-op there and
/// the re-enable is what writes it back. Callers must have selected the
/// desired thread first. Shared by the REPL and [`Session::step`].
pub fn step_over_current_breakpoint(
    backend: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    debugger: &Target,
    breakpoints: &mut BreakpointManager,
) -> Result<bool> {
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
        return Ok(false);
    };

    match (breakpoints.disable(backend, debugger, bp_id), cr3) {
        (Ok(()), _) => {}
        (Err(Error::BadVirtualAddress(_) | Error::AddressNotInDump(_)), Some(cr3)) => {
            breakpoints
                .disable_guest_memory_patch_in_address_space(backend, debugger, bp_id, cr3)?;
        }
        (Err(err), _) => return Err(err),
    }

    let stepped = if backend.single_step_unsafe() {
        run_past_site(backend, register_map, debugger, &regs, rip, cr3)
    } else {
        step_one_and_clear_tf(backend, register_map)
    };

    // Re-arm whether or not the step worked: a failed step must not leave the
    // site unpatched with the manager still believing it is enabled.
    match breakpoints.enable(backend, debugger, bp_id) {
        Ok(()) => {}
        Err(Error::BadVirtualAddress(_) | Error::AddressNotInDump(_)) => {
            // Address space no longer exists; drop the breakpoint and move on.
            breakpoints.discard(backend, bp_id)?;
        }
        Err(err) => return stepped.and(Err(err)),
    }
    stepped.map(|()| true)
}

/// How long a vCPU resumed alone gets to execute the one instruction under a
/// breakpoint site. Kernel code finishes it in microseconds; a vCPU that
/// waits on a held one (an IPI, a spinlock) never will.
const RUN_PAST_TIMEOUT: Duration = Duration::from_secs(1);

/// Execute the instruction under the (already lifted) breakpoint site at
/// `rip` without a single step, which is unsafe on this backend (see
/// [`STEP_UNDER_WINDOWS_HYPERVISOR`]): plant temporary breakpoints on every
/// address it can continue at, resume this vCPU alone, and take the stop.
/// Other vCPUs stay held, so none can run through the lifted site.
fn run_past_site(
    backend: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    debugger: &Target,
    regs: &[u8],
    rip: u64,
    cr3: Option<u64>,
) -> Result<()> {
    let successors = site_successors(debugger, register_map, regs, rip, cr3)?;
    let mut planted = Vec::with_capacity(successors.len());
    let result = run_to_successors(backend, register_map, rip, &successors, &mut planted);
    for address in planted {
        let removed = backend.remove_breakpoint(address);
        if result.is_ok() {
            removed?;
        }
    }
    result
}

fn run_to_successors(
    backend: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    rip: u64,
    successors: &[u64],
    planted: &mut Vec<u64>,
) -> Result<()> {
    for &address in successors {
        backend.set_breakpoint(address)?;
        planted.push(address);
    }
    backend.continue_current_thread()?;
    let event = match backend.try_wait_for_stop(RUN_PAST_TIMEOUT)? {
        Some(event) => event,
        None => backend.interrupt()?,
    };
    if event.is_bugcheck {
        return Err(Error::DebugInfo(format!(
            "target bugchecked while running past the breakpoint at {rip:#x}"
        )));
    }
    let now = register_map.read_u64("rip", &backend.read_registers()?)?;
    if now == rip {
        return Err(Error::DebugInfo(format!(
            "could not run past the breakpoint at {rip:#x}: its vCPU, resumed alone, did not \
             execute it within {RUN_PAST_TIMEOUT:?}; disable the breakpoint to continue"
        )));
    }
    // Anywhere else (an interrupt taken first, another breakpoint) is
    // progress: the site is armed again and hits on the way back.
    Ok(())
}

/// Every address execution can continue at after the instruction at `rip`,
/// decoded from the guest (the site is already lifted) and resolved against
/// the stopped vCPU's registers and memory.
pub fn site_successors(
    debugger: &Target,
    register_map: &RegisterMap,
    regs: &[u8],
    rip: u64,
    cr3: Option<u64>,
) -> Result<Vec<u64>> {
    // As `current_instruction` reads it: CR3 carries PCID and flush bits,
    // and a module's own root serves its code.
    let trace = resolve_thread_trace_context(debugger, cr3.unwrap_or(0));
    let memory = debugger.address_space(preferred_code_dtb(&trace, rip));
    let mut bytes = [0u8; 16];
    memory.read_bytes(VirtAddr(rip), &mut bytes)?;
    let bitness = debugger.code_bitness(VirtAddr(rip));
    let instruction = Decoder::with_ip(bitness, &bytes, rip, DecoderOptions::NONE).decode();
    if instruction.is_invalid() {
        return Err(Error::DebugInfo(format!(
            "failed to decode instruction at {rip:#x}"
        )));
    }
    let width = if bitness == 32 { 4 } else { 8 };
    let pointer = |address: u64| -> Result<u64> {
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
            "cannot run past the breakpoint at {rip:#x} without single-stepping: `{}` has no \
             successor known from here; {STEP_UNDER_WINDOWS_HYPERVISOR}",
            format!("{:?}", instruction.mnemonic()).to_ascii_lowercase()
        ))
    };
    let successors = match instruction.flow_control() {
        FlowControl::Next => vec![instruction.next_ip()],
        FlowControl::ConditionalBranch => {
            vec![instruction.next_ip(), instruction.near_branch_target()]
        }
        FlowControl::UnconditionalBranch | FlowControl::Call
            if instruction.op0_kind() != OpKind::FarBranch16
                && instruction.op0_kind() != OpKind::FarBranch32 =>
        {
            vec![instruction.near_branch_target()]
        }
        FlowControl::IndirectBranch | FlowControl::IndirectCall => {
            vec![indirect_target(&instruction, &register, &pointer).ok_or_else(unsupported)??]
        }
        FlowControl::Return => vec![pointer(register(Register::RSP)?)?],
        _ => return Err(unsupported()),
    };
    let mut successors = successors;
    successors.dedup();
    Ok(successors)
}

/// Where an indirect `jmp`/`call` goes: a register, or a pointer in memory
/// without a segment override. `None` for forms this does not evaluate.
fn indirect_target(
    instruction: &Instruction,
    register: &impl Fn(Register) -> Result<u64>,
    pointer: &impl Fn(u64) -> Result<u64>,
) -> Option<Result<u64>> {
    match instruction.op0_kind() {
        OpKind::Register => Some(register(instruction.op0_register())),
        OpKind::Memory if !matches!(instruction.segment_prefix(), Register::FS | Register::GS) => {
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
                )
            })();
            Some(address)
        }
        _ => None,
    }
}
