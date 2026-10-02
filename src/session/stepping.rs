//! Instruction-level execution: single steps, step over/out, run-to,
//! step-until walks, and call tracing.

use std::mem;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use iced_x86::{
    Code, Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, MemorySize,
    Mnemonic, OpAccess, OpKind, Register,
};

use crate::backend::MemoryOps;
use crate::breakpoints::{
    BreakpointManager, StepFrame, ThreadScope, lift_target_site, plant_target_site,
};
use crate::dbg_backend::{
    ContinueDisposition, DebugBackend, HwBreakpointAccess, STEP_UNDER_WINDOWS_HYPERVISOR,
    StopEvent, clear_trap_flag, processor_index_from_backend_thread_id,
};
use crate::disasm::{ControlFlow, classify};
use crate::error::{Error, Result};
use crate::gdb::RegisterMap;
use crate::session::breakpoints::event_word;
use crate::session::context::windows_thread_on_backend_thread;
use crate::session::hits::{reported_watch_hit, stack_pointer};
use crate::session::{
    CallTrace, CallTraceEnd, CallTraceFrame, ContinueOutcome, ControlState, CurrentInstruction,
    ModuleTrap, PendingWalk, STATUS_BREAKPOINT, STATUS_SINGLE_STEP, Session, StepKind, StepMode,
    StepStack,
};
use crate::target::{DiagnosticValue, KTHREAD_STATE_RUNNING, KTHREAD_STATE_STANDBY, Target};
use crate::types::{Arch, Dtb, VirtAddr};
use crate::unwind::{
    build_stacktrace, guest_vp_running, halted_in_windows_hypervisor, preferred_code_dtb,
    resolve_thread_trace_context, thread_root, try_format_symbol_at,
};

impl Session {
    /// Single-step one instruction on the currently selected thread. If RIP sits
    /// on one of our breakpoints, do the disable/step/enable dance; otherwise
    /// plain step + trap-flag clear. Afterward re-arm enabled breakpoints (the
    /// stub can drop non-hit ones on a stop) and re-select the landed-on thread.
    /// The full "step one instruction", shared by the REPL (`si`) and the SDK.
    /// It ends on a `Step` where the vCPU is or, under the Windows hypervisor,
    /// on a watchpoint's hit another vCPU made while this one waited on them
    /// (see [`RunPast::Kept`]).
    pub fn step(&mut self) -> Result<ContinueOutcome> {
        let (outcome, stepped) = self.step_once()?;
        if stepped == RunPast::Diverted {
            self.note_diverted();
        }
        Ok(outcome)
    }

    /// [`Self::step`], saying whether the vCPU was diverted: resumed alone,
    /// it reached no successor and was broken in on elsewhere, in an
    /// interrupt handler that waits on a held vCPU. Stepping on from there
    /// steps that handler's wait, which no held vCPU will ever end; loops
    /// that step stop instead ([`Self::note_diverted`] says so).
    fn step_once(&mut self) -> Result<(ContinueOutcome, RunPast)> {
        // A stop a run past kept before this step, while a hit was passed
        // over for the host (see [`Self::pass_declined_hit`]), is the step's.
        if let Some(outcome) = self.kept_watch_hit()? {
            return Ok((outcome, RunPast::Kept));
        }
        self.require_steppable_vcpu()?;
        self.target.selected_frame = None;
        // Advancing the VM spends any stop `service_idle` parked, so drop it (the
        // other advance paths clear it via `resume`; a bare single-step doesn't).
        self.parked_stop = None;
        self.current_stop = None;
        self.target.breakpoint_stop = None;
        self.backend.set_current_thread(&self.current_thread)?;
        let mut stepped = match self.step_over_site_at_pc()? {
            Some(stepped) => stepped,
            None if self.backend.single_step_unsafe() => step_without_trap(
                self.backend.as_mut(),
                &self.register_map,
                &self.target,
                &self.breakpoints,
                &self.current_thread,
            )?,
            None => {
                step_one_and_clear_tf(
                    self.backend.as_mut(),
                    &self.register_map,
                    &self.target.interrupt,
                )?;
                RunPast::Reached
            }
        };
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
        if stepped == RunPast::Kept {
            if let Some(outcome) = self.kept_watch_hit()? {
                return Ok((outcome, stepped));
            }
            // Declined, the hit leaves the vCPU where its run was diverted.
            stepped = RunPast::Diverted;
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
        // A thread that blocked lets NT idle its processor, where the
        // hypervisor can run a guest partition's VP: the vCPU then shows
        // that guest, whose code no step can start from.
        if let Some(vp) = self.vcpu_guest_vp()? {
            return Err(Error::DebugInfo(format!(
                "{} began running {vp} of a guest partition before finishing the step: the \
                 Windows hypervisor put it on the processor while NT waits there. Resume with g",
                self.current_thread
            )));
        }
        Ok((ContinueOutcome::Step { rip }, stepped))
    }

    /// Say that a step stopped where it was diverted (see [`Self::step_once`]).
    fn note_diverted(&mut self) {
        self.notices.push(format!(
            "{} did not reach the next instruction within {RUN_PAST_TIMEOUT:?} of running \
             alone: it took an interrupt first, and stopped in the handler (or in another \
             thread it switched to); resume with g to let it finish",
            self.current_thread
        ));
    }

    /// Step the current thread past the debugger site its PC is on: one of
    /// the manager's breakpoints, a module trap, or both at one address;
    /// `None` when it is on neither. The trap is lifted for the step and
    /// planted again, as a breakpoint is; one that cannot be planted again is
    /// dropped, and the next resume arms it anew. Callers must have selected
    /// the current thread on the backend.
    pub fn step_over_site_at_pc(&mut self) -> Result<Option<RunPast>> {
        if self.module_traps.is_empty() {
            return self.step_over_breakpoint_at_pc();
        }
        let regs = self.backend.read_registers()?;
        let rip = self.register_map.read_u64("rip", &regs)?;
        let Some(index) = self
            .module_traps
            .iter()
            .position(|trap| trap.site.address.0 == rip)
        else {
            return self.step_over_breakpoint_at_pc();
        };
        let ModuleTrap { event, site: trap } = self.module_traps[index].clone();
        let cr3 = self
            .register_map
            .read_u64(self.target.arch().dtb_register(), &regs)
            .ok();
        lift_target_site(self.backend.as_mut(), &self.target, trap.address)?;
        let stepped = match self.step_over_breakpoint_at_pc() {
            Ok(Some(stepped)) => Ok(stepped),
            Ok(None) => execute_lifted_site(
                self.backend.as_mut(),
                &self.register_map,
                &self.target,
                &self.breakpoints,
                &self.current_thread,
                &regs,
                rip,
                cr3,
            ),
            Err(error) => Err(error),
        };
        // Planted again whether or not the step worked, as a breakpoint is.
        let original = (!trap.original.is_empty()).then_some(trap.original.as_slice());
        if let Err(error) =
            plant_target_site(self.backend.as_mut(), &self.target, trap.address, original)
        {
            self.module_traps.remove(index);
            self.notices.push(format!(
                "failed to re-arm the module-{} trap: {error}",
                event_word(event)
            ));
        }
        // Interrupted on the trap itself, the thread returns to it and hits
        // it again; that hit is this event, not a new one.
        if matches!(stepped, Ok(RunPast::Diverted | RunPast::Kept)) {
            self.module_trap_interrupted =
                interrupted_on(&self.target, &self.register_map, &regs, rip, cr3)
                    .map(|stack| (event, stack));
        }
        stepped.map(Some)
    }

    /// [`step_over_current_breakpoint`] on the current thread.
    fn step_over_breakpoint_at_pc(&mut self) -> Result<Option<RunPast>> {
        step_over_current_breakpoint(
            self.backend.as_mut(),
            &self.register_map,
            &self.target,
            &mut self.breakpoints,
            &self.current_thread,
        )
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
        self.mask_code(VirtAddr(pc), &mut bytes, active_dtb);

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
        self.read_control().map(|(state, ..)| state)
    }

    /// [`Self::control_state`] with the registers and the (masked)
    /// instruction bytes it was read from.
    fn read_control(&mut self) -> Result<(ControlState, Vec<u8>, [u8; 16])> {
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
        let state = ControlState {
            ip,
            sp,
            dtb,
            flow: classify(&bytes[..length], self.target.arch(), bitness),
        };
        Ok((state, registers, bytes))
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
    /// or an elapsed `timeout` ends the walk where it is, as a `Step`;
    /// `limit` instructions without a match is an error.
    ///
    /// The walk follows the Windows thread it started in, not its vCPU: a
    /// step an interrupt diverted off the instruction (see
    /// [`Self::walk_step`]) goes on by running until that thread has
    /// executed the instruction, on whichever vCPU it is scheduled. Without
    /// the thread known (no kernel symbols, VTL1), a
    /// diverted step ends the walk where it is (see [`Self::step_once`]).
    pub fn step_until(
        &mut self,
        mode: StepMode,
        limit: usize,
        timeout: Option<Duration>,
        stop: impl Fn(u64, ControlFlow) -> bool,
    ) -> Result<ContinueOutcome> {
        self.pending_walk = None;
        self.walk_until(mode, limit, timeout, stop)
    }

    /// Go on with a [`Self::step_until`] walk another stop ended, after the
    /// host passed over that stop (the SDK's declined `when=` hit), from
    /// where the walk's execution is rather than where the processor is now:
    /// a walk ended while running over a call, or while its step was
    /// diverted off the instruction (into an interrupt handler, or another
    /// thread), first runs to where its thread goes on (see
    /// [`PendingWalk::sites`]). Otherwise a hit on another vCPU than the
    /// walk's is stepped past and the walk's vCPU selected again.
    pub fn resume_step_until(
        &mut self,
        mode: StepMode,
        limit: usize,
        timeout: Option<Duration>,
        stop: impl Fn(u64, ControlFlow) -> bool,
    ) -> Result<ContinueOutcome> {
        let deadline = timeout.map(|timeout| Instant::now() + timeout);
        if let Some(PendingWalk { vcpu, sites }) = self.pending_walk.take() {
            if sites.is_empty() {
                self.pass_declined_hit(&vcpu)?;
            } else {
                let cancel = Arc::clone(&self.target.interrupt);
                match self.run_to_any(&sites, timeout, &cancel)? {
                    ContinueOutcome::Step { .. } => {}
                    ContinueOutcome::Running => {
                        let outcome = ContinueOutcome::Step {
                            rip: self.current_rip(),
                        };
                        self.note_stop(&outcome);
                        return Ok(outcome);
                    }
                    other => {
                        self.pending_walk = Some(PendingWalk { vcpu, sites });
                        return Ok(other);
                    }
                }
            }
        }
        let remaining = deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()));
        self.walk_until(mode, limit, remaining, stop)
    }

    fn walk_until(
        &mut self,
        mode: StepMode,
        limit: usize,
        timeout: Option<Duration>,
        stop: impl Fn(u64, ControlFlow) -> bool,
    ) -> Result<ContinueOutcome> {
        self.require_steppable_vcpu()?;
        self.clear_selected_frame();
        let deadline = timeout.map(|timeout| Instant::now() + timeout);
        let remaining =
            || deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()));
        let cancel = Arc::clone(&self.target.interrupt);
        let walked = windows_thread_on_backend_thread(&self.target, &self.current_thread)
            .map(|thread| ThreadScope::new(&thread));
        for _ in 0..limit {
            if cancel.swap(false, Ordering::SeqCst) {
                let outcome = ContinueOutcome::Step {
                    rip: self.current_rip(),
                };
                self.note_stop(&outcome);
                return Ok(outcome);
            }
            let (state, registers, bytes) = self.read_control()?;
            if stop(state.ip, state.flow)
                || deadline.is_some_and(|deadline| Instant::now() >= deadline)
            {
                let outcome = ContinueOutcome::Step { rip: state.ip };
                self.note_stop(&outcome);
                return Ok(outcome);
            }
            let vcpu = self.current_thread.clone();
            let (step, sites) = match self.step_over_target()? {
                StepKind::RunTo(next) if mode == StepMode::Over => {
                    let sites = vec![(next, self.step_frame(StepStack::CallReturn)?)];
                    (self.run_to_any(&sites, remaining(), &cancel)?, sites)
                }
                _ => match self.walk_step(&state, &registers, &bytes, walked.as_ref())? {
                    WalkStep::At(rip) => (ContinueOutcome::Step { rip }, Vec::new()),
                    WalkStep::Follow(sites) => {
                        (self.run_to_any(&sites, remaining(), &cancel)?, sites)
                    }
                    WalkStep::Stop(outcome) => {
                        self.note_stop(&outcome);
                        return Ok(outcome);
                    }
                },
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
                other => {
                    self.pending_walk = Some(PendingWalk { vcpu, sites });
                    return Ok(other);
                }
            };
            if let Some(outcome) = self
                .code_breakpoint_after_step(state.ip, rip)
                .and_then(|id| self.breakpoint_outcome(id, rip))
            {
                self.pending_walk = Some(PendingWalk {
                    vcpu,
                    sites: Vec::new(),
                });
                self.note_stop(&outcome);
                return Ok(outcome);
            }
        }
        Err(Error::StepLimit(limit))
    }

    /// Single-step the instruction a walk of thread `walked` is at (`state`).
    /// An interrupt taken first can end the step off the instruction's
    /// successors: in the handler (waiting on a held vCPU, or on a
    /// breakpoint), or in another thread the handler switched to. That
    /// happens under the Windows hypervisor, where the vCPU runs alone to the
    /// successors, and over KD, where the trap flag does not hold interrupts
    /// off and the other processors run too (and one may stop first). A step
    /// ended at a successor on its own vCPU completed in `walked`, even if the
    /// instruction made another thread current (NT's `CurrentThread` changes
    /// before the stacks do), unless it loaded the other thread's stack: the
    /// vCPU then runs that thread, and `walked` goes on at the successors when
    /// it is switched back in. Where `walked` goes on is known only before the
    /// step, so it is decoded first, from the `registers` and instruction
    /// `bytes` `state` was read from.
    fn walk_step(
        &mut self,
        state: &ControlState,
        registers: &[u8],
        bytes: &[u8; 16],
        walked: Option<&ThreadScope>,
    ) -> Result<WalkStep> {
        // An instruction without known successors is not followed; one run
        // alone fails its step the same way.
        let (successors, floor) = match walked {
            Some(_) if self.target.arch() != Arch::Arm64 => self
                .walk_continuation(state, registers, bytes)
                .unwrap_or_default(),
            _ => (Vec::new(), None),
        };
        let vcpu = self.current_thread.clone();
        let (outcome, stepped) = self.step_once()?;
        // Where the walked thread goes on: past the instruction, which it
        // executes whether the interrupt came before or after it, at no
        // lower a stack than the instruction leaves (the same code reached
        // by a deeper call is not it). Stopping it on the instruction
        // instead, to step it again, can starve it: under load, the step
        // after such a stop was switched out again every time.
        let resume_sites = |walked: &ThreadScope| -> Vec<(VirtAddr, Option<StepFrame>)> {
            successors
                .iter()
                .map(|&address| {
                    let frame = StepFrame {
                        thread: walked.clone(),
                        min_stack_pointer: floor,
                    };
                    (VirtAddr(address), Some(frame))
                })
                .collect()
        };
        let ContinueOutcome::Step { rip } = outcome else {
            // Another vCPU's watchpoint hit, made while this one waited on
            // them, ends the walk there. Passed over, the walk goes on where
            // its thread does, as after a breakpoint the step reached.
            let sites = walked
                .filter(|_| !successors.is_empty())
                .map(resume_sites)
                .unwrap_or_default();
            self.pending_walk = Some(PendingWalk { vcpu, sites });
            return Ok(WalkStep::Stop(outcome));
        };
        let plain = |session: &mut Self| {
            if stepped == RunPast::Diverted {
                session.note_diverted();
                return WalkStep::Stop(ContinueOutcome::Step { rip });
            }
            WalkStep::At(rip)
        };
        let Some(walked) = walked.filter(|_| !successors.is_empty()) else {
            return Ok(plain(self));
        };
        let elsewhere = self.current_thread != vcpu;
        // NT makes the next thread current before it loads that thread's
        // stack, so in a context switch a step lands on a successor with
        // another thread current and the walked one still running. Once the
        // stack is no longer the walked thread's, this vCPU runs the other
        // thread, and the walked one goes on at the successors when it is
        // switched back in.
        let left = !elsewhere && self.vcpu_left_thread(walked);
        if !elsewhere && !left && successors.contains(&rip) {
            return Ok(WalkStep::At(rip));
        }
        let sites = resume_sites(walked);
        let switched = elsewhere
            || left
            || stepped == RunPast::Diverted
            || nt_thread_on(&self.target, &vcpu).is_some_and(|now| now != walked.ethread.0);
        if let Some(outcome) = self
            .code_breakpoint_after_step(state.ip, rip)
            .and_then(|id| self.breakpoint_outcome(id, rip))
        {
            self.pending_walk = Some(PendingWalk { vcpu, sites });
            return Ok(WalkStep::Stop(outcome));
        }
        // Elsewhere, diverted, or switched out, the walked thread goes on
        // when it runs again. Otherwise it is in a handler of its own (a
        // fault a trap-flag step entered), which the walk goes on through.
        Ok(if switched {
            WalkStep::Follow(sites)
        } else {
            WalkStep::At(rip)
        })
    }

    /// Whether the selected vCPU runs another thread than `walked` on that
    /// thread's own stack: another thread is current, and the stack pointer
    /// has left `walked`'s kernel stack. A thread current alone is not
    /// enough: NT makes the next thread current while the outgoing one still
    /// runs, on its own stack, to the point where it loads the next one's.
    fn vcpu_left_thread(&mut self, walked: &ThreadScope) -> bool {
        if nt_thread_on(&self.target, &self.current_thread)
            .is_none_or(|now| now == walked.ethread.0)
        {
            return false;
        }
        let Ok(thread) = self.target.thread_info_from_ethread(walked.ethread) else {
            return false;
        };
        let (Some(base), Some(limit)) = (thread.stack_base, thread.stack_limit) else {
            return false;
        };
        self.read_registers()
            .ok()
            .and_then(|registers| stack_pointer(&self.register_map, &registers))
            .is_some_and(|sp| !(limit.0..base.0).contains(&sp))
    }

    /// Where the execution at `state` continues past its instruction: every
    /// address it can continue at (see [`site_successors`]), and the lowest
    /// stack pointer it can have there (see [`stack_floor`]).
    fn walk_continuation(
        &self,
        state: &ControlState,
        registers: &[u8],
        bytes: &[u8; 16],
    ) -> Result<(Vec<u64>, Option<u64>)> {
        let cr3 = self
            .register_map
            .read_u64(self.target.arch().dtb_register(), registers)
            .ok();
        let successors = instruction_successors(
            &self.target,
            &self.register_map,
            &self.current_thread,
            registers,
            state.ip,
            cr3,
            bytes,
        )?;
        let bitness = self.target.code_bitness(VirtAddr(state.ip));
        let instruction = Decoder::with_ip(bitness, bytes, state.ip, DecoderOptions::NONE).decode();
        Ok((successors, stack_floor(&instruction, state.sp)))
    }

    fn breakpoint_outcome(&self, id: u32, rip: u64) -> Option<ContinueOutcome> {
        let breakpoint = self.breakpoints.get(id)?;
        Some(ContinueOutcome::breakpoint_hit(breakpoint, rip, None))
    }

    /// Single-step the current function and collect its call tree (`wt`), up
    /// to `limit` instructions. A frame closes on a `ret` that moves the stack
    /// pointer above the one it was entered with, so a `ret` that does not
    /// the frame (a retpoline) is not taken for a return. The trace follows
    /// the Windows thread it started in, as a walk does (see
    /// [`Self::step_until`]): a step an interrupt diverted runs until that
    /// thread has executed the instruction. An interrupt request
    /// ([`Target::interrupt`]), a breakpoint, a diverted step whose thread is
    /// not known, or a failed step ends the trace early; [`CallTrace::end`]
    /// says which.
    pub fn trace_calls(&mut self, limit: usize) -> Result<CallTrace> {
        if limit == 0 {
            return Err(Error::InvalidArgument(
                "the instruction limit must be greater than zero".into(),
            ));
        }
        self.require_steppable_vcpu()?;
        let name = |target: &Target, state: &ControlState| {
            try_format_symbol_at(target, state.dtb, state.ip)
                .unwrap_or_else(|| format!("{:#x}", state.ip))
        };
        let frame = |name| CallTraceFrame {
            name,
            instructions: 0,
            children: Vec::new(),
        };
        let (mut current, mut registers, mut bytes) = self.read_control()?;
        let walked = windows_thread_on_backend_thread(&self.target, &self.current_thread)
            .map(|thread| ThreadScope::new(&thread));
        let cancel = Arc::clone(&self.target.interrupt);
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
            match self.walk_step(&current, &registers, &bytes, walked.as_ref()) {
                Ok(WalkStep::At(_)) => {}
                Ok(WalkStep::Follow(sites)) => match self.run_to_any(&sites, None, &cancel) {
                    Ok(ContinueOutcome::Step { .. }) => {}
                    // Cancelled: the target is halted where it was.
                    Ok(ContinueOutcome::Running) => {
                        cancel.store(false, Ordering::SeqCst);
                        break CallTraceEnd::Interrupted;
                    }
                    Ok(ContinueOutcome::Breakpoint { .. }) => break CallTraceEnd::Breakpoint,
                    Ok(_) => {
                        break CallTraceEnd::Failed(
                            "the target stopped on an exception while the traced thread was \
                             switched out"
                                .into(),
                        );
                    }
                    Err(error) => break CallTraceEnd::Failed(error.to_string()),
                },
                Ok(WalkStep::Stop(ContinueOutcome::Breakpoint { .. })) => {
                    break CallTraceEnd::Breakpoint;
                }
                Ok(WalkStep::Stop(_)) => break CallTraceEnd::Diverted,
                Err(error) => break CallTraceEnd::Failed(error.to_string()),
            }
            instructions += 1;
            let next = match self.read_control() {
                Ok((state, next_registers, next_bytes)) => {
                    (registers, bytes) = (next_registers, next_bytes);
                    state
                }
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

    /// The stepping thread's [`StepFrame`] for a run-to whose arrival must
    /// find its stack per `stack`. `None` when the thread cannot be
    /// identified (a VTL1 stop, no kernel symbols): the run-to then stops for
    /// any thread.
    pub fn step_frame(&mut self, stack: StepStack) -> Result<Option<StepFrame>> {
        let Some(thread) = windows_thread_on_backend_thread(&self.target, &self.current_thread)
        else {
            return Ok(None);
        };
        let min_stack_pointer = match stack {
            StepStack::Any => None,
            StepStack::CallReturn | StepStack::FunctionReturn => {
                let registers = self.read_registers()?;
                stack_pointer(&self.register_map, &registers).map(|sp| {
                    // An x86 `ret` pops its return address; an AArch64 `ret`
                    // leaves the stack pointer where the callee found it.
                    if stack == StepStack::FunctionReturn && self.target.arch() != Arch::Arm64 {
                        sp + 1
                    } else {
                        sp
                    }
                })
            }
        };
        Ok(Some(StepFrame {
            thread: ThreadScope::new(&thread),
            min_stack_pointer,
        }))
    }

    /// Run until `address` is reached, by the execution `frame` names when
    /// given. If a breakpoint is already set there in
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
        frame: Option<StepFrame>,
        timeout: Option<Duration>,
        cancel: &AtomicBool,
    ) -> Result<ContinueOutcome> {
        self.run_to_any(&[(address, frame)], timeout, cancel)
    }

    /// [`Self::run_to`] whichever of `sites` is reached first, each by the
    /// execution its frame names.
    fn run_to_any(
        &mut self,
        sites: &[(VirtAddr, Option<StepFrame>)],
        timeout: Option<Duration>,
        cancel: &AtomicBool,
    ) -> Result<ContinueOutcome> {
        let mut temporary = Vec::with_capacity(sites.len());
        for (address, frame) in sites {
            // Already breakpointed here → the existing bp will report.
            if self
                .breakpoints
                .enabled_breakpoint_id_for_current_context(&self.target, *address)
                .is_some()
            {
                continue;
            }
            match self.breakpoints.add_temporary_code(
                self.backend.as_mut(),
                &self.target,
                *address,
                frame.clone(),
            ) {
                Ok(id) => temporary.push(id),
                Err(error) => {
                    self.remove_temporary(&temporary);
                    return Err(error);
                }
            }
        }
        let followed = sites
            .iter()
            .find_map(|(_, frame)| frame.as_ref().map(|frame| frame.thread.clone()));
        let watch = followed
            .as_ref()
            .and_then(|thread| self.watch_followed(thread, &temporary));
        let outcome = self.wait_for_sites(followed.as_ref(), watch.as_ref(), timeout, cancel);

        // A cancel or timeout leaves the VM running; halt it where it is (the
        // temp breakpoints' removal writes guest memory anyway).
        if self.backend.is_running() {
            let _ = self.interrupt();
        }
        if let Some(watch) = watch {
            self.end_follow_watch(watch);
        }
        self.remove_temporary(&temporary);

        let outcome = match outcome? {
            ContinueOutcome::Breakpoint { id, rip, .. } if temporary.contains(&id) => {
                ContinueOutcome::Step { rip }
            }
            other => other,
        };
        self.note_stop(&outcome);
        Ok(outcome)
    }

    /// Wait for one of a run's sites, as [`Self::continue_until_break`]
    /// does, except that a run following a thread (`followed`) checks
    /// between waits of [`FOLLOW_CHECK`] that the thread can still reach
    /// them. Switched out, a thread runs a pending termination when it is
    /// next scheduled, and an exited thread never reaches its sites. With a
    /// `watch` on the thread's state, its `sites` are armed only while it
    /// is about to run (see [`Self::watch_followed`]).
    fn wait_for_sites(
        &mut self,
        followed: Option<&ThreadScope>,
        watch: Option<&FollowWatch>,
        timeout: Option<Duration>,
        cancel: &AtomicBool,
    ) -> Result<ContinueOutcome> {
        let Some(thread) = followed else {
            return self.continue_until_break(timeout, cancel, ContinueDisposition::Handled);
        };
        let deadline = timeout.map(|timeout| Instant::now() + timeout);
        loop {
            let slice = deadline.map_or(FOLLOW_CHECK, |deadline| {
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(FOLLOW_CHECK)
            });
            let outcome =
                self.continue_until_break(Some(slice), cancel, ContinueDisposition::Handled)?;
            if let ContinueOutcome::Breakpoint { id, .. } = outcome
                && let Some(watch) = watch.filter(|watch| watch.id == id)
            {
                self.follow_watch_hit(watch)?;
                continue;
            }
            if !matches!(outcome, ContinueOutcome::Running)
                || cancel.load(Ordering::SeqCst)
                || deadline.is_some_and(|deadline| Instant::now() >= deadline)
            {
                return Ok(outcome);
            }
            // Read while the target runs; a read that fails proves nothing.
            let now = self.target.thread_info_from_ethread(thread.ethread);
            // What a follow that never ends waited on: the thread's state,
            // and whether its sites and watch are armed.
            step_trace!(
                "following {}: state {:?}, {}",
                thread.label(),
                now.as_ref().ok().and_then(|now| now.state),
                watch.map_or("sites armed throughout".to_string(), |watch| {
                    let enabled = |id| self.breakpoints.get(id).is_some_and(|bp| bp.enabled);
                    format!(
                        "sites {}, watch #{} {}",
                        if watch.sites.iter().any(|&id| enabled(id)) {
                            "armed"
                        } else {
                            "disarmed"
                        },
                        watch.id,
                        if enabled(watch.id) { "armed" } else { "gone" }
                    )
                })
            );
            if now.is_ok_and(|now| thread.exited(&now)) {
                return Err(followed_thread_exited(thread));
            }
        }
    }

    /// Watch switched-out `thread`'s `KTHREAD.State`, and arm `sites`, the
    /// run's to where it goes on, only while it is about to run: the
    /// dispatcher makes a thread Standby or Running before it runs it. Each
    /// hit another thread makes on an armed site stops the target, and a
    /// thread is often switched out in code every thread runs, a lock
    /// release say, hit hundreds of times a second: the guest then runs too
    /// little for a low-priority thread to be scheduled at all. `None`, the
    /// sites armed throughout, without the field's offset or a free debug
    /// register.
    pub fn watch_followed(&mut self, thread: &ThreadScope, sites: &[u32]) -> Option<FollowWatch> {
        if sites.is_empty() {
            return None;
        }
        let offset = (self.target.guest().ok()?.ntoskrnl.types())
            .layout("_KTHREAD")
            .ok()?
            .field_offset("State")
            .ok()?;
        let kthread = self
            .target
            .thread_info_from_ethread(thread.ethread)
            .ok()?
            .kthread;
        let watch = self
            .breakpoints
            .add_temporary_watch(
                self.backend.as_mut(),
                &self.target,
                VirtAddr(kthread.0 + offset),
                1,
            )
            .ok()?;
        // Read with the watch armed and the target halted, so no write is
        // missed between the two.
        let state = self
            .target
            .thread_info_from_ethread(thread.ethread)
            .ok()
            .and_then(|now| now.state);
        if self.arm_followed_sites(sites, about_to_run(state)).is_err() {
            self.remove_temporary(&[watch]);
            let _ = self.arm_followed_sites(sites, true);
            return None;
        }
        Some(FollowWatch {
            id: watch,
            thread: thread.clone(),
            sites: sites.to_vec(),
        })
    }

    /// Take a stop on `watch`, a write to its thread's state: arm its sites
    /// if the thread is about to run, or disarm them. An error when the
    /// thread exited, which then never reaches them.
    pub fn follow_watch_hit(&mut self, watch: &FollowWatch) -> Result<()> {
        let now = self.target.thread_info_from_ethread(watch.thread.ethread);
        if now.as_ref().is_ok_and(|now| watch.thread.exited(now)) {
            return Err(followed_thread_exited(&watch.thread));
        }
        let state = now.ok().and_then(|now| now.state);
        step_trace!(
            "follow watch #{} on {}: state {state:?}, sites {}",
            watch.id,
            watch.thread.label(),
            if about_to_run(state) {
                "armed"
            } else {
                "disarmed"
            }
        );
        self.arm_followed_sites(&watch.sites, about_to_run(state))
    }

    /// Remove `watch`, leaving its sites as they are; the target must be
    /// halted.
    pub fn end_follow_watch(&mut self, watch: FollowWatch) {
        self.remove_temporary(&[watch.id]);
    }

    /// Enable `sites` (`armed`) or disable them.
    fn arm_followed_sites(&mut self, sites: &[u32], armed: bool) -> Result<()> {
        for &id in sites {
            if armed {
                self.breakpoints
                    .enable(self.backend.as_mut(), &self.target, id)?;
            } else {
                self.breakpoints
                    .disable(self.backend.as_mut(), &self.target, id)?;
            }
        }
        Ok(())
    }

    /// Remove run-to breakpoints. A target reload already cleared the
    /// manager, so a removal may be a no-op; its error is ignored.
    fn remove_temporary(&mut self, ids: &[u32]) {
        for &id in ids {
            let _ = self
                .breakpoints
                .remove(self.backend.as_mut(), &self.target, id);
        }
    }

    /// Step over the current instruction: single-step it, or, if it's a `call`,
    /// run to the instruction after it ([`ContinueOutcome::Step`] on completion).
    /// Shared by the REPL `p` (target only) and the SDKs.
    pub fn step_over(&mut self, cancel: &AtomicBool) -> Result<ContinueOutcome> {
        match self.step_over_target()? {
            StepKind::Single => self.step(),
            StepKind::RunTo(addr) => {
                let frame = self.step_frame(StepStack::CallReturn)?;
                self.run_to(addr, frame, None, cancel)
            }
        }
    }

    /// Step out of the current function: run to the caller's return address.
    pub fn step_out(&mut self, cancel: &AtomicBool) -> Result<ContinueOutcome> {
        let target = self.step_out_target()?;
        let frame = self.step_frame(StepStack::FunctionReturn)?;
        self.run_to(target, frame, None, cancel)
    }
}

/// Single-step the current thread and clear `TF` afterward (KVM leaves it set).
/// A fault or bugcheck instead of the step trap is returned as an error.
/// `interrupt` (Ctrl+C) ends the wait with a break-in.
pub fn step_one_and_clear_tf(
    backend: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    interrupt: &AtomicBool,
) -> Result<()> {
    backend.step()?;
    let event = wait_for_step_stop(backend, interrupt)?;
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

/// Wait for the stop that ends a step. The stop normally arrives at once,
/// but a target can run on and never report it. `interrupt` (Ctrl+C) then
/// breaks in, and the break-in's stop ends the wait. The flag is checked
/// only after a poll finds no stop, so a step that stops is never broken in
/// on. It stays raised, so a loop of steps around this one ends too.
fn wait_for_step_stop(backend: &mut dyn DebugBackend, interrupt: &AtomicBool) -> Result<StopEvent> {
    loop {
        if let Some(event) = backend.try_wait_for_stop(STEP_POLL_INTERVAL)? {
            return Ok(event);
        }
        if interrupt.load(Ordering::SeqCst) {
            return backend.interrupt();
        }
    }
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
    step_trace!("stepping {thread} off #{bp_id} at {rip:#x}");
    // An execution interrupted on the site that got back onto it some other
    // way than hitting it (stepped through its handler) runs past it now;
    // its remembered hit must not absorb a later, real one.
    if let Ok(rsp) = register_map.read_u64("rsp", &regs) {
        breakpoints.forget_interrupted_hit(bp_id, rsp);
    }

    match (breakpoints.lift(backend, debugger, bp_id), cr3) {
        (Ok(()), _) => {}
        (Err(Error::BadVirtualAddress(_) | Error::AddressNotInDump(_)), Some(cr3)) => {
            breakpoints
                .disable_guest_memory_patch_in_address_space(backend, debugger, bp_id, cr3)?;
        }
        (Err(err), _) => return Err(err),
    }

    let stepped = execute_lifted_site(
        backend,
        register_map,
        debugger,
        breakpoints,
        thread,
        &regs,
        rip,
        cr3,
    );

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
    if matches!(stepped, Ok(RunPast::Diverted | RunPast::Kept))
        && let Some(rsp) = interrupted_on(debugger, register_map, &regs, rip, cr3)
    {
        breakpoints.note_interrupted_hit(bp_id, rsp);
    }
    stepped.map(Some)
}

/// Execute the instruction at `rip` of `thread`, whose registers are
/// `regs`, under a site already lifted: single-step it, or where a single
/// step is unsafe (the Windows hypervisor), run the vCPU alone past it.
fn execute_lifted_site(
    backend: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    debugger: &Target,
    breakpoints: &BreakpointManager,
    thread: &str,
    regs: &[u8],
    rip: u64,
    cr3: Option<u64>,
) -> Result<RunPast> {
    if backend.single_step_unsafe() {
        run_past_site(
            backend,
            register_map,
            debugger,
            breakpoints,
            thread,
            regs,
            rip,
            cr3,
        )
    } else {
        step_one_and_clear_tf(backend, register_map, &debugger.interrupt).map(|()| RunPast::Reached)
    }
}

/// The stack pointer of the execution at `regs` when an interrupt it took on
/// the instruction at `rip`, before executing it, is still pending return:
/// the processor pushed a return frame (RIP, CS, RFLAGS, RSP, SS) below the
/// 16-byte-aligned stack pointer, and an error code, for the exceptions with
/// one, below that; NT builds its trap frame below both. `None` without such a frame:
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
    let mut frame = [0u8; 40];
    let base = (rsp & !0xf).wrapping_sub(frame.len() as u64);
    memory.read_bytes(VirtAddr(base), &mut frame).ok()?;
    let word = |index: usize| {
        u64::from_le_bytes(frame[index * 8..index * 8 + 8].try_into().expect("8 bytes"))
    };
    (word(0) == rip && word(1) & 3 == 0 && word(3) == rsp).then_some(rsp)
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
    /// held vCPUs were let run, the thread was switched out). Or the vCPU
    /// switched to another thread, which stopped on the kept site (see
    /// [`keeper_slot`]).
    Diverted,
    /// Stopped on a watchpoint's hit short of the successors, another vCPU's
    /// while this one waited on them, or its own in a handler. The backend
    /// keeps that stop for the next wait (see
    /// [`DebugBackend::keep_last_stop`]), with the vCPU where it stood, as
    /// for [`Self::Diverted`].
    Kept,
}

/// How one single step of a walk ended (see [`Session::walk_step`]).
enum WalkStep {
    /// At `rip`, still in the walked thread (or with none known).
    At(u64),
    /// The walked thread was switched out: run to these sites, where it goes
    /// on.
    Follow(Vec<(VirtAddr, Option<StepFrame>)>),
    /// The walk ends on this stop.
    Stop(ContinueOutcome),
}

/// How long a vCPU resumed alone gets to execute one instruction before the
/// others are broken in on. Measured under VBS
/// over 7761 run-pasts on hot kernel functions: every one that finished did
/// so within 24 ms, and the rest (3-4%, waiting on a held vCPU) never
/// finished alone, so waiting longer only delays the release that frees
/// them. Under a busy Hyper-V guest those waits come many times a second.
const RUN_PAST_TIMEOUT: Duration = Duration::from_millis(30);

/// How many times a vCPU run alone past a kept site may stop on it again
/// before the keeper is lifted. Each is an interrupt it took before the
/// instruction, back on it without `RF`, or a target where `RF` does not
/// get it past.
const KEEPER_RETRIES: u32 = 3;

/// How often a step's wait for its stop checks for Ctrl+C.
const STEP_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// How often a run to a followed thread's sites checks that the thread has
/// not exited (see [`Session::wait_for_sites`]).
const FOLLOW_CHECK: Duration = Duration::from_secs(1);

/// A watch on the `KTHREAD.State` of the thread a run's sites follow,
/// which arms them only while the thread is about to run (see
/// [`Session::watch_followed`]).
pub struct FollowWatch {
    /// The temporary write watchpoint's breakpoint id.
    pub id: u32,
    thread: ThreadScope,
    sites: Vec<u32>,
}

/// Whether a thread in `state` is about to run, or runs: Standby or
/// Running. A state that could not be read counts, so the sites stay armed.
fn about_to_run(state: Option<u8>) -> bool {
    state.is_none_or(|state| matches!(state, KTHREAD_STATE_RUNNING | KTHREAD_STATE_STANDBY))
}

/// The error a run following `thread` ends with when the thread exited.
fn followed_thread_exited(thread: &ThreadScope) -> Error {
    Error::DebugInfo(format!(
        "the followed thread ({}) exited before it went on",
        thread.label()
    ))
}

/// How long every vCPU runs when the one executing an instruction waits on
/// the others, so they can answer it.
const RELEASE_WINDOW: Duration = Duration::from_millis(20);

/// How long the held vCPUs are let run, in all, for one instruction before
/// it is given up on. A run ends early when another vCPU reaches a marked
/// site, which in hot code is at once, so the runs are bounded by time
/// rather than counted. The time is the runs' own, not the wall time: the
/// checks between runs can take longer than the runs (the first that finds
/// a vCPU in the Windows hypervisor names its code, over half a second), and
/// would give up on an instruction the vCPUs were barely let run for.
pub const RELEASE_BUDGET: Duration = if cfg!(test) {
    // The mock target never frees a waiting vCPU; don't spin tests for it.
    Duration::from_millis(20)
} else {
    Duration::from_secs(1)
};

/// How much longer than [`RELEASE_BUDGET`] the vCPUs run for the waiting
/// vCPU's handler to come back to NT from a call into the Windows
/// hypervisor (see [`Release::gives_up`]). A spin loop that notifies the
/// hypervisor of its long wait enters it again and again, briefly; the runs
/// end every few milliseconds, so a quarter of the budget looks tens of times.
const RELEASE_GRACE: Duration = Duration::from_nanos(RELEASE_BUDGET.as_nanos() as u64 / 4);

/// Execute the instruction under the (already lifted) breakpoint site at
/// `rip` without a single step, which is unsafe on this backend (see
/// [`STEP_UNDER_WINDOWS_HYPERVISOR`]): plant temporary breakpoints on every
/// address it can continue at, resume this vCPU alone, and take the stop.
/// Other vCPUs stay held, but the vCPU itself can switch to another thread
/// before it gets past, and that thread would run through the lifted site
/// unseen; a debug-register keeper marks the site for it (see
/// [`keeper_slot`]).
fn run_past_site(
    backend: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    debugger: &Target,
    breakpoints: &BreakpointManager,
    thread: &str,
    regs: &[u8],
    rip: u64,
    cr3: Option<u64>,
) -> Result<RunPast> {
    let successors = site_successors(debugger, register_map, thread, regs, rip, cr3)?;
    let sites = temporary_sites(backend, debugger, breakpoints, rip, cr3, &successors)?;
    let keeper = keeper_slot(backend, breakpoints, &sites, successors.len());
    run_past(
        backend,
        register_map,
        debugger,
        breakpoints,
        thread,
        regs,
        &successors,
        &sites,
        keeper,
    )
}

/// The debug-register slot that keeps the lifted site of a run past it
/// marked: the one [`TemporarySites::Hardware`] holds for the instruction
/// itself, or for software sites any slot no breakpoint holds. `None`
/// without one; the site then goes unmarked while its vCPU runs alone.
///
/// A debug register traps on every vCPU, the stepping one too, so that one
/// resumes with `RF` set (see [`pass_keeper`]). Another thread the vCPU
/// switches to stops on the site before executing it, as on the planted
/// breakpoint, which takes its hit once the run is over.
fn keeper_slot(
    backend: &dyn DebugBackend,
    breakpoints: &BreakpointManager,
    sites: &TemporarySites,
    successors: usize,
) -> Option<u8> {
    match sites {
        TemporarySites::Software => breakpoints.free_execute_slots(backend).first().copied(),
        TemporarySites::Hardware(slots) => slots.get(successors).copied(),
    }
}

/// Set `RF` on the selected vCPU when it stands on `rip`, where a keeper
/// would otherwise trap it before it executes the instruction: an execute
/// breakpoint is a fault, and `RF` suppresses it for one instruction.
fn pass_keeper(backend: &mut dyn DebugBackend, register_map: &RegisterMap, rip: u64) -> Result<()> {
    const RF: u64 = 1 << 16;
    let mut regs = backend.read_registers()?;
    if register_map.read_u64("rip", &regs)? != rip {
        return Ok(());
    }
    let eflags = register_map.read_u64("eflags", &regs)?;
    if eflags & RF == 0 {
        register_map.write_u64("eflags", &mut regs, eflags | RF)?;
        backend.write_registers(&regs)?;
    }
    Ok(())
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
    let sites = temporary_sites(backend, debugger, breakpoints, rip, cr3, &successors)?;
    run_past(
        backend,
        register_map,
        debugger,
        breakpoints,
        thread,
        &regs,
        &successors,
        &sites,
        None,
    )
}

/// How to mark `successors` of the instruction at `rip` (root `cr3`).
/// Debug-register sites, in slots no breakpoint holds, where an `int3`
/// must not be written: in secure-kernel code, and, on a backend without
/// user-mode breakpoints, in user space, where a GDB stub would write and
/// lift it through whichever vCPU it has selected, which need not map the
/// page. Software sites elsewhere.
fn temporary_sites(
    backend: &dyn DebugBackend,
    debugger: &Target,
    breakpoints: &BreakpointManager,
    rip: u64,
    cr3: Option<u64>,
    successors: &[u64],
) -> Result<TemporarySites> {
    let secure = debugger.is_secure_address(VirtAddr(rip))
        || cr3.is_some_and(|cr3| debugger.recognize_secure_root(cr3))
        || successors
            .iter()
            .any(|&address| debugger.is_secure_address(VirtAddr(address)));
    let user_space = !backend.supports_user_mode_breakpoints()
        && successors.iter().any(|&address| {
            !BreakpointManager::is_kernel_space(debugger.arch(), VirtAddr(address))
        });
    if !secure && !user_space {
        return Ok(TemporarySites::Software);
    }
    let slots = breakpoints.free_execute_slots(backend);
    if slots.len() < successors.len() {
        let step = if secure {
            "a VTL1 step"
        } else {
            "a step into user space"
        };
        return Err(Error::Breakpoint(format!(
            "{step} at {rip:#x} needs {} free hardware breakpoint slot(s) and {} are free; clear \
             a hardware breakpoint to step",
            successors.len(),
            slots.len()
        )));
    }
    Ok(TemporarySites::Hardware(slots))
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
    /// Whether an `index`th site can be planted.
    fn has_room(&self, index: usize) -> bool {
        match self {
            Self::Software => true,
            Self::Hardware(slots) => index < slots.len(),
        }
    }

    /// Plant the `index`th site at `address`, which [`Self::has_room`] for:
    /// `None` for a software site, the slot for a hardware one.
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
                let slot = slots[index];
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

/// Plant `sites` on every successor, and the `keeper` slot on the
/// instruction at its PC in `regs`, run the vCPU alone past it, and lift
/// them again whatever happened.
fn run_past(
    backend: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    debugger: &Target,
    breakpoints: &BreakpointManager,
    thread: &str,
    regs: &[u8],
    successors: &[u64],
    sites: &TemporarySites,
    keeper: Option<u8>,
) -> Result<RunPast> {
    let mut planted = Vec::with_capacity(successors.len());
    let result = run_to_successors(
        backend,
        register_map,
        debugger,
        breakpoints,
        thread,
        regs,
        successors,
        sites,
        keeper,
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
    breakpoints: &BreakpointManager,
    thread: &str,
    regs: &[u8],
    successors: &[u64],
    sites: &TemporarySites,
    keeper: Option<u8>,
    planted: &mut Vec<(u64, Option<u8>)>,
) -> Result<RunPast> {
    let rip = register_map.read_u64("rip", regs)?;
    for (index, &address) in successors.iter().enumerate() {
        let slot = sites.plant(backend, index, address)?;
        planted.push((address, slot));
    }
    let rsp = register_map.read_u64("rsp", regs).ok();
    // Best effort: without the keeper the site goes unmarked, as it did.
    let mut keeper = keeper.filter(|&slot| {
        backend
            .set_hardware_breakpoint(slot, rip, HwBreakpointAccess::Execute, 1)
            .is_ok()
    });
    if let Some(slot) = keeper {
        planted.push((rip, Some(slot)));
    }
    let nt_thread = keeper.and_then(|_| nt_thread_on(debugger, thread));
    // Stops of the same execution back on the instruction, each resumed
    // with `RF` set again; one that keeps faulting there gets no keeper.
    let mut kept_back = 0;
    let mut release = Release::new(rip, rsp);
    loop {
        if keeper.is_some() {
            pass_keeper(backend, register_map, rip)?;
        }
        backend.continue_current_thread()?;
        let (event, timed_out) = match backend.try_wait_for_stop(RUN_PAST_TIMEOUT)? {
            Some(event) => (event, false),
            // The stop that answers the break-in can be a watchpoint's,
            // which came first.
            None => {
                let event = backend.interrupt()?;
                let broken_in = event.watchpoint_address.is_none();
                (event, broken_in)
            }
        };
        if event.is_bugcheck {
            return Err(Error::DebugInfo(format!(
                "target bugchecked while running past the instruction at {rip:#x}"
            )));
        }
        let now_regs = backend.read_registers()?;
        let now = register_map.read_u64("rip", &now_regs)?;
        step_trace!(
            "run past {thread} at {rip:#x}: {:?} stopped at {now:#x}{}{}",
            event.thread_id,
            if timed_out { ", broken in" } else { "" },
            watch_note(event.watchpoint_address)
        );
        if !timed_out || successors.contains(&now) {
            if now == rip
                && let Some(slot) = keeper
            {
                let same = nt_thread_on(debugger, thread) == nt_thread
                    && register_map.read_u64("rsp", &now_regs).ok() == rsp;
                if !same {
                    // Another execution reached the site, which the
                    // planted breakpoint takes once the run is over.
                    return Ok(RunPast::Diverted);
                }
                kept_back += 1;
                if kept_back > KEEPER_RETRIES {
                    lift_site(backend, rip, Some(slot))?;
                    planted.retain(|&site| site != (rip, Some(slot)));
                    keeper = None;
                }
                continue;
            }
            if now == rip {
                return Err(Error::DebugInfo(format!(
                    "{thread} could not execute the instruction at {rip:#x}: resumed alone, it \
                     stopped on it again; resume with g, disabling any breakpoint there first"
                )));
            }
            // Stopped by itself short of the successors, in the handler of
            // an interrupt taken first, on a watchpoint's hit: a stop for the
            // session to report, not this run's end.
            if !successors.contains(&now)
                && reported_watch_hit(
                    breakpoints,
                    backend.hardware_breakpoint_slots(),
                    event.watchpoint_address,
                    Some(now),
                )
                .is_some()
                && backend.keep_last_stop().is_ok()
            {
                return Ok(RunPast::Kept);
            }
            return Ok(RunPast::Reached);
        }
        // Short of the successors, it waits on a vCPU this holds: in the
        // Windows hypervisor, on the instruction, or in the handler of an
        // interrupt taken first. Let them all run so it can finish.
        let mut in_nt =
            now != rip && outside_nt(debugger, register_map, thread, &now_regs).is_none();
        // Seen in a handler in NT since it was last on the instruction, it
        // is no longer stuck on the instruction.
        let mut handling = in_nt;
        loop {
            if release.gives_up(in_nt, handling) {
                step_trace!(
                    "release of {thread} at {rip:#x} exhausted: {}",
                    release.summary()
                );
                if in_nt {
                    return Ok(RunPast::Diverted);
                }
                return Err(Error::DebugInfo(format!(
                    "{thread} could not execute the instruction at {rip:#x}: resumed alone, it \
                     did not get past it within {RUN_PAST_TIMEOUT:?}, and letting every vCPU \
                     run for {RELEASE_BUDGET:?} did not free it (it waits on another vCPU, in \
                     the Windows hypervisor, or while the hypervisor runs a guest partition's VP \
                     on its processor); resume with g, disabling any breakpoint there first"
                )));
            }
            match release.run(
                backend,
                register_map,
                debugger,
                breakpoints,
                thread,
                successors,
                sites,
                keeper.is_some(),
            )? {
                Released::Reached => {
                    step_trace!(
                        "release of {thread} at {rip:#x} reached: {}",
                        release.summary()
                    );
                    return Ok(RunPast::Reached);
                }
                Released::Diverted => {
                    step_trace!(
                        "release of {thread} at {rip:#x} diverted: {}",
                        release.summary()
                    );
                    return Ok(RunPast::Diverted);
                }
                Released::Back => {
                    step_trace!(
                        "release of {thread} at {rip:#x} back on it: {}",
                        release.summary()
                    );
                    break;
                }
                Released::Kept => {
                    step_trace!(
                        "release of {thread} at {rip:#x} kept a watchpoint's stop: {}",
                        release.summary()
                    );
                    return Ok(RunPast::Kept);
                }
                Released::Waiting { in_handler } => {
                    in_nt = in_handler;
                    handling |= in_handler;
                }
            }
        }
    }
}

/// What vCPU `thread`, with registers `regs`, runs instead of NT, if
/// anything: the Windows hypervisor, or a guest partition's VP that the
/// hypervisor put on its processor ([`guest_vp_running`]), whose registers
/// the vCPU then shows. Either way NT is not running there, and waits.
fn outside_nt(
    debugger: &Target,
    register_map: &RegisterMap,
    thread: &str,
    regs: &[u8],
) -> Option<String> {
    let value = |name| register_map.read_u64(name, regs).ok();
    let (cr3, rip) = (value(debugger.arch().dtb_register())?, value("rip")?);
    if halted_in_windows_hypervisor(debugger, cr3, rip) {
        return Some("the Windows hypervisor".to_string());
    }
    let processor = processor_index_from_backend_thread_id(thread);
    guest_vp_running(debugger, cr3, rip, processor).map(|vp| format!("{vp} of a guest partition"))
}

/// ", watch <address>" for a stop that reported the data address a
/// watchpoint trapped on, for the step trace.
fn watch_note(watch: Option<u64>) -> String {
    watch
        .map(|address| format!(", watch {address:#x}"))
        .unwrap_or_default()
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
    /// Running another Windows thread (the step's was switched out), or
    /// stopped on a breakpoint in the handler: the step ends where the vCPU
    /// is.
    Diverted,
    /// A vCPU stopped on a watchpoint's hit, whose stop the backend keeps
    /// for the session (see [`RunPast::Kept`]): the step ends there.
    Kept,
}

/// Letting every vCPU run while one executing an instruction at `rip` waits
/// on them. The instruction stays marked, so the vCPU stops on it if it
/// returns there without executing it; the successors stay marked, so it
/// stops past it. Another vCPU can stop on one of those too, ending that
/// run early, or on any breakpoint; it executes the instruction once the
/// step is over and they are lifted. Until then it traps again each time
/// it is resumed, so it would end every run within a round trip, leaving
/// the waiting vCPU almost no time. Such a parked vCPU is held for every
/// other run, and resumed with the runs between, where it takes its
/// pending interrupts before it traps again: holding it for good can hold
/// the very vCPU the hypervisor waits for (an IPI's target). A
/// watchpoint's hit ends the release instead: a watchpoint traps after the
/// access, so the vCPU resumed would not stop on it again, and the hit
/// would be lost.
struct Release {
    rip: u64,
    rsp: Option<u64>,
    /// The Windows thread on the vCPU when it first waited.
    nt_thread: Option<Option<u64>>,
    /// When the first run began, for the step trace.
    started: Option<Instant>,
    /// The runs so far, and how long the target ran in them, which
    /// [`RELEASE_BUDGET`] bounds.
    runs: u32,
    ran: Duration,
    /// Every vCPU's backend thread, listed for the first run that holds one.
    vcpus: Vec<String>,
    /// The other vCPUs seen stopped on a site, and its address, which each
    /// traps on again at once when resumed.
    parked: Vec<(String, u64)>,
    /// The runs that held the parked vCPUs, for the step trace.
    held: u32,
    /// Whether the last run held them, so the next resumes them.
    holding: bool,
}

impl Release {
    fn new(rip: u64, rsp: Option<u64>) -> Self {
        Self {
            rip,
            rsp,
            nt_thread: None,
            started: None,
            runs: 0,
            ran: Duration::ZERO,
            vcpus: Vec::new(),
            parked: Vec::new(),
            held: 0,
            holding: false,
        }
    }

    /// Whether to stop letting the vCPUs run once they have run for
    /// [`RELEASE_BUDGET`]: the step then ends where the waiting vCPU is, in
    /// a handler in NT (`in_nt`), or fails. A handler can be in the Windows
    /// hypervisor only for a moment, in a call it makes (a spin loop's
    /// long-wait notification), where no step can end; one seen in NT
    /// before (`handling`) gets [`RELEASE_GRACE`] more to come back, rather
    /// than failing the step for where that moment fell.
    fn gives_up(&self, in_nt: bool, handling: bool) -> bool {
        self.ran >= RELEASE_BUDGET
            && (in_nt || !handling || self.ran >= RELEASE_BUDGET + RELEASE_GRACE)
    }

    /// The runs so far, for the step trace.
    fn summary(&self) -> String {
        format!(
            "{} runs, ran {:?} in {:?}, {} holding parked vCPUs",
            self.runs,
            self.ran,
            self.started
                .map(|started| started.elapsed())
                .unwrap_or_default(),
            self.held
        )
    }

    /// The vCPUs the next run resumes: all but the parked ones every other
    /// run while some are parked, else `None` for every vCPU.
    fn next_runners(
        &mut self,
        backend: &mut dyn DebugBackend,
        thread: &str,
    ) -> Result<Option<Vec<String>>> {
        self.holding = !self.parked.is_empty() && !self.holding;
        if !self.holding {
            return Ok(None);
        }
        if self.vcpus.is_empty() {
            self.vcpus = backend.thread_list()?;
        }
        let mut runners: Vec<String> = self
            .vcpus
            .iter()
            .filter(|&vcpu| !self.parked.iter().any(|(parked, _)| parked == vcpu))
            .cloned()
            .collect();
        if !runners.iter().any(|vcpu| vcpu == thread) {
            runners.push(thread.to_string());
        }
        Ok(Some(runners))
    }

    /// Note where the other vCPUs that ended a run stand: `stopper` stopped
    /// on its own at `stopper_rip`. A vCPU resumed by the run that is still
    /// on its site trapped there again (or never left it); one that moved
    /// took an interrupt, and the handler went on.
    fn note_parked(
        &mut self,
        backend: &mut dyn DebugBackend,
        register_map: &RegisterMap,
        stopper: Option<&str>,
        stopper_rip: Option<u64>,
    ) {
        if !self.holding {
            let parked = mem::take(&mut self.parked);
            self.parked = parked
                .into_iter()
                .filter(|(vcpu, at)| {
                    Some(vcpu.as_str()) != stopper
                        && rip_of(backend, register_map, vcpu) == Some(*at)
                })
                .collect();
        }
        if let (Some(vcpu), Some(at)) = (stopper, stopper_rip) {
            self.parked.push((vcpu.to_string(), at));
        }
    }

    fn run(
        &mut self,
        backend: &mut dyn DebugBackend,
        register_map: &RegisterMap,
        debugger: &Target,
        breakpoints: &BreakpointManager,
        thread: &str,
        successors: &[u64],
        sites: &TemporarySites,
        kept: bool,
    ) -> Result<Released> {
        self.started.get_or_insert_with(Instant::now);
        let nt_thread = *self
            .nt_thread
            .get_or_insert_with(|| nt_thread_on(debugger, thread));
        let runners = self.next_runners(backend, thread)?;
        // A keeper marks the instruction already. Without one, or a slot
        // left for it, it goes unmarked: a vCPU returning to it runs it,
        // and stops on a successor.
        let site = if kept || successors.contains(&self.rip) || !sites.has_room(successors.len()) {
            None
        } else {
            Some(sites.plant(backend, successors.len(), self.rip)?)
        };
        // Whichever vCPU stops first ends the run, or a break-in does.
        self.runs += 1;
        let run_started = Instant::now();
        let resumed = match &runners {
            Some(runners) => backend.continue_threads(runners),
            None => backend.continue_execution(),
        };
        let stop = resumed.and_then(|()| {
            Ok(match backend.try_wait_for_stop(RELEASE_WINDOW)? {
                Some(event) => (event.thread_id, event.watchpoint_address),
                None => {
                    // A watchpoint's stop can answer the break-in.
                    let event = backend.interrupt()?;
                    match event.watchpoint_address {
                        Some(watch) => (event.thread_id, Some(watch)),
                        None => (None, None),
                    }
                }
            })
        });
        self.ran += run_started.elapsed();
        if let Some(slot) = site {
            let lifted = lift_site(backend, self.rip, slot);
            if stop.is_ok() {
                lifted?;
            }
        }
        let (stopped, watch) = stop?;
        if runners.is_some() {
            self.held += 1;
        }
        // Which other vCPU ended the run, and where: one stopped on a site
        // ends every run after at once, and a watchpoint's hit is told from
        // a site's by it.
        let stopper = stopped.as_deref().filter(|&by| by != thread);
        let stopper_rip = stopper.and_then(|by| rip_of(backend, register_map, by));
        backend.set_current_thread(thread)?;
        let regs = backend.read_registers()?;
        let now = register_map.read_u64("rip", &regs)?;
        // NT does not run on the vCPU while it is in the hypervisor, or runs
        // a guest partition's VP: whatever NT's thread was is not what the
        // vCPU shows, so the step waits for NT to run there again.
        let outside = outside_nt(debugger, register_map, thread, &regs);
        step_trace!(
            "release run {} of {thread}{}: {}{}; {thread} at {now:#x}{}",
            self.runs,
            if runners.is_some() {
                format!(
                    " holding {}",
                    self.parked
                        .iter()
                        .map(|(vcpu, _)| vcpu.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            } else {
                String::new()
            },
            match (stopped.as_deref(), stopper_rip) {
                (None, _) => "broken in".to_string(),
                (Some(by), Some(rip)) => format!("{by} stopped at {rip:#x}"),
                (Some(by), None) => format!("{by} stopped"),
            },
            watch_note(watch),
            outside
                .as_ref()
                .map(|place| format!(" in {place}"))
                .unwrap_or_default()
        );
        // The vCPU's own stop at a successor, or back on the instruction,
        // ends its step whatever else it reports.
        let own_end =
            stopped.as_deref() == Some(thread) && (successors.contains(&now) || now == self.rip);
        let stopper_pc = match stopped.as_deref() {
            Some(by) if by == thread => Some(now),
            _ => stopper_rip,
        };
        if !own_end
            && reported_watch_hit(
                breakpoints,
                backend.hardware_breakpoint_slots(),
                watch,
                stopper_pc,
            )
            .is_some()
            && backend.keep_last_stop().is_ok()
        {
            return Ok(Released::Kept);
        }
        self.note_parked(backend, register_map, stopper, stopper_rip);
        backend.set_current_thread(thread)?;
        if outside.is_some() {
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
        // Stopped by itself short of the marked sites, it hit a breakpoint
        // (or the bugcheck trap) in the handler: the step ends there.
        if stopped.as_deref() == Some(thread) {
            return Ok(Released::Diverted);
        }
        Ok(Released::Waiting { in_handler: true })
    }
}

/// The `_ETHREAD` NT runs on the processor backend `thread` stands for.
fn nt_thread_on(debugger: &Target, thread: &str) -> Option<u64> {
    let processor = processor_index_from_backend_thread_id(thread)?;
    debugger
        .current_ethread_for_processor(processor)
        .ok()
        .map(|ethread| ethread.0)
}

/// The IP of the halted vCPU backend `thread` stands for, which it selects.
fn rip_of(backend: &mut dyn DebugBackend, register_map: &RegisterMap, thread: &str) -> Option<u64> {
    backend.set_current_thread(thread).ok()?;
    let registers = backend.read_registers().ok()?;
    register_map.read_u64("rip", &registers).ok()
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
    let mut bytes = [0u8; 16];
    debugger
        .address_space(code_root(debugger, cr3, rip))
        .read_bytes(VirtAddr(rip), &mut bytes)?;
    instruction_successors(debugger, register_map, thread, regs, rip, cr3, &bytes)
}

/// [`site_successors`] of the instruction `bytes` at `rip`.
fn instruction_successors(
    debugger: &Target,
    register_map: &RegisterMap,
    thread: &str,
    regs: &[u8],
    rip: u64,
    cr3: Option<u64>,
    bytes: &[u8; 16],
) -> Result<Vec<u64>> {
    // The vCPU fetches the instruction and follows its pointers through its
    // own root. Without one, a module's own root serves its code.
    let memory = debugger.address_space(code_root(debugger, cr3, rip));
    let bitness = debugger.code_bitness(VirtAddr(rip));
    let instruction = Decoder::with_ip(bitness, bytes, rip, DecoderOptions::NONE).decode();
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
    // The secure kernel enters system calls and interrupts through its own
    // entry and IDT, which NT's symbols and tables do not describe, and a
    // hypercall there can return to VTL0 instead of the next instruction.
    let vtl1 = debugger.is_secure_address(VirtAddr(rip))
        || cr3.is_some_and(|cr3| debugger.recognize_secure_root(cr3));
    let through_nt_tables = matches!(
        instruction.code(),
        Code::Syscall | Code::Vmcall | Code::Vmmcall | Code::Int_imm8 | Code::Int3 | Code::Int1
    ) || matches!(
        instruction.mnemonic(),
        Mnemonic::Into | Mnemonic::Ud0 | Mnemonic::Ud1 | Mnemonic::Ud2
    );
    if vtl1 && through_nt_tables {
        return Err(Error::DebugInfo(format!(
            "cannot step the instruction at {rip:#x}: in VTL1, `{}` continues through the \
             secure kernel's own entry or IDT, or returns to VTL0, which is not known from \
             here; resume with g",
            format!("{:?}", instruction.mnemonic()).to_ascii_lowercase()
        )));
    }
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

/// The lowest stack pointer an execution at `sp` has once past
/// `instruction`, for a pop, push, call, return, `enter`, or `add`/`sub` of
/// an immediate; `sp` for one that leaves the stack pointer alone. `None`
/// when it is not known from here: an instruction that switches stacks
/// (interrupts, system calls and their returns, far transfers) or sets the
/// stack pointer some other way (`mov`, `and`, `leave`, ...).
pub fn stack_floor(instruction: &Instruction, sp: u64) -> Option<u64> {
    let switches_stack = matches!(
        instruction.mnemonic(),
        Mnemonic::Iret
            | Mnemonic::Iretd
            | Mnemonic::Iretq
            | Mnemonic::Syscall
            | Mnemonic::Sysret
            | Mnemonic::Sysretq
            | Mnemonic::Sysenter
            | Mnemonic::Sysexit
            | Mnemonic::Sysexitq
            | Mnemonic::Int
            | Mnemonic::Int1
            | Mnemonic::Int3
            | Mnemonic::Into
            | Mnemonic::Ud0
            | Mnemonic::Ud1
            | Mnemonic::Ud2
            | Mnemonic::Retf
    ) || instruction.is_jmp_far()
        || instruction.is_call_far()
        || instruction.is_jmp_far_indirect()
        || instruction.is_call_far_indirect();
    if switches_stack {
        return None;
    }
    let lowered_by = |delta: i64| Some(sp.wrapping_add_signed(delta.min(0)));
    let increment = instruction.stack_pointer_increment();
    if increment != 0 {
        return lowered_by(i64::from(increment));
    }
    let writes_sp = InstructionInfoFactory::new()
        .info(instruction)
        .used_registers()
        .iter()
        .any(|used| {
            used.register().full_register() == Register::RSP
                && matches!(
                    used.access(),
                    OpAccess::Write
                        | OpAccess::CondWrite
                        | OpAccess::ReadWrite
                        | OpAccess::ReadCondWrite
                )
        });
    if !writes_sp {
        return Some(sp);
    }
    if instruction.op0_kind() != OpKind::Register
        || instruction.op0_register().full_register() != Register::RSP
    {
        return None;
    }
    let immediate = match instruction.op1_kind() {
        OpKind::Immediate8to64 | OpKind::Immediate32to64 => instruction.immediate(1) as i64,
        OpKind::Immediate8to32 | OpKind::Immediate32 => {
            i64::from(instruction.immediate(1) as u32 as i32)
        }
        OpKind::Immediate8to16 | OpKind::Immediate16 => {
            i64::from(instruction.immediate(1) as u16 as i16)
        }
        _ => return None,
    };
    match instruction.mnemonic() {
        Mnemonic::Add => lowered_by(immediate),
        Mnemonic::Sub => lowered_by(immediate.wrapping_neg()),
        _ => None,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn release_that_ran(ran: Duration) -> Release {
        Release {
            ran,
            ..Release::new(0x1000, None)
        }
    }

    /// Once the vCPUs have run for the budget, a step whose vCPU waits in
    /// a handler in NT ends there, and one whose vCPU never left the
    /// instruction fails. A handler caught in the Windows hypervisor, in a
    /// call it makes, gets the grace to come back to NT first: giving up
    /// there failed the step for where the last run happened to end.
    #[test]
    fn a_handler_in_the_hypervisor_when_the_budget_is_spent_gets_the_grace() {
        let short = release_that_ran(RELEASE_BUDGET - Duration::from_millis(1));
        assert!(!short.gives_up(false, true));
        assert!(!short.gives_up(true, true));
        let spent = release_that_ran(RELEASE_BUDGET);
        assert!(spent.gives_up(true, true), "in a handler in NT");
        assert!(spent.gives_up(false, false), "never left the instruction");
        assert!(!spent.gives_up(false, true), "a handler in the hypervisor");
        let late = release_that_ran(RELEASE_BUDGET + RELEASE_GRACE);
        assert!(late.gives_up(false, true), "past the grace");
    }
}
