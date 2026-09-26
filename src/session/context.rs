//! The inspection selection: the current vCPU, a parked Windows thread, a
//! selected frame, and the register file and address space they imply.

use std::collections::HashMap;

use crate::dbg_backend::{DebugCapability, processor_index_from_backend_thread_id};
use crate::error::{Error, Result};
use crate::gdb::RegisterMap;
use crate::memory::DTB_IDENTITY;
use crate::session::{Selection, Session, ThreadContext, VcpuInfo};
use crate::target::{HYPERVISOR_CONTEXT, SelectedFrame, Target, ThreadInfo};
use crate::types::VirtAddr;
use crate::unwind::{
    RecoveredStackTrace, build_stacktrace_with_context, build_stacktrace_with_register_values,
    resolve_thread_trace_context_at, saved_vtl_summary, try_format_symbol,
};

pub(super) fn update_target_context_from_registers(
    target: &mut Target,
    register_map: &RegisterMap,
    registers: Result<Vec<u8>>,
) {
    target.selected_frame = None;
    let Ok(registers) = registers else {
        target.registers = None;
        target.clear_context_dtb_override();
        return;
    };
    target.registers = Some(register_map.to_hashmap(&registers));
    match register_map.read_u64(target.arch().dtb_register(), &registers) {
        // For triage dumps all modules are loaded with DTB_IDENTITY and
        // memory reads use identity mapping, so the context DTB from the
        // CONTEXT
        // record is meaningless.  Setting it here would cause a DTB
        // mismatch that makes symbol lookup, type resolution, and eval
        // fail.
        Ok(dtb) if dtb != 0 && target.guest.is_some() && target.kernel_dtb() != DTB_IDENTITY => {
            target.recognize_secure_root(dtb);
            target.set_context_dtb_override(dtb)
        }
        _ => target.clear_context_dtb_override(),
    }
}

/// [`Error::TargetRunning`] payload for the live register file.
const REGISTERS_NEED_HALT: &str = "Registers belong to the halted context.";

impl Session {
    /// Select `id` as the current inspection thread (e.g. a vCPU id), so
    /// registers/backtrace/step operate on it. Validates the id against the
    /// backend. Shared by the REPL's `thread`/`vcpu` commands and the SDKs.
    pub fn set_current_thread(&mut self, id: &str) -> Result<()> {
        self.backend.set_current_thread(id)?;
        self.target.selected_frame = None;
        self.current_thread = id.to_string();
        self.refresh_context_for_current_thread();
        Ok(())
    }

    /// Select a non-running Windows thread for metadata and stack inspection
    /// without changing the backend vCPU. This deliberately does not attempt to
    /// manufacture a register context for the parked thread.
    pub fn select_parked_windows_thread(&mut self, thread: &ThreadInfo) {
        self.target.selected_frame = None;
        self.parked_windows_thread = Some(thread.ethread);
        self.target.set_parked_windows_thread(thread.clone());
    }

    /// Install a debugger-selected frame/context as the inspection context:
    /// its recovered registers shadow the live ones and its address space
    /// becomes the expression/memory scope. Shared by the REPL's `.frame` /
    /// `.cxr` / `.trap` and the DAP frame selection so the two can't drift.
    pub fn select_frame(&mut self, selected: SelectedFrame) {
        self.target.select_frame(selected);
    }

    pub fn parked_windows_thread(&self) -> Option<&ThreadInfo> {
        let ethread = self.parked_windows_thread?;
        self.target
            .windows_thread_selection
            .as_ref()
            .filter(|thread| thread.ethread == ethread)
    }

    /// Every Windows thread the target knows plus the ones currently on a
    /// vCPU (which a mid-creation walk may not list yet). The candidate set
    /// for selecting a thread by tid/ETHREAD/KTHREAD.
    pub fn windows_thread_candidates(&mut self) -> Result<Vec<ThreadInfo>> {
        let mut threads = self.target.enumerate_threads()?;
        let active = self.active_thread_map();
        for (_, thread) in active.values() {
            if !threads.iter().any(|known| known.ethread == thread.ethread) {
                threads.push(thread.clone());
            }
        }
        if threads.is_empty()
            && let Some(thread) = self.target.windows_thread_selection.clone()
        {
            threads.push(thread);
        }
        Ok(threads)
    }

    /// The one Windows thread `value` names: a thread id, an ETHREAD, or a
    /// KTHREAD address. Ambiguity (a tid colliding with an address) is an
    /// error rather than a guess.
    pub fn find_windows_thread(&mut self, value: u64) -> Result<ThreadInfo> {
        let matches: Vec<ThreadInfo> = self
            .windows_thread_candidates()?
            .into_iter()
            .filter(|thread| {
                thread.tid == Some(value) || thread.ethread.0 == value || thread.kthread.0 == value
            })
            .collect();
        match matches.len() {
            1 => Ok(matches.into_iter().next().unwrap()),
            0 => Err(Error::DebugInfo(format!(
                "no Windows thread matches {value:#x} (tid, ETHREAD, or KTHREAD)"
            ))),
            many => Err(Error::DebugInfo(format!(
                "ambiguous Windows thread {value:#x}: {many} matches"
            ))),
        }
    }

    /// Make `thread` the inspection context (`.thread`): a thread that is on
    /// a vCPU switches to that vCPU (see [`Self::select_running_windows_thread`]);
    /// any other thread is parked (stack-only, no coherent register file).
    pub fn select_windows_thread(&mut self, thread: &ThreadInfo) -> Result<ThreadContext> {
        let active = self.active_thread_map();
        match active.get(&thread.ethread.0) {
            Some((vcpu, _)) => {
                let vcpu = vcpu.clone();
                self.select_running_windows_thread(&vcpu, thread)
            }
            None => {
                self.select_parked_windows_thread(thread);
                Ok(ThreadContext::Parked)
            }
        }
    }

    /// Switch to `vcpu` with `thread`, the Windows thread it runs, as the
    /// inspection context. A vCPU halted in the Windows hypervisor holds the
    /// hypervisor's registers, not the thread's: switching to it selects the
    /// VTL0 state the hypervisor saved (see
    /// [`Self::select_stop_context_default`]), so registers, `k`, and
    /// expressions see where NT left off. Without a saved state (no eVMCS)
    /// the vCPU's own registers stay the context.
    pub fn select_running_windows_thread(
        &mut self,
        vcpu: &str,
        thread: &ThreadInfo,
    ) -> Result<ThreadContext> {
        self.set_current_thread(vcpu)?;
        self.target
            .set_current_windows_thread_context(thread.clone());
        // Switching vCPUs drops any selection, so a selected context now is
        // the saved VTL0 state the switch installed.
        Ok(if self.target.selected_frame.is_some() {
            ThreadContext::SavedVtl0(vcpu.to_string())
        } else {
            ThreadContext::Live(vcpu.to_string())
        })
    }

    /// The default inspection context of the current vCPU at a stop: its own
    /// registers, or, when it is halted in the Windows hypervisor, where NT
    /// left off (the saved VTL0 state; `.cxr` returns to the hypervisor's).
    /// Leaves an existing selection or a parked thread alone.
    pub(super) fn select_stop_context_default(&mut self) {
        if self.parked_windows_thread.is_none() && !self.backend.is_running() {
            self.target.select_saved_vtl0(&self.current_thread);
        }
    }

    /// Drop any selected frame or context and return to the stop's default
    /// ([`Self::select_stop_context_default`]). A host that forgets its frame
    /// handles at a stop (DAP) resets through this, so it lands where the
    /// console does.
    pub fn reset_to_stop_context(&mut self) {
        // Whatever dropped the selection (`.process` attaching drops it too)
        // may have left its registers behind: start from the vCPU's own.
        self.target.selected_frame = None;
        self.restore_live_register_cache();
        self.select_stop_context_default();
    }

    /// The backend vCPU of each NT processor, by processor index. Empty when
    /// the backend cannot list its vCPUs.
    pub fn processor_vcpus(&mut self) -> HashMap<u16, String> {
        self.backend
            .thread_list()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|vcpu| Some((processor_index_from_backend_thread_id(&vcpu)?, vcpu)))
            .collect()
    }

    /// Drop any Windows-thread selection and return to the backend's current
    /// vCPU context and the thread it is running (`.thread` with no argument).
    pub fn reset_windows_thread(&mut self) -> Result<()> {
        let current = self.current_thread.clone();
        self.set_current_thread(&current)
    }

    /// Move the whole inspection selection out (process scope, frame, parked
    /// thread, vCPU), leaving the session detached on the same vCPU. A host
    /// that scopes one operation itself (the Python SDK binds every handle to
    /// its own address space) runs it between this and
    /// [`Self::restore_selection`], so the user's `.process`/`.thread`/`.frame`
    /// choice survives untouched.
    pub fn take_selection(&mut self) -> Selection {
        Selection {
            target: self.target.take_selection(),
            current_thread: self.current_thread.clone(),
            parked_windows_thread: self.parked_windows_thread.take(),
        }
    }

    /// Put back a selection taken with [`Self::take_selection`], switching the
    /// backend back to its vCPU if the operation moved it.
    pub fn restore_selection(&mut self, selection: Selection) -> Result<()> {
        let switched = if self.current_thread != selection.current_thread {
            self.backend.set_current_thread(&selection.current_thread)
        } else {
            Ok(())
        };
        self.current_thread = selection.current_thread;
        self.parked_windows_thread = selection.parked_windows_thread;
        self.target.restore_selection(selection.target);
        switched
    }

    /// Select stack frame `index` (`.frame N`) of the current live thread as
    /// the inspection context, so registers, locals, and expressions see that
    /// frame's recovered register file. Returns the frame. A parked thread has
    /// no register file to unwind from and is refused.
    pub fn select_frame_index(&mut self, index: usize) -> Result<SelectedFrame> {
        const MAX_FRAME_INDEX: usize = 4096;
        if index > MAX_FRAME_INDEX {
            return Err(Error::InvalidArgument("frame index is too large".into()));
        }
        let (trace, seed, live) = self.recovered_live_trace(index.saturating_add(1))?;
        let selected = SelectedFrame::from_recovered(&trace, index, Some(&seed), live)
            .ok_or_else(|| Error::DebugInfo(format!("frame {index} is unavailable")))?;
        self.select_frame(selected.clone());
        Ok(selected)
    }

    /// Refill the target's register cache from the live backend context, or
    /// clear it while the VM runs, so expression evaluation follows the
    /// current thread's address space. A parked thread has no register file:
    /// its process's address space is the scope again.
    pub fn restore_live_register_cache(&mut self) {
        if let Some(thread) = self.parked_windows_thread().cloned() {
            self.target.registers = None;
            self.target.scope_to_parked_thread(&thread);
            return;
        }
        let registers = if self.backend.is_running() {
            Err(Error::TargetRunning(REGISTERS_NEED_HALT))
        } else {
            self.read_registers()
        };
        update_target_context_from_registers(&mut self.target, &self.register_map, registers);
    }

    /// Forget a selected frame/context and go back to the live register file
    /// (`.frame` reset / `.cxr` with no argument).
    pub fn clear_selected_frame(&mut self) {
        if self.target.selected_frame.take().is_some() {
            self.restore_live_register_cache();
        }
    }

    /// Unwind `limit` frames from the current context: the selected frame's
    /// seed registers when one is selected, else the live vCPU file. Returns
    /// the trace, the seed register values, and whether that seed is the
    /// vCPU's own register file (a `.cxr`/`.trap` context is not).
    pub fn recovered_live_trace(
        &mut self,
        limit: usize,
    ) -> Result<(RecoveredStackTrace, HashMap<String, u64>, bool)> {
        if let Some(selected) = self.target.selected_frame.as_ref() {
            let seed = if selected.seed_registers.is_empty() {
                &selected.registers
            } else {
                &selected.seed_registers
            };
            let seed = seed.clone();
            let trace = build_stacktrace_with_register_values(
                &self.target,
                &self.register_map,
                &seed,
                limit,
            );
            return Ok((trace, seed, selected.seed_live));
        }
        if self.parked_windows_thread().is_some() {
            return Err(Error::DebugInfo(
                "frame selection requires a live register context; use `vcpu <id>`".into(),
            ));
        }
        let registers = self.read_registers()?;
        let seed = self.register_map.to_hashmap(&registers);
        let trace =
            build_stacktrace_with_context(&self.target, &self.register_map, &registers, limit);
        Ok((trace, seed, true))
    }

    /// Whether the current vCPU is halted in the Windows hypervisor's code.
    fn vcpu_halted_in_hypervisor(&mut self) -> Result<bool> {
        if self.backend.is_running() {
            return Ok(false);
        }
        let registers = self
            .backend
            .set_current_thread(&self.current_thread)
            .and_then(|()| self.backend.read_registers())?;
        let value = |name| self.register_map.read_u64(name, &registers).ok();
        let (Some(cr3), Some(rip)) = (value(self.target.arch().dtb_register()), value("rip"))
        else {
            return Ok(false);
        };
        Ok(
            resolve_thread_trace_context_at(&self.target, cr3, rip).description
                == HYPERVISOR_CONTEXT,
        )
    }

    /// Refuse to step a vCPU halted in the Windows hypervisor: the step would
    /// run hypervisor code, not the NT code the stop shows, and plant its
    /// temporary sites in the hypervisor's image.
    pub(super) fn require_steppable_vcpu(&mut self) -> Result<()> {
        self.require_live_register_context()?;
        if self.vcpu_halted_in_hypervisor()? {
            return Err(Error::DebugInfo(format!(
                "{} is halted in the Windows hypervisor: a step would run hypervisor code, not \
                 the NT code shown. Resume with g, or stop in NT with a breakpoint",
                self.current_thread
            )));
        }
        Ok(())
    }

    pub(super) fn require_live_register_context(&self) -> Result<()> {
        if self.parked_windows_thread().is_some() {
            return Err(Error::DebugInfo(
                "selected Windows thread is parked; registers and execution control require a live vCPU context (use `vcpu <id>`)".into(),
            ));
        }
        Ok(())
    }

    /// Align the inspection context to the currently selected thread's address
    /// space: when halted, read that thread's registers and set
    /// `target.registers` and `context_dtb_override` from its CR3 (or ARM64
    /// TTBR0), so reads,
    /// steps, and breakpoint installs scope to the focused thread rather than
    /// an earlier stop on another thread. Called from the thread-selection entry
    /// points; `continue_until_break` establishes the same context inline. Best-
    /// effort and a no-op while the guest runs (no coherent register file).
    /// Make the current vCPU the inspection context: its registers, and the
    /// Windows thread it is running (what `!thread` and `$thread` read).
    pub(super) fn refresh_context_for_current_thread(&mut self) {
        self.parked_windows_thread = None;
        self.target.clear_current_windows_thread_context();
        if self.backend.is_running() {
            return;
        }
        let registers = self
            .backend
            .set_current_thread(&self.current_thread)
            .and_then(|_| self.backend.read_registers());
        update_target_context_from_registers(&mut self.target, &self.register_map, registers);
        refresh_windows_thread_context_for_backend_thread(&mut self.target, &self.current_thread);
        self.select_stop_context_default();
    }

    /// Best-effort current RIP of the selected thread (0 if unreadable).
    pub fn current_rip(&mut self) -> u64 {
        self.backend
            .read_registers()
            .ok()
            .and_then(|r| {
                self.register_map
                    .read_u64("rip", &r)
                    .or_else(|_| self.register_map.read_u64("pc", &r))
                    .ok()
            })
            .unwrap_or(0)
    }

    /// Read the selected live vCPU register file. A parked Windows thread is a
    /// stack-only inspection target and must never fall through to the backend's
    /// unrelated live register context.
    pub fn read_registers(&mut self) -> Result<Vec<u8>> {
        self.require_live_register_context()?;
        if self.backend.is_running() {
            return Err(Error::TargetRunning(REGISTERS_NEED_HALT));
        }
        self.backend.set_current_thread(&self.current_thread)?;
        self.backend.read_registers()
    }

    /// Set a single register on the current thread by name, as a read-modify-
    /// write of the register file (read all, patch the one, write back).
    pub fn write_register(&mut self, name: &str, value: u64) -> Result<()> {
        self.patch_registers(|map, regs| map.write_u64(name, regs, value))
    }

    /// Read-modify-write the current thread's register file: `patch` edits the
    /// raw file laid out by [`Self::register_map`], which is written back and
    /// becomes the live frame's register view.
    pub fn patch_registers(
        &mut self,
        patch: impl FnOnce(&RegisterMap, &mut [u8]) -> Result<()>,
    ) -> Result<()> {
        self.require_live_register_context()?;
        // A recovered context (a caller frame, `.cxr`, a thread's saved VTL0
        // state) is not the vCPU's register file; writing would change the
        // vCPU's instead.
        if self
            .target
            .selected_frame
            .as_ref()
            .is_some_and(|frame| !frame.is_live())
        {
            return Err(Error::DebugInfo(
                "the selected context's registers are recovered, not the vCPU's, and are read-only"
                    .into(),
            ));
        }
        if self.backend.is_running() {
            return Err(Error::TargetRunning(REGISTERS_NEED_HALT));
        }
        // The hypervisor's own registers: changing them would corrupt it,
        // and it is not what a Windows debugger is editing.
        if self.vcpu_halted_in_hypervisor()? {
            return Err(Error::DebugInfo(format!(
                "{} is halted in the Windows hypervisor, whose registers are read-only",
                self.current_thread
            )));
        }
        if !self
            .backend
            .capabilities()
            .iter()
            .any(|entry| entry.capability == DebugCapability::WriteRegisters && entry.supported)
        {
            return Err(Error::RegisterWriteUnsupported);
        }
        let mut regs = self.read_registers()?;
        if self
            .register_map
            .read_u64(self.target.arch().dtb_register(), &regs)
            .is_ok_and(|dtb| self.target.recognize_secure_root(dtb))
        {
            return Err(Error::DebugInfo("VTL1 registers are read-only".into()));
        }
        patch(&self.register_map, &mut regs)?;
        self.backend.write_registers(&regs)?;
        let values = self.register_map.to_hashmap(&regs);
        // A live frame 0 selection is this register file; keep it, and the
        // seed a `.frame N` walk starts from, in step with the write.
        if let Some(frame) = self
            .target
            .selected_frame
            .as_mut()
            .filter(|frame| frame.is_live())
        {
            frame.registers.clone_from(&values);
            frame.seed_registers.clone_from(&values);
        }
        self.target.registers = Some(values);
        Ok(())
    }

    /// Inspect every backend execution context (vCPU): its RIP, the address space
    /// it is running in (kernel / a process / unknown), and the nearest symbol.
    /// Selects each vCPU in turn to read its register file, then restores the
    /// originally-stopped one. The VM must be halted.
    pub fn vcpus(&mut self) -> Result<Vec<VcpuInfo>> {
        let original = self.backend.stopped_thread_id()?;
        let threads = self.backend.thread_list()?;
        let mut out = Vec::with_capacity(threads.len());
        for thread in &threads {
            let regs = self
                .backend
                .set_current_thread(thread)
                .and_then(|_| self.backend.read_registers());
            out.push(match regs {
                Ok(regs) => self.describe_vcpu(thread, &regs),
                Err(e) => VcpuInfo {
                    id: thread.clone(),
                    rip: None,
                    context: String::new(),
                    symbol: None,
                    saved_vtl: Vec::new(),
                    error: Some(e.to_string()),
                },
            });
        }

        let _ = self.backend.set_current_thread(&original);
        Ok(out)
    }

    /// What vCPU `id`, whose register file is `regs`, is running: the address
    /// space, the nearest symbol (code outside NT named for what it is, such
    /// as the Windows hypervisor), and, in the hypervisor, where its VTLs left
    /// off.
    pub(super) fn describe_vcpu(&self, id: &str, regs: &[u8]) -> VcpuInfo {
        let (Ok(rip), Ok(dtb)) = (
            self.register_map.read_u64("rip", regs),
            self.register_map
                .read_u64(self.target.arch().dtb_register(), regs),
        ) else {
            return VcpuInfo {
                id: id.to_string(),
                rip: None,
                context: String::new(),
                symbol: None,
                saved_vtl: Vec::new(),
                error: None,
            };
        };

        // RIP=0 means the dump did not capture this CPU's context
        if rip == 0 {
            return VcpuInfo {
                id: id.to_string(),
                rip: Some(0),
                context: "no context".to_string(),
                symbol: None,
                saved_vtl: Vec::new(),
                error: None,
            };
        }

        let dtb_mask = self.target.arch().dtb_page_mask();
        let dtb_masked = dtb & dtb_mask;
        let kernel_dtb_masked = self
            .target
            .guest
            .as_ref()
            .map(|g| g.ntoskrnl.dtb() & dtb_mask);
        let (context, symbol) = if self.target.recognize_secure_root(dtb_masked) {
            let trace = resolve_thread_trace_context_at(&self.target, dtb, rip);
            (
                trace.description.clone(),
                try_format_symbol(&self.target, &trace, rip),
            )
        } else if kernel_dtb_masked.is_some_and(|k| dtb_masked == k) {
            let sym = self
                .target
                .symbols
                .format_closest_symbol_for_address(self.target.kernel_dtb(), VirtAddr(rip));
            ("kernel".to_string(), sym)
        } else {
            let processes = self
                .target
                .guest
                .as_ref()
                .and_then(|g| g.enumerate_processes().ok())
                .unwrap_or_default();
            match processes.iter().find(|p| (p.dtb & dtb_mask) == dtb_masked) {
                Some(proc) => {
                    let sym = self
                        .target
                        .symbols
                        .format_closest_symbol_for_address(proc.dtb, VirtAddr(rip));
                    (proc.name.clone(), sym)
                }
                None => match self
                    .target
                    .symbols
                    .format_closest_symbol_for_address(dtb_masked, VirtAddr(rip))
                {
                    Some(sym) => ("kernel".to_string(), Some(sym)),
                    // Outside NT under VBS: the hypervisor or VTL1.
                    None => {
                        let trace = resolve_thread_trace_context_at(&self.target, dtb, rip);
                        let symbol = try_format_symbol(&self.target, &trace, rip);
                        (trace.description, symbol)
                    }
                },
            }
        };

        // A refused state is reported by the stop header and .vtlcxr;
        // listed here it would read as a saved state.
        let saved_vtl = if context == HYPERVISOR_CONTEXT {
            saved_vtl_summary(
                &self.target,
                dtb,
                processor_index_from_backend_thread_id(id),
            )
            .unwrap_or_default()
        } else {
            Vec::new()
        };
        VcpuInfo {
            id: id.to_string(),
            rip: Some(rip),
            context,
            symbol,
            saved_vtl,
            error: None,
        }
    }

    /// Map each *active* Windows thread (one currently scheduled on a vCPU) to
    /// the vCPU running it and its [`ThreadInfo`], keyed by `ETHREAD` address.
    /// Walks every backend vCPU, resolves the Windows thread it is executing,
    /// and restores the originally-stopped vCPU. Best-effort (empty map if the
    /// backend can't enumerate vCPUs).
    pub fn active_thread_map(&mut self) -> HashMap<u64, (String, ThreadInfo)> {
        let Ok(original) = self.backend.stopped_thread_id() else {
            return HashMap::new();
        };
        let Ok(vcpus) = self.backend.thread_list() else {
            return HashMap::new();
        };

        let mut active = HashMap::new();
        for vcpu in &vcpus {
            if self.backend.set_current_thread(vcpu).is_err() {
                continue;
            }
            if self
                .target
                .guest
                .as_ref()
                .and_then(|guest| guest.cached_secure_kernel())
                .is_some()
                && self
                    .backend
                    .read_registers()
                    .ok()
                    .and_then(|regs| {
                        self.register_map
                            .read_u64(self.target.arch().dtb_register(), &regs)
                            .ok()
                    })
                    .is_some_and(|dtb| self.target.recognize_secure_root(dtb))
            {
                continue;
            }
            let Some(processor) = processor_index_from_backend_thread_id(vcpu) else {
                continue;
            };
            if let Ok(thread) = self.target.current_windows_thread_for_processor(processor) {
                active.insert(thread.ethread.0, (vcpu.clone(), thread));
            }
        }

        let _ = self.backend.set_current_thread(&original);
        active
    }

    /// Enumerate all Windows threads, merged with the currently-active threads
    /// (so a thread scheduled on a vCPU but absent from the walk is still
    /// included), sorted by `(pid, tid)`. Returns the threads plus a map of
    /// `ETHREAD -> vCPU id` for those currently running; hosts apply their own
    /// filtering/rendering.
    pub fn windows_threads(&mut self) -> Result<(Vec<ThreadInfo>, HashMap<u64, String>)> {
        let active = self.active_thread_map();
        let mut threads = self.target.enumerate_threads()?;
        for (_, thread) in active.values() {
            if !threads.iter().any(|known| known.ethread == thread.ethread) {
                threads.push(thread.clone());
            }
        }
        threads
            .sort_by_key(|thread| (thread.pid.unwrap_or(u64::MAX), thread.tid, thread.ethread.0));
        let active_vcpus = active
            .into_iter()
            .map(|(ethread, (vcpu, _))| (ethread, vcpu))
            .collect();
        Ok((threads, active_vcpus))
    }
}

/// Adopt the Windows thread a backend vCPU is running as the inspection
/// context, walked from that processor's KPRCB. Returns it, or `None` when the
/// id is not a processor context or the walk fails, clearing the stale
/// selection either way.
///
/// Every host has to do this at every stop: the selection is what `!thread`
/// reports and what the `$thread`/`$proc` pseudo-registers read, and a resume
/// clears it. Shared by the REPL (re-exported from `repl::stop`) and
/// [`Session::run_status`] so the two cannot report different threads.
pub fn refresh_windows_thread_context_for_backend_thread(
    debugger: &mut Target,
    thread_id: &str,
) -> Option<ThreadInfo> {
    let thread = windows_thread_on_backend_thread(debugger, thread_id);
    match thread.clone() {
        Some(thread) => debugger.set_current_windows_thread_context(thread),
        None => debugger.clear_current_windows_thread_context(),
    }
    thread
}

/// The Windows thread a backend vCPU is running, walked from that
/// processor's KPRCB, without selecting it. `None` when the id is not a
/// processor context, the walk fails, or the vCPU runs VTL1: NT's per-CPU
/// current thread is suspended then, and presenting it as the secure thread
/// gives false IDs, stacks, and filters.
pub fn windows_thread_on_backend_thread(debugger: &Target, thread_id: &str) -> Option<ThreadInfo> {
    if debugger
        .registers
        .as_ref()
        .and_then(|registers| registers.get(debugger.arch().dtb_register()))
        .is_some_and(|dtb| debugger.recognize_secure_root(*dtb))
    {
        return None;
    }
    processor_index_from_backend_thread_id(thread_id).and_then(|processor| {
        debugger
            .current_windows_thread_for_processor(processor)
            .ok()
    })
}
