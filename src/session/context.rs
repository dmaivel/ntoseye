//! The inspection selection: the current vCPU, a parked Windows thread, a
//! selected frame, and the register file and address space they imply.

use std::collections::HashMap;

use crate::dbg_backend::{DebugCapability, processor_index_from_backend_thread_id};
use crate::error::{Error, Result};
use crate::gdb::RegisterMap;
use crate::memory::DTB_IDENTITY;
use crate::session::{Selection, Session, VcpuInfo};
use crate::target::{SelectedFrame, Target, ThreadInfo};
use crate::types::VirtAddr;
use crate::unwind::{
    RecoveredStackTrace, build_stacktrace_with_context, build_stacktrace_with_register_values,
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
        self.parked_windows_thread = None;
        self.target.clear_current_windows_thread_context();
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
        self.target.registers = Some(selected.registers.clone());
        let dtb_register = self.target.arch().dtb_register();
        let dtb = selected.dtb.or_else(|| {
            selected.registers.get(dtb_register).copied().filter(|dtb| {
                *dtb != 0 && self.target.guest.is_some() && self.target.kernel_dtb() != DTB_IDENTITY
            })
        });
        match dtb {
            Some(dtb) => self.target.set_context_dtb_override(dtb),
            None => self.target.clear_context_dtb_override(),
        }
        self.target.selected_frame = Some(selected);
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
    /// a vCPU switches the live register context to that vCPU; any other
    /// thread is parked (stack-only, no coherent register file). Returns the
    /// vCPU id when the selection is live.
    pub fn select_windows_thread(&mut self, thread: &ThreadInfo) -> Result<Option<String>> {
        let active = self.active_thread_map();
        match active.get(&thread.ethread.0) {
            Some((vcpu, _)) => {
                let vcpu = vcpu.clone();
                self.set_current_thread(&vcpu)?;
                self.target.selected_frame = None;
                self.target
                    .set_current_windows_thread_context(thread.clone());
                Ok(Some(vcpu))
            }
            None => {
                self.select_parked_windows_thread(thread);
                Ok(None)
            }
        }
    }

    /// Drop any Windows-thread selection and return to the backend's current
    /// vCPU context (`.thread` with no argument).
    pub fn reset_windows_thread(&mut self) -> Result<()> {
        let current = self.current_thread.clone();
        self.set_current_thread(&current)?;
        self.target.selected_frame = None;
        self.target.clear_current_windows_thread_context();
        Ok(())
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
    /// clear it while the VM runs or a parked thread is selected, so
    /// expression evaluation follows the current thread's address space.
    pub fn restore_live_register_cache(&mut self) {
        let registers = if self.backend.is_running() || self.parked_windows_thread().is_some() {
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
    pub(super) fn refresh_context_for_current_thread(&mut self) {
        self.parked_windows_thread = None;
        if self.backend.is_running() {
            return;
        }
        let registers = self
            .backend
            .set_current_thread(&self.current_thread)
            .and_then(|_| self.backend.read_registers());
        update_target_context_from_registers(&mut self.target, &self.register_map, registers);
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
        if self.backend.is_running() {
            return Err(Error::TargetRunning(REGISTERS_NEED_HALT));
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
        let processes = self
            .target
            .guest
            .as_ref()
            .and_then(|g| g.enumerate_processes().ok())
            .unwrap_or_default();
        let dtb_mask = self.target.arch().dtb_page_mask();
        let kernel_dtb_masked = self
            .target
            .guest
            .as_ref()
            .map(|g| g.ntoskrnl.dtb() & dtb_mask);

        let mut out = Vec::with_capacity(threads.len());
        for thread in &threads {
            let regs = self
                .backend
                .set_current_thread(thread)
                .and_then(|_| self.backend.read_registers());
            let regs = match regs {
                Ok(regs) => regs,
                Err(e) => {
                    out.push(VcpuInfo {
                        id: thread.clone(),
                        rip: None,
                        context: String::new(),
                        symbol: None,
                        error: Some(e.to_string()),
                    });
                    continue;
                }
            };
            let (Ok(rip), Ok(dtb)) = (
                self.register_map.read_u64("rip", &regs),
                self.register_map
                    .read_u64(self.target.arch().dtb_register(), &regs),
            ) else {
                out.push(VcpuInfo {
                    id: thread.clone(),
                    rip: None,
                    context: String::new(),
                    symbol: None,
                    error: None,
                });
                continue;
            };

            // RIP=0 means the dump did not capture this CPU's context
            if rip == 0 {
                out.push(VcpuInfo {
                    id: thread.clone(),
                    rip: Some(0),
                    context: "no context".to_string(),
                    symbol: None,
                    error: None,
                });
                continue;
            }

            let dtb_masked = dtb & dtb_mask;
            let (context, symbol) = if kernel_dtb_masked.is_some_and(|k| dtb_masked == k) {
                let sym = self
                    .target
                    .guest
                    .as_ref()
                    .and_then(|g| g.ntoskrnl.closest_symbol(VirtAddr(rip)).ok())
                    .map(|(s, o)| format!("{s}+{o:#x}"));
                ("kernel".to_string(), sym)
            } else {
                match processes.iter().find(|p| (p.dtb & dtb_mask) == dtb_masked) {
                    Some(proc) => {
                        let sym = self
                            .target
                            .symbols
                            .format_closest_symbol_for_address(proc.dtb, VirtAddr(rip));
                        (proc.name.clone(), sym)
                    }
                    None => {
                        let sym = self.target.closest_symbol_current_context(VirtAddr(rip));
                        let ctx = if sym.is_some() { "kernel" } else { "unknown" };
                        (ctx.to_string(), sym)
                    }
                }
            };

            out.push(VcpuInfo {
                id: thread.clone(),
                rip: Some(rip),
                context,
                symbol,
                error: None,
            });
        }

        let _ = self.backend.set_current_thread(&original);
        Ok(out)
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
    let thread = processor_index_from_backend_thread_id(thread_id).and_then(|processor| {
        debugger
            .current_windows_thread_for_processor(processor)
            .ok()
    });
    match thread.clone() {
        Some(thread) => debugger.set_current_windows_thread_context(thread),
        None => debugger.clear_current_windows_thread_context(),
    }
    thread
}
