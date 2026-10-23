//! Windows thread commands: listing threads, inspecting one with its
//! stack, and switching the register and stack context to it.

use std::collections::HashMap;

use tabled::builder::Builder;

use owo_colors::OwoColorize;

use ntoseye_macros::{command, grammar};

use crate::backend::dbg_backend::{processor_index_from_backend_thread_id, thread_label};
use crate::base::error::{Error, Result};
use crate::base::types::VirtAddr;
use crate::hosts::repl::args::{ArgCursor, ArgCx, ArgError, Current, FromArg};
use crate::hosts::repl::*;
use crate::hosts::ui;
use crate::nt::bugchecks::looks_like_kernel_pointer;
use crate::nt::target::sched::ThreadDetail;
use crate::nt::target::{ThreadInfo, kthread_state_name, wait_reason_name};
use crate::nt::unwind::ThreadStackSource;
use crate::session::{Session, ThreadContext};

use super::process::{display_decimal, display_pointer};

pub enum ThreadResolution {
    Found(ThreadInfo),
    Missing,
    Ambiguous(usize),
}

pub(super) const THREAD_STACK_LIMIT: usize = 32;
const DEFAULT_THREAD_FRAME_LIMIT: usize = 16;

fn thread_state_label(thread: &ThreadInfo) -> String {
    thread
        .state
        .map(|state| format!("{} ({:#x})", kthread_state_name(state), state))
        .unwrap_or_else(|| "?".to_string())
}

fn wait_reason_label(thread: &ThreadInfo) -> String {
    thread
        .wait_reason
        .map(|reason| format!("{} ({:#x})", wait_reason_name(reason), reason))
        .unwrap_or_else(|| "?".to_string())
}

fn thread_matches_filter(thread: &ThreadInfo, filter: &str) -> bool {
    let filter_lower = filter.to_ascii_lowercase();
    thread
        .process_name
        .as_deref()
        .is_some_and(|name| name.to_ascii_lowercase().contains(&filter_lower))
        || thread
            .pid
            .is_some_and(|pid| pid.to_string() == filter || format!("{:#x}", pid) == filter_lower)
        || thread
            .tid
            .is_some_and(|tid| tid.to_string() == filter || format!("{:#x}", tid) == filter_lower)
        || format!("{:#x}", thread.ethread.0) == filter_lower
        || format!("{:x}", thread.ethread.0) == filter_lower.trim_start_matches("0x")
}

fn print_thread_info(thread: &ThreadInfo) {
    outln!(
        "{} {}  TID {}  PID {}  process {}",
        ui::label("thread:"),
        ui::addr(thread.ethread.0),
        thread
            .tid
            .map(ui::Value)
            .map(|tid| tid.to_string())
            .unwrap_or_else(|| "-".to_string()),
        thread
            .pid
            .map(ui::Value)
            .map(|pid| pid.to_string())
            .unwrap_or_else(|| "-".to_string()),
        thread.process_name.as_deref().unwrap_or("unknown")
    );
    outln!(
        "  state={} wait={} kthread={} eprocess={}",
        thread_state_label(thread),
        wait_reason_label(thread),
        ui::addr(thread.kthread.0),
        thread
            .eprocess
            .map(|addr| ui::addr(addr.0))
            .unwrap_or_else(|| "-".to_string())
    );
    outln!(
        "  start={} win32_start={} teb={} kernel_stack={}",
        thread
            .start_address
            .map(|addr| ui::addr(addr.0))
            .unwrap_or_else(|| "-".to_string()),
        thread
            .win32_start_address
            .map(|addr| ui::addr(addr.0))
            .unwrap_or_else(|| "-".to_string()),
        thread
            .teb
            .map(|addr| ui::addr(addr.0))
            .unwrap_or_else(|| "-".to_string()),
        thread
            .kernel_stack
            .map(|addr| ui::addr(addr.0))
            .unwrap_or_else(|| "-".to_string())
    );
    outln!(
        "  priority={} base_priority={} wait_irql={} stack_resident={}",
        thread
            .priority
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string()),
        thread
            .base_priority
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string()),
        thread
            .wait_irql
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string()),
        thread
            .kernel_stack_resident
            .map(|resident| if resident { "yes" } else { "no" })
            .unwrap_or("-")
    );
    outln!(
        "  stack_base={} stack_limit={} trap_frame={}",
        thread
            .stack_base
            .map(|addr| ui::addr(addr.0))
            .unwrap_or_else(|| "-".to_string()),
        thread
            .stack_limit
            .map(|addr| ui::addr(addr.0))
            .unwrap_or_else(|| "-".to_string()),
        thread
            .trap_frame
            .map(|addr| ui::addr(addr.0))
            .unwrap_or_else(|| "-".to_string())
    );
    if let Some(irps) = &thread.pending_irps {
        if irps.is_empty() {
            outln!("  irp_list=empty");
        } else {
            outln!("  irp_list={} pending", irps.len());
            for (index, irp) in irps.iter().enumerate() {
                outln!("    [{}] {}", index, ui::addr(irp.0));
            }
        }
    }
}

/// `!thread`'s text for one thread, as `!process` lists threads too.
pub(super) fn print_thread_detail(detail: &ThreadDetail) {
    print_thread_info(&detail.thread);
    outln!("  win32thread={}", display_pointer(detail.win32_thread));
    outln!(
        "  times user={} kernel={} wait_time={} ready_time={} quantum_target={}",
        display_decimal(detail.user_time),
        display_decimal(detail.kernel_time),
        display_decimal(detail.wait_time),
        display_decimal(detail.ready_time),
        display_decimal(detail.quantum_target),
    );
}

impl ReplState<'_> {
    fn thread_matches_value(thread: &ThreadInfo, value: Option<u64>) -> bool {
        value.is_some_and(|value| {
            thread.tid == Some(value) || thread.ethread.0 == value || thread.kthread.0 == value
        })
    }

    /// The thread `value` names. A running thread and an ETHREAD (or
    /// KTHREAD, which shares its base) of a listed process are read
    /// directly; only a thread id pays for the walk over every process.
    pub fn resolve_windows_thread(
        &mut self,
        value: Option<u64>,
        active: &HashMap<u64, (String, ThreadInfo)>,
    ) -> Result<ThreadResolution> {
        if let Some(value) = value {
            if let Some((_, thread)) = active.get(&value) {
                return Ok(ThreadResolution::Found(thread.clone()));
            }
            if looks_like_kernel_pointer(self.ctx.target.arch(), value)
                && let Ok(thread) = self.ctx.target.thread_info_from_ethread(VirtAddr(value))
                && let Ok(processes) = self.ctx.target.guest()?.enumerate_processes()
                && thread
                    .eprocess
                    .is_some_and(|owner| processes.iter().any(|p| p.eprocess == owner))
            {
                return Ok(ThreadResolution::Found(thread));
            }
        }
        let threads = self.ctx.windows_thread_candidates()?;
        *self.caches.threads.write().unwrap() = threads.clone();
        let mut matches: Vec<ThreadInfo> = threads
            .into_iter()
            .filter(|thread| Self::thread_matches_value(thread, value))
            .collect();
        Ok(match matches.len() {
            0 => ThreadResolution::Missing,
            1 => ThreadResolution::Found(matches.remove(0)),
            count => ThreadResolution::Ambiguous(count),
        })
    }

    /// `thread`'s stack as [`crate::session::Session::backtrace_thread`] walks
    /// it, without selecting it.
    fn print_thread_kstack(&mut self, thread: &ThreadInfo, running_on: Option<&str>, limit: usize) {
        match self.ctx.backtrace_thread(thread, running_on, limit) {
            Ok(trace) => {
                outln!("k-stack ({}):", trace.source.as_str());
                print_stacktrace_data_with_provenance(
                    self.ctx.target.arch(),
                    &trace.stacktrace,
                    limit,
                    false,
                );
            }
            Err(error) => error!("failed to unwind thread stack: {}", error),
        }
    }

    fn print_running_kstack(&mut self, source: &str, limit: usize) {
        match self.ctx.backtrace(limit) {
            Ok(trace) => {
                outln!("k-stack ({source}):");
                print_stacktrace_data(self.ctx.target.arch(), &trace, limit, false);
            }
            Err(error) => error!("failed to unwind thread stack: {}", error),
        }
    }

    /// The thread `text` names (its value `value`), as `!thread` and
    /// `.thread` resolve it.
    fn thread_named(
        &mut self,
        text: &str,
        value: Option<u64>,
    ) -> std::result::Result<ThreadInfo, ArgError> {
        let active = self.ctx.active_thread_map();
        match self.resolve_windows_thread(value, &active) {
            Ok(ThreadResolution::Found(thread)) => Ok(thread),
            Ok(ThreadResolution::Missing) => Err(ArgError::Message(format!(
                "no Windows thread matches '{text}'"
            ))),
            Ok(ThreadResolution::Ambiguous(count)) => Err(ArgError::Message(format!(
                "ambiguous Windows thread '{text}': {count} matches"
            ))),
            Err(error) => Err(ArgError::Message(format!(
                "failed to enumerate threads: {error}"
            ))),
        }
    }

    /// `!thread`'s text: the thread, selected when the target is halted
    /// (its vCPU's registers, or its stack when parked), then the stack or
    /// registers `action` asks for.
    fn show_thread(&mut self, detail: &ThreadDetail, action: &ThreadAction, count: Option<u64>) {
        let thread = &detail.thread;
        let count = count.and_then(|count| usize::try_from(count).ok());
        let frame_limit = count.unwrap_or(DEFAULT_THREAD_FRAME_LIMIT).max(1);
        let stack_limit = count.unwrap_or(THREAD_STACK_LIMIT).max(1);
        let word = action.word.as_deref();

        // Selecting a thread lasts until the target resumes, so a running
        // target has nothing to select into: the thread is only shown.
        if self.ctx.backend.is_running() {
            print_thread_detail(detail);
            match word {
                Some("k" | "r" | "registers") => error!(
                    "VM is running; `thread <tid> k|r` selects the thread, which needs a halted target"
                ),
                Some(other) if !action.numeric => {
                    error!("unknown thread action '{}': expected k or r", other)
                }
                _ => {}
            }
            if action.default_stack {
                self.print_thread_kstack(thread, detail.vcpu.as_deref(), stack_limit);
            }
            outln!();
            return;
        }

        let Some(vcpu) = &detail.vcpu else {
            print_thread_detail(detail);
            outln!(
                "{}",
                "thread is parked: stack inspection is available, registers are not".bright_black()
            );
            self.ctx.select_parked_windows_thread(thread);
            self.clear_selected_frame();
            self.caches.refresh_symbol_context(&self.ctx.target);
            if action.default_stack {
                self.print_thread_kstack(thread, None, stack_limit);
            } else {
                match word {
                    Some("k") => match self.ctx.backtrace(frame_limit) {
                        Ok(stacktrace) => print_stacktrace_data_with_provenance(
                            self.ctx.target.arch(),
                            &stacktrace,
                            frame_limit,
                            false,
                        ),
                        Err(error) => error!("failed to unwind parked thread stack: {}", error),
                    },
                    Some("r" | "registers") => error!(
                        "parked thread has no coherent register context; select a live vCPU with `vcpu <id>`"
                    ),
                    Some(_) if action.numeric => {}
                    Some(other) => {
                        error!("unknown thread action '{}': expected k or r", other)
                    }
                    None => {}
                }
            }
            outln!();
            return;
        };

        let selection = match self.ctx.select_running_windows_thread(vcpu, thread) {
            Ok(selection) => selection,
            Err(e) => {
                error!("failed to switch to {}: {e}", ui::thread(vcpu));
                return;
            }
        };
        self.caches.refresh_symbol_context(&self.ctx.target);
        outln!(
            "switched to {} running ETHREAD {}\n",
            ui::thread(&self.ctx.current_thread),
            ui::addr(thread.ethread.0)
        );
        print_thread_detail(detail);
        let source = match selection {
            ThreadContext::SavedVtl0(_) => ThreadStackSource::SavedVtl0,
            _ => ThreadStackSource::Live,
        }
        .as_str();

        if action.default_stack {
            self.print_running_kstack(source, stack_limit);
        } else {
            match word {
                Some("k") => match self.ctx.backtrace(frame_limit) {
                    Ok(trace) => {
                        print_stacktrace_data(self.ctx.target.arch(), &trace, frame_limit, false)
                    }
                    Err(error) => error!("failed to unwind thread stack: {}", error),
                },
                Some("r" | "registers") => {
                    if let Some(frame) = self.ctx.target.selected_frame.as_ref() {
                        print_sparse_registers(
                            &frame.registers,
                            self.ctx.target.arch(),
                            Some(&format!("registers ({source}):")),
                            4,
                        );
                    } else {
                        let regs = match self.ctx.read_registers() {
                            Ok(regs) => regs,
                            Err(e) => {
                                error!("failed to read registers: {e}");
                                return;
                            }
                        };
                        print_registers(
                            &self.ctx.register_map,
                            self.ctx.target.arch(),
                            &regs,
                            None,
                            None,
                        );
                    }
                }
                Some(_) if action.numeric => {}
                Some(other) => error!("unknown thread action '{}': expected k or r", other),
                None => {}
            }
        }
        outln!();
    }
}

impl FromArg for ThreadInfo {
    const COMPLETION: CompletionStrategy = CompletionStrategy::Thread;

    /// An ETHREAD, KTHREAD or TID expression; `.` is the current thread.
    fn from_arg(cx: &mut ArgCx<'_, '_>, text: &str) -> std::result::Result<Self, ArgError> {
        if text == "." {
            return Self::current(cx);
        }
        let value = cx.eval(text).ok().map(|value| value.0);
        cx.state.thread_named(text, value)
    }
}

impl Current for ThreadInfo {
    /// The thread `.thread` selected, or else the one the current processor
    /// runs.
    fn current(cx: &mut ArgCx<'_, '_>) -> std::result::Result<Self, ArgError> {
        let session = &mut *cx.state.ctx;
        let address = session
            .target
            .windows_thread_selection
            .as_ref()
            .map(|thread| thread.ethread)
            .or_else(|| {
                processor_index_from_backend_thread_id(&session.current_thread).and_then(
                    |processor| {
                        session
                            .target
                            .current_windows_thread_for_processor(processor)
                            .ok()
                            .map(|thread| thread.ethread)
                    },
                )
            });
        let Some(address) = address else {
            return Err(ArgError::Message(
                "no current Windows thread; name one by ETHREAD or TID".to_string(),
            ));
        };
        cx.state.thread_named(".", Some(address.0))
    }
}

/// List the Windows threads, with an optional filter by process, PID, TID, or ETHREAD.
#[command(
    names = ["threads"],
    category = "processes and modules",
    kind = Query,
    target = Kernel,
    python = none,
)]
fn threads(
    session: &mut Session,
    #[arg(render, complete = Process)] filter: Option<String>,
) -> Result<WindowsThreads> {
    let (threads, active) = session
        .windows_threads()
        .map_err(|error| Error::DebugInfo(format!("failed to enumerate threads: {error}")))?;
    Ok(WindowsThreads { threads, active })
}

/// Every Windows thread, and the processor running each that runs.
struct WindowsThreads {
    threads: Vec<ThreadInfo>,
    active: HashMap<u64, String>,
}

impl Render<Option<String>> for WindowsThreads {
    fn render(&self, repl: &mut ReplState<'_>, filter: Option<String>) {
        // Completion wants every thread, not just the ones this listing shows.
        *repl.caches.threads.write().unwrap() = self.threads.clone();
        let threads: Vec<&ThreadInfo> = self
            .threads
            .iter()
            .filter(|thread| {
                filter
                    .as_deref()
                    .is_none_or(|filter| thread_matches_filter(thread, filter))
            })
            .collect();
        if threads.is_empty() {
            outln!("{}\n", "no matching threads".bright_black());
            return;
        }

        let mut builder = Builder::default();
        builder.push_record(vec![
            "Processor".to_string(),
            "ETHREAD".to_string(),
            "PID".to_string(),
            "TID".to_string(),
            "Process".to_string(),
            "State".to_string(),
            "Wait".to_string(),
            "Start".to_string(),
        ]);
        for thread in threads {
            let active_vcpu = self
                .active
                .get(&thread.ethread.0)
                .map_or_else(|| "-".to_string(), |vcpu| thread_label(vcpu));
            let start = thread.start_address.or(thread.win32_start_address);
            builder.push_record(vec![
                active_vcpu,
                ui::addr(thread.ethread.0).to_string(),
                thread
                    .pid
                    .map(ui::Value)
                    .map(|pid| pid.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                thread
                    .tid
                    .map(ui::Value)
                    .map(|tid| tid.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                thread
                    .process_name
                    .as_deref()
                    .unwrap_or("unknown")
                    .to_string(),
                thread_state_label(thread).to_string(),
                wait_reason_label(thread).to_string(),
                start
                    .map(|addr| ui::addr(addr.0))
                    .unwrap_or_else(|| "-".to_string()),
            ]);
        }
        print_padded_table(builder);
    }
}

/// Show a Windows thread and, optionally, its kernel stack.
///
/// You can also use the legacy `thread <tid> k|r [count]` forms. A numeric
/// flags value selects the detail and stack output, and count sets the
/// maximum number of stack frames (32 by default, or 16 for `k`). The command
/// shows `-` for a field that is not available. If the vCPU of a running
/// thread is halted in the Windows hypervisor (VBS), the command shows the
/// thread from the VTL0 state that the hypervisor saved, and `.thread`
/// selects the thread in the same way. While the target runs, the command
/// shows the thread but does not select it, and a thread that runs on a
/// processor has no stack.
#[command(
    names = ["!thread", "thread"],
    category = "processes and modules",
    kind = Query,
    target = Kernel,
    python = Thread,
    python_name = "inspect",
)]
fn thread(
    session: &mut Session,
    #[arg(receiver, current, name = "ethread|tid")] thread: ThreadInfo,
    #[arg(render, parse = thread_action)] action: ThreadAction,
    #[arg(render, complete = None)] count: Option<u64>,
) -> Result<ThreadDetail> {
    let cpu = session
        .active_thread_map()
        .remove(&thread.ethread.0)
        .map(|(vcpu, _)| vcpu);
    Ok(session.target.thread_detail(thread, cpu))
}

/// What `!thread` shows after the thread: its flags (bit 4 is the stack,
/// which `!thread` shows by default and the legacy `thread` does not), or
/// the legacy `k` (the stack) or `r` (the registers).
struct ThreadAction {
    word: Option<String>,
    /// The word is a flags value.
    numeric: bool,
    default_stack: bool,
}

#[grammar(usage = "[flags|k|r]", complete = [None])]
fn thread_action(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<ThreadAction, ArgError> {
    let word = cursor.word().map(|word| word.into_owned());
    let flags = word
        .as_deref()
        .and_then(|word| cx.eval(word).ok())
        .map(|value| value.0);
    Ok(ThreadAction {
        default_stack: cx.name == "!thread"
            && (word.is_none() || flags.is_some_and(|flags| flags & 4 != 0)),
        numeric: flags.is_some(),
        word,
    })
}

impl Render<(ThreadAction, Option<u64>)> for ThreadDetail {
    fn render(&self, repl: &mut ReplState<'_>, (action, count): (ThreadAction, Option<u64>)) {
        repl.show_thread(self, &action, count);
    }
}

/// Switch the register and stack context to a Windows thread.
///
/// For a running thread, the command switches to its vCPU. If that vCPU is
/// halted in the Windows hypervisor (VBS), the context is the VTL0 state that
/// the hypervisor saved, at the point where NT stopped, which `.vtlcxr` also
/// selects. If this state is not available (no hv-evmcs), the context is the
/// registers of the vCPU. For a thread that is not running, the command
/// selects the stack only. The memory scope is the address space of the
/// thread's process, so `k`, `.frame`, and `r` of a selected frame walk the
/// saved stack of the thread, and `.trap` and `.cxr` on the thread read and
/// walk that process. While the target runs, and always on the memory
/// backend, the command selects the stack only for all threads, and each walk
/// reads the thread as it is at that time. With no argument, the command goes
/// back to the context of the current vCPU, which is the vCPU registers or,
/// if the vCPU is halted in the Windows hypervisor, the point where NT
/// stopped.
#[command(
    names = [".thread"],
    category = "execution and stack",
    kind = Action,
    target = Kernel,
    python = none,
)]
fn dot_thread(
    state: &mut ReplState<'_>,
    #[arg(name = "ethread|tid")] thread: Option<ThreadInfo>,
) -> Result<()> {
    let Some(thread) = thread else {
        let current = state.ctx.current_thread.clone();
        state.ctx.reset_windows_thread().map_err(|error| {
            Error::DebugInfo(format!("failed to reset thread context: {error}"))
        })?;
        state.caches.refresh_symbol_context(&state.ctx.target);
        if state.ctx.backend.is_running() {
            outln!("cleared the thread selection\n");
        } else {
            outln!("reset thread context to {}\n", ui::thread(&current));
        }
        return Ok(());
    };
    match state.ctx.select_windows_thread(&thread) {
        Ok(ThreadContext::Live(vcpu)) => outln!(
            "switched register context to {} (ETHREAD {})\n",
            vcpu,
            ui::addr(thread.ethread.0)
        ),
        Ok(ThreadContext::SavedVtl0(vcpu)) => outln!(
            "switched register context to the VTL0 state the hypervisor saved for {} (ETHREAD {})\n",
            vcpu,
            ui::addr(thread.ethread.0)
        ),
        Ok(ThreadContext::Parked) => outln!(
            "selected parked thread context ETHREAD {} (stack only)\n",
            ui::addr(thread.ethread.0)
        ),
        Err(error) => {
            return Err(Error::DebugInfo(format!(
                "failed to switch thread context: {error}"
            )));
        }
    }
    state.caches.refresh_symbol_context(&state.ctx.target);
    Ok(())
}
