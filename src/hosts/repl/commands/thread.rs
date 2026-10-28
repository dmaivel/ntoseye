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
use crate::nt::expr::Expr;
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
        .unwrap_or_else(|| "-".to_string())
}

fn wait_reason_label(thread: &ThreadInfo) -> String {
    thread
        .wait_reason
        .map(|reason| format!("{} ({:#x})", wait_reason_name(reason), reason))
        .unwrap_or_else(|| "-".to_string())
}

/// Whether `thread` matches a `threads` filter: its process's name, or its
/// PID, TID or ETHREAD written out, or `number`, the filter read as a number
/// literal (`0n6996`, `0x1b54`, or a bare number in the session radix).
fn thread_matches_filter(thread: &ThreadInfo, filter: &str, number: Option<u64>) -> bool {
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
        || number.is_some_and(|number| {
            thread.pid == Some(number) || thread.tid == Some(number) || thread.ethread.0 == number
        })
}

/// `!thread`'s text for one thread, as `!process` lists threads too.
pub(super) fn print_thread_detail(detail: &ThreadDetail) {
    let thread = &detail.thread;
    let id =
        |value: Option<u64>| value.map_or_else(|| "-".to_string(), |id| ui::Value(id).to_string());
    outln!(
        "{} {}  TID {}  PID {}  process {}",
        ui::label("THREAD"),
        ui::addr(thread.ethread.0),
        id(thread.tid),
        id(thread.pid),
        thread.process_name.as_deref().unwrap_or("-")
    );
    let address =
        |value: Option<VirtAddr>| value.map_or_else(|| "-".to_string(), |addr| ui::addr(addr.0));
    let number =
        |value: Option<u8>| value.map_or_else(|| "-".to_string(), |value| value.to_string());
    let fields = [
        ("state", thread_state_label(thread)),
        ("wait reason", wait_reason_label(thread)),
        ("KTHREAD", ui::addr(thread.kthread.0)),
        ("EPROCESS", address(thread.eprocess)),
        ("start address", address(thread.start_address)),
        ("Win32 start address", address(thread.win32_start_address)),
        ("TEB", address(thread.teb)),
        ("Win32Thread", display_pointer(detail.win32_thread)),
        ("priority", number(thread.priority)),
        ("base priority", number(thread.base_priority)),
        ("wait IRQL", number(thread.wait_irql)),
        ("kernel stack", address(thread.kernel_stack)),
        (
            "stack resident",
            thread
                .kernel_stack_resident
                .map_or("-", |resident| if resident { "yes" } else { "no" })
                .to_string(),
        ),
        ("stack base", address(thread.stack_base)),
        ("stack limit", address(thread.stack_limit)),
        ("trap frame", address(thread.trap_frame)),
        (
            "pending IRPs",
            thread
                .pending_irps
                .as_ref()
                .map_or_else(|| "-".to_string(), |irps| irps.len().to_string()),
        ),
        ("user time", display_decimal(detail.user_time)),
        ("kernel time", display_decimal(detail.kernel_time)),
        ("wait time", display_decimal(detail.wait_time)),
        ("ready time", display_decimal(detail.ready_time)),
        ("quantum target", display_decimal(detail.quantum_target)),
    ];
    let width = fields
        .iter()
        .map(|(label, _)| label.len())
        .max()
        .unwrap_or(0);
    for (label, value) in fields {
        outln!("  {label:<width$}  {value}");
        // Each pending IRP, under the count, at the values' column.
        if label == "pending IRPs" {
            for irp in thread.pending_irps.iter().flatten() {
                outln!("  {:width$}  {}", "", ui::addr(irp.0));
            }
        }
    }
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
                print_section(&format!("stack ({})", trace.source.as_str()));
                print_stacktrace_data_with_provenance(
                    self.ctx.target.arch(),
                    &trace.stacktrace,
                    limit,
                    false,
                );
            }
            // The walk's error says the stack is unavailable and why.
            Err(error) => error!("{error}"),
        }
    }

    fn print_running_kstack(&mut self, source: &str, limit: usize) {
        match self.ctx.backtrace(limit) {
            Ok(trace) => {
                print_section(&format!("stack ({source})"));
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
                    "the target is running; `thread <tid> k|r` selects the thread, which needs a halted target"
                ),
                Some(other) if !action.numeric => {
                    error!("unknown thread action '{}': expected k or r", other)
                }
                _ => {}
            }
            if action.default_stack {
                self.print_thread_kstack(thread, detail.vcpu.as_deref(), stack_limit);
            }
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
                        Ok(stacktrace) => {
                            print_section("stack");
                            print_stacktrace_data_with_provenance(
                                self.ctx.target.arch(),
                                &stacktrace,
                                frame_limit,
                                false,
                            )
                        }
                        Err(error) => error!("{error}"),
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
            return;
        };

        let previous = self.ctx.current_thread.clone();
        let selection = match self.ctx.select_running_windows_thread(vcpu, thread) {
            Ok(selection) => selection,
            Err(e) => {
                error!("failed to switch to {}: {e}", ui::thread(vcpu));
                return;
            }
        };
        self.caches.refresh_symbol_context(&self.ctx.target);
        // Selecting the thread the current processor already runs
        // switches nothing, so only a real switch is reported.
        if self.ctx.current_thread != previous {
            outln!(
                "switched to {} running thread {:#x}",
                ui::thread(&self.ctx.current_thread),
                thread.ethread.0
            );
        }
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
                        print_section(&format!("stack ({source})"));
                        print_stacktrace_data(self.ctx.target.arch(), &trace, frame_limit, false)
                    }
                    Err(error) => error!("failed to unwind thread stack: {}", error),
                },
                Some("r" | "registers") => {
                    if let Some(frame) = self.ctx.target.selected_frame.as_ref() {
                        print_known_registers(
                            &frame.registers,
                            self.ctx.target.arch(),
                            &format!("registers ({source})"),
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
                            Some(&format!("registers ({source})")),
                        );
                    }
                }
                Some(_) if action.numeric => {}
                Some(other) => error!("unknown thread action '{}': expected k or r", other),
                None => {}
            }
        }
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
///
/// With no filter while attached to a process (attach, .process), the
/// command lists that process's threads, and * lists every thread. The start
/// address is the thread's own entry (its Win32 start address), else where
/// the kernel started it, named from the symbols loaded: the kernel's, and
/// the attached process's.
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
        // Unfiltered, the attached process's; `*`, every thread.
        let attached = repl.ctx.target.attached_process().cloned();
        let scope = attached.as_ref().filter(|_| filter.is_none());
        let number =
            filter
                .as_deref()
                .and_then(|filter| match Expr::parse_with_radix(filter, repl.radix) {
                    Ok(Expr::Literal(number)) => Some(number.0),
                    _ => None,
                });
        let threads: Vec<&ThreadInfo> = self
            .threads
            .iter()
            .filter(|thread| match (filter.as_deref(), scope) {
                (Some("*"), _) | (None, None) => true,
                (Some(filter), _) => thread_matches_filter(thread, filter, number),
                (None, Some(process)) => thread.eprocess == Some(process.eprocess),
            })
            .collect();
        if let Some(process) = scope {
            outln!(
                "{}",
                ui::muted(&format!(
                    "threads of {} (PID {}); `threads *` lists every thread",
                    process.name, process.pid
                ))
            );
        }
        if threads.is_empty() {
            let note = match filter.as_deref() {
                Some(filter) => format!("no threads matching '{filter}'"),
                None => "no threads".to_string(),
            };
            outln!("{}", ui::muted(&note));
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
            "Wait reason".to_string(),
            "Start address".to_string(),
        ]);
        for thread in threads {
            let active_vcpu = self
                .active
                .get(&thread.ethread.0)
                .map_or_else(|| "-".to_string(), |vcpu| thread_label(vcpu));
            let start = thread
                .win32_start_address
                .filter(|address| address.0 != 0)
                .or(thread.start_address);
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
                thread.process_name.as_deref().unwrap_or("-").to_string(),
                thread_state_label(thread).to_string(),
                wait_reason_label(thread).to_string(),
                start
                    .map(|address| start_label(repl, thread, address))
                    .unwrap_or_else(|| "-".to_string()),
            ]);
        }
        print_padded_table(builder);
    }
}

/// A thread's start `address`, named where its symbols are loaded: kernel
/// code, and the code of the attached process, whose modules are. Naming
/// another process's would load every process's symbols.
fn start_label(repl: &ReplState<'_>, thread: &ThreadInfo, address: VirtAddr) -> String {
    let target = &repl.ctx.target;
    let symbol = if target.arch().paging().is_kernel_address(address) {
        target
            .symbols
            .format_closest_symbol_for_address(target.kernel_dtb(), address)
    } else if target
        .attached_process()
        .is_some_and(|process| thread.eprocess == Some(process.eprocess))
    {
        target.closest_symbol_current_context(address)
    } else {
        None
    };
    symbol.unwrap_or_else(|| ui::addr(address.0).to_string())
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
            outln!("cleared the thread selection");
        } else {
            outln!("reset thread context to {}", ui::thread(&current));
        }
        return Ok(());
    };
    match state.ctx.select_windows_thread(&thread) {
        Ok(ThreadContext::Live(vcpu)) => outln!(
            "switched register context to {} (thread {:#x})",
            ui::thread(&vcpu),
            thread.ethread.0
        ),
        Ok(ThreadContext::SavedVtl0(vcpu)) => outln!(
            "switched register context to the VTL0 state the hypervisor saved for {} (thread {:#x})",
            ui::thread(&vcpu),
            thread.ethread.0
        ),
        Ok(ThreadContext::Parked) => outln!(
            "selected the stack of parked thread {:#x}; it has no register context",
            thread.ethread.0
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
