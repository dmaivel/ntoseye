//! Windows thread commands: listing threads, inspecting one with its
//! stack, and switching the register and stack context to it.

use std::collections::HashMap;

use tabled::builder::Builder;

use owo_colors::OwoColorize;

use crate::bugchecks::looks_like_kernel_pointer;
use crate::dbg_backend::processor_index_from_backend_thread_id;
use crate::error::Result;
use crate::expr::Expr;
use crate::target::{Target, ThreadInfo, kthread_state_name, wait_reason_name};
use crate::types::VirtAddr;
use crate::ui;

use crate::repl::*;

use super::process::{display_decimal, display_pointer};

pub enum ThreadResolution {
    Found(ThreadInfo),
    Missing,
    Ambiguous(usize),
}

pub(super) const THREAD_STACK_LIMIT: usize = 32;
const DEFAULT_THREAD_FRAME_LIMIT: usize = 16;

repl_command! {
    cmd_threads;
    names: ["threads"],
    usage: "threads [filter]",
    summary: "List Windows threads, optionally filtered by process, PID, TID, or ETHREAD.",
    completion: Process,
    run_state: Halted,
}

repl_command! {
    cmd_thread;
    names: ["!thread", "thread"],
    usage: "!thread [ethread|tid] [flags] [count]",
    summary: "Display a Windows thread and optionally its kernel stack.",
    details: "The legacy `thread <tid> k|r [count]` forms remain available. A numeric flags value selects detail/stack output; unavailable fields are shown as `-`.",
    completion: [Thread, None, None],
    run_state: Halted,
}

repl_command! {
    cmd_dot_thread;
    names: [".thread"],
    usage: ".thread [ethread|tid]",
    summary: "Switch the register and stack context to a Windows thread.",
    completion: Thread,
    run_state: Halted,
}

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

fn print_thread_detail(thread: &ThreadInfo) {
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

pub(super) fn print_thread_extended_detail(target: &Target, thread: &ThreadInfo) {
    print_thread_detail(thread);
    let detail = target.thread_extended_detail(thread);
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
    fn cmd_threads(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let filter = invocation.arg(0);
        let (mut threads, active) = match self.ctx.windows_threads() {
            Ok(result) => result,
            Err(e) => {
                error!("failed to enumerate threads: {}", e);
                return Ok(());
            }
        };
        // Completion wants every thread, not just the ones this listing shows.
        *self.caches.threads.write().unwrap() = threads.clone();
        if let Some(filter) = filter {
            threads.retain(|thread| thread_matches_filter(thread, filter));
        }

        if threads.is_empty() {
            outln!("{}\n", "no matching threads".bright_black());
            return Ok(());
        }

        let mut builder = Builder::default();
        builder.push_record(vec![
            "Active".to_string(),
            "ETHREAD".to_string(),
            "PID".to_string(),
            "TID".to_string(),
            "Process".to_string(),
            "State".to_string(),
            "Wait".to_string(),
            "Start".to_string(),
        ]);
        for thread in &threads {
            let active_vcpu = active
                .get(&thread.ethread.0)
                .map(|vcpu| vcpu.as_str())
                .unwrap_or("-");
            let start = thread.start_address.or(thread.win32_start_address);
            builder.push_record(vec![
                active_vcpu.to_string(),
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
        Ok(())
    }

    fn windows_thread_candidates(&mut self) -> Result<Vec<ThreadInfo>> {
        self.ctx.windows_thread_candidates()
    }

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
            if looks_like_kernel_pointer(value)
                && let Ok(thread) = self.ctx.target.thread_info_from_ethread(VirtAddr(value))
                && let Ok(processes) = self.ctx.target.guest()?.enumerate_processes()
                && thread
                    .eprocess
                    .is_some_and(|owner| processes.iter().any(|p| p.eprocess_va == owner))
            {
                return Ok(ThreadResolution::Found(thread));
            }
        }
        let threads = self.windows_thread_candidates()?;
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

    fn cmd_thread(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let active = self.ctx.active_thread_map();

        let target = invocation.arg(0).unwrap_or(".");
        let current_alias_address = if target == "." {
            self.ctx
                .target
                .windows_thread_selection
                .as_ref()
                .map(|thread| thread.ethread)
                .or_else(|| {
                    processor_index_from_backend_thread_id(&self.ctx.current_thread).and_then(
                        |processor| {
                            self.ctx
                                .target
                                .current_windows_thread_for_processor(processor)
                                .ok()
                                .map(|thread| thread.ethread)
                        },
                    )
                })
        } else {
            None
        };
        let target_value = current_alias_address
            .or_else(|| Expr::eval_with_radix(target, &self.ctx.target, self.radix).ok())
            .map(|address| address.0);
        let thread = match self.resolve_windows_thread(target_value, &active) {
            Ok(ThreadResolution::Found(thread)) => thread,
            Ok(ThreadResolution::Missing) => {
                error!("no Windows thread matches '{}'", target);
                return Ok(());
            }
            Ok(ThreadResolution::Ambiguous(count)) => {
                error!("ambiguous Windows thread '{}': {} matches", target, count);
                return Ok(());
            }
            Err(e) => {
                error!("failed to enumerate threads: {}", e);
                return Ok(());
            }
        };
        let thread = &thread;

        let action = invocation.arg(1);
        let numeric_action = action.and_then(|text| {
            Expr::eval_with_radix(text, &self.ctx.target, self.radix)
                .ok()
                .map(|value| value.0)
        });
        let default_stack = invocation.name == "!thread"
            && (action.is_none() || numeric_action.is_some_and(|flags| flags & 4 != 0));
        let frame_limit = invocation
            .arg(2)
            .and_then(|count| {
                Expr::eval_with_radix(count, &self.ctx.target, self.radix)
                    .ok()
                    .and_then(|value| usize::try_from(value.0).ok())
            })
            .unwrap_or(DEFAULT_THREAD_FRAME_LIMIT)
            .max(1);

        let Some((vcpu, _)) = active.get(&thread.ethread.0) else {
            print_thread_extended_detail(&self.ctx.target, thread);
            outln!(
                "{}",
                "thread is parked: stack inspection is available, registers are not".bright_black()
            );
            self.ctx.select_parked_windows_thread(thread);
            self.clear_selected_frame();
            self.caches.refresh_symbol_context(&self.ctx.target);
            if default_stack {
                match self.ctx.backtrace_thread(thread, THREAD_STACK_LIMIT) {
                    Ok(trace) => {
                        outln!("k-stack ({}):", trace.source.as_str());
                        print_stacktrace_data_with_provenance(
                            &trace.stacktrace,
                            THREAD_STACK_LIMIT,
                            false,
                        );
                    }
                    Err(error) => error!("failed to unwind thread stack: {}", error),
                }
            } else {
                match action {
                    Some("k") => match self.ctx.backtrace(frame_limit) {
                        Ok(stacktrace) => {
                            print_stacktrace_data_with_provenance(&stacktrace, frame_limit, false)
                        }
                        Err(error) => error!("failed to unwind parked thread stack: {}", error),
                    },
                    Some("r" | "registers") => error!(
                        "parked thread has no coherent register context; select a live vCPU with `vcpu <id>`"
                    ),
                    Some(_) if numeric_action.is_some() => {}
                    Some(other) => {
                        error!("unknown thread action '{}': expected k or r", other)
                    }
                    None => {}
                }
            }
            outln!();
            return Ok(());
        };

        if let Err(e) = self.ctx.set_current_thread(vcpu) {
            error!("failed to switch to vCPU {}: {:?}", vcpu, e);
            return Ok(());
        }
        self.clear_selected_frame();
        self.ctx
            .target
            .set_current_windows_thread_context((*thread).clone());
        self.caches.refresh_symbol_context(&self.ctx.target);
        outln!(
            "switched to {} running ETHREAD {}\n",
            self.ctx.current_thread,
            ui::addr(thread.ethread.0)
        );
        print_thread_extended_detail(&self.ctx.target, thread);

        if default_stack {
            self.print_live_kstack();
        } else {
            match action {
                Some("k") => {
                    let regs = match self.ctx.read_registers() {
                        Ok(regs) => regs,
                        Err(e) => {
                            error!("failed to read registers: {:?}", e);
                            return Ok(());
                        }
                    };
                    print_stacktrace(
                        &self.ctx.target,
                        &self.ctx.register_map,
                        &regs,
                        frame_limit,
                        frame_limit,
                        false,
                    );
                }
                Some("r" | "registers") => {
                    let regs = match self.ctx.read_registers() {
                        Ok(regs) => regs,
                        Err(e) => {
                            error!("failed to read registers: {:?}", e);
                            return Ok(());
                        }
                    };
                    print_registers(&self.ctx.register_map, &regs, false);
                }
                Some(_) if numeric_action.is_some() => {}
                Some(other) => error!("unknown thread action '{}': expected k or r", other),
                None => {}
            }
        }
        outln!();
        Ok(())
    }

    fn print_live_kstack(&mut self) {
        match self.ctx.backtrace(THREAD_STACK_LIMIT) {
            Ok(trace) => {
                outln!("k-stack (live):");
                print_stacktrace_data(&trace, THREAD_STACK_LIMIT, false);
            }
            Err(error) => error!("failed to unwind thread stack: {}", error),
        }
    }

    fn cmd_dot_thread(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(selector) = invocation.arg(0) else {
            let current = self.ctx.current_thread.clone();
            if let Err(error) = self.ctx.reset_windows_thread() {
                error!("failed to reset thread context: {}", error);
                return Ok(());
            }
            self.clear_selected_frame();
            self.caches.refresh_symbol_context(&self.ctx.target);
            outln!("reset thread context to {}\n", current);
            return Ok(());
        };

        let threads = match self.windows_thread_candidates() {
            Ok(threads) => threads,
            Err(error) => {
                error!("failed to enumerate threads: {}", error);
                Vec::new()
            }
        };
        let target_value = Expr::eval_with_radix(selector, &self.ctx.target, self.radix)
            .ok()
            .map(|address| address.0);
        let matches = threads
            .iter()
            .filter(|thread| Self::thread_matches_value(thread, target_value))
            .collect::<Vec<_>>();
        let Some(thread) = (match matches.as_slice() {
            [thread] => Some(*thread),
            [] => {
                error!("no Windows thread matches '{}'", selector);
                None
            }
            many => {
                error!(
                    "ambiguous Windows thread '{}': {} matches",
                    selector,
                    many.len()
                );
                None
            }
        }) else {
            return Ok(());
        };

        let thread = thread.clone();
        match self.ctx.select_windows_thread(&thread) {
            Ok(Some(vcpu)) => {
                self.clear_selected_frame();
                outln!(
                    "switched register context to {} (ETHREAD {})\n",
                    vcpu,
                    ui::addr(thread.ethread.0)
                );
            }
            Ok(None) => {
                self.clear_selected_frame();
                outln!(
                    "selected parked thread context ETHREAD {} (stack only)\n",
                    ui::addr(thread.ethread.0)
                );
            }
            Err(error) => {
                error!("failed to switch thread context: {}", error);
                return Ok(());
            }
        }
        self.caches.refresh_symbol_context(&self.ctx.target);
        Ok(())
    }
}
