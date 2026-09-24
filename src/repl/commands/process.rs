use tabled::builder::Builder;

use owo_colors::OwoColorize;

use crate::error::{Error, Result};
use crate::expr::Expr;
use crate::guest::ProcessInfo;
use crate::symbols::glob_matches;
use crate::target::sched::ProcessDetail;
use crate::target::{AttachReport, decimal_pid_literal, process_matches};
use crate::triage_report::time::filetime_to_iso;
use crate::types::VirtAddr;
use crate::ui;

use crate::repl::*;

use super::thread::{THREAD_STACK_LIMIT, print_thread_extended_detail};

const MAX_PROCESS_THREADS: usize = 512;

repl_command! {
    cmd_process;
    names: ["!process"],
    usage: "!process [eprocess|pid|0] [flags] [image-name]",
    summary: "List or inspect Windows processes.",
    details: "`!process 0 0` lists all processes; bit 1 adds process detail, bit 2 adds threads, and bit 4 adds each thread's stack. `ps` retains its concise legacy listing.",
    completion: [Process, None, Process],
}

repl_command! {
    cmd_process;
    names: ["ps"],
    usage: "ps [filter]",
    summary: "List running processes.",
    completion: Process,
}

repl_command! {
    cmd_attach;
    names: ["attach"],
    usage: "attach <pid>",
    summary: "Attach to a process by PID.",
    completion: Process,
}

repl_command! {
    cmd_process_context;
    names: [".process"],
    usage: ".process [/i] [/p] [/r] [eprocess|pid]",
    summary: "Select a process address space for inspection.",
    details: "For this debugger `/i` is equivalent to attach; `/p` and `/r` select the same non-invasive context. With no argument, print the current process context.",
    completion: Process,
}

repl_command! {
    cmd_detach();
    names: ["detach"],
    usage: "detach",
    summary: "Detach from current process.",
}

repl_command! {
    cmd_context;
    names: [".context"],
    usage: ".context <dtb>",
    summary: "Set the translation base used for inspection.",
    completion: Expression,
}

struct ProcessArguments<'a> {
    selector: Option<&'a str>,
    flags: Option<&'a str>,
    image: Option<&'a str>,
}

fn parse_process_arguments<'a>(
    args: &'a [&'a str],
) -> std::result::Result<ProcessArguments<'a>, String> {
    if args.len() > 3 {
        return Err("!process accepts at most a selector, flags, and image name".to_string());
    }
    let selector = args.first().copied();
    Ok(ProcessArguments {
        selector,
        flags: args.get(1).copied(),
        image: args.get(2).copied(),
    })
}

pub(super) fn display_decimal(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_string())
}

pub(super) fn display_pointer(value: Option<VirtAddr>) -> String {
    value
        .filter(|value| !value.is_zero())
        .map(|value| ui::addr(value.0))
        .unwrap_or_else(|| "-".to_string())
}

fn process_brief_row(process: &ProcessInfo, detail: &ProcessDetail) -> Vec<String> {
    vec![
        display_pointer(Some(process.eprocess_va)),
        display_decimal(detail.session_id.map(u64::from)),
        format!("{} ({:#x})", process.pid, process.pid),
        display_pointer(detail.peb),
        display_pointer(process.wow64_peb),
        display_decimal(detail.parent_pid),
        display_pointer(detail.directory_table_base.map(VirtAddr)),
        display_pointer(detail.object_table),
        display_decimal(detail.handle_count),
        process.name.clone(),
    ]
}

fn print_process_detail(process: &ProcessInfo, detail: &ProcessDetail) {
    outln!("  VadRoot        {}", display_pointer(detail.vad_root));
    outln!("  Token         {}", display_pointer(detail.token));
    outln!("  Wow64Peb      {}", display_pointer(process.wow64_peb));
    outln!(
        "  CreateTime    {}",
        detail
            .create_time
            .and_then(filetime_to_iso)
            .unwrap_or_else(|| "-".to_string())
    );
    outln!("  UserTime      {}", display_decimal(detail.user_time));
    outln!("  KernelTime    {}", display_decimal(detail.kernel_time));
    outln!(
        "  QuotaPoolUsage paged={} nonpaged={}",
        display_decimal(detail.quota_paged_pool),
        display_decimal(detail.quota_nonpaged_pool)
    );
    outln!(
        "  WorkingSet    {}  Commit={}  PeakVirtualSize={}  PrivatePageCount={}",
        display_decimal(detail.working_set_size),
        display_decimal(detail.commit_charge),
        display_decimal(detail.peak_virtual_size),
        display_decimal(detail.private_page_count),
    );
    outln!(
        "  DebugPort     {}  Job={}",
        display_pointer(detail.debug_port),
        display_pointer(detail.job)
    );
}

impl ReplState<'_> {
    pub(super) fn current_process_context(&self, processes: &[ProcessInfo]) -> Option<ProcessInfo> {
        if let Some(process) = self.ctx.target.attached_process() {
            return Some(process.clone());
        }
        if let Some(thread) = &self.ctx.target.windows_thread_selection
            && let Some(process) = processes.iter().find(|process| {
                thread.eprocess == Some(process.eprocess_va)
                    || thread.pid.is_some_and(|pid| pid == process.pid)
            })
        {
            return Some(process.clone());
        }
        self.ctx
            .target
            .process_for_cr3(self.ctx.target.current_dtb())
    }

    pub fn process_for_selector(
        &self,
        selector: &str,
        processes: &[ProcessInfo],
    ) -> Option<ProcessInfo> {
        // A bare decimal PID first: that is the spelling every listing prints
        // and tab completion inserts, and reading it in the session radix
        // would silently select a different process (or none).
        if let Some(pid) = decimal_pid_literal(selector)
            && let Some(process) = processes.iter().find(|process| process.pid == pid)
        {
            return Some(process.clone());
        }
        let address = Expr::eval_with_radix(selector, &self.ctx.target, self.radix).ok();
        if let Some(address) = address
            && let Some(process) = processes
                .iter()
                .find(|process| process.eprocess_va == address)
        {
            return Some(process.clone());
        }
        address
            .map(|address| address.0)
            .and_then(|pid| processes.iter().find(|process| process.pid == pid).cloned())
    }

    fn print_process_threads(&mut self, process: &ProcessInfo, include_stack: bool) {
        let mut threads = match self.ctx.target.enumerate_threads_for_process_info(process) {
            Ok(threads) => threads,
            Err(error) => {
                error!("  thread list unavailable: {}", error);
                return;
            }
        };
        let truncated = threads.len() > MAX_PROCESS_THREADS;
        threads.truncate(MAX_PROCESS_THREADS);
        *self.caches.threads.write().unwrap() = threads.clone();
        for thread in &threads {
            print_thread_extended_detail(&self.ctx.target, thread);
            if include_stack {
                match self.ctx.backtrace_thread(thread, THREAD_STACK_LIMIT) {
                    Ok(trace) => {
                        outln!("  k-stack ({}):", trace.source.as_str());
                        print_stacktrace_data_with_provenance(
                            &trace.stacktrace,
                            THREAD_STACK_LIMIT,
                            true,
                        );
                    }
                    Err(error) => error!(
                        "  k-stack {} unavailable: {}",
                        ui::addr(thread.ethread.0),
                        error
                    ),
                }
            }
        }
        if truncated {
            outln!("  thread list truncated at {MAX_PROCESS_THREADS} entries");
        }
    }

    fn cmd_process(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if invocation.name == "ps" {
            return self.cmd_ps_legacy(invocation.arg(0));
        }
        let args = invocation
            .argv
            .iter()
            .map(|arg| arg.as_ref())
            .collect::<Vec<_>>();
        let parsed = match parse_process_arguments(&args) {
            Ok(parsed) => parsed,
            Err(error) => {
                error!("{}", error);
                return Ok(());
            }
        };
        let flags = match parsed.flags {
            Some(text) => {
                match Expr::eval_with_radix(text, &self.ctx.target, self.radix).and_then(|value| {
                    u32::try_from(value.0).map_err(|_| {
                        Error::InvalidArgument(format!("invalid !process flags: {text}"))
                    })
                }) {
                    Ok(flags) => flags,
                    Err(_) => {
                        error!("invalid !process flags: {}", text);
                        return Ok(());
                    }
                }
            }
            None => 0,
        };
        if flags & 4 != 0 && self.ctx.backend.is_running() {
            error!("VM is running; process stacks require a halted target");
            return Ok(());
        }
        let processes = match self.ctx.target.matching_processes(None) {
            Ok(processes) => processes,
            Err(error) => {
                error!("failed to enumerate processes: {}", error);
                return Ok(());
            }
        };
        *self.caches.processes.write().unwrap() = processes
            .iter()
            .map(|process| (process.name.clone(), process.pid))
            .collect();

        let mut selected = if let Some(selector) = parsed.selector {
            if selector == "0" {
                processes.clone()
            } else {
                self.process_for_selector(selector, &processes)
                    .into_iter()
                    .collect()
            }
        } else {
            self.current_process_context(&processes)
                .into_iter()
                .collect()
        };
        if let Some(filter) = parsed.image {
            selected.retain(|process| {
                glob_matches(filter, &process.name, true)
                    || process.name.eq_ignore_ascii_case(filter)
                    || process_matches(process, filter)
            });
        }
        if selected.is_empty() {
            error!("no matching process");
            return Ok(());
        }

        let mut builder = Builder::default();
        builder.push_record(vec![
            "PROCESS".to_string(),
            "SessionId".to_string(),
            "Cid".to_string(),
            "Peb".to_string(),
            "Wow64".to_string(),
            "ParentCid".to_string(),
            "DirBase".to_string(),
            "ObjectTable".to_string(),
            "HandleCount".to_string(),
            "Image".to_string(),
        ]);
        let details: Vec<ProcessDetail> = selected
            .iter()
            .map(|process| self.ctx.target.process_detail(process))
            .collect();
        for (process, detail) in selected.iter().zip(&details) {
            builder.push_record(process_brief_row(process, detail));
        }
        print_padded_table(builder);

        if flags & 1 != 0 || flags & 2 != 0 || flags & 4 != 0 {
            for (process, detail) in selected.iter().zip(&details) {
                outln!(
                    "{} {} ({})",
                    ui::label("process:"),
                    ui::addr(process.eprocess_va.0),
                    process.name
                );
                if flags & 1 != 0 {
                    print_process_detail(process, detail);
                }
                if flags & 2 != 0 || flags & 4 != 0 {
                    self.print_process_threads(process, flags & 4 != 0);
                }
            }
        }
        Ok(())
    }

    fn cmd_ps_legacy(&mut self, filter: Option<&str>) -> Result<()> {
        let processes = match self.ctx.target.matching_processes(None) {
            Ok(processes) => processes,
            Err(error) => {
                error!("failed to enumerate processes: {}", error);
                return Ok(());
            }
        };
        *self.caches.processes.write().unwrap() = processes
            .iter()
            .map(|process| (process.name.clone(), process.pid))
            .collect();
        let mut builder = Builder::default();
        builder.push_record(vec![
            "Name".to_string(),
            "PID".to_string(),
            "EPROCESS".to_string(),
            "DTB".to_string(),
            "Wow64".to_string(),
        ]);
        let mut count = 0;
        for process in processes {
            if filter.is_some_and(|filter| !process_matches(&process, filter)) {
                continue;
            }
            count += 1;
            builder.push_record(vec![
                process.name.to_string(),
                format!("{}", ui::Value(process.pid)),
                ui::addr(process.eprocess_va.0).to_string(),
                ui::addr(process.dtb),
                if process.is_wow64() { "x86" } else { "-" }.to_string(),
            ]);
        }
        if count == 0 {
            outln!("{}\n", "no matching processes".bright_black());
        } else {
            print_padded_table(builder);
        }
        Ok(())
    }

    fn cmd_attach(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let pid_str = require_arg!(invocation, 0, "attach");
        // Same selector grammar as `.process`, so a PID copied from `ps` (or
        // inserted by completion) means the same thing in both.
        let processes = match self.ctx.target.matching_processes(None) {
            Ok(processes) => processes,
            Err(error) => {
                error!("failed to enumerate processes: {}", error);
                return Ok(());
            }
        };
        let Some(process) = self.process_for_selector(pid_str, &processes) else {
            error!("no process matches '{}'", pid_str);
            return Ok(());
        };
        match self.ctx.target.attach(process.pid) {
            Ok(AttachReport {
                name,
                symbol_report,
            }) => {
                self.caches.refresh_symbol_context(&self.ctx.target);
                self.clear_selected_frame();
                outln!("attached to {} (PID {})", name, process.pid);
                print_module_symbol_report(&symbol_report);
                outln!();
            }
            Err(e) => error!("failed to attach: {}", e),
        }

        Ok(())
    }

    fn cmd_process_context(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let mut selector = None;
        for arg in &invocation.argv {
            let arg = arg.as_ref();
            if arg.starts_with('/') {
                if !matches!(arg, "/i" | "/p" | "/r") {
                    error!("unknown .process switch '{}'; expected /i, /p, or /r", arg);
                    return Ok(());
                }
            } else if selector.replace(arg).is_some() {
                error!(".process accepts one process selector");
                return Ok(());
            }
        }
        if selector == Some("0") {
            return self.cmd_detach();
        }
        let processes = match self.ctx.target.matching_processes(None) {
            Ok(processes) => processes,
            Err(error) => {
                error!("failed to enumerate processes: {}", error);
                return Ok(());
            }
        };
        let Some(selector) = selector else {
            if let Some(process) = self.current_process_context(&processes) {
                outln!(
                    "process context: {} {} (PID {}, DTB {}{})\n",
                    ui::addr(process.eprocess_va.0),
                    process.name,
                    process.pid,
                    ui::addr(process.dtb),
                    if process.is_wow64() { ", WOW64" } else { "" },
                );
            } else {
                outln!(
                    "process context: kernel (DTB {})\n",
                    ui::addr(self.ctx.target.kernel_dtb())
                );
            }
            return Ok(());
        };
        let Some(process) = self.process_for_selector(selector, &processes) else {
            error!("no process matches '{}'", selector);
            return Ok(());
        };
        match self.ctx.target.attach_process_info(process.clone()) {
            Ok(AttachReport {
                name,
                symbol_report,
            }) => {
                self.caches.refresh_symbol_context(&self.ctx.target);
                self.clear_selected_frame();
                outln!(
                    "process context: {} (PID {}, EPROCESS {}{})",
                    name,
                    process.pid,
                    ui::addr(process.eprocess_va.0),
                    if process.is_wow64() { ", WOW64" } else { "" },
                );
                print_module_symbol_report(&symbol_report);
            }
            Err(error) => error!("failed to select process context: {}", error),
        }
        Ok(())
    }

    fn cmd_context(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let text = require_arg!(invocation, 0, ".context");
        let dtb = match Expr::eval_with_radix(text, &self.ctx.target, self.radix) {
            Ok(value) => value,
            Err(error) => {
                error!("invalid translation base '{}': {}", text, error);
                return Ok(());
            }
        };
        if self.ctx.target.attached_process().is_some() {
            self.ctx.target.detach();
        }
        self.clear_selected_frame();
        self.ctx.target.set_context_dtb_override(dtb.0);
        self.caches.refresh_symbol_context(&self.ctx.target);
        outln!("inspection context DTB set to {}\n", ui::addr(dtb.0));
        Ok(())
    }

    fn cmd_detach(&mut self) -> Result<()> {
        if self.ctx.target.attached_process().is_none() {
            error!("not attached to any process");
        } else {
            self.ctx.target.detach();
            self.caches.refresh_symbol_context(&self.ctx.target);
            self.clear_selected_frame();
            outln!("detached, now in kernel context\n");
        }

        Ok(())
    }
}
