use std::collections::HashMap;

use tabled::builder::Builder;

use owo_colors::OwoColorize;

use ntoseye_macros::{command, grammar};

use crate::error::{Error, Result};
use crate::expr::Expr;
use crate::guest::ProcessInfo;
use crate::symbols::glob_matches;
use crate::target::sched::ProcessDetail;
use crate::target::{AttachReport, decimal_pid_literal, process_by_name, process_matches};
use crate::time::filetime_to_iso;
use crate::types::VirtAddr;
use crate::ui;

use crate::repl::args::{ArgCursor, ArgCx, ArgError};
use crate::repl::*;
use crate::session::Session;

use super::thread::{THREAD_STACK_LIMIT, print_thread_detail};

const MAX_PROCESS_THREADS: usize = 512;

/// List or inspect Windows processes.
///
/// `!process 0 0` lists all processes. Bit 1 adds process details, bit 2
/// adds threads, and bit 4 adds the stack of each thread. An image name in
/// place of the process shows every process whose name contains it or
/// matches it as a glob, as the last argument filters: `!process
/// explorer.exe` shows explorer.exe, and `!process svchost 0` lists each
/// svchost.exe. `ps` keeps its short legacy list format.
#[command(
    names = ["!process"],
    category = "processes and modules",
    kind = Query,
    target = Kernel,
    python = Process,
    python_name = "inspect",
)]
fn process(
    session: &Session,
    #[arg(receiver, each = process_selection)] process: ProcessInfo,
    #[arg(render, parse = process_flags)] flags: u32,
) -> Result<ProcessDetail> {
    Ok(session.target.process_detail(process))
}

/// The processes `!process <process> [flags] [image]` names: `0` is every
/// process, an EPROCESS or PID one, anything else an image name; the image
/// name filters them, and none is the current process.
#[grammar(usage = "[eprocess|pid|image-name|0]", complete = [Process])]
fn process_selection(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Vec<ProcessInfo>, ArgError> {
    if cursor.remaining() > 3 {
        return Err(ArgError::Message(
            "!process accepts at most a selector, flags, and image name".to_string(),
        ));
    }
    let selector = cursor.word();
    let image = cursor.word_at(1);
    let state = &*cx.state;
    let processes =
        state.ctx.target.matching_processes(None).map_err(|error| {
            ArgError::Message(format!("failed to enumerate processes: {error}"))
        })?;
    state.caches.remember_processes(&processes);
    let mut selected = match selector.as_deref() {
        Some("0") => processes,
        Some(selector) => match state.process_for_selector(selector, &processes) {
            Some(process) => vec![process],
            // Neither an EPROCESS nor a PID: an image name, matched as
            // the last argument matches one.
            None => processes
                .into_iter()
                .filter(|process| image_matches(process, selector))
                .collect(),
        },
        None => state.ctx.target.current_process().into_iter().collect(),
    };
    if let Some(filter) = &image {
        selected.retain(|process| image_matches(process, filter));
    }
    if selected.is_empty() {
        return Err(ArgError::Message(match (selector.as_deref(), image) {
            (Some(selector), None) if selector != "0" => format!(
                "no process has the EPROCESS, PID, or image name '{selector}'; `!process 0 0` \
                 lists them"
            ),
            _ => "no matching process".to_string(),
        }));
    }
    Ok(selected)
}

/// `!process`'s flags: 1 details, 2 threads, 4 their stacks.
#[grammar(usage = "[flags] [image-name]", complete = [None, Process])]
fn process_flags(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<u32, ArgError> {
    let Some(text) = cursor.word() else {
        return Ok(0);
    };
    cx.eval(&text)
        .ok()
        .and_then(|value| u32::try_from(value.0).ok())
        .ok_or_else(|| ArgError::Message(format!("invalid !process flags: {text}")))
}

impl Render<u32> for Vec<ProcessDetail> {
    fn render(&self, repl: &mut ReplState<'_>, flags: u32) {
        #[cfg(feature = "cli")]
        native::render(
            || native::lists::processes(self),
            || print_process_briefs(self),
        );
        #[cfg(not(feature = "cli"))]
        print_process_briefs(self);

        if flags & 7 == 0 {
            return;
        }
        for detail in self {
            let process = &detail.process;
            outln!(
                "{} {} ({})",
                ui::label("process:"),
                ui::addr(process.eprocess.0),
                process.name
            );
            if flags & 1 != 0 {
                print_process_detail(detail);
            }
            if flags & 6 != 0 && !repl.print_process_threads(process, flags & 4 != 0) {
                break;
            }
        }
    }
}

/// List running processes.
#[command(
    names = ["ps"],
    category = "processes and modules",
    kind = Query,
    target = Kernel,
    python = none,
)]
fn ps(
    session: &Session,
    #[arg(render, complete = Process)] filter: Option<String>,
) -> Result<Vec<ProcessInfo>> {
    session
        .target
        .matching_processes(None)
        .map_err(|error| Error::DebugInfo(format!("failed to enumerate processes: {error}")))
}

/// `ps`: the short legacy list, of the processes `filter` matches.
impl Render<Option<String>> for Vec<ProcessInfo> {
    fn render(&self, repl: &mut ReplState<'_>, filter: Option<String>) {
        repl.caches.remember_processes(self);
        let shown = self
            .iter()
            .filter(|process| {
                filter
                    .as_deref()
                    .is_none_or(|filter| process_matches(process, filter))
            })
            .cloned()
            .collect::<Vec<_>>();
        if shown.is_empty() {
            outln!("{}\n", "no matching processes".bright_black());
            return;
        }
        #[cfg(feature = "cli")]
        native::render(|| native::lists::ps(&shown), || print_ps(&shown));
        #[cfg(not(feature = "cli"))]
        print_ps(&shown);
    }
}

/// What `.process` selects.
enum ProcessContext {
    /// `0`: the kernel's, as `detach`.
    Kernel,
    Process(ProcessInfo),
}

#[grammar(usage = "[eprocess|pid|0]", complete = [Process])]
fn process_context_selector(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Option<ProcessContext>, ArgError> {
    let Some(selector) = cursor.word() else {
        return Ok(None);
    };
    if cursor.remaining() > 0 {
        return Err(ArgError::Message(
            ".process accepts one process selector".to_string(),
        ));
    }
    if selector == "0" {
        return Ok(Some(ProcessContext::Kernel));
    }
    let state = &*cx.state;
    let processes =
        state.ctx.target.matching_processes(None).map_err(|error| {
            ArgError::Message(format!("failed to enumerate processes: {error}"))
        })?;
    match state.process_for_selector(&selector, &processes) {
        Some(process) => Ok(Some(ProcessContext::Process(process))),
        None => Err(ArgError::Message(format!(
            "no process matches '{selector}'"
        ))),
    }
}

/// Select a process address space to inspect.
///
/// In this debugger, `/i` is the same as attach. `/p` and `/r` select the
/// same non-invasive context. With no argument, the command prints the
/// current process context.
#[command(
    names = [".process"],
    category = "processes and modules",
    kind = Action,
    target = Machine,
    python = none,
)]
fn process_context(
    state: &mut ReplState<'_>,
    #[arg(switch = "/i")] _invasive: bool,
    #[arg(switch = "/p")] _translate: bool,
    #[arg(switch = "/r")] _reload: bool,
    #[arg(parse = process_context_selector)] selection: Option<ProcessContext>,
) -> Result<()> {
    let process = match selection {
        Some(ProcessContext::Kernel) => return detach(state),
        Some(ProcessContext::Process(process)) => process,
        None => {
            state.print_process_context();
            return Ok(());
        }
    };
    state.leave_vtl1();
    let report = state
        .ctx
        .target
        .attach_process_info(process.clone())
        .map_err(|error| Error::DebugInfo(format!("failed to select process context: {error}")))?;
    state.caches.refresh_symbol_context(&state.ctx.target);
    state.clear_selected_frame();
    outln!(
        "process context: {} (PID {}, EPROCESS {}{})",
        report.name,
        process.pid,
        ui::addr(process.eprocess.0),
        if process.is_wow64() { ", WOW64" } else { "" },
    );
    print_user_modules(&report);
    Ok(())
}

/// Attach to a process by PID.
#[command(
    names = ["attach"],
    category = "processes and modules",
    kind = Action,
    target = Machine,
    python = none,
)]
fn attach(state: &mut ReplState<'_>, #[arg(complete = Process)] pid: String) -> Result<()> {
    // Same selector grammar as `.process`, so a PID copied from `ps` (or
    // inserted by completion) means the same thing in both.
    let processes = match state.ctx.target.matching_processes(None) {
        Ok(processes) => processes,
        Err(error) => {
            error!("failed to enumerate processes: {}", error);
            return Ok(());
        }
    };
    let Some(process) = state.process_for_selector(&pid, &processes) else {
        error!("no process matches '{}'", pid);
        return Ok(());
    };
    state.leave_vtl1();
    match state.ctx.target.attach(process.pid) {
        Ok(report) => {
            state.caches.refresh_symbol_context(&state.ctx.target);
            state.clear_selected_frame();
            outln!("attached to {} (PID {})", report.name, process.pid);
            print_user_modules(&report);
            outln!();
        }
        Err(e) => error!("failed to attach: {}", e),
    }

    Ok(())
}

/// Detach from the current process.
#[command(
    names = ["detach"],
    category = "processes and modules",
    kind = Action,
    target = Machine,
    python = none
)]
fn detach(state: &mut ReplState<'_>) -> Result<()> {
    if state.ctx.target.attached_process().is_none() && !state.ctx.target.in_secure_scope() {
        error!("not attached to any process");
    } else {
        state.leave_vtl1();
        state.ctx.target.detach();
        state.caches.refresh_symbol_context(&state.ctx.target);
        state.clear_selected_frame();
        outln!("detached, now in kernel context\n");
    }

    Ok(())
}

/// Set the translation base that inspection uses.
#[command(
    names = [".context"],
    category = "processes and modules",
    kind = Action,
    target = Machine,
    python = none,
)]
fn context(state: &mut ReplState<'_>, #[arg(complete = Expression)] dtb: String) -> Result<()> {
    let text = dtb.as_str();
    let dtb = match Expr::eval_with_radix(text, &state.ctx.target, state.radix) {
        Ok(value) => value,
        Err(error) => {
            error!("invalid translation base '{}': {}", text, error);
            return Ok(());
        }
    };
    // A VTL1 root outside `.vtl 1` would pair it with a VTL0 register
    // file; only a live VTL1 stop may do that, with its own registers.
    let target = &state.ctx.target;
    if target.symbols.is_secure_root(target.normalize_dtb(dtb.0)) {
        error!(
            "{} is a VTL1 root; use .vtl 1 [pid] to inspect it",
            ui::addr(dtb.0)
        );
        return Ok(());
    }
    state.leave_vtl1();
    if state.ctx.target.attached_process().is_some() {
        state.ctx.target.detach();
    }
    state.clear_selected_frame();
    state.ctx.target.set_context_dtb_override(dtb.0);
    state.caches.refresh_symbol_context(&state.ctx.target);
    outln!("inspection context DTB set to {}\n", ui::addr(dtb.0));
    Ok(())
}

/// Whether `!process` takes `process` for an image name: as a glob, whole,
/// or contained in its name, ignoring case.
fn image_matches(process: &ProcessInfo, filter: &str) -> bool {
    glob_matches(filter, &process.name, true)
        || process.name.eq_ignore_ascii_case(filter)
        || process_matches(process, filter)
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

/// A selected process's user modules: their symbol loading, or why there
/// are none to list.
fn print_user_modules(report: &AttachReport) {
    match &report.modules_error {
        Some(error) => crate::diagnostics::print_warning(format!(
            "user modules unavailable: {error}; the address space is selected without them"
        )),
        None => print_module_symbol_report(&report.symbol_report),
    }
}

fn process_brief_row(detail: &ProcessDetail) -> Vec<String> {
    let process = &detail.process;
    vec![
        display_pointer(Some(process.eprocess)),
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

/// The `!process` table: one brief row per process.
fn print_process_briefs(details: &[ProcessDetail]) {
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
    for detail in details {
        builder.push_record(process_brief_row(detail));
    }
    print_padded_table(builder);
}

/// `ps`: the short legacy list.
fn print_ps(processes: &[ProcessInfo]) {
    let mut builder = Builder::default();
    builder.push_record(vec![
        "Name".to_string(),
        "PID".to_string(),
        "EPROCESS".to_string(),
        "DTB".to_string(),
        "Wow64".to_string(),
    ]);
    for process in processes {
        builder.push_record(vec![
            process.name.to_string(),
            format!("{}", ui::Value(process.pid)),
            ui::addr(process.eprocess.0).to_string(),
            ui::addr(process.dtb),
            if process.is_wow64() { "x86" } else { "-" }.to_string(),
        ]);
    }
    print_padded_table(builder);
}

fn print_process_detail(detail: &ProcessDetail) {
    outln!("  VadRoot        {}", display_pointer(detail.vad_root));
    outln!("  Token         {}", display_pointer(detail.token));
    outln!(
        "  Wow64Peb      {}",
        display_pointer(detail.process.wow64_peb)
    );
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
            && let Some(process) = processes.iter().find(|process| process.eprocess == address)
        {
            return Some(process.clone());
        }
        address
            .map(|address| address.0)
            .and_then(|pid| processes.iter().find(|process| process.pid == pid).cloned())
    }

    /// [`Self::process_for_selector`], or else the process a name names (see
    /// [`process_by_name`]).
    pub fn process_for_selector_or_name(
        &self,
        selector: &str,
        processes: &[ProcessInfo],
    ) -> Result<ProcessInfo> {
        match self.process_for_selector(selector, processes) {
            Some(process) => Ok(process),
            None => process_by_name(processes, selector).cloned(),
        }
    }

    /// The process `selector` names (see [`Self::process_for_selector_or_name`]),
    /// or the current process when there is none.
    pub fn process_or_current(&self, selector: Option<&str>) -> Result<ProcessInfo> {
        let target = &self.ctx.target;
        match selector {
            Some(selector) => {
                self.process_for_selector_or_name(selector, &target.matching_processes(None)?)
            }
            None => target.selected_process_info(),
        }
    }

    /// The threads of `process`, with their stacks when asked; false when an
    /// interrupt cut the list short.
    fn print_process_threads(&mut self, process: &ProcessInfo, include_stack: bool) -> bool {
        let mut threads = match self.ctx.target.enumerate_threads_for_process_info(process) {
            Ok(threads) => threads,
            Err(error) => {
                error!("  thread list unavailable: {}", error);
                return true;
            }
        };
        let truncated = threads.len() > MAX_PROCESS_THREADS;
        threads.truncate(MAX_PROCESS_THREADS);
        *self.caches.threads.write().unwrap() = threads.clone();
        let active = if include_stack {
            self.ctx.active_thread_map()
        } else {
            HashMap::new()
        };
        for (index, thread) in threads.iter().enumerate() {
            if self.ctx.target.interrupted() {
                outln!("  interrupted after {index} thread(s)");
                return false;
            }
            let vcpu = active.get(&thread.ethread.0).map(|(vcpu, _)| vcpu.as_str());
            print_thread_detail(
                &self
                    .ctx
                    .target
                    .thread_detail(thread.clone(), vcpu.map(str::to_string)),
            );
            if include_stack {
                match self.ctx.backtrace_thread(thread, vcpu, THREAD_STACK_LIMIT) {
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
        true
    }

    /// `.process` with no argument: the address space inspection uses.
    fn print_process_context(&self) {
        let target = &self.ctx.target;
        if target.in_secure_scope() {
            outln!(
                "process context: VTL1 memory view (DTB {})\n",
                ui::addr(target.current_dtb())
            );
        } else if target.in_secure_address_space() {
            outln!(
                "process context: VTL1 live stop (DTB {})\n",
                ui::addr(target.current_dtb())
            );
        } else if let Some(process) = target.current_process() {
            outln!(
                "process context: {} {} (PID {}, DTB {}{})\n",
                ui::addr(process.eprocess.0),
                process.name,
                process.pid,
                ui::addr(process.dtb),
                if process.is_wow64() { ", WOW64" } else { "" },
            );
        } else {
            outln!(
                "process context: kernel (DTB {})\n",
                ui::addr(target.kernel_dtb())
            );
        }
    }
}
