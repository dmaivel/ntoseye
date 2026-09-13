use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

use tabled::builder::Builder;

use owo_colors::OwoColorize;

use crate::error::{Error, Result};
use crate::expr::Expr;
use crate::guest::{ModuleInfo, ProcessInfo, StructRef};
use crate::memory::PAGE_SIZE;
use crate::session::processor_index_from_backend_thread_id;
use crate::symbols::{ModuleSymbolStatus, glob_matches};
use crate::target::{
    AttachReport, MemoryRegionInfo, Target, ThreadInfo, kthread_state_name, process_matches,
    wait_reason_name,
};
use crate::triage_report::filetime_to_iso;
use crate::types::{Value, VirtAddr};
use crate::ui;

use crate::repl::*;

const MAX_PROCESSOR_SELECTION: usize = 256;
const MAX_PROCESS_THREADS: usize = 512;
const THREAD_STACK_LIMIT: usize = 32;
const DEFAULT_THREAD_FRAME_LIMIT: usize = 16;
const PAGE_SHIFT: u32 = PAGE_SIZE.trailing_zeros();
const BYTES_PER_KIB: u64 = 1024;
const BYTES_PER_MIB: u64 = BYTES_PER_KIB * 1024;

repl_command! {
    cmd_vcpus();
    names: ["~", "vcpus"],
    usage: "~",
    summary: "List vCPU contexts and their RIP values.",
    run_state: Halted,
}

repl_command! {
    cmd_vcpu;
    names: ["vcpu"],
    usage: "vcpu <id>",
    summary: "Switch to a different vCPU context.",
    completion: Vcpu,
    run_state: Halted,
}

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
    cmd_lm;
    names: ["lm"],
    usage: "lm [m <pattern>] [v] [u|k] [t]",
    summary: "List loaded modules.",
    details: "`m` applies a module-name glob, `v m` prints verbose symbol information, `u` selects user modules, `k` selects kernel modules, and `t` adds timestamps.",
    completion: [None, Symbol, None, None],
}

repl_command! {
    cmd_drivers;
    names: ["drivers"],
    usage: "drivers [filter]",
    summary: "List driver objects from the \\Driver object directory.",
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
    cmd_vmmap;
    names: ["!vad", "vmmap"],
    usage: "!vad [pid|eprocess]",
    summary: "Display a process's VAD tree (defaults to the selected process context).",
    details: "Select a process by PID or EPROCESS expression; with no argument the current context is used (`.process /p <pid>` to select one). `vmmap [address|filter]` keeps the flat region view of the attached process, or the kernel modules when detached. VAD walks are bounded and skip unreadable entries rather than aborting the listing.",
    completion: [Process, None],
    run_state: Halted,
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

fn read_struct_path<T>(root: StructRef<'_>, path: &[&str]) -> Option<T>
where
    T: Copy + zerocopy::FromZeros + zerocopy::FromBytes + zerocopy::IntoBytes,
{
    let (field, parents) = path.split_last()?;
    let mut current = root;
    for parent in parents {
        current = match current.embedded(parent) {
            Ok(nested) => nested,
            Err(_) => current.follow(parent).ok()?,
        };
    }
    current.read_field(field).ok()
}

fn process_field<T>(target: &Target, process: &ProcessInfo, paths: &[&[&str]]) -> Option<T>
where
    T: Copy + zerocopy::FromZeros + zerocopy::FromBytes + zerocopy::IntoBytes,
{
    paths.iter().find_map(|path| {
        let root = target
            .guest()
            .ok()?
            .ntoskrnl
            .types_in(process.dtb)
            .struct_at("_EPROCESS", process.eprocess_va)
            .ok()?;
        read_struct_path(root, path)
    })
}

fn thread_field<T>(
    target: &Target,
    thread: &ThreadInfo,
    type_name: &str,
    base: VirtAddr,
    paths: &[&[&str]],
) -> Option<T>
where
    T: Copy + zerocopy::FromZeros + zerocopy::FromBytes + zerocopy::IntoBytes,
{
    let dtb = target
        .thread_process_dtb(thread)
        .unwrap_or_else(|| target.current_dtb());
    paths.iter().find_map(|path| {
        let root = target
            .guest()
            .ok()?
            .ntoskrnl
            .types_in(dtb)
            .struct_at(type_name, base)
            .ok()?;
        read_struct_path(root, path)
    })
}

fn display_decimal(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_string())
}

fn display_pointer(value: Option<u64>) -> String {
    value
        .filter(|value| *value != 0)
        .map(ui::addr)
        .unwrap_or_else(|| "-".to_string())
}

fn masked_fast_ref(value: Option<u64>) -> Option<u64> {
    value.map(|value| value & !0xf)
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
            .map(Value)
            .map(|tid| tid.to_string())
            .unwrap_or_else(|| "-".to_string()),
        thread
            .pid
            .map(Value)
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

fn print_thread_extended_detail(target: &Target, thread: &ThreadInfo) {
    print_thread_detail(thread);
    let win32_thread = thread_field(
        target,
        thread,
        "_ETHREAD",
        thread.ethread,
        &[&["Win32Thread"]],
    );
    let user_time =
        thread_field::<u32>(target, thread, "_KTHREAD", thread.kthread, &[&["UserTime"]])
            .map(u64::from)
            .or_else(|| {
                thread_field::<u32>(target, thread, "_ETHREAD", thread.ethread, &[&["UserTime"]])
                    .map(u64::from)
            });
    let kernel_time = thread_field::<u32>(
        target,
        thread,
        "_KTHREAD",
        thread.kthread,
        &[&["KernelTime"]],
    )
    .map(u64::from)
    .or_else(|| {
        thread_field::<u32>(
            target,
            thread,
            "_ETHREAD",
            thread.ethread,
            &[&["KernelTime"]],
        )
        .map(u64::from)
    });
    let wait_time =
        thread_field::<u32>(target, thread, "_KTHREAD", thread.kthread, &[&["WaitTime"]])
            .map(u64::from);
    let ready_time = thread_field::<u32>(
        target,
        thread,
        "_KTHREAD",
        thread.kthread,
        &[&["ReadyTime"]],
    )
    .map(u64::from);
    let quantum_target = thread_field::<u32>(
        target,
        thread,
        "_KTHREAD",
        thread.kthread,
        &[&["QuantumTarget"]],
    )
    .map(u64::from);
    outln!("  win32thread={}", display_pointer(win32_thread));
    outln!(
        "  times user={} kernel={} wait_time={} ready_time={} quantum_target={}",
        display_decimal(user_time),
        display_decimal(kernel_time),
        display_decimal(wait_time),
        display_decimal(ready_time),
        display_decimal(quantum_target),
    );
}

fn process_brief_row(target: &Target, process: &ProcessInfo) -> Vec<String> {
    let object_table = process_field::<u64>(target, process, &[&["ObjectTable"]]);
    let handle_count = object_table
        .and_then(|object_table| {
            target
                .guest()
                .ok()?
                .ntoskrnl
                .types_in(process.dtb)
                .struct_at("_HANDLE_TABLE", VirtAddr(object_table & !0xf))
                .ok()?
                .read_field::<u32>("HandleCount")
                .ok()
                .map(u64::from)
        })
        .or_else(|| process_field::<u32>(target, process, &[&["HandleCount"]]).map(u64::from));
    let dirbase = process_field(
        target,
        process,
        &[&["Pcb", "DirectoryTableBase"], &["DirectoryTableBase"]],
    );
    let parent = process_field(
        target,
        process,
        &[&["InheritedFromUniqueProcessId"], &["ParentCid"]],
    );
    let session_id =
        super::security::process_session_id(target, process.eprocess_va).map(u64::from);
    vec![
        display_pointer((process.eprocess_va.0 != 0).then_some(process.eprocess_va.0)),
        display_decimal(session_id),
        format!("{} ({:#x})", process.pid, process.pid),
        display_pointer(process_field(target, process, &[&["Peb"]])),
        display_decimal(parent),
        display_pointer(dirbase),
        display_pointer(object_table),
        display_decimal(handle_count),
        process.name.clone(),
    ]
}

fn print_process_detail(target: &Target, process: &ProcessInfo) {
    let token = masked_fast_ref(process_field(target, process, &[&["Token"]]));
    let vm = |field| process_field(target, process, &[&["Vm", field], &[field]]);
    let quota_paged = process_field(
        target,
        process,
        &[
            &["QuotaUsage", "PagedPool"],
            &["QuotaUsage", "PagedPoolUsage"],
        ],
    );
    let quota_nonpaged = process_field(
        target,
        process,
        &[
            &["QuotaUsage", "NonPagedPool"],
            &["QuotaUsage", "NonPagedPoolUsage"],
        ],
    );
    outln!(
        "  VadRoot        {}",
        display_pointer(process_field(
            target,
            process,
            &[&["VadRoot", "Root"], &["VadRoot"]]
        ))
    );
    outln!("  Token         {}", display_pointer(token));
    let create_time = process_field(target, process, &[&["CreateTime"]]).and_then(filetime_to_iso);
    outln!(
        "  CreateTime    {}",
        create_time.unwrap_or_else(|| "-".to_string())
    );
    outln!(
        "  UserTime      {}",
        display_decimal(process_field(target, process, &[&["UserTime"]]))
    );
    outln!(
        "  KernelTime    {}",
        display_decimal(process_field(target, process, &[&["KernelTime"]]))
    );
    outln!(
        "  QuotaPoolUsage paged={} nonpaged={}",
        display_decimal(quota_paged),
        display_decimal(quota_nonpaged)
    );
    outln!(
        "  WorkingSet    {}  Commit={}  PeakVirtualSize={}  PrivatePageCount={}",
        display_decimal(vm("WorkingSetSize")),
        display_decimal(vm("PagefileUsage").or_else(|| vm("CommitCharge"))),
        display_decimal(vm("PeakVirtualSize")),
        display_decimal(
            vm("PrivatePageCount")
                .or_else(|| vm("PrivateUsage"))
                .or_else(|| process_field(target, process, &[&["NumberOfPrivatePages"]])),
        )
    );
    outln!(
        "  DebugPort     {}  Job={}",
        display_pointer(process_field(target, process, &[&["DebugPort"]])),
        display_pointer(process_field(target, process, &[&["Job"]]))
    );
}

fn format_region_size(size: u64) -> String {
    if size >= BYTES_PER_MIB {
        format!("{:#x} ({} MiB)", size, size / BYTES_PER_MIB)
    } else if size >= BYTES_PER_KIB {
        format!("{:#x} ({} KiB)", size, size / BYTES_PER_KIB)
    } else {
        format!("{:#x}", size)
    }
}

fn vad_protection_label(protection: Option<u64>) -> String {
    match protection {
        Some(0) => "none".to_string(),
        Some(1) => "r".to_string(),
        Some(2) => "x".to_string(),
        Some(3) => "x/r".to_string(),
        Some(4) => "rw".to_string(),
        Some(5) => "cow".to_string(),
        Some(6) => "x/rw".to_string(),
        Some(7) => "x/cow".to_string(),
        Some(value) => format!("prot:{value}"),
        None => "-".to_string(),
    }
}

fn vad_type_label(region: &MemoryRegionInfo) -> String {
    match region.vad_type {
        Some(2) => "mapped".to_string(),
        Some(3) => "image".to_string(),
        Some(_) if region.private_memory == Some(true) => "private".to_string(),
        Some(value) => format!("vad:{value}"),
        None => "vad".to_string(),
    }
}

fn region_matches_filter(
    region: &MemoryRegionInfo,
    filter: Option<&str>,
    address: Option<VirtAddr>,
) -> bool {
    // A filter that resolved to an address selects by containment only; the
    // textual match below would otherwise also pick regions whose printed
    // bounds merely contain the digits.
    if let Some(address) = address {
        return (region.start..region.end).contains(&address);
    }
    let Some(filter) = filter.map(str::to_ascii_lowercase) else {
        return true;
    };
    format!("{:#x}", region.start.0).contains(&filter)
        || format!("{:#x}", region.end.0).contains(&filter)
        || region
            .details
            .as_deref()
            .is_some_and(|details| details.to_ascii_lowercase().contains(&filter))
        || vad_type_label(region).contains(&filter)
        || vad_protection_label(region.protection)
            .to_ascii_lowercase()
            .contains(&filter)
}

impl ReplState<'_> {
    pub fn cmd_tilde(&mut self, line: &str) -> Result<Flow> {
        let body = line.trim().strip_prefix('~').unwrap_or_default();
        if body.is_empty() {
            self.cmd_vcpus()?;
            return Ok(Flow::Continue);
        }
        let (selector, action) = if let Some(rest) = body.strip_prefix('*') {
            (None, rest.chars().next())
        } else {
            let digits = body.chars().take_while(|ch| ch.is_ascii_digit()).count();
            if digits == 0 {
                error!(
                    "invalid processor selector '{}'; expected ~, ~N[s|k|r], or ~*k",
                    line
                );
                return Ok(Flow::Continue);
            }
            let selector =
                match Expr::eval_with_radix(&body[..digits], &self.ctx.target, self.radix) {
                    Ok(value) => Some(value.0),
                    Err(_) => {
                        error!("processor {} out of range", &body[..digits]);
                        return Ok(Flow::Continue);
                    }
                };
            (selector, body[digits..].chars().next())
        };
        let action = action.unwrap_or('s');
        if !matches!(action, 's' | 'k' | 'r') {
            error!("invalid processor action '{}'; expected s, k, or r", action);
            return Ok(Flow::Continue);
        }
        let ids = match self.ctx.backend.thread_list() {
            Ok(ids) => ids,
            Err(error) => {
                error!("failed to list processors: {}", error);
                return Ok(Flow::Continue);
            }
        };
        let resolve = |number: u64| {
            ids.iter()
                .find(|id| processor_index_from_backend_thread_id(id) == u16::try_from(number).ok())
                .cloned()
                .or_else(|| {
                    ids.iter()
                        .find(|id| {
                            id.as_str()
                                .eq_ignore_ascii_case(&format!("p1.{:x}", number.saturating_add(1)))
                        })
                        .cloned()
                })
                .or_else(|| {
                    usize::try_from(number)
                        .ok()
                        .and_then(|index| ids.get(index).cloned())
                })
        };
        let selected = if let Some(number) = selector {
            if usize::try_from(number).map_or(true, |number| number >= ids.len()) {
                error!("processor {} out of range", number);
                return Ok(Flow::Continue);
            }
            resolve(number).into_iter().collect::<Vec<_>>()
        } else {
            ids.iter()
                .take(MAX_PROCESSOR_SELECTION)
                .cloned()
                .collect::<Vec<_>>()
        };
        if selected.is_empty() {
            error!("processor not found");
            return Ok(Flow::Continue);
        }
        let original = self.ctx.current_thread.clone();
        if action == 's' {
            let id = selected[0].clone();
            if let Err(error) = self.ctx.set_current_thread(&id) {
                error!("failed to switch processor: {}", error);
            } else {
                self.clear_selected_frame();
                refresh_windows_thread_context_for_backend_thread(&mut self.ctx.target, &id);
                self.caches.refresh_symbol_context(&self.ctx.target);
                outln!("switched to processor {}\n", id);
            }
            return Ok(Flow::Continue);
        }

        for id in selected {
            if let Err(error) = self.ctx.set_current_thread(&id) {
                error!("failed to switch processor {}: {}", id, error);
                continue;
            }
            self.clear_selected_frame();
            refresh_windows_thread_context_for_backend_thread(&mut self.ctx.target, &id);
            self.caches.refresh_symbol_context(&self.ctx.target);
            if let Err(error) = self.dispatch_line(if action == 'k' { "k" } else { "r" }) {
                error!("processor {} command failed: {}", id, error);
            }
        }
        if let Err(error) = self.ctx.set_current_thread(&original) {
            error!("failed to restore processor {}: {}", original, error);
        } else {
            self.clear_selected_frame();
            refresh_windows_thread_context_for_backend_thread(&mut self.ctx.target, &original);
            self.caches.refresh_symbol_context(&self.ctx.target);
        }
        Ok(Flow::Continue)
    }

    fn cmd_vcpus(&mut self) -> Result<()> {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.black.bright} {msg}")
                .unwrap(),
        );

        pb.set_message(format!("{}", "Waiting on GDB...".bright_black()));
        pb.enable_steady_tick(Duration::from_millis(100));

        let vcpus = match self.ctx.vcpus() {
            Ok(vcpus) => vcpus,
            Err(e) => {
                pb.finish_and_clear();
                error!("{}", e);
                return Ok(());
            }
        };
        self.caches.refresh_vcpus(self.ctx.backend.as_mut());

        pb.finish_and_clear();

        let mut builder = Builder::default();
        builder.push_record(vec!["vCPU", "RIP", "Context", "Symbol"]);
        for vcpu in vcpus {
            let (rip_cell, symbol_cell) = match vcpu.rip {
                Some(rip) => (
                    ui::addr(rip),
                    vcpu.symbol.unwrap_or_else(|| format!("{rip:#x}")),
                ),
                None => (ui::muted("unavailable"), vcpu.error.unwrap_or_default()),
            };
            builder.push_record(vec![
                format!("{}", vcpu.id),
                format!("{}", rip_cell),
                format!("{}", vcpu.context),
                symbol_cell,
            ]);
        }

        print_padded_table(builder);

        Ok(())
    }

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
                format!("{}", active_vcpu),
                format!("{}", ui::addr(thread.ethread.0)),
                format!(
                    "{}",
                    thread
                        .pid
                        .map(Value)
                        .map(|pid| pid.to_string())
                        .unwrap_or_else(|| "-".to_string())
                ),
                format!(
                    "{}",
                    thread
                        .tid
                        .map(Value)
                        .map(|tid| tid.to_string())
                        .unwrap_or_else(|| "-".to_string())
                ),
                format!("{}", thread.process_name.as_deref().unwrap_or("unknown")),
                format!("{}", thread_state_label(thread)),
                format!("{}", wait_reason_label(thread)),
                start
                    .map(|addr| ui::addr(addr.0))
                    .unwrap_or_else(|| "-".to_string()),
            ]);
        }
        print_padded_table(builder);
        Ok(())
    }

    fn windows_thread_candidates(&mut self) -> Result<Vec<ThreadInfo>> {
        let mut threads = self.ctx.target.enumerate_threads()?;
        let active = self.ctx.active_thread_map();
        for (_, thread) in active.values() {
            if !threads.iter().any(|known| known.ethread == thread.ethread) {
                threads.push(thread.clone());
            }
        }
        if threads.is_empty()
            && let Some(thread) = self.ctx.target.windows_thread_selection.clone()
        {
            threads.push(thread);
        }
        Ok(threads)
    }

    fn thread_matches_value(thread: &ThreadInfo, value: Option<u64>) -> bool {
        value.is_some_and(|value| {
            thread.tid == Some(value) || thread.ethread.0 == value || thread.kthread.0 == value
        })
    }

    fn cmd_thread(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let threads = match self.windows_thread_candidates() {
            Ok(threads) => threads,
            Err(e) => {
                error!("failed to enumerate threads: {}", e);
                Vec::new()
            }
        };

        let active = self.ctx.active_thread_map();
        *self.caches.threads.write().unwrap() = threads.clone();

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
        let matches = threads
            .iter()
            .filter(|thread| Self::thread_matches_value(thread, target_value))
            .collect::<Vec<_>>();

        let thread = match matches.as_slice() {
            [thread] => *thread,
            [] => {
                error!("no Windows thread matches '{}'", target);
                return Ok(());
            }
            many => {
                error!(
                    "ambiguous Windows thread '{}': {} matches",
                    target,
                    many.len()
                );
                return Ok(());
            }
        };

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
            if let Err(error) = self.ctx.set_current_thread(&current) {
                error!("failed to reset thread context: {}", error);
                return Ok(());
            }
            self.clear_selected_frame();
            self.ctx.target.clear_current_windows_thread_context();
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
        let active = self.ctx.active_thread_map();
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

        if let Some((vcpu, _)) = active.get(&thread.ethread.0) {
            if let Err(error) = self.ctx.set_current_thread(vcpu) {
                error!("failed to switch to vCPU {}: {}", vcpu, error);
                return Ok(());
            }
            self.clear_selected_frame();
            self.ctx
                .target
                .set_current_windows_thread_context((*thread).clone());
            outln!(
                "switched register context to {} (ETHREAD {})\n",
                vcpu,
                ui::addr(thread.ethread.0)
            );
        } else {
            self.ctx.select_parked_windows_thread(thread);
            self.clear_selected_frame();
            outln!(
                "selected parked thread context ETHREAD {} (stack only)\n",
                ui::addr(thread.ethread.0)
            );
        }
        self.caches.refresh_symbol_context(&self.ctx.target);
        Ok(())
    }

    fn cmd_vmmap(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let is_vad = invocation.name == "!vad";
        let filter = invocation.arg(0);
        let filter_address = filter
            .and_then(|filter| Expr::eval_with_radix(filter, &self.ctx.target, self.radix).ok());

        let vad_process = if is_vad {
            let processes = match self.ctx.target.matching_processes(None) {
                Ok(processes) => processes,
                Err(error) => {
                    error!("failed to enumerate processes: {}", error);
                    return Ok(());
                }
            };
            match filter {
                Some(selector) => match self.process_for_selector(selector, &processes) {
                    Some(process) => Some(process),
                    None => {
                        error!("no process matches '{selector}' (expected a PID or EPROCESS)");
                        return Ok(());
                    }
                },
                None => self.current_process_context(&processes),
            }
        } else {
            self.ctx.target.current_process_info.clone()
        };

        if let Some(process) = vad_process {
            let regions = match self
                .ctx
                .target
                .enumerate_vad_regions_for_process_info(&process)
            {
                Ok(regions) => regions,
                Err(e) => {
                    error!("failed to enumerate VADs: {}", e);
                    return Ok(());
                }
            };

            let mut builder = Builder::default();
            if is_vad {
                builder.push_record(vec![
                    "VAD".to_string(),
                    "Level".to_string(),
                    "Start VPN".to_string(),
                    "End VPN".to_string(),
                    "Commit".to_string(),
                    "Type/Protection".to_string(),
                    "File".to_string(),
                ]);
            } else {
                builder.push_record(vec![
                    "Start".to_string(),
                    "End".to_string(),
                    "Size".to_string(),
                    "Protect".to_string(),
                    "Type".to_string(),
                    "Commit".to_string(),
                    "Details".to_string(),
                ]);
            }

            let mut shown = 0usize;
            for region in regions
                .iter()
                .filter(|region| is_vad || region_matches_filter(region, filter, filter_address))
            {
                shown += 1;
                if is_vad {
                    builder.push_record(vec![
                        ui::addr(region.node_address.0),
                        region.level.to_string(),
                        format!("{:#x}", region.start.0 >> PAGE_SHIFT),
                        format!("{:#x}", region.end.0.saturating_sub(1) >> PAGE_SHIFT),
                        region
                            .commit_charge
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "-".to_string()),
                        format!(
                            "{}/{}",
                            vad_type_label(region),
                            vad_protection_label(region.protection)
                        ),
                        region.details.as_deref().unwrap_or("-").to_string(),
                    ]);
                } else {
                    builder.push_record(vec![
                        format!("{}", ui::addr(region.start.0)),
                        format!("{}", ui::addr(region.end.0)),
                        format!("{}", format_region_size(region.size())),
                        format!("{}", vad_protection_label(region.protection)),
                        format!("{}", vad_type_label(region)),
                        format!(
                            "{}",
                            region
                                .commit_charge
                                .map(|value| value.to_string())
                                .unwrap_or_else(|| "-".to_string())
                        ),
                        region.details.as_deref().unwrap_or("-").to_string(),
                    ]);
                }
            }

            if shown == 0 {
                outln!("{}\n", "no matching memory regions".bright_black());
            } else {
                outln!(
                    "{} {} ({})",
                    ui::label("process"),
                    process.name,
                    Value(process.pid)
                );
                print_padded_table(builder);
            }
            return Ok(());
        }

        if is_vad {
            error!("!vad requires a current process or an EPROCESS selector");
            return Ok(());
        }

        let modules = match self.ctx.target.kernel_modules_with_versions() {
            Ok(modules) => modules,
            Err(e) => {
                error!("failed to enumerate kernel modules: {}", e);
                return Ok(());
            }
        };
        let mut builder = Builder::default();
        builder.push_record(vec![
            "Start".to_string(),
            "End".to_string(),
            "Size".to_string(),
            "Module".to_string(),
            "Image".to_string(),
        ]);
        let mut shown = 0usize;
        for module in modules {
            let matches = filter.is_none_or(|filter| {
                module
                    .short_name
                    .to_ascii_lowercase()
                    .contains(&filter.to_ascii_lowercase())
                    || module
                        .name
                        .to_ascii_lowercase()
                        .contains(&filter.to_ascii_lowercase())
                    || filter_address.is_some_and(|address| module.contains_address(address))
            });
            if !matches {
                continue;
            }
            shown += 1;
            builder.push_record(vec![
                format!("{}", ui::addr(module.base_address.0)),
                format!("{}", ui::addr(module.end_address().0)),
                format!("{}", format_region_size(module.size as u64)),
                format!("{}", module.short_name),
                module.name,
            ]);
        }

        if shown == 0 {
            outln!("no matching kernel regions\n");
        } else {
            print_padded_table(builder);
        }
        Ok(())
    }

    fn current_process_context(&self, processes: &[ProcessInfo]) -> Option<ProcessInfo> {
        if let Some(process) = &self.ctx.target.current_process_info {
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

    fn process_for_selector(
        &self,
        selector: &str,
        processes: &[ProcessInfo],
    ) -> Option<ProcessInfo> {
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
                    u32::try_from(value.0)
                        .map_err(|_| Error::Rsp(format!("invalid !process flags: {text}")))
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
            "ParentCid".to_string(),
            "DirBase".to_string(),
            "ObjectTable".to_string(),
            "HandleCount".to_string(),
            "Image".to_string(),
        ]);
        for process in &selected {
            builder.push_record(process_brief_row(&self.ctx.target, process));
        }
        print_padded_table(builder);

        if flags & 1 != 0 || flags & 2 != 0 || flags & 4 != 0 {
            for process in &selected {
                outln!(
                    "{} {} ({})",
                    ui::label("process:"),
                    ui::addr(process.eprocess_va.0),
                    process.name
                );
                if flags & 1 != 0 {
                    print_process_detail(&self.ctx.target, process);
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
        ]);
        let mut count = 0;
        for process in processes {
            if filter.is_some_and(|filter| !process_matches(&process, filter)) {
                continue;
            }
            count += 1;
            builder.push_record(vec![
                format!("{}", process.name),
                format!("{}", Value(process.pid)),
                format!("{}", ui::addr(process.eprocess_va.0)),
                ui::addr(process.dtb),
            ]);
        }
        if count == 0 {
            outln!("{}\n", "no matching processes".bright_black());
        } else {
            print_padded_table(builder);
        }
        Ok(())
    }

    fn cmd_drivers(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let filter = invocation.arg(0).map(|s| s.to_lowercase());

        match self.ctx.target.enumerate_driver_objects() {
            Ok(drivers) => {
                let mut builder = Builder::default();
                builder.push_record(vec![
                    "DriverObject".to_string(),
                    "Name".to_string(),
                    "DriverStart".to_string(),
                    "Size".to_string(),
                    "Module".to_string(),
                    "DeviceObject".to_string(),
                    "DriverUnload".to_string(),
                ]);

                let mut count = 0;
                for driver in &drivers {
                    if let Some(ref f) = filter
                        && !driver.name.to_lowercase().contains(f)
                        && !format!("{:#x}", driver.object.0).starts_with(f)
                    {
                        continue;
                    }
                    count += 1;
                    let module = self
                        .ctx
                        .target
                        .symbols
                        .find_module_for_address(self.ctx.target.kernel_dtb(), driver.driver_start)
                        .map(|module| module.name)
                        .unwrap_or_else(|| "-".to_string());
                    builder.push_record(vec![
                        format!("{}", ui::addr(driver.object.0)),
                        format!("{}", driver.name),
                        format!("{}", ui::addr(driver.driver_start.0)),
                        format!("0x{:x}", driver.driver_size),
                        format!("{}", module),
                        format!("{}", ui::addr(driver.device_object.0)),
                        ui::addr(driver.driver_unload.0),
                    ]);
                }

                if count == 0 {
                    outln!("{}\n", "no matching drivers".bright_black());
                } else {
                    print_padded_table(builder);
                }
                *self.caches.drivers.write().unwrap() = drivers;
            }
            Err(e) => {
                error!("failed to list drivers: {}", e);
            }
        }

        Ok(())
    }

    fn cmd_lm(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let mut pattern = None;
        let mut verbose = false;
        let mut user = false;
        let mut kernel = false;
        let mut timestamp = false;
        let mut glob_filter = false;
        let mut index = 0;
        while index < invocation.argv.len() {
            let arg = invocation.arg(index).unwrap_or_default();
            let lower = arg.to_ascii_lowercase();
            match lower.as_str() {
                "v" => verbose = true,
                "u" => user = true,
                "k" => kernel = true,
                "t" => timestamp = true,
                "m" => {
                    glob_filter = true;
                    index += 1;
                    pattern = invocation.arg(index);
                }
                _ if pattern.is_none() => pattern = Some(arg),
                _ => {}
            }
            index += 1;
        }
        let dtb = if kernel {
            self.ctx.target.kernel_dtb()
        } else {
            self.ctx
                .target
                .current_process_info
                .as_ref()
                .map(|process| process.dtb)
                .unwrap_or_else(|| self.ctx.target.kernel_dtb())
        };
        let modules = if kernel {
            self.ctx.target.kernel_modules_with_versions()
        } else if user {
            if self.ctx.target.current_process_info.is_none() {
                Ok(Vec::new())
            } else {
                self.ctx.target.modules_with_versions()
            }
        } else {
            self.ctx.target.modules_with_versions()
        };
        match modules {
            Ok(modules) => {
                let matches = |module: &ModuleInfo| {
                    pattern.is_none_or(|pattern| {
                        if glob_filter {
                            glob_matches(pattern, &module.short_name, true)
                                || glob_matches(pattern, &module.name, true)
                                || module
                                    .name
                                    .rsplit(['\\', '/'])
                                    .next()
                                    .is_some_and(|name| glob_matches(pattern, name, true))
                        } else {
                            module
                                .short_name
                                .to_ascii_lowercase()
                                .contains(&pattern.to_ascii_lowercase())
                                || module
                                    .name
                                    .to_ascii_lowercase()
                                    .contains(&pattern.to_ascii_lowercase())
                        }
                    })
                };
                if verbose {
                    let mut shown = 0;
                    for module in modules.iter().filter(|module| matches(module)) {
                        shown += 1;
                        let status = self
                            .ctx
                            .target
                            .symbols
                            .module_symbol_status(dtb, module.base_address);
                        outln!("{} ({})", module.name, module.short_name);
                        outln!(
                            "  range   : {} - {}",
                            ui::addr(module.base_address.0),
                            ui::addr(module.end_address().0)
                        );
                        outln!(
                            "  symbols : {}",
                            status
                                .as_ref()
                                .map(|status| status.label().to_string())
                                .unwrap_or_else(|| "unknown".to_string())
                        );
                        outln!(
                            "  source  : {}",
                            self.ctx
                                .target
                                .symbols
                                .module_symbol_source(dtb, module.base_address)
                                .map(|source| source.label().to_string())
                                .unwrap_or_else(|| "-".to_string())
                        );
                        match self
                            .ctx
                            .target
                            .symbols
                            .module_pdb_identity(dtb, module.base_address)
                        {
                            Some(identity) => {
                                outln!("  pdb guid: {:032X}", identity.guid);
                                outln!("  pdb age : {}", identity.age);
                            }
                            None => outln!("  pdb     : -"),
                        }
                        if let Some(ModuleSymbolStatus::Failed(reason)) = status {
                            outln!("  error   : {}", reason);
                        }
                        if timestamp {
                            outln!(
                                "  timestamp: {}",
                                module
                                    .time_date_stamp
                                    .map(|stamp| format!("{stamp:#x}"))
                                    .unwrap_or_else(|| "-".to_string())
                            );
                        }
                        outln!();
                    }
                    if shown == 0 {
                        outln!("{}\n", "no matching modules".bright_black());
                    }
                    return Ok(());
                }
                let mut builder = Builder::default();
                let mut header = vec![
                    "Start".to_string(),
                    "End".to_string(),
                    "Module".to_string(),
                    "Version".to_string(),
                    "Symbols".to_string(),
                    "Source".to_string(),
                ];
                if timestamp {
                    header.push("Timestamp".to_string());
                }
                header.push("Image".to_string());
                builder.push_record(header);

                let mut count = 0;
                for module in modules {
                    if !matches(&module) {
                        continue;
                    }
                    count += 1;
                    let mut row = vec![
                        format!("{}", ui::addr(module.base_address.0)),
                        format!("{}", ui::addr(module.end_address().0)),
                        format!("{}", module.short_name),
                        format!("{}", module.file_version.as_deref().unwrap_or("-")),
                        format!(
                            "{}",
                            self.ctx
                                .target
                                .symbols
                                .module_symbol_status(dtb, module.base_address)
                                .map(|status| status.label().to_string())
                                .unwrap_or_else(|| "unknown".to_string())
                        ),
                        format!(
                            "{}",
                            self.ctx
                                .target
                                .symbols
                                .module_symbol_source(dtb, module.base_address)
                                .map(|source| source.label().to_string())
                                .unwrap_or_else(|| "-".to_string())
                        ),
                    ];
                    if timestamp {
                        row.push(
                            module
                                .time_date_stamp
                                .map(|stamp| format!("{stamp:#x}"))
                                .unwrap_or_else(|| "-".to_string()),
                        );
                    }
                    row.push(module.name);
                    builder.push_record(row);
                }

                if count == 0 {
                    outln!("{}\n", "no matching modules".bright_black());
                } else {
                    print_padded_table(builder);
                }
            }
            Err(e) => {
                error!("failed to list modules: {}", e);
            }
        }

        Ok(())
    }

    fn cmd_attach(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let pid_str = require_arg!(invocation, 0, "attach");
        match Expr::eval_with_radix(pid_str, &self.ctx.target, self.radix) {
            Ok(value) => match self.ctx.target.attach(value.0) {
                Ok(AttachReport {
                    name,
                    symbol_report,
                }) => {
                    self.caches.refresh_symbol_context(&self.ctx.target);
                    self.clear_selected_frame();
                    outln!("attached to {} (PID {})", name, value.0);
                    print_module_symbol_report(&symbol_report);
                    outln!();
                }
                Err(e) => {
                    error!("failed to attach: {}", e);
                }
            },
            Err(error) => {
                error!("invalid PID {}: {}", pid_str, error);
            }
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
                    "process context: {} {} (PID {}, DTB {})\n",
                    ui::addr(process.eprocess_va.0),
                    process.name,
                    process.pid,
                    ui::addr(process.dtb)
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
                    "process context: {} (PID {}, EPROCESS {})",
                    name,
                    process.pid,
                    ui::addr(process.eprocess_va.0)
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
        if self.ctx.target.current_process.is_some() {
            self.ctx.target.detach();
        }
        self.clear_selected_frame();
        self.ctx.target.set_context_dtb_override(dtb.0);
        self.caches.refresh_symbol_context(&self.ctx.target);
        outln!("inspection context DTB set to {}\n", ui::addr(dtb.0));
        Ok(())
    }

    fn cmd_detach(&mut self) -> Result<()> {
        if self.ctx.target.current_process.is_none() {
            error!("not attached to any process");
        } else {
            self.ctx.target.detach();
            self.caches.refresh_symbol_context(&self.ctx.target);
            self.clear_selected_frame();
            outln!("detached, now in kernel context\n");
        }

        Ok(())
    }

    fn cmd_vcpu(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let requested = require_arg!(invocation, 0, "vcpu");

        let threads = match self.ctx.backend.thread_list() {
            Ok(t) => t,
            Err(e) => {
                error!("failed to get vCPU list: {:?}", e);
                return Ok(());
            }
        };

        let thread_id = threads
            .iter()
            .find(|thread| thread.as_str() == requested)
            .cloned()
            .or_else(|| {
                Expr::eval_with_radix(requested, &self.ctx.target, self.radix)
                    .ok()
                    .and_then(|value| u16::try_from(value.0).ok())
                    .and_then(|number| {
                        threads
                            .iter()
                            .find(|thread| {
                                processor_index_from_backend_thread_id(thread) == Some(number)
                            })
                            .cloned()
                            .or_else(|| threads.get(number as usize).cloned())
                    })
            });
        let Some(thread_id) = thread_id else {
            error!("vCPU '{}' not found (use 'vcpus' to list vCPUs)", requested);
            return Ok(());
        };

        if let Err(e) = self.ctx.set_current_thread(&thread_id) {
            error!("failed to switch vCPU: {:?}", e);
            return Ok(());
        }

        self.clear_selected_frame();

        refresh_windows_thread_context_for_backend_thread(
            &mut self.ctx.target,
            &self.ctx.current_thread,
        );
        self.caches.refresh_symbol_context(&self.ctx.target);
        outln!("switched to vCPU {}\n", self.ctx.current_thread);

        Ok(())
    }
}
