use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

use tabled::builder::Builder;

use owo_colors::OwoColorize;

use crate::error::Result;
use crate::expr::Expr;
use crate::target::{
    AttachReport, MemoryRegionInfo, ThreadInfo, kthread_state_name, process_matches,
    wait_reason_name,
};
use crate::types::{Value, VirtAddr};
use crate::ui;

use crate::repl::*;

repl_command! {
    cmd_vcpus();
    names: ["vcpus"],
    usage: "vcpus",
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
    names: ["thread"],
    usage: "thread <tid|ethread|.> [k|r] [count]",
    summary: "Inspect a Windows thread and switch to it if it is currently running.",
    completion: [Thread, None, None],
    run_state: Halted,
}

repl_command! {
    cmd_ps;
    names: ["ps"],
    usage: "ps [filter]",
    summary: "List running processes.",
}

repl_command! {
    cmd_lm;
    names: ["lm"],
    usage: "lm [filter]",
    summary: "List loaded modules.",
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
    cmd_detach();
    names: ["detach"],
    usage: "detach",
    summary: "Detach from current process.",
}

repl_command! {
    cmd_vmmap;
    names: ["vmmap"],
    usage: "vmmap [address|filter]",
    summary: "Display virtual memory regions for the attached process, or kernel modules when detached.",
    completion: Expression,
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
    println!(
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
    println!(
        "  state={} wait={} kthread={} eprocess={}",
        thread_state_label(thread),
        wait_reason_label(thread),
        ui::addr(thread.kthread.0),
        thread
            .eprocess
            .map(|addr| ui::addr(addr.0))
            .unwrap_or_else(|| "-".to_string())
    );
    println!(
        "  start={} win32={} teb={} kernel_stack={}",
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
    println!(
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
    println!(
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
            println!("  irp_list=empty");
        } else {
            println!("  irp_list={} pending", irps.len());
            for (index, irp) in irps.iter().enumerate() {
                println!("    [{}] {}", index, ui::addr(irp.0));
            }
        }
    }
}

fn format_region_size(size: u64) -> String {
    if size >= 1024 * 1024 {
        format!("{:#x} ({} MiB)", size, size / (1024 * 1024))
    } else if size >= 1024 {
        format!("{:#x} ({} KiB)", size, size / 1024)
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
    if let Some(address) = address
        && address >= region.start
        && address < region.end
    {
        return true;
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
                format!("{}  ", vcpu.id),
                format!("{}  ", rip_cell),
                format!("{}  ", vcpu.context),
                symbol_cell,
            ]);
        }

        print_plain_table(builder);

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
        if let Some(filter) = filter {
            threads.retain(|thread| thread_matches_filter(thread, filter));
        }
        *self.caches.threads.write().unwrap() = threads.clone();

        if threads.is_empty() {
            println!("{}\n", "no matching threads".bright_black());
            return Ok(());
        }

        let mut builder = Builder::default();
        builder.push_record(vec![
            "Active  ".to_string(),
            "ETHREAD  ".to_string(),
            "PID  ".to_string(),
            "TID  ".to_string(),
            "Process  ".to_string(),
            "State  ".to_string(),
            "Wait  ".to_string(),
            "Start".to_string(),
        ]);
        for thread in &threads {
            let active_vcpu = active
                .get(&thread.ethread.0)
                .map(|vcpu| vcpu.as_str())
                .unwrap_or("-");
            let start = thread.start_address.or(thread.win32_start_address);
            builder.push_record(vec![
                format!("{}  ", active_vcpu),
                format!("{}  ", ui::addr(thread.ethread.0)),
                format!(
                    "{}  ",
                    thread
                        .pid
                        .map(Value)
                        .map(|pid| pid.to_string())
                        .unwrap_or_else(|| "-".to_string())
                ),
                format!(
                    "{}  ",
                    thread
                        .tid
                        .map(Value)
                        .map(|tid| tid.to_string())
                        .unwrap_or_else(|| "-".to_string())
                ),
                format!("{}  ", thread.process_name.as_deref().unwrap_or("unknown")),
                format!("{}  ", thread_state_label(thread)),
                format!("{}  ", wait_reason_label(thread)),
                start
                    .map(|addr| ui::addr(addr.0))
                    .unwrap_or_else(|| "-".to_string()),
            ]);
        }
        print_plain_table(builder);
        Ok(())
    }

    fn cmd_thread(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let target = require_arg!(invocation, 0, "thread");
        let mut threads = match self.ctx.target.enumerate_threads() {
            Ok(threads) => threads,
            Err(e) => {
                error!("failed to enumerate threads: {}", e);
                return Ok(());
            }
        };

        let active = self.ctx.active_thread_map();
        for (_, thread) in active.values() {
            if !threads.iter().any(|known| known.ethread == thread.ethread) {
                threads.push(thread.clone());
            }
        }
        *self.caches.threads.write().unwrap() = threads.clone();

        let current_alias_address = if target == "." {
            self.ctx
                .target
                .current_windows_thread
                .as_ref()
                .map(|t| t.ethread)
        } else {
            None
        };
        let target_address =
            current_alias_address.or_else(|| Expr::eval(target, &self.ctx.target).ok());
        let matches = threads
            .iter()
            .filter(|thread| {
                thread
                    .tid
                    .is_some_and(|tid| tid.to_string() == target || format!("{:#x}", tid) == target)
                    || target_address.is_some_and(|addr| addr == thread.ethread)
                    || format!("{:#x}", thread.ethread.0) == target
                    || format!("{:x}", thread.ethread.0) == target.trim_start_matches("0x")
            })
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
        let frame_limit = invocation
            .arg(2)
            .and_then(|count| count.parse::<usize>().ok())
            .unwrap_or(16)
            .max(1);

        let Some((vcpu, _)) = active.get(&thread.ethread.0) else {
            print_thread_detail(thread);
            println!(
                "{}\n",
                "thread is not currently executing on any vCPU".bright_black()
            );
            return Ok(());
        };

        // Route through Session::set_current_thread so the inspection context
        // (registers + the thread's CR3 as the read/install DTB) is established
        // uniformly with the SDK; the REPL layers the Windows-thread context and
        // symbol-cache refresh on top.
        if let Err(e) = self.ctx.set_current_thread(vcpu) {
            error!("failed to switch to vCPU {}: {:?}", vcpu, e);
            return Ok(());
        }
        self.ctx
            .target
            .set_current_windows_thread_context((*thread).clone());
        self.caches.refresh_symbol_context(&self.ctx.target);
        println!(
            "switched to {} running ETHREAD {}\n",
            self.ctx.current_thread,
            ui::addr(thread.ethread.0)
        );
        print_thread_detail(thread);

        match action {
            Some("k") => {
                let regs = match self.ctx.backend.read_registers() {
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
                let regs = match self.ctx.backend.read_registers() {
                    Ok(regs) => regs,
                    Err(e) => {
                        error!("failed to read registers: {:?}", e);
                        return Ok(());
                    }
                };
                print_registers(&self.ctx.register_map, &regs, false);
            }
            Some(other) => error!("unknown thread action '{}': expected k or r", other),
            None => {}
        }
        println!();
        Ok(())
    }

    fn cmd_vmmap(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let filter = invocation.arg(0);
        let filter_address = filter.and_then(|filter| Expr::eval(filter, &self.ctx.target).ok());

        if let Some(process) = self.ctx.target.current_process_info.clone() {
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
            builder.push_record(vec![
                "Start".to_string(),
                "End".to_string(),
                "Size".to_string(),
                "Protect".to_string(),
                "Type".to_string(),
                "Commit  ".to_string(),
                "Details".to_string(),
            ]);

            let mut shown = 0usize;
            for region in regions
                .iter()
                .filter(|region| region_matches_filter(region, filter, filter_address))
            {
                shown += 1;
                builder.push_record(vec![
                    format!("{}  ", ui::addr(region.start.0)),
                    format!("{}  ", ui::addr(region.end.0)),
                    format!("{}  ", format_region_size(region.size())),
                    format!("{}  ", vad_protection_label(region.protection)),
                    format!("{}  ", vad_type_label(region)),
                    format!(
                        "{}  ",
                        region
                            .commit_charge
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "-".to_string())
                    ),
                    region.details.as_deref().unwrap_or("-").to_string(),
                ]);
            }

            if shown == 0 {
                println!("{}\n", "no matching memory regions".bright_black());
            } else {
                println!(
                    "{} {} ({})",
                    ui::label("vmmap:"),
                    process.name,
                    Value(process.pid)
                );
                print_plain_table(builder);
            }
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
                format!("{}  ", ui::addr(module.base_address.0)),
                format!("{}  ", ui::addr(module.end_address().0)),
                format!("{}  ", format_region_size(module.size as u64)),
                format!("{}  ", module.short_name),
                module.name,
            ]);
        }

        if shown == 0 {
            println!("no matching kernel regions\n");
        } else {
            println!("{} kernel", ui::label("vmmap:"));
            print_plain_table(builder);
        }
        Ok(())
    }

    fn cmd_ps(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let filter = invocation.arg(0);

        let guest = match self.ctx.target.guest() {
            Ok(g) => g,
            Err(_) => {
                error!("process enumeration requires the kernel; not available in this dump");
                return Ok(());
            }
        };
        match guest.enumerate_processes() {
            Ok(processes) => {
                *self.caches.processes.write().unwrap() =
                    processes.iter().map(|p| (p.name.clone(), p.pid)).collect();

                let mut builder = Builder::default();
                builder.push_record(vec![
                    "Name".to_string(),
                    "PID".to_string(),
                    "EPROCESS".to_string(),
                    "DTB".to_string(),
                ]);

                let mut count = 0;
                for proc in processes {
                    if let Some(f) = filter
                        && !process_matches(&proc, f)
                    {
                        continue;
                    }
                    count += 1;
                    builder.push_record(vec![
                        format!("{}  ", proc.name),
                        format!("{}  ", Value(proc.pid)),
                        format!("{}  ", ui::addr(proc.eprocess_va.0)),
                        ui::addr(proc.dtb), // TODO technically is phys addr..
                    ]);
                }

                if count == 0 {
                    println!("{}\n", "no matching processes".bright_black());
                } else {
                    print_plain_table(builder);
                }
            }
            Err(e) => {
                error!("failed to enumerate processes: {}", e);
            }
        }

        Ok(())
    }

    fn cmd_drivers(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let filter = invocation.arg(0).map(|s| s.to_lowercase());

        match self.ctx.target.enumerate_driver_objects() {
            Ok(drivers) => {
                let mut builder = Builder::default();
                builder.push_record(vec![
                    "DriverObject  ".to_string(),
                    "Name  ".to_string(),
                    "DriverStart  ".to_string(),
                    "Size  ".to_string(),
                    "Module  ".to_string(),
                    "DeviceObject  ".to_string(),
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
                        format!("{}  ", ui::addr(driver.object.0)),
                        format!("{}  ", driver.name),
                        format!("{}  ", ui::addr(driver.driver_start.0)),
                        format!("0x{:x}  ", driver.driver_size),
                        format!("{}  ", module),
                        format!("{}  ", ui::addr(driver.device_object.0)),
                        ui::addr(driver.driver_unload.0),
                    ]);
                }

                if count == 0 {
                    println!("{}\n", "no matching drivers".bright_black());
                } else {
                    print_plain_table(builder);
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
        let filter = invocation.arg(0).map(|s| s.to_lowercase());

        let dtb = match &self.ctx.target.current_process_info {
            Some(process_info) => process_info.dtb,
            None => self.ctx.target.kernel_dtb(),
        };

        match self.ctx.target.modules_with_versions() {
            Ok(modules) => {
                let mut builder = Builder::default();
                builder.push_record(vec![
                    "Start".to_string(),
                    "End".to_string(),
                    "Module".to_string(),
                    "Version".to_string(),
                    "Symbols".to_string(),
                    "Source".to_string(),
                    "Image".to_string(),
                ]);

                let mut count = 0;
                for module in modules {
                    if let Some(ref f) = filter
                        && !module.short_name.to_lowercase().contains(f)
                        && !module.name.to_lowercase().contains(f)
                    {
                        continue;
                    }
                    count += 1;
                    builder.push_record(vec![
                        format!("{}  ", ui::addr(module.base_address.0)),
                        format!("{}  ", ui::addr(module.end_address().0)),
                        format!("{}  ", module.short_name),
                        format!("{}  ", module.file_version.as_deref().unwrap_or("-")),
                        format!(
                            "{}  ",
                            self.ctx
                                .target
                                .symbols
                                .module_symbol_status(dtb, module.base_address)
                                .map(|status| status.label().to_string())
                                .unwrap_or_else(|| "unknown".to_string())
                        ),
                        format!(
                            "{}  ",
                            self.ctx
                                .target
                                .symbols
                                .module_symbol_source(dtb, module.base_address)
                                .map(|source| source.label().to_string())
                                .unwrap_or_else(|| "-".to_string())
                        ),
                        module.name,
                    ]);
                }

                if count == 0 {
                    println!("{}\n", "no matching modules".bright_black());
                } else {
                    print_plain_table(builder);
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
        match pid_str.parse::<u64>() {
            Ok(pid) => match self.ctx.target.attach(pid) {
                Ok(AttachReport {
                    name,
                    symbol_report,
                }) => {
                    self.caches.refresh_symbol_context(&self.ctx.target);
                    if let Err(e) = self.caches.refresh_processes(&self.ctx.target) {
                        error!("failed to refresh process cache: {}", e);
                    }
                    println!("attached to {} (PID {})", name, pid);
                    print_module_symbol_report(&symbol_report);
                    println!();
                }
                Err(e) => {
                    error!("failed to attach: {}", e);
                }
            },
            Err(_) => {
                error!("invalid PID: {}", pid_str);
            }
        }

        Ok(())
    }

    fn cmd_detach(&mut self) -> Result<()> {
        if self.ctx.target.current_process.is_none() {
            error!("not attached to any process");
        } else {
            self.ctx.target.detach();
            self.caches.refresh_symbol_context(&self.ctx.target);
            if let Err(e) = self.caches.refresh_processes(&self.ctx.target) {
                error!("failed to refresh process cache: {}", e);
            }
            println!("detached, now in kernel context\n");
        }

        Ok(())
    }

    fn cmd_vcpu(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let thread_id = require_arg!(invocation, 0, "vcpu");

        let threads = match self.ctx.backend.thread_list() {
            Ok(t) => t,
            Err(e) => {
                error!("failed to get vCPU list: {:?}", e);
                return Ok(());
            }
        };

        if !threads.iter().any(|t| t == thread_id) {
            error!("vCPU '{}' not found (use 'vcpus' to list vCPUs)", thread_id);
            return Ok(());
        }

        if let Err(e) = self.ctx.set_current_thread(thread_id) {
            error!("failed to switch vCPU: {:?}", e);
            return Ok(());
        }

        refresh_windows_thread_context_for_backend_thread(
            &mut self.ctx.target,
            &self.ctx.current_thread,
        );
        self.caches.refresh_symbol_context(&self.ctx.target);
        println!("switched to vCPU {}\n", self.ctx.current_thread);

        Ok(())
    }
}
